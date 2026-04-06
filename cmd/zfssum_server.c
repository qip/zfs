/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or https://opensource.org/licenses/CDDL-1.0.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * zfssum-server - persistent daemon for zfssum requests.
 *
 * Protocol (Unix stream socket, one request per line):
 *   <dataset>\t<path>[\t<algo>,<flags>]\n
 * Response:
 *   OK <hex-digest>\n
 *   ERR <message>\n
 *
 * <algo> is one of: blake3, sha256, sha512, bp
 * <flags> is comma-separated: size|nosize, holefill|skipholes
 * Default (when third field is absent): blake3,size,holefill
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/dmu.h>
#include <sys/dmu_objset.h>
#include <sys/zap.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_znode.h>
#include <sys/zfs_sa.h>
#include <sys/sa.h>
#include <sys/sa_impl.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_pool.h>
#include <sys/dbuf.h>
#include <sys/zil_impl.h>
#include <sys/arc_impl.h>
#include <sys/dsl_scan.h>
#include <sys/blkptr.h>
#include <sys/sha2.h>
#include <sys/blake3.h>
#include <libzpool.h>

extern int reference_tracking_enable;
extern int zfs_recover;
extern uint_t zfs_vdev_async_read_max_active;
extern boolean_t spa_load_verify_dryrun;
extern boolean_t spa_mode_readable_spacemaps;
extern uint_t zfs_btree_verify_intensity;

/* ------------------------------------------------------------------ */
/*  Hash algorithm abstraction                                        */
/* ------------------------------------------------------------------ */

typedef enum {
	HASH_SHA256,
	HASH_SHA512,
	HASH_BLAKE3,
	HASH_BP
} hash_algo_t;

typedef struct {
	hash_algo_t algo;
	union {
		SHA2_CTX sha2;
		BLAKE3_CTX blake3;
	};
	unsigned digest_len;
} hash_ctx_t;

typedef struct {
	hash_algo_t algo;
	boolean_t include_size;
	boolean_t fill_holes;
} zfssum_opts_t;

#define	MAX_DIGEST_LEN	SHA512_DIGEST_LENGTH	/* 64 */
#define	MAX_HEX_LEN	(MAX_DIGEST_LEN * 2 + 1)

static const zfssum_opts_t default_opts = {
	.algo = HASH_BLAKE3,
	.include_size = B_TRUE,
	.fill_holes = B_TRUE,
};

static void
hash_init(hash_ctx_t *h, hash_algo_t algo)
{
	h->algo = algo;
	switch (algo) {
	case HASH_SHA256:
		SHA2Init(SHA256, &h->sha2);
		h->digest_len = SHA256_DIGEST_LENGTH;
		break;
	case HASH_SHA512:
		SHA2Init(SHA512, &h->sha2);
		h->digest_len = SHA512_DIGEST_LENGTH;
		break;
	case HASH_BLAKE3:
		Blake3_Init(&h->blake3);
		h->digest_len = BLAKE3_OUT_LEN;
		break;
	default:
		abort();
	}
}

static void
hash_update(hash_ctx_t *h, const void *data, size_t len)
{
	switch (h->algo) {
	case HASH_SHA256:
	case HASH_SHA512:
		SHA2Update(&h->sha2, data, len);
		break;
	case HASH_BLAKE3:
		Blake3_Update(&h->blake3, data, len);
		break;
	default:
		abort();
	}
}

static void
hash_final(hash_ctx_t *h, unsigned char *digest)
{
	switch (h->algo) {
	case HASH_SHA256:
	case HASH_SHA512:
		SHA2Final(digest, &h->sha2);
		break;
	case HASH_BLAKE3:
		Blake3_Final(&h->blake3, digest);
		break;
	default:
		abort();
	}
}

static int
parse_opts(const char *str, zfssum_opts_t *opts)
{
	char *copy = strdup(str);
	if (copy == NULL)
		return (ENOMEM);

	*opts = default_opts;

	char *saveptr = NULL;
	char *token = strtok_r(copy, ",", &saveptr);
	while (token != NULL) {
		if (strcmp(token, "sha256") == 0)
			opts->algo = HASH_SHA256;
		else if (strcmp(token, "sha512") == 0)
			opts->algo = HASH_SHA512;
		else if (strcmp(token, "blake3") == 0)
			opts->algo = HASH_BLAKE3;
		else if (strcmp(token, "bp") == 0)
			opts->algo = HASH_BP;
		else if (strcmp(token, "size") == 0)
			opts->include_size = B_TRUE;
		else if (strcmp(token, "nosize") == 0)
			opts->include_size = B_FALSE;
		else if (strcmp(token, "holefill") == 0)
			opts->fill_holes = B_TRUE;
		else if (strcmp(token, "skipholes") == 0)
			opts->fill_holes = B_FALSE;
		else {
			free(copy);
			return (EINVAL);
		}
		token = strtok_r(NULL, ",", &saveptr);
	}
	free(copy);
	return (0);
}

/* ------------------------------------------------------------------ */

static const char cmdname[] = "zfssum-server";
static char curpath[PATH_MAX];
static objset_t *sa_os = NULL;
static sa_attr_type_t *sa_attr_table = NULL;

static void __attribute__((noreturn))
fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) fprintf(stderr, "%s: ", cmdname);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
	(void) fprintf(stderr, "\n");
	exit(1);
}

static void
usage(void)
{
	(void) fprintf(stderr,
	    "usage: %s [-d] [-s socket] [-m mode]"
	    " [-u uid] [-g gid]\n\n", cmdname);
	(void) fprintf(stderr,
	    "  -d, --daemon       daemonize after startup\n"
	    "  -s, --socket PATH  server socket"
	    " (default: /var/run/zfssum.sock)\n"
	    "  -m, --mode MODE    socket permission mode"
	    " in octal (default: 0666)\n"
	    "  -u, --uid UID      socket owner uid\n"
	    "  -g, --gid GID      socket owner gid\n");
	exit(1);
}

static int
open_objset(const char *path, const void *tag, objset_t **osp)
{
	int err;
	uint64_t sa_attrs = 0;
	uint64_t version = 0;

	VERIFY0P(sa_os);

	err = dmu_objset_hold_flags(path, 0, tag, osp);
	if (err != 0)
		return (err);

	dsl_dataset_long_hold(dmu_objset_ds(*osp), tag);
	dsl_pool_rele(dmu_objset_pool(*osp), tag);

	if (dmu_objset_type(*osp) == DMU_OST_ZFS && !(*osp)->os_encrypted) {
		(void) zap_lookup(*osp, MASTER_NODE_OBJ, ZPL_VERSION_STR,
		    8, 1, &version);
		if (version >= ZPL_VERSION_SA) {
			(void) zap_lookup(*osp, MASTER_NODE_OBJ, ZFS_SA_ATTRS,
			    8, 1, &sa_attrs);
		}
		err = sa_setup(*osp, sa_attrs, zfs_attr_table, ZPL_END,
		    &sa_attr_table);
		if (err != 0) {
			dsl_dataset_long_rele(dmu_objset_ds(*osp), tag);
			dsl_dataset_rele_flags(dmu_objset_ds(*osp), 0, tag);
			*osp = NULL;
			return (err);
		}
	}

	sa_os = *osp;
	return (0);
}

static void
close_objset(objset_t *os, const void *tag)
{
	VERIFY3P(os, ==, sa_os);
	if (os->os_sa != NULL)
		sa_tear_down(os);
	dsl_dataset_long_rele(dmu_objset_ds(os), tag);
	dsl_dataset_rele_flags(dmu_objset_ds(os), 0, tag);
	sa_attr_table = NULL;
	sa_os = NULL;
}

static uint64_t
get_file_size(objset_t *os, uint64_t object)
{
	uint64_t size = 0;
	sa_handle_t *hdl;

	if (object == 0 || sa_attr_table == NULL)
		return (0);
	if (sa_handle_get(os, object, NULL, SA_HDL_PRIVATE, &hdl) == 0) {
		(void) sa_lookup(hdl, sa_attr_table[ZPL_SIZE],
		    &size, sizeof (size));
		sa_handle_destroy(hdl);
	}
	return (size);
}

static void
hash_blkptr_cksum(hash_ctx_t *ctx, const blkptr_t *bp)
{
	hash_update(ctx, bp->blk_cksum.zc_word,
	    sizeof (bp->blk_cksum.zc_word));
}

static void
hash_embedded_bp(hash_ctx_t *ctx, const blkptr_t *bp)
{
	const uint64_t *words = (const uint64_t *)bp;
	for (unsigned i = 0; i < sizeof (blkptr_t) / sizeof (uint64_t); i++) {
		if (BPE_IS_PAYLOADWORD(bp, &words[i]))
			hash_update(ctx, &words[i], sizeof (uint64_t));
	}
}

static void
process_leaf_bp(const blkptr_t *bp, const zbookmark_phys_t *zb,
    const dnode_phys_t *dnp, hash_ctx_t *ctx)
{
	if (!BP_IS_EMBEDDED(bp)) {
		ASSERT3U(BP_GET_TYPE(bp), ==, dnp->dn_type);
		ASSERT3U(BP_GET_LEVEL(bp), ==, zb->zb_level);
	}
	ASSERT0(zb->zb_level);
	if (BP_IS_EMBEDDED(bp))
		hash_embedded_bp(ctx, bp);
	else
		hash_blkptr_cksum(ctx, bp);
}

static int
visit_indirect(spa_t *spa, const dnode_phys_t *dnp,
    blkptr_t *bp, const zbookmark_phys_t *zb,
    hash_ctx_t *ctx, boolean_t fill_holes)
{
	int err = 0;

	if (BP_GET_BIRTH(bp) == 0) {
		if (zb->zb_level == 0 && fill_holes) {
			static const uint8_t zeros[32] = { 0 };
			hash_update(ctx, zeros, sizeof (zeros));
		}
		return (0);
	}
	if (zb->zb_level == 0) {
		process_leaf_bp(bp, zb, dnp, ctx);
		return (0);
	}
	if (BP_GET_LEVEL(bp) > 0 && !BP_IS_HOLE(bp)) {
		arc_flags_t flags = ARC_FLAG_WAIT;
		int epb = BP_GET_LSIZE(bp) >> SPA_BLKPTRSHIFT;
		arc_buf_t *buf;

		err = arc_read(NULL, spa, bp, arc_getbuf_func, &buf,
		    ZIO_PRIORITY_ASYNC_READ, ZIO_FLAG_CANFAIL, &flags, zb);
		if (err)
			return (err);

		blkptr_t *cbp = buf->b_data;
		for (int i = 0; i < epb; i++, cbp++) {
			zbookmark_phys_t czb;
			SET_BOOKMARK(&czb, zb->zb_objset, zb->zb_object,
			    zb->zb_level - 1, zb->zb_blkid * epb + i);
			err = visit_indirect(spa, dnp, cbp, &czb, ctx,
			    fill_holes);
			if (err)
				break;
		}
		arc_buf_destroy(buf, &buf);
	}
	return (err);
}

static int
dump_file_hash(dnode_t *dn, uint64_t file_size,
    const zfssum_opts_t *opts, unsigned char *digest, unsigned *digest_len)
{
	dnode_phys_t *dnp = dn->dn_phys;
	zbookmark_phys_t czb;
	hash_ctx_t ctx;

	hash_init(&ctx, opts->algo);
	*digest_len = ctx.digest_len;

	if (opts->include_size)
		hash_update(&ctx, &file_size, sizeof (file_size));

	SET_BOOKMARK(&czb, dmu_objset_id(dn->dn_objset),
	    dn->dn_object, dnp->dn_nlevels - 1, 0);
	for (int j = 0; j < dnp->dn_nblkptr; j++) {
		czb.zb_blkid = j;
		int err = visit_indirect(dmu_objset_spa(dn->dn_objset), dnp,
		    &dnp->dn_blkptr[j], &czb, &ctx, opts->fill_holes);
		if (err)
			return (err);
	}
	hash_final(&ctx, digest);
	return (0);
}

static int
dump_file_bp_hash(dnode_t *dn, unsigned char *digest, unsigned *digest_len)
{
	dnode_phys_t *dnp = dn->dn_phys;
	int nactive = 0;
	boolean_t have_embedded = B_FALSE;
	int single_idx = -1;

	for (int j = 0; j < dnp->dn_nblkptr; j++) {
		blkptr_t *bp = &dnp->dn_blkptr[j];
		if (BP_GET_BIRTH(bp) != 0) {
			nactive++;
			single_idx = j;
			if (BP_IS_EMBEDDED(bp))
				have_embedded = B_TRUE;
		}
	}

	if (nactive == 1 && !have_embedded) {
		memcpy(digest,
		    dnp->dn_blkptr[single_idx].blk_cksum.zc_word,
		    sizeof (zio_cksum_t));
		*digest_len = sizeof (zio_cksum_t);
		return (0);
	}

	BLAKE3_CTX ctx;
	Blake3_Init(&ctx);
	for (int j = 0; j < dnp->dn_nblkptr; j++) {
		blkptr_t *bp = &dnp->dn_blkptr[j];
		if (BP_GET_BIRTH(bp) == 0)
			continue;
		if (BP_IS_EMBEDDED(bp)) {
			const uint64_t *w = (const uint64_t *)bp;
			for (unsigned i = 0;
			    i < sizeof (blkptr_t) / sizeof (uint64_t); i++) {
				if (BPE_IS_PAYLOADWORD(bp, &w[i]))
					Blake3_Update(&ctx, &w[i],
					    sizeof (uint64_t));
			}
		} else {
			Blake3_Update(&ctx, bp->blk_cksum.zc_word,
			    sizeof (bp->blk_cksum.zc_word));
		}
	}
	Blake3_Final(&ctx, digest);
	*digest_len = BLAKE3_OUT_LEN;
	return (0);
}

static int
dump_object(objset_t *os, uint64_t object,
    const zfssum_opts_t *opts, unsigned char *digest, unsigned *digest_len)
{
	dmu_buf_t *db = NULL;
	dmu_object_info_t doi;
	dnode_t *dn;
	boolean_t dnode_held = B_FALSE;
	int error;
	uint64_t file_size = 0;

	if (object == 0) {
		dn = DMU_META_DNODE(os);
	} else {
		error = dmu_object_info(os, object, &doi);
		if (error)
			return (error);
		if (os->os_encrypted &&
		    DMU_OT_IS_ENCRYPTED(doi.doi_bonus_type)) {
			error = dnode_hold(os, object, FTAG, &dn);
			if (error)
				return (error);
			dnode_held = B_TRUE;
		} else {
			error = dmu_bonus_hold(os, object, FTAG, &db);
			if (error)
				return (error);
			dn = DB_DNODE((dmu_buf_impl_t *)db);
		}
	}

	if (opts->include_size && opts->algo != HASH_BP)
		file_size = get_file_size(os, object);

	if (opts->algo == HASH_BP)
		error = dump_file_bp_hash(dn, digest, digest_len);
	else
		error = dump_file_hash(dn, file_size, opts,
		    digest, digest_len);

	if (db != NULL)
		dmu_buf_rele(db, FTAG);
	if (dnode_held)
		dnode_rele(dn, FTAG);
	return (error);
}

static int
dump_path_impl(objset_t *os, uint64_t obj, char *name, uint64_t *retobj)
{
	int err;
	uint64_t child_obj;
	char *s;
	dmu_buf_t *db;
	dmu_object_info_t doi;

	if ((s = strchr(name, '/')) != NULL)
		*s = '\0';
	err = zap_lookup(os, obj, name, 8, 1, &child_obj);
	(void) strlcat(curpath, name, sizeof (curpath));
	if (err != 0)
		return (err);

	child_obj = ZFS_DIRENT_OBJ(child_obj);
	err = sa_buf_hold(os, child_obj, FTAG, &db);
	if (err != 0)
		return (EINVAL);
	dmu_object_info_from_db(db, &doi);
	sa_buf_rele(db, FTAG);

	if (doi.doi_bonus_type != DMU_OT_SA &&
	    doi.doi_bonus_type != DMU_OT_ZNODE)
		return (EINVAL);

	(void) strlcat(curpath, "/", sizeof (curpath));
	switch (doi.doi_type) {
	case DMU_OT_DIRECTORY_CONTENTS:
		if (s != NULL && *(s + 1) != '\0')
			return (dump_path_impl(os, child_obj, s + 1, retobj));
		zfs_fallthrough;
	case DMU_OT_PLAIN_FILE_CONTENTS:
		*retobj = child_obj;
		return (0);
	default:
		return (EINVAL);
	}
}

static int
hash_path_from_root(objset_t *os, uint64_t root_obj,
    const char *ds, const char *path, const zfssum_opts_t *opts,
    unsigned char *digest, unsigned *digest_len)
{
	int err;
	uint64_t object;
	char *path_copy;

	(void) snprintf(curpath, sizeof (curpath), "dataset=%s path=/", ds);
	path_copy = strdup(path);
	if (path_copy == NULL)
		return (ENOMEM);
	err = dump_path_impl(os, root_obj, path_copy, &object);
	free(path_copy);
	if (err != 0)
		return (err);
	return (dump_object(os, object, opts, digest, digest_len));
}

static void
digest_to_hex(const unsigned char *digest, unsigned len, char *out)
{
	for (unsigned int i = 0; i < len; i++)
		(void) snprintf(&out[i * 2], 3, "%02x", digest[i]);
	out[len * 2] = '\0';
}

static int
read_line(FILE *fp, char *buf, size_t bufsz)
{
	if (fgets(buf, bufsz, fp) == NULL)
		return (errno == 0 ? EOF : errno);
	size_t len = strlen(buf);
	if (len > 0 && buf[len - 1] == '\n')
		buf[len - 1] = '\0';
	return (0);
}

static int
send_err(FILE *fp, const char *msg)
{
	if (fprintf(fp, "ERR %s\n", msg) < 0)
		return (EIO);
	if (fflush(fp) != 0)
		return (EIO);
	return (0);
}

static int
serve_client(int fd, objset_t **cached_os, char *cached_ds, size_t cached_ds_sz,
    uint64_t *cached_root_obj)
{
	FILE *fp = fdopen(fd, "r+");
	char line[8192];
	if (fp == NULL)
		return (errno);

	while (1) {
		char *tab;
		char *ds;
		char *path;
		unsigned char digest[MAX_DIGEST_LEN];
		unsigned digest_len;
		char hex[MAX_HEX_LEN];
		int err;
		zfssum_opts_t opts = default_opts;

		err = read_line(fp, line, sizeof (line));
		if (err == EOF)
			break;
		if (err != 0 || line[0] == '\0') {
			(void) send_err(fp, "invalid request");
			continue;
		}

		tab = strchr(line, '\t');
		if (tab == NULL) {
			(void) send_err(fp, "expected dataset<TAB>path");
			continue;
		}
		*tab = '\0';
		ds = line;
		char *rest = tab + 1;

		char *tab2 = strchr(rest, '\t');
		if (tab2 != NULL) {
			*tab2 = '\0';
			path = rest;
			if (parse_opts(tab2 + 1, &opts) != 0) {
				(void) send_err(fp, "invalid options");
				continue;
			}
		} else {
			path = rest;
		}

		if (ds[0] == '\0' || path[0] == '\0') {
			(void) send_err(fp, "empty dataset or path");
			continue;
		}

		if (*cached_os == NULL || strcmp(cached_ds, ds) != 0) {
			if (*cached_os != NULL) {
				close_objset(*cached_os, FTAG);
				*cached_os = NULL;
			}
			err = open_objset(ds, FTAG, cached_os);
			if (err != 0) {
				(void) send_err(fp, strerror(err));
				continue;
			}
			err = zap_lookup(*cached_os, MASTER_NODE_OBJ,
			    ZFS_ROOT_OBJ, 8, 1, cached_root_obj);
			if (err != 0) {
				(void) send_err(fp, "can't lookup root znode");
				close_objset(*cached_os, FTAG);
				*cached_os = NULL;
				continue;
			}
			(void) strlcpy(cached_ds, ds, cached_ds_sz);
		}

		err = hash_path_from_root(*cached_os, *cached_root_obj,
		    ds, path, &opts, digest, &digest_len);
		if (err != 0) {
			(void) send_err(fp, strerror(err));
			continue;
		}

		digest_to_hex(digest, digest_len, hex);
		if (fprintf(fp, "OK %s\n", hex) < 0)
			break;
		if (fflush(fp) != 0)
			break;
	}

	(void) fclose(fp);
	return (0);
}

static int
create_server_socket(const char *sock_path, mode_t mode,
    uid_t uid, gid_t gid)
{
	int fd;
	struct sockaddr_un addr = { 0 };

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return (-1);

	(void) unlink(sock_path);
	addr.sun_family = AF_UNIX;
	(void) strlcpy(addr.sun_path, sock_path, sizeof (addr.sun_path));
	if (bind(fd, (struct sockaddr *)&addr, sizeof (addr)) != 0) {
		(void) close(fd);
		return (-1);
	}
	if (chmod(sock_path, mode) != 0) {
		(void) close(fd);
		return (-1);
	}
	if ((uid != (uid_t)-1 || gid != (gid_t)-1) &&
	    chown(sock_path, uid, gid) != 0) {
		(void) close(fd);
		return (-1);
	}
	if (listen(fd, 32) != 0) {
		(void) close(fd);
		return (-1);
	}
	return (fd);
}

int
main(int argc, char **argv)
{
	const char *sock_path = "/var/run/zfssum.sock";
	boolean_t daemonize = B_FALSE;
	mode_t sock_mode = 0666;
	uid_t sock_uid = (uid_t)-1;
	gid_t sock_gid = (gid_t)-1;
	char *spa_config_path_env;
	int c;
	int srv_fd;
	objset_t *cached_os = NULL;
	char cached_ds[ZFS_MAX_DATASET_NAME_LEN];
	uint64_t cached_root_obj = 0;

	static struct option long_options[] = {
		{"daemon",	no_argument,		NULL, 'd'},
		{"socket",	required_argument,	NULL, 's'},
		{"mode",	required_argument,	NULL, 'm'},
		{"uid",		required_argument,	NULL, 'u'},
		{"gid",		required_argument,	NULL, 'g'},
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "dg:m:s:u:",
	    long_options, NULL)) != -1) {
		switch (c) {
		case 'd':
			daemonize = B_TRUE;
			break;
		case 'g':
			sock_gid = (gid_t)strtol(optarg, NULL, 10);
			break;
		case 'm':
			sock_mode = (mode_t)strtol(optarg, NULL, 8);
			break;
		case 's':
			sock_path = optarg;
			break;
		case 'u':
			sock_uid = (uid_t)strtol(optarg, NULL, 10);
			break;
		default:
			usage();
		}
	}
	if (optind != argc)
		usage();

	spa_config_path_env = getenv("SPA_CONFIG_PATH");
	if (spa_config_path_env != NULL)
		spa_config_path = spa_config_path_env;

	zfs_btree_verify_intensity = 3;
#if defined(_LP64)
	zfs_arc_min = 2ULL << SPA_MAXBLOCKSHIFT;
	zfs_arc_max = 256 * 1024 * 1024;
#endif
	zfs_vdev_async_read_max_active = 10;
	reference_tracking_enable = B_FALSE;
	spa_load_verify_dryrun = B_TRUE;
	spa_mode_readable_spacemaps = B_TRUE;

	kernel_init(SPA_MODE_READ);

	srv_fd = create_server_socket(sock_path, sock_mode, sock_uid, sock_gid);
	if (srv_fd < 0)
		fatal("failed to create server socket %s: %s",
		    sock_path, strerror(errno));

	if (daemonize) {
		if (daemon(0, 0) != 0)
			fatal("daemon() failed: %s", strerror(errno));
	}

	(void) memset(cached_ds, 0, sizeof (cached_ds));
	while (1) {
		int cfd = accept(srv_fd, NULL, NULL);
		if (cfd < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		(void) serve_client(cfd, &cached_os, cached_ds,
		    sizeof (cached_ds), &cached_root_obj);
	}

	if (cached_os != NULL)
		close_objset(cached_os, FTAG);
	(void) close(srv_fd);
	(void) unlink(sock_path);
	kernel_fini();
	return (0);
}
