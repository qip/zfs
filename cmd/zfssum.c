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
 * zfssum - Generate a file content fingerprint from ZFS block checksums.
 *
 * By default, queries a running zfssum-server daemon via Unix socket.
 * With -l, operates directly against the pool (slow due to
 * kernel_init / spa_open overhead per invocation).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <sys/socket.h>
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

static hash_algo_t
parse_algo(const char *name)
{
	if (strcmp(name, "sha256") == 0)
		return (HASH_SHA256);
	if (strcmp(name, "sha512") == 0)
		return (HASH_SHA512);
	if (strcmp(name, "blake3") == 0)
		return (HASH_BLAKE3);
	if (strcmp(name, "bp") == 0)
		return (HASH_BP);
	return ((hash_algo_t)-1);
}

static void
opts_to_str(const zfssum_opts_t *opts, char *buf, size_t bufsz)
{
	const char *algo;
	switch (opts->algo) {
	case HASH_SHA256: algo = "sha256"; break;
	case HASH_SHA512: algo = "sha512"; break;
	case HASH_BLAKE3: algo = "blake3"; break;
	case HASH_BP:     algo = "bp"; break;
	default:          algo = "unknown"; break;
	}
	(void) snprintf(buf, bufsz, "%s,%s,%s", algo,
	    opts->include_size ? "size" : "nosize",
	    opts->fill_holes ? "holefill" : "skipholes");
}

/* ------------------------------------------------------------------ */

static const char cmdname[] = "zfssum";

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
	    "usage: %s [-l] [-s socket] [-a algo] [-S] [-Z]"
	    " <dataset> <path> [path ...]\n\n", cmdname);
	(void) fprintf(stderr,
	    "  Generate a fingerprint of a file from ZFS block pointer\n"
	    "  checksums, without reading file data.\n\n"
	    "  -a, --algo ALGO    hash algorithm: blake3 (default),"
	    " sha256, sha512, bp\n"
	    "  -l, --local        local mode"
	    " (no server, slow per invocation)\n"
	    "  -s, --socket PATH  server socket"
	    " (default: /var/run/zfssum.sock)\n"
	    "  -S, --no-size      do NOT include file size in hash\n"
	    "  -Z, --skip-holes   skip holes instead of"
	    " filling zeros\n");
	exit(1);
}

/* ------------------------------------------------------------------ */
/*  Local (direct libzpool) mode                                      */
/* ------------------------------------------------------------------ */

static objset_t *sa_os = NULL;
static sa_attr_type_t *sa_attr_table = NULL;
static char curpath[PATH_MAX];

static int
open_objset(const char *path, const void *tag, objset_t **osp)
{
	int err;
	uint64_t sa_attrs = 0;
	uint64_t version = 0;

	VERIFY0P(sa_os);

	err = dmu_objset_hold_flags(path, 0, tag, osp);
	if (err != 0) {
		(void) fprintf(stderr, "failed to hold dataset '%s': %s\n",
		    path, strerror(err));
		return (err);
	}
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
			(void) fprintf(stderr, "sa_setup failed: %s\n",
			    strerror(err));
			dsl_dataset_long_rele(dmu_objset_ds(*osp), tag);
			dsl_dataset_rele_flags(dmu_objset_ds(*osp), 0, tag);
			*osp = NULL;
		}
	}
	sa_os = *osp;

	return (err);
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
		uint64_t fill = 0;

		ASSERT(!BP_IS_REDACTED(bp));

		err = arc_read(NULL, spa, bp, arc_getbuf_func, &buf,
		    ZIO_PRIORITY_ASYNC_READ, ZIO_FLAG_CANFAIL, &flags, zb);
		if (err)
			return (err);
		ASSERT(buf->b_data);

		blkptr_t *cbp = buf->b_data;
		for (int i = 0; i < epb; i++, cbp++) {
			zbookmark_phys_t czb;

			SET_BOOKMARK(&czb, zb->zb_objset, zb->zb_object,
			    zb->zb_level - 1,
			    zb->zb_blkid * epb + i);
			err = visit_indirect(spa, dnp, cbp, &czb, ctx,
			    fill_holes);
			if (err)
				break;
			fill += BP_GET_FILL(cbp);
		}
		if (!err)
			ASSERT3U(fill, ==, BP_GET_FILL(bp));
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

	if (err != 0) {
		(void) fprintf(stderr, "failed to lookup %s: %s\n",
		    curpath, strerror(err));
		return (err);
	}

	child_obj = ZFS_DIRENT_OBJ(child_obj);
	err = sa_buf_hold(os, child_obj, FTAG, &db);
	if (err != 0) {
		(void) fprintf(stderr,
		    "failed to get SA dbuf for obj %llu: %s\n",
		    (u_longlong_t)child_obj, strerror(err));
		return (EINVAL);
	}
	dmu_object_info_from_db(db, &doi);
	sa_buf_rele(db, FTAG);

	if (doi.doi_bonus_type != DMU_OT_SA &&
	    doi.doi_bonus_type != DMU_OT_ZNODE) {
		(void) fprintf(stderr, "invalid bonus type %d for obj %llu\n",
		    doi.doi_bonus_type, (u_longlong_t)child_obj);
		return (EINVAL);
	}

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
		(void) fprintf(stderr, "object %llu has non-file/directory "
		    "type %d\n", (u_longlong_t)obj, doi.doi_type);
		break;
	}

	return (EINVAL);
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
		fatal("out of memory while duplicating path");

	err = dump_path_impl(os, root_obj, path_copy, &object);
	free(path_copy);
	if (err != 0)
		return (err);

	return (dump_object(os, object, opts, digest, digest_len));
}

static void
print_digest(const unsigned char *digest, unsigned digest_len,
    const char *path, int include_path)
{
	for (unsigned int i = 0; i < digest_len; i++)
		(void) printf("%02x", digest[i]);

	if (include_path)
		(void) printf("  %s", path);
	(void) printf("\n");
}

static int
run_local(int argc, char **argv, int optidx, const zfssum_opts_t *opts)
{
	char *spa_config_path_env;
	objset_t *os = NULL;
	uint64_t root_obj;
	int include_path;
	int ret = 0;
	char *dataset;

	if (optidx + 2 > argc)
		usage();

	dataset = argv[optidx++];
	include_path = ((argc - optidx) > 1);

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

	ret = open_objset(dataset, FTAG, &os);
	if (ret != 0)
		goto out;

	ret = zap_lookup(os, MASTER_NODE_OBJ, ZFS_ROOT_OBJ, 8, 1, &root_obj);
	if (ret != 0) {
		(void) fprintf(stderr, "can't lookup root znode: %s\n",
		    strerror(ret));
		ret = EINVAL;
		goto out;
	}

	for (int i = optidx; i < argc; i++) {
		unsigned char digest[MAX_DIGEST_LEN];
		unsigned digest_len;

		ret = hash_path_from_root(os, root_obj, dataset,
		    argv[i], opts, digest, &digest_len);
		if (ret != 0)
			goto out;

		print_digest(digest, digest_len, argv[i], include_path);
	}

out:
	if (os != NULL)
		close_objset(os, FTAG);
	kernel_fini();
	return (ret);
}

/* ------------------------------------------------------------------ */
/*  Server (socket client) mode                                       */
/* ------------------------------------------------------------------ */

static int
connect_socket(const char *sock_path)
{
	int fd;
	struct sockaddr_un addr = { 0 };

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return (-1);
	addr.sun_family = AF_UNIX;
	(void) strlcpy(addr.sun_path, sock_path, sizeof (addr.sun_path));
	if (connect(fd, (struct sockaddr *)&addr, sizeof (addr)) != 0) {
		(void) close(fd);
		return (-1);
	}
	return (fd);
}

/*
 * Keep up to this many requests in flight to hide per-request
 * round-trip latency on the Unix socket.
 */
#define	PIPELINE_DEPTH	128

static int
run_server(int argc, char **argv, int optidx, const char *sock_path,
    const zfssum_opts_t *opts)
{
	char *dataset;
	int include_path;
	int fd, rfd;
	FILE *wfp, *rfp;
	char opts_str[64];
	int nfiles, sent, recvd;
	char line[4096];
	char *status, *payload, *nl;
	const char *path;

	if (optidx + 2 > argc)
		usage();

	dataset = argv[optidx++];
	nfiles = argc - optidx;
	include_path = (nfiles > 1);
	opts_to_str(opts, opts_str, sizeof (opts_str));

	fd = connect_socket(sock_path);
	if (fd < 0) {
		fatal("failed to connect %s: %s (is zfssum-server running?)",
		    sock_path, strerror(errno));
	}

	rfd = dup(fd);
	if (rfd < 0) {
		(void) close(fd);
		fatal("dup failed: %s", strerror(errno));
	}
	wfp = fdopen(fd, "w");
	rfp = fdopen(rfd, "r");
	if (wfp == NULL || rfp == NULL) {
		if (wfp != NULL)
			(void) fclose(wfp);
		else
			(void) close(fd);
		if (rfp != NULL)
			(void) fclose(rfp);
		else
			(void) close(rfd);
		fatal("fdopen failed: %s", strerror(errno));
	}

	for (sent = 0, recvd = 0; recvd < nfiles; recvd++) {
		while (sent < nfiles && sent - recvd < PIPELINE_DEPTH) {
			if (fprintf(wfp, "%s\t%s\t%s\n",
			    dataset, argv[optidx + sent], opts_str) < 0) {
				(void) fclose(wfp);
				(void) fclose(rfp);
				fatal("write failed: %s", strerror(errno));
			}
			sent++;
		}
		if (fflush(wfp) != 0) {
			(void) fclose(wfp);
			(void) fclose(rfp);
			fatal("flush failed: %s", strerror(errno));
		}

		path = argv[optidx + recvd];

		if (fgets(line, sizeof (line), rfp) == NULL) {
			(void) fclose(wfp);
			(void) fclose(rfp);
			fatal("read failed for %s: %s",
			    path, strerror(errno));
		}
		nl = strchr(line, '\n');
		if (nl != NULL)
			*nl = '\0';

		status = strtok(line, " ");
		payload = strtok(NULL, "");
		if (status == NULL || payload == NULL) {
			(void) fclose(wfp);
			(void) fclose(rfp);
			fatal("malformed server response");
		}
		if (strcmp(status, "OK") != 0) {
			(void) fclose(wfp);
			(void) fclose(rfp);
			fatal("server error for %s: %s", path, payload);
		}

		if (include_path)
			(void) printf("%s  %s\n", payload, path);
		else
			(void) printf("%s\n", payload);
	}

	(void) fclose(wfp);
	(void) fclose(rfp);
	return (0);
}

/* ------------------------------------------------------------------ */
/*  main                                                              */
/* ------------------------------------------------------------------ */

int
main(int argc, char **argv)
{
	const char *sock_path = "/var/run/zfssum.sock";
	boolean_t local_mode = B_FALSE;
	zfssum_opts_t opts = default_opts;
	int c;

	static struct option long_options[] = {
		{"algo",	required_argument,	NULL, 'a'},
		{"local",	no_argument,		NULL, 'l'},
		{"socket",	required_argument,	NULL, 's'},
		{"no-size",	no_argument,		NULL, 'S'},
		{"skip-holes",	no_argument,		NULL, 'Z'},
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "a:ls:SZ",
	    long_options, NULL)) != -1) {
		switch (c) {
		case 'a':
			opts.algo = parse_algo(optarg);
			if ((int)opts.algo == -1)
				fatal("unknown algorithm '%s'", optarg);
			break;
		case 'l':
			local_mode = B_TRUE;
			break;
		case 's':
			sock_path = optarg;
			break;
		case 'S':
			opts.include_size = B_FALSE;
			break;
		case 'Z':
			opts.fill_holes = B_FALSE;
			break;
		default:
			usage();
		}
	}

	if (local_mode)
		return (run_local(argc, argv, optind, &opts));
	else
		return (run_server(argc, argv, optind, sock_path, &opts));
}
