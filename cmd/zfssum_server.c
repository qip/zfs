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
 *   <dataset>\t<path>\n
 * Response:
 *   OK <hex-digest>\n
 *   ERR <message>\n
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
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
#include <libzpool.h>

extern int reference_tracking_enable;
extern int zfs_recover;
extern uint_t zfs_vdev_async_read_max_active;
extern boolean_t spa_load_verify_dryrun;
extern boolean_t spa_mode_readable_spacemaps;
extern uint_t zfs_btree_verify_intensity;

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
	(void) fprintf(stderr, "usage: %s [-d] [-s socket_path]\n", cmdname);
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

static void
hash_blkptr_cksum(SHA2_CTX *ctx, const blkptr_t *bp)
{
	SHA2Update(ctx, bp->blk_cksum.zc_word, sizeof (bp->blk_cksum.zc_word));
}

static void
hash_embedded_bp(SHA2_CTX *ctx, const blkptr_t *bp)
{
	SHA2Update(ctx, bp, sizeof (blkptr_t));
}

static void
process_leaf_bp(const blkptr_t *bp, const zbookmark_phys_t *zb,
    const dnode_phys_t *dnp, SHA2_CTX *ctx)
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
    blkptr_t *bp, const zbookmark_phys_t *zb, SHA2_CTX *ctx)
{
	int err = 0;

	if (BP_GET_BIRTH(bp) == 0)
		return (0);
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
			err = visit_indirect(spa, dnp, cbp, &czb, ctx);
			if (err)
				break;
		}
		arc_buf_destroy(buf, &buf);
	}
	return (err);
}

static int
dump_file_hash(dnode_t *dn, unsigned char digest[SHA256_DIGEST_LENGTH])
{
	dnode_phys_t *dnp = dn->dn_phys;
	zbookmark_phys_t czb;
	SHA2_CTX ctx;

	SHA2Init(SHA256, &ctx);
	SET_BOOKMARK(&czb, dmu_objset_id(dn->dn_objset),
	    dn->dn_object, dnp->dn_nlevels - 1, 0);
	for (int j = 0; j < dnp->dn_nblkptr; j++) {
		czb.zb_blkid = j;
		int err = visit_indirect(dmu_objset_spa(dn->dn_objset), dnp,
		    &dnp->dn_blkptr[j], &czb, &ctx);
		if (err)
			return (err);
	}
	SHA2Final(digest, &ctx);
	return (0);
}

static int
dump_object(objset_t *os, uint64_t object,
    unsigned char digest[SHA256_DIGEST_LENGTH])
{
	dmu_buf_t *db = NULL;
	dmu_object_info_t doi;
	dnode_t *dn;
	boolean_t dnode_held = B_FALSE;
	int error;

	if (object == 0) {
		dn = DMU_META_DNODE(os);
	} else {
		error = dmu_object_info(os, object, &doi);
		if (error)
			return (error);
		if (os->os_encrypted && DMU_OT_IS_ENCRYPTED(doi.doi_bonus_type)) {
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

	error = dump_file_hash(dn, digest);

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
    const char *ds, const char *path,
    unsigned char digest[SHA256_DIGEST_LENGTH])
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
	return (dump_object(os, object, digest));
}

static void
digest_to_hex(const unsigned char digest[SHA256_DIGEST_LENGTH], char *out)
{
	for (unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		(void) snprintf(&out[i * 2], 3, "%02x", digest[i]);
	out[SHA256_DIGEST_LENGTH * 2] = '\0';
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
		unsigned char digest[SHA256_DIGEST_LENGTH];
		char hex[(SHA256_DIGEST_LENGTH * 2) + 1];
		int err;

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
		path = tab + 1;
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
			err = zap_lookup(*cached_os, MASTER_NODE_OBJ, ZFS_ROOT_OBJ,
			    8, 1, cached_root_obj);
			if (err != 0) {
				(void) send_err(fp, "can't lookup root znode");
				close_objset(*cached_os, FTAG);
				*cached_os = NULL;
				continue;
			}
			(void) strlcpy(cached_ds, ds, cached_ds_sz);
		}

		err = hash_path_from_root(*cached_os, *cached_root_obj, ds, path, digest);
		if (err != 0) {
			(void) send_err(fp, strerror(err));
			continue;
		}

		digest_to_hex(digest, hex);
		if (fprintf(fp, "OK %s\n", hex) < 0)
			break;
		if (fflush(fp) != 0)
			break;
	}

	(void) fclose(fp);
	return (0);
}

static int
create_server_socket(const char *sock_path)
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
	char *spa_config_path_env;
	int c;
	int srv_fd;
	objset_t *cached_os = NULL;
	char cached_ds[ZFS_MAX_DATASET_NAME_LEN];
	uint64_t cached_root_obj = 0;

	while ((c = getopt(argc, argv, "ds:")) != -1) {
		switch (c) {
		case 'd':
			daemonize = B_TRUE;
			break;
		case 's':
			sock_path = optarg;
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

	srv_fd = create_server_socket(sock_path);
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
		(void) serve_client(cfd, &cached_os, cached_ds, sizeof (cached_ds),
		    &cached_root_obj);
	}

	if (cached_os != NULL)
		close_objset(cached_os, FTAG);
	(void) close(srv_fd);
	(void) unlink(sock_path);
	kernel_fini();
	return (0);
}
