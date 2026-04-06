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
 * Walks the indirect block tree for a given file, collects the L0 block
 * pointer checksums (which are already computed and stored by ZFS), hashes
 * them together with SHA256, and prints a single hex digest.  This produces
 * a content fingerprint without reading any file data, only metadata.
 *
 * Embedded block pointers (small blocks stored inline in the BP) have their
 * raw embedded payload hashed instead of blk_cksum.
 *
 * Holes (unallocated regions) do not contribute to the hash, so files
 * differing only in hole layout will produce the same digest.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
	(void) fprintf(stderr, "usage: %s <dataset> <path>\n\n", cmdname);
	(void) fprintf(stderr,
	    "  Generate a SHA256 fingerprint of a file from ZFS block\n"
	    "  pointer checksums, without reading file data.\n\n"
	    "  <dataset>  ZFS dataset name (e.g. tank/data)\n"
	    "  <path>     path within the dataset (e.g. dir/file.txt)\n");
	exit(1);
}

/*
 * Hash a single L0 block pointer's checksum into the running digest.
 */
static void
hash_blkptr_cksum(SHA2_CTX *ctx, const blkptr_t *bp)
{
	SHA2Update(ctx, bp->blk_cksum.zc_word, sizeof (bp->blk_cksum.zc_word));
}

/*
 * Hash the raw embedded data payload of an embedded BP.  Embedded BPs
 * store small blocks inline and have no blk_cksum, so we hash their
 * actual content instead.
 */
static void
hash_embedded_bp(SHA2_CTX *ctx, const blkptr_t *bp)
{
	SHA2Update(ctx, bp, sizeof (blkptr_t));
}

/*
 * Process a block pointer at the leaf (L0) level.
 */
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

/*
 * Recursively walk indirect blocks down to L0 and feed each leaf BP's
 * checksum into the hash context.
 */
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
			err = visit_indirect(spa, dnp, cbp, &czb, ctx);
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

/*
 * Compute and print a SHA256 digest over all L0 block checksums for
 * the given dnode.
 */
static void
dump_file_hash(dnode_t *dn)
{
	dnode_phys_t *dnp = dn->dn_phys;
	zbookmark_phys_t czb;
	SHA2_CTX ctx;
	unsigned char digest[SHA256_DIGEST_LENGTH];

	SHA2Init(SHA256, &ctx);

	SET_BOOKMARK(&czb, dmu_objset_id(dn->dn_objset),
	    dn->dn_object, dnp->dn_nlevels - 1, 0);
	for (int j = 0; j < dnp->dn_nblkptr; j++) {
		czb.zb_blkid = j;
		int err = visit_indirect(dmu_objset_spa(dn->dn_objset), dnp,
		    &dnp->dn_blkptr[j], &czb, &ctx);
		if (err)
			fatal("visit_indirect failed: %s", strerror(err));
	}

	SHA2Final(digest, &ctx);

	for (unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		(void) printf("%02x", digest[i]);
	(void) printf("\n");
}

/*
 * Open the dnode for the given object and compute its file hash.
 */
static void
dump_object(objset_t *os, uint64_t object)
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
			fatal("dmu_object_info() failed, errno %u", error);

		if (os->os_encrypted &&
		    DMU_OT_IS_ENCRYPTED(doi.doi_bonus_type)) {
			error = dnode_hold(os, object, FTAG, &dn);
			if (error)
				fatal("dnode_hold() failed, errno %u", error);
			dnode_held = B_TRUE;
		} else {
			error = dmu_bonus_hold(os, object, FTAG, &db);
			if (error)
				fatal("dmu_bonus_hold(%llu) failed, errno %u",
				    (u_longlong_t)object, error);
			dn = DB_DNODE((dmu_buf_impl_t *)db);
		}
	}

	dump_file_hash(dn);

	if (db != NULL)
		dmu_buf_rele(db, FTAG);
	if (dnode_held)
		dnode_rele(dn, FTAG);
}

static objset_t *sa_os = NULL;
static sa_attr_type_t *sa_attr_table = NULL;

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

	if (dmu_objset_type(*osp) == DMU_OST_ZFS &&
	    !(*osp)->os_encrypted) {
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

static char curpath[PATH_MAX];

/*
 * Iterate through the path components, recursively passing
 * current one's obj and remaining path until we find the obj
 * for the last one.
 */
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
		if (retobj != NULL) {
			*retobj = child_obj;
		} else {
			dump_object(os, child_obj);
		}
		return (0);
	default:
		(void) fprintf(stderr, "object %llu has non-file/directory "
		    "type %d\n", (u_longlong_t)obj, doi.doi_type);
		break;
	}

	return (EINVAL);
}

static int
dump_path(char *ds, char *path, uint64_t *retobj)
{
	int err;
	objset_t *os;
	uint64_t root_obj;

	err = open_objset(ds, FTAG, &os);
	if (err != 0)
		return (err);

	err = zap_lookup(os, MASTER_NODE_OBJ, ZFS_ROOT_OBJ, 8, 1, &root_obj);
	if (err != 0) {
		(void) fprintf(stderr, "can't lookup root znode: %s\n",
		    strerror(err));
		close_objset(os, FTAG);
		return (EINVAL);
	}

	(void) snprintf(curpath, sizeof (curpath), "dataset=%s path=/", ds);

	err = dump_path_impl(os, root_obj, path, retobj);

	close_objset(os, FTAG);
	return (err);
}

int
main(int argc, char **argv)
{
	char *spa_config_path_env;

	dprintf_setup(&argc, argv);

	spa_config_path_env = getenv("SPA_CONFIG_PATH");
	if (spa_config_path_env != NULL)
		spa_config_path = spa_config_path_env;

	zfs_btree_verify_intensity = 3;

#if defined(_LP64)
	/*
	 * Limit the ARC to 256 MB since we only read metadata.
	 */
	zfs_arc_min = 2ULL << SPA_MAXBLOCKSHIFT;
	zfs_arc_max = 256 * 1024 * 1024;
#endif

	zfs_vdev_async_read_max_active = 10;
	reference_tracking_enable = B_FALSE;
	spa_load_verify_dryrun = B_TRUE;
	spa_mode_readable_spacemaps = B_TRUE;

	kernel_init(SPA_MODE_READ);

	if (argc < 3)
		usage();

	int ret = dump_path(argv[1], argv[2], NULL);
	kernel_fini();
	return (ret);
}

