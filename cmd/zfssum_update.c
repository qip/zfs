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
 * zfssum-update – update zfssum xattrs for every file in a dataset.
 *
 * Phase 1: build obj->path mapping via ZAP-level directory walk.
 * Phase 2: iterate objects sequentially via dmu_object_next(),
 *          compute checksums, write xattrs via lsetxattr().
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <sys/xattr.h>
#include <mntent.h>

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

#ifndef DT_DIR
#define	DT_DIR	4
#endif
#ifndef DT_REG
#define	DT_REG	8
#endif

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

static void
digest_to_hex(const unsigned char *digest, unsigned len, char *out)
{
	for (unsigned i = 0; i < len; i++)
		(void) snprintf(&out[i * 2], 3, "%02x", digest[i]);
	out[len * 2] = '\0';
}

/* ------------------------------------------------------------------ */
/*  Path map (obj -> relative path hash table)                        */
/* ------------------------------------------------------------------ */

#define	PMAP_INIT_CAP	4096

typedef struct {
	uint64_t obj;		/* 0 = empty slot */
	char *path;
} pmap_entry_t;

typedef struct {
	pmap_entry_t *entries;
	size_t cap;		/* always power of 2 */
	size_t count;
} path_map_t;

static size_t
pmap_hash(uint64_t obj, size_t mask)
{
	obj ^= obj >> 33;
	obj *= 0xff51afd7ed558ccdULL;
	obj ^= obj >> 33;
	return (obj & mask);
}

static void pmap_insert(path_map_t *pm, uint64_t obj, const char *path);

static void
pmap_insert_raw(path_map_t *pm, uint64_t obj, char *path)
{
	size_t mask = pm->cap - 1;
	size_t idx = pmap_hash(obj, mask);
	while (pm->entries[idx].obj != 0) {
		if (pm->entries[idx].obj == obj)
			return;
		idx = (idx + 1) & mask;
	}
	pm->entries[idx].obj = obj;
	pm->entries[idx].path = path;
	pm->count++;
}

static void
pmap_grow(path_map_t *pm)
{
	size_t old_cap = pm->cap;
	pmap_entry_t *old = pm->entries;

	pm->cap *= 2;
	pm->entries = calloc(pm->cap, sizeof (pmap_entry_t));
	pm->count = 0;
	for (size_t i = 0; i < old_cap; i++) {
		if (old[i].obj != 0)
			pmap_insert_raw(pm, old[i].obj, old[i].path);
	}
	free(old);
}

static void
pmap_insert(path_map_t *pm, uint64_t obj, const char *path)
{
	if (pm->count * 10 >= pm->cap * 7)
		pmap_grow(pm);
	pmap_insert_raw(pm, obj, strdup(path));
}

static const char *
pmap_lookup(const path_map_t *pm, uint64_t obj)
{
	size_t mask = pm->cap - 1;
	size_t idx = pmap_hash(obj, mask);
	while (pm->entries[idx].obj != 0) {
		if (pm->entries[idx].obj == obj)
			return (pm->entries[idx].path);
		idx = (idx + 1) & mask;
	}
	return (NULL);
}

static void
pmap_init(path_map_t *pm)
{
	pm->cap = PMAP_INIT_CAP;
	pm->entries = calloc(pm->cap, sizeof (pmap_entry_t));
	pm->count = 0;
}

static void
pmap_destroy(path_map_t *pm)
{
	for (size_t i = 0; i < pm->cap; i++)
		free(pm->entries[i].path);
	free(pm->entries);
}

/* ------------------------------------------------------------------ */
/*  Utility / fatal                                                   */
/* ------------------------------------------------------------------ */

static const char cmdname[] = "zfssum-update";

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
	    "usage: %s [-a algo] [-S] [-Z] [-v] [--update]"
	    " <dataset> [mountpoint]\n\n", cmdname);
	(void) fprintf(stderr,
	    "  Compute zfssum checksums for every file in <dataset>\n"
	    "  and store them as xattrs on the mounted filesystem.\n\n"
	    "  -a, --algo ALGO    hash algorithm: blake3 (default),"
	    " sha256, sha512, bp\n"
	    "  -S, --no-size      do NOT include file size in hash\n"
	    "  -Z, --skip-holes   skip holes instead of"
	    " filling zeros\n"
	    "  -v, --verbose      per-file timing to stderr\n"
	    "      --update       skip files whose xattr cache"
	    " is still valid\n");
	exit(1);
}

/* ------------------------------------------------------------------ */
/*  Objset helpers                                                    */
/* ------------------------------------------------------------------ */

static int
open_objset(const char *path, const void *tag, objset_t **osp,
    sa_attr_type_t **sa_table)
{
	int err;
	uint64_t sa_attrs = 0;
	uint64_t version = 0;

	err = dmu_objset_hold_flags(path, 0, tag, osp);
	if (err != 0)
		return (err);

	dsl_dataset_long_hold(dmu_objset_ds(*osp), tag);
	dsl_pool_rele(dmu_objset_pool(*osp), tag);

	*sa_table = NULL;
	if (dmu_objset_type(*osp) == DMU_OST_ZFS && !(*osp)->os_encrypted) {
		(void) zap_lookup(*osp, MASTER_NODE_OBJ, ZPL_VERSION_STR,
		    8, 1, &version);
		if (version >= ZPL_VERSION_SA) {
			(void) zap_lookup(*osp, MASTER_NODE_OBJ, ZFS_SA_ATTRS,
			    8, 1, &sa_attrs);
		}
		err = sa_setup(*osp, sa_attrs, zfs_attr_table, ZPL_END,
		    sa_table);
		if (err != 0) {
			dsl_dataset_long_rele(dmu_objset_ds(*osp), tag);
			dsl_dataset_rele_flags(dmu_objset_ds(*osp), 0, tag);
			*osp = NULL;
			return (err);
		}
	}

	return (0);
}

static void
close_objset(objset_t *os, const void *tag)
{
	if (os->os_sa != NULL)
		sa_tear_down(os);
	dsl_dataset_long_rele(dmu_objset_ds(os), tag);
	dsl_dataset_rele_flags(dmu_objset_ds(os), 0, tag);
}

/* ------------------------------------------------------------------ */
/*  Block pointer walk & checksum computation                         */
/* ------------------------------------------------------------------ */

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
compute_checksum(objset_t *os, uint64_t object, uint64_t file_size,
    const zfssum_opts_t *opts,
    unsigned char *digest, unsigned *digest_len)
{
	dmu_buf_t *db = NULL;
	dmu_object_info_t doi;
	dnode_t *dn;
	boolean_t dnode_held = B_FALSE;
	int error;

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

/* ------------------------------------------------------------------ */
/*  Phase 1: ZAP-level directory walk for path mapping                */
/* ------------------------------------------------------------------ */

static unsigned
resolve_dirent_type(objset_t *os, uint64_t child_de)
{
	unsigned t = ZFS_DIRENT_TYPE(child_de);
	if (t != 0)
		return (t);
	dmu_object_info_t cdoi;
	if (dmu_object_info(os, ZFS_DIRENT_OBJ(child_de), &cdoi) != 0)
		return (0);
	if (cdoi.doi_type == DMU_OT_DIRECTORY_CONTENTS)
		return (DT_DIR);
	if (cdoi.doi_type == DMU_OT_PLAIN_FILE_CONTENTS)
		return (DT_REG);
	return (0);
}

/*
 * Two-pass directory scan:
 *   Pass 1 – enumerate entries: insert files into path map, issue
 *            dmu_prefetch for every subdirectory ZAP.
 *   Pass 2 – re-iterate (ARC-hot) and recurse into subdirectories.
 *
 * The prefetch lets the disk start loading sibling directory ZAPs in
 * parallel while we recurse depth-first into the first child.
 */
static void
build_path_map_r(objset_t *os, uint64_t dir_obj,
    char *pathbuf, size_t prefix_len, path_map_t *pm,
    uint64_t *nfiles, uint64_t *ndirs, hrtime_t *t_last_print)
{
	zap_cursor_t zc;
	zap_attribute_t *za = zap_attribute_alloc();

	(*ndirs)++;
	hrtime_t now = gethrtime();
	if (now - *t_last_print >= 1000000000LL) {
		(void) fprintf(stderr,
		    "\rbuilding path map... %llu files, %llu dirs",
		    (u_longlong_t)*nfiles, (u_longlong_t)*ndirs);
		*t_last_print = now;
	}

	/* Pass 1: handle files, prefetch subdirectory ZAPs */
	for (zap_cursor_init(&zc, os, dir_obj);
	    zap_cursor_retrieve(&zc, za) == 0;
	    zap_cursor_advance(&zc)) {
		uint64_t child_de = za->za_first_integer;
		uint64_t child_obj = ZFS_DIRENT_OBJ(child_de);
		unsigned child_type = resolve_dirent_type(os, child_de);
		size_t namelen = strlen(za->za_name);

		if (prefix_len + namelen + 2 > PATH_MAX)
			continue;

		if (child_type == DT_REG) {
			memcpy(pathbuf + prefix_len, za->za_name, namelen);
			pathbuf[prefix_len + namelen] = '\0';
			pmap_insert(pm, child_obj, pathbuf);
			(*nfiles)++;
		} else if (child_type == DT_DIR) {
			dmu_prefetch(os, child_obj, 0, 0, 0,
			    ZIO_PRIORITY_ASYNC_READ);
		}
	}
	zap_cursor_fini(&zc);

	/* Pass 2: recurse into subdirectories (ZAPs are being prefetched) */
	for (zap_cursor_init(&zc, os, dir_obj);
	    zap_cursor_retrieve(&zc, za) == 0;
	    zap_cursor_advance(&zc)) {
		uint64_t child_de = za->za_first_integer;
		unsigned child_type = ZFS_DIRENT_TYPE(child_de);

		if (child_type == 0) {
			dmu_object_info_t cdoi;
			if (dmu_object_info(os,
			    ZFS_DIRENT_OBJ(child_de), &cdoi) != 0)
				continue;
			if (cdoi.doi_type == DMU_OT_DIRECTORY_CONTENTS)
				child_type = DT_DIR;
		}

		if (child_type == DT_DIR) {
			uint64_t child_obj = ZFS_DIRENT_OBJ(child_de);
			size_t namelen = strlen(za->za_name);
			if (prefix_len + namelen + 2 > PATH_MAX)
				continue;
			memcpy(pathbuf + prefix_len, za->za_name, namelen);
			pathbuf[prefix_len + namelen] = '/';
			pathbuf[prefix_len + namelen + 1] = '\0';
			build_path_map_r(os, child_obj, pathbuf,
			    prefix_len + namelen + 1, pm,
			    nfiles, ndirs, t_last_print);
		}
	}
	zap_cursor_fini(&zc);

	zap_attribute_free(za);
}

static int
build_path_map(objset_t *os, path_map_t *pm,
    uint64_t *nfiles, uint64_t *ndirs)
{
	uint64_t root_obj;
	char pathbuf[PATH_MAX];
	int err;

	err = zap_lookup(os, MASTER_NODE_OBJ, ZFS_ROOT_OBJ, 8, 1, &root_obj);
	if (err != 0)
		return (err);

	pathbuf[0] = '\0';
	*nfiles = 0;
	*ndirs = 0;
	hrtime_t t_last_print = gethrtime();
	build_path_map_r(os, root_obj, pathbuf, 0, pm,
	    nfiles, ndirs, &t_last_print);
	return (0);
}

/* ------------------------------------------------------------------ */
/*  xattr meta format / parse / cache check                           */
/* ------------------------------------------------------------------ */

static void
format_meta(char *buf, size_t bufsz, const char *opts_str,
    const uint64_t mtime[2], uint64_t fsize)
{
	(void) snprintf(buf, bufsz, "alg=%s;mtime=%llu.%09llu;size=%llu",
	    opts_str,
	    (u_longlong_t)mtime[0], (u_longlong_t)mtime[1],
	    (u_longlong_t)fsize);
}

static boolean_t
meta_matches(const char *meta, size_t meta_len,
    const char *opts_str, const uint64_t mtime[2], uint64_t fsize)
{
	char alg_buf[64];
	unsigned long long mt_sec, mt_nsec, sz;

	char meta_copy[256];
	if (meta_len >= sizeof (meta_copy))
		return (B_FALSE);
	memcpy(meta_copy, meta, meta_len);
	meta_copy[meta_len] = '\0';

	if (sscanf(meta_copy, "alg=%63[^;];mtime=%llu.%llu;size=%llu",
	    alg_buf, &mt_sec, &mt_nsec, &sz) != 4)
		return (B_FALSE);

	if (strcmp(alg_buf, opts_str) != 0)
		return (B_FALSE);
	if ((uint64_t)mt_sec != mtime[0] || (uint64_t)mt_nsec != mtime[1])
		return (B_FALSE);
	if ((uint64_t)sz != fsize)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Read ZPL_DXATTR (SA xattr nvlist) and check whether user.zfssum.meta
 * matches the current parameters.  Returns B_TRUE if cached.
 *
 * Only works for xattr=sa; for xattr=dir the SA check returns empty
 * and the file is treated as uncached (conservative).
 */
static boolean_t
check_sa_cache(sa_handle_t *hdl, sa_attr_type_t *sa_table,
    const char *opts_str, const uint64_t mtime[2], uint64_t fsize)
{
	int xattr_size = 0;
	boolean_t cached = B_FALSE;

	if (sa_size(hdl, sa_table[ZPL_DXATTR], &xattr_size) != 0 ||
	    xattr_size == 0)
		return (B_FALSE);

	char *packed = malloc(xattr_size);
	if (packed == NULL)
		return (B_FALSE);

	if (sa_lookup(hdl, sa_table[ZPL_DXATTR], packed, xattr_size) != 0) {
		free(packed);
		return (B_FALSE);
	}

	nvlist_t *nvl;
	if (nvlist_unpack(packed, xattr_size, &nvl, 0) != 0) {
		free(packed);
		return (B_FALSE);
	}

	uchar_t *val;
	uint_t len;
	if (nvlist_lookup_byte_array(nvl, "user.zfssum.meta",
	    &val, &len) == 0) {
		cached = meta_matches((const char *)val, len,
		    opts_str, mtime, fsize);
	}

	nvlist_free(nvl);
	free(packed);
	return (cached);
}

/* ------------------------------------------------------------------ */
/*  Mountpoint resolution                                             */
/* ------------------------------------------------------------------ */

static int
resolve_mountpoint(const char *dataset, char *buf, size_t bufsz)
{
	FILE *fp = setmntent("/proc/self/mounts", "r");
	if (fp == NULL)
		return (ENOENT);

	struct mntent *mnt;
	while ((mnt = getmntent(fp)) != NULL) {
		if (strcmp(mnt->mnt_type, "zfs") == 0 &&
		    strcmp(mnt->mnt_fsname, dataset) == 0) {
			(void) strlcpy(buf, mnt->mnt_dir, bufsz);
			endmntent(fp);
			return (0);
		}
	}

	endmntent(fp);
	return (ENOENT);
}

/* ------------------------------------------------------------------ */
/*  Progress helpers                                                  */
/* ------------------------------------------------------------------ */

static void
format_elapsed(hrtime_t ns, char *buf, size_t bufsz)
{
	uint64_t secs = ns / 1000000000ULL;
	unsigned h = secs / 3600;
	unsigned m = (secs % 3600) / 60;
	unsigned s = secs % 60;
	(void) snprintf(buf, bufsz, "%02u:%02u:%02u", h, m, s);
}

static void
print_progress(hrtime_t elapsed, uint64_t processed, uint64_t total,
    uint64_t cached, uint64_t errors, boolean_t update_mode)
{
	char tbuf[16];
	format_elapsed(elapsed, tbuf, sizeof (tbuf));
	double secs = (double)elapsed / 1000000000.0;
	double rate = secs > 0 ? (double)processed / secs : 0;
	double pct = total > 0 ? (double)processed * 100.0 / (double)total : 0;

	if (update_mode) {
		(void) fprintf(stderr,
		    "\r[%s] %llu/%llu files (%.1f%%) | %.1f files/s"
		    " | cached: %llu | errors: %llu",
		    tbuf,
		    (u_longlong_t)processed, (u_longlong_t)total, pct, rate,
		    (u_longlong_t)cached, (u_longlong_t)errors);
	} else {
		(void) fprintf(stderr,
		    "\r[%s] %llu/%llu files (%.1f%%) | %.1f files/s"
		    " | errors: %llu",
		    tbuf,
		    (u_longlong_t)processed, (u_longlong_t)total, pct, rate,
		    (u_longlong_t)errors);
	}
}

/* ------------------------------------------------------------------ */
/*  Main update loop                                                  */
/* ------------------------------------------------------------------ */

static int
run_update(const char *dataset, const char *mountpoint,
    const zfssum_opts_t *opts, boolean_t update_mode, boolean_t verbose)
{
	objset_t *os = NULL;
	sa_attr_type_t *sa_table = NULL;
	path_map_t pmap;
	uint64_t total_files = 0;
	uint64_t processed = 0, cached = 0, errors = 0;
	char opts_str[64];
	int ret;

	opts_to_str(opts, opts_str, sizeof (opts_str));
	pmap_init(&pmap);

	ret = open_objset(dataset, FTAG, &os, &sa_table);
	if (ret != 0) {
		(void) fprintf(stderr, "%s: failed to open dataset '%s': %s\n",
		    cmdname, dataset, strerror(ret));
		pmap_destroy(&pmap);
		return (ret);
	}
	if (sa_table == NULL) {
		(void) fprintf(stderr,
		    "%s: SA table not available"
		    " (encrypted or unsupported dataset)\n", cmdname);
		close_objset(os, FTAG);
		pmap_destroy(&pmap);
		return (ENOTSUP);
	}

	/* Phase 1: build path map */
	uint64_t total_dirs = 0;
	(void) fprintf(stderr, "building path map...");
	ret = build_path_map(os, &pmap, &total_files, &total_dirs);
	if (ret != 0) {
		(void) fprintf(stderr, " failed: %s\n", strerror(ret));
		close_objset(os, FTAG);
		pmap_destroy(&pmap);
		return (ret);
	}
	(void) fprintf(stderr,
	    "\rbuilding path map... %llu files, %llu dirs - done\n",
	    (u_longlong_t)total_files, (u_longlong_t)total_dirs);

	/* Phase 2: iterate objects sequentially */
	hrtime_t t_start = gethrtime();
	hrtime_t t_last_print = t_start;
	uint64_t object = 0;

	while (dmu_object_next(os, &object, B_FALSE, 0) == 0) {
		const char *rel_path = pmap_lookup(&pmap, object);
		if (rel_path == NULL)
			continue;

		sa_handle_t *hdl;
		if (sa_handle_get(os, object, NULL, SA_HDL_PRIVATE,
		    &hdl) != 0) {
			errors++;
			processed++;
			continue;
		}

		uint64_t mode = 0, fsize = 0;
		uint64_t mtime[2] = {0, 0};
		sa_bulk_attr_t bulk[3];
		int idx = 0;
		SA_ADD_BULK_ATTR(bulk, idx, sa_table[ZPL_MODE],
		    NULL, &mode, 8);
		SA_ADD_BULK_ATTR(bulk, idx, sa_table[ZPL_SIZE],
		    NULL, &fsize, 8);
		SA_ADD_BULK_ATTR(bulk, idx, sa_table[ZPL_MTIME],
		    NULL, mtime, 16);

		if (sa_bulk_lookup(hdl, bulk, idx) != 0) {
			sa_handle_destroy(hdl);
			errors++;
			processed++;
			continue;
		}

		if (!S_ISREG(mode)) {
			sa_handle_destroy(hdl);
			continue;
		}

		if (update_mode &&
		    check_sa_cache(hdl, sa_table, opts_str, mtime, fsize)) {
			sa_handle_destroy(hdl);
			cached++;
			processed++;
			goto progress;
		}

		sa_handle_destroy(hdl);

		/* compute checksum */
		hrtime_t t0 = verbose ? gethrtime() : 0;

		unsigned char digest[MAX_DIGEST_LEN];
		unsigned digest_len;
		uint64_t hash_size =
		    (opts->include_size && opts->algo != HASH_BP) ? fsize : 0;
		int err = compute_checksum(os, object, hash_size,
		    opts, digest, &digest_len);
		if (err != 0) {
			if (verbose) {
				(void) fprintf(stderr, "\n  ERR %s: %s\n",
				    rel_path, strerror(err));
			}
			errors++;
			processed++;
			goto progress;
		}

		/* write xattrs */
		char hex[MAX_HEX_LEN];
		digest_to_hex(digest, digest_len, hex);

		char meta[256];
		format_meta(meta, sizeof (meta), opts_str, mtime, fsize);

		char fullpath[PATH_MAX];
		(void) snprintf(fullpath, sizeof (fullpath), "%s/%s",
		    mountpoint, rel_path);

		if (lsetxattr(fullpath, "user.zfssum.checksum",
		    hex, strlen(hex), 0) != 0 ||
		    lsetxattr(fullpath, "user.zfssum.meta",
		    meta, strlen(meta), 0) != 0) {
			if (verbose) {
				(void) fprintf(stderr, "\n  xattr %s: %s\n",
				    rel_path, strerror(errno));
			}
			errors++;
		}
		processed++;

		if (verbose) {
			hrtime_t t1 = gethrtime();
			(void) fprintf(stderr, "\n  %s  %.3fms  %s",
			    hex, (double)(t1 - t0) / 1000000.0, rel_path);
		}

progress:
		;
		hrtime_t now = gethrtime();
		if (now - t_last_print >= 1000000000LL) {
			print_progress(now - t_start, processed,
			    total_files, cached, errors, update_mode);
			t_last_print = now;
		}
	}

	/* final progress line */
	hrtime_t elapsed = gethrtime() - t_start;
	print_progress(elapsed, processed, total_files,
	    cached, errors, update_mode);
	(void) fprintf(stderr, "\n");

	/* summary */
	char tbuf[16];
	format_elapsed(elapsed, tbuf, sizeof (tbuf));
	double secs = (double)elapsed / 1000000000.0;
	double rate = secs > 0 ? (double)processed / secs : 0;
	(void) fprintf(stderr,
	    "done: %llu files, %llu checksummed, %llu cached,"
	    " %llu errors in %s (%.1f files/s)\n",
	    (u_longlong_t)total_files,
	    (u_longlong_t)(processed - cached - errors),
	    (u_longlong_t)cached,
	    (u_longlong_t)errors,
	    tbuf, rate);

	close_objset(os, FTAG);
	pmap_destroy(&pmap);
	return (errors > 0 ? 1 : 0);
}

/* ------------------------------------------------------------------ */
/*  main                                                              */
/* ------------------------------------------------------------------ */

int
main(int argc, char **argv)
{
	zfssum_opts_t opts = default_opts;
	boolean_t update_mode = B_FALSE;
	boolean_t verbose = B_FALSE;
	char *spa_config_path_env;
	int c;

	enum { OPT_UPDATE = 256 };
	static struct option long_options[] = {
		{"algo",	required_argument,	NULL, 'a'},
		{"no-size",	no_argument,		NULL, 'S'},
		{"skip-holes",	no_argument,		NULL, 'Z'},
		{"verbose",	no_argument,		NULL, 'v'},
		{"update",	no_argument,		NULL, OPT_UPDATE},
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "a:SZv",
	    long_options, NULL)) != -1) {
		switch (c) {
		case 'a':
			opts.algo = parse_algo(optarg);
			if ((int)opts.algo == -1)
				fatal("unknown algorithm '%s'", optarg);
			break;
		case 'S':
			opts.include_size = B_FALSE;
			break;
		case 'Z':
			opts.fill_holes = B_FALSE;
			break;
		case 'v':
			verbose = B_TRUE;
			break;
		case OPT_UPDATE:
			update_mode = B_TRUE;
			break;
		default:
			usage();
		}
	}

	if (optind >= argc)
		usage();

	const char *dataset = argv[optind++];

	char mnt_buf[PATH_MAX];
	const char *mountpoint;
	if (optind < argc) {
		mountpoint = argv[optind];
	} else {
		if (resolve_mountpoint(dataset, mnt_buf,
		    sizeof (mnt_buf)) != 0)
			fatal("cannot find mountpoint for '%s'"
			    " (specify it explicitly)", dataset);
		mountpoint = mnt_buf;
	}

	spa_config_path_env = getenv("SPA_CONFIG_PATH");
	if (spa_config_path_env != NULL)
		spa_config_path = spa_config_path_env;

	zfs_btree_verify_intensity = 3;
#if defined(_LP64)
	zfs_arc_min = 2ULL << SPA_MAXBLOCKSHIFT;
#endif
	reference_tracking_enable = B_FALSE;
	spa_load_verify_dryrun = B_TRUE;
	spa_mode_readable_spacemaps = B_TRUE;

	kernel_init(SPA_MODE_READ);

	int ret = run_update(dataset, mountpoint, &opts,
	    update_mode, verbose);

	kernel_fini();
	return (ret);
}
