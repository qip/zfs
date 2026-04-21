# zfssum System Design

## 1. Overview

zfssum is a suite of tools that compute file fingerprints from ZFS block
pointer checksums without reading file data.  The suite has four components:

| Component | Binary | Source | Role |
|-----------|--------|--------|------|
| **zfssum** | `zfssum` | `cmd/zfssum.c` | CLI client — queries one or more files. |
| **zfssum-server** | `zfssum-server` | `cmd/zfssum_server.c` | Persistent daemon — keeps the pool open, serves requests over a Unix socket. |
| **zfssum-update** | `zfssum-update` | `cmd/zfssum_update.c` | Batch updater — computes checksums for every file in a dataset and writes them as xattrs. |
| **zfssum.sh** | _(shell script)_ | `cmd/zfssum.sh` | User-facing wrapper — resolves absolute paths, checks xattr cache, auto-starts the server. |

All three C binaries link against `libzpool`, `libzfs_core`, and `libnvpair`.
They operate in userspace via `kernel_init(SPA_MODE_READ)` and never modify
pool state.

## 2. Architecture

```
  ┌──────────────────┐
  │   zfssum.sh      │  shell wrapper: resolves paths, checks xattr cache
  │  (cmd/zfssum.sh) │  auto-starts zfssum-server if needed
  └────────┬─────────┘
           │ invokes
           v
  ┌──────────────────┐       Unix socket        ┌───────────────────────┐
  │     zfssum       │ ─────────────────────────>│   zfssum-server       │
  │  (cmd/zfssum.c)  │   dataset\tpath\topts\n   │  (cmd/zfssum_server.c)│
  │                  │ <─────────────────────────│                       │
  │  -l: local mode  │   OK <hex>\n / ERR …\n   │  multi-threaded,      │
  └──────────────────┘                           │  caches objset/SA     │
                                                 └───────────────────────┘

  ┌──────────────────────┐
  │   zfssum-update       │  batch: walks entire dataset, writes xattrs
  │ (cmd/zfssum_update.c) │  Phase 1: ZAP dir walk → path map
  │                       │  Phase 2: dmu_object_next → checksum + lsetxattr
  └───────────────────────┘
```

### Data flow

1. **zfssum.sh** receives absolute file paths from the user.
2. It checks `user.zfssum.meta` / `user.zfssum.checksum` xattrs for a
   cache hit (algorithm + mtime + size must match).
3. On cache miss it resolves the file to `dataset + relpath` via the
   mount table, ensures zfssum-server is running, and calls `zfssum`.
4. **zfssum** (server mode) sends `dataset\trelpath\topts\n` to the
   server and reads back `OK <hex>\n`.
5. **zfssum** (local mode, `-l`) calls `kernel_init`, opens the objset
   directly, walks the block tree, and prints the digest.
6. **zfssum-update** is a standalone batch tool that runs both the DMU
   path resolution and checksum computation internally, then writes
   results as xattrs via the VFS (`lsetxattr`).

## 3. Hash Algorithm Abstraction

All three C files share an identical set of types and functions:

```c
typedef enum { HASH_SHA256, HASH_SHA512, HASH_BLAKE3, HASH_BP } hash_algo_t;

typedef struct {
    hash_algo_t algo;
    union { SHA2_CTX sha2; BLAKE3_CTX blake3; };
    unsigned digest_len;
} hash_ctx_t;

typedef struct {
    hash_algo_t algo;
    boolean_t include_size;
    boolean_t fill_holes;
} zfssum_opts_t;
```

| Function | Purpose |
|----------|---------|
| `hash_init` | Initialise the appropriate context for the chosen algorithm. |
| `hash_update` | Feed data into the running context. |
| `hash_final` | Finalize and produce the digest. |
| `parse_algo` | Map a string (`"blake3"`, `"sha256"`, …) to `hash_algo_t`. |
| `opts_to_str` | Serialize `zfssum_opts_t` to the wire format `blake3,size,holefill`. |

Default options: `HASH_BLAKE3`, `include_size = true`, `fill_holes = true`.

### `bp` mode (HASH_BP)

A fast path that avoids walking the full block tree:

- **Single active root BP, non-embedded**: returns `blk_cksum` verbatim
  (32 bytes / `sizeof(zio_cksum_t)`).
- **Multiple active BPs or embedded**: BLAKE3-combines all checksums /
  payload words into a single 256-bit digest.
- `-S` and `-Z` are ignored.

## 4. Block Pointer Tree Walk

The core algorithm (`visit_indirect`) recursively descends the block pointer
tree from the dnode's root block pointers to level-0 leaf BPs:

```
visit_indirect(spa, dnp, bp, zb, ctx, fill_holes):
    if BP birth == 0 (hole):
        if level-0 and fill_holes: hash 32 zero bytes
        return
    if level-0:
        if embedded: hash payload words
        else: hash blk_cksum (32 bytes)
        return
    if level > 0 and not hole:
        arc_read the indirect block
        for each child BP:
            recurse with level-1
```

Indirect blocks are read via `arc_read` (async priority, `ARC_FLAG_WAIT`).
The ARC caches them so repeated walks hit memory.

For `dump_file_hash`, before walking the tree:
1. If `include_size`: hash the 8-byte `ZPL_SIZE` value.
2. Walk from `dn_blkptr[0..dn_nblkptr-1]` at `dn_nlevels - 1`.

## 5. Client-Server Protocol

Unix stream socket, default path `/var/run/zfssum.sock`.

### Request (one per line)

```
<dataset>\t<path>[\t<opts>]\n
```

`<opts>` is a comma-separated token string parsed by `parse_opts()`:

| Token | Meaning |
|-------|---------|
| `blake3`, `sha256`, `sha512`, `bp` | Algorithm. |
| `size` / `nosize` | Include file size in hash. |
| `holefill` / `skipholes` | Hole handling. |

Default when absent: `blake3,size,holefill`.

### Response

```
OK <hex-digest>\n
ERR <message>\n
```

### Pipelining

The client (`zfssum` server mode) pipelines up to `PIPELINE_DEPTH` (128)
requests before draining responses.  This hides per-request round-trip
latency on the Unix socket.

### Server architecture

- `nworkers` threads (default 4), each calling `accept()` on the
  shared listener fd.
- Each worker caches one `objset_t *` (keyed by dataset name), the
  `sa_attr_type_t` table, and the root object number.
- Dataset switches within a connection close and reopen the objset.
- `-v` prints per-request timing (resolve + hash) to stderr.

## 6. zfssum-update Internals

### Phase 1: Path Map Construction

`build_path_map_r` performs a two-pass ZAP-level directory traversal:

1. **Pass 1**: enumerate entries. Insert regular files (`DT_REG`) into
   the path map hash table. Issue `dmu_prefetch` for every subdirectory
   ZAP object.
2. **Pass 2**: re-iterate (ZAPs are ARC-hot from prefetch) and recurse
   into subdirectories depth-first.

This prefetch-then-recurse pattern keeps sibling ZAP blocks loading in
parallel while the first child is being traversed.

### Path Map Hash Table

Open-addressing with linear probing, 70% load factor threshold:

```c
typedef struct {
    uint64_t obj;       // 0 = empty slot
    char *path;
} pmap_entry_t;

typedef struct {
    pmap_entry_t *entries;
    size_t cap;         // always power of 2
    size_t count;
} path_map_t;
```

Hash function: two-round multiply-xorshift on the object number.

### Phase 2: Sequential Object Iteration

Iterates all objects via `dmu_object_next(os, &object, B_FALSE, 0)`.
For each object in the path map:

1. Read `ZPL_MODE`, `ZPL_SIZE`, `ZPL_MTIME` via `sa_bulk_lookup`.
2. Skip non-regular files (`!S_ISREG(mode)`).
3. If `--update` and `check_sa_cache()` matches → skip (cached).
4. `compute_checksum()` → `dump_file_hash` / `dump_file_bp_hash`.
5. Write `user.zfssum.checksum` and `user.zfssum.meta` via
   `lsetxattr(mountpoint/relpath, …)`.

Sequential object-number order maximizes ARC hit rates because dnode
blocks contain ~32 adjacent dnodes.

### xattr Cache Format

Two xattrs per file:

| xattr | Content | Example |
|-------|---------|---------|
| `user.zfssum.checksum` | Hex-encoded digest. | `a1b2c3d4…` |
| `user.zfssum.meta` | `alg=<opts_str>;mtime=<sec>.<nsec>;size=<bytes>` | `alg=blake3,size,holefill;mtime=1712345678.123456789;size=12345` |

`check_sa_cache()` reads the `ZPL_DXATTR` SA attribute (packed nvlist),
extracts `user.zfssum.meta`, and compares algorithm + mtime + size. This
avoids a VFS round-trip for the cache check. Only works with
`xattr=sa` (the default); `xattr=dir` always reports a cache miss.

## 7. zfssum.sh Wrapper

Shell script that provides the easiest user interface:

1. Parses ZFS mount table from `/proc/self/mounts` once at startup.
2. For each file argument:
   - Resolves to absolute path via `realpath`.
   - Checks `user.zfssum.meta` / `user.zfssum.checksum` xattrs
     (via `getfattr`) against current `stat` mtime and size.
   - On cache hit → prints cached checksum immediately.
   - On cache miss → finds the ZFS dataset via longest-prefix mount
     match, ensures zfssum-server is running (lazy start), and
     invokes `zfssum -s $SOCKET $dataset $relpath`.
3. Cleans up: kills a self-started server on `EXIT` trap.

## 8. Build System

Defined in `cmd/Makefile.am`:

| Target | Sources | Extra link flags |
|--------|---------|------------------|
| `zfssum` | `cmd/zfssum.c` | `libzpool libnvpair libzfs_core` |
| `zfssum-server` | `cmd/zfssum_server.c` | `libzpool libnvpair libzfs_core` |
| `zfssum-update` | `cmd/zfssum_update.c` | `libzpool libnvpair libzfs_core` |

All three use `$(LIBZPOOL_CPPFLAGS)` and are installed to `sbin`.
`zfssum.sh` is a standalone shell script (not installed via autotools).

## 9. Man Pages

| Page | Source |
|------|--------|
| `zfssum(8)` | `man/man8/zfssum.8` — covers both `zfssum` and `zfssum-server`. |
| `zfssum-update(8)` | `man/man8/zfssum-update.8` — covers the batch updater. |

## 10. Limitations and Caveats

- Digests depend on pool storage properties (checksum algorithm, record
  size, compression). Comparisons are valid only within datasets sharing
  the same configuration.
- Embedded BPs hash only payload words (14 of 16 uint64 words), excluding
  `blk_prop` and `blk_birth_word[1]` so digests survive `zfs send | recv`.
- `bp` mode root checksum may change after send/recv for multi-level files
  because it covers DVAs and birth TXGs.
- Encrypted datasets are not supported (SA attributes unreadable from
  userspace).
- `--update` cache check in `zfssum-update` requires `xattr=sa`.
