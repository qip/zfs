# zfssum

Generate file fingerprints from ZFS block pointer checksums.

## Overview

`zfssum` generates a content fingerprint for files stored on a ZFS dataset by
hashing the on-disk block pointer checksums rather than reading actual file
data. This makes it significantly faster than traditional tools such as
`sha256sum(1)` for change detection, especially on large files.

ZFS stores a checksum for every data block in its block pointer tree. `zfssum`
walks the tree for each named file, collects the leaf-level block checksums,
and hashes them together into a single digest. Because the leaf checksums
depend on file content (via the pool's checksum algorithm), any change to the
file data produces a different `zfssum` output.

The suite consists of four components:

| Component | Description |
|-----------|-------------|
| `zfssum` | CLI client that queries one or more files. |
| `zfssum-server` | Persistent daemon that keeps the pool open and serves requests over a Unix socket. |
| `zfssum-update` | Batch tool that computes checksums for every file in a dataset and stores them as xattrs. |
| `zfssum.sh` | Shell wrapper that resolves absolute paths, checks the xattr cache, and auto-starts the server. |

## Synopsis

```
zfssum      [-l] [-s socket] [-a algo] [-S] [-Z] dataset path [path ...]
zfssum-server [-d] [-v] [-j jobs] [-s socket] [-m mode] [-u uid] [-g gid]
zfssum-update [-a algo] [-S] [-Z] [-v] [--update] dataset [mountpoint]
zfssum.sh   [-v] [-a algo] [-S] [-Z] [-s socket] [--] file [file ...]
```

## Quick Start

The simplest way to use zfssum is through the shell wrapper:

```
# Fingerprint a single file (auto-starts server if needed)
zfssum.sh /tank/data/myfile

# Multiple files at once
zfssum.sh /tank/data/file1 /tank/data/file2

# Pre-populate xattr cache for an entire dataset
zfssum-update tank/data

# Subsequent calls hit the xattr cache and return instantly
zfssum.sh /tank/data/myfile
```

## zfssum

By default, queries a running `zfssum-server` daemon via Unix socket. With
`-l`, operates directly against the pool (slow due to `kernel_init` /
`spa_open` overhead per invocation).

### Options

| Short | Long | Argument | Description |
|-------|------|----------|-------------|
| `-a` | `--algo` | *algo* | Hash algorithm (see below). Default: `blake3`. |
| `-l` | `--local` | | Operate directly via libzpool instead of connecting to `zfssum-server`. |
| `-s` | `--socket` | *path* | Unix domain socket path. Default: `/var/run/zfssum.sock`. |
| `-S` | `--no-size` | | Do not include file size in the hash. |
| `-Z` | `--skip-holes` | | Skip holes instead of filling zeros. |

### Hash Algorithms (`-a`)

| Value | Description |
|-------|-------------|
| `blake3` | BLAKE3, 256-bit digest (default). |
| `sha256` | SHA-256, 256-bit digest. |
| `sha512` | SHA-512, 512-bit digest. |
| `bp` | Root block pointer mode -- outputs the `blk_cksum` from the dnode's root block pointer directly, without walking the block tree. Fastest mode, but the hash may change after `zfs send | recv` for multi-level files because the root checksum covers indirect block metadata (DVAs, birth TXGs). When the dnode has multiple root BPs or the root BP is embedded, the checksums are combined with BLAKE3. `-S` and `-Z` are ignored in this mode. |

### File Size in Hash

By default the file size (from the SA attribute `ZPL_SIZE`) is fed into the
hash context before the block checksums. This prevents theoretical collisions
between files of different sizes whose block checksums happen to match. Use
`-S` / `--no-size` to disable.

### Hole Handling

By default, 32 zero bytes are fed into the hash for each level-0 hole block
pointer (`BP_GET_BIRTH() == 0`) so that sparse files with different hole
layouts produce different digests. With `-Z` / `--skip-holes`, holes are
silently skipped (the original behavior).

## zfssum-server

Persistent daemon that keeps the pool open across requests, eliminating the
per-invocation cost of `kernel_init` / `spa_open`. Multi-threaded (default: 4
worker threads), each caching the most recently used objset.

### Options

| Short | Long | Argument | Description |
|-------|------|----------|-------------|
| `-d` | `--daemon` | | Daemonize after creating the server socket. |
| `-j` | `--jobs` | *N* | Number of worker threads. Default: `4`. |
| `-v` | `--verbose` | | Print per-request timing (resolve + hash) to stderr. |
| `-s` | `--socket` | *path* | Unix domain socket path. Default: `/var/run/zfssum.sock`. |
| `-m` | `--mode` | *mode* | Socket permission mode in octal. Default: `0666`. |
| `-u` | `--uid` | *uid* | Set socket owner to this numeric UID. |
| `-g` | `--gid` | *gid* | Set socket group to this numeric GID. |

### Client-Server Protocol

`zfssum-server` listens on a Unix stream socket. Each client connection may
send multiple requests, one per line.

#### Request

```
<dataset>\t<path>[\t<opts>]\n
```

The optional third field *opts* is a comma-separated string of tokens:

| Token | Meaning |
|-------|---------|
| `blake3`, `sha256`, `sha512`, `bp` | Algorithm selection (default: `blake3`). |
| `size`, `nosize` | Include or exclude file size (default: `size`). |
| `holefill`, `skipholes` | Fill zeros for holes or skip (default: `holefill`). |

When the third field is absent the server uses `blake3,size,holefill`.

#### Response

```
OK <hex-digest>\n
ERR <message>\n
```

The client pipelines up to 128 requests before draining responses.

## zfssum-update

Batch tool that computes `zfssum` checksums for every regular file in a
dataset and stores the results as extended attributes on the mounted
filesystem. Useful for pre-populating the xattr cache so that subsequent
`zfssum.sh` calls return instantly.

### Options

| Short | Long | Argument | Description |
|-------|------|----------|-------------|
| `-a` | `--algo` | *algo* | Hash algorithm: `blake3` (default), `sha256`, `sha512`, `bp`. |
| `-S` | `--no-size` | | Do not include file size in the hash. |
| `-Z` | `--skip-holes` | | Skip holes instead of filling zeros. |
| `-v` | `--verbose` | | Print per-file hex digest and timing to stderr. |
| | `--update` | | Skip files whose xattr cache is still valid (mtime + size + algo match). |

### How It Works

The tool operates in two phases:

1. **ZAP directory walk**: the dataset's directory tree is traversed at
   the DMU level using ZAP cursor APIs, building an in-memory mapping
   from object number to relative path. No VFS transitions occur during
   this phase.

2. **Sequential object iteration**: all objects in the dataset are visited
   in object-number order via `dmu_object_next()`. For each regular file
   the block pointer checksum is computed and both xattrs are written via
   `lsetxattr(2)`. Sequential ordering maximizes ARC hit rates because
   dnode blocks contain ~32 adjacent dnodes.

### xattr Cache

Two xattrs are written per file:

| xattr | Content |
|-------|---------|
| `user.zfssum.checksum` | Hex-encoded digest. |
| `user.zfssum.meta` | `alg=<opts>;mtime=<sec>.<nsec>;size=<bytes>` |

With `--update`, before computing a checksum the tool reads the existing
`user.zfssum.meta` from the SA xattr nvlist (at the DMU level, no VFS
call). If the recorded algorithm, modification time, and file size all
match the current values, the file is skipped.

### Requirements

- The dataset must be mounted so xattrs can be written through VFS.
- `xattr=sa` (the default) is recommended. With `xattr=dir` the
  `--update` cache check always reports a miss.
- Encrypted datasets are not supported.

## zfssum.sh

Shell wrapper that provides the easiest user interface. It:

1. Resolves each file argument to an absolute path.
2. Checks the `user.zfssum.meta` and `user.zfssum.checksum` xattrs
   against the current file mtime and size. On cache hit, prints the
   cached checksum immediately.
3. On cache miss, finds the ZFS dataset by longest-prefix mount match.
4. Lazily starts `zfssum-server` if no server socket exists.
5. Calls `zfssum` with the resolved dataset and relative path.
6. On exit, kills a self-started server.

### Options

| Short | Argument | Description |
|-------|----------|-------------|
| `-v` | | Verbose: report each step to stderr. |
| `-a` | *algo* | Hash algorithm: `blake3` (default), `sha256`, `sha512`, `bp`. |
| `-S` | | Do not include file size in hash. |
| `-Z` | | Skip holes instead of filling zeros. |
| `-s` | *path* | Server socket path. Default: `/var/run/zfssum.sock`. |

### Dependencies

- `getfattr` (from `attr` package) for reading xattrs.
- `stat`, `realpath`, `cut` (standard coreutils).
- `zfssum` and `zfssum-server` binaries in `$PATH`.

## Caveats

The digest depends on the pool's storage configuration. The same logical file
content stored with different settings will produce different digests:

- **Checksum algorithm** (e.g., sha256 vs blake3) -- different algorithms
  produce different per-block checksums.
- **Record size** (e.g., `recordsize=128K` vs `1M`) -- different block
  boundaries yield a different set of checksums.
- **Compression** (e.g., lz4 vs zstd vs off) -- ZFS checksums are computed on
  post-compression data.

Digests are meaningful for comparison only within the same dataset or between
datasets with identical storage properties.

For embedded block pointers (very small files whose data is stored inside the
block pointer itself), only the 14 payload words are hashed; the metadata words
(`blk_prop`, `blk_birth_word[1]`) are excluded so that the digest remains
stable across `zfs send | recv`.

## Examples

Generate a fingerprint using the default algorithm (BLAKE3):

```
# zfssum tank/data path/to/file
a1b2c3d4...
```

Use SHA-512 in local mode without the server:

```
# zfssum -l -a sha512 tank/data myfile
e5f6a7b8...
```

Fast root block pointer hash for change detection:

```
# zfssum -a bp tank/data largefile
1234abcd...
```

Start the server as a daemon with group-writable socket:

```
# zfssum-server -d --mode 0660 --gid 1000
```

Pre-populate xattr cache for the entire dataset:

```
# zfssum-update tank/data
```

Incremental update after a few files have changed:

```
# zfssum-update --update tank/data
```

Use the wrapper for the simplest experience:

```
# zfssum.sh /tank/data/file1 /tank/data/file2
a1b2c3d4...
e5f6a7b8...
```
