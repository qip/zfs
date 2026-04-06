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

`zfssum-server` is a persistent daemon that keeps the pool open across
requests, eliminating the per-invocation cost of `objset.open`. `zfssum`
connects to a running `zfssum-server` by default. Use `-l` to operate directly
against the pool without the server (slower per invocation).

## Synopsis

```
zfssum [-l] [-s socket] [-a algo] [-S] [-Z] dataset path [path ...]
zfssum-server [-d] [-s socket] [-m mode] [-u uid] [-g gid]
```

## zfssum Options

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

## zfssum-server Options

| Short | Long | Argument | Description |
|-------|------|----------|-------------|
| `-d` | `--daemon` | | Daemonize after creating the server socket. |
| `-s` | `--socket` | *path* | Unix domain socket path. Default: `/var/run/zfssum.sock`. |
| `-m` | `--mode` | *mode* | Socket permission mode in octal. Default: `0666`. |
| `-u` | `--uid` | *uid* | Set socket owner to this numeric UID. |
| `-g` | `--gid` | *gid* | Set socket group to this numeric GID. |

## Client-Server Protocol

`zfssum-server` listens on a Unix stream socket. Each client connection may
send multiple requests, one per line.

### Request

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

### Response

```
OK <hex-digest>\n
ERR <message>\n
```

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
