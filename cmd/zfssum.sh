#!/bin/bash
#
# Wrapper for zfssum with xattr caching and automatic zfssum-server
# lifecycle management.  Resolves absolute file paths to ZFS
# dataset + relative path automatically.
#
# Usage: zfssum.sh [-v] [-a algo] [-S] [-Z] [-s socket] [--] file [file ...]

SOCKET="/var/run/zfssum.sock"
ALGO="blake3"
SIZE_OPT="size"
HOLES_OPT="holefill"
VERBOSE=0
ZFSSUM_ARGS=()
STARTED_SERVER=0
SERVER_PID=

usage() {
	cat >&2 <<-'EOF'
	usage: zfssum.sh [-v] [-a algo] [-S] [-Z] [-s socket] [--] file [file ...]

	  -v         verbose: report each step to stderr
	  -a ALGO    hash algorithm: blake3 (default), sha256, sha512, bp
	  -S         do NOT include file size in hash
	  -Z         skip holes instead of filling zeros
	  -s PATH    server socket (default: /var/run/zfssum.sock)
	EOF
	exit 1
}

vlog() { (( VERBOSE )) && printf '%s\n' "$*" >&2 || true; }

while getopts "a:s:SZvh" opt; do
	case "$opt" in
	a)	ALGO="$OPTARG"; ZFSSUM_ARGS+=(-a "$OPTARG") ;;
	s)	SOCKET="$OPTARG" ;;
	S)	SIZE_OPT="nosize";     ZFSSUM_ARGS+=(-S) ;;
	Z)	HOLES_OPT="skipholes"; ZFSSUM_ARGS+=(-Z) ;;
	v)	VERBOSE=1 ;;
	*)	usage ;;
	esac
done
shift $((OPTIND - 1))
[[ $# -gt 0 ]] || usage

OPTS_STR="${ALGO},${SIZE_OPT},${HOLES_OPT}"

# ------------------------------------------------------------------
#  ZFS mount table (parsed once)
# ------------------------------------------------------------------

declare -A MOUNT_TO_DS
while read -r dev mnt fstype _rest; do
	[[ "$fstype" == "zfs" ]] && MOUNT_TO_DS["$mnt"]="$dev"
done </proc/self/mounts
vlog "mount table: ${#MOUNT_TO_DS[@]} ZFS mount(s)"

# Longest-prefix match against cached mount table.
# Prints "dataset<space>mountpoint" or nothing.
find_zfs_mount() {
	local path=$1 best= best_len=0
	for mnt in "${!MOUNT_TO_DS[@]}"; do
		[[ "$path" == "$mnt"/* || "$path" == "$mnt" ]] || continue
		if (( ${#mnt} > best_len )); then
			best=$mnt
			best_len=${#mnt}
		fi
	done
	[[ -n "$best" ]] && printf '%s %s\n' "${MOUNT_TO_DS[$best]}" "$best"
}

# ------------------------------------------------------------------
#  Server lifecycle (lazy start)
# ------------------------------------------------------------------

ensure_server() {
	if [[ $STARTED_SERVER -eq 1 ]]; then
		return 0
	fi
	if [[ -S "$SOCKET" ]]; then
		vlog "server: already running at $SOCKET"
		return 0
	fi
	vlog "server: starting zfssum-server -s $SOCKET (pid will follow)"
	zfssum-server -s "$SOCKET" &
	SERVER_PID=$!
	STARTED_SERVER=1
	vlog "server: started pid $SERVER_PID, waiting for socket"
	local i
	for (( i = 0; i < 50; i++ )); do
		[[ -S "$SOCKET" ]] && { vlog "server: socket ready"; return 0; }
		sleep 0.1
	done
	echo "zfssum.sh: timeout waiting for zfssum-server socket" >&2
	exit 1
}

cleanup() {
	if [[ $STARTED_SERVER -eq 1 && -n "$SERVER_PID" ]]; then
		vlog "cleanup: killing server pid $SERVER_PID"
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
		rm -f "$SOCKET"
	fi
}
trap cleanup EXIT

# ------------------------------------------------------------------
#  Per-file processing
# ------------------------------------------------------------------

for file in "$@"; do
	abspath=$(realpath -- "$file" 2>/dev/null) || {
		vlog "$file: realpath failed, skipping"
		echo; continue
	}
	vlog "$file: abspath=$abspath"

	# --- try xattr cache first ---
	meta=$(getfattr -n user.zfssum.meta --only-values \
	    -- "$abspath" 2>/dev/null) || meta=
	if [[ -n "$meta" ]]; then
		vlog "$file: xattr meta=$meta"
		stat_out=$(stat -c '%Y %s %y' -- "$abspath" 2>/dev/null) || {
			vlog "$file: stat failed, skipping"
			echo; continue
		}
		mtime_sec=${stat_out%% *}
		rest=${stat_out#* }
		fsize=${rest%% *}
		mtime_nsec=$(printf '%s' "$stat_out" |
		    cut -d. -f2 | cut -d' ' -f1)

		expected="alg=${OPTS_STR};mtime=${mtime_sec}.${mtime_nsec};size=${fsize}"
		if [[ "$meta" == "$expected" ]]; then
			cksum=$(getfattr -n user.zfssum.checksum --only-values \
			    -- "$abspath" 2>/dev/null) || cksum=
			if [[ -n "$cksum" ]]; then
				vlog "$file: cache hit"
				printf '%s\n' "$cksum"
				continue
			fi
			vlog "$file: meta matches but checksum xattr missing"
		else
			vlog "$file: cache stale (expected $expected)"
		fi
	else
		vlog "$file: no xattr meta"
	fi

	# --- cache miss / stale -- check if file is on ZFS ---
	zfs_info=$(find_zfs_mount "$abspath")
	if [[ -z "$zfs_info" ]]; then
		vlog "$file: not on ZFS"
		echo
		continue
	fi
	dataset=${zfs_info%% *}
	mountpoint=${zfs_info#* }

	if [[ "$abspath" == "$mountpoint" ]]; then
		relpath=/
	else
		relpath=${abspath#"$mountpoint"/}
	fi
	vlog "$file: dataset=$dataset relpath=$relpath"

	ensure_server

	vlog "$file: running zfssum"
	zfssum -s "$SOCKET" ${ZFSSUM_ARGS[@]+"${ZFSSUM_ARGS[@]}"} \
	    "$dataset" "$relpath" || echo
done
