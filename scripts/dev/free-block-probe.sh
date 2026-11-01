#!/bin/sh
# Free-block probe (#3718): leave copies of a synthetic token only in freed
# blocks of a mounted filesystem, then scan a raw device or image for them.
# It proves whether a disk's free blocks are readable, and that a clearing
# removed them. POSIX sh with coreutils and grep, so it runs in any Debian
# image, including a Pod with a Block volume.
#
#   free-block-probe.sh plant DIR MARKERS
#   free-block-probe.sh scan DISK MARKERS
#
# plant makes the directory MARKERS, which must not exist and must lie outside
# DIR, holding two new random markers, `token` and `control`. In DIR it keeps
# `free-block-probe-control`, which holds the control marker, and writes the
# token in four generations: a file, then three rewrites under a new name
# each renamed over the last, as a sign-in store rewrites its file. It then
# removes the token file and syncs, so every copy of the token lies in freed
# blocks. The markers never appear on a command line, which `cw run` records:
# they travel in MARKERS.
#
# scan reads DISK (a block device or an image) once and prints `token N` and
# `control N`, the copies of each it found. Exit status:
#   0   no token, and the control found: no freed copy is readable;
#   1   a token found: freed copies are readable;
#   2   no control found: the scan cannot vouch for anything (the wrong disk,
#       or one that is not plain), whatever it says of the token;
#   64  usage, or a refused argument.
set -eu

usage() {
  echo "usage: $0 plant DIR MARKERS | scan DISK MARKERS" >&2
  exit 64
}

refuse() {
  echo "free-block-probe: $1" >&2
  exit 64
}

marker() {
  printf 'cw-free-block-probe-%s-%s\n' "$1" \
    "$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')"
}

# The token file's body for one generation: a few blocks' worth of a
# sign-in-shaped line.
token_body() {
  i=0
  while [ "$i" -lt 1024 ]; do
    printf '{"generation":%s,"access_token":"%s"}\n' "$1" "$2"
    i=$((i + 1))
  done
}

plant() {
  dir=$1
  markers=$2
  [ -d "$dir" ] || refuse "$dir is not a directory"
  [ ! -e "$markers" ] || refuse "$markers already exists"
  real_dir=$(realpath "$dir")
  real_parent=$(realpath "$(dirname "$markers")")
  case "$real_parent/" in
    "$real_dir"/*) refuse "$markers lies inside $dir, which the scan reads" ;;
  esac
  (umask 077 && mkdir "$markers")
  marker token >"$markers/token"
  marker control >"$markers/control"
  token=$(cat "$markers/token")
  control=$(cat "$markers/control")

  i=0
  while [ "$i" -lt 100 ]; do
    printf '%s\n' "$control"
    i=$((i + 1))
  done >"$dir/free-block-probe-control"
  token_body 0 "$token" >"$dir/free-block-probe-token"
  sync
  for generation in 1 2 3; do
    token_body "$generation" "$token" >"$dir/free-block-probe-token.new"
    sync
    mv -f "$dir/free-block-probe-token.new" "$dir/free-block-probe-token"
    sync
  done
  rm -f "$dir/free-block-probe-token"
  sync
  echo "planted: 4 generations of the token removed, the control kept in $dir/free-block-probe-control"
}

scan() {
  disk=$1
  markers=$2
  [ -r "$disk" ] || refuse "$disk is not readable"
  [ -s "$markers/token" ] && [ -s "$markers/control" ] ||
    refuse "$markers holds no markers"
  found=$(mktemp "${TMPDIR:-/tmp}/free-block-probe.XXXXXX")
  trap 'rm -f "$found"' EXIT
  # -z splits the disk at NUL bytes, which free space is full of, so no
  # "line" grows large. Each match is printed NUL-terminated.
  status=0
  cat "$markers/token" "$markers/control" |
    LC_ALL=C grep -a -z -o -F -f - "$disk" >"$found" || status=$?
  [ "$status" -le 1 ] || refuse "grep failed reading $disk (exit status $status)"
  tokens=$(tr '\000' '\n' <"$found" | grep -c -x -F -f "$markers/token" || true)
  controls=$(tr '\000' '\n' <"$found" | grep -c -x -F -f "$markers/control" || true)
  echo "token $tokens"
  echo "control $controls"
  if [ "$controls" -eq 0 ]; then
    exit 2
  elif [ "$tokens" -gt 0 ]; then
    exit 1
  fi
  exit 0
}

[ "$#" -eq 3 ] || usage
case "$1" in
  plant) plant "$2" "$3" ;;
  scan) scan "$2" "$3" ;;
  *) usage ;;
esac
