#!/usr/bin/env bash
# Fail before Cargo starts when its cache filesystem cannot hold a cold job.
set -euo pipefail

minimum_kib=2097152
minimum_inodes=10000
df_bin='df'

usage() {
  printf 'usage: assert-cargo-cache-capacity.sh [--minimum-kib KIB] [--minimum-inodes COUNT] [--df-bin PATH] CARGO_HOME\n' >&2
}

die() {
  printf '[cargo-cache] ERROR: %s\n' "$*" >&2
  exit 1
}

is_positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --minimum-kib)
      [[ $# -ge 2 ]] || {
        usage
        exit 2
      }
      minimum_kib="$2"
      shift 2
      ;;
    --minimum-inodes)
      [[ $# -ge 2 ]] || {
        usage
        exit 2
      }
      minimum_inodes="$2"
      shift 2
      ;;
    --df-bin)
      [[ $# -ge 2 ]] || {
        usage
        exit 2
      }
      df_bin="$2"
      shift 2
      ;;
    --*)
      usage
      exit 2
      ;;
    *)
      break
      ;;
  esac
done

[[ $# -eq 1 && -n "$1" ]] || {
  usage
  exit 2
}
is_positive_integer "$minimum_kib" || die "minimum KiB must be a positive integer, got: $minimum_kib"
is_positive_integer "$minimum_inodes" || die "minimum inode count must be a positive integer, got: $minimum_inodes"
if [[ "$df_bin" != */* ]]; then
  df_bin="$(command -v "$df_bin" || true)"
fi
[[ -n "$df_bin" && -x "$df_bin" ]] || die "df executable is unavailable"

cargo_home="$1"
mkdir -p "$cargo_home"

available_kib="$("$df_bin" -Pk "$cargo_home" | awk 'END { print $4 }')"
available_inodes="$("$df_bin" -Pi "$cargo_home" | awk 'END { print $4 }')"
[[ "$available_kib" =~ ^[0-9]+$ ]] || die "unable to read available KiB for $cargo_home"
[[ "$available_inodes" =~ ^[0-9]+$ ]] || die "unable to read available inodes for $cargo_home"

if (( available_kib < minimum_kib )); then
  die "Cargo cache filesystem for $cargo_home has ${available_kib} KiB available; at least ${minimum_kib} KiB is required"
fi
if (( available_inodes > 0 && available_inodes < minimum_inodes )); then
  die "Cargo cache filesystem for $cargo_home has ${available_inodes} inodes available; at least ${minimum_inodes} are required"
fi

if (( available_inodes == 0 )); then
  inode_status='inode accounting unavailable'
else
  inode_status="${available_inodes} inodes available"
fi
printf '[cargo-cache] capacity: OK (%s KiB available, %s at %s)\n' \
  "$available_kib" "$inode_status" "$cargo_home"
