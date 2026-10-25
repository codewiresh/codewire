#!/usr/bin/env bash
# Compile once (infra#1632): fetch the test archive the build job reported
# from the archive store, and keep it only when its bytes hash to that
# SHA-256. The store is content-addressed, but this check is the boundary: a
# test job runs nothing it did not verify itself.
#
# Usage: fetch-test-archive.sh SHA256 FILE
# ARCHIVE_STORE_URL names the store.
set -euo pipefail

die() {
  echo "fetch-test-archive: $*" >&2
  exit 2
}

[ "$#" -eq 2 ] || die 'usage: fetch-test-archive.sh SHA256 FILE'
digest="$1" file="$2"
[[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die 'the build job reported no SHA-256 archive digest'
: "${ARCHIVE_STORE_URL:?ARCHIVE_STORE_URL is required}"
mkdir -p "$(dirname "$file")"
rm -f -- "$file" "$file.partial"
started=$SECONDS
curl -fsS --retry 3 --retry-connrefused --connect-timeout 10 \
  -o "$file.partial" "$ARCHIVE_STORE_URL/v1/archives/$digest" ||
  die "the store has no archive $digest (evicted or never published); rerun the build job"
actual="$(sha256sum "$file.partial" | cut -d' ' -f1)"
[ "$actual" = "$digest" ] || { rm -f -- "$file.partial"; die "the fetched archive hashes to $actual, not $digest"; }
mv "$file.partial" "$file"
echo "fetch-test-archive: $digest ($(stat -c %s "$file") bytes) fetched and verified in $((SECONDS - started)) s"
