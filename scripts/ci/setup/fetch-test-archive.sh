#!/usr/bin/env bash
# Compile once (infra#1632): fetch the test archive the build job reported
# from the archive store, and keep it only when its bytes hash to that
# SHA-256. The store is content-addressed, but this check is the boundary: a
# test job runs nothing it did not verify itself.
#
# Usage: fetch-test-archive.sh [--or-build] SHA256 FILE
# ARCHIVE_STORE_URL names the store.
#
# With --or-build, a job that can still build its tests itself treats an
# archive it cannot get (no digest reported, no store, or a store that no
# longer holds it) as a miss: it warns, writes ready=false to GITHUB_OUTPUT
# and succeeds, and the job builds in place as it did before compile once. A
# miss costs time, never a red run. An archive whose bytes do not hash to the
# digest always fails. A fetched and verified archive writes ready=true.
set -euo pipefail

die() {
  echo "fetch-test-archive: $*" >&2
  exit 2
}

or_build=false
if [ "${1:-}" = --or-build ]; then
  or_build=true
  shift
fi

ready() {
  [ -z "${GITHUB_OUTPUT:-}" ] || echo "ready=$1" >> "$GITHUB_OUTPUT"
}

miss() {
  [ "$or_build" = true ] || die "$*; rerun the build job"
  echo "::warning::fetch-test-archive: $*; this job builds its tests itself"
  ready false
  exit 0
}

[ "$#" -eq 2 ] || die 'usage: fetch-test-archive.sh [--or-build] SHA256 FILE'
digest="$1" file="$2"
if [ -z "$digest" ] && [ "$or_build" = true ]; then
  # Nothing was built for this run (a main push, or no Rust compile).
  echo 'fetch-test-archive: no archive was built for this run; this job builds its tests itself'
  ready false
  exit 0
fi
[[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die 'the build job reported no SHA-256 archive digest'
[ -n "${ARCHIVE_STORE_URL:-}" ] || miss 'no archive store is configured'
mkdir -p "$(dirname "$file")"
rm -f -- "$file" "$file.partial"
started=$SECONDS
curl -fsS --retry 3 --retry-connrefused --connect-timeout 10 \
  -o "$file.partial" "$ARCHIVE_STORE_URL/v1/archives/$digest" || {
    rm -f -- "$file.partial"
    miss "the store has no archive $digest (evicted or never published)"
  }
actual="$(sha256sum "$file.partial" | cut -d' ' -f1)"
[ "$actual" = "$digest" ] || { rm -f -- "$file.partial"; die "the fetched archive hashes to $actual, not $digest"; }
mv "$file.partial" "$file"
echo "fetch-test-archive: $digest ($(stat -c %s "$file") bytes) fetched and verified in $((SECONDS - started)) s"
ready true
