#!/usr/bin/env bash
# Compile once (infra#1632): fetch the test archive the build job reported
# from the archive store, and keep it only when its bytes hash to that
# SHA-256. The store is content-addressed, but this check is the boundary: a
# test job runs nothing it did not verify itself.
#
# Usage: fetch-test-archive.sh [--or-build] [--extract] SHA256 PATH
# ARCHIVE_STORE_URL names the store.
#
# With --extract, the archive is a zstd tar (a cargo-nextest archive) and PATH
# is a new folder: the download streams through the hash and into tar, so the
# fetch and the extraction overlap and the archive is never written to disk
# (infra#1534: 26 s of fetch, then 43 s of extraction, in main run 23934).
# The digest is still checked before anything reports ready: bytes that do not
# hash to it leave no folder behind and fail the job. A download that fails
# part way is fetched once more to a file and extracted from there.
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
extract=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --or-build) or_build=true ;;
    --extract) extract=true ;;
    *) break ;;
  esac
  shift
done

ready() {
  [ -z "${GITHUB_OUTPUT:-}" ] || echo "ready=$1" >> "$GITHUB_OUTPUT"
}

miss() {
  [ "$or_build" = true ] || die "$*; rerun the build job"
  echo "::warning::fetch-test-archive: $*; this job builds its tests itself"
  ready false
  exit 0
}

[ "$#" -eq 2 ] || die 'usage: fetch-test-archive.sh [--or-build] [--extract] SHA256 PATH'
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
rm -rf -- "$file" "$file.partial"
started=$SECONDS
url="$ARCHIVE_STORE_URL/v1/archives/$digest"

# extract_from SOURCE_COMMAND...: unpack the zstd tar the command writes into
# $file.partial, hashing the same bytes into $work/sha256. Prints the exit
# statuses of the source, tee, zstd and tar, then "hash" if hashing failed.
# Run it in a command substitution: its pipeline's failures are reported, not
# fatal.
extract_from() {
  set +e
  rm -rf -- "$file.partial" "$work/sha256" "$work/bytes"
  mkdir -p "$file.partial"
  mkfifo "$work/bytes"
  sha256sum < "$work/bytes" > "$work/sha256" &
  local hasher=$! status
  "$@" | tee "$work/bytes" | zstd -dcq | tar -x -p --no-same-owner -C "$file.partial"
  status="${PIPESTATUS[*]}"
  wait "$hasher" || status="$status hash"
  echo "$status"
}

if [ "$extract" = true ]; then
  work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/fetch-test-archive.XXXXXX")"
  trap 'rm -rf -- "$work"' EXIT
  # One streamed attempt: a retry could not take back the bytes already
  # unpacked, so a download that fails is fetched again to a file below.
  status="$(extract_from curl -fsS --connect-timeout 10 "$url")"
  read -r curl_status _ <<< "$status"
  if [ "$curl_status" != 0 ]; then
    echo "fetch-test-archive: the streamed download failed (curl $curl_status); fetching it to a file"
    curl -fsS --retry 3 --retry-connrefused --connect-timeout 10 -o "$work/archive" "$url" || {
      rm -rf -- "$file.partial"
      miss "the store has no archive $digest (evicted or never published)"
    }
    status="$(extract_from cat "$work/archive")"
  fi
  actual="$(cut -d' ' -f1 "$work/sha256" 2>/dev/null || true)"
  [ "$actual" = "$digest" ] || {
    rm -rf -- "$file.partial"
    die "the fetched archive hashes to ${actual:-nothing}, not $digest"
  }
  [ "$status" = '0 0 0 0' ] || {
    rm -rf -- "$file.partial"
    die "the verified archive did not unpack (source, tee, zstd, tar: $status)"
  }
  mv -- "$file.partial" "$file"
  echo "fetch-test-archive: $digest fetched, verified and extracted to $file in $((SECONDS - started)) s"
  ready true
  exit 0
fi

curl -fsS --retry 3 --retry-connrefused --connect-timeout 10 \
  -o "$file.partial" "$url" || {
    rm -f -- "$file.partial"
    miss "the store has no archive $digest (evicted or never published)"
  }
actual="$(sha256sum "$file.partial" | cut -d' ' -f1)"
[ "$actual" = "$digest" ] || { rm -f -- "$file.partial"; die "the fetched archive hashes to $actual, not $digest"; }
mv "$file.partial" "$file"
echo "fetch-test-archive: $digest ($(stat -c %s "$file") bytes) fetched and verified in $((SECONDS - started)) s"
ready true
