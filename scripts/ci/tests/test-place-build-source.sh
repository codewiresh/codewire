#!/usr/bin/env bash
# place-build-source.sh puts a pull request's merged source, as the build
# published it, in a test job's hands (#5146): fetched and verified by its
# digest, made a one-commit repository with the merge identity, and handed on
# only when its tree is the one selection merged. A wrong tree, a missing
# archive or a missing digest fails, and hands nothing on.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="$ROOT/scripts/ci/setup/place-build-source.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/test-place-build-source.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
fail() { echo "test-place-build-source: $*" >&2; exit 1; }
unset GITHUB_OUTPUT

# A merged tree: an executable, a nested file, and a tracked file .gitignore names.
repo="$work/repo"
git init -q "$repo"
mkdir -p "$repo/crates/new/src" "$repo/scripts"
printf 'fn main() {}\n' > "$repo/crates/new/src/main.rs"
printf '#!/bin/sh\necho ok\n' > "$repo/scripts/run.sh"
chmod 0755 "$repo/scripts/run.sh"
printf 'ignored.txt\n' > "$repo/.gitignore"
printf 'tracked anyway\n' > "$repo/ignored.txt"
git -C "$repo" add --all --force
git -C "$repo" -c user.name=t -c user.email=t@t.invalid -c commit.gpgSign=false commit -q -m tree
tree="$(git -C "$repo" rev-parse 'HEAD^{tree}')"

mkdir -p "$work/store/v1/archives"
# The archive as build-once.sh publishes it.
# shellcheck source=scripts/ci/setup/merge-identity.sh
source "$ROOT/scripts/ci/setup/merge-identity.sh"
ci_source_archive "$repo" "$work/source.tar.zst"
digest="$(sha256sum "$work/source.tar.zst" | cut -d' ' -f1)"
cp "$work/source.tar.zst" "$work/store/v1/archives/$digest"

head_sha="$(printf 'h%.0s' {1..40} | tr h a)"
tip_sha="$(printf 'h%.0s' {1..40} | tr h b)"
place() {
  # place DIGEST DIR MERGED_TREE: the script's status; its env file is $work/env.
  : > "$work/env"
  GITHUB_ENV="$work/env" ARCHIVE_STORE_URL="file://$work/store" \
    MERGE_ONTO="$tip_sha" MERGED_TREE="$3" HEAD_SHA="$head_sha" \
    "$SCRIPT" "$1" "$2" > "$work/log" 2>&1
}

place "$digest" "$work/placed" "$tree" || fail "the merged source was not placed: $(cat "$work/log")"
grep -qx "BUILD_SOURCE_DIR=$work/placed" "$work/env" || fail 'BUILD_SOURCE_DIR was not handed on'
[ "$(git -C "$work/placed" rev-parse 'HEAD^{tree}')" = "$tree" ] || fail 'the placed repository has another tree'
[ "$(git -C "$work/placed" log -1 --format='%an <%ae> %at %cn <%ce> %ct')" = \
  'Codewire CI merge <ci-merge@codewire.invalid> 946684800 Codewire CI merge <ci-merge@codewire.invalid> 946684800' ] ||
  fail 'the placed commit does not carry merge-identity.sh'"'"'s identity'
[ "$(git -C "$work/placed" log -1 --format=%s)" = "ci: pull request head $head_sha merged onto $tip_sha" ] ||
  fail 'the placed commit does not carry the merge message'
[ -x "$work/placed/scripts/run.sh" ] || fail 'the executable lost its mode'
[ -f "$work/placed/ignored.txt" ] || fail 'a tracked file .gitignore names was dropped'
# A checkout's modes: nothing the archive gave is group- or world-writable,
# which the platform runtime's tests refuse (run 58615).
writable="$(find "$work/placed" -path "$work/placed/.git" -prune -o -perm /022 -print)"
[ -z "$writable" ] || fail "the placed source is group- or world-writable: $writable"
# The same inputs give the same commit wherever they are placed.
place "$digest" "$work/again" "$tree" || fail "a second placement failed: $(cat "$work/log")"
[ "$(git -C "$work/again" rev-parse HEAD)" = "$(git -C "$work/placed" rev-parse HEAD)" ] ||
  fail 'two placements of the same source gave different commits'

# Refused, handing nothing on: another tree, an archive the store lacks, no digest.
other="$(printf 't%.0s' {1..40} | tr t c)"
if place "$digest" "$work/wrong-tree" "$other"; then fail 'a source with another tree was placed'; fi
grep -q "not the merged tree $other" "$work/log" || fail "a wrong tree gave no reason: $(cat "$work/log")"
[ ! -s "$work/env" ] || fail 'a wrong tree handed BUILD_SOURCE_DIR on'
missing="$(printf 'm%.0s' {1..64} | tr m d)"
if place "$missing" "$work/missing" "$tree"; then fail 'a source the store lacks was placed'; fi
[ ! -s "$work/env" ] || fail 'a missing archive handed BUILD_SOURCE_DIR on'
if place '' "$work/empty" "$tree"; then fail 'a merge build without a source digest was placed'; fi
grep -q 'reported no source archive' "$work/log" || fail "a missing digest gave no reason: $(cat "$work/log")"

echo 'test-place-build-source: the merged source is fetched by digest, made one commit with the merge identity and handed on only with the merged tree; another tree, a missing archive or no digest is refused'
