#!/usr/bin/env bash
# place-build-source.sh DIGEST DIR: a test job runs a pull request's archives
# against the merged source the build compiled, not its own checkout of the
# head (#5146). The tests read repository files at runtime (goldens,
# deployment YAML, askpass.sh's bytes against its compiled copy, seed SQL,
# scripts) and run from each package's folder, and a crate main added after
# the head's base exists only in the merged tree, so the build path holds the
# merged source (the survey on #5146).
#
# Fetches the build's source archive (source_sha256) by its digest, verified
# as every archive is (fetch-test-archive.sh), into DIR, then makes DIR a
# one-commit repository with merge-identity.sh's identity, since some tests
# list files with git. Its tree must be the tree selection merged
# (MERGED_TREE); the commit's parents differ from the build's merge commit, so
# only the tree is compared. Writes BUILD_SOURCE_DIR=DIR to GITHUB_ENV, which
# the test runners copy to the build path instead of the checkout.
#
# MERGE_ONTO, MERGED_TREE and HEAD_SHA come from selection; ARCHIVE_STORE_URL
# names the store. A missing archive fails: running the merged archives
# against the head's files would test neither tree.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
die() { echo "::error::place-build-source: $*" >&2; exit 1; }

[ "$#" -eq 2 ] || die 'usage: place-build-source.sh DIGEST DIR'
digest="$1" dir="$2"
[[ "$digest" =~ ^[0-9a-f]{64}$ ]] ||
  die 'the build reported no source archive for this merge build; rerun Build test archives'
for name in MERGE_ONTO MERGED_TREE HEAD_SHA; do
  [[ "${!name:-}" =~ ^[0-9a-f]{40}$ ]] || die "$name must be a full commit or tree ID"
done

"$ROOT/scripts/ci/setup/fetch-test-archive.sh" --extract "$digest" "$dir"

# shellcheck source=scripts/ci/setup/merge-identity.sh
source "$ROOT/scripts/ci/setup/merge-identity.sh"
ci_merge_commit_env "$HEAD_SHA" "$MERGE_ONTO"
git -C "$dir" init -q
# --force: the archive holds only tracked files, some of which .gitignore
# names (a tracked file stays tracked whatever .gitignore says).
git -C "$dir" add --all --force
git -C "$dir" -c commit.gpgSign=false commit -q --no-verify -m "$CI_MERGE_MESSAGE"
tree="$(git -C "$dir" rev-parse 'HEAD^{tree}')"
[ "$tree" = "$MERGED_TREE" ] ||
  die "the source archive gives tree $tree, not the merged tree $MERGED_TREE selection checked"
echo "place-build-source: the merged tree ${tree:0:12} is in $dir"
echo "BUILD_SOURCE_DIR=$dir" >> "${GITHUB_ENV:?GITHUB_ENV is required}"
