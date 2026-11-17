#!/usr/bin/env bash
# merge-identity.sh: the fixed identity, date and message of the commit CI
# makes when it merges a pull request onto its base branch's tip (#5146). The
# build runner makes it (build-once.sh prepare) and the test jobs remake it
# over the source the build published, so the same head and tip always give
# the same commit, wherever it is made. Source it; then call
# ci_merge_commit_env HEAD TIP to export the identity for one merge, and make
# the commit with `git -c commit.gpgSign=false merge --no-ff --no-edit -m
# "$CI_MERGE_MESSAGE" HEAD` from a detached TIP: a signature would differ.
ci_merge_commit_env() {
  export GIT_AUTHOR_NAME='Codewire CI merge'
  export GIT_AUTHOR_EMAIL='ci-merge@codewire.invalid'
  export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME"
  export GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
  export GIT_AUTHOR_DATE='2000-01-01T00:00:00+0000'
  export GIT_COMMITTER_DATE="$GIT_AUTHOR_DATE"
  CI_MERGE_MESSAGE="ci: pull request head $1 merged onto $2"
  export CI_MERGE_MESSAGE
}

# ci_source_archive SRC OUT: SRC's HEAD as the zstd tar a merge build
# publishes and the test jobs extract (place-build-source.sh). git archive's
# default tar.umask, 0002, writes group-writable modes, which the extraction's
# tar -p restores; the platform runtime's tests then refuse their fixture
# folders (UnsafeState, run 58615). 0022 gives the modes of a checkout.
ci_source_archive() {
  git -c tar.umask=0022 -C "$1" archive --format=tar HEAD | zstd -q -3 -T0 -o "$2"
}
