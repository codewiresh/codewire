#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RESOLVER="$ROOT/scripts/ci/verify/resolve-cargo-target-dir.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
unset CARGO_TARGET_DIR

fail() {
  echo "test-resolve-cargo-target-dir: $*" >&2
  exit 1
}

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  [ "$actual" = "$expected" ] ||
    fail "$label: expected '$expected', got '$actual'"
}

standalone_repo="$TMP/standalone checkout"
mkdir -p "$standalone_repo"
git -C "$standalone_repo" init -q
assert_eq standalone "$standalone_repo/target" \
  "$($RESOLVER "$standalone_repo")"

repo="$TMP/repository root"
worktree_one="$TMP/linked one"
worktree_two="$TMP/linked two"
mkdir -p "$repo"
git -C "$repo" init -q
git -C "$repo" config user.name 'Cargo Target Fixture'
git -C "$repo" config user.email 'cargo-target-fixture@codewire.test'
printf 'fixture\n' > "$repo/fixture.txt"
git -C "$repo" add fixture.txt
git -C "$repo" commit -q -m fixture
git -C "$repo" worktree add -q -b linked-one "$worktree_one"
git -C "$repo" worktree add -q -b linked-two "$worktree_two"

expected="$repo/target"
assert_eq primary-with-links "$expected" "$($RESOLVER "$repo")"
assert_eq linked-one "$expected" "$($RESOLVER "$worktree_one")"
assert_eq linked-two "$expected" "$($RESOLVER "$worktree_two")"

relative_actual="$(
  cd "$TMP"
  CARGO_TARGET_DIR='relative target' "$RESOLVER" "$worktree_one"
)"
assert_eq relative-override "$TMP/relative target" "$relative_actual"

absolute_override="$TMP/absolute target"
absolute_actual="$(
  CARGO_TARGET_DIR="$absolute_override" "$RESOLVER" "$worktree_two"
)"
assert_eq absolute-override "$absolute_override" "$absolute_actual"

mkdir -p "$TMP/not-a-repository"
if "$RESOLVER" "$TMP/not-a-repository" >"$TMP/nonrepo.out" 2>"$TMP/nonrepo.err"; then
  fail 'non-repository input was accepted'
fi
grep -qF 'not a Git worktree' "$TMP/nonrepo.err" ||
  fail 'non-repository failure did not explain the boundary'

printf 'resolve Cargo target directory: green\n'
