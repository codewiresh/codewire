#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RESOLVER="$ROOT/scripts/ci/verify/resolve-cargo-target-dir.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
unset CARGO_TARGET_DIR CODEWIRE_CARGO_TARGET_MODE

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
# Keep disposable fixture commits independent of a developer's signing policy.
git -C "$repo" config commit.gpgsign false
printf 'fixture\n' > "$repo/fixture.txt"
git -C "$repo" add fixture.txt
git -C "$repo" -c maintenance.autoDetach=false -c gc.autoDetach=false commit -q -m fixture
git -C "$repo" worktree add -q -b linked-one "$worktree_one"
git -C "$repo" worktree add -q -b linked-two "$worktree_two"

assert_eq primary-with-links "$repo/target" "$($RESOLVER "$repo")"
assert_eq linked-one-isolated "$worktree_one/target" "$($RESOLVER "$worktree_one")"
assert_eq linked-two-isolated "$worktree_two/target" "$($RESOLVER "$worktree_two")"
assert_eq explicit-isolated "$worktree_one/target" \
  "$(CODEWIRE_CARGO_TARGET_MODE=isolated "$RESOLVER" "$worktree_one")"

assert_eq primary-shared "$repo/target" \
  "$(CODEWIRE_CARGO_TARGET_MODE=shared "$RESOLVER" "$repo")"
assert_eq linked-one-shared "$repo/target" \
  "$(CODEWIRE_CARGO_TARGET_MODE=shared "$RESOLVER" "$worktree_one")"
assert_eq linked-two-shared "$repo/target" \
  "$(CODEWIRE_CARGO_TARGET_MODE=shared "$RESOLVER" "$worktree_two")"

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

invalid_mode_output="$(
  CODEWIRE_CARGO_TARGET_MODE=invalid "$RESOLVER" "$worktree_one" 2>&1 || true
)"
if CODEWIRE_CARGO_TARGET_MODE=invalid "$RESOLVER" "$worktree_one" >/dev/null 2>&1; then
  fail 'invalid Cargo target mode was accepted'
fi
grep -qF 'CODEWIRE_CARGO_TARGET_MODE must be isolated or shared' \
  <<<"$invalid_mode_output" || fail 'invalid target mode was not explained'

override_with_invalid_mode="$(
  CODEWIRE_CARGO_TARGET_MODE=invalid CARGO_TARGET_DIR="$absolute_override" \
    "$RESOLVER" "$worktree_one"
)"
assert_eq override-before-mode "$absolute_override" "$override_with_invalid_mode"

mkdir -p "$TMP/not-a-repository"
if "$RESOLVER" "$TMP/not-a-repository" >"$TMP/nonrepo.out" 2>"$TMP/nonrepo.err"; then
  fail 'non-repository input was accepted'
fi
grep -qF 'not a Git worktree' "$TMP/nonrepo.err" ||
  fail 'non-repository failure did not explain the boundary'

printf 'resolve Cargo target directory: green\n'
