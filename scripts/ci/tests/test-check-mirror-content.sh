#!/usr/bin/env bash
# Prove the mirror content gate refuses the commits that must not go public and
# lets clean ones through, in a synthetic repository. Forbidden strings are
# assembled at run time so this file is itself clean.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly CHECK="$ROOT/scripts/ci/release/check-mirror-content.sh"
readonly MIRROR="$ROOT/scripts/ci/release/mirror-github.sh"

fail() {
  printf '[test-check-mirror-content] ERROR: %s\n' "$*" >&2
  exit 1
}

command -v gitleaks >/dev/null || fail 'gitleaks is required for the mirror gate fixtures'

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/check-mirror-content.XXXXXX")"
trap 'rm -rf "$work"' EXIT
repo="$work/repo"
mkdir -p "$repo/scripts/ci/release"
cp "$CHECK" "$repo/scripts/ci/release/check-mirror-content.sh"
cp "$ROOT/scripts/ci/release/public-content-patterns.txt" "$repo/scripts/ci/release/"
cp "$ROOT/.gitleaks.toml" "$repo/.gitleaks.toml"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
git -C "$repo" init -q -b main
git -C "$repo" config user.name 'Test Author'
git -C "$repo" config user.email 'author@example.invalid'
git -C "$repo" config commit.gpgsign false
printf 'clean\n' >"$repo/README.md"
git -C "$repo" add -A
git -C "$repo" commit -q -m 'initial'
base="$(git -C "$repo" rev-parse HEAD)"

run_check() { (cd "$repo" && scripts/ci/release/check-mirror-content.sh "$@"); }

commit_file() {
  local name="$1" content="$2" message="${3:-change}"
  printf '%s\n' "$content" >"$repo/$name"
  git -C "$repo" add -A
  git -C "$repo" commit -q -m "$message"
}
reset_to_base() { git -C "$repo" reset -q --hard "$base"; }

# Clean commits pass, and a range with no commits is accepted.
run_check "$base" >/dev/null || fail 'an empty range was refused'
commit_file notes.txt 'plain text'
run_check "$base" >/dev/null || fail 'a clean commit was refused'
reset_to_base

# Each forbidden pattern is refused in added lines, naming the commit only.
tail_host='worker.private''.invalid'
home_path='/home''/user/src'
runner_name='mac''-runner'
node_name='private''-site-1'
private_ref='private/''repo#12'
for content in "$tail_host" "$home_path" "$runner_name" "$node_name" "$private_ref"; do
  commit_file leak.txt "see $content"
  if run_check "$base" >"$work/out" 2>&1; then
    fail "added text was accepted: pattern for ${content:0:4}"
  fi
  grep -Fq 'found in added lines of' "$work/out" || fail 'a refusal does not name the commit'
  if grep -Fq "$content" "$work/out"; then fail 'a refusal printed the matched text'; fi
  reset_to_base
done

# Public Forgejo URLs that merely contain the owner name are not a finding.
commit_file ok.txt 'https://git.example.invalid/infra/ci/builders/v1'
run_check "$base" >/dev/null || fail 'the public builder URL was refused'
reset_to_base

# Removing forbidden text is allowed: only added lines count.
git -C "$repo" checkout -q "$base"
printf 'see %s\n' "$tail_host" >"$repo/old.txt"
git -C "$repo" add -A
git -C "$repo" commit -q --no-verify -m 'old'
old="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" rm -q old.txt
git -C "$repo" commit -q -m 'drop it'
run_check "$old" >/dev/null || fail 'removing forbidden text was refused'
git -C "$repo" checkout -q -B main "$base"

# A Reviewed-on trailer that links to the forge is refused; one that names
# only the pull request number is the public form and passes.
trailer='Reviewed-on'
commit_file msg.txt 'x' "feat: change

${trailer}: https://example.invalid/pulls/1"
if run_check "$base" >"$work/out" 2>&1; then fail 'a Reviewed-on link was accepted'; fi
grep -Fq 'found in the messages of' "$work/out" || fail 'a message refusal does not name the commit'
reset_to_base
commit_file msg.txt 'x' "feat: change (#12)

${trailer}: #12"
run_check "$base" >/dev/null || fail 'a Reviewed-on pull request number was refused'
reset_to_base

# gitleaks over the range refuses a secret.
token="gh""p_$(printf 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8' | head -c 36)"
commit_file secret.txt "token=$token"
if run_check "$base" >"$work/out" 2>&1; then fail 'a committed token was accepted'; fi
grep -Fq 'gitleaks reported a finding' "$work/out" || fail 'a secret refusal is not attributable'
if grep -Fq "$token" "$work/out"; then fail 'a refusal printed the secret'; fi
reset_to_base

# An unknown, malformed or non-ancestor mirror head fails closed.
for head in '' 'not-a-sha' "$(printf '0%.0s' {1..40})"; do
  if run_check "$head" >"$work/out" 2>&1; then fail "mirror head '$head' was accepted"; fi
done
git -C "$repo" checkout -q -b other
commit_file other.txt 'x'
other="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" checkout -q main
if run_check "$other" >"$work/out" 2>&1; then fail 'a non-ancestor mirror head was accepted'; fi

# The mirror script scans the pending range before it pushes.
scan_line="$(grep -n 'check-mirror-content.sh' "$MIRROR" | head -1 | cut -d: -f1)"
push_line="$(grep -n 'push github HEAD:refs/heads/main' "$MIRROR" | head -1 | cut -d: -f1)"
[[ -n "$scan_line" && -n "$push_line" && "$scan_line" -lt "$push_line" ]] ||
  fail 'the mirror pushes before scanning'
if grep -Eq 'CODEWIRE_MIRROR_[A-Z_]*(SKIP|BYPASS|CHECK)' "$MIRROR"; then
  fail 'the mirror script offers a way to skip the content gate'
fi

printf '[test-check-mirror-content] mirror content gate contract passed\n'
