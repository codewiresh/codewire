#!/usr/bin/env bash
# Prove the mirror content gate refuses the commits that must not go public and
# lets clean ones through, in a synthetic repository. The private patterns are
# synthetic and arrive through MIRROR_PRIVATE_CONTENT_PATTERNS, as in the mirror
# job; strings the tracked generic patterns refuse are assembled at run time so
# this file is itself clean.
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

# Synthetic stand-ins for the private names the operator stores in the
# Forgejo Actions variable: comments and blank lines are ignored.
readonly private_patterns='# synthetic private names
mesh\.example-private\.invalid

(^|[^/])acme/(vault|ledger)
build-box-[0-9]+'
readonly WORKFLOW="$ROOT/.gitea/workflows/mirror-github.yaml"

# run_gate [NAME=VALUE...] -- ARGS...: run the gate in the synthetic repository
# with no CI or pattern environment beyond the given assignments.
run_gate() {
  local -a assignments=()
  while [[ $# -gt 0 && "$1" != -- ]]; do
    assignments+=("$1")
    shift
  done
  shift
  (cd "$repo" && env -u CI -u GITHUB_ACTIONS -u MIRROR_CONTENT_LOCAL_TEST \
    -u MIRROR_PRIVATE_CONTENT_PATTERNS "${assignments[@]}" \
    scripts/ci/release/check-mirror-content.sh "$@")
}
# The mirror job's environment: CI, with the private patterns set.
run_check() { run_gate CI=true "MIRROR_PRIVATE_CONTENT_PATTERNS=$private_patterns" -- "$@"; }

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

# Each private pattern from the environment is refused in added lines, naming
# the commit and the pattern number, never the text or the pattern.
number=0
for content in 'api.mesh.example-private.invalid' 'acme/vault#12' 'build-box-7'; do
  number=$((number + 1))
  commit_file leak.txt "see $content"
  if run_check "$base" >"$work/out" 2>&1; then
    fail "added text was accepted: private pattern $number"
  fi
  grep -Fq "private pattern $number found in added lines of" "$work/out" ||
    fail "a refusal does not name the commit and private pattern $number"
  if grep -Fq "$content" "$work/out"; then fail 'a refusal printed the matched text'; fi
  if grep -Fq 'example-private' "$work/out"; then fail 'a refusal printed a private pattern'; fi
  reset_to_base
done

# A private pattern in a commit message is refused too.
commit_file msg.txt 'x' 'fix: the build-box-3 runner'
if run_check "$base" >"$work/out" 2>&1; then fail 'a private name in a message was accepted'; fi
grep -Fq 'private pattern 3 found in the messages of' "$work/out" ||
  fail 'a private message refusal does not name the commit'
reset_to_base

# Private patterns are extended regular expressions: an anchored repository
# reference does not match the same path inside a public URL.
commit_file ok.txt 'https://forge.example.invalid/acme/vault/releases'
run_check "$base" >/dev/null || fail 'a public URL path was refused'
reset_to_base

# A variable saved through a web form may carry CRLF line ends; its patterns
# still match.
commit_file leak.txt 'see build-box-9'
if run_gate CI=true "MIRROR_PRIVATE_CONTENT_PATTERNS=$(printf 'mesh\\.example-private\\.invalid\r\nbuild-box-[0-9]+\r\n')" \
  -- "$base" >"$work/out" 2>&1; then
  fail 'a CRLF private pattern was accepted'
fi
grep -Fq 'private pattern 2 found in added lines of' "$work/out" ||
  fail 'a CRLF private pattern did not match'
reset_to_base

# An invalid private pattern fails closed without quoting it.
commit_file notes.txt 'plain text'
if run_gate CI=true 'MIRROR_PRIVATE_CONTENT_PATTERNS=build-box-(' -- "$base" >"$work/out" 2>&1; then
  fail 'an invalid private pattern was accepted'
fi
grep -Fq 'private pattern 1 is not a valid extended regular expression' "$work/out" ||
  fail 'an invalid private pattern is not attributable'
if grep -Fq 'build-box' "$work/out"; then fail 'an invalid private pattern was printed'; fi
reset_to_base

# Without private patterns the gate fails closed in CI, even with the local
# test flag, and outside CI unless that flag is set.
commit_file notes.txt 'plain text'
for ci_env in CI=true GITHUB_ACTIONS=true; do
  for patterns_env in 'MIRROR_PRIVATE_CONTENT_PATTERNS=' \
    "MIRROR_PRIVATE_CONTENT_PATTERNS=$(printf '# comment only\n\n')"; do
    if run_gate "$ci_env" "$patterns_env" MIRROR_CONTENT_LOCAL_TEST=1 -- "$base" >"$work/out" 2>&1; then
      fail "an empty pattern variable was accepted with $ci_env"
    fi
    grep -Fq 'MIRROR_PRIVATE_CONTENT_PATTERNS is empty' "$work/out" ||
      fail "an empty pattern variable refusal is not attributable with $ci_env"
  done
done
if run_gate -- "$base" >"$work/out" 2>&1; then
  fail 'an empty pattern variable was accepted without the local test flag'
fi
grep -Fq 'MIRROR_CONTENT_LOCAL_TEST=1' "$work/out" ||
  fail 'a local refusal does not name the local test flag'
run_gate MIRROR_CONTENT_LOCAL_TEST=1 -- "$base" >/dev/null 2>&1 ||
  fail 'a clean local test run without private patterns was refused'
reset_to_base

# Removing forbidden text is allowed: only added lines count.
git -C "$repo" checkout -q "$base"
printf 'see %s\n' 'build-box-1' >"$repo/old.txt"
git -C "$repo" add -A
git -C "$repo" commit -q --no-verify -m 'old'
old="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" rm -q old.txt
git -C "$repo" commit -q -m 'drop it'
run_check "$old" >/dev/null || fail 'removing forbidden text was refused'
git -C "$repo" checkout -q -B main "$base"

# The tracked generic patterns apply with or without private patterns: a
# Reviewed-on trailer that links to the forge is refused; one that names only
# the pull request number is the public form and passes.
trailer='Reviewed-on'
commit_file msg.txt 'x' "feat: change

${trailer}: https://example.invalid/pulls/1"
if run_check "$base" >"$work/out" 2>&1; then fail 'a Reviewed-on link was accepted'; fi
grep -Fq 'pattern 1 found in the messages of' "$work/out" ||
  fail 'a message refusal does not name the commit'
if run_gate MIRROR_CONTENT_LOCAL_TEST=1 -- "$base" >"$work/out" 2>&1; then
  fail 'a Reviewed-on link was accepted in a local test run'
fi
grep -Fq 'pattern 1 found in the messages of' "$work/out" ||
  fail 'a local message refusal does not name the commit'
reset_to_base
commit_file msg.txt 'x' "feat: change (#12)

${trailer}: #12"
run_check "$base" >/dev/null || fail 'a Reviewed-on pull request number was refused'
reset_to_base
identity="INFISICA""L_MACHINE_IDENTITY_ID=$(printf '0%.0s' {1..8})-0000-0000-0000-$(printf '0%.0s' {1..12})"
commit_file env.txt "$identity"
if run_check "$base" >"$work/out" 2>&1; then fail 'a retired identity id was accepted'; fi
grep -Fq 'pattern 2 found in added lines of' "$work/out" ||
  fail 'a retired identity id refusal does not name the commit'
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

# Home directories. Owner rule: never commit one, in a comment or anywhere
# else. The paths are assembled here so this file is itself clean.
home_of() { printf '/%s/%s' "$1" "$2"; }
leak="$(home_of home alice)/src/project"
mac_leak="$(home_of Users alice)/Library"
for content in "// a file above the worktree, as $leak holds" "HOME=$mac_leak" \
  "$(home_of home user)/$(home_of home alice)/"; do
  commit_file notes.txt "$content"
  if run_check "$base" >"$work/out" 2>&1; then fail "a home directory was accepted: $content"; fi
  grep -Fq 'pattern 3 found in added lines of' "$work/out" ||
    fail 'a home directory refusal does not name the commit and pattern 3'
  if grep -Fq alice "$work/out"; then fail 'a refusal printed the home directory'; fi
  reset_to_base
done
# The reviewed placeholders and product users pass, and so does a home segment
# under another root, which is not an absolute home directory.
for content in "$(home_of home user)/src/codewire" "$(home_of home codewire)/.codex" \
  "$(home_of Users someone)/Library" "$(home_of home tester)" "\$TMP$(home_of home .claude)/jobs" \
  "/synthetic$(home_of home .codewire)/credentials-v1"; do
  commit_file notes.txt "$content"
  run_check "$base" >"$work/out" 2>&1 || {
    cat "$work/out" >&2
    fail "a reviewed placeholder or relative home segment was refused: $content"
  }
  reset_to_base
done
# Old behaviour: without the home-directory rule the same leak went through, as
# it did before the rule existed.
grep -v -e '^except: ' -e "hom\[e\]" "$repo/scripts/ci/release/public-content-patterns.txt" >"$work/old-patterns.txt"
commit_file notes.txt "// as $leak holds"
run_check --patterns "$work/old-patterns.txt" "$base" >/dev/null 2>&1 ||
  fail 'the old patterns already refused a home directory; this fixture no longer shows the change'
reset_to_base
# An except line needs its own pattern above it.
printf 'except: anything\n' >"$work/bad-patterns.txt"
commit_file notes.txt 'plain'
if run_check --patterns "$work/bad-patterns.txt" "$base" >"$work/out" 2>&1; then
  fail 'an except line without a pattern was accepted'
fi
grep -Fq 'except line without its own pattern' "$work/out" || fail 'a stray except line is not attributable'
reset_to_base

# The pull request scan runs the same patterns before merge, over the commits
# after the merge base: a branch behind main is not blamed for main's commits.
git -C "$repo" checkout -q -b feature "$base"
commit_file feature.txt "// as $leak holds" 'feat: a change'
leaky_feature="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" checkout -q main
commit_file main-only.txt 'see build-box-4' 'main: its own change'
main_head="$(git -C "$repo" rev-parse HEAD)"
run_pull_request() {
  run_gate CI=true "MIRROR_PRIVATE_CONTENT_PATTERNS=$private_patterns" -- --pull-request --no-gitleaks "$@"
}
if run_pull_request "$main_head" "$leaky_feature" >"$work/out" 2>&1; then
  fail 'a pull request adding a home directory was accepted'
fi
grep -Fq "pattern 3 found in added lines of: $(git -C "$repo" rev-parse --short "$leaky_feature")" "$work/out" ||
  fail 'a pull request refusal does not name its commit and pattern 3'
grep -Fq 'must not reach main' "$work/out" || fail 'a pull request refusal does not say it blocks the merge'
if grep -Fq 'private pattern' "$work/out"; then fail "main's own commit was blamed on the pull request"; fi
if grep -Fq alice "$work/out"; then fail 'a pull request refusal printed the home directory'; fi
git -C "$repo" checkout -q -B feature "$base"
commit_file feature.txt 'plain' 'feat: a clean change'
clean_feature="$(git -C "$repo" rev-parse HEAD)"
run_pull_request "$main_head" "$clean_feature" >/dev/null 2>&1 ||
  fail 'a clean pull request behind main was refused'
# The title and body become the squash message, so they are scanned too.
printf 'feat: wire build-box-2 in\n\nBody text.\n' >"$work/pr-text"
if run_pull_request --message-file "$work/pr-text" "$main_head" "$clean_feature" >"$work/out" 2>&1; then
  fail 'a private name in the pull request title was accepted'
fi
grep -Fq 'private pattern 3 found in the pull request title or body' "$work/out" ||
  fail 'a title refusal does not name the pattern'
if grep -Fq build-box "$work/out"; then fail 'a title refusal printed the private name'; fi
# The candidate's own pattern file cannot weaken the scan: the caller passes
# the protected base's copy.
git -C "$repo" checkout -q feature
printf '# emptied by the candidate\n' >"$repo/scripts/ci/release/public-content-patterns.txt"
printf '// as %s holds\n' "$leak" >"$repo/feature.txt"
git -C "$repo" add -A
git -C "$repo" commit -q -m 'feat: drop the rules'
weakening="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" checkout -q main
cp "$ROOT/scripts/ci/release/public-content-patterns.txt" "$work/trusted-patterns.txt"
if run_pull_request --patterns "$work/trusted-patterns.txt" "$main_head" "$weakening" >"$work/out" 2>&1; then
  fail "a candidate's emptied pattern file let a home directory through"
fi
grep -Fq 'pattern 3 found in added lines of' "$work/out" || fail 'the trusted patterns were not applied'
# Fail closed without the private patterns, and on a malformed or missing commit.
if run_gate CI=true -- --pull-request --no-gitleaks "$main_head" "$clean_feature" >"$work/out" 2>&1; then
  fail 'a pull request scan without private patterns was accepted'
fi
grep -Fq 'MIRROR_PRIVATE_CONTENT_PATTERNS is empty' "$work/out" || fail 'an empty private list is not attributable'
for pair in "main $clean_feature" "$main_head $(printf '0%.0s' {1..40})"; do
  # shellcheck disable=SC2086 # the pair is two words by construction
  if run_pull_request $pair >/dev/null 2>&1; then fail "pull request commits '$pair' were accepted"; fi
done
git -C "$repo" checkout -q -B main "$base"
git -C "$repo" branch -q -D feature

# The policy core's tree scan names the file and line of a committed home
# directory, never the text, and needs no private patterns.
printf 'line one\n# as %s holds\n%s/src/codewire\n' "$leak" "$(home_of home user)" >"$repo/tree.txt"
git -C "$repo" add -A
git -C "$repo" commit -q -m 'tree fixture'
if run_gate CI=true -- --tree >"$work/out" 2>&1; then fail 'the tree scan accepted a committed home directory'; fi
grep -Fq 'pattern 3 found at: tree.txt:2 ' "$work/out" || fail 'the tree scan does not name the file and line'
if grep -Fq alice "$work/out"; then fail 'the tree scan printed the home directory'; fi
printf 'line one\n%s/src/codewire\n' "$(home_of home user)" >"$repo/tree.txt"
git -C "$repo" add -A
git -C "$repo" commit -q -m 'tree fixture clean'
run_gate CI=true -- --tree >"$work/out" 2>&1 || { cat "$work/out" >&2; fail 'the tree scan refused a placeholder'; }
reset_to_base

# The protected-base source-approval workflow runs the scan on every pull
# request, from its own copy of the script and patterns.
readonly APPROVAL="$ROOT/.gitea/workflows/source-approval.yml"
grep -Fq "if: forgejo.event_name == 'pull_request_target'" "$APPROVAL" &&
  grep -Fq 'trusted="$GITHUB_WORKSPACE/.source-approval-base/scripts/ci/release"' "$APPROVAL" &&
  grep -Fq 'bash "$trusted/check-mirror-content.sh" --pull-request' "$APPROVAL" &&
  grep -Fq -- '--patterns "$trusted/public-content-patterns.txt"' "$APPROVAL" ||
  fail 'source approval does not run the protected-base content scan on pull requests'
# shellcheck disable=SC2016 # the workflow expression is matched literally
grep -Fq 'MIRROR_PRIVATE_CONTENT_PATTERNS: ${{ vars.MIRROR_PRIVATE_CONTENT_PATTERNS }}' "$APPROVAL" ||
  fail 'source approval does not pass the private content patterns'
if grep -Fq 'MIRROR_CONTENT_LOCAL_TEST' "$APPROVAL"; then
  fail 'source approval runs the content scan as a local test'
fi

# The mirror script scans the pending range before it pushes.
scan_line="$(grep -n 'check-mirror-content.sh' "$MIRROR" | head -1 | cut -d: -f1)"
push_line="$(grep -n 'push github HEAD:refs/heads/main' "$MIRROR" | head -1 | cut -d: -f1)"
[[ -n "$scan_line" && -n "$push_line" && "$scan_line" -lt "$push_line" ]] ||
  fail 'the mirror pushes before scanning'
if grep -Eq 'CODEWIRE_MIRROR_[A-Z_]*(SKIP|BYPASS|CHECK)' "$MIRROR"; then
  fail 'the mirror script offers a way to skip the content gate'
fi
if grep -Fq 'MIRROR_CONTENT_LOCAL_TEST' "$MIRROR" "$WORKFLOW"; then
  fail 'the mirror job runs the content gate as a local test'
fi
# shellcheck disable=SC2016 # the workflow expression is matched literally
grep -Fq 'MIRROR_PRIVATE_CONTENT_PATTERNS: ${{ vars.MIRROR_PRIVATE_CONTENT_PATTERNS }}' "$WORKFLOW" ||
  fail 'the mirror workflow does not pass the private content patterns'

printf '[test-check-mirror-content] mirror content gate contract passed\n'
