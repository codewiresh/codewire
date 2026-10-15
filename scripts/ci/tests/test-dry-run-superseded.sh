#!/usr/bin/env bash
# Execute scripts/ci/release/dry-run-superseded.sh against a real synthetic
# main history: each commit stands for one merged pull request.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT

fail() {
  printf '[test-dry-run-superseded] ERROR: %s\n' "$*" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_AUTHOR_NAME=fixture \
  GIT_AUTHOR_EMAIL=fixture@example.invalid GIT_COMMITTER_NAME=fixture \
  GIT_COMMITTER_EMAIL=fixture@example.invalid PYTHONDONTWRITEBYTECODE=1

builder="$work/builder"
origin="$work/origin.git"
git init --quiet --initial-branch=main "$builder"
git init --quiet --bare --initial-branch=main "$origin"
mkdir -p "$builder/scripts/ci" "$builder/.gitea/workflows"
cp -R "$ROOT/scripts/ci/release" "$builder/scripts/ci/release"
cp "$ROOT/.gitea/workflows/cw-release-dry-run.yaml" "$builder/.gitea/workflows/"
find "$builder" -name __pycache__ -prune -exec rm -rf {} +
printf 'base\n' >"$builder/Cargo.lock"
git -C "$builder" add -A
git -C "$builder" commit --quiet -m base
base="$(git -C "$builder" rev-parse HEAD)"

change() {
  mkdir -p "$builder/$(dirname "$1")"
  printf '%s\n' "$2" >>"$builder/$1"
  git -C "$builder" add -A
  git -C "$builder" commit --quiet -m "$1"
  git -C "$builder" rev-parse HEAD
}

# Chain P: a cw change, changes no dry run sees (docs, and a crate cw does
# not link), then a cw change.
x_parts="$(change crates/codewire-cli/src/a.rs 'pub fn a() {}')"
docs_only="$(change docs/notes.md 'no dry run')"
server_only="$(change crates/codewire-dashboard-web/src/s.rs 'pub fn s() {}')"
t_parts="$(change crates/codewire-daemon/src/b.rs 'pub fn b() {}')"
git -C "$builder" branch chain-p
# Chain F: a runtime input, then a cw change, then another runtime input.
git -C "$builder" checkout --quiet -b chain-f "$base"
x_full="$(change Cargo.lock 'lock change')"
t_after_full="$(change crates/codewire-client/src/c.rs 'pub fn c() {}')"
f_full="$(change rust-toolchain.toml '[toolchain]')"
git -C "$builder" push --quiet "$origin" chain-p chain-f "$base:refs/heads/main"

clone="$work/clone"
git clone --quiet --no-local "$origin" "$clone"
git -C "$clone" fetch --quiet origin '+refs/heads/*:refs/remotes/origin/*'
git -C "$clone" checkout --quiet --detach "$base"
script="$clone/scripts/ci/release/dry-run-superseded.sh"

# A git that reports a fixed canonical main from ls-remote and is real otherwise.
fake_bin="$work/fake-bin"
mkdir "$fake_bin"
real_git="$(command -v git)"
cat >"$fake_bin/git" <<GIT
#!/usr/bin/env bash
if [[ "\$1" == ls-remote && -n "\${FAKE_LS_REMOTE+set}" ]]; then
  printf '%s\trefs/heads/main\n' "\$FAKE_LS_REMOTE"
  exit 0
fi
exec "$real_git" "\$@"
GIT
chmod +x "$fake_bin/git"

# run CASE MAIN SHA BEFORE [EVENT] -> prints superseded=..., or "failed"
run() {
  local name="$1" main="$2" sha="$3" before="$4" event="${5:-push}" output result
  git -C "$origin" update-ref refs/heads/main "$main"
  output="$work/$name.out"
  : >"$output"
  if (cd "$clone" && env GITHUB_OUTPUT="$output" GITHUB_EVENT_NAME="$event" \
      "${case_env[@]}" "$script" "$sha" "$before") >"$work/$name.log" 2>&1; then
    result="$(cat "$output")"
  else
    result=failed
  fi
  printf '%s\n' "$result"
}

expect() {
  local name="$1" want="$2" got
  shift 2
  got="$(run "$name" "$@")"
  [[ "$got" == "$want" ]] || {
    sed 's/^/  /' "$work/$name.log" >&2
    fail "$name: want $want, got $got"
  }
}

case_env=(PATH="$PATH")
expect head superseded=false "$x_parts" "$x_parts" "$base"
grep -Fq 'building the canonical main commit' "$work/head.log" || fail 'head case did not say why'
expect superseded superseded=true "$t_parts" "$x_parts" "$base"
grep -Fq "the queued dry run of $t_parts builds this commit's changes" "$work/superseded.log" ||
  fail 'superseded case did not name the newer run in one line'
expect no-later-run superseded=false "$docs_only" "$x_parts" "$base"
expect server-crate-runs-none superseded=false "$server_only" "$x_parts" "$base"
expect dispatched superseded=false "$t_parts" "$x_parts" "$base" workflow_dispatch
expect runtime-not-rebuilt superseded=false "$t_after_full" "$x_full" "$base"
expect runtime-rebuilt superseded=true "$f_full" "$x_full" "$base"
expect unknown-before-newest-full superseded=true "$f_full" "$t_after_full" ''
expect unknown-before-parts superseded=false "$t_parts" "$x_parts" ''
expect not-on-main failed "$t_parts" "$x_full" "$base"
expect malformed-sha failed "$t_parts" not-a-commit "$base"
case_env=(PATH="$fake_bin:$PATH" FAKE_LS_REMOTE=not-a-commit)
expect malformed-main failed "$t_parts" "$x_parts" "$base"
case_env=(PATH="$fake_bin:$PATH" FAKE_LS_REMOTE='')
expect empty-main failed "$t_parts" "$x_parts" "$base"
case_env=(PATH="$PATH")
git -C "$clone" remote set-url origin "$work/missing.git"
expect unreadable-main failed "$t_parts" "$x_parts" "$base"
git -C "$clone" remote set-url origin "$origin"

# A depth-1 checkout judges the later pushes on fetched history.
shallow="$work/shallow"
git clone --quiet --no-local --depth 1 --branch chain-p "$origin" "$shallow"
git -C "$origin" update-ref refs/heads/main "$t_parts"
git -C "$shallow" checkout --quiet --detach "$t_parts"
: >"$work/shallow.out"
(cd "$shallow" && GITHUB_OUTPUT="$work/shallow.out" GITHUB_EVENT_NAME=push \
  "$shallow/scripts/ci/release/dry-run-superseded.sh" "$x_parts" "$base") >"$work/shallow.log" 2>&1 ||
  { sed 's/^/  /' "$work/shallow.log" >&2; fail 'shallow checkout failed'; }
[[ "$(cat "$work/shallow.out")" == superseded=true ]] || fail 'shallow checkout did not see the later push'

echo 'test-dry-run-superseded: PASS cases=15'
