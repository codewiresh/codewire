#!/usr/bin/env bash
# Synthetic proof for the Nix release pin proposal: one automation branch, one
# pull request whose body is the recomputation, only nix/release.json changes,
# only the release-pin bot's private token file is used, and the token never
# reaches arguments or output. The pin tool itself is proven by
# test-nix-release-pin.py; here a stand-in writes a given pin and report.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
CASES=0

fail() {
  printf '[test-propose-nix-release-pin] ERROR: %s\n' "$*" >&2
  exit 1
}
pass() { CASES=$((CASES + 1)); }

work="$(mktemp -d "${TMPDIR:-/tmp}/propose-nix-release-pin.XXXXXX")"
trap 'rm -rf "$work"' EXIT
readonly TOKEN='synthetic-release-pin-bot-token-0123456789'
printf '%s' "$TOKEN" >"$work/bot-token"
chmod 0600 "$work/bot-token"

pin_json() {
  jq -n --arg tag "$1" --arg hex "$(printf "${2}%.0s" {1..64})" '{
    schema: "codewire.cw.nix/v1", release_tag: $tag,
    targets: {"x86_64-linux": {target: "x86_64-unknown-linux-musl", sha256: $hex, size: 1}}}'
}
pin_json v0.4.24 1 >"$work/old-pin.json"
pin_json v0.4.25 2 >"$work/new-pin.json"
printf '| `x86_64-linux` | ... | exact match |\n' >"$work/report.md"

# A fixture repository with the real script and the old pin on main.
repo="$work/repo"
origin="$work/origin.git"
git init -q -b main "$repo"
git init -q --bare -b main "$origin"
git -C "$repo" config user.name fixture
git -C "$repo" config user.email fixture@example.invalid
git -C "$repo" config commit.gpgsign false
mkdir -p "$repo/scripts/ci/release" "$repo/nix"
install -m 755 "$ROOT/scripts/ci/release/propose-nix-release-pin.sh" "$repo/scripts/ci/release/"
cp "$work/old-pin.json" "$repo/nix/release.json"
printf 'sums for v0.4.24\n' >"$repo/nix/SHA256SUMS"
printf 'signature for v0.4.24\n' >"$repo/nix/SHA256SUMS.asc"
printf 'flake\n' >"$repo/flake.nix"
git -C "$repo" add -A
git -C "$repo" commit -qm 'pin v0.4.24'
git -C "$repo" remote add origin "$origin"
git -C "$repo" push -q origin main

mkdir -p "$work/bin"
# The pin tool's stand-in: render writes FAKE_PIN and FAKE_REPORT, or nothing
# when a newer release is stable, or fails.
cat >"$work/bin/pin-tool.py" <<'MOCK'
import os, shutil, sys
args = sys.argv[1:]
assert args[0] == "render", args
values = dict(zip(args[1::2], args[2::2]))
with open(os.environ["FAKE_PIN_CALLS"], "a") as calls:
    calls.write(" ".join(args) + "\n")
mode = os.environ.get("FAKE_PIN_MODE", "write")
if mode == "fail":
    print("nix-release-pin: REJECT PinError: synthetic", file=sys.stderr)
    sys.exit(1)
if mode == "write":
    shutil.copy(os.environ["FAKE_PIN"], values["--output"])
    shutil.copy(os.environ["FAKE_REPORT"], values["--report"])
    tag = open(os.environ["FAKE_PIN"]).read().split('"release_tag": "')[1].split('"')[0]
    with open(values["--sums"], "w") as sums:
        sums.write(f"sums for {tag}\n")
    with open(values["--sums-signature"], "w") as signature:
        signature.write(f"signature for {tag}\n")
MOCK
cat >"$work/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${FAKE_CURL_CALLS:?}"
printf '\n' >>"$FAKE_CURL_CALLS"
output=''
data=''
url=''
method=GET
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --data-binary) data="${2#@}"; method="${method/GET/POST}"; shift 2 ;;
    --request) method="$2"; shift 2 ;;
    --config|--header|--connect-timeout|--max-time) shift 2 ;;
    *) url="$1"; shift ;;
  esac
done
case "$method $url" in
  'GET https://forgejo.invalid/api/v1/repos/codewire/codewire/pulls?state=open&page=1&limit=50')
    printf '%s\n' "${FAKE_OPEN_PULLS:-[]}" >"$output" ;;
  'POST https://forgejo.invalid/api/v1/repos/codewire/codewire/pulls')
    cp "$data" "${FAKE_CREATED_BODY:?}"
    printf '{"number":7}\n' >"$output" ;;
  'PATCH https://forgejo.invalid/api/v1/repos/codewire/codewire/pulls/7')
    cp "$data" "${FAKE_EDITED_BODY:?}"
    printf '{"number":7}\n' >"$output" ;;
  *) exit 91 ;;
esac
MOCK
chmod +x "$work/bin/curl"

# propose TAG [NAME=VALUE...]: run the proposal for TAG with extra environment.
propose() {
  local tag="$1"
  shift
  (
    cd "$repo"
    env -u GITEA_TOKEN PATH="$work/bin:$PATH" RELEASE_PIN_BOT_TOKEN_FILE="$work/bot-token" \
      GITHUB_REPOSITORY=codewire/codewire GITHUB_SERVER_URL=https://forgejo.invalid \
      RUNNER_TEMP="$work" FAKE_CURL_CALLS="$work/curl-calls" FAKE_PIN_CALLS="$work/pin-calls" \
      NIX_RELEASE_PIN_TOOL="$work/bin/pin-tool.py" FAKE_PIN="$work/new-pin.json" \
      FAKE_REPORT="$work/report.md" FAKE_CREATED_BODY="$work/created-body.json" \
      FAKE_EDITED_BODY="$work/edited-body.json" "$@" \
      scripts/ci/release/propose-nix-release-pin.sh "$tag"
  )
}
branch_head() { git -C "$origin" rev-parse -q --verify refs/heads/automation/nix-release-pin || true; }

# A new release is proposed on the automation branch, changing only the pin,
# and the pull request's body is the recomputation.
: >"$work/curl-calls"
propose v0.4.25 >"$work/propose.out" 2>&1 || fail "proposal failed: $(cat "$work/propose.out")"
grep -Fq 'opened proposal #7 for v0.4.25' "$work/propose.out" || fail 'the proposal was not opened'
grep -Fq 'render --version v0.4.25 --output' "$work/pin-calls" || fail 'the pin was not rendered for the tag'
[[ "$(git -C "$origin" diff --name-only main automation/nix-release-pin | tr '\n' ' ')" == \
  'nix/SHA256SUMS nix/SHA256SUMS.asc nix/release.json ' ]] ||
  fail 'the proposal does not change exactly the pin and its signed checksums'
git -C "$origin" show automation/nix-release-pin:nix/release.json | cmp -s - "$work/new-pin.json" ||
  fail 'the proposal does not carry the rendered pin'
jq -e '.head == "automation/nix-release-pin" and .base == "main"
  and .title == "chore(nix): pin the flake to cw v0.4.25"
  and (.body | startswith("| `x86_64-linux` | ... | exact match |"))
  and (.body | contains("release-pin bot opened this pull request"))' "$work/created-body.json" >/dev/null ||
  fail "the pull request is not the recomputation from the automation branch: $(cat "$work/created-body.json")"
[[ "$(git -C "$origin" log -1 --format='%an <%ae>|%s' automation/nix-release-pin)" == \
  'Codewire <hello@codewire.sh>|chore(nix): pin the flake to cw v0.4.25' ]] ||
  fail 'the proposal commit is not the bot'\''s'
if grep -rqF "$TOKEN" "$work/curl-calls" "$work/propose.out" "$work/created-body.json" "$work/pin-calls"; then
  fail 'the token reached curl arguments, output or the request body'
fi
pass

# An open proposal is updated in place, with a new body; no second pull
# request is opened.
OPEN='[{"number":7,"head":{"ref":"automation/nix-release-pin"}}]'
rm -f "$work/created-body.json"
pin_json v0.4.26 3 >"$work/newer-pin.json"
propose v0.4.26 FAKE_OPEN_PULLS="$OPEN" FAKE_PIN="$work/newer-pin.json" >"$work/update.out" 2>&1 ||
  fail "update failed: $(cat "$work/update.out")"
grep -Fq 'updated proposal #7 to v0.4.26' "$work/update.out" || fail "the open proposal was not updated: $(cat "$work/update.out")"
git -C "$origin" show automation/nix-release-pin:nix/release.json | cmp -s - "$work/newer-pin.json" ||
  fail 'the open proposal does not carry the newer pin'
jq -e '(keys == ["body", "title"]) and .title == "chore(nix): pin the flake to cw v0.4.26"
  and (.body | contains("exact match"))' "$work/edited-body.json" >/dev/null ||
  fail 'the updated proposal did not get a new title and body'
[[ ! -e "$work/created-body.json" ]] || fail 'an open proposal got a second pull request'
pass

# A release main already pins changes nothing.
before="$(branch_head)"
propose v0.4.24 FAKE_PIN="$work/old-pin.json" >"$work/same.out" 2>&1 || fail "same pin failed: $(cat "$work/same.out")"
grep -Fq 'main already pins v0.4.24' "$work/same.out" || fail "a pin main already has was proposed: $(cat "$work/same.out")"
[[ "$(branch_head)" == "$before" ]] || fail 'a pin main already has was pushed'
pass

# A channel already on a newer release writes nothing, so nothing is pushed.
propose v0.4.25 FAKE_PIN_MODE=superseded >"$work/superseded.out" 2>&1 ||
  fail "superseded failed: $(cat "$work/superseded.out")"
grep -Fq 'its own run proposes the pin' "$work/superseded.out" || fail 'a superseded release was proposed'
[[ "$(branch_head)" == "$before" ]] || fail 'a superseded release was pushed'
pass

# Refusals before any push: a pin tool failure, a malformed tag, the job token,
# a token file others can read, a malformed token, and anything but the pin
# in the proposal.
expect_refusal() {
  local name="$1" expected="$2"
  shift 2
  if propose "$@" >"$work/$name.out" 2>&1; then
    fail "$name was not refused"
  fi
  grep -Fq "$expected" "$work/$name.out" || fail "$name was refused for another reason: $(cat "$work/$name.out")"
  [[ "$(branch_head)" == "$before" ]] || fail "$name pushed the branch"
  pass
}
expect_refusal tool-failed 'REJECT PinError: synthetic' v0.4.25 FAKE_PIN_MODE=fail
expect_refusal bad-tag 'not vMAJOR.MINOR.PATCH' 'v0.4.25;x'
expect_refusal job-token 'GITEA_TOKEN is set' v0.4.25 GITEA_TOKEN=job
cp "$work/bot-token" "$work/open-token"
chmod 0644 "$work/open-token"
expect_refusal open-token 'must be a private regular file' v0.4.25 RELEASE_PIN_BOT_TOKEN_FILE="$work/open-token"
printf 'not a token!' >"$work/bad-token"
chmod 0600 "$work/bad-token"
expect_refusal bad-token 'is malformed' v0.4.25 RELEASE_PIN_BOT_TOKEN_FILE="$work/bad-token"
git -C "$repo" switch -q main
printf 'stray\n' >"$repo/stray"
expect_refusal stray-file 'changed more than the pin' v0.4.25 FAKE_OPEN_PULLS="$OPEN"
rm "$repo/stray"

printf '[test-propose-nix-release-pin] %d cases passed\n' "$CASES"
