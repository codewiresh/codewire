#!/usr/bin/env bash
# Synthetic proof for the cw-egress pin proposal: it proposes only a digest
# whose main-CI-verified signature names a source on main with main's egress
# inputs; it changes only the component's pin on one automation branch, opens
# one pull request, and never puts the bot's token in arguments or output.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
export CODEWIRE_IMAGE_REGISTRY=registry.example.invalid

fail() {
  printf '[test-propose-egress-image-pin] ERROR: %s\n' "$*" >&2
  exit 1
}

work="$(mktemp -d "${TMPDIR:-/tmp}/propose-egress-image-pin.XXXXXX")"
trap 'rm -rf "$work"' EXIT
readonly TOKEN='synthetic-workspace-pin-bot-token-0123456789'
printf '%s' "$TOKEN" >"$work/bot-token"
chmod 0600 "$work/bot-token"
FINGERPRINT="$(printf 'f%.0s' {1..64})"
OTHER_FINGERPRINT="$(printf 'e%.0s' {1..64})"
DIGEST="sha256:$(printf 'a%.0s' {1..64})"

# A fixture repository with the real proposer and pin tool, and fakes for the
# planner, the registry and the signature verifier at the paths it calls.
repo="$work/repo"
origin="$work/origin.git"
git init -q -b main "$repo"
git init -q --bare -b main "$origin"
git -C "$repo" config user.name fixture
git -C "$repo" config user.email fixture@example.invalid
git -C "$repo" config commit.gpgsign false
mkdir -p "$repo/scripts/ci/images" "$repo/scripts/ci/plan" "$repo/scripts/ci/trust" "$repo/deployments/k8s/egress"
install -m 755 "$ROOT/scripts/ci/images/egress-image-pin.py" "$repo/scripts/ci/images/"
install -m 755 "$ROOT/scripts/ci/images/propose-egress-image-pin.sh" "$repo/scripts/ci/images/"
install -m 644 "$ROOT/deployments/k8s/egress/kustomization.yaml" "$repo/deployments/k8s/egress/"
printf 'synthetic public key\n' >"$repo/scripts/ci/trust/codewire-runtime-signing.pub"
# The planner reads each commit's fingerprint from a map the test writes.
cat >"$repo/scripts/ci/plan/planner.py" <<'PY'
import json, os, sys
args = sys.argv[1:]
head = args[args.index("--head") + 1]
output = args[args.index("--output") + 1]
fingerprints = dict(line.split() for line in open(os.environ["FAKE_FINGERPRINTS"]))
json.dump({"artifacts": {"egress_image": {"head_fingerprint": fingerprints.get(head, "f" * 64)}}}, open(output, "w"))
PY
cat >"$repo/scripts/ci/images/egress-image-tag.sh" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == fp-digest ]] || exit 64
[[ -n "${FAKE_FP_DIGEST:-}" ]] || exit 3
printf '%s\n' "$FAKE_FP_DIGEST"
MOCK
cat >"$repo/scripts/ci/images/verify-runtime-image-signatures.sh" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == --egress ]] || exit 64
printf '%s\n' "$2" >>"${FAKE_VERIFY_CALLS:?}"
[[ -n "${FAKE_SIGNED_SOURCES:-}" ]] || { echo 'no valid signature' >&2; exit 1; }
printf '%s\n' $FAKE_SIGNED_SOURCES
MOCK
chmod 0755 "$repo/scripts/ci/images/egress-image-tag.sh" "$repo/scripts/ci/images/verify-runtime-image-signatures.sh"
git -C "$repo" add -A
git -C "$repo" commit -qm 'egress component with no pin'
signed_source="$(git -C "$repo" rev-parse HEAD)"
printf 'later\n' >"$repo/later.txt"
git -C "$repo" add -A
git -C "$repo" commit -qm 'a later commit with the same egress inputs'
main_sha="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" remote add origin "$origin"
git -C "$repo" push -q origin main

mkdir -p "$work/bin"
cat >"$work/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${FAKE_CURL_CALLS:?}"
printf '\n' >>"$FAKE_CURL_CALLS"
output='' data='' url=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --data-binary) data="${2#@}"; shift 2 ;;
    --config|--header|--connect-timeout|--max-time) shift 2 ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  *'/pulls?state=open&page=1&limit=50') printf '%s\n' "${FAKE_OPEN_PULLS:-[]}" >"$output" ;;
  */pulls) cp "$data" "${FAKE_CREATED_BODY:?}"; printf '{"number":9}\n' >"$output" ;;
  *) exit 91 ;;
esac
MOCK
chmod 0755 "$work/bin/curl"

export FAKE_FINGERPRINTS="$work/fingerprints"
export FAKE_CURL_CALLS="$work/curl.calls"
export FAKE_VERIFY_CALLS="$work/verify.calls"
export FAKE_CREATED_BODY="$work/created.json"
printf '%s %s\n%s %s\n' "$main_sha" "$FINGERPRINT" "$signed_source" "$FINGERPRINT" >"$FAKE_FINGERPRINTS"

propose() {
  : >"$FAKE_CURL_CALLS"
  : >"$FAKE_VERIFY_CALLS"
  rm -f "$FAKE_CREATED_BODY"
  git -C "$repo" switch -q main
  git -C "$repo" reset -q --hard "$main_sha"
  PATH="$work/bin:$PATH" RUNNER_TEMP="$work" \
    GITHUB_SHA="${PROPOSE_SHA:-$main_sha}" GITHUB_REPOSITORY=codewire/codewire \
    GITHUB_SERVER_URL=https://forgejo.invalid WORKSPACE_PIN_BOT_TOKEN_FILE="$work/bot-token" \
    "$repo/scripts/ci/images/propose-egress-image-pin.sh"
}
remote_pin() {
  git -C "$repo" fetch -q origin automation/egress-image-pin 2>/dev/null || return 0
  git -C "$repo" show FETCH_HEAD:deployments/k8s/egress/kustomization.yaml | sed -n 's/^    digest: //p'
}

# A commit main has moved past proposes nothing.
PROPOSE_SHA="$signed_source" propose >"$work/moved.out"
grep -Fq 'its newest push proposes' "$work/moved.out" || fail 'an older commit proposed'

# No signed image of main's inputs yet: nothing to propose.
propose >"$work/none.out"
grep -Fq 'no signed image of fingerprint' "$work/none.out" || fail 'a missing signed image was not reported'
[[ ! -s "$FAKE_CURL_CALLS" && ! -s "$FAKE_VERIFY_CALLS" ]] || fail 'a missing signed image reached Forgejo or the verifier'

# A tag whose signature does not verify is refused, not proposed.
export FAKE_FP_DIGEST="$DIGEST"
if FAKE_SIGNED_SOURCES='' propose >"$work/unsigned.out" 2>"$work/unsigned.err"; then
  fail 'an image without a verified signature was proposed'
fi
grep -Fq 'no valid main-CI-verified signature' "$work/unsigned.err" || fail 'the unsigned refusal was not attributable'
[[ ! -s "$FAKE_CURL_CALLS" ]] || fail 'an unverified image reached Forgejo'

# A verified signature whose source main does not contain is refused.
foreign="$(printf '7%.0s' {1..40})"
if FAKE_SIGNED_SOURCES="$foreign" propose >/dev/null 2>"$work/foreign.err"; then
  fail 'an image signed from a source outside main was proposed'
fi
grep -Fq 'names a source on main with fingerprint' "$work/foreign.err" || fail 'the foreign-source refusal was not attributable'

# A source on main with other egress inputs is refused.
printf '%s %s\n%s %s\n' "$main_sha" "$FINGERPRINT" "$signed_source" "$OTHER_FINGERPRINT" >"$FAKE_FINGERPRINTS"
if FAKE_SIGNED_SOURCES="$signed_source" propose >/dev/null 2>&1; then
  fail 'an image signed from other egress inputs was proposed'
fi
printf '%s %s\n%s %s\n' "$main_sha" "$FINGERPRINT" "$signed_source" "$FINGERPRINT" >"$FAKE_FINGERPRINTS"

# A verified image of main's inputs is proposed: only the pin changes.
export FAKE_SIGNED_SOURCES="$foreign $signed_source"
propose >"$work/opened.out" 2>"$work/opened.err" || { cat "$work/opened.err" >&2; fail 'a verified image was not proposed'; }
grep -Fq 'opened proposal #9' "$work/opened.out" || fail 'no proposal was opened'
[[ "$(remote_pin)" == "$DIGEST" ]] || fail 'the proposal does not pin the verified digest'
changed="$(git -C "$repo" diff --name-only "$main_sha" FETCH_HEAD)"
[[ "$changed" == deployments/k8s/egress/kustomization.yaml ]] || fail "the proposal changed more than the pin: $changed"
[[ "$(git -C "$repo" log -1 --format='%an <%ae>' FETCH_HEAD)" == 'Codewire <hello@codewire.sh>' ]] ||
  fail 'the proposal was not committed as the bot'
jq -e --arg digest "$DIGEST" '.head == "automation/egress-image-pin" and .base == "main" and (.body | contains($digest))' \
  "$FAKE_CREATED_BODY" >/dev/null || fail 'the pull request does not name the branch and digest'

# An open proposal that already pins this digest is left to its CI.
FAKE_OPEN_PULLS='[{"head":{"ref":"automation/egress-image-pin"}}]' propose >"$work/open.out"
grep -Fq 'already pins' "$work/open.out" || fail 'an up-to-date open proposal was pushed again'

# Main already pinning the digest proposes nothing.
git -C "$repo" switch -q main
python3 "$repo/scripts/ci/images/egress-image-pin.py" render --digest "$DIGEST"
git -C "$repo" commit -qam 'pin the signed image'
main_sha="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" push -q origin main
printf '%s %s\n%s %s\n' "$main_sha" "$FINGERPRINT" "$signed_source" "$FINGERPRINT" >"$FAKE_FINGERPRINTS"
propose >"$work/pinned.out"
grep -Fq "main already pins $DIGEST" "$work/pinned.out" || fail 'a pinned digest was proposed again'

if grep -rqF "$TOKEN" "$work"/*.out "$work"/*.err "$FAKE_CURL_CALLS" 2>/dev/null; then
  fail 'the bot token reached arguments or output'
fi
printf '[test-propose-egress-image-pin] verified-only pin proposal passed\n'
