#!/usr/bin/env bash
# Synthetic proof for the Homebrew tap dispatch: it starts the tap's
# update-formula.yml for the tag on main, waits for that one run, passes only
# when it succeeds, says the tap is behind otherwise, and keeps the token out
# of arguments and output.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly DISPATCH="$ROOT/scripts/ci/release/dispatch-homebrew-tap.sh"
CASES=0

fail() {
  printf '[test-dispatch-homebrew-tap] ERROR: %s\n' "$*" >&2
  exit 1
}
pass() { CASES=$((CASES + 1)); }

work="$(mktemp -d "${TMPDIR:-/tmp}/dispatch-homebrew-tap.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/runner"
readonly TOKEN='synthetic-tap-installation-token-0123456789'
printf '%s\n' "$TOKEN" >"$work/token"
chmod 0600 "$work/token"

# The fake GitHub: the dispatch answers FAKE_DISPATCH (a file), and each read
# of the run answers the next status from FAKE_STATUSES, "STATUS:CONCLUSION".
cat >"$work/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${FAKE_CURL_CALLS:?}"
printf '\n' >>"$FAKE_CURL_CALLS"
output='' data='' url='' method=GET config=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --config) config="$2"; shift 2 ;;
    --data-binary) data="${2#@}"; shift 2 ;;
    --request) method="$2"; shift 2 ;;
    --header|--connect-timeout|--max-time) shift 2 ;;
    *) url="$1"; shift ;;
  esac
done
grep -Fq "Authorization: Bearer ${FAKE_TOKEN:?}" "$config" || exit 92
case "$method $url" in
  'POST https://api.github.com/repos/codewiresh/homebrew-codewire/actions/workflows/update-formula.yml/dispatches')
    cp "$data" "${FAKE_DISPATCH_BODY:?}"
    [[ -n "${FAKE_DISPATCH:-}" ]] || exit 22
    cp "$FAKE_DISPATCH" "$output" ;;
  'GET https://api.github.com/repos/codewiresh/homebrew-codewire/actions/runs/4242')
    count=$(($(cat "$FAKE_POLLS" 2>/dev/null || echo 0) + 1))
    printf '%s' "$count" >"$FAKE_POLLS"
    read -ra statuses <<<"${FAKE_STATUSES:?}"
    index=$((count <= ${#statuses[@]} ? count - 1 : ${#statuses[@]} - 1))
    jq -n --arg status "${statuses[$index]%%:*}" --arg conclusion "${statuses[$index]#*:}" \
      '{id: 4242, status: $status, conclusion: (if $conclusion == "" then null else $conclusion end)}' >"$output" ;;
  *) exit 91 ;;
esac
MOCK
chmod +x "$work/bin/curl"
printf '{"workflow_run_id":4242,"run_url":"https://api.github.invalid/x","html_url":"https://github.invalid/run/4242"}\n' \
  >"$work/dispatched.json"

# dispatch TAG [NAME=VALUE...]: run the dispatch with extra environment.
dispatch() {
  local tag="$1"
  shift
  rm -f "$work/polls" "$work/body.json"
  env PATH="$work/bin:$PATH" RUNNER_TEMP="$work/runner" HOMEBREW_TAP_TOKEN_FILE="$work/token" \
    HOMEBREW_TAP_POLL_SECONDS=0 HOMEBREW_TAP_WAIT_SECONDS=5 \
    FAKE_TOKEN="$TOKEN" FAKE_CURL_CALLS="$work/curl-calls" FAKE_POLLS="$work/polls" \
    FAKE_DISPATCH="$work/dispatched.json" FAKE_DISPATCH_BODY="$work/body.json" \
    FAKE_STATUSES='queued: in_progress: completed:success' "$@" \
    "$DISPATCH" "$tag"
}

# A run that succeeds: the dispatch names main and the tag, the script waits
# through queued and in progress, and passes.
: >"$work/curl-calls"
dispatch v0.4.25 >"$work/ok.out" 2>&1 || fail "a successful tap run failed: $(cat "$work/ok.out")"
jq -e '. == {ref: "main", inputs: {version: "v0.4.25"}}' "$work/body.json" >/dev/null ||
  fail "the dispatch is not main with the tag: $(cat "$work/body.json")"
[[ "$(cat "$work/polls")" == 3 ]] || fail 'the script did not wait for the run to complete'
grep -Fq 'the tap moved its formula to v0.4.25 in run 4242' "$work/ok.out" || fail 'success was not reported'
if grep -rqF "$TOKEN" "$work/curl-calls" "$work/ok.out"; then
  fail 'the token reached curl arguments or output'
fi
[[ -z "$(find "$work/runner" -mindepth 1 -print -quit)" ]] || fail 'the curl config survived cleanup'
pass

# The token goes only to GitHub's API: the fake answers no other host, and an
# environment naming another one changes nothing.
dispatch v0.4.25 HOMEBREW_TAP_API=https://elsewhere.invalid >"$work/host.out" 2>&1 ||
  fail "an environment moved the API host: $(cat "$work/host.out")"
pass

# Every other ending fails and says the tap is behind, naming the run.
expect_behind() {
  local name="$1" expected="$2"
  shift 2
  if dispatch v0.4.25 "$@" >"$work/$name.out" 2>&1; then
    fail "$name passed"
  fi
  if ! grep -Fq 'the Homebrew tap is behind' "$work/$name.out" || ! grep -Fq "$expected" "$work/$name.out"; then
    fail "$name did not say the tap is behind: $(cat "$work/$name.out")"
  fi
  grep -Fq 'The release is published' "$work/$name.out" || fail "$name did not say the release is published"
  pass
}
expect_behind run-failed 'its run 4242 for v0.4.25 ended failure' FAKE_STATUSES='in_progress: completed:failure'
expect_behind run-cancelled 'ended cancelled' FAKE_STATUSES='completed:cancelled'
expect_behind run-timeout 'had not finished after 0s' FAKE_STATUSES='in_progress:' HOMEBREW_TAP_WAIT_SECONDS=0
expect_behind dispatch-refused 'dispatching its update-formula.yml failed' FAKE_DISPATCH=
printf '{"run_url":"x"}\n' >"$work/no-run.json"
expect_behind no-run 'GitHub named no run' FAKE_DISPATCH="$work/no-run.json"

# Refusals before any request: a malformed tag, and a token file that is
# missing, a link or readable by others.
expect_refusal() {
  local name="$1" expected="$2" tag="$3"
  shift 3
  : >"$work/curl-calls"
  if dispatch "$tag" "$@" >"$work/$name.out" 2>&1; then
    fail "$name was not refused"
  fi
  grep -Fq "$expected" "$work/$name.out" || fail "$name was refused for another reason: $(cat "$work/$name.out")"
  [[ ! -s "$work/curl-calls" ]] || fail "$name reached a request"
  pass
}
expect_refusal bad-tag 'is not vMAJOR.MINOR.PATCH' 'v0.4.25;x'
expect_refusal missing-token 'one nonempty regular file' v0.4.25 HOMEBREW_TAP_TOKEN_FILE="$work/absent"
ln -s "$work/token" "$work/token-link"
expect_refusal linked-token 'one nonempty regular file' v0.4.25 HOMEBREW_TAP_TOKEN_FILE="$work/token-link"
cp "$work/token" "$work/open-token"
chmod 0644 "$work/open-token"
expect_refusal open-token 'mode 0400 or 0600' v0.4.25 HOMEBREW_TAP_TOKEN_FILE="$work/open-token"

printf '[test-dispatch-homebrew-tap] %d cases passed\n' "$CASES"
