#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GATE="$ROOT/scripts/runtime/dev/hosted-interception-gate.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-hosted-interception-gate-tests.XXXXXX")"
chmod 0700 "$TEST_TMP"

readonly EMAIL="e2e@codewire.sh"

cleanup() { rm -rf -- "$TEST_TMP"; }
trap cleanup EXIT
fail() { printf 'hosted-interception-gate tests: %s\n' "$*" >&2; exit 1; }

# A cw that keeps the account's credentials, profiles and Sandboxes in JSON
# files, and answers the gate's two in-Sandbox commands with what a Dev
# Sandbox reports: MOCK_MODE picks a pass, a leaked canary, or a failed
# create. OpenAI's refusal names the last four characters of the OpenAI key
# the gate actually added, as OpenAI does.
make_fake_cw() {
  cat >"$1" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$MOCK_STATE/argv"
[[ "$1 $2" == '--server https://codewire-dev.sh' ]] || exit 90
shift 2
S="$MOCK_STATE"
new_id() { printf '%08x-0000-4000-8000-%012x\n' "$(wc -l <"$S/ids")" "$RANDOM"; printf 'x\n' >>"$S/ids"; }
save() { mv "$S/next.json" "$S/$1.json"; }
profile_ref() {
  if [[ "$1" == id:* ]]; then jq -r --arg id "${1#id:}" '.[] | select(.id == $id) | .id' "$S/profiles.json"
  else jq -r --arg name "$1" '.[] | select(.name == $name) | .id' "$S/profiles.json"; fi
}
case "$*" in
  'whoami --output json') jq -n --arg email "$MOCK_EMAIL" '{email: $email}' ;;
  'credentials --cloud list --output json') cat "$S/credentials.json" ;;
  'credentials --cloud profiles list --output json') cat "$S/profiles.json" ;;
  '--cloud ls --output json') cat "$S/sandboxes.json" ;;
  'credentials --cloud add '*' --name '*)
    provider="$4" name="${*: -1}" key="$(cat)"
    printf '%s %s\n' "$provider" "$key" >>"$S/keys"
    id="$(new_id)"
    jq --arg id "$id" --arg n "$name" --arg p "$provider" '. + [{id: $id, name: $n, provider: $p}]' \
      "$S/credentials.json" >"$S/next.json" && save credentials ;;
  'credentials --cloud --profile '*' set '*' id:'*)
    ref="$4" slot="$6" credential="${7#id:}"
    id="$(profile_ref "$ref")"
    if [[ -n "$id" ]]; then
      jq --arg id "$id" --arg s "$slot" --arg c "$credential" \
        'map(if .id == $id then .entries[$s] = $c else . end)' "$S/profiles.json" >"$S/next.json"
    else
      id="$(new_id)"
      jq --arg id "$id" --arg n "$ref" --arg s "$slot" --arg c "$credential" \
        '. + [{id: $id, name: $n, is_default: false, entries: {($s): $c}}]' "$S/profiles.json" >"$S/next.json"
    fi
    save profiles ;;
  'credentials --cloud --profile id:'*' delete --yes')
    jq --arg id "${4#id:}" 'map(select(.id != $id))' "$S/profiles.json" >"$S/next.json" && save profiles ;;
  'credentials --cloud delete id:'*' --yes')
    jq --arg id "${4#id:}" 'map(select(.id != $id))' "$S/credentials.json" >"$S/next.json" && save credentials ;;
  '--cloud create --name '*' --profile id:'*' --file '*' --ttl 30m --yes')
    [[ "$MOCK_MODE" != create_fails ]] || exit 1
    id="$(new_id)"
    jq --arg id "$id" --arg n "$4" --arg p "${6#id:}" '. + [{id: $id, name: $n, profile: $p}]' \
      "$S/sandboxes.json" >"$S/next.json" && save sandboxes ;;
  '--cloud info '*' --output json')
    jq --arg id "$3" '[.[] | select(.id == $id) | {source_selection: {credentials: {profile: ("platform:id:" + .profile)}}}]' \
      "$S/sandboxes.json" ;;
  '--cloud rm '*' --yes')
    jq --arg id "$3" 'map(select(.id != $id))' "$S/sandboxes.json" >"$S/next.json" && save sandboxes ;;
  'run --cloud --in '*' --name interception-gate -- sh -c '*)
    tail4="$(awk '$1 == "openai" {print substr($2, length($2) - 3)}' "$S/keys")"
    canary=0; [[ "$MOCK_MODE" != leak ]] || canary=1
    cat <<REPORT
ca_certs=1
ca_der_sha256=0000000000000000000000000000000000000000000000000000000000000000
node_extra_ca_named=1
key_is_placeholder=1
key_is_canary=$canary
base_url_set=0
system_store_http=000
front_door_ready_after_s=0 front_door_first_attempt_http=403 front_door_first_http=403
placeholder_http=401 placeholder_error_type=authentication_error placeholder_rid=11111111-1111-4111-8111-111111111111 placeholder_refusal=none
madeup_http=403 madeup_error_type=unparsed madeup_rid=22222222-2222-4222-8222-222222222222 madeup_refusal=selected_credential_only
openai_key_managed=1 openai_base_loopback=1
openai_http=401 openai_error_code=invalid_api_key openai_echo_tail=$tail4
claude_rc=1 claude_lines=2 claude_auth_errors=1 claude_tls_errors=0
REPORT
    ;;
  'exec --in '*' -- sudo -n sh -c '*)
    cat >"$S/scan-stdin"
    printf 'scan_rc=0\ncanary_found=0\ncontrol_in_file=1\ncontrol_in_environ=1\ncontrol_in_cmdline=1\nscan_error_detail=\n' ;;
  *) printf 'unexpected cw call: %s\n' "$*" >&2; exit 91 ;;
esac
FAKE
  chmod 0700 "$1"
}

# A fresh account: its own default profile and nothing else.
new_state() {
  local state="$TEST_TMP/$1"
  mkdir -m 0700 "$state" "$state/run" "$state/run/cw"
  : >"$state/argv"; : >"$state/ids"; : >"$state/keys"
  printf '[]\n' >"$state/credentials.json"
  printf '[]\n' >"$state/sandboxes.json"
  printf '[{"id":"d3318812-49be-4e8c-8323-8a6ffe21b120","name":"me","is_default":true,"entries":{}}]\n' >"$state/profiles.json"
  make_fake_cw "$state/cw"
  printf '%s\n' "$state"
}

# run_gate STATE MODE [ENV...]: the gate's exit status; its output in STATE/out.
run_gate() {
  local state="$1" mode="$2" status=0
  shift 2
  env -i PATH="$PATH" HOME="$state" XDG_RUNTIME_DIR="$state/run" CW_CONFIG_DIR="$state/run/cw" \
    CODEWIRE_SERVER_URL=https://codewire-dev.sh CW_BIN="$state/cw" GATE_EXPECTED_EMAIL="$EMAIL" \
    MOCK_STATE="$state" MOCK_MODE="$mode" MOCK_EMAIL="$EMAIL" "$@" \
    bash "$GATE" >"$state/out" 2>&1 || status=$?
  return "$status"
}

# Nothing but the account's own default profile is left.
assert_clean() {
  local state="$1"
  [[ "$(jq length "$state/credentials.json")" == 0 ]] || fail "$2: a credential is left"
  [[ "$(jq length "$state/sandboxes.json")" == 0 ]] || fail "$2: a Sandbox is left"
  [[ "$(jq -c '[.[].name]' "$state/profiles.json")" == '["me"]' ]] || fail "$2: a profile is left"
}

# No key the gate added appears in its output or on any argv.
assert_no_value() {
  local state="$1" key
  while read -r _ key; do
    grep -qF -- "$key" "$state/out" && fail "$2: a key is printed"
    grep -qF -- "$key" "$state/argv" && fail "$2: a key is on argv"
  done <"$state/keys"
  return 0
}

state="$(new_state pass)"
run_gate "$state" pass || { cat "$state/out" >&2; fail 'a passing Sandbox fails the gate'; }
grep -q 'PASS run=' "$state/out" || fail 'a pass does not say so'
grep -q 'ok   OpenAI refused the gate' "$state/out" || fail "OpenAI's echo is not checked"
[[ "$(awk '{print $1}' "$state/keys" | sort | tr '\n' ' ')" == 'anthropic openai ' ]] || fail 'the two synthetic keys are not added'
grep -q 'CWCANARY-INTERCEPTION-GATE-' "$state/keys" || fail 'the keys are not canary-marked'
[[ "$(wc -l <"$state/scan-stdin")" == 2 ]] || fail 'the scan does not get both canaries on stdin'
assert_clean "$state" pass
assert_no_value "$state" pass

state="$(new_state leak)"
if run_gate "$state" leak; then fail 'a canary in the Sandbox passes the gate'; fi
grep -q 'FAIL key_is_canary=1' "$state/out" || fail 'a leaked canary is not named'
assert_clean "$state" leak
assert_no_value "$state" leak

state="$(new_state create)"
if run_gate "$state" create_fails; then fail 'a failed create passes the gate'; fi
assert_clean "$state" create_fails

state="$(new_state origin)"
if run_gate "$state" pass CODEWIRE_SERVER_URL=https://codewire.sh; then fail 'a non-Dev origin is accepted'; fi
grep -q 'Dev only' "$state/out" || fail 'a non-Dev origin is not named'
[[ ! -s "$state/argv" ]] || fail 'cw ran against a non-Dev origin'

state="$(new_state identity)"
if run_gate "$state" pass GATE_EXPECTED_EMAIL=someone@example.com; then fail 'a non-test identity is accepted'; fi
[[ ! -s "$state/argv" ]] || fail 'cw ran for a non-test identity'

state="$(new_state signed-in)"
if run_gate "$state" pass MOCK_EMAIL=someone@example.com; then fail 'a sign-in as another account is accepted'; fi
[[ "$(jq length "$state/credentials.json")" == 0 ]] || fail 'the gate added a credential as another account'

state="$(new_state tracing)"
status=0
env -i PATH="$PATH" HOME="$state" XDG_RUNTIME_DIR="$state/run" CW_CONFIG_DIR="$state/run/cw" \
  CODEWIRE_SERVER_URL=https://codewire-dev.sh CW_BIN="$state/cw" GATE_EXPECTED_EMAIL="$EMAIL" \
  MOCK_STATE="$state" MOCK_MODE=pass MOCK_EMAIL="$EMAIL" bash -x "$GATE" >"$state/out" 2>&1 || status=$?
[[ "$status" != 0 ]] || fail 'shell tracing is accepted'
[[ ! -s "$state/argv" ]] || fail 'cw ran under shell tracing'

echo 'hosted-interception-gate tests: passed'
