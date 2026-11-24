#!/usr/bin/env bash
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR CODEWIRE_SERVER_URL  # the tests exercise the script defaults

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HELPER="$ROOT/scripts/runtime/dev/with-dev-personal-walk.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-dev-personal-walk-auth-tests.XXXXXX")"
chmod 0700 "$TEST_TMP"
# The helper refuses a runtime directory that is not on tmpfs, so each case's
# stands in under /dev/shm.
[[ "$(stat -f -c %T /dev/shm 2>/dev/null)" == tmpfs ]] ||
  { printf 'with-dev-personal-walk tests: /dev/shm is not tmpfs\n' >&2; exit 1; }
SHM_TMP="$(mktemp -d /dev/shm/codewire-personal-walk-tests.XXXXXX)"
chmod 0700 "$SHM_TMP"

readonly EMAIL="success+codewire-dev-personal-walk@simulator.amazonses.com"
readonly PASSWORD="SyntheticPersonalWalkPassword0123456789abcd"
readonly BAO_TOKEN_FIXTURE="synthetic-bao-token-6074"

cleanup() { rm -rf -- "$TEST_TMP" "$SHM_TMP"; }
trap cleanup EXIT
fail() { printf 'with-dev-personal-walk tests: %s\n' "$*" >&2; exit 1; }

make_fake_tools() {
  local bin="$1"
  mkdir -p "$bin"

  cat >"$bin/bao" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf 'bao %s\n' "$*" >>"$MOCK_STATE/argv"
[[ "$*" == "kv get -format=json $MOCK_BAO_PATH" ]] || exit 90
[[ "${BAO_ADDR:-}" == https://openbao.example.invalid && "${BAO_TOKEN:-}" == synthetic-bao-token-6074 ]] || exit 91
printf 'bao-read\n' >>"$MOCK_STATE/events"
password="$(cat "$MOCK_STATE/password")"
case "$MOCK_MODE" in
  missing) printf 'No value found at %s\n' "${MOCK_BAO_PATH/codewire\//data/codewire/}" >&2; exit 2 ;;
  permission) printf 'permission denied (status code: 403)\n' >&2; exit 2 ;;
  extra_field) jq -n --arg password "$password" --arg email "$EMAIL" \
    '{data: {metadata: {version: 2}, data: {password: $password, userEmail: $email, apiKey: "cw_x"}}}' ;;
  wrong_email) jq -n --arg password "$password" \
    '{data: {metadata: {version: 2}, data: {password: $password, userEmail: "person@example.test"}}}' ;;
  bad_password) jq -n --arg email "$EMAIL" \
    '{data: {metadata: {version: 2}, data: {password: "short", userEmail: $email}}}' ;;
  not_json) printf 'not json\n' ;;
  *) jq -n --arg password "$password" --arg email "$EMAIL" \
    '{data: {metadata: {version: 2}, data: {password: $password, userEmail: $email}}}' ;;
esac
FAKE

  cat >"$bin/../access" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == 'bao human' ]] || exit 95
printf 'token\n' >>"$MOCK_STATE/tokens"
printf '%s' 'synthetic-bao-token-6074' >&3
FAKE

  # Dev's HTTP surface: the OpenBao token revocation, the password sign-in and
  # device approval, and the OAuth introspection and revocation of the CLI
  # sign-in's tokens, which live in $MOCK_STATE/active. Each password sign-in
  # mints a session token (in $MOCK_STATE/minted); the live ones are in
  # $MOCK_STATE/sessions, and a call's session is the cookie in its -b jar.
  cat >"$bin/curl" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf 'curl %s\n' "$*" >>"$MOCK_STATE/argv"
url="" output="" write_out="" jar_out="" jar_in="" body="" token_file="" header_file="" hint=""
declare -A form=()
while (($# > 0)); do
  case "$1" in
    --url) url="$2"; shift 2 ;;
    -o|--output) output="$2"; shift 2 ;;
    -w|--write-out) write_out="$2"; shift 2 ;;
    -c) jar_out="$2"; shift 2 ;;
    -b) jar_in="$2"; shift 2 ;;
    --max-time|--connect-timeout|--retry|--max-redirs|--proto|--noproxy|--request|-X|-H) shift 2 ;;
    --header) header_file="${2#@}"; shift 2 ;;
    --data) body="$2"; shift 2 ;;
    --data-urlencode)
      case "$2" in
        token@*) token_file="${2#token@}" ;;
        token_type_hint=*) hint="${2#*=}" ;;
        *=*) form["${2%%=*}"]="${2#*=}" ;;
      esac
      shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
respond() { if [[ -n "$output" ]]; then printf '%s' "$1" >"$output"; else printf '%s' "$1"; fi; }
code() { [[ -z "$write_out" ]] || printf '%s' "$1"; }
active() { grep -qxF -- "$1" "$MOCK_STATE/active" 2>/dev/null; }
session_of() {
  [[ -n "$jar_in" && -f "$jar_in" ]] || return 0
  awk -F '\t' '$6 == "codewire.session_token" { print $7 }' "$jar_in" | tail -1
}
live() { [[ -n "$1" ]] && grep -qxF -- "$1" "$MOCK_STATE/sessions" 2>/dev/null; }
case "$url" in
  https://openbao.example.invalid/v1/auth/token/revoke-self)
    [[ "$(<"$header_file")" == 'X-Vault-Token: synthetic-bao-token-6074' ]] || exit 97
    printf 'revoke\n' >>"$MOCK_STATE/revokes"
    printf 'bao-revoke\n' >>"$MOCK_STATE/events"
    if [[ "$MOCK_MODE" == bao_revoke_refused ]]; then printf '403'; else printf '204'; fi ;;
  https://codewire-dev.sh/api/auth/sign-in)
    [[ "$body" == @- ]] || exit 98
    sent="$(cat)"
    jq -e --arg email "$EMAIL" --rawfile password "$MOCK_STATE/password" \
      '.email == $email and .password == $password' <<<"$sent" >/dev/null || exit 99
    # While the password is in flight, it is in exactly one file, 0600.
    find "$XDG_RUNTIME_DIR" "$TMPDIR" "$HOME" -type f -print0 2>/dev/null |
      xargs -0 -r grep -lF -- "$(cat "$MOCK_STATE/password")" >"$MOCK_STATE/password-files" || true
    while IFS= read -r file; do stat -c '%a' "$file"; done <"$MOCK_STATE/password-files" \
      >"$MOCK_STATE/password-file-modes"
    printf 'sign-in\n' >>"$MOCK_STATE/events"
    token="session-$(($(wc -l <"$MOCK_STATE/minted") + 1))"
    printf '%s\n' "$token" >>"$MOCK_STATE/minted"
    printf '%s\n' "$token" >>"$MOCK_STATE/sessions"
    printf '#HttpOnly_codewire-dev.sh\tFALSE\t/\tTRUE\t1795600000\tcodewire.session_token\t%s\n' \
      "$token" >"$jar_out"
    code 200 ;;
  https://codewire-dev.sh/api/auth/two-factor/skip-setup)
    token="$(session_of)"
    live "$token" || exit 104
    if [[ "$token" == session-1 ]]; then printf 'skip-setup\n' >>"$MOCK_STATE/events"
    else printf 'skip-setup %s\n' "$token" >>"$MOCK_STATE/events"; fi
    code 200 ;;
  'https://codewire-dev.sh/device?user_code=ABCDEFGH')
    printf 'device-page\n' >>"$MOCK_STATE/events"
    respond '<form><input type="hidden" name="_csrf" value="csrf-1"></form>' ;;
  https://codewire-dev.sh/device/_actions/approve)
    [[ "${form[_csrf]:-}" == csrf-1 && "${form[user_code_1]:-}" == A && "${form[user_code_8]:-}" == H ]] || exit 100
    printf 'approve\n' >>"$MOCK_STATE/events"
    : >"$MOCK_STATE/approved"
    respond 'approved' ;;
  https://codewire-dev.sh/api/auth/sign-out)
    token="$(session_of)"
    if [[ "$token" == session-1 ]]; then printf 'browser-sign-out\n' >>"$MOCK_STATE/events"
    else printf 'sign-out %s\n' "$token" >>"$MOCK_STATE/events"; fi
    if [[ "$MOCK_MODE" != browser_sign_out_ignored || "$token" == session-1 ]]; then
      grep -vxF -- "$token" "$MOCK_STATE/sessions" >"$MOCK_STATE/sessions.next" || true
      mv "$MOCK_STATE/sessions.next" "$MOCK_STATE/sessions"
    fi ;;
  https://codewire-dev.sh/api/auth/get-session)
    token="$(session_of)"
    email="$EMAIL"
    [[ "$MOCK_MODE" != browser_wrong_identity || "$token" == session-1 ]] || email=someone@example.test
    if live "$token"; then
      respond "$(jq -cn --arg email "$email" --arg id "sid${token#session}" '{user: {email: $email}, session: {id: $id}}')"
    else respond null; fi ;;
  https://codewire-dev.sh/api/oauth/introspect)
    [[ "${form[client_id]:-}" == codewire-cli && -n "$hint" ]] || exit 101
    token="$(cat "$token_file")"
    printf 'introspect %s\n' "$token" >>"$MOCK_STATE/events"
    if active "$token"; then respond '{"active":true}'; else respond '{"active":false}'; fi ;;
  https://codewire-dev.sh/api/oauth/revoke)
    [[ "${form[client_id]:-}" == codewire-cli ]] || exit 102
    token="$(cat "$token_file")"
    printf 'revoke %s\n' "$token" >>"$MOCK_STATE/events"
    if [[ "$MOCK_MODE" != revoke_ignored ]]; then
      grep -vxF -- "$token" "$MOCK_STATE/active" >"$MOCK_STATE/active.next" || true
      mv "$MOCK_STATE/active.next" "$MOCK_STATE/active"
    fi
    code 200 ;;
  *) printf 'unexpected curl url %s\n' "$url" >&2; exit 103 ;;
esac
FAKE

  # cw: login prints its code and waits for the approval, then saves a token
  # pair; refresh rotates it as the server does (the old access token lives on
  # until it expires); logout revokes the saved pair unless told not to.
  cat >"$bin/cw" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf 'cw %s\n' "$*" >>"$MOCK_STATE/argv"
[[ "${1:-}" != version ]] || { printf 'cw 0.0.0-test\n'; exit 0; }
[[ "$1 $2" == '--server https://codewire-dev.sh' ]] || exit 110
save() {
  jq -n --arg a "$1" --arg r "$2" '{issuer: "https://codewire-dev.sh", client_id: "codewire-cli",
    access_token: $a, refresh_token: $r, expires_at_unix: 1, scope: "openid"}' >"$CW_CONFIG_DIR/credentials.json"
  printf '%s\n%s\n' "$1" "$2" >>"$MOCK_STATE/active"
}
case "$3" in
  login)
    printf 'cw-login\n' >>"$MOCK_STATE/events"
    printf '%s %s\n' "$CW_CONFIG_DIR" "$(stat -c '%a' "$CW_CONFIG_DIR")" >"$MOCK_STATE/login-config"
    printf "If browser doesn't open, visit: https://codewire-dev.sh/device\nYour code: ABCD-EFGH\n"
    for _ in $(seq 1 200); do [[ -e "$MOCK_STATE/approved" ]] && break; sleep 0.05; done
    [[ -e "$MOCK_STATE/approved" ]] || exit 1
    save at-1 rt-1
    printf 'Logged in as Codewire Dev personal walk.\n' ;;
  refresh)
    grep -vxF rt-1 "$MOCK_STATE/active" >"$MOCK_STATE/active.next" || true
    mv "$MOCK_STATE/active.next" "$MOCK_STATE/active"
    save at-2 rt-2 ;;
  whoami)
    printf 'cw-whoami\n' >>"$MOCK_STATE/events"
    if [[ "$MOCK_MODE" == wrong_account ]]; then printf '{"email":"someone@example.test"}\n'
    else jq -n --arg email "$EMAIL" '{email: $email}'; fi ;;
  logout)
    printf 'cw-logout\n' >>"$MOCK_STATE/events"
    if [[ "$MOCK_MODE" == logout_unconfirmed || "$MOCK_MODE" == revoke_ignored ]]; then
      rm -f "$CW_CONFIG_DIR/credentials.json"
      printf 'Removed the sign-in from this machine, but the server did not confirm it ended.\n' >&2
      exit 1
    fi
    for token in $(jq -r '.access_token, .refresh_token' "$CW_CONFIG_DIR/credentials.json"); do
      grep -vxF -- "$token" "$MOCK_STATE/active" >"$MOCK_STATE/active.next" || true
      mv "$MOCK_STATE/active.next" "$MOCK_STATE/active"
    done
    rm -f "$CW_CONFIG_DIR/credentials.json"
    printf 'Logged out; the server ended this sign-in.\n' >&2 ;;
  *) exit 111 ;;
esac
FAKE
  chmod 0755 "$bin"/* "$bin/../access"
}

make_child() {
  cat >"$1" <<'CHILD'
#!/usr/bin/env bash
set -euo pipefail
printf 'child\n' >>"$MOCK_STATE/events"
env >"$MOCK_STATE/child.env"
[[ "$CODEWIRE_SERVER_URL" == https://codewire-dev.sh ]]
[[ "$EXPECTED_PERSONAL_WALK_USER_EMAIL" == "$MOCK_EMAIL" ]]
[[ "$CW_BIN" == */bin/cw ]]
# The sign-in lives in a private 0700 folder on the tmpfs runtime directory.
[[ "$CW_CONFIG_DIR" == "$XDG_RUNTIME_DIR"/codewire-personal-walk.*/cw-config ]]
[[ "$(stat -c '%a' "$CW_CONFIG_DIR")" == 700 && -f "$CW_CONFIG_DIR/credentials.json" ]]
[[ "$(stat -c '%a' "$(dirname "$CW_CONFIG_DIR")")" == 700 ]]
[[ "$CODEWIRE_NATIVE_STATE_ROOT" == "$(dirname "$CW_CONFIG_DIR")"/no-local-vm-state && ! -e "$CODEWIRE_NATIVE_STATE_ROOT" ]]
# None of the caller's cw or OpenBao environment.
bao_names=( "${!BAO_@}" )
[[ "${#bao_names[@]}" == 0 ]]
for name in VAULT_TOKEN CODEWIRE_API_KEY CODEWIRE_ORG CODEWIRE_ACCESS_CLIENT \
  CODEWIRE_DEV_SMOKE_API_KEY CODEWIRE_MESH_AUTH_TOKEN CW_MESH_DATA_DIR; do
  [[ -z "${!name+x}" ]]
done
# The password file is already gone.
[[ ! -e "$(dirname "$CW_CONFIG_DIR")/private/document.json" ]]
[[ "${MOCK_MODE:-}" != refresh_in_child ]] || "$CW_BIN" --server "$CODEWIRE_SERVER_URL" refresh
# Browser sessions: one 0600 storage state per session, each holding only its
# live session's cookie for the Dev origin.
if [[ "${MOCK_BROWSER_SESSIONS:-0}" -gt 0 ]]; then
  IFS=: read -r -a states <<<"$PERSONAL_WALK_BROWSER_STORAGE_STATES"
  [[ "${#states[@]}" == "$MOCK_BROWSER_SESSIONS" ]]
  for state in "${states[@]}"; do
    [[ "$state" == "$(dirname "$CW_CONFIG_DIR")"/browser/state-*.json ]]
    [[ "$(stat -c '%a' "$state")" == 600 ]]
    token="$(jq -er '.origins == [] and (.cookies | length == 1) and .cookies[0].name == "codewire.session_token"
      and .cookies[0].domain == "codewire-dev.sh" and .cookies[0].httpOnly and .cookies[0].secure
      | if . then "ok" else error("shape") end' "$state")"
    token="$(jq -r '.cookies[0].value' "$state")"
    grep -qxF -- "$token" "$MOCK_STATE/sessions"
  done
  case "${MOCK_MODE:-}" in
    browser_writeback)
      # The browser's final state: another session for the Dev origin, one for
      # another host, and page storage.
      printf 'session-extra\n' | tee -a "$MOCK_STATE/minted" >>"$MOCK_STATE/sessions"
      jq '.cookies += [.cookies[0] + {value: "session-extra"}, .cookies[0] + {domain: "example.test", value: "other-host"}]
        | .origins = [{origin: "https://codewire-dev.sh", localStorage: [{name: "k", value: "v"}]}]' \
        "${states[0]}" >"${states[0]}.next"
      mv "${states[0]}.next" "${states[0]}" ;;
    browser_bad_state) printf 'not json\n' >"${states[0]}" ;;
    browser_term) kill -TERM "$PPID" ;;
  esac
fi
printf 'child-ran\n'
exit "${MOCK_CHILD_STATUS:-0}"
CHILD
  chmod 0755 "$1"
}

# run_case NAME MODE EXPECT_STATUS [HELPER ARGS...]: the helper's exit status
# must be EXPECT_STATUS. Leaves the case folder in $CASE.
run_case() {
  local name="$1" mode="$2" expect="$3"; shift 3
  CASE="$TEST_TMP/$name"
  RUNTIME="$SHM_TMP/$name"
  mkdir -p "$CASE/state" "$CASE/tmp" "$CASE/home"
  mkdir -m 0700 "$RUNTIME"
  printf '%s' "$PASSWORD" >"$CASE/state/password"
  : >"$CASE/state/events"
  : >"$CASE/state/argv"
  : >"$CASE/state/tokens"
  : >"$CASE/state/revokes"
  : >"$CASE/state/active"
  : >"$CASE/state/minted"
  : >"$CASE/state/sessions"
  make_fake_tools "$CASE/bin"
  make_child "$CASE/child"
  local status=0
  [[ -n "${NO_COMMAND:-}" ]] || set -- "$@" -- "$CASE/child"
  env -i PATH="$CASE/bin:$PATH" HOME="$CASE/home" TMPDIR="$CASE/tmp" \
    XDG_RUNTIME_DIR="${CASE_RUNTIME:-$RUNTIME}" MOCK_STATE="$CASE/state" MOCK_MODE="$mode" \
    MOCK_EMAIL="${IDENTITY_EMAIL:-$EMAIL}" EMAIL="${IDENTITY_EMAIL:-$EMAIL}" \
    MOCK_BAO_PATH="${IDENTITY_PATH:-apps/codewire/dev/ci-personal-walk}" MOCK_CHILD_STATUS="${CHILD_STATUS:-0}" \
    MOCK_BROWSER_SESSIONS="${BROWSER:-0}" \
    CW_BIN="$CASE/bin/cw" CODEWIRE_ACCESS_CLIENT="$CASE/access" \
    ${SERVER_URL:+CODEWIRE_SERVER_URL="$SERVER_URL"} \
    BAO_ADDR=https://openbao.example.invalid BAO_TOKEN=stale-owner-token VAULT_TOKEN=stale \
    CODEWIRE_API_KEY=cw_owner CODEWIRE_ORG=owner-org CODEWIRE_DEV_SMOKE_API_KEY=cw_smoke \
    CODEWIRE_MESH_AUTH_TOKEN=owner-mesh CW_MESH_DATA_DIR="$CASE/owner-mesh" \
    CW_CONFIG_DIR="$CASE/owner-cw" \
    bash "$HELPER" "$@" <"${STDIN_FILE:-/dev/null}" >"$CASE/out" 2>"$CASE/err" || status=$?
  [[ "$status" == "$expect" ]] ||
    { cat "$CASE/out" "$CASE/err" >&2; fail "$name: exit $status, want $expect"; }
  # The password never reaches output, argv, the child's environment or any
  # file left behind.
  local file
  for file in "$CASE/out" "$CASE/err" "$CASE/state/argv" "$CASE/state/events"; do
    ! grep -qF -- "$PASSWORD" "$file" || fail "$name: the password reached $(basename "$file")"
  done
  [[ ! -f "$CASE/state/child.env" ]] || ! grep -qF -- "$PASSWORD" "$CASE/state/child.env" ||
    fail "$name: the password reached the child's environment"
  ! grep -rqF -- "$PASSWORD" "$RUNTIME" "$CASE/tmp" "$CASE/home" || fail "$name: the password was left in a file"
  ! grep -qF -- "$BAO_TOKEN_FIXTURE" "$CASE/out" "$CASE/err" || fail "$name: the OpenBao token reached output"
  # No session token reaches argv, output or the child's environment either.
  local token
  while IFS= read -r token; do
    for file in "$CASE/out" "$CASE/err" "$CASE/state/argv"; do
      ! grep -qF -- "$token" "$file" || fail "$name: session token $token reached $(basename "$file")"
    done
    [[ ! -f "$CASE/state/child.env" ]] || ! grep -qF -- "$token" "$CASE/state/child.env" ||
      fail "$name: session token $token reached the child's environment"
  done <"$CASE/state/minted"
  # Every OpenBao token issued was revoked, and nothing is left behind.
  [[ "$(wc -l <"$CASE/state/revokes")" == "$(wc -l <"$CASE/state/tokens")" ]] ||
    fail "$name: an OpenBao token was left unrevoked"
  [[ -z "$(find "$RUNTIME" "$CASE/tmp" -mindepth 1 -print -quit)" ]] || fail "$name: left private files"
}

expect_events() {
  local want="$1"
  [[ "$(cat "$CASE/state/events")" == "$want" ]] ||
    fail "$(basename "$CASE"): events were [$(tr '\n' ',' <"$CASE/state/events")], want [$(tr '\n' ',' <<<"$want")]"
}
expect_err() {
  grep -qF -- "$1" "$CASE/err" || { cat "$CASE/err" >&2; fail "$(basename "$CASE"): stderr lacks: $1"; }
}
expect_no_grant() {
  [[ ! -s "$CASE/state/active" ]] || fail "$(basename "$CASE"): a CLI sign-in token is still active"
}
expect_password_in_one_file() {
  [[ "$(cat "$CASE/state/password-file-modes")" == 600 ]] ||
    fail "$(basename "$CASE"): while signing in the password was in files with modes [$(tr '\n' ',' <"$CASE/state/password-file-modes")], want one 0600 file"
}
readonly SIGN_IN=$'bao-read\nbao-revoke\ncw-login\nsign-in\nskip-setup\ndevice-page\napprove\nbrowser-sign-out\ncw-whoami'
readonly CHECKED=$'cw-logout\nintrospect at-1\nintrospect rt-1\nintrospect at-1\nintrospect rt-1'

run_case success success 0
expect_events "$SIGN_IN"$'\nchild\n'"$CHECKED"
expect_password_in_one_file
expect_no_grant
grep -qx 'child-ran' "$CASE/out" || fail 'success: the child did not run'
expect_err 'PASS cli_sign_in_ended=true logout=confirmed revoked_by_token=0'
read -r config mode <"$CASE/state/login-config"
[[ "$config" == "$RUNTIME"/codewire-personal-walk.*/cw-config && "$mode" == 700 ]] ||
  fail 'success: cw login did not use a private 0700 folder on the runtime directory'

# The child's failure is the helper's, and the sign-in still ends.
CHILD_STATUS=7 run_case child_fails success 7
expect_events "$SIGN_IN"$'\nchild\n'"$CHECKED"
expect_no_grant
expect_err 'the command exited 7'
expect_err 'PASS cli_sign_in_ended=true logout=confirmed'

# Logout that cannot revoke: the helper revokes each token by itself.
run_case logout_unconfirmed logout_unconfirmed 0
expect_events "$SIGN_IN"$'\nchild\ncw-logout\nintrospect at-1\nrevoke at-1\nintrospect at-1\nintrospect rt-1\nrevoke rt-1\nintrospect rt-1\nintrospect at-1\nintrospect rt-1'
expect_no_grant
expect_err 'PASS cli_sign_in_ended=true logout=unconfirmed revoked_by_token=2'

# A token the server will not revoke fails the run, loudly.
run_case revoke_ignored revoke_ignored 1
expect_err 'still active on the server'
expect_err 'FAIL cli_sign_in_ended=false'

# A refresh during the command leaves the first access token live until it
# expires; logout ends only the current pair, so the helper still revokes the
# first. But a refresh it didn't see could have left another, so the run fails
# and says to rotate the identity, which revokes every CLI token by id.
run_case refresh_in_child refresh_in_child 1
expect_events "$SIGN_IN"$'\nchild\ncw-logout\nintrospect at-1\nrevoke at-1\nintrospect at-1\nintrospect rt-1\nintrospect at-2\nintrospect rt-2'
expect_no_grant
expect_err 'the CLI sign-in refreshed during the walk'
expect_err 'FAIL cli_sign_in_ended=false'

# Signed in as anyone else: nothing runs, and the sign-in still ends.
run_case wrong_account wrong_account 1
expect_events "$SIGN_IN"$'\n'"$CHECKED"
expect_no_grant
expect_err 'not signed in as the personal-walk identity'

expect_no_session() {
  [[ ! -s "$CASE/state/sessions" ]] ||
    fail "$(basename "$CASE"): sessions still signed in: [$(tr '\n' ',' <"$CASE/state/sessions")]"
}

# Browser sessions are made before the password file is removed, each
# checked as this identity's before its setup is skipped, and every one is
# signed out afterwards.
readonly SIGN_IN_ONE_BROWSER=$'bao-read\nbao-revoke\ncw-login\nsign-in\nsign-in\nskip-setup session-2\nskip-setup\ndevice-page\napprove\nbrowser-sign-out\ncw-whoami'
readonly BROWSER_SIGN_IN=$'bao-read\nbao-revoke\ncw-login\nsign-in\nsign-in\nskip-setup session-2\nsign-in\nskip-setup session-3\nskip-setup\ndevice-page\napprove\nbrowser-sign-out\ncw-whoami'
BROWSER=2 run_case browser_sessions success 0 --browser-sessions 2
expect_events "$BROWSER_SIGN_IN"$'\nchild\n'"$CHECKED"$'\nsign-out session-2\nsign-out session-3'
expect_password_in_one_file
expect_no_grant
expect_no_session
expect_err 'browser session 1: id sid-2'
expect_err 'browser session 2: id sid-3'
expect_err 'PASS browser_sessions_ended=2 secret_values_printed=false'
grep -qx 'child-ran' "$CASE/out" || fail 'browser_sessions: the child did not run'

# A session the browser's final state holds is signed out too; another host's
# cookie is not the helper's to touch.
BROWSER=1 run_case browser_writeback browser_writeback 0 --browser-sessions 1
expect_no_session
grep -qx 'sign-out session-extra' "$CASE/state/events" || fail 'browser_writeback: the written-back session was not signed out'
! grep -q 'other-host' "$CASE/state/events" || fail 'browser_writeback: another host cookie was used'
expect_err 'PASS browser_sessions_ended=2'

# A state file that can't be read fails the run; the sessions still end.
BROWSER=1 run_case browser_bad_state browser_bad_state 1 --browser-sessions 1
expect_no_session
expect_err "a browser storage-state file can't be read: state-1.json"
expect_err 'FAIL browser_sessions_ended=1'

# A session the server still knows after its sign-out fails the run, by id.
BROWSER=1 run_case browser_sign_out_ignored browser_sign_out_ignored 1 --browser-sessions 1
expect_err 'browser session sid-2 is still signed in; revoke it by id'
expect_err 'FAIL browser_sessions_ended=0'

# A session that is not this identity's: its setup is never skipped, nothing
# runs, and it is still signed out.
BROWSER=1 run_case browser_wrong_identity browser_wrong_identity 1 --browser-sessions 1
expect_no_session
expect_err "browser session 1 is not the personal-walk identity's"
! grep -q '^skip-setup session-2' "$CASE/state/events" || fail 'browser_wrong_identity: setup was skipped'
! grep -qx child "$CASE/state/events" || fail 'browser_wrong_identity: the child ran'

# A signal to the helper still runs the sign-out sweep.
BROWSER=2 run_case browser_term browser_term 130 --browser-sessions 2
expect_no_session
expect_no_grant
expect_err 'PASS browser_sessions_ended=2'

# N is exactly 1 or 2, refused before anything is read or made.
for count in 0 3 12 x ''; do
  run_case "browser_count_${count:-empty}" success 1 --browser-sessions "$count"
  expect_events ''
  expect_err '--browser-sessions takes 1 or 2'
done

# Dev only: another origin is refused before OpenBao is read.
SERVER_URL=https://codewire.sh run_case production_origin success 1
expect_events ''
expect_err 'exists only on Dev; refusing server https://codewire.sh'
SERVER_URL=https://codewire-dev.sh.example.test run_case lookalike_origin success 1
expect_events ''

# A missing or malformed document fails closed: no sign-in, no command.
for mode in missing permission extra_field wrong_email bad_password not_json; do
  run_case "$mode" "$mode" 1
  expect_events $'bao-read\nbao-revoke'
  [[ "$mode" != missing ]] || expect_err 'does not exist; run provision-dev-personal-walk-user.sh'
  [[ "$mode" != permission ]] || expect_err 'lacks the exact Dev path apps/codewire/dev/ci-personal-walk'
  [[ "$mode" == missing || "$mode" == permission ]] || expect_err 'has an unexpected shape'
  ! grep -q '^cw --server' "$CASE/state/argv" || fail "$mode: cw ran"
done

run_case bao_revoke_refused bao_revoke_refused 1
expect_events $'bao-read\nbao-revoke'
expect_err 'not confirmed revoked; nothing runs'

# --document-stdin (#6302): the document a CI step read with its own role
# arrives on stdin; no bao and no access client run, the same shape check
# applies, and the sign-in and its end are the same.
document() { # EMAIL: OpenBao's KV read response for the walk identity
  jq -n --arg password "$PASSWORD" --arg email "$1" \
    '{data: {metadata: {version: 2}, data: {password: $password, userEmail: $email}}}'
}
document "$EMAIL" >"$TEST_TMP/stdin-document.json"
STDIN_FILE="$TEST_TMP/stdin-document.json" run_case stdin_success success 0 --document-stdin
expect_events "${SIGN_IN#$'bao-read\nbao-revoke\n'}"$'\nchild\n'"$CHECKED"
expect_no_grant
[[ ! -s "$CASE/state/tokens" ]] || fail 'stdin_success: the access client was asked for a token'
! grep -q '^bao ' "$CASE/state/argv" || fail 'stdin_success: bao ran'
expect_err 'PASS cli_sign_in_ended=true logout=confirmed'
document person@example.test >"$TEST_TMP/stdin-wrong.json"
STDIN_FILE="$TEST_TMP/stdin-wrong.json" run_case stdin_wrong_email success 1 --document-stdin
expect_events ''
expect_err 'has an unexpected shape'
run_case stdin_empty success 1 --document-stdin
expect_events ''
expect_err 'has an unexpected shape'
# --document-stdin and --browser-sessions together, in either order: the
# browser sessions come from the document on stdin, and every one ends.
for order in stdin_first browser_first; do
  if [[ "$order" == stdin_first ]]; then flags=(--document-stdin --browser-sessions 2)
  else flags=(--browser-sessions 2 --document-stdin); fi
  BROWSER=2 STDIN_FILE="$TEST_TMP/stdin-document.json" run_case "stdin_browser_$order" success 0 "${flags[@]}"
  expect_events "${BROWSER_SIGN_IN#$'bao-read\nbao-revoke\n'}"$'\nchild\n'"$CHECKED"$'\nsign-out session-2\nsign-out session-3'
  expect_no_grant
  expect_no_session
  [[ ! -s "$CASE/state/tokens" ]] || fail "stdin_browser_$order: the access client was asked for a token"
  ! grep -q '^bao ' "$CASE/state/argv" || fail "stdin_browser_$order: bao ran"
  expect_err 'PASS browser_sessions_ended=2 secret_values_printed=false'
done
# Each flag at most once, refused before anything is read.
STDIN_FILE="$TEST_TMP/stdin-document.json" run_case stdin_twice success 1 --document-stdin --browser-sessions 1 --document-stdin
expect_events ''
expect_err '--document-stdin is given twice'
run_case browser_twice success 1 --browser-sessions 1 --browser-sessions 2
expect_events ''
expect_err '--browser-sessions is given twice'
rm -f -- "$TEST_TMP/stdin-document.json" "$TEST_TMP/stdin-wrong.json"

# --identity invitee: the synthetic invitee's document, sign-in and browser
# sessions, in either order with --browser-sessions, everything ended as for
# the personal-walk identity.
readonly INVITEE_EMAIL="success+codewire-dev-invitee@simulator.amazonses.com"
readonly INVITEE_PATH="apps/codewire/dev/ci-invitee"
for order in identity_first browser_first; do
  if [[ "$order" == identity_first ]]; then flags=(--identity invitee --browser-sessions 1)
  else flags=(--browser-sessions 1 --identity invitee); fi
  IDENTITY_EMAIL="$INVITEE_EMAIL" IDENTITY_PATH="$INVITEE_PATH" BROWSER=1 \
    run_case "invitee_$order" success 0 "${flags[@]}"
  expect_events "$SIGN_IN_ONE_BROWSER"$'\nchild\n'"$CHECKED"$'\nsign-out session-2'
  expect_password_in_one_file
  expect_no_grant
  expect_no_session
  grep -qxF "bao kv get -format=json $INVITEE_PATH" "$CASE/state/argv" ||
    fail "invitee_$order: the invitee's document was not read"
  expect_err "identity: $INVITEE_EMAIL"
  expect_err 'PASS browser_sessions_ended=1 secret_values_printed=false'
done
# The personal-walk identity's document at the invitee's path: refused by its
# email before anything signs in.
IDENTITY_PATH="$INVITEE_PATH" run_case invitee_wrong_document success 1 --identity invitee
expect_events $'bao-read\nbao-revoke'
expect_err 'has an unexpected shape'
# The invitee has no CI reader, so --document-stdin is refused with it, and
# --identity takes only invitee, once; all before anything is read.
document "$INVITEE_EMAIL" >"$TEST_TMP/stdin-invitee.json"
STDIN_FILE="$TEST_TMP/stdin-invitee.json" run_case invitee_stdin success 1 --identity invitee --document-stdin
expect_events ''
expect_err '--document-stdin is for the personal-walk identity only'
rm -f -- "$TEST_TMP/stdin-invitee.json"
run_case identity_twice success 1 --identity invitee --identity invitee
expect_events ''
expect_err '--identity is given twice'
for value in personal-walk smoke ''; do
  run_case "identity_${value:-empty}" success 1 --identity "$value"
  expect_events ''
  expect_err '--identity takes invitee'
done

# The runtime directory must be the caller's own 0700 tmpfs directory.
mkdir -m 0700 "$TEST_TMP/disk-runtime"
CASE_RUNTIME="$TEST_TMP/disk-runtime" run_case disk_runtime success 1
expect_events ''
expect_err 'not on tmpfs'
mkdir -m 0755 "$SHM_TMP/open-runtime"
CASE_RUNTIME="$SHM_TMP/open-runtime" run_case open_runtime success 1
expect_events ''
expect_err 'your own 0700 runtime directory'

# No command, no run.
NO_COMMAND=1 run_case no_command success 1
expect_events ''
expect_err 'name the command to run'

printf 'with-dev-personal-walk tests: PASS\n'
