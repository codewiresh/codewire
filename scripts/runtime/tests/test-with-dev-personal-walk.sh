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
[[ "$*" == 'kv get -format=json apps/codewire/dev/ci-personal-walk' ]] || exit 90
[[ "${BAO_ADDR:-}" == https://openbao.example.invalid && "${BAO_TOKEN:-}" == synthetic-bao-token-6074 ]] || exit 91
printf 'bao-read\n' >>"$MOCK_STATE/events"
password="$(cat "$MOCK_STATE/password")"
case "$MOCK_MODE" in
  missing) printf 'No value found at apps/data/codewire/dev/ci-personal-walk\n' >&2; exit 2 ;;
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
  # sign-in's tokens, which live in $MOCK_STATE/active.
  cat >"$bin/curl" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf 'curl %s\n' "$*" >>"$MOCK_STATE/argv"
url="" output="" write_out="" jar_out="" body="" token_file="" header_file="" hint=""
declare -A form=()
while (($# > 0)); do
  case "$1" in
    --url) url="$2"; shift 2 ;;
    -o|--output) output="$2"; shift 2 ;;
    -w|--write-out) write_out="$2"; shift 2 ;;
    -c) jar_out="$2"; shift 2 ;;
    -b|--max-time|--connect-timeout|--retry|--max-redirs|--proto|--noproxy|--request|-X|-H) shift 2 ;;
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
    printf '#HttpOnly_codewire-dev.sh\tFALSE\t/\tTRUE\t0\tcodewire.session_token\tsession-1\n' >"$jar_out"
    code 200 ;;
  https://codewire-dev.sh/api/auth/two-factor/skip-setup) printf 'skip-setup\n' >>"$MOCK_STATE/events" ;;
  'https://codewire-dev.sh/device?user_code=ABCDEFGH')
    printf 'device-page\n' >>"$MOCK_STATE/events"
    respond '<form><input type="hidden" name="_csrf" value="csrf-1"></form>' ;;
  https://codewire-dev.sh/device/_actions/approve)
    [[ "${form[_csrf]:-}" == csrf-1 && "${form[user_code_1]:-}" == A && "${form[user_code_8]:-}" == H ]] || exit 100
    printf 'approve\n' >>"$MOCK_STATE/events"
    : >"$MOCK_STATE/approved"
    respond 'approved' ;;
  https://codewire-dev.sh/api/auth/sign-out)
    printf 'browser-sign-out\n' >>"$MOCK_STATE/events"
    : >"$MOCK_STATE/browser-signed-out" ;;
  https://codewire-dev.sh/api/auth/get-session)
    if [[ -e "$MOCK_STATE/browser-signed-out" ]]; then respond null; else respond '{"user":{}}'; fi ;;
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
  make_fake_tools "$CASE/bin"
  make_child "$CASE/child"
  local status=0
  [[ -n "${NO_COMMAND:-}" ]] || set -- "$@" -- "$CASE/child"
  env -i PATH="$CASE/bin:$PATH" HOME="$CASE/home" TMPDIR="$CASE/tmp" \
    XDG_RUNTIME_DIR="${CASE_RUNTIME:-$RUNTIME}" MOCK_STATE="$CASE/state" MOCK_MODE="$mode" \
    MOCK_EMAIL="$EMAIL" EMAIL="$EMAIL" MOCK_CHILD_STATUS="${CHILD_STATUS:-0}" \
    CW_BIN="$CASE/bin/cw" CODEWIRE_ACCESS_CLIENT="$CASE/access" \
    ${SERVER_URL:+CODEWIRE_SERVER_URL="$SERVER_URL"} \
    BAO_ADDR=https://openbao.example.invalid BAO_TOKEN=stale-owner-token VAULT_TOKEN=stale \
    CODEWIRE_API_KEY=cw_owner CODEWIRE_ORG=owner-org CODEWIRE_DEV_SMOKE_API_KEY=cw_smoke \
    CODEWIRE_MESH_AUTH_TOKEN=owner-mesh CW_MESH_DATA_DIR="$CASE/owner-mesh" \
    CW_CONFIG_DIR="$CASE/owner-cw" \
    bash "$HELPER" "$@" >"$CASE/out" 2>"$CASE/err" || status=$?
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
