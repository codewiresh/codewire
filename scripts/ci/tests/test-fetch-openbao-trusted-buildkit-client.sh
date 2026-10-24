#!/usr/bin/env bash
# Execute fetch-openbao-trusted-buildkit-client.sh against a fake curl: only
# the Dev, support and production publisher roles and the two protected-main
# release builds read the trusted builder's client tuple, it lands only in an
# empty private directory as three mode-0600
# PEM files, nothing secret is printed or passed as an argument, and every
# failure says what failed.
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR  # the tests exercise the script default

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly FETCHER="$ROOT/scripts/ci/setup/fetch-openbao-trusted-buildkit-client.sh"

fail() {
  printf '[test-fetch-openbao-trusted-buildkit-client] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/fetch-openbao-trusted-buildkit.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/runner"

cat >"$work/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${FAKE_CURL_CALLS:?}"
printf '\n' >>"$FAKE_CURL_CALLS"
output='' url=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --config|--header|--data-binary|--connect-timeout|--max-time) shift 2 ;;
    --silent|--show-error|--fail) shift ;;
    *) url="$1"; shift ;;
  esac
done
[[ -n "$output" && -n "$url" ]]
case "$url" in
  https://git.example.invalid/*audience=openbao-codewire-source-dev-publisher | \
    https://git.example.invalid/*audience=openbao-codewire-source-support-publisher | \
    https://git.example.invalid/*audience=openbao-codewire-source-prod-publisher | \
    https://git.example.invalid/*audience=openbao-codewire-source-cli-release-build | \
    https://git.example.invalid/*audience=openbao-codewire-source-release-dry-run-build)
    jq -n --arg value synthetic-forgejo-jwt '{value:$value}' >"$output" ;;
  https://openbao.example.invalid/v1/auth/forgejo-jwt/login)
    jq -n '{auth:{client_token:"synthetic-openbao-token"}}' >"$output" ;;
  https://openbao.example.invalid/v1/platform/data/ci/codewire/trusted-buildkit-client)
    case "${FAKE_DOCUMENT:-valid}" in
      denied) exit 22 ;;
      valid) jq -n --arg ca "$FAKE_CA" --arg cert "$FAKE_CERT" --arg key "$FAKE_KEY" \
        '{data:{data:{caCertificate:$ca, certificate:$cert, privateKey:$key}}}' >"$output" ;;
      no-key) jq -n --arg ca "$FAKE_CA" --arg cert "$FAKE_CERT" \
        '{data:{data:{caCertificate:$ca, certificate:$cert}}}' >"$output" ;;
      not-pem) jq -n --arg ca "$FAKE_CA" --arg key "$FAKE_KEY" \
        '{data:{data:{caCertificate:$ca, certificate:"not a certificate", privateKey:$key}}}' >"$output" ;;
    esac ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$work/bin/curl"

export PATH="$work/bin:$PATH"
export FAKE_CURL_CALLS="$work/curl-calls"
export FAKE_CA=$'-----BEGIN CERTIFICATE-----\nc3ludGhldGljLWNh\n-----END CERTIFICATE-----'
export FAKE_CERT=$'-----BEGIN CERTIFICATE-----\nc3ludGhldGljLWNsaWVudA==\n-----END CERTIFICATE-----'
export FAKE_KEY=$'-----BEGIN PRIVATE KEY-----\nc3ludGhldGljLWtleQ==\n-----END PRIVATE KEY-----'
export ACTIONS_ID_TOKEN_REQUEST_URL='https://git.example.invalid/api/actions/oidc?job=synthetic'
export ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token'
export OPENBAO_ROLE='codewire-source-support-publisher'
export OPENBAO_AUDIENCE='openbao-codewire-source-support-publisher'
export RUNNER_TEMP="$work/runner"

private_dir() {
  local dir="$work/$1"
  mkdir -m 0700 "$dir"
  printf '%s\n' "$dir"
}

# The approved role writes exactly the three PEM files, private, and prints no secret.
tls="$(private_dir tls)"
"$FETCHER" "$tls" >"$work/ok.out" 2>&1 || { cat "$work/ok.out" >&2; fail 'the support publisher could not read the client tuple'; }
[[ "$(cd "$tls" && find . -type f | sort | tr '\n' ' ')" == './ca.crt ./client.crt ./client.key ' ]] ||
  fail 'the client tuple is not exactly ca.crt, client.crt and client.key'
[[ "$(<"$tls/ca.crt")" == "$FAKE_CA" && "$(<"$tls/client.crt")" == "$FAKE_CERT" && "$(<"$tls/client.key")" == "$FAKE_KEY" ]] ||
  fail 'the client tuple differs from the OpenBao document'
for file in ca.crt client.crt client.key; do
  [[ "$(stat -c '%a' "$tls/$file")" == 600 ]] || fail "$file is not mode 0600"
done
for secret in c3ludGhldGljLWtleQ c3ludGhldGljLWNsaWVudA synthetic-openbao-token synthetic-forgejo-jwt \
    "$ACTIONS_ID_TOKEN_REQUEST_TOKEN"; do
  if grep -qF "$secret" "$work/ok.out" "$FAKE_CURL_CALLS"; then
    fail 'credential material was printed or passed as an argument'
  fi
done
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'temporary OIDC or OpenBao material survived'
[[ "$(grep -Fc -- '--connect-timeout 10 --max-time 30' "$FAKE_CURL_CALLS")" -eq 3 ]] ||
  fail 'an OIDC or OpenBao request lacks the reviewed network deadline'

# refuse NAME MESSAGE DIRECTORY [ENV...]: fails, says why, writes nothing.
refuse() {
  local name="$1" message="$2" dir="$3"
  shift 3
  if env "$@" "$FETCHER" "$dir" >"$work/$name.out" 2>&1; then
    fail "$name was accepted"
  fi
  grep -qF "$message" "$work/$name.out" || { cat "$work/$name.out" >&2; fail "$name was not attributable"; }
  [[ ! -e "$dir/client.key" ]] || fail "$name left a private key behind"
}
# The Dev and production publishers read the same tuple.
dev_tls="$(private_dir dev-tls)"
OPENBAO_ROLE=codewire-source-dev-publisher OPENBAO_AUDIENCE=openbao-codewire-source-dev-publisher \
  "$FETCHER" "$dev_tls" >"$work/dev.out" 2>&1 || { cat "$work/dev.out" >&2; fail 'the Dev publisher could not read the client tuple'; }
[[ "$(cd "$dev_tls" && find . -type f | sort | tr '\n' ' ')" == './ca.crt ./client.crt ./client.key ' ]] ||
  fail 'the Dev publisher did not receive exactly the client tuple'
prod_tls="$(private_dir prod-tls)"
OPENBAO_ROLE=codewire-source-prod-publisher OPENBAO_AUDIENCE=openbao-codewire-source-prod-publisher \
  "$FETCHER" "$prod_tls" >"$work/prod.out" 2>&1 || { cat "$work/prod.out" >&2; fail 'the production publisher could not read the client tuple'; }
[[ "$(cd "$prod_tls" && find . -type f | sort | tr '\n' ' ')" == './ca.crt ./client.crt ./client.key ' ]] ||
  fail 'the production publisher did not receive exactly the client tuple'
# So do the two protected-main release builds (#3119).
for role in codewire-source-cli-release-build codewire-source-release-dry-run-build; do
  release_tls="$(private_dir "$role")"
  OPENBAO_ROLE="$role" OPENBAO_AUDIENCE="openbao-$role" \
    "$FETCHER" "$release_tls" >"$work/$role.out" 2>&1 || { cat "$work/$role.out" >&2; fail "$role could not read the client tuple"; }
  [[ "$(cd "$release_tls" && find . -type f | sort | tr '\n' ' ')" == './ca.crt ./client.crt ./client.key ' ]] ||
    fail "$role did not receive exactly the client tuple"
done
calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
refuse other-role 'only the Dev, support and production publisher roles' "$(private_dir other-role)" \
  OPENBAO_ROLE=codewire-source-ci-cache OPENBAO_AUDIENCE=openbao-codewire-source-ci-cache
refuse mixed-role 'only the Dev, support and production publisher roles' "$(private_dir mixed-role)" \
  OPENBAO_ROLE=codewire-source-prod-publisher OPENBAO_AUDIENCE=openbao-codewire-source-support-publisher
refuse release-signing-role 'only the Dev, support and production publisher roles' "$(private_dir release-signing)" \
  OPENBAO_ROLE=codewire-source-cli-release-signing OPENBAO_AUDIENCE=openbao-codewire-source-cli-release-signing
refuse mixed-release-role 'only the Dev, support and production publisher roles' "$(private_dir mixed-release)" \
  OPENBAO_ROLE=codewire-source-cli-release-build OPENBAO_AUDIENCE=openbao-codewire-source-release-dry-run-build
shared="$work/shared"; mkdir -m 0755 "$shared"
refuse shared-directory 'empty private directory' "$shared"
used="$(private_dir used)"; : >"$used/leftover"
refuse used-directory 'empty private directory' "$used"
refuse relative-directory 'empty private directory' relative-tls
[[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] || fail 'a refused request reached the network'
refuse denied 'is not readable at platform/data/ci/codewire/trusted-buildkit-client with role codewire-source-support-publisher' \
  "$(private_dir denied)" FAKE_DOCUMENT=denied
refuse no-key 'has no privateKey' "$(private_dir no-key)" FAKE_DOCUMENT=no-key
refuse not-pem "certificate is not PEM" "$(private_dir not-pem)" FAKE_DOCUMENT=not-pem
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'a failed read left material behind'

# A schedule role is read only by the release schedule's own first attempt
# (#2892): under the owner's dispatch, or on a rerun, it is refused before any
# request; the schedule's first attempt passes the guard.
for identity in 'GITHUB_EVENT_NAME=workflow_dispatch GITHUB_ACTOR=noel GITHUB_RUN_ATTEMPT=1' \
    'GITHUB_EVENT_NAME=schedule GITHUB_ACTOR=forgejo-actions GITHUB_RUN_ATTEMPT=2' \
    'GITHUB_EVENT_NAME=schedule GITHUB_ACTOR=forgejo-actions GITHUB_RUN_ATTEMPT=1'; do
  calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
  schedule_dir="$(private_dir "schedule-$RANDOM")"
  # shellcheck disable=SC2086 # Each identity is three assignments.
  env $identity GITHUB_REF=refs/heads/main GITHUB_REPOSITORY=codewire/codewire \
    OPENBAO_ROLE=codewire-source-cli-release-build-schedule OPENBAO_AUDIENCE=openbao-codewire-source-cli-release-build-schedule \
    "$FETCHER" "$schedule_dir" >"$work/schedule-guard.out" 2>&1 && guarded=0 || guarded=$?
  if [[ "$identity" == *GITHUB_RUN_ATTEMPT=1 && "$identity" == *schedule* ]]; then
    ! grep -Fq "only the release schedule's first attempt" "$work/schedule-guard.out" ||
      fail "the schedule's first attempt was refused a schedule role"
  else
    [[ "$guarded" -ne 0 ]] || fail "a schedule role was read under $identity"
    grep -Fq "only the release schedule's first attempt" "$work/schedule-guard.out" ||
      fail "a schedule role under $identity was not refused by the guard: $(cat "$work/schedule-guard.out")"
    [[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] ||
      fail "a schedule role under $identity reached a request"
  fi
done

echo 'test-fetch-openbao-trusted-buildkit-client: PASS cases=12'
