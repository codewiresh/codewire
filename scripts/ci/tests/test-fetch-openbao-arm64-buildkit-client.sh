#!/usr/bin/env bash
# Execute fetch-openbao-arm64-buildkit-client.sh against a fake curl: only the
# support publisher role reads the arm64 node's client tuple, it lands only in
# an empty private directory as three mode-0600 PEM files, nothing secret is
# printed or passed as an argument, and every failure says what failed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly FETCHER="$ROOT/scripts/ci/setup/fetch-openbao-arm64-buildkit-client.sh"

fail() {
  printf '[test-fetch-openbao-arm64-buildkit-client] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/fetch-openbao-arm64-buildkit.XXXXXX")"
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
  https://git.example.invalid/*audience=openbao-codewire-source-support-publisher)
    jq -n --arg value synthetic-forgejo-jwt '{value:$value}' >"$output" ;;
  https://openbao.example.invalid/v1/auth/forgejo-jwt/login)
    jq -n '{auth:{client_token:"synthetic-openbao-token"}}' >"$output" ;;
  https://openbao.example.invalid/v1/platform/data/ci/codewire/arm64-buildkit-client)
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
calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
refuse other-role 'only the support publisher role' "$(private_dir other-role)" \
  OPENBAO_ROLE=codewire-source-dev-publisher OPENBAO_AUDIENCE=openbao-codewire-source-dev-publisher
shared="$work/shared"; mkdir -m 0755 "$shared"
refuse shared-directory 'empty private directory' "$shared"
used="$(private_dir used)"; : >"$used/leftover"
refuse used-directory 'empty private directory' "$used"
refuse relative-directory 'empty private directory' relative-tls
[[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] || fail 'a refused request reached the network'
refuse denied 'is not readable at platform/data/ci/codewire/arm64-buildkit-client with role codewire-source-support-publisher' \
  "$(private_dir denied)" FAKE_DOCUMENT=denied
refuse no-key 'has no privateKey' "$(private_dir no-key)" FAKE_DOCUMENT=no-key
refuse not-pem "certificate is not PEM" "$(private_dir not-pem)" FAKE_DOCUMENT=not-pem
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'a failed read left material behind'

echo 'test-fetch-openbao-arm64-buildkit-client: PASS cases=9'
