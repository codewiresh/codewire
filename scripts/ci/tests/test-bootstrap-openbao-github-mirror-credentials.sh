#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly BOOTSTRAP="$ROOT/scripts/ci/setup/bootstrap-openbao-github-mirror-credentials.sh"

fail() {
  printf '[test-bootstrap-openbao-github-mirror-credentials] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/bootstrap-openbao-github.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/runner"

cat >"$work/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${FAKE_CURL_CALLS:?}"
printf '\n' >>"$FAKE_CURL_CALLS"
output=''
url=''
write_out=''
data_file=''
method=GET
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --write-out) write_out="$2"; shift 2 ;;
    --data-binary)
      data_file="${2#@}"
      shift 2
      ;;
    --request) method="$2"; shift 2 ;;
    --config|--header|--connect-timeout|--max-time) shift 2 ;;
    --silent|--show-error|--fail) shift ;;
    *) url="$1"; shift ;;
  esac
done
[[ -n "$output" && -n "$url" ]]
status=200
case "$url" in
  https://git.example.invalid/*audience=openbao-codewire-source-github-mirror)
    jq -n --arg value "${FAKE_FORGEJO_JWT:?}" '{value:$value}' >"$output"
    ;;
  https://openbao.example.invalid/v1/auth/forgejo-jwt/login)
    jq -n --arg token "${FAKE_OPENBAO_TOKEN:?}" '{auth:{client_token:$token}}' >"$output"
    ;;
  https://openbao.example.invalid/v1/platform/data/ci/codewire/github-mirror)
    if [ "$method" = POST ]; then
      jq -e \
        --arg appId "${FAKE_APP_ID:?}" \
        --arg installationId "${FAKE_INSTALLATION_ID:?}" \
        --arg privateKey "${FAKE_PRIVATE_KEY:?}" '
          .options.cas == 0 and
          .data == {appId:$appId,installationId:$installationId,privateKey:$privateKey}
        ' "$data_file" >/dev/null
      cp "$data_file" "${FAKE_OPENBAO_STATE:?}"
      jq -n '{data:{version:1}}' >"$output"
    elif [ -f "${FAKE_OPENBAO_STATE:?}" ]; then
      jq '{data:{data:.data}}' "$FAKE_OPENBAO_STATE" >"$output"
    else
      jq -n '{errors:[]}' >"$output"
      status=404
    fi
    ;;
  *) exit 91 ;;
esac
if [ -n "$write_out" ]; then
  [[ "$write_out" == '%{http_code}' ]]
  printf '%s' "$status"
fi
MOCK
chmod 0755 "$work/bin/curl" "$BOOTSTRAP"

export PATH="$work/bin:$PATH"
export FAKE_CURL_CALLS="$work/curl-calls"
export FAKE_OPENBAO_STATE="$work/openbao-state.json"
export FAKE_FORGEJO_JWT='synthetic-forgejo-jwt'
export FAKE_OPENBAO_TOKEN='synthetic-openbao-token'
export FAKE_APP_ID='12345'
export FAKE_INSTALLATION_ID='67890'
export FAKE_PRIVATE_KEY=$'-----BEGIN PRIVATE KEY-----\nsynthetic-private-key\n-----END PRIVATE KEY-----'
export ACTIONS_ID_TOKEN_REQUEST_URL='https://git.example.invalid/api/actions/oidc?job=synthetic'
export ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token'
export OPENBAO_GITHUB_ROLE='codewire-source-github-mirror'
export OPENBAO_GITHUB_AUDIENCE='openbao-codewire-source-github-mirror'
export MIRROR_GITHUB_APP_ID="$FAKE_APP_ID"
export MIRROR_GITHUB_INSTALLATION_ID="$FAKE_INSTALLATION_ID"
export MIRROR_GITHUB_PRIVATE_KEY="$FAKE_PRIVATE_KEY"
export RUNNER_TEMP="$work/runner"

"$BOOTSTRAP" >"$work/create.out"
grep -Fq 'create-only OpenBao tuple verified' "$work/create.out" ||
  fail 'absent document was not created and verified'
jq -e '.options.cas == 0' "$FAKE_OPENBAO_STATE" >/dev/null ||
  fail 'create did not retain the create-only CAS guard'
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] ||
  fail 'temporary OIDC, OpenBao, or source credential material survived cleanup'

"$BOOTSTRAP" >"$work/existing.out"
grep -Fq 'existing OpenBao tuple verified' "$work/existing.out" ||
  fail 'an identical existing document was not accepted idempotently'

if MIRROR_GITHUB_APP_ID=99999 "$BOOTSTRAP" \
    >"$work/mismatch.out" 2>"$work/mismatch.err"; then
  fail 'a differing existing OpenBao document was accepted'
fi
grep -Fq 'existing OpenBao GitHub App ID differs' "$work/mismatch.err" ||
  fail 'existing-document mismatch was not attributable'

for secret in "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$FAKE_FORGEJO_JWT" \
    "$FAKE_OPENBAO_TOKEN" 'synthetic-private-key'; do
  if grep -qF "$secret" "$FAKE_CURL_CALLS"; then
    fail 'credential material reached curl arguments'
  fi
done

printf '[test-bootstrap-openbao-github-mirror-credentials] create-only migration contract passed\n'
