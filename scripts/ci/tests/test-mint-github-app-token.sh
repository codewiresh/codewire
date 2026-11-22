#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly MINTER="$ROOT/scripts/ci/release/mint-github-app-token.sh"

fail() {
  printf '[test-mint-github-app-token] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/mint-github-token.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/input" "$work/output" "$work/runner"
printf '12345\n' >"$work/input/app-id"
printf '67890\n' >"$work/input/installation-id"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$work/input/private-key" >/dev/null 2>&1
chmod 0600 "$work/input/"*

cat >"$work/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >"${FAKE_CURL_ARGS:?}"
printf '\n' >>"$FAKE_CURL_ARGS"
output=''
url=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --config|--connect-timeout|--max-time) shift 2 ;;
    *) url="$1"; shift ;;
  esac
done
[[ "$url" == 'https://api.github.com/app/installations/67890/access_tokens' ]]
jq -n --arg token "${FAKE_INSTALLATION_TOKEN:?}" '{token:$token}' >"$output"
MOCK
chmod +x "$work/bin/curl"

export PATH="$work/bin:$PATH"
export FAKE_CURL_ARGS="$work/curl-args"
export FAKE_INSTALLATION_TOKEN='github-installation-token-value'
export RUNNER_TEMP="$work/runner"
"$MINTER" "$work/input/app-id" "$work/input/installation-id" \
  "$work/input/private-key" "$work/output/token" >/dev/null
[[ "$(<"$work/output/token")" == "$FAKE_INSTALLATION_TOKEN" ]] || fail 'token differs'
[[ "$(stat -c '%a' "$work/output/token")" == 600 ]] || fail 'token mode is not 0600'
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] ||
  fail 'temporary App JWT material survived cleanup'
if grep -qF "$FAKE_INSTALLATION_TOKEN" "$FAKE_CURL_ARGS"; then
  fail 'installation token reached curl arguments'
fi
if grep -qF 'PRIVATE KEY' "$FAKE_CURL_ARGS"; then
  fail 'private key reached curl arguments'
fi
grep -Fq -- '--connect-timeout 10 --max-time 30' "$FAKE_CURL_ARGS" ||
  fail 'GitHub token request lacks the reviewed network deadline'

chmod 0644 "$work/input/app-id"
if "$MINTER" "$work/input/app-id" "$work/input/installation-id" \
    "$work/input/private-key" "$work/output/rejected" \
    >"$work/rejected.out" 2>&1; then
  fail 'insecure GitHub App input mode was accepted'
fi
[[ ! -e "$work/output/rejected" ]] || fail 'rejected input created a token'

# Without GITHUB_APP_JWT_FILE, as the mirror calls it, the output is exactly
# the one line and the token is the only file written.
chmod 0600 "$work/input/app-id"
mkdir "$work/plain"
env -u GITHUB_APP_JWT_FILE "$MINTER" "$work/input/app-id" "$work/input/installation-id" \
  "$work/input/private-key" "$work/plain/token" >"$work/plain.out" 2>&1
printf '[mint-github-app-token] wrote one private installation token\n' |
  cmp -s - "$work/plain.out" || fail 'the default output changed'
[[ "$(find "$work/plain" -mindepth 1 -printf '%f\n')" == token ]] ||
  fail 'the default mint wrote more than the token'

# With it, the JWT is kept at that new 0600 path, and still never in arguments.
mkdir "$work/scoped"
: >"$FAKE_CURL_ARGS"
GITHUB_APP_JWT_FILE="$work/scoped/app.jwt" "$MINTER" "$work/input/app-id" \
  "$work/input/installation-id" "$work/input/private-key" "$work/scoped/token" >"$work/scoped.out" 2>&1
cmp -s "$work/plain.out" "$work/scoped.out" || fail 'keeping the JWT changed the output'
[[ "$(stat -c '%a' "$work/scoped/app.jwt")" == 600 ]] || fail 'the kept JWT is not mode 0600'
[[ "$(<"$work/scoped/app.jwt")" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]] ||
  fail 'the kept JWT is not a JWT'
if grep -qF "$(<"$work/scoped/app.jwt")" "$FAKE_CURL_ARGS" "$work/scoped.out"; then
  fail 'the App JWT reached curl arguments or output'
fi
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] ||
  fail 'temporary App JWT material survived cleanup'
if GITHUB_APP_JWT_FILE="$work/scoped/app.jwt" "$MINTER" "$work/input/app-id" \
    "$work/input/installation-id" "$work/input/private-key" "$work/scoped/again" \
    >"$work/again.out" 2>&1; then
  fail 'an existing JWT path was overwritten'
fi
[[ ! -e "$work/scoped/again" ]] || fail 'a refused JWT path still minted a token'

printf '[test-mint-github-app-token] private-file mint contract passed\n'
