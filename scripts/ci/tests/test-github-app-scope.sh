#!/usr/bin/env bash
# Contract for github-app-scope.sh and revoke-github-app-token.sh (#5407): the
# scope check prints only its fixed fields and fails on any difference, the
# revocation always exits 0, and neither credential reaches arguments or output.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly SCOPE="$ROOT/scripts/ci/release/github-app-scope.sh"
readonly REVOKE="$ROOT/scripts/ci/release/revoke-github-app-token.sh"

fail() {
  printf '[test-github-app-scope] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/github-app-scope.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/input" "$work/runner"
readonly JWT='sentinel-app-jwt-value'
readonly TOKEN='sentinel-installation-token-value'
printf '12345\n' >"$work/input/app-id"
printf '%s\n' "$JWT" >"$work/input/app.jwt"
printf '%s\n' "$TOKEN" >"$work/input/token"
chmod 0600 "$work/input/"*

# GitHub, faked: each answer needs the right credential in the curl config.
cat >"$work/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${FAKE_CURL_ARGS:?}"
printf '\n' >>"$FAKE_CURL_ARGS"
config='' output='' url=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) config="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    --connect-timeout|--max-time) shift 2 ;;
    *) url="$1"; shift ;;
  esac
done
auth="$(sed -n 's/^header = "Authorization: Bearer \(.*\)"$/\1/p' "$config")"
method=GET
grep -qx 'request = "DELETE"' "$config" && method=DELETE
printf '%s %s\n' "$method" "$url" >>"${FAKE_CURL_CALLS:?}"
case "$method $url" in
  'GET https://api.github.com/app')
    [[ "$auth" == "${FAKE_JWT:?}" ]] || exit 22
    cp "${FAKE_APP:?}" "$output" ;;
  'GET https://api.github.com/installation/repositories?per_page=100')
    [[ "$auth" == "${FAKE_TOKEN:?}" ]] || exit 22
    cp "${FAKE_REPOSITORIES:?}" "$output" ;;
  'DELETE https://api.github.com/installation/token')
    [[ "$auth" == "$FAKE_TOKEN" && -z "${FAKE_DELETE_FAILS:-}" ]] || exit 22 ;;
  *) exit 22 ;;
esac
MOCK
chmod +x "$work/bin/curl"

export PATH="$work/bin:$PATH" RUNNER_TEMP="$work/runner"
export FAKE_CURL_ARGS="$work/curl-args" FAKE_CURL_CALLS="$work/curl-calls"
export FAKE_JWT="$JWT" FAKE_TOKEN="$TOKEN"
export FAKE_APP="$work/app.json" FAKE_REPOSITORIES="$work/repositories.json"

app() {
  jq -n --arg slug "$1" --argjson id "$2" --argjson permissions "$3" \
    '{slug: $slug, id: $id, name: "ignored", owner: {login: "codewiresh"}, permissions: $permissions}' >"$FAKE_APP"
}
repositories() {
  jq -n --argjson names "$1" \
    '{total_count: ($names | length), repositories: [$names[] | {full_name: ., private: false}]}' >"$FAKE_REPOSITORIES"
}
scope() {
  "$SCOPE" "$work/input/app-id" "$work/input/app.jwt" "$work/input/token" \
    codewire-release-homebrew actions=write,metadata=read codewiresh/homebrew-codewire
}
no_secrets() {
  local file
  for file in "$@"; do
    ! grep -qF -e "$JWT" -e "$TOKEN" "$file" || fail "$1: a credential reached output or arguments"
  done
}

readonly GOOD='{"metadata": "read", "actions": "write"}'
app codewire-release-homebrew 12345 "$GOOD"
repositories '["codewiresh/homebrew-codewire"]'
scope >"$work/good.out" 2>&1 || { cat "$work/good.out" >&2; fail 'the expected App was refused'; }
diff -u - "$work/good.out" <<'EXPECTED' || fail 'the scope check printed other than its fixed fields'
[github-app-scope] app slug=codewire-release-homebrew app_id=matches permissions=actions=write,metadata=read
[github-app-scope] installation total_count=1 repositories=codewiresh/homebrew-codewire
[github-app-scope] codewire-release-homebrew holds exactly actions=write,metadata=read on codewiresh/homebrew-codewire
EXPECTED
no_secrets "$work/good.out" "$FAKE_CURL_ARGS"
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'the scope check left files behind'

refused() {
  local name="$1" want="$2"
  if scope >"$work/$name.out" 2>&1; then
    fail "$name: the scope check passed"
  fi
  grep -qF -- "$want" "$work/$name.out" || { cat "$work/$name.out" >&2; fail "$name: the refusal doesn't say $want"; }
  no_secrets "$work/$name.out" "$FAKE_CURL_ARGS"
  app codewire-release-homebrew 12345 "$GOOD"
  repositories '["codewiresh/homebrew-codewire"]'
}
app codewire-homebrew-tap 12345 "$GOOD"
refused other-slug 'the App is codewire-homebrew-tap, not codewire-release-homebrew'
app codewire-release-homebrew 54321 "$GOOD"
refused other-id 'not the one whose ID is stored'
app codewire-release-homebrew 12345 '{"actions": "write", "contents": "write", "metadata": "read"}'
refused contents "permissions are actions=write,contents=write,metadata=read"
app codewire-release-homebrew 12345 '{"actions": "read", "metadata": "read"}'
refused actions-read 'permissions are actions=read,metadata=read'
app codewire-release-homebrew 12345 '{"actions": "write", "metadata": "read", "workflows": "write"}'
refused workflows 'not exactly actions=write,metadata=read'
repositories '["codewiresh/homebrew-codewire", "codewiresh/codewire"]'
refused two-repositories 'reaches 2 repositories'
repositories '["codewiresh/codewire"]'
refused other-repository 'repositories (codewiresh/codewire)'
FAKE_JWT=other-jwt refused jwt-refused 'GitHub refused GET /app'

chmod 0644 "$work/input/token"
refused loose-token 'mode 0400 or 0600'
chmod 0600 "$work/input/token"

# The revocation: always exit 0, the token only in the config.
: >"$FAKE_CURL_CALLS"
"$REVOKE" "$work/input/token" >"$work/revoke.out" 2>&1 || fail 'the revocation exited non-zero'
grep -qx 'DELETE https://api.github.com/installation/token' "$FAKE_CURL_CALLS" || fail 'the token was not revoked'
grep -qxF '[revoke-github-app-token] revoked the installation token' "$work/revoke.out" || fail 'the revocation was not reported'
FAKE_DELETE_FAILS=1 "$REVOKE" "$work/input/token" >"$work/revoke-failed.out" 2>&1 ||
  fail 'a refused revocation exited non-zero'
grep -qF 'did not confirm the revocation' "$work/revoke-failed.out" || fail 'a refused revocation was not reported'
: >"$FAKE_CURL_CALLS"
"$REVOKE" "$work/input/missing" >"$work/revoke-missing.out" 2>&1 || fail 'a missing token exited non-zero'
[[ ! -s "$FAKE_CURL_CALLS" ]] || fail 'a missing token still called GitHub'
no_secrets "$work/revoke.out" "$work/revoke-failed.out" "$FAKE_CURL_ARGS"
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'the revocation left files behind'

printf '[test-github-app-scope] scope and revocation contract passed\n'
