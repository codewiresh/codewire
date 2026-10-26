#!/usr/bin/env bash
# Synthetic proof for the SDK releases' exact-path npm and PyPI token reader.
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR  # the tests exercise the script default

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly FETCHER="$ROOT/scripts/ci/setup/fetch-openbao-sdk-publish-token.sh"
CASES=0

fail() {
  printf '[test-fetch-openbao-sdk-publish-token] ERROR: %s\n' "$*" >&2
  exit 1
}
pass() { CASES=$((CASES + 1)); }

work="$(mktemp -d "${TMPDIR:-/tmp}/fetch-openbao-sdk-publish.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/runner"

b64url() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
jwt() {
  local claims="$1"
  printf '%s.%s.%s' "$(printf '{"alg":"RS256"}' | b64url)" "$(printf '%s' "$claims" | b64url)" \
    "$(printf 'synthetic-signature' | b64url)"
}
claims_for() {
  jq -cn --arg registry "$1" '{
    aud: "openbao-codewire-source-sdk-\($registry)-publish",
    sub: "repo:codewire-41/codewire-58:ref:refs/heads/main",
    repository: "codewire/codewire",
    actor: "noel",
    workflow_ref: "codewire/codewire/.gitea/workflows/sdk-release-\($registry).yaml@refs/heads/main",
    ref: "refs/heads/main",
    event_name: "workflow_dispatch"
  }'
}

cat >"$work/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${FAKE_CURL_CALLS:?}"
printf '\n' >>"$FAKE_CURL_CALLS"
output=''
url=''
data_file=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --data-binary) data_file="${2#@}"; shift 2 ;;
    --config|--header|--connect-timeout|--max-time) shift 2 ;;
    --silent|--show-error|--fail) shift ;;
    *) url="$1"; shift ;;
  esac
done
[[ -n "$output" && -n "$url" ]]
registry="${FAKE_REGISTRY:?}"
case "$url" in
  "https://git.example.invalid/"*"audience=openbao-codewire-source-sdk-$registry-publish")
    jq -n --arg value "${FAKE_FORGEJO_JWT:?}" '{value:$value}' >"$output"
    ;;
  https://openbao.example.invalid/v1/auth/forgejo-jwt/login)
    jq -e --arg role "codewire-source-sdk-$registry-publish" '.role == $role' "$data_file" >/dev/null
    printf 'login\n' >>"$FAKE_EVENTS"
    jq -n --arg token "${FAKE_OPENBAO_TOKEN:?}" '{auth:{client_token:$token}}' >"$output"
    ;;
  "https://openbao.example.invalid/v1/platform/data/ci/codewire/$registry-publisher")
    printf 'read\n' >>"$FAKE_EVENTS"
    jq -n --arg token "${FAKE_PUBLISH_TOKEN:?}" --argjson extra "${FAKE_EXTRA_FIELDS:-{\}}" \
      '{data:{data:({token:$token} + $extra)}}' >"$output"
    ;;
  *) exit 91 ;;
esac
MOCK
chmod +x "$work/bin/curl"

export PATH="$work/bin:$PATH"
export FAKE_CURL_CALLS="$work/curl-calls"
export FAKE_EVENTS="$work/events"
export FAKE_OPENBAO_TOKEN='synthetic-openbao-token-0123456789'
export ACTIONS_ID_TOKEN_REQUEST_URL='https://git.example.invalid/api/actions/oidc?job=synthetic'
export GITHUB_EVENT_NAME=workflow_dispatch
export GITHUB_REF=refs/heads/main
export GITHUB_ACTOR=noel
export GITHUB_REPOSITORY=codewire/codewire
export RUNNER_TEMP="$work/runner"
unset NPM_TOKEN NODE_AUTH_TOKEN TWINE_PASSWORD PYPI_TOKEN BAO_TOKEN VAULT_TOKEN
: >"$FAKE_CURL_CALLS"

fetch() {
  local output="$1"
  shift
  ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token-0123456789' "$@" "$FETCHER" "$FAKE_REGISTRY" "$output"
}

# Unknown registries and a missing argument are refused before any request.
for args in 'crates' ''; do
  # shellcheck disable=SC2086 # the empty case must pass no registry at all.
  if ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token-0123456789' "$FETCHER" $args "$work/unknown" \
      >"$work/unknown.out" 2>&1; then
    fail "registry '$args' was accepted"
  fi
  [[ ! -s "$FAKE_CURL_CALLS" && ! -e "$work/unknown" ]] || fail "registry '$args' reached a request"
  pass
done

for registry in npm pypi; do
  export FAKE_REGISTRY="$registry"
  good_claims="$(claims_for "$registry")"
  other="$([[ "$registry" == npm ]] && echo pypi || echo npm)"
  FAKE_FORGEJO_JWT="$(jwt "$good_claims")"
  export FAKE_FORGEJO_JWT
  # Assembled at run time so no token-shaped literal is committed for secret
  # scanners to match.
  if [[ "$registry" == npm ]]; then
    FAKE_PUBLISH_TOKEN="npm_$(printf 'A%.0s' {1..36})"
    malformed_tokens=(FAKE_PUBLISH_TOKEN=npm_short "FAKE_PUBLISH_TOKEN=pypi-$(printf 'A%.0s' {1..60})")
  else
    FAKE_PUBLISH_TOKEN="pypi-$(printf 'A%.0s' {1..60})"
    malformed_tokens=(FAKE_PUBLISH_TOKEN=pypi-short "FAKE_PUBLISH_TOKEN=npm_$(printf 'A%.0s' {1..36})")
  fi
  export FAKE_PUBLISH_TOKEN
  out="$work/$registry"
  mkdir -p "$out"

  # The exact protected run writes one private token file without a newline.
  : >"$FAKE_EVENTS"
  fetch "$out/token" env >"$out/success.out" 2>&1 || fail "$(cat "$out/success.out")"
  [[ -f "$out/token" && ! -L "$out/token" ]] || fail "$registry token output is not a regular file"
  [[ "$(stat -c '%a' "$out/token")" == 600 ]] || fail "$registry token file mode is not 0600"
  cmp -s "$out/token" <(printf '%s' "$FAKE_PUBLISH_TOKEN") || fail "$registry token file differs from the document"
  [[ "$(cat "$FAKE_EVENTS")" == $'login\nread' ]] || fail "the $registry fetch did not log in once and read once"
  [[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'OIDC or OpenBao material survived cleanup'
  for secret in synthetic-request-token-0123456789 "$FAKE_FORGEJO_JWT" "$FAKE_OPENBAO_TOKEN" "$FAKE_PUBLISH_TOKEN"; do
    if grep -qF -- "$secret" "$FAKE_CURL_CALLS" "$out/success.out"; then
      fail "$registry token material reached curl arguments or output"
    fi
  done
  [[ "$(grep -Fc -- '--connect-timeout 10 --max-time 30' "$FAKE_CURL_CALLS")" -ge 3 ]] ||
    fail 'a request lacks the reviewed network deadline'
  pass

  # Wrong actor, ref, event or repository is refused before any request.
  for override in GITHUB_ACTOR=mallory GITHUB_ACTOR=forgejo-actions GITHUB_REF=refs/heads/feature \
      GITHUB_REF=refs/tags/v0.1.0 GITHUB_EVENT_NAME=push GITHUB_EVENT_NAME=schedule \
      GITHUB_EVENT_NAME=pull_request GITHUB_REPOSITORY=codewire/fork; do
    calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
    name="${override//[^A-Za-z0-9]/-}"
    if fetch "$out/$name" env "$override" >"$out/$name.out" 2>&1; then
      fail "$registry: unapproved $override was accepted"
    fi
    [[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] || fail "$registry: $override reached a request"
    [[ ! -e "$out/$name" ]] || fail "$registry: $override wrote a token"
    pass
  done

  # Ambient or cached credentials are never a fallback.
  for ambient in NPM_TOKEN=ambient NODE_AUTH_TOKEN=ambient TWINE_PASSWORD=ambient PYPI_TOKEN=ambient \
      BAO_TOKEN=ambient VAULT_TOKEN=ambient; do
    calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
    if fetch "$out/ambient" env "$ambient" >"$out/ambient.out" 2>&1; then
      fail "$registry: ambient $ambient was accepted"
    fi
    [[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] || fail "$registry: ambient $ambient reached a request"
    pass
  done

  # A token whose own claims are not this exact run never reaches OpenBao,
  # including the other registry's release.
  for claim in '.actor = "mallory"' \
      ".workflow_ref = \"codewire/codewire/.gitea/workflows/sdk-release-$other.yaml@refs/heads/main\"" \
      '.workflow_ref = "codewire/codewire/.gitea/workflows/ci.yaml@refs/heads/main"' \
      ".aud = \"openbao-codewire-source-sdk-$other-publish\"" \
      '.ref = "refs/heads/feature"' '.event_name = "push"' \
      '.sub = "repo:codewire-41/codewire-58:pull_request"' 'del(.workflow_ref)'; do
    : >"$FAKE_EVENTS"
    bad_jwt="$(jwt "$(jq -c "$claim" <<<"$good_claims")")"
    if FAKE_FORGEJO_JWT="$bad_jwt" fetch "$out/claims" env >"$out/claims.out" 2>&1; then
      fail "$registry: mismatched claim $claim was accepted"
    fi
    grep -Fq "OIDC token claims are not the protected $registry SDK release" "$out/claims.out" ||
      fail "$registry: claim $claim was not refused by the claim check"
    [[ ! -s "$FAKE_EVENTS" ]] || fail "$registry: claim $claim reached OpenBao"
    [[ ! -e "$out/claims" ]] || fail "$registry: claim $claim wrote a token"
    [[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'refused claims left private material'
    pass
  done

  # The document must contain exactly one well-formed token for this registry.
  for extra in '{"username":"codewire"}' '{"password":"synthetic"}'; do
    if FAKE_EXTRA_FIELDS="$extra" fetch "$out/extra" env >"$out/extra.out" 2>&1; then
      fail "$registry: token document with $extra was accepted"
    fi
    [[ ! -e "$out/extra" ]] || fail "$registry: an extra-field document wrote a token"
    pass
  done
  for malformed in "${malformed_tokens[@]}"; do
    if fetch "$out/malformed" env "$malformed" >"$out/malformed.out" 2>&1; then
      fail "$registry: malformed token ${malformed:19:12} was accepted"
    fi
    [[ ! -e "$out/malformed" ]] || fail "$registry: a malformed token was written"
    [[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'a refused document left private material'
    pass
  done

  # An existing path or a symlink is never overwritten.
  if fetch "$out/token" env >"$out/existing.out" 2>&1; then
    fail "$registry: an existing output path was overwritten"
  fi
  ln -s "$out/elsewhere" "$out/link"
  if fetch "$out/link" env >"$out/link.out" 2>&1; then
    fail "$registry: a symlink output path was followed"
  fi
  [[ ! -e "$out/elsewhere" ]] || fail "$registry: a symlink output path received the token"
  pass
done

printf 'test-fetch-openbao-sdk-publish-token: PASS cases=%s\n' "$CASES"
