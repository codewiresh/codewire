#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly RESOLVER="$ROOT/scripts/ci/images/resolve-published-support-pair.sh"
readonly SOURCE_SHA='1111111111111111111111111111111111111111'
readonly TEST_TOKEN='test-only-support-registry-token'

fail() {
  printf '[test-resolve-published-support-pair] ERROR: %s\n' "$*" >&2
  exit 1
}

install -d "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/support-baseline-test.XXXXXX")"
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT
mkdir -p "$work/bin" "$work/capture"

cat >"$work/bin/fetch-secret" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == GHCR_PUBLISH_TOKEN ]]
[[ -z "${FAIL_FETCH:-}" ]] || exit 1
printf '%s' "$FAKE_TOKEN" >"$2"
chmod 600 "$2"
printf '%s\n' "$2" >"$MOCK_CAPTURE_DIR/fetch-target"
MOCK
chmod +x "$work/bin/fetch-secret"

cat >"$work/bin/docker" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$MOCK_CAPTURE_DIR/docker-calls"
case "$1 $2" in
  'volume create') printf '%s\n' support-baseline-auth ;;
  'volume rm') ;;
  *) exit 2 ;;
esac
MOCK
chmod +x "$work/bin/docker"

cat >"$work/bin/skopeo" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$MOCK_CAPTURE_DIR/skopeo-calls"
case "$1" in
  login)
    token="$(cat)"
    [[ "$token" == "$FAKE_TOKEN" ]]
    [[ -z "${FAIL_LOGIN:-}" ]] || exit 1
    ;;
  inspect)
    [[ -n "${SKOPEO_AUTH_VOLUME:-}" || -n "${ANONYMOUS_SUCCESS:-}" ]] || exit 1
    ref="${*: -1}"
    case "$ref" in
      *'/base:latest') image=base; digest="sha256:$(printf '1%.0s' {1..64})" ;;
      *'/workspace:latest') image=workspace; digest="sha256:$(printf '2%.0s' {1..64})" ;;
      *) exit 2 ;;
    esac
    [[ "${FAIL_IMAGE:-}" != "$image" ]] || exit 1
    if [[ "${MALFORMED_IMAGE:-}" == "$image" ]]; then
      printf '%s\n' 'not-json'
      exit 0
    fi
    printf '{"Name":"ghcr.io/codewiresh/%s","Digest":"%s","Labels":{"org.opencontainers.image.revision":"%s"}}\n' \
      "$image" "$digest" "$SOURCE_SHA"
    ;;
  *) exit 2 ;;
esac
MOCK
chmod +x "$work/bin/skopeo"

run_resolver() {
  local output="$1"
  shift
  env \
    GHCR_PUBLISH_USERNAME=codewire-package-publisher \
    INFISICAL_SECRET_FETCHER="$work/bin/fetch-secret" \
    SKOPEO_RUNNER="$work/bin/skopeo" \
    DOCKER_BIN="$work/bin/docker" \
    MOCK_CAPTURE_DIR="$work/capture" \
    FAKE_TOKEN="$TEST_TOKEN" \
    SOURCE_SHA="$SOURCE_SHA" \
    "$@" \
    "$RESOLVER" "$output"
}

success="$work/success.json"
run_resolver "$success"
if ! jq -e --arg source "$SOURCE_SHA" '
  .schema == "codewire.ci-published-support-candidate/v1"
  and .retrieval == {valid: true, reasons: []}
  and .images.base.repository == "ghcr.io/codewiresh/base"
  and .images.workspace.repository == "ghcr.io/codewiresh/workspace"
  and .images.base.tag == "latest"
  and .images.workspace.tag == "latest"
  and .images.base.revision == $source
  and .images.workspace.revision == $source
  and (.images.base.digest | test("^sha256:[0-9a-f]{64}$"))
  and (.images.workspace.digest | test("^sha256:[0-9a-f]{64}$"))
' "$success" >/dev/null; then
  jq . "$success" >&2
  fail 'matching registry response was not preserved'
fi
if grep -Fq "$TEST_TOKEN" "$success" "$work/capture/skopeo-calls"; then
  fail 'resolver exposed the registry token'
fi
token_target="$(cat "$work/capture/fetch-target")"
[[ ! -e "$token_target" ]] || fail 'resolver retained the registry token file'
grep -Fxq 'volume rm support-baseline-auth' "$work/capture/docker-calls" ||
  fail 'resolver did not remove the Skopeo auth volume'

rm -f "$work/capture/fetch-target"
anonymous="$work/anonymous.json"
run_resolver "$anonymous" ANONYMOUS_SUCCESS=1 FAIL_FETCH=1
jq -e '.retrieval == {valid: true, reasons: []}' "$anonymous" >/dev/null ||
  fail 'anonymous public registry response was rejected'
[[ ! -e "$work/capture/fetch-target" ]] ||
  fail 'anonymous registry success still retrieved a credential'

lookup_failure="$work/lookup-failure.json"
run_resolver "$lookup_failure" FAIL_IMAGE=workspace
jq -e '.retrieval == {valid: false, reasons: ["workspace_registry_lookup_failed"]} and .images == {}' \
  "$lookup_failure" >/dev/null || fail 'partial publication did not fail closed'

malformed="$work/malformed.json"
run_resolver "$malformed" MALFORMED_IMAGE=base
jq -e '.retrieval == {valid: false, reasons: ["base_registry_response_malformed"]}' \
  "$malformed" >/dev/null || fail 'malformed registry response did not fail closed'

fetch_failure="$work/fetch-failure.json"
run_resolver "$fetch_failure" FAIL_FETCH=1
jq -e '.retrieval == {valid: false, reasons: ["credential_unavailable"]}' \
  "$fetch_failure" >/dev/null || fail 'missing registry credential did not fail closed'

printf '[test-resolve-published-support-pair] matching, partial, malformed, and credential cases passed\n'
