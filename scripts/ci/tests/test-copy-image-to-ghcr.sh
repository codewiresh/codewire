#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
# CI names these in Actions variables and the job context; the scripts
# require them.
export CODEWIRE_IMAGE_REGISTRY=registry.example.invalid
readonly COPY_IMAGE="$ROOT/scripts/ci/images/copy-image-to-ghcr.sh"

fail() {
  printf '[test-copy-image-to-ghcr] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/copy-image-to-ghcr.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/state"

expected_digest="sha256:$(printf 'a%.0s' {1..64})"
other_digest="sha256:$(printf 'b%.0s' {1..64})"
source_sha="$(printf 'c%.0s' {1..40})"
release_tag="v1.2.3"
source_ref="registry.example.invalid/codewire/daemon@$expected_digest"
target_repository="ghcr.io/codewiresh/daemon"

printf 'harbor-test-password' >"$work/harbor-password"
printf 'ghcr-test-token' >"$work/ghcr-token"
chmod 600 "$work/harbor-password" "$work/ghcr-token"

cat >"$work/bin/skopeo-runner" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

[[ "${SKOPEO_AUTH_VOLUME:?}" == fake-auth-volume ]]

printf '%q ' "$@" >>"${FAKE_CALLS:?}"
printf '\n' >>"$FAKE_CALLS"

command="$1"
shift
if [ "${FAKE_RUNTIME_FAILURE:-0}" = 1 ]; then
  echo '[skopeo-runtime] class=runtime-unavailable detail=approved-image-missing' >&2
  exit 1
fi
case "$command" in
  login)
    credential="$(cat)"
    [ -n "$credential" ]
    host="${!#}"
    if [ "$host" = registry.example.invalid ] && [ -n "${FAKE_HARBOR_LOGIN_FAILURES:-}" ]; then
      count="$(cat "${FAKE_HARBOR_LOGIN_STATE:?}")"
      if [ "$count" -lt "$FAKE_HARBOR_LOGIN_FAILURES" ]; then
        printf '%s\n' "$((count + 1))" >"$FAKE_HARBOR_LOGIN_STATE"
        echo 'time="fixture" level=fatal msg="logging into registry.example.invalid: invalid username/password"' >&2
        exit 1
      fi
    fi
    if [ "$host" = ghcr.io ] && [ -n "${FAKE_GHCR_CONNECT_FAILURES:-}" ]; then
      count="$(cat "${FAKE_GHCR_CONNECT_STATE:?}")"
      if [ "$count" -lt "$FAKE_GHCR_CONNECT_FAILURES" ]; then
        printf '%s\n' "$((count + 1))" >"$FAKE_GHCR_CONNECT_STATE"
        echo 'time="fixture" level=fatal msg="authenticating creds for ghcr.io: pinging container registry ghcr.io: Get https://ghcr.io/v2/: dial tcp 140.82.121.33:443: i/o timeout"' >&2
        exit 1
      fi
    fi
    ;;
  inspect)
    ref="${!#}"
    ref="${ref#docker://}"
    if [[ "$ref" == registry.example.invalid/*@sha256:* ]]; then
      printf '%s\n' "${FAKE_SOURCE_DIGEST:?}"
      exit 0
    fi
    if [ "${FAKE_INSPECT_ERROR:-0}" = 1 ]; then
      echo 'temporary registry transport failure' >&2
      exit 1
    fi
    tag="${ref##*:}"
    state="${FAKE_STATE:?}/$tag"
    if [ ! -f "$state" ]; then
      echo 'manifest unknown' >&2
      exit 1
    fi
    cat "$state"
    ;;
  copy)
    args=("$@")
    destination="${args[${#args[@]}-1]}"
    tag="${destination##*:}"
    printf '%s\n' "${FAKE_SOURCE_DIGEST:?}" >"${FAKE_STATE:?}/$tag"
    ;;
  *)
    echo "unexpected fake skopeo command: $command" >&2
    exit 1
    ;;
esac
EOF
cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"${FAKE_DOCKER_CALLS:?}"
case "$*" in
  'volume create') printf 'fake-auth-volume\n' ;;
  'volume rm fake-auth-volume') ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$work/bin/skopeo-runner" "$work/bin/docker"

export SKOPEO_RUNNER="$work/bin/skopeo-runner"
export DOCKER_BIN="$work/bin/docker"
export FAKE_CALLS="$work/calls"
export FAKE_DOCKER_CALLS="$work/docker-calls"
export FAKE_STATE="$work/state"
export FAKE_SOURCE_DIGEST="$expected_digest"
export HARBOR_PUBLISH_USERNAME='robot$codewire+publisher'
export HARBOR_PUBLISH_PASSWORD_FILE="$work/harbor-password"
export GHCR_PUBLISH_USERNAME="codewire-package-publisher"
export GHCR_PUBLISH_TOKEN_FILE="$work/ghcr-token"
export GITHUB_OUTPUT="$work/output"

printf '0\n' >"$work/harbor-login-state"
FAKE_HARBOR_LOGIN_FAILURES=1 \
FAKE_HARBOR_LOGIN_STATE="$work/harbor-login-state" \
  "$COPY_IMAGE" "$source_ref" "$target_repository" "$source_sha" "$release_tag" \
  >"$work/transient-login.out" 2>&1
grep -qF 'Harbor registry login was rejected; retrying authentication' \
  "$work/transient-login.out" || fail 'transient Harbor login was not reported'
[[ "$(grep -c '^login .*registry.example.invalid ' "$FAKE_CALLS")" -eq 2 ]] ||
  fail 'transient Harbor login was not retried exactly once'

for tag in "$source_sha" "$release_tag"; do
  [[ "$(<"$work/state/$tag")" == "$expected_digest" ]] ||
    fail "copied $tag does not have the canonical digest"
done
[[ "$(grep -c '^copy ' "$FAKE_CALLS")" -eq 2 ]] ||
  fail "first publication did not copy both immutable tags"
grep -qxF "source_digest=$expected_digest" "$GITHUB_OUTPUT" ||
  fail "source digest output is absent"
grep -qxF "ghcr_ref=$target_repository:$source_sha" "$GITHUB_OUTPUT" ||
  fail "first GHCR ref output is absent"
grep -qxF "ghcr_digest=$expected_digest" "$GITHUB_OUTPUT" ||
  fail "GHCR digest output is absent"

"$COPY_IMAGE" \
  "registry.example.invalid/codewire/confidential-probe@$expected_digest" \
  'ghcr.io/codewiresh/confidential-probe' "$source_sha" >/dev/null ||
  fail 'confidential-probe publication family is absent'
if grep -qF 'harbor-test-password' "$FAKE_CALLS" \
  || grep -qF 'ghcr-test-token' "$FAKE_CALLS"; then
  fail "a registry token reached the command arguments"
fi
[[ "$(grep -c '^volume create$' "$FAKE_DOCKER_CALLS")" -eq 2 ]] ||
  fail "each publication did not create one private auth volume"
[[ "$(grep -c '^volume rm fake-auth-volume$' "$FAKE_DOCKER_CALLS")" -eq 2 ]] ||
  fail "each publication did not delete its private auth volume"

printf '0\n' >"$work/ghcr-connect-state"
ghcr_login_calls_before="$(grep -c '^login .*ghcr.io ' "$FAKE_CALLS")"
if FAKE_GHCR_CONNECT_FAILURES=1 \
  FAKE_GHCR_CONNECT_STATE="$work/ghcr-connect-state" \
  "$COPY_IMAGE" "$source_ref" "$target_repository" "$source_sha" \
    >"$work/exhausted-connect.out" 2>&1; then
  fail 'exhausted GHCR connectivity failure was accepted'
fi
grep -qF 'Unable to reach GHCR registry after bounded retries' \
  "$work/exhausted-connect.out" || fail 'exhausted GHCR connectivity was mislabeled'
[[ "$(grep -c '^login .*ghcr.io ' "$FAKE_CALLS")" -eq $((ghcr_login_calls_before + 1)) ]] ||
  fail 'the copy helper retried an exhausted Skopeo network operation'

"$COPY_IMAGE" "$source_ref" "$target_repository" "$source_sha" "$release_tag" >/dev/null
[[ "$(grep -c '^copy ' "$FAKE_CALLS")" -eq 2 ]] ||
  fail "idempotent publication copied an existing matching tag"

printf '%s\n' "$other_digest" >"$work/state/$source_sha"
if "$COPY_IMAGE" "$source_ref" "$target_repository" "$source_sha" \
    >"$work/conflict.out" 2>&1; then
  fail "conflicting immutable destination tag was replaced"
fi
[[ "$(<"$work/state/$source_sha")" == "$other_digest" ]] ||
  fail "conflicting immutable destination state changed"

rm -f "$work/state/$source_sha"
if FAKE_INSPECT_ERROR=1 "$COPY_IMAGE" "$source_ref" "$target_repository" \
    "$source_sha" >"$work/transport.out" 2>&1; then
  fail "a transient destination inspection failure was treated as absence"
fi
[[ "$(grep -c '^copy ' "$FAKE_CALLS")" -eq 2 ]] ||
  fail "transport failure attempted a copy"

if FAKE_SOURCE_DIGEST="$other_digest" "$COPY_IMAGE" "$source_ref" \
    "$target_repository" "$source_sha" >"$work/source-mismatch.out" 2>&1; then
  fail "source digest mismatch was accepted"
fi

if "$COPY_IMAGE" "$source_ref" 'ghcr.io/codewiresh/services' "$source_sha" \
    >"$work/family-mismatch.out" 2>&1; then
  fail "source and destination image family mismatch was accepted"
fi
if "$COPY_IMAGE" "$source_ref" "$target_repository" latest \
    >"$work/moving-tag.out" 2>&1; then
  fail "runtime moving destination tag was accepted"
fi

printf '0\n' >"$work/persistent-harbor-login-state"
harbor_login_calls_before="$(grep -c '^login .*registry.example.invalid ' "$FAKE_CALLS")"
if FAKE_HARBOR_LOGIN_FAILURES=3 \
  FAKE_HARBOR_LOGIN_STATE="$work/persistent-harbor-login-state" \
  "$COPY_IMAGE" "$source_ref" "$target_repository" "$source_sha" \
    >"$work/persistent-login.out" 2>&1; then
  fail 'persistent Harbor login failure was accepted'
fi
grep -qF 'Unable to authenticate to Harbor registry' \
  "$work/persistent-login.out" || fail 'persistent Harbor login failure was not explicit'
[[ "$(grep -c '^login .*registry.example.invalid ' "$FAKE_CALLS")" -eq $((harbor_login_calls_before + 3)) ]] ||
  fail 'persistent Harbor login did not stop after three bounded attempts'

runtime_calls_before="$(wc -l <"$FAKE_CALLS")"
if FAKE_RUNTIME_FAILURE=1 "$COPY_IMAGE" "$source_ref" "$target_repository" \
    "$source_sha" >"$work/runtime-unavailable.out" 2>&1; then
  fail 'missing Skopeo runtime was accepted during registry login'
fi
grep -qF 'Skopeo runtime became unavailable during registry operation' \
  "$work/runtime-unavailable.out" || fail 'runtime failure was mislabeled as registry authentication'
if grep -qF 'Unable to authenticate to Harbor registry' "$work/runtime-unavailable.out"; then
  fail 'runtime failure retained the misleading Harbor authentication label'
fi
[[ "$(wc -l <"$FAKE_CALLS")" -eq $((runtime_calls_before + 1)) ]] ||
  fail 'runtime failure was retried as registry authentication'

support_source_ref="registry.example.invalid/codewire/base@$expected_digest"
support_target_repository='ghcr.io/codewiresh/base'
printf '%s\n' "$other_digest" >"$work/state/latest"
copy_calls_before="$(grep -c '^copy ' "$FAKE_CALLS")"
"$COPY_IMAGE" "$support_source_ref" "$support_target_repository" \
  "$source_sha" latest >"$work/support-latest.out"
[[ "$(<"$work/state/latest")" == "$expected_digest" ]] ||
  fail "support compatibility alias did not advance to the canonical digest"
[[ "$(grep -c '^copy ' "$FAKE_CALLS")" -eq $((copy_calls_before + 2)) ]] ||
  fail "support publication did not copy the immutable and compatibility aliases"
grep -qF 'Updating support-image compatibility alias' "$work/support-latest.out" ||
  fail "support compatibility update was not reported"

copy_calls_before="$(grep -c '^copy ' "$FAKE_CALLS")"
"$COPY_IMAGE" "$support_source_ref" "$support_target_repository" \
  "$source_sha" latest >/dev/null
[[ "$(grep -c '^copy ' "$FAKE_CALLS")" -eq "$copy_calls_before" ]] ||
  fail "matching support compatibility aliases were copied again"

"$COPY_IMAGE" "registry.example.invalid/codewire/workspace@$expected_digest" \
  'ghcr.io/codewiresh/workspace' latest >/dev/null ||
  fail "workspace compatibility alias was rejected"

if "$COPY_IMAGE" 'registry.example.invalid/codewire/daemon:latest' "$target_repository" \
    "$source_sha" >"$work/moving-source.out" 2>&1; then
  fail "moving source reference was accepted"
fi
if GHCR_PUBLISH_TOKEN_FILE="$work/missing" "$COPY_IMAGE" "$source_ref" \
    "$target_repository" "$source_sha" >"$work/missing-token.out" 2>&1; then
  fail "missing credential file was accepted"
fi

# Harbor is the registry deployments pull from: same exact-copy contract,
# its own publisher credential, and the Harbor keep tag of the exact digest.
printf 'harbor-test-password' >"$work/harbor-password"
chmod 600 "$work/harbor-password"
rm -f "$work/state/"*
harbor_repository='registry.example.invalid/codewire/daemon'
: >"$GITHUB_OUTPUT"
env -u GHCR_PUBLISH_USERNAME -u GHCR_PUBLISH_TOKEN_FILE \
  HARBOR_PUBLISH_USERNAME='robot$codewire+publisher' \
  HARBOR_PUBLISH_PASSWORD_FILE="$work/harbor-password" \
  "$COPY_IMAGE" "$source_ref" "$harbor_repository" "$source_sha" \
  "keep-${expected_digest/:/-}" >"$work/harbor.out" 2>&1 ||
  { cat "$work/harbor.out" >&2; fail 'Harbor publication failed'; }
grep -q '^login .*registry.example.invalid ' "$FAKE_CALLS" ||
  fail 'Harbor publication did not log in to registry.example.invalid'
[[ "$(<"$work/state/$source_sha")" == "$expected_digest" ]] ||
  fail 'Harbor source tag does not have the canonical digest'
grep -qxF "harbor_ref=$harbor_repository:$source_sha" "$GITHUB_OUTPUT" ||
  fail 'Harbor ref output is absent'
if grep -qF 'harbor-test-password' "$FAKE_CALLS"; then
  fail 'the Harbor credential reached the command arguments'
fi
if HARBOR_PUBLISH_USERNAME='robot$codewire+publisher' \
  HARBOR_PUBLISH_PASSWORD_FILE="$work/harbor-password" \
  "$COPY_IMAGE" "$source_ref" "$harbor_repository" "keep-sha256-$(printf 'd%.0s' {1..64})" \
    >"$work/harbor-keep-mismatch.out" 2>&1; then
  fail 'a Harbor keep tag for another digest was accepted'
fi
if "$COPY_IMAGE" "$source_ref" "$target_repository" "keep-${expected_digest/:/-}" \
    >"$work/ghcr-keep.out" 2>&1; then
  fail 'a Harbor keep tag was accepted for the GHCR mirror'
fi
if "$COPY_IMAGE" "$source_ref" 'registry.example.invalid/other/daemon' "$source_sha" \
    >"$work/harbor-project.out" 2>&1; then
  fail 'a Harbor repository outside the codewire project was accepted'
fi
if env -u HARBOR_PUBLISH_PASSWORD_FILE HARBOR_PUBLISH_USERNAME=x \
  "$COPY_IMAGE" "$source_ref" "$harbor_repository" "$source_sha" \
    >"$work/harbor-missing.out" 2>&1; then
  fail 'Harbor publication without its credential was accepted'
fi

echo 'copy-image-to-ghcr tests passed'
