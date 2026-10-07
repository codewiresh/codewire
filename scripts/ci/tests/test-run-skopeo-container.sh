#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly RUNNER="$ROOT/scripts/ci/images/run-skopeo-container.sh"
readonly IMAGE='registry.example.invalid/oci-approved/skopeo/stable@sha256:8b23fe434af822adf71bc7c8674a8dfab379771aa1400fb81ff655a5cecfca87'

fail() {
  printf '[test-run-skopeo-container] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/run-skopeo-container.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = image ] && [ "${2:-}" = inspect ]; then
  printf '%s\n' "$*" >>"${FAKE_DOCKER_CHECKS:?}"
  if [ "${FAKE_IMAGE_MISSING:-0}" = 1 ]; then
    exit 1
  fi
  printf 'sha256:fixture\n'
  exit 0
fi
attempt=1
if [ -f "${FAKE_DOCKER_ATTEMPTS:?}" ]; then
  attempt="$(($(cat "$FAKE_DOCKER_ATTEMPTS") + 1))"
fi
printf '%s\n' "$attempt" >"$FAKE_DOCKER_ATTEMPTS"
printf '%s\n' "$@" >"${FAKE_DOCKER_ARGS:?}"
cat >"${FAKE_STDIN_PREFIX:?}.$attempt"
if [ "${FAKE_NONRETRYABLE_FAILURE:-0}" = 1 ]; then
  echo 'registry authorization failed' >&2
  exit 9
fi
if [ "$attempt" -le "${FAKE_NETWORK_FAILURES:-0}" ]; then
  echo 'time="fixture" level=fatal msg="Error listing repository tags: pinging container registry ghcr.io: Get https://ghcr.io/v2/: dial tcp 140.82.121.33:443: i/o timeout"' >&2
  exit 7
fi
if [ "$attempt" -le "${FAKE_TRANSIENT_FAILURES:-0}" ]; then
  echo 'runtime/cgo: pthread_create failed: Resource temporarily unavailable' >&2
  exit 2
fi
printf 'skopeo-ok\n'
EOF
chmod +x "$work/bin/docker"

export DOCKER_BIN="$work/bin/docker"
export FAKE_DOCKER_ARGS="$work/docker-args"
export FAKE_DOCKER_ATTEMPTS="$work/docker-attempts"
export FAKE_DOCKER_CHECKS="$work/docker-checks"
export FAKE_STDIN_PREFIX="$work/stdin"
TEST_REF="docker://git.example.invalid/codewire/daemon@sha256:$(printf 'a%.0s' {1..64})"
readonly TEST_REF
"$RUNNER" --check >"$work/check.out"
grep -qxF 'SKOPEO_RUNTIME_READY' "$work/check.out" ||
  fail 'Skopeo runtime check did not emit its fixed success marker'
grep -qxF "image inspect --format {{.Id}} $IMAGE" "$FAKE_DOCKER_CHECKS" ||
  fail 'Skopeo runtime check did not inspect the exact approved digest'
SKOPEO_AUTH_VOLUME=codewire-auth-fixture \
  "$RUNNER" inspect --authfile /auth/auth.json \
  "$TEST_REF" </dev/null

for required in \
  'run' '--rm' '-i' '--pull=never' '--env' 'GOMAXPROCS=2' '--pids-limit=256' '--cap-drop=ALL' \
  '--security-opt=no-new-privileges' '--network=bridge' \
  'type=volume,src=codewire-auth-fixture,dst=/auth' \
  "$IMAGE" 'inspect' '--authfile' '/auth/auth.json'; do
  grep -qxF -- "$required" "$FAKE_DOCKER_ARGS" ||
    fail "Docker invocation omits $required"
done
if grep -qi token "$FAKE_DOCKER_ARGS"; then
  fail 'Docker arguments contain token-like material'
fi
[[ "$(cat "$FAKE_DOCKER_ATTEMPTS")" == 1 ]] ||
  fail 'successful Skopeo startup was repeated'
[[ "$(wc -l <"$FAKE_DOCKER_CHECKS")" -eq 2 ]] ||
  fail 'Skopeo runtime was not checked before direct use'

rm -f "$FAKE_DOCKER_ATTEMPTS"
if SKOPEO_AUTH_VOLUME='invalid/volume' "$RUNNER" inspect example \
    >"$work/invalid.out" 2>&1; then
  fail 'malformed auth volume was accepted'
fi
[[ ! -e "$FAKE_DOCKER_ATTEMPTS" ]] ||
  fail 'malformed auth volume reached Docker'

retry_secret='retry-stdin-secret'
retry_output="$work/retry.out"
rm -f "$FAKE_DOCKER_ATTEMPTS"
if ! printf '%s' "$retry_secret" | \
  FAKE_TRANSIENT_FAILURES=2 SKOPEO_STARTUP_RETRY_DELAY_SECONDS=0 \
  "$RUNNER" inspect example >"$retry_output" 2>&1; then
  fail 'bounded transient Skopeo startup recovery failed'
fi
[[ "$(cat "$FAKE_DOCKER_ATTEMPTS")" == 3 ]] ||
  fail 'transient Skopeo startup did not use the bounded retry count'
for attempt in 1 2 3; do
  [[ "$(cat "$FAKE_STDIN_PREFIX.$attempt")" == "$retry_secret" ]] ||
    fail "private stdin was not preserved for startup attempt $attempt"
done
[[ "$(grep -Fc 'transient thread exhaustion' "$retry_output")" == 2 ]] ||
  fail 'transient startup retries were not reported without details'
grep -Fq 'skopeo-ok' "$retry_output" ||
  fail 'successful retry did not preserve Skopeo output'
if grep -Fq "$retry_secret" "$retry_output"; then
  fail 'private stdin reached retry output'
fi

rm -f "$FAKE_DOCKER_ATTEMPTS"
network_retry_output="$work/network-retry.out"
network_retry_secret='network-retry-stdin-secret'
if ! printf '%s' "$network_retry_secret" | \
  FAKE_NETWORK_FAILURES=2 SKOPEO_NETWORK_RETRY_DELAY_SECONDS=0 \
    "$RUNNER" list-tags --no-creds docker://ghcr.io/codewiresh/base \
      >"$network_retry_output" 2>&1; then
  fail 'bounded transient registry recovery failed'
fi
[[ "$(cat "$FAKE_DOCKER_ATTEMPTS")" == 3 ]] ||
  fail 'transient registry operation did not use three bounded attempts'
[[ "$(grep -Fc '[skopeo-network] transient registry connectivity' "$network_retry_output")" == 2 ]] ||
  fail 'transient registry retries were not reported with fixed markers'
[[ "$(grep -Fc 'dial tcp 140.82.121.33:443: i/o timeout' "$network_retry_output")" == 2 ]] ||
  fail 'transient registry retries suppressed their structural error evidence'
if grep -Fq "$network_retry_secret" "$network_retry_output"; then
  fail 'private stdin reached transient registry output'
fi

rm -f "$FAKE_DOCKER_ATTEMPTS"
if FAKE_NETWORK_FAILURES=3 SKOPEO_NETWORK_RETRY_DELAY_SECONDS=0 \
  "$RUNNER" login ghcr.io >"$work/network-exhausted.out" 2>&1; then
  fail 'exhausted registry retries were accepted'
fi
[[ "$(cat "$FAKE_DOCKER_ATTEMPTS")" == 3 ]] ||
  fail 'registry recovery exceeded three bounded attempts'
grep -qxF '[skopeo-network] class=transient-exhausted' \
  <(grep -F '[skopeo-network] class=transient-exhausted' "$work/network-exhausted.out") ||
  fail 'exhausted registry connectivity lacks its fixed marker'
grep -Fq 'dial tcp 140.82.121.33:443: i/o timeout' "$work/network-exhausted.out" ||
  fail 'exhausted registry connectivity suppressed the terminal error'

rm -f "$FAKE_DOCKER_ATTEMPTS"
if printf 'private' | FAKE_NONRETRYABLE_FAILURE=1 \
  SKOPEO_STARTUP_RETRY_DELAY_SECONDS=0 \
  "$RUNNER" inspect example >"$work/nonretryable.out" 2>&1; then
  fail 'non-retryable Skopeo failure was accepted'
fi
[[ "$(cat "$FAKE_DOCKER_ATTEMPTS")" == 1 ]] ||
  fail 'registry failure was incorrectly retried'
grep -Fq 'registry authorization failed' "$work/nonretryable.out" ||
  fail 'non-retryable Skopeo error was not preserved'

rm -f "$FAKE_DOCKER_ATTEMPTS"
if FAKE_TRANSIENT_FAILURES=3 SKOPEO_STARTUP_RETRY_DELAY_SECONDS=0 \
  "$RUNNER" inspect example >"$work/exhausted.out" 2>&1; then
  fail 'exhausted Skopeo startup retries were accepted'
fi
[[ "$(cat "$FAKE_DOCKER_ATTEMPTS")" == 3 ]] ||
  fail 'Skopeo startup recovery exceeded its bounded attempts'

rm -f "$FAKE_DOCKER_ATTEMPTS"
if SKOPEO_STARTUP_RETRY_DELAY_SECONDS=invalid \
  "$RUNNER" inspect example >"$work/invalid-delay.out" 2>&1; then
  fail 'invalid startup retry delay was accepted'
fi
[[ ! -e "$FAKE_DOCKER_ATTEMPTS" ]] ||
  fail 'invalid startup retry delay reached Docker'

rm -f "$FAKE_DOCKER_ATTEMPTS"
if SKOPEO_NETWORK_RETRY_DELAY_SECONDS=invalid \
  "$RUNNER" inspect example >"$work/invalid-network-delay.out" 2>&1; then
  fail 'invalid network retry delay was accepted'
fi
[[ ! -e "$FAKE_DOCKER_ATTEMPTS" ]] ||
  fail 'invalid network retry delay reached Docker'

rm -f "$FAKE_DOCKER_ATTEMPTS"
if FAKE_IMAGE_MISSING=1 "$RUNNER" --check >"$work/missing-image.out" 2>&1; then
  fail 'missing approved Skopeo image was accepted'
fi
grep -qxF '[skopeo-runtime] class=runtime-unavailable detail=approved-image-missing' \
  "$work/missing-image.out" || fail 'missing runtime did not emit its fixed class'
[[ ! -e "$FAKE_DOCKER_ATTEMPTS" ]] ||
  fail 'missing approved Skopeo image reached docker run'

printf '[test-run-skopeo-container] exact container runtime contract passed\n'
