#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly RUNNER="$ROOT/scripts/ci/images/run-skopeo-container.sh"
readonly IMAGE='quay.io/skopeo/stable@sha256:8b23fe434af822adf71bc7c8674a8dfab379771aa1400fb81ff655a5cecfca87'

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
export FAKE_STDIN_PREFIX="$work/stdin"
TEST_REF="docker://git.example.invalid/codewire/gateway@sha256:$(printf 'a%.0s' {1..64})"
readonly TEST_REF
SKOPEO_AUTH_VOLUME=codewire-auth-fixture \
  "$RUNNER" inspect --authfile /auth/auth.json \
  "$TEST_REF" </dev/null

for required in \
  'run' '--rm' '-i' '--env' 'GOMAXPROCS=2' '--pids-limit=256' '--cap-drop=ALL' \
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

printf '[test-run-skopeo-container] exact container runtime contract passed\n'
