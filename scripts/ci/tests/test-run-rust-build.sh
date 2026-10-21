#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly RUNNER="$ROOT/scripts/ci/images/run-rust-build.sh"

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/codewire-run-rust-build.XXXXXXXX")"
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT

mkdir -p "$work/bin"
cat >"$work/bin/sccache" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  --zero-stats)
    [[ -z "${FAKE_SCCACHE_LOG:-}" ]] ||
      printf 'start bucket=%s uds=%s conf=%s\n' "${SCCACHE_BUCKET:-none}" \
        "$SCCACHE_SERVER_UDS" "$(cat "${SCCACHE_CONF:-/dev/null}")" >>"$FAKE_SCCACHE_LOG"
    # Model a server that cannot start because its backend is unreachable,
    # or one whose R2 level alone times out.
    case "${FAKE_SCCACHE_START:-ok}" in
      ok) ;;
      fail-r2) [[ -z "${SCCACHE_BUCKET:-}" ]] || exit 2 ;;
      *)
        printf 'sccache: error: Timed out waiting for server startup\n' >&2
        exit 2
        ;;
    esac
    ;;
  --show-stats|--stop-server) ;;
  *) exit 64 ;;
esac
EOF
chmod +x "$work/bin/sccache"

cat >"$work/assert-local" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for name in \
  SCCACHE_BUCKET SCCACHE_ENDPOINT SCCACHE_REGION SCCACHE_S3_USE_SSL \
  SCCACHE_S3_KEY_PREFIX SCCACHE_MULTILEVEL_CHAIN \
  SCCACHE_MULTILEVEL_WRITE_ERROR_POLICY SCCACHE_IGNORE_SERVER_IO_ERROR \
  AWS_SHARED_CREDENTIALS_FILE AWS_PROFILE AWS_ACCESS_KEY_ID \
  AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_WEB_IDENTITY_TOKEN_FILE \
  AWS_ROLE_ARN; do
  [[ ! -v "$name" ]] || {
    printf 'local cache retained remote variable %s\n' "$name" >&2
    exit 1
  }
done
[[ "$AWS_EC2_METADATA_DISABLED" == true ]]
[[ "$RUSTC_WRAPPER" == /usr/local/bin/sccache ]]
[[ "$SCCACHE_DIR" == /var/cache/sccache ]]
[[ "$SCCACHE_DIRECT" == false ]]
[[ "$SCCACHE_SERVER_UDS" == /tmp/codewire-sccache.sock ]]
EOF
chmod +x "$work/assert-local"

env \
  PATH="$work/bin:$PATH" \
  CODEWIRE_SCCACHE_MODE=local \
  SCCACHE_BUCKET=remote-bucket \
  SCCACHE_ENDPOINT=https://example.invalid \
  SCCACHE_REGION=auto \
  SCCACHE_S3_USE_SSL=true \
  SCCACHE_S3_KEY_PREFIX=untrusted/codewire/v1 \
  SCCACHE_MULTILEVEL_CHAIN=disk,s3 \
  SCCACHE_MULTILEVEL_WRITE_ERROR_POLICY=ignore \
  SCCACHE_IGNORE_SERVER_IO_ERROR=1 \
  AWS_SHARED_CREDENTIALS_FILE=/tmp/remote-credentials \
  AWS_PROFILE=default \
  AWS_ACCESS_KEY_ID=not-a-secret \
  AWS_SECRET_ACCESS_KEY=not-a-secret \
  AWS_SESSION_TOKEN=not-a-secret \
  AWS_WEB_IDENTITY_TOKEN_FILE=/tmp/token \
  AWS_ROLE_ARN=arn:aws:iam::000000000000:role/example \
  "$RUNNER" "$work/assert-local" >/dev/null

printf '[test-run-rust-build] local fallback is disk-only\n'

CODEWIRE_SCCACHE_MODE=disabled RUSTC_WRAPPER=/must-not-run RUSTC_WORKSPACE_WRAPPER=/must-not-run \
  "$RUNNER" bash -eu -c '[[ ! -v RUSTC_WRAPPER && ! -v RUSTC_WORKSPACE_WRAPPER ]]' >/dev/null
printf '[test-run-rust-build] disabled mode clears inherited wrappers\n'

fallback_log="$work/fallback.log"
env \
  PATH="$work/bin:$PATH" \
  FAKE_SCCACHE_START=timeout \
  CODEWIRE_SCCACHE_MODE=local \
  "$RUNNER" bash -eu -c '[[ ! -v RUSTC_WRAPPER && ! -v RUSTC_WORKSPACE_WRAPPER ]]' \
  >"$fallback_log" 2>&1 || {
    cat "$fallback_log" >&2
    printf 'an sccache startup failure failed the build\n' >&2
    exit 1
  }
grep -qF 'sccache did not start; compiling without it' "$fallback_log"
grep -qF 'CODEWIRE_CI_PHASE name=rust-compile-link mode=unavailable' "$fallback_log"
printf '[test-run-rust-build] an sccache startup failure compiles without the cache\n'

set +e
env PATH="$work/bin:$PATH" FAKE_SCCACHE_START=timeout CODEWIRE_SCCACHE_MODE=local \
  "$RUNNER" bash -c 'exit 7' >/dev/null 2>&1
failed_status=$?
set -e
[[ "$failed_status" -eq 7 ]] || {
  printf 'a failing build after an sccache fallback returned %s, not 7\n' "$failed_status" >&2
  exit 1
}
printf '[test-run-rust-build] the build status survives the fallback\n'

# An R2 server that cannot start retries as the disk-only cache on its own
# socket, with the minute-long startup wait, and still compiles cached.
printf '%s\n' '[default]' 'aws_access_key_id = synthetic' >"$work/r2.aws"
r2_log="$work/r2-start.log"
env \
  PATH="$work/bin:$PATH" \
  TMPDIR="$work" \
  FAKE_SCCACHE_START=fail-r2 \
  FAKE_SCCACHE_LOG="$r2_log" \
  CODEWIRE_SCCACHE_MODE=r2 \
  SCCACHE_BUCKET=remote-bucket \
  SCCACHE_ENDPOINT=https://example.invalid \
  CODEWIRE_SCCACHE_PREFIX=untrusted/codewire/v1 \
  AWS_SHARED_CREDENTIALS_FILE="$work/r2.aws" \
  "$RUNNER" bash -eu -c '
    [[ "$RUSTC_WRAPPER" == /usr/local/bin/sccache ]]
    [[ ! -v SCCACHE_BUCKET && ! -v SCCACHE_MULTILEVEL_CHAIN && ! -v AWS_SHARED_CREDENTIALS_FILE ]]
    [[ "$SCCACHE_SERVER_UDS" == /tmp/codewire-sccache.sock.local ]]' \
  >"$work/r2.out" 2>&1 || {
    cat "$work/r2.out" >&2
    printf 'an R2 startup failure did not fall back to the local cache\n' >&2
    exit 1
  }
[[ "$(cat "$r2_log")" == "start bucket=remote-bucket uds=/tmp/codewire-sccache.sock conf=server_startup_timeout_ms = 60000
start bucket=none uds=/tmp/codewire-sccache.sock.local conf=server_startup_timeout_ms = 60000" ]] || {
  cat "$r2_log" >&2
  printf 'R2 fallback did not retry exactly once, disk-only, on its own socket\n' >&2
  exit 1
}
grep -qF 'sccache did not start with R2; retrying with the local cache' "$work/r2.out"
grep -qF 'CODEWIRE_CI_PHASE name=rust-compile-link mode=local' "$work/r2.out"
[[ -z "$(find "$work" -maxdepth 1 -name 'codewire-sccache-conf.*' -print -quit)" ]] || {
  printf 'the startup timeout config outlived the build\n' >&2
  exit 1
}
# An explicit Cargo job count reaches Cargo; an empty build argument leaves
# Cargo's own default, and anything else is refused before Cargo runs.
jobs_of() {
  rm -f "$work/jobs.seen"
  # shellcheck disable=SC2016 # The probe expands in the wrapped command.
  env "$@" CODEWIRE_SCCACHE_MODE=disabled PATH="$work/bin:$PATH" JOBS_SEEN="$work/jobs.seen" \
    "$RUNNER" bash -c 'printf "%s" "${CARGO_BUILD_JOBS-unset}" >"$JOBS_SEEN"' >/dev/null || return
  cat "$work/jobs.seen"
}
[[ "$(jobs_of CARGO_BUILD_JOBS=14)" == 14 ]] || { echo 'explicit Cargo jobs did not reach Cargo' >&2; exit 1; }
[[ "$(jobs_of CARGO_BUILD_JOBS=)" == unset ]] || { echo 'an empty Cargo job count reached Cargo' >&2; exit 1; }
[[ "$(jobs_of -u CARGO_BUILD_JOBS)" == unset ]] || { echo 'an absent Cargo job count was invented' >&2; exit 1; }
for bad in 0 -1 1x 1000 ' 4'; do
  if jobs_of CARGO_BUILD_JOBS="$bad" >/dev/null 2>"$work/jobs.err"; then
    echo "an invalid Cargo job count was accepted: $bad" >&2
    exit 1
  fi
  grep -qF 'invalid CARGO_BUILD_JOBS' "$work/jobs.err" || { echo "Cargo job refusal was not attributable: $bad" >&2; exit 1; }
done
printf '[test-run-rust-build] an R2 startup failure falls back to the local cache\n'
