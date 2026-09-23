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
    # Model a server that cannot start because its backend is unreachable.
    [[ "${FAKE_SCCACHE_START:-ok}" == ok ]] || {
      printf 'sccache: error: Timed out waiting for server startup\n' >&2
      exit 2
    }
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
