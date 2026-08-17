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
  --zero-stats|--show-stats|--stop-server) exit 0 ;;
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
