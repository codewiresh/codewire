#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly RUNNER="$ROOT/scripts/ci/verify/run-host-rust-build.sh"

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/codewire-run-host-rust-build.XXXXXXXX")"
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT

mkdir -p "$work/bin" "$work/target"
cat >"$work/bin/sccache" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  --zero-stats|--show-stats|--stop-server) exit 0 ;;
  *) exit 64 ;;
esac
EOF
chmod +x "$work/bin/sccache"

cat >"$work/assert-r2" <<EOF
#!/usr/bin/env bash
set -euo pipefail
[[ "\$AWS_SHARED_CREDENTIALS_FILE" == "$work/r2.aws" ]]
[[ "\$SCCACHE_DIR" == "$work/target/sccache-host" ]]
[[ "\$SCCACHE_S3_KEY_PREFIX" == untrusted/codewire/test ]]
[[ "\$SCCACHE_MULTILEVEL_CHAIN" == disk,s3 ]]
[[ "\$CODEWIRE_RUST_PROFILE" == ci ]]
[[ "\$RUSTC_WRAPPER" == /usr/local/bin/sccache ]]
EOF
chmod +x "$work/assert-r2"
printf '[default]\naws_access_key_id = test\naws_secret_access_key = test\n' >"$work/r2.aws"
chmod 0600 "$work/r2.aws"

env PATH="$work/bin:$PATH" \
  CARGO_TARGET_DIR="$work/target" \
  CODEWIRE_SCCACHE_MODE=r2 \
  CODEWIRE_SCCACHE_CREDENTIALS_FILE="$work/r2.aws" \
  CODEWIRE_SCCACHE_PREFIX=untrusted/codewire/test \
  SCCACHE_BUCKET=test \
  SCCACHE_ENDPOINT=https://example.invalid \
  "$RUNNER" "$work/assert-r2" >/dev/null

if env PATH="$work/bin:$PATH" \
  CARGO_TARGET_DIR="$work/target" \
  CODEWIRE_SCCACHE_MODE=r2 \
  CODEWIRE_SCCACHE_CREDENTIALS_FILE="$work/r2.aws" \
  CODEWIRE_SCCACHE_PREFIX=protected/codewire/test \
  SCCACHE_BUCKET=test \
  SCCACHE_ENDPOINT=https://example.invalid \
  "$RUNNER" true >/dev/null 2>&1; then
  printf 'host Rust cache accepted a protected prefix in an untrusted job\n' >&2
  exit 1
fi

CODEWIRE_SCCACHE_MODE=disabled "$RUNNER" true >/dev/null
printf '[test-run-host-rust-build] host adapter preserves disabled fallback and scopes R2 writes\n'
