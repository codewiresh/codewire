#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly RUNNER="$ROOT/scripts/ci/verify/run-host-rust-build.sh"

# Each case chooses every compiler-cache setting itself. A caller's own
# selection, such as the sccache environment a CI job exports,
# must not reach the runner under test.
for name in "${!SCCACHE_@}" "${!CODEWIRE_SCCACHE_@}" RUSTC_WRAPPER \
    AWS_SHARED_CREDENTIALS_FILE AWS_PROFILE; do
  unset "$name"
done

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
  CODEWIRE_SCCACHE_PREFIX=other/codewire/test \
  SCCACHE_BUCKET=test \
  SCCACHE_ENDPOINT=https://example.invalid \
  "$RUNNER" true >/dev/null 2>&1; then
  printf 'host Rust cache accepted a prefix outside the reviewed caches\n' >&2
  exit 1
fi

CODEWIRE_SCCACHE_MODE=disabled "$RUNNER" true >/dev/null

# A workstation build with no job selection uses the shared local cache. Its
# server outlives the build: the image runner must not zero or stop it.
mkdir -p "$work/local-bin"
printf '%s\n' "$work/local-calls" >"$work/local-bin/calls-path"
cat >"$work/local-bin/sccache" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$(cat "$(dirname "$0")/calls-path")"
case "${1:-}" in
  --version) printf 'sccache 0.17.0\n' ;;
  --dist-status) [[ ! -e "$(dirname "$0")/start-fails" ]] ;;
  *) exit 64 ;;
esac
EOF
chmod +x "$work/local-bin/sccache"
cat >"$work/assert-local" <<EOF
#!/usr/bin/env bash
set -euo pipefail
[[ "\$RUSTC_WRAPPER" == "$ROOT/scripts/ci/verify/local-rust-cache-rustc.sh" ]]
[[ -z "\${CARGO_INCREMENTAL+x}" ]]
[[ "\$SCCACHE_DIR" == "$work/local-cache/cache" ]]
[[ "\$CODEWIRE_RUST_PROFILE" == ci ]]
EOF
chmod +x "$work/assert-local"
run_local() {
  env -u GITHUB_ACTIONS -u CI -u CODEWIRE_SCCACHE_MODE -u RUSTC_WRAPPER \
    -u CARGO_INCREMENTAL -u CODEWIRE_LOCAL_RUST_CACHE \
    PATH="$work/local-bin:$PATH" CODEWIRE_LOCAL_SCCACHE_BASE="$work/local-cache" \
    "$RUNNER" "$@"
}
run_local "$work/assert-local" >/dev/null 2>&1
if grep -Eq -- '--zero-stats|--stop-server|--show-stats' "$work/local-calls"; then
  printf 'host Rust build managed the shared local cache server\n' >&2
  exit 1
fi
# The cache is best effort: a server that does not start compiles uncached.
touch "$work/local-bin/start-fails"
run_local bash -c '[[ -z "${RUSTC_WRAPPER:-}" ]]' >/dev/null 2>&1
printf '[test-run-host-rust-build] host adapter preserves disabled fallback, scopes R2 writes and shares the local cache\n'
