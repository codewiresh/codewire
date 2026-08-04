#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PACKAGE="$ROOT/scripts/ci/release/package-codewire-desktop.sh"
CI_WORKFLOW="$ROOT/.gitea/workflows/ci.yaml"
RUNNER_ASSERTION="$ROOT/scripts/ci/setup/assert-ci-runner-image.sh"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/test-package-codewire-desktop.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# Wry links xkbcommon-x11 directly. The immutable runner image owns the native
# package, and the planner-selected Rust capability group must assert that
# contract before the detached package dry run.
grep -Fq 'libxkbcommon-x11-dev' "$RUNNER_ASSERTION"
grep -Fq 'scripts/ci/setup/assert-ci-runner-image.sh' "$CI_WORKFLOW"
grep -Fq "contains(needs.verification-selection.outputs.selection, '|rust_pkg_codewire_desktop|')" \
  "$CI_WORKFLOW"
[ ! -e "$ROOT/.gitea/workflows/desktop-package.yaml" ]

mkdir -p "$TMP/bin" "$TMP/target/release"
printf '#!/usr/bin/env sh\nexit 0\n' >"$TMP/target/release/codewire"
chmod +x "$TMP/target/release/codewire"

cat >"$TMP/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  build) exit 0 ;;
  *) exit 1 ;;
esac
EOF
cat >"$TMP/bin/rustc" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "${1:-}" = -vV ]
printf 'host: x86_64-unknown-linux-gnu\n'
EOF
chmod +x "$TMP/bin/cargo" "$TMP/bin/rustc"

PATH="$TMP/bin:$PATH" \
  CARGO_TARGET_DIR="$TMP/target" \
  CODEWIRE_DESKTOP_PACKAGE_DIR="$TMP/package" \
  "$PACKAGE" --dry-run 0.0.0-ci >"$TMP/output"

grep -Fq 'desktop package dry-run:' "$TMP/output"
[ -f "$TMP/package/codewire-desktop-0.0.0-ci-x86_64-unknown-linux-gnu.tar.gz" ]
[ -f "$TMP/package/SHA256SUMS" ]
(
  cd "$TMP/package"
  sha256sum --check SHA256SUMS
)
archive="$TMP/package/codewire-desktop-0.0.0-ci-x86_64-unknown-linux-gnu.tar.gz"
archive_entries="$(tar -tzf "$archive")"
grep -Fq 'codewire-desktop-0.0.0-ci-x86_64-unknown-linux-gnu/bin/codewire' \
  <<<"$archive_entries"
grep -Fq 'codewire-desktop-0.0.0-ci-x86_64-unknown-linux-gnu/LICENSE' \
  <<<"$archive_entries"
grep -Fq 'codewire-desktop-0.0.0-ci-x86_64-unknown-linux-gnu/BUILD-INFO' \
  <<<"$archive_entries"
build_info="$(tar -xOzf "$archive" \
  codewire-desktop-0.0.0-ci-x86_64-unknown-linux-gnu/BUILD-INFO)"
grep -Fqx 'version=0.0.0-ci' <<<"$build_info"

if PATH="$TMP/bin:$PATH" \
  CARGO_TARGET_DIR="$TMP/target" \
  CODEWIRE_DESKTOP_PACKAGE_DIR="$TMP/signed" \
  "$PACKAGE" 0.0.0-ci >/dev/null 2>&1; then
  echo 'package desktop test failed: unsigned publication unexpectedly succeeded' >&2
  exit 1
fi

echo 'desktop package dry-run tests passed'
