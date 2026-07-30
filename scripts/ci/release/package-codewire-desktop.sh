#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: package-codewire-desktop.sh [--dry-run] <version>

Builds one host-native, private desktop package. --dry-run produces an
unsigned package only; signed publication is reserved for WS14 OP-1.

Environment:
  CODEWIRE_DESKTOP_PACKAGE_DIR  Output directory (default: dist/codewire-desktop)
  CARGO_TARGET_DIR              Cargo target directory (default: target)
EOF
}

die() {
  echo "package-codewire-desktop: $*" >&2
  exit 1
}

dry_run=false
case "${1:-}" in
  --dry-run)
    dry_run=true
    shift
    ;;
  --help|-h)
    usage
    exit 0
    ;;
esac

version="${1:-${VERSION:-}}"
[ -n "$version" ] || die "version is required"
case "$version" in
  v[0-9]*.[0-9]*.[0-9]*|[0-9]*.[0-9]*.[0-9]*-ci)
    ;;
  *)
    die "version must be a release tag or CI version"
    ;;
esac

[ "$dry_run" = true ] || die "signed publication is authorized only by WS14 OP-1; use --dry-run"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
manifest="$root/crates/codewire-desktop/Cargo.toml"
target_dir="${CARGO_TARGET_DIR:-$root/target}"
package_dir="${CODEWIRE_DESKTOP_PACKAGE_DIR:-$root/dist/codewire-desktop}"
host="$(rustc -vV | awk '/^host:/ {print $2}')"
package_name="codewire-desktop-${version}-${host}"

rm -rf "$package_dir"
mkdir -p "$package_dir/$package_name/bin"

cargo build --locked --manifest-path "$manifest" --release --target-dir "$target_dir"
binary="$target_dir/release/codewire"
[ -x "$binary" ] || die "expected desktop binary at $binary"

cp "$binary" "$package_dir/$package_name/bin/codewire"
cp "$root/crates/codewire-desktop/LICENSE" "$package_dir/$package_name/LICENSE"
printf '%s\n' "source_sha=$(git -C "$root" rev-parse HEAD)" >"$package_dir/$package_name/BUILD-INFO"
printf '%s\n' "version=$version" >>"$package_dir/$package_name/BUILD-INFO"
printf '%s\n' "target=$host" >>"$package_dir/$package_name/BUILD-INFO"

archive="$package_dir/$package_name.tar.gz"
tar -C "$package_dir" -czf "$archive" "$package_name"
(
  cd "$package_dir"
  sha256sum "$(basename "$archive")" >SHA256SUMS
  sha256sum --check SHA256SUMS
)

echo "desktop package dry-run: $archive"
