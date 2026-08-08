#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: package-cw-release.sh <vX.Y.Z>

Builds Rust cw release assets into $CW_RELEASE_DIST_DIR.

Environment:
  CW_RELEASE_TARGETS             Space-separated target triples.
  CW_RELEASE_PROFILE             Cargo profile to build (default: release).
  CW_RELEASE_BUILD_CMD           Cargo command prefix (default: cargo build).
  CW_RELEASE_DIST_DIR            Output directory (default: dist/cw-release).
  CW_RELEASE_REQUIRE_SIGNATURE   Require SHA256SUMS.asc (default: 1).
  CW_RELEASE_GPG_PRIVATE_KEY     ASCII-armored private key for signing.
  CW_RELEASE_GPG_PASSPHRASE      Optional GPG passphrase.
  CW_RELEASE_GPG_KEY_ID          Optional signing key id.
EOF
}

die() {
  echo "package-cw-release: $*" >&2
  exit 1
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi

version="${1:-${VERSION:-}}"
[ -n "$version" ] || die "version is required"
case "$version" in
  v[0-9]*.[0-9]*.[0-9]*)
    ;;
  *)
    die "version must look like vX.Y.Z, got: $version"
    ;;
esac

host_target="$(rustc -vV | awk '/^host:/ {print $2}')"
targets="${CW_RELEASE_TARGETS:-$host_target}"
profile="${CW_RELEASE_PROFILE:-release}"
build_cmd="${CW_RELEASE_BUILD_CMD:-cargo build}"
dist_dir="${CW_RELEASE_DIST_DIR:-dist/cw-release}"
require_signature="${CW_RELEASE_REQUIRE_SIGNATURE:-1}"
target_dir="${CARGO_TARGET_DIR:-target}"

case "$profile" in
  dev)
    profile_dir="debug"
    profile_flag=()
    ;;
  release)
    profile_dir="release"
    profile_flag=(--release)
    ;;
  *)
    profile_dir="$profile"
    profile_flag=(--profile "$profile")
    ;;
esac

rm -rf "$dist_dir"
mkdir -p "$dist_dir"

for target in $targets; do
  echo "building cw $version for $target"
  # shellcheck disable=SC2206
  cmd=($build_cmd)
  CODEWIRE_VERSION="$version" "${cmd[@]}" \
    --locked \
    "${profile_flag[@]}" \
    -p codewire-cli-bin \
    --bin cw \
    --target "$target"

  binary="$target_dir/$target/$profile_dir/cw"
  [ -x "$binary" ] || die "expected built binary at $binary"
  cp "$binary" "$dist_dir/cw-$version-$target"
done

(
  cd "$dist_dir"
  sha256sum cw-* | sort -k2 > SHA256SUMS
)

if [ -n "${CW_RELEASE_GPG_PRIVATE_KEY:-}" ]; then
  gnupg_home="$(mktemp -d)"
  cleanup_gpg() {
    rm -rf "$gnupg_home"
  }
  trap cleanup_gpg EXIT
  chmod 700 "$gnupg_home"
  export GNUPGHOME="$gnupg_home"

  printf '%s\n' "$CW_RELEASE_GPG_PRIVATE_KEY" | gpg --batch --import
  gpg_args=(--batch --yes --pinentry-mode loopback --armor --detach-sign)
  if [ -n "${CW_RELEASE_GPG_PASSPHRASE:-}" ]; then
    gpg_args+=(--passphrase-fd 0)
  fi
  if [ -n "${CW_RELEASE_GPG_KEY_ID:-}" ]; then
    gpg_args+=(--local-user "$CW_RELEASE_GPG_KEY_ID")
  fi
  if [ -n "${CW_RELEASE_GPG_PASSPHRASE:-}" ]; then
    printf '%s' "$CW_RELEASE_GPG_PASSPHRASE" |
      gpg "${gpg_args[@]}" \
        --output "$dist_dir/SHA256SUMS.asc" \
        "$dist_dir/SHA256SUMS"
  else
    gpg "${gpg_args[@]}" \
      --output "$dist_dir/SHA256SUMS.asc" \
      "$dist_dir/SHA256SUMS"
  fi
elif [ "$require_signature" = "1" ]; then
  die "CW_RELEASE_GPG_PRIVATE_KEY is required to produce SHA256SUMS.asc"
else
  echo "warning: unsigned dry-run; SHA256SUMS.asc was not produced" >&2
fi

echo "release assets:"
find "$dist_dir" -maxdepth 1 -type f -printf '  %f\n' | sort
