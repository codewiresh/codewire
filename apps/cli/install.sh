#!/usr/bin/env bash
set -euo pipefail

REPO="codewiresh/codewire"
BINARY_NAME="cw"
GPG_KEY_URL="https://raw.githubusercontent.com/${REPO}/main/apps/cli/GPG_PUBLIC_KEY.asc"
GPG_KEY_ID="39F95DC66BA8EFBEAF49FAEF39D46239F95F4632"

VERSION=""
PREFIX=""
VERBOSE=false

usage() {
  cat <<EOF
Install codewire (cw) - persistent process server for AI coding agents.

Usage: install.sh [OPTIONS]

Options:
  --version VERSION   Install a specific version (e.g., v0.1.0)
  --prefix DIR        Install to DIR/bin instead of default location
  --verbose           Show detailed output
  --help              Show this help message

Default install location: /usr/local/bin (falls back to ~/.local/bin)

Examples:
  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | bash
  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | bash -s -- --version v0.1.0
  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | bash -s -- --prefix ~/.local
EOF
}

log() {
  echo "==> $*"
}

verbose() {
  if [ "$VERBOSE" = true ]; then
    echo "    $*"
  fi
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      VERSION="$2"
      shift 2
      ;;
    --prefix)
      PREFIX="$2"
      shift 2
      ;;
    --verbose)
      VERBOSE=true
      shift
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      die "Unknown option: $1. Use --help for usage."
      ;;
  esac
done

# Detect platform
detect_platform() {
  local os arch target

  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Linux)
      case "$arch" in
        x86_64)  target="x86_64-unknown-linux-musl" ;;
        aarch64) target="aarch64-unknown-linux-gnu" ;;
        arm64)   target="aarch64-unknown-linux-gnu" ;;
        *) die "Unsupported Linux architecture: $arch" ;;
      esac
      ;;
    Darwin)
      case "$arch" in
        x86_64)  target="x86_64-apple-darwin" ;;
        arm64)   target="aarch64-apple-darwin" ;;
        aarch64) target="aarch64-apple-darwin" ;;
        *) die "Unsupported macOS architecture: $arch" ;;
      esac
      ;;
    *)
      die "Unsupported OS: $os"
      ;;
  esac

  echo "$target"
}

# Get latest version from GitHub API
get_latest_version() {
  local url="https://api.github.com/repos/${REPO}/releases/latest"
  verbose "Fetching latest version from $url"

  local version
  version="$(curl -fsSL "$url" | grep '"tag_name"' | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/')"

  if [ -z "$version" ]; then
    die "Failed to determine latest version. Try --version to specify manually."
  fi

  echo "$version"
}

# Determine install directory
get_install_dir() {
  if [ -n "$PREFIX" ]; then
    echo "${PREFIX}/bin"
    return
  fi

  if [ -w /usr/local/bin ]; then
    echo "/usr/local/bin"
  else
    echo "${HOME}/.local/bin"
  fi
}

main() {
  local target version install_dir tmp_dir

  target="$(detect_platform)"
  log "Detected platform: $target"

  if [ -n "$VERSION" ]; then
    version="$VERSION"
  else
    log "Fetching latest version..."
    version="$(get_latest_version)"
  fi
  log "Version: $version"

  install_dir="$(get_install_dir)"
  log "Install directory: $install_dir"

  # Create temp dir for downloads
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "${tmp_dir:-}"' EXIT
  verbose "Temp directory: $tmp_dir"

  local base_url="https://github.com/${REPO}/releases/download/${version}"
  local binary_name="cw-${version}-${target}"

  # Download binary, checksums, and signature
  log "Downloading ${binary_name}..."
  curl -fsSL -o "${tmp_dir}/${binary_name}" "${base_url}/${binary_name}" \
    || die "Failed to download binary. Check that version ${version} exists and has a build for ${target}."

  log "Downloading checksums..."
  curl -fsSL -o "${tmp_dir}/SHA256SUMS" "${base_url}/SHA256SUMS" \
    || die "Failed to download SHA256SUMS."

  curl -fsSL -o "${tmp_dir}/SHA256SUMS.asc" "${base_url}/SHA256SUMS.asc" \
    || die "Failed to download SHA256SUMS.asc."

  # GPG verification (optional — warns if gpg not available)
  if command -v gpg &>/dev/null; then
    log "Verifying GPG signature..."
    verbose "Importing public key from $GPG_KEY_URL"

    curl -fsSL -o "${tmp_dir}/GPG_PUBLIC_KEY.asc" "$GPG_KEY_URL" \
      || die "Failed to download the release-signing public key."
    local key_records downloaded_key_count downloaded_key_id release_gnupg_home
    release_gnupg_home="${tmp_dir}/gnupg"
    mkdir -m 700 "$release_gnupg_home"
    key_records="${tmp_dir}/release-key.records"
    GNUPGHOME="$release_gnupg_home" \
      gpg --batch --no-options --with-colons --import-options show-only \
        --import "${tmp_dir}/GPG_PUBLIC_KEY.asc" >"$key_records" 2>/dev/null \
      || die "Release-signing public key is not valid OpenPGP."
    downloaded_key_count="$(awk -F: '$1 == "pub" { count++ } END { print count + 0 }' "$key_records")"
    [ "$downloaded_key_count" -eq 1 ] \
      || die "Release-signing public key must contain exactly one primary key."
    downloaded_key_id="$(awk -F: '$1 == "fpr" { print $10; exit }' "$key_records")"
    [ -n "$downloaded_key_id" ] \
      || die "Release-signing public key is not valid OpenPGP."
    [ "$downloaded_key_id" = "$GPG_KEY_ID" ] \
      || die "Release-signing public key fingerprint does not match the pinned key."

    local gpg_status valid_signature_count valid_signature_id
    GNUPGHOME="$release_gnupg_home" \
      gpg --batch --no-options --import "${tmp_dir}/GPG_PUBLIC_KEY.asc" >/dev/null 2>&1 \
      || die "Failed to import the release-signing public key."
    if ! gpg_status="$(
      GNUPGHOME="$release_gnupg_home" \
        gpg --batch --no-options --status-fd 1 \
          --verify "${tmp_dir}/SHA256SUMS.asc" "${tmp_dir}/SHA256SUMS" 2>/dev/null
    )"; then
      die "GPG signature verification FAILED. The checksums file may have been tampered with."
    fi
    valid_signature_count="$(
      awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { count++ } END { print count + 0 }' \
        <<<"$gpg_status"
    )"
    valid_signature_id="$(
      awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print $3; exit }' \
        <<<"$gpg_status"
    )"
    [ "$valid_signature_count" -eq 1 ] && [ "$valid_signature_id" = "$GPG_KEY_ID" ] \
      || die "GPG signature was not made by the pinned release-signing key."
    log "GPG signature verified."
  else
    echo "WARNING: gpg not found — skipping signature verification."
    echo "         Install gnupg to enable GPG verification."
  fi

  # SHA256 verification (mandatory)
  log "Verifying SHA256 checksum..."
  cd "$tmp_dir"

  if command -v sha256sum &>/dev/null; then
    sha256sum --check --ignore-missing SHA256SUMS \
      || die "SHA256 checksum verification FAILED. The binary may have been tampered with."
  elif command -v shasum &>/dev/null; then
    # macOS uses shasum
    local expected actual
    expected="$(grep "${binary_name}" SHA256SUMS | awk '{print $1}')"
    actual="$(shasum -a 256 "${binary_name}" | awk '{print $1}')"
    if [ "$expected" != "$actual" ]; then
      die "SHA256 checksum verification FAILED. Expected: ${expected}, Got: ${actual}"
    fi
  else
    die "No SHA256 tool found (need sha256sum or shasum)."
  fi
  log "SHA256 checksum verified."

  # Install
  mkdir -p "$install_dir"
  chmod +x "${tmp_dir}/${binary_name}"
  cp "${tmp_dir}/${binary_name}" "${install_dir}/${BINARY_NAME}"
  log "Installed ${BINARY_NAME} to ${install_dir}/${BINARY_NAME}"

  # Check if install dir is in PATH
  case ":$PATH:" in
    *":${install_dir}:"*) ;;
    *)
      echo ""
      echo "NOTE: ${install_dir} is not in your PATH."
      echo "      Add it with: export PATH=\"${install_dir}:\$PATH\""
      ;;
  esac

  echo ""
  log "Done! Run 'cw --help' to get started."
}

main
