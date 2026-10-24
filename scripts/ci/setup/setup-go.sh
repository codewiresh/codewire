#!/usr/bin/env bash
set -euo pipefail

version="${1:-1.27.3}"
goos="${GO_OS:-linux}"
goarch="${GO_ARCH:-amd64}"

if [[ "$goos" != "linux" || "$goarch" != "amd64" ]]; then
  echo "unsupported Go platform: ${goos}-${goarch}" >&2
  exit 1
fi

case "$version" in
  1.27.3)
    official_url="https://go.dev/dl/go1.27.3.linux-amd64.tar.gz"
    official_sha256="65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40"
    ;;
  *)
    echo "unsupported Go version: ${version}" >&2
    exit 1
    ;;
esac

toolcache_root="${RUNNER_TOOL_CACHE:-}"
if [[ -n "$toolcache_root" ]] && mkdir -p "${toolcache_root}/go/${version}/x64" 2>/dev/null; then
  goroot="${toolcache_root}/go/${version}/x64"
else
  goroot="${RUNNER_TEMP:-/tmp}/codewire-go-toolcache/go/${version}/x64"
  mkdir -p "$goroot"
fi

valid_goroot() {
  [[ -x "${goroot}/bin/go" && -x "${goroot}/bin/gofmt" ]] || return 1
  # Validate the distribution by asking its own go command to resolve the
  # full standard library. This catches a half-copied src tree without
  # assuming the archive uses particular internal source filenames.
  GOROOT="$goroot" GOTOOLCHAIN=local GOWORK=off \
    "${goroot}/bin/go" list std >/dev/null 2>&1
}

# General-runner jobs share RUNNER_TOOL_CACHE. Without a cross-process lock,
# concurrent cold starts can both remove/copy the same GOROOT: one job sees a
# valid bin/go while another has deleted half of src/, then reports standard
# library packages as missing. Keep validation and repair inside one lock.
lock_path="$(dirname "$goroot")/.install-${version}-${goarch}.lock"
if ! command -v flock >/dev/null 2>&1; then
  echo "flock is required for concurrency-safe Go toolcache setup" >&2
  exit 1
fi
exec 9>"$lock_path"
flock 9

if ! valid_goroot; then
  tmpdir="$(mktemp -d)"
  cleanup() {
    rm -rf "$tmpdir"
  }
  trap cleanup EXIT

  archive="${tmpdir}/go.tgz"
  curl --proto '=https' --tlsv1.2 -fsSL --retry 5 --retry-delay 2 \
    "$official_url" -o "$archive"
  echo "${official_sha256}  ${archive}" | sha256sum -c -

  extract_dir="${tmpdir}/extract"
  mkdir -p "$extract_dir"
  tar -C "$extract_dir" -xzf "$archive"
  install_dir="${tmpdir}/install"
  mkdir -p "$install_dir"
  if [[ -f "${extract_dir}/bin/go" ]]; then
    cp -a "${extract_dir}/." "$install_dir/"
  elif [[ -f "${extract_dir}/go/bin/go" ]]; then
    cp -a "${extract_dir}/go/." "$install_dir/"
  else
    echo "downloaded Go archive did not contain bin/go" >&2
    exit 1
  fi
  chmod +x "${install_dir}/bin/go" "${install_dir}/bin/gofmt"

  # Publish only a fully extracted tree. The lock protects the replacement;
  # the rename prevents future readers from observing a partial copy.
  rm -rf "$goroot"
  mv "$install_dir" "$goroot"
  if ! valid_goroot; then
    echo "installed Go toolchain is incomplete" >&2
    exit 1
  fi
fi

flock -u 9

if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "${goroot}/bin" >> "$GITHUB_PATH"
fi

export PATH="${goroot}/bin:${PATH}"
go version

gopath="$(go env GOPATH)"
if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "${gopath}/bin" >> "$GITHUB_PATH"
fi
export PATH="${gopath}/bin:${PATH}"
