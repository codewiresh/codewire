#!/usr/bin/env bash
# Install a pinned Node.js release from nodejs.org, checked against its
# pinned SHA-256, and put it first on the job's PATH. The setup-node action
# first asked github.com for its version manifest, which the CI guests cannot
# reach: every Standard job waited 133 s for that connection to time out
# before the action fell back to the same nodejs.org download (infra#1534).
set -euo pipefail

version="${1:?usage: setup-node.sh VERSION}"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) platform=linux-x64 ;;
  *)
    echo "unsupported Node.js platform: $(uname -s)-$(uname -m)" >&2
    exit 1
    ;;
esac

case "$version-$platform" in
  22.23.4-linux-x64)
    official_sha256="b8492284c76a54baf58d61668dd0e41ee0fc98adabf9503d30f05d08f55b4406"
    ;;
  *)
    echo "unsupported Node.js version: ${version} (${platform})" >&2
    exit 1
    ;;
esac
official_url="https://nodejs.org/dist/v${version}/node-v${version}-${platform}.tar.gz"

toolcache_root="${RUNNER_TOOL_CACHE:-}"
if [[ -n "$toolcache_root" ]] && mkdir -p "${toolcache_root}/node/${version}" 2>/dev/null; then
  node_root="${toolcache_root}/node/${version}/${platform}"
else
  node_root="${RUNNER_TEMP:-/tmp}/codewire-node-toolcache/node/${version}/${platform}"
  mkdir -p "$(dirname "$node_root")"
fi

valid_node_root() {
  [[ -x "${node_root}/bin/node" && -x "${node_root}/bin/npm" ]] || return 1
  [[ "$("${node_root}/bin/node" --version 2>/dev/null)" == "v${version}" ]]
}

# Jobs on one runner share RUNNER_TOOL_CACHE: validate and repair under one
# lock, and publish only a fully extracted tree, in one rename.
lock_path="$(dirname "$node_root")/.install-${platform}.lock"
if ! command -v flock >/dev/null 2>&1; then
  echo "flock is required for concurrency-safe Node.js toolcache setup" >&2
  exit 1
fi
exec 9>"$lock_path"
flock 9

if ! valid_node_root; then
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT
  archive="${tmpdir}/node.tgz"
  curl --proto '=https' --tlsv1.2 -fsSL --retry 5 --retry-delay 2 --connect-timeout 20 \
    "$official_url" -o "$archive"
  echo "${official_sha256}  ${archive}" | sha256sum -c -
  mkdir "${tmpdir}/extract"
  tar -C "${tmpdir}/extract" -xzf "$archive"
  extracted="${tmpdir}/extract/node-v${version}-${platform}"
  [[ -x "${extracted}/bin/node" ]] || {
    echo "downloaded Node.js archive did not contain bin/node" >&2
    exit 1
  }
  rm -rf "$node_root"
  mv "$extracted" "$node_root"
  valid_node_root || {
    echo "installed Node.js ${version} is incomplete" >&2
    exit 1
  }
fi

flock -u 9

if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "${node_root}/bin" >> "$GITHUB_PATH"
fi
export PATH="${node_root}/bin:${PATH}"
node --version
