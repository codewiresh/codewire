#!/usr/bin/env bash
set -euo pipefail

packages=(
  ca-certificates
  curl
  jq
  libgtk-3-dev
  libprotobuf-dev
  libwebkit2gtk-4.1-dev
  libxkbcommon-x11-dev
  pkg-config
  postgresql-client
  protobuf-compiler
  xz-utils
)

missing=()
for package in "${packages[@]}"; do
  if ! dpkg-query -W -f='${Status}\n' "$package" 2>/dev/null \
    | grep -Fxq 'install ok installed'; then
    missing+=("$package")
  fi
done

if ((${#missing[@]} > 0)); then
  printf '::error::CI runner image is missing required packages: %s\n' "${missing[*]}" >&2
  printf 'Use the immutable act-node-docker digest admitted for this workflow; do not install packages at job time.\n' >&2
  exit 1
fi

test -s /usr/local/share/codewire-ci-native-packages.txt
pkg-config --exists gtk+-3.0
pkg-config --exists webkit2gtk-4.1
pkg-config --exists xkbcommon-x11
protoc --version
test -f /usr/include/google/protobuf/duration.proto
test -f /usr/include/google/protobuf/timestamp.proto
psql --version

readonly helm_version='v3.16.4'
[[ "$(helm version --template '{{.Version}}')" == "$helm_version" ]]

readonly rust_version='1.91.1'
readonly rust_host='x86_64-unknown-linux-gnu'
readonly -a rust_targets=(
  "$rust_host"
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-gnu
  x86_64-apple-darwin
  aarch64-apple-darwin
)

[[ "$(rustc --version)" == "rustc $rust_version (ed61e7d7e 2025-11-07)" ]]
[[ "$(cargo --version)" == "cargo $rust_version (ea2d97820 2025-10-10)" ]]
[[ "$(rustfmt --version)" == 'rustfmt 1.8.0-stable (ed61e7d7e2 2025-11-07)' ]]
[[ "$(clippy-driver --version)" == 'clippy 0.1.91 (ed61e7d7e2 2025-11-07)' ]]
[[ "$(rustup show active-toolchain | awk '{print $1}')" == "$rust_version-$rust_host" ]]

installed_targets="$(rustup target list --installed | LC_ALL=C sort)"
expected_targets="$(printf '%s\n' "${rust_targets[@]}" | LC_ALL=C sort)"
[[ "$installed_targets" == "$expected_targets" ]] || {
  printf '::error::CI runner image Rust target set differs from the sealed contract\n' >&2
  exit 1
}

echo 'Codewire CI runner image contract: OK'
