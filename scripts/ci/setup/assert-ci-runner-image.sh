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

echo 'Codewire CI runner image contract: OK'
