#!/usr/bin/env bash
# Builds the app's Rust shell (crates/codewire-client-ffi, #3825) for iOS and
# the iOS Simulator and wraps both static libraries, with the committed header
# and module map, as Frameworks/CodewireClientFFI.xcframework. Package.swift
# links the shell only when that file exists. Needs a Mac with Xcode and the
# Rust targets aarch64-apple-ios and aarch64-apple-ios-sim.
#
# usage: apps/ios/scripts/build-rust.sh [debug|release]   (default: release)
set -euo pipefail

profile="${1:-release}"
case "$profile" in
  debug) cargo_profile=() ;;
  release) cargo_profile=(--release) ;;
  *) echo "usage: $0 [debug|release]" >&2; exit 2 ;;
esac
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
IOS="$ROOT/apps/ios"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
[ "$(uname -s)" = Darwin ] || { echo 'build-rust.sh: needs a Mac with Xcode' >&2; exit 1; }

cd "$ROOT"
libraries=()
for target in aarch64-apple-ios aarch64-apple-ios-sim; do
  # An empty array under set -u fails on macOS's bash 3.2 unless guarded.
  cargo build --locked ${cargo_profile[@]+"${cargo_profile[@]}"} -p codewire-client-ffi --lib \
    --target "$target"
  libraries+=(-library "$TARGET_DIR/$target/$profile/libcodewire_client_ffi.a"
    -headers "$IOS/FFI/include")
done

framework="$IOS/Frameworks/CodewireClientFFI.xcframework"
rm -rf -- "$framework"
mkdir -p "$IOS/Frameworks"
xcodebuild -create-xcframework "${libraries[@]}" -output "$framework"
printf 'built %s (%s)\n' "$framework" "$profile"
