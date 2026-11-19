#!/usr/bin/env bash
# Stage the Rust SDK's sources for `cargo package` and `cargo publish`: HEAD's
# committed tree in DIR, with the repository's proto/ copied to
# crates/codewire-proto/proto, where the published crate reads its protos.
# codewire-proto's `include` list chooses which of them it ships.
#
# usage: stage-sdk-rust-source.sh DIR
#
# DIR must be an empty directory. The repository keeps no link there instead:
# a tracked directory link broke Flux's checkout of older commits and the cw
# runtime source capsule (#5260), and repo policy refuses one.
set -euo pipefail

fail() {
  printf '[stage-sdk-rust-source] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || fail 'usage: stage-sdk-rust-source.sh DIR'
root="$(cd "$(dirname "$0")/../../.." && pwd)"
dir="$1"
[[ -d "$dir" && ! -L "$dir" && -z "$(find "$dir" -mindepth 1 -maxdepth 1 -print -quit)" ]] ||
  fail 'DIR must be an existing empty directory'

git -C "$root" archive --format=tar HEAD | tar -x -C "$dir"
[[ ! -e "$dir/crates/codewire-proto/proto" ]] || fail 'crates/codewire-proto/proto is already in the tree'
cp -R "$dir/proto" "$dir/crates/codewire-proto/proto"
