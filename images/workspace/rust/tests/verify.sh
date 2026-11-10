#!/bin/bash
# Run only in the disposable native fixture with an empty tmpfs home:
# docker run --rm --network none --cpus 1 --memory 1g --pids-limit 128 --user 1000:1000 \
#   --tmpfs /home/codewire:rw,exec,uid=1000,gid=1000,mode=0700,size=256m IMAGE
set -euo pipefail
trap 'printf "Rust native contract failed at line %s\n" "$LINENO" >&2' ERR

fail() { printf 'Rust native contract: %s\n' "$*" >&2; exit 1; }
selected() {
  local selection
  selection="$(rustup show active-toolchain)"
  printf '%s' "${selection%% *}"
}

[[ "$(id -u):$(id -g)" = 1000:1000 ]]
[[ "$HOME" = /home/codewire && "$CARGO_HOME" = "$HOME/.cargo" ]]
[[ ! ${RUSTUP_HOME+x} && ! ${RUSTUP_TOOLCHAIN+x} ]]
awk '$5 == "/home/codewire" { found = 1 } END { exit !found }' /proc/self/mountinfo
[[ ! -e "$HOME/.cargo" && ! -e "$HOME/.rustup" ]]
for directory in /opt/codewire/rust/bin /opt/codewire/rust/cargo/bin; do
  [[ "$(stat -c %u:%g "$directory")" = 0:0 && ! -w "$directory" ]]
done
[[ -w /opt/codewire/rust/rustup ]]

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
cargo --version
rustc --version | grep -E '^rustc 1\.99\.0 '
rustfmt --version
cargo clippy --version
toolchain="$(selected)"
[[ "$toolchain" = 1.99.0-* ]]
compiler="$(rustup which rustc)"
toolchain_path="${compiler%/bin/rustc}"
[[ "$toolchain_path" = /opt/codewire/rust/rustup/toolchains/"$toolchain" ]]

mkdir "$work/project"
cd "$work/project"
cargo init --bin --name rust_image_check --vcs none .
printf 'fn main() {\n    println!("rust-image-ok");\n}\n' >src/main.rs
cargo fmt --check
cargo clippy --offline -- -D warnings
[[ "$(cargo run --quiet --offline)" = rust-image-ok ]]

# The native permission guard must reject before contacting an update server
# or installing proxies into the higher-priority persistent Cargo prefix.
if RUSTUP_UPDATE_ROOT=file:///nonexistent-rustup-update-root rustup self update >"$work/self-update" 2>&1; then
  fail 'the image-managed Rustup executable allowed self-update'
fi
grep -Fq 'self-update is disabled for this build of rustup' "$work/self-update"
[[ ! -e "$CARGO_HOME/bin/rustup" && ! -e "$CARGO_HOME/bin/rustup-init" ]]
rustc --version

# Ordinary mutations still operate in the selected writable toolchain store.
rustup default "$toolchain"
rustup component add rustfmt --toolchain "$toolchain"
[[ "$(selected)" = "$toolchain" ]]
# Use the pinned toolchain's own distribution manifest as an offline update
# server. Do not rewrite update hashes or modify the installed manifest.
mkdir "$work/dist"
cp "$toolchain_path/lib/rustlib/multirust-channel-manifest.toml" "$work/dist/channel-rust-1.99.0.toml"
(cd "$work/dist"; sha256sum channel-rust-1.99.0.toml >channel-rust-1.99.0.toml.sha256)
RUSTUP_DIST_SERVER="file://$work" RUSTUP_UPDATE_ROOT=file:///nonexistent-rustup-update-root rustup update 1.99.0
[[ "$(selected)" = "$toolchain" ]]

# Existing user state wins; the dispatcher must neither migrate nor hide it.
RUSTUP_HOME="$HOME/.rustup" rustup toolchain link cw-user "$toolchain_path"
rustup default cw-user
[[ "$(selected)" = cw-user ]]
for name in cw-project cw-plus cw-env; do
  rustup toolchain link "$name" "$toolchain_path"
done
printf '[toolchain]\nchannel = "cw-project"\n' >rust-toolchain.toml
[[ "$(selected)" = cw-project ]]
[[ "$(RUSTUP_TOOLCHAIN=cw-env selected)" = cw-env ]]
RUSTUP_TOOLCHAIN=cw-missing cargo +cw-plus --version
if RUSTUP_TOOLCHAIN=cw-missing cargo --version >"$work/missing" 2>&1; then
  fail 'an unavailable environment override silently fell back'
fi
rm rust-toolchain.toml
[[ "$(selected)" = cw-user ]]

RUSTUP_HOME="$work/explicit" rustup toolchain link cw-explicit "$toolchain_path"
RUSTUP_HOME="$work/explicit" rustup default cw-explicit
[[ "$(RUSTUP_HOME="$work/explicit" selected)" = cw-explicit ]]
[[ "$(selected)" = cw-user ]]

mv "$HOME/.rustup" "$work/user-rustup"
mkdir "$HOME/.rustup"
if RUSTUP_AUTO_INSTALL=0 cargo --version >"$work/incomplete" 2>&1; then
  fail 'an incomplete user installation silently used the image store'
fi
mv "$HOME/.rustup" "$work/incomplete-home"
mv "$work/user-rustup" "$HOME/.rustup"

mkdir -p "$CARGO_HOME/bin"
printf '#!/bin/sh\nprintf "user-cargo\\n"\n' >"$CARGO_HOME/bin/cargo"
chmod +x "$CARGO_HOME/bin/cargo"
# A fresh process observes PATH without this noninteractive test shell's hash.
[[ "$(bash -c 'cargo --version')" = user-cargo ]]
# Removing a component must affect the selected toolchain, and its missing
# proxy must fail rather than using a different store or version.
RUSTUP_HOME=/opt/codewire/rust/rustup rustup component remove rustfmt --toolchain "$toolchain"
if rustfmt --version >"$work/missing-component" 2>&1; then
  fail 'a removed component silently used another toolchain'
fi
[[ "$(selected)" = cw-user ]]
printf 'Rust native contract: mounted-home compile, updates and selection passed\n'
