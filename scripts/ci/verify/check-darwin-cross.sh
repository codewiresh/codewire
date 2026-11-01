#!/usr/bin/env bash
# Preserve the Linux-hosted Darwin package check, including bundled C inputs.
# Installation belongs to the selected workflow job or local developer setup.
# It runs clippy with warnings as errors: Linux clippy never compiles
# cfg(target_os = "macos") code, so a rustc warning or clippy lint there is
# caught only here (a macOS-only unused variable passed `check` for a week).
# It checks the local VMM's macOS unit tests too (#3810).
#
# With --cli it checks the CLI library's macOS unit tests, cw's integration
# tests (#3810) and the macOS cw for
# both Mac targets instead. That cw links Apple frameworks (Security,
# SystemConfiguration), so only a Mac links it; this compile-only check
# catches its source errors on Linux.
# Its time is the build job's "local-vmm checks" and "cw Darwin cross-check"
# phases (run-rust-checks.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly DARWIN_CHECK_ZIG_VERSION=0.15.2
readonly DARWIN_CHECK_ZIGBUILD_VERSION=0.23.0

die() {
  printf '[darwin-cross] ERROR: %s\n' "$*" >&2
  exit 1
}

mode=transport
if [[ "${1:-}" == --cli ]]; then
  mode=cli
  shift
fi
[[ $# -eq 0 ]] || die 'usage: check-darwin-cross.sh [--cli]'
[[ "$(uname -s)" == Linux ]] || die 'this cross-check requires a Linux host; use the native Mac developer loop on macOS'
cd "$ROOT"

# cargo-zigbuild preserves inherited compiler settings with add_env_if_missing.
# Both cc-rs target spellings matter: the hyphenated spelling takes precedence
# over the underscore spelling that cargo-zigbuild installs. Empty overrides
# also count as present. Never silently use a different compiler or Apple SDK.
for variable in \
    CC CXX AR RANLIB LD TARGET_CC TARGET_CXX TARGET_AR TARGET_RANLIB TARGET_LD \
    CC_aarch64_apple_darwin CXX_aarch64_apple_darwin \
    AR_aarch64_apple_darwin RANLIB_aarch64_apple_darwin LD_aarch64_apple_darwin \
    CC_aarch64-apple-darwin CXX_aarch64-apple-darwin \
    AR_aarch64-apple-darwin RANLIB_aarch64-apple-darwin LD_aarch64-apple-darwin \
    CC_x86_64_apple_darwin CXX_x86_64_apple_darwin \
    AR_x86_64_apple_darwin RANLIB_x86_64_apple_darwin LD_x86_64_apple_darwin \
    CC_x86_64-apple-darwin CXX_x86_64-apple-darwin \
    AR_x86_64-apple-darwin RANLIB_x86_64-apple-darwin LD_x86_64-apple-darwin \
    CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER \
    SDKROOT ZIG_COMMAND \
    CARGO_ZIGBUILD_ZIG_PATH CARGO_ZIGBUILD_PYTHON_PATH \
    CARGO_ZIGBUILD_ZIG_VERSION CARGO_ZIGBUILD_RUSTC_VERSION CARGO \
    CARGO_BIN_EXE_cargo-zigbuild LIBSQLITE3_SYS_USE_PKG_CONFIG LIBSQLITE3_FLAGS \
    CFLAGS CXXFLAGS TARGET_CFLAGS TARGET_CXXFLAGS \
    CFLAGS_aarch64_apple_darwin CXXFLAGS_aarch64_apple_darwin \
    CFLAGS_aarch64-apple-darwin CXXFLAGS_aarch64-apple-darwin \
    CFLAGS_x86_64_apple_darwin CXXFLAGS_x86_64_apple_darwin \
    CFLAGS_x86_64-apple-darwin CXXFLAGS_x86_64-apple-darwin; do
  if printenv "$variable" >/dev/null; then
    die "unset inherited $variable before the pinned Darwin cross-check"
  fi
done

# Workflow pins may confirm the checked-in versions, but cannot replace them.
if [[ ${ZIG_VERSION+x} && "$ZIG_VERSION" != "$DARWIN_CHECK_ZIG_VERSION" ]]; then
  die "ZIG_VERSION must match the checked-in $DARWIN_CHECK_ZIG_VERSION pin"
fi
if [[ ${CARGO_ZIGBUILD_VERSION+x} && "$CARGO_ZIGBUILD_VERSION" != "$DARWIN_CHECK_ZIGBUILD_VERSION" ]]; then
  die "CARGO_ZIGBUILD_VERSION must match the checked-in $DARWIN_CHECK_ZIGBUILD_VERSION pin"
fi

zig_bin="$(type -P zig)" || die "install Zig $DARWIN_CHECK_ZIG_VERSION on PATH"
zigbuild_bin="$(type -P cargo-zigbuild)" || die "install cargo-zigbuild $DARWIN_CHECK_ZIGBUILD_VERSION on PATH"
[[ "$zig_bin" == /* ]] || zig_bin="$PWD/$zig_bin"
[[ "$zigbuild_bin" == /* ]] || zigbuild_bin="$PWD/$zigbuild_bin"
zig_version="$("$zig_bin" version)" || die 'the Zig version command failed'
[[ "$zig_version" == "$DARWIN_CHECK_ZIG_VERSION" ]] || die "installed Zig must be $DARWIN_CHECK_ZIG_VERSION"
zigbuild_version="$("$zigbuild_bin" --version)" || die 'the cargo-zigbuild version command failed'
[[ "$zigbuild_version" == "cargo-zigbuild $DARWIN_CHECK_ZIGBUILD_VERSION" ]] || die "installed cargo-zigbuild must be $DARWIN_CHECK_ZIGBUILD_VERSION"

# Version 0.23.0 tries `python3 -m ziglang` before the Zig binary. Disable that
# discovery with a failing executable, then bind the binary we just verified.
# These are supported upstream discovery inputs, not compiler or SDK shims.
[[ -x /usr/bin/false ]] || die 'missing /usr/bin/false for disabling Python Zig discovery'
export CARGO_ZIGBUILD_PYTHON_PATH=/usr/bin/false
export CARGO_ZIGBUILD_ZIG_PATH="$zig_bin"
if [[ "$mode" == cli ]]; then
  printf '[darwin-cross] Zig %s; cargo-zigbuild %s; macOS cw for aarch64 and x86_64\n' \
    "$zig_version" "$DARWIN_CHECK_ZIGBUILD_VERSION"
  # The CLI's macOS-only unit tests too: Linux never compiles them, and a
  # signature change once broke them unnoticed (#2745).
  "$zigbuild_bin" clippy --locked -p codewire-cli --lib --tests \
    --target aarch64-apple-darwin -- -D warnings
  # The cw integration tests' macOS code too (#3810): nothing else compiles it.
  "$zigbuild_bin" clippy --locked -p codewire-cli-bin --tests \
    --target aarch64-apple-darwin -- -D warnings
  exec "$zigbuild_bin" clippy --locked -p codewire-cli-bin --bin cw \
    --target aarch64-apple-darwin --target x86_64-apple-darwin -- -D warnings
fi
printf '[darwin-cross] Zig %s; cargo-zigbuild %s; target aarch64-apple-darwin\n' \
  "$zig_version" "$DARWIN_CHECK_ZIGBUILD_VERSION"

# `cargo zigbuild clippy` is a build invocation, not this check subcommand.
# Keep the original packages, locked resolution, target and default features.
# exec propagates the one actual Cargo check's failure to qualification.
"$zigbuild_bin" clippy --locked -p codewire-local-vmm -p codewire-vmm-guest-probe \
  --target aarch64-apple-darwin -- -D warnings
# The local VMM's macOS unit tests too (#3810): nothing else compiles them.
exec "$zigbuild_bin" clippy --locked -p codewire-local-vmm --lib --tests \
  --target aarch64-apple-darwin -- -D warnings
