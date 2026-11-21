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

# The pinned Zig is taken from its own install directory when it is there, so
# a workstation whose `zig` on PATH is another version still runs this check:
# on 2026-11-15 a shared link moved to 0.17.1 for another project and every
# local run stopped at the version check. CI installs the pin on PATH, which
# is the fallback. The version is checked below wherever the binary came from.
zig_bin="${HOME:-}/.local/opt/zig-$HOSTTYPE-linux-$DARWIN_CHECK_ZIG_VERSION/zig"
if [[ -z "${HOME:-}" || ! -x "$zig_bin" ]]; then
  zig_bin="$(type -P zig)" || die "install Zig $DARWIN_CHECK_ZIG_VERSION on PATH"
fi
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
  # Under a shared jobserver (CI's build job, which bounds every compiler),
  # each cw runs beside the aarch64 test checks in a target folder of its own
  # and its own zigbuild cache: after them, in one folder, the two cw builds
  # added about 109-135 s (infra#1534, steps A3 and A4). Without one (a workstation, where
  # preflight runs this as one job) the builds run one after another, as
  # before, so they never take every core three times over.
  if [[ "${CARGO_MAKEFLAGS:-}" != *--jobserver-auth=* ]]; then
    "$zigbuild_bin" clippy --locked -p codewire-cli --lib --tests \
      --target aarch64-apple-darwin -- -D warnings
    "$zigbuild_bin" clippy --locked -p codewire-cli-bin --tests \
      --target aarch64-apple-darwin -- -D warnings
    exec "$zigbuild_bin" clippy --locked -p codewire-cli-bin --bin cw \
      --target aarch64-apple-darwin --target x86_64-apple-darwin -- -D warnings
  fi
  # The aarch64 cw builds the CLI crate in another mode than its --tests
  # checks, so it shares little with them and runs beside them too, in a
  # folder of its own: after them it was 109 s of the chain's 315 (main run
  # 67041; infra#1534, step A4). The cw tests check stays after the CLI's,
  # whose build it reuses.
  side_by_side() {
    # side_by_side NAME TARGET: cw for TARGET in BASE/NAME, in the background.
    local folder="${CARGO_TARGET_DIR:-$ROOT/target}/$1"
    CARGO_TARGET_DIR="$folder" CARGO_ZIGBUILD_CACHE_DIR="$folder" \
      "$zigbuild_bin" clippy --locked -p codewire-cli-bin --bin cw \
      --target "$2" -- -D warnings &
  }
  side_by_side x86_64-cw x86_64-apple-darwin
  x86_64=$!
  side_by_side aarch64-cw aarch64-apple-darwin
  aarch64_cw=$!
  status=0
  "$zigbuild_bin" clippy --locked -p codewire-cli --lib --tests \
    --target aarch64-apple-darwin -- -D warnings &&
    # The cw integration tests' macOS code too (#3810): nothing else compiles it.
    "$zigbuild_bin" clippy --locked -p codewire-cli-bin --tests \
      --target aarch64-apple-darwin -- -D warnings || status=$?
  # The first failure is the exit status; the cw checks always finish.
  for job in "$aarch64_cw" "$x86_64"; do
    wait "$job" || { job_status=$?; [ "$status" != 0 ] || status=$job_status; }
  done
  exit "$status"
fi
printf '[darwin-cross] Zig %s; cargo-zigbuild %s; target aarch64-apple-darwin\n' \
  "$zig_version" "$DARWIN_CHECK_ZIGBUILD_VERSION"

# `cargo zigbuild clippy` is a build invocation, not this check subcommand.
# Keep the original packages, locked resolution, target and default features.
# exec propagates the one actual Cargo check's failure to qualification.
"$zigbuild_bin" clippy --locked -p codewire-local-vmm -p codewire-vmm-guest-probe \
  -p codewire-confinement -p codewire-egress-worker \
  --target aarch64-apple-darwin -- -D warnings
# The macOS unit tests of the local VMM, its confinement and its network
# worker too (#3810): nothing else compiles them.
exec "$zigbuild_bin" clippy --locked -p codewire-local-vmm -p codewire-confinement -p codewire-egress-worker \
  --lib --tests \
  --target aarch64-apple-darwin -- -D warnings
