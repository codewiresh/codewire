#!/usr/bin/env bash
# Fail fast on workstation conditions that otherwise surface late inside a
# selected verification family. Preflight passes only the needs its selected
# families have; every check is read-only and reports its fix.
#
#   scripts/dev/preflight-environment.sh [--rust] [--darwin-cross] [--browser]
#     [--kind-browser] [--node-modules] [--proto-venv]
#
# TMPDIR is always checked. Exit status 1 lists every failed check.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
need_rust=false
need_darwin_cross=false
need_browser=false
need_kind_browser=false
need_node_modules=false
need_proto_venv=false
for argument in "$@"; do
  case "$argument" in
    --rust) need_rust=true ;;
    --darwin-cross) need_darwin_cross=true ;;
    --browser) need_browser=true ;;
    --kind-browser) need_kind_browser=true ;;
    --node-modules) need_node_modules=true ;;
    --proto-venv) need_proto_venv=true ;;
    *)
      printf 'usage: %s [--rust] [--darwin-cross] [--browser] [--kind-browser] [--node-modules] [--proto-venv]\n' \
        "$0" >&2
      exit 2
      ;;
  esac
done

failures=0
ok() {
  printf '[preflight-environment] ok: %s\n' "$*"
}
problem() {
  local message="$1" fix="$2"
  printf '[preflight-environment] FAILED: %s\n' "$message" >&2
  printf '[preflight-environment]   fix: %s\n' "$fix" >&2
  failures=$((failures + 1))
}

# shellcheck disable=SC2016 # Printed literally as the fix to run.
per_task_tmpdir_fix='export TMPDIR="$HOME/.cache/cwt-<short task>" (mkdir -p it): executable, at most 34 characters, outside /run and ~/.claude'

# Unix-socket tests bind below TMPDIR, and sun_path holds fewer than 104
# bytes on every supported host. The longest known binding, the codewire-cli
# host-control test's .tmpXXXXXX/registry/<uuid>/daemon.sock, adds 69 bytes.
readonly MAX_TMPDIR_LENGTH=34

check_tmpdir() {
  local configured="${TMPDIR:-/tmp}" resolved probe status
  if [ ! -d "$configured" ] || [ ! -w "$configured" ]; then
    problem "TMPDIR=${configured} is not a writable directory" "$per_task_tmpdir_fix"
    return
  fi
  resolved="$(cd "$configured" && pwd -P)"
  # /tmp is accepted wherever it allows executing files; where it is mounted
  # noexec, the probe below refuses it.
  case "$resolved" in
    /run|/run/*)
      problem "TMPDIR resolves to ${resolved}; native mount tests refuse projects inside /run" \
        "$per_task_tmpdir_fix"
      return
      ;;
  esac
  case "/${resolved#/}/" in
    */.claude/*)
      problem "TMPDIR resolves to ${resolved}; the image-source policy test rejects every path with a .claude component" \
        "$per_task_tmpdir_fix"
      return
      ;;
  esac
  if [ "${#configured}" -gt "$MAX_TMPDIR_LENGTH" ]; then
    problem "TMPDIR=${configured} is ${#configured} characters; Unix-socket tests below it need ${MAX_TMPDIR_LENGTH} or fewer" \
      "$per_task_tmpdir_fix"
    return
  fi
  # Rust, Go and fixture tests execute files they create under TMPDIR.
  if ! probe="$(mktemp "$resolved/preflight-exec-probe.XXXXXX" 2>/dev/null)"; then
    problem "cannot create a file in TMPDIR=${resolved}" "$per_task_tmpdir_fix"
    return
  fi
  printf '#!/bin/sh\nexit 0\n' >"$probe"
  chmod 0700 "$probe"
  status=0
  "$probe" 2>/dev/null || status=$?
  rm -f -- "$probe"
  if [ "$status" -ne 0 ]; then
    problem "TMPDIR=${resolved} does not allow executing files (noexec mount)" "$per_task_tmpdir_fix"
    return
  fi
  ok "TMPDIR=${configured} is short, executable and outside /run and .claude"
}

pinned_rust_channel() {
  sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
    "$ROOT/rust-toolchain.toml" 2>/dev/null | head -n 1
}

check_rust() {
  local pinned rustc_path cargo_path rustc_version cargo_version fix
  pinned="$(pinned_rust_channel)"
  if [ -z "$pinned" ]; then
    problem 'rust-toolchain.toml does not pin a toolchain channel' \
      'restore the checked-in rust-toolchain.toml'
    return
  fi
  fix="put rustup's proxies first: export PATH=\"\$HOME/.cargo/bin:\$PATH\"; rustup toolchain install ${pinned} --component clippy,rustfmt"
  if [ -n "${RUSTUP_TOOLCHAIN:-}" ] && [ "$RUSTUP_TOOLCHAIN" != "$pinned" ]; then
    problem "RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN} overrides the pinned ${pinned}" \
      "unset RUSTUP_TOOLCHAIN (or export RUSTUP_TOOLCHAIN=${pinned})"
    return
  fi
  rustc_path="$(command -v rustc || true)"
  cargo_path="$(command -v cargo || true)"
  if [ -z "$rustc_path" ] || [ -z "$cargo_path" ]; then
    problem 'rustc or cargo is not on PATH' "$fix"
    return
  fi
  # rustup resolves rust-toolchain.toml from the working directory.
  rustc_version="$(cd "$ROOT" && rustc --version 2>/dev/null || true)"
  cargo_version="$(cd "$ROOT" && cargo --version 2>/dev/null || true)"
  if [[ "$rustc_version" != "rustc ${pinned} "* ]] && [ "$rustc_version" != "rustc ${pinned}" ]; then
    problem "${rustc_path} reports '${rustc_version:-no version}'; the pinned toolchain is ${pinned}" "$fix"
    return
  fi
  if [[ "$cargo_version" != "cargo ${pinned} "* ]] && [ "$cargo_version" != "cargo ${pinned}" ]; then
    problem "${cargo_path} reports '${cargo_version:-no version}'; the pinned toolchain is ${pinned}" "$fix"
    return
  fi
  if ! (cd "$ROOT" && cargo fmt --version >/dev/null 2>&1) \
      || ! (cd "$ROOT" && cargo clippy --version >/dev/null 2>&1); then
    problem "the ${pinned} toolchain lacks rustfmt or clippy" \
      "rustup component add --toolchain ${pinned} rustfmt clippy"
    return
  fi
  ok "rustc and cargo ${pinned} (${rustc_path})"
}

darwin_pin() {
  sed -nE "s/^readonly $1=([0-9][0-9.]*)$/\\1/p" \
    "$ROOT/scripts/ci/verify/check-darwin-cross.sh" | head -n 1
}

check_darwin_cross() {
  local zig_pin zigbuild_pin zig_version zigbuild_version
  zig_pin="$(darwin_pin DARWIN_CHECK_ZIG_VERSION)"
  zigbuild_pin="$(darwin_pin DARWIN_CHECK_ZIGBUILD_VERSION)"
  if [ -z "$zig_pin" ] || [ -z "$zigbuild_pin" ]; then
    problem 'scripts/ci/verify/check-darwin-cross.sh no longer declares its Zig pins' \
      'restore the checked-in Darwin cross-check pins'
    return
  fi
  if [ "$(uname -s)" != Linux ]; then
    problem 'the Darwin cross-check selected by local-vmm changes needs a Linux host' \
      'run merge qualification on the Linux workstation'
    return
  fi
  zigbuild_version="$(cargo-zigbuild --version 2>/dev/null || true)"
  if [ "$zigbuild_version" != "cargo-zigbuild ${zigbuild_pin}" ]; then
    problem "cargo-zigbuild ${zigbuild_pin} is required on PATH (found '${zigbuild_version:-none}')" \
      "cargo install --locked cargo-zigbuild@${zigbuild_pin}, and put \$HOME/.cargo/bin first on PATH"
    return
  fi
  zig_version="$(zig version 2>/dev/null || true)"
  if [ "$zig_version" != "$zig_pin" ]; then
    problem "Zig ${zig_pin} is required on PATH (found '${zig_version:-none}')" \
      "install Zig ${zig_pin} and put it on PATH"
    return
  fi
  ok "cargo-zigbuild ${zigbuild_pin} and Zig ${zig_pin}"
}

pinned_chromium_version() {
  sed -n "s/^readonly chromium_version='\([^']*\)'/\1/p" \
    "$ROOT/scripts/ci/install-pinned-playwright-chromium.sh"
}

# shellcheck disable=SC2016 # Printed literally as the fix to run.
chromium_fix='export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$(scripts/ci/install-pinned-playwright-chromium.sh)"'

# The same runtime check the browser families run, moved before the first
# family. It verifies the pinned version, snapshot environment, TMPDIR length
# and renderer backing.
check_chromium_runtime() {
  local chromium="$1" output
  # shellcheck source=scripts/ci/verify/playwright-browser-runtime.sh
  source "$ROOT/scripts/ci/verify/playwright-browser-runtime.sh"
  if ! output="$(prepare_playwright_browser_runtime "$chromium" "$ROOT" 2>&1)"; then
    problem "pinned Chromium runtime check failed for ${chromium}: $(printf '%s' "$output" | tr '\n' ' ')" \
      "$chromium_fix; keep TMPDIR short (48 characters or fewer)"
    return
  fi
  ok "pinned Chromium $(pinned_chromium_version) at ${chromium}"
}

check_browser() {
  local expected candidate
  expected="$(pinned_chromium_version)"
  if [ -n "${PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH:-}" ]; then
    check_chromium_runtime "$PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"
    return
  fi
  # The design fixtures reuse a verified download in this checkout and
  # otherwise download and verify the pinned archive themselves.
  for candidate in "$ROOT"/.tmp/playwright-chromium.*/chrome-linux64/chrome; do
    if [ -x "$candidate" ] && "$candidate" --version 2>/dev/null | grep -Fq " $expected"; then
      check_chromium_runtime "$candidate"
      return
    fi
  done
  ok "no pinned Chromium ${expected} yet; the web family downloads and verifies it"
}

check_kind_browser() {
  local chromium
  chromium="${PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH:-}"
  if [ -z "$chromium" ]; then
    chromium="$(command -v chromium || command -v google-chrome || command -v google-chrome-stable || true)"
  fi
  if [ -z "$chromium" ] || [ ! -x "$chromium" ]; then
    problem 'the Kind browser gate needs a pre-provisioned pinned Chromium' "$chromium_fix"
    return
  fi
  check_chromium_runtime "$chromium"
}

check_not_symlink() {
  local path="$1" fix="$2"
  if [ -L "$ROOT/$path" ]; then
    problem "${path} is a symlink to $(readlink "$ROOT/$path"); families would change another checkout" "$fix"
    return 1
  fi
  return 0
}

check_node_modules() {
  local path clean=true
  for path in node_modules apps/*/node_modules packages/*/node_modules; do
    [ -e "$ROOT/$path" ] || [ -L "$ROOT/$path" ] || continue
    check_not_symlink "$path" \
      "rm ${path} && PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 bun install --frozen-lockfile --ignore-scripts" \
      || clean=false
  done
  if [ "$clean" = true ]; then
    ok 'node_modules directories belong to this worktree'
  fi
}

check_proto_venv() {
  if check_not_symlink .venv-proto 'rm .venv-proto; the contracts family recreates it'; then
    ok '.venv-proto belongs to this worktree'
  fi
}

check_tmpdir
[ "$need_rust" = false ] || check_rust
[ "$need_darwin_cross" = false ] || check_darwin_cross
[ "$need_browser" = false ] || check_browser
[ "$need_kind_browser" = false ] || check_kind_browser
[ "$need_node_modules" = false ] || check_node_modules
[ "$need_proto_venv" = false ] || check_proto_venv

if [ "$failures" -gt 0 ]; then
  printf '[preflight-environment] %s check(s) failed; no family ran\n' "$failures" >&2
  exit 1
fi
printf '[preflight-environment] OK\n'
