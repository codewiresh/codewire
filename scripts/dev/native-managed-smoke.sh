#!/usr/bin/env bash
# Build the inputs of the native local smoke's managed credential-broker modes
# from this checkout, then run the smoke with them.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly ROOT
readonly SMOKE="$ROOT/scripts/ci/verify/smoke-native-local-environment.sh"
# The version the runtime's sealed guest cw reports; the smoke checks none.
readonly RUNTIME_VERSION='v0.1.0'
# A session bus address that leads nowhere: no step reaches the desktop keyring.
readonly NO_BUS='unix:path=/nonexistent/codewire-native-managed-smoke'

usage() {
  cat <<'USAGE' >&2
usage: native-managed-smoke.sh build --out ABSOLUTE_NEW_DIRECTORY
       native-managed-smoke.sh run --out ABSOLUTE_DIRECTORY [-- SMOKE_ARGUMENTS...]

build makes, from this clean checkout, everything
scripts/ci/verify/smoke-native-local-environment.sh --managed-credential-broker
needs, under the new directory:
  bin/          cw-local-credential-broker-smoke (cw built with the
                local-broker-synthetic-smoke feature), the data-plane,
                credential-bridge and state-probe smokes, and the OCI importer
                built with synthetic-oci-input-smoke
  runtime/      the Linux x86_64 local runtime from this commit
  home/         an isolated HOME whose runtime is installed with
                `setup --local --from runtime/linux-x86_64`
It also verifies the workspace image (verify-workspace-image.sh), whose
receipt the smoke reads from this checkout's .tmp/. It takes one to two
hours; run it in a build slot. It leaves target/debug/cw built with the
synthetic feature.

run checks that this checkout is clean and still at the commit build used,
then runs the smoke with --managed-credential-broker, the built inputs and
SMOKE_ARGUMENTS, such as --egress-interception. GITHUB_SERVER_URL and
CODEWIRE_FORGEJO_FIXTURE_REPOSITORY must be set as the smoke's usage says.
Each run gets its own scratch directory under the directory. It runs for up
to three hours and needs KVM and passwordless sudo.

Docker pulls only public images here: both steps give Docker a configuration
whose credential helper holds nothing, so it never asks the desktop keyring.
USAGE
}

log() {
  printf '[native-managed-smoke] %s\n' "$*" >&2
}

die() {
  printf '[native-managed-smoke] ERROR: %s\n' "$*" >&2
  exit 1
}

require_clean() {
  [[ -z "$(git -C "$ROOT" status --porcelain)" ]] || die "$1: the checkout is not clean"
}

# A Docker configuration of OUT's own whose credential store answers every
# lookup with "not found".
docker_without_credentials() {
  local out="$1"
  mkdir "$out/docker-config" "$out/docker-bin"
  printf '{"credsStore": "codewire-none"}\n' >"$out/docker-config/config.json"
  cat >"$out/docker-bin/docker-credential-codewire-none" <<'HELPER'
#!/bin/sh
case "$1" in
  get) cat >/dev/null; echo 'credentials not found in native keychain'; exit 1 ;;
  list) echo '{}' ;;
  store | erase) cat >/dev/null ;;
  *) exit 1 ;;
esac
HELPER
  chmod 0755 "$out/docker-bin/docker-credential-codewire-none"
}

use_out_environment() {
  local out="$1"
  export DOCKER_CONFIG="$out/docker-config"
  export PATH="$out/docker-bin:$PATH"
  export DBUS_SESSION_BUS_ADDRESS="$NO_BUS"
}

build() {
  local out="$1" sha target
  [[ ! -e "$out" ]] || die "$out already exists"
  require_clean build
  sha="$(git -C "$ROOT" rev-parse HEAD)"
  target="${CARGO_TARGET_DIR:-$ROOT/target}/debug"
  mkdir "$out"
  mkdir "$out/bin" "$out/home"
  docker_without_credentials "$out"
  use_out_environment "$out"
  cd "$ROOT"

  log "smoke binaries at $sha"
  timeout 5400 cargo build --locked -p codewire-local-vmm \
    --bin codewire-local-public-data-smoke \
    --bin codewire-local-codex-bridge-smoke \
    --bin codewire-local-state-probe
  install -m 0755 "$target/codewire-local-public-data-smoke" \
    "$target/codewire-local-codex-bridge-smoke" \
    "$target/codewire-local-state-probe" "$out/bin/"
  timeout 5400 cargo build --locked -p codewire-cli-bin --features local-broker-synthetic-smoke
  install -m 0755 "$target/cw" "$out/bin/cw-local-credential-broker-smoke"
  timeout 5400 cargo build --locked -p codewire-local-vmm --features synthetic-oci-input-smoke \
    --bin codewire-local-oci-import-smoke
  install -m 0755 "$target/codewire-local-oci-import-smoke" "$out/bin/"

  log 'Linux x86_64 local runtime'
  LOCAL_RUNTIME_LINUX_X86_64_ONLY=1 timeout 6000 scripts/ci/release/build-local-runtime.sh \
    linux --source-sha "$sha" --version "$RUNTIME_VERSION" --output "$out/runtime"

  log 'workspace image'
  timeout 7000 bash scripts/ci/verify/verify-workspace-image.sh
  require_clean 'after the workspace image'

  log 'runtime install in the isolated home'
  env -i PATH=/usr/bin:/bin HOME="$out/home" LC_ALL=C TERM=dumb \
    DBUS_SESSION_BUS_ADDRESS="$NO_BUS" \
    timeout 600 "$out/bin/cw-local-credential-broker-smoke" setup --local \
    --from "$out/runtime/linux-x86_64"
  [[ -f "$out/home/.cache/codewire/local-vmm-v1/artifacts.lock.json" ]] ||
    die 'setup wrote no artifact lock'
  printf '%s\n' "$sha" >"$out/source-sha"
  log "built for $sha in $out"
}

run() {
  local out="$1" sha scratch artifacts
  shift
  [[ -f "$out/source-sha" ]] || die "$out holds no finished build"
  require_clean run
  sha="$(git -C "$ROOT" rev-parse HEAD)"
  [[ "$(cat "$out/source-sha")" == "$sha" ]] ||
    die "$out was built at $(cat "$out/source-sha"), not at HEAD $sha"
  use_out_environment "$out"
  scratch="$(mktemp -d "$out/scratch.XXXXXX")"
  artifacts="$out/home/.cache/codewire/local-vmm-v1"
  log "smoke at $sha, scratch $scratch"
  TMPDIR="$scratch" timeout 10800 "$SMOKE" \
    --cw-bin "$out/bin/cw-local-credential-broker-smoke" \
    --data-plane-smoke-bin "$out/bin/codewire-local-public-data-smoke" \
    --credential-bridge-smoke-bin "$out/bin/codewire-local-codex-bridge-smoke" \
    --state-probe-bin "$out/bin/codewire-local-state-probe" \
    --workspace-image-import-bin "$out/bin/codewire-local-oci-import-smoke" \
    --artifact-root "$artifacts/artifacts" --artifact-lock "$artifacts/artifacts.lock.json" \
    --scratch-parent "$scratch" \
    --managed-credential-broker "$@"
}

main() {
  local command="${1:-}" out=''
  [[ $# -ge 1 ]] && shift
  [[ "$command" == build || "$command" == run ]] || { usage; exit 2; }
  [[ "${1:-}" == --out && $# -ge 2 ]] || { usage; exit 2; }
  out="$2"
  shift 2
  [[ "$out" == /* ]] || die '--out must be an absolute path'
  if [[ "$command" == build ]]; then
    [[ $# -eq 0 ]] || { usage; exit 2; }
    build "$out"
    return
  fi
  if [[ $# -gt 0 ]]; then
    [[ "$1" == -- ]] || { usage; exit 2; }
    shift
  fi
  run "$out" "$@"
}

main "$@"
