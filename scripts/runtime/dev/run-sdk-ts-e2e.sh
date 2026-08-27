#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

readonly DEV_SERVER_URL="https://codewire-dev.sh"

CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-$DEV_SERVER_URL}"
CW_BIN="${CW_BIN:-cw}"
RUN_DIR=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/with-dev-smoke-auth.sh -- \
    scripts/runtime/dev/run-sdk-ts-e2e.sh

Runs the fixed TypeScript SDK e2e suite against deployed dev only. This runner
accepts no child command. It must receive the existing dev smoke key from
with-dev-smoke-auth.sh; it resolves that key's one organization with cw, then
passes only the API key, organization ID, and dev origin to make sdk-e2e-ts.
USAGE
}

log() {
  printf '[sdk-ts-e2e] %s\n' "$*" >&2
}

die() {
  printf '[sdk-ts-e2e] ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local dir="${RUN_DIR:-}"
  [[ -n "$dir" ]] || return 0
  rm -rf -- "$dir" || return 1
  [[ ! -e "$dir" ]] || return 1
  RUN_DIR=""
}

unset_openbao_environment() {
  local name
  local -a names=( "${!BAO_@}" )
  for name in "${names[@]}"; do
    unset "$name" 2>/dev/null || die "cannot remove inherited OpenBao environment"
  done
}

case "$-" in
  *x*) die "shell tracing is enabled; rerun without set -x" ;;
esac

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

[[ "$#" -eq 0 ]] || die "this runner accepts no child command"
[[ "$CODEWIRE_SERVER_URL" == "$DEV_SERVER_URL" ]] || \
  die "refusing to run against $CODEWIRE_SERVER_URL"
[[ "${CODEWIRE_DEV_SMOKE_API_KEY:-}" =~ ^cw_[0-9a-f]{64}$ ]] || \
  die "CODEWIRE_DEV_SMOKE_API_KEY is required; use with-dev-smoke-auth.sh"

for required_command in jq make mktemp "$CW_BIN"; do
  command -v "$required_command" >/dev/null 2>&1 || \
    die "missing required command: $required_command"
done

# The parent wrapper has already removed OpenBao material. Clear it again so
# neither the org lookup nor the fixed e2e child can inherit a platform token.
unset_openbao_environment
unset KUBECONFIG KUBE_CONTEXT 2>/dev/null || \
  die "cannot remove inherited Kubernetes configuration"
ulimit -c 0 || die "cannot disable core dumps"
umask 077

RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/codewire-sdk-ts-e2e.XXXXXX")"
chmod 0700 "$RUN_DIR"
trap 'cleanup || true' EXIT
trap 'exit 130' HUP INT TERM

CW_CONFIG_DIR="$RUN_DIR/cw-config"
mkdir -m 0700 "$CW_CONFIG_DIR"
ORGS_JSON="$RUN_DIR/orgs.json"
ORGS_ERR="$RUN_DIR/orgs.err"

if ! CODEWIRE_API_KEY="$CODEWIRE_DEV_SMOKE_API_KEY" \
  CODEWIRE_SERVER_URL="$CODEWIRE_SERVER_URL" \
  CW_CONFIG_DIR="$CW_CONFIG_DIR" \
  "$CW_BIN" org list --output json >"$ORGS_JSON" 2>"$ORGS_ERR"; then
  die "failed to resolve the dev smoke organization; output suppressed"
fi

if ! CODEWIRE_ORG_ID="$(jq -er '
  if type == "array"
    and length == 1
    and ((.[0].id | type) == "string")
    and ((.[0].id | length) > 0)
  then .[0].id
  else error("expected exactly one organization with a non-empty id")
  end
' "$ORGS_JSON" 2>/dev/null)"; then
  die "dev smoke key must resolve exactly one organization"
fi
[[ "$CODEWIRE_ORG_ID" =~ ^[A-Za-z0-9_-]+$ ]] || \
  die "resolved organization ID has an unexpected shape"

log "running fixed SDK e2e against deployed dev"
env -i \
  PATH="$PATH" \
  HOME="${HOME:?HOME is required}" \
  TMPDIR="${TMPDIR:-/tmp}" \
  CODEWIRE_API_KEY="$CODEWIRE_DEV_SMOKE_API_KEY" \
  CODEWIRE_ORG_ID="$CODEWIRE_ORG_ID" \
  CODEWIRE_SERVER_URL="$CODEWIRE_SERVER_URL" \
  make -C "$ROOT" sdk-e2e-ts
