#!/usr/bin/env bash
# Load one fixed API-key smoke identity from OpenBao and exec one child without
# leaking the OpenBao session or an on-disk key.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly OPENBAO_ADDR="https://openbao.example.invalid"

TARGET=""
OPENBAO_PATH=""
AUTH_TMPDIR=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/apikey/with-apikey-smoke-auth.sh --target dev|prod|prod-evidence-secondary [--] [command args...]

Loads one target-scoped API key from its canonical OpenBao document, removes
the OpenBao environment, and execs the command. With no command, runs the API
key lifecycle smoke for the selected target.

Establish the normal human OIDC session first:

  BAO_ADDR=https://openbao.example.invalid \
    bao login -method=oidc -path=oidc -no-print role=human
USAGE
}

log() { printf '[apikey-smoke-auth] %s\n' "$*" >&2; }
die() { printf '[apikey-smoke-auth] ERROR: %s\n' "$*" >&2; exit 1; }

secure_remove() {
  [[ "$#" -gt 0 ]] || return 0
  if command -v shred >/dev/null 2>&1; then
    shred -u -- "$@" 2>/dev/null && return 0
  fi
  rm -f -- "$@" 2>/dev/null
}

cleanup() {
  local status=0
  if [[ -n "$AUTH_TMPDIR" && -d "$AUTH_TMPDIR" ]]; then
    while IFS= read -r -d '' file; do secure_remove "$file" || status=1; done \
      < <(find "$AUTH_TMPDIR" -type f -print0)
    rmdir "$AUTH_TMPDIR" 2>/dev/null || status=1
    [[ ! -e "$AUTH_TMPDIR" ]] || status=1
  fi
  AUTH_TMPDIR=""
  return "$status"
}

unset_openbao_environment() {
  local name
  local -a names=( "${!BAO_@}" )
  for name in "${names[@]}"; do
    unset "$name" 2>/dev/null || die 'cannot remove inherited OpenBao environment'
  done
}

trap 'cleanup || true' EXIT
trap 'exit 130' HUP INT TERM
case "$-" in *x*) die 'shell tracing is enabled; rerun without set -x' ;; esac

while (($# > 0)); do
  case "$1" in
    --target) [[ $# -ge 2 ]] || die '--target requires a value'; TARGET="$2"; shift 2 ;;
    --) shift; break ;;
    -h|--help) usage; exit 0 ;;
    *) break ;;
  esac
done

case "$TARGET" in
  dev) OPENBAO_PATH='apps/codewire/dev/apikey-smoke' ;;
  prod) OPENBAO_PATH='apps/codewire/prod/apikey-smoke' ;;
  prod-evidence-secondary) OPENBAO_PATH='apps/codewire/prod/apikey-evidence-secondary' ;;
  *) die '--target must be dev, prod, or prod-evidence-secondary' ;;
esac

if (($# == 0)); then
  set -- "$ROOT/scripts/runtime/apikey/smoke-apikey-lifecycle.sh" --target "$TARGET"
fi

for command in bao find jq mktemp rm rmdir; do
  command -v "$command" >/dev/null 2>&1 || die "missing required command: $command"
done
[[ "${BAO_ADDR:-$OPENBAO_ADDR}" == "$OPENBAO_ADDR" ]] ||
  die 'BAO_ADDR must be the canonical OpenBao Tailnet endpoint'
unset CODEWIRE_API_KEY 2>/dev/null || die 'cannot remove inherited API key'
ulimit -c 0 || die 'cannot disable core dumps'

umask 077
AUTH_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/codewire-apikey-smoke-auth.XXXXXX")"
chmod 0700 "$AUTH_TMPDIR"
DOCUMENT="$AUTH_TMPDIR/openbao.json"
ERROR_FILE="$AUTH_TMPDIR/openbao.stderr"
KEY_FILE="$AUTH_TMPDIR/api-key"
for file in "$DOCUMENT" "$ERROR_FILE" "$KEY_FILE"; do : >"$file"; chmod 0600 "$file"; done

if ! BAO_ADDR="$OPENBAO_ADDR" bao kv get -format=json "$OPENBAO_PATH" \
  >"$DOCUMENT" 2>"$ERROR_FILE"; then
  if grep -Eqi 'permission denied|status code: 403|code 403' "$ERROR_FILE"; then
    die "OpenBao OIDC session is stale or lacks target=$TARGET"
  fi
  die "failed to fetch target=$TARGET API-key document; output suppressed"
fi
jq -e '
  (.data.metadata.version | type == "number" and . > 0) and
  (.data.data | type == "object" and keys == ["apiKey"]) and
  (.data.data.apiKey | type == "string" and test("^cw_[0-9a-f]{64}$"))
' "$DOCUMENT" >/dev/null || die "target=$TARGET API-key document has an unexpected shape"
jq -er '.data.data.apiKey' "$DOCUMENT" >"$KEY_FILE"
IFS= read -r CODEWIRE_API_KEY <"$KEY_FILE"

cleanup || die 'failed to remove temporary API-key material'
trap - EXIT HUP INT TERM
unset_openbao_environment
export CODEWIRE_API_KEY
log "loaded target=$TARGET API key from canonical OpenBao"
exec "$@"
