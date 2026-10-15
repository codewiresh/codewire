#!/usr/bin/env bash
# Load the dedicated Dev smoke identity from its canonical OpenBao document,
# scrub the owner credential surface, and exec exactly one child.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

readonly OPENBAO_ADDR="${CODEWIRE_OPENBAO_ADDR:-https://openbao.example.invalid}"
readonly OPENBAO_PATH="apps/codewire/dev/ci-smoke"

AUTH_TMPDIR=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/with-dev-smoke-auth.sh [--] [command args...]

Loads the two dedicated Dev smoke values from the canonical OpenBao document,
removes all OpenBao and inherited smoke credentials, and execs the requested
command. With no command, runs:

  scripts/runtime/dev/smoke-dev-commodity.sh

The wrapper is intentionally non-interactive. Establish the normal human OIDC
session first with:

  BAO_ADDR=https://openbao.example.invalid \
    bao login -method=oidc -path=oidc -no-print role=human
USAGE
}

log() { printf '[runtime-smoke-auth] %s\n' "$*" >&2; }
die() { printf '[runtime-smoke-auth] ERROR: %s\n' "$*" >&2; exit 1; }

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
if [[ "${1:-}" == '-h' || "${1:-}" == '--help' ]]; then usage; exit 0; fi
for command in bao find grep jq mktemp rm rmdir; do
  command -v "$command" >/dev/null 2>&1 || die "missing required command: $command"
done
[[ "${BAO_ADDR:-$OPENBAO_ADDR}" == "$OPENBAO_ADDR" ]] ||
  die 'BAO_ADDR must be the canonical OpenBao Tailnet endpoint'

unset CODEWIRE_DEV_SMOKE_API_KEY EXPECTED_CODEWIRE_SMOKE_USER_EMAIL CODEWIRE_API_KEY \
  2>/dev/null || die 'cannot remove inherited smoke auth environment'
ulimit -c 0 || die 'cannot disable core dumps'

umask 077
AUTH_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/codewire-dev-smoke-auth.XXXXXX")"
chmod 0700 "$AUTH_TMPDIR"
DOCUMENT="$AUTH_TMPDIR/openbao.json"
ERROR_FILE="$AUTH_TMPDIR/openbao.stderr"
API_KEY_FILE="$AUTH_TMPDIR/api-key"
EMAIL_FILE="$AUTH_TMPDIR/user-email"
for file in "$DOCUMENT" "$ERROR_FILE" "$API_KEY_FILE" "$EMAIL_FILE"; do
  : >"$file"
  chmod 0600 "$file"
done

if ! BAO_ADDR="$OPENBAO_ADDR" bao kv get -format=json "$OPENBAO_PATH" \
  >"$DOCUMENT" 2>"$ERROR_FILE"; then
  if grep -Eqi 'permission denied|status code: 403|code 403' "$ERROR_FILE"; then
    die 'OpenBao OIDC session is stale or lacks the exact Dev smoke path'
  fi
  die 'failed to fetch the canonical Dev smoke document; output suppressed'
fi

jq -e '
  (.data.metadata.version | type == "number" and . > 0) and
  (.data.data | type == "object" and keys == ["apiKey", "userEmail"]) and
  (.data.data.apiKey | type == "string" and test("^cw_[0-9a-f]{64}$")) and
  (.data.data.userEmail | type == "string" and
    test("^[^[:space:]@]+@[^[:space:]@]+\\.[^[:space:]@]+$"))
' "$DOCUMENT" >/dev/null || die 'canonical Dev smoke document has an unexpected shape'
jq -er '.data.data.apiKey' "$DOCUMENT" >"$API_KEY_FILE"
jq -er '.data.data.userEmail' "$DOCUMENT" >"$EMAIL_FILE"

IFS= read -r CODEWIRE_DEV_SMOKE_API_KEY <"$API_KEY_FILE"
IFS= read -r EXPECTED_CODEWIRE_SMOKE_USER_EMAIL <"$EMAIL_FILE"
cleanup || die 'failed to remove temporary smoke auth material'
trap - EXIT HUP INT TERM
unset_openbao_environment
unset CODEWIRE_API_KEY
export CODEWIRE_DEV_SMOKE_API_KEY EXPECTED_CODEWIRE_SMOKE_USER_EMAIL

if [[ "${1:-}" == '--' ]]; then shift; fi
if [[ "$#" -eq 0 ]]; then set -- "$ROOT/scripts/runtime/dev/smoke-dev-commodity.sh"; fi

log 'loaded the two fixed Dev smoke values from canonical OpenBao'
exec "$@"
