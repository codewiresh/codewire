#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TARGET=""
TMPDIR_SMOKE=""
BOOTSTRAP_API_KEY=""
CREATED_KEY_ID=""
CREATED_KEY_DELETED=0

usage() {
  cat <<'USAGE'
Usage:
  CODEWIRE_API_KEY=... scripts/runtime/apikey/smoke-apikey-lifecycle.sh --target dev|prod|prod-evidence-secondary

Runs the real cw CLI through the fixed public edge: expected-identity check,
create with one-day expiry, list/resolve, authenticate with the new key,
restore bootstrap auth, delete, and confirm absence.

Use scripts/runtime/apikey/with-apikey-smoke-auth.sh for value-blind secret loading.
The smoke accepts no arbitrary server URL, organization, identity, or key.
USAGE
}

log() {
  printf '[apikey-smoke] %s\n' "$*" >&2
}

die() {
  printf '[apikey-smoke] ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local rc=$?
  local cleanup_failed=0
  trap - EXIT HUP INT TERM

  if [[ -n "$CREATED_KEY_ID" && "$CREATED_KEY_DELETED" != "1" && -n "$BOOTSTRAP_API_KEY" ]]; then
    log "attempting leftover key cleanup"
    if ! CODEWIRE_API_KEY="$BOOTSTRAP_API_KEY" \
      "$CW_BIN" api-keys delete "$CREATED_KEY_ID" \
      >"${TMPDIR_SMOKE:-/dev/null}/cleanup.out" \
      2>"${TMPDIR_SMOKE:-/dev/null}/cleanup.err"; then
      cleanup_failed=1
      log "leftover key cleanup failed"
    fi
  fi

  unset CODEWIRE_API_KEY BOOTSTRAP_API_KEY
  if [[ -n "$TMPDIR_SMOKE" && -d "$TMPDIR_SMOKE" ]]; then
    rm -rf "$TMPDIR_SMOKE"
  fi
  if [[ "$rc" == "0" && "$cleanup_failed" == "1" ]]; then
    rc=1
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

case "$-" in
  *x*) die "shell tracing is enabled; rerun without set -x" ;;
esac

while (($# > 0)); do
  case "$1" in
    --target)
      [[ $# -ge 2 ]] || die "--target requires dev, prod, or prod-evidence-secondary"
      TARGET="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

case "$TARGET" in
  dev)
    CODEWIRE_SERVER_URL="https://codewire-dev.sh"
    EXPECTED_USER_EMAIL="connect-apikey-smoke-dev@codewire-dev.sh"
    ;;
  prod)
    CODEWIRE_SERVER_URL="https://codewire.sh"
    EXPECTED_USER_EMAIL="connect-apikey-smoke-prod@codewire.sh"
    ;;
  prod-evidence-secondary)
    CODEWIRE_SERVER_URL="https://codewire.sh"
    EXPECTED_USER_EMAIL="connect-apikey-evidence-prod-secondary@codewire.sh"
    ;;
  *)
    die "--target must be dev, prod, or prod-evidence-secondary"
    ;;
esac
export CODEWIRE_SERVER_URL

for command in awk jq; do
  command -v "$command" >/dev/null 2>&1 || die "missing required command: $command"
done
[[ "${CODEWIRE_API_KEY:-}" =~ ^cw_[0-9a-f]{64}$ ]] || \
  die "CODEWIRE_API_KEY must contain the target bootstrap key"
BOOTSTRAP_API_KEY="$CODEWIRE_API_KEY"

TMPDIR_SMOKE="$(mktemp -d "${TMPDIR:-/tmp}/codewire-apikey-lifecycle.XXXXXX")"
chmod 0700 "$TMPDIR_SMOKE"
export CW_CONFIG_DIR="$TMPDIR_SMOKE/cw-config"
mkdir -m 0700 "$CW_CONFIG_DIR"
unset KUBECONFIG KUBE_CONTEXT

if [[ -z "${CW_BIN:-}" ]]; then
  log "building locked cw CLI"
  if ! (
    cd "$ROOT"
    cargo build --locked --profile ci -p codewire-cli-bin --bin cw
  ) >"$TMPDIR_SMOKE/cargo-build.out" 2>"$TMPDIR_SMOKE/cargo-build.err"; then
    die "failed to build cw CLI; build output retained only until cleanup"
  fi
  CW_BIN="$ROOT/target/ci/cw"
fi
[[ -x "$CW_BIN" ]] || die "CW_BIN is not executable"

CLI_VERSION="$("$CW_BIN" --version 2>"$TMPDIR_SMOKE/version.err")" || \
  die "failed to read cw version"
[[ "$CLI_VERSION" == cw\ * ]] || die "CW_BIN did not report a cw version"

WHOAMI_FILE="$TMPDIR_SMOKE/whoami.json"
if ! "$CW_BIN" whoami --output json >"$WHOAMI_FILE" 2>"$TMPDIR_SMOKE/whoami.err"; then
  die "bootstrap key failed the expected-identity check"
fi
ACTUAL_USER_EMAIL="$(jq -er '.email // empty' "$WHOAMI_FILE")" || \
  die "cw whoami returned no email"
[[ "$ACTUAL_USER_EMAIL" == "$EXPECTED_USER_EMAIL" ]] || \
  die "bootstrap key authenticated an unexpected target identity"

RUN_COMPONENT="${GITHUB_RUN_ID:-local}-$(date -u +%Y%m%d%H%M%S)-${RANDOM}"
KEY_NAME="connect-apikey-${TARGET}-${RUN_COMPONENT}"
[[ "$KEY_NAME" =~ ^[a-z0-9-]+$ ]] || die "generated key name is not whitespace-free"

NEW_KEY_FILE="$TMPDIR_SMOKE/new-key"
umask 077
if ! "$CW_BIN" api-keys create "$KEY_NAME" --expires 1 \
  >"$NEW_KEY_FILE" 2>"$TMPDIR_SMOKE/create.err"; then
  die "cw api-keys create failed"
fi
chmod 0600 "$NEW_KEY_FILE"
if ! awk 'BEGIN { ok=0 } /^cw_[0-9a-f]{64}$/ { ok++ } END { exit ok == 1 ? 0 : 1 }' "$NEW_KEY_FILE"; then
  die "cw api-keys create did not return exactly one well-formed key"
fi

BOOTSTRAP_LIST="$TMPDIR_SMOKE/list-bootstrap.txt"
if ! "$CW_BIN" api-keys list >"$BOOTSTRAP_LIST" 2>"$TMPDIR_SMOKE/list-bootstrap.err"; then
  die "bootstrap-authenticated cw api-keys list failed"
fi
mapfile -t matching_rows < <(awk -v expected="$KEY_NAME" 'NR > 1 && $2 == expected { print $1 "|" $3 }' "$BOOTSTRAP_LIST")
[[ "${#matching_rows[@]}" == "1" ]] || die "new key name did not resolve to exactly one list row"
KEY_PREFIX="${matching_rows[0]%%|*}"
CREATED_KEY_ID="${matching_rows[0]#*|}"
[[ "$KEY_PREFIX" =~ ^[0-9a-f]{8}$ ]] || die "new key list row had a malformed prefix"
[[ -n "$CREATED_KEY_ID" && "$CREATED_KEY_ID" != *[[:space:]]* ]] || \
  die "new key list row had a malformed key ID"

CODEWIRE_API_KEY="$(awk 'NR == 1 { print; exit }' "$NEW_KEY_FILE")"
export CODEWIRE_API_KEY
if ! "$CW_BIN" api-keys list \
  >"$TMPDIR_SMOKE/list-new-key.txt" 2>"$TMPDIR_SMOKE/list-new-key.err"; then
  die "newly created key failed to authenticate cw api-keys list"
fi
new_key_row_count="$(
  awk -v expected_name="$KEY_NAME" -v expected_id="$CREATED_KEY_ID" \
    'NR > 1 && $2 == expected_name && $3 == expected_id { count++ } END { print count + 0 }' \
    "$TMPDIR_SMOKE/list-new-key.txt"
)"
[[ "$new_key_row_count" == "1" ]] || \
  die "new-key-authenticated list did not contain the exact created key"
for list_file in "$BOOTSTRAP_LIST" "$TMPDIR_SMOKE/list-new-key.txt"; do
  if grep -F -f "$NEW_KEY_FILE" "$list_file" >/dev/null; then
    die "cw api-keys list exposed raw key material"
  fi
done

CODEWIRE_API_KEY="$BOOTSTRAP_API_KEY"
export CODEWIRE_API_KEY
if ! "$CW_BIN" api-keys delete "$CREATED_KEY_ID" \
  >"$TMPDIR_SMOKE/delete.out" 2>"$TMPDIR_SMOKE/delete.err"; then
  die "bootstrap-authenticated cw api-keys delete failed"
fi
CREATED_KEY_DELETED=1

FINAL_LIST="$TMPDIR_SMOKE/list-final.txt"
if ! "$CW_BIN" api-keys list >"$FINAL_LIST" 2>"$TMPDIR_SMOKE/list-final.err"; then
  die "final bootstrap-authenticated cw api-keys list failed"
fi
if awk -v expected="$KEY_NAME" 'NR > 1 && $2 == expected { found=1 } END { exit found ? 0 : 1 }' "$FINAL_LIST"; then
  die "deleted key still appears in the final list"
fi

log "target=$TARGET lifecycle passed cli_version=$CLI_VERSION key_id=$CREATED_KEY_ID key_prefix=$KEY_PREFIX"
