#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly EVIDENCE_CYCLES=5
readonly PRODUCTION_CONFIRMATION="RUN APIKEY PROD EVIDENCE"

RELEASE_TAG=""
CONFIRMATION=""

usage() {
  cat <<'USAGE'
Usage:
  CW_BIN=/path/to/verified/cw scripts/runtime/apikey/run-apikey-g4-evidence.sh \
    --release-tag vX.Y.Z --confirm 'RUN APIKEY PROD EVIDENCE'

Runs the fixed two-principal production ApiKeyService evidence sequence. The
binary must be the already downloaded, checksum- and signature-verified release
artifact. Exactly five complete lifecycle cycles run for each fixed production
principal, producing at least 50 ApiKeyService RPC events.

This command accepts no target URL, user, organization, key, cycle count,
kubeconfig, or cluster context.
USAGE
}

log() {
  printf '[apikey-g4-evidence] %s\n' "$*" >&2
}

die() {
  printf '[apikey-g4-evidence] ERROR: %s\n' "$*" >&2
  exit 1
}

case "$-" in
  *x*) die "shell tracing is enabled; rerun without set -x" ;;
esac

while (($# > 0)); do
  case "$1" in
    --release-tag)
      [[ $# -ge 2 ]] || die "--release-tag requires vX.Y.Z"
      RELEASE_TAG="$2"
      shift 2
      ;;
    --confirm)
      [[ $# -ge 2 ]] || die "--confirm requires the exact production phrase"
      CONFIRMATION="$2"
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

[[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
  die "--release-tag must be an exact stable semver tag"
[[ "$CONFIRMATION" == "$PRODUCTION_CONFIRMATION" ]] || \
  die "production evidence requires the exact confirmation phrase"
[[ -n "${CW_BIN:-}" && -x "$CW_BIN" ]] || \
  die "CW_BIN must be the executable verified release artifact"

cli_version="$($CW_BIN --version)" || die "failed to read cw release version"
[[ "$cli_version" == "cw $RELEASE_TAG" ]] || \
  die "CW_BIN version '$cli_version' does not match release $RELEASE_TAG"

unset KUBECONFIG KUBE_CONTEXT
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "start release=$RELEASE_TAG started_at=$started_at principals=2 cycles_each=$EVIDENCE_CYCLES"

for principal in prod prod-evidence-secondary; do
  for cycle in $(seq 1 "$EVIDENCE_CYCLES"); do
    log "principal=$principal cycle=$cycle/$EVIDENCE_CYCLES"
    CW_BIN="$CW_BIN" \
      "$ROOT/scripts/runtime/apikey/with-apikey-smoke-auth.sh" \
        --target "$principal" -- \
        "$ROOT/scripts/runtime/apikey/smoke-apikey-lifecycle.sh" --target "$principal"
  done
done

completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "complete release=$RELEASE_TAG started_at=$started_at completed_at=$completed_at expected_rpc_minimum=50"
