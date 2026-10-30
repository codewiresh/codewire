#!/usr/bin/env bash
# Dev acceptance for confidential workspace storage (#2321, #2497).
#
# Creates one confidential environment on Dev's SEV-SNP node through the
# product CLI and proves:
#   - a marker written in /workspace survives a stop and start on the same
#     volume, so the guest reopened it with its released key;
#   - with the environment stopped, the host device starts with a LUKS2 header
#     and the marker is not in the clear anywhere after that header;
#   - KBS released the LUKS key only after an attestation, to that guest;
#   - a delete removes the PVC, PV, LINSTOR resource and LV, then the KBS
#     resources, then the OpenBao recovery copy.
#
# It reads Kubernetes with get and logs. It also execs three fixed read-only
# commands in the node's LINSTOR satellite: `lvs`, the device's first 8 bytes
# (the LUKS magic and version, never a keyslot), and a scan past the 16 MiB LUKS2
# metadata area. It also lists KBS's resource names. The marker is random and
# not a secret. No key material is read.
#
# Run it as the smoke identity:
#   scripts/runtime/dev/with-dev-smoke-auth.sh -- \
#     scripts/runtime/confidential/prove-dev-confidential-storage.sh [--cw-bin PATH]
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-https://codewire-dev.sh}"
SANDBOX_NAMESPACE="${SANDBOX_NAMESPACE:-dev-sandboxes}"
KUBE_CONTEXT="${KUBE_CONTEXT:-codewire-dev}"
SNP_NODE_LABEL="${SNP_NODE_LABEL:-node.codewire.sh/confidential-snp=true}"
SNP_NODE=""
STORAGE_NAMESPACE="${STORAGE_NAMESPACE:-piraeus-datastore}"
TRUSTEE_NAMESPACE="${TRUSTEE_NAMESPACE:-codewire-trustee}"
LINSTOR_VG="${LINSTOR_VG:-linstor_nvme}"
OPENBAO_RECOVERY_MOUNT="${OPENBAO_RECOVERY_MOUNT:-codewire-confidential-dev}"
PROOF_MEMORY="${PROOF_MEMORY:-16GB}"
PROOF_DISK="${PROOF_DISK:-20GB}"
PROOF_TIMEOUT_SECONDS="${PROOF_TIMEOUT_SECONDS:-1800}"
DELETE_TIMEOUT_SECONDS="${DELETE_TIMEOUT_SECONDS:-600}"
PROOF_TMP_PARENT="${PROOF_TMP_PARENT:-$ROOT/.tmp}"
SMOKE_ORG_SLUG="codewire-dev-smoke"
readonly LUKS2_HEADER_START="4c 55 4b 53 ba be 00 02"
readonly LUKS2_METADATA_MIB=16
MARKER_PATH="/workspace/.cw-storage-proof"
CW_BIN="${CW_BIN:-}"
ENV_ID=""
CREATED=0
TMPDIR_PROOF=""
FAILURES=0
RESULTS=()

log() { printf '[confidential-storage] %s\n' "$*" >&2; }
die() { printf '[confidential-storage] ERROR: %s\n' "$*" >&2; exit 1; }
pass() { RESULTS+=("PASS $*"); log "PASS $*"; }
fail() { RESULTS+=("FAIL $*"); FAILURES=$((FAILURES + 1)); log "FAIL $*"; }
check() {
  local label="$1"
  shift
  if "$@"; then pass "$label"; else fail "$label"; fi
}
seconds_now() { date +%s; }
cw() { timeout 180 "$CW_BIN" --server "$CODEWIRE_SERVER_URL" "$@"; }

kubectl_ro() {
  [[ "$1" == get || "$1" == logs ]] || die "read-only kubectl refused verb $1"
  kubectl --context "$KUBE_CONTEXT" "$@"
}

# The only exec: one of the fixed read-only commands above.
satellite_exec() {
  local pod
  pod="$(kubectl_ro get pods -n "$STORAGE_NAMESPACE" \
    --field-selector "spec.nodeName=$SNP_NODE" -o json |
    jq -r '[.items[].metadata.name | select(startswith("linstor-satellite"))] | .[0] // empty')"
  [[ -n "$pod" ]] || die "no LINSTOR satellite on $SNP_NODE"
  kubectl --context "$KUBE_CONTEXT" exec -n "$STORAGE_NAMESPACE" "$pod" -c linstor-satellite -- "$@"
}

cleanup() {
  if [[ "$CREATED" == 1 && -n "$ENV_ID" ]]; then
    cw rm --yes "$ENV_ID" >/dev/null 2>&1 || log "cleanup: could not remove $ENV_ID"
  fi
  if [[ -n "$TMPDIR_PROOF" && -d "$TMPDIR_PROOF" ]]; then
    rm -rf -- "$TMPDIR_PROOF"
  fi
}

use_smoke_identity() {
  [[ -n "${CODEWIRE_DEV_SMOKE_API_KEY:-}" ]] ||
    die "CODEWIRE_DEV_SMOKE_API_KEY is not set; run under scripts/runtime/dev/with-dev-smoke-auth.sh"
  export CODEWIRE_API_KEY="$CODEWIRE_DEV_SMOKE_API_KEY"
  export CW_CONFIG_DIR="$TMPDIR_PROOF/cw-config"
  mkdir -p "$CW_CONFIG_DIR"
  local orgs="$TMPDIR_PROOF/organizations.json"
  cw org list --output json >"$orgs" 2>/dev/null ||
    die "the smoke identity cannot sign in to $CODEWIRE_SERVER_URL"
  jq -e --arg slug "$SMOKE_ORG_SLUG" '
    type == "array" and length == 1 and .[0].slug == $slug and .[0].role == "owner"
  ' "$orgs" >/dev/null || die "the API key does not own exactly the $SMOKE_ORG_SLUG organization"
}

env_state() {
  local out="$TMPDIR_PROOF/env-info.out"
  cw info "$ENV_ID" >"$out" 2>&1 || return 1
  awk '$1 == "State:" {print $2; exit}' "$out"
}

wait_for_state() {
  local want="$1" deadline state
  deadline=$(( $(seconds_now) + PROOF_TIMEOUT_SECONDS ))
  while (( $(seconds_now) < deadline )); do
    state="$(env_state || true)"
    [[ "$state" == "$want" ]] && return 0
    if [[ "$state" == error ]]; then
      log "environment $ENV_ID entered error while waiting for $want"
      return 1
    fi
    sleep 10
  done
  log "environment $ENV_ID did not reach $want within ${PROOF_TIMEOUT_SECONDS}s"
  return 1
}

create_env() {
  local out="$TMPDIR_PROOF/create.out"
  if ! cw create --image workspace --name "storage-proof-$(date +%s)" --cpu 2 \
    --memory "$PROOF_MEMORY" --disk "$PROOF_DISK" --isolation confidential --ttl 3h \
    --no-network --no-wait --yes --no-profile --output json >"$out" 2>&1; then
    sed 's/[[:cntrl:]]//g' "$out" >&2
    die "confidential create was refused"
  fi
  ENV_ID="$(jq -r '.id // empty' "$out" 2>/dev/null || true)"
  [[ "$ENV_ID" =~ ^[0-9a-f-]{36}$ ]] || die "could not read the created environment ID"
  CREATED=1
  pass "confidential create accepted ($ENV_ID)"
  wait_for_state running || die "confidential environment never reached running"
  pass "confidential environment reached running"
}

volume_identity() {
  kubectl_ro get pvc -n "$SANDBOX_NAMESPACE" "workspace-sandbox-$ENV_ID" \
    -o jsonpath='{.metadata.uid}{" "}{.spec.volumeName}'
}

device_path() { printf '/dev/%s/%s_00000' "$LINSTOR_VG" "$1"; }

host_device_starts_with_luks2() {
  local start
  start="$(satellite_exec sh -c "head -c 8 '$(device_path "$1")' | od -An -tx1")" || return 1
  [[ "$(printf '%s' "$start" | xargs)" == "$LUKS2_HEADER_START" ]]
}

# Past the LUKS2 metadata, what the guest wrote must be there, as ciphertext.
# Zeros are squeezed so a thin device stays cheap and no line grows unbounded.
marker_scan() { # DEVICE MARKER
  satellite_exec sh -c "dd if='$1' bs=1M skip=$LUKS2_METADATA_MIB status=none | tr -s '\\000' '\\n' | grep -aFc '$2' || true"
}

device_holds_ciphertext() {
  local bytes
  bytes="$(satellite_exec sh -c "dd if='$1' bs=1M skip=$LUKS2_METADATA_MIB count=1024 status=none | tr -d '\\000' | head -c 1 | wc -c")" || return 1
  [[ "$bytes" == 1 ]]
}

marker_absent_from_device() {
  local count
  count="$(marker_scan "$1" "$2")" || return 1
  [[ "$count" == 0 ]]
}

same_volume() { [[ "$(volume_identity)" == "$1" ]]; }
marker_digest_is() { [[ "$(read_marker_digest)" == "$1" ]]; }

read_marker_digest() {
  timeout 180 "$CW_BIN" --server "$CODEWIRE_SERVER_URL" run --no-tty --in "$ENV_ID" -- \
    sha256sum "$MARKER_PATH" 2>/dev/null | awk '{print $1}'
}

write_marker() {
  timeout 180 "$CW_BIN" --server "$CODEWIRE_SERVER_URL" run --no-tty --in "$ENV_ID" -- \
    sh -c "printf %s '$1' >'$MARKER_PATH' && sync" >/dev/null 2>&1
}

kbs_guest_requests() {
  kubectl_ro logs -n "$TRUSTEE_NAMESPACE" deploy/codewire-trustee-kbs -c kbs --since-time="$PROOF_STARTED_AT" 2>/dev/null |
    sed 's/\x1b\[[0-9;]*m//g' | grep 'attestation-agent-kbs-client' || true
}

# Every release of the LUKS key follows an attestation by the same client.
key_released_only_after_attestation() { # requests on stdin
  awk -v env="$ENV_ID" '
    {
      client = $0; sub(/.*logger: /, "", client); sub(/ .*/, "", client)
      if ($0 ~ /POST \/kbs\/v0\/attest HTTP[^"]*" 200 /) attested[client] = 1
      if ($0 ~ ("GET /kbs/v0/resource/default/codewire-workspace-luks/" env " HTTP[^\"]*\" 200 ")) {
        released++
        if (!(client in attested)) bad = 1
      }
    }
    END { exit (released >= 1 && !bad) ? 0 : 1 }
  '
}

wait_until_gone() { # LABEL COMMAND...
  local label="$1" deadline
  shift
  deadline=$(( $(seconds_now) + DELETE_TIMEOUT_SECONDS ))
  while (( $(seconds_now) < deadline )); do
    if ! "$@"; then
      pass "$label"
      return 0
    fi
    sleep 10
  done
  fail "$label"
}

pvc_exists() { kubectl_ro get pvc -n "$SANDBOX_NAMESPACE" "workspace-sandbox-$ENV_ID" >/dev/null 2>&1; }
pv_exists() { kubectl_ro get pv "$1" >/dev/null 2>&1; }
lv_exists() { satellite_exec lvs --noheadings -o lv_name "$LINSTOR_VG" 2>/dev/null | grep -Fq "$1"; }
kbs_holds_environment() {
  kubectl --context "$KUBE_CONTEXT" exec -n "$TRUSTEE_NAMESPACE" deploy/codewire-trustee-kbs -c kbs -- \
    ls /opt/confidential-containers/kbs/repository/repository 2>/dev/null | grep -Fq "$ENV_ID"
}

# Metadata only, never a value. A session that may not read this mount reports
# the copy as unobserved, which fails the proof rather than passing it silently.
recovery_copy_state() {
  local err="$TMPDIR_PROOF/bao.err"
  if bao kv metadata get -mount="$OPENBAO_RECOVERY_MOUNT" -format=json \
    "confidential-storage/$ENV_ID" >/dev/null 2>"$err"; then
    printf present
  elif grep -q 'No value found' "$err"; then
    printf absent
  else
    printf unobserved
  fi
}

recovery_copy_is_gone() {
  local state
  state="$(recovery_copy_state)"
  log "OpenBao recovery copy: $state"
  [[ "$state" == absent ]]
}

main() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --cw-bin) CW_BIN="${2:?}"; shift 2 ;;
      -h|--help) sed -n '2,22p' "${BASH_SOURCE[0]}"; return 0 ;;
      *) die "unknown option: $1" ;;
    esac
  done
  [[ -x "$CW_BIN" ]] || die "--cw-bin must name a built cw"
  local command
  for command in jq kubectl bao awk sha256sum; do
    command -v "$command" >/dev/null 2>&1 || die "missing required command: $command"
  done
  mkdir -p "$PROOF_TMP_PARENT"
  TMPDIR_PROOF="$(mktemp -d "$PROOF_TMP_PARENT/confidential-storage.XXXXXX")"
  trap cleanup EXIT
  PROOF_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  use_smoke_identity
  SNP_NODE="$(kubectl_ro get nodes -l "$SNP_NODE_LABEL" -o json |
    jq -er 'if (.items | length) == 1 then .items[0].metadata.name else error("expected one") end')" ||
    die "expected exactly one node labelled $SNP_NODE_LABEL"
  create_env

  local marker digest identity volume device
  marker="cw-storage-proof-$(head -c 32 /dev/urandom | sha256sum | awk '{print $1}')"
  digest="$(printf %s "$marker" | sha256sum | awk '{print $1}')"
  write_marker "$marker" || die "could not write the marker in $MARKER_PATH"
  [[ "$(read_marker_digest)" == "$digest" ]] || die "the marker did not read back"
  pass "a marker written in the workspace reads back"
  identity="$(volume_identity)"
  volume="${identity#* }"
  [[ -n "$volume" ]] || die "could not read the workspace volume"
  device="$(device_path "$volume")"

  cw stop "$ENV_ID" >/dev/null || die "stop refused"
  wait_for_state stopped || die "environment did not stop"
  check "the host device starts with a LUKS2 header" host_device_starts_with_luks2 "$volume"
  check "the host device holds written data past the LUKS2 metadata" device_holds_ciphertext "$device"
  check "the marker is not in the clear on the host device" marker_absent_from_device "$device" "$marker"

  cw start "$ENV_ID" >/dev/null || die "start refused"
  wait_for_state running || die "environment did not restart"
  check "start kept the same volume" same_volume "$identity"
  check "the marker survived the stop and start" marker_digest_is "$digest"

  kbs_guest_requests >"$TMPDIR_PROOF/kbs.log"
  check "KBS released the LUKS key only after an attestation" \
    key_released_only_after_attestation <"$TMPDIR_PROOF/kbs.log"

  cw rm --yes "$ENV_ID" >/dev/null || die "delete refused"
  CREATED=0
  wait_until_gone "delete removed the PVC" pvc_exists
  wait_until_gone "delete removed the PV" pv_exists "$volume"
  wait_until_gone "delete removed the LV" lv_exists "$volume"
  wait_until_gone "delete removed the KBS resources" kbs_holds_environment
  check "delete removed the OpenBao recovery copy" recovery_copy_is_gone

  printf '%s\n' "${RESULTS[@]}"
  if (( FAILURES > 0 )); then
    die "$FAILURES check(s) failed"
  fi
  log "confidential storage proven on $ENV_ID"
}

main "$@"
