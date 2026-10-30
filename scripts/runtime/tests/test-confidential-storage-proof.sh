#!/usr/bin/env bash
# Offline contract for the Dev confidential-storage proof (#2321, #2497): its
# device, key-release and recovery-copy checks accept what they should and
# refuse each drift, and it touches the cluster only through its guarded calls.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROOF="$ROOT/scripts/runtime/confidential/prove-dev-confidential-storage.sh"
ENV_ID_FIXTURE="be31063a-8ec8-46d5-aa17-75cda1729370"

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/confidential-storage-proof.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

die_test() { printf 'test-confidential-storage-proof: %s\n' "$*" >&2; exit 1; }

bash -n "$PROOF"
"$PROOF" --help | grep -F 'prove-dev-confidential-storage.sh' >/dev/null
# Exec is limited to the satellite wrapper and the KBS name listing, and
# nothing mutates the cluster.
if grep -nE 'kubectl[^|]*[[:space:]](apply|delete|patch|create|edit|port-forward|label|annotate|scale|replace|cordon|drain)[[:space:]]' \
  "$PROOF" >/dev/null; then
  die_test "the proof names a mutating kubectl verb"
fi
[[ "$(grep -c 'kubectl --context' "$PROOF")" == 3 ]] || die_test "kubectl is called outside its guarded calls"
# The device read stops at the magic and version; no keyslot is read.
grep -F 'head -c 8' "$PROOF" >/dev/null || die_test "the header check reads more than the magic and version"
grep -F 'readonly LUKS2_METADATA_MIB=16' "$PROOF" >/dev/null || die_test "the scan does not skip the LUKS2 metadata"

# The sourced proof reads these variables and calls these fakes.
# shellcheck disable=SC2034,SC2329
(
  # shellcheck disable=SC1090
  source <(sed '$d' "$PROOF")
  ENV_ID="$ENV_ID_FIXTURE"
  TMPDIR_PROOF="$work"
  # The fake satellite runs the same commands against local files.
  satellite_exec() { "$@"; }
  kubectl_ro() { die_test "the device checks reached the cluster"; }

  device_path() { printf '%s/%s' "$work" "$1"; }

  # A LUKS2 device: the header, zeros, then ciphertext past the metadata.
  { printf 'LUKS\272\276\000\002'; head -c $((17 * 1024 * 1024)) /dev/zero; head -c 4096 /dev/urandom; } >"$work/luks"
  host_device_starts_with_luks2 luks || die_test "a LUKS2 device was refused"
  device_holds_ciphertext "$work/luks" || die_test "written data was not seen"
  marker_absent_from_device "$work/luks" "cw-storage-proof-abc" || die_test "a marker was seen in ciphertext"

  # A LUKS1 header and an unformatted device are refused.
  { printf 'LUKS\272\276\000\001'; head -c 1024 /dev/zero; } >"$work/luks1"
  if host_device_starts_with_luks2 luks1; then die_test "a LUKS1 device was accepted"; fi
  head -c $((17 * 1024 * 1024)) /dev/zero >"$work/zeros"
  if host_device_starts_with_luks2 zeros; then die_test "an unformatted device was accepted"; fi
  if device_holds_ciphertext "$work/zeros"; then die_test "an empty device was read as written"; fi

  # A marker in the clear, in a run of zeros, fails the check.
  { cat "$work/luks"; printf 'plain cw-storage-proof-abc plain\n'; head -c 4096 /dev/zero; } >"$work/clear"
  if marker_absent_from_device "$work/clear" "cw-storage-proof-abc"; then
    die_test "a marker in the clear was not found"
  fi

  attest='INFO actix_web::middleware::logger: 10.0.0.1 "POST /kbs/v0/attest HTTP/1.1" 200 20397 "-"'
  release="INFO actix_web::middleware::logger: 10.0.0.1 \"GET /kbs/v0/resource/default/codewire-workspace-luks/$ENV_ID HTTP/1.1\" 200 434 \"-\""
  other="INFO actix_web::middleware::logger: 10.0.0.2 \"GET /kbs/v0/resource/default/codewire-workspace-luks/$ENV_ID HTTP/1.1\" 200 434 \"-\""
  printf '%s\n%s\n' "$attest" "$release" | key_released_only_after_attestation ||
    die_test "a release after attestation was refused"
  if printf '%s\n%s\n' "$release" "$attest" | key_released_only_after_attestation; then
    die_test "a release before attestation was accepted"
  fi
  if printf '%s\n%s\n' "$attest" "$other" | key_released_only_after_attestation; then
    die_test "a release to a client that never attested was accepted"
  fi
  if printf '%s\n' "$attest" | key_released_only_after_attestation; then
    die_test "a run with no release was accepted"
  fi

  # Only a positively absent recovery copy passes; a denied read is unobserved.
  bao() { return 0; }
  [[ "$(recovery_copy_state)" == present ]] || die_test "a present copy was not reported"
  if recovery_copy_is_gone 2>/dev/null; then die_test "a present copy counted as gone"; fi
  bao() { printf 'No value found at x\n' >&2; return 2; }
  recovery_copy_is_gone 2>/dev/null || die_test "an absent copy was refused"
  bao() { printf 'permission denied\n' >&2; return 2; }
  [[ "$(recovery_copy_state)" == unobserved ]] || die_test "a denied read was not unobserved"
  if recovery_copy_is_gone 2>/dev/null; then die_test "a denied read counted as gone"; fi
)
