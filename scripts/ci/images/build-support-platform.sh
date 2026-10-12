#!/usr/bin/env bash
# Build one platform of the support pair: its base, then its workspace from
# that exact base, each pushed by digest without a tag and verified by
# build-push-image.sh. The join job (support-images.yaml) assembles both
# platforms into the published index. Each platform has its own time budget,
# so a slow leg fails here with a clear message instead of an unexplained
# runner kill.
#
# Usage: build-support-platform.sh linux/amd64|linux/arm64
# Requires SUPPORT_PLATFORM_BUDGET_MINUTES; writes base_digest and
# workspace_digest to $GITHUB_OUTPUT.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly BUILDER="$ROOT/scripts/ci/images/build-push-image.sh"

fail() {
  printf '[build-support-platform] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || { echo 'usage: build-support-platform.sh linux/amd64|linux/arm64' >&2; exit 2; }
readonly PLATFORM="$1"
case "$PLATFORM" in
  linux/amd64|linux/arm64) ;;
  *) fail "unsupported support platform: $PLATFORM" ;;
esac
budget="${SUPPORT_PLATFORM_BUDGET_MINUTES:-}"
[[ "$budget" =~ ^[1-9][0-9]{0,2}$ ]] || fail 'SUPPORT_PLATFORM_BUDGET_MINUTES must be a whole number of minutes'
output="${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

umask 077
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
readonly started="$SECONDS" deadline=$((SECONDS + budget * 60))

# build FAMILY DOCKERFILE CONTEXT [ENV ...] prints the verified platform digest.
build() {
  local family="$1" dockerfile="$2" context="$3" remaining phase_started status=0 digest
  shift 3
  remaining=$((deadline - SECONDS))
  if [[ "$remaining" -le 0 ]]; then
    printf '::error::the %s support build used its %s-minute budget before the %s image\n' \
      "$PLATFORM" "$budget" "$family" >&2
    return 124
  fi
  : >"$work/$family.output"
  phase_started="$SECONDS"
  env "$@" CODEWIRE_IMAGE_PLATFORM="$PLATFORM" GITHUB_OUTPUT="$work/$family.output" \
    timeout --signal=TERM --kill-after=60s "${remaining}s" \
    "$BUILDER" "$family" "$dockerfile" "$context" >&2 || status=$?
  printf 'CODEWIRE_CI_PHASE name=support-%s-%s seconds=%s status=%s\n' \
    "${PLATFORM#linux/}" "$family" "$((SECONDS - phase_started))" "$status" >&2
  if [[ "$status" -eq 124 ]]; then
    printf '::error::the %s support build exceeded its %s-minute budget in the %s image after %s minutes; the streamed build steps above show where the time went\n' \
      "$PLATFORM" "$budget" "$family" "$(((SECONDS - started) / 60))" >&2
    return 124
  fi
  [[ "$status" -eq 0 ]] || return "$status"
  digest="$(sed -n 's/^platform_digest=\(sha256:[0-9a-f]\{64\}\)$/\1/p' "$work/$family.output")"
  [[ "$(wc -l <<<"$digest")" -eq 1 && "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    fail "the $PLATFORM $family build reported no exact digest"
  printf '%s\n' "$digest"
}

base_digest="$(build base images/base/Dockerfile images/base)"
workspace_digest="$(build workspace images/workspace/Dockerfile . \
  "CODEWIRE_BASE_IMAGE_REF=registry.example.invalid/codewire/base@$base_digest")"
printf 'base_digest=%s\nworkspace_digest=%s\n' "$base_digest" "$workspace_digest" >>"$output"
printf 'Built and verified the %s support pair in %s minutes: base %s, workspace %s\n' \
  "$PLATFORM" "$(((SECONDS - started) / 60))" "$base_digest" "$workspace_digest"
