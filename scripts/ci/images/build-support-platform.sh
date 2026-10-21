#!/usr/bin/env bash
# Build one platform of the support pair: its base, then its workspace from
# that exact base, each pushed by digest without a tag and verified by
# build-push-image.sh. The join job (support-images.yaml) assembles both
# platforms into the published index. Each platform has its own time budget,
# so a slow leg fails here with a clear message instead of an unexplained
# runner kill.
#
# linux/amd64 builds on the trusted BuildKit builder (trusted-buildkit.sh), or
# in the job's own pinned BuildKit container only on the owner's explicit
# recovery. linux/arm64 builds natively on the protected arm64 BuildKit node
# (infra runbooks/ci-arm64-builder.md). Both are reached over mutual TLS with
# client certificates this job's publisher role reads from OpenBao. If a
# certificate cannot be read or a builder does not answer as its platform,
# the build fails: arm64 never falls back to emulation, which cannot finish in
# time, and amd64 never silently falls back to building in the job.
#
# Usage: build-support-platform.sh linux/amd64|linux/arm64
# Requires SUPPORT_PLATFORM_BUDGET_MINUTES; writes base_digest and
# workspace_digest to $GITHUB_OUTPUT. CODEWIRE_SOURCE_DIR (default .) names
# the checkout whose images are built: deploy-prod.yaml builds a release
# tag's pair from .release-source with this tree's scripts, and passes the
# tag's CODEWIRE_SOURCE_SHA and CODEWIRE_RELEASE_TAG through to the builder.
# SUPPORT_PLATFORM_BASE_DIGEST, when set, is this platform's image in a base
# index main already published for the same source: the base is not rebuilt
# and the workspace is built from exactly that digest.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly BUILDER="$ROOT/scripts/ci/images/build-push-image.sh"
readonly ARM64_CLIENT_FETCHER="$ROOT/scripts/ci/setup/fetch-openbao-arm64-buildkit-client.sh"
readonly ARM64_BUILDKIT_HOST="${ARM64_BUILDKIT_HOST:-arm64-builder.example.invalid}"
readonly ARM64_BUILDKIT_ENDPOINT="tcp://$ARM64_BUILDKIT_HOST:1234"
# shellcheck source=scripts/ci/setup/trusted-buildkit.sh
source "$ROOT/scripts/ci/setup/trusted-buildkit.sh"

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
source_dir="${CODEWIRE_SOURCE_DIR:-.}"
[[ "$source_dir" =~ ^[A-Za-z0-9._][A-Za-z0-9._/-]*$ && "$source_dir" != *..* && -d "$source_dir" ]] ||
  fail "CODEWIRE_SOURCE_DIR must name a relative checkout directory: $source_dir"
# The image paths the builder receives, relative to the job's directory.
if [[ "$source_dir" == . ]]; then
  base_dockerfile=images/base/Dockerfile base_context=images/base
  workspace_dockerfile=images/workspace/Dockerfile workspace_context=.
else
  source_dir="${source_dir%/}"
  base_dockerfile="$source_dir/images/base/Dockerfile" base_context="$source_dir/images/base"
  workspace_dockerfile="$source_dir/images/workspace/Dockerfile" workspace_context="$source_dir"
fi
readonly base_dockerfile base_context workspace_dockerfile workspace_context

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/codewire-support-platform.XXXXXX")"
remote_builder=''
cleanup() {
  if [[ -n "$remote_builder" ]]; then
    # Removing a remote builder only forgets it locally; the node is untouched.
    DOCKER_CONFIG="$work/docker-config" timeout 30 docker buildx rm "$remote_builder" >/dev/null 2>&1 || true
  fi
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf -- "$work"
}
trap cleanup EXIT
readonly started="$SECONDS" deadline=$((SECONDS + budget * 60))

# Attach the native arm64 node as this job's only builder, in a private
# Docker configuration that build-push-image.sh then uses for its registry
# login and every build.
attach_arm64_builder() {
  local tls="$work/arm64-buildkit-tls" platforms
  mkdir -m 0700 "$tls" "$work/docker-config"
  "$ARM64_CLIENT_FETCHER" "$tls" || {
    printf '::error::the arm64 BuildKit client certificate could not be read; the linux/arm64 support build does not fall back to emulation\n' >&2
    return 1
  }
  remote_builder="codewire-support-arm64-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
  DOCKER_CONFIG="$work/docker-config" docker buildx create --name "$remote_builder" \
    --driver remote --platform linux/arm64 \
    --driver-opt "cacert=$tls/ca.crt,cert=$tls/client.crt,key=$tls/client.key,servername=$ARM64_BUILDKIT_HOST" \
    "$ARM64_BUILDKIT_ENDPOINT" >/dev/null
  if ! platforms="$(DOCKER_CONFIG="$work/docker-config" timeout 120 \
      docker buildx inspect "$remote_builder" --bootstrap 2>&1)" \
      || ! grep -Eq '^Status: +running$' <<<"$platforms" \
      || ! grep -Eq '^Platforms: .*linux/arm64' <<<"$platforms"; then
    printf '::error::the native arm64 BuildKit node %s did not answer as a running linux/arm64 builder; the linux/arm64 support build does not fall back to emulation\n' \
      "$ARM64_BUILDKIT_ENDPOINT" >&2
    return 1
  fi
  printf 'Attached the native arm64 BuildKit node %s\n' "$ARM64_BUILDKIT_ENDPOINT" >&2
}
builder_env=()
if [[ "$PLATFORM" == linux/arm64 ]]; then
  attach_arm64_builder
  builder_env=(CODEWIRE_EXTERNAL_BUILDX_BUILDER="$remote_builder" CODEWIRE_EXTERNAL_DOCKER_CONFIG="$work/docker-config")
elif ! trusted_buildkit_in_job; then
  mkdir -m 0700 "$work/trusted-buildkit-tls" "$work/docker-config"
  remote_builder="codewire-support-amd64-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
  trusted_buildkit_attach "$remote_builder" "$work/docker-config" "$work/trusted-buildkit-tls"
  builder_env=(CODEWIRE_EXTERNAL_BUILDX_BUILDER="$remote_builder" CODEWIRE_EXTERNAL_DOCKER_CONFIG="$work/docker-config")
fi

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
  env "$@" "${builder_env[@]}" CODEWIRE_IMAGE_PLATFORM="$PLATFORM" GITHUB_OUTPUT="$work/$family.output" \
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

published_base="${SUPPORT_PLATFORM_BASE_DIGEST:-}"
if [[ -n "$published_base" ]]; then
  [[ "$published_base" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    fail "SUPPORT_PLATFORM_BASE_DIGEST is not an exact digest: $published_base"
  base_digest="$published_base"
  printf 'Building the %s workspace from the published base %s\n' "$PLATFORM" "$base_digest" >&2
else
  base_digest="$(build base "$base_dockerfile" "$base_context")"
fi
workspace_digest="$(build workspace "$workspace_dockerfile" "$workspace_context" \
  "CODEWIRE_BASE_IMAGE_REF=registry.example.invalid/codewire/base@$base_digest")"
printf 'base_digest=%s\nworkspace_digest=%s\n' "$base_digest" "$workspace_digest" >>"$output"
printf 'Built and verified the %s support pair in %s minutes: base %s, workspace %s\n' \
  "$PLATFORM" "$(((SECONDS - started) / 60))" "$base_digest" "$workspace_digest"
