#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly WORKFLOW="$ROOT/.gitea/workflows/support-images.yaml"
readonly LEGACY_GITHUB_WORKFLOW="$ROOT/.github/workflows/build-workspace-image.yml"
readonly WORKSPACE_DOCKERFILE="$ROOT/images/workspace/Dockerfile"

fail() {
  printf '[test-support-images-workflow] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -f "$WORKFLOW" ]] || fail 'Gitea support-image workflow is missing'
if [[ -e "$LEGACY_GITHUB_WORKFLOW" || -L "$LEGACY_GITHUB_WORKFLOW" ]]; then
  fail 'legacy GitHub workspace-image builder must remain retired'
fi
if grep -q '^  workflow_dispatch:' "$WORKFLOW"; then
  fail 'support-image publication must be canonical-main push-only'
fi
if grep -q '^concurrency:$' "$WORKFLOW"; then
  fail 'support-image publication must not rely on unsupported Gitea concurrency'
fi
if grep -Fq 'CODEWIRE_GHCR_PUBLISH_ENABLED' "$WORKFLOW"; then
  fail 'support GHCR publication retains its rollout flag'
fi
selection_job="$(sed -n '/^  support-selection:/,/^  publish-support-images:/p' "$WORKFLOW")"
if grep -q '^    paths:' "$WORKFLOW"; then
  fail 'support publication still duplicates artifact impact in workflow paths'
fi
grep -Fq '          fetch-depth: 0' <<<"$selection_job" ||
  fail 'support selection does not receive canonical history for ancestry validation'
grep -Fq 'https://forgejo.example.invalid/noel/actions-checkout@34e114876b0b11c390a56381ad16ebd13914f8d5' \
  <<<"$selection_job" || fail 'support selection checkout action is not pinned'
grep -Fq 'name: Verify sealed Rust toolchain' \
  <<<"$selection_job" ||
  fail 'support selection does not verify the sealed Rust toolchain for artifact classification'
toolchain_line="$(grep -n -m1 'name: Verify sealed Rust toolchain' \
  <<<"$selection_job" | cut -d: -f1)"
classifier_line="$(grep -n -m1 'name: Plan atomic support build from validated baseline' \
  <<<"$selection_job" | cut -d: -f1)"
[[ "$toolchain_line" -lt "$classifier_line" ]] ||
  fail 'support selection verifies Rust after artifact classification'
grep -Fq 'scripts/ci/images/resolve-published-support-pair.sh "$candidate"' \
  <<<"$selection_job" || fail 'support selection does not resolve published pair metadata'
grep -Fq 'GHCR_PUBLISH_USERNAME: ${{ vars.GHCR_PUBLISH_USERNAME }}' \
  <<<"$selection_job" || fail 'support baseline resolver omits configured registry identity'
grep -Fq -- '--baseline-candidate "$RUNNER_TEMP/codewire-published-support-candidate.json"' \
  <<<"$selection_job" || fail 'planner does not consume the untrusted registry candidate'
grep -Fq -- '--target-base "$GITHUB_SHA"' <<<"$selection_job" ||
  fail 'support planner target is not the exact canonical head'
grep -Fq -- '--trusted-policy "$GITHUB_SHA"' <<<"$selection_job" ||
  fail 'support planner policy is not the exact canonical head'
grep -Fq 'scripts/ci/plan/apply-support-plan.py' <<<"$selection_job" ||
  fail 'support event adapter does not consume planner facts'
grep -Fq 'name: Remove untrusted registry candidate' <<<"$selection_job" ||
  fail 'support selection does not remove candidate metadata'
grep -Fq 'rm -f -- "$RUNNER_TEMP/codewire-published-support-candidate.json"' \
  <<<"$selection_job" || fail 'support selection cleanup does not use the fixed runner-temp path'
if grep -Fq '"$GITHUB_SHA^"' <<<"$selection_job" \
  || grep -Eq 'select-support-images\.sh' <<<"$selection_job"; then
  fail 'support selection retains HEAD-parent or legacy path classification'
fi
if grep -Fq 'secrets.' <<<"$selection_job"; then
  fail 'support selection bypasses the existing Infisical credential handoff'
fi
for output in build_support_images reason matched_categories base_image_state \
  workspace_image_state baseline_sha head_sha head_tree ci_plan_sha256 \
  ci_policy_sha256 baseline_valid; do
  grep -Fq "      ${output}: \${{ steps.select.outputs.${output} }}" <<<"$selection_job" ||
    fail "support selection omits ${output} planner output"
done
[[ "$(grep -Fc "if: \${{ needs.support-selection.outputs.build_support_images == 'true' }}" \
  "$WORKFLOW")" -eq 1 ]] ||
  fail 'the atomic support build/publication job is not gated by one selection'
grep -qF 'needs: [support-selection]' "$WORKFLOW" ||
  fail 'support build does not wait for support selection'
grep -qF 'scripts/ci/images/build-push-image.sh base images/base/Dockerfile images/base' \
  "$WORKFLOW" || fail 'base is not built by the canonical Gitea helper'
# shellcheck disable=SC2016
grep -qF 'CODEWIRE_BASE_IMAGE_REF: ${{ steps.base.outputs.candidate_ref }}' \
  "$WORKFLOW" || fail 'workspace does not consume the same-job exact base candidate'
grep -qF 'scripts/ci/images/build-push-image.sh workspace images/workspace/Dockerfile .' \
  "$WORKFLOW" || fail 'workspace is not built by the canonical Gitea helper'
publish_job="$(sed -n '/^  publish-support-images:/,$p' "$WORKFLOW")"
grep -qF 'needs: [support-selection]' <<<"$publish_job" ||
  fail 'support publisher is not bound to selection'
# shellcheck disable=SC2016
grep -Fq 'GHCR_PUBLISH_USERNAME: ${{ vars.GHCR_PUBLISH_USERNAME }}' \
  <<<"$publish_job" || fail 'support publisher identity is not repository configuration'
[[ "$(grep -Fc 'scripts/ci/images/publish-image-to-ghcr.sh' <<<"$publish_job")" -eq 1 ]] ||
  fail 'support publisher does not use one pair publication boundary'
grep -Fq -- '--support-pair' <<<"$publish_job" ||
  fail 'support publisher does not require pair preflight and ordering'
# shellcheck disable=SC2016
[[ "$(grep -Fc 'steps.' <<<"$publish_job" | tr -d '[:space:]')" -gt 0 ]] ||
  fail 'support publisher does not consume same-job step outputs'
[[ "$(grep -Fc 'outputs.source_sha }}" == "$GITHUB_SHA"' <<<"$publish_job")" -eq 2 ]] ||
  fail 'support publisher does not verify both exact build sources'
if grep -Fq 'needs.build-' <<<"$publish_job"; then
  fail 'support publisher still crosses a runner job-output boundary'
fi
# shellcheck disable=SC2016
grep -Fq '"${{ steps.base.outputs.candidate_ref }}"' <<<"$publish_job" ||
  fail 'support publisher omits the immutable base candidate'
# shellcheck disable=SC2016
grep -Fq '"${{ steps.workspace.outputs.candidate_ref }}"' <<<"$publish_job" ||
  fail 'support publisher omits the immutable workspace candidate'
if grep -Fq 'secrets.' <<<"$publish_job"; then
  fail 'support publisher bypasses the Infisical credential handoff'
fi
grep -qF -- '-p codewire-cli-bin --bin cw' "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace builds cw from the wrong Rust package'
builder_stage="$(sed -n '/^FROM rust:.* AS cw-builder$/,/^FROM /p' "$WORKSPACE_DOCKERFILE")"
grep -qF 'protobuf-compiler' <<<"$builder_stage" ||
  fail 'workspace Rust builder does not install protoc'
grep -qF 'libprotobuf-dev' <<<"$builder_stage" ||
  fail 'workspace Rust builder does not install well-known protobuf contracts'
grep -qF -- '--mount=type=bind,target=/src,readonly' <<<"$builder_stage" ||
  fail 'workspace Rust builder does not consume the source tree read-only'
grep -qF -- '--manifest-path /src/Cargo.toml' <<<"$builder_stage" ||
  fail 'workspace Rust builder does not build the canonical workspace manifest'
if grep -Eq '^COPY (Cargo|crates|proto|libs)' <<<"$builder_stage"; then
  fail 'workspace Rust builder still copies repository source into image layers'
fi
grep -qF 'COPY --from=cw-builder /out/cw /usr/local/bin/cw' \
  "$WORKSPACE_DOCKERFILE" || fail 'workspace final stage receives more than the exported cw binary'
grep -qF 'ln -s cw /usr/local/bin/daemon' "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace image does not expose the daemon process alias through cw'
grep -qF 'ln -s cw /usr/local/bin/codewire-daemon' "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace image does not expose the codewire-daemon process alias through cw'
cw_copy_line="$(grep -n -m1 'COPY --from=cw-builder /out/cw /usr/local/bin/cw' \
  "$WORKSPACE_DOCKERFILE" | cut -d: -f1)"
for moving_tool_pattern in \
  'go install golang.org/x/tools/gopls@latest' \
  'pipx install aider-chat' \
  'npm install -g --ignore-scripts' \
  'https://sh.rustup.rs'; do
  moving_tool_line="$(grep -n -m1 -F "$moving_tool_pattern" \
    "$WORKSPACE_DOCKERFILE" | cut -d: -f1)"
  [[ -n "$moving_tool_line" && "$moving_tool_line" -lt "$cw_copy_line" ]] ||
    fail "moving tool layer '$moving_tool_pattern' must precede the source-built cw handoff"
done
[[ "$(tail -n 1 "$WORKSPACE_DOCKERFILE")" == 'USER codewire' ]] ||
  fail 'workspace image does not restore the unprivileged runtime user after installing cw'

if grep -Eq '(nexus-system-cluster\.private\.invalid/oci-promoted/codewire|ghcr\.io/codewiresh)/(base|workspace):(latest|main)' \
    "$WORKFLOW"; then
  fail 'support-image publication contains a moving image tag'
fi
grep -qxF 'ARG BASE_IMAGE_REF' "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace build does not require an explicit exact base'
base_arg_line="$(grep -n '^ARG BASE_IMAGE_REF$' "$WORKSPACE_DOCKERFILE" | cut -d: -f1)"
first_from_line="$(grep -n '^FROM ' "$WORKSPACE_DOCKERFILE" | head -1 | cut -d: -f1)"
[[ "$base_arg_line" -lt "$first_from_line" ]] ||
  fail 'workspace base argument must be declared before the first build stage'
# shellcheck disable=SC2016
grep -qF 'FROM ${BASE_IMAGE_REF}' "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace Dockerfile does not consume its exact base argument'
if grep -qF 'ghcr.io/codewiresh/base:latest' "$WORKSPACE_DOCKERFILE"; then
  fail 'workspace Dockerfile still consumes the moving base tag'
fi
grep -Eq '^FROM ubuntu:noble@sha256:[0-9a-f]{64}$' "$ROOT/images/base/Dockerfile" ||
  fail 'base image foundation is not digest-pinned'
grep -Eq '^FROM rust:1\.91\.1-slim-bookworm@sha256:[0-9a-f]{64} AS cw-builder$' \
  "$WORKSPACE_DOCKERFILE" || fail 'workspace builder foundation is not digest-pinned'
for dockerfile in "$ROOT/images/base/Dockerfile" "$WORKSPACE_DOCKERFILE"; do
  grep -qF 'amd64)' "$dockerfile" || fail "$dockerfile omits amd64 installers"
  grep -qF 'arm64)' "$dockerfile" || fail "$dockerfile omits arm64 installers"
  grep -qF 'sha256sum -c -' "$dockerfile" || fail "$dockerfile omits checksum verification"
done
for checksum_var in docker_sha buildx_sha compose_sha gh_sha; do
  [[ "$(grep -Ec "${checksum_var}=[0-9a-f]{64}" "$ROOT/images/base/Dockerfile")" -eq 2 ]] ||
    fail "base image does not define $checksum_var exactly once per supported architecture"
done
for checksum_var in node_sha go_sha; do
  [[ "$(grep -Ec "${checksum_var}=[0-9a-f]{64}" "$WORKSPACE_DOCKERFILE")" -eq 2 ]] ||
    fail "workspace image does not define $checksum_var exactly once per supported architecture"
done
grep -qF 'snapshot.ubuntu.com/ubuntu/20260803T000000Z/' "$ROOT/images/base/ubuntu.sources" ||
  fail 'base apt inputs are not bound to the reviewed Ubuntu snapshot'
grep -qF 'snapshot.debian.org/archive/debian/20251208T000000Z/' \
  "$ROOT/images/workspace/debian.sources" ||
  fail 'workspace builder apt inputs are not bound to the reviewed Debian snapshot'
for agent_package in @openai/codex @anthropic-ai/claude-code @google/gemini-cli \
  @moonshot-ai/kimi-code @earendil-works/pi-coding-agent; do
  grep -qF "$agent_package" "$WORKSPACE_DOCKERFILE" ||
    fail "workspace omits moving agent package $agent_package"
  if grep -Fq "${agent_package}@" "$WORKSPACE_DOCKERFILE"; then
    fail "moving agent package $agent_package is unexpectedly version-pinned"
  fi
done
grep -qF 'npm@latest pnpm yarn' "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace does not update the Node archive npm together with its package managers'
grep -qF 'npm cache clean --force' "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace retains the root package-manager installer cache'
grep -qF -- 'allow-scripts=@anthropic-ai/claude-code --location=user' \
  "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace does not persist the narrow Claude update policy under current npm'
[[ "$(grep -Fc -- 'allow-scripts=' "$WORKSPACE_DOCKERFILE")" -eq 1 ]] ||
  fail 'workspace grants lifecycle-script permission beyond the Claude installer'

echo 'support-image workflow contract: OK'
