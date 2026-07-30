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
selection_job="$(sed -n '/^  support-selection:/,/^  build-base-image:/p' "$WORKFLOW")"
grep -Fq '          fetch-depth: 2' <<<"$selection_job" ||
  fail 'support selection does not receive the parent and exact main commit'
grep -Fq 'uses: dtolnay/rust-toolchain@b3b07ba8b418998c39fb20f53e8b695cdcc8de1b' \
  <<<"$selection_job" ||
  fail 'support selection does not install the pinned Rust toolchain for artifact classification'
toolchain_line="$(grep -n -m1 'uses: dtolnay/rust-toolchain@' \
  <<<"$selection_job" | cut -d: -f1)"
classifier_line="$(grep -n -m1 'name: Select atomic support build' \
  <<<"$selection_job" | cut -d: -f1)"
[[ "$toolchain_line" -lt "$classifier_line" ]] ||
  fail 'support selection installs Rust after artifact classification'
grep -Fq 'base_sha="$(git rev-parse "$GITHUB_SHA^")"' <<<"$selection_job" ||
  fail 'support selection does not resolve the exact parent SHA'
grep -Fq 'scripts/ci/select/select-support-images.sh "$base_sha" "$GITHUB_SHA"' \
  <<<"$selection_job" || fail 'support selection is not bound to the exact push range'
if grep -Fq 'secrets.' <<<"$selection_job"; then
  fail 'support selection unexpectedly receives a credential'
fi
grep -qF -- "- 'scripts/ci/select/artifact-impact.py'" "$WORKFLOW" ||
  fail 'artifact classifier changes do not activate support selection'
grep -qF -- "- 'scripts/ci/select/select-support-images.sh'" "$WORKFLOW" ||
  fail 'support wrapper changes do not activate support selection'
grep -qF -- "- 'rust-toolchain.toml'" "$WORKFLOW" ||
  fail 'Rust toolchain changes do not activate support selection'
[[ "$(grep -Fc "if: \${{ needs.support-selection.outputs.build_support_images == 'true' }}" \
  "$WORKFLOW")" -eq 3 ]] ||
  fail 'all support build/publication jobs are not gated by one selection'
grep -qF 'needs: [support-selection]' "$WORKFLOW" ||
  fail 'base build does not wait for support selection'
grep -qF 'scripts/ci/images/build-push-image.sh base images/base/Dockerfile images/base' \
  "$WORKFLOW" || fail 'base is not built by the canonical Gitea helper'
grep -qF 'needs: [support-selection, build-base-image]' "$WORKFLOW" ||
  fail 'workspace does not wait for the exact base build'
# shellcheck disable=SC2016
grep -qF 'CODEWIRE_BASE_IMAGE_REF: ${{ needs.build-base-image.outputs.candidate_ref }}' \
  "$WORKFLOW" || fail 'workspace does not consume the exact base candidate'
grep -qF 'scripts/ci/images/build-push-image.sh workspace images/workspace/Dockerfile .' \
  "$WORKFLOW" || fail 'workspace is not built by the canonical Gitea helper'
publish_job="$(sed -n '/^  publish-support-images:/,$p' "$WORKFLOW")"
grep -qF 'needs: [support-selection, build-base-image, build-workspace-image]' \
  <<<"$publish_job" || fail 'support publisher is not bound to selection and both builds'
# shellcheck disable=SC2016
grep -Fq 'GHCR_PUBLISH_USERNAME: ${{ vars.GHCR_PUBLISH_USERNAME }}' \
  <<<"$publish_job" || fail 'support publisher identity is not repository configuration'
[[ "$(grep -Fc 'scripts/ci/images/publish-image-to-ghcr.sh' <<<"$publish_job")" -eq 2 ]] ||
  fail 'support publisher does not copy exactly two image families'
[[ "$(grep -Ec '^[[:space:]]+latest$' <<<"$publish_job")" -eq 2 ]] ||
  fail 'both public support families must refresh their compatibility latest alias'
# shellcheck disable=SC2016
[[ "$(grep -Fc 'outputs.source_sha }}" == "$GITHUB_SHA"' <<<"$publish_job")" -eq 2 ]] ||
  fail 'support publisher does not verify both exact build sources'
for family in base workspace; do
  grep -Fq "ghcr.io/codewiresh/$family" <<<"$publish_job" ||
    fail "support publisher omits $family"
done
if grep -Fq 'secrets.' <<<"$publish_job"; then
  fail 'support publisher bypasses the Infisical credential handoff'
fi
grep -qF -- "- 'crates/codewire-cli-bin/**'" "$WORKFLOW" ||
  fail 'workspace binary package changes do not trigger the support build'
grep -qF -- "- 'crates/codewire-daemon/**'" "$WORKFLOW" ||
  fail 'environment daemon core changes do not trigger the support build'
grep -qF -- "- 'crates/codewire-gateway-proto/**'" "$WORKFLOW" ||
  fail 'environment daemon protocol changes do not trigger the support build'
grep -qF -- "- 'libs/gateway-proto/**'" "$WORKFLOW" ||
  fail 'environment daemon schema changes do not trigger the support build'
grep -qF -- "- 'crates/codewire-proto/**'" "$WORKFLOW" ||
  fail 'workspace Rust protobuf package changes do not trigger the support build'
grep -qF -- "- 'proto/**'" "$WORKFLOW" ||
  fail 'workspace protobuf contract changes do not trigger the support build'
grep -qF 'cargo build --locked --release -p codewire-cli-bin --bin cw' \
  "$WORKSPACE_DOCKERFILE" || fail 'workspace builds cw from the wrong Rust package'
builder_stage="$(sed -n '/^FROM rust:.* AS cw-builder$/,/^FROM /p' "$WORKSPACE_DOCKERFILE")"
grep -qF 'protobuf-compiler' <<<"$builder_stage" ||
  fail 'workspace Rust builder does not install protoc'
grep -qF 'libprotobuf-dev' <<<"$builder_stage" ||
  fail 'workspace Rust builder does not install well-known protobuf contracts'
grep -qF 'COPY proto ./proto' <<<"$builder_stage" ||
  fail 'workspace Rust builder does not receive protobuf contracts'
grep -qF 'COPY libs/gateway-proto ./libs/gateway-proto' <<<"$builder_stage" ||
  fail 'workspace Rust builder does not receive the daemon protocol schema'
grep -qF 'ln -s cw /usr/local/bin/daemon' "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace image does not expose the daemon process alias through cw'
grep -qF 'ln -s cw /usr/local/bin/codewire-daemon' "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace image does not expose the codewire-daemon process alias through cw'

if grep -Eq '(git\.example\.invalid/codewire|ghcr\.io/codewiresh)/(base|workspace):(latest|main)' \
    "$WORKFLOW"; then
  fail 'support-image publication contains a moving image tag'
fi
grep -Eq '^ARG BASE_IMAGE_REF=(git\.example\.invalid/codewire/base|ghcr\.io/codewiresh/base)@sha256:[0-9a-f]{64}$' \
  "$WORKSPACE_DOCKERFILE" || fail 'standalone workspace base is not digest-pinned'
base_arg_line="$(grep -n '^ARG BASE_IMAGE_REF=' "$WORKSPACE_DOCKERFILE" | cut -d: -f1)"
first_from_line="$(grep -n '^FROM ' "$WORKSPACE_DOCKERFILE" | head -1 | cut -d: -f1)"
[[ "$base_arg_line" -lt "$first_from_line" ]] ||
  fail 'workspace base argument must be declared before the first build stage'
# shellcheck disable=SC2016
grep -qF 'FROM ${BASE_IMAGE_REF}' "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace Dockerfile does not consume its exact base argument'
if grep -qF 'ghcr.io/codewiresh/base:latest' "$WORKSPACE_DOCKERFILE"; then
  fail 'workspace Dockerfile still consumes the moving base tag'
fi

echo 'support-image workflow contract: OK'
