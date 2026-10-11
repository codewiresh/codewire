#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly WORKFLOW="$ROOT/.gitea/workflows/support-images.yaml"
readonly LEGACY_GITHUB_WORKFLOW="$ROOT/.github/workflows/build-workspace-image.yml"
readonly WORKSPACE_DOCKERFILE="$ROOT/images/workspace/Dockerfile"
readonly WORKSPACE_AGENTS="$ROOT/images/workspace/agents"
readonly CONFIDENTIAL_PROBE_DOCKERFILE="$ROOT/images/confidential-probe/Dockerfile"

fail() {
  printf '[test-support-images-workflow] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -f "$WORKFLOW" ]] || fail 'Gitea support-image workflow is missing'
if grep -qE '^permissions:' "$WORKFLOW"; then
  fail 'support workflow relies on ignored GitHub permissions syntax'
fi
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
grep -Fq '    runs-on: ci-protected' <<<"$selection_job" ||
  fail 'support selection does not receive the pinned Skopeo capability'
if grep -Fq 'enable-openid-connect: true' <<<"$selection_job"; then
  fail 'support selection can request publisher OIDC'
fi
if grep -q '^    paths:' "$WORKFLOW"; then
  fail 'support publication still duplicates artifact impact in workflow paths'
fi
grep -Fq '          fetch-depth: 0' <<<"$selection_job" ||
  fail 'support selection does not receive canonical history for ancestry validation'
grep -Fq 'https://git.example.invalid/noel/actions-checkout@34e114876b0b11c390a56381ad16ebd13914f8d5' \
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
if grep -Fq 'GHCR_PUBLISH_USERNAME:' <<<"$selection_job"; then
  fail 'support baseline resolver receives a credential despite anonymous registry access'
fi
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
  fail 'support selection receives a credential despite anonymous registry access'
fi
for output in build_support_images build_confidential_probe_image reason matched_categories base_image_state \
  workspace_image_state confidential_probe_image_state baseline_sha head_sha head_tree ci_plan_sha256 \
  ci_policy_sha256 baseline_valid; do
  grep -Fq "      ${output}: \${{ steps.select.outputs.${output} }}" <<<"$selection_job" ||
    fail "support selection omits ${output} planner output"
done
grep -Fq "if: \${{ needs.support-selection.outputs.build_support_images == 'true' }}" \
  "$WORKFLOW" || fail 'support-pair publication is not independently selected'
grep -Fq "if: \${{ needs.support-selection.outputs.build_confidential_probe_image == 'true' }}" \
  "$WORKFLOW" || fail 'confidential-probe publication is not independently selected'
[[ "$(grep -Fc 'needs: [support-selection]' "$WORKFLOW")" -eq 2 ]] ||
  fail 'independent publisher jobs do not both wait for support selection'
grep -qF 'scripts/ci/images/build-push-image.sh base images/base/Dockerfile images/base' \
  "$WORKFLOW" || fail 'base is not built by the canonical Gitea helper'
# shellcheck disable=SC2016
grep -qF 'CODEWIRE_BASE_IMAGE_REF: ${{ steps.base.outputs.candidate_ref }}' \
  "$WORKFLOW" || fail 'workspace does not consume the same-job exact base candidate'
grep -qF 'scripts/ci/images/build-push-image.sh workspace images/workspace/Dockerfile .' \
  "$WORKFLOW" || fail 'workspace is not built by the canonical Gitea helper'
grep -qF 'scripts/ci/images/build-push-image.sh confidential-probe images/confidential-probe/Dockerfile images/confidential-probe' \
  "$WORKFLOW" || fail 'confidential probe is not built by the canonical Gitea helper'
publish_job="$(sed -n '/^  publish-support-images:/,/^  publish-confidential-probe:/p' "$WORKFLOW")"
probe_job="$(sed -n '/^  publish-confidential-probe:/,/^  propose-workspace-image-pin:/p' "$WORKFLOW")"
pin_job="$(sed -n '/^  propose-workspace-image-pin:/,$p' "$WORKFLOW")"
grep -Fq '    runs-on: ci-protected' <<<"$publish_job" ||
  fail 'support-pair publisher does not use the protected CI tier'
grep -Fq '    runs-on: ci-protected' <<<"$probe_job" ||
  fail 'confidential-probe publisher does not use the protected CI tier'
grep -Fq '    enable-openid-connect: true' <<<"$publish_job" ||
  fail 'support-pair publisher lacks job-scoped OIDC'
grep -Fq '    enable-openid-connect: true' <<<"$probe_job" ||
  fail 'confidential-probe publisher lacks job-scoped OIDC'
[[ "$(grep -Fc 'enable-openid-connect: true' "$WORKFLOW")" -eq 3 ]] ||
  fail 'support workflow exposes OIDC outside the two publisher jobs and the pin proposal'
grep -qF 'needs: [support-selection]' <<<"$publish_job" ||
  fail 'support-pair publisher is not bound to selection'
grep -qF 'needs: [support-selection]' <<<"$probe_job" ||
  fail 'confidential-probe publisher is not bound to selection'
[[ "$(grep -Fc 'OPENBAO_GHCR_ROLE: codewire-source-support-publisher' "$WORKFLOW")" -eq 2 ]] ||
  fail 'publisher jobs lack their exact OpenBao GHCR role'
grep -Fq 'OPENBAO_GHCR_AUDIENCE: openbao-codewire-source-support-publisher' \
  <<<"$publish_job" || fail 'support-pair publisher lacks its exact OpenBao GHCR audience'
grep -Fq 'OPENBAO_GHCR_AUDIENCE: openbao-codewire-source-support-publisher' \
  <<<"$probe_job" || fail 'confidential-probe publisher lacks its exact OpenBao GHCR audience'
if grep -Fq 'GHCR_PUBLISH_USERNAME:' "$WORKFLOW"; then
  fail 'support workflow retains a split Forgejo GHCR username'
fi
[[ "$(grep -Fc 'scripts/ci/images/publish-image-to-ghcr.sh' <<<"$publish_job")" -eq 1 ]] ||
  fail 'support-pair publisher does not expose exactly one publication boundary'
[[ "$(grep -Fc 'scripts/ci/images/publish-image-to-ghcr.sh' <<<"$probe_job")" -eq 1 ]] ||
  fail 'confidential-probe publisher does not expose exactly one publication boundary'
grep -Fq -- '--support-pair' <<<"$publish_job" ||
  fail 'support publisher does not require pair preflight and ordering'
# shellcheck disable=SC2016
[[ "$(grep -Fc 'steps.' <<<"$publish_job" | tr -d '[:space:]')" -gt 0 ]] ||
  fail 'support publisher does not consume same-job step outputs'
[[ "$(grep -Fc 'outputs.source_sha }}" == "$GITHUB_SHA"' <<<"$publish_job")" -eq 2 ]] ||
  fail 'support-pair publisher does not verify both exact build sources'
[[ "$(grep -Fc 'outputs.source_sha }}" == "$GITHUB_SHA"' <<<"$probe_job")" -eq 1 ]] ||
  fail 'confidential-probe publisher does not verify its exact build source'
if grep -Fq 'needs.build-' <<<"$publish_job$probe_job"; then
  fail 'publisher still crosses a runner job-output boundary'
fi
# shellcheck disable=SC2016
grep -Fq '"${{ steps.confidential_probe.outputs.candidate_ref }}"' <<<"$probe_job" ||
  fail 'confidential-probe publisher omits the immutable candidate'
grep -Fq 'ghcr.io/codewiresh/confidential-probe' <<<"$probe_job" ||
  fail 'confidential-probe publisher omits the public repository'
# shellcheck disable=SC2016
grep -Fq '"${{ steps.base.outputs.candidate_ref }}"' <<<"$publish_job" ||
  fail 'support publisher omits the immutable base candidate'
# shellcheck disable=SC2016
grep -Fq '"${{ steps.workspace.outputs.candidate_ref }}"' <<<"$publish_job" ||
  fail 'support publisher omits the immutable workspace candidate'
if grep -Fq 'secrets.' <<<"$publish_job$probe_job"; then
  fail 'publisher bypasses the OpenBao OIDC credential handoff'
fi
grep -qF -- '-p codewire-cli-bin --bin cw' "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace builds cw from the wrong Rust package'
# amd64 consumes the verified static cw; only the arm64 stage compiles source.
builder_stage="$(sed -n '/^FROM cw-toolchain AS cw-builder-arm64$/,/^FROM /p' "$WORKSPACE_DOCKERFILE")"
[[ -n "$builder_stage" ]] || fail 'workspace source builder stage is missing'
toolchain_stage="$(sed -n '/^FROM rust:.* AS cw-toolchain$/,/^FROM /p' "$WORKSPACE_DOCKERFILE")"
# The pinned upstream archive supplies both protoc and its well-known includes.
# Distribution protobuf packages are too old for the canonical descriptors.
protoc_inputs=(
  'ADD --checksum=sha256:6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7'
  'https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip'
  'unzip -q /tmp/protoc.zip -d /opt/protoc'
  'ENV PROTOC=/opt/protoc/bin/protoc'
  'test "$(/opt/protoc/bin/protoc --version)" = '\''libprotoc 35.1'\'''
)
workspace_protoc_contract() {
  local stage="$1" input
  for input in "${protoc_inputs[@]}"; do
    grep -qF -- "$input" <<<"$stage" || return 1
  done
}
workspace_protoc_contract "$toolchain_stage" ||
  fail 'workspace Rust builder lacks the exact checked protoc archive and includes'
for protoc_input in "${protoc_inputs[@]}"; do
  incomplete_stage="$(grep -vF -- "$protoc_input" <<<"$toolchain_stage")"
  if workspace_protoc_contract "$incomplete_stage"; then
    fail 'workspace protoc guard accepted a missing pinned input'
  fi
done
grep -qF -- '--mount=type=bind,target=/src,readonly' <<<"$builder_stage" ||
  fail 'workspace Rust builder does not consume the source tree read-only'
grep -qF -- '--manifest-path /src/Cargo.toml' <<<"$builder_stage" ||
  fail 'workspace Rust builder does not build the canonical workspace manifest'
if grep -Eq '^COPY (Cargo|crates|proto|libs)' <<<"$builder_stage"; then
  fail 'workspace Rust builder still copies repository source into image layers'
fi
grep -qF 'rm -rf /tmp/cargo-target' <<<"$builder_stage" ||
  fail 'workspace compiler exports disposable target artifacts to the layer cache'
[[ "$(grep -c '^RUN ' <<<"$builder_stage")" == 1 ]] ||
  fail 'workspace target cleanup must share the compile layer'
floating_stage="$(sed -n '/^FROM workspace-foundation AS workspace-floating-tools$/,/^FROM /p' "$WORKSPACE_DOCKERFILE")"
for tool in 'NPM_CONFIG_PREFIX=/usr/local npm install' 'npm@12.2.0 pnpm@12.9.0 yarn@1.22.22' \
  'https://bun.sh/install' 'gopls@latest' 'hcloud@latest' 'pipx install poetry' 'pipx install uv' 'pipx install aider-chat'; do
  grep -qF "$tool" <<<"$floating_stage" || fail "floating tool omitted from the fresh stage: $tool"
done
[[ "$(grep -E '^COPY --from=cw-builder ' "$WORKSPACE_DOCKERFILE")" == \
  'COPY --from=cw-builder --chown=0:0 --chmod=0555 /out/cw /usr/local/bin/cw
COPY --from=cw-builder --chown=0:0 /out/provenance/ /usr/local/share/codewire/cw-runtime/' ]] ||
  fail 'workspace final stage receives more than the exported cw binary and its provenance'
if grep -Eq '/usr/local/bin/(daemon|codewire-daemon)' "$WORKSPACE_DOCKERFILE"; then
  fail 'workspace image still exposes a public daemon process alias'
fi
cw_copy_line="$(grep -n -m1 '^COPY --from=cw-builder .* /out/cw /usr/local/bin/cw$' \
  "$WORKSPACE_DOCKERFILE" | cut -d: -f1)"
[[ -n "$cw_copy_line" ]] || fail 'workspace final stage lacks the cw handoff'
for moving_tool_pattern in \
  'go install golang.org/x/tools/gopls@latest' \
  'pipx install aider-chat' \
  'npm install -g --ignore-scripts' \
  'COPY --from=cw-toolchain --chown=codewire:codewire /usr/local/rustup/ /home/codewire/.rustup/'; do
  moving_tool_line="$(grep -n -m1 -F "$moving_tool_pattern" \
    "$WORKSPACE_DOCKERFILE" | cut -d: -f1)"
  [[ -n "$moving_tool_line" && "$moving_tool_line" -lt "$cw_copy_line" ]] ||
    fail "moving tool layer '$moving_tool_pattern' must precede the source-built cw handoff"
done
if grep -qF 'https://sh.rustup.rs' "$WORKSPACE_DOCKERFILE"; then
  fail 'workspace image restores the mutable Rustup network installer'
fi
[[ "$(tail -n 1 "$WORKSPACE_DOCKERFILE")" == 'USER codewire' ]] ||
  fail 'workspace image does not restore the unprivileged runtime user after installing cw'

grep -qF 'FROM registry.example.invalid/oci-approved/e2e-test-images/busybox@sha256:caec39cad3b12c26600baf6e67ba811ac15d28a9288d0ccdfffb4b318992c3bb' \
  "$CONFIDENTIAL_PROBE_DOCKERFILE" || fail 'confidential probe does not use the approved exact Harbor base'
[[ "$(grep -c '^FROM ' "$CONFIDENTIAL_PROBE_DOCKERFILE")" -eq 1 ]] ||
  fail 'confidential probe must have exactly one approved base'
if grep -qF 'registry.k8s.io/' "$CONFIDENTIAL_PROBE_DOCKERFILE"; then
  fail 'confidential probe bypasses the approved Harbor base'
fi
grep -Eq '^ADD --checksum=sha256:[0-9a-f]{64} \\' \
  "$CONFIDENTIAL_PROBE_DOCKERFILE" || fail 'confidential probe snpguest input is not checksum-pinned'
grep -Fq 'https://github.com/virtee/snpguest/releases/download/v0.10.0/snpguest' \
  "$CONFIDENTIAL_PROBE_DOCKERFILE" || fail 'confidential probe does not use the accepted snpguest release'
[[ "$(tail -n 1 "$CONFIDENTIAL_PROBE_DOCKERFILE")" == 'USER 65532:65532' ]] ||
  fail 'confidential probe does not restore its unprivileged runtime user'

if grep -Eq '(registry\.example\.invalid/codewire|ghcr\.io/codewiresh)/(base|workspace):(latest|main)' \
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
grep -Eq '^FROM rust:1\.93\.0-slim-bookworm@sha256:[0-9a-f]{64} AS cw-toolchain$' \
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
# The shipped agents come from one exact lockfile: every package from the
# registry with its integrity, and only Claude's reviewed installer allowed.
python3 - "$WORKSPACE_AGENTS/package.json" "$WORKSPACE_AGENTS/package-lock.json" <<'PY' ||
import json
import re
import sys

package = json.load(open(sys.argv[1]))
lock = json.load(open(sys.argv[2]))
agents = {
    "@anthropic-ai/claude-code": "2.1.288",
    "@earendil-works/pi-coding-agent": "1.0.0",
    "@google/gemini-cli": "0.62.0",
    "@moonshot-ai/kimi-code": "2.1.1",
    "@openai/codex": "0.160.0",
}
assert package["dependencies"] == agents
assert lock["lockfileVersion"] == 3
assert lock["packages"][""]["dependencies"] == agents
for path, entry in lock["packages"].items():
    if path:
        assert not entry.get("link"), path
        assert re.fullmatch(r"https://registry\.npmjs\.org/\S+\.tgz", entry["resolved"]), path
        assert entry["integrity"].startswith("sha512-"), path
for name, version in agents.items():
    assert lock["packages"]["node_modules/" + name]["version"] == version, name
allowed = [spec for spec, allow in package["allowScripts"].items() if allow is not False]
assert allowed == ["@anthropic-ai/claude-code@2.1.288"], allowed
PY
  fail 'workspace agents are not one exact, registry-pinned lockfile'
grep -qF 'npm ci --strict-allow-scripts --no-audit --no-fund' "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace does not install the agent lockfile under its strict script policy'
grep -qF 'env -u NPM_CONFIG_ALLOW_SCRIPTS -u NPM_CONFIG_PREFIX' "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace agent install inherits the user-facing global npm configuration'
if grep -Eq 'npm install .*(@openai/codex|@anthropic-ai/claude-code|@google/gemini-cli|@moonshot-ai/kimi-code|@earendil-works/pi-coding-agent)' \
    "$WORKSPACE_DOCKERFILE"; then
  fail 'workspace installs an agent outside its lockfile'
fi
grep -qF 'npm@12.2.0 pnpm@12.9.0 yarn@1.22.22' "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace does not pin the Node archive npm together with its package managers'
grep -qF 'npm cache clean --force' "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace retains the root package-manager installer cache'
grep -qFx -- 'ENV NPM_CONFIG_ALLOW_SCRIPTS="@anthropic-ai/claude-code"' \
  "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace does not persist the narrow Claude update policy under current npm'
[[ "$(grep -Ec -- 'allow-scripts=|NPM_CONFIG_ALLOW_SCRIPTS=' "$WORKSPACE_DOCKERFILE")" -eq 1 ]] ||
  fail 'workspace grants lifecycle-script permission beyond the Claude installer'

# Harbor is the required publication; the GHCR mirror never gates delivery.
for job_name in publish_job probe_job; do
  job="${!job_name}"
  [[ "$(grep -Fc 'scripts/ci/images/publish-image-to-harbor.sh' <<<"$job")" -eq 1 ]] ||
    fail "$job_name does not publish exactly once to Harbor"
  harbor_line="$(grep -n 'scripts/ci/images/publish-image-to-harbor.sh' <<<"$job" | cut -d: -f1)"
  ghcr_line="$(grep -n 'scripts/ci/images/publish-image-to-ghcr.sh' <<<"$job" | cut -d: -f1)"
  [[ -n "$harbor_line" && -n "$ghcr_line" && "$harbor_line" -lt "$ghcr_line" ]] ||
    fail "$job_name does not publish to Harbor before the GHCR mirror"
  mirror_step="$(awk '/^      - name: / { capture = ($0 ~ /GHCR/) } capture' <<<"$job")"
  grep -Fq 'scripts/ci/images/publish-image-to-ghcr.sh' <<<"$mirror_step" ||
    fail "$job_name GHCR copy is outside its named mirror step"
  grep -qx '        continue-on-error: true' <<<"$mirror_step" ||
    fail "$job_name GHCR mirror can fail support delivery"
  if awk '/^      - name: / { capture = ($0 !~ /GHCR/) } capture' <<<"$job" | grep -q continue-on-error; then
    fail "$job_name lets a required Harbor step continue on error"
  fi
done
grep -Fq 'registry.example.invalid/codewire/confidential-probe' <<<"$probe_job" ||
  fail 'confidential probe is not published to its Harbor repository'

# The published workspace image is proposed as the new pin by the
# workspace-pin bot: after a successful public mirror, on one automation
# branch, with only the bot token read just in time from its exact OpenBao role.
# shellcheck disable=SC2016
grep -Fq 'workspace_ref: ${{ steps.workspace.outputs.candidate_ref }}' <<<"$publish_job" ||
  fail 'support publisher does not expose the published workspace digest'
# shellcheck disable=SC2016
grep -Fq "workspace_mirrored: \${{ steps.mirror.outcome == 'success' }}" <<<"$publish_job" ||
  fail 'support publisher does not expose the public mirror outcome'
grep -Fq '        id: mirror' <<<"$publish_job" || fail 'the GHCR mirror step has no outcome id'

# pin_job_violation JOB prints the first broken pin-proposal rule, if any.
# shellcheck disable=SC2016
pin_job_violation() {
  local job="$1"
  [[ -n "$job" ]] || { echo 'the published workspace image is never proposed as the pin'; return; }
  grep -Fq '    needs: [publish-support-images]' <<<"$job" ||
    { echo 'the pin proposal does not wait for the support publication'; return; }
  grep -Fq "if: \${{ needs.publish-support-images.outputs.workspace_mirrored == 'true' }}" <<<"$job" ||
    { echo 'the pin proposal can name an image the public mirror lacks'; return; }
  grep -Fq '    runs-on: ci-protected' <<<"$job" ||
    { echo 'the pin proposal leaves the protected tier'; return; }
  grep -Fq '    enable-openid-connect: true' <<<"$job" ||
    { echo 'the pin proposal lacks job-scoped OIDC for the bot token'; return; }
  grep -Fq '          persist-credentials: false' <<<"$job" ||
    { echo 'the pin checkout keeps the job token, which git would send beside the bot token'; return; }
  if grep -Eq 'github\.token|GITEA_TOKEN|GITHUB_TOKEN|OPENBAO_|secrets\.' <<<"$job"; then
    echo 'the pin proposal holds a capability beyond the workspace-pin bot token'
    return
  fi
  if [[ "$(grep -c 'fetch-openbao-' <<<"$job")" -ne 1 ]] ||
      ! grep -Fq 'scripts/ci/setup/fetch-openbao-workspace-pin-bot-token.sh "$bot_work/token"' <<<"$job"; then
    echo 'the pin proposal does not read exactly the workspace-pin bot token'
    return
  fi
  grep -Fq "trap 'find \"\$bot_work\" -type f -exec shred -u {} +; rm -rf \"\$bot_work\"' EXIT" <<<"$job" ||
    { echo 'the workspace-pin bot token outlives its step'; return; }
  if ! grep -Fq 'WORKSPACE_PIN_BOT_TOKEN_FILE="$bot_work/token"' <<<"$job" ||
      ! grep -Fq 'scripts/ci/images/propose-workspace-image-pin.sh "$WORKSPACE_REF"' <<<"$job"; then
    echo 'the pin proposal does not run the reviewed proposer with the bot token file'
    return
  fi
  grep -Fq 'WORKSPACE_REF: ${{ needs.publish-support-images.outputs.workspace_ref }}' <<<"$job" ||
    { echo 'the pin proposal does not use the published digest'; return; }
}
violation="$(pin_job_violation "$pin_job")"
[[ -z "$violation" ]] || fail "$violation"

# Each rule refuses its own regression of the reviewed job.
# shellcheck disable=SC2016
pin_mutations=(
  'drop OIDC::/enable-openid-connect: true/d'
  'keep checkout credentials::/persist-credentials: false/d'
  'job token beside the bot::/WORKSPACE_REF:/i\          GITEA_TOKEN: ${{ github.token }}'
  'job token instead of the bot::s|WORKSPACE_PIN_BOT_TOKEN_FILE="$bot_work/token"|GITEA_TOKEN="${{ github.token }}"|'
  'publisher OpenBao role::/WORKSPACE_REF:/i\          OPENBAO_ROLE: codewire-source-support-publisher'
  'Actions secret::/WORKSPACE_REF:/i\          TOKEN: ${{ secrets.WORKSPACE_PIN_TOKEN }}'
  'another document::s|fetch-openbao-workspace-pin-bot-token.sh|fetch-openbao-ghcr-credentials.sh|'
  'a second document::/fetch-openbao-workspace-pin-bot-token.sh/a\          scripts/ci/setup/fetch-openbao-harbor-credentials.sh "$bot_work/harbor"'
  'token outlives the step::/trap /d'
  'unprotected tier::s|runs-on: ci-protected|runs-on: ci|'
  'no mirror gate::/workspace_mirrored == .true./d'
  'no publication wait::/needs: \[publish-support-images\]/d'
)
for mutation in "${pin_mutations[@]}"; do
  label="${mutation%%::*}"
  mutated="$(sed -e "${mutation#*::}" <<<"$pin_job")"
  [[ "$mutated" != "$pin_job" ]] || fail "pin job mutation did not apply: $label"
  [[ -n "$(pin_job_violation "$mutated")" ]] || fail "pin job mutation was accepted: $label"
done

echo 'support-image workflow contract: OK'
