#!/usr/bin/env bash
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR ARM64_BUILDKIT_HOST  # the tests exercise the script defaults

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly WORKFLOW="$ROOT/.gitea/workflows/support-images.yaml"
readonly LEGACY_GITHUB_WORKFLOW="$ROOT/.github/workflows/build-workspace-image.yml"
readonly WORKSPACE_DOCKERFILE="$ROOT/images/workspace/Dockerfile"
readonly WORKSPACE_AGENTS="$ROOT/images/workspace/agents"
readonly CONFIDENTIAL_PROBE_DOCKERFILE="$ROOT/images/confidential-probe/Dockerfile"
readonly PLATFORM_BUILDER="$ROOT/scripts/ci/images/build-support-platform.sh"

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
# Publication is for main commits only: a push publishes for its own commit,
# and a dispatch of main for its head or for an earlier first-parent main
# commit it names (dispatch-source.sh --main-history refuses anything else).
python3 - "$WORKFLOW" <<'PY' || fail 'support-image publication accepts events or inputs beyond main pushes and the source_sha dispatch'
import sys

import yaml

on = yaml.safe_load(open(sys.argv[1]))[True]
assert set(on) == {"push", "workflow_dispatch"}, on
assert on["push"] == {"branches": ["main"]}, on["push"]
inputs = on["workflow_dispatch"]["inputs"]
assert list(inputs) == ["source_sha"], inputs
assert inputs["source_sha"]["required"] is False and inputs["source_sha"]["default"] == "", inputs
PY
# A running support build finishes when main moves on, and a newer push's run
# waits behind it in one group rather than building beside it (owner,
# 2026-10-21). A waiting commit that main has moved past builds nothing.
concurrency_block="$(sed -n '/^concurrency:$/,/^$/p' "$WORKFLOW")"
# shellcheck disable=SC2016 # Match the literal workflow expression.
[[ "$concurrency_block" == $'concurrency:\n  group: support-images-${{ github.ref }}\n  cancel-in-progress: false' ]] ||
  fail 'a newer main push cancels a running support build, or support runs build in parallel'
if grep -Fq 'CODEWIRE_GHCR_PUBLISH_ENABLED' "$WORKFLOW"; then
  fail 'support GHCR publication retains its rollout flag'
fi
selection_job="$(sed -n '/^  support-selection:/,/^  build-support-amd64:/p' "$WORKFLOW")"
if grep -Fq 'enable-openid-connect: true' <<<"$selection_job"; then
  fail 'support selection can request publisher OIDC'
fi
if grep -q '^    paths:' "$WORKFLOW"; then
  fail 'support publication still duplicates artifact impact in workflow paths'
fi
grep -Fq '          fetch-depth: 0' <<<"$selection_job" ||
  fail 'support selection does not receive canonical history for ancestry validation'
grep -Fq 'scripts/ci/images/resolve-published-support-pair.sh "$candidate"' \
  <<<"$selection_job" || fail 'support selection does not resolve published pair metadata'
if grep -Fq 'GHCR_PUBLISH_USERNAME:' <<<"$selection_job"; then
  fail 'support baseline resolver receives a credential despite anonymous registry access'
fi
grep -Fq -- '--baseline-candidate "$RUNNER_TEMP/codewire-published-support-candidate.json"' \
  <<<"$selection_job" || fail 'planner does not consume the untrusted registry candidate'
grep -Fq -- '--target-base "$SOURCE_SHA"' <<<"$selection_job" ||
  fail 'support planner target is not the exact chosen source'
grep -Fq -- '--trusted-policy "$SOURCE_SHA"' <<<"$selection_job" ||
  fail 'support planner policy is not the exact chosen source'
grep -Fq -- '--head "$SOURCE_SHA"' <<<"$selection_job" ||
  fail 'support adapter head is not the exact chosen source'
if grep -Fq '"$GITHUB_SHA' <<<"$(sed -n '/name: Plan atomic support build/,/name: Remove untrusted registry candidate/p' <<<"$selection_job")"; then
  fail 'support planning still names the dispatched head instead of the chosen source'
fi
# The chosen source comes only from dispatch-source.sh, before anything reads
# the registry: main's first-parent history, and a run of main.
source_step=$'      - name: Choose the commit this run publishes for\n        id: source\n        env:\n          DISPATCH_SOURCE_SHA: ${{ github.event.inputs.source_sha }}\n        run: scripts/ci/select/dispatch-source.sh --main-history'
grep -Fq "$source_step" <<<"$selection_job" ||
  fail 'support selection does not choose its source with dispatch-source.sh --main-history'
[[ "$(grep -Fc 'SOURCE_SHA: ${{ steps.source.outputs.source_sha }}' <<<"$selection_job")" -eq 2 ]] ||
  fail 'support resolution and planning do not both read the chosen source'
grep -Fq '      source_sha: ${{ steps.source.outputs.source_sha }}' <<<"$selection_job" ||
  fail 'support selection does not expose the chosen source'
grep -Fq 'scripts/ci/images/resolve-published-support-pair.sh "$candidate" "$SOURCE_SHA"' <<<"$selection_job" ||
  fail 'a dispatch does not plan against its source'"'"'s newest published ancestor pair'
# An earlier commit that needs a build builds its pair from its own checkout
# with main's scripts, as deploy-prod.yaml builds a release's pair (owner,
# 2026-11-12, #4243). Only the confidential probe and the pin proposal stay
# with main's own commit.
if grep -Fq 'name: Refuse a build' <<<"$selection_job"; then
  fail 'a dispatch for an earlier commit that needs a build is still refused'
fi
[[ "$(grep -Fc "needs.support-selection.outputs.source_sha == github.sha }}" "$WORKFLOW")" -eq 2 ]] ||
  fail 'the probe or the pin proposal can run for an earlier commit'
source_checkout=$'      - uses: noel/actions-checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: ${{ needs.support-selection.outputs.source_sha }}\n          path: .support-source'
gated_source_checkout=$'      - uses: noel/actions-checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        if: ${{ steps.canonical.outputs.superseded == \'false\' }}\n        with:\n          ref: ${{ needs.support-selection.outputs.source_sha }}\n          path: .support-source'
for source_job in build-support-amd64 build-support-arm64 publish-support-images; do
  source_job_text="$(sed -n "/^  $source_job:/,/^  [a-z][a-z0-9-]*:\$/p" "$WORKFLOW" | sed '$d')"
  grep -qxF '      CODEWIRE_SOURCE_SHA: ${{ needs.support-selection.outputs.source_sha }}' <<<"$source_job_text" &&
    grep -qxF '      CODEWIRE_SOURCE_DIR: .support-source' <<<"$source_job_text" ||
    fail "$source_job does not build for the selected source"
  [[ "$source_job_text" == *"$source_checkout"* || "$source_job_text" == *"$gated_source_checkout"* ]] ||
    fail "$source_job does not check out the selected source"
  if grep -Fq 'github.sha' <<<"$(grep '^    if: ' <<<"$source_job_text")"; then
    fail "$source_job runs only for main's own commit"
  fi
done
grep -Fq 'scripts/ci/plan/apply-support-plan.py' <<<"$selection_job" ||
  fail 'support event adapter does not consume planner facts'
grep -Fq 'rm -f -- "$RUNNER_TEMP/codewire-published-support-candidate.json"' \
  <<<"$selection_job" || fail 'support selection cleanup does not use the fixed runner-temp path'
if grep -Fq '"$GITHUB_SHA^"' <<<"$selection_job" \
  || grep -Eq 'select-support-images\.sh' <<<"$selection_job"; then
  fail 'support selection retains HEAD-parent or legacy path classification'
fi
if grep -Fq 'secrets.' <<<"$selection_job"; then
  fail 'support selection receives a credential despite anonymous registry access'
fi
grep -qF 'scripts/ci/images/build-push-image.sh base .support-source/images/base/Dockerfile .support-source/images/base' \
  "$WORKFLOW" || fail 'base is not built by the canonical Gitea helper'
# shellcheck disable=SC2016
grep -qF '"CODEWIRE_BASE_IMAGE_REF=$REGISTRY_HOST/codewire/base@$base_digest"' \
  "$PLATFORM_BUILDER" || fail 'a platform workspace does not consume that platform'"'"'s exact base'
grep -qF 'scripts/ci/images/build-push-image.sh workspace .support-source/images/workspace/Dockerfile .support-source' \
  "$WORKFLOW" || fail 'workspace is not built by the canonical Gitea helper'
grep -qF 'scripts/ci/images/build-push-image.sh confidential-probe images/confidential-probe/Dockerfile images/confidential-probe' \
  "$WORKFLOW" || fail 'confidential probe is not built by the canonical Gitea helper'
publish_job="$(sed -n '/^  publish-support-images:/,/^  publish-confidential-probe:/p' "$WORKFLOW")"
probe_job="$(sed -n '/^  publish-confidential-probe:/,/^  propose-workspace-image-pin:/p' "$WORKFLOW")"
pin_job="$(sed -n '/^  propose-workspace-image-pin:/,/^  alias-support-pair:/p' "$WORKFLOW")"
alias_job="$(sed -n '/^  alias-support-pair:/,$p' "$WORKFLOW")"
# The probe builds on the trusted BuildKit builder, never on a BuildKit image
# this job pulls itself, except under the owner's exact-commit recovery.
grep -qxF "      CODEWIRE_TRUSTED_BUILDKIT: '1'" <<<"$probe_job" ||
  fail 'confidential-probe does not build on the trusted BuildKit builder'
grep -qxF "      CODEWIRE_IN_JOB_BUILD: \${{ vars.CODEWIRE_IN_JOB_BUILD_SHA == github.sha && '1' || '0' }}" <<<"$probe_job" ||
  fail "confidential-probe lacks the owner's exact-commit recovery switch"
if grep -Fq 'GHCR_PUBLISH_USERNAME:' "$WORKFLOW"; then
  fail 'support workflow retains a split Forgejo GHCR username'
fi
grep -Fq -- '--support-pair' <<<"$publish_job" ||
  fail 'support publisher does not require pair preflight and ordering'
# Only main's own commit moves latest; an earlier commit's pair gets its own
# tag alone (#4243).
# shellcheck disable=SC2016
[[ "$(grep -Fxc "          PAIR_MODE: \${{ needs.support-selection.outputs.source_sha == github.sha && '--support-pair' || '--earlier-support-pair' }}" <<<"$publish_job")" -eq 2 \
  && "$(grep -Fxc '            "$PAIR_MODE" \' <<<"$publish_job")" -eq 2 ]] ||
  fail 'the support publisher can move latest to an earlier commit'"'"'s pair'
# shellcheck disable=SC2016
[[ "$(grep -Fc 'steps.' <<<"$publish_job" | tr -d '[:space:]')" -gt 0 ]] ||
  fail 'support publisher does not consume same-job step outputs'
[[ "$(grep -Fc 'outputs.source_sha }}" == "$CODEWIRE_SOURCE_SHA"' <<<"$publish_job")" -eq 2 ]] ||
  fail 'support-pair publisher does not verify both exact build sources'
[[ "$(grep -Fc 'outputs.source_sha }}" == "$GITHUB_SHA"' <<<"$probe_job")" -eq 1 ]] ||
  fail 'confidential-probe publisher does not verify its exact build source'
# Publication consumes only same-job candidates. The platform digests cross
# the job boundary only into the two joins, which verify the whole index
# (both platforms, their provenance and SBOMs) before reporting a candidate.
# The job's own condition reads only whether each platform skipped (pinned
# exactly below).
[[ "$(grep -v '^    if: ' <<<"$publish_job" | grep -Fc 'needs.build-')" -eq 2 \
  && "$(grep -Fc '          CODEWIRE_IMAGE_JOIN: ${{ needs.build-support-amd64.outputs.base_digest }} ${{ needs.build-support-arm64.outputs.base_digest }}' <<<"$publish_job")" -eq 1 \
  && "$(grep -Fc '          CODEWIRE_IMAGE_JOIN: ${{ needs.build-support-amd64.outputs.workspace_digest }} ${{ needs.build-support-arm64.outputs.workspace_digest }}' <<<"$publish_job")" -eq 1 ]] ||
  fail 'publisher consumes another job'"'"'s output outside the verifying joins'
if grep -Fq 'needs.build-' <<<"$probe_job"; then
  fail 'probe publisher crosses a runner job-output boundary'
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
# amd64 consumes the verified static cw. arm64 cross-compiles the same static
# musl target on the build platform: no Rust compiler runs under emulation.
builder_stage="$(sed -n '/^FROM cw-cross-compiler AS cw-builder-arm64$/,/^FROM /p' "$WORKSPACE_DOCKERFILE")"
[[ -n "$builder_stage" ]] || fail 'workspace arm64 cross-compiling builder stage is missing'
toolchain_stage="$(sed -n '/^FROM rust:.* AS cw-toolchain$/,/^FROM /p' "$WORKSPACE_DOCKERFILE")"
tool_stages="$(sed -n '/^FROM scratch AS sccache-amd64$/,/^FROM --platform=/p' "$WORKSPACE_DOCKERFILE")"
compiler_stage="$(sed -n '/^FROM --platform=.* AS cw-cross-compiler$/,/^FROM /p' "$WORKSPACE_DOCKERFILE")"
# Each compiler tool is checksum-pinned for both build architectures and
# selected by the build platform. The pinned protoc archive also supplies the
# well-known includes; distribution packages are too old for the descriptors.
# shellcheck disable=SC2016 # Match literal Dockerfile platform selectors.
tool_stage_inputs=(
  'FROM scratch AS sccache-amd64'
  'ADD --checksum=sha256:67c4a96dd237c1f518f6b36083f270f9976d516f1e57fce891755ea782e50006'
  'sccache-v0.17.0-x86_64-unknown-linux-musl.tar.gz /sccache.tar.gz'
  'FROM scratch AS sccache-arm64'
  'ADD --checksum=sha256:821a86343191aa1cbab74bd42f9e93c9a63bf85e4742945f40d3ae84193c1c77'
  'sccache-v0.17.0-aarch64-unknown-linux-musl.tar.gz /sccache.tar.gz'
  'FROM scratch AS protoc-amd64'
  'ADD --checksum=sha256:6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7'
  'https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip /protoc.zip'
  'FROM scratch AS protoc-arm64'
  'ADD --checksum=sha256:01bf9d08808c7f96678b63f4bd8efa559bb4f83d5a7a270d5edaf507f9d5d9cf'
  'https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-aarch_64.zip /protoc.zip'
  'FROM scratch AS zig-amd64'
  'ADD --checksum=sha256:02aa270f183da276e5b5920b1dac44a63f1a49e55050ebde3aecc9eb82f93239'
  'https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz /zig.tar.xz'
  'FROM scratch AS zig-arm64'
  'ADD --checksum=sha256:958ed7d1e00d0ea76590d27666efbf7a932281b3d7ba0c6b01b0ff26498f667f'
  'https://ziglang.org/download/0.15.2/zig-aarch64-linux-0.15.2.tar.xz /zig.tar.xz'
  'FROM sccache-${BUILDARCH} AS build-sccache'
  'FROM protoc-${BUILDARCH} AS build-protoc'
  'FROM zig-${BUILDARCH} AS build-zig'
)
# shellcheck disable=SC2016 # Match literal Dockerfile commands.
compiler_inputs=(
  'FROM --platform=$BUILDPLATFORM rust:1.99.1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS cw-cross-compiler'
  'COPY --from=build-protoc /protoc.zip /tmp/protoc.zip'
  'COPY --from=build-sccache /sccache.tar.gz /tmp/sccache.tar.gz'
  'COPY --from=build-zig /zig.tar.xz /tmp/zig.tar.xz'
  'unzip -q /tmp/protoc.zip -d /opt/protoc'
  'test "$(/opt/protoc/bin/protoc --version)" = '\''libprotoc 35.1'\'''
  'test "$(sccache --version)" = '\''sccache 0.17.0'\'''
  'test "$(/opt/zig/zig version)" = '\''0.15.2'\'''
  'ENV PROTOC=/opt/protoc/bin/protoc'
  'rustup target add --toolchain 1.99.1 aarch64-unknown-linux-musl'
  'cargo install --locked cargo-zigbuild --version 0.23.0'
  'test "$(cargo-zigbuild --version)" = '\''cargo-zigbuild 0.23.0'\'''
  'COPY --chmod=0755 scripts/ci/images/run-rust-build.sh /usr/local/bin/codewire-rust-build'
)
# shellcheck disable=SC2016 # Match literal Dockerfile commands.
builder_inputs=(
  'codewire-rust-build cargo zigbuild --manifest-path /src/Cargo.toml --locked --profile "$CODEWIRE_RUST_PROFILE"'
  '--target aarch64-unknown-linux-musl -p codewire-cli-bin --bin cw'
  'install -D -m 0755 "/tmp/cargo-target/aarch64-unknown-linux-musl/$CODEWIRE_RUST_PROFILE/cw" /out/cw'
)
workspace_cross_contract() {
  local tools="$1" compiler="$2" builder="$3" toolchain="$4" recipe="$5" input
  for input in "${tool_stage_inputs[@]}"; do grep -qF -- "$input" <<<"$tools" || return 1; done
  for input in "${compiler_inputs[@]}"; do grep -qF -- "$input" <<<"$compiler" || return 1; done
  for input in "${builder_inputs[@]}"; do grep -qF -- "$input" <<<"$builder" || return 1; done
  # The image-platform toolchain only adds the shipped developer components.
  [[ "$(grep -c '^RUN ' <<<"$toolchain")" == 1 ]] || return 1
  grep -qxF 'RUN rustup component add --toolchain 1.99.1 rustfmt clippy' <<<"$toolchain" || return 1
  ! grep -Eq '^(ADD|COPY) ' <<<"$toolchain" || return 1
  # Compiler tools follow the build platform, and only cross builds run Cargo.
  ! grep -Eq '^FROM (sccache|protoc|zig)-\$\{TARGETARCH\}' <<<"$recipe" || return 1
  ! grep -Eq 'cargo build' <<<"$recipe" || return 1
  [[ "$(grep -c 'cargo zigbuild' <<<"$recipe")" == 1 && "$(grep -c 'cargo install' <<<"$recipe")" == 1 ]]
}
workspace_recipe="$(<"$WORKSPACE_DOCKERFILE")"
workspace_cross_contract "$tool_stages" "$compiler_stage" "$builder_stage" "$toolchain_stage" "$workspace_recipe" ||
  fail 'workspace arm64 cw is not cross-compiled with the exact pinned build-platform tools'
for input in "${tool_stage_inputs[@]}"; do
  if workspace_cross_contract "$(grep -vF -- "$input" <<<"$tool_stages")" \
      "$compiler_stage" "$builder_stage" "$toolchain_stage" "$workspace_recipe"; then
    fail 'workspace cross-compile guard accepted a missing pinned tool input'
  fi
done
for input in "${compiler_inputs[@]}"; do
  if workspace_cross_contract "$tool_stages" "$(grep -vF -- "$input" <<<"$compiler_stage")" \
      "$builder_stage" "$toolchain_stage" "$workspace_recipe"; then
    fail 'workspace cross-compile guard accepted a missing compiler input'
  fi
done
for input in "${builder_inputs[@]}"; do
  if workspace_cross_contract "$tool_stages" "$compiler_stage" \
      "$(grep -vF -- "$input" <<<"$builder_stage")" "$toolchain_stage" "$workspace_recipe"; then
    fail 'workspace cross-compile guard accepted a missing builder input'
  fi
done
# The historical recipe compiled cw in the image-platform toolchain, with an
# x86-64 protoc, under emulation for arm64.
historical_toolchain="$(printf '%s\n%s\n' "$toolchain_stage" \
  'COPY --from=protoc-archive /protoc.zip /tmp/protoc.zip')"
historical_recipe="$(printf '%s\n%s\n' "$workspace_recipe" \
  'RUN codewire-rust-build cargo build --manifest-path /src/Cargo.toml -p codewire-cli-bin --bin cw')"
# shellcheck disable=SC2016 # Match literal Dockerfile platform selectors.
target_selected_recipe="${workspace_recipe//FROM protoc-\$\{BUILDARCH\}/FROM protoc-\$\{TARGETARCH\}}"
if workspace_cross_contract "$tool_stages" "$compiler_stage" "$builder_stage" "$historical_toolchain" "$workspace_recipe" \
    || workspace_cross_contract "$tool_stages" "$compiler_stage" "$builder_stage" "$toolchain_stage" "$historical_recipe" \
    || workspace_cross_contract "$tool_stages" "$compiler_stage" "$builder_stage" "$toolchain_stage" "$target_selected_recipe"; then
  fail 'workspace cross-compile guard accepted an emulated or image-platform compiler'
fi
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
# The shipped agents install in a fresh stage of their own, as codewire, and
# reach the image once, owned by root (owner, 2026-11-12, #3013).
agents_stage="$(sed -n '/^FROM workspace-floating-tools AS workspace-agents$/,/^FROM /p' "$WORKSPACE_DOCKERFILE")"
grep -qF 'PIPX_HOME=/opt/codewire/agents/pipx PIPX_BIN_DIR=/opt/codewire/agents/bin pipx install aider-chat' \
  <<<"$agents_stage" || fail 'aider is not installed in the fresh agents stage'
grep -qxF 'COPY --from=workspace-agents --chown=0:0 /opt/codewire/agents/ /opt/codewire/agents/' "$WORKSPACE_DOCKERFILE" ||
  fail 'the shipped agents do not reach the workspace once, owned by root'
if grep -qF 'chown -R -h root:root /opt/codewire/agents' "$WORKSPACE_DOCKERFILE"; then
  fail 'a recursive chown copies every agent file into a second layer'
fi
for tool in 'NPM_CONFIG_PREFIX=/usr/local npm install' 'npm@12.2.0 pnpm@12.9.0 yarn@1.22.22' \
  'echo "${bun_sha}  /tmp/bun.zip" | sha256sum -c -' 'pipx install poetry' 'pipx install uv' \
  'COPY --from=workspace-floating-go --chown=codewire:codewire /out/ /home/codewire/go/bin/' \
  'RUN gopls version && hcloud version'; do
  grep -qF "$tool" <<<"$floating_stage" || fail "floating tool omitted from the fresh stage: $tool"
done
# The Go tools cross-compile natively on the build platform, never under
# emulation, still at @latest when the image is built.
# shellcheck disable=SC2016 # Match the Dockerfile's literal variables.
go_stage="$(sed -n '/^FROM --platform=$BUILDPLATFORM rust:1.99.1-bookworm@sha256:[0-9a-f]\{64\} AS workspace-floating-go$/,/^FROM /p' "$WORKSPACE_DOCKERFILE")"
# shellcheck disable=SC2016
for go_input in 'GOOS=linux GOARCH="$TARGETARCH" CGO_ENABLED=0' \
  '/usr/local/go/bin/go install golang.org/x/tools/gopls@latest' \
  '/usr/local/go/bin/go install github.com/hetznercloud/cli/cmd/hcloud@latest' \
  '"https://go.dev/dl/go${GO_VERSION}.linux-${BUILDARCH}.tar.gz"' \
  'echo "${go_sha}  /tmp/go.tgz" | sha256sum -c -' \
  'install -D -m 0755 "$binaries/gopls" /out/gopls' 'install -D -m 0755 "$binaries/hcloud" /out/hcloud'; do
  grep -qF -- "$go_input" <<<"$go_stage" || fail "build-platform Go tool stage omits: $go_input"
done
if grep -q 'go install' <<<"$floating_stage"; then
  fail 'the emulated floating stage still compiles Go tools'
fi
go_shas="$(sed -n 's/^ *\(amd64\|arm64\)) .*go_sha=\([0-9a-f]\{64\}\).*$/\1 \2/p' "$WORKSPACE_DOCKERFILE" | sort -u)"
[[ "$(wc -l <<<"$go_shas")" -eq 2 ]] || fail 'the build-platform Go archive differs from the workspace Go archive'
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
  'COPY --from=workspace-floating-go --chown=codewire:codewire' \
  'pipx install aider-chat' \
  'npm install -g --ignore-scripts' \
  'COPY --from=cw-toolchain --chown=codewire:codewire /usr/local/rustup/ /opt/codewire/rust/rustup/'; do
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

grep -qx 'ARG CODEWIRE_IMAGE_REGISTRY' "$CONFIDENTIAL_PROBE_DOCKERFILE" ||
  fail 'confidential probe does not take the registry host as a build argument'
grep -qF 'FROM ${CODEWIRE_IMAGE_REGISTRY}/oci-approved/e2e-test-images/busybox@sha256:caec39cad3b12c26600baf6e67ba811ac15d28a9288d0ccdfffb4b318992c3bb' \
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

if grep -Eq '(\$CODEWIRE_IMAGE_REGISTRY/codewire|ghcr\.io/codewiresh)/(base|workspace):(latest|main)' \
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
# An OCI image config carries no SHELL, so a base imported through an OCI
# store would hand its stages /bin/sh. Each base stage selects bash itself.
# shellcheck disable=SC2016 # Match the literal Dockerfile base argument.
base_stage_shells="$(grep -A2 -F 'FROM ${BASE_IMAGE_REF} AS ' "$WORKSPACE_DOCKERFILE" |
  grep -cxF 'SHELL ["/bin/bash", "-c"]' || true)"
# shellcheck disable=SC2016
[[ "$(grep -cF 'FROM ${BASE_IMAGE_REF} AS ' "$WORKSPACE_DOCKERFILE")" -eq 2 && "$base_stage_shells" -eq 2 ]] ||
  fail 'a workspace stage built from the base image inherits its shell'
if grep -qF 'ghcr.io/codewiresh/base:latest' "$WORKSPACE_DOCKERFILE"; then
  fail 'workspace Dockerfile still consumes the moving base tag'
fi
grep -Eq '^FROM ubuntu:noble@sha256:[0-9a-f]{64}$' "$ROOT/images/base/Dockerfile" ||
  fail 'base image foundation is not digest-pinned'
grep -Eq '^FROM rust:1\.99\.1-slim-bookworm@sha256:[0-9a-f]{64} AS cw-toolchain$' \
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
[[ "$(grep -Ec "node_sha=[0-9a-f]{64}" "$WORKSPACE_DOCKERFILE")" -eq 2 ]] ||
  fail "workspace image does not define node_sha exactly once per supported architecture"
# The installed Go and the build-platform Go that cross-compiles the Go tools
# are the same archive: two stages, one checksum per architecture.
[[ "$(grep -Ec "go_sha=[0-9a-f]{64}" "$WORKSPACE_DOCKERFILE")" -eq 4 \
  && "$(grep -Eo "go_sha=[0-9a-f]{64}" "$WORKSPACE_DOCKERFILE" | sort -u | wc -l)" -eq 2 ]] ||
  fail "workspace image does not use one Go archive checksum per supported architecture"
grep -qF 'snapshot.ubuntu.com/ubuntu/20261015T000000Z/' "$ROOT/images/base/ubuntu.sources" ||
  fail 'base apt inputs are not bound to the reviewed Ubuntu snapshot'
grep -qF 'snapshot.debian.org/archive/debian/20261015T000000Z/' \
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
    "@anthropic-ai/claude-code": "2.1.308",
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
assert allowed == ["@anthropic-ai/claude-code@2.1.308"], allowed
PY
  fail 'workspace agents are not one exact, registry-pinned lockfile'
grep -qF 'npm ci --strict-allow-scripts --no-audit --no-fund' "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace does not install the agent lockfile under its strict script policy'
grep -qF 'env -u NPM_CONFIG_PREFIX' "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace agent install inherits the user-facing global npm configuration'
if grep -Eq 'npm install .*(@openai/codex|@anthropic-ai/claude-code|@google/gemini-cli|@moonshot-ai/kimi-code|@earendil-works/pi-coding-agent)' \
    "$WORKSPACE_DOCKERFILE"; then
  fail 'workspace installs an agent outside its lockfile'
fi
grep -qF 'npm@12.2.0 pnpm@12.9.0 yarn@1.22.22' "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace does not pin the Node archive npm together with its package managers'
grep -qF 'npm cache clean --force' "$WORKSPACE_DOCKERFILE" ||
  fail 'workspace retains the root package-manager installer cache'
# Project and user npm installs keep npm's default lifecycle-script policy; a
# global allowlist made every project install fail (#2876).
[[ "$(grep -Ec -- 'allow-scripts=|NPM_CONFIG_ALLOW_SCRIPTS' "$WORKSPACE_DOCKERFILE")" -eq 0 ]] ||
  fail 'workspace sets a global npm lifecycle-script policy for project installs'

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
grep -Fq '"$CODEWIRE_IMAGE_REGISTRY/codewire/confidential-probe"' <<<"$probe_job" ||
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
  grep -Fq "needs.publish-support-images.outputs.workspace_mirrored == 'true'" <<<"$(grep '^    if: ' <<<"$job")" ||
    { echo 'the pin proposal can name an image the public mirror lacks'; return; }
  grep -Fq "github.event_name == 'push'" <<<"$(grep '^    if: ' <<<"$job")" ||
    { echo 'the pin proposal runs on a dispatch, which may not read the bot token'; return; }
  grep -Fqx "    if: \${{ github.event_name == 'push' && needs.publish-support-images.outputs.workspace_mirrored == 'true' && needs.support-selection.outputs.source_sha == github.sha }}" <<<"$job" ||
    { echo 'the pin proposal can name an earlier commit'"'"'s workspace'; return; }
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
  'keep checkout credentials::/persist-credentials: false/d'
  'job token beside the bot::/WORKSPACE_REF:/i\          GITEA_TOKEN: ${{ github.token }}'
  'job token instead of the bot::s|WORKSPACE_PIN_BOT_TOKEN_FILE="$bot_work/token"|GITEA_TOKEN="${{ github.token }}"|'
  'publisher OpenBao role::/WORKSPACE_REF:/i\          OPENBAO_ROLE: codewire-source-support-publisher'
  'Actions secret::/WORKSPACE_REF:/i\          TOKEN: ${{ secrets.WORKSPACE_PIN_TOKEN }}'
  'another document::s|fetch-openbao-workspace-pin-bot-token.sh|fetch-openbao-ghcr-credentials.sh|'
  'a second document::/fetch-openbao-workspace-pin-bot-token.sh/a\          scripts/ci/setup/fetch-openbao-harbor-credentials.sh "$bot_work/harbor"'
  'token outlives the step::/trap /d'
  'no mirror gate::/workspace_mirrored == .true./d'
  'earlier commit pinned::s/ \&\& needs.support-selection.outputs.source_sha == github.sha//'
  'a dispatch proposes::s/github.event_name == .push. \&\& //'
)
for mutation in "${pin_mutations[@]}"; do
  label="${mutation%%::*}"
  mutated="$(sed -e "${mutation#*::}" <<<"$pin_job")"
  [[ "$mutated" != "$pin_job" ]] || fail "pin job mutation did not apply: $label"
  [[ -n "$(pin_job_violation "$mutated")" ]] || fail "pin job mutation was accepted: $label"
done

# A commit whose pair inputs equal the validated published pair's gets that
# pair's exact indexes under its own tag, from a protected job with the join's
# publisher identity, whatever its supersession; it never builds or moves latest.
# alias_job_violation JOB prints the first broken alias rule, if any.
# shellcheck disable=SC2016
alias_job_violation() {
  local job="$1"
  [[ -n "$job" ]] || { echo 'no job aliases an unchanged commit to its identical published pair'; return; }
  grep -Fqx "    if: \${{ needs.support-selection.outputs.alias_support_pair == 'true' }}" <<<"$job" ||
    { echo 'the alias runs without the planner'"'"'s identical-inputs decision'; return; }
  local role
  for role in 'OPENBAO_ROLE: codewire-source-support-publisher' \
      'OPENBAO_GHCR_ROLE: codewire-source-support-publisher'; do
    grep -Fqx "      $role" <<<"$job" || { echo "the alias does not use the join's publisher identity ($role)"; return; }
  done
  if grep -Eq 'secrets\.|github\.token|build-support-platform|build-push-image|--support-pair|latest|continue-on-error' <<<"$job"; then
    echo 'the alias builds, moves latest, tolerates failure or holds another capability'
    return
  fi
  for binding in \
      'SOURCE_SHA: ${{ needs.support-selection.outputs.source_sha }}' \
      'ALIAS_FROM_SHA: ${{ needs.support-selection.outputs.alias_source_sha }}' \
      'ALIAS_BASE_DIGEST: ${{ needs.support-selection.outputs.alias_base_digest }}' \
      'ALIAS_WORKSPACE_DIGEST: ${{ needs.support-selection.outputs.alias_workspace_digest }}'; do
    grep -Fqx "          $binding" <<<"$job" || { echo "the alias does not take the planner's $binding"; return; }
  done
  grep -Fq 'scripts/ci/images/alias-support-pair.sh \
            "$SOURCE_SHA" "$ALIAS_FROM_SHA" "$ALIAS_BASE_DIGEST" "$ALIAS_WORKSPACE_DIGEST"' <<<"$job" ||
    { echo 'the alias does not run the reviewed alias publisher'; return; }
}
violation="$(alias_job_violation "$alias_job")"
[[ -z "$violation" ]] || fail "$violation"
# shellcheck disable=SC2016
alias_mutations=(
  'no decision::/alias_support_pair == .true./d'
  'superseded gate::s/alias_support_pair == .true. }}/alias_support_pair == '"'"'true'"'"' \&\& needs.support-selection.outputs.superseded == '"'"'false'"'"' }}/'
  'another identity::s|OPENBAO_GHCR_ROLE: codewire-source-support-publisher|OPENBAO_GHCR_ROLE: codewire-other|'
  'moves latest::s|"$ALIAS_WORKSPACE_DIGEST"$|"$ALIAS_WORKSPACE_DIGEST" latest|'
  'tolerated failure::/      - name: Tag the identical/a\        continue-on-error: true'
  'an unplanned digest::s|alias_base_digest }}|baseline_sha }}|'
  'a rebuild::/      - name: Tag the identical/i\      - run: scripts/ci/images/build-support-platform.sh linux/amd64'
  'Actions secret::/ALIAS_FROM_SHA:/i\          TOKEN: ${{ secrets.GHCR_TOKEN }}'
)
for mutation in "${alias_mutations[@]}"; do
  label="${mutation%%::*}"
  mutated="$(sed -e "${mutation#*::}" <<<"$alias_job")"
  [[ "$mutated" != "$alias_job" ]] || fail "alias job mutation did not apply: $label"
  [[ -n "$(alias_job_violation "$mutated")" ]] || fail "alias job mutation was accepted: $label"
done

# Forgejo keeps every queued run, so one that starts after main moved on must
# publish nothing; the newer commit's run is queued behind it and plans against
# the published pair. The selection job asks first, and each build job asks
# again as its first step after checkout, before it reads a credential or
# builds: a build job can wait minutes for a protected runner, and six pairs
# on 2026-10-23 and 2026-10-24 started both platforms after main moved on
# (infra#1534). Execute the checked-in rule for the current, superseded,
# unreadable and malformed cases. (Deploy Dev no longer skips itself: a newer
# run cancels an older delivery once that commit's main CI can no longer
# verify it, #2892.)
readonly SUPERSEDED_RULE="$ROOT/scripts/ci/images/support-superseded.sh"
[[ -x "$SUPERSEDED_RULE" ]] || fail 'the superseded-commit rule is missing'
superseded_bin="$(mktemp -d)"
trap 'rm -rf -- "$superseded_bin"' EXIT
recheck_step=$'      - name: Skip a superseded commit\n        id: canonical\n        run: scripts/ci/images/support-superseded.sh'
# shellcheck disable=SC2016 # Match the literal workflow expression.
grep -Fq '      superseded: ${{ steps.canonical.outputs.superseded }}' <<<"$selection_job" ||
  fail 'support selection does not expose whether its commit was superseded'
grep -Fq "$recheck_step" <<<"$selection_job" ||
  fail 'support selection does not run the superseded-commit rule'
superseded_line="$(grep -n -m1 'name: Skip a superseded commit' <<<"$selection_job" | cut -d: -f1)"
resolve_line="$(grep -n -m1 'name: Resolve untrusted published support pair' <<<"$selection_job" | cut -d: -f1)"
[[ "$superseded_line" -lt "$resolve_line" ]] ||
  fail 'support selection resolves the published pair before it knows whether its commit was superseded'
# rechecked_job_violation JOB [CLEANUP_STEP]: prints why JOB does not decide
# again before it builds. Its first step after checkout runs the rule, every
# later step but the named credential cleanup runs only when its commit is
# still main's tip, and a platform job reports the answer to the join.
rechecked_job_violation() {
  local job="$1" cleanup="${2:-}" steps name
  steps="$(awk '/^    steps:$/ { s = 1; next } s' <<<"$job")"
  [[ "$(awk '/^      - /' <<<"$steps" | sed -n '1,2p')" == \
    $'      - uses: noel/actions-checkout@'*$'\n      - name: Skip a superseded commit' ]] ||
    { echo 'it does not decide first after checkout'; return; }
  grep -Fq "$recheck_step" <<<"$steps" || { echo 'it does not run the rule'; return; }
  while IFS= read -r name; do
    [[ "$name" == 'Skip a superseded commit' ]] && continue
    if [[ -n "$cleanup" && "$name" == "$cleanup" ]]; then
      awk -v n="      - name: $name" '$0 == n { s = 1; next } s && /^      - / { exit } s' <<<"$steps" |
        grep -Fqx '        if: ${{ always() }}' || { echo "its cleanup step $name does not always run"; return; }
      continue
    fi
    awk -v n="      - name: $name" '$0 == n { s = 1; next } s && /^      - / { exit } s' <<<"$steps" |
      grep -Fqx "        if: \${{ steps.canonical.outputs.superseded == 'false' }}" ||
      { echo "step $name runs for a superseded commit"; return; }
  done < <(sed -n 's/^      - name: //p' <<<"$steps")
}
amd64_job="$(sed -n '/^  build-support-amd64:/,/^  build-support-arm64:/p' "$WORKFLOW")"
arm64_job="$(sed -n '/^  build-support-arm64:/,/^  publish-support-images:/p' "$WORKFLOW")"
for platform_job_name in amd64 arm64; do
  platform_job_text="$amd64_job"
  [[ "$platform_job_name" == amd64 ]] || platform_job_text="$arm64_job"
  violation="$(rechecked_job_violation "$platform_job_text" 'Remove the protected R2 compiler-cache credential')"
  [[ -z "$violation" ]] || fail "the $platform_job_name support build may build a superseded commit: $violation"
  # shellcheck disable=SC2016 # Match the literal workflow expression.
  grep -Fq '      superseded: ${{ steps.canonical.outputs.superseded }}' <<<"$platform_job_text" ||
    fail "the $platform_job_name support build does not report whether it skipped"
done
violation="$(rechecked_job_violation "$probe_job")"
[[ -z "$violation" ]] || fail "the confidential probe may build a superseded commit: $violation"
# shellcheck disable=SC2016 # Match the literal workflow expression.
grep -Fqx "    if: \${{ needs.build-support-amd64.outputs.superseded == 'false' && needs.build-support-arm64.outputs.superseded == 'false' }}" \
  <<<"$publish_job" || fail 'the join can run when a platform skipped its superseded build'
# Each mutation of the amd64 build must be refused.
recheck_mutations=(
  'no recheck::/^      - name: Skip a superseded commit$/,/^        run: scripts\/ci\/images\/support-superseded.sh$/d'
  'ungated build::/^      - name: Build the linux\/amd64 base and workspace by digest$/{n;d}'
  'ungated cache credential::/^      - name: Select the protected R2 compiler cache$/{n;d}'
  'recheck after the cache::/^      - name: Skip a superseded commit$/,/^        run: scripts\/ci\/images\/support-superseded.sh$/d;/^      - name: Build the linux\/amd64 base/i\      - name: Skip a superseded commit\n        id: canonical\n        run: scripts/ci/images/support-superseded.sh'
)
for mutation in "${recheck_mutations[@]}"; do
  label="${mutation%%::*}"
  mutated="$(sed -e "${mutation#*::}" <<<"$amd64_job")"
  [[ "$mutated" != "$amd64_job" ]] || fail "recheck mutation did not apply: $label"
  [[ -n "$(rechecked_job_violation "$mutated" 'Remove the protected R2 compiler-cache credential')" ]] ||
    fail "recheck mutation was accepted: $label"
done
cat >"$superseded_bin/git" <<'GIT'
#!/usr/bin/env bash
[[ "$*" == 'ls-remote origin refs/heads/main' ]] || exit 64
[[ -n "${FAKE_MAIN_SHA:-}" ]] || exit 1
printf '%s\trefs/heads/main\n' "$FAKE_MAIN_SHA"
GIT
chmod +x "$superseded_bin/git"
superseded_case() {
  local main="$1" event="${2:-push}" output
  output="$(mktemp)"
  if env PATH="$superseded_bin:$PATH" FAKE_MAIN_SHA="$main" GITHUB_EVENT_NAME="$event" \
      GITHUB_SHA=1111111111111111111111111111111111111111 GITHUB_OUTPUT="$output" \
      "$SUPERSEDED_RULE" >/dev/null 2>&1; then
    cat "$output"
  else
    printf 'failed\n'
  fi
  rm -f -- "$output"
}
[[ "$(superseded_case 1111111111111111111111111111111111111111)" == superseded=false ]] ||
  fail 'the canonical main commit was treated as superseded'
[[ "$(superseded_case 2222222222222222222222222222222222222222)" == superseded=true ]] ||
  fail 'a commit behind canonical main was not skipped'
[[ "$(superseded_case '')" == failed ]] ||
  fail 'an unreadable canonical main did not fail closed'
[[ "$(superseded_case not-a-commit)" == failed ]] ||
  fail 'a malformed canonical main did not fail closed'
# A dispatch names its commit, usually an earlier one a release needs, and
# builds it wherever main is now (#4243).
[[ "$(superseded_case 2222222222222222222222222222222222222222 workflow_dispatch)" == superseded=false ]] ||
  fail 'a dispatch was skipped because main moved on'

# Each platform of the pair builds in its own protected job with its own time
# budget below the runner's ceiling, pushes only by digest and publishes
# nothing; the join is the only publisher.
for platform in amd64 arm64; do
  case "$platform" in
    # amd64 compiles cw on the trusted BuildKit builder; arm64 drives the
    # remote arm64 node. The amd64 workspace digest leaves its job only
    # through the contract.
    amd64) next_job=build-support-arm64 digest_step=contract ;;
    arm64) next_job=publish-support-images digest_step=build ;;
  esac
  platform_job="$(sed -n "/^  build-support-$platform:/,/^  $next_job:/p" "$WORKFLOW")"
  # The joins take each platform's digest only from the step that proved it.
  for expected in "        run: scripts/ci/images/build-support-platform.sh linux/$platform" \
      '      base_digest: ${{ steps.build.outputs.base_digest }}' \
      "      workspace_digest: \${{ steps.$digest_step.outputs.workspace_digest }}"; do
    grep -qxF -- "$expected" <<<"$platform_job" || fail "linux/$platform support build omits: $expected"
  done
  # Its own budget fails the build before the job's timeout does.
  timeout_minutes="$(sed -n 's/^    timeout-minutes: //p' <<<"$platform_job")"
  budget="$(sed -n "s/^          SUPPORT_PLATFORM_BUDGET_MINUTES: '\([0-9]*\)'\$/\1/p" <<<"$platform_job")"
  [[ -n "$budget" && -n "$timeout_minutes" && "$budget" -lt "$timeout_minutes" ]] ||
    fail "linux/$platform support build budget does not fail before the runner ceiling"
  if [[ "$platform" == amd64 ]]; then
    grep -qxF "      CODEWIRE_IN_JOB_BUILD: \${{ vars.CODEWIRE_IN_JOB_BUILD_SHA == needs.support-selection.outputs.source_sha && '1' || '0' }}" <<<"$platform_job" ||
      fail "linux/amd64 support build lacks the owner's exact-commit recovery switch"
  fi
  if grep -Eq 'publish-image-to-|OPENBAO_GHCR|secrets\.|--support-pair' <<<"$platform_job"; then
    fail "linux/$platform support build crosses the publication boundary"
  fi
done

# The workspace agent contract runs on the exact amd64 image the build pushed,
# after the compiler-cache credential is gone, and the job reports the digest
# only from that step: the joins consume nothing that skipped the contract.
# contract_step_violation FILE prints the first broken rule, if any.
contract_step_violation() {
  python3 - "$1" <<'PY'
import sys

import yaml

try:
    job = yaml.safe_load(open(sys.argv[1]))["jobs"]["build-support-amd64"]
except Exception as error:  # A mutation may break the document itself.
    sys.exit(f"the workflow does not parse: {error}")
steps = job.get("steps") or []
names = [step.get("name") for step in steps]
contract = [index for index, step in enumerate(steps) if step.get("id") == "contract"]
if len(contract) != 1:
    sys.exit("the amd64 build job has no single workspace contract step")
expected = {
    "name": "Run the workspace contract on the exact image",
    "if": "${{ steps.canonical.outputs.superseded == 'false' }}",
    "id": "contract",
    "env": {"WORKSPACE_DIGEST": "${{ steps.build.outputs.workspace_digest }}"},
    "run": "scripts/ci/images/run-workspace-contract-on-image.sh \\\n"
           '  "$CODEWIRE_IMAGE_REGISTRY/codewire/workspace@$WORKSPACE_DIGEST" "$CODEWIRE_SOURCE_SHA" \\\n'
           "  .support-source/scripts/ci/verify/workspace-agent-contract.sh\n",
}
if steps[contract[0]] != expected:
    sys.exit("the workspace contract step differs from the reviewed exact-image step")
build = [index for index, step in enumerate(steps) if step.get("id") == "build"]
removal = [index for index, name in enumerate(names)
           if name == "Remove the protected R2 compiler-cache credential"]
if len(build) != 1 or len(removal) != 1 or not build[0] < removal[0] < contract[0]:
    sys.exit("the workspace contract does not follow the build and the credential removal")
if (job.get("outputs") or {}).get("workspace_digest") != "${{ steps.contract.outputs.workspace_digest }}":
    sys.exit("the amd64 workspace digest leaves the job without the contract")
if "continue-on-error" in job:
    sys.exit("the amd64 build job continues on error")
if any("artifact" in str(step.get("uses", "")) for step in steps):
    sys.exit("the amd64 build job takes an artifact input")
PY
}
violation="$(contract_step_violation "$WORKFLOW" 2>&1)" && [[ -z "$violation" ]] || fail "$violation"
# Each rule refuses its own regression of the reviewed job.
contract_tree="$(mktemp -d)"
trap 'rm -rf -- "$superseded_bin" "$contract_tree"' EXIT
move_contract_before() {
  awk -v anchor="$1" '
    /^  [A-Za-z0-9_-]+:$/ { job = $0 }
    job == "  build-support-amd64:" && $0 == "      - name: Run the workspace contract on the exact image" { grab = 1 }
    grab { if ($0 == "") { grab = 0 } else { block = block $0 "\n" }; next }
    { line[++count] = $0; owner[count] = job }
    END {
      for (index_ = 1; index_ <= count; index_++) {
        if (owner[index_] == "  build-support-amd64:" && line[index_] == anchor) printf "%s\n", block
        print line[index_]
      }
    }
  ' "$WORKFLOW"
}
amd64_range='/^  build-support-amd64:/,/^  build-support-arm64:/'
# shellcheck disable=SC2016 # The mutations insert literal workflow expressions.
contract_mutations=(
  "contract step removed::$amd64_range{/- name: Run the workspace contract on the exact image/,/^\$/d}"
  "digest from the build step::s/workspace_digest: \${{ steps.contract.outputs.workspace_digest }}/workspace_digest: \${{ steps.build.outputs.workspace_digest }}/"
  "continue-on-error::/        id: contract/a\\        continue-on-error: true"
  "job continue-on-error::$amd64_range{/    timeout-minutes: 120/a\\    continue-on-error: true
}"
  "skippable contract::/        id: contract/a\\        if: \${{ always() }}"
  'needs. input::/          WORKSPACE_DIGEST: /a\          SOURCE_SHA: ${{ needs.support-selection.outputs.head_sha }}'
  'needs. digest::s/WORKSPACE_DIGEST: ${{ steps.build.outputs.workspace_digest }}/WORKSPACE_DIGEST: ${{ needs.support-selection.outputs.baseline_sha }}/'
  'artifact contract::s|            .support-source/scripts/ci/verify/workspace-agent-contract.sh|            "$RUNNER_TEMP/artifact/workspace-agent-contract.sh"|'
  'main'"'"'s contract::s|            .support-source/scripts/ci/verify/workspace-agent-contract.sh|            scripts/ci/verify/workspace-agent-contract.sh|'
  'main'"'"'s revision::s|@$WORKSPACE_DIGEST" "$CODEWIRE_SOURCE_SHA"|@$WORKSPACE_DIGEST" "$GITHUB_SHA"|'
  "artifact step::$amd64_range{/      - name: Run the workspace contract on the exact image/i\\      - uses: noel/actions-download-artifact@a9bc5e6ef2cb54c177f32aa5726adaa15e7e2d59
}"
  'tagged image::s|"$CODEWIRE_IMAGE_REGISTRY/codewire/workspace@$WORKSPACE_DIGEST"|"$CODEWIRE_IMAGE_REGISTRY/codewire/workspace:$GITHUB_SHA"|'
  'public mirror source::s|run-workspace-contract-on-image.sh \\$|run-workspace-contract-on-image.sh --source ghcr \\|'
)
for mutation in "${contract_mutations[@]}"; do
  label="${mutation%%::*}"
  sed -e "${mutation#*::}" "$WORKFLOW" >"$contract_tree/workflow.yaml"
  ! cmp -s "$WORKFLOW" "$contract_tree/workflow.yaml" || fail "contract mutation did not apply: $label"
  [[ -n "$(contract_step_violation "$contract_tree/workflow.yaml" 2>&1)" ]] ||
    fail "contract mutation was accepted: $label"
done
move_contract_before '      - name: Remove the protected R2 compiler-cache credential' >"$contract_tree/removal.yaml"
move_contract_before '      - name: Build the linux/amd64 base and workspace by digest' >"$contract_tree/build.yaml"
for moved in removal build; do
  ! cmp -s "$WORKFLOW" "$contract_tree/$moved.yaml" || fail "contract move did not apply: $moved"
  [[ -n "$(contract_step_violation "$contract_tree/$moved.yaml" 2>&1)" ]] ||
    fail "a workspace contract moved before the $moved step was accepted"
done
grep -qE '^    timeout-minutes: [0-9]+$' <<<"$publish_job" || fail 'support join has no explicit time budget'
if grep -qF 'build-support-platform.sh' <<<"$publish_job"; then
  fail 'support join rebuilds a platform'
fi

# The platform script, run in a copy of its tree against a recording builder,
# a recording Docker and a stub for the arm64 node's client certificate.
platform_tree="$(mktemp -d)"
trap 'rm -rf -- "$superseded_bin" "$contract_tree" "$platform_tree"' EXIT
mkdir -p "$platform_tree/scripts/ci/images" "$platform_tree/scripts/ci/setup" "$platform_tree/bin" "$platform_tree/runner"
cp "$PLATFORM_BUILDER" "$platform_tree/scripts/ci/images/"
cp "$ROOT/scripts/ci/setup/trusted-buildkit.sh" "$platform_tree/scripts/ci/setup/"
cat >"$platform_tree/scripts/ci/images/build-push-image.sh" <<'STUB'
#!/usr/bin/env bash
printf '%s|%s|%s|%s|%s\n' "$1" "${CODEWIRE_IMAGE_PLATFORM:-}" "${CODEWIRE_BASE_IMAGE_REF:-}" \
  "${CODEWIRE_EXTERNAL_BUILDX_BUILDER:-}" "$*" >>"$STUB_CALLS"
printf '%s %s\n' "$1" "${CODEWIRE_CARGO_BUILD_JOBS:-default}" >>"$STUB_CALLS.jobs"
[[ -z "${CODEWIRE_EXTERNAL_DOCKER_CONFIG:-}" || -d "$CODEWIRE_EXTERNAL_DOCKER_CONFIG" ]] || exit 7
case "${STUB_MODE:-ok}:$1" in
  fail:base) exit 9 ;;
  nodigest:base) exit 0 ;;
esac
case "$1" in
  base) digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;
  workspace) digest=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ;;
esac
printf 'platform_digest=%s\n' "$digest" >>"$GITHUB_OUTPUT"
STUB
cat >"$platform_tree/scripts/ci/setup/fetch-openbao-arm64-buildkit-client.sh" <<'STUB'
#!/usr/bin/env bash
printf '%s %s\n' "$1" "$(stat -c '%a' "$1")" >>"$STUB_FETCHES"
[[ "${STUB_FETCH:-ok}" == ok ]] || exit 1
for file in ca.crt client.crt client.key; do printf 'synthetic\n' >"$1/$file"; done
STUB
cat >"$platform_tree/scripts/ci/setup/fetch-openbao-trusted-buildkit-client.sh" <<'STUB'
#!/usr/bin/env bash
printf '%s %s\n' "$1" "$(stat -c '%a' "$1")" >>"$STUB_TRUSTED_FETCHES"
[[ "${STUB_TRUSTED_FETCH:-ok}" == ok ]] || exit 1
for file in ca.crt client.crt client.key; do printf 'synthetic\n' >"$1/$file"; done
STUB
cat >"$platform_tree/bin/docker" <<'STUB'
#!/usr/bin/env bash
printf 'DOCKER_CONFIG=%s %s\n' "${DOCKER_CONFIG:-}" "$*" >>"$STUB_DOCKER"
node="${STUB_NODE:-arm64}"
[[ "${3:-}" != codewire-support-amd64-* ]] || node="${STUB_TRUSTED_NODE:-amd64}"
case "$1 $2" in
  'buildx inspect')
    case "$node" in
      arm64) printf 'Name: x\nDriver: remote\nStatus:             running\nPlatforms:          linux/arm64*, linux/arm64/v8\n' ;;
      amd64) printf 'Status:             running\nPlatforms:          linux/amd64*\n' ;;
      stopped) printf 'Status:             stopped\nPlatforms:          linux/arm64*\n' ;;
      down) echo 'ERROR: connection refused' >&2; exit 1 ;;
    esac ;;
esac
exit 0
STUB
chmod +x "$platform_tree/scripts/ci/images/build-push-image.sh" "$platform_tree/scripts/ci/images/build-support-platform.sh" \
  "$platform_tree/scripts/ci/setup/fetch-openbao-arm64-buildkit-client.sh" \
  "$platform_tree/scripts/ci/setup/fetch-openbao-trusted-buildkit-client.sh" "$platform_tree/bin/docker"
platform_case() {
  local budget="$1" platform="$2"
  shift 2
  : >"$platform_tree/calls"; : >"$platform_tree/output"; : >"$platform_tree/fetches"; : >"$platform_tree/docker"
  : >"$platform_tree/trusted-fetches"; : >"$platform_tree/calls.jobs"
  if env CODEWIRE_IMAGE_REGISTRY=registry.example.invalid "$@" PATH="$platform_tree/bin:$PATH" RUNNER_TEMP="$platform_tree/runner" \
      STUB_CALLS="$platform_tree/calls" STUB_FETCHES="$platform_tree/fetches" STUB_DOCKER="$platform_tree/docker" \
      STUB_TRUSTED_FETCHES="$platform_tree/trusted-fetches" \
      GITHUB_OUTPUT="$platform_tree/output" GITHUB_RUN_ID=77 GITHUB_RUN_ATTEMPT=1 \
      SUPPORT_PLATFORM_BUDGET_MINUTES="$budget" \
      "$platform_tree/scripts/ci/images/build-support-platform.sh" "$platform" >"$platform_tree/out" 2>&1; then
    echo ok
  else
    echo "failed $?"
  fi
}
base_a=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
# amd64 builds on the trusted BuildKit builder, attached with this job's
# publisher certificate; it never reads the arm64 node's certificate.
[[ "$(platform_case 110 linux/amd64)" == ok ]] || { cat "$platform_tree/out" >&2; fail 'amd64 platform build failed'; }
read -r tls_dir tls_mode <"$platform_tree/trusted-fetches"
[[ "$tls_mode" == 700 && "$tls_dir" == "$platform_tree/runner/codewire-support-platform."*/trusted-buildkit-tls ]] ||
  fail 'the trusted builder certificate was not fetched into a private job directory'
[[ ! -s "$platform_tree/fetches" ]] || fail 'amd64 build read the arm64 certificate'
[[ -z "$(find "$platform_tree/runner" -mindepth 1 -print -quit)" ]] ||
  fail 'the trusted builder certificate or the private Docker configuration survived the build'
docker_config="${tls_dir%/trusted-buildkit-tls}/docker-config"
create_call="$(grep ' buildx create ' "$platform_tree/docker")"
[[ "$create_call" == "DOCKER_CONFIG=$docker_config buildx create --name codewire-support-amd64-77-1-"*" --driver remote --platform linux/amd64 --driver-opt cacert=$tls_dir/ca.crt,cert=$tls_dir/client.crt,key=$tls_dir/client.key,servername=ams3-1-trusted-builder-large-0.forgejo-ci-builder.svc.cluster.local tcp://ams3-1-trusted-builder-large-0.forgejo-ci-builder.svc.cluster.local:1234" ]] ||
  fail "the trusted builder is not attached as the mutual-TLS remote builder: $create_call"
trusted_name="$(sed -n 's/^.* buildx create --name \([^ ]*\) .*$/\1/p' "$platform_tree/docker")"
grep -qxF "DOCKER_CONFIG=$docker_config buildx inspect $trusted_name --bootstrap" "$platform_tree/docker" ||
  fail 'the trusted builder was not checked before building'
grep -qxF "DOCKER_CONFIG=$docker_config buildx rm $trusted_name" "$platform_tree/docker" ||
  fail 'the trusted builder was not forgotten after the build'
[[ "$(cat "$platform_tree/calls")" == "base|linux/amd64||$trusted_name|base images/base/Dockerfile images/base
workspace|linux/amd64|registry.example.invalid/codewire/base@$base_a|$trusted_name|workspace images/workspace/Dockerfile ." ]] ||
  fail 'amd64 build does not build its base, then its workspace from that exact base, on the trusted builder'
[[ "$(cat "$platform_tree/calls.jobs")" == $'base 14\nworkspace 14' ]] ||
  fail 'amd64 builds on the trusted builder did not bound Cargo'"'"'s jobs to its memory'
[[ "$(cat "$platform_tree/output")" == "base_digest=$base_a
workspace_digest=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" ]] ||
  fail 'platform build does not report both exact digests'
grep -Eq '^CODEWIRE_CI_PHASE name=support-amd64-workspace seconds=[0-9]+ status=0$' "$platform_tree/out" ||
  fail 'platform build does not report each phase'"'"'s time'
# arm64 builds natively on the protected node, attached with this job's certificate.
[[ "$(platform_case 110 linux/arm64)" == ok ]] || { cat "$platform_tree/out" >&2; fail 'arm64 platform build failed'; }
read -r tls_dir tls_mode <"$platform_tree/fetches"
[[ "$tls_mode" == 700 && "$tls_dir" == "$platform_tree/runner/codewire-support-platform."*/arm64-buildkit-tls ]] ||
  fail 'the arm64 certificate was not fetched into a private job directory'
[[ ! -e "$tls_dir" && -z "$(find "$platform_tree/runner" -mindepth 1 -print -quit)" ]] ||
  fail 'the arm64 certificate or the private Docker configuration survived the build'
docker_config="${tls_dir%/arm64-buildkit-tls}/docker-config"
builder=codewire-support-arm64-77-1-
create_call="$(grep ' buildx create ' "$platform_tree/docker")"
[[ "$create_call" == "DOCKER_CONFIG=$docker_config buildx create --name $builder"*" --driver remote --platform linux/arm64 --driver-opt cacert=$tls_dir/ca.crt,cert=$tls_dir/client.crt,key=$tls_dir/client.key,servername=arm64-builder.example.invalid tcp://arm64-builder.example.invalid:1234" ]] ||
  fail "the arm64 node is not attached as the mutual-TLS remote builder: $create_call"
remote_name="$(sed -n 's/^.* buildx create --name \([^ ]*\) .*$/\1/p' "$platform_tree/docker")"
grep -qxF "DOCKER_CONFIG=$docker_config buildx inspect $remote_name --bootstrap" "$platform_tree/docker" ||
  fail 'the arm64 node was not checked before building'
grep -qxF "DOCKER_CONFIG=$docker_config buildx rm $remote_name" "$platform_tree/docker" ||
  fail 'the remote builder was not forgotten after the build'
[[ "$(cat "$platform_tree/calls")" == "base|linux/arm64||$remote_name|base images/base/Dockerfile images/base
workspace|linux/arm64|registry.example.invalid/codewire/base@$base_a|$remote_name|workspace images/workspace/Dockerfile ." ]] ||
  fail 'arm64 images were not built on the attached node'
[[ "$(cat "$platform_tree/calls.jobs")" == $'base default\nworkspace default' ]] ||
  fail 'arm64 builds took the trusted builder'"'"'s Cargo job count'
# deploy-prod.yaml builds a release tag's pair from its separate checkout with
# this tree's scripts; arm64 still builds only on the attached native node.
mkdir -p "$platform_tree/.release-source"
[[ "$(cd "$platform_tree" && platform_case 110 linux/arm64 CODEWIRE_SOURCE_DIR=.release-source)" == ok ]] ||
  { cat "$platform_tree/out" >&2; fail 'arm64 release-source build failed'; }
remote_name="$(sed -n 's/^.* buildx create --name \([^ ]*\) .*$/\1/p' "$platform_tree/docker")"
[[ -n "$remote_name" && "$(cat "$platform_tree/calls")" == "base|linux/arm64||$remote_name|base .release-source/images/base/Dockerfile .release-source/images/base
workspace|linux/arm64|registry.example.invalid/codewire/base@$base_a|$remote_name|workspace .release-source/images/workspace/Dockerfile .release-source" ]] ||
  fail 'a release-source arm64 build did not build that checkout on the attached node'
for bad_source in /abs ../outside missing-dir; do
  [[ "$(cd "$platform_tree" && platform_case 110 linux/amd64 CODEWIRE_SOURCE_DIR="$bad_source")" == failed* && ! -s "$platform_tree/calls" ]] ||
    fail "a platform build accepted the source directory $bad_source"
done
# A base index already published for the release source is not rebuilt: the
# workspace is built from exactly that platform image.
published_base=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
[[ "$(platform_case 110 linux/amd64 SUPPORT_PLATFORM_BASE_DIGEST="$published_base")" == ok ]] ||
  { cat "$platform_tree/out" >&2; fail 'platform build from a published base failed'; }
trusted_name="$(sed -n 's/^.* buildx create --name \([^ ]*\) .*$/\1/p' "$platform_tree/docker")"
[[ "$(cat "$platform_tree/calls")" == "workspace|linux/amd64|registry.example.invalid/codewire/base@$published_base|$trusted_name|workspace images/workspace/Dockerfile ." ]] ||
  fail 'a published base was rebuilt or not used for the workspace'
grep -qxF "base_digest=$published_base" "$platform_tree/output" ||
  fail 'a platform build from a published base does not report that base'
[[ "$(platform_case 110 linux/amd64 SUPPORT_PLATFORM_BASE_DIGEST=sha256:short)" == failed* && ! -s "$platform_tree/calls" ]] ||
  fail 'a malformed published base digest was accepted'
# The arm64 build fails closed, never falling back to emulation.
for arm64_failure in 'STUB_FETCH=fail|client certificate could not be read' \
    'STUB_NODE=down|did not answer as a running linux/arm64 builder' \
    'STUB_NODE=amd64|did not answer as a running linux/arm64 builder' \
    'STUB_NODE=stopped|did not answer as a running linux/arm64 builder'; do
  [[ "$(platform_case 110 linux/arm64 "${arm64_failure%%|*}")" == failed* ]] ||
    fail "arm64 build did not fail closed: ${arm64_failure%%|*}"
  grep -qF "${arm64_failure#*|}" "$platform_tree/out" && grep -qF 'does not fall back to emulation' "$platform_tree/out" ||
    fail "arm64 failure was not attributable: ${arm64_failure%%|*}"
  [[ ! -s "$platform_tree/calls" ]] || fail "arm64 build ran without the native node: ${arm64_failure%%|*}"
  [[ -z "$(find "$platform_tree/runner" -mindepth 1 -print -quit)" ]] ||
    fail "a failed arm64 attach left the certificate behind: ${arm64_failure%%|*}"
done
# The amd64 build fails fast without the trusted builder and never builds in
# the job on its own; the error names the owner's recovery.
for amd64_failure in 'STUB_TRUSTED_FETCH=fail|client certificate could not be read' \
    'STUB_TRUSTED_NODE=down|did not answer as a running linux/amd64 builder' \
    'STUB_TRUSTED_NODE=arm64|did not answer as a running linux/amd64 builder'; do
  [[ "$(platform_case 110 linux/amd64 "${amd64_failure%%|*}")" == failed* ]] ||
    fail "amd64 build did not fail fast: ${amd64_failure%%|*}"
  for expected in "${amd64_failure#*|}" 'do not fall back to building in the job' 'CODEWIRE_IN_JOB_BUILD_SHA'; do
    grep -qF "$expected" "$platform_tree/out" || fail "amd64 failure was not attributable: ${amd64_failure%%|*}"
  done
  [[ ! -s "$platform_tree/calls" ]] || fail "amd64 build ran without the trusted builder: ${amd64_failure%%|*}"
  [[ -z "$(find "$platform_tree/runner" -mindepth 1 -print -quit)" ]] ||
    fail "a failed trusted attach left the certificate behind: ${amd64_failure%%|*}"
done
# The owner's explicit recovery builds amd64 in the job's own builder.
[[ "$(platform_case 110 linux/amd64 CODEWIRE_IN_JOB_BUILD=1)" == ok ]] ||
  { cat "$platform_tree/out" >&2; fail 'the in-job amd64 recovery failed'; }
[[ "$(cat "$platform_tree/calls")" == "base|linux/amd64|||base images/base/Dockerfile images/base
workspace|linux/amd64|registry.example.invalid/codewire/base@$base_a||workspace images/workspace/Dockerfile ." ]] ||
  fail 'the in-job amd64 recovery did not build on the job'"'"'s own builder'
[[ ! -s "$platform_tree/trusted-fetches" && ! -s "$platform_tree/fetches" && ! -s "$platform_tree/docker" ]] ||
  fail 'the in-job amd64 recovery read a certificate or attached a remote builder'
grep -qF 'owner-invoked recovery path' "$platform_tree/out" || fail 'the in-job amd64 recovery was not announced'
[[ "$(platform_case 110 linux/amd64 CODEWIRE_IN_JOB_BUILD=true)" == failed* && ! -s "$platform_tree/calls" ]] ||
  fail 'an ambiguous recovery switch was accepted'
[[ "$(platform_case 110 linux/amd64 STUB_MODE=fail)" == 'failed 9' && ! -s "$platform_tree/output" ]] ||
  fail 'a failed platform base did not fail the build with its status'
[[ "$(platform_case 110 linux/amd64 STUB_MODE=nodigest)" == 'failed 1' ]] ||
  fail 'a platform build that reported no digest was accepted'
[[ "$(platform_case 0 linux/amd64)" == failed* && "$(platform_case '' linux/amd64)" == failed* ]] ||
  fail 'a platform build without a valid budget was accepted'
[[ "$(platform_case 110 linux/amd64 CODEWIRE_IMAGE_REGISTRY=)" == failed* && ! -s "$platform_tree/calls" ]] &&
  grep -Fq 'CODEWIRE_IMAGE_REGISTRY' "$platform_tree/out" ||
  fail 'a platform build without the registry host did not stop naming CODEWIRE_IMAGE_REGISTRY'
[[ "$(platform_case 110 linux/riscv64)" == failed* && ! -s "$platform_tree/calls" ]] ||
  fail 'an unsupported platform was built'
grep -qF -- '--kill-after=60s "${remaining}s"' "$PLATFORM_BUILDER" ||
  fail 'platform build does not bound each image by the remaining budget'
grep -qF "::error::the %s support build exceeded its %s-minute budget in the %s image" "$PLATFORM_BUILDER" ||
  fail 'platform build does not explain an exhausted budget'
"$ROOT/scripts/ci/tests/test-fetch-openbao-arm64-buildkit-client.sh" >/dev/null
"$ROOT/scripts/ci/tests/test-fetch-openbao-trusted-buildkit-client.sh" >/dev/null

# A failed half of the support pair reports "failure" with its whole log, and
# its other half finishes: no job cancels its own run (#3119; owner,
# 2026-10-21). A cancel turned the failure into "cancelled" and cut the
# failing job's log (infra#1229).
if grep -qE '/actions/runs/[^ ]*/cancel' "$WORKFLOW"; then
  fail 'a support pair half cancels its own run'
fi

echo 'support-image workflow contract: OK'
