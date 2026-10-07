#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly WORKFLOW="$ROOT/.gitea/workflows/deploy-dev.yaml"
readonly RUNTIME_BUILDER="$ROOT/scripts/ci/images/build-push-runtime-images.sh"
readonly RUNTIME_SIGNER="$ROOT/scripts/ci/images/sign-runtime-image-set.sh"
readonly RUNTIME_PUBLIC_KEY="$ROOT/scripts/ci/trust/codewire-runtime-signing.pub"
readonly LEGACY_GITHUB_GATEWAY_WORKFLOW="$ROOT/.github/workflows/build-gateway-image.yml"
readonly DEV_KUSTOMIZATION="$ROOT/deployments/k8s/overlays/dev/kustomization.yaml"
readonly DEV_CONFIG_IMAGES="$ROOT/deployments/k8s/overlays/dev/config-images.yaml"
readonly DEV_MESH_RELEASE="$ROOT/deployments/k8s/flux/mesh-dev/helmrelease.yaml"
readonly DEV_MESH_VALUES="$ROOT/deployments/k8s/mesh-dev/values.yaml"
readonly MESH_CHART="$ROOT/apps/cli/charts/codewire-mesh"

fail() {
  printf '[test-deploy-dev] ERROR: %s\n' "$*" >&2
  exit 1
}

bash -n "$0"

if grep -q '^  workflow_dispatch:' "$WORKFLOW"; then
  fail "dev image publication must be canonical-main push-only"
fi
if grep -q '^concurrency:$' "$WORKFLOW"; then
  fail "dev image publication must not rely on unsupported Gitea concurrency"
fi
if grep -qE '^permissions:|^enable-openid-connect:' "$WORKFLOW"; then
  fail "Dev delivery retains ignored permissions or workflow-wide OIDC"
fi
if grep -q "github.event_name == 'workflow_dispatch'" "$WORKFLOW"; then
  fail "dev job selection still includes a manual-dispatch bypass"
fi
if grep -q 'azure/setup-helm' "$WORKFLOW"; then
  fail "Deploy Dev still installs Helm"
fi
if [[ -e "$LEGACY_GITHUB_GATEWAY_WORKFLOW" ]]; then
  fail "GitHub still independently builds the gateway image"
fi
if grep -Eq 'CODEWIRE_(GHCR_PUBLISH|DEPLOY_SHA_DISPATCH)_ENABLED' "$WORKFLOW"; then
  fail "dev publication or dispatch retains a rollout flag"
fi

selection_job="$(sed -n '/^  deploy-selection:/,/^  build-publish-runtime-images:/p' "$WORKFLOW")"
grep -Fq '    runs-on: ci-lite' <<<"$selection_job" ||
  fail "deploy selection does not use the non-privileged CI tier"
grep -Fq '    enable-openid-connect: true' <<<"$selection_job" ||
  fail "deploy selection cannot request its read-only baseline identity"
if grep -Eq 'OPENBAO_(ROLE|AUDIENCE)|secrets\.' <<<"$selection_job"; then
  fail "deploy selection receives a publisher or static credential"
fi
grep -Fq '    timeout-minutes: 15' <<<"$selection_job" ||
  fail "deploy selection lacks a bounded ci-lite deadline"
grep -Fq '          fetch-depth: 0' <<<"$selection_job" ||
  fail "deploy selection does not receive the complete cumulative history"
grep -Fq 'name: Verify sealed Rust toolchain' \
  <<<"$selection_job" ||
  fail "deploy selection does not verify the sealed Rust toolchain for artifact classification"
toolchain_line="$(grep -n -m1 'name: Verify sealed Rust toolchain' \
  <<<"$selection_job" | cut -d: -f1)"
classifier_line="$(grep -n -m1 'name: Plan and select atomic Dev deployment' \
  <<<"$selection_job" | cut -d: -f1)"
[[ "$toolchain_line" -lt "$classifier_line" ]] ||
  fail "deploy selection verifies Rust after artifact classification"
grep -Fq "scripts/ci/deploy/resolve-deployed-source.sh \"\$candidate\" \"\$GITHUB_SHA\"" \
  <<<"$selection_job" || fail "deploy selection does not resolve an exact-head candidate"
if grep -Fq 'CODEWIRE_DEPLOY_PROMOTION_TOKEN' <<<"$selection_job"; then
  fail "baseline resolver retains the retired static deploy credential"
fi
grep -Fq -- "--deployed-source-candidate \"\$RUNNER_TEMP/codewire-deployed-source-candidate.json\"" \
  <<<"$selection_job" || fail "planner is not bound to the resolved candidate"
grep -Fq -- "--target-base \"\$GITHUB_SHA\"" <<<"$selection_job" ||
  fail "planner target is not exact current main"
grep -Fq -- "--head \"\$GITHUB_SHA\"" <<<"$selection_job" ||
  fail "planner head is not exact current main"
grep -Fq -- "--trusted-policy \"\$GITHUB_SHA\"" <<<"$selection_job" ||
  fail "planner policy is not exact current main"
grep -Fq 'scripts/ci/plan/apply-deploy-plan.py' <<<"$selection_job" ||
  fail "deploy selection does not apply trusted runtime artifact facts"
if compgen -G "$ROOT/scripts/ci/select/select-deploy-*" >/dev/null \
  || compgen -G "$ROOT/scripts/ci/select/artifact-*" >/dev/null; then
  fail "legacy deployment classifier remains in the repository"
fi
select_step="$(sed -n '/      - name: Plan and select atomic Dev deployment/,/^  build-publish-runtime-images:/p' \
  <<<"$selection_job")"
if grep -Fq 'secrets.' <<<"$select_step"; then
  fail "artifact classifier receives the private deploy credential"
fi
grep -Fq "if: \${{ always() }}" <<<"$selection_job" ||
  fail "untrusted deployed-source candidate is not cleaned up unconditionally"
grep -Fq "rm -f -- \"\$RUNNER_TEMP/codewire-deployed-source-candidate.json\"" \
  <<<"$selection_job" || fail "untrusted deployed-source candidate cleanup is missing"
for output in deploy_dev reason matched_categories \
  dashboard_image_state daemon_image_state derp_image_state services_image_state mesh_image_state \
  baseline_sha head_sha head_tree ci_plan_sha256 ci_policy_sha256 baseline_valid; do
  # shellcheck disable=SC2016
  grep -Fq "$output: \${{ steps.select.outputs.$output }}" <<<"$selection_job" ||
    fail "deploy selection does not expose $output"
done

[[ "$(grep -Fc "if: \${{ needs.deploy-selection.outputs.deploy_dev == 'true' }}" \
  "$WORKFLOW")" -eq 1 ]] ||
  fail "all-unaffected selection does not skip the combined runtime build/publication"

build_job="$(sed -n '/^  build-publish-runtime-images:/,$p' "$WORKFLOW")"
grep -Fq '    runs-on: ci-protected' <<<"$build_job" ||
  fail "runtime set does not build and publish on the protected CI tier"
[[ "$(grep -Fc '    enable-openid-connect: true' "$WORKFLOW")" -eq 2 ]] ||
  fail "Dev workflow does not confine OIDC to selection and publication"
grep -Fq '    enable-openid-connect: true' <<<"$build_job" ||
  fail "protected runtime transaction cannot mint just-in-time identities"
grep -Fq '    timeout-minutes: 110' <<<"$build_job" ||
  fail "runtime set exceeds the protected runner lifetime"
grep -Fq '        run: scripts/ci/images/build-push-runtime-images.sh' <<<"$build_job" ||
  fail "runtime set does not use the bounded shared-builder entrypoint"
# The shared protected compiler cache is best effort: the selector's step
# output admits exactly r2 or the job-local fallback, and nothing else.
# shellcheck disable=SC2016 # Match the literal workflow expression.
grep -Fxq "          CODEWIRE_SCCACHE_MODE: \${{ steps.compiler-cache.outputs.mode == 'r2' && 'r2' || 'local' }}" \
  <<<"$build_job" ||
  fail "protected runtime build does not select the shared protected compiler cache with a local fallback"
[[ "$(grep -Fc 'CODEWIRE_SCCACHE_MODE:' <<<"$build_job")" -eq 1 ]] ||
  fail "protected runtime build fixes its compiler-cache mode outside the fail-open selector"
# shellcheck disable=SC2016 # Match the literal workflow environment.
grep -Fq '          SCCACHE_BUCKET: example-ci-cache-protected' <<<"$build_job" ||
  fail "protected runtime build does not use the dedicated protected cache bucket"
# shellcheck disable=SC2016 # Match the literal workflow environment.
grep -Fq '          CODEWIRE_SCCACHE_PREFIX: protected/codewire/v1' <<<"$build_job" ||
  fail "protected runtime build does not stay below the protected cache prefix"
# shellcheck disable=SC2016 # Match the literal workflow environment.
grep -Fq '          CODEWIRE_SCCACHE_CREDENTIALS_FILE: ${{ runner.temp }}/codewire-sccache-r2-protected.aws' \
  <<<"$build_job" ||
  fail "protected runtime build does not receive its private cache credential file"
grep -Fq '      - name: Select the protected R2 compiler cache' <<<"$build_job" ||
  fail "protected runtime build does not select its compiler cache"
grep -Fq '          scripts/ci/setup/select-protected-rust-cache.sh \' <<<"$build_job" ||
  fail "protected runtime build does not fetch its job-scoped cache credential through the fail-open selector"
# shellcheck disable=SC2016 # Match the literal workflow command.
grep -Fq '            "$RUNNER_TEMP/codewire-sccache-r2-protected.aws"' <<<"$build_job" ||
  fail "protected runtime build does not keep its cache credential below RUNNER_TEMP"
if grep -Fq 'scripts/ci/setup/fetch-openbao-sccache-r2-protected-credentials.sh' <<<"$build_job"; then
  fail "protected runtime build fetches its cache credential outside the fail-open selector"
fi
cache_steps="$(grep -E '^      - name: ' <<<"$build_job" | sed -n '1,3p')"
[[ "$cache_steps" == "$(printf '%s\n' \
    '      - name: Select the protected R2 compiler cache' \
    '      - name: Build and push the exact runtime image set' \
    '      - name: Remove the protected R2 compiler-cache credential')" ]] ||
  fail "protected cache credential is not selected before, and removed right after, the build"
cleanup_step="$(awk '
  /^      - name: / { capture = ($0 == "      - name: Remove the protected R2 compiler-cache credential") }
  capture { print }
' <<<"$build_job")"
# shellcheck disable=SC2016 # Match the literal workflow expression.
grep -Fxq '        if: ${{ always() }}' <<<"$cleanup_step" ||
  fail "protected cache credential removal is not unconditional"
if grep -Fq 'scripts/ci/setup/fetch-openbao-sccache-r2-credentials.sh' <<<"$build_job"; then
  fail "protected runtime build consumes the untrusted cache credential"
fi
if grep -Fq 'example-ci-cache-untrusted' <<<"$build_job"; then
  fail "protected runtime build consumes the disposable untrusted cache bucket"
fi
grep -Fq 'shred -u -- "$RUNNER_TEMP/codewire-sccache-r2-protected.aws"' <<<"$build_job" ||
  fail "protected runtime build does not remove its cache credential"
# shellcheck disable=SC2016 # Match the literal gated workflow environment.
grep -Fq "          CODEWIRE_RUNTIME_CARRY_FORWARD: '0'" <<<"$build_job" ||
  fail "runtime carry-forward must stay gated until codewire/deploy accepts carried provenance"
# shellcheck disable=SC2016 # Match the literal workflow expression.
grep -Fq '          CODEWIRE_DEPLOY_BASELINE_SHA: ${{ needs.deploy-selection.outputs.baseline_sha }}' \
  <<<"$build_job" ||
  fail "runtime build does not receive the planner-certified deployed baseline"
for family in DASHBOARD DERP DAEMON SERVICES MESH; do
  lc="$(tr 'A-Z' 'a-z' <<<"$family")"
  # shellcheck disable=SC2016 # Match the literal workflow expression.
  grep -Fq "          CODEWIRE_IMAGE_STATE_${family}: \${{ needs.deploy-selection.outputs.${lc}_image_state }}" \
    <<<"$build_job" ||
    fail "runtime build does not receive the trusted ${lc} planner state"
done
[[ "$(grep -Fc 'scripts/ci/images/sign-runtime-image-set.sh' <<<"$build_job")" -eq 2 ]] ||
  fail "runtime workflow does not sign the Harbor set and GHCR mirror exactly once each"
for family in DASHBOARD DERP DAEMON SERVICES MESH; do
  lc="$(tr 'A-Z' 'a-z' <<<"$family")"
  # shellcheck disable=SC2016 # Match the literal workflow expression.
  [[ "$(grep -Fc "          CODEWIRE_BUILT_FROM_${family}: \${{ steps.build.outputs.${lc}_built_from }}" <<<"$build_job")" -eq 2 ]] ||
    fail "runtime signing does not receive the exact ${lc} built-from source for both registries"
done
[[ "$(grep -Fc '          CODEWIRE_DEPLOY_BASELINE_SHA:' <<<"$build_job")" -eq 3 ]] ||
  fail "certified deployed baseline does not reach the build and both signing steps"
if grep -Fq 'scripts/ci/verify/kind-e2e.sh' <<<"$build_job"; then
  fail "protected delivery duplicates the locally required Kind gate"
fi
for family in dashboard derp daemon services mesh; do
  # shellcheck disable=SC2016
  [[ "$(grep -Fc "\${{ steps.build.outputs.${family}_candidate_ref }}" <<<"$build_job")" -eq 1 ]] ||
    fail "runtime bundle construction does not consume the exact $family candidate once"
done
if grep -Eq '^  (build-(daemon-image|dashboard-image|derp|services-image|mesh-image)|publish-runtime-images):' "$WORKFLOW"; then
  fail "runtime products still allocate independent protected workers"
fi

bash -n "$RUNTIME_BUILDER"
[[ -x "$RUNTIME_BUILDER" ]] || fail "runtime image-set builder is not executable"
[[ "$(grep -Ec '^build_one (dashboard|derp|daemon|mesh|services) ' "$RUNTIME_BUILDER")" -eq 5 ]] ||
  fail "runtime image-set builder does not build exactly five separate product targets"
grep -Fq "'  max-parallelism = 2'" "$RUNTIME_BUILDER" ||
  fail "runtime image-set builder lacks the CPX42 memory bound"
# shellcheck disable=SC2016 # Match the literal runtime-builder assignment.
grep -Fq 'CODEWIRE_EXTERNAL_BUILDX_BUILDER="$builder"' "$RUNTIME_BUILDER" ||
  fail "runtime image-set builder does not share its transient BuildKit daemon"
grep -Fq 'Protected runtime builds may use only the protected R2 compiler-cache prefix' \
  "$RUNTIME_BUILDER" || fail "protected runtime build does not confine the shared cache to its protected prefix"
grep -Fq 'Protected runtime builds may use only job-local, disabled, or protected-prefix R2 sccache' \
  "$RUNTIME_BUILDER" || fail "protected runtime build does not reject unknown compiler-cache modes"
grep -Fq 'Protected runtime builds may use only the protected R2 compiler-cache bucket' \
  "$RUNTIME_BUILDER" || fail "protected runtime build does not confine the shared cache to its protected bucket"

publish_job="$build_job"
grep -Fq 'OPENBAO_GHCR_ROLE: codewire-source-dev-publisher' \
  <<<"$build_job" || fail "runtime publisher lacks its exact OpenBao GHCR role"
grep -Fq 'OPENBAO_GHCR_AUDIENCE: openbao-codewire-source-dev-publisher' \
  <<<"$build_job" || fail "runtime publisher lacks its exact OpenBao GHCR audience"
if grep -Fq 'GHCR_PUBLISH_USERNAME:' "$WORKFLOW"; then
  fail "runtime publisher retains a split Forgejo GHCR username"
fi
[[ "$(grep -Fc 'scripts/ci/images/publish-image-to-harbor.sh' <<<"$publish_job")" -eq 2 ]] ||
  fail "runtime publisher does not publish the bundle and pinned defaults to Harbor"
# shellcheck disable=SC2016
grep -Fq -- '--runtime-bundle "$bundle"' <<<"$publish_job" ||
  fail "runtime publisher does not consume the validated bundle"
grep -Fq 'scripts/ci/images/publish-image-to-harbor.sh --pinned-defaults' <<<"$publish_job" ||
  fail "runtime publisher does not keep the compiled-in default digests in Harbor"
[[ "$(grep -Fc 'scripts/ci/images/publish-image-to-ghcr.sh' <<<"$publish_job")" -eq 1 ]] ||
  fail "runtime publisher does not mirror the bundle to GHCR exactly once"
if grep -Fq 'outputs.source_sha' <<<"$publish_job"; then
  fail "runtime publisher duplicates the immutable workflow source through job outputs"
fi
validation_line="$(grep -n 'scripts/ci/images/image-bundle.py create' <<<"$publish_job" | cut -d: -f1)"
first_copy_line="$(grep -n 'scripts/ci/images/publish-image-to-harbor.sh' <<<"$publish_job" | head -1 | cut -d: -f1)"
last_copy_line="$(grep -n 'scripts/ci/images/publish-image-to-harbor.sh' <<<"$publish_job" | tail -1 | cut -d: -f1)"
signer_line="$(grep -n 'scripts/ci/images/sign-runtime-image-set.sh' <<<"$publish_job" | head -1 | cut -d: -f1)"
canonical_line="$(grep -n 'canonical_main_sha=' <<<"$publish_job" | cut -d: -f1)"
dispatch_line="$(grep -n 'scripts/ci/deploy/dispatch-deploy-dev.sh' <<<"$publish_job" | cut -d: -f1)"
ghcr_mirror_line="$(grep -n 'scripts/ci/images/publish-image-to-ghcr.sh' <<<"$publish_job" | cut -d: -f1)"
ghcr_signer_line="$(grep -n 'sign-runtime-image-set.sh --ghcr-mirror' <<<"$publish_job" | cut -d: -f1)"
[[ -n "$validation_line" && -n "$first_copy_line" && "$validation_line" -lt "$first_copy_line" ]] ||
  fail "complete runtime bundle validation does not precede Harbor copies"
[[ -n "$last_copy_line" && -n "$signer_line" && "$last_copy_line" -lt "$signer_line" ]] ||
  fail "runtime signing does not follow every Harbor copy"
[[ -n "$signer_line" && -n "$canonical_line" && -n "$dispatch_line" \
  && "$signer_line" -lt "$canonical_line" && "$canonical_line" -lt "$dispatch_line" ]] ||
  fail "deploy dispatch does not follow signing and canonical-head verification"
[[ -n "$ghcr_mirror_line" && -n "$ghcr_signer_line" \
  && "$dispatch_line" -lt "$ghcr_mirror_line" && "$ghcr_mirror_line" -lt "$ghcr_signer_line" ]] ||
  fail "the GHCR mirror does not follow the deploy dispatch"
# The GHCR mirror must never gate delivery: both mirror steps continue on error.
mirror_steps="$(awk '
  /^      - name: / { capture = ($0 ~ /GHCR/) }
  capture { print }
' <<<"$publish_job")"
[[ "$(grep -c '^      - name: ' <<<"$mirror_steps")" -eq 2 ]] ||
  fail "expected exactly two GHCR mirror steps"
[[ "$(grep -c '^        continue-on-error: true$' <<<"$mirror_steps")" -eq 2 ]] ||
  fail "a GHCR mirror step can fail delivery"
if awk '/^      - name: / { capture = ($0 !~ /GHCR/) } capture' <<<"$publish_job" \
    | grep -q 'continue-on-error'; then
  fail "a delivery step outside the GHCR mirror continues on error"
fi
[[ "$(grep -Fc '            --candidate ' <<<"$publish_job")" -eq 5 ]] ||
  fail "runtime validation does not contain exactly five image candidates"
# shellcheck disable=SC2016
grep -Fq '"${RUNNER_TEMP:?}/codewire-dev-image-bundle.json"' <<<"$publish_job" ||
  fail "runtime signer does not consume the exact validated image bundle"
grep -Fq 'scripts/ci/trust/codewire-runtime-signing.pub' <<<"$publish_job" ||
  fail "runtime signer does not use the tracked public trust root"
bash -n "$RUNTIME_SIGNER"
[[ -x "$RUNTIME_SIGNER" ]] || fail "runtime signer is not executable"
openssl pkey -pubin -in "$RUNTIME_PUBLIC_KEY" -pubcheck -noout >/dev/null 2>&1 ||
  fail "tracked runtime signing public key is invalid"
[[ "$(openssl pkey -pubin -in "$RUNTIME_PUBLIC_KEY" -outform DER | sha256sum | cut -d' ' -f1)" == \
  64d7ac8c85493f8b600047ab27c48cb2bed516c94c25d5a532dafc3bf611bcff ]] ||
  fail "tracked runtime signing public key changed unexpectedly"
if grep -Fq 'promote-image-bundle.sh' <<<"$publish_job"; then
  fail "source workflow retains the retired deploy-writing promotion wrapper"
fi
for family in dashboard derp daemon services mesh; do
  grep -Fq -- "--candidate $family \"\$GITHUB_SHA\"" <<<"$publish_job" ||
    fail "runtime bundle omits $family"
done
if grep -Fq 'secrets.' <<<"$publish_job"; then
  fail "runtime publisher bypasses the reviewed credential handoff"
fi
for retired_dev_control in \
  '^  aggregate-image-promotion:' \
  '^  deploy-dev:' \
  'CODEWIRE_DEPLOY_PROMOTION_ENABLED' \
  'CODEWIRE_DEPLOY_OBSERVER_ENABLED' \
  'codewire-dev-promotion-receipt' \
  'gitea-upload-artifact' \
  'gitea-download-artifact' \
  'scripts/ci/deploy-dev.sh' \
  'scripts/ci/promote-image-bundle.sh'; do
  if grep -Eq "$retired_dev_control" "$WORKFLOW"; then
    fail "retired dev writer or observer remains in the source workflow: $retired_dev_control"
  fi
done

if grep -Fq '  dispatch-deploy-dev:' "$WORKFLOW"; then
  fail "deploy dispatch retains a second credential-bearing runner job"
fi
if grep -Fq 'CODEWIRE_DEPLOY_PROMOTION_TOKEN' "$WORKFLOW"; then
  fail "Dev delivery retains the retired static deploy credential"
fi
for dev_dispatch_source in \
  "$ROOT/scripts/ci/deploy/dispatch-deploy-dev.sh" \
  "$ROOT/scripts/ci/deploy/resolve-deployed-source.sh" \
  "$ROOT/scripts/ci/setup/fetch-forgejo-deploy-dev-token.sh"; do
  if grep -Fq 'CODEWIRE_DEPLOY_PROMOTION_TOKEN' "$dev_dispatch_source"; then
    fail "Dev dispatch source retains the retired static deploy credential"
  fi
done
# shellcheck disable=SC2016
grep -Fq 'scripts/ci/deploy/dispatch-deploy-dev.sh "${GITHUB_SHA:?}"' <<<"$build_job" ||
  fail "deploy dispatch sends anything other than the workflow source SHA"
grep -Fq 'return_run_info:true' "$ROOT/scripts/ci/deploy/dispatch-deploy-dev.sh" ||
  fail "Dev dispatch does not request its exact Forgejo run ID"
if grep -Fq 'wait-for-deploy-run.sh' "$ROOT/scripts/ci/deploy/dispatch-deploy-dev.sh"; then
  fail "Dev dispatch holds a source runner while the downstream run needs capacity"
fi
[[ ! -e "$ROOT/scripts/ci/deploy/wait-for-deploy-run.sh" ]] ||
  fail "retired source-runner deploy poller remains"
if grep -Eq 'candidate_ref|image_digest|deploy_commit|promotion-receipt' \
  "$ROOT/scripts/ci/deploy/dispatch-deploy-dev.sh"; then
  fail "source-to-deploy dispatch carries deployment state beyond the source SHA"
fi
# shellcheck disable=SC2016
if grep -Fq '$imagepolicy' \
  "$DEV_KUSTOMIZATION" "$DEV_CONFIG_IMAGES" "$DEV_MESH_RELEASE"; then
  fail "retired dev image-automation setter marker remains in source manifests"
fi
grep -Fq 'name: git.example.com/codewire/dashboard' "$DEV_KUSTOMIZATION" ||
  fail "dev workload render input was removed with its setter marker"
grep -Fq 'SANDBOX_DAEMON_IMAGE:' "$DEV_CONFIG_IMAGES" ||
  fail "dev daemon render input was removed with its setter marker"
grep -Fq 'name: codewire-mesh' "$DEV_MESH_RELEASE" ||
  fail "dev Mesh render input was removed with its setter marker"

assert_mesh_database_input() {
  local label="$1"
  local block="$2"
  grep -Eq '^[[:space:]]+enabled: true$' <<<"$block" ||
    fail "$label does not enable the dedicated Mesh database"
  grep -Eq '^[[:space:]]+secretName: ("?codewire-mesh-db-app"?)$' <<<"$block" ||
    fail "$label does not reference the CNPG Mesh app Secret"
  grep -Eq '^[[:space:]]+uriKey: ("?uri"?)$' <<<"$block" ||
    fail "$label does not select the CNPG URI key"
}

mesh_release_database="$(sed -n '/^    database:$/,/^    mesh:$/p' "$DEV_MESH_RELEASE")"
mesh_values_database="$(sed -n '/^database:$/,/^mesh:$/p' "$DEV_MESH_VALUES")"
assert_mesh_database_input "dev Mesh HelmRelease" "$mesh_release_database"
assert_mesh_database_input "dev Mesh values" "$mesh_values_database"

assert_mesh_authorization_input() {
  local label="$1"
  local block="$2"
  grep -Eq '^[[:space:]]+url: "?https://codewire-orchestration\.dev\.svc\.cluster\.local:8088"?$' <<<"$block" ||
    fail "$label does not target the internal primary authorization TLS listener"
  grep -Eq '^[[:space:]]+tlsRootsConfigMap: "?codewire-orchestration-internal-roots"?$' <<<"$block" ||
    fail "$label does not verify the internal listener with its public roots"
  grep -Eq '^[[:space:]]+name: "?codewire-secrets"?$' <<<"$block" ||
    fail "$label does not use the existing HMAC Secret"
  grep -Eq '^[[:space:]]+key: "?SESSION_SECRET"?$' <<<"$block" ||
    fail "$label does not select the scoped HMAC key"
}

mesh_release_authorization="$(sed -n '/^    meshAuthorization:$/,/^    mesh:$/p' "$DEV_MESH_RELEASE")"
mesh_values_authorization="$(sed -n '/^meshAuthorization:$/,/^mesh:$/p' "$DEV_MESH_VALUES")"
assert_mesh_authorization_input "dev Mesh HelmRelease" "$mesh_release_authorization"
assert_mesh_authorization_input "dev Mesh values" "$mesh_values_authorization"

assert_mesh_transport_input() {
  local label="$1" block="$2"
  grep -Eq '^[[:space:]]+baseURL: "?https://mesh\.codewire-dev\.sh"?$' <<<"$block" ||
    fail "$label does not select the Dev Mesh API"
  grep -Eq '^[[:space:]]+derpURL: "?https://derp\.codewire-dev\.sh"?$' <<<"$block" ||
    fail "$label must advertise the separate Dev DERP relay, not the Mesh API"
}

assert_mesh_transport_input "dev Mesh HelmRelease" \
  "$(sed -n '/^    mesh:$/,/^    ingress:$/p' "$DEV_MESH_RELEASE")"
assert_mesh_transport_input "dev Mesh values" \
  "$(sed -n '/^mesh:$/,/^ingress:$/p' "$DEV_MESH_VALUES")"

# Render the actual chart: source values alone do not prove the process receives
# them. Helm is already a sealed prerequisite of the selected deploy verifier.
dev_mesh_transport="$(helm template codewire-mesh-dev "$MESH_CHART" \
  -f "$DEV_MESH_VALUES" --show-only templates/deployment.yaml)"
[[ "$(grep -Fc -- '--derp-url=' <<<"$dev_mesh_transport")" == 1 &&
   "$(grep -Fc -- '- "--derp-url=https://derp.codewire-dev.sh"' <<<"$dev_mesh_transport")" == 1 ]] ||
  fail "Dev Mesh does not receive exactly one separate DERP relay argument"
default_mesh_transport="$(helm template test "$MESH_CHART" \
  --set mesh.baseURL=https://mesh.example.test --show-only templates/deployment.yaml)"
if grep -Fq -- '--derp-url' <<<"$default_mesh_transport"; then
  fail "an unselected chart relay must not render an empty DERP override"
fi

printf '[test-deploy-dev] SHA-only dispatch contract passed\n'
