#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly WORKFLOW="$ROOT/.gitea/workflows/deploy-dev.yaml"
readonly LEGACY_GITHUB_GATEWAY_WORKFLOW="$ROOT/.github/workflows/build-gateway-image.yml"
readonly DEV_KUSTOMIZATION="$ROOT/deployments/k8s/overlays/dev/kustomization.yaml"
readonly DEV_CONFIG_IMAGES="$ROOT/deployments/k8s/overlays/dev/config-images.yaml"
readonly DEV_MESH_RELEASE="$ROOT/deployments/k8s/flux/mesh-dev/helmrelease.yaml"
readonly DEV_MESH_VALUES="$ROOT/deployments/k8s/mesh-dev/values.yaml"

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

selection_job="$(sed -n '/^  deploy-selection:/,/^  build-gateway-image:/p' "$WORKFLOW")"
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
select_step="$(sed -n '/      - name: Plan and select atomic Dev deployment/,/^  build-gateway-image:/p' \
  <<<"$selection_job")"
if grep -Fq 'secrets.' <<<"$select_step"; then
  fail "artifact classifier receives the private deploy credential"
fi
grep -Fq "if: \${{ always() }}" <<<"$selection_job" ||
  fail "untrusted deployed-source candidate is not cleaned up unconditionally"
grep -Fq "rm -f -- \"\$RUNNER_TEMP/codewire-deployed-source-candidate.json\"" \
  <<<"$selection_job" || fail "untrusted deployed-source candidate cleanup is missing"
for output in deploy_dev reason matched_categories \
  dashboard_image_state gateway_image_state derp_image_state services_image_state mesh_image_state \
  baseline_sha head_sha head_tree ci_plan_sha256 ci_policy_sha256 baseline_valid; do
  # shellcheck disable=SC2016
  grep -Fq "$output: \${{ steps.select.outputs.$output }}" <<<"$selection_job" ||
    fail "deploy selection does not expose $output"
done

[[ "$(grep -Fc "if: \${{ needs.deploy-selection.outputs.deploy_dev == 'true' }}" \
  "$WORKFLOW")" -eq 6 ]] ||
  fail "all-unaffected selection does not skip all five builds and runtime publication"

publish_job="$(sed -n '/^  publish-runtime-images:/,/^  dispatch-deploy-dev:/p' "$WORKFLOW")"
grep -Fq "if: \${{ needs.deploy-selection.outputs.deploy_dev == 'true' }}" \
  <<<"$publish_job" || fail "all-unaffected selection does not skip runtime publication"
grep -Fq 'OPENBAO_GHCR_ROLE: codewire-source-dev-ghcr-publisher' \
  "$WORKFLOW" || fail "runtime publisher lacks its exact OpenBao GHCR role"
grep -Fq 'OPENBAO_GHCR_AUDIENCE: openbao-codewire-source-dev-ghcr-publisher' \
  "$WORKFLOW" || fail "runtime publisher lacks its exact OpenBao GHCR audience"
if grep -Fq 'GHCR_PUBLISH_USERNAME:' "$WORKFLOW"; then
  fail "runtime publisher retains a split Forgejo GHCR username"
fi
[[ "$(grep -Fc 'scripts/ci/images/publish-image-to-ghcr.sh' <<<"$publish_job")" -eq 5 ]] ||
  fail "runtime publisher does not copy exactly five image families"
if grep -Fq 'outputs.source_sha' <<<"$publish_job"; then
  fail "runtime publisher duplicates the immutable workflow source through job outputs"
fi
# shellcheck disable=SC2016
[[ "$(grep -Fc '"$GITHUB_SHA"' <<<"$publish_job")" -eq 11 ]] ||
  fail "bundle validation and five exact copies do not share one workflow source SHA"
validation_line="$(grep -n 'scripts/ci/images/image-bundle.py create' <<<"$publish_job" | cut -d: -f1)"
first_copy_line="$(grep -n 'scripts/ci/images/publish-image-to-ghcr.sh' <<<"$publish_job" | head -1 | cut -d: -f1)"
[[ -n "$validation_line" && -n "$first_copy_line" && "$validation_line" -lt "$first_copy_line" ]] ||
  fail "complete runtime bundle validation does not precede GHCR copies"
[[ "$(grep -Fc '            --candidate ' <<<"$publish_job")" -eq 5 ]] ||
  fail "runtime validation does not contain exactly five image candidates"
if grep -Fq 'promote-image-bundle.sh' <<<"$publish_job"; then
  fail "source workflow retains the retired deploy-writing promotion wrapper"
fi
for family in dashboard derp gateway services mesh; do
  grep -Fq "ghcr.io/codewiresh/$family" <<<"$publish_job" ||
    fail "runtime publisher omits $family"
done
if grep -Fq 'secrets.' <<<"$publish_job"; then
  fail "runtime publisher bypasses the Infisical credential handoff"
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

dispatch_job="$(sed -n '/^  dispatch-deploy-dev:/,$p' "$WORKFLOW")"
grep -Fq '  dispatch-deploy-dev:' <<<"$dispatch_job" ||
  fail "SHA-only deploy dispatch job is missing"
grep -Fq '    runs-on: untrusted-validation' <<<"$dispatch_job" ||
  fail "deploy dispatch does not use the live non-privileged validation profile"
grep -Fq '    timeout-minutes: 15' <<<"$dispatch_job" ||
  fail "deploy dispatch can outlive the validation runner deadline"
grep -Fq '      - publish-runtime-images' <<<"$dispatch_job" ||
  fail "deploy dispatch can run before exact GHCR publication"
grep -Fq "needs.publish-runtime-images.result == 'success'" <<<"$dispatch_job" ||
  fail "deploy dispatch does not require successful exact GHCR publication"
grep -Fq "github.ref == 'refs/heads/main'" <<<"$dispatch_job" ||
  fail "deploy dispatch is not restricted to canonical main"
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
grep -Fq 'enable-openid-connect: true' "$WORKFLOW" ||
  fail "Dev delivery cannot request its short-lived Authorized Integration JWT"
# shellcheck disable=SC2016
grep -Fq 'scripts/ci/deploy/dispatch-deploy-dev.sh "${GITHUB_SHA:?}"' <<<"$dispatch_job" ||
  fail "deploy dispatch sends anything other than the workflow source SHA"
grep -Fq 'return_run_info:true' "$ROOT/scripts/ci/deploy/dispatch-deploy-dev.sh" ||
  fail "Dev dispatch does not request its exact Forgejo run ID"
if grep -Fq 'wait-for-deploy-run.sh' "$ROOT/scripts/ci/deploy/dispatch-deploy-dev.sh"; then
  fail "Dev dispatch holds a source runner while the downstream run needs capacity"
fi
[[ ! -e "$ROOT/scripts/ci/deploy/wait-for-deploy-run.sh" ]] ||
  fail "retired source-runner deploy poller remains"
if grep -Eq 'candidate_ref|image_digest|deploy_commit|promotion-receipt' \
  <<<"$dispatch_job"; then
  fail "source-to-deploy dispatch carries deployment state beyond the source SHA"
fi
# shellcheck disable=SC2016
if grep -Fq '$imagepolicy' \
  "$DEV_KUSTOMIZATION" "$DEV_CONFIG_IMAGES" "$DEV_MESH_RELEASE"; then
  fail "retired dev image-automation setter marker remains in source manifests"
fi
grep -Fq 'name: git.example.com/codewire/dashboard' "$DEV_KUSTOMIZATION" ||
  fail "dev workload render input was removed with its setter marker"
grep -Fq 'SANDBOX_GATEWAY_IMAGE:' "$DEV_CONFIG_IMAGES" ||
  fail "dev gateway render input was removed with its setter marker"
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
  grep -Eq '^[[:space:]]+url: "?http://codewire-orchestration\.dev\.svc\.cluster\.local:8085"?$' <<<"$block" ||
    fail "$label does not target the internal primary authorization listener"
  grep -Eq '^[[:space:]]+name: "?codewire-secrets"?$' <<<"$block" ||
    fail "$label does not use the existing HMAC Secret"
  grep -Eq '^[[:space:]]+key: "?SESSION_SECRET"?$' <<<"$block" ||
    fail "$label does not select the scoped HMAC key"
}

mesh_release_authorization="$(sed -n '/^    meshAuthorization:$/,/^    mesh:$/p' "$DEV_MESH_RELEASE")"
mesh_values_authorization="$(sed -n '/^meshAuthorization:$/,/^mesh:$/p' "$DEV_MESH_VALUES")"
assert_mesh_authorization_input "dev Mesh HelmRelease" "$mesh_release_authorization"
assert_mesh_authorization_input "dev Mesh values" "$mesh_values_authorization"

printf '[test-deploy-dev] SHA-only dispatch contract passed\n'
