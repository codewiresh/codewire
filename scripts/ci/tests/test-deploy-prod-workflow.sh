#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly WORKFLOW="$ROOT/.gitea/workflows/deploy-prod.yaml"

fail() {
  printf '[test-deploy-prod-workflow] ERROR: %s\n' "$*" >&2
  exit 1
}

bash -n "$0"

grep -Fq 'OPENBAO_GHCR_ROLE: codewire-source-prod-publisher' \
  "$WORKFLOW" || fail "production publisher lacks its exact OpenBao GHCR role"
grep -Fq 'OPENBAO_GHCR_AUDIENCE: openbao-codewire-source-prod-publisher' \
  "$WORKFLOW" || fail "production publisher lacks its exact OpenBao GHCR audience"
if grep -Fq 'GHCR_PUBLISH_USERNAME:' "$WORKFLOW"; then
  fail "production publisher retains a split Forgejo GHCR username"
fi

publish_job="$(sed -n '/^  publish-runtime-images:/,/^  dispatch-deploy-prod:/p' "$WORKFLOW")"
[[ "$(grep -Fc 'scripts/ci/images/image-bundle.py create' <<<"$publish_job")" -eq 1 ]] ||
  fail "production must validate exactly one complete runtime candidate set"
[[ "$(grep -Fc '            --candidate ' <<<"$publish_job")" -eq 5 ]] ||
  fail "production validation must contain exactly five image candidates"
grep -Fq -- '--environment prod' <<<"$publish_job" ||
  fail "production candidate validation lost its explicit environment"
# shellcheck disable=SC2016
grep -Fq -- '--source-sha "$SOURCE_SHA"' <<<"$publish_job" ||
  fail "production candidate validation is not bound to the selected source"
validation_line="$(grep -n 'scripts/ci/images/image-bundle.py create' <<<"$publish_job" | cut -d: -f1)"
first_copy_line="$(grep -n 'scripts/ci/images/publish-image-to-ghcr.sh' <<<"$publish_job" | head -1 | cut -d: -f1)"
[[ -n "$validation_line" && -n "$first_copy_line" && "$validation_line" -lt "$first_copy_line" ]] ||
  fail "complete production validation does not precede registry publication"

for job in build-gateway-image build-dashboard-image build-derp build-services-image build-mesh-image; do
  grep -Fq "      - $job" <<<"$publish_job" ||
    fail "production aggregate does not require $job"
done
if grep -Fq 'always()' <<<"$publish_job"; then
  fail "production aggregate could run after one-of-five failure"
fi
[[ "$(grep -Fc "          REQUIRE_EXISTING_SOURCE_IMAGE: '1'" "$WORKFLOW")" -eq 5 ]] ||
  fail "production may rebuild instead of requiring all five source-SHA images"
# shellcheck disable=SC2016
[[ "$(grep -Fc '      source_sha: ${{ steps.build.outputs.source_sha }}' "$WORKFLOW")" -eq 5 ]] ||
  fail "all five production runtime jobs must expose source provenance"
# shellcheck disable=SC2016
[[ "$(grep -Fc '      candidate_ref: ${{ steps.build.outputs.candidate_ref }}' "$WORKFLOW")" -eq 5 ]] ||
  fail "all five production runtime jobs must expose digest candidates"
[[ "$(grep -Fc 'scripts/ci/images/publish-image-to-ghcr.sh' "$WORKFLOW")" -eq 7 ]] ||
  fail "production must copy exactly seven image manifests to GHCR"
# shellcheck disable=SC2016
[[ "$(grep -Fc '            "$SOURCE_SHA" "$RELEASE_TAG"' "$WORKFLOW")" -eq 7 ]] ||
  fail "every production image must receive source-SHA and stable SemVer aliases"
for family in base workspace; do
  grep -Fq "            ghcr.io/codewiresh/$family" "$WORKFLOW" ||
    fail "production omits the $family support image"
done

support_job="$(sed -n '/^  publish-support-release-images:/,/^  publish-runtime-images:/p' "$WORKFLOW")"
grep -Fq '    needs: [release-selection]' <<<"$support_job" ||
  fail "support release job must depend only on release selection"
grep -Fq '        id: base' <<<"$support_job" ||
  fail "support release job does not retain the base step output"
grep -Fq '        id: workspace' <<<"$support_job" ||
  fail "support release job does not retain the workspace step output"
# shellcheck disable=SC2016
grep -Fq 'CODEWIRE_BASE_IMAGE_REF: ${{ steps.base.outputs.candidate_ref }}' \
  <<<"$support_job" || fail "workspace does not consume the same-job base digest"
# shellcheck disable=SC2016
grep -Fq '"${{ steps.workspace.outputs.candidate_ref }}"' <<<"$support_job" ||
  fail "publisher does not consume the same-job workspace digest"
if grep -Fq 'needs.build-' <<<"$support_job"; then
  fail "support release publication still crosses a runner job-output boundary"
fi
workspace_line="$(grep -n 'id: workspace' <<<"$support_job" | cut -d: -f1)"
support_copy_line="$(grep -n 'scripts/ci/images/publish-image-to-ghcr.sh' <<<"$support_job" | head -1 | cut -d: -f1)"
[[ -n "$workspace_line" && -n "$support_copy_line" && "$workspace_line" -lt "$support_copy_line" ]] ||
  fail "support release publication can run before the same-job workspace build"

dispatch_job="$(sed -n '/^  dispatch-deploy-prod:/,$p' "$WORKFLOW")"
grep -Fq '      - publish-runtime-images' <<<"$dispatch_job" ||
  fail "production dispatch can run before runtime publication"
grep -Fq '      - publish-support-release-images' <<<"$dispatch_job" ||
  fail "production dispatch can run before support publication"
# shellcheck disable=SC2016
grep -Fq 'run: scripts/ci/deploy/dispatch-deploy-prod.sh "$RELEASE_TAG"' <<<"$dispatch_job" ||
  fail "production dispatch sends more than the signed source tag"
grep -Fq '    runs-on: ci-protected' <<<"$dispatch_job" ||
  fail "production dispatch does not use the protected CI tier"
grep -Fq '    timeout-minutes: 15' <<<"$dispatch_job" ||
  fail "production dispatch can outlive the validation runner deadline"
if grep -Fq 'wait-for-deploy-run.sh' \
  "$ROOT/scripts/ci/deploy/dispatch-deploy-prod.sh"; then
  fail "production dispatch holds a source runner while the downstream run needs capacity"
fi
if grep -Fq 'CODEWIRE_DEPLOY_PROMOTION_TOKEN' "$WORKFLOW"; then
  fail "production dispatch retains the static deploy token"
fi
grep -Fq 'fetch-forgejo-deploy-prod-token.sh' \
  "$ROOT/scripts/ci/deploy/dispatch-deploy-prod.sh" ||
  fail "production dispatch cannot request its short-lived Authorized Integration JWT"

if grep -Eq 'promote-image-bundle|promotion-receipt|gitea-(upload|download)-artifact|CODEWIRE_DEPLOY_PROMOTION_USERNAME|observe-production:|deploy-prod-observer\.sh|setup-kubeconfig|kubectl|helm' "$WORKFLOW"; then
  fail "source production workflow retains desired-state writes, receipts, or cluster observation"
fi

printf '[test-deploy-prod-workflow] signed-tag publication and dispatch contract passed\n'
