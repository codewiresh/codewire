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
# Runs of different commits never cancel or queue behind each other (#2892):
# each commit has its own group, so only a rerun of the same commit queues,
# while leaving the block out would cancel on every push. The selection's
# cancellation step is the only place one delivery stops another.
concurrency_block="$(sed -n '/^concurrency:$/,/^$/p' "$WORKFLOW")"
# shellcheck disable=SC2016 # Match the literal workflow expression.
[[ "$concurrency_block" == $'concurrency:\n  group: deploy-dev-${{ github.sha }}\n  cancel-in-progress: false' ]] ||
  fail "Deploy Dev runs of different commits cancel or queue behind each other"
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

selection_job="$(sed -n '/^  deploy-selection:/,/^  build-service-images:/p' "$WORKFLOW")"
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
select_step="$(sed -n '/      - name: Plan and select atomic Dev deployment/,/^  build-service-images:/p' \
  <<<"$selection_job")"
if grep -Fq 'secrets.' <<<"$select_step"; then
  fail "artifact classifier receives the private deploy credential"
fi
grep -Fq "if: \${{ always() }}" <<<"$selection_job" ||
  fail "untrusted deployed-source candidate is not cleaned up unconditionally"
grep -Fq "rm -f -- \"\$RUNNER_TEMP/codewire-deployed-source-candidate.json\"" \
  <<<"$selection_job" || fail "untrusted deployed-source candidate cleanup is missing"
# Reruns are no recovery path and red CI is fixed forward (#2892): the
# superseded-delivery stop, its 45-minute rule and the ancestor delivery are
# gone, and with them the stale claim that deliveries queue one at a time.
for retired in 'delivery-superseded' 'baseline_committed_at' 'COMMITTED_AT' 'deployed-age' \
    'merge-base --is-ancestor' 'queue one at a time' 'outputs.stopped' \
    'start-check' 'publish-check' 'Skip a superseded commit' 'steps.canonical' \
    'outputs.superseded' 'require-main-head' 'cancel-in-progress: true'; do
  if grep -Fq -- "$retired" "$WORKFLOW"; then
    fail "Deploy Dev retains the retired superseded-delivery path: $retired"
  fi
done
[[ ! -e "$ROOT/scripts/ci/deploy/delivery-superseded.sh" && ! -e "$ROOT/scripts/ci/tests/test-delivery-superseded.sh" ]] ||
  fail "the retired superseded-delivery stop remains in the repository"
[[ ! -e "$ROOT/scripts/ci/deploy/require-main-head.sh" ]] ||
  fail "the retired main-head check remains in the repository"
for output in deploy_dev reason matched_categories \
  dashboard_image_state daemon_image_state derp_image_state services_image_state mesh_image_state \
  baseline_sha head_sha head_tree ci_plan_sha256 ci_policy_sha256 baseline_valid; do
  # shellcheck disable=SC2016
  grep -Fq "$output: \${{ steps.select.outputs.$output }}" <<<"$selection_job" ||
    fail "deploy selection does not expose $output"
done

# Both build halves and the publisher skip an all-unaffected selection; a
# failed or cancelled build skips the publisher too.
[[ "$(grep -Fxc "    if: \${{ needs.deploy-selection.outputs.deploy_dev == 'true' }}" \
  "$WORKFLOW")" -eq 3 ]] ||
  fail "an all-unaffected selection does not skip both runtime builds and publication"

# A newer push cancels an older delivery only once that commit's own main CI
# can no longer verify it, and only before it publishes (#2892); the contract
# of that decision is test-cancel-superseded-deliveries.py. Here: the step
# runs it with the job token, before planning, and it can neither fail nor
# hold up this run's own delivery.
cancel_step="$(awk '
  /^      - / { capture = ($0 == "      - name: Cancel the older deliveries this push supersedes") }
  capture && /^$/ { exit }
  capture { print }
' <<<"$selection_job")"
# shellcheck disable=SC2016 # Match the literal workflow expression.
[[ "$cancel_step" == "$(printf '%s\n' \
    '      - name: Cancel the older deliveries this push supersedes' \
    '        timeout-minutes: 5' \
    '        continue-on-error: true' \
    '        env:' \
    '          GITEA_TOKEN: ${{ github.token }}' \
    '        run: python3 -I -B scripts/ci/deploy/cancel-superseded-deliveries.py')" ]] ||
  fail "the superseded-delivery cancellation step is not the bounded, non-gating script run"
cancel_step_line="$(grep -n -m1 'name: Cancel the older deliveries this push supersedes' <<<"$selection_job" | cut -d: -f1)"
[[ "$toolchain_line" -lt "$cancel_step_line" && "$cancel_step_line" -lt "$classifier_line" ]] ||
  fail "the cancellation step does not run before planning"
# Apart from fail-fast jobs cancelling their own run, the only run
# cancellation anywhere is that script's.
# shellcheck disable=SC2016 # Match the literal workflow expression.
cancel_users="$(grep -rE '/actions/runs/[^ ]*/cancel' "$ROOT/.gitea/workflows" "$ROOT/scripts" |
  grep -vF '/actions/runs/${GITHUB_RUN_ID}/cancel' | grep -v '/tests/' | cut -d: -f1 |
  sed "s|^$ROOT/||" | sort -u)"
[[ "$cancel_users" == 'scripts/ci/deploy/cancel-superseded-deliveries.py' ]] ||
  fail "a run is cancelled outside cancel-superseded-deliveries.py: $cancel_users"

# The runtime set builds in two protected halves on separate workers, joined
# by one publishing job: exactly these four jobs, no per-image workers.
[[ "$(sed -n '/^jobs:$/,$p' "$WORKFLOW" | grep -E '^  [a-z0-9-]+:$' | tr -d ' :' | paste -sd' ')" == \
  'deploy-selection build-service-images build-daemon-image publish-runtime-images' ]] ||
  fail "Dev delivery is not exactly selection, two build halves and one publisher"
service_job="$(sed -n '/^  build-service-images:/,/^  build-daemon-image:/p' "$WORKFLOW")"
daemon_job="$(sed -n '/^  build-daemon-image:/,/^  publish-runtime-images:/p' "$WORKFLOW")"
# The daemon's cw producer is the longest compile; it runs on a 32-CPU metal slot.
grep -Fxq '    runs-on: ci-protected-metal' <<<"$daemon_job" ||
  fail "the daemon image build does not select a metal protected slot"
grep -Fxq '    runs-on: ci-protected' <<<"$service_job" ||
  fail "the service image build left the ordinary protected pool"
publish_job="$(sed -n '/^  publish-runtime-images:/,$p' "$WORKFLOW")"
[[ "$(grep -Fc '    enable-openid-connect: true' "$WORKFLOW")" -eq 4 ]] ||
  fail "Dev workflow does not confine OIDC to selection, the protected builds and publication"
grep -Fxq '    needs: [deploy-selection, build-service-images, build-daemon-image]' <<<"$publish_job" ||
  fail "publication does not wait for both exact build halves"
grep -Fxq '    timeout-minutes: 45' <<<"$publish_job" ||
  fail "publication lacks its bounded protected deadline"

assert_build_half() {
  local half="$1" job="$2" step="$3"
  shift 3
  grep -Fq '    runs-on: ci-protected' <<<"$job" ||
    fail "$half half does not build and push on the protected CI tier"
  grep -Fq '    enable-openid-connect: true' <<<"$job" ||
    fail "$half half cannot mint just-in-time identities"
  grep -Fq '    timeout-minutes: 110' <<<"$job" ||
    fail "$half half exceeds the protected runner lifetime"
  grep -Fxq '    needs: [deploy-selection]' <<<"$job" ||
    fail "$half half does not depend only on the trusted selection"
  grep -Fxq "        run: scripts/ci/images/build-push-runtime-images.sh $half" <<<"$job" ||
    fail "$half half does not use the bounded shared-builder entrypoint"
  # The push path builds and pushes by digest, unsigned (#2892).
  if grep -Eq 'OPENBAO_GHCR_|publish-image-to-|sign-runtime-image-set|dispatch-deploy-dev|main-ci-verdict|require-dev-descent|cancel-superseded|cosign|CODEWIRE_MAIN_CI_RUN' <<<"$job"; then
    fail "$half half publishes, signs, dispatches or reads main CI outside the publishing job"
  fi
  # The shared protected compiler cache is best effort: the selector's step
  # output admits exactly r2 or the job-local fallback, and nothing else.
  # shellcheck disable=SC2016 # Match the literal workflow expression.
  grep -Fxq "          CODEWIRE_SCCACHE_MODE: \${{ steps.compiler-cache.outputs.mode == 'r2' && 'r2' || 'local' }}" \
    <<<"$job" ||
    fail "$half half does not select the shared protected compiler cache with a local fallback"
  [[ "$(grep -Fc 'CODEWIRE_SCCACHE_MODE:' <<<"$job")" -eq 1 ]] ||
    fail "$half half fixes its compiler-cache mode outside the fail-open selector"
  grep -Fq '          SCCACHE_BUCKET: example-ci-cache-protected' <<<"$job" ||
    fail "$half half does not use the dedicated protected cache bucket"
  grep -Fq '          CODEWIRE_SCCACHE_PREFIX: protected/codewire/v1' <<<"$job" ||
    fail "$half half does not stay below the protected cache prefix"
  # shellcheck disable=SC2016 # Match the literal workflow environment.
  grep -Fq '          CODEWIRE_SCCACHE_CREDENTIALS_FILE: ${{ runner.temp }}/codewire-sccache-r2-protected.aws' \
    <<<"$job" ||
    fail "$half half does not receive its private cache credential file"
  # shellcheck disable=SC2016 # Match the literal workflow command.
  grep -Fq '            "$RUNNER_TEMP/codewire-sccache-r2-protected.aws"' <<<"$job" ||
    fail "$half half does not keep its cache credential below RUNNER_TEMP"
  grep -Fq '          scripts/ci/setup/select-protected-rust-cache.sh \' <<<"$job" ||
    fail "$half half does not fetch its job-scoped cache credential through the fail-open selector"
  if grep -Fq 'scripts/ci/setup/fetch-openbao-sccache-r2-protected-credentials.sh' <<<"$job"; then
    fail "$half half fetches its cache credential outside the fail-open selector"
  fi
  [[ "$(grep -E '^      - name: ' <<<"$job")" == "$(printf '%s\n' \
      '      - name: Select the protected R2 compiler cache' \
      "      - name: $step" \
      '      - name: Remove the protected R2 compiler-cache credential')" ]] ||
    fail "$half half does not select its cache credential before, and remove it right after, the build"
  # shellcheck disable=SC2016 # Match the literal workflow expression.
  awk '
    /^      - name: / { capture = ($0 == "      - name: Remove the protected R2 compiler-cache credential") }
    capture { print }
  ' <<<"$job" | grep -Fxq '        if: ${{ always() }}' ||
    fail "$half half does not remove its cache credential unconditionally"
  # shellcheck disable=SC2016 # Match the literal workflow command.
  grep -Fq 'shred -u -- "$RUNNER_TEMP/codewire-sccache-r2-protected.aws"' <<<"$job" ||
    fail "$half half does not remove its cache credential"
  if grep -Fq 'scripts/ci/setup/fetch-openbao-sccache-r2-credentials.sh' <<<"$job" \
      || grep -Fq 'example-ci-cache-untrusted' <<<"$job"; then
    fail "$half half consumes the untrusted cache"
  fi
  grep -Fq "          CODEWIRE_RUNTIME_CARRY_FORWARD: '0'" <<<"$job" ||
    fail "$half half carry-forward must stay gated until codewire/deploy accepts carried provenance"
  # shellcheck disable=SC2016 # Match the literal workflow expression.
  grep -Fq '          CODEWIRE_DEPLOY_BASELINE_SHA: ${{ needs.deploy-selection.outputs.baseline_sha }}' \
    <<<"$job" || fail "$half half does not receive the planner-certified deployed baseline"
  if grep -Fq 'scripts/ci/verify/kind-e2e.sh' <<<"$job"; then
    fail "$half half duplicates the locally required Kind gate"
  fi
  local family upper
  for family in dashboard derp daemon services mesh; do
    upper="$(tr 'a-z' 'A-Z' <<<"$family")"
    if [[ " $* " == *" $family "* ]]; then
      # shellcheck disable=SC2016 # Match the literal workflow expression.
      grep -Fq "          CODEWIRE_IMAGE_STATE_${upper}: \${{ needs.deploy-selection.outputs.${family}_image_state }}" \
        <<<"$job" || fail "$half half does not receive the trusted $family planner state"
      for output in candidate_ref built_from; do
        # shellcheck disable=SC2016 # Match the literal workflow expression.
        grep -Fxq "      ${family}_${output}: \${{ steps.build.outputs.${family}_${output} }}" <<<"$job" ||
          fail "$half half does not expose its exact $family $output"
      done
    elif grep -Eq "CODEWIRE_IMAGE_STATE_${upper}|${family}_(candidate_ref|built_from)" <<<"$job"; then
      fail "$half half builds or reports the $family image of the other half"
    fi
  done
}
assert_build_half services "$service_job" 'Build and push the service runtime images' \
  dashboard derp services mesh
assert_build_half daemon "$daemon_job" 'Build and push the daemon runtime image' daemon

# The publisher takes every digest from this run's build-job outputs only.
for family in dashboard derp daemon services mesh; do
  half=build-service-images
  [[ "$family" != daemon ]] || half=build-daemon-image
  # shellcheck disable=SC2016
  [[ "$(grep -Fc "\${{ needs.${half}.outputs.${family}_candidate_ref }}" <<<"$publish_job")" -eq 1 ]] ||
    fail "runtime bundle construction does not consume the exact $family candidate once"
  upper="$(tr 'a-z' 'A-Z' <<<"$family")"
  # shellcheck disable=SC2016 # Match the literal workflow expression.
  [[ "$(grep -Fc "          CODEWIRE_BUILT_FROM_${upper}: \${{ needs.${half}.outputs.${family}_built_from }}" <<<"$publish_job")" -eq 2 ]] ||
    fail "runtime signing does not receive the exact $family built-from source for both registries"
done
if grep -Eq 'steps\.build\.outputs|imagetools inspect|build-push-runtime-images|build-push-image' <<<"$publish_job"; then
  fail "publication resolves or rebuilds a candidate instead of taking its build job's digest"
fi
# Dev runs only commits whose main CI passed (#2892). The publisher reads main
# CI's verdict for this exact commit first; only a verified verdict publishes,
# and only while the commit moves Dev forward does it sign and, checked again,
# dispatch. Exactly these steps, in this order.
[[ "$(grep -E '^      - name: ' <<<"$publish_job")" == "$(printf '%s\n' \
    "      - name: Read main CI's verdict for this commit" \
    '      - name: Publish the complete runtime set to Harbor without rebuilding' \
    '      - name: Require this commit to move Dev forward before signing' \
    '      - name: Sign the exact runtime set' \
    '      - name: Require this commit to move Dev forward before dispatch' \
    '      - name: Dispatch only the canonical source SHA' \
    '      - name: Mirror the runtime set to GHCR without gating delivery' \
    '      - name: Sign the GHCR mirror without gating delivery')" ]] ||
  fail "publication does not read the verdict, publish, check Dev descent, sign, check it again and dispatch, in that order"
step_of_job() {
  awk -v name="      - name: $2" '
    /^      - / { capture = ($0 == name) }
    capture { print }
  ' <<<"$1"
}
verdict_step="$(step_of_job "$publish_job" "Read main CI's verdict for this commit")"
grep -Fxq '        id: verdict' <<<"$verdict_step" || fail "the verdict step has no id"
# shellcheck disable=SC2016 # Match the literal workflow expression.
grep -Fxq '          GITEA_TOKEN: ${{ github.token }}' <<<"$verdict_step" ||
  fail "the verdict is not read with the read-only job token"
grep -Fq 'python3 -I -B scripts/ci/plan/main-ci-verdict.py check' <<<"$verdict_step" ||
  fail "the verdict is not read through the shared predicate"
# shellcheck disable=SC2016 # Match the literal workflow command.
grep -Fq -- '--sha "$GITHUB_SHA" --tree "$(git rev-parse "$GITHUB_SHA^{tree}")" --github-output' <<<"$verdict_step" ||
  fail "the verdict is not read for this run's exact commit and tree"
if grep -Eq '^        if:' <<<"$verdict_step"; then
  fail "the verdict is not read on every publish run"
fi
assert_step_if() {
  local step="$1" condition="$2" block
  block="$(step_of_job "$publish_job" "$step")"
  [[ -n "$block" ]] || fail "publication lacks the step: $step"
  grep -Fxq "        if: \${{ $condition }}" <<<"$block" ||
    fail "the step '$step' does not run only when $condition"
}
assert_step_if 'Publish the complete runtime set to Harbor without rebuilding' "steps.verdict.outputs.verified == 'true'"
assert_step_if 'Require this commit to move Dev forward before signing' "steps.verdict.outputs.verified == 'true'"
assert_step_if 'Sign the exact runtime set' "steps.descent-before-signing.outputs.deliver == 'true'"
assert_step_if 'Require this commit to move Dev forward before dispatch' "steps.descent-before-signing.outputs.deliver == 'true'"
assert_step_if 'Dispatch only the canonical source SHA' "steps.descent-before-dispatch.outputs.deliver == 'true'"
assert_step_if 'Mirror the runtime set to GHCR without gating delivery' "steps.dispatch.outcome == 'success'"
assert_step_if 'Sign the GHCR mirror without gating delivery' "steps.ghcr-mirror.outcome == 'success'"
grep -Fxq '        run: scripts/ci/deploy/require-dev-descent.sh signing' \
  <<<"$(step_of_job "$publish_job" 'Require this commit to move Dev forward before signing')" ||
  fail "the descent check before signing is not the shared descent check"
grep -Fxq '        run: scripts/ci/deploy/require-dev-descent.sh dispatching' \
  <<<"$(step_of_job "$publish_job" 'Require this commit to move Dev forward before dispatch')" ||
  fail "the descent check before dispatch is not the shared descent check"
# The descent checks need main's history, not one commit.
[[ "$(sed -n '/^    steps:$/,/^      # Main CI/p' <<<"$publish_job" | grep -Fxc '          fetch-depth: 0')" -eq 1 ]] ||
  fail "publication checks Dev descent without main's history"
for signer in 'Sign the exact runtime set' 'Sign the GHCR mirror without gating delivery'; do
  # shellcheck disable=SC2016 # Match the literal workflow expression.
  grep -Fxq '          CODEWIRE_MAIN_CI_RUN: ${{ steps.verdict.outputs.ci_run }}' \
    <<<"$(step_of_job "$publish_job" "$signer")" ||
    fail "the step '$signer' does not sign with the verifying main CI run"
done
# Signing happens only here: no other job of any workflow signs a runtime set.
[[ "$(grep -Fc 'sign-runtime-image-set.sh' "$WORKFLOW")" -eq 2 ]] ||
  fail "a runtime set is signed outside the publishing job"
while IFS= read -r -d '' other_workflow; do
  [[ "$other_workflow" == "$WORKFLOW" ]] && continue
  if grep -Fq 'sign-runtime-image-set.sh' "$other_workflow"; then
    fail "${other_workflow#"$ROOT/"} signs a runtime set; only Deploy Dev's publish job may"
  fi
done < <(find "$ROOT/.gitea/workflows" -type f -name '*.yaml' -print0)
# The only main-CI rerun call targets this job, from CI's final push-on-main job.
rerun_users="$(grep -rlE '/actions/jobs/[^ ]*/rerun|actions/jobs/\{job_id\}/rerun' \
  "$ROOT/.gitea/workflows" "$ROOT/scripts" | grep -v '/tests/' | sed "s|^$ROOT/||" | sort)"
[[ "$rerun_users" == 'scripts/ci/deploy/rerun-dev-publish.py' ]] ||
  fail "a job rerun is requested outside rerun-dev-publish.py: $rerun_users"

# Execute the shared descent check in a scratch copy beside a stub resolver,
# on a real history A-B-C (#2892). Old rule: only main's head delivered, so
# a verified B behind C signed nothing and steady merges starved Dev. New
# rule: B delivers while Dev runs A, even though main is now C; B signs
# nothing once Dev runs B or C; an unreadable or unknown Dev source fails
# closed.
descent_check="$ROOT/scripts/ci/deploy/require-dev-descent.sh"
bash -n "$descent_check"
[[ -x "$descent_check" ]] || fail "the descent check is not executable"
descent_root="$(mktemp -d)"
trap 'rm -rf -- "$descent_root"' EXIT
mkdir -p "$descent_root/bin/scripts/ci/deploy" "$descent_root/repo"
cp "$descent_check" "$descent_root/bin/scripts/ci/deploy/"
cat >"$descent_root/bin/scripts/ci/deploy/resolve-deployed-source.sh" <<'RESOLVER'
#!/usr/bin/env bash
# Stub: write the candidate resolve-deployed-source.sh would, from FAKE_DEV_SHA.
set -euo pipefail
[[ $# -eq 2 ]] || exit 2
if [[ -z "${FAKE_DEV_SHA:-}" ]]; then
  printf '{"retrieval":{"valid":false,"reasons":["api_unavailable"]},"source":{}}\n' >"$1"
else
  printf '{"retrieval":{"valid":true,"reasons":[]},"source":{"repository":"codewire/codewire","sha":"%s"}}\n' \
    "$FAKE_DEV_SHA" >"$1"
fi
RESOLVER
chmod +x "$descent_root/bin/scripts/ci/deploy/resolve-deployed-source.sh"
git -C "$descent_root/repo" init -q
for commit in A B C; do
  git -C "$descent_root/repo" -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false \
    commit -q --allow-empty -m "$commit"
done
sha_a="$(git -C "$descent_root/repo" rev-parse HEAD~2)"
sha_b="$(git -C "$descent_root/repo" rev-parse HEAD~1)"
sha_c="$(git -C "$descent_root/repo" rev-parse HEAD)"
descent_case() {
  local purpose="$1" dev="$2" output log
  output="$(mktemp)"
  log="$(mktemp)"
  if (cd "$descent_root/repo" && env FAKE_DEV_SHA="$dev" GITHUB_SHA="$sha_b" GITHUB_OUTPUT="$output" \
      "$descent_root/bin/scripts/ci/deploy/require-dev-descent.sh" "$purpose") >"$log" 2>&1; then
    printf '%s|%s\n' "$(cat "$output")" "$(cat "$log")"
  else
    printf 'failed|%s\n' "$(cat "$log")"
  fi
  rm -f -- "$output" "$log"
}
for purpose in signing dispatching; do
  result="$(descent_case "$purpose" "$sha_a")"
  [[ "$result" == "deliver=true|descent check before $purpose: $sha_b descends from Dev's source $sha_a" ]] ||
    fail "a verified commit behind main's head did not move Dev forward before $purpose: $result"
  result="$(descent_case "$purpose" "$sha_b")"
  [[ "$result" == "deliver=false|descent check before $purpose: Dev already runs $sha_b; $purpose nothing" ]] ||
    fail "the commit Dev already runs was delivered again before $purpose: $result"
  result="$(descent_case "$purpose" "$sha_c")"
  [[ "$result" == "deliver=false|descent check before $purpose: Dev runs $sha_c, which $sha_b does not move forward; $purpose nothing, Dev never moves backwards" ]] ||
    fail "a commit behind Dev's source was delivered before $purpose: $result"
  [[ "$(descent_case "$purpose" '')" == failed* ]] ||
    fail "an unreadable Dev source did not fail closed before $purpose"
  [[ "$(descent_case "$purpose" not-a-commit)" == failed* ]] ||
    fail "a malformed Dev source did not fail closed before $purpose"
  [[ "$(descent_case "$purpose" 4444444444444444444444444444444444444444)" == failed* ]] ||
    fail "a Dev source outside main's history did not fail closed before $purpose"
done
if (cd "$descent_root/repo" && FAKE_DEV_SHA="$sha_a" GITHUB_SHA="$sha_b" GITHUB_OUTPUT=/dev/null \
    "$descent_root/bin/scripts/ci/deploy/require-dev-descent.sh" publishing) >/dev/null 2>&1; then
  fail "the descent check accepted an unknown purpose"
fi

[[ "$(grep -Fc 'scripts/ci/images/sign-runtime-image-set.sh' <<<"$publish_job")" -eq 2 ]] ||
  fail "runtime workflow does not sign the Harbor set and GHCR mirror exactly once each"
[[ "$(grep -Fc '          CODEWIRE_DEPLOY_BASELINE_SHA:' <<<"$publish_job")" -eq 2 ]] ||
  fail "certified deployed baseline does not reach both signing steps"
grep -Fq 'CODEWIRE_MAIN_CI_RUN' "$RUNTIME_SIGNER" ||
  fail "runtime signer does not require main CI's verifying run"

bash -n "$RUNTIME_BUILDER"
[[ -x "$RUNTIME_BUILDER" ]] || fail "runtime image-set builder is not executable"
[[ "$(grep -Ec '^[[:space:]]*build_one (dashboard|derp|daemon|mesh|services) ' "$RUNTIME_BUILDER")" -eq 5 ]] ||
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

grep -Fq 'OPENBAO_GHCR_ROLE: codewire-source-dev-publisher' \
  <<<"$publish_job" || fail "runtime publisher lacks its exact OpenBao GHCR role"
grep -Fq 'OPENBAO_GHCR_AUDIENCE: openbao-codewire-source-dev-publisher' \
  <<<"$publish_job" || fail "runtime publisher lacks its exact OpenBao GHCR audience"
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
[[ -n "$validation_line" && -n "$first_copy_line" && "$validation_line" -lt "$first_copy_line" ]] ||
  fail "complete runtime bundle validation does not precede Harbor copies"
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
grep -Fq 'scripts/ci/deploy/dispatch-deploy-dev.sh "${GITHUB_SHA:?}"' <<<"$publish_job" ||
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
