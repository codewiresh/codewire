#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
# shellcheck source=scripts/ci/tests/fixtures/ci-runners.sh
source "$ROOT/scripts/ci/tests/fixtures/ci-runners.sh"
readonly WORKFLOW="$ROOT/.gitea/workflows/deploy-prod.yaml"

fail() {
  printf '[test-deploy-prod-workflow] ERROR: %s\n' "$*" >&2
  exit 1
}

bash -n "$0"

# role_by_event KEY NAME: the workflow line that picks NAME, or its schedule
# twin when the run is the release schedule's pickup (#2892).
role_by_event() {
  printf "  %s: \${{ github.event_name == 'schedule' && '%s-schedule' || '%s' }}" "$1" "$2" "$2"
}
# Each role's audience is test-ci-workflow-structure.py's to prove.
for pair in OPENBAO_ROLE:codewire-source-prod-publisher OPENBAO_GHCR_ROLE:codewire-source-prod-publisher; do
  expected="$(role_by_event "${pair%%:*}" "${pair#*:}")"
  grep -Fxq -- "$expected" "$WORKFLOW" || fail "production publisher lacks: $expected"
done
if grep -Fq 'GHCR_PUBLISH_USERNAME:' "$WORKFLOW"; then
  fail "production publisher retains a split Forgejo GHCR username"
fi

readonly ALIASES="$ROOT/scripts/ci/release/alias-release-images.sh"
readonly FINISH="$ROOT/scripts/ci/release/finish-prod-release.sh"

# The common release is one protected job (#3246): it selects the support
# pair, aliases the five runtime images, validates and publishes the runtime
# bundle and, with a reused pair, finishes the release.
publish_job="$(sed -n '/^  publish-release:/,/^  build-support-amd64:/p' "$WORKFLOW")"
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
first_copy_line="$(grep -n 'scripts/ci/images/publish-image-to-harbor.sh' <<<"$publish_job" | head -1 | cut -d: -f1)"
[[ -n "$validation_line" && -n "$first_copy_line" && "$validation_line" -lt "$first_copy_line" ]] ||
  fail "complete production validation does not precede registry publication"
# Reused source images must carry their Dev delivery signature for this exact
# source before any release tag points at them.
[[ "$(grep -Fc 'scripts/ci/images/verify-runtime-image-signatures.sh' <<<"$publish_job")" -eq 1 ]] ||
  fail "production does not require the delivery signature exactly once"
# shellcheck disable=SC2016 # Match the literal workflow command.
grep -Fq '            "$bundle" scripts/ci/trust/codewire-runtime-signing.pub' <<<"$publish_job" ||
  fail "production signature check is not bound to the validated bundle and tracked key"
signature_line="$(grep -n 'scripts/ci/images/verify-runtime-image-signatures.sh' <<<"$publish_job" | cut -d: -f1)"
[[ -n "$signature_line" && "$validation_line" -lt "$signature_line" && "$signature_line" -lt "$first_copy_line" ]] ||
  fail "production signature check does not sit between validation and publication"
if grep -Fq 'always()' <<<"$publish_job"; then
  fail "production publication could run after a failed step"
fi

# The five aliases run side by side in one step, each requiring the existing
# source image, and the bundle consumes exactly what that step reported.
[[ "$(grep -Fc '        run: scripts/ci/release/alias-release-images.sh' "$WORKFLOW")" -eq 1 ]] ||
  fail "production must alias the runtime images in exactly one step"
alias_step="$(sed -n '/- name: Alias the five existing runtime images side by side/,/^$/p' <<<"$publish_job")"
for expected in '        id: alias' "          REQUIRE_EXISTING_SOURCE_IMAGE: '1'" \
    '          CODEWIRE_SOURCE_DIR: .release-source'; do
  grep -qxF -- "$expected" <<<"$alias_step" || fail "the alias step omits: $expected"
done
for image in daemon derp services mesh dashboard; do
  for field in source_sha candidate_ref; do
    grep -Fq "\${{ steps.alias.outputs.${image}_${field} }}" <<<"$publish_job" ||
      fail "production does not take the $image $field from the alias step"
  done
done
[[ "$(grep -oF '${{ steps.alias.outputs.' "$WORKFLOW" | wc -l)" -eq 20 ]] ||
  fail "production consumes alias outputs outside the bundle, its publication and its mirror"
grep -Fq '[[ "${REQUIRE_EXISTING_SOURCE_IMAGE:-}" == 1 ]] ||' "$ALIASES" ||
  fail "the alias helper can build instead of reusing source images"
for entry in 'daemon deployments/docker/daemon.Dockerfile' 'derp deployments/docker/derp.Dockerfile' \
    'services deployments/docker/services.Dockerfile' 'mesh deployments/docker/mesh.Dockerfile' \
    'dashboard apps/dashboard/Dockerfile'; do
  grep -Fxq "  '$entry'" "$ALIASES" || fail "the alias helper omits $entry"
done
[[ "$(grep -c "^  '[a-z]* [^']*'$" "$ALIASES")" -eq 5 ]] || fail 'the alias helper does not alias exactly five images'

# Runtime images: five to Harbor and five mirrored to GHCR in the workflow;
# the support pair: two of each in the finishing script.
[[ "$(grep -Fc 'scripts/ci/images/publish-image-to-harbor.sh' "$WORKFLOW")" -eq 5 ]] ||
  fail "production must publish exactly five runtime manifests to Harbor"
[[ "$(grep -Fc 'scripts/ci/images/publish-image-to-ghcr.sh' "$WORKFLOW")" -eq 5 ]] ||
  fail "production must mirror exactly five runtime manifests to GHCR"
# shellcheck disable=SC2016
[[ "$(grep -Fc '            "$SOURCE_SHA" "$RELEASE_TAG"' "$WORKFLOW")" -eq 10 ]] ||
  fail "every production runtime image must receive source-SHA and stable SemVer aliases in Harbor and GHCR"
# Harbor gates release; every GHCR copy sits in a mirror step that continues on error.
ghcr_steps="$(awk '/^      - name: / { capture = ($0 ~ /GHCR/) } capture' "$WORKFLOW")"
[[ "$(grep -Fc 'scripts/ci/images/publish-image-to-ghcr.sh' <<<"$ghcr_steps")" -eq 5 ]] ||
  fail "a production GHCR copy is outside a named mirror step"
[[ "$(grep -c '^      - name: ' <<<"$ghcr_steps")" -eq "$(grep -c '^        continue-on-error: true$' <<<"$ghcr_steps")" ]] ||
  fail "a production GHCR mirror step can fail release"
# Never piped into `grep -q`: its early exit would kill the writer, and pipefail
# would then pass the violation it just found.
if grep -q continue-on-error <<<"$(awk '/^      - name: / { capture = ($0 !~ /GHCR/) } capture' "$WORKFLOW")"; then
  fail "a required production step continues on error"
fi

# The finishing script joins each support image (verifying the whole index),
# checks its source, publishes both to Harbor, mirrors them without gating,
# and only then dispatches the signed tag.
# shellcheck disable=SC2016
for expected in \
    'join base "$source_dir/images/base/Dockerfile" "$source_dir/images/base" \' \
    'join workspace "$source_dir/images/workspace/Dockerfile" "$source_dir" \' \
    '  [[ "$sha" == "$source_sha" ]] || fail "the $image index is from ${sha:-no source}, not $source_sha"' \
    '    "$(<"$work/$image.ref")" "$registry/codewire/$image" "$source_sha" "$tag"' \
    '    "$(<"$work/$image.ref")" "ghcr.io/codewiresh/$image" "$source_sha" "$tag" ||' \
    '"$ROOT/scripts/ci/deploy/dispatch-deploy-prod.sh" "$tag"'; do
  grep -Fxq -- "$expected" "$FINISH" || fail "the finishing script omits: $expected"
done
finish_order="$(grep -nE '^[^#]*(join workspace|publish-image-to-harbor|publish-image-to-ghcr|dispatch-deploy-prod)' "$FINISH" | cut -d: -f1 | tr '\n' ' ')"
read -r join_line harbor_line ghcr_line dispatch_line <<<"$finish_order"
[[ "$join_line" -lt "$harbor_line" && "$harbor_line" -lt "$ghcr_line" && "$ghcr_line" -lt "$dispatch_line" ]] ||
  fail "the finishing script does not join, publish, mirror and then dispatch"
[[ "$(tail -1 "$FINISH")" == '"$ROOT/scripts/ci/deploy/dispatch-deploy-prod.sh" "$tag"' ]] ||
  fail "the finishing script does work after the dispatch"
if grep -Fq 'build-support-platform.sh' "$FINISH"; then
  fail "the finishing script rebuilds a platform"
fi

# A reused pair finishes in the publishing job, after the runtime bundle.
# shellcheck disable=SC2016
reused="$(sed -n '/- name: Publish the reused support pair and deliver the release to Production/,/^$/p' <<<"$publish_job")"
for expected in "        if: \${{ steps.pair.outputs.build == 'false' }}" "          BUILD_SUPPORT_PAIR: 'false'" \
    '          CODEWIRE_SOURCE_DIR: .release-source' '        run: scripts/ci/release/finish-prod-release.sh' \
    "          SUPPORT_PROVENANCE_REVISION: \${{ steps.pair.outputs.provenance_revision }}"; do
  grep -qxF -- "$expected" <<<"$reused" || fail "the reused-pair finish omits: $expected"
done
# Only a reused pair may name another commit's provenance: a release that
# builds its pair verifies it against its own source.
[[ "$(grep -c 'SUPPORT_PROVENANCE_REVISION' "$WORKFLOW")" -eq 1 ]] ||
  fail 'a support pair other than the reused one takes another commit'"'"'s provenance'
grep -q 'DIGEST' <<<"$reused" && fail 'the reused-pair finish takes platform digests'
[[ "$(grep -n 'run: scripts/ci/release/finish-prod-release.sh' <<<"$publish_job" | cut -d: -f1)" -gt \
   "$(grep -n 'Mirror the runtime release to GHCR' <<<"$publish_job" | cut -d: -f1)" ]] ||
  fail "a reused pair finishes before the runtime release is published"
# shellcheck disable=SC2016
grep -Fq '        run: scripts/ci/images/release-support-pair-state.sh "$SOURCE_SHA"' <<<"$publish_job" ||
  fail "the release support pair is not selected from what main published"

# A built pair finishes in its own job, only after both native builds
# succeeded, and takes exactly their four verified digests.
finish_job="$(sed -n '/^  finish-built-release:/,$p' "$WORKFLOW")"
# shellcheck disable=SC2016
grep -Fxq "    if: \${{ always() && needs.release-selection.result == 'success' && needs.publish-release.result == 'success' && needs.publish-release.outputs.build == 'true' && needs.build-support-amd64.result == 'success' && needs.build-support-arm64.result == 'success' }}" <<<"$finish_job" ||
  fail "the built-pair finish can run without both native platform builds"
# shellcheck disable=SC2016
[[ "$(grep -oF 'needs.build-support-' <<<"$finish_job" | wc -l)" -eq 6 \
  && "$(grep -Fxc '          BASE_AMD64_DIGEST: ${{ needs.build-support-amd64.outputs.base_digest }}' <<<"$finish_job")" -eq 1 \
  && "$(grep -Fxc '          BASE_ARM64_DIGEST: ${{ needs.build-support-arm64.outputs.base_digest }}' <<<"$finish_job")" -eq 1 \
  && "$(grep -Fxc '          WORKSPACE_AMD64_DIGEST: ${{ needs.build-support-amd64.outputs.workspace_digest }}' <<<"$finish_job")" -eq 1 \
  && "$(grep -Fxc '          WORKSPACE_ARM64_DIGEST: ${{ needs.build-support-arm64.outputs.workspace_digest }}' <<<"$finish_job")" -eq 1 ]] ||
  fail "the built-pair finish consumes another job's output outside the verifying joins"
for expected in "          BUILD_SUPPORT_PAIR: 'true'" '        run: scripts/ci/release/finish-prod-release.sh'; do
  grep -qxF -- "$expected" <<<"$finish_job" || fail "the built-pair finish omits: $expected"
done
[[ "$(grep -Fc 'run: scripts/ci/release/finish-prod-release.sh' "$WORKFLOW")" -eq 2 ]] ||
  fail "the release finishes from other than the two finishing steps"
if grep -Fq 'dispatch-deploy-prod.sh' <<<"$(grep -v '^ *#' "$WORKFLOW")"; then
  fail "the workflow dispatches outside the finishing script"
fi

for platform in amd64 arm64; do
  case "$platform" in
    amd64) next_job=build-support-arm64 ;;
    arm64) next_job=finish-built-release ;;
  esac
  platform_job="$(sed -n "/^  build-support-$platform:/,/^  $next_job:/p" "$WORKFLOW")"
  for expected in "    if: \${{ needs.publish-release.outputs.build == 'true' }}" \
      '          CODEWIRE_SOURCE_DIR: .release-source' \
      "          SUPPORT_PLATFORM_BASE_DIGEST: \${{ needs.publish-release.outputs.base_${platform}_digest }}" \
      "          SUPPORT_PLATFORM_BUDGET_MINUTES: '110'" \
      "        run: scripts/ci/images/build-support-platform.sh linux/$platform"; do
    grep -qxF -- "$expected" <<<"$platform_job" || fail "linux/$platform release support build omits: $expected"
  done
  # Release-source code runs here, so no publication or deploy credential does.
  if grep -Eq 'publish-image-to-|finish-prod-release|dispatch-deploy-prod|OPENBAO_GHCR|secrets\.' <<<"$platform_job"; then
    fail "linux/$platform release support build crosses the publication boundary"
  fi
done
# shellcheck disable=SC2016 # Match the literal workflow expression.
grep -qxF '      workspace_digest: ${{ steps.build.outputs.workspace_digest }}' \
  <<<"$(sed -n '/^  build-support-arm64:/,/^  finish-built-release:/p' "$WORKFLOW")" ||
  fail 'the linux/arm64 release support build does not report its workspace digest'

# The release tag's own workspace agent contract runs inside the exact amd64
# image the build pushed, and the job reports the digest only from that step:
# the join consumes nothing that skipped the contract.
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
contract = [index for index, step in enumerate(steps) if step.get("id") == "contract"]
if len(contract) != 1:
    sys.exit("the amd64 release build job has no single workspace contract step")
expected = {
    "name": "Run the workspace contract on the exact image",
    "id": "contract",
    "env": {"WORKSPACE_DIGEST": "${{ steps.build.outputs.workspace_digest }}"},
    "run": "set -euo pipefail\n"
           'release_source_sha="$(git -C .release-source rev-parse HEAD)"\n'
           "scripts/ci/images/run-workspace-contract-on-image.sh \\\n"
           '  "$CODEWIRE_IMAGE_REGISTRY/codewire/workspace@$WORKSPACE_DIGEST" "$release_source_sha" \\\n'
           "  .release-source/scripts/ci/verify/workspace-agent-contract.sh\n",
}
if steps[contract[0]] != expected:
    sys.exit("the workspace contract step differs from the reviewed exact-image step")
build = [index for index, step in enumerate(steps) if step.get("id") == "build"]
if len(build) != 1 or not build[0] < contract[0]:
    sys.exit("the workspace contract does not follow the build")
if (job.get("outputs") or {}).get("workspace_digest") != "${{ steps.contract.outputs.workspace_digest }}":
    sys.exit("the amd64 workspace digest leaves the job without the contract")
if "continue-on-error" in job:
    sys.exit("the amd64 release build job continues on error")
if any("artifact" in str(step.get("uses", "")) for step in steps):
    sys.exit("the amd64 release build job takes an artifact input")
PY
}
violation="$(contract_step_violation "$WORKFLOW" 2>&1)" && [[ -z "$violation" ]] || fail "$violation"
# Each rule refuses its own regression of the reviewed job.
contract_tree="$(mktemp -d)"
trap 'rm -rf -- "$contract_tree"' EXIT
amd64_range='/^  build-support-amd64:/,/^  build-support-arm64:/'
# shellcheck disable=SC2016 # The mutations insert literal workflow expressions.
contract_mutations=(
  "contract step removed::$amd64_range{/- name: Run the workspace contract on the exact image/,/^\$/d}"
  "digest from the build step::s/workspace_digest: \${{ steps.contract.outputs.workspace_digest }}/workspace_digest: \${{ steps.build.outputs.workspace_digest }}/"
  "continue-on-error::/        id: contract/a\\        continue-on-error: true"
  "job continue-on-error::$amd64_range{/    timeout-minutes: 120/a\\    continue-on-error: true
}"
  "skippable contract::/        id: contract/a\\        if: \${{ always() }}"
  'needs. input::/          WORKSPACE_DIGEST: /a\          SOURCE_SHA: ${{ needs.release-selection.outputs.source_sha }}'
  'needs. revision::s/"$release_source_sha" \\$/"${{ needs.release-selection.outputs.source_sha }}" \\/'
  'contract outside the release source::s|            .release-source/scripts/ci/verify/workspace-agent-contract.sh|            scripts/ci/verify/workspace-agent-contract.sh|'
  'artifact contract::s|            .release-source/scripts/ci/verify/workspace-agent-contract.sh|            "$RUNNER_TEMP/artifact/workspace-agent-contract.sh"|'
  "artifact step::$amd64_range{/      - name: Run the workspace contract on the exact image/i\\      - uses: noel/actions-download-artifact@a9bc5e6ef2cb54c177f32aa5726adaa15e7e2d59
}"
  'tagged image::s|"$CODEWIRE_IMAGE_REGISTRY/codewire/workspace@$WORKSPACE_DIGEST"|"$CODEWIRE_IMAGE_REGISTRY/codewire/workspace:$release_source_sha"|'
  'public mirror source::s|run-workspace-contract-on-image.sh \\$|run-workspace-contract-on-image.sh --source ghcr \\|'
)
for mutation in "${contract_mutations[@]}"; do
  label="${mutation%%::*}"
  sed -e "${mutation#*::}" "$WORKFLOW" >"$contract_tree/workflow.yaml"
  ! cmp -s "$WORKFLOW" "$contract_tree/workflow.yaml" || fail "contract mutation did not apply: $label"
  [[ -n "$(contract_step_violation "$contract_tree/workflow.yaml" 2>&1)" ]] ||
    fail "contract mutation was accepted: $label"
done
awk '
  /^  [A-Za-z0-9_-]+:$/ { job = $0 }
  job == "  build-support-amd64:" && $0 == "      - name: Run the workspace contract on the exact image" { grab = 1 }
  grab { if ($0 == "") { grab = 0 } else { block = block $0 "\n" }; next }
  { line[++count] = $0; owner[count] = job }
  END {
    for (index_ = 1; index_ <= count; index_++) {
      if (owner[index_] == "  build-support-amd64:" && line[index_] == "      - name: Build the linux/amd64 base and workspace by digest") printf "%s\n", block
      print line[index_]
    }
  }
' "$WORKFLOW" >"$contract_tree/moved.yaml"
! cmp -s "$WORKFLOW" "$contract_tree/moved.yaml" || fail 'contract move did not apply'
[[ -n "$(contract_step_violation "$contract_tree/moved.yaml" 2>&1)" ]] ||
  fail 'a workspace contract moved before the build was accepted'

# No deploy-prod job builds linux/arm64 under emulation: every support image
# is built only by build-support-platform.sh (arm64 on the protected remote
# node, failing closed) or joined from its digests; every other image call
# must reuse an existing source image; nothing selects platforms or emulators.
python3 - "$WORKFLOW" <<'PYCHECK' || fail "a deploy-prod job can build linux/arm64 without the protected remote builder"
import re, sys, yaml
workflow = yaml.safe_load(open(sys.argv[1]))
arm64_builders = []
for job_name, job in workflow["jobs"].items():
    for step in job.get("steps", []):
        run = step.get("run", "")
        env = {**job.get("env", {}), **step.get("env", {})}
        for key in ("CODEWIRE_IMAGE_PLATFORM", "CODEWIRE_EXTERNAL_BUILDX_BUILDER", "CODEWIRE_IMAGE_JOIN"):
            if key in env:
                sys.exit(f"{job_name}: sets {key} in the workflow")
        if re.search(r"(--platform|platforms[:=]|setup-qemu|binfmt|tonistiigi|qemu-user)", run + " " + str(step.get("uses", ""))):
            sys.exit(f"{job_name}: selects a platform or an emulator directly")
        for match in re.finditer(r"build-support-platform\.sh (\S+)", run):
            if match.group(1) == "linux/arm64":
                arm64_builders.append(job_name)
        if ("build-push-image.sh" in run or "alias-release-images.sh" in run) \
                and env.get("REQUIRE_EXISTING_SOURCE_IMAGE") != "1":
            sys.exit(f"{job_name}: may build an image instead of reusing its source image")
        if re.search(r"build-push-image\.sh (base|workspace)\b", run):
            sys.exit(f"{job_name}: builds a support image outside the native platform jobs")
if arm64_builders != ["build-support-arm64"]:
    sys.exit(f"linux/arm64 is built by {arm64_builders}, not exactly the native build-support-arm64 job")
PYCHECK

# The dispatch runs only in the finishing script, so only in a job that
# finished every publication first (asserted above).
for job in publish-release finish-built-release; do
  job_text="$(sed -n "/^  $job:/,/^  [a-z0-9-]*:\$/p" "$WORKFLOW")"
  grep -Fq "    runs-on: ${RUNS_ON_TRUSTED_LIGHT}" <<<"$job_text" ||
    fail "the $job delivery does not use the protected CI tier"
done
# The dispatch waits for promote-prod's verdict, so a green release run means
# Production accepted the release (#2892). The delivering job holds one
# protected runner while promote-prod runs on the same pool: deploy-prod's
# release turn allows one such wait at a time (release-turn.py, tested in
# test-release-turn.py), and the pool runs several protected jobs at once.
# Each delivering job's deadline outlasts that 30-minute wait.
for job_text in "$publish_job" "$finish_job"; do
  [[ "$(sed -n 's/^    timeout-minutes: //p' <<<"$job_text")" -gt 30 ]] ||
    fail "a delivering job has no deadline beyond its work and 30-minute wait"
done
grep -Fxq '        run: python3 -I -B scripts/ci/release/release-turn.py deploy-prod' "$WORKFLOW" &&
  grep -Fxq "        if: \${{ steps.turn.outputs.turn == 'go' }}" "$WORKFLOW" ||
  fail "production dispatches can wait on deploy runs side by side"
grep -A1 -Fx '  group: deploy-prod-release-${{ github.run_id }}' "$WORKFLOW" | grep -Fxq '  cancel-in-progress: false' ||
  fail "a new release can cancel a dispatch while promote-prod runs"
# shellcheck disable=SC2016
grep -Fq 'readonly wait_seconds="${DEPLOY_PROD_WAIT_SECONDS:-1800}"' \
  "$ROOT/scripts/ci/deploy/dispatch-deploy-prod.sh" ||
  fail "production dispatch does not wait for promote-prod's verdict"
if grep -Fq 'CODEWIRE_DEPLOY_PROMOTION_TOKEN' "$WORKFLOW"; then
  fail "production dispatch retains the static deploy token"
fi
grep -Fq 'fetch-forgejo-deploy-prod-token.sh' \
  "$ROOT/scripts/ci/deploy/dispatch-deploy-prod.sh" ||
  fail "production dispatch cannot request its short-lived Authorized Integration JWT"

if grep -Eq 'promote-image-bundle|promotion-receipt|gitea-(upload|download)-artifact|CODEWIRE_DEPLOY_PROMOTION_USERNAME|observe-production:|deploy-prod-observer\.sh|setup-kubeconfig|kubectl|helm' "$WORKFLOW"; then
  fail "source production workflow retains desired-state writes, receipts, or cluster observation"
fi
# Production renders only in codewire/deploy promote-prod, which the dispatch
# starts with the signed tag alone; the source tree keeps no production render.
[[ ! -e "$ROOT/scripts/ci/deploy/deploy-prod.sh" ]] ||
  fail "the retired source production render is back"
if grep -Eq 'scripts/ci/deploy/deploy-prod\.sh|--render-only|kustomize' \
  "$WORKFLOW" "$ROOT/scripts/ci/deploy/dispatch-deploy-prod.sh"; then
  fail "the production path renders manifests in the source repository"
fi

# The join script never builds: a built pair is joined from both exact
# platform digests, a reused pair must already exist.
stub_tree="$(mktemp -d)"
trap 'rm -rf -- "$contract_tree" "$stub_tree"' EXIT
cat >"$stub_tree/builder" <<'STUB'
#!/usr/bin/env bash
printf 'join=%s require=%s platform=%s args=%s\n' "${CODEWIRE_IMAGE_JOIN:-}" "${REQUIRE_EXISTING_SOURCE_IMAGE:-}" \
  "${CODEWIRE_IMAGE_PLATFORM:-}" "$*" >>"$STUB_CALLS"
STUB
chmod +x "$stub_tree/builder"
digest_a=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
digest_b=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
join_case() {
  : >"$stub_tree/calls"
  if env -u CODEWIRE_IMAGE_JOIN -u REQUIRE_EXISTING_SOURCE_IMAGE "$@" STUB_CALLS="$stub_tree/calls" \
      RELEASE_SUPPORT_IMAGE_BUILDER="$stub_tree/builder" CODEWIRE_IMAGE_PLATFORM=linux/arm64 \
      "$ROOT/scripts/ci/images/join-release-support-image.sh" workspace .release-source/images/workspace/Dockerfile .release-source \
      >"$stub_tree/out" 2>&1; then echo ok; else echo failed; fi
}
[[ "$(join_case BUILD_SUPPORT_PAIR=true AMD64_DIGEST="$digest_a" ARM64_DIGEST="$digest_b")" == ok \
  && "$(cat "$stub_tree/calls")" == "join=$digest_a $digest_b require= platform= args=workspace .release-source/images/workspace/Dockerfile .release-source" ]] ||
  fail "a built release pair is not joined from exactly its amd64 then arm64 digests"
[[ "$(join_case BUILD_SUPPORT_PAIR=false)" == ok \
  && "$(cat "$stub_tree/calls")" == "join= require=1 platform= args=workspace .release-source/images/workspace/Dockerfile .release-source" ]] ||
  fail "a reused release pair can be built instead of required"
for bad in 'BUILD_SUPPORT_PAIR=true AMD64_DIGEST=sha256:aaaa' "BUILD_SUPPORT_PAIR=true ARM64_DIGEST=$digest_b" \
    "BUILD_SUPPORT_PAIR=false AMD64_DIGEST=$digest_a" 'BUILD_SUPPORT_PAIR=' 'BUILD_SUPPORT_PAIR=maybe'; do
  read -r -a bad_env <<<"$bad"
  [[ "$(join_case "${bad_env[@]}")" == failed && ! -s "$stub_tree/calls" ]] ||
    fail "the join script accepted: $bad"
done

# The selection reads both source-SHA indexes with the pull robot.
mkdir -p "$stub_tree/bin"
cat >"$stub_tree/fetcher" <<'STUB'
#!/usr/bin/env bash
[[ "$1" == --pull ]] || exit 64
printf 'robot\n' >"$2"; printf 'synthetic\n' >"$3"
STUB
cat >"$stub_tree/bin/docker" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  login) exit 0 ;;
  buildx)
    image="${*: -1}"; image="${image#registry.example.invalid/codewire/}"; image="${image%%:*}"
    if [[ " $* " == *' {{json .Provenance}} '* ]]; then
      # Each platform's provenance names the commit that built the index.
      revision_var="STUB_REVISION_${image}"
      revision="${!revision_var:-$STUB_SOURCE}"
      arm64_revision="${STUB_ARM64_REVISION:-$revision}"
      printf '{"linux/amd64":{"SLSA":{"runDetails":{"metadata":{"buildkit_metadata":{"vcs":{"revision":"%s"}}}}}},' "$revision"
      printf '"linux/arm64":{"SLSA":{"runDetails":{"metadata":{"buildkit_metadata":{"vcs":{"revision":"%s"}}}}}}}\n' "$arm64_revision"
      exit 0
    fi
    if [[ " $* " == *' --raw '* ]]; then
      printf '{"manifests":[{"digest":"sha256:%064d","platform":{"os":"linux","architecture":"amd64"}},' 1
      printf '{"digest":"sha256:%064d","platform":{"os":"linux","architecture":"arm64"}},' 2
      printf '{"digest":"sha256:%064d","platform":{"os":"unknown","architecture":"unknown"}}]}\n' 3
      exit 0
    fi
    case " $STUB_PUBLISHED " in
      *" $image "*) [[ "$image" == base ]] && printf '{"digest":"sha256:%064d"}\n' 1 || printf '{"digest":"sha256:%064d"}\n' 4 ;;
      *" error "*) echo 'connection reset by peer' >&2; exit 1 ;;
      *) echo 'ERROR: registry.example.invalid/codewire/x: not found' >&2; exit 1 ;;
    esac ;;
esac
STUB
# The alias verifier stand-in records its arguments and refuses on request.
cat >"$stub_tree/alias-verifier" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$STUB_ALIAS_CALLS"
[[ "${STUB_ALIAS_REFUSES:-0}" == 0 ]] || { echo 'support alias: the support inputs differ' >&2; exit 1; }
STUB
chmod +x "$stub_tree/fetcher" "$stub_tree/bin/docker" "$stub_tree/alias-verifier"
release_source="$(printf '%040d' 7)"
alias_origin="$(printf '%040d' 5)"
state_case() {
  local published="$1"
  shift
  : >"$stub_tree/output"
  : >"$stub_tree/alias-calls"
  if env PATH="$stub_tree/bin:$PATH" STUB_PUBLISHED="$published" OPENBAO_HARBOR_CREDENTIAL_FETCHER="$stub_tree/fetcher" \
      CODEWIRE_IMAGE_REGISTRY=registry.example.invalid STUB_SOURCE="$release_source" \
      RELEASE_SUPPORT_ALIAS_VERIFIER="$stub_tree/alias-verifier" STUB_ALIAS_CALLS="$stub_tree/alias-calls" \
      GITHUB_OUTPUT="$stub_tree/output" RUNNER_TEMP="$stub_tree" "$@" \
      "$ROOT/scripts/ci/images/release-support-pair-state.sh" "$release_source" >"$stub_tree/out" 2>&1; then
    cat "$stub_tree/output"
  else
    echo failed
  fi
}
[[ "$(state_case 'base workspace')" == "build=false
provenance_revision=$release_source" && ! -s "$stub_tree/alias-calls" ]] ||
  fail "a published release pair built for its own source is not reused as it is"
# A pair main aliased from an earlier commit (#3504) keeps that commit's
# provenance. The release reuses it only when the alias verifier derives the
# same alias from Git, for exactly the published digests, and then verifies
# the indexes against that commit.
[[ "$(state_case 'base workspace' STUB_REVISION_base="$alias_origin" STUB_REVISION_workspace="$alias_origin")" == "build=false
provenance_revision=$alias_origin" ]] || fail "an aliased release pair is not reused: $(cat "$stub_tree/out")"
[[ "$(cat "$stub_tree/alias-calls")" == "--repository $ROOT --source $release_source --origin $alias_origin --base-digest sha256:$(printf '%064d' 1) --workspace-digest sha256:$(printf '%064d' 4)" ]] ||
  fail "the alias was not proved for exactly the published pair: $(cat "$stub_tree/alias-calls")"
if [[ "$(state_case 'base workspace' STUB_REVISION_base="$alias_origin" STUB_REVISION_workspace="$alias_origin" STUB_ALIAS_REFUSES=1)" != failed ]] ||
    ! grep -qF "was built for $alias_origin, and is not its alias" "$stub_tree/out"; then
  fail "a pair built for a commit with other support inputs was reused"
fi
if [[ "$(state_case 'base workspace' STUB_REVISION_base="$alias_origin")" != failed ]] ||
    ! grep -qF 'a pair has one source' "$stub_tree/out" || [[ -s "$stub_tree/alias-calls" ]]; then
  fail "a pair whose base and workspace name different commits was reused"
fi
if [[ "$(state_case 'base workspace' STUB_ARM64_REVISION="$alias_origin")" != failed ]] ||
    ! grep -qF 'does not name one source commit for every platform' "$stub_tree/out"; then
  fail "an index whose platforms name different commits was reused"
fi
[[ "$(state_case '')" == build=true ]] || fail "an unpublished release pair is not built"
# A base a cancelled release published is reused per platform; only the
# workspace is built, from exactly those images.
[[ "$(state_case 'base')" == "build=true
base_amd64_digest=sha256:$(printf '%064d' 1)
base_arm64_digest=sha256:$(printf '%064d' 2)" ]] || fail "a published base alone is not reused per platform"
if [[ "$(state_case 'workspace')" != failed ]] || ! grep -qF 'workspace is published without its base' "$stub_tree/out"; then
  fail "a workspace published without its base was accepted"
fi
[[ "$(state_case 'error')" == failed ]] || fail "an unreadable registry was taken as an unpublished pair"
[[ -z "$(find "$stub_tree" -maxdepth 1 -name 'codewire-release-support-pair.*' -print -quit)" ]] ||
  fail "the selection left its pull credential behind"

# A failed half of the support pair reports "failure" with its whole log, and
# its other half finishes: no job cancels its own run (#3119; owner,
# 2026-10-21). A cancel turned the failure into "cancelled" and cut the
# failing job's log (infra#1229).
if grep -qE '/actions/runs/[^ ]*/cancel' "$WORKFLOW"; then
  fail 'a support pair half cancels its own run'
fi

# The release's amd64 support build runs on the trusted BuildKit builder and
# fails fast without it. Only the owner's explicit in_job_build dispatch builds
# it in the job; nothing else sets the switch.
python3 - "$WORKFLOW" <<'PY' || fail 'the owner-only in-job recovery input is not exactly wired'
import sys

import yaml

document = yaml.safe_load(open(sys.argv[1]))
triggers = document.get("on", document.get(True))
recovery = triggers["workflow_dispatch"]["inputs"]["in_job_build"]
assert recovery["type"] == "boolean" and recovery["default"] is False and recovery["required"] is False, recovery
expected = "${{ (inputs.in_job_build == true || inputs.in_job_build == 'true') && '1' || '0' }}"
jobs = document["jobs"]
assert jobs["build-support-amd64"]["env"]["CODEWIRE_IN_JOB_BUILD"] == expected
assert [name for name, job in jobs.items() if "CODEWIRE_IN_JOB_BUILD" in (job.get("env") or {})] == ["build-support-amd64"]
assert all(str(job.get("runs-on", "")).startswith("${{ vars.CODEWIRE_CI_RUNNER_") for job in jobs.values())
PY
printf '[test-deploy-prod-workflow] signed-tag publication and dispatch contract passed\n'
