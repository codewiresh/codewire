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
first_copy_line="$(grep -n 'scripts/ci/images/publish-image-to-harbor.sh' <<<"$publish_job" | head -1 | cut -d: -f1)"
[[ -n "$validation_line" && -n "$first_copy_line" && "$validation_line" -lt "$first_copy_line" ]] ||
  fail "complete production validation does not precede registry publication"

for job in build-daemon-image build-dashboard-image build-derp build-services-image build-mesh-image; do
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
[[ "$(grep -Fc 'scripts/ci/images/publish-image-to-harbor.sh' "$WORKFLOW")" -eq 7 ]] ||
  fail "production must publish exactly seven image manifests to Harbor"
[[ "$(grep -Fc 'scripts/ci/images/publish-image-to-ghcr.sh' "$WORKFLOW")" -eq 7 ]] ||
  fail "production must mirror exactly seven image manifests to GHCR"
# shellcheck disable=SC2016
[[ "$(grep -Fc '            "$SOURCE_SHA" "$RELEASE_TAG"' "$WORKFLOW")" -eq 14 ]] ||
  fail "every production image must receive source-SHA and stable SemVer aliases in Harbor and GHCR"
for family in base workspace; do
  grep -Fq "            registry.example.invalid/codewire/$family" "$WORKFLOW" ||
    fail "production omits the $family support image from Harbor"
  grep -Fq "            ghcr.io/codewiresh/$family" "$WORKFLOW" ||
    fail "production omits the $family support image from the GHCR mirror"
done
# Harbor gates release; every GHCR copy sits in a mirror step that continues on error.
ghcr_steps="$(awk '/^      - name: / { capture = ($0 ~ /GHCR/) } capture' "$WORKFLOW")"
[[ "$(grep -Fc 'scripts/ci/images/publish-image-to-ghcr.sh' <<<"$ghcr_steps")" -eq 7 ]] ||
  fail "a production GHCR copy is outside a named mirror step"
[[ "$(grep -c '^      - name: ' <<<"$ghcr_steps")" -eq "$(grep -c '^        continue-on-error: true$' <<<"$ghcr_steps")" ]] ||
  fail "a production GHCR mirror step can fail release"
if awk '/^      - name: / { capture = ($0 !~ /GHCR/) } capture' "$WORKFLOW" | grep -q continue-on-error; then
  fail "a required production step continues on error"
fi

support_job="$(sed -n '/^  publish-support-release-images:/,/^  publish-runtime-images:/p' "$WORKFLOW")"
grep -Fq '    needs: [release-selection, support-pair-selection, build-support-amd64, build-support-arm64]' <<<"$support_job" ||
  fail "support release publication does not wait for the selection and both platform builds"
# shellcheck disable=SC2016
grep -Fq "    if: \${{ always() && needs.release-selection.result == 'success' && needs.support-pair-selection.result == 'success' && (needs.support-pair-selection.outputs.build == 'false' || (needs.build-support-amd64.result == 'success' && needs.build-support-arm64.result == 'success')) }}" <<<"$support_job" ||
  fail "support release publication can run without a reused pair or both native platform builds"
grep -Fq '        id: base' <<<"$support_job" ||
  fail "support release job does not retain the base step output"
grep -Fq '        id: workspace' <<<"$support_job" ||
  fail "support release job does not retain the workspace step output"
# shellcheck disable=SC2016
grep -Fq '"${{ steps.workspace.outputs.candidate_ref }}"' <<<"$support_job" ||
  fail "publisher does not consume the same-job workspace digest"
# Publication consumes only same-job candidates. The platform digests cross
# the job boundary only into the two joins, which verify the whole index.
# shellcheck disable=SC2016
[[ "$(grep -oF 'needs.build-support-' <<<"$support_job" | wc -l)" -eq 6 \
  && "$(grep -Fc '          AMD64_DIGEST: ${{ needs.build-support-amd64.outputs.base_digest }}' <<<"$support_job")" -eq 1 \
  && "$(grep -Fc '          ARM64_DIGEST: ${{ needs.build-support-arm64.outputs.base_digest }}' <<<"$support_job")" -eq 1 \
  && "$(grep -Fc '          AMD64_DIGEST: ${{ needs.build-support-amd64.outputs.workspace_digest }}' <<<"$support_job")" -eq 1 \
  && "$(grep -Fc '          ARM64_DIGEST: ${{ needs.build-support-arm64.outputs.workspace_digest }}' <<<"$support_job")" -eq 1 ]] ||
  fail "support release publication consumes another job's output outside the verifying joins"
workspace_line="$(grep -n 'id: workspace' <<<"$support_job" | cut -d: -f1)"
support_copy_line="$(grep -n 'scripts/ci/images/publish-image-to-harbor.sh' <<<"$support_job" | head -1 | cut -d: -f1)"
[[ -n "$workspace_line" && -n "$support_copy_line" && "$workspace_line" -lt "$support_copy_line" ]] ||
  fail "support release publication can run before the same-job workspace join"
if grep -Fq 'build-support-platform.sh' <<<"$support_job"; then
  fail "support release publication rebuilds a platform"
fi
selection_job="$(sed -n '/^  support-pair-selection:/,/^  build-support-amd64:/p' "$WORKFLOW")"
# shellcheck disable=SC2016
grep -Fq '        run: scripts/ci/images/release-support-pair-state.sh "$SOURCE_SHA"' <<<"$selection_job" ||
  fail "the release support pair is not selected from what main published"
for platform in amd64 arm64; do
  case "$platform" in
    amd64) next_job=build-support-arm64 ;;
    arm64) next_job=publish-support-release-images ;;
  esac
  platform_job="$(sed -n "/^  build-support-$platform:/,/^  $next_job:/p" "$WORKFLOW")"
  for expected in '    runs-on: ci-protected' '    timeout-minutes: 120' \
      '    needs: [release-selection, support-pair-selection]' \
      "    if: \${{ needs.support-pair-selection.outputs.build == 'true' }}" \
      '          CODEWIRE_SOURCE_DIR: .release-source' \
      "          SUPPORT_PLATFORM_BASE_DIGEST: \${{ needs.support-pair-selection.outputs.base_${platform}_digest }}" \
      "          SUPPORT_PLATFORM_BUDGET_MINUTES: '110'" \
      "        run: scripts/ci/images/build-support-platform.sh linux/$platform"; do
    grep -qxF -- "$expected" <<<"$platform_job" || fail "linux/$platform release support build omits: $expected"
  done
  if grep -Eq 'publish-image-to-|OPENBAO_GHCR|secrets\.' <<<"$platform_job"; then
    fail "linux/$platform release support build crosses the publication boundary"
  fi
done

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
        if "build-push-image.sh" in run and env.get("REQUIRE_EXISTING_SOURCE_IMAGE") != "1":
            sys.exit(f"{job_name}: may build an image instead of reusing its source image")
        if re.search(r"build-push-image\.sh (base|workspace)\b", run):
            sys.exit(f"{job_name}: builds a support image outside the native platform jobs")
if arm64_builders != ["build-support-arm64"]:
    sys.exit(f"linux/arm64 is built by {arm64_builders}, not exactly the native build-support-arm64 job")
PYCHECK

dispatch_job="$(sed -n '/^  dispatch-deploy-prod:/,$p' "$WORKFLOW")"
grep -Fq '      - publish-runtime-images' <<<"$dispatch_job" ||
  fail "production dispatch can run before runtime publication"
grep -Fq '      - publish-support-release-images' <<<"$dispatch_job" ||
  fail "production dispatch can run before support publication"
# shellcheck disable=SC2016
grep -Fq "    if: \${{ always() && needs.release-selection.result == 'success' && needs.publish-runtime-images.result == 'success' && needs.publish-support-release-images.result == 'success' }}" <<<"$dispatch_job" ||
  fail "production dispatch does not require every direct prerequisite to succeed"
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

# The join script never builds: a built pair is joined from both exact
# platform digests, a reused pair must already exist.
stub_tree="$(mktemp -d)"
trap 'rm -rf -- "$stub_tree"' EXIT
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
    if [[ " $* " == *' --raw '* ]]; then
      printf '{"manifests":[{"digest":"sha256:%064d","platform":{"os":"linux","architecture":"amd64"}},' 1
      printf '{"digest":"sha256:%064d","platform":{"os":"linux","architecture":"arm64"}},' 2
      printf '{"digest":"sha256:%064d","platform":{"os":"unknown","architecture":"unknown"}}]}\n' 3
      exit 0
    fi
    case " $STUB_PUBLISHED " in
      *" $image "*) printf '{"digest":"sha256:%064d"}\n' 1 ;;
      *" error "*) echo 'connection reset by peer' >&2; exit 1 ;;
      *) echo 'ERROR: registry.example.invalid/codewire/x: not found' >&2; exit 1 ;;
    esac ;;
esac
STUB
chmod +x "$stub_tree/fetcher" "$stub_tree/bin/docker"
state_case() {
  : >"$stub_tree/output"
  if env PATH="$stub_tree/bin:$PATH" STUB_PUBLISHED="$1" OPENBAO_HARBOR_CREDENTIAL_FETCHER="$stub_tree/fetcher" \
      GITHUB_OUTPUT="$stub_tree/output" RUNNER_TEMP="$stub_tree" \
      "$ROOT/scripts/ci/images/release-support-pair-state.sh" "$(printf '%040d' 7)" >"$stub_tree/out" 2>&1; then
    cat "$stub_tree/output"
  else
    echo failed
  fi
}
[[ "$(state_case 'base workspace')" == build=false ]] || fail "a published release pair is not reused"
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

printf '[test-deploy-prod-workflow] signed-tag publication and dispatch contract passed\n'
