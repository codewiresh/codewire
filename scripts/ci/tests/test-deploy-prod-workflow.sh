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

# The release is one protected job (#3246): it requires the support pair main
# published, aliases the five runtime images, validates and publishes the
# runtime bundle and finishes the release. It is the workflow's last job.
publish_job="$(sed -n '/^  publish-release:/,$p' "$WORKFLOW")"
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

# The finishing script verifies each published support image (the whole index),
# checks its source, publishes both to Harbor, mirrors them without gating,
# and only then dispatches the signed tag.
# shellcheck disable=SC2016
for expected in \
    'join base "$source_dir/images/base/Dockerfile" "$source_dir/images/base"' \
    'join workspace "$source_dir/images/workspace/Dockerfile" "$source_dir"' \
    '  [[ "$sha" == "$source_sha" ]] || fail "the $image index is from ${sha:-no source}, not $source_sha"' \
    '    "$(<"$work/$image.ref")" "$registry/codewire/$image" "$source_sha" "$tag"' \
    '    "$(<"$work/$image.ref")" "ghcr.io/codewiresh/$image" "$source_sha" "$tag" ||' \
    '"$ROOT/scripts/ci/deploy/dispatch-deploy-prod.sh" "$tag"'; do
  grep -Fxq -- "$expected" "$FINISH" || fail "the finishing script omits: $expected"
done
finish_order="$(grep -nE '^[^#]*(join workspace|publish-image-to-harbor|publish-image-to-ghcr|dispatch-deploy-prod)' "$FINISH" | cut -d: -f1 | tr '\n' ' ')"
read -r join_line harbor_line dispatch_line ghcr_line <<<"$finish_order"
[[ "$join_line" -lt "$harbor_line" && "$harbor_line" -lt "$dispatch_line" && "$dispatch_line" -lt "$ghcr_line" ]] ||
  fail "the finishing script does not join, publish, dispatch and then mirror (#4492)"
[[ "$(grep -n . "$FINISH" | tail -1 | cut -d: -f1)" -gt "$ghcr_line" && "$(tail -1 "$FINISH")" == 'done' ]] ||
  fail "the finishing script does work other than the mirror after the dispatch"
if grep -Fq 'build-support-platform.sh' "$FINISH"; then
  fail "the finishing script rebuilds a platform"
fi

# The reused pair finishes in the publishing job, after the runtime bundle.
# shellcheck disable=SC2016
reused="$(sed -n '/- name: Publish the reused support pair and deliver the release to Production/,/^$/p' <<<"$publish_job")"
for expected in '          CODEWIRE_SOURCE_DIR: .release-source' '        run: scripts/ci/release/finish-prod-release.sh' \
    "          SUPPORT_PROVENANCE_REVISION: \${{ steps.pair.outputs.provenance_revision }}"; do
  grep -qxF -- "$expected" <<<"$reused" || fail "the reused-pair finish omits: $expected"
done
# The reused pair's provenance comes only from the step that proved it.
[[ "$(grep -c 'SUPPORT_PROVENANCE_REVISION' "$WORKFLOW")" -eq 1 ]] ||
  fail 'the support pair takes its provenance from somewhere other than the pair step'
if grep -q '^ *if:' <<<"$reused"; then fail 'the reused-pair finish can be skipped'; fi
grep -q 'DIGEST' <<<"$reused" && fail 'the reused-pair finish takes platform digests'
# Production pulls from Harbor, so the runtime GHCR mirror follows the
# reused-pair delivery instead of delaying it (#4492).
[[ "$(grep -n 'run: scripts/ci/release/finish-prod-release.sh' <<<"$publish_job" | cut -d: -f1)" -lt \
   "$(grep -n 'Mirror the runtime release to GHCR' <<<"$publish_job" | cut -d: -f1)" ]] ||
  fail "the runtime GHCR mirror delays a reused pair's delivery"
[[ "$(grep -n 'Validate and publish the production bundle to Harbor' <<<"$publish_job" | cut -d: -f1)" -lt \
   "$(grep -n 'run: scripts/ci/release/finish-prod-release.sh' <<<"$publish_job" | cut -d: -f1)" ]] ||
  fail "a reused pair finishes before the runtime release is in Harbor"
# shellcheck disable=SC2016
grep -Fq '        run: scripts/ci/images/release-support-pair-state.sh "$SOURCE_SHA"' <<<"$publish_job" ||
  fail "the release support pair is not selected from what main published"
[[ "$(grep -n 'release-support-pair-state.sh' <<<"$publish_job" | cut -d: -f1)" -lt \
   "$(grep -n 'run: scripts/ci/release/alias-release-images.sh' <<<"$publish_job" | cut -d: -f1)" ]] ||
  fail "the release publishes before it requires the support pair"

[[ "$(grep -Fc 'run: scripts/ci/release/finish-prod-release.sh' "$WORKFLOW")" -eq 1 ]] ||
  fail "the release finishes from other than the one finishing step"
if grep -Fq 'dispatch-deploy-prod.sh' <<<"$(grep -v '^ *#' "$WORKFLOW")"; then
  fail "the workflow dispatches outside the finishing script"
fi

# A release builds nothing (#2892): the jobs are the pickup, the selection
# and the one publishing job; no step builds an image, selects a builder,
# platform or emulator, or switches to an in-job build; every image call
# reuses an existing source image. The tag's pre-push check and the pair step
# require the pair main published, and support-images.yaml backfills it.
builds_nothing_violation() {
  python3 - "$1" <<'PYCHECK'
import re, sys, yaml
try:
    workflow = yaml.safe_load(open(sys.argv[1]))
except Exception as error:  # A mutation may break the document itself.
    sys.exit(f"the workflow does not parse: {error}")
jobs = workflow["jobs"]
if list(jobs) != ["pending", "release-selection", "publish-release"]:
    sys.exit(f"deploy-prod runs jobs other than the pickup, the selection and the publication: {list(jobs)}")
triggers = workflow.get("on", workflow.get(True))
if list(triggers["workflow_dispatch"]["inputs"]) != ["release_tag"]:
    sys.exit("a dispatch takes an input other than the release tag")
for job_name, job in jobs.items():
    if job.get("if") and "needs.publish-release" in str(job.get("if")):
        sys.exit(f"{job_name}: follows the publication")
    for step in job.get("steps", []):
        run = step.get("run", "") + " " + str(step.get("uses", ""))
        env = {**(job.get("env") or {}), **(step.get("env") or {})}
        for key in ("CODEWIRE_IMAGE_PLATFORM", "CODEWIRE_EXTERNAL_BUILDX_BUILDER", "CODEWIRE_IMAGE_JOIN",
                    "CODEWIRE_IN_JOB_BUILD", "SUPPORT_PLATFORM_BUDGET_MINUTES"):
            if key in env:
                sys.exit(f"{job_name}: sets {key}")
        if re.search(r"(--platform|platforms[:=]|setup-qemu|binfmt|tonistiigi|qemu-user)", run):
            sys.exit(f"{job_name}: selects a platform or an emulator")
        if re.search(r"build-support-platform\.sh|trusted-buildkit|buildx build|docker build|build-push-image\.sh", run):
            sys.exit(f"{job_name}: builds an image")
        if "alias-release-images.sh" in run and env.get("REQUIRE_EXISTING_SOURCE_IMAGE") != "1":
            sys.exit(f"{job_name}: may build an image instead of reusing its source image")
PYCHECK
}
violation="$(builds_nothing_violation "$WORKFLOW" 2>&1)" && [[ -z "$violation" ]] || fail "$violation"
build_tree="$(mktemp -d)"
trap 'rm -rf -- "$build_tree"' EXIT
# Each mutation puts back part of the build path #2892 removed.
# shellcheck disable=SC2016 # The mutations insert literal workflow expressions.
build_mutations=(
  'a platform build job::$a\
\
  build-support-amd64:\
    runs-on: ${{ vars.CODEWIRE_CI_RUNNER_TRUSTED_LIGHT }}\
    needs: [release-selection, publish-release]\
    steps:\
      - run: scripts/ci/images/build-support-platform.sh linux/amd64'
  'a platform build step::/      - name: Alias the five existing runtime images side by side/i\      - run: scripts/ci/images/build-support-platform.sh linux/amd64\
'
  'the in-job build input::/        type: string/a\      in_job_build:\
        required: false\
        type: boolean'
  'an in-job build switch::/          REQUIRE_EXISTING_SOURCE_IMAGE: .1./a\          CODEWIRE_IN_JOB_BUILD: '"'"'1'"'"''
  'aliases that may build::s/          REQUIRE_EXISTING_SOURCE_IMAGE: .1./          REQUIRE_EXISTING_SOURCE_IMAGE: '"'"'0'"'"'/'
  'a direct image build::/      - name: Alias the five existing runtime images side by side/i\      - run: docker buildx build --push images/base\
'
)
for mutation in "${build_mutations[@]}"; do
  label="${mutation%%::*}"
  sed -e "${mutation#*::}" "$WORKFLOW" >"$build_tree/workflow.yaml"
  ! cmp -s "$WORKFLOW" "$build_tree/workflow.yaml" || fail "build mutation did not apply: $label"
  [[ -n "$(builds_nothing_violation "$build_tree/workflow.yaml" 2>&1)" ]] ||
    fail "build mutation was accepted: $label"
done

# The dispatch runs only in the finishing script, so only in a job that
# finished every publication first (asserted above).
grep -Fq "    runs-on: ${RUNS_ON_TRUSTED_LIGHT}" <<<"$publish_job" ||
  fail "the delivery does not use the protected CI tier"
# The dispatch waits for promote-prod's verdict, so a green release run means
# Production accepted the release (#2892). The delivering job holds one
# protected runner while promote-prod runs on the same pool: deploy-prod's
# release turn allows one such wait at a time (release-turn.py, tested in
# test-release-turn.py), and the pool runs several protected jobs at once.
# The delivering job's deadline outlasts that 30-minute wait.
[[ "$(sed -n 's/^    timeout-minutes: //p' <<<"$publish_job")" -gt 30 ]] ||
  fail "the delivering job has no deadline beyond its work and 30-minute wait"
grep -Fxq '        run: python3 -I -B scripts/ci/release/release-turn.py deploy-prod' "$WORKFLOW" &&
  grep -Fxq "        if: \${{ steps.turn.outputs.turn == 'go' }}" "$WORKFLOW" ||
  fail "production dispatches can wait on deploy runs side by side"
# cancel-in-progress false with no group: Forgejo neither queues a run nor
# cancels one. With no block each tick cancels a delivery; with a group every
# run queues (test-release-turn.py models Forgejo's rule).
[[ "$(sed -n '/^concurrency:$/,/^$/p' "$WORKFLOW")" == $'concurrency:\n  group: \'\'\n  cancel-in-progress: false' ]] ||
  fail "a tick can cancel a Production delivery, or release runs queue behind one another"
# shellcheck disable=SC2016
grep -Fq 'readonly wait_seconds="${DEPLOY_PROD_WAIT_SECONDS:-2700}"' \
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

# The join script never builds: the pair must already exist.
# The stub runs, so it lives in the repository's .tmp: a workstation /tmp may be
# noexec, where a stub there cannot run and every join looks failed.
mkdir -p "$ROOT/.tmp"
stub_tree="$(mktemp -d "$ROOT/.tmp/deploy-prod-join.XXXXXX")"
trap 'rm -rf -- "$build_tree" "$stub_tree"' EXIT
cat >"$stub_tree/builder" <<'STUB'
#!/usr/bin/env bash
printf 'join=%s require=%s platform=%s args=%s\n' "${CODEWIRE_IMAGE_JOIN:-}" "${REQUIRE_EXISTING_SOURCE_IMAGE:-}" \
  "${CODEWIRE_IMAGE_PLATFORM:-}" "$*" >>"$STUB_CALLS"
STUB
chmod +x "$stub_tree/builder"
digest_a=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
join_case() {
  : >"$stub_tree/calls"
  if env -u CODEWIRE_IMAGE_JOIN -u REQUIRE_EXISTING_SOURCE_IMAGE "$@" STUB_CALLS="$stub_tree/calls" \
      RELEASE_SUPPORT_IMAGE_BUILDER="$stub_tree/builder" CODEWIRE_IMAGE_PLATFORM=linux/arm64 \
      "$ROOT/scripts/ci/images/join-release-support-image.sh" workspace .release-source/images/workspace/Dockerfile .release-source \
      >"$stub_tree/out" 2>&1; then echo ok; else echo failed; fi
}
# A join set by the caller, or a retired build switch, never reaches the builder.
for given in '' "CODEWIRE_IMAGE_JOIN=$digest_a" BUILD_SUPPORT_PAIR=true; do
  read -r -a given_env <<<"$given"
  [[ "$(join_case "${given_env[@]}")" == ok \
    && "$(cat "$stub_tree/calls")" == "join= require=1 platform= args=workspace .release-source/images/workspace/Dockerfile .release-source" ]] ||
    fail "a reused release pair can be built instead of required (given: ${given:-nothing})"
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
[[ "$(state_case 'base workspace')" == "provenance_revision=$release_source" && ! -s "$stub_tree/alias-calls" ]] ||
  fail "a published release pair built for its own source is not reused as it is"
# A pair main aliased from an earlier commit (#3504) keeps that commit's
# provenance. The release reuses it only when the alias verifier derives the
# same alias from Git, for exactly the published digests, and then verifies
# the indexes against that commit.
[[ "$(state_case 'base workspace' STUB_REVISION_base="$alias_origin" STUB_REVISION_workspace="$alias_origin")" == "provenance_revision=$alias_origin" ]] || fail "an aliased release pair is not reused: $(cat "$stub_tree/out")"
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
# A release builds nothing (#2892): a missing or half-published pair stops it
# before it publishes, naming the backfill, with nothing written to the output.
for published in '' base workspace; do
  if [[ "$(state_case "$published")" != failed ]] ||
      ! grep -qF "dispatch support-images.yaml on main with source_sha=$release_source" "$stub_tree/out" ||
      [[ -s "$stub_tree/output" ]]; then
    fail "a release whose published pair is '${published:-nothing}' did not stop: $(cat "$stub_tree/out")"
  fi
done
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

python3 - "$WORKFLOW" <<'PY' || fail 'a deploy-prod job runs outside the protected runner tiers'
import sys

import yaml

jobs = yaml.safe_load(open(sys.argv[1]))["jobs"]
assert all(str(job.get("runs-on", "")).startswith("${{ vars.CODEWIRE_CI_RUNNER_") for job in jobs.values())
PY
printf '[test-deploy-prod-workflow] signed-tag publication and dispatch contract passed\n'
