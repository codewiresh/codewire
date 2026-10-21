#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly WORKFLOW="$ROOT/.gitea/workflows/ci.yaml"
readonly STANDALONE_WORKFLOW="$ROOT/.gitea/workflows/workspace-image-verify.yaml"
readonly VERIFY="$ROOT/scripts/ci/verify/verify-workspace-image.sh"
readonly HELPER="$ROOT/scripts/ci/images/build-local-image.sh"
readonly AGENT_CONTRACT="$ROOT/scripts/ci/verify/workspace-agent-contract.sh"

fail() {
  printf '[test-workspace-image-verify-workflow] ERROR: %s\n' "$*" >&2
  exit 1
}

# The apt snapshot cache is CI job configuration; an ambient value must not
# change what this contract observes.
unset CODEWIRE_APT_SNAPSHOT_MIRROR

[[ -f "$WORKFLOW" ]] || fail 'required CI workflow is missing'
[[ ! -e "$STANDALONE_WORKFLOW" ]] || fail 'standalone workspace-image workflow still exists'
[[ -x "$VERIFY" ]] || fail 'workspace-image verification script is not executable'
[[ -x "$HELPER" ]] || fail 'local Buildx image helper is missing'
[[ -x "$AGENT_CONTRACT" ]] || fail 'workspace agent contract is missing'
last_context_reinclude="$(grep -n '^!' "$ROOT/.dockerignore" | tail -1 | cut -d: -f1)"
for generated_python in '**/__pycache__' '**/*.pyc' '**/*.pyo'; do
  grep -Fxq "$generated_python" "$ROOT/.dockerignore" ||
    fail "workspace Docker context does not exclude generated Python input: $generated_python"
  ignore_line="$(grep -nFx "$generated_python" "$ROOT/.dockerignore" | cut -d: -f1)"
  [[ "$ignore_line" -gt "$last_context_reinclude" ]] ||
    fail "generated Python exclusion is overridden by a later Docker context re-inclusion: $generated_python"
done
# Exactly the jobs that build the base or workspace image set the apt snapshot
# cache, at job level, on the heavy or protected pools, with one exact value.
python3 - "$ROOT/.gitea/workflows" <<'PY' || fail 'apt snapshot cache is not scoped to base/workspace image builders'
import pathlib
import re
import sys

import yaml

MIRROR = "http://apt-snapshot-cache.forgejo-runner-control.svc.cluster.local:8080"
NAME = "CODEWIRE_APT_SNAPSHOT_MIRROR"
BUILDER = re.compile(
    r"verify-workspace-image\.sh|probe-workspace-r2-cache\.sh|build-push-image\.sh (base|workspace) "
    r"|build-support-platform\.sh linux/"
)
HEAVY = "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' && 'ci-heavy-main' || 'ci-heavy' }}"
# Jobs that call an image builder without the cache: the arm64 support legs
# build on the remote ci-arm64-builder node outside the cluster, and the
# support join only assembles the two platform digests. A release's own pair
# (deploy-prod.yaml) builds exactly as support-images does.
CANONICAL = {
    "deploy-prod.yaml:build-support-arm64",
    "support-images.yaml:build-support-arm64",
    "support-images.yaml:publish-support-images",
}
EXPECTED = {
    "ci.yaml:kind-workspace",
    "ci.yaml:workspace-cache-measurement",
    "ci.yaml:workspace-cache-probes",
    "ci.yaml:workspace-image",
    "deploy-prod.yaml:build-support-amd64",
    "support-images.yaml:build-support-amd64",
}
builders, configured = set(), set()
for path in sorted(pathlib.Path(sys.argv[1]).glob("*.y*ml")):
    text = path.read_text()
    document = yaml.safe_load(text) or {}
    if NAME in (document.get("env") or {}):
        raise SystemExit(f"{path.name}: workflow-level env names the apt snapshot cache")
    file_jobs = 0
    for name, job in (document.get("jobs") or {}).items():
        steps = job.get("steps") or []
        key = f"{path.name}:{name}"
        if any(NAME in (step.get("env") or {}) for step in steps):
            raise SystemExit(f"{key}: a step env names the apt snapshot cache")
        if BUILDER.search("\n".join(str(step.get("run", "")) for step in steps)):
            builders.add(key)
        if NAME in (job.get("env") or {}):
            if job["env"][NAME] != MIRROR:
                raise SystemExit(f"{key}: unexpected apt snapshot cache value")
            # ci-protected-metal slots are ci-protected pool pods (same cache policy).
            if job.get("runs-on") not in ("ci-heavy", "ci-protected", "ci-protected-metal", HEAVY):
                raise SystemExit(f"{key}: apt snapshot cache set outside ci-heavy/ci-protected")
            configured.add(key)
            file_jobs += 1
    if text.count(NAME) != file_jobs or text.count("apt-snapshot-cache.") != file_jobs:
        raise SystemExit(f"{path.name}: the apt snapshot cache appears outside job env")
if builders != EXPECTED | CANONICAL or configured != EXPECTED:
    raise SystemExit(f"builders={sorted(builders)} configured={sorted(configured)}")
PY
workspace_job="$(awk '
  $0 == "  workspace-image:" { capture = 1 }
  capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ && $0 != "  workspace-image:" { exit }
  capture { print }
' "$WORKFLOW")"
grep -qF '  workspace-image:' <<<"$workspace_job" || fail 'workspace-image job is missing'
grep -qF '    name: Container contract verification' <<<"$workspace_job" ||
  fail 'workspace job is not named for its complete non-publishing scope'
# shellcheck disable=SC2016 # The workflow expression is literal text.
grep -qxF '    runs-on: ${{ github.event_name == '"'"'push'"'"' && github.ref == '"'"'refs/heads/main'"'"' && '"'"'ci-heavy-main'"'"' || '"'"'ci-heavy'"'"' }}' <<<"$workspace_job" ||
  fail 'Docker-backed workspace verification is not assigned to the heavy capability profile'
grep -qF '    timeout-minutes: 55' <<<"$workspace_job" ||
  fail 'workspace cold-build ceiling does not preserve the runner cleanup margin'
grep -qF '    needs: [verification-selection]' <<<"$workspace_job" ||
  fail 'workspace job does not consume the canonical verification plan'
grep -qF "    if: \${{ needs.verification-selection.outputs.workspace_image_expected == 'true' }}" \
  <<<"$workspace_job" ||
  fail 'workspace job does not use the trusted server-side dispatch decision'
if grep -qF '    strategy:' <<<"$workspace_job"; then
  fail 'workspace job retains empty-matrix dispatch'
fi
grep -qF 'name: Container contracts not selected' <<<"$workspace_job" ||
  fail 'container job has no explicit unaffected path'
grep -qF 'no checkout, download, installation, or build required' <<<"$workspace_job" ||
  fail 'workspace no-op does not prove its cheap behavior'
grep -qF 'name: Resolve container contract scope' <<<"$workspace_job" ||
  fail 'container job does not resolve its workspace, dashboard, and iOS scope'
# shellcheck disable=SC2016 # Match literal workflow expressions.
grep -qF 'WORKSPACE_IMAGE_SELECTED: ${{ needs.verification-selection.outputs.workspace_image_selected }}' \
  <<<"$workspace_job" || fail 'container scope omits canonical workspace-image selection'
grep -qF "steps.container-scope.outputs.selected != 'true'" <<<"$workspace_job" ||
  fail 'container no-op does not use its resolved scope'
grep -qF "steps.container-scope.outputs.selected == 'true'" <<<"$workspace_job" ||
  fail 'container checkout does not use its resolved scope'
grep -qF "steps.container-scope.outputs.workspace == 'true'" <<<"$workspace_job" ||
  fail 'workspace positive path does not use its resolved workspace scope'
grep -qF "trusted_adapter='.trusted-ci-policy/scripts/ci/plan/apply-verification-plan.py'" \
  "$WORKFLOW" || fail 'artifact facts do not come from the trusted adapter'
# shellcheck disable=SC2016 # Match the workflow's literal shell variables.
grep -qF 'python3 "$trusted_adapter" --plan "$plan_output"' "$WORKFLOW" ||
  fail 'trusted artifact adapter is not applied directly'
grep -qF -- '--unclassified' "$WORKFLOW" ||
  fail 'non-PR artifact selection does not fail closed'
if grep -qF 'selector_version=v2' "$WORKFLOW" \
    || grep -qF 'One-time v3 cutover' "$WORKFLOW"; then
  fail 'workspace selection retains a superseded transition bridge'
fi
step_count="$(grep -Ec '^      - (name:|uses:)' <<<"$workspace_job")"
guard_count="$(grep -Ec '^        if:' <<<"$workspace_job")"
[[ "$step_count" == "$guard_count" ]] ||
  fail 'every workspace job step must have a receipt/artifact selection guard'
if grep -Eiq 'docker push|--push|contents: write|secrets\.' <<<"$workspace_job"; then
  fail 'workspace verification must have no publishing or protected credential'
fi
if grep -qE '^[[:space:]]*permissions:' "$WORKFLOW"; then
  fail 'workflow declares GitHub-only permissions that Forgejo ignores'
fi
grep -qF 'scripts/ci/verify/verify-workspace-image.sh' <<<"$workspace_job" ||
  fail 'workflow does not invoke the image verifier'
dashboard_step="$(awk '
  /- name: Build and inspect the standalone dashboard image/ { capture = 1 }
  capture && /^      - name:/ && !/- name: Build and inspect the standalone dashboard image/ { exit }
  capture { print }
' <<<"$workspace_job")"
grep -qF 'CODEWIRE_SCCACHE_MODE: disabled' <<<"$dashboard_step" ||
  fail 'standalone dashboard bake inherits workspace R2 mode without a secret mount'
if grep -Eq 'docker (buildx )?build.*--push|docker push' "$VERIFY"; then
  fail 'verification must not publish an image'
fi
[[ "$(grep -Ec '^workspace_cache_build (base|workspace) ' "$VERIFY")" -eq 2 ]] ||
  fail 'verification does not build the exact local base/workspace pair'
# The published arm64 leg cross-compiles cw. Verification builds exactly that
# stage on amd64 hosts, without publication, emulation or a measured case.
# shellcheck disable=SC2016 # Match the verifier's literal shell condition.
arm64_cw_block="$(sed -n '/^if \[\[ "$architecture" == amd64 && -z "$workspace_measurement_case" \]\]; then$/,/^fi$/p' "$VERIFY")"
[[ "$(grep -c '^ *workspace_cache_build ' <<<"$arm64_cw_block")" -eq 1 \
    && "$(grep -c '^  workspace_cache_build cw-arm64 ' "$VERIFY")" -eq 1 ]] ||
  fail 'verification does not gate exactly one arm64 cw cross-compile build'
# shellcheck disable=SC2016 # Match the verifier's literal shell variables.
for arm64_cw_input in \
    'workspace_cache_build cw-arm64 "$source_tree" arm64 ' '--target cw-builder-arm64' \
    '--output type=cacheonly' '--provenance=false --sbom=false' '"${compiler_args[@]}"' \
    '--build-arg CODEWIRE_RUST_PROFILE=runtime' '--build-arg "BASE_IMAGE_REF=$base_foundation"' \
    '--file "$ROOT/images/workspace/Dockerfile"'; do
  grep -qF -- "$arm64_cw_input" <<<"$arm64_cw_block" ||
    fail "arm64 cw cross-compile check omits: $arm64_cw_input"
done
if grep -Eq -- '--push|--load|type=(oci|docker|image|registry)' <<<"$arm64_cw_block"; then
  fail 'arm64 cw cross-compile check exports an image'
fi
# shellcheck disable=SC2016 # Match the verifier's literal shell variables.
grep -qF -- '--output "type=oci,dest=$base_layout,tar=false"' "$VERIFY" ||
  fail 'base verification does not export a local OCI layout'
# shellcheck disable=SC2016 # Match the verifier's literal shell variables.
grep -qF -- '--metadata-file "$base_metadata"' "$VERIFY" ||
  fail 'base verification does not capture its immutable output digest'
# shellcheck disable=SC2016 # Match the verifier's literal shell variables.
grep -qF -- '--build-context "$base_context_name=oci-layout://$base_layout@$base_digest"' \
  "$VERIFY" || fail 'workspace verification does not consume its exact OCI base digest'
# shellcheck disable=SC2016 # Match the verifier's literal shell variables.
grep -qF -- '--build-arg "BASE_IMAGE_REF=$base_context_name"' "$VERIFY" ||
  fail 'workspace verification does not bind FROM to the local OCI context'
grep -qF -- '--load' "$VERIFY" ||
  fail 'workspace verification does not load its final image for inspection'
grep -qF 'images/base/Dockerfile' "$VERIFY" ||
  fail 'workspace verification omits the base image build'
grep -qF 'scripts/ci/tests/test-build-local-image.sh' <<<"$workspace_job" ||
  fail 'workflow does not run the mocked helper contract'
grep -qF 'scripts/ci/tests/test-workspace-agent-contract.sh' <<<"$workspace_job" ||
  fail 'workflow does not run the mocked PID/agent contract'
grep -qF 'scripts/ci/verify/rehearse-build-local-image.sh' <<<"$workspace_job" ||
  fail 'workflow does not run the real no-load/load rehearsal'
grep -qF -- '--pids-limit=2048' "$VERIFY" ||
  fail 'nested workspace verification does not declare its PID limit'
grep -qF -- 'docker_bin" run --rm --interactive --pids-limit=2048' "$VERIFY" ||
  fail 'workspace verifier does not attach the streamed agent contract'
grep -qF 'scripts/ci/verify/workspace-agent-contract.sh' "$VERIFY" ||
  fail 'workspace verifier does not stream the PID/agent contract into the image'
# shellcheck disable=SC2016 # Match the literal in-container shell contract.
grep -qF 'IFS= read -r actual_pids_max < "$cgroup_root/pids.max"' "$AGENT_CONTRACT" ||
  fail 'workspace verification does not prove pids.max with a shell builtin'
grep -qF 'pids.current pids.max' "$AGENT_CONTRACT" ||
  fail 'workspace failure evidence omits bounded PID counters'
# shellcheck disable=SC2016 # Match the literal in-container shell contract.
grep -qF '"$cgroup_root/pids.events"' "$AGENT_CONTRACT" ||
  fail 'workspace failure evidence omits pids.events'
for agent in codex claude gemini kimi pi aider; do
  grep -qF "$agent" "$AGENT_CONTRACT" || fail "verification omits $agent"
done
for tool in cw docker dockerd docker-compose gh git go gopls hcloud node npm bun pnpm yarn \
  python3 pipx poetry uv cargo rustc psql protoc bwrap; do
  grep -qF "$tool" "$AGENT_CONTRACT" || fail "verification omits $tool"
done
grep -qF 'dynamic_bun_runner="bun""x"' "$AGENT_CONTRACT" ||
  fail 'verification omits the installed Bun package runner without invoking it literally'
grep -qF 'shipped agents are writable' "$AGENT_CONTRACT" ||
  fail 'verification does not prove the shipped agents are read-only'
grep -qF 'does not upgrade into the home' "$AGENT_CONTRACT" ||
  fail 'verification does not prove agent upgrades reach the persistent home'
grep -qF 'npm install --global --dry-run --ignore-scripts --no-audit --no-fund @openai/codex@0.160.0' "$AGENT_CONTRACT" ||
  fail 'verification does not prove the explicit user-scoped Codex install plan'
grep -qF -- '--tmpfs /home/codewire:rw,exec,uid=1000,gid=1000,mode=0700,size=256m' "$VERIFY" ||
  fail 'verification omits the fresh persistent-home boundary'
grep -qF "[[ \"\$VERIFICATION_SELECTION\" != *'|kind|'* ]] || [ \"\${KIND_WORKSPACE_SOURCE:-}\" = pinned ]" \
  <<<"$workspace_job" || fail 'standalone workspace verification duplicates selected Kind ownership'
# The companion suites are independent programs with private scratch
# directories. They run in two lanes beside the verifier fixture below and
# are joined, in this order, before the contract is reported: every suite
# still runs every case, and any failure fails this test. The cache
# experiment suite is its own step beside this one wherever this test is a
# step (run-product-verification.sh).
mkdir -p "$ROOT/.tmp"
work=''
companions="$(mktemp -d "$ROOT/.tmp/workspace-image-companions.XXXXXX")"
companion_names=()
companion_pids=()
cleanup() {
  local pid
  for pid in "${companion_pids[@]}"; do
    # A lane leads its own process group when setsid is available.
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  done
  for pid in "${companion_pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$work" "$companions"
}
trap cleanup EXIT
start_companion_lane() {
  local name="$1"
  shift
  local -a leader=()
  ! command -v setsid >/dev/null || leader=(setsid)
  # shellcheck disable=SC2016 # The lane's own shell expands its arguments.
  "${leader[@]}" bash -euo pipefail -c '
    for suite; do
      case "$suite" in
        *.py) PYTHONDONTWRITEBYTECODE=1 python3 "$suite" ;;
        *) "$suite" ;;
      esac
    done
  ' bash "$@" >"$companions/$name.out" 2>"$companions/$name.err" &
  companion_names+=("$name")
  companion_pids+=("$!")
}
join_companion_lanes() {
  local index status failed=false
  for index in "${!companion_pids[@]}"; do
    status=0
    wait "${companion_pids[$index]}" || status=$?
    cat "$companions/${companion_names[$index]}.out"
    cat "$companions/${companion_names[$index]}.err" >&2
    if [[ "$status" != 0 ]]; then
      printf '[test-workspace-image-verify-workflow] ERROR: companion lane %s failed with status %s\n' \
        "${companion_names[$index]}" "$status" >&2
      failed=true
    fi
  done
  companion_pids=()
  [[ "$failed" == false ]] || exit 1
}
start_companion_lane artifact-and-probes \
  "$ROOT/scripts/ci/tests/test-workspace-image-artifact.py" \
  "$ROOT/scripts/ci/tests/test-workspace-cache-probes.py"
start_companion_lane selector-and-cache \
  "$ROOT/scripts/ci/tests/test-select-untrusted-workspace-cache.sh" \
  "$ROOT/scripts/ci/tests/test-workspace-cache.sh" \
  "$ROOT/scripts/ci/tests/test-buildx-builder.sh"

# Execute the verifier against a fake Docker client. This catches command-order,
# digest-handoff, cleanup, and fail-closed regressions without building an image.
work="$(mktemp -d "$ROOT/.tmp/workspace-image-verifier-test.XXXXXX")"
mkdir -p "$work/bin" "$work/tmp"
# Execute the actual workflow decision, not a second handwritten selector.
awk '
  /- name: Resolve container contract scope/ { scope = 1 }
  scope && /^        run: \|$/ { run = 1; next }
  run && /^          / { print substr($0, 11); next }
  run { exit }
' "$WORKFLOW" >"$work/container-scope.sh"
[[ -s "$work/container-scope.sh" ]] || fail 'container scope script was not extracted'
# Ownership of the exact-source workspace build (workspace=) and of the job's
# checkout (selected=). CI owns the workspace on pull requests, dispatches and
# when the owner is unset; a push to main leaves it to support-images, which
# runs the contract on the exact image it publishes (#2892). Selected Kind
# owns it only when it builds it; when it runs the published pin, this job
# keeps the selected workspace build. Dashboard and iOS work keep the job
# under either owner.
# OWNER|WORKSPACE SELECTED|SELECTION|KIND SOURCE|WORKSPACE|SELECTED
while IFS='|' read -r owner workspace_selected selection kind_source expected_workspace expected; do
  selection="|${selection//,/|}|"
  : >"$work/scope-output"
  env ${owner:+"WORKSPACE_IMAGE_OWNER=$owner"} \
    WORKSPACE_IMAGE_SELECTED="$workspace_selected" VERIFICATION_SELECTION="$selection" \
    KIND_WORKSPACE_SOURCE="$kind_source" \
    GITHUB_OUTPUT="$work/scope-output" bash "$work/container-scope.sh"
  grep -Fxq "workspace=$expected_workspace" "$work/scope-output" ||
    fail "workspace ownership differs for owner=${owner:-unset} workspace=$workspace_selected selection=$selection kind=$kind_source"
  grep -Fxq "selected=$expected" "$work/scope-output" ||
    fail "container ownership differs for owner=${owner:-unset} workspace=$workspace_selected selection=$selection kind=$kind_source"
done <<'EOF'
ci|true|kind||false|false
ci|true|kind|source|false|false
ci|true|kind|pinned|true|true
ci|false|kind|pinned|false|false
ci|false|kind||false|false
ci|true|policy||true|true
ci|true|policy|pinned|true|true
ci|false|policy||false|false
ci|false|web||false|true
ci|false|kind,web||false|false
ci|false|kind,web|pinned|false|false
ci|true|kind,web||false|false
ci|true|kind,web|pinned|true|true
ci|false|ios||false|true
ci|true|kind,ios||false|true
|true|policy||true|true
|true|kind|pinned|true|true
|false|policy||false|false
support-images|true|policy||false|false
support-images|true|policy|pinned|false|false
support-images|true|kind|pinned|false|false
support-images|true|kind,web|pinned|false|false
support-images|true|kind||false|false
support-images|false|policy||false|false
support-images|true|web||false|true
support-images|false|web||false|true
support-images|true|ios||false|true
support-images|true|kind,ios||false|true
EOF
# shellcheck disable=SC2016 # Match the literal workflow expression.
grep -qF 'KIND_WORKSPACE_SOURCE: ${{ needs.verification-selection.outputs.kind_workspace_source }}' <<<"$workspace_job" ||
  fail 'container workspace build does not take over from a pinned Kind workspace'

# A push to main can never run the workspace build, and a pull request or a
# dispatch always runs it when its exact-source workspace is selected and
# Kind does not build it. owner_violation FILE [--mutations] prints the first
# broken rule; with --mutations it also proves each rule refuses its own
# regression of the reviewed workflow.
owner_violation() {
  python3 -B - "$@" <<'OWNER_PY'
import itertools
import os
import subprocess
import sys
import tempfile

import yaml

OWNER = ("${{ github.event_name == 'push' && github.ref == 'refs/heads/main' "
         "&& 'support-images' || 'ci' }}")
RECEIPT = "needs.verification-selection.outputs.tested_tree_receipt != 'accepted'"
WORKSPACE = "steps.container-scope.outputs.workspace == 'true'"
EXPERIMENT = "needs.verification-selection.outputs.workspace_cache_experiment == 'true'"
GUARDED = {
    "Prove isolated Buildx load contract": f"${{{{ {RECEIPT} && {WORKSPACE} }}}}",
    "Select independent workspace caches": f"${{{{ {RECEIPT} && {WORKSPACE} }}}}",
    "Prove labeled R2 backend compatibility":
        f"${{{{ {RECEIPT} && {WORKSPACE} && env.CODEWIRE_WORKSPACE_CACHE_CANARY == 'true' }}}}",
    "Prepare selected workspace cache seed": f"${{{{ {RECEIPT} && {EXPERIMENT} && {WORKSPACE} }}}}",
    "Build and inspect without publication": f"${{{{ {RECEIPT} && {WORKSPACE} }}}}",
    "Clean workspace cache credentials": f"${{{{ always() && {RECEIPT} && {WORKSPACE} }}}}",
    "Finalize selected workspace cache seed":
        f"${{{{ success() && {RECEIPT} && {EXPERIMENT} && {WORKSPACE} }}}}",
}
# Commands that build, verify or cache the exact-source workspace.
WORKSPACE_WORK = (
    "verify-workspace-image.sh", "select-untrusted-workspace-cache.sh",
    "canary-workspace-r2-cache.sh", "prepare-workspace-cache-measurement.sh",
    "workspace-cache-report.py", "finish-untrusted-rust-cache.sh",
    "test-build-local-image.sh", "test-workspace-agent-contract.sh",
    "rehearse-build-local-image.sh",
)


def scope_outputs(script, owner, workspace_selected, selection, kind_source):
    with tempfile.NamedTemporaryFile("r") as output:
        environment = {
            "PATH": os.environ["PATH"], "GITHUB_OUTPUT": output.name,
            "WORKSPACE_IMAGE_SELECTED": workspace_selected,
            "VERIFICATION_SELECTION": selection, "KIND_WORKSPACE_SOURCE": kind_source,
        }
        if owner is not None:
            environment["WORKSPACE_IMAGE_OWNER"] = owner
        status = subprocess.run(["bash", "-c", script], env=environment, check=False,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        return status, dict(line.split("=", 1) for line in output.read().splitlines() if "=" in line)


def violation(text):
    try:
        jobs = yaml.safe_load(text)["jobs"]
        dispatch = [step for step in jobs["verification-selection"]["steps"] if step.get("id") == "dispatch"]
        steps = jobs["workspace-image"]["steps"]
    except Exception as error:  # A mutation may break the document itself.
        return f"the workflow does not parse: {error}"
    if len(dispatch) != 1 or (dispatch[0].get("env") or {}).get("WORKSPACE_IMAGE_OWNER") != OWNER:
        return "the dispatch decision does not receive the main-push workspace owner"
    scope = [step for step in steps if step.get("id") == "container-scope"]
    if len(scope) != 1 or (scope[0].get("env") or {}).get("WORKSPACE_IMAGE_OWNER") != OWNER:
        return "the container scope does not receive the main-push workspace owner"
    if "continue-on-error" in scope[0]:
        return "the container scope continues on error"
    scope_index = steps.index(scope[0])
    seen = set()
    for index, step in enumerate(steps):
        name = step.get("name") or step.get("uses", "")
        if name in GUARDED:
            seen.add(name)
            if step.get("if") != GUARDED[name]:
                return f"{name} is not guarded by the resolved workspace scope"
            if index < scope_index:
                return f"{name} runs before the container scope resolves"
        elif any(command in str(step.get("run", "")) for command in WORKSPACE_WORK):
            return f"{name} runs workspace work outside the guarded steps"
    if seen != set(GUARDED):
        return f"guarded workspace steps are missing: {sorted(set(GUARDED) - seen)}"
    # The executed decision: support-images never builds; CI builds exactly a
    # selected workspace that Kind does not build; dashboard and iOS keep the
    # job's checkout under either owner.
    script = scope[0].get("run", "")
    for owner, workspace_selected, kind, web, ios, kind_source in itertools.product(
            (None, "", "ci", "support-images"), ("true", "false"),
            (False, True), (False, True), (False, True), ("", "source", "pinned")):
        tokens = ["policy"] + [token for token, on in (("kind", kind), ("web", web), ("ios", ios)) if on]
        selection = "|valid:v3|" + "|".join(tokens) + "|complete|"
        status, outputs = scope_outputs(script, owner, workspace_selected, selection, kind_source)
        workspace = (owner != "support-images" and workspace_selected == "true"
                     and (not kind or kind_source == "pinned"))
        expected = {"workspace": str(workspace).lower(),
                    "selected": str(workspace or ios or (web and not kind)).lower()}
        if status != 0 or outputs != expected:
            return (f"the container scope decided {outputs} (status {status}) for owner={owner!r} "
                    f"workspace={workspace_selected} selection={selection} kind={kind_source!r}; "
                    f"expected {expected}")
    for owner in ("support_images", "CI", "main", "publish", " ci", "ci "):
        status, outputs = scope_outputs(script, owner, "true", "|valid:v3|policy|complete|", "")
        if status == 0 or outputs:
            return f"the container scope accepted the workspace owner {owner!r}"
    return None


text = open(sys.argv[1], encoding="utf-8").read()
problem = violation(text)
if problem:
    sys.exit(problem)
if sys.argv[2:] == ["--mutations"]:
    old_guard = ("needs.verification-selection.outputs.workspace_image_selected == 'true' && "
                 "(!contains(needs.verification-selection.outputs.selection, '|kind|') || "
                 "needs.verification-selection.outputs.kind_workspace_source == 'pinned')")
    build = "      - name: Build and inspect without publication\n        if: "
    build_if = GUARDED["Build and inspect without publication"]
    rehearsal = "      - name: Prove isolated Buildx load contract\n        if: "
    rehearsal_if = GUARDED["Prove isolated Buildx load contract"]
    scope_owner = "          # Same value as the dispatch decision's owner.\n          WORKSPACE_IMAGE_OWNER: "
    dispatch_owner = "Same value as the container scope below.\n          WORKSPACE_IMAGE_OWNER: "
    checkout = f"        if: ${{{{ {RECEIPT} && steps.container-scope.outputs.selected == 'true' }}}}\n"
    mutations = {
        "build guarded by the artifact fact": (build + build_if, build + build_if.replace(WORKSPACE, old_guard)),
        "build bypassed on a push":
            (build + build_if, build + build_if.replace(" }}", " || github.event_name == 'push' }}")),
        "build guarded by the receipt alone": (build + build_if, build + f"${{{{ {RECEIPT} }}}}"),
        "rehearsal guarded by the artifact fact":
            (rehearsal + rehearsal_if, rehearsal + rehearsal_if.replace(WORKSPACE, old_guard)),
        "scope owner forced to ci": (scope_owner + OWNER, scope_owner + "ci"),
        "dispatch owner forced to ci": (dispatch_owner + OWNER, dispatch_owner + "ci"),
        "scope owner forced to support-images": (scope_owner + OWNER, scope_owner + "support-images"),
        "scope owner removed": (scope_owner + OWNER + "\n", "\n"),
        "scope ignores the owner":
            ('if [ "$owner" = ci ] && [ "$WORKSPACE_IMAGE_SELECTED" = true ]',
             'if [ "$WORKSPACE_IMAGE_SELECTED" = true ]'),
        "scope never builds": ("            workspace=true\n", "            workspace=false\n"),
        "scope accepts any owner": ("            ci|support-images) ;;\n", "            *) ;;\n"),
        "scope continues on error":
            ("        id: container-scope\n", "        id: container-scope\n        continue-on-error: true\n"),
        "unguarded workspace build":
            (checkout, checkout + "\n      - name: Build the workspace\n"
                                  f"        if: ${{{{ {RECEIPT} }}}}\n"
                                  "        run: scripts/ci/verify/verify-workspace-image.sh\n"),
    }
    for label, (old, new) in mutations.items():
        if text.count(old) != 1:
            sys.exit(f"owner mutation did not apply: {label}")
        if violation(text.replace(old, new)) is None:
            sys.exit(f"owner mutation was accepted: {label}")
    print(f"workspace owner: {len(mutations)} mutations refused")
OWNER_PY
}
owner_report="$(owner_violation "$WORKFLOW" --mutations 2>&1)" ||
  fail "${owner_report:-workspace owner check failed}"
printf '%s\n' "$owner_report"
# Both workflow owners execute the same fail-closed canary entrypoint. Execute
# that checked-in shell in an isolated mock tree; unavailable identity must fail
# before the harness, and a failed harness must stop the selected job.
awk '
  /- name: Prove labeled R2 backend compatibility/ { scope = 1; next }
  scope && /^        run: \|$/ { run = 1; next }
  run && /^          / { print substr($0, 11); next }
  run { exit }
' "$WORKFLOW" >"$work/canary-step.sh"
[[ -s "$work/canary-step.sh" ]] || fail 'labeled canary script was not extracted'
[[ "$(grep -Fc "env.CODEWIRE_WORKSPACE_CACHE_CANARY == 'true'" "$WORKFLOW")" -eq 2 ]] ||
  fail 'both workspace owners must explicitly select the labeled canary'
mkdir -p "$work/scripts/ci/tests"
cat >"$work/scripts/ci/tests/canary-workspace-r2-cache.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >"$CANARY_CALL"
exit "${CANARY_STATUS:-0}"
EOF
chmod +x "$work/scripts/ci/tests/canary-workspace-r2-cache.sh"
for mode in local disabled r2; do
  rm -f "$work/canary-call"
  status=0
  (cd "$work" && env CODEWIRE_BUILDKIT_CACHE_MODE="$mode" \
    CODEWIRE_SCCACHE_CREDENTIALS_FILE='/mock/private-cache.aws' RUNNER_TEMP='/mock/temp' \
    CANARY_CALL="$work/canary-call" bash "$work/canary-step.sh") >"$work/canary-step.log" 2>&1 || status=$?
  if [[ "$mode" == r2 ]]; then
    [[ "$status" == 0 && -s "$work/canary-call" ]] || fail 'R2 canary was not executed'
    [[ "$(cat "$work/canary-call")" == $'/mock/private-cache.aws\n/mock/temp/workspace-r2-cache-canary' ]] ||
      fail 'canary did not receive only the existing credential path and bounded report path'
  else
    [[ "$status" != 0 && ! -e "$work/canary-call" ]] || fail 'canary accepted unavailable R2 identity'
    grep -qF 'could not obtain its existing cache identity' "$work/canary-step.log" ||
      fail 'identity failure was not distinguished from backend failure'
  fi
done
if (cd "$work" && env CODEWIRE_BUILDKIT_CACHE_MODE=r2 \
    CODEWIRE_SCCACHE_CREDENTIALS_FILE='/mock/private-cache.aws' RUNNER_TEMP='/mock/temp' \
    CANARY_CALL="$work/canary-call" CANARY_STATUS=71 bash "$work/canary-step.sh"); then
  fail 'workflow accepted a failed R2 compatibility canary'
fi
# Run the actual verifier and identity helper in a private source fixture. Never
# write a synthetic acceptance receipt into the developer checkout.
fixture_root="$work/source"
fixture_helper="$ROOT/scripts/ci/tests/cw_image_fixtures.py"
python3 -B "$fixture_helper" source "$fixture_root" >"$work/source-identity.json"
fixture_sha="$(jq -er .source_sha "$work/source-identity.json")"
fixture_tree="$(jq -er .source_tree "$work/source-identity.json")"
case "$(uname -m)" in
  x86_64) standalone_producers=1 ;;
  aarch64) standalone_producers=0 ;;
  *) fail 'workspace fixture requires native amd64 or arm64' ;;
esac
fixture_receipt="$fixture_root/.tmp/codewire-workspace-image-verification.json"
cat >"$work/bin/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *'status --porcelain --untracked-files=normal' && "${FAKE_DIRTY:-false}" != false ]]; then
  printf ' M tracked-file\n'; exit 0
fi
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0
exec /usr/bin/git -c core.hooksPath=/dev/null -c maintenance.auto=false -c gc.auto=0 "$@"
EOF
cat >"$work/bin/docker" <<EOF
#!/usr/bin/env bash
set -euo pipefail
# The copied-byte verifier deliberately clears its child environment. These
# are only fixed private fixture paths, never production fake-env exceptions.
FAKE_DOCKER_LOG=\${FAKE_DOCKER_LOG:-$(printf '%q' "$work/docker.log")}
FAKE_IMAGE_ID=\${FAKE_IMAGE_ID:-$(printf '%q' "$work/image-id")}
FAKE_IMAGE_LABELS=\${FAKE_IMAGE_LABELS:-$(printf '%q' "$work/image-labels")}
FAKE_SELECTED_RESULT=$(printf '%q' "$work/selected-producer-result")
FAKE_SOURCE=$(printf '%q' "$fixture_root")
CW_IMAGE_FIXTURES=$(printf '%q' "$fixture_helper")
FAKE_CASE_MODE_FILE=$(printf '%q' "$work/current-fixture-mode")
FAKE_REUSE_RESULT_FILE=$(printf '%q' "$work/reuse-producer-result")
EOF
cat >>"$work/bin/docker" <<'EOF'
FAKE_FAIL=${FAKE_FAIL-$(<"$FAKE_CASE_MODE_FILE")}
printf '%q ' "$@" >>"$FAKE_DOCKER_LOG"
printf '\n' >>"$FAKE_DOCKER_LOG"

case "${1:-} ${2:-}" in
  'info --format') printf 'daemon-%s\n' "$FAKE_BUILDER_SUFFIX" ;;
  'version --format') printf '29.7.1\n' ;;
  'buildx version') printf 'buildx pinned-fixture\n' ;;
  'buildx inspect')
    if [[ "${FAKE_FAIL:-}" == cleanup-gone && -e "$FAKE_DAEMON_FILE.removed" && "${3:-}" == codewire-workspace-* ]]; then
      echo "ERROR: no builder \"$3\" found" >&2
      exit 1
    fi
    printf 'Name: %s\n' "${FAKE_SELECTED_BUILDER:-selected-verifier}"
    printf 'Driver: %s\n' "${FAKE_SELECTED_DRIVER:-docker-container}"
    ;;
  'buildx create')
    printf 'workspace-verifier-%s\n' "$FAKE_BUILDER_SUFFIX"
    ;;
  'buildx history')
    [[ "$3 $4 $6 $7" == 'logs --builder --progress rawjson' ]] || exit 97
    [[ "${FAKE_FAIL:-}" != history-failure ]] || exit 47
    if [[ "$8" == bbbbbbbbbbbbbbbbbbbbbbbbb ]]; then
      [[ "$5/$5-node/$8" == "$(<"$FAKE_IMAGE_ID.producer-ref")" ]] || exit 97
      vertex='[cw-builder 1/1] RUN fixed synthetic compiler input'
    else
      [[ "$5/$5-node/$8" == "$(<"$FAKE_IMAGE_ID.build-ref")" ]] || exit 97
      if [[ "$(uname -m)" == x86_64 ]]; then
        vertex='[cw-builder 1/1] COPY admitted cw /usr/local/bin/cw'
      else
        vertex='[cw-builder 1/1] RUN cargo build'
      fi
    fi
    printf '{"vertexes":[{"digest":"sha256:%064d","inputs":["sha256:%064d"],"name":"%s","started":"2026-09-10T10:00:00Z","completed":"2026-09-10T10:00:01Z"}]}\n' 6 7 "$vertex" >&2
    ;;
  'buildx build')
    if [[ "${FAKE_FAIL:-}" == cancel ]]; then
      # The actual verifier owns this pipeline. Deliver TERM to that process,
      # exercising its signal trap while an owned builder exists.
      kill -TERM "$PPID"
      exit 143
    fi
    if [[ " $* " == *' --target cw-runtime-export '* ]]; then
      metadata=''; producer_builder=''
      for ((index=1; index<=$#; index++)); do
        next=$((index+1))
        case "${!index}" in
          --metadata-file) metadata="${!next}" ;;
          --builder) producer_builder="${!next}" ;;
        esac
      done
      [[ -n "$metadata" && -n "$producer_builder" ]]
      printf '%s/%s-node/bbbbbbbbbbbbbbbbbbbbbbbbb' "$producer_builder" "$producer_builder" >"$FAKE_IMAGE_ID.producer-ref"
      printf '%s/cw-producer-result.json\n' "$(dirname "$(dirname "$(dirname "$metadata")")")" >"$FAKE_SELECTED_RESULT"
      exec python3 -B "$CW_IMAGE_FIXTURES" export -- "$@"
    fi
    metadata_file=''
    archive_file=''
    builder=''
    : >"$FAKE_IMAGE_LABELS.next"
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --metadata-file) metadata_file="$2"; shift ;;
        --builder) builder="$2"; shift ;;
        --output)
          if [[ "$2" == type=oci,dest=*.oci.tar ]]; then archive_file="${2#type=oci,dest=}"; fi
          shift ;;
        --label) printf '%s\n' "$2" >>"$FAKE_IMAGE_LABELS.next"; shift ;;
      esac
      shift
    done
    if [[ -s "$FAKE_IMAGE_LABELS.next" ]]; then
      mv "$FAKE_IMAGE_LABELS.next" "$FAKE_IMAGE_LABELS"
    fi
    if [[ -n "$metadata_file" ]]; then
      case "${FAKE_METADATA_MODE:-valid}" in
        valid) printf '{"containerimage.digest":"sha256:%064d"}\n' 0 >"$metadata_file" ;;
        missing) printf '{}\n' >"$metadata_file" ;;
        malformed) printf '{not-json}\n' >"$metadata_file" ;;
        *) exit 98 ;;
      esac
    fi
    # Only the base build hands the producer pointer to its metadata directory;
    # the cache-only arm64 cw check has no metadata and no pointer.
    if [[ -z "$archive_file" && -n "$metadata_file" && -s "$FAKE_REUSE_RESULT_FILE" ]]; then
      reused_result="$(<"$FAKE_REUSE_RESULT_FILE")"
      if [[ -n "$reused_result" ]]; then
        result_path="$(dirname "$metadata_file")/cw-image-work/cw-producer-result.json"
        python3 -B "$CW_IMAGE_FIXTURES" retain-result "$FAKE_SOURCE" "$reused_result" "$result_path"
        printf '%s\n' "$result_path" >"$FAKE_SELECTED_RESULT"
      fi
    fi
    if [[ -n "${CODEWIRE_WORKSPACE_CACHE_CASE:-}" ]]; then
      measurement_sleep_pid=''
      trap 'trap "" TERM INT
        measurement_sleep_pid="${measurement_sleep_pid:-${!:-}}";
        if [[ -n "$measurement_sleep_pid" ]]; then
          wait "$measurement_sleep_pid" 2>/dev/null || true
        fi
        exit 143' TERM INT
      sleep 0.1 &
      measurement_sleep_pid=$!
      wait "$measurement_sleep_pid"
      trap - TERM INT
      if [[ -n "$archive_file" ]]; then
        if [[ "${FAKE_FAIL:-}" == sampler-bookkeeping ]]; then
          mkdir "$CODEWIRE_WORKSPACE_CACHE_REPORT_DIR/sampler-stop-request"
        fi
        printf '#1 [workspace-floating-tools 1/2] RUN npm install\n#1 DONE 0.1s\n'
        printf '#2 [workspace-floating-tools 2/2] RUN go install\n#2 DONE 0.1s\n'
        if [[ "$(uname -m)" == x86_64 ]]; then
          printf '#3 [cw-builder 1/1] COPY admitted cw /usr/local/bin/cw\n#3 DONE 0.1s\n'
        else
          printf '#3 [cw-builder 1/1] RUN cargo build\n#3 DONE 0.1s\n#3 0.1 Cache hits 4\n'
        fi
      fi
      [[ "$CODEWIRE_BUILDKIT_CACHE_MODE" != r2 ]] || printf '#9 exporting cache to Amazon S3\n#9 DONE 0.1s\n'
    elif [[ -n "$archive_file" ]]; then
      if [[ "$(uname -m)" == x86_64 ]]; then
        printf '#3 [cw-builder 1/1] COPY admitted cw /usr/local/bin/cw\n#3 DONE 0.1s\n'
      else
        printf '#3 [cw-builder 1/1] RUN cargo build\n#3 DONE 0.1s\n'
      fi
    fi
    if [[ -n "$archive_file" ]]; then
      python3 - "$FAKE_OCI_FIXTURE" "$archive_file" "$FAKE_IMAGE_ID" <<'PY'
import hashlib, json, os, platform, runpy, sys
from pathlib import Path
fixture = runpy.run_path(sys.argv[1])
config_value = {'os': 'linux',
                'architecture': {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()],
                'rootfs': {'type': 'layers', 'diff_ids': []}}
if os.environ.get('FAKE_FAIL') == 'receipt':
    config_value['config'] = {'Env': ['SYNTHETIC_EXPORT_FAILURE=1']}
config = json.dumps(config_value, sort_keys=True).encode()
change = None
if os.environ.get('FAKE_ARCHIVE_VARIANT') == 'true':
    change = lambda entries: entries.update({
        'oci-layout': b'{ "imageLayoutVersion": "1.0.0" }\n',
    })
fixture['write_archive'](Path(sys.argv[2]), config=config, change=change)
Path(sys.argv[3]).write_text('sha256:' + hashlib.sha256(config).hexdigest())
PY
      printf '%s/%s-node/aaaaaaaaaaaaaaaaaaaaaaaaa' "$builder" "$builder" >"$FAKE_IMAGE_ID.build-ref"
      python3 - "$metadata_file" "$FAKE_IMAGE_ID" <<'PY'
import json, sys
from pathlib import Path
image = Path(sys.argv[2])
Path(sys.argv[1]).write_text(json.dumps({'containerimage.config.digest': image.read_text(),
                                       'buildx.build.ref': Path(str(image) + '.build-ref').read_text()}))
PY
    fi
    ;;
  'buildx rm')
    [[ "${FAKE_FAIL:-}" != cleanup ]] || exit 43
    if [[ "${FAKE_FAIL:-}" == cleanup-gone ]]; then
      # The CLI reports failure although the owned container is already gone.
      : >"$FAKE_DAEMON_FILE.removed"
      echo 'ERROR: failed to remove one or more builders' >&2
      exit 43
    fi
    # Exercise the real timeout boundary, not a fake timeout implementation.
    [[ "${FAKE_FAIL:-}" != slow-cleanup ]] || sleep 11
    ;;
  'container inspect')
    if [[ "${FAKE_FAIL:-}" == cleanup-gone && -e "$FAKE_DAEMON_FILE.removed" ]]; then
      echo "Error: No such container: ${*: -1}" >&2
      exit 1
    fi
    if [[ "$5" == '{{.Id}}' ]]; then
      printf '%064d\n' 4
    elif [[ "$5" == '{{.Image}}' ]]; then
      printf 'sha256:%064d\n' 8
    else
      printf '%s\n' 'docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5'
    fi
    ;;
  'volume inspect')
    # Only a failed builder removal probes the state volume. It is gone once
    # the synthetic daemon removed the builder; otherwise it persists.
    [[ "${*: -1}" == buildx_buildkit_codewire-workspace-*-node_state ]] || exit 99
    if [[ "${FAKE_FAIL:-}" == cleanup-gone && -e "$FAKE_DAEMON_FILE.removed" ]]; then
      echo "Error response from daemon: get ${*: -1}: no such volume" >&2
      exit 1
    fi
    printf '%s\n' "${*: -1}"
    ;;
  'volume rm')
    [[ "${*: -1}" == buildx_buildkit_codewire-workspace-*-node_state ]] || exit 99
    echo 'Error response from daemon: volume is in use' >&2
    exit 1
    ;;
  'exec --interactive') cat >"$FAKE_DAEMON_FILE" ;;
  'image inspect')
    if [[ "${4:-}" == --format ]]; then
      cat "$FAKE_IMAGE_ID"
    else
      python3 - "$FAKE_IMAGE_LABELS" "$FAKE_IMAGE_ID" <<'PY'
import json, platform, sys
from pathlib import Path
labels = dict(line.split('=', 1) for line in Path(sys.argv[1]).read_text().splitlines())
print(json.dumps([{'Id': Path(sys.argv[2]).read_text(), 'Os': 'linux',
                  'Architecture': {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()],
                  'Config': {'Labels': labels}}]))
PY
    fi
    ;;
  'image tag')
    ;;
  'container ls')
    [[ "$#" == 8 && "$3 $4 $5 $7 $8" == '--all --no-trunc --filter --format {{.ID}}' \
      && "$6" =~ ^name=\^/codewire-workspace-cw-[0-9a-f]{32}\$$ ]] || exit 99
    # The synthetic --rm observation never leaves a container behind.
    ;;
  'rm --force')
    # A failed builder removal removes its daemon container again; that
    # container persists in the synthetic daemon. Others are contract runs.
    [[ "${3:-}" == buildx_buildkit_* ]] || rm -f "$FAKE_CONTRACT_RUNNING"
    ;;
  'run --rm')
    if [[ " $* " == *' --entrypoint /usr/bin/cat '* ]]; then
      copy_options=()
      [[ "${FAKE_FAIL:-}" != cw-mismatch ]] || copy_options+=(--mismatch)
      exec python3 -B "$CW_IMAGE_FIXTURES" docker-cat "${copy_options[@]}" "$FAKE_SOURCE" "$(<"$FAKE_SELECTED_RESULT")" "$(<"$FAKE_IMAGE_ID")" -- "$@"
    fi
    if [[ "$*" == *'--entrypoint python3'* ]]; then
      python3 - <<'PY'
import json
print(json.dumps({key: 'version1' for key in ('npm', 'pnpm', 'yarn', 'bun', 'gopls', 'hcloud', 'poetry', 'uv', 'aider')}))
PY
      exit 0
    fi
    if [[ "${FAKE_FAIL:-}" == hang-contract ]]; then
      printf '%s\n' "$$" >"$FAKE_CONTRACT_PROCESS"
      : >"$FAKE_CONTRACT_RUNNING"
      sleep 30 &
      child_pid=$!
      printf '%s\n' "$child_pid" >"$FAKE_CONTRACT_CHILD"
      trap 'kill "$child_pid" 2>/dev/null || true; wait "$child_pid" 2>/dev/null || true; exit 143' TERM INT
      wait "$child_pid"
      exit 0
    fi
    if [[ "$*" == *'--mounted-home-agents'* ]]; then
      [[ "${FAKE_FAIL:-}" != mounted ]] || exit 42
      if [[ "${FAKE_FAIL:-}" == receipt ]]; then
        # Force atomic receipt replacement to fail only after both contracts
        # pass. This must retire the newly exported, distinct archive.
        mkdir "$FAKE_RECEIPT"
      fi
    else
      [[ "${FAKE_FAIL:-}" != full ]] || exit 41
    fi
    ;;
  *)
    if [[ "$1" == exec && "${3:-}" == sh ]]; then
      if tr '\0' ' ' <"/proc/$PPID/cmdline" | grep -q 'workspace-cache-report.py sample ' \
          && [[ ! -e "$FAKE_SAMPLER_PROCESS" ]]; then
        # Publish one complete private identity without unlinking an open reader.
        sampler_identity="$(mktemp "$FAKE_SAMPLER_PROCESS.XXXXXX")"
        printf '%s\n' "$PPID" >"$sampler_identity"
        mv -T -- "$sampler_identity" "$FAKE_SAMPLER_PROCESS"
      fi
      printf '1000 10000 2000 8000 3000 4000\n'
      exit 0
    fi
    if [[ "$1" == exec && "${3:-}" == rm ]]; then
      [[ "${FAKE_FAIL:-}" != daemon-erase ]] || exit 45
      rm -f "$FAKE_DAEMON_FILE"
      exit 0
    fi
    printf 'unexpected docker command: %s\n' "$*" >&2
    exit 99
    ;;
esac
EOF
chmod +x "$work/bin/docker" "$work/bin/git"
printf '{"repository":{"full_name":"codewire/codewire"},"pull_request":{"number":2047,"base":{"ref":"main","repo":{"full_name":"codewire/codewire"}},"head":{"ref":"experiment/workspace-r2-cache/fixture","sha":"%s"},"labels":[]}}\n' "$fixture_sha" >"$work/measurement-event.json"
mkdir "$work/measurement"

run_mock_verifier() {
  printf '%s\n' "${4:-}" >"$work/current-fixture-mode"
  printf '%s\n' "${MOCK_PRODUCER_RESULT:-}" >"$work/reuse-producer-result"
  local -a invocation=(env PATH="$work/bin:$PATH" \
    CODEWIRE_VERSION=0.0.0-ci \
    CODEWIRE_DOCKER_BIN="$work/bin/docker" \
    CODEWIRE_SCCACHE_MODE="${MOCK_COMPILER:-local}" \
    CODEWIRE_BUILDKIT_CACHE_MODE="${MOCK_LAYERS:-local}" \
    CODEWIRE_WORKSPACE_IMAGE_REUSE="${MOCK_REUSE:-auto}" \
    CODEWIRE_WORKSPACE_CW_PRODUCER_RETAIN="${MOCK_RETAIN:-0}" \
    CODEWIRE_WORKSPACE_CACHE_CASE="${MOCK_MEASUREMENT_CASE:-}" \
    CODEWIRE_WORKSPACE_CACHE_REPORT_DIR="$work/measurement/$1" \
    CODEWIRE_EXPECTED_SOURCE_SHA="$fixture_sha" CODEWIRE_EXPECTED_SOURCE_TREE="$fixture_tree" \
    GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$work/measurement-event.json" \
    GITHUB_REF=refs/pull/2047/head GITHUB_SHA="$fixture_sha" GITHUB_REPOSITORY=codewire/codewire \
    GITHUB_JOB=workspace-fixture GITHUB_RUN_ID=2047 GITHUB_RUN_ATTEMPT=1 RUNNER_TEMP="$work/measurement" \
    CODEWIRE_SCCACHE_CREDENTIALS_FILE="${MOCK_CREDENTIALS:-}" \
    SCCACHE_BUCKET=example-ci-cache-untrusted \
    SCCACHE_ENDPOINT=https://00000000000000000000000000000000.r2.cloudflarestorage.com \
    CODEWIRE_SCCACHE_PREFIX=untrusted/codewire/v1 \
    CODEWIRE_APT_SNAPSHOT_MIRROR="${MOCK_APT_MIRROR:-}" \
    FAKE_DOCKER_LOG="$work/docker.log" \
    FAKE_BUILDER_SUFFIX="$1" \
    FAKE_METADATA_MODE="${2:-valid}" \
    FAKE_SELECTED_DRIVER="${3:-docker-container}" \
    FAKE_IMAGE_LABELS="$work/image-labels" \
    FAKE_IMAGE_ID="$work/image-id" \
    FAKE_OCI_FIXTURE="$ROOT/scripts/ci/tests/test-workspace-image-artifact.py" \
    FAKE_ARCHIVE_VARIANT="${MOCK_ARCHIVE_VARIANT:-false}" \
    FAKE_RECEIPT="$fixture_receipt" \
    FAKE_DAEMON_FILE="$work/daemon.aws" \
    FAKE_CONTRACT_PROCESS="$work/contract-process" \
    FAKE_CONTRACT_CHILD="$work/contract-child" \
    FAKE_CONTRACT_RUNNING="$work/contract-running" \
    FAKE_SAMPLER_PROCESS="$work/sampler-process" \
    FAKE_FAIL="${4:-}" \
    FAKE_DIRTY="${5:-false}" \
    TMPDIR="$work/tmp" \
    "$fixture_root/scripts/ci/verify/verify-workspace-image.sh")
  if [[ "${MOCK_EXEC:-false}" == true ]]; then exec "${invocation[@]}"; fi
  "${invocation[@]}"
}

# Base/workspace builds exclude the original CW producer and the arm64 cw check.
pair_build_count() {
  grep '^buildx build ' "$work/docker.log" | grep -v -- '--target cw-runtime-export' |
    { grep -vc -- '--target cw-builder-arm64' || true; }
}
arm64_cw_build_count() {
  grep '^buildx build ' "$work/docker.log" | { grep -c -- '--target cw-builder-arm64' || true; }
}

# Assert behavior and ordering rather than incidental inspection call counts.
: >"$work/docker.log"
run_mock_verifier success >/dev/null
grep -q '^buildx create --name codewire-workspace-' "$work/docker.log" || fail 'owned builder was not created'
grep -q -- '--driver-opt image=docker.io/moby/buildkit:v0.29.0@sha256:' "$work/docker.log" || fail 'daemon is not pinned'
[[ "$(pair_build_count)" == 2 ]] || fail 'base/workspace pair was not built once'
[[ "$(grep -c -- '--target cw-runtime-export' "$work/docker.log" || true)" == "$standalone_producers" ]] || fail 'CW producer count differs from the selected architecture'
# Only an amd64 host cross-checks the arm64 cw; an arm64 host builds it natively.
[[ "$(arm64_cw_build_count)" == "$standalone_producers" ]] || fail 'arm64 cw cross-compile count differs from the selected architecture'
if [[ "$standalone_producers" == 1 ]]; then
  arm64_cw_call="$(grep '^buildx build ' "$work/docker.log" | grep -- '--target cw-builder-arm64')"
  for arm64_cw_input in '--platform linux/arm64' '--output type=cacheonly' \
      '--build-arg CODEWIRE_RUST_PROFILE=runtime' '--build-arg CODEWIRE_SCCACHE_MODE=local' \
      "--build-arg BASE_IMAGE_REF=$(sed -n 's/^FROM \(ubuntu:noble@sha256:[0-9a-f]\{64\}\)$/\1/p' "$ROOT/images/base/Dockerfile")"; do
    grep -qF -- "$arm64_cw_input" <<<"$arm64_cw_call" || fail "arm64 cw cross-compile call omits $arm64_cw_input"
  done
  arm64_cw_line="$(grep -n -- '--target cw-builder-arm64' "$work/docker.log" | cut -d: -f1)"
  [[ "$arm64_cw_line" -lt "$(grep -n '^buildx rm ' "$work/docker.log" | cut -d: -f1)" ]] ||
    fail 'arm64 cw cross-compile ran outside the owned builder lifetime'
fi
grep -q -- '--output type=oci\\,dest=.*base.oci\\,tar=false' "$work/docker.log" || fail 'exact base OCI export missing'
grep -q -- '--build-context codewire-verified-base=oci-layout://.*base.oci@sha256:' "$work/docker.log" || fail 'exact base handoff missing'
grep -q -- '--no-cache-filter workspace-floating-tools' "$work/docker.log" || fail 'floating tools could be reused'
grep -q -- '--build-arg CODEWIRE_SCCACHE_MODE=local' "$work/docker.log" || fail 'compiler policy missing'
image_id="$(cat "$work/image-id")"
grep -Eq "run --rm --interactive --pids-limit=2048 --name codewire-workspace-[^ ]+-full --user 1000:1000 --entrypoint bash $image_id -eu -s " "$work/docker.log" || fail 'full image contract omitted'
grep -q -- '--tmpfs /home/codewire:rw.* --entrypoint bash .* --mounted-home-agents' "$work/docker.log" || fail 'mounted-home contract omitted'
cleanup_line="$(grep -n '^buildx rm ' "$work/docker.log" | cut -d: -f1)"
seal_line="$(grep -n '^image tag ' "$work/docker.log" | cut -d: -f1)"
contract_line="$(grep -n -- '--mounted-home-agents' "$work/docker.log" | cut -d: -f1)"
[[ "$cleanup_line" -lt "$contract_line" && "$contract_line" -lt "$seal_line" ]] || fail 'builder outlived contracts or seal preceded acceptance'
[[ -s "$fixture_receipt" && "$(stat -c %a "$fixture_receipt")" == 600 ]] || fail 'private receipt missing'
if [[ "$standalone_producers" == 1 ]]; then
  default_producer_pointer="$(<"$work/selected-producer-result")"
  [[ ! -e "$default_producer_pointer" && ! -e "${default_producer_pointer%/cw-image-work/*}" ]] ||
    fail 'default verification retained its original producer staging'
fi
archive_name="$(jq -er '.workspace_oci.file' "$fixture_receipt")"
[[ "$(stat -c '%a %h' "$fixture_root/.tmp/$archive_name")" == '400 1' ]] ||
  fail 'verified OCI archive is not immutable and single-linked'
grep -q -- '--output type=oci\\,dest=.*workspace.oci.tar' "$work/docker.log" ||
  fail 'workspace build did not export the verified image for native use'
grep -Eq -- '--provenance(=| )false --sbom(=| )false' "$work/docker.log" ||
  fail 'verification-only OCI export unexpectedly contains attestations'
! grep -q 'codewire-apt-mirror' "$work/docker.log" ||
  fail 'an empty apt snapshot cache setting reached BuildKit'

: >"$work/docker.log"
run_mock_verifier reuse >/dev/null
[[ "$(wc -l <"$work/docker.log")" == 2 ]] || fail 'exact-tree reuse rebuilt or reran contracts'
! grep -Eq '^buildx |^run ' "$work/docker.log" || fail 'verified image reuse performed duplicate qualification'

# An image-only acceptance is insufficient for opt-in producer retention. Run
# the unchanged compiler/copy/contracts/seal route and retain its original
# paths, not a copied JSON descriptor or a relabeled build reference.
if [[ "$standalone_producers" == 1 ]]; then
  : >"$work/docker.log"
  MOCK_RETAIN=1 run_mock_verifier retained >"$work/retained.out" 2>&1 || {
    cat "$work/retained.out" >&2; fail 'opt-in producer retention failed';
  }
  [[ "$(pair_build_count)" == 2 \
    && "$(grep -c -- '--target cw-runtime-export' "$work/docker.log")" == 1 ]] ||
    fail 'image-only reuse bypassed retained producer qualification'
  retained_pointer="$(<"$work/selected-producer-result")"
  [[ "$retained_pointer" == "$work/tmp/"*/cw-image-work/cw-producer-result.json \
    && -s "$retained_pointer" && -s "$fixture_receipt" ]] ||
    fail 'opt-in success discarded its original producer pointer'
  python3 -B - "$fixture_root" "$retained_pointer" "$work/retained.out" <<'PY'
from contextlib import closing
import hashlib, importlib.util, json, os, pathlib, stat, sys
root, pointer, log = map(pathlib.Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location('retention_contract', root / 'scripts/ci/images/cw-image-consumer.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
with closing(module.asset.HeldFile(pointer, module.release.MAX_JSON)) as held:
    value = module.release.parse_canonical(held.data)
    lines = [line for line in log.read_text().splitlines() if line.startswith('{')
             and module.release.parse_json(line.encode()).get('status') == 'workspace-cw-producer-retained']
    assert len(lines) == 1, 'retention result missing or repeated'
    note = module.release.parse_canonical(lines[0].encode() + b'\n')
    assert note == {'status': 'workspace-cw-producer-retained', 'result': held.evidence(),
                    'profile': value['profile'], 'version': value['version'],
                    'source': value['source'], 'original_build_ref': value['build_ref']}
    revision = module.producer.source.git(root, ['rev-parse', 'HEAD']).strip().decode()
    with module.producer.reopen(value['receipt']['path'], value['receipt']['sha256'], root,
                                revision, 'runtime', module.effective_version(root, None)) as retained:
        assert value == {key: retained.summary[key] for key in value}
        original = pathlib.Path(value['receipt']['path']).parent
        assert original.is_relative_to(pointer.parent) and stat.S_IMODE(original.stat().st_mode) == 0o700
        assert len(module.producer.finalizer.FILES) == 8
        for name in module.producer.finalizer.FILES:
            path = original / 'assets' / name
            assert path.is_file() and path.stat().st_nlink == 1
            assert stat.S_IMODE(path.stat().st_mode) == (0o500 if name == 'cw' else 0o400)
        assert (original / 'source-context/source').is_dir() and (original / 'source-context/git').is_dir()
        assert (original / 'source-context/request.json').is_file()
        metadata = json.loads((original / 'metadata.json').read_bytes())
        assert metadata['buildx.build.ref'] == value['build_ref'] == note['original_build_ref']
        assert hashlib.sha256((original / 'assets/cw.d').read_bytes()).hexdigest() == retained.model['depinfo']['sha256']
        retained.revalidate(); held.revalidate(content=True)
    sealed = next(i for i, line in enumerate(log.read_text().splitlines()) if line.startswith('localhost/codewire-ci/workspace:source-'))
    reported = next(i for i, line in enumerate(log.read_text().splitlines()) if line == lines[0])
    assert sealed < reported, 'retention success preceded the original seal'
PY
  : >"$work/docker.log"
  run_mock_verifier reuse-retained >"$work/reuse-retained.out" 2>&1
  ! grep -Eq '^buildx |^run ' "$work/docker.log" || fail 'default reuse after retention rebuilt'
  ! grep -q 'workspace-cw-producer-retained' "$work/reuse-retained.out" || fail 'image-only reuse claimed retained producer success'
  [[ -s "$retained_pointer" ]] || fail 'default image reuse deleted previously retained staging'
  printf 'workspace producer retention: success/original8exports/default/reuse contract OK\n'
fi

: >"$work/docker.log"
if MOCK_RETAIN=invalid run_mock_verifier invalid-retention >"$work/invalid-retention.out" 2>&1; then
  fail 'invalid producer retention mode was accepted'
fi
[[ ! -s "$work/docker.log" ]] || fail 'invalid producer retention reached Docker or image reuse'

# Fresh verification invalidates the old marker immediately, but successful
# publication still retires that marker's exact previously verified archive.
previous_archive="$fixture_root/.tmp/$archive_name"
: >"$work/docker.log"
MOCK_REUSE=disabled MOCK_ARCHIVE_VARIANT=true run_mock_verifier replacement >/dev/null
replacement_archive="$(jq -er '.workspace_oci.file' "$fixture_receipt")"
[[ "$replacement_archive" != "$archive_name" ]] || fail 'replacement fixture did not produce distinct archive bytes'
[[ ! -e "$previous_archive" && -s "$fixture_root/.tmp/$replacement_archive" ]] ||
  fail 'successful fresh verification did not retire only its prior archive'

# Explicit experiments must build even when an identical receipt exists. A
# failed fresh attempt invalidates the old receipt before it can be consumed.
: >"$work/docker.log"
if MOCK_REUSE=disabled run_mock_verifier invalid missing docker >/dev/null 2>&1; then fail 'accepted missing base digest'; fi
[[ "$(grep -c '^buildx build ' "$work/docker.log")" == 1 ]] || fail 'invalid base reached workspace build'
grep -q '^buildx rm --force codewire-workspace-' "$work/docker.log" || fail 'failed build retained its builder'
[[ ! -e "$fixture_receipt" ]] || fail 'failed fresh attempt retained old receipt'

for failure in full mounted cleanup cancel; do
  : >"$work/docker.log"
  if run_mock_verifier "$failure" valid docker "$failure" >"$work/$failure.out" 2>&1; then fail "accepted $failure failure"; fi
  [[ ! -e "$fixture_receipt" ]] || fail "$failure failure emitted a receipt"
  ! grep -q '^image tag ' "$work/docker.log" || fail "$failure failure sealed an alias"
done
grep -Eq '^workspace cache cleanup: phase=builder-removal status=43 elapsed_seconds=[0-9]+ persists: builder codewire-workspace-[^,]+, container buildx_buildkit_codewire-workspace-[^,]+-node, volume buildx_buildkit_codewire-workspace-[^,]+-node_state$' \
  "$work/cleanup.out" || fail 'builder removal failure did not name what persists'
grep -q 'workspace cache cleanup: builder-removal output: ' "$work/cleanup.out" ||
  fail 'builder removal failure omitted its bounded Buildx output'

# A removal the CLI reports as failed, after Docker confirms the exact owned
# container is gone, achieved the cleanup and must not fail the verification.
: >"$work/docker.log"
rm -f "$work/daemon.aws.removed"
run_mock_verifier cleanup-gone valid docker cleanup-gone >"$work/cleanup-gone.out" 2>&1 ||
  fail 'confirmed-absent builder removal failed the verification'
grep -Eq '^workspace cache cleanup: phase=builder-removal status=43 confirmed-absent=true elapsed_seconds=[0-9]+$' \
  "$work/cleanup-gone.out" || fail 'confirmed-absent builder removal was not reported'
[[ -e "$fixture_receipt" ]] || fail 'confirmed-absent builder removal emitted no receipt'
rm -f "$work/daemon.aws.removed"

if [[ "$standalone_producers" == 1 ]]; then
  for failure in full mounted cleanup receipt cw-mismatch; do
    : >"$work/docker.log"
    if MOCK_RETAIN=1 MOCK_REUSE=disabled run_mock_verifier "retain-$failure" valid docker "$failure" \
        >"$work/retain-$failure.out" 2>&1; then
      fail "retention accepted $failure failure"
    fi
    ! grep -q 'workspace-cw-producer-retained' "$work/retain-$failure.out" ||
      fail "retention success was emitted for $failure failure"
    if [[ "$failure" == receipt ]]; then
      [[ -d "$fixture_receipt" ]] || fail 'retained seal failure was not reached'
      rmdir "$fixture_receipt"
    else
      [[ ! -e "$fixture_receipt" ]] || fail "$failure retention failure emitted a receipt"
    fi
    failed_pointer="$(<"$work/selected-producer-result")"
    if [[ "$failure" == cw-mismatch ]]; then
      [[ -s "$failed_pointer" ]] || fail 'opt-in copy failure discarded original failure evidence'
      grep -q 'failed CW copy evidence retained at ' "$work/retain-$failure.out" ||
        fail 'opt-in copy failure omitted its existing retention diagnostic'
    else
      [[ ! -e "$failed_pointer" ]] || fail "$failure failure retained successful-producer staging"
    fi
  done
  printf 'workspace producer retention: five failure contracts OK\n'
fi

: >"$work/docker.log"
archives_before="$(find "$fixture_root/.tmp" -maxdepth 1 -name 'workspace-image-*.oci.tar' -printf '%f\n' | sort)"
if run_mock_verifier receipt valid docker receipt >/dev/null 2>&1; then
  fail 'verifier accepted atomic receipt failure'
fi
[[ -d "$fixture_receipt" ]] || fail 'receipt-failure fixture was not reached'
rmdir "$fixture_receipt"
[[ "$(find "$fixture_root/.tmp" -maxdepth 1 -name 'workspace-image-*.oci.tar' -printf '%f\n' | sort)" == "$archives_before" ]] ||
  fail 'receipt failure leaked a new archive or removed an existing artifact'
[[ -z "$(find "$fixture_root/.tmp" -maxdepth 1 -name '.workspace-oci.*' -print -quit)" ]] ||
  fail 'receipt failure leaked its staging directory'

: >"$work/docker.log"
# This case's output goes to a file that the exit trap removes; show it when
# the verification fails instead of exiting silently.
MOCK_REUSE=disabled run_mock_verifier slow-cleanup valid docker slow-cleanup >"$work/slow-cleanup.out" 2>&1 || {
  cat "$work/slow-cleanup.out" >&2
  fail 'verification with a slow but bounded state deletion failed'
}
[[ -s "$fixture_receipt" ]] || fail 'bounded slow state deletion failed verification'
cleanup_line="$(grep -n '^buildx rm ' "$work/docker.log" | cut -d: -f1)"
contract_line="$(grep -n '^run --rm ' "$work/docker.log" | head -n1 | cut -d: -f1)"
[[ "$cleanup_line" -lt "$contract_line" ]] || fail 'slow cleanup outlived contract execution'

: >"$work/docker.log"
if run_mock_verifier dirty valid docker-container '' true >/dev/null 2>&1; then fail 'dirty source accepted'; fi
[[ ! -s "$work/docker.log" ]] || fail 'dirty source reached Docker'

: >"$work/docker.log"
MOCK_COMPILER=disabled MOCK_LAYERS=disabled run_mock_verifier cold >/dev/null
[[ "$(grep '^buildx build ' "$work/docker.log" | grep -v -- '--target cw-runtime-export' | grep -v -- '--target cw-builder-arm64' | grep -c -- '--no-cache ')" == 2 ]] || fail 'disabled layer cache did not bypass both builds'
[[ "$(grep -- '--target cw-builder-arm64' "$work/docker.log" | grep -c -- '--no-cache ' || true)" == "$standalone_producers" ]] || fail 'disabled layer cache reused the arm64 cw cross-compile'
if [[ "$standalone_producers" == 1 ]]; then
  grep -- '--target cw-runtime-export' "$work/docker.log" | grep -q -- '--no-cache ' || fail 'disabled producer cache was reused'
else
  ! grep -q -- '--target cw-runtime-export' "$work/docker.log" || fail 'ARM route ran the AMD producer'
fi
! grep -q -- '--no-cache-filter' "$work/docker.log" || fail 'mutually exclusive cache flags were combined'
[[ "$(jq -r '.cache_modes.compiler + "/" + .cache_modes.layers' "$fixture_receipt")" == disabled/disabled ]] || fail 'receipt omitted cache modes'
: >"$work/docker.log"
run_mock_verifier changed-mode >/dev/null
[[ "$(pair_build_count)" == 2 ]] || fail 'mode change reused incompatible evidence'
[[ "$(grep -c -- '--target cw-runtime-export' "$work/docker.log" || true)" == "$standalone_producers" ]] || fail 'mode change producer count differs from its architecture'
: >"$work/docker.log"
if MOCK_LAYERS=invalid run_mock_verifier invalid-mode >/dev/null 2>&1; then fail 'invalid mode accepted'; fi
[[ ! -s "$work/docker.log" ]] || fail 'invalid mode reached receipt reuse or Docker'

# The CI apt snapshot cache reaches both image builds only as an optional
# BuildKit secret read from the environment, never as an argument value.
: >"$work/docker.log"
MOCK_REUSE=disabled MOCK_APT_MIRROR=http://apt-cache.invalid:8080 run_mock_verifier apt-mirror >/dev/null
[[ "$(pair_build_count)" == 2 ]] || fail 'apt snapshot cache changed the build pair'
[[ "$(grep '^buildx build ' "$work/docker.log" | grep -v -- '--target cw-runtime-export' |
  grep -v -- '--target cw-builder-arm64' |
  grep -c -- ' --secret id=codewire-apt-mirror\\,env=CODEWIRE_APT_SNAPSHOT_MIRROR ')" == 2 ]] ||
  fail 'base and workspace builds did not both receive the apt snapshot secret'
! grep -q 'apt-cache.invalid' "$work/docker.log" "$fixture_receipt" ||
  fail 'apt snapshot cache host reached build arguments or the receipt'

umask 077
printf '%s\n' '[default]' 'aws_access_key_id = synthetic-workspace-access' \
  'aws_secret_access_key = synthetic-workspace-secret' >"$work/r2.aws"
: >"$work/docker.log"
MOCK_COMPILER=r2 MOCK_LAYERS=r2 MOCK_CREDENTIALS="$work/r2.aws" run_mock_verifier remote >/dev/null
[[ -s "$work/r2.aws" && ! -e "$work/daemon.aws" ]] || fail 'workspace changed borrowed credential lifetime'
grep -q -- '--secret id=aws_shared_credentials' "$work/docker.log" || fail 'compiler did not get its secret mount'
erase_line="$(grep -n 'exec .* rm -f /run/codewire-cache/aws-credentials' "$work/docker.log" | cut -d: -f1)"
seal_line="$(grep -n '^image tag ' "$work/docker.log" | cut -d: -f1)"
[[ "$erase_line" -lt "$seal_line" ]] || fail 'receipt preceded daemon credential cleanup'
if grep -Eq 'synthetic-workspace-(access|secret)' "$work/docker.log" "$fixture_receipt"; then fail 'provider value reached arguments or receipt'; fi
: >"$work/docker.log"
if MOCK_COMPILER=r2 MOCK_LAYERS=r2 MOCK_CREDENTIALS="$work/r2.aws" MOCK_REUSE=disabled \
    run_mock_verifier erase valid docker daemon-erase >"$work/erase.out" 2>&1; then fail 'daemon cleanup failure accepted'; fi
[[ ! -e "$fixture_receipt" && -s "$work/r2.aws" ]] || fail 'failed daemon cleanup left a receipt or erased the borrowed file'
grep -q 'workspace cache cleanup: phase=credential-erasure status=45 elapsed_seconds=' \
  "$work/erase.out" || fail 'credential erasure failure omitted its bounded diagnostic'

: >"$work/docker.log"
MOCK_EXEC=true MOCK_COMPILER=r2 MOCK_LAYERS=r2 MOCK_CREDENTIALS="$work/r2.aws" MOCK_REUSE=disabled \
  run_mock_verifier hanging-contract valid docker hang-contract >"$work/hanging-contract.out" 2>&1 &
verifier_pid=$!
# A readiness wait only (up to 60 s on a loaded host): the state asserted
# next is the same whenever the contract starts.
for ((attempt=0; attempt<1200; attempt++)); do
  [[ ! -s "$work/contract-child" ]] || break
  sleep 0.05
done
[[ -s "$work/contract-child" && ! -e "$work/daemon.aws" ]] || {
  kill -TERM "$verifier_pid" 2>/dev/null || true
  wait "$verifier_pid" 2>/dev/null || true
  fail 'contract did not start after daemon cleanup'
}
kill -TERM "$verifier_pid"
set +e
wait "$verifier_pid"
status=$?
set -e
[[ "$status" != 0 && ! -e "$fixture_receipt" && ! -e "$work/contract-running" ]] || fail 'hanging contract survived cancellation or sealed a receipt'
grep -q '^rm --force codewire-workspace-.*-full ' "$work/docker.log" || fail 'cancellation did not remove the owned runtime container'
for pid_file in "$work/contract-process" "$work/contract-child"; do
  child_pid="$(<"$pid_file")"
  state="$(ps -o stat= -p "$child_pid" || true)"
  [[ -z "$state" || "$state" == Z* ]] || { kill -TERM "$child_pid"; fail 'contract left a live child'; }
done

# Exercise the complete measurement lifecycle against the absolute fake client.
# Reports are finalized only after the job-owned credential finisher succeeds.
crash_owned_sampler() {
  python3 - "$work/sampler-process" "$1" <<'PY'
import os, select, signal, stat, sys, time
from pathlib import Path

# A readiness budget only: every check below asserts state, not speed.
deadline = time.monotonic() + 60
pins = {}
paused = False
sampler = None
verifier = None
injected = False

def interrupted(_signal, _frame):
    raise InterruptedError('owned sampler crash observation interrupted')

signal.signal(signal.SIGTERM, interrupted)

def require(value, message):
    if not value:
        raise ValueError(message)

def identity(pid):
    directory = Path('/proc') / str(pid)
    fields = (directory / 'stat').read_text().rsplit(') ', 1)[1].split()
    return (int(fields[1]), fields[19], directory.stat().st_uid), fields[0]

def alive(fd):
    poll = select.poll()
    poll.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return not poll.poll(0)

def pin(pid):
    before, _ = identity(pid)
    require(before[2] == os.geteuid(), 'sampler ancestor is not owned')
    fd = os.pidfd_open(pid)
    try:
        require(identity(pid)[0] == before and alive(fd), 'sampler ancestor birth changed')
    except BaseException:
        os.close(fd)
        raise
    pins[pid] = (fd, before)
    return before

def revalidate():
    for pid, (fd, expected) in pins.items():
        require(alive(fd) and identity(pid)[0] == expected, 'sampler ancestry changed')

def paused_children():
    result = set()
    tasks = list((Path('/proc') / str(sampler) / 'task').iterdir())
    require(0 < len(tasks) <= 128, 'sampler task count refused')
    for task in tasks:
        require(task.name.isdecimal(), 'sampler task identity refused')
        fields = (task / 'stat').read_text().rsplit(') ', 1)[1].split()
        if fields[0] not in ('T', 't'):
            return None
        raw = (task / 'children').read_bytes()
        require(len(raw) <= 8192, 'sampler child inventory is too large')
        result.update(int(value) for value in raw.split())
    return result

try:
    verifier = int(sys.argv[2])
    require(pin(verifier)[0] == os.getppid(), 'verifier is not an owned direct child')
    while not Path(sys.argv[1]).is_file():
        require(time.monotonic() < deadline, 'sampler identity was not reported')
        revalidate()
        time.sleep(0.01)
    fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        metadata = os.fstat(fd)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid()
                and metadata.st_nlink == 1 and stat.S_IMODE(metadata.st_mode) == 0o600
                and 0 < metadata.st_size <= 32, 'sampler identity file refused')
        raw = os.read(fd, 33)
        require(raw.endswith(b'\n') and raw[:-1].isdigit(), 'sampler identity bytes refused')
        sampler = int(raw)
    finally:
        os.close(fd)
    current = sampler
    for _ in range(12):
        require(current > 1 and current not in pins, 'sampler lineage refused')
        current = pin(current)[0]
        if current == verifier:
            break
    else:
        raise ValueError('sampler is not a verifier descendant')
    while True:
        require(time.monotonic() < deadline, 'sampler could not reach child-free pause')
        revalidate()
        signal.pidfd_send_signal(pins[sampler][0], signal.SIGSTOP)
        paused = True
        children = paused_children()
        while children is None:
            require(time.monotonic() < deadline, 'sampler pause did not complete')
            revalidate()
            time.sleep(0.005)
            children = paused_children()
        revalidate()
        if children:
            signal.pidfd_send_signal(pins[sampler][0], signal.SIGCONT)
            paused = False
            time.sleep(0.01)
            continue
        require(paused_children() == set(), 'paused sampler child inventory changed')
        revalidate()
        signal.pidfd_send_signal(pins[sampler][0], signal.SIGKILL)
        paused = False
        injected = True
        break
finally:
    try:
        if paused and sampler in pins:
            fd, _ = pins[sampler]
            if alive(fd):
                signal.pidfd_send_signal(fd, signal.SIGCONT)
    finally:
        try:
            if not injected and verifier in pins:
                fd, _ = pins[verifier]
                if alive(fd):
                    signal.pidfd_send_signal(fd, signal.SIGTERM)
        finally:
            for fd, _ in pins.values():
                os.close(fd)
PY
}

for measurement in seed sampler-crash sampler-bookkeeping history-failure; do
  status=0
  rm -f "$work/sampler-process"
  : >"$work/docker.log"
  if [[ "$measurement" == sampler-crash ]]; then
    MOCK_EXEC=true MOCK_MEASUREMENT_CASE=seed MOCK_COMPILER=r2 MOCK_LAYERS=r2 MOCK_CREDENTIALS="$work/r2.aws" \
      run_mock_verifier "$measurement" valid docker "$measurement" >"$work/$measurement.log" 2>&1 &
    verifier_pid=$!
    crash_owned_sampler "$verifier_pid" || {
      wait "$verifier_pid" 2>/dev/null || true
      fail 'owned sampler crash injection failed'
    }
    wait "$verifier_pid" || status=$?
  else
    MOCK_MEASUREMENT_CASE=seed MOCK_COMPILER=r2 MOCK_LAYERS=r2 MOCK_CREDENTIALS="$work/r2.aws" \
      run_mock_verifier "$measurement" valid docker "$measurement" >"$work/$measurement.log" 2>&1 || status=$?
  fi
  directory="$work/measurement/$measurement"
  [[ ! -e "$work/daemon.aws" ]] || fail 'measurement retained daemon credentials'
  grep -q '^buildx rm --force codewire-workspace-' "$work/docker.log" || fail 'measurement retained its owned builder'
  if [[ -s "$work/sampler-process" ]]; then
    sampler_process="$(<"$work/sampler-process")"
    state="$(ps -o stat= -p "$sampler_process" || true)"
    [[ -z "$state" || "$state" == Z* ]] || { kill -TERM "$sampler_process"; fail 'measurement left a live sampler'; }
  fi
  if [[ "$measurement" == sampler-* || "$measurement" == history-failure ]]; then
    [[ "$status" != 0 && ! -e "$fixture_receipt" && ! -e "$directory/result.json" ]] || fail 'sampler failure emitted an acceptance marker'
    continue
  fi
  [[ "$status" == 0 && -s "$fixture_receipt" ]] || {
    cat "$work/$measurement.log" >&2
    fail 'measurement verifier did not complete its ordinary contracts'
  }
  status=0
  env RUNNER_TEMP="$work/measurement" GITHUB_OUTPUT="$work/measurement-output" \
    CODEWIRE_EXPECTED_SOURCE_SHA="$fixture_sha" CODEWIRE_EXPECTED_SOURCE_TREE="$fixture_tree" \
    CODEWIRE_SCCACHE_MODE=r2 CODEWIRE_BUILDKIT_CACHE_MODE=r2 \
    python3 "$fixture_root/scripts/ci/verify/workspace-cache-report.py" finalize "$directory" "$fixture_receipt" \
    >"$work/$measurement-report.log" 2>&1 || status=$?
  [[ "$status" == 0 && -s "$directory/result.json" ]] || {
    cat "$work/$measurement-report.log" >&2
    fail 'valid seed measurement failed'
  }
  grep -q 'ignore-error=false' "$work/docker.log" || fail 'seed export remains best effort'
done

# Bind the original policy witness to its actual prior bytes, not a modified
# success stub. Both policies reuse one real-admission synthetic producer and
# drive the existing workspace/base/contract/seal route through the CW wrapper.
if [[ "$(uname -m)" == x86_64 ]]; then
  cp "$fixture_root/scripts/ci/verify/verify-workspace-image.sh" "$work/current-verifier.sh"
  python3 -B - "$work/current-verifier.sh" "$work/prior-verifier.sh" <<'PY'
import hashlib, sys
from pathlib import Path
current = Path(sys.argv[1]).read_text()
# Reconstruct the hash-bound verifier before this retention addition first;
# the original installed-byte counterproof below still uses its exact bytes.
def remove_between(start, end):
    global current
    assert current.count(start) == current.count(end) == 1
    left, right = current.index(start), current.index(end)
    assert left < right
    current = current[:left] + current[right:]

def replace_once(old, new):
    global current
    assert current.count(old) == 1
    current = current.replace(old, new, 1)

remove_between('retain_cw_producer="${CODEWIRE_WORKSPACE_CW_PRODUCER_RETAIN:-0}"\n',
               'if [[ -n "$workspace_measurement_case" ]]; then\n  # Experiments always build; an old image receipt cannot seed a measurement.\n')
remove_between('if [[ "$retain_cw_producer" == 1 && "$architecture" != amd64 ]]; then\n',
               'if [[ "$retain_cw_producer" == 0 && "${CODEWIRE_WORKSPACE_IMAGE_REUSE:-auto}" == auto ]]')
replace_once('if [[ "$retain_cw_producer" == 0 && "${CODEWIRE_WORKSPACE_IMAGE_REUSE:-auto}" == auto ]]',
             'if [[ "${CODEWIRE_WORKSPACE_IMAGE_REUSE:-auto}" == auto ]]')
remove_between('retained_cw_producer() {\n', 'stop_sampler() {\n')
replace_once("  local status=$? cleanup_status=0 retained_result=''\n", '  local status=$? cleanup_status=0\n')
replace_once('''    # Opt-in success keeps the entire original private staging tree. Defer its
    # deletion until the existing cleanup and atomic seal have been observed.
    [[ "$retain_cw_producer" == 1 ]] || rm -rf "$work"
''', '    rm -rf "$work"\n')
replace_once('''  if [[ "$status" -eq 0 ]]; then
    if [[ "$retain_cw_producer" == 1 ]]; then
      retained_result="$(retained_cw_producer)" || status=$?
    fi
  fi
''', '')
replace_once('''  if [[ "$retain_cw_producer" == 1 && "$cw_copy_started" == false ]]; then
    if [[ "$status" -eq 0 ]]; then
      printf '%s\\n' "$retained_result"
    else
      rm -rf "$work"
    fi
  fi
''', '')
# The later arm64 cw cross-compile check is also outside the prior witness.
remove_between('# The published arm64 leg cross-compiles cw on the build platform. Build only\n',
               '# Loaded runtime bytes do not depend on BuildKit.')
assert hashlib.sha256(current.encode()).hexdigest() == '4a9556428364ce20fc450cb245f00774a6ffa2ea0b1c0bdb8046653814716d19'
copy = '''if [[ "$architecture" == amd64 ]]; then
  # Keep original source provenance and prove the installed bytes after the
  # owning builder/provider file is gone. This never executes incoming CW.
  cw_copy_started=true
  python3 "$artifact_tool" verify-cw "$ROOT" "$workspace_id" \\
    "$build_log_root/cw-image-work/cw-producer-result.json"
  cw_copy_started=false
fi
'''
cleanup = '''  if [[ "$cw_copy_started" == false ]]; then
    rm -rf "$work"
  else
    printf 'workspace image verification: failed CW copy evidence retained at %s\\n' "$work" >&2
  fi
'''
assert current.count(copy) == current.count(cleanup) == 1
old = current.replace(copy, '').replace(cleanup, '  rm -rf "$work"\n')
assert old.count('cw_copy_started=false\n') == 1
old = old.replace('cw_copy_started=false\n', '')
assert hashlib.sha256(old.encode()).hexdigest() == '9bb5cdec3c4ddb0d46ea7c19e9ad3fafa86c454e5acca207ddde9c3eaf53aa66'
Path(sys.argv[2]).write_text(old)
PY
  python3 -B "$fixture_helper" producer --profile runtime "$fixture_root" "$work/copy-policy-producer" "$work/copy-policy-result.json"
  original_cw_sha="$(sha256sum "$work/copy-policy-producer/assets/cw" | cut -d' ' -f1)"
  fixture_policy() {
    cp "$1" "$fixture_root/scripts/ci/verify/verify-workspace-image.sh"
    env GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0 \
      /usr/bin/git -c core.hooksPath=/dev/null -c maintenance.auto=false -c gc.auto=0 \
      -C "$fixture_root" add scripts/ci/verify/verify-workspace-image.sh
    env GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0 \
      /usr/bin/git -c core.hooksPath=/dev/null -c maintenance.auto=false -c gc.auto=0 \
      -c user.name=Synthetic -c user.email=synthetic@example.invalid \
      -C "$fixture_root" commit -q -m 'synthetic installed-copy policy witness'
    fixture_sha="$(/usr/bin/git -C "$fixture_root" rev-parse HEAD)"
    fixture_tree="$(/usr/bin/git -C "$fixture_root" rev-parse 'HEAD^{tree}')"
  }
  fixture_policy "$work/prior-verifier.sh"
  : >"$work/docker.log"
  MOCK_REUSE=disabled MOCK_PRODUCER_RESULT="$work/copy-policy-result.json" \
    run_mock_verifier copy-policy-old valid docker cw-mismatch >"$work/copy-policy-old.log" 2>&1 || {
      cat "$work/copy-policy-old.log" >&2; fail 'exact prior copy policy witness did not accept';
    }
  grep -q -- '--mounted-home-agents' "$work/docker.log" || fail 'prior policy skipped its agent contracts'
  grep -q '^image tag ' "$work/docker.log" || fail 'prior policy did not seal the simulated wrong-CW image'
  ! grep -q -- '--entrypoint /usr/bin/cat' "$work/docker.log" || fail 'prior policy unexpectedly proved installed CW'
  fixture_policy "$work/current-verifier.sh"
  : >"$work/docker.log"
  if MOCK_REUSE=disabled MOCK_PRODUCER_RESULT="$work/copy-policy-result.json" \
      run_mock_verifier copy-policy-new valid docker cw-mismatch >"$work/copy-policy-new.log" 2>&1; then
    fail 'current policy accepted wrong installed CW bytes'
  fi
  grep -q -- '--entrypoint /usr/bin/cat' "$work/docker.log" || fail 'current copy refusal did not observe installed bytes'
  ! grep -Eq -- '--entrypoint bash|^image tag ' "$work/docker.log" || fail 'copy failure reached agent contracts or sealing'
  [[ ! -e "$fixture_receipt" ]] || fail 'copy failure published an acceptance receipt'
  retained_copy="$(sed -n 's/^workspace image verification: failed CW copy evidence retained at //p' "$work/copy-policy-new.log")"
  [[ "$retained_copy" == "$work/tmp/"* && -d "$retained_copy" \
    && -s "$retained_copy/cw-image-work/cw-producer-result.json" ]] || fail 'copy failure discarded its private evidence'
  [[ "$(sha256sum "$work/copy-policy-producer/assets/cw" | cut -d' ' -f1)" == "$original_cw_sha" ]] || fail 'copy witness changed original producer bytes'
  printf 'workspace copied-CW policy: exact prior accepts / current refuses before contracts; original producer retained\n'
fi

join_companion_lanes
echo 'workspace-image verification workflow contract: OK'
