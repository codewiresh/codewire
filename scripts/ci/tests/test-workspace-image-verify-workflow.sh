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

[[ -f "$WORKFLOW" ]] || fail 'required CI workflow is missing'
[[ ! -e "$STANDALONE_WORKFLOW" ]] || fail 'standalone workspace-image workflow still exists'
[[ -x "$VERIFY" ]] || fail 'workspace-image verification script is not executable'
[[ -x "$HELPER" ]] || fail 'local Buildx image helper is missing'
[[ -x "$AGENT_CONTRACT" ]] || fail 'workspace agent contract is missing'
workspace_job="$(awk '
  $0 == "  workspace-image:" { capture = 1 }
  capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ && $0 != "  workspace-image:" { exit }
  capture { print }
' "$WORKFLOW")"
grep -qF '  workspace-image:' <<<"$workspace_job" || fail 'workspace-image job is missing'
grep -qF '    name: Container contract verification' <<<"$workspace_job" ||
  fail 'workspace job is not named for its complete non-publishing scope'
grep -qF '    runs-on: ci-heavy' <<<"$workspace_job" ||
  fail 'Docker-backed workspace verification is not assigned to the heavy capability profile'
grep -qF '    timeout-minutes: 55' <<<"$workspace_job" ||
  fail 'workspace cold-build ceiling does not preserve the runner cleanup margin'
grep -qF '    needs: [verification-selection]' <<<"$workspace_job" ||
  fail 'workspace job does not consume the canonical verification plan'
if grep -qE '^    if:' <<<"$workspace_job"; then
  fail 'workspace job must remain a static required runner task'
fi
grep -qF 'name: Container contracts not selected' <<<"$workspace_job" ||
  fail 'container job has no explicit unaffected path'
grep -qF 'no checkout, download, installation, or build required' <<<"$workspace_job" ||
  fail 'workspace no-op does not prove its cheap behavior'
grep -qF 'name: Resolve container contract scope' <<<"$workspace_job" ||
  fail 'container job does not resolve its workspace, dashboard, and iOS scope'
grep -qF 'WORKSPACE_IMAGE_SELECTED: ${{ needs.verification-selection.outputs.workspace_image_selected }}' \
  <<<"$workspace_job" || fail 'container scope omits canonical workspace-image selection'
grep -qF "steps.container-scope.outputs.selected != 'true'" <<<"$workspace_job" ||
  fail 'container no-op does not use its resolved scope'
grep -qF "steps.container-scope.outputs.selected == 'true'" <<<"$workspace_job" ||
  fail 'container checkout does not use its resolved scope'
grep -qF "workspace_image_selected == 'true'" <<<"$workspace_job" ||
  fail 'workspace positive path does not use canonical planner selection'
grep -qF "trusted_adapter='.trusted-ci-policy/scripts/ci/plan/apply-verification-plan.py'" \
  "$WORKFLOW" || fail 'artifact facts do not come from the trusted adapter'
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
  fail 'workspace verification must remain credential-free and non-publishing'
fi
if grep -qE '^[[:space:]]*permissions:' "$WORKFLOW"; then
  fail 'workflow declares GitHub-only permissions that Forgejo ignores'
fi
grep -qF 'scripts/ci/verify/verify-workspace-image.sh' <<<"$workspace_job" ||
  fail 'workflow does not invoke the image verifier'
if grep -Eq 'docker (buildx )?build.*--push|docker push' "$VERIFY"; then
  fail 'verification must not publish an image'
fi
[[ "$(grep -Fc '"$docker_bin" buildx build' "$VERIFY")" -eq 2 ]] ||
  fail 'verification does not build the exact local base/workspace pair'
grep -qF -- '--output "type=oci,dest=$base_layout,tar=false"' "$VERIFY" ||
  fail 'base verification does not export a local OCI layout'
grep -qF -- '--metadata-file "$base_metadata"' "$VERIFY" ||
  fail 'base verification does not capture its immutable output digest'
grep -qF -- '--build-context "$base_context_name=oci-layout://$base_layout@$base_digest"' \
  "$VERIFY" || fail 'workspace verification does not consume its exact OCI base digest'
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
  python3 pipx poetry uv cargo rustc infisical psql protoc; do
  grep -qF "$tool" "$AGENT_CONTRACT" || fail "verification omits $tool"
done
grep -qF 'dynamic_bun_runner="bun""x"' "$AGENT_CONTRACT" ||
  fail 'verification omits the installed Bun package runner without invoking it literally'
grep -qF 'test -O' "$AGENT_CONTRACT" || fail 'verification does not prove user ownership'
grep -qF 'npm update --global --dry-run @openai/codex' "$AGENT_CONTRACT" ||
  fail 'verification does not prove the user-scoped Codex update path'

# Execute the verifier against a fake Docker client. This catches command-order,
# digest-handoff, cleanup, and fail-closed regressions without building an image.
mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/workspace-image-verifier-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/tmp"
cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"$FAKE_DOCKER_LOG"
printf '\n' >>"$FAKE_DOCKER_LOG"

case "${1:-} ${2:-}" in
  'buildx inspect')
    printf 'Name: %s\n' "${FAKE_SELECTED_BUILDER:-selected-verifier}"
    printf 'Driver: %s\n' "${FAKE_SELECTED_DRIVER:-docker-container}"
    ;;
  'buildx create')
    printf 'workspace-verifier-%s\n' "$FAKE_BUILDER_SUFFIX"
    ;;
  'buildx build')
    metadata_file=''
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == '--metadata-file' ]]; then
        metadata_file="$2"
        break
      fi
      shift
    done
    if [[ -n "$metadata_file" ]]; then
      case "${FAKE_METADATA_MODE:-valid}" in
        valid) printf '{"containerimage.digest":"sha256:%064d"}\n' 0 >"$metadata_file" ;;
        missing) printf '{}\n' >"$metadata_file" ;;
        malformed) printf '{not-json}\n' >"$metadata_file" ;;
        *) exit 98 ;;
      esac
    fi
    ;;
  'buildx rm'|'run --rm')
    ;;
  *)
    printf 'unexpected docker command: %s\n' "$*" >&2
    exit 99
    ;;
esac
EOF
chmod +x "$work/bin/docker"

run_mock_verifier() {
  env PATH="$work/bin:$PATH" \
    CODEWIRE_DOCKER_BIN=docker \
    FAKE_DOCKER_LOG="$work/docker.log" \
    FAKE_BUILDER_SUFFIX="$1" \
    FAKE_METADATA_MODE="${2:-valid}" \
    FAKE_SELECTED_DRIVER="${3:-docker-container}" \
    GITHUB_SHA=mock-source \
    TMPDIR="$work/tmp" \
    "$VERIFY"
}

: >"$work/docker.log"
run_mock_verifier success >/dev/null
mapfile -t docker_calls <"$work/docker.log"
[[ "${#docker_calls[@]}" -eq 4 ]] ||
  fail "verifier issued an unexpected number of Docker calls: ${#docker_calls[@]}"
[[ "${docker_calls[0]}" == 'buildx inspect ' ]] ||
  fail "verifier selected-builder inspection drifted: ${docker_calls[0]}"
[[ "${docker_calls[1]}" == *'buildx build --builder selected-verifier --pull --metadata-file '* ]] ||
  fail 'verifier did not build base metadata with the selected container builder'
[[ "${docker_calls[1]}" == *'--output type=oci\,dest='*'/base.oci\,tar=false '* ]] ||
  fail 'verifier did not export the base OCI layout'
[[ "${docker_calls[2]}" == *'--build-context codewire-verified-base=oci-layout://'*'/base.oci@sha256:'* ]] ||
  fail 'verifier did not hand the exact base digest to the workspace build'
[[ "${docker_calls[2]}" == *'--load --build-arg BASE_IMAGE_REF=codewire-verified-base '* ]] ||
  fail 'verifier did not load a workspace built from the named base context'
[[ "${docker_calls[3]}" == 'run --rm --interactive --pids-limit=2048 --user codewire --entrypoint bash codewire-workspace-verify:mock-source -eu -s ' ]] ||
  fail "workspace runtime contract invocation drifted: ${docker_calls[3]}"
if grep -qF 'buildx create' "$work/docker.log" || grep -qF 'buildx rm' "$work/docker.log"; then
  fail 'verifier replaced or removed the caller-selected container builder'
fi

: >"$work/docker.log"
set +e
run_mock_verifier invalid missing docker >/dev/null 2>&1
mock_status=$?
set -e
[[ "$mock_status" -ne 0 ]] || fail 'verifier accepted missing base digest metadata'
[[ "$(grep -Fc 'buildx build' "$work/docker.log")" -eq 1 ]] ||
  fail 'verifier continued into workspace build after invalid base metadata'
grep -Fxq 'buildx rm --force workspace-verifier-invalid ' "$work/docker.log" ||
  fail 'verifier did not clean its Docker-driver fallback after invalid metadata'

echo 'workspace-image verification workflow contract: OK'
