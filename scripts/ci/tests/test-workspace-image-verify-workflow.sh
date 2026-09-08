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
grep -qF "workspace_image_selected == 'true'" <<<"$workspace_job" ||
  fail 'workspace positive path does not use canonical planner selection'
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
# shellcheck disable=SC2016 # Match the verifier's literal shell variables.
[[ "$(grep -Fc '"$docker_bin" buildx build' "$VERIFY")" -eq 2 ]] ||
  fail 'verification does not build the exact local base/workspace pair'
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
  python3 pipx poetry uv cargo rustc psql protoc; do
  grep -qF "$tool" "$AGENT_CONTRACT" || fail "verification omits $tool"
done
grep -qF 'dynamic_bun_runner="bun""x"' "$AGENT_CONTRACT" ||
  fail 'verification omits the installed Bun package runner without invoking it literally'
grep -qF 'test -O' "$AGENT_CONTRACT" || fail 'verification does not prove user ownership'
grep -qF 'npm install --global --dry-run --ignore-scripts --no-audit --no-fund @openai/codex@0.149.0' "$AGENT_CONTRACT" ||
  fail 'verification does not prove the explicit user-scoped Codex install plan'
grep -qF -- '--tmpfs /home/codewire:rw,exec,uid=1000,gid=1000,mode=0700,size=256m' "$VERIFY" ||
  fail 'verification omits the fresh persistent-home boundary'
grep -qF "!contains(needs.verification-selection.outputs.selection, '|kind|')" <<<"$workspace_job" ||
  fail 'standalone workspace verification duplicates selected Kind ownership'
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/ci/tests/test-workspace-image-artifact.py"

# Execute the verifier against a fake Docker client. This catches command-order,
# digest-handoff, cleanup, and fail-closed regressions without building an image.
mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/workspace-image-verifier-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/tmp"
# Execute the actual workflow decision, not a second handwritten selector.
awk '
  /- name: Resolve container contract scope/ { scope = 1 }
  scope && /^        run: \|$/ { run = 1; next }
  run && /^          / { print substr($0, 11); next }
  run { exit }
' "$WORKFLOW" >"$work/container-scope.sh"
[[ -s "$work/container-scope.sh" ]] || fail 'container scope script was not extracted'
for fixture in \
  'true|kind|false' 'false|kind|false' 'true|policy|true' 'false|policy|false' \
  'false|web|true' 'false|kind,web|false' 'true|kind,web|false' \
  'false|ios|true' 'true|kind,ios|true'; do
  IFS='|' read -r workspace_selected selection expected <<<"$fixture"
  selection="|${selection//,/|}|"
  : >"$work/scope-output"
  env WORKSPACE_IMAGE_SELECTED="$workspace_selected" VERIFICATION_SELECTION="$selection" \
    GITHUB_OUTPUT="$work/scope-output" bash "$work/container-scope.sh"
  grep -Fxq "selected=$expected" "$work/scope-output" ||
    fail "container ownership differs for workspace=$workspace_selected selection=$selection"
done
# Run the actual verifier and identity helper in a private source fixture. Never
# write a synthetic acceptance receipt into the developer checkout.
fixture_root="$work/source"
for path in images/base/Dockerfile images/workspace/Dockerfile .dockerignore \
  scripts/ci/verify/workspace-agent-contract.sh \
  scripts/ci/verify/verify-workspace-image.sh \
  scripts/ci/verify/workspace-image-artifact.py; do
  mkdir -p "$fixture_root/$(dirname "$path")"
  cp "$ROOT/$path" "$fixture_root/$path"
done
fixture_receipt="$fixture_root/.tmp/codewire-workspace-image-verification.json"
cat >"$work/bin/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == -C ]] || exit 99
shift 2
case "$*" in
  'status --porcelain --untracked-files=normal')
    [[ "${FAKE_DIRTY:-false}" == false ]] || printf ' M tracked-file\n' ;;
  'rev-parse HEAD') printf '%040d\n' 1 ;;
  'rev-parse HEAD^{tree}'|'rev-parse 0000000000000000000000000000000000000001^{tree}')
    printf '%040d\n' 2 ;;
  *) exit 99 ;;
esac
EOF
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
    archive_file=''
    : >"$FAKE_IMAGE_LABELS.next"
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --metadata-file) metadata_file="$2"; shift ;;
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
fixture['write_archive'](Path(sys.argv[2]), config=config)
Path(sys.argv[3]).write_text('sha256:' + hashlib.sha256(config).hexdigest())
PY
    fi
    ;;
  'buildx rm')
    [[ "${FAKE_FAIL:-}" != cleanup ]] || exit 43
    ;;
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
  'run --rm')
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
    printf 'unexpected docker command: %s\n' "$*" >&2
    exit 99
    ;;
esac
EOF
chmod +x "$work/bin/docker" "$work/bin/git"

run_mock_verifier() {
  env PATH="$work/bin:$PATH" \
    CODEWIRE_DOCKER_BIN=docker \
    FAKE_DOCKER_LOG="$work/docker.log" \
    FAKE_BUILDER_SUFFIX="$1" \
    FAKE_METADATA_MODE="${2:-valid}" \
    FAKE_SELECTED_DRIVER="${3:-docker-container}" \
    FAKE_IMAGE_LABELS="$work/image-labels" \
    FAKE_IMAGE_ID="$work/image-id" \
    FAKE_OCI_FIXTURE="$ROOT/scripts/ci/tests/test-workspace-image-artifact.py" \
    FAKE_RECEIPT="$fixture_receipt" \
    FAKE_FAIL="${4:-}" \
    FAKE_DIRTY="${5:-false}" \
    TMPDIR="$work/tmp" \
    "$fixture_root/scripts/ci/verify/verify-workspace-image.sh"
}

: >"$work/docker.log"
run_mock_verifier success >/dev/null
mapfile -t docker_calls <"$work/docker.log"
[[ "${#docker_calls[@]}" -eq 9 ]] ||
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
image_id="$(cat "$work/image-id")"
[[ "${docker_calls[4]}" == "run --rm --interactive --pids-limit=2048 --user codewire --entrypoint bash $image_id -eu -s " ]] ||
  fail "workspace runtime contract invocation drifted: ${docker_calls[4]}"
[[ "${docker_calls[5]}" == *'--tmpfs /home/codewire:rw\,exec\,uid=1000\,gid=1000\,mode=0700\,size=256m --entrypoint bash '*"$image_id -eu -s -- --mounted-home-agents " ]] ||
  fail 'mounted-home contract did not execute the same immutable image'
[[ "${docker_calls[6]}" == "image inspect $image_id " ]] || fail 'receipt preceded contract checks'
[[ -s "$fixture_receipt" ]] || fail 'successful verification emitted no receipt'
[[ "$(stat -c %a "$fixture_receipt")" == 600 ]] || fail 'receipt permissions are not private'
archive_name="$(jq -er '.workspace_oci.file' "$fixture_receipt")"
[[ "$(stat -c '%a %h' "$fixture_root/.tmp/$archive_name")" == '400 1' ]] ||
  fail 'verified OCI archive is not immutable and single-linked'
[[ "${docker_calls[2]}" == *'--output type=oci\,dest='*'/workspace.oci.tar '* ]] ||
  fail 'workspace build did not export the same image for native verification'
[[ "${docker_calls[2]}" == *'--provenance=false --sbom=false '* ]] ||
  fail 'verification-only OCI export unexpectedly contains attestation artifacts'
if grep -qF 'buildx create' "$work/docker.log" || grep -qF 'buildx rm' "$work/docker.log"; then
  fail 'verifier replaced or removed the caller-selected container builder'
fi

: >"$work/docker.log"
run_mock_verifier reuse >/dev/null
[[ "$(wc -l <"$work/docker.log")" -eq 2 ]] || fail 'exact-tree reuse rebuilt or reran contracts'
if grep -Eq '^buildx |^run ' "$work/docker.log"; then
  fail 'verified image reuse performed duplicate qualification'
fi

rm "$fixture_receipt"
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
[[ ! -e "$fixture_receipt" ]] || fail 'invalid base emitted a receipt'

for failure in full mounted cleanup; do
  : >"$work/docker.log"
  if run_mock_verifier "$failure" valid docker "$failure" >/dev/null 2>&1; then
    fail "verifier accepted $failure failure"
  fi
  [[ ! -e "$fixture_receipt" ]] || fail "$failure failure emitted a receipt"
  if grep -q '^image tag ' "$work/docker.log"; then
    fail "$failure failure sealed an image alias"
  fi
done

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
if run_mock_verifier dirty valid docker-container '' true >/dev/null 2>&1; then
  fail 'dirty source was accepted'
fi
[[ ! -s "$work/docker.log" ]] || fail 'dirty source reached Docker'

: >"$work/docker.log"
run_mock_verifier fallback valid docker >/dev/null
grep -Fxq 'buildx rm --force workspace-verifier-fallback ' "$work/docker.log" ||
  fail 'successful fallback did not remove its owned builder'
cleanup_line="$(grep -n '^buildx rm ' "$work/docker.log" | cut -d: -f1)"
seal_line="$(grep -n '^image tag ' "$work/docker.log" | cut -d: -f1)"
[[ "$cleanup_line" -lt "$seal_line" ]] || fail 'receipt preceded owned-builder cleanup'
[[ -s "$fixture_receipt" ]] || fail 'successful fallback emitted no receipt'

echo 'workspace-image verification workflow contract: OK'
