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
"$ROOT/scripts/ci/tests/test-select-untrusted-workspace-cache.sh"
"$ROOT/scripts/ci/tests/test-workspace-cache.sh"

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
for path in images/base/Dockerfile images/workspace/Dockerfile .dockerignore \
  scripts/ci/verify/workspace-agent-contract.sh \
  scripts/ci/verify/verify-workspace-image.sh \
  scripts/ci/verify/workspace-image-artifact.py \
  scripts/ci/images/workspace-cache.sh \
  scripts/ci/images/run-rust-build.sh \
  scripts/ci/setup/select-untrusted-workspace-cache.sh; do
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
    if [[ "${FAKE_FAIL:-}" == cancel ]]; then
      # The actual verifier owns this pipeline. Deliver TERM to that process,
      # exercising its signal trap while an owned builder exists.
      kill -TERM "$PPID"
      exit 143
    fi
    metadata_file=''
    : >"$FAKE_IMAGE_LABELS.next"
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --metadata-file) metadata_file="$2"; shift ;;
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
    ;;
  'buildx rm')
    [[ "${FAKE_FAIL:-}" != cleanup ]] || exit 43
    # Exercise the real timeout boundary, not a fake timeout implementation.
    [[ "${FAKE_FAIL:-}" != slow-cleanup ]] || sleep 11
    ;;
  'container inspect')
    if [[ "$5" == '{{.Id}}' ]]; then
      printf '%064d\n' 4
    else
      printf '%s\n' 'docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5'
    fi
    ;;
  'exec --interactive') cat >"$FAKE_DAEMON_FILE" ;;
  'image inspect')
    if [[ "${4:-}" == --format ]]; then
      printf 'sha256:%064d\n' 3
    else
      python3 - "$FAKE_IMAGE_LABELS" <<'PY'
import json, platform, sys
from pathlib import Path
labels = dict(line.split('=', 1) for line in Path(sys.argv[1]).read_text().splitlines())
print(json.dumps([{'Id': 'sha256:' + '3'.zfill(64), 'Os': 'linux',
                  'Architecture': {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()],
                  'Config': {'Labels': labels}}]))
PY
    fi
    ;;
  'image tag')
    ;;
  'rm --force') rm -f "$FAKE_CONTRACT_RUNNING" ;;
  'run --rm')
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
    else
      [[ "${FAKE_FAIL:-}" != full ]] || exit 41
    fi
    ;;
  *)
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

run_mock_verifier() {
  local -a invocation=(env PATH="$work/bin:$PATH" \
    CODEWIRE_DOCKER_BIN="$work/bin/docker" \
    CODEWIRE_SCCACHE_MODE="${MOCK_COMPILER:-local}" \
    CODEWIRE_BUILDKIT_CACHE_MODE="${MOCK_LAYERS:-local}" \
    CODEWIRE_WORKSPACE_IMAGE_REUSE="${MOCK_REUSE:-auto}" \
    CODEWIRE_SCCACHE_CREDENTIALS_FILE="${MOCK_CREDENTIALS:-}" \
    SCCACHE_BUCKET=example-ci-cache-untrusted \
    SCCACHE_ENDPOINT=https://00000000000000000000000000000000.r2.cloudflarestorage.com \
    CODEWIRE_SCCACHE_PREFIX=untrusted/codewire/v1 \
    FAKE_DOCKER_LOG="$work/docker.log" \
    FAKE_BUILDER_SUFFIX="$1" \
    FAKE_METADATA_MODE="${2:-valid}" \
    FAKE_SELECTED_DRIVER="${3:-docker-container}" \
    FAKE_IMAGE_LABELS="$work/image-labels" \
    FAKE_DAEMON_FILE="$work/daemon.aws" \
    FAKE_CONTRACT_PROCESS="$work/contract-process" \
    FAKE_CONTRACT_CHILD="$work/contract-child" \
    FAKE_CONTRACT_RUNNING="$work/contract-running" \
    FAKE_FAIL="${4:-}" \
    FAKE_DIRTY="${5:-false}" \
    TMPDIR="$work/tmp" \
    "$fixture_root/scripts/ci/verify/verify-workspace-image.sh")
  if [[ "${MOCK_EXEC:-false}" == true ]]; then exec "${invocation[@]}"; fi
  "${invocation[@]}"
}

# Assert behavior and ordering rather than incidental inspection call counts.
: >"$work/docker.log"
run_mock_verifier success >/dev/null
grep -q '^buildx create --name codewire-workspace-' "$work/docker.log" || fail 'owned builder was not created'
grep -q -- '--driver-opt image=docker.io/moby/buildkit:v0.29.0@sha256:' "$work/docker.log" || fail 'daemon is not pinned'
[[ "$(grep -c '^buildx build ' "$work/docker.log")" == 2 ]] || fail 'base/workspace pair was not built once'
grep -q -- '--output type=oci\\,dest=.*base.oci\\,tar=false' "$work/docker.log" || fail 'exact base OCI export missing'
grep -q -- '--build-context codewire-verified-base=oci-layout://.*base.oci@sha256:' "$work/docker.log" || fail 'exact base handoff missing'
grep -q -- '--no-cache-filter workspace-floating-tools' "$work/docker.log" || fail 'floating tools could be reused'
grep -q -- '--build-arg CODEWIRE_SCCACHE_MODE=local' "$work/docker.log" || fail 'compiler policy missing'
image_id="$(printf 'sha256:%064d' 3)"
grep -Eq "run --rm --interactive --pids-limit=2048 --name codewire-workspace-[^ ]+-full --user codewire --entrypoint bash $image_id -eu -s " "$work/docker.log" || fail 'full image contract omitted'
grep -q -- '--tmpfs /home/codewire:rw.* --entrypoint bash .* --mounted-home-agents' "$work/docker.log" || fail 'mounted-home contract omitted'
cleanup_line="$(grep -n '^buildx rm ' "$work/docker.log" | cut -d: -f1)"
seal_line="$(grep -n '^image tag ' "$work/docker.log" | cut -d: -f1)"
contract_line="$(grep -n -- '--mounted-home-agents' "$work/docker.log" | cut -d: -f1)"
[[ "$cleanup_line" -lt "$contract_line" && "$contract_line" -lt "$seal_line" ]] || fail 'builder outlived contracts or seal preceded acceptance'
[[ -s "$fixture_receipt" && "$(stat -c %a "$fixture_receipt")" == 600 ]] || fail 'private receipt missing'

: >"$work/docker.log"
run_mock_verifier reuse >/dev/null
[[ "$(wc -l <"$work/docker.log")" == 2 ]] || fail 'exact-tree reuse rebuilt or reran contracts'
! grep -Eq '^buildx |^run ' "$work/docker.log" || fail 'verified image reuse performed duplicate qualification'

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
grep -q 'workspace cache cleanup: phase=builder-removal status=43 elapsed_seconds=' \
  "$work/cleanup.out" || fail 'builder removal failure omitted its bounded diagnostic'

: >"$work/docker.log"
MOCK_REUSE=disabled run_mock_verifier slow-cleanup valid docker slow-cleanup >"$work/slow-cleanup.out" 2>&1
[[ -s "$fixture_receipt" ]] || fail 'bounded slow state deletion failed verification'
cleanup_line="$(grep -n '^buildx rm ' "$work/docker.log" | cut -d: -f1)"
contract_line="$(grep -n '^run --rm ' "$work/docker.log" | head -n1 | cut -d: -f1)"
[[ "$cleanup_line" -lt "$contract_line" ]] || fail 'slow cleanup outlived contract execution'

: >"$work/docker.log"
if run_mock_verifier dirty valid docker-container '' true >/dev/null 2>&1; then fail 'dirty source accepted'; fi
[[ ! -s "$work/docker.log" ]] || fail 'dirty source reached Docker'

: >"$work/docker.log"
MOCK_COMPILER=disabled MOCK_LAYERS=disabled run_mock_verifier cold >/dev/null
[[ "$(grep -c -- '--no-cache ' "$work/docker.log")" == 2 ]] || fail 'disabled layer cache did not bypass both builds'
! grep -q -- '--no-cache-filter' "$work/docker.log" || fail 'mutually exclusive cache flags were combined'
[[ "$(jq -r '.cache_modes.compiler + "/" + .cache_modes.layers' "$fixture_receipt")" == disabled/disabled ]] || fail 'receipt omitted cache modes'
: >"$work/docker.log"
run_mock_verifier changed-mode >/dev/null
[[ "$(grep -c '^buildx build ' "$work/docker.log")" == 2 ]] || fail 'mode change reused incompatible evidence'
: >"$work/docker.log"
if MOCK_LAYERS=invalid run_mock_verifier invalid-mode >/dev/null 2>&1; then fail 'invalid mode accepted'; fi
[[ ! -s "$work/docker.log" ]] || fail 'invalid mode reached receipt reuse or Docker'

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
for ((attempt=0; attempt<100; attempt++)); do
  [[ ! -s "$work/contract-child" ]] || break
  sleep 0.02
done
[[ -s "$work/contract-child" && ! -e "$work/daemon.aws" ]] || { kill -TERM "$verifier_pid"; fail 'contract did not start after daemon cleanup'; }
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

echo 'workspace-image verification workflow contract: OK'
