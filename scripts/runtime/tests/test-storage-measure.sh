#!/usr/bin/env bash
# Static and fixture tests for scripts/runtime/storage-measure. No cluster:
# kubectl, git and cargo are local doubles, and every JSON input is synthetic.
# shellcheck disable=SC2016 # jq programs are single-quoted on purpose.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SM="$ROOT/scripts/runtime/storage-measure"
FIX="$ROOT/scripts/runtime/tests/fixtures/storage-measure"
# Command doubles must be executable, so they live under the repository's
# ignored .tmp rather than a possibly noexec TMPDIR.
mkdir -p "$ROOT/.tmp"
WORK="$(mktemp -d "$ROOT/.tmp/storage-measure-test.XXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT
COUNT=0
RUN_ID_FIXTURE=sm-20260929100000-abcdef

fail() {
  printf '[test-storage-measure] FAIL: %s\n' "$*" >&2
  exit 1
}

pass() {
  COUNT=$((COUNT + 1))
}

smjq() {
  jq -L "$SM" "$@"
}

same_json() {
  local label="$1" expected="$2" actual="$3"
  if ! diff -u <(jq -S . "$expected") <(jq -S . "$actual") >"$WORK/diff" 2>&1; then
    cat "$WORK/diff" >&2
    fail "$label differs from $expected"
  fi
  pass
}

check() {
  local label="$1" program="$2" input="$3"
  jq -e "$program" "$input" >/dev/null || fail "$label: $program"
  pass
}

# --- syntax and help -------------------------------------------------------
for script in "$SM"/*.sh "$SM"/pod/*.sh; do
  bash -n "$script" || fail "syntax: $script"
done
pass
"$SM/measure-storage.sh" --help >"$WORK/help"
grep -Fq -- '--i-own-this-namespace' "$WORK/help" || fail "help omits --i-own-this-namespace"
pass

# --- refusals: before any cluster access ------------------------------------
mkdir -p "$WORK/bin"
cat >"$WORK/bin/kubectl" <<'KUBECTL'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$KUBECTL_CALLS"
case "$*" in
  'config get-contexts -o name') printf 'ctx\n' ;;
  *' get namespace storage-measure -o json') cat "$FAKE_NAMESPACE_JSON" ;;
  *) exit 99 ;;
esac
KUBECTL
chmod +x "$WORK/bin/kubectl"
export KUBECTL_CALLS="$WORK/kubectl-calls"
export FAKE_NAMESPACE_JSON="$WORK/namespace.json"
printf '{"metadata":{"name":"storage-measure","labels":{}}}\n' >"$FAKE_NAMESPACE_JSON"

run_harness() {
  local rc=0
  rm -f "$KUBECTL_CALLS"
  PATH="$WORK/bin:$PATH" "$SM/measure-storage.sh" "$@" >"$WORK/out" 2>"$WORK/err" || rc=$?
  printf '%s\n' "$rc"
}

expect_refusal() {
  local label="$1" pattern="$2" rc
  shift 2
  rc="$(run_harness "$@")"
  [[ "$rc" == 2 ]] || fail "$label: exit $rc, expected 2; stderr: $(cat "$WORK/err")"
  grep -Fq -- "$pattern" "$WORK/err" || fail "$label: stderr lacks '$pattern': $(cat "$WORK/err")"
  [[ ! -e "$KUBECTL_CALLS" ]] || fail "$label: kubectl ran before the refusal"
  pass
}

base=(--context ctx --namespace storage-measure --storage-class local-path --skip-fio
  --output-dir "$WORK/evidence")
expect_refusal 'ownership flag' 'pass --i-own-this-namespace' "${base[@]}"
expect_refusal 'system namespace' 'is a system namespace' \
  --context ctx --namespace kube-system --storage-class local-path --skip-fio --i-own-this-namespace
expect_refusal 'default namespace' 'is a system namespace' \
  --context ctx --namespace default --storage-class local-path --skip-fio --i-own-this-namespace
expect_refusal 'context required' '--context is required' \
  --namespace storage-measure --storage-class local-path --skip-fio --i-own-this-namespace
expect_refusal 'fio image required' '--fio-image is required' \
  --context ctx --namespace storage-measure --storage-class local-path --i-own-this-namespace
expect_refusal 'fio image digest' 'must be a digest-pinned image reference' \
  --context ctx --namespace storage-measure --storage-class local-path --i-own-this-namespace \
  --fio-image fio:latest
expect_refusal 'probe image digest' 'must be a digest-pinned image reference' \
  "${base[@]}" --i-own-this-namespace --probe-image registry.k8s.io/busybox:1.36
expect_refusal 'runs bound' '--runs must be an integer from 1 to 500' \
  "${base[@]}" --i-own-this-namespace --runs 0
expect_refusal 'runs overflow' '--runs must be an integer from 1 to 500' \
  "${base[@]}" --i-own-this-namespace --runs 99999999999999999999
expect_refusal 'git commit' '--git-commit has an invalid value' \
  "${base[@]}" --i-own-this-namespace --git-commit main
expect_refusal 'git url' '--git-url has an invalid value' \
  "${base[@]}" --i-own-this-namespace --git-url 'http://example.com/repo;rm'
expect_refusal 'unknown option' 'unknown option: --force' "${base[@]}" --i-own-this-namespace --force
mkdir -p "$WORK/full" && : >"$WORK/full/existing"
expect_refusal 'non-empty output' 'is not empty' \
  --context ctx --namespace storage-measure --storage-class local-path --skip-fio \
  --i-own-this-namespace --output-dir "$WORK/full"

# Preflight: only reads, and the sandbox-namespace and missing-class guards.
expect_preflight_refusal() {
  local label="$1" pattern="$2" rc
  rc="$(run_harness "${base[@]}" --i-own-this-namespace --output-dir "$WORK/pre-$label")"
  [[ "$rc" == 2 ]] || fail "$label: exit $rc, expected 2; stderr: $(cat "$WORK/err")"
  grep -Fq -- "$pattern" "$WORK/err" || fail "$label: stderr lacks '$pattern': $(cat "$WORK/err")"
  if grep -Eq '(^| )(create|delete|apply|patch|replace|label|annotate|exec)( |$)' "$KUBECTL_CALLS"; then
    fail "$label: preflight mutated the cluster: $(cat "$KUBECTL_CALLS")"
  fi
  [[ ! -e "$WORK/pre-$label/summary.json" ]] || fail "$label: refused run wrote a summary"
  pass
}
printf '{"metadata":{"name":"storage-measure","labels":{"codewire.sh/runtime-scope":"shared"}}}\n' \
  >"$FAKE_NAMESPACE_JSON"
expect_preflight_refusal sandbox-namespace 'is a Codewire sandbox namespace'
printf '{"metadata":{"name":"storage-measure","labels":{}}}\n' >"$FAKE_NAMESPACE_JSON"
expect_preflight_refusal missing-class 'StorageClass local-path does not exist'

# --- attach runs against a simulated cluster ---------------------------------
# The double answers only the calls the attach phase needs; anything else is
# recorded as unexpected.
cat >"$WORK/bin/kubectl" <<'KUBECTL'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$KUBECTL_CALLS"
args=()
while (($# > 0)); do
  case "$1" in
    --context|-n) shift 2 ;;
    --request-timeout=*) shift ;;
    *) args+=("$1"); shift ;;
  esac
done
set -- "${args[@]}"
object_name() { printf '%s' "${2##*/}"; }
case "$*" in
  'config get-contexts -o name') printf 'ctx\n' ;;
  'get namespace storage-measure -o json') printf '{"metadata":{"name":"storage-measure","labels":{}}}\n' ;;
  'get storageclass local-path -o json')
    printf '{"provisioner":"rancher.io/local-path","volumeBindingMode":"WaitForFirstConsumer","reclaimPolicy":"Delete"}\n' ;;
  'version -o json') printf '{"serverVersion":{"gitVersion":"v1.34.1"}}\n' ;;
  'get --raw /apis/metrics.k8s.io/v1beta1') exit 1 ;;
  'create -f '*) cp "$3" "$FAKE_CREATED/$(date +%s%N).json" ;;
  'wait --for=delete '*) ;;
  'wait '*) [[ "${FAKE_WAIT_FAIL:-0}" == 0 ]] || exit 1 ;;
  'get pvc '*' -o json')
    printf '{"metadata":{"name":"%s","creationTimestamp":"2026-09-29T10:00:00Z"},"spec":{"volumeName":"pv-%s"},"status":{"phase":"Bound"}}\n' "$3" "$3" ;;
  'get pv '*' -o json')
    printf '{"metadata":{"creationTimestamp":"2026-09-29T10:00:02Z"},"spec":{"persistentVolumeReclaimPolicy":"Delete"}}\n' ;;
  'get pod '*' -o json')
    printf '{"metadata":{"creationTimestamp":"2026-09-29T10:00:00Z"},"spec":{"nodeName":"node-a"},"status":{"conditions":[{"type":"PodScheduled","status":"True","lastTransitionTime":"2026-09-29T10:00:01Z"},{"type":"ContainersReady","status":"True","lastTransitionTime":"2026-09-29T10:00:04Z"}]}}\n' ;;
  'get events '*) printf '{"items":[]}\n' ;;
  'delete '*) ;;
  'get pod,pvc,configmap -l '*' -o name') ;;
  *) printf 'UNEXPECTED %s\n' "$*" >>"$KUBECTL_CALLS"; exit 97 ;;
esac
KUBECTL
export FAKE_CREATED="$WORK/created"

simulate() {
  local label="$1" rc
  shift
  rm -rf "$FAKE_CREATED" && mkdir -p "$FAKE_CREATED"
  rc="$(run_harness --context ctx --namespace storage-measure --i-own-this-namespace \
    --storage-class local-path --runtime-class none --skip-fio --skip-workload \
    --output-dir "$WORK/sim-$label" "$@")"
  printf '%s\n' "$rc"
}

rc="$(simulate ok --runs 3 --warmup 1)"
[[ "$rc" == 0 ]] || fail "simulated run exited $rc: $(cat "$WORK/err")"
! grep -q '^UNEXPECTED' "$KUBECTL_CALLS" || fail "unexpected kubectl calls: $(grep '^UNEXPECTED' "$KUBECTL_CALLS")"
[[ "$(find "$FAKE_CREATED" -name '*.json' | wc -l)" == 4 ]] || fail 'expected four create calls'
jq -e -s 'all(.[].items[]; .metadata.labels["codewire.sh/storage-measure"] | test("^sm-[0-9]{14}-[0-9a-f]{6}$"))' \
  "$FAKE_CREATED"/*.json >/dev/null || fail 'a created object lacks the run label'
for kinds in pod pvc,configmap; do
  grep -Eq -- "^--context ctx -n storage-measure delete $kinds -l codewire.sh/storage-measure=sm-" \
    "$KUBECTL_CALLS" || fail "exit cleanup did not delete $kinds by run label"
done
if grep -E '(^| )(create|delete)( |$)' "$KUBECTL_CALLS" | grep -vq -- ' -n storage-measure '; then
  fail "a mutating call left the namespace: $(grep -E '(create|delete)' "$KUBECTL_CALLS")"
fi
check 'simulated summary' '.status == "ok" and .provision_attach.runs_ok == 3
  and .provision_attach.warmup_runs == 1 and .provision_attach.server.provision_ms.p50 == 1000
  and .provision_attach.server.create_to_ready_ms.p95 == 4000
  and (.provision_attach.client.create_to_ready_ms.n == 3)
  and .teardown.n == 3 and .cleanup.status == "clean"
  and ([.phases[].phase] == ["attach"]) and .node_overhead.available == false' \
  "$WORK/sim-ok/summary.json"
[[ ! -e "$WORK/sim-ok/.phase" && ! -e "$WORK/sim-ok/.node" ]] || fail 'harness state files remain'
pass

rc="$(FAKE_WAIT_FAIL=1 simulate failing --runs 5 --warmup 0 --max-failures 2)"
[[ "$rc" == 1 ]] || fail "failing simulated run exited $rc, expected 1"
[[ "$(find "$WORK/sim-failing/attach" -name 'run-*.json' | wc -l)" == 2 ]] ||
  fail 'the failure budget did not stop the runs'
check 'failing summary' '.status == "failed" and .provision_attach.runs_ok == 0
  and .provision_attach.runs_measured == 2
  and (.phases[0].reason | startswith("stopped after 2 failed runs"))' "$WORK/sim-failing/summary.json"

# --- manifests ---------------------------------------------------------------
digest() {
  printf '%s@sha256:%s' "$1" "$(printf '%64s' '' | tr ' ' "$2")"
}

render_all() {
  local runtime_class="$1" node="$2" docker="$3" fio_pvc="$4" snapshot="$5"
  (
    # shellcheck source=scripts/runtime/storage-measure/measure-storage.sh
    source "$SM/measure-storage.sh"
    RUN_ID="$RUN_ID_FIXTURE"
    NAMESPACE=storage-measure
    STORAGE_CLASS=linstor-thin
    RUNTIME_CLASS="$runtime_class"
    NODE="$node"
    WITH_DOCKER="$docker"
    SKIP_FIO=0
    FIO_IMAGE="$(digest registry.example/fio f)"
    WORKLOAD_IMAGE="$(digest registry.example/workspace a)"
    DIND_IMAGE="$(digest registry.example/dind d)"
    build_config
    render '[sm_pvc($cfg; "sm-p"; "attach"; $snapshot), sm_probe_pod($cfg; "sm-p"; "sm-p"; "attach"),
             sm_pvc($cfg; "sm-b"; "bench"; ""), sm_bench_pod($cfg; "sm-b"; "sm-b"; $fio_pvc; "sm-s"),
             sm_scripts_configmap($cfg; "sm-s"; "w"; "d"),
             sm_volume_snapshot($cfg; "sm-v"; "linstor-local"; "sm-b"; "snapshot-local")] | sm_list' \
      --arg snapshot "$snapshot" --arg fio_pvc "$fio_pvc"
  )
}

render_all commodity cw-dev-prod-node-1 1 sm-b-fio sm-snap >"$WORK/full.json"
render_all none '' 0 '' '' >"$WORK/plain.json"
for manifest in "$WORK/full.json" "$WORK/plain.json"; do
  check 'list' '.kind == "List" and (.items | length) == 6' "$manifest"
  jq -e --arg run "$RUN_ID_FIXTURE" 'all(.items[];
      .metadata.namespace == "storage-measure"
      and .metadata.labels["codewire.sh/storage-measure"] == $run
      and .metadata.labels["app.kubernetes.io/managed-by"] == "codewire-storage-measure")' \
    "$manifest" >/dev/null || fail "an object lacks the run label or namespace in $manifest"
  pass
  check 'digest-pinned images' \
    '[.items[] | select(.kind == "Pod") | .spec.containers[].image] | all(test("@sha256:[0-9a-f]{64}$"))' "$manifest"
  check 'pod isolation' '[.items[] | select(.kind == "Pod") | .spec] | all(
      .automountServiceAccountToken == false and .restartPolicy == "Never"
      and (.activeDeadlineSeconds | type) == "number"
      and .securityContext.fsGroup == 1000 and .securityContext.runAsUser == 1000
      and ([.volumes[] | has("hostPath")] | any | not))' "$manifest"
  check 'only dind is privileged' '[.items[] | select(.kind == "Pod") | .spec.containers[]
      | select(.name != "dind")] | all(.securityContext.allowPrivilegeEscalation == false
      and .securityContext.runAsNonRoot == true and .securityContext.capabilities.drop == ["ALL"]
      and (.securityContext.privileged // false) == false)' "$manifest"
  check 'wait-for-first-consumer claims' \
    '[.items[] | select(.kind == "PersistentVolumeClaim") | .spec] | all(.storageClassName == "linstor-thin"
      and .accessModes == ["ReadWriteOnce"] and .resources.requests.storage == "20Gi")' "$manifest"
  check 'snapshot source' '.items[5].spec == {volumeSnapshotClassName: "linstor-local",
      source: {persistentVolumeClaimName: "sm-b"}}' "$manifest"
done
check 'runtime class and node' '.items[1].spec.runtimeClassName == "commodity"
  and .items[1].spec.nodeSelector == {"kubernetes.io/hostname": "cw-dev-prod-node-1"}
  and .items[3].spec.runtimeClassName == "commodity"' "$WORK/full.json"
check 'runtime class none' '[.items[] | select(.kind == "Pod") | .spec]
  | all((has("runtimeClassName") | not) and (has("nodeSelector") | not))' "$WORK/plain.json"
check 'clone data source' '.items[0].spec.dataSource == {apiGroup: "snapshot.storage.k8s.io",
  kind: "VolumeSnapshot", name: "sm-snap"}' "$WORK/full.json"
check 'no data source' '.items[0].spec | has("dataSource") | not' "$WORK/plain.json"
check 'bench containers' '[.items[3].spec.containers[].name] == ["workload", "fio", "dind"]
  and ([.items[3].spec.volumes[].name] == ["workspace", "scripts", "fio", "docker-sock"])
  and (.items[3].spec.containers[2].securityContext.privileged == true)
  and (.items[3].spec.containers[0].env | any(.name == "DOCKER_HOST"))' "$WORK/full.json"
check 'bench without docker or fio' '[.items[3].spec.containers[].name] == ["workload"]
  and ([.items[3].spec.volumes[].name] == ["workspace", "scripts"])' "$WORK/plain.json"
check 'probe exits on TERM' '.items[1].spec.containers[0].command[2] | startswith("trap '"'"'exit 0'"'"' TERM;")' \
  "$WORK/plain.json"

# The product defaults are read from their single Rust source.
(
  # shellcheck source=scripts/runtime/storage-measure/measure-storage.sh
  source "$SM/measure-storage.sh"
  workspace="$(read_rust_image_const "$SM_RUNTIME_IMAGES" DEFAULT_WORKSPACE_IMAGE)"
  dind="$(read_rust_image_const "$SM_TEMPLATE_IMAGES" DEFAULT_DIND_IMAGE)"
  [[ "$workspace" =~ ^registry\.example\.invalid/codewire/workspace@sha256:[0-9a-f]{64}$ ]] ||
    fail "unexpected DEFAULT_WORKSPACE_IMAGE: $workspace"
  [[ "$dind" =~ @sha256:[0-9a-f]{64}$ ]] || fail "unexpected DEFAULT_DIND_IMAGE: $dind"
)
pass

# --- jq library --------------------------------------------------------------
smjq -n -e 'include "measure";
  (["2026-09-29T10:00:00Z", "2026-09-29T10:00:00.5Z", "2026-09-29T10:00:00.123456Z",
    "2026-09-29T10:00:00+00:00", "2026-09-29T10:00:00+02:00", null, "garbage"] | map(ts_ms))
  == [1790676000000, 1790676000500, 1790676000123, 1790676000000, null, null, null]' >/dev/null ||
  fail 'ts_ms'
pass
smjq -n -e 'include "measure";
  ([range(1; 21)] | stats) == {n: 20, min: 1, p50: 10, p95: 19, max: 20, mean: 10.5}
  and ([7] | stats) == {n: 1, min: 7, p50: 7, p95: 7, max: 7, mean: 7}
  and ([null, "x"] | stats) == {n: 0, min: null, p50: null, p95: null, max: null, mean: null}
  and ([40, 10, 30, 20] | stats | [.p50, .p95]) == [20, 40]' >/dev/null || fail 'stats'
pass
smjq -n -e 'include "measure";
  (["123456789n", "250m", "2", "1500u", "12x", null] | map(cpu_mcores)) == [123.457, 250, 2000, 1.5, null, null]
  and (["1048576Ki", "512Mi", "1Gi", "1000000", "bad"] | map(mem_mib)) == [1024, 512, 1024, 0.954, null]' \
  >/dev/null || fail 'quantities'
pass
smjq -n -e 'include "measure";
  metrics_sample(1; "attach"; "n1";
    {usage: {cpu: "2500m", memory: "2Gi"}};
    {items: [{metadata: {name: "a"}, spec: {nodeName: "n1"}}, {metadata: {name: "b"}, spec: {nodeName: "n2"}}]};
    {items: [{metadata: {name: "a"}, containers: [{usage: {cpu: "100m", memory: "64Mi"}}, {usage: {cpu: "50m", memory: "32Mi"}}]},
             {metadata: {name: "b"}, containers: [{usage: {cpu: "900m", memory: "900Mi"}}]}]})
  == {t_ms: 1, phase: "attach", node: "n1", node_cpu_mcores: 2500, node_mem_mib: 2048,
      storage_pods: 1, storage_cpu_mcores: 150, storage_mem_mib: 96}
  and (metrics_sample(1; "idle"; "n1"; {usage: {cpu: "1", memory: "1Mi"}}; null; null)
       | .storage_pods == null and .storage_cpu_mcores == null)' >/dev/null || fail 'metrics_sample'
pass

smjq -n --slurpfile pvc "$FIX/raw/pvc.json" --slurpfile pv "$FIX/raw/pv.json" \
  --slurpfile pod "$FIX/raw/pod.json" --slurpfile pvc_events "$FIX/raw/pvc-events.json" \
  --slurpfile pod_events "$FIX/raw/pod-events.json" \
  'include "measure"; {pvc: $pvc[0], pv: $pv[0], pod: $pod[0], pvc_events: $pvc_events[0],
    pod_events: $pod_events[0]} | server_timeline' >"$WORK/timeline.json"
same_json 'server timeline' "$FIX/timeline.expected.json" "$WORK/timeline.json"
smjq -n -e 'include "measure"; {pvc: null, pv: null, pod: null, pvc_events: null, pod_events: null}
  | server_timeline | .create_to_ready_ms == null and .image_pulled == false' >/dev/null ||
  fail 'server timeline tolerates missing objects'
pass

# --- harness helpers ---------------------------------------------------------
(
  # shellcheck source=scripts/runtime/storage-measure/measure-storage.sh
  source "$SM/measure-storage.sh"
  extract_fio_json <"$FIX/fio-randread-4k-qd1.raw" >"$WORK/fio-document.json"
  parse_workload_output "$FIX/workload.out" 0 >"$WORK/workload.json"
)
smjq 'include "measure";
  fio_summary({name: "randread-4k-qd1", rw: "randread", bs: "4k", iodepth: 1, direction: "read"})' \
  "$WORK/fio-document.json" >"$WORK/fio.json"
same_json 'fio summary' "$FIX/fio.expected.json" "$WORK/fio.json"
same_json 'workload parse' "$FIX/workload.expected.json" "$WORK/workload.json"

# --- in-pod workload script with local doubles ------------------------------
mkdir -p "$WORK/podbin"
cat >"$WORK/podbin/git" <<'GIT'
#!/usr/bin/env bash
case "$1" in
  clone) dir="${!#}"; mkdir -p "$dir"; printf '[package]\nname = "fixture"\n' >"$dir/Cargo.toml" ;;
  -C) [[ "$3" != rev-parse ]] || printf '%s\n' "$FAKE_COMMIT" ;;
  *) exit 64 ;;
esac
GIT
cat >"$WORK/podbin/cargo" <<'CARGO'
#!/usr/bin/env bash
case "$1" in
  fetch) mkdir -p "$CARGO_HOME/registry/src/index/crate" && printf 'x\n' >"$CARGO_HOME/registry/src/index/crate/lib.rs" ;;
  build) exit "${FAKE_CARGO_BUILD_RC:-0}" ;;
  *) exit 64 ;;
esac
CARGO
chmod +x "$WORK/podbin/git" "$WORK/podbin/cargo"
commit=e89fff89ac9af12e8d4ce9d5fd07beb408ca730f

run_workload() {
  local rc=0
  env PATH="$WORK/podbin:$PATH" SM_ROOT="$WORK/pod/sm" SM_GIT_URL=https://example.invalid/repo \
    SM_GIT_COMMIT="$commit" FAKE_COMMIT="$commit" SM_STEP_TIMEOUT_SECONDS=60 "$@" \
    bash "$SM/pod/workload.sh" >"$WORK/pod.out" 2>"$WORK/pod.err" || rc=$?
  (
    # shellcheck source=scripts/runtime/storage-measure/measure-storage.sh
    source "$SM/measure-storage.sh"
    parse_workload_output "$WORK/pod.out" "$rc"
  ) >"$WORK/pod.json"
}

run_workload
check 'workload steps' '.exit_code == 0 and .info.nproc >= 1
  and ([.steps[] | [.step, .status]] == [["git_clone", "ok"], ["cargo_fetch", "ok"], ["cargo_build", "ok"],
    ["file_tree_pack", "ok"], ["file_tree_unpack", "ok"], ["file_tree_remove", "ok"],
    ["docker_build", "skipped"]])
  and ([.steps[] | select(.status == "ok") | .ms] | all(type == "number" and . >= 0))' "$WORK/pod.json"
[[ ! -e "$WORK/pod/sm/work/tree" && ! -e "$WORK/pod/sm/work/tree.tar" ]] || fail 'file tree was not removed'
pass
run_workload FAKE_CARGO_BUILD_RC=3
check 'workload failure' '.exit_code == 1
  and (.steps[] | select(.step == "cargo_build") | .status == "failed" and .exit_code == 3)
  and (.steps[] | select(.step == "file_tree_unpack") | .status == "ok")' "$WORK/pod.json"
SM_ROOT="$WORK/marker" bash "$SM/pod/workload.sh" --write-marker remote-2:fixture 1
[[ "$(cat "$WORK/marker/marker")" == remote-2:fixture ]] || fail 'marker content'
delta_files=("$WORK"/marker/delta-*.bin)
[[ ${#delta_files[@]} -eq 1 && "$(stat -c %s "${delta_files[0]}")" == 1048576 ]] || fail 'delta file size'
pass
if bash "$SM/pod/workload.sh" --step not-a-step >/dev/null 2>&1; then
  fail 'unknown workload step accepted'
fi
pass

# --- summarizer --------------------------------------------------------------
"$SM/summarize.sh" "$FIX/evidence" >"$WORK/summary.json"
same_json 'summary' "$FIX/summary.expected.json" "$WORK/summary.json"
if "$SM/summarize.sh" "$WORK" >/dev/null 2>&1; then
  fail 'summarize accepted a directory without meta.json'
fi
pass

printf 'storage-measure tests: %d passed\n' "$COUNT"
