#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/dind-probe-tests.XXXXXX")"
trap 'rm -rf "$TEST_TMP"' EXIT
mkdir "$TEST_TMP/bin"
export PROBE_TEST_LOG="$TEST_TMP/calls.jsonl"
REAL_GIT="$(command -v git)"
export REAL_GIT
cat >"$TEST_TMP/bin/git" <<'SH'
#!/usr/bin/env bash
case "$*" in
  *'status --porcelain'*) [[ "${PROBE_CASE:-}" != dirty ]] || printf ' M candidate\n' ;;
  *'rev-parse HEAD^{tree}') printf '%040d\n' 2 ;;
  *'rev-parse HEAD') printf '%040d\n' 1 ;;
  *) exec "$REAL_GIT" "$@" ;;
esac
SH
cat >"$TEST_TMP/bin/cargo" <<'PY'
#!/usr/bin/env python3
import hashlib,json,sys
name,image,storage=sys.argv[-3:]
dind='docker.io/library/docker:29.9.2-dind@sha256:'+'a'*64
policy={'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':{'name':'cw-daemon-net-'+name,'namespace':'dev-sandboxes'},'spec':{'podSelector':{'matchLabels':{'codewire.sh/environment-id':name,'codewire.sh/type':'workspace'}}}}
command=['sh','-ec','exec dockerd']
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
print(json.dumps({'schema_version':1,'support_image':image,'dind_image':dind,
 'bootstrap_argv_sha256':digest(command),'network_policy_sha256':digest(policy),'objects':[
 {'apiVersion':'v1','kind':'PersistentVolumeClaim','metadata':{'name':name+'-workspace','namespace':'dev-sandboxes'},'spec':{'storageClassName':storage,'volumeMode':'Block','accessModes':['ReadWriteOnce'],'resources':{'requests':{'storage':'8Gi'}}}},
 {'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':'dev-sandboxes','annotations':{'codewire.sh/workspace':'true'},'labels':{'codewire.sh/environment-id':name,'codewire.sh/type':'workspace'}},'spec':{'runtimeClassName':'commodity','restartPolicy':'Never','serviceAccountName':'codewire-sandbox','automountServiceAccountToken':False,'initContainers':[{'name':'mount-workspace','image':image,'volumeDevices':[{'name':'workspace','devicePath':'/dev/cwws'}]}],'volumes':[{'name':'scratch','emptyDir':{}},{'name':'workspace','persistentVolumeClaim':{'claimName':name+'-workspace'}}],'containers':[{'name':'dind','image':dind,'resources':{'limits':{'cpu':'2','memory':'2Gi'}},'command':command},{'name':'client','image':dind,'resources':{'limits':{'cpu':'1','memory':'512Mi'}},'securityContext':{'runAsUser':1000,'allowPrivilegeEscalation':False,'capabilities':{'drop':['ALL']}},'command':['sh','-ec','umask 077; mkdir "$DOCKER_CONFIG"; exec sleep 86400'],'env':[{'name':'DOCKER_HOST','value':'unix:///var/run/docker/docker.sock'},{'name':'DOCKER_CONFIG','value':'/tmp/codewire-dind-client'}]}]}},policy]}))
PY
cat >"$TEST_TMP/bin/kubectl" <<'PY'
#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with open(os.environ['PROBE_TEST_LOG'],'a') as f:f.write(json.dumps(args)+'\n')
assert args[:4]==['--context','example-dev','-n','dev-sandboxes'],args
args=args[4:]
case=os.environ.get('PROBE_CASE')
if args[0]=='create':
 obj=json.loads(Path(args[args.index('-f')+1]).read_text())
 if obj['kind']=='PersistentVolumeClaim':
  if case=='pvc-collision':sys.exit(19)
  print(json.dumps({'metadata':{'uid':'pvc-own'}}))
 elif obj['kind']=='NetworkPolicy':
  if case=='policy-collision':sys.exit(20)
  print('policy-own',end='')
 else:
  if case=='admission':
   print('admission denied fixture',file=sys.stderr);sys.exit(42)
  print('pod-own',end='')
elif args[0]=='get':
 if args[1]=='pod':
  if args[-1]=='json':print(json.dumps({'metadata':{'uid':'pod-own'},'spec':{'nodeName':'fixture-node'},'status':{'phase':'Running','containerStatuses':[]}}))
  else:print('pod-replaced' if case=='replaced' else 'pod-own',end='')
 elif args[1]=='networkpolicy':print('policy-replaced' if case=='policy-replaced' else 'policy-own',end='')
 else:print('pvc-own',end='')
elif args[0] in ['wait','delete','annotate']:pass
elif args[0]=='exec':
 cmd=args[args.index('--')+1:]
 if '-c' in args and args[args.index('-c')+1]=='dind':print('pid1=dockerd\ncgroup=/sys/fs/cgroup\ncgroup.type=domain threaded')
 elif 'info' in cmd:
  if case=='readiness-timeout':sys.exit(1)
  print('null' if '{{json .DriverStatus}}' in cmd else 'vfs')
 elif 'version' in cmd:print('{}')
 elif 'pull' in cmd:print('pinned fixture image')
 elif 'run' in cmd:
  if '--cpus' in cmd or '--memory' in cmd:sys.exit(125)
 else:raise AssertionError(cmd)
else:raise AssertionError(args)
PY
chmod +x "$TEST_TMP/bin/"*
export PATH="$TEST_TMP/bin:$PATH"
SUPPORT="registry.example.invalid/daemon@sha256:$(printf 'a%.0s' {1..64})"
readonly SUPPORT
fail() { printf 'dind-storage probe tests: %s\n' "$*" >&2; exit 1; }
# The scripts take the cluster names from their environment; these are not real.
export CODEWIRE_DEV_CLUSTER=example-dev CODEWIRE_PROD_CLUSTER=example-prod
run_case() {
  local name="$1" expected="$2" rc=0
  shift 2
  : >"$PROBE_TEST_LOG"
  if [[ "$name" == offline || "$name" == dirty ]]; then
    env -u KUBE_CONTEXT -u INFRA_TRANSIENT_KUBE_AUTH -u KUBECONFIG PROBE_CASE="$name" \
      bash "$ROOT/scripts/runtime/dev/smoke-dev-dind-storage.sh" --support-image "$SUPPORT" \
      --storage-class example-workspace --evidence-dir "$TEST_TMP/$name" "$@" >"$TEST_TMP/out" 2>"$TEST_TMP/err" || rc=$?
  else
    local bundle="$TEST_TMP/offline/fixture.json" hash
    [[ "$name" != qualify ]] || bundle="$TEST_TMP/modern/fixture.json"
    hash="$(shasum -a 256 "$bundle" | cut -d ' ' -f 1)"
    PROBE_CASE="$name" KUBE_CONTEXT=example-dev INFRA_TRANSIENT_KUBE_AUTH=1 KUBECONFIG=/not-read-by-fixture \
      bash "$ROOT/scripts/runtime/dev/smoke-dev-dind-storage.sh" --support-image "$SUPPORT" \
      --storage-class example-workspace --rendered-fixture "$bundle" --fixture-sha256 "$hash" \
      --evidence-dir "$TEST_TMP/$name" "$@" >"$TEST_TMP/out" 2>"$TEST_TMP/err" || rc=$?
  fi
  [[ "$rc" == "$expected" ]] || { cat "$TEST_TMP/err" >&2; fail "$name exited$rc expected$expected"; }
}
run_case offline 0 --render-only --baseline
# A second export covers the strict modern qualification path.
env -u KUBECONFIG -u INFRA_TRANSIENT_KUBE_AUTH bash "$ROOT/scripts/runtime/dev/smoke-dev-dind-storage.sh" --support-image "$SUPPORT" --storage-class example-workspace --evidence-dir "$TEST_TMP/modern" --render-only >"$TEST_TMP/out" 2>"$TEST_TMP/err"
[[ ! -s "$PROBE_TEST_LOG" ]] || fail 'offline render accessed Kubernetes'
jq -e '.source_sha == "0000000000000000000000000000000000000001" and .source_tree == "0000000000000000000000000000000000000002" and (.render_sha256 | length == 64)' "$TEST_TMP/offline/source-receipt.json" >/dev/null
printf 'dind-storage test: offline source/tree/render binding\n'
run_case dirty 1 --render-only
[[ ! -s "$PROBE_TEST_LOG" ]] || fail 'dirty candidate reached Kubernetes'
printf 'dind-storage test: dirty candidate refused\n'
# Trusted-host apply must never build code with its Kubernetes authority.
printf '#!/bin/sh\nexit 99\n' >"$TEST_TMP/bin/cargo"
chmod +x "$TEST_TMP/bin/cargo"
run_case baseline 0 --baseline
python3 - "$TEST_TMP/baseline/resource-matrix.tsv" <<'PY'
import sys
assert open(sys.argv[1]).read().splitlines()==['cpu-first\t125','plain\t0','pids\t0','cpu-after\t125','memory\t125']
PY
printf 'dind-storage test: ordered baseline distinguishes expected resource failures\n'
run_case admission 42 --baseline
python3 - <<'PY'
import json,os
calls=[json.loads(s)[4:] for s in open(os.environ['PROBE_TEST_LOG'])]
assert any(c[:2]==['delete','pvc'] for c in calls),calls
assert not any(c[:2]==['delete','pod'] for c in calls),calls
PY
printf 'dind-storage test: admission failure removes only owned PVC\n'
run_case pvc-collision 19 --baseline
! grep -q 'delete\|annotate' "$PROBE_TEST_LOG" || fail 'collision caused deletion'
printf 'dind-storage test: create collision cannot authorize cleanup\n'
run_case replaced 1 --baseline
! grep -q 'delete\|annotate' "$PROBE_TEST_LOG" || fail 'replacement UID caused deletion'
printf 'dind-storage test: changed Pod UID preserves Pod and workspace\n'
run_case qualify 1
grep -q 'resource case cpu-first failed exit125' "$TEST_TMP/err" || fail 'resource rejection did not fail qualification'
printf 'dind-storage test: qualification refuses baseline resource failure\n'
rc=0
env -u KUBE_CONTEXT -u INFRA_TRANSIENT_KUBE_AUTH -u KUBECONFIG bash "$ROOT/scripts/runtime/dev/smoke-dev-dind-storage.sh" \
  --support-image "$SUPPORT" --storage-class example-workspace --baseline --rendered-fixture "$TEST_TMP/offline/fixture.json" --fixture-sha256 "$(shasum -a 256 "$TEST_TMP/offline/fixture.json" | cut -d ' ' -f 1)" --evidence-dir "$TEST_TMP/ambient" >"$TEST_TMP/out" 2>"$TEST_TMP/err" || rc=$?
[[ "$rc" == 1 ]] || fail 'ambient auth was accepted'
grep -q 'ambient kubeconfig is refused' "$TEST_TMP/err" || fail 'ambient auth repair missing'
printf 'dind-storage test: ambient Kubernetes authority refused\n'
run_case policy-collision 20 --baseline
! grep -q '"delete", "networkpolicy"' "$PROBE_TEST_LOG" || fail 'policy collision deleted unrelated policy'
printf 'dind-storage test: policy collision preserves unrelated policy\n'
run_case policy-replaced 1 --baseline
! grep -q '"delete", "networkpolicy"' "$PROBE_TEST_LOG" || fail 'policy replacement was deleted'
printf 'dind-storage test: replacement policy UID is preserved\n'
run_case readiness-timeout 1 --baseline --wait-seconds 1
grep -q 'rendered bootstrap did not start Docker' "$TEST_TMP/err" || fail 'readiness failure was not bounded'
python3 - <<'PYTEST'
import json,os
calls=[json.loads(s)[4:] for s in open(os.environ['PROBE_TEST_LOG'])]
probes=[c[c.index('--')+1:] for c in calls if c[0]=='exec']
assert probes and all(p[:2]==['timeout','5'] for p in probes if 'info' in p),probes
assert not any('run' in p for p in probes),probes
PYTEST
printf 'dind-storage test: short readiness deadline refuses child execution\n'
# Recompute the outer expected hash for malformed but intentionally supplied
# bundles: shape/source/link checks must still reject them before any API call.
for mutation in source name host-network privileged-observer host-path secret-volume extra-object foreign-pvc secret-env secret-env-from client-config client-setup bootstrap policy; do
  bundle="$TEST_TMP/reject-$mutation.json"
  python3 - "$TEST_TMP/offline/fixture.json" "$bundle" "$mutation" <<'MUTATE'
import hashlib,json,sys
bundle=json.load(open(sys.argv[1]));render=bundle['render'];mode=sys.argv[3]
pod=render['objects'][1]['spec']
if mode=='source':bundle['receipt']['source_sha']='f'*40
elif mode=='name':bundle['receipt']['name']='existing-user-workspace'
elif mode=='host-network':pod['hostNetwork']=True
elif mode=='privileged-observer':pod['containers'][1]['securityContext']['privileged']=True
elif mode=='host-path':pod['volumes'].append({'name':'host','hostPath':{'path':'/'}})
elif mode=='secret-volume':pod['volumes'].append({'name':'secret','secret':{'secretName':'unrelated'}})
elif mode=='extra-object':render['objects'].append({'apiVersion':'v1','kind':'ServiceAccount'})
elif mode=='foreign-pvc':pod['volumes'].append({'name':'foreign','persistentVolumeClaim':{'claimName':'unrelated-user-workspace'}})
elif mode=='secret-env':pod['containers'][1]['env']=[{'name':'TOKEN','valueFrom':{'secretKeyRef':{'name':'unrelated','key':'token'}}}]
elif mode=='secret-env-from':pod['initContainers'][0]['envFrom']=[{'secretRef':{'name':'unrelated'}}]
elif mode=='client-config':pod['containers'][1]['env'][1]['value']='/root/.docker'
elif mode=='client-setup':pod['containers'][1]['command']=['sh','-ec','exec sleep 86400']
elif mode=='bootstrap':pod['containers'][0]['command']=['sh','-c','unexpected']
elif mode=='policy':render['objects'][2]['spec']['egress']=[{}]
canonical=json.dumps(render,sort_keys=True,ensure_ascii=False,separators=(',',':'))+'\n'
bundle['receipt']['render_sha256']=hashlib.sha256(canonical.encode()).hexdigest()
json.dump(bundle,open(sys.argv[2],'w'))
MUTATE
  : >"$PROBE_TEST_LOG"
  rc=0
  PROBE_CASE=reject KUBE_CONTEXT=example-dev INFRA_TRANSIENT_KUBE_AUTH=1 KUBECONFIG=/not-read-by-fixture \
    bash "$ROOT/scripts/runtime/dev/smoke-dev-dind-storage.sh" --support-image "$SUPPORT" --storage-class example-workspace --baseline \
    --rendered-fixture "$bundle" --fixture-sha256 "$(shasum -a 256 "$bundle" | cut -d ' ' -f 1)" \
    --evidence-dir "$TEST_TMP/reject-$mutation-evidence" >"$TEST_TMP/out" 2>"$TEST_TMP/err" || rc=$?
  [[ "$rc" != 0 && ! -s "$PROBE_TEST_LOG" ]] || fail "unsafe $mutation reached Kubernetes"
done
printf 'dind-storage test: source/name/unsafe shape/bootstrap/policy rejected before API (14 cases)\n'
: >"$PROBE_TEST_LOG"
rc=0
KUBE_CONTEXT=example-dev INFRA_TRANSIENT_KUBE_AUTH=1 KUBECONFIG=/not-read-by-fixture \
  bash "$ROOT/scripts/runtime/dev/smoke-dev-dind-storage.sh" --support-image "$SUPPORT" --storage-class example-workspace --baseline \
  --rendered-fixture "$TEST_TMP/offline/fixture.json" --fixture-sha256 "$(printf '0%.0s' {1..64})" \
  --evidence-dir "$TEST_TMP/bad-hash" >"$TEST_TMP/out" 2>"$TEST_TMP/err" || rc=$?
[[ "$rc" == 1 && ! -s "$PROBE_TEST_LOG" ]] || fail 'tampered custody hash reached Kubernetes'
printf 'dind-storage test: out-of-band custody hash required\n'
: >"$PROBE_TEST_LOG"
rc=0
# Without the Dev cluster's name nothing is asked of Kubernetes: an empty name
# never matches an empty context.
env -u CODEWIRE_DEV_CLUSTER KUBE_CONTEXT= INFRA_TRANSIENT_KUBE_AUTH=1 KUBECONFIG=/not-read-by-fixture \
  bash "$ROOT/scripts/runtime/dev/smoke-dev-dind-storage.sh" --support-image "$SUPPORT" --storage-class example-workspace --baseline \
  --rendered-fixture "$TEST_TMP/offline/fixture.json" --fixture-sha256 "$(shasum -a 256 "$TEST_TMP/offline/fixture.json" | cut -d ' ' -f 1)" \
  --evidence-dir "$TEST_TMP/no-cluster" >"$TEST_TMP/out" 2>"$TEST_TMP/err" || rc=$?
[[ "$rc" != 0 && ! -s "$PROBE_TEST_LOG" ]] || fail 'a run without the Dev cluster name reached Kubernetes'
grep -q 'CODEWIRE_DEV_CLUSTER is required' "$TEST_TMP/err" || fail "a missing Dev cluster name is not named: $(cat "$TEST_TMP/err")"
printf 'dind-storage test: a missing Dev cluster name is refused before API\n'
# Homebrew's prefixed tool works without changing global PATH or stty.
PROBE_REAL_TIMEOUT="$(builtin command -v timeout || builtin command -v gtimeout)"
export PROBE_REAL_TIMEOUT
cat >"$TEST_TMP/bin/gtimeout" <<'TIMEOUT'
#!/bin/sh
printf 'used\n' >>"${PROBE_TEST_LOG}.timeout"
exec "$PROBE_REAL_TIMEOUT" "$@"
TIMEOUT
chmod +x "$TEST_TMP/bin/gtimeout"
# shellcheck disable=SC2329 # Exported into child Bash to exercise its tool lookup.
command() {
  if [[ "${PROBE_CASE:-}" == no-timeout && "$1" == -v && ( "$2" == timeout || "$2" == gtimeout ) ]]; then return 1; fi
  if [[ "${PROBE_CASE:-}" == prefixed-timeout && "$1" == -v && "$2" == timeout ]]; then return 1; fi
  builtin command "$@"
}
export -f command
run_case no-timeout 1 --baseline
[[ ! -s "$PROBE_TEST_LOG" ]] || fail 'missing host timeout reached Kubernetes'
grep -q 'missing timeout or gtimeout' "$TEST_TMP/err" || fail 'missing tool repair was not reported'
run_case prefixed-timeout 0 --baseline
[[ -s "${PROBE_TEST_LOG}.timeout" ]] || fail 'prefixed timeout was not selected'
unset -f command
printf 'dind-storage test: host timeout capability precedes API and supports gtimeout (2 cases)\n'
printf 'dind-storage probe fixture tests: 28 passed\n'
