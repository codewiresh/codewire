#!/usr/bin/env bash
# Hermetic contract for `dev-loop.sh device-ownership`: it turns containerd's
# device_ownership_from_security_context on in each Kind node's config, restarts
# containerd only where it was off, waits for it and for the nodes, is
# idempotent, and fails closed. Fake kind, kubectl, docker and sleep stand in
# for the cluster; a fake node's containerd runs with what its config said at
# its last restart.
set -euo pipefail
unset CLUSTER KIND_PROFILE

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
FIXTURE="$(mktemp -d "$ROOT/.tmp/kind-device-ownership.XXXXXX")"
trap 'rm -rf -- "$FIXTURE"' EXIT
BIN="$FIXTURE/bin"
STATE="$FIXTURE/state"
CALLS="$FIXTURE/docker-calls"
SCRIPT="$ROOT/scripts/dev/kind/dev-loop.sh"
TEMPLATE="$ROOT/tests/e2e/kind/kind-config.yaml"
readonly KEY=device_ownership_from_security_context

fail() {
  printf '[test-kind-device-ownership] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$BIN" "$STATE"

cat >"$BIN/kind" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  'get clusters') printf '%s\n' codewire-e2e-ci ;;
  'get nodes --name codewire-e2e-ci') printf '%s\n' $FAKE_NODES ;;
  *) exit 64 ;;
esac
EOF

cat >"$BIN/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *' get deployment codewire-credential-service') ;;
  '--context kind-codewire-e2e-ci wait node --all --for=condition=Ready --timeout=120s')
    [ "${FAKE_NOT_READY:-0}" != 1 ] ;;
  *) exit 64 ;;
esac
EOF

# Each node is a config file and a "running" file holding the setting its
# containerd started with. The container path of the config maps to the file.
cat >"$BIN/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_CALLS"
[ "$1" = exec ] || exit 64
config="$FAKE_STATE/$2.toml"
running="$FAKE_STATE/$2.running"
shift 2
arguments=("$@")
last=$((${#arguments[@]} - 1))
[ "${arguments[$last]}" != /etc/containerd/config.toml ] || arguments[$last]="$config"
case "${arguments[0]}" in
  crictl)
    [ "${arguments[*]}" = 'crictl info' ] || exit 64
    [ "${FAKE_CRICTL_FAIL:-0}" != 1 ] || exit 1
    printf '{\n  "config": {\n    "device_ownership_from_security_context": %s,\n    "enableCDI": true\n  }\n}\n' \
      "$(cat "$running")"
    ;;
  grep|sed) "${arguments[@]}" ;;
  systemctl)
    [ "${arguments[*]}" = 'systemctl restart containerd' ] || exit 64
    if [ "${FAKE_RESTART_IGNORES_CONFIG:-0}" != 1 ] \
      && grep -q '^  device_ownership_from_security_context = true$' "$config"; then
      echo true >"$running"
    fi
    ;;
  *) exit 64 ;;
esac
EOF

printf '#!/bin/sh\n' >"$BIN/sleep"
chmod +x "$BIN/kind" "$BIN/kubectl" "$BIN/docker" "$BIN/sleep"

# A Kind node's containerd config: the CRI table after its sub-tables, as
# kindest/node writes it.
write_node() {
  local node="$1" table_line="$2" extra="${3:-}"
  {
    printf 'version = 2\n\n'
    printf '[plugins."io.containerd.grpc.v1.cri".containerd]\n  snapshotter = "overlayfs"\n\n'
    printf '%s\n' "$table_line"
    [ -z "$extra" ] || printf '%s\n' "$extra"
    printf '  restrict_oom_score_adj = false\n'
  } >"$STATE/${node}.toml"
  echo false >"$STATE/${node}.running"
}

readonly TABLE='[plugins."io.containerd.grpc.v1.cri"]'

reset() {
  rm -f "$STATE"/*
  : >"$CALLS"
}

# Leading NAME=value arguments set the fakes for this run; the rest go to the
# command.
run_step() {
  local settings=()
  while [[ "${1:-}" == FAKE_*=* ]]; do
    settings+=("$1")
    shift
  done
  env PATH="$BIN:$PATH" KIND_CLUSTER_NAME=codewire-e2e-ci FAKE_NODES='kind-control-plane kind-worker' \
    FAKE_STATE="$STATE" FAKE_CALLS="$CALLS" "${settings[@]}" "$SCRIPT" device-ownership "$@"
}

expect_failure() {
  local label="$1" message="$2"
  shift 2
  if "$@" >"$FIXTURE/${label}.out" 2>&1; then
    fail "${label} unexpectedly succeeded"
  fi
  grep -Fq -- "$message" "$FIXTURE/${label}.out" \
    || fail "${label} did not report: ${message} ($(cat "$FIXTURE/${label}.out"))"
}

restarts() {
  grep -c " systemctl restart containerd$" "$CALLS" || true
}

key_lines() {
  grep -c "^  ${KEY} = true$" "$STATE/$1.toml" || true
}

# The template a new cluster is created from sets the same key under the CRI
# table, so a new cluster and a fixed old one agree.
python3 - "$TEMPLATE" "$KEY" <<'PY' || fail "tests/e2e/kind/kind-config.yaml does not turn ${KEY} on"
import sys, tomllib, yaml
template, key = sys.argv[1], sys.argv[2]
patches = yaml.safe_load(open(template))["containerdConfigPatches"]
assert any(tomllib.loads(p)["plugins"]["io.containerd.grpc.v1.cri"].get(key) is True for p in patches)
PY

# A `standard` Pod's image disk is an image volume, which Kind's Kubernetes
# drops without an error while the gate is off, and its /dev/kvm plugin runs on
# the sandbox pool, so both new-cluster configs turn the gate on and the e2e
# node carries the pool's label (#5602).
python3 - "$TEMPLATE" "$ROOT/deployments/kind/cluster-config.yaml" <<'PY' || fail "a Kind config does not turn ImageVolume on, or the e2e node is not in the sandbox pool"
import sys, yaml
e2e, local = (yaml.safe_load(open(path)) for path in sys.argv[1:])
assert all(config.get("featureGates", {}).get("ImageVolume") is True for config in (e2e, local))
patch = yaml.safe_load(e2e["nodes"][0]["kubeadmConfigPatches"][0])
labels = patch["nodeRegistration"]["kubeletExtraArgs"]["node-labels"].split(",")
assert "codewire.sh/node-pool=sandbox" in labels
PY

# Two nodes without the setting: each gets one key line under the CRI table,
# one restart, and containerd back with it on.
reset
write_node kind-control-plane "$TABLE"
write_node kind-worker "$TABLE"
run_step FAKE_NODES="kind-control-plane kind-worker" >"$FIXTURE/first.out" 2>&1 || fail "first run failed: $(cat "$FIXTURE/first.out")"
for node in kind-control-plane kind-worker; do
  [ "$(key_lines "$node")" = 1 ] || fail "${node} config does not hold the key once: $(cat "$STATE/${node}.toml")"
  [ "$(cat "$STATE/${node}.running")" = true ] || fail "${node} containerd does not run with the key"
  python3 -c 'import sys, tomllib; c = tomllib.load(open(sys.argv[1], "rb"))
assert c["plugins"]["io.containerd.grpc.v1.cri"][sys.argv[2]] is True
assert c["plugins"]["io.containerd.grpc.v1.cri"]["restrict_oom_score_adj"] is False' \
    "$STATE/${node}.toml" "$KEY" || fail "${node} config is not the CRI table with the key added"
done
[ "$(restarts)" = 2 ] || fail "expected two restarts, saw $(restarts)"

# A second run changes nothing and restarts nothing.
: >"$CALLS"
run_step >"$FIXTURE/second.out" 2>&1 || fail "second run failed: $(cat "$FIXTURE/second.out")"
[ "$(restarts)" = 0 ] || fail "a second run restarted containerd"
! grep -q ' sed ' "$CALLS" || fail "a second run edited a config"
[ "$(key_lines kind-worker)" = 1 ] || fail "a second run added the key again"
grep -Fq "already gives a device the container's own user" "$FIXTURE/second.out" \
  || fail "a second run did not say the nodes were already set"

# A node already running with it is left alone while the other is fixed.
reset
write_node kind-control-plane "$TABLE" "  ${KEY} = true"
echo true >"$STATE/kind-control-plane.running"
write_node kind-worker "$TABLE"
run_step >"$FIXTURE/mixed.out" 2>&1 || fail "mixed run failed: $(cat "$FIXTURE/mixed.out")"
[ "$(restarts)" = 1 ] || fail "expected one restart, saw $(restarts)"
! grep -q '^exec kind-control-plane systemctl' "$CALLS" || fail "a node already set was restarted"

# Fails closed: a config that sets the key otherwise, a config with no CRI
# table, an unreadable containerd, a containerd that comes back without the
# setting, nodes that are not Ready, and an argument.
reset
write_node kind-control-plane "$TABLE" "  ${KEY} = false"
expect_failure set-otherwise "already sets ${KEY}, but containerd does not run with it on" \
  run_step FAKE_NODES=kind-control-plane
[ "$(restarts)" = 0 ] || fail "a config that sets the key otherwise was restarted"
[ "$(key_lines kind-control-plane)" = 0 ] || fail "a config that sets the key otherwise was edited"

reset
write_node kind-control-plane '[plugins."io.containerd.cri.v1.runtime"]'
expect_failure no-table "has no ${TABLE} table" \
  run_step FAKE_NODES=kind-control-plane
[ "$(restarts)" = 0 ] || fail "a config with no CRI table was restarted"

reset
write_node kind-control-plane "$TABLE"
expect_failure crictl "could not read containerd's settings on kind-control-plane" \
  run_step FAKE_NODES=kind-control-plane FAKE_CRICTL_FAIL=1

reset
write_node kind-control-plane "$TABLE"
expect_failure not-back "did not come back with ${KEY} on within 60 s" \
  run_step FAKE_NODES=kind-control-plane FAKE_RESTART_IGNORES_CONFIG=1

reset
write_node kind-control-plane "$TABLE"
expect_failure not-ready "are not Ready after containerd restarted" \
  run_step FAKE_NODES=kind-control-plane FAKE_NOT_READY=1

reset
expect_failure usage "usage: " run_step --all

echo "[test-kind-device-ownership] device-ownership contract passed"
