#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="$ROOT/scripts/ci/verify/kind-e2e.sh"
COMMON="${CODEWIRE_TEST_KIND_COMMON:-$ROOT/scripts/ci/verify/kind/common.sh}"
INTEGRATED="$ROOT/scripts/ci/verify/kind/suites/integrated.sh"
FIXTURE="$(mktemp -d)"
CLUSTERS="$FIXTURE/clusters"
DELETIONS="$FIXTURE/deletions"
DOCKER_CALLS="$FIXTURE/docker-calls"
DOCKER_PS="$FIXTURE/docker-ps"
KIND_CONFIG="$FIXTURE/kind-config.yaml"
KIND_GET_FAILURE=0
KIND_DELETE_FAILURE=''
DOCKER_PS_FAILURE=0
# The fixture owns this transaction name even when hosted CI exports its own.
export KIND_CLUSTER_NAME=codewire-e2e-ci
unset CLUSTER KIND_PROFILE
# The fixture requests the default host topology even when the caller exports
# a shifted harness port set; the occupied-port cases below occupy ports this
# run requested, and the shifted case sets its own assignment explicitly.
export KIND_INGRESS_HOST_PORT=8090
export KIND_INGRESS_TLS_HOST_PORT=10443
export KIND_TEMPORAL_HOST_PORT=7233
export KIND_ORCHESTRATION_HOST_PORT=8084
export KIND_COORDINATOR_DIRECT_HOST_PORT=18092
export KIND_POSTGRES_HOST_PORT=25432

cleanup_fixture() {
  rm -rf "$FIXTURE"
}
trap cleanup_fixture EXIT

fail() {
  printf '[test-kind-e2e-cleanup] ERROR: %s\n' "$*" >&2
  exit 1
}

kind() {
  case "${1:-} ${2:-}" in
    'get clusters')
      if [ "$KIND_GET_FAILURE" = '1' ]; then
        printf 'fake Kind enumeration failure\n' >&2
        return 1
      fi
      cat "$CLUSTERS"
      ;;
    'delete cluster')
      [ "${3:-}" = '--name' ] || fail "unexpected kind delete arguments: $*"
      local name="${4:-}"
      printf '%s\n' "$name" >> "$DELETIONS"
      if [ "$name" = "$KIND_DELETE_FAILURE" ]; then
        return 1
      fi
      awk -v name="$name" '$0 != name { print }' "$CLUSTERS" > "$CLUSTERS.next"
      mv "$CLUSTERS.next" "$CLUSTERS"
      ;;
    *)
      fail "unexpected kind invocation: $*"
      ;;
  esac
}

docker() {
  printf '%s\n' "$*" >> "$DOCKER_CALLS"
  if [ "${1:-}" != 'ps' ]; then
    fail "cleanup tried to mutate an unrelated Docker container: $*"
  fi
  if [ "$DOCKER_PS_FAILURE" = '1' ]; then
    printf 'fake Docker inspection failure\n' >&2
    return 1
  fi
  cat "$DOCKER_PS"
}

reset_fixture() {
  : > "$CLUSTERS"
  : > "$DELETIONS"
  : > "$DOCKER_CALLS"
  : > "$DOCKER_PS"
  KIND_GET_FAILURE=0
  KIND_DELETE_FAILURE=''
  DOCKER_PS_FAILURE=0
}

expect_failure() {
  local label="$1"
  if reclaim_cancelled_ci_clusters "$KIND_CONFIG" >"$FIXTURE/${label}.out" 2>&1; then
    fail "$label unexpectedly succeeded"
  fi
}

bash -n "$SCRIPT" "$COMMON" "$INTEGRATED" \
  "$ROOT/scripts/ci/verify/kind/suites/final-fencing.sh" "$0"

# Source the shared startup core without running a heavyweight suite. The
# explicit alternate source exists to demonstrate old failing behavior.
# shellcheck source=scripts/ci/verify/kind/common.sh
source "$COMMON"

cat > "$KIND_CONFIG" <<'EOF'
kind: Cluster
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 80
        hostPort: 8090
      - containerPort: 443
        hostPort: 10443
EOF

# Existing names, including the selected name and the same CI prefix, are
# retained until their owner removes them explicitly.
reset_fixture
cat > "$CLUSTERS" <<'EOF'
codewire-e2e-ci-8683
personal-kind
codewire-e2e-ci
codewire-e2e-ciary-1
codewire-e2e-ci-8770
EOF
cp "$CLUSTERS" "$FIXTURE/want-clusters"
expect_failure existing-cluster
[ ! -s "$DELETIONS" ] || fail 'startup deleted an existing cluster'
cmp -s "$FIXTURE/want-clusters" "$CLUSTERS" || fail 'unrelated Kind cluster was changed'
[ ! -s "$DOCKER_CALLS" ] || fail 'startup continued after an existing-cluster refusal'

# Prefix neighbors never authorize reclamation. Repeated absent startup is
# deterministic and inspects ports without any runtime deletion.
reset_fixture
printf '%s\n' codewire-e2e-ci-8683 personal-kind > "$CLUSTERS"
cp "$CLUSTERS" "$FIXTURE/want-clusters"
reclaim_cancelled_ci_clusters "$KIND_CONFIG"
reclaim_cancelled_ci_clusters "$KIND_CONFIG"
cmp -s "$FIXTURE/want-clusters" "$CLUSTERS" || fail 'same-prefix cluster changed'
[ ! -s "$DELETIONS" ] || fail 'name prefix authorized deletion'

# Enumeration failures are fatal and cannot trigger broad deletion attempts.
reset_fixture
KIND_GET_FAILURE=1
expect_failure enumeration-failure
[ ! -s "$DELETIONS" ] || fail 'enumeration failure triggered a deletion'

# A non-Codewire container holding a fixed port is diagnosed, never removed.
reset_fixture
printf '%s\n' personal-kind > "$CLUSTERS"
printf 'abc123\tunrelated-postgres\t0.0.0.0:8090->5432/tcp\n' > "$DOCKER_PS"
expect_failure occupied-port
printf '%s\n' personal-kind | cmp -s - "$CLUSTERS" || fail 'unrelated Kind cluster was deleted on occupied port'
[ ! -s "$DELETIONS" ] || fail 'occupied port triggered a Kind deletion outside the CI prefix'
if grep -Ev '^ps --format ' "$DOCKER_CALLS" | grep -q .; then
  fail 'occupied port triggered a mutating Docker command'
fi

# A shifted run never requested the default ports: a holder of one must not
# block its startup, but a holder of the requested port must, named in the
# error, without mutating the unrelated cluster or container.
reset_fixture
printf '%s\n' personal-kind > "$CLUSTERS"
printf 'abc123\tunrelated-postgres\t0.0.0.0:8090->5432/tcp\n' > "$DOCKER_PS"
(
  KIND_INGRESS_HOST_PORT=18090
  reclaim_cancelled_ci_clusters "$KIND_CONFIG"
) || fail 'shifted startup was blocked by a port it never requested'
printf '%s\n' personal-kind | cmp -s - "$CLUSTERS" || fail 'shifted startup changed an unrelated Kind cluster'
[ ! -s "$DELETIONS" ] || fail 'shifted startup deleted a cluster outside the CI prefix'
reset_fixture
printf '%s\n' personal-kind > "$CLUSTERS"
printf 'abc123\tunrelated-postgres\t0.0.0.0:18090->5432/tcp\n' > "$DOCKER_PS"
if (
  KIND_INGRESS_HOST_PORT=18090
  reclaim_cancelled_ci_clusters "$KIND_CONFIG"
) >"$FIXTURE/shifted-occupied.out" 2>&1; then
  fail 'requested-port holder did not block shifted startup'
fi
grep -Fq 'fixed Kind host port 18090 remains occupied' "$FIXTURE/shifted-occupied.out" ||
  fail 'shifted occupied-port error does not name the requested port'
[ ! -s "$DELETIONS" ] || fail 'requested-port holder triggered a Kind deletion outside the CI prefix'

# A saved profile's config is already rendered to its requested ports. They
# are admitted as requested, a holder of one still blocks startup, and a port
# that is not one of the profile's requested ports is refused.
cat > "$FIXTURE/profile-kind-config.yaml" <<'EOF'
kind: Cluster
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 80
        hostPort: 39985
      - containerPort: 443
        hostPort: 52383
EOF
reset_fixture
printf '%s\n' personal-kind > "$CLUSTERS"
(
  KIND_PROFILE=1 KIND_INGRESS_HOST_PORT=39985 KIND_INGRESS_TLS_HOST_PORT=52383
  reclaim_cancelled_ci_clusters "$FIXTURE/profile-kind-config.yaml"
) || fail 'profile startup refused its own rendered host ports'
reset_fixture
printf '%s\n' personal-kind > "$CLUSTERS"
printf 'abc123\tunrelated-postgres\t127.0.0.1:39985->5432/tcp\n' > "$DOCKER_PS"
if (
  KIND_PROFILE=1 KIND_INGRESS_HOST_PORT=39985 KIND_INGRESS_TLS_HOST_PORT=52383
  reclaim_cancelled_ci_clusters "$FIXTURE/profile-kind-config.yaml"
) >"$FIXTURE/profile-occupied.out" 2>&1; then
  fail 'profile requested-port holder did not block startup'
fi
grep -Fq 'fixed Kind host port 39985 remains occupied' "$FIXTURE/profile-occupied.out" ||
  fail 'profile occupied-port error does not name the requested port'
reset_fixture
printf '%s\n' personal-kind > "$CLUSTERS"
if (
  KIND_PROFILE=1 KIND_INGRESS_HOST_PORT=39985 KIND_INGRESS_TLS_HOST_PORT=40000
  reclaim_cancelled_ci_clusters "$FIXTURE/profile-kind-config.yaml"
) >"$FIXTURE/profile-unknown.out" 2>&1; then
  fail 'profile startup admitted a host port it never requested'
fi
grep -Fq 'host port 52383 is not one of its KIND_*_HOST_PORT values' "$FIXTURE/profile-unknown.out" ||
  fail 'profile unknown-port error does not name the port'
[ ! -s "$DELETIONS" ] || fail 'profile startup deleted a cluster'

# Failure to prove fixed-port release is itself fatal.
reset_fixture
DOCKER_PS_FAILURE=1
expect_failure docker-inspection-failure

main_cleanup_line="$(
  awk '
    /^run_integrated_kind_suite\(\)/ { in_main=1 }
    in_main && /reclaim_cancelled_ci_clusters/ { print NR; exit }
  ' "$INTEGRATED"
)"
main_create_line="$(
  awk '
    /^run_integrated_kind_suite\(\)/ { in_main=1 }
    in_main && /^[[:space:]]+create_cluster([[:space:]]|$)/ { print NR; exit }
  ' "$INTEGRATED"
)"
[ -n "$main_cleanup_line" ] || fail 'integrated suite does not invoke startup cleanup'
[ -n "$main_create_line" ] || fail 'integrated suite does not create the Kind cluster'
[ "$main_cleanup_line" -lt "$main_create_line" ] || fail 'startup cleanup does not precede Kind creation'

printf '[test-kind-e2e-cleanup] cancelled-run cleanup contract passed\n'
