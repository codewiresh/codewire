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
