#!/usr/bin/env bash
# EnvironmentSession direct-Connect/public-gRPC suite for an explicitly named,
# retained prepared Kind cluster. This suite diagnoses one capability; it never
# owns cluster deletion.
set -euo pipefail

if [ "${KIND_E2E_COMMON_LOADED:-0}" != "1" ]; then
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/common.sh"
fi

run_retained_environment_session_suite() {
  local environment_id=env-crd-smoke
  local daemon_pod=crd-smoke-workspace-daemon
  local fixture

  require_kind_errexit
  require_tool cargo
  require_tool kind
  require_tool kubectl

  trap retained_suite_cleanup EXIT
  validate_retained_cluster_identity
  if ! kubectl -n "$SANDBOX_NS" wait "pod/${daemon_pod}" \
      --for=condition=Ready --timeout=30s; then
    echo "::error::retained environment-session fixture pod ${daemon_pod} is not ready"
    return 1
  fi
  fixture="$(
    kubectl -n "$NS" exec deploy/postgres -- \
      psql -U codewire -d codewire -Atc \
      "SELECT e.state || ':' || b.pod_name
       FROM environments e
       JOIN sandbox_environment_backend b ON b.environment_id = e.id
       WHERE e.id = '${environment_id}';"
  )"
  if [ "$fixture" != "running:${daemon_pod}" ]; then
    echo "::error::retained environment-session fixture is ${fixture:-missing}; want running:${daemon_pod}"
    return 1
  fi

  (
    cd "$ROOT"
    cargo build --profile ci -p codewire-client --example environment-session-smoke
  )
  environment_session_protocol_smoke "$environment_id"
  log "retained environment-session suite green"
}
