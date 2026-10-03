#!/usr/bin/env bash
# Retained credential journey: certificate bootstrap and the public
# enroll/profile/native Codex acceptance. The acceptance asserts the synthetic
# fixture's exact provider events since its pod started, so this suite needs
# fake credential mode and restarts the credential-service first. 10+ minutes.
set -euo pipefail

if [ "${KIND_E2E_COMMON_LOADED:-0}" != "1" ]; then
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/common.sh"
fi

run_retained_credentials_suite() {
  local command
  require_kind_errexit
  require_tool jq
  require_tool kind
  require_tool kubectl
  require_tool openssl
  require_tool python3

  trap retained_suite_cleanup EXIT
  validate_retained_cluster
  command="$(kubectl -n "$NS" get deployment codewire-credential-service \
    -o 'jsonpath={.spec.template.spec.containers[?(@.name=="credential-service")].command[0]}')"
  if [ "$command" != /codewire-kind-fixtures/credential-service ]; then
    echo "::error::the credentials suite needs the synthetic fixture; run kind-e2e.sh credentials fake first"
    return 1
  fi
  build_retained_kind_smokes
  log "restarting the synthetic credential-service for a fresh provider event log"
  kubectl -n "$NS" rollout restart deployment/codewire-credential-service
  kubectl -n "$NS" rollout status deployment/codewire-credential-service --timeout=180s
  kind_credential_bootstrap_smoke
  kind_credential_native_smoke
  log "retained credentials suite green"
}
