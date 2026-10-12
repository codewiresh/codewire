#!/usr/bin/env bash
# Retained credential journey: certificate bootstrap, the public
# enroll/profile/native Codex acceptance and stock Claude Code with an Anthropic
# API key and a Claude subscription token. The acceptance asserts the synthetic
# fixture's exact provider events since its pod started, so this suite needs
# fake credential mode and restarts the credential-service first. Its length
# is set by a real projected-token rotation (kubelet replaces the token about
# eight minutes in) and the 60-second authority windows. Each authority change
# starts only while the serving bridge epoch is three minutes from its natural
# end; otherwise the journey first waits, up to about 90 seconds, for the
# relay's next epoch.
set -euo pipefail

if [ "${KIND_E2E_COMMON_LOADED:-0}" != "1" ]; then
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/common.sh"
fi

# `rollout status` returns once the new Pod is available, while the replaced
# one is still terminating and can still be chosen for the Service, so the
# first enrollment could reach a closed listener. Wait until the Service's
# endpoints are exactly the new ready Pods.
restart_credential_service() {
  local selector previous endpoints deadline
  # shellcheck disable=SC2016 # a Go template, expanded by kubectl
  selector="$(kubectl -n "$NS" get service/codewire-credential-service \
    -o 'go-template={{range $k, $v := .spec.selector}}{{$k}}={{$v}},{{end}}')"
  selector="${selector%,}"
  [ -n "$selector" ]
  previous="$(kubectl -n "$NS" get pods -l "$selector" -o name | sort)"
  kubectl -n "$NS" rollout restart deployment/codewire-credential-service
  kubectl -n "$NS" rollout status deployment/codewire-credential-service --timeout=180s
  deadline=$((SECONDS + 360))
  while :; do
    # One line per endpoint: its Pod, then whether it is ready.
    endpoints="$(kubectl -n "$NS" get endpointslices \
      -l kubernetes.io/service-name=codewire-credential-service \
      -o go-template='{{range .items}}{{range .endpoints}}pod/{{.targetRef.name}} {{.conditions.ready}}{{"\n"}}{{end}}{{end}}')"
    if [ -n "$endpoints" ] && ! grep -qv ' true$' <<<"$endpoints" \
        && ! comm -12 <(cut -d' ' -f1 <<<"$endpoints" | sort) <(printf '%s\n' "$previous") | grep -q .; then
      log "credential-service endpoints are the new ready Pods: $(cut -d' ' -f1 <<<"$endpoints" | tr '\n' ' ')"
      return 0
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "::error::credential-service endpoints never became only the new ready Pods: ${endpoints:-none}" >&2
      return 1
    fi
    sleep 2
  done
}

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
  restart_credential_service
  kind_credential_native_smoke
  kind_credential_claude_session
  log "retained credentials suite green"
}
