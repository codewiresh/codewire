#!/usr/bin/env bash
# Retained credential journey: certificate bootstrap, the public
# enroll/profile/native Codex acceptance and stock Claude Code with an Anthropic
# API key and a Claude subscription token. The acceptance asserts the synthetic
# fixture's exact provider events since its pod started, so this suite needs
# fake credential mode and restarts the credential-service first. It also
# gives orchestration the overlay's Codex login check period when a retained
# cluster's configuration predates it, restarting orchestration once. Its length
# is set by a real projected-token rotation (kubelet replaces the token about
# eight minutes in) and the 60-second authority windows. Each authority change
# starts only while the serving bridge epoch has three minutes left before its
# natural end; otherwise the journey first waits for the relay's next epoch,
# usually under two and a half minutes.
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

# The Codex login check period the checked-in Kind overlay gives
# orchestration, in whole seconds: what a new cluster renders into
# codewire-config.
kind_overlay_codex_login_check_period() {
  local overlay="$ROOT/tests/e2e/kind/support.yaml" period
  period="$(sed -n 's/^  SANDBOX_CODEX_LOGIN_CHECK_PERIOD_SECONDS: "\(.*\)"$/\1/p' "$overlay")" ||
    return $?
  if ! [[ "$period" =~ ^[1-9][0-9]{1,2}$ ]] || [ "$period" -lt 10 ] || [ "$period" -gt 120 ]; then
    echo "::error::${overlay} must set SANDBOX_CODEX_LOGIN_CHECK_PERIOD_SECONDS once, to 10-120 whole seconds" >&2
    return 1
  fi
  printf '%s\n' "$period"
}

# A retained cluster keeps the codewire-config it was created with: a deploy
# replaces binaries, never settings. Without the overlay's Codex login check
# period its workspace daemons keep the 120-second default and this suite its
# 135-second login windows. Set the overlay's value, as a new cluster renders
# it, and restart orchestration, the one Deployment that reads it, only when
# that changes the setting. Sandboxes created afterwards run with it.
apply_kind_codex_login_check_period() {
  local key=SANDBOX_CODEX_LOGIN_CHECK_PERIOD_SECONDS want have previous
  want="$(kind_overlay_codex_login_check_period)" || return $?
  have="$(kubectl -n "$NS" get configmap codewire-config -o "jsonpath={.data.${key}}")" || return $?
  if [ "$have" = "$want" ]; then
    log "codewire-config already sets the overlay's Codex login check period (${want}s)"
    return 0
  fi
  previous="$(kubectl -n "$NS" get pods \
    -l app.kubernetes.io/name=codewire,app.kubernetes.io/component=orchestration -o name)" || return $?
  kubectl -n "$NS" patch configmap codewire-config --type merge \
    -p "{\"data\":{\"${key}\":\"${want}\"}}" >/dev/null || return $?
  kubectl -n "$NS" rollout restart deployment/codewire-orchestration >/dev/null || return $?
  kubectl -n "$NS" rollout status deployment/codewire-orchestration --timeout=180s >/dev/null ||
    return $?
  # A rollout reports done while the replaced Pod still terminates; the
  # journey needs the one orchestration Pod that read the new setting.
  if [ -n "$previous" ]; then
    # shellcheck disable=SC2086 # one argument for each replaced Pod
    kubectl -n "$NS" wait --for=delete $previous --timeout=120s >/dev/null || return $?
  fi
  log "set the overlay's Codex login check period in codewire-config (${have:-unset} -> ${want}s) and restarted orchestration, which reads it"
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
  apply_kind_codex_login_check_period
  log "restarting the synthetic credential-service for a fresh provider event log"
  restart_credential_service
  kind_credential_native_smoke
  kind_credential_claude_session
  log "retained credentials suite green"
}
