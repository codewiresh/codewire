#!/usr/bin/env bash
# Ordinary UID1000 CW bootstrap/update/rollback on one retained production-
# created environment. The original support-image daemon stays separate from
# the two admitted release producers. The explicit cw-managed-agents suite
# adds stock managed workers to this same retained-Pod journey.
set -euo pipefail

if [ "${KIND_E2E_COMMON_LOADED:-0}" != 1 ]; then
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/common.sh"
fi

run_retained_cw_runtime_suite() {
  require_kind_errexit
  require_tool python3
  # An explicit named profile owns the cluster, private kubeconfig, immutable
  # smoke artifacts and inherited operation lock used throughout this suite.
  if [ "${KIND_PROFILE:-0}" != 1 ] || [ -z "${CLUSTER:-}" ]; then
    echo '::error::cw-runtime requires an existing named Kind profile' >&2
    return 2
  fi
  case "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" in
    build-ci | prebuilt-ci) ;;
    *)
      echo '::error::cw-runtime requires the synthetic CI support-image contract' >&2
      return 2
      ;;
  esac
  # Full current-source/original-eight-export admission happens in the fixed
  # helper before it dispatches any cluster/API command. No asset is produced
  # here, and no caller-selected command or executable is accepted.
  python3 -B "$ROOT/scripts/ci/verify/kind/cw_runtime_assets.py" \
    --source-sha "${CW_RUNTIME_SOURCE_SHA:-}" \
    --a-build-json "${CW_RUNTIME_A_BUILD_JSON:-}" \
    --a-build-sha256 "${CW_RUNTIME_A_BUILD_SHA256:-}" \
    --a-sha256 "${CW_RUNTIME_A_SHA256:-}" \
    --b-build-json "${CW_RUNTIME_B_BUILD_JSON:-}" \
    --b-build-sha256 "${CW_RUNTIME_B_BUILD_SHA256:-}" \
    --b-sha256 "${CW_RUNTIME_B_SHA256:-}" \
    --support-build-json "${CW_RUNTIME_SUPPORT_BUILD_JSON:-}" \
    --support-build-sha256 "${CW_RUNTIME_SUPPORT_BUILD_SHA256:-}"
}

run_retained_cw_managed_agents_suite() {
  # A retained cluster without a named profile (`make kind-test`) has no
  # admitted release producers: it runs the managed journey alone, against
  # the daemon image the cluster deploys. A named profile keeps the full
  # admitted CW A/B/A journey with managed workers.
  if [ "${KIND_PROFILE:-0}" != 1 ] || [ -z "${CLUSTER:-}" ]; then
    run_retained_managed_agents_journey
    return $?
  fi
  CW_RUNTIME_MANAGED_AGENTS=1 run_retained_cw_runtime_suite
}

cw_runtime_require_synthetic_provider() {
  local deployment_projection pod_projection names pod
  deployment_projection='{.spec.template.spec.containers[?(@.name=="credential-service")].command}{.spec.template.spec.containers[?(@.name=="credential-service")].env[?(@.name=="CODEWIRE_KIND_CREDENTIAL_FIXTURE")].value}'
  pod_projection='{.spec.containers[?(@.name=="credential-service")].command}{.spec.containers[?(@.name=="credential-service")].env[?(@.name=="CODEWIRE_KIND_CREDENTIAL_FIXTURE")].value}'
  kubectl --request-timeout=10s -n "$NS" get deployment/codewire-credential-service \
    -o "jsonpath-as-json=$deployment_projection" | jq -es \
    'length == 2 and .[0] == [["/codewire-kind-fixtures/credential-service"]] and .[1] == ["1"]' >/dev/null
  names="$(kubectl --request-timeout=10s -n "$NS" get pods \
    -l app.kubernetes.io/name=codewire,app.kubernetes.io/component=credential-service \
    -o 'jsonpath-as-json={.items[*].metadata.name}' | jq -er '
      if type == "array" and length >= 1 and length <= 8
        and all(.[]; type == "string" and length <= 253 and test("^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$"))
      then .[] else error("expected bounded synthetic credential Pods") end')"
  while IFS= read -r pod; do
    kubectl --request-timeout=10s -n "$NS" get "pod/$pod" \
      -o "jsonpath-as-json=$pod_projection" | jq -es \
      'length == 2 and .[0] == [["/codewire-kind-fixtures/credential-service"]] and .[1] == ["1"]' >/dev/null
  done <<<"$names"
}

cw_runtime_pod_identity() {
  local identity claims claim pvcs='[]' pvc
  # Only public identity/runtime metadata is projected, never container Env,
  # projected capabilities, Secrets or provider material.
  identity="$(kubectl --request-timeout=10s -n "$SANDBOX_NS" get "pod/$1" \
    -o 'jsonpath-as-json={.metadata.name}{.metadata.namespace}{.metadata.uid}{.metadata.deletionTimestamp}{.spec.containers[?(@.name=="workspace")].image}{.status.containerStatuses[?(@.name=="workspace")].containerID}{.status.containerStatuses[?(@.name=="workspace")].imageID}{.status.containerStatuses[?(@.name=="workspace")].restartCount}{.status.containerStatuses[?(@.name=="workspace")].ready}{.spec.volumes[*].persistentVolumeClaim.claimName}' |
    jq -ces --arg name "$1" --arg namespace "$SANDBOX_NS" '
      if length == 10 and .[0] == [$name] and .[1] == [$namespace]
        and (.[2] | length == 1 and (.[0] | type == "string" and length > 0 and length <= 128))
        and .[3] == []
        and all(.[4:7][]; length == 1 and (.[0] | type == "string" and length > 0 and length <= 512))
        and (.[7] | length == 1 and (.[0] | type == "number" and . >= 0 and . == floor))
        and .[8] == [true]
        and (.[9] | type == "array" and length <= 4 and (unique | length) == length
          and all(.[]; type == "string" and length > 0 and length <= 253
            and test("^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")))
      then {name: .[0][0], namespace: .[1][0], uid: .[2][0], image: .[4][0],
        container_id: .[5][0], image_id: .[6][0], restart_count: .[7][0], claims: (.[9] | sort)}
      else error("original ready workspace Pod identity refused") end')"
  claims="$(jq -r '.claims[]' <<<"$identity")"
  while IFS= read -r claim; do
    [ -n "$claim" ] || continue
    pvc="$(kubectl --request-timeout=10s -n "$SANDBOX_NS" get "pvc/$claim" \
      -o 'jsonpath-as-json={.metadata.name}{.metadata.namespace}{.metadata.uid}{.metadata.deletionTimestamp}{.spec.volumeName}{.status.phase}' |
      jq -ces --arg claim "$claim" --arg namespace "$SANDBOX_NS" '
        if length == 6 and .[0] == [$claim] and .[1] == [$namespace]
          and (.[2] | length == 1 and (.[0] | type == "string" and length > 0 and length <= 128))
          and .[3] == [] and (.[4] | length == 1 and (.[0] | type == "string" and length > 0 and length <= 253))
          and .[5] == ["Bound"]
        then {claim: .[0][0], namespace: .[1][0], uid: .[2][0], volume: .[4][0]}
        else error("original workspace PVC identity refused") end')"
    pvcs="$(jq -cn --argjson old "$pvcs" --argjson pvc "$pvc" '$old + [$pvc]')"
  done <<<"$claims"
  jq -cn --argjson pod "$identity" --argjson pvcs "$pvcs" '$pod | del(.claims) | .workspace_pvcs = $pvcs'
}

# Stop/Start replaces the Pod (#2651, #2639). The managed-agent records the
# journey left stay in the session store and still list, an ordinary command
# runs, and the new Pod, with its own request book, launches a managed agent
# and stops it. Before #2651 every managed-agent request after a Start was
# refused, and the CLI reported it as an unknown outcome.
cw_runtime_managed_after_restart() {
  local environment="$1" before_pod="$2" before_uid after_uid pod launched session listed
  local state attempt output
  before_uid="$(kubectl -n "$SANDBOX_NS" get pod "$before_pod" -o 'jsonpath={.metadata.uid}')"
  kind_credential_cli --cloud stop "$environment" --output json >/dev/null
  wait_kind_credential_environment "$environment" stopped
  kind_credential_cli --cloud start "$environment" --output json >/dev/null
  wait_kind_credential_environment "$environment" running
  pod="$(kind_credential_workspace "$environment")"
  after_uid="$(kubectl -n "$SANDBOX_NS" get pod "$pod" -o 'jsonpath={.metadata.uid}')"
  [ -n "$after_uid" ] && [ "$after_uid" != "$before_uid" ] || {
    echo '::error::Stop/Start did not replace the workspace Pod' >&2
    return 1
  }
  listed="$(kind_credential_cli list "$environment" --output json)"
  jq -e 'any(.[]; .command[1] == "__platform-agent-driver")' <<<"$listed" >/dev/null || {
    echo '::error::the managed-agent records from the first Pod did not list after Stop/Start' >&2
    return 1
  }
  # A top-level conversation from the first Pod continues in this one
  # (#2705): a new message resumes it from its saved native session, at the
  # next generation, and is delivered to its driver here. Nothing from the
  # first Pod is replayed.
  local earlier generation sent message resumed waited
  # `cw ls` shows a top-level conversation's parent as "".
  earlier="$(jq -er '[.[] | select(.command[1] == "__platform-agent-driver"
    and (.parent_session_id // "") == "")][0]' <<<"$listed")" || {
    echo '::error::no top-level managed conversation from the first Pod listed after Stop/Start' >&2
    return 1
  }
  generation="$(jq -er '.launch_generation' <<<"$earlier")"
  sent="$(kind_credential_cli msg "$environment" --session "$(jq -er .session_id <<<"$earlier")" \
    'Return the synthetic reply after Stop/Start.' --output json)" || {
    echo '::error::a message to a conversation from the first Pod did not resume it' >&2
    return 1
  }
  message="$(jq -er '(.messageId // .message_id)' <<<"$sent")"
  # The journey may have revoked this agent's provider: an answered turn or
  # the provider's own refusal both prove the resumed driver took the message.
  waited="$(kind_credential_cli wait --message "$message" --timeout 5m --output json || true)"
  jq -e '.state == "completed" or .state == "error"' <<<"$waited" >/dev/null || {
    echo '::error::the message to the resumed conversation did not reach its driver' >&2
    return 1
  }
  resumed="$(kind_credential_cli list "$environment" --output json | jq -er \
    --arg id "$(jq -er .session_id <<<"$earlier")" '[.[] | select(.session_id == $id)][0].launch_generation')"
  [ "$resumed" = "$((generation + 1))" ] || {
    echo "::error::the resumed conversation is at generation ${resumed}, not $((generation + 1))" >&2
    return 1
  }
  kind_credential_cli stop "$environment" --session "$(jq -er .session_id <<<"$earlier")" \
    --output json >/dev/null
  launched="$(kind_credential_launch "$environment" --no-tty --detach --output json -- \
    sh -c 'printf cw-runtime-after-restart')"
  session="$(jq -er '.session_id | select(type == "string" and test("^session-[0-9a-f-]{36}$"))' \
    <<<"$launched")"
  for ((attempt = 0; attempt < 30; attempt++)); do
    state="$(kind_credential_cli list "$environment" --output json | jq -er --arg id "$session" '
      [.[] | select(.session_id == $id)] |
      if length == 1 then .[0] | "\(.state) \(.exit_code // "none")"
      else error("expected one launched session") end')"
    case "$state" in
      "Starting "* | "Running "*) sleep 1 ;;
      *) break ;;
    esac
  done
  output="$(kind_credential_cli logs "$environment" --session "$session" --raw)"
  [ "$state" = "Exited 0" ] && [ "$output" = cw-runtime-after-restart ] || {
    echo "::error::an ordinary command after Stop/Start ended ${state:-unknown}" >&2
    return 1
  }
  launched="$(kind_credential_cli run --in "$environment" --agent codex --output json)"
  session="$(jq -er '(.sessionId // .session_id)
    | select(type == "string" and test("^session-[0-9a-f-]{36}$"))' <<<"$launched")"
  kind_credential_cli stop "$environment" --session "$session" --output json >/dev/null
  log "the restarted Pod launched and stopped managed agent ${session}"
}

# Fixed public canaries go only to write-only platform enrollment. No provider
# token, keyring, auth file or value-read route enters the guest.
cw_runtime_add_managed_credentials() {
  local credential_name="$1" anthropic_name="$2" profile_name="$3"
  printf '%s\n' cwlocalopenai0123456789abcdef0123456789abcdef |
    kind_credential_cli credentials --cloud add openai --name "$credential_name"
  printf '%s\n' cwlocalanthropic0123456789abcdef0123456789abcdef |
    kind_credential_cli credentials --cloud add anthropic --name "$anthropic_name"
  kind_credential_cli credentials --cloud get "$anthropic_name" --output json | jq -e \
    --arg name "$anthropic_name" 'length == 1 and .[0].name == $name
      and .[0].provider == "anthropic" and .[0].status == "CREDENTIAL_STATUS_ACTIVE"
      and .[0].authenticationKind == "CREDENTIAL_AUTHENTICATION_KIND_API_KEY"' >/dev/null
  kind_credential_cli credentials --cloud --profile "$profile_name" set openai "$credential_name"
  kind_credential_cli credentials --cloud --profile "$profile_name" set anthropic "$anthropic_name"
}

# The product's pinned workspace image, which `make kind-runtime-images` loads
# into every node by digest. A managed agent runs only on an image whose agent
# clients match the daemon's pins. The retained cluster's recorded
# source-built workspace image can be older than main's daemon; managed info
# then refuses it (#2694), so the journey runs on the pinned image instead.
retained_managed_workspace_image() {
  local reference node images
  reference="$(sed -n 's/^pub const PUBLIC_IMAGE: &str = "\(.*\)";$/\1/p' \
    "$ROOT/crates/codewire-workspace-image/src/pin.rs")"
  if ! [[ "$reference" =~ ^ghcr\.io/codewiresh/workspace@sha256:[0-9a-f]{64}$ ]]; then
    echo '::error::crates/codewire-workspace-image/src/pin.rs names no pinned workspace image' >&2
    return 1
  fi
  for node in $(kind get nodes --name "$KIND_CLUSTER_NAME"); do
    # Read the whole listing first: grep -q stopping at the pin would end the
    # listing with SIGPIPE, which pipefail reports as a missing image.
    if ! images="$(docker exec "$node" ctr -n k8s.io images ls -q)" ||
      ! grep -qxF "$reference" <<<"$images"; then
      echo "::error::${node} lacks the pinned workspace image ${reference}; run make kind-runtime-images" >&2
      return 1
    fi
  done
  printf '%s\n' "$reference"
}

# The credential-service replica count the denied-Resume step scaled to
# zero, and the suite's EXIT trap it runs after restoring it. Empty while
# nothing is to restore.
CW_RUNTIME_CREDENTIAL_SERVICE_REPLICAS=""
CW_RUNTIME_OUTAGE_PREVIOUS_EXIT=""

# Scales the credential service back to the count the step read and waits
# until that many replicas are ready. Running it again is harmless.
cw_runtime_restore_credential_service() {
  local replicas="$CW_RUNTIME_CREDENTIAL_SERVICE_REPLICAS" ready
  [ -n "$replicas" ] || return 0
  kubectl -n "$NS" scale deployment/codewire-credential-service --replicas="$replicas" >/dev/null \
    || return 1
  kubectl -n "$NS" rollout status deployment/codewire-credential-service --timeout=180s >/dev/null \
    || return 1
  ready="$(kubectl -n "$NS" get deployment/codewire-credential-service \
    -o 'jsonpath={.status.readyReplicas}')" || return 1
  [ "${ready:-0}" = "$replicas" ] || {
    echo "::error::the credential service has ${ready:-0} of ${replicas} replicas ready" >&2
    return 1
  }
  CW_RUNTIME_CREDENTIAL_SERVICE_REPLICAS=""
}

# The EXIT trap while the credential service is scaled down: restore it,
# then run the suite's own EXIT trap with the original status.
cw_runtime_credential_outage_exit() {
  local status=$?
  cw_runtime_restore_credential_service \
    || echo '::error::the credential service was not restored to its replica count' >&2
  if [ -n "$CW_RUNTIME_OUTAGE_PREVIOUS_EXIT" ]; then
    (exit "$status")
    eval "$CW_RUNTIME_OUTAGE_PREVIOUS_EXIT"
  fi
}

# Fails the step during the outage: says why, then restores the credential
# service, so it is back before the step returns.
cw_runtime_outage_failed() {
  echo "::error::$1" >&2
  cw_runtime_restore_credential_service
  return 1
}

# Every platform-managed request this environment's journal holds, oldest
# first: action, phase and the target's receipt reason.
cw_runtime_agent_requests() {
  kubectl -n "$NS" exec -i deploy/postgres -- psql -U codewire -d codewire \
    -v ON_ERROR_STOP=1 -v environment="$1" -At <<'SQL'
SELECT coalesce(json_agg(json_build_object(
    'action', r.mutation_json->>'action', 'phase', r.phase,
    'reason', r.receipt_json->>'reason_code') ORDER BY r.admitted_at), '[]')
FROM public.environment_platform_agent_requests AS r
WHERE r.environment_id = :'environment';
SQL
}

# A Resume denied before its agent runs (#2769): after Stop/Start, the
# credential service is unavailable, so the launch's environment
# projection is refused. `cw msg` is refused definitely ("nothing ran"),
# never unknown; the journal holds that Resume as Rejected denied-before-run
# and nothing else; and once the service is back, `cw msg` resumes the
# conversation at the next generation. The service's replica count is read,
# and restored, by traps too, before this step returns.
cw_runtime_managed_resume_denied_before_run() {
  local environment="$1" session="$2" generation="$3" previous pods requests count
  local output sent message attempt resumed refused
  kind_credential_cli --cloud stop "$environment" --output json >/dev/null
  wait_kind_credential_environment "$environment" stopped
  kind_credential_cli --cloud start "$environment" --output json >/dev/null
  wait_kind_credential_environment "$environment" running
  wait_kind_credential_setup_complete "$environment"
  refused="$(mktemp)"
  requests="$(cw_runtime_agent_requests "$environment")"
  count="$(jq -er 'length' <<<"$requests")"

  CW_RUNTIME_CREDENTIAL_SERVICE_REPLICAS="$(kubectl -n "$NS" \
    get deployment/codewire-credential-service -o 'jsonpath={.spec.replicas}')"
  [[ "$CW_RUNTIME_CREDENTIAL_SERVICE_REPLICAS" =~ ^[1-9][0-9]*$ ]] || {
    echo "::error::the credential service runs ${CW_RUNTIME_CREDENTIAL_SERVICE_REPLICAS:-no} replicas" >&2
    CW_RUNTIME_CREDENTIAL_SERVICE_REPLICAS=""
    return 1
  }
  previous="$(trap -p EXIT)"
  previous="${previous#trap -- }"
  eval "CW_RUNTIME_OUTAGE_PREVIOUS_EXIT=${previous% EXIT}"
  trap cw_runtime_credential_outage_exit EXIT
  trap 'cw_runtime_restore_credential_service || true; exit 130' INT
  trap 'cw_runtime_restore_credential_service || true; exit 143' TERM
  pods="$(kubectl -n "$NS" get pods \
    -l app.kubernetes.io/name=codewire,app.kubernetes.io/component=credential-service -o name)"
  kubectl -n "$NS" scale deployment/codewire-credential-service --replicas=0 >/dev/null
  if [ -n "$pods" ]; then
    # shellcheck disable=SC2086 # one argument for each captured Pod
    kubectl -n "$NS" wait --for=delete $pods --timeout=120s >/dev/null
  fi

  # Only the refusal on standard error is kept.
  if output="$(kind_credential_cli msg "$environment" --session "$session" \
      'Return the synthetic reply while the credential service is down.' \
      --output json 2>&1 >/dev/null)"; then
    cw_runtime_outage_failed 'a message was delivered while the credential service was down'
    return 1
  fi
  grep -Fq 'nothing ran, so send the message again' <<<"$output" || {
    cw_runtime_outage_failed "the denied Resume was not refused definitely: ${output}"
    return 1
  }
  requests="$(cw_runtime_agent_requests "$environment")"
  jq -e --argjson count "$count" '
    length == $count + 1
    and (.[-1] | .action == "resume" and .phase == "rejected" and .reason == "denied-before-run")' \
    <<<"$requests" >/dev/null || {
    cw_runtime_outage_failed "the journal does not hold exactly one Rejected denied-before-run Resume: $(jq -c ".[${count}:]" <<<"$requests")"
    return 1
  }

  cw_runtime_restore_credential_service
  if [ -n "$CW_RUNTIME_OUTAGE_PREVIOUS_EXIT" ]; then
    trap -- "$CW_RUNTIME_OUTAGE_PREVIOUS_EXIT" EXIT
  else
    trap - EXIT
  fi
  trap - INT TERM
  CW_RUNTIME_OUTAGE_PREVIOUS_EXIT=""

  # The refusal says to send the message again. Each attempt the returning
  # service is not yet ready for is refused the same way, never unknown.
  for ((attempt = 1; ; attempt++)); do
    if sent="$(kind_credential_cli msg "$environment" --session "$session" \
        'Return the synthetic reply after the credential service returned.' \
        --output json 2>"$refused")"; then
      break
    fi
    grep -Fq 'nothing ran, so send the message again' "$refused" && [ "$attempt" -lt 12 ] || {
      echo "::error::the conversation did not resume after the credential service returned: $(cat "$refused")" >&2
      return 1
    }
    sleep 5
  done
  rm -f -- "$refused"
  message="$(jq -er '(.messageId // .message_id)' <<<"$sent")"
  kind_credential_cli wait --message "$message" --timeout 5m --output json | jq -e \
    '.state == "completed" and ((.result // "") | contains("CWOPENAI"))' >/dev/null || {
    echo '::error::the conversation resumed after the denied Resume did not answer' >&2
    return 1
  }
  resumed="$(kind_credential_cli list "$environment" --output json | jq -er --arg id "$session" \
    '[.[] | select(.session_id == $id)][0].launch_generation')"
  [ "$resumed" = "$((generation + 1))" ] || {
    echo "::error::after the denied Resume the conversation is at generation ${resumed}, not $((generation + 1))" >&2
    return 1
  }
}

# The OpenAI API-key attempts the synthetic fixture has served so far.
cw_runtime_openai_attempts() {
  kind_credential_fixture_events | jq -er \
    '[.[] | select(.event == "api_key_attempt" and .family == "openai")] | length'
}

# A conversation continues across Stop/Start (#2705): after the Start, a
# message to the same session resumes it from its saved native session at
# the next generation and gets the synthetic reply, its earlier message
# keeps its state and generation, and the provider sees exactly one more
# turn: nothing from before the Stop is replayed. Then back-to-back messages
# to the resumed conversation, each once the one before it is final, all
# complete; none ends unknown (#2782). It runs in an environment of its own
# on the journey's profile: a resumed conversation is listed in its new
# Pod, where the smoke's session inventory and the later Stop/Start check
# must not find it.
cw_runtime_managed_resume_continues() {
  local profile="$1" workspace_image="$2" environment update operation pod
  local launched session first generation before after listed sent message waited resumed
  local back_to_back=20 round
  environment="$(kind_credential_cli --cloud create --name "kind-cw-resume-${RANDOM}-${RANDOM}" \
    --image "$workspace_image" --cpu 500m --memory 2Gi --disk 2Gi --ttl 1h \
    --no-network --yes --output json | jq -er '.id')"
  [[ "$environment" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]
  log "checking that a managed conversation continues across Stop/Start in environment $environment"
  wait_kind_credential_environment "$environment" running
  # A source change is refused until setup finishes.
  wait_kind_credential_setup_complete "$environment"
  update="$(kind_credential_cli --cloud update "$environment" \
    --profile "platform:$profile" --yes --output json)"
  operation="$(jq -er '.operation_generation |
    if type == "number" and . > 0 and . == floor then .
    else error("expected the acknowledged positive setup generation") end' <<<"$update")"
  wait_kind_credential_environment "$environment" running
  wait_kind_credential_restarted_workspace "$environment" "$operation" >/dev/null
  wait_kind_credential_setup_complete "$environment"
  launched="$(kind_credential_cli run --in "$environment" --name resume-check --agent codex \
    --detach --output json --prompt 'Return the synthetic reply before Stop/Start.')"
  session="$(jq -er '(.sessionId // .session_id)
    | select(type == "string" and test("^session-[0-9a-f-]{36}$"))' <<<"$launched")"
  first="$(jq -er '(.messageId // .message_id)' <<<"$launched")"
  waited="$(kind_credential_cli wait --message "$first" --timeout 5m --output json)"
  jq -e '.state == "completed" and ((.result // "") | contains("CWOPENAI"))' <<<"$waited" \
    >/dev/null || {
    echo '::error::the conversation did not answer before Stop/Start' >&2
    return 1
  }
  listed="$(kind_credential_cli list "$environment" --output json)"
  generation="$(jq -er --arg id "$session" \
    '[.[] | select(.session_id == $id)][0].launch_generation' <<<"$listed")"
  before="$(cw_runtime_openai_attempts)"
  kind_credential_cli --cloud stop "$environment" --output json >/dev/null
  wait_kind_credential_environment "$environment" stopped
  kind_credential_cli --cloud start "$environment" --output json >/dev/null
  wait_kind_credential_environment "$environment" running
  # Start reads running before its setup finishes, and a message is refused
  # until then ("environment runtime or setup is not ready").
  wait_kind_credential_setup_complete "$environment"
  sent="$(kind_credential_cli msg "$environment" --session "$session" \
    'Return the synthetic reply after Stop/Start.' --output json)" || {
    echo '::error::a message after Stop/Start did not resume the conversation and complete' >&2
    return 1
  }
  message="$(jq -er '(.messageId // .message_id)' <<<"$sent")"
  waited="$(kind_credential_cli wait --message "$message" --timeout 5m --output json)"
  jq -e '.state == "completed" and ((.result // "") | contains("CWOPENAI"))' <<<"$waited" \
    >/dev/null || {
    echo '::error::the resumed conversation did not answer' >&2
    return 1
  }
  resumed="$(kind_credential_cli list "$environment" --output json | jq -er --arg id "$session" \
    '[.[] | select(.session_id == $id)][0].launch_generation')"
  [ "$resumed" = "$((generation + 1))" ] || {
    echo "::error::the resumed conversation is at generation ${resumed}, not $((generation + 1))" >&2
    return 1
  }
  # The message from before the Stop is untouched, not run again.
  kind_credential_cli wait --message "$first" --timeout 30s --output json | jq -e \
    --argjson generation "$generation" \
    '.state == "completed" and ((.platform_launch_generation // $generation) == $generation)' \
    >/dev/null || {
    echo '::error::the message from before Stop/Start changed' >&2
    return 1
  }
  after="$(cw_runtime_openai_attempts)"
  [ "$after" = "$((before + 1))" ] || {
    echo "::error::the provider saw $((after - before)) calls for one resumed turn" >&2
    return 1
  }
  # `cw msg` fails unless its request completed, so an unknown one stops here.
  for ((round = 1; round <= back_to_back; round++)); do
    sent="$(kind_credential_cli msg "$environment" --session "$session" \
      "Return the synthetic reply, message ${round} of ${back_to_back} after Resume." \
      --output json)" || {
      echo "::error::back-to-back message ${round} of ${back_to_back} after Resume did not complete" >&2
      return 1
    }
    message="$(jq -er '(.messageId // .message_id)' <<<"$sent")"
    kind_credential_cli wait --message "$message" --timeout 2m --output json | jq -e \
      '.state == "completed" and ((.result // "") | contains("CWOPENAI"))' >/dev/null || {
      echo "::error::back-to-back message ${round} of ${back_to_back} after Resume did not answer" >&2
      return 1
    }
  done
  after="$(cw_runtime_openai_attempts)"
  [ "$after" = "$((before + 1 + back_to_back))" ] || {
    echo "::error::the provider saw $((after - before - 1)) calls for ${back_to_back} back-to-back turns" >&2
    return 1
  }
  log "checking that a Resume denied before its agent runs is refused and can resume again"
  cw_runtime_managed_resume_denied_before_run "$environment" "$session" "$resumed"
  kind_credential_cli stop "$environment" --session "$session" --output json >/dev/null
  pod="$(kind_credential_workspace "$environment")"
  kind_credential_cli --cloud rm "$environment" --yes --output json >/dev/null
  wait_kind_credential_environment "$environment" destroyed
  kubectl -n "$SANDBOX_NS" wait --for=delete --timeout=120s "pod/$pod"
}

# The managed-agent journey alone on a retained cluster without a named
# profile (#2672): the same synthetic providers, profile and no-network
# environment as the admitted journey, then the smoke in managed-only mode
# against the deployed daemon image, with twenty back-to-back MESSAGEs to one
# conversation, none of which may end unknown (#2782), then Stop/Start
# (#2657). Failure keeps the environment and its credentials for diagnosis,
# like the admitted path.
run_retained_managed_agents_journey() {
  local KIND_CREDENTIAL_CLI_HOME credential_name anthropic_name profile_name environment
  local workspace_image update generation pod cli_sha256
  require_kind_errexit
  require_tool jq
  require_tool kind
  require_tool kubectl
  umask 077
  trap retained_suite_cleanup EXIT
  validate_retained_cluster
  cw_runtime_require_synthetic_provider
  build_retained_kind_smokes cw-managed-agents
  if [ ! -x "$CARGO_CI_DIR/examples/environment-cw-runtime-smoke" ]; then
    echo '::error::the Kind smoke set lacks environment-cw-runtime-smoke; rebuild it before this suite' >&2
    return 1
  fi
  workspace_image="$(retained_managed_workspace_image)"
  KIND_CREDENTIAL_CLI_HOME="$(mktemp -d /dev/shm/codewire-kind-cw-managed.XXXXXX)"
  [ "$(stat -f -c %T "$KIND_CREDENTIAL_CLI_HOME")" = tmpfs ]
  [ "$(stat -c '%u:%a' "$KIND_CREDENTIAL_CLI_HOME")" = "$(id -u):700" ]
  prepare_kind_credential_cli
  credential_name="kind-cw-openai-${RANDOM}-${RANDOM}"
  anthropic_name="kind-cw-anthropic-${RANDOM}-${RANDOM}"
  profile_name="kind-cw-profile-${RANDOM}-${RANDOM}"
  kind_credential_cli org set org_contract_1
  cw_runtime_add_managed_credentials "$credential_name" "$anthropic_name" "$profile_name"
  # First, while the synthetic providers the smoke later revokes are valid,
  # a conversation continues across Stop/Start in its own environment (#2705).
  cw_runtime_managed_resume_continues "$profile_name" "$workspace_image"
  environment="$(kind_credential_cli --cloud create --name "$profile_name" \
    --image "$workspace_image" --cpu 500m --memory 2Gi --disk 2Gi --ttl 1h \
    --no-network --yes --output json | jq -er '.id')"
  [[ "$environment" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]
  wait_kind_credential_environment "$environment" running
  # As in the admitted journey: nothing is projected before the profile is
  # bound, and the probe's session waits for environment setup to finish,
  # which a source change requires.
  kind_credential_probe "$environment" unselected
  update="$(kind_credential_cli --cloud update "$environment" \
    --profile "platform:$profile_name" --yes --output json)"
  generation="$(jq -er '.operation_generation |
    if type == "number" and . > 0 and . == floor then .
    else error("expected the acknowledged positive setup generation") end' <<<"$update")"
  wait_kind_credential_environment "$environment" running
  pod="$(wait_kind_credential_restarted_workspace "$environment" "$generation")"
  cli_sha256="$(sha256sum "$CARGO_CI_DIR/cw" | cut -d ' ' -f1)"
  log "starting the managed-agent journey for environment $environment on the deployed daemon image"
  env -i PATH=/usr/bin:/bin HOME="$KIND_CREDENTIAL_CLI_HOME" \
    SMOKE_CW_RUNTIME_BASE_URL="$KIND_INGRESS_URL" \
    SMOKE_ORG_ID=org_contract_1 SMOKE_ENVIRONMENT_ID="$environment" \
    SMOKE_ACCESS_TOKEN=at_kind_connect_oidc_codewire_api \
    SMOKE_CW_CLI_PATH="$CARGO_CI_DIR/cw" SMOKE_CW_CLI_SHA256="$cli_sha256" \
    SMOKE_CW_CLI_HOME="$KIND_CREDENTIAL_CLI_HOME" \
    SMOKE_CW_MANAGED_AGENTS=only SMOKE_CW_MANAGED_BACK_TO_BACK=20 \
    "SMOKE_CW_MANAGED_OPENAI_CREDENTIAL=$credential_name" \
    "SMOKE_CW_MANAGED_ANTHROPIC_CREDENTIAL=$anthropic_name" \
    "$CARGO_CI_DIR/examples/environment-cw-runtime-smoke"
  kind_credential_fixture_events | jq -e '
    any(.[]; .event == "api_key_attempt" and .family == "openai" and .api_attempt > 0)
    and any(.[]; .event == "api_key_attempt" and .family == "anthropic" and .api_attempt > 0)' >/dev/null
  cw_runtime_managed_after_restart "$environment" "$pod"
  pod="$(kind_credential_workspace "$environment")"
  kind_credential_cli --cloud rm "$environment" --yes --output json
  wait_kind_credential_environment "$environment" destroyed
  kubectl -n "$SANDBOX_NS" wait --for=delete --timeout=120s "pod/$pod"
  kind_credential_cli credentials --cloud --profile "$profile_name" delete --yes
  # A stored platform credential is revoked before its record is deleted.
  local name
  for name in "$credential_name" "$anthropic_name"; do
    kind_credential_cli credentials --cloud revoke "$name" --output json >/dev/null
    kind_credential_cli credentials --cloud delete "$name" --yes
  done
  rm -rf -- "$KIND_CREDENTIAL_CLI_HOME"
  log "retained managed-agent journey (launch, steer, interrupt, revoked provider, Stop, Restart, Stop/Start) green"
}

run_admitted_cw_runtime_journey() {
  local task="$1" KIND_CREDENTIAL_CLI_HOME credential_name profile_name environment
  local managed="${CW_RUNTIME_MANAGED_AGENTS:-0}" anthropic_name=''
  local workspace_image update generation pod before after cli_sha256
  require_kind_errexit
  require_tool jq
  require_tool kind
  require_tool kubectl
  [[ "$managed" =~ ^[01]$ ]] || {
    echo '::error::managed CW journey selection must be exactly0 or1' >&2
    return 2
  }
  umask 077
  trap retained_suite_cleanup EXIT
  validate_retained_cluster
  cw_runtime_require_synthetic_provider
  build_retained_kind_smokes cw-runtime
  if [ ! -x "$CARGO_CI_DIR/examples/environment-cw-runtime-smoke" ]; then
    echo '::error::the immutable Kind smoke set lacks environment-cw-runtime-smoke; rebuild that set before this suite' >&2
    return 1
  fi
  workspace_image="$(kind_workspace_runtime_image)"
  # Synthetic login/config is tmpfs-only. Failure keeps it and the exact task
  # for diagnosis; no failed or unknown update is retried or auto-destroyed.
  KIND_CREDENTIAL_CLI_HOME="$(mktemp -d /dev/shm/codewire-kind-cw-runtime.XXXXXX)"
  [ "$(stat -f -c %T "$KIND_CREDENTIAL_CLI_HOME")" = tmpfs ]
  [ "$(stat -c '%u:%a' "$KIND_CREDENTIAL_CLI_HOME")" = "$(id -u):700" ]
  printf '%s\n' "$KIND_CREDENTIAL_CLI_HOME" >"$task/cli-home-path"
  prepare_kind_credential_cli
  if [ "$managed" = 1 ]; then
    credential_name="kind-cw-openai-${RANDOM}-${RANDOM}"
    anthropic_name="kind-cw-anthropic-${RANDOM}-${RANDOM}"
  else
    credential_name="kind-cw-codex-${RANDOM}-${RANDOM}"
  fi
  profile_name="kind-cw-profile-${RANDOM}-${RANDOM}"
  jq -cn --arg credential "$credential_name" --arg profile "$profile_name" \
    '{credential_name: $credential, profile_name: $profile}' >"$task/setup-names.json"
  kind_credential_cli org list --output json | jq -e '
    map({id, role}) | sort_by(.id) == [
      {id: "org_contract_1", role: "member"}, {id: "org_contract_2", role: "owner"}]' >/dev/null
  kind_credential_cli org set org_contract_1
  kind_credential_cli org current | awk '
    $1 == "ID:" { id = $2; count++ }
    END { exit !(count == 1 && id == "org_contract_1") }'
  if [ "$managed" = 1 ]; then
    cw_runtime_add_managed_credentials "$credential_name" "$anthropic_name" "$profile_name"
  else
    kind_credential_cli credentials --cloud connect codex --name "$credential_name"
    kind_credential_cli credentials --cloud --profile "$profile_name" set codex "$credential_name"
  fi
  kind_credential_cli credentials --cloud get "$credential_name" --output json | jq -e \
    --arg name "$credential_name" 'length == 1 and .[0].name == $name
      and .[0].provider == "openai" and .[0].status == "CREDENTIAL_STATUS_ACTIVE"' >/dev/null
  if [ "$managed" = 1 ]; then
    kind_credential_cli credentials --cloud get "$credential_name" --output json | jq -e \
      'length == 1 and .[0].authenticationKind == "CREDENTIAL_AUTHENTICATION_KIND_API_KEY"' >/dev/null
  fi
  environment="$(kind_credential_cli --cloud create --name "$profile_name" \
    --image "$workspace_image" --cpu 500m --memory 2Gi --disk 2Gi --ttl 1h \
    --no-network --yes --output json | jq -er '.id')"
  [[ "$environment" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]
  [ "$environment" != 00000000-0000-0000-0000-000000000000 ]
  printf '%s\n' "$environment" >"$task/environment-id"
  wait_kind_credential_environment "$environment" running
  # Nothing is projected before the profile is bound.
  kind_credential_probe "$environment" unselected
  # Profile setup may replace the initial sandbox before the baseline exists.
  # It is completed once; the same-Pod CW journey follows on that Pod, and
  # the managed journey then Stops and Starts the environment.
  update="$(kind_credential_cli --cloud update "$environment" \
    --profile "platform:$profile_name" --yes --output json)"
  generation="$(jq -er '.operation_generation |
    if type == "number" and . > 0 and . == floor then .
    else error("expected the acknowledged positive setup generation") end' <<<"$update")"
  wait_kind_credential_environment "$environment" running
  pod="$(wait_kind_credential_restarted_workspace "$environment" "$generation")"
  if [ "$managed" = 0 ]; then
    kind_credential_probe "$environment" selected
    kind_credential_daemon_probe "$environment" success
  fi
  before="$(cw_runtime_pod_identity "$pod")"
  printf '%s\n' "$before" >"$task/pod-before.json"
  cli_sha256="$(sha256sum "$CARGO_CI_DIR/cw" | cut -d ' ' -f1)"
  log "starting one public same-Pod ordinary CW runtime journey for environment $environment"
  local managed_projection=()
  if [ "$managed" = 1 ]; then
    # Twenty MESSAGEs to one conversation, each sent once the one before it
    # is final; none may end unknown (#2782).
    managed_projection=(SMOKE_CW_MANAGED_AGENTS=1 SMOKE_CW_MANAGED_BACK_TO_BACK=20
      "SMOKE_CW_MANAGED_OPENAI_CREDENTIAL=$credential_name"
      "SMOKE_CW_MANAGED_ANTHROPIC_CREDENTIAL=$anthropic_name")
  fi
  env -i PATH=/usr/bin:/bin HOME="$KIND_CREDENTIAL_CLI_HOME" \
    SMOKE_CW_RUNTIME_BASE_URL="$KIND_INGRESS_URL" \
    SMOKE_ORG_ID=org_contract_1 SMOKE_ENVIRONMENT_ID="$environment" \
    SMOKE_ACCESS_TOKEN=at_kind_connect_oidc_codewire_api \
    SMOKE_CW_CLI_PATH="$CARGO_CI_DIR/cw" SMOKE_CW_CLI_SHA256="$cli_sha256" \
    SMOKE_CW_CLI_HOME="$KIND_CREDENTIAL_CLI_HOME" \
    SMOKE_CW_RELEASE_A="$SMOKE_CW_RELEASE_A" SMOKE_CW_RELEASE_B="$SMOKE_CW_RELEASE_B" \
    SMOKE_CW_SHA256_A="$SMOKE_CW_SHA256_A" SMOKE_CW_SHA256_B="$SMOKE_CW_SHA256_B" \
    SMOKE_CW_INPUT_WITNESS_FILE="$SMOKE_CW_INPUT_WITNESS_FILE" \
    SMOKE_CW_INPUT_WITNESS_SHA256="$SMOKE_CW_INPUT_WITNESS_SHA256" \
    "${managed_projection[@]}" \
    "$CARGO_CI_DIR/examples/environment-cw-runtime-smoke"
  after="$(cw_runtime_pod_identity "$pod")"
  printf '%s\n' "$after" >"$task/pod-after.json"
  [ "$before" = "$after" ] || {
    echo '::error::ordinary CW update changed the original Pod/container identity' >&2
    return 1
  }
  if [ "$managed" = 0 ]; then
    # Brokerage still answers on the same Pod after the CW update.
    kind_credential_probe "$environment" selected
    kind_credential_daemon_probe "$environment" success
  else
    kind_credential_fixture_events | jq -e '
      any(.[]; .event == "api_key_attempt" and .family == "openai" and .api_attempt > 0)
      and any(.[]; .event == "api_key_attempt" and .family == "anthropic" and .api_attempt > 0)' >/dev/null
    cw_runtime_managed_after_restart "$environment" "$pod"
    pod="$(kind_credential_workspace "$environment")"
  fi
  # Public cleanup runs only after the complete journey, including Observe,
  # stale-incarnation refusal and permanent Attach closure, has succeeded.
  kind_credential_cli --cloud rm "$environment" --yes --output json
  wait_kind_credential_environment "$environment" destroyed
  kubectl -n "$SANDBOX_NS" wait --for=delete --timeout=120s "pod/$pod"
  kind_credential_cli credentials --cloud --profile "$profile_name" delete --yes
  # A stored platform credential is revoked before its record is deleted.
  kind_credential_cli credentials --cloud revoke "$credential_name" --output json >/dev/null
  kind_credential_cli credentials --cloud delete "$credential_name" --yes
  if [ "$managed" = 1 ]; then
    kind_credential_cli credentials --cloud revoke "$anthropic_name" --output json >/dev/null
    kind_credential_cli credentials --cloud delete "$anthropic_name" --yes
  fi
  rm -rf -- "$KIND_CREDENTIAL_CLI_HOME"
  log "retained cw-runtime public create, original Attach/daemon/Pod, UID1000 A/B/A, CAS/Observe/refusal and cleanup green"
}
