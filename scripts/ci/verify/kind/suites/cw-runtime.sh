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
  kind_credential_cli env --platform stop "$environment" --output json >/dev/null
  wait_kind_credential_environment "$environment" stopped
  kind_credential_cli env --platform start "$environment" --output json >/dev/null
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
  output="$(kind_credential_cli logs "$environment" "$session" --raw)"
  [ "$state" = "Exited 0" ] && [ "$output" = cw-runtime-after-restart ] || {
    echo "::error::an ordinary command after Stop/Start ended ${state:-unknown}" >&2
    return 1
  }
  launched="$(kind_credential_cli run "$environment" --agent codex --output json)"
  session="$(jq -er '(.sessionId // .session_id)
    | select(type == "string" and test("^session-[0-9a-f-]{36}$"))' <<<"$launched")"
  kind_credential_cli stop "$environment" "$session" --output json >/dev/null
  log "the restarted Pod launched and stopped managed agent ${session}"
}

# Fixed public canaries go only to write-only platform enrollment. No provider
# token, keyring, auth file or value-read route enters the guest.
cw_runtime_add_managed_credentials() {
  local credential_name="$1" anthropic_name="$2" profile_name="$3"
  printf '%s\n' cwlocalopenai0123456789abcdef0123456789abcdef |
    kind_credential_cli credentials --platform add openai --name "$credential_name"
  printf '%s\n' cwlocalanthropic0123456789abcdef0123456789abcdef |
    kind_credential_cli credentials --platform add anthropic --name "$anthropic_name"
  kind_credential_cli credentials --platform get "$anthropic_name" --output json | jq -e \
    --arg name "$anthropic_name" 'length == 1 and .[0].name == $name
      and .[0].provider == "anthropic" and .[0].status == "CREDENTIAL_STATUS_ACTIVE"
      and .[0].authenticationKind == "CREDENTIAL_AUTHENTICATION_KIND_API_KEY"' >/dev/null
  kind_credential_cli credentials --platform --profile "$profile_name" set openai "$credential_name"
  kind_credential_cli credentials --platform --profile "$profile_name" set anthropic "$anthropic_name"
}

# The managed-agent journey alone on a retained cluster without a named
# profile (#2672): the same synthetic providers, profile and no-network
# environment as the admitted journey, then the smoke in managed-only mode
# against the deployed daemon image, then Stop/Start (#2657). Failure keeps
# the environment and its credentials for diagnosis, like the admitted path.
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
  build_retained_kind_smokes
  if [ ! -x "$CARGO_CI_DIR/examples/environment-cw-runtime-smoke" ]; then
    echo '::error::the Kind smoke set lacks environment-cw-runtime-smoke; rebuild it before this suite' >&2
    return 1
  fi
  workspace_image="$(kind_workspace_runtime_image)"
  KIND_CREDENTIAL_CLI_HOME="$(mktemp -d /dev/shm/codewire-kind-cw-managed.XXXXXX)"
  [ "$(stat -f -c %T "$KIND_CREDENTIAL_CLI_HOME")" = tmpfs ]
  [ "$(stat -c '%u:%a' "$KIND_CREDENTIAL_CLI_HOME")" = "$(id -u):700" ]
  prepare_kind_credential_cli
  credential_name="kind-cw-openai-${RANDOM}-${RANDOM}"
  anthropic_name="kind-cw-anthropic-${RANDOM}-${RANDOM}"
  profile_name="kind-cw-profile-${RANDOM}-${RANDOM}"
  kind_credential_cli org set org_contract_1
  cw_runtime_add_managed_credentials "$credential_name" "$anthropic_name" "$profile_name"
  environment="$(kind_credential_cli env --platform create --name "$profile_name" \
    --image "$workspace_image" --cpu 500 --memory 2Gi --disk 2Gi --ttl 1h \
    --no-network --yes --output json | jq -er '.id')"
  [[ "$environment" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]
  wait_kind_credential_environment "$environment" running
  update="$(kind_credential_cli env --platform update "$environment" \
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
    SMOKE_CW_MANAGED_AGENTS=only \
    "SMOKE_CW_MANAGED_OPENAI_CREDENTIAL=$credential_name" \
    "SMOKE_CW_MANAGED_ANTHROPIC_CREDENTIAL=$anthropic_name" \
    "$CARGO_CI_DIR/examples/environment-cw-runtime-smoke"
  kind_credential_fixture_events | jq -e '
    any(.[]; .event == "api_key_attempt" and .family == "openai" and .api_attempt > 0)
    and any(.[]; .event == "api_key_attempt" and .family == "anthropic" and .api_attempt > 0)' >/dev/null
  cw_runtime_managed_after_restart "$environment" "$pod"
  pod="$(kind_credential_workspace "$environment")"
  kind_credential_cli env --platform rm "$environment" --yes --output json
  wait_kind_credential_environment "$environment" destroyed
  kubectl -n "$SANDBOX_NS" wait --for=delete --timeout=120s "pod/$pod"
  kind_credential_cli credentials --platform --profile "$profile_name" delete --yes
  # A stored platform credential is revoked before its record is deleted.
  local name
  for name in "$credential_name" "$anthropic_name"; do
    kind_credential_cli credentials --platform revoke "$name" --output json >/dev/null
    kind_credential_cli credentials --platform delete "$name" --yes
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
  build_retained_kind_smokes
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
    kind_credential_cli credentials --platform connect codex --name "$credential_name"
    kind_credential_cli credentials --platform --profile "$profile_name" set codex "$credential_name"
  fi
  kind_credential_cli credentials --platform get "$credential_name" --output json | jq -e \
    --arg name "$credential_name" 'length == 1 and .[0].name == $name
      and .[0].provider == "openai" and .[0].status == "CREDENTIAL_STATUS_ACTIVE"' >/dev/null
  if [ "$managed" = 1 ]; then
    kind_credential_cli credentials --platform get "$credential_name" --output json | jq -e \
      'length == 1 and .[0].authenticationKind == "CREDENTIAL_AUTHENTICATION_KIND_API_KEY"' >/dev/null
  fi
  environment="$(kind_credential_cli env --platform create --name "$profile_name" \
    --image "$workspace_image" --cpu 500 --memory 2Gi --disk 2Gi --ttl 1h \
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
  update="$(kind_credential_cli env --platform update "$environment" \
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
    managed_projection=(SMOKE_CW_MANAGED_AGENTS=1
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
  kind_credential_cli env --platform rm "$environment" --yes --output json
  wait_kind_credential_environment "$environment" destroyed
  kubectl -n "$SANDBOX_NS" wait --for=delete --timeout=120s "pod/$pod"
  kind_credential_cli credentials --platform --profile "$profile_name" delete --yes
  # A stored platform credential is revoked before its record is deleted.
  kind_credential_cli credentials --platform revoke "$credential_name" --output json >/dev/null
  kind_credential_cli credentials --platform delete "$credential_name" --yes
  if [ "$managed" = 1 ]; then
    kind_credential_cli credentials --platform revoke "$anthropic_name" --output json >/dev/null
    kind_credential_cli credentials --platform delete "$anthropic_name" --yes
  fi
  rm -rf -- "$KIND_CREDENTIAL_CLI_HOME"
  log "retained cw-runtime public create, original Attach/daemon/Pod, UID1000 A/B/A, CAS/Observe/refusal and cleanup green"
}
