#!/usr/bin/env bash
# Managed Kind credential fixture mechanics; not a standalone live installer.
set -euo pipefail

kind_credential_support_images() {
  # Image manifests resolved from the signed v1.17.1 release's official
  # registry references; Linux/amd64 only, like this native Kind gate.
  # Sealed runners preload the same manifests through their approved Nexus
  # boundary. Docker digest references include the repository, so an approved
  # Nexus reference cannot satisfy an inspection of the public Quay name.
  local registry sealed_status=0
  validate_sealed_kind_images >&2 || sealed_status=$?
  case "$sealed_status" in
    0) registry=nexus.example.invalid/oci-approved/jetstack ;;
    1) registry=quay.io/jetstack ;;
    *) return "$sealed_status" ;;
  esac
  printf '%s\n' \
    "${registry}/cert-manager-controller@sha256:8615625f29f821542fca5351e3791a21121bf869aa63c72607e0a51e4c233a4a|localhost/codewire-ci/cert-manager-controller:verified-8615625f29f821542fca5351e3791a21121bf869aa63c72607e0a51e4c233a4a" \
    "${registry}/cert-manager-webhook@sha256:f7ad7d3c6dbe73ead365c2324dbe6575b4fc618ed06f0863f250c5eafb35a246|localhost/codewire-ci/cert-manager-webhook:verified-f7ad7d3c6dbe73ead365c2324dbe6575b4fc618ed06f0863f250c5eafb35a246" \
    "${registry}/cert-manager-cainjector@sha256:da14ecb33386bd53c86d22a7a996e9783da5a09aa4ce9c55e161128fc2632985|localhost/codewire-ci/cert-manager-cainjector:verified-da14ecb33386bd53c86d22a7a996e9783da5a09aa4ce9c55e161128fc2632985"
}

prepare_kind_credential_support_images() {
  local source alias images
  # Capture and check the complete inventory before any image operation. A
  # process substitution would hide an invalid tuple or generator failure.
  images="$(kind_credential_support_images)" || return $?
  while IFS='|' read -r source alias; do
    if ! docker image inspect "$source" >/dev/null 2>&1; then
      # Sealed CI must preload dependencies at its existing trusted boundary;
      # never give a repository-controlled job a new registry credential.
      if validate_sealed_kind_images; then
        echo "::error::exact credential fixture image was not preloaded: ${source}" >&2
        return 1
      else
        local status=$?
        [ "$status" -eq 1 ] || return "$status"
      fi
      log "pulling exact credential fixture dependency ${source}"
      docker pull "$source"
    fi
    docker image tag "$source" "$alias"
  done <<<"$images"
}

load_kind_credential_support_images() {
  local source alias images
  images="$(kind_credential_support_images)" || return $?
  while IFS='|' read -r source alias; do
    docker image inspect "$source" >/dev/null
    log "loading ${alias} into Kind"
    kind load docker-image --name "$KIND_CLUSTER_NAME" "$alias"
    wait_for_kind_api_after_image_load
  done <<<"$images"
}

deploy_kind_credential_cert_manager() {
  local -r expected_manifest_sha256=c8d451522fbf7db1a4c11d2d8c4c0253f51f4b54fd4396b467c0a582fe834615
  local manifest actual current_context
  manifest="$ROOT/tests/e2e/kind/vendor/cert-manager-v1.17.1.yaml"
  actual="$(sha256sum "$manifest" | cut -d' ' -f1)"
  if [ "$actual" != "$expected_manifest_sha256" ]; then
    echo "::error::credential fixture cert-manager manifest differs from its reviewed render" >&2
    return 1
  fi
  current_context="$(kubectl config current-context)"
  if [ "${KIND_E2E_COMMON_LOADED:-0}" != 1 ] \
      || [ "$NS" != codewire-e2e ] || [ "$SANDBOX_NS" != dev-sandboxes ] \
      || [ "$current_context" != "kind-${KIND_CLUSTER_NAME}" ]; then
    echo "::error::credential certificate fixture requires the managed disposable Kind context" >&2
    return 1
  fi
  log "deploying exact cert-manager credential fixture"
  kubectl create namespace cert-manager --dry-run=client -o yaml | kubectl_apply -f -
  # CRDs exceed client-side last-applied annotation limits. Retain the managed
  # helper's timeout and use an explicit owner without forcing conflicts.
  kubectl_apply --server-side --field-manager=codewire-kind-credentials -f "$manifest"
  kubectl wait --for=condition=Established --timeout=90s \
    crd/certificates.cert-manager.io crd/certificaterequests.cert-manager.io \
    crd/issuers.cert-manager.io
  local deployment
  for deployment in cert-manager cert-manager-cainjector cert-manager-webhook; do
    kubectl -n cert-manager rollout status "deployment/$deployment" --timeout=180s
  done
}

deploy_kind_credential_issuers() {
  log "issuing independent synthetic Kind gateway and broker roots"
  kubectl_apply -f "$ROOT/tests/e2e/kind/credential-issuers.yaml"
  kubectl -n "$SANDBOX_NS" wait --for=condition=Ready --timeout=120s \
    certificate/codewire-kind-credential-gateway-root issuer/codewire-credential-gateway
  kubectl -n "$NS" wait --for=condition=Ready --timeout=120s \
    certificate/codewire-kind-credential-broker-root issuer/codewire-credential-broker \
    certificate/codewire-credential-broker \
    certificate/codewire-kind-postgres-root issuer/codewire-kind-postgres \
    certificate/codewire-kind-postgres-tls
  local gateway_roots broker_roots
  # Only public certificates leave these synthetic controller-owned Secrets.
  # No private key is copied into the host, workspace, ConfigMap or log.
  gateway_roots="$(kubectl -n "$SANDBOX_NS" get secret codewire-kind-credential-gateway-root \
    -o 'jsonpath={.data.tls\.crt}' | base64 -d)"
  broker_roots="$(kubectl -n "$NS" get secret codewire-kind-credential-broker-root \
    -o 'jsonpath={.data.tls\.crt}' | base64 -d)"
  [ -n "$gateway_roots" ] && [ -n "$broker_roots" ] && [ "$gateway_roots" != "$broker_roots" ] || {
    echo '::error::Kind credential trust domains are missing or not distinct' >&2
    return 1
  }
  kubectl -n "$SANDBOX_NS" create configmap codewire-credential-gateway-roots \
    --from-literal="ca.crt=$gateway_roots" --dry-run=client -o yaml | kubectl_apply -f -
  kubectl -n "$SANDBOX_NS" create configmap codewire-credential-broker-roots \
    --from-literal="ca.crt=$broker_roots" --dry-run=client -o yaml | kubectl_apply -f -
}

delete_kind_credential_bootstrap() {
  local environment="$1"
  [[ "$environment" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1
  # Remove the issuing object first. Foreground GC retains it while deleting
  # its leaf, which can start cert-manager issuance again. Background removes
  # that intent while its owner references still collect late controller work.
  # Both phases must complete; this is not best-effort teardown.
  kubectl -n "$SANDBOX_NS" delete "certificate/cw-credential-gateway-$environment" \
    --ignore-not-found=true --cascade=background --wait=true --timeout=120s >/dev/null || return $?
  kubectl -n "$SANDBOX_NS" delete \
    "secret/cw-credential-gateway-$environment" \
    "configmap/cw-credential-codex-$environment" \
    --ignore-not-found=true --wait=true --timeout=120s >/dev/null
}

kind_credential_bootstrap_smoke() (
  log "checking credential bootstrap with real Kind admission and certificate issuance"
  local binary kubeconfig
  local kubeconfig_args=()
  binary="$(jq -ser '
    [.[] | select(.reason == "compiler-artifact" and .profile.test == true
      and .target.name == "codewire_orchestration" and .executable != null) | .executable]
    | if length == 1 then .[0] else error("expected one orchestration libtest") end
  ' "$RUN_DIR/credential-bootstrap-build.jsonl")"
  [ -x "$binary" ] || { echo '::error::credential bootstrap executable is missing' >&2; return 1; }
  # Export only this disposable cluster's identity. Do not let the Rust client
  # fall back to any ambient kubeconfig or external cluster credentials.
  kubeconfig="$(mktemp "$RUN_DIR/credential-bootstrap-kubeconfig.XXXXXX")"
  trap 'rm -f -- "$kubeconfig"' EXIT
  if is_remote_dind_kind_job; then
    kubeconfig_args+=(--internal)
  fi
  kind get kubeconfig "${kubeconfig_args[@]}" --name "$KIND_CLUSTER_NAME" >"$kubeconfig"
  KUBECONFIG="$kubeconfig" CODEWIRE_KIND_CONTEXT="kind-$KIND_CLUSTER_NAME" \
    CODEWIRE_KIND_CREDENTIAL_BOOTSTRAP=1 \
    "$binary" --exact sandbox::client::credentials::kind::credential_bootstrap_kind \
      --ignored --nocapture --test-threads=1 | tee "$RUN_DIR/credential-bootstrap-kind.log"
  grep -q '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "$RUN_DIR/credential-bootstrap-kind.log" || {
    echo '::error::credential bootstrap gate did not execute exactly one passing test' >&2
    return 1
  }
)

start_kind_credential_fixture() {
  if [ "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" = prebuilt-release ]; then
    # A release-image gate must never load or execute a synthetic authority.
    # The dedicated synthetic composition is owned by the services-ci gate.
    log "release-image gate: synthetic credential service is not selected"
    return 0
  fi
  local profile promotable
  profile="$(docker image inspect --format '{{ index .Config.Labels "dev.codewire.build.profile" }}' codewire-services:e2e)"
  promotable="$(docker image inspect --format '{{ index .Config.Labels "dev.codewire.promotable" }}' codewire-services:e2e)"
  if [ "$profile" != ci ] || [ "$promotable" != false ]; then
    echo '::error::synthetic credentials require the exact non-promotable services-ci image' >&2
    return 1
  fi
  log "provisioning synthetic restricted Kind credential login"
  kubectl -n "$NS" exec -i deploy/postgres -- psql -U codewire -d codewire \
    -v ON_ERROR_STOP=1 < "$ROOT/tests/e2e/kind/credential-broker.sql"
  kubectl_apply -f "$ROOT/tests/e2e/kind/credential-fixture-config.yaml"
  kubectl -n "$NS" patch deployment codewire-credential-service --type=strategic \
    --patch-file "$ROOT/tests/e2e/kind/credential-fixture-patch.yaml"
  kubectl -n "$NS" scale deployment/codewire-credential-service --replicas=1
  kubectl -n "$NS" rollout status deployment/codewire-credential-service --timeout=180s
}

prepare_kind_credential_cli() (
  # Model an already-authenticated personal Codewire login, not an org API
  # key. The shared seed has multiple memberships, so normal saved-login org
  # selection is required. This is not proof of Codewire's device-login flow.
  # Only the fixed synthetic bearer is stored; refresh is deliberately absent
  # from the seed and any attempt to refresh must fail closed.
  [ ! -L "$KIND_CREDENTIAL_CLI_HOME" ] \
    && [ "$(stat -f -c %T "$KIND_CREDENTIAL_CLI_HOME")" = tmpfs ] \
    && [ "$(stat -c %u "$KIND_CREDENTIAL_CLI_HOME")" = "$(id -u)" ] \
    && [ "$(stat -c %a "$KIND_CREDENTIAL_CLI_HOME")" = 700 ] || {
    echo '::error::synthetic CLI login requires an owned private tmpfs home' >&2
    return 1
  }
  umask 077
  mkdir "$KIND_CREDENTIAL_CLI_HOME/cw" || return 1
  jq -n --arg server "$KIND_INGRESS_URL" '{server_url: $server}' \
    > "$KIND_CREDENTIAL_CLI_HOME/cw/config.json"
  jq -n --arg issuer "${KIND_INGRESS_URL%/}" '{
    issuer: $issuer, client_id: "oidc_kind_connect",
    access_token: "at_kind_connect_oidc_codewire_api",
    refresh_token: "kind-synthetic-refresh-not-issued",
    expires_at_unix: ((now | floor) + 3600), scope: "openid codewire.api"
  }' > "$KIND_CREDENTIAL_CLI_HOME/cw/credentials.json"
)

kind_credential_cli() {
  env -i PATH=/usr/bin:/bin HOME="$KIND_CREDENTIAL_CLI_HOME" \
    XDG_CONFIG_HOME="$KIND_CREDENTIAL_CLI_HOME/config" \
    XDG_DATA_HOME="$KIND_CREDENTIAL_CLI_HOME/data" \
    XDG_CACHE_HOME="$KIND_CREDENTIAL_CLI_HOME/cache" \
    CW_CONFIG_DIR="$KIND_CREDENTIAL_CLI_HOME/cw" \
    CODEWIRE_SERVER_URL="$KIND_INGRESS_URL" \
    "$CARGO_CI_DIR/cw" "$@"
}

wait_kind_credential_environment() {
  local environment="$1" expected="$2" state attempt
  for ((attempt = 0; attempt < 180; attempt++)); do
    if [ "$expected" = destroyed ]; then
      # The CLI resolves targets through the active environment list, which
      # hides destroying as well as destroyed rows. Absence there is not
      # terminal proof. Observe the exact owned row through the managed Kind
      # database, just as the other lifecycle acceptance probes do.
      state="$(kubectl -n "$NS" exec -i deploy/postgres -- psql -U codewire -d codewire \
        -v ON_ERROR_STOP=1 -v environment="$environment" -At <<'SQL'
SELECT state FROM environments
WHERE id = :'environment' AND org_id = 'org_contract_1';
SQL
      )"
    else
      state="$(kind_credential_cli env --platform info "$environment" --output json | jq -er '.state')"
    fi
    if [ "$state" = "$expected" ]; then return 0; fi
    if [ "$state" = error ]; then
      echo '::error::credential fixture environment entered error state' >&2
      return 1
    fi
    sleep 2
  done
  echo "::error::credential fixture environment did not reach ${expected}" >&2
  return 1
}

kind_credential_workspace() {
  kubectl -n "$SANDBOX_NS" get pods \
    -l "codewire.sh/environment-id=$1,codewire.sh/type=workspace" -o json | jq -er '
      [.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running")]
      | if length == 1 and .[0].spec.serviceAccountName == "codewire-sandbox"
          and .[0].spec.automountServiceAccountToken == false
        then .[0].metadata.name else error("expected one exact managed workspace") end'
}

kind_credential_probe() {
  local environment="$1" mode="$2" pod
  pod="$(kind_credential_workspace "$environment")"
  kubectl -n "$SANDBOX_NS" exec -i "$pod" -c workspace -- \
    python3 -B -u - "$environment" "$mode" < "$ROOT/scripts/ci/verify/kind/credential_probe.py"
}

kind_credential_fixture_events() {
  # This test-only subscriber disables all SQL/HTTP/material diagnostics.
  # Do not turn on a generic debug logger to obtain acceptance evidence.
  kubectl -n "$NS" logs deployment/codewire-credential-service -c credential-service | \
    jq -Rsc '[split("\n")[] | fromjson? | select(.target == "codewire_kind_credential_fixture") | .fields]'
}

assert_kind_credential_provider_counts() {
  local baseline="$1" counts
  counts="$(kind_credential_fixture_events)"
  jq -e --argjson baseline "$baseline" '
    # Keep response and refresh events interleaved. Final totals alone can
    # hide a refresh before rejection, replay, or the retired third request.
    # The failed replay is a nonretryable 400 for the stock client. Double-401
    # forwarding and the broker-only retry bound have separate runtime proof.
    [.[] | select(.event == "provider_response" or .event == "provider_refresh") |
      [.event, .scenario, .attempt, .status, .response_calls, .refresh_calls]] as $observed |
    ($baseline == 2 or $baseline == 3) and
    ($observed == ([
      ["provider_response", "baseline", 1, 200, 1, 0],
      ["provider_response", "baseline", 2, 200, 2, 0],
      ["provider_response", "broker_retry_once", 1, 401, 3, 0],
      ["provider_refresh", null, null, null, 3, 1],
      ["provider_response", "broker_retry_once", 2, 200, 4, 1],
      ["provider_response", "broker_retry_exhausted", 1, 401, 5, 1],
      ["provider_refresh", null, null, null, 5, 2],
      ["provider_response", "broker_retry_exhausted", 2, 400, 6, 2]
    ] + if $baseline == 3 then [["provider_response", "baseline", 3, 200, 7, 2]] else [] end))
  ' <<<"$counts" >/dev/null || {
    echo '::error::synthetic provider retry/refresh counts differ from the exact hosted scenarios' >&2
    return 1
  }
  kubectl -n "$NS" get pods -l app.kubernetes.io/component=credential-service -o json | jq -e '
    [.items[] | select(.metadata.deletionTimestamp == null)] |
    length == 1 and .[0].status.containerStatuses[0].restartCount == 0
  ' >/dev/null || { echo '::error::credential fixture restarted during acceptance' >&2; return 1; }
}

save_kind_credential_rotation_evidence() (
  # Save only closed public fixture fields, not arbitrary subscriber fields or
  # messages. Invalid values become null for diagnosis; the assertions below
  # still consume the original events and are never relaxed by this projection.
  umask 077
  local directory
  directory="$(mktemp -d "$RUN_DIR/credential-rotation.XXXXXX")" || return $?
  jq -ce --arg environment "$1" --arg generation "$2" --arg workspace "$3" --arg gateway "$4" '
    def uuid: if type == "string" and
      test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
      then . else null end;
    def count: if type == "number" and . >= 0 and . <= 9007199254740991 and floor == .
      then . else null end;
    def boolean: if type == "boolean" then . else null end;
    def event:
      if type != "object" then {event:null}
      elif .event == "bridge_authenticated" then {
        event, environment_id:(.environment_id | uuid), generation:(.generation | count),
        workspace_pod_uid:(.workspace_pod_uid | uuid), gateway_pod_uid:(.gateway_pod_uid | uuid),
        auth_sequence:(.auth_sequence | count), workspace_token_changed:(.workspace_token_changed | boolean)
      }
      elif .event == "provider_response" then {
        event, scenario:(.scenario | if . == "baseline" or . == "broker_retry_once" or
          . == "broker_retry_exhausted" then . else null end),
        attempt:(.attempt | count), status:(.status | count | if . >= 100 and . <= 599 then . else null end),
        response_calls:(.response_calls | count), refresh_calls:(.refresh_calls | count)
      }
      elif .event == "provider_refresh" or .event == "provider_totals" then {
        event, response_calls:(.response_calls | count), refresh_calls:(.refresh_calls | count)
      }
      else {event:null} end;
    if type == "array" and length <= 4096 then {
      expected:{environment_id:($environment | uuid),
        generation:($generation | try tonumber catch null | count),
        workspace_pod_uid:($workspace | uuid), gateway_pod_uid:($gateway | uuid)},
      events:map(event)
    } else error("invalid bounded fixture transcript") end
  ' > "$directory/evidence.pending" 2>/dev/null || {
    echo '::error::could not preserve bounded credential fixture evidence' >&2
    return 1
  }
  # The closed schemas already bound output; keep an explicit publication cap
  # so a future projection change cannot silently broaden retained evidence.
  [ "$(wc -c < "$directory/evidence.pending")" -le 2097152 ] || return 1
  mv "$directory/evidence.pending" "$directory/evidence.json" || return $?
  printf '%s\n' "$directory/evidence.json"
)

assert_kind_credential_rotation() {
  local environment="$1" generation="$2" workspace_uid="$3" gateway_uid="$4" session="$5" events evidence
  events="$(kind_credential_fixture_events)" || return $?
  evidence="$(save_kind_credential_rotation_evidence "$environment" "$generation" \
    "$workspace_uid" "$gateway_uid" <<<"$events")" || return $?
  # Authentication is not Ready/admission by itself. Compose the exact live
  # authenticator transcript with the >600s epoch bound and a successful stock
  # turn after actual projected-token replacement; never print token digests.
  jq -es '
    map(.event) == ["baseline_completed", "projected_token_rotated", "rotation_turn_completed",
      "broker_retry_completed", "broker_retry_exhausted", "complete"] and
    .[0].codex_processes == 1 and
    ([.[0,2,3,4].legacy_auth_commands] == [0,0,0,0]) and
    .[1].changed == true and .[1].elapsed_ms > 600000 and .[1].elapsed_ms < 720000 and
    all(.[3,4]; .elapsed_ms >= 0 and .elapsed_ms < 30000) and
    .[5] == {event:"complete", turns:4, completed:3, failed:1, same_process:true, token_changed:true}
  ' "$session" >/dev/null || {
    echo "::error::stock Codex hosted rotation/session evidence is incomplete; fixture record: $evidence" >&2
    return 1
  }
  jq -e --arg environment "$environment" --argjson generation "$generation" \
    --arg workspace "$workspace_uid" --arg gateway "$gateway_uid" '
    def uuid: type == "string" and test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    to_entries as $events |
    [$events[] | select(.value.event == "provider_response" and .value.scenario == "baseline"
      and .value.attempt == 1 and .value.status == 200)] as $baseline |
    [$events[] | select(.value.event == "provider_response" and .value.scenario == "baseline"
      and .value.attempt == 2 and .value.status == 200)] as $rotation |
    [$events[] | select(.value.event == "bridge_authenticated")] as $all_auth |
    # A source restart retains its workflow generation but replaces both Pods.
    # Start at the exact selected identity; earlier unbound probes cannot prove
    # this journey. Do not filter away any later identity/generation change.
    [$all_auth[] | select(.value.environment_id == $environment and .value.generation == $generation and
      .value.workspace_pod_uid == $workspace and .value.gateway_pod_uid == $gateway)] as $selected |
    [$all_auth[] | select(.value.environment_id == $environment and .key >= $selected[0].key)] as $auth |
    ($environment | uuid) and ($workspace | uuid) and ($gateway | uuid) and $generation > 0 and
    ($baseline | length == 1) and ($rotation | length == 1) and
    $baseline[0].key < $rotation[0].key and ($selected | length >= 2) and
    $selected[0].key < $baseline[0].key and $selected[0].value.workspace_token_changed == false and
    ([$all_auth[].value.auth_sequence] == [range(1; ($all_auth | length) + 1)]) and
    all($all_auth[].value; (.environment_id | uuid) and (.workspace_pod_uid | uuid) and
      (.gateway_pod_uid | uuid) and (.generation | type == "number") and .generation > 0 and
      (.workspace_token_changed | type == "boolean")) and
    all($auth[].value; .environment_id == $environment and .generation == $generation and
      .workspace_pod_uid == $workspace and .gateway_pod_uid == $gateway and
      (.workspace_token_changed | type == "boolean")) and
    $all_auth[0].value.workspace_token_changed == false and
    any($auth[]; .key < $baseline[0].key) and
    any($auth[]; .key > $baseline[0].key and .key < $rotation[0].key and
      .value.workspace_token_changed == true)
  ' <<<"$events" >/dev/null || {
    echo "::error::fresh same-identity hosted authentication evidence is incomplete; fixture record: $evidence" >&2
    return 1
  }
}

kind_credential_native_smoke() (
  if [ "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" = prebuilt-release ]; then
    log "release-image gate: synthetic native credential composition is not selected"
    return 0
  fi
  log "running public platform enrollment/profile/native Codex acceptance with synthetic credentials"
  local KIND_CREDENTIAL_CLI_HOME credential_name profile_name environment pod pod_uid generation gateway_uid
  local certificate certificate_uid config_uid after_certificate_uid after_config_uid workspace_image
  workspace_image="$(kind_workspace_runtime_image)" || return $?
  KIND_CREDENTIAL_CLI_HOME="$(mktemp -d /dev/shm/codewire-kind-credentials.XXXXXX)"
  trap 'rm -rf -- "$KIND_CREDENTIAL_CLI_HOME"' EXIT
  [ "$(stat -f -c %T "$KIND_CREDENTIAL_CLI_HOME")" = tmpfs ] || return 1
  credential_name="kind-codex-${RANDOM}-${RANDOM}"
  profile_name="kind-profile-${RANDOM}-${RANDOM}"
  prepare_kind_credential_cli
  # Keep both seeded memberships intact. Explicitly choose the member scope,
  # never the other organization where this same test user is an owner.
  kind_credential_cli org list --output json | jq -e \
    'map({id, role}) | sort_by(.id) == [
      {id: "org_contract_1", role: "member"},
      {id: "org_contract_2", role: "owner"}]' >/dev/null
  kind_credential_cli org set org_contract_1
  kind_credential_cli org current | awk '
    $1 == "ID:" { id = $2; count++ }
    END { exit !(count == 1 && id == "org_contract_1") }'
  kind_credential_cli credentials --platform connect codex --name "$credential_name"
  kind_credential_cli credentials --platform get "$credential_name" --output json | jq -e \
    --arg name "$credential_name" 'length == 1 and .[0].name == $name
      and .[0].provider == "openai" and .[0].status == "CREDENTIAL_STATUS_ACTIVE"' >/dev/null
  # The first explicit identity selection creates the named profile atomically.
  kind_credential_cli credentials --platform --profile "$profile_name" set codex "$credential_name"
  # Let the public create path resolve a runnable preset for the exact runtime
  # image. preset_contract_1 is an API contract fixture with no template config.
  environment="$(kind_credential_cli env --platform create --name "$profile_name" \
    --image "$workspace_image" \
    --cpu 500 --memory 2Gi --disk 2Gi --ttl 1h --no-network --yes --output json | jq -er '.id')"
  [[ "$environment" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1
  wait_kind_credential_environment "$environment" running
  kind_credential_probe "$environment" wrong-root
  kind_credential_probe "$environment" missing
  kind_credential_probe "$environment" unbound
  kind_credential_cli env --platform update "$environment" \
    --profile "platform:$profile_name" --yes --output json
  wait_kind_credential_environment "$environment" running
  pod="$(kind_credential_workspace "$environment")"
  pod_uid="$(kubectl -n "$SANDBOX_NS" get pod "$pod" -o 'jsonpath={.metadata.uid}')"
  generation="$(kubectl -n "$SANDBOX_NS" get pod "$pod" -o json | jq -er '
    [.spec.containers[] | select(.name == "workspace") | .env[] |
      select(.name == "CODEWIRE_ENVIRONMENT_OPERATION_GENERATION") | .value] |
    if length == 1 and (.[0] | test("^[1-9][0-9]*$")) then .[0]
    else error("expected exact immutable workspace generation") end')"
  gateway_uid="$(kubectl -n "$SANDBOX_NS" get pods \
    -l "codewire.sh/environment-id=$environment,codewire.sh/type=gateway" -o json | jq -er '
      [.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running")] |
      if length == 1 then .[0].metadata.uid else error("expected one exact managed gateway") end')"
  kubectl -n "$SANDBOX_NS" exec -i "$pod" -c workspace -- python3 -B -u - \
    < "$ROOT/scripts/ci/verify/kind/codex_session.py" | tee "$RUN_DIR/credential-native-session.jsonl"
  assert_kind_credential_rotation "$environment" "$generation" "$pod_uid" "$gateway_uid" \
    "$RUN_DIR/credential-native-session.jsonl"
  [ "$(kubectl -n "$SANDBOX_NS" get pod "$pod" -o 'jsonpath={.metadata.uid}')" = "$pod_uid" ] || {
    echo '::error::native Codex rotation proof changed workspace Pod identity' >&2
    return 1
  }
  assert_kind_credential_provider_counts 2

  certificate="cw-credential-gateway-$environment"
  certificate_uid="$(kubectl -n "$SANDBOX_NS" get certificate "$certificate" -o 'jsonpath={.metadata.uid}')"
  config_uid="$(kubectl -n "$SANDBOX_NS" get configmap "cw-credential-codex-$environment" -o 'jsonpath={.metadata.uid}')"
  kind_credential_cli env --platform stop "$environment" --output json
  wait_kind_credential_environment "$environment" stopped
  after_certificate_uid="$(kubectl -n "$SANDBOX_NS" get certificate "$certificate" -o 'jsonpath={.metadata.uid}')"
  after_config_uid="$(kubectl -n "$SANDBOX_NS" get configmap "cw-credential-codex-$environment" -o 'jsonpath={.metadata.uid}')"
  [ "$certificate_uid" = "$after_certificate_uid" ] && [ "$config_uid" = "$after_config_uid" ] || {
    echo '::error::ordinary stop did not retain its environment bootstrap' >&2
    return 1
  }
  kind_credential_cli env --platform start "$environment" --output json
  wait_kind_credential_environment "$environment" running
  kind_credential_probe "$environment" success
  assert_kind_credential_provider_counts 3
  kind_credential_cli credentials --platform revoke "$credential_name" --output json
  kind_credential_probe "$environment" revoked
  assert_kind_credential_provider_counts 3

  # Do not unbind before destroy: terminal cleanup itself must remove the
  # binding, so a tombstone cannot permanently pin the profile and credential.
  kind_credential_cli env --platform rm "$environment" --yes --output json
  wait_kind_credential_environment "$environment" destroyed
  kubectl -n "$SANDBOX_NS" wait --for=delete --timeout=120s \
    "certificate/$certificate" "secret/$certificate" "configmap/cw-credential-codex-$environment"
  kind_credential_cli credentials --platform --profile "$profile_name" delete --yes
  kind_credential_cli credentials --platform delete "$credential_name" --yes
  log "public synthetic Codex flow, native rotation/retry, revocation and terminal cleanup passed"
)
