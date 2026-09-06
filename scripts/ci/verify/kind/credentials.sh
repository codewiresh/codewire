#!/usr/bin/env bash
# Managed Kind credential fixture mechanics; not a standalone live installer.
set -euo pipefail

kind_credential_support_images() {
  # Image manifests resolved from the signed v1.17.1 release's official
  # registry references; Linux/amd64 only, like this native Kind gate.
  printf '%s\n' \
    'quay.io/jetstack/cert-manager-controller@sha256:8615625f29f821542fca5351e3791a21121bf869aa63c72607e0a51e4c233a4a|localhost/codewire-ci/cert-manager-controller:verified-8615625f29f821542fca5351e3791a21121bf869aa63c72607e0a51e4c233a4a' \
    'quay.io/jetstack/cert-manager-webhook@sha256:f7ad7d3c6dbe73ead365c2324dbe6575b4fc618ed06f0863f250c5eafb35a246|localhost/codewire-ci/cert-manager-webhook:verified-f7ad7d3c6dbe73ead365c2324dbe6575b4fc618ed06f0863f250c5eafb35a246' \
    'quay.io/jetstack/cert-manager-cainjector@sha256:da14ecb33386bd53c86d22a7a996e9783da5a09aa4ce9c55e161128fc2632985|localhost/codewire-ci/cert-manager-cainjector:verified-da14ecb33386bd53c86d22a7a996e9783da5a09aa4ce9c55e161128fc2632985'
}

prepare_kind_credential_support_images() {
  local source alias
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
  done < <(kind_credential_support_images)
}

load_kind_credential_support_images() {
  local source alias
  while IFS='|' read -r source alias; do
    docker image inspect "$source" >/dev/null
    log "loading ${alias} into Kind"
    kind load docker-image --name "$KIND_CLUSTER_NAME" "$alias"
    wait_for_kind_api_after_image_load
  done < <(kind_credential_support_images)
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
    certificate/codewire-credential-broker
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
  if [ "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" != build-ci ]; then
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

kind_credential_cli() {
  env -i PATH=/usr/bin:/bin HOME="$KIND_CREDENTIAL_CLI_HOME" \
    XDG_CONFIG_HOME="$KIND_CREDENTIAL_CLI_HOME/config" \
    XDG_DATA_HOME="$KIND_CREDENTIAL_CLI_HOME/data" \
    XDG_CACHE_HOME="$KIND_CREDENTIAL_CLI_HOME/cache" \
    CW_CONFIG_DIR="$KIND_CREDENTIAL_CLI_HOME/cw" \
    CODEWIRE_SERVER_URL="$KIND_INGRESS_URL" \
    CODEWIRE_API_KEY=at_kind_connect_oidc_codewire_api \
    "$CARGO_CI_DIR/cw" "$@"
}

wait_kind_credential_environment() {
  local environment="$1" expected="$2" state attempt
  for ((attempt = 0; attempt < 180; attempt++)); do
    state="$(kind_credential_cli env --platform info "$environment" --output json | jq -er '.state')"
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

assert_kind_credential_provider_counts() {
  local baseline="$1" counts
  # This test-only subscriber disables all SQL/HTTP/material diagnostics.
  # Do not turn on a generic debug logger to obtain acceptance evidence.
  counts="$(kubectl -n "$NS" logs deployment/codewire-credential-service -c credential-service | \
    jq -Rsc '[split("\n")[] | fromjson? | select(.target == "codewire_kind_credential_fixture") | .fields]')"
  jq -e --argjson baseline "$baseline" '
    [.[] | select(.event == "provider_response")] as $responses |
    [.[] | select(.event == "provider_refresh")] as $refreshes |
    ([$responses[] | select(.scenario == "baseline") | .status] == [range($baseline) | 200]) and
    ([$responses[] | select(.scenario == "broker_retry_once") | .status] == [401,200]) and
    ([$responses[] | select(.scenario == "native_reread") | .status] == [401,401,200]) and
    ([$refreshes[].refresh_calls] == [1,2]) and
    ($responses | length == $baseline + 5) and
    ($responses[-1].response_calls == $baseline + 5 and $responses[-1].refresh_calls == 2)
  ' <<<"$counts" >/dev/null || {
    echo '::error::synthetic provider retry/refresh counts differ from the exact native scenarios' >&2
    return 1
  }
  kubectl -n "$NS" get pods -l app.kubernetes.io/component=credential-service -o json | jq -e '
    [.items[] | select(.metadata.deletionTimestamp == null)] |
    length == 1 and .[0].status.containerStatuses[0].restartCount == 0
  ' >/dev/null || { echo '::error::credential fixture restarted during acceptance' >&2; return 1; }
}

kind_credential_native_smoke() (
  if [ "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" != build-ci ]; then
    log "release-image gate: synthetic native credential composition is not selected"
    return 0
  fi
  log "running public platform enrollment/profile/native Codex acceptance with synthetic credentials"
  local KIND_CREDENTIAL_CLI_HOME credential_name profile_name environment pod pod_uid
  local certificate certificate_uid config_uid after_certificate_uid after_config_uid
  KIND_CREDENTIAL_CLI_HOME="$(mktemp -d /dev/shm/codewire-kind-credentials.XXXXXX)"
  trap 'rm -rf -- "$KIND_CREDENTIAL_CLI_HOME"' EXIT
  [ "$(stat -f -c %T "$KIND_CREDENTIAL_CLI_HOME")" = tmpfs ] || return 1
  credential_name="kind-codex-${RANDOM}-${RANDOM}"
  profile_name="kind-profile-${RANDOM}-${RANDOM}"
  # An explicit bearer uses the single-membership path, not a saved login's
  # selected organization. Prove that identity without creating auth config.
  kind_credential_cli org list --output json | jq -e \
    'length == 1 and .[0].id == "org_contract_1"' >/dev/null
  kind_credential_cli credentials --platform connect codex --name "$credential_name"
  kind_credential_cli credentials --platform get "$credential_name" --output json | jq -e \
    --arg name "$credential_name" 'length == 1 and .[0].name == $name
      and .[0].provider == "openai" and .[0].status == "CREDENTIAL_STATUS_ACTIVE"' >/dev/null
  kind_credential_cli credentials --platform profile create "$profile_name"
  kind_credential_cli credentials --platform profile set "$profile_name" codex "$credential_name"
  environment="$(kind_credential_cli env --platform create --name "$profile_name" \
    --preset-id preset_contract_1 --image "$(kind_workspace_runtime_image)" \
    --cpu 500 --memory 2Gi --disk 2Gi --ttl 1h --no-network --yes --output json | jq -er '.id')"
  [[ "$environment" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1
  wait_kind_credential_environment "$environment" running
  kind_credential_probe "$environment" wrong-root
  kind_credential_probe "$environment" missing
  kind_credential_probe "$environment" unbound
  kind_credential_cli credentials --platform profile bind "$profile_name" \
    --environment "$environment" --confirm-personal-credentials
  pod="$(kind_credential_workspace "$environment")"
  pod_uid="$(kubectl -n "$SANDBOX_NS" get pod "$pod" -o 'jsonpath={.metadata.uid}')"
  kubectl -n "$SANDBOX_NS" exec -i "$pod" -c workspace -- python3 -B -u - \
    < "$ROOT/scripts/ci/verify/kind/codex_session.py" | tee "$RUN_DIR/credential-native-session.jsonl"
  jq -es '
    map(.event) == ["baseline_completed", "projected_token_rotated", "rotation_turn_completed",
      "broker_retry_completed", "native_reread_completed", "complete"]
  ' "$RUN_DIR/credential-native-session.jsonl" >/dev/null
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
  kind_credential_cli credentials --platform profile delete "$profile_name" --yes
  kind_credential_cli credentials --platform delete "$credential_name" --yes
  log "public synthetic Codex flow, native rotation/retry, revocation and terminal cleanup passed"
)
