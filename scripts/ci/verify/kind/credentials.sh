#!/usr/bin/env bash
# Managed Kind credential fixture mechanics; not a standalone live installer.
set -euo pipefail

kind_credential_support_images() {
  # Image manifests resolved from the signed v1.17.1 release's official
  # registry references; Linux/amd64 only, like this native Kind gate.
  # Sealed runners preload the same manifests through their approved Harbor
  # boundary. Docker digest references include the repository, so an approved
  # Harbor reference cannot satisfy an inspection of the public Quay name.
  local registry sealed_status=0
  validate_sealed_kind_images >&2 || sealed_status=$?
  case "$sealed_status" in
    0) registry=registry.example.invalid/oci-approved/jetstack ;;
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
      docker pull "$source" || return $?
    fi
    docker image tag "$source" "$alias" || return $?
  done <<<"$images"
}

load_kind_credential_support_images() {
  local source alias images
  images="$(kind_credential_support_images)" || return $?
  while IFS='|' read -r source alias; do
    docker image inspect "$source" >/dev/null || return $?
    log "loading ${alias} into Kind"
    kind load docker-image --name "$KIND_CLUSTER_NAME" "$alias" || return $?
    wait_for_kind_api_after_image_load || return $?
  done <<<"$images"
}

deploy_kind_credential_cert_manager() {
  local -r expected_manifest_sha256=c8d451522fbf7db1a4c11d2d8c4c0253f51f4b54fd4396b467c0a582fe834615
  local manifest actual current_context
  manifest="$ROOT/tests/e2e/kind/vendor/cert-manager-v1.17.1.yaml"
  actual="$(sha256sum "$manifest" | cut -d' ' -f1)" || return $?
  if [ "$actual" != "$expected_manifest_sha256" ]; then
    echo "::error::credential fixture cert-manager manifest differs from its reviewed render" >&2
    return 1
  fi
  current_context="$(kubectl config current-context)" || return $?
  if [ "${KIND_E2E_COMMON_LOADED:-0}" != 1 ] \
      || [ "$NS" != codewire-e2e ] || [ "$SANDBOX_NS" != dev-sandboxes ] \
      || [ "$current_context" != "kind-${KIND_CLUSTER_NAME}" ]; then
    echo "::error::credential certificate fixture requires the managed disposable Kind context" >&2
    return 1
  fi
  log "deploying exact cert-manager credential fixture"
  kubectl create namespace cert-manager --dry-run=client -o yaml | kubectl_apply -f - || return $?
  # CRDs exceed client-side last-applied annotation limits. Retain the managed
  # helper's timeout and use an explicit owner without forcing conflicts.
  kubectl_apply --server-side --field-manager=codewire-kind-credentials -f "$manifest" || return $?
  kubectl wait --for=condition=Established --timeout=90s \
    crd/certificates.cert-manager.io crd/certificaterequests.cert-manager.io \
    crd/issuers.cert-manager.io || return $?
  local deployment
  for deployment in cert-manager cert-manager-cainjector cert-manager-webhook; do
    kubectl -n cert-manager rollout status "deployment/$deployment" --timeout=180s || return $?
  done
}

deploy_kind_credential_issuers() {
  log "issuing independent synthetic Kind broker, orchestration and coordinator roots"
  kubectl_apply -f "$ROOT/tests/e2e/kind/credential-issuers.yaml" || return $?
  kubectl -n "$NS" wait --for=condition=Ready --timeout=120s \
    certificate/codewire-kind-credential-broker-root issuer/codewire-credential-broker \
    certificate/codewire-credential-broker \
    certificate/codewire-kind-orchestration-internal-root issuer/codewire-orchestration-internal \
    certificate/codewire-orchestration-internal \
    certificate/codewire-kind-postgres-root issuer/codewire-kind-postgres \
    certificate/codewire-kind-postgres-tls \
    certificate/codewire-kind-coordinator-root issuer/codewire-kind-coordinator \
    certificate/codewire-kind-coordinator-tls || return $?
  publish_kind_trust_roots || return $?
}

# The trust bundle for one synthetic root: the current root first, then every
# certificate already published that has not expired and is not a duplicate,
# in published order. Roots renew at 72 of their 96 hours, and leaves signed by
# the previous root stay in use until they renew, so a retained cluster must
# trust both until the previous root expires. Only public certificates pass
# through here.
kind_trust_bundle_union() (
  set -euo pipefail
  local current="$1" published="$2" dir file fingerprint
  local -a current_files=() published_files=()
  local -A seen=()
  dir="$(mktemp -d)"
  trap 'rm -rf "$dir"' EXIT
  split_certificates() {
    awk -v prefix="$2" '
      /-----BEGIN CERTIFICATE-----/ { count++; file = sprintf("%s-%04d.pem", prefix, count) }
      count && file { print > file }
      /-----END CERTIFICATE-----/ { close(file); file = "" }
    ' <<<"$1"
  }
  split_certificates "$current" "$dir/current"
  split_certificates "$published" "$dir/published"
  shopt -s nullglob
  current_files=("$dir"/current-*.pem)
  published_files=("$dir"/published-*.pem)
  shopt -u nullglob
  if [ "${#current_files[@]}" -ne 1 ] \
      || ! openssl x509 -in "${current_files[0]}" -noout -checkend 0 >/dev/null 2>&1; then
    echo '::error::the current Kind trust root is not exactly one unexpired certificate' >&2
    exit 1
  fi
  for file in "${current_files[@]}" "${published_files[@]}"; do
    fingerprint="$(openssl x509 -in "$file" -noout -fingerprint -sha256 2>/dev/null)" || {
      echo '::error::a published Kind trust root is not a certificate' >&2
      exit 1
    }
    [ -z "${seen[$fingerprint]+x}" ] || continue
    openssl x509 -in "$file" -noout -checkend 0 >/dev/null 2>&1 || continue
    seen[$fingerprint]=1
    openssl x509 -in "$file"
  done
)

# Publish each synthetic Kind trust domain to the ConfigMaps its verifiers
# read, keeping the previous root while it is still valid. The initial deploy,
# every `make kind-deploy` and `make kind-trust-roots` call this, so a retained
# cluster survives its 72-hour root renewal. Arguments go before each kubectl
# subcommand, for example `--context kind-NAME`. Only public `tls.crt` and
# `ca.crt` certificates are read; no private key leaves its Secret.
# shellcheck disable=SC2120 # the dev-loop callers pass their --context
publish_kind_trust_roots() {
  local -a kube=(kubectl "$@")
  local ns="${NS:-codewire-e2e}" sandbox_ns="${SANDBOX_NS:-dev-sandboxes}"
  local broker_roots orchestration_roots coordinator_roots
  broker_roots="$("${kube[@]}" -n "$ns" get secret codewire-kind-credential-broker-root \
    -o 'jsonpath={.data.tls\.crt}' | base64 -d)" || return $?
  orchestration_roots="$("${kube[@]}" -n "$ns" get secret codewire-kind-orchestration-internal-root \
    -o 'jsonpath={.data.tls\.crt}' | base64 -d)" || return $?
  coordinator_roots="$("${kube[@]}" -n "$ns" get secret codewire-kind-coordinator-root \
    -o 'jsonpath={.data.tls\.crt}' | base64 -d)" || return $?
  [ -n "$broker_roots" ] && [ -n "$orchestration_roots" ] && [ -n "$coordinator_roots" ] \
    && [ "$orchestration_roots" != "$broker_roots" ] \
    && [ "$coordinator_roots" != "$broker_roots" ] \
    && [ "$coordinator_roots" != "$orchestration_roots" ] || {
    echo '::error::Kind credential trust domains are missing or not distinct' >&2
    return 1
  }
  local target namespace name roots published bundle
  # Orchestration, the credential relay, verifies the broker in its own
  # namespace. Workspace daemons (sandbox namespace) verify orchestration's
  # binding listener, and Mesh (this namespace) its internal one. Workspace
  # daemons (SANDBOX_COORDINATOR_EXTRA_ROOTS) verify the in-cluster
  # coordinator edge with this root alone, beside the WebPKI roots.
  for target in \
      "$ns codewire-credential-broker-roots broker" \
      "$sandbox_ns codewire-orchestration-internal-roots orchestration" \
      "$ns codewire-orchestration-internal-roots orchestration" \
      "$sandbox_ns codewire-coordinator-extra-roots coordinator"; do
    read -r namespace name roots <<<"$target"
    case "$roots" in
      broker) roots="$broker_roots" ;;
      orchestration) roots="$orchestration_roots" ;;
      coordinator) roots="$coordinator_roots" ;;
    esac
    published="$("${kube[@]}" -n "$namespace" get configmap "$name" --ignore-not-found \
      -o 'jsonpath={.data.ca\.crt}')" || return $?
    bundle="$(kind_trust_bundle_union "$roots" "$published")" || return $?
    if [ "$bundle" = "$published" ]; then
      printf '[kind-trust-roots] %s/%s is current\n' "$namespace" "$name" >&2
      continue
    fi
    "${kube[@]}" -n "$namespace" create configmap "$name" \
      --from-literal="ca.crt=$bundle" --dry-run=client -o yaml \
      | "${kube[@]}" --request-timeout="${KUBECTL_REQUEST_TIMEOUT:-30s}" apply -f - >/dev/null \
      || return $?
    printf '[kind-trust-roots] published %s root(s) to %s/%s\n' \
      "$(grep -c -- '-----BEGIN CERTIFICATE-----' <<<"$bundle")" "$namespace" "$name" >&2
  done
}

start_kind_credential_fixture() {
  local fixture_patch
  if [ "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" = prebuilt-release ]; then
    # A release-image gate must never load or execute a synthetic authority.
    # The dedicated synthetic composition is owned by the services-ci gate.
    log "release-image gate: synthetic credential service is not selected"
    return 0
  fi
  local profile promotable image_ref fixture_patch
  image_ref="${KIND_PROFILE_SERVICES_IMAGE_ID:-codewire-services:e2e}"
  profile="$(docker image inspect --format '{{ index .Config.Labels "dev.codewire.build.profile" }}' "$image_ref")"
  promotable="$(docker image inspect --format '{{ index .Config.Labels "dev.codewire.promotable" }}' "$image_ref")"
  if [ "$profile" != ci ] || [ "$promotable" != false ]; then
    echo '::error::synthetic credentials require the exact non-promotable services-ci image' >&2
    return 1
  fi
  log "provisioning synthetic restricted Kind credential login"
  kubectl -n "$NS" exec -i deploy/postgres -- psql -U codewire -d codewire \
    -v ON_ERROR_STOP=1 < "$ROOT/tests/e2e/kind/credential-broker.sql" || return $?
  kubectl_apply -f "$ROOT/tests/e2e/kind/credential-fixture-config.yaml" || return $?
  fixture_patch="$(render_kind_credential_fixture_patch)" || return $?
  kubectl -n "$NS" patch deployment codewire-credential-service --type=strategic \
    --patch-file "$fixture_patch" || return $?
  kubectl -n "$NS" scale deployment/codewire-credential-service --replicas=1 || return $?
  kubectl -n "$NS" rollout status deployment/codewire-credential-service --timeout=180s || return $?
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
    elif ! state="$(kind_credential_cli env --platform info "$environment" --output json |
        jq -er '.state')" || [ -z "$state" ]; then
      # A failed observation must name itself. jq exits 4 without a word when
      # its input is empty, and older jq variants return success with no
      # output there, so an empty state is an observation failure too —
      # otherwise the suite either dies silently or burns its whole budget.
      echo "::error::credential fixture environment observation failed while waiting for ${expected}" >&2
      return 1
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

# A new environment reads running before its setup finishes, and a profile
# update is refused until then ("environment setup is not ready").
wait_kind_credential_setup_complete() {
  local environment="$1" attempt
  for ((attempt = 0; attempt < 180; attempt++)); do
    if kind_credential_cli env --platform info "$environment" --output json |
        jq -e '.state == "running" and .setup_complete == true' >/dev/null; then
      return 0
    fi
    sleep 2
  done
  echo '::error::credential fixture environment setup did not complete' >&2
  return 1
}

# A managed restart replaces the workspace Pod after the update is accepted.
# The environment state can read running again while the new Pod is still
# Pending, and one-shot selectors then miss it: a jq empty result exits 4
# without printing anything, which is how the failure reaches the log as a
# bare exit code. A recreated Pod is also Running before its workspace
# container accepts execs, so phase alone cannot gate the suite's next
# commands — every one of them selects or execs into exactly that container.
# Wait for exactly one exact workspace labelled with the restart's operation
# generation, answering an exec, and print its name; the generation keeps the
# pre-restart Pod from satisfying the wait. Orchestration is the credential
# relay: there is no gateway Pod.
wait_kind_credential_restarted_workspace() {
  local environment="$1" generation="$2" attempt pod
  [[ "$generation" =~ ^[1-9][0-9]*$ ]] || return 1
  for ((attempt = 0; attempt < 90; attempt++)); do
    if pod="$(kubectl -n "$SANDBOX_NS" get pods \
        -l "codewire.sh/environment-id=$environment" -o json | jq -er \
        --arg generation "$generation" '
      [.items[] | select(.metadata.deletionTimestamp == null
          and .status.phase == "Running"
          and .metadata.labels["codewire.sh/type"] == "workspace"
          and .metadata.labels["codewire.sh/environment-operation-generation"] == $generation
          and .spec.serviceAccountName == "codewire-sandbox"
          and .spec.automountServiceAccountToken == false)] |
      if length == 1 then .[0].metadata.name else empty end')" && [ -n "$pod" ]; then
      if kubectl -n "$SANDBOX_NS" exec "$pod" -c workspace -- true 2>/dev/null; then
        printf '%s\n' "$pod"
        return 0
      fi
    fi
    sleep 2
  done
  echo "::error::credential fixture environment ${environment} did not materialize its generation-${generation} workspace Pod exec-ready after the managed restart" >&2
  return 1
}

# The credential relay: the one running orchestration Pod, as its name and UID.
kind_credential_relay_pod() {
  kubectl -n "$NS" get pods \
    -l "app.kubernetes.io/name=codewire,app.kubernetes.io/component=orchestration" -o json | jq -er '
      [.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running")]
      | if length == 1 then .[0].metadata.name + "\n" + .[0].metadata.uid
        else error("expected one running orchestration Pod, the credential relay") end'
}

kind_credential_workspace() {
  kubectl -n "$SANDBOX_NS" get pods \
    -l "codewire.sh/environment-id=$1,codewire.sh/type=workspace" -o json | jq -er '
      [.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running")]
      | if length == 1 and .[0].spec.serviceAccountName == "codewire-sandbox"
          and .[0].spec.automountServiceAccountToken == false
        then .[0].metadata.name else error("expected one exact managed workspace") end'
}

# The workspace's credential projection, without a request: MODE `unselected`
# before any profile is selected, `selected` once Codex is. Either way no
# provider value is in the child environment and Codex's files are the
# daemon's own.
kind_credential_probe() {
  local environment="$1" mode="$2" pod
  [[ "$mode" =~ ^(selected|unselected)$ ]] || return 1
  pod="$(kind_credential_workspace "$environment")" || return $?
  kubectl -n "$SANDBOX_NS" exec -i "$pod" -c workspace -- \
    python3 -B -u - "$mode" < "$ROOT/scripts/ci/verify/kind/credential_probe.py"
}

# The broker reuses a hosted epoch's authority decision for at most 60
# seconds. A membership or binding change must take effect on the daemon's
# connected epoch within this many milliseconds of the first request after it,
# polled once a second. A credential change applies to the very next request.
KIND_AUTHORITY_CHANGE_WITHIN_MS=65000

# An authority change is observed on one connected epoch. The relay admits an
# epoch's natural successor about 90 seconds before it ends, and a successor
# keeps the scope it was admitted with (credential-service authority.rs,
# Resolved::same_authority): admitted inside a change window, it never answers
# the expected denial, or can never serve the restore. A change therefore
# starts only while the serving epoch has this long left: the 90-second
# successor lead, the 65-second change window, and 25 seconds for the requests
# before the change, the changes themselves and the restore (the two windows
# measured 63 and 62 seconds end to end). Otherwise the journey first waits
# for the relay's next admission (#2574). An epoch ends with the earlier of
# the relay's and the workspace's projected tokens, which expire at unrelated
# times, so the next epoch can be a short one and the wait can span two
# renewals: at most this many seconds.
KIND_AUTHORITY_EPOCH_HEADROOM_MS=180000
KIND_AUTHORITY_EPOCH_WAIT_SECONDS=360

# The relay's epoch admissions for ENVIRONMENT in log order, one
# "admitted_unix_ms ends_in_ms" line each: a first or fresh epoch and each
# overlap state when their epoch ends (credential_relay/epoch.rs). 0 means the
# broker reported no expiry, so the relay plans no renewal.
kind_credential_epoch_admissions() {
  local environment="$1" relay_pod="$2" logs
  [[ "$environment" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1
  logs="$(kubectl -n "$NS" logs "pod/$relay_pod" -c orchestration)" || return $?
  jq -Rr --arg environment "$environment" '
    fromjson? | select(type == "object"
      and .target == "codewire_orchestration::worker::credential_relay::epoch"
      and (.fields | type == "object") and .fields.environment_id == $environment)
    | (if .fields.event == "credential_bridge_epoch_admitted" then .fields.ends_in_ms
       elif .fields.event == "credential_bridge_epoch_overlap" then .fields.next_ends_in_ms
       else empty end) as $ends
    | select(($ends | type) == "number" and $ends >= 0)
    | (.timestamp | strings | capture("^(?<whole>[^.Z]+)(\\.(?<fraction>[0-9]+))?Z$")) as $t
    | (($t.whole + "Z" | fromdateiso8601) * 1000
        + ((($t.fraction // "") + "000")[0:3] | tonumber)) as $at
    | "\($at) \($ends | floor)"' <<<"$logs"
}

# Whether the serving epoch, the last of ADMISSIONS, has the headroom an
# authority change needs at NOW_MS.
kind_credential_epoch_has_headroom() {
  local admissions="$1" now_ms="$2" at ends
  read -r at ends <<<"$(tail -n 1 <<<"$admissions")"
  [[ "$at" =~ ^[0-9]+$ && "$ends" =~ ^[0-9]+$ ]] || return 1
  [ "$ends" -eq 0 ] || [ "$((at + ends - now_ms))" -ge "$KIND_AUTHORITY_EPOCH_HEADROOM_MS" ]
}

# Before an authority change: print "current" when the serving epoch has the
# headroom, or wait for the relay's next admission with it and print "renewed".
await_kind_credential_epoch_headroom() {
  local environment="$1" relay_pod="$2" admissions deadline
  admissions="$(kind_credential_epoch_admissions "$environment" "$relay_pod")" || return $?
  if [ -z "$admissions" ]; then
    echo "::error::the credential relay logged no epoch admission for ${environment}" >&2
    return 1
  fi
  if kind_credential_epoch_has_headroom "$admissions" "$(date +%s%3N)"; then
    printf 'current\n'
    return 0
  fi
  log "the serving epoch renews within $((KIND_AUTHORITY_EPOCH_HEADROOM_MS / 1000))s; waiting for the relay's next admission before the authority change" >&2
  deadline=$((SECONDS + KIND_AUTHORITY_EPOCH_WAIT_SECONDS))
  while [ "$SECONDS" -lt "$deadline" ]; do
    sleep 2
    # An epoch's time left only falls, so headroom means a later admission.
    admissions="$(kind_credential_epoch_admissions "$environment" "$relay_pod")" || return $?
    if kind_credential_epoch_has_headroom "$admissions" "$(date +%s%3N)"; then
      printf 'renewed\n'
      return 0
    fi
  done
  echo "::error::the credential relay admitted no epoch with $((KIND_AUTHORITY_EPOCH_HEADROOM_MS / 1000))s of headroom within ${KIND_AUTHORITY_EPOCH_WAIT_SECONDS}s" >&2
  return 1
}

# After an authority change window that opened at FROM_MS, or when a probe
# inside it failed: the relay must not have admitted an epoch for ENVIRONMENT
# since. If it did, the probes say nothing about one connected epoch.
assert_kind_credential_no_renewal_since() {
  local environment="$1" relay_pod="$2" from_ms="$3" admissions
  [[ "$from_ms" =~ ^[0-9]+$ ]] || return 1
  admissions="$(kind_credential_epoch_admissions "$environment" "$relay_pod")" || return $?
  if awk -v from="$from_ms" '$1 >= from { found = 1 } END { exit !found }' <<<"$admissions"; then
    echo "::error::renewal inside change window: the credential relay admitted an epoch for ${environment} during an authority change, so its probes are not evidence about one connected epoch; rerun the suite" >&2
    return 1
  fi
}

# The Codex login check period the workspace daemon in POD was given: 120
# seconds, or the shorter one the Kind deployment rendered for it.
kind_credential_codex_login_check_period() {
  local pod="$1" value
  value="$(kubectl -n "$SANDBOX_NS" get pod "$pod" -o \
    'jsonpath={.spec.containers[?(@.name=="workspace")].env[?(@.name=="CODEWIRE_CODEX_LOGIN_CHECK_PERIOD_SECONDS")].value}')" ||
    return $?
  value="${value:-120}"
  if ! [[ "$value" =~ ^[1-9][0-9]{1,2}$ ]] || [ "$value" -lt 10 ] || [ "$value" -gt 120 ]; then
    echo '::error::the workspace daemon was given an invalid Codex login check period' >&2
    return 1
  fi
  printf '%s\n' "$value"
}

# Proxied Codex requests through the workspace daemon's loopback ingress, on
# its long-lived bridge epoch: the path stock Codex's proxy provider uses, and
# the one on which an epoch reuses decrypted material and must see an
# authority change while it stays connected. With a third argument, request
# until MODE answers within that many milliseconds (see daemon_probe.py).
# Its one closed event goes to stdout and, when KIND_DAEMON_PROBE_LOG names a
# file, is appended there too.
kind_credential_daemon_probe() {
  local environment="$1" mode="$2" within="${3:-}" pod output status=0
  [[ "$mode" =~ ^(success|denied|revoked)$ ]] || return 1
  [[ -z "$within" || "$within" =~ ^[1-9][0-9]{0,4}$ ]] || return 1
  pod="$(kind_credential_workspace "$environment")" || return $?
  output="$(kubectl -n "$SANDBOX_NS" exec -i "$pod" -c workspace -- \
    python3 -B -u - "$mode" ${within:+"$within"} \
    < "$ROOT/scripts/ci/verify/kind/daemon_probe.py")" || status=$?
  printf '%s\n' "$output"
  if [ -n "${KIND_DAEMON_PROBE_LOG:-}" ]; then
    printf '%s\n' "$output" >> "$KIND_DAEMON_PROBE_LOG" || return $?
  fi
  [ "$status" -eq 0 ] && jq -e --arg mode "$mode" \
    '.event == "daemon_probe" and .mode == $mode' <<<"$output" >/dev/null || {
    echo "::error::the daemon-path ${mode} request failed" >&2
    return 1
  }
}

# How many proxied Codex requests the credential service has logged.
kind_credential_codex_request_count() {
  kubectl -n "$NS" logs deployment/codewire-credential-service -c credential-service |
    jq -Rs '[split("\n")[] | fromjson? | select(type == "object"
      and .target == "codewire_credential_broker::timing"
      and .fields.event == "proxied_request" and .fields.slot == "codex")] | length'
}

# Change the environment creator's membership role in its organization, a
# write to the row runtime authority reads, through the managed Kind database.
# Removing the row would cascade the seeded member assignments, so the journey
# changes the role and restores it instead.
set_kind_credential_member_role() {
  local environment="$1" role="$2" changed
  [[ "$environment" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1
  [[ "$role" =~ ^(admin|member)$ ]] || return 1
  changed="$(kubectl -n "$NS" exec -i deploy/postgres -- psql -U codewire -d codewire \
    -v ON_ERROR_STOP=1 -v environment="$environment" -v role="$role" -qAt <<'SQL'
UPDATE org_members AS m SET role = :'role'
FROM environments AS e
WHERE e.id = :'environment' AND m.org_id = e.org_id AND m.user_id = e.created_by
  AND m.role <> :'role'
RETURNING m.id;
SQL
  )" || return $?
  [ -n "$changed" ] && [ "$(wc -l <<<"$changed")" -eq 1 ] || {
    echo "::error::the credential fixture creator's membership did not change to ${role}" >&2
    return 1
  }
}

# The profile revision a running environment's binding names.
kind_credential_bound_revision() {
  local environment="$1" revision
  [[ "$environment" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1
  revision="$(kubectl -n "$NS" exec -i deploy/postgres -- psql -U codewire -d codewire \
    -v ON_ERROR_STOP=1 -v environment="$environment" -qAt <<'SQL'
SELECT profile_revision FROM platform_environment_access_bindings
WHERE environment_id = :'environment';
SQL
  )" || return $?
  [[ "$revision" =~ ^[1-9][0-9]*$ ]] || {
    echo '::error::the credential fixture environment has no profile binding' >&2
    return 1
  }
  printf '%s\n' "$revision"
}

# Rebind a running environment to its profile's current revision, or to the
# exact REVISION given, through the managed Kind database. The product's
# rebind (`env update --profile`) restarts the environment and so admits a new
# epoch; this write is the one way to change the binding under a connected
# epoch, which must then be denied (or admitted again, when the binding
# returns to the revision it was admitted with).
rebind_kind_credential_environment() {
  local environment="$1" revision="${2:-}" rebound
  [[ "$environment" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1
  [[ -z "$revision" || "$revision" =~ ^[1-9][0-9]{0,17}$ ]] || return 1
  rebound="$(kubectl -n "$NS" exec -i deploy/postgres -- psql -U codewire -d codewire \
    -v ON_ERROR_STOP=1 -v environment="$environment" -v revision="$revision" -qAt <<'SQL'
UPDATE platform_environment_access_bindings AS b
SET profile_revision = COALESCE(NULLIF(:'revision', '')::bigint, p.current_revision),
    updated_at = now()
FROM platform_access_profiles AS p
WHERE b.environment_id = :'environment' AND p.id = b.profile_id
  AND b.profile_revision <> COALESCE(NULLIF(:'revision', '')::bigint, p.current_revision)
RETURNING b.profile_revision;
SQL
  )" || return $?
  [[ "$rebound" =~ ^[1-9][0-9]*$ ]] || {
    echo "::error::the credential fixture environment was not rebound to another profile revision" >&2
    return 1
  }
}

# Replace the environment's sandbox Pods through Stop/Start. The new workspace
# daemon admits a new bridge epoch, which evaluates authority afresh; the
# login it delivers again proves that epoch serves.
replace_kind_credential_sandbox() {
  local environment="$1" before after
  before="$(kubectl -n "$SANDBOX_NS" get pod "$(kind_credential_workspace "$environment")" \
    -o 'jsonpath={.metadata.uid}')" || return $?
  kind_credential_cli env --platform stop "$environment" --output json >/dev/null || return $?
  wait_kind_credential_environment "$environment" stopped || return $?
  kind_credential_cli env --platform start "$environment" --output json >/dev/null || return $?
  wait_kind_credential_environment "$environment" running || return $?
  after="$(kubectl -n "$SANDBOX_NS" get pod "$(kind_credential_workspace "$environment")" \
    -o 'jsonpath={.metadata.uid}')" || return $?
  [ -n "$after" ] && [ "$after" != "$before" ] || {
    echo '::error::Stop/Start did not replace the workspace Pod' >&2
    return 1
  }
  kind_credential_codex_login "$environment" redelivered >/dev/null || return $?
}

# One codex_login.py mode in the exact workspace. Its stdout is closed events
# only; the mode passes only when its last event is its own completion.
kind_credential_codex_login() {
  local environment="$1" mode="$2" pod output status=0
  shift 2
  pod="$(kind_credential_workspace "$environment")" || return $?
  output="$(kubectl -n "$SANDBOX_NS" exec -i "$pod" -c workspace -- \
    python3 -B -u - "$mode" "$@" < "$ROOT/scripts/ci/verify/kind/codex_login.py")" || status=$?
  printf '%s\n' "$output" >> "$RUN_DIR/credential-codex-login.jsonl" || return $?
  printf '%s\n' "$output"
  if [ "$status" -ne 0 ] || ! jq -se --arg mode "$mode" \
      'length >= 2 and .[-1] == {event: "complete", mode: $mode}
        and all(.[]; .event != "failed")' <<<"$output" >/dev/null; then
    echo "::error::Codex ChatGPT login acceptance failed in mode ${mode}" >&2
    return 1
  fi
}

# The credential service reuses a decrypted value for at most this long after
# its read.
KIND_MATERIAL_REUSE_SECONDS=120

# Proxied requests through the bridge while a natural epoch renewal happens.
# The probe stops at its stop file, or after this bound as a backstop only: an
# overlap happens within the first ten minutes, and the Codex session it spans
# normally ends soon after it.
KIND_BRIDGE_RENEWAL_MAX_SECONDS=900
# About one request a second; a window spanning one renewal sees hundreds.
KIND_BRIDGE_RENEWAL_MIN_REQUESTS=60
# Bound on asking the in-Pod probe to stop.
KIND_BRIDGE_RENEWAL_STOP_TIMEOUT=15s

# The Codex session's rotation idle ends once the workspace token is replaced
# and a fresh-token epoch is admitted, rather than after the full 600-second
# epoch bound. The admission is what the credential fixture records: this
# environment's first bridge authentication with a replaced workspace token
# after the baseline response. Poll for it in the background of the calling
# shell (KIND_ADMISSION_WATCH_PID) and mark it in the workspace; the session
# still requires the replaced token itself, and assert_kind_credential_rotation
# still asserts the whole transcript.
KIND_ADMISSION_WATCH_SECONDS=720
start_kind_credential_admission_watch() {
  local environment="$1" pod="$2" marker="$3"
  [[ "$marker" =~ ^/tmp/codewire-kind-fresh-admission-[0-9]{1,12}$ ]] || return 1
  watch_kind_credential_fresh_admission "$environment" "$pod" "$marker" &
  KIND_ADMISSION_WATCH_PID=$!
}

watch_kind_credential_fresh_admission() {
  local environment="$1" pod="$2" marker="$3" deadline=$((SECONDS + KIND_ADMISSION_WATCH_SECONDS))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if kind_credential_fixture_events 2>/dev/null | jq -e --arg environment "$environment" '
        (map(.event == "provider_response" and .scenario == "baseline"
          and .attempt == 1 and .status == 200) | index(true)) as $baseline |
        $baseline != null and (to_entries | any(.[]; .key > $baseline
          and .value.event == "bridge_authenticated" and .value.environment_id == $environment
          and .value.workspace_token_changed == true))' >/dev/null 2>&1; then
      kubectl -n "$SANDBOX_NS" exec "$pod" -c workspace -- touch "$marker" && return 0
    fi
    sleep 5
  done
  return 1
}

# Start bridge_renewal.py in the exact workspace, in the background of the
# calling shell, and set KIND_BRIDGE_RENEWAL_PID. Its stdout is the closed
# event stream, kept in the run directory.
start_kind_credential_bridge_renewal() {
  local pod="$1" stop="$2"
  [[ "$stop" =~ ^/tmp/codewire-kind-bridge-renewal-[0-9]{1,12}$ ]] || return 1
  kubectl -n "$SANDBOX_NS" exec -i "$pod" -c workspace -- \
    python3 -B -u - "$stop" "$KIND_BRIDGE_RENEWAL_MAX_SECONDS" \
    < "$ROOT/scripts/ci/verify/kind/bridge_renewal.py" \
    > "$RUN_DIR/credential-bridge-renewal.jsonl" &
  KIND_BRIDGE_RENEWAL_PID=$!
}

# Ask the in-Pod probe to stop, within a bounded request.
signal_kind_credential_bridge_renewal() {
  local pod="$1" stop="$2"
  [[ "$stop" =~ ^/tmp/codewire-kind-bridge-renewal-[0-9]{1,12}$ ]] || return 1
  kubectl --request-timeout="$KIND_BRIDGE_RENEWAL_STOP_TIMEOUT" -n "$SANDBOX_NS" \
    exec "$pod" -c workspace -- touch "$stop"
}

# Failure path: ask the in-Pod probe to stop, best effort, then end the local
# exec. Killing only the local kubectl could leave the probe running in the
# Pod until its backstop.
abandon_kind_credential_bridge_renewal() {
  local pod="$1" stop="$2" pid="$3"
  signal_kind_credential_bridge_renewal "$pod" "$stop" >/dev/null 2>&1 || true
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

# Ask the probe to stop, await its own exit status, then remove the stop file.
# The first failure wins; the probe is never left running locally.
stop_kind_credential_bridge_renewal() {
  local pod="$1" stop="$2" pid="$3" status=0
  [[ "$stop" =~ ^/tmp/codewire-kind-bridge-renewal-[0-9]{1,12}$ ]] || return 1
  if ! signal_kind_credential_bridge_renewal "$pod" "$stop"; then
    abandon_kind_credential_bridge_renewal "$pod" "$stop" "$pid"
    echo '::error::could not stop the bridge renewal probe' >&2
    return 1
  fi
  wait "$pid" || status=$?
  kubectl -n "$SANDBOX_NS" exec "$pod" -c workspace -- rm -f "$stop" || {
    [ "$status" -ne 0 ] || status=1
  }
  if [ "$status" -ne 0 ]; then
    echo '::error::bridge renewal probe failed' >&2
  fi
  return "$status"
}

# Every proxied request through the renewal window was answered by the broker
# (the unselected slot's 403): none failed with 503 for want of an epoch. The
# relay also logged admitting this environment's successor while its
# predecessor drained, inside that same window. Log timestamps have one-second
# resolution after their fraction is dropped; allow two seconds of slack at
# each end.
assert_kind_credential_bridge_renewal() {
  local probe="$1" environment="$2" relay_pod="$3" window logs
  [[ "$environment" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1
  [[ "$relay_pod" =~ ^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$ ]] || return 1
  window="$(jq -sce --argjson minimum "$KIND_BRIDGE_RENEWAL_MIN_REQUESTS" '
    def count: type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;
    if length == 1 and (.[0] | type == "object")
        and (.[0] | keys == ["ended_unix_ms", "event", "requests", "started_unix_ms", "statuses"])
        and .[0].event == "bridge_renewal_probe"
        and (.[0].started_unix_ms | count) and (.[0].ended_unix_ms | count)
        and .[0].ended_unix_ms > .[0].started_unix_ms
        and (.[0].requests | count) and .[0].requests >= $minimum
        and .[0].statuses == {"403": .[0].requests}
    then {started: .[0].started_unix_ms, ended: .[0].ended_unix_ms}
    else error("bridge renewal probe evidence is invalid") end
  ' "$probe" 2>/dev/null)" || {
    echo "::error::a proxied request failed or the probe was incomplete across the bridge renewal; probe record: $probe" >&2
    return 1
  }
  logs="$(kubectl -n "$NS" logs "pod/$relay_pod" -c orchestration)" || {
    echo '::error::could not read the credential relay log for bridge renewal evidence' >&2
    return 1
  }
  jq -Rne --argjson window "$window" --arg environment "$environment" '
    [inputs | fromjson? | select(type == "object"
        and .target == "codewire_orchestration::worker::credential_relay::epoch"
        and (.fields | type == "object")
        and .fields.event == "credential_bridge_epoch_overlap"
        and .fields.environment_id == $environment)
      | .timestamp | strings | sub("\\.[0-9]+Z$"; "Z") | (fromdateiso8601? // empty)
      | . * 1000]
    | any(.[]; . >= $window.started - 2000 and . <= $window.ended + 2000)
  ' <<<"$logs" >/dev/null || {
    echo '::error::the credential relay logged no epoch overlap while proxied requests were running' >&2
    return 1
  }
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
    # After the retry scenarios of the session, every baseline response is
    # one more served request, numbered in order.
    ($baseline | type == "number" and . == floor and . >= 2 and . <= 256) and
    ($observed == ([
      ["provider_response", "baseline", 1, 200, 1, 0],
      ["provider_response", "baseline", 2, 200, 2, 0],
      ["provider_response", "broker_retry_once", 1, 401, 3, 0],
      ["provider_refresh", null, null, null, 3, 1],
      ["provider_response", "broker_retry_once", 2, 200, 4, 1],
      ["provider_response", "broker_retry_exhausted", 1, 401, 5, 1],
      ["provider_refresh", null, null, null, 5, 2],
      ["provider_response", "broker_retry_exhausted", 2, 400, 6, 2]
    ] + [range(3; $baseline + 1) as $attempt
      | ["provider_response", "baseline", $attempt, 200, $attempt + 4, 2]]))
  ' <<<"$counts" >/dev/null || {
    echo '::error::synthetic provider retry/refresh counts differ from the exact hosted scenarios' >&2
    return 1
  }
  kubectl -n "$NS" get pods -l app.kubernetes.io/component=credential-service -o json | jq -e '
    [.items[] | select(.metadata.deletionTimestamp == null)] |
    length == 1 and .[0].status.containerStatuses[0].restartCount == 0
  ' >/dev/null || { echo '::error::credential fixture restarted during acceptance' >&2; return 1; }
}

assert_kind_credential_material_reuse() {
  # On the daemon's bridge epoch: a request, a second one, then Reconnect,
  # then one more, all on that one epoch. The second request reuses the first
  # one's authority decision and login: no resolve or grant evaluation, one
  # record read and no material read, unless that decision reached its minute
  # in between. Reconnect changed the record, so the very next request
  # evaluates again, reads and presents the new login. A new epoch admitted
  # between them is a failure, never an excuse: it would make the reuse proof
  # vacuous.
  local logs
  logs="$(kubectl -n "$NS" logs deployment/codewire-credential-service -c credential-service)" ||
    return $?
  jq -Rse '
    [split("\n")[] | fromjson? | select(type == "object")] as $lines |
    [$lines[] | select(.target == "codewire_credential_broker::timing")
      | select((.fields.event == "proxied_request" and .fields.slot == "codex")
        or (.fields.event == "epoch_admission" and .fields.outcome == "admitted"))
      | .fields] as $timed |
    [$timed | to_entries[] | select(.value.event == "proxied_request") | .key] as $requests |
    ($requests | length) >= 3 and
    all($timed[$requests[-3]:$requests[-1]][]; .event != "epoch_admission")
  ' <<<"$logs" >/dev/null || {
    echo '::error::a new bridge epoch was admitted inside the material reuse window' >&2
    return 1
  }
  jq -Rse --argjson window "$KIND_MATERIAL_REUSE_SECONDS" '
    def seconds: capture("^(?<whole>[^.Z]+)(?<fraction>[.][0-9]+)?Z$")
      | ((.whole + "Z") | fromdateiso8601) + ("0" + (.fraction // ".0") | tonumber);
    [split("\n")[] | fromjson? | select(type == "object")] as $lines |
    [$lines[] | select(.target == "codewire_kind_credential_fixture"
      and .fields.event == "provider_response" and .fields.scenario == "baseline"
      and .fields.attempt >= 3) | .fields | [.attempt, .status, .generation]] as $presented |
    [$lines[] | select(.target == "codewire_credential_broker::timing"
        and .fields.event == "proxied_request" and .fields.slot == "codex")
      | .fields + {at: (.timestamp | seconds)}] as $requests |
    ($requests[-3] // {}) as $warm | ($requests[-2] // {}) as $reuse |
    # The warm-up and the reuse present the refreshed login; Reconnect
    # published a newly enrolled one, generation 0.
    ($presented | map(.[0:2])) == [[3, 200], [4, 200], [5, 200]] and
    ($presented[0][2] | type == "number" and . > 0) and
    $presented[1][2] == $presented[0][2] and
    $presented[2][2] == 0 and
    ($requests | length >= 3) and
    ($requests[-3:] | map([.outcome, .status])) == [["response", 200],
      ["response", 200], ["response", 200]] and
    ($warm | .cache == "miss" and .material_reads >= 1) and
    # The warm-up filled before its line, at most its total time earlier.
    ($reuse.at - $warm.at + $warm.total_ms / 1000) < $window and
    ($reuse | .cache == "hit" and .material_reads == 0 and .unwraps == 0) and
    (($reuse | .authority == "reused" and .record_reads == 1 and .authority_checks == 0
        and .grant_evaluations == 0 and .resolves == 0)
      or ($warm.authority == "reused" and $reuse.authority == "evaluated")) and
    ($requests[-1] | .cache == "miss" and .material_reads >= 1 and .authority == "evaluated")
  ' <<<"$logs" >/dev/null || {
    echo '::error::the epoch material cache did not reuse, or reused a login after Reconnect' >&2
    return 1
  }
}

# Every daemon-path request of the authority journey, recorded by its probes
# (KIND_DAEMON_PROBE_LOG) and by the credential service's timing lines from
# its proxied Codex request number FROM on. The two must agree request by
# request: a 200 is a served response, and a 403 a denial (after revocation,
# the fixed 403 Reconnect explanation). A change's probe ends at its first
# denial, and a revocation's single request is refused; each must follow the
# request before it on the same, still-connected epoch: no epoch was admitted
# between them. Each change took effect within the bound. Requests served
# while a refusal was awaited, and repeated requests, reused the epoch's
# authority decision: no authority check, resolve or grant evaluation, and
# one record read. Repeated requests also reused the login, with no material
# read. A request served while a refusal is awaited may read it again, once
# for each daemon Codex login check that can fall inside a change window (one
# at production's 120-second period, LOGIN_CHECK_SECONDS): a full-check lease
# that the same change refuses on that epoch clears the epoch's material
# cache. A refusal, a restore and a revocation evaluated the decision; a
# refusal answered while a restore was awaited may come from either. A
# `sandbox_replaced` or `epoch_renewed` record marks the next request as the
# first on a new epoch: one was admitted before it, cold.
assert_kind_credential_authority_changes() {
  local from="$1" probes="$2" login_check_seconds="${3:-120}" logs
  [[ "$from" =~ ^[0-9]+$ ]] || return 1
  [[ "$login_check_seconds" =~ ^[1-9][0-9]{1,2}$ ]] || return 1
  logs="$(kubectl -n "$NS" logs deployment/codewire-credential-service -c credential-service)" ||
    return $?
  jq -Rse --argjson from "$from" --argjson within "$KIND_AUTHORITY_CHANGE_WITHIN_MS" \
    --argjson period "$login_check_seconds" --slurpfile probes "$probes" '
    [split("\n")[] | fromjson? | select(type == "object")] as $lines |
    [$lines[] | select(.target == "codewire_credential_broker::timing")
      | select((.fields.event == "proxied_request" and .fields.slot == "codex")
        or (.fields.event == "epoch_admission" and .fields.outcome == "admitted"))
      | .fields] as $timed |
    [$timed | to_entries[] | select(.value.event == "proxied_request")][$from:] as $logged |
    # What each probe saw, request by request. A change probe saw the answer
    # from before the change until its last request.
    [range(0; $probes | length) as $at | $probes[$at] | select(.event == "daemon_probe")
      | . as $probe
      | ($at > 0 and ($probes[$at - 1].event | . == "sandbox_replaced" or . == "epoch_renewed"))
        as $replaced
      | (if $probe.within_ms == null then [] else
          [range(1; $probe.requests) | {status: (if $probe.status == 200 then 403 else 200 end),
            mode: "before", change: false}] end)
        + [{status: $probe.status, mode: $probe.mode, change: ($probe.within_ms != null)}]
      | map(. + {replaced: false}) | .[0].replaced = $replaced
      | .[]] as $seen |
    # A credential that needs Reconnect answers with its fixed 403
    # explanation, without a provider call.
    def agrees($seen):
      if $seen.status == 200 then .outcome == "response" and .status == 200
      elif $seen.mode == "revoked" then .outcome == "response" and .status == 403
      elif $seen.mode == "denied" then .outcome == "denied"
      else .outcome == "denied" or (.outcome == "response" and .status == 403) end;
    def hit: .cache == "hit" and .material_reads == 0 and .unwraps == 0;
    def decision_reused: .authority == "reused" and .authority_checks == 0
      and .resolves == 0 and .grant_evaluations == 0 and .record_reads == 1
      and (hit or (.cache == "miss" and .material_reads == 1));
    def decided($seen):
      if $seen.replaced then .cache == "miss"
      elif $seen.mode == "before" and $seen.status == 403 then true
      elif $seen.mode == "before" then decision_reused
      elif $seen.status == 200 and ($seen.change | not) then decision_reused and hit
      else .authority == "evaluated" end;
    def admitted($from; $to): any($timed[($from + 1):$to][]; .event == "epoch_admission");
    ($seen | length) > 0 and ($logged | length) == ($seen | length) and
    ($probes[-1].event == "daemon_probe") and
    ([range(0; $seen | length) as $index
      | select($seen[$index].mode == "before" and $seen[$index].status == 200
          and $logged[$index].value.cache != "hit")] | length)
      <= ([$probes[] | select(.within_ms != null and .status == 403)] | length)
        # The daemon checks at least 90% of its period apart.
        * ((($within / ($period * 900)) | floor) + 1) and
    all($probes[]; .event == "sandbox_replaced" or .event == "epoch_renewed" or (.event == "daemon_probe"
      and (.within_ms == null or (.within_ms == $within and .waited_ms <= $within)))) and
    all(range(0; $seen | length);
      . as $index | $seen[$index] as $now | $logged[$index] as $log |
      ($log.value | agrees($now) and decided($now)) and
      (if ($now.change or $now.mode == "revoked") and $now.status == 403 then
         $index > 0 and ($logged[$index - 1].value | .outcome == "response" and .status == 200) and
         (admitted($logged[$index - 1].key; $log.key) | not)
       elif $now.replaced then
         $index > 0 and admitted($logged[$index - 1].key; $log.key)
       else true end))
  ' <<<"$logs" >/dev/null || {
    echo '::error::an authority change did not reach the connected daemon epoch in time, or the service logs disagree with the probes' >&2
    return 1
  }
}

save_kind_credential_rotation_evidence() (
  # Save only closed public fixture fields, not arbitrary subscriber fields or
  # messages. Invalid values become null for diagnosis; the assertions below
  # still consume the original events and are never relaxed by this projection.
  umask 077
  local directory
  directory="$(mktemp -d "$RUN_DIR/credential-rotation.XXXXXX")" || return $?
  jq -ce --arg environment "$1" --arg generation "$2" --arg workspace "$3" --arg relay "$4" '
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
        workspace_pod_uid:(.workspace_pod_uid | uuid), relay_pod_uid:(.relay_pod_uid | uuid),
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
        workspace_pod_uid:($workspace | uuid), relay_pod_uid:($relay | uuid)},
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
  local environment="$1" generation="$2" workspace_uid="$3" relay_uid="$4" session="$5" events evidence
  events="$(kind_credential_fixture_events)" || return $?
  evidence="$(save_kind_credential_rotation_evidence "$environment" "$generation" \
    "$workspace_uid" "$relay_uid" <<<"$events")" || return $?
  # Authentication is not Ready/admission by itself. Compose the exact live
  # authenticator transcript with a successful stock turn after actual
  # projected-token replacement and a fresh-token epoch: the fixture's
  # admission mark, or else the >600s epoch bound. Never print token digests.
  jq -es '
    map(.event) == ["baseline_completed", "projected_token_rotated", "rotation_turn_completed",
      "broker_retry_completed", "broker_retry_exhausted", "complete"] and
    .[0].codex_processes == 1 and
    ([.[0,2,3,4].legacy_auth_commands] == [0,0,0,0]) and
    .[1].changed == true and .[1].elapsed_ms < 720000 and
    (.[1].rotated_ms | type == "number" and . >= 0) and .[1].rotated_ms <= .[1].elapsed_ms and
    (.[1].fresh_admission == true or .[1].elapsed_ms > 600000) and
    all(.[3,4]; .elapsed_ms >= 0 and .elapsed_ms < 30000) and
    .[5] == {event:"complete", turns:4, completed:3, failed:1, same_process:true, token_changed:true}
  ' "$session" >/dev/null || {
    echo "::error::stock Codex hosted rotation/session evidence is incomplete; fixture record: $evidence" >&2
    return 1
  }
  log "$(jq -sr '.[1] | "projected workspace token replaced \(.rotated_ms / 1000 | floor)s after the baseline; idle ended at \(.elapsed_ms / 1000 | floor)s " + (if .fresh_admission then "on a fresh-token admission" else "at the epoch bound" end)' "$session")"
  jq -e --arg environment "$environment" --argjson generation "$generation" \
    --arg workspace "$workspace_uid" --arg relay "$relay_uid" '
    def uuid: type == "string" and test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    to_entries as $events |
    [$events[] | select(.value.event == "provider_response" and .value.scenario == "baseline"
      and .value.attempt == 1 and .value.status == 200)] as $baseline |
    [$events[] | select(.value.event == "provider_response" and .value.scenario == "baseline"
      and .value.attempt == 2 and .value.status == 200)] as $rotation |
    [$events[] | select(.value.event == "bridge_authenticated")] as $all_auth |
    # A source restart retains its workflow generation but replaces the
    # workspace Pod. Start at the exact selected identity; earlier unbound
    # probes cannot prove this journey. Do not filter away any later
    # identity/generation change.
    [$all_auth[] | select(.value.environment_id == $environment and .value.generation == $generation and
      .value.workspace_pod_uid == $workspace and .value.relay_pod_uid == $relay)] as $selected |
    [$all_auth[] | select(.value.environment_id == $environment and .key >= $selected[0].key)] as $auth |
    ($environment | uuid) and ($workspace | uuid) and ($relay | uuid) and $generation > 0 and
    ($baseline | length == 1) and ($rotation | length == 1) and
    $baseline[0].key < $rotation[0].key and ($selected | length >= 2) and
    $selected[0].key < $baseline[0].key and $selected[0].value.workspace_token_changed == false and
    ([$all_auth[].value.auth_sequence] == [range(1; ($all_auth | length) + 1)]) and
    all($all_auth[].value; (.environment_id | uuid) and (.workspace_pod_uid | uuid) and
      (.relay_pod_uid | uuid) and (.generation | type == "number") and .generation > 0 and
      (.workspace_token_changed | type == "boolean")) and
    all($auth[].value; .environment_id == $environment and .generation == $generation and
      .workspace_pod_uid == $workspace and .relay_pod_uid == $relay and
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

# A failed stage must not leave what it created live: a leftover Sandbox keeps
# authenticating to the bridge, and the synthetic fixture compares every bridge
# authentication with the previous one, so the next run fails its
# same-identity evidence. Remove, best-effort and logged, in dependency order:
# the environment, its profiles, then each credential, revoked before it is
# deleted (the CLI refuses to delete an active one). A stage forgets each name
# once its own steps removed it, so a passing stage removes nothing here.
cleanup_kind_credential_stage() {
  local environment="$1" profiles="$2" credentials="$3" item
  [ -n "${environment}${profiles}${credentials}" ] || return 0
  log "removing what the stage left: environment ${environment:-none}; profiles ${profiles:-none}; credentials ${credentials:-none}"
  if [ -n "$environment" ]; then
    if kind_credential_cli env --platform rm "$environment" --yes --output json >/dev/null 2>&1 \
        && wait_kind_credential_environment "$environment" destroyed >/dev/null 2>&1; then
      log "removed environment ${environment}"
    else
      log "could not remove environment ${environment}; remove it before the next run"
    fi
  fi
  for item in $profiles; do
    if kind_credential_cli credentials --platform --profile "$item" delete --yes >/dev/null 2>&1; then
      log "deleted profile ${item}"
    else
      log "could not delete profile ${item}"
    fi
  done
  for item in $credentials; do
    kind_credential_cli credentials --platform revoke "$item" --output json >/dev/null 2>&1 || true
    if kind_credential_cli credentials --platform delete "$item" --yes >/dev/null 2>&1; then
      log "deleted credential ${item}"
    else
      log "could not delete credential ${item}"
    fi
  done
}

kind_credential_native_smoke() (
  if [ "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" = prebuilt-release ]; then
    log "release-image gate: synthetic native credential composition is not selected"
    return 0
  fi
  log "running public platform enrollment/profile/native Codex acceptance with synthetic credentials"
  local KIND_CREDENTIAL_CLI_HOME credential_name profile_name environment pod pod_uid generation relay relay_pod relay_uid
  local workspace_image marker
  local login_events login_generation update restart_generation renewal_stop renewal_pid=""
  local member_role_changed="" bound_revision journey_from served
  local stage_environment="" stage_profiles="" stage_credentials="" admission admission_pid=""
  local authority_window_from="" headroom login_check_seconds
  # The acceptance must never die with a bare exit status again (runs 10381,
  # 10459, 10465 all lost the failing command to a silent jq exit 4). Report
  # the exact failing command before errexit unwinds the suite.
  set -E
  trap 'echo "::error::native Codex acceptance failed: command=${BASH_COMMAND} status=$?" >&2' ERR
  workspace_image="$(kind_workspace_runtime_image)" || return $?
  KIND_CREDENTIAL_CLI_HOME="$(mktemp -d /dev/shm/codewire-kind-credentials.XXXXXX)"
  # A failed step must not leave the renewal probe running, here or in the
  # Pod, and a failure while the creator is an admin restores the seeded
  # member role, so a retained cluster can run this suite again.
  trap '[ -z "$authority_window_from" ] || assert_kind_credential_no_renewal_since "$environment" "$relay_pod" "$authority_window_from" || true; [ -z "$admission_pid" ] || { kill "$admission_pid" 2>/dev/null; wait "$admission_pid" 2>/dev/null; }; [ -z "$renewal_pid" ] || abandon_kind_credential_bridge_renewal "$pod" "$renewal_stop" "$renewal_pid"; [ -z "$member_role_changed" ] || set_kind_credential_member_role "$environment" member >/dev/null 2>&1 || true; cleanup_kind_credential_stage "$stage_environment" "$stage_profiles" "$stage_credentials"; rm -rf -- "$KIND_CREDENTIAL_CLI_HOME"' EXIT
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
  stage_credentials="$credential_name"
  kind_credential_cli credentials --platform connect codex --name "$credential_name"
  kind_credential_cli credentials --platform get "$credential_name" --output json | jq -e \
    --arg name "$credential_name" 'length == 1 and .[0].name == $name
      and .[0].provider == "openai" and .[0].status == "CREDENTIAL_STATUS_ACTIVE"' >/dev/null
  # The first explicit identity selection creates the named profile atomically.
  stage_profiles="$profile_name"
  kind_credential_cli credentials --platform --profile "$profile_name" set codex "$credential_name"
  # Let the public create path resolve a runnable preset for the exact runtime
  # image. preset_contract_1 is an API contract fixture with no template config.
  environment="$(kind_credential_cli env --platform create --name "$profile_name" \
    --image "$workspace_image" \
    --cpu 500 --memory 2Gi --disk 2Gi --ttl 1h --no-network --yes --output json | jq -er '.id')"
  [[ "$environment" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1
  stage_environment="$environment"
  wait_kind_credential_environment "$environment" running
  kind_credential_probe "$environment" unselected
  update="$(kind_credential_cli env --platform update "$environment" \
    --profile "platform:$profile_name" --yes --output json)"
  printf '%s\n' "$update"
  restart_generation="$(jq -er '.operation_generation |
    if type == "number" and . > 0 and . == floor then .
    else error("expected a positive operation generation") end' <<<"$update")"
  wait_kind_credential_environment "$environment" running
  pod="$(wait_kind_credential_restarted_workspace "$environment" "$restart_generation")"
  pod_uid="$(kubectl -n "$SANDBOX_NS" get pod "$pod" -o 'jsonpath={.metadata.uid}')"
  # The workspace Pod carries the update's generation; the broker reviews it
  # against the binding orchestration recorded for that Pod.
  generation="$restart_generation"
  relay="$(kind_credential_relay_pod)"
  relay_pod="$(sed -n '1p' <<<"$relay")"
  relay_uid="$(sed -n '2p' <<<"$relay")"
  # The creator's own login reaches Codex's auth.json; stock Codex reads it as
  # ChatGPT, reads usage and completes a turn against a synthetic backend.
  login_events="$(kind_credential_codex_login "$environment" deliver)" || return $?
  # jq's empty-result exit code is image-dependent (4 in jq 1.8, success with
  # no output in the job image), and either way a failing assignment would
  # outrun the content check, so disarm the exit status and test the content.
  login_generation="$(jq -er 'select(.event == "delivered") | .generation' <<<"$login_events" || true)"
  [[ "$login_generation" =~ ^[0-9]+$ ]] || {
    echo '::error::the delivered Codex login event is missing its generation' >&2
    return 1
  }
  # The session idles past a projected-token rotation, so at least one natural
  # bridge epoch renewal happens under it. Proxied requests run throughout.
  renewal_stop="/tmp/codewire-kind-bridge-renewal-${RANDOM}${RANDOM}"
  start_kind_credential_bridge_renewal "$pod" "$renewal_stop" || return $?
  renewal_pid="$KIND_BRIDGE_RENEWAL_PID"
  # The proxy session forces the proxy provider; its broker refreshes rotate
  # the delivered login too.
  admission="/tmp/codewire-kind-fresh-admission-${RANDOM}${RANDOM}"
  start_kind_credential_admission_watch "$environment" "$pod" "$admission" || return $?
  admission_pid="$KIND_ADMISSION_WATCH_PID"
  kubectl -n "$SANDBOX_NS" exec -i "$pod" -c workspace -- python3 -B -u - "$admission" \
    < "$ROOT/scripts/ci/verify/kind/codex_session.py" | tee "$RUN_DIR/credential-native-session.jsonl"
  kill "$admission_pid" 2>/dev/null || true
  wait "$admission_pid" 2>/dev/null || true
  admission_pid=""
  stop_kind_credential_bridge_renewal "$pod" "$renewal_stop" "$renewal_pid" || return $?
  renewal_pid=""
  assert_kind_credential_rotation "$environment" "$generation" "$pod_uid" "$relay_uid" \
    "$RUN_DIR/credential-native-session.jsonl"
  assert_kind_credential_bridge_renewal "$RUN_DIR/credential-bridge-renewal.jsonl" \
    "$environment" "$relay_pod" || return $?
  [ "$(kubectl -n "$SANDBOX_NS" get pod "$pod" -o 'jsonpath={.metadata.uid}')" = "$pod_uid" ] || {
    echo '::error::native Codex rotation proof changed workspace Pod identity' >&2
    return 1
  }
  assert_kind_credential_provider_counts 2
  # The file adopts the rotation at the next check, a user's own login is
  # never touched, and `codex logout` stays logged out.
  kind_credential_codex_login "$environment" rotation "$login_generation" || return $?
  kind_credential_codex_login "$environment" own-login || return $?
  kind_credential_codex_login "$environment" logout || return $?

  # Codex's home is ~/.codex on the persistent home: state written there
  # survives Stop/Start, as on a laptop.
  marker="kind-persistence-${RANDOM}${RANDOM}"
  kubectl -n "$SANDBOX_NS" exec "$pod" -c workspace -- \
    sh -ec 'umask 077; printf "%s\n" "$1" > /home/codewire/.codex/kind-persistence' sh "$marker" ||
    return $?
  kind_credential_cli env --platform stop "$environment" --output json
  wait_kind_credential_environment "$environment" stopped
  kind_credential_cli env --platform start "$environment" --output json
  wait_kind_credential_environment "$environment" running
  pod="$(kind_credential_workspace "$environment")" || return $?
  [ "$(kubectl -n "$SANDBOX_NS" exec "$pod" -c workspace -- \
    cat /home/codewire/.codex/kind-persistence)" = "$marker" ] || {
    echo '::error::Codex home state did not survive Stop/Start' >&2
    return 1
  }
  kubectl -n "$SANDBOX_NS" exec "$pod" -c workspace -- rm -f /home/codewire/.codex/kind-persistence ||
    return $?
  # A new container forgets the logout and receives the login again.
  kind_credential_codex_login "$environment" redelivered || return $?
  # The selected projection after Stop/Start, with no provider request since
  # the session.
  kind_credential_probe "$environment" selected
  assert_kind_credential_provider_counts 2
  # The daemon's long-lived bridge epoch: its first proxied request reads the
  # login and fills the epoch's material cache; the next one, inside two
  # minutes, reuses it. Reconnect then replaces the login: the next request
  # on the same epoch must present the new one. These requests and the role
  # change after them are observed on one epoch, so they start only on one
  # with headroom before its natural renewal; after a wait, the first request
  # below is the new epoch's first.
  headroom="$(await_kind_credential_epoch_headroom "$environment" "$relay_pod")" || return $?
  authority_window_from="$(date +%s%3N)"
  kind_credential_daemon_probe "$environment" success
  kind_credential_daemon_probe "$environment" success
  kind_credential_cli credentials --platform connect codex --name "$credential_name" --yes
  kind_credential_daemon_probe "$environment" success
  assert_kind_credential_provider_counts 5
  assert_kind_credential_material_reuse
  # Authority changes on that same, still-connected epoch, while it is minutes
  # from a natural renewal: repeated requests reuse its authority decision;
  # each change refuses requests once that decision reaches its minute, and
  # each restore serves them again, within the bound.
  journey_from="$(kind_credential_codex_request_count)" || return $?
  login_check_seconds="$(kind_credential_codex_login_check_period "$pod")" || return $?
  KIND_DAEMON_PROBE_LOG="$(mktemp "$RUN_DIR/credential-daemon-authority.XXXXXX")" || return $?
  kind_credential_daemon_probe "$environment" success
  kind_credential_daemon_probe "$environment" success
  member_role_changed=1
  set_kind_credential_member_role "$environment" admin
  kind_credential_daemon_probe "$environment" denied "$KIND_AUTHORITY_CHANGE_WITHIN_MS"
  set_kind_credential_member_role "$environment" member
  member_role_changed=""
  kind_credential_daemon_probe "$environment" success "$KIND_AUTHORITY_CHANGE_WITHIN_MS"
  kind_credential_daemon_probe "$environment" success
  assert_kind_credential_no_renewal_since "$environment" "$relay_pod" "$authority_window_from"
  authority_window_from=""
  # A rebind under the connected epoch, to a revision without Codex, then
  # back to the revision the epoch was admitted with.
  bound_revision="$(kind_credential_bound_revision "$environment")" || return $?
  # The rebind too starts only on an epoch with headroom. After a wait, the
  # first request on the new epoch is a plain one, recorded as such, so the
  # change is still observed on a warm epoch.
  headroom="$(await_kind_credential_epoch_headroom "$environment" "$relay_pod")" || return $?
  if [ "$headroom" = renewed ]; then
    printf '%s\n' '{"event":"epoch_renewed"}' >> "$KIND_DAEMON_PROBE_LOG"
    kind_credential_daemon_probe "$environment" success
  fi
  authority_window_from="$(date +%s%3N)"
  kind_credential_cli credentials --platform --profile "$profile_name" unset codex
  rebind_kind_credential_environment "$environment"
  kind_credential_daemon_probe "$environment" denied "$KIND_AUTHORITY_CHANGE_WITHIN_MS"
  rebind_kind_credential_environment "$environment" "$bound_revision"
  kind_credential_daemon_probe "$environment" success "$KIND_AUTHORITY_CHANGE_WITHIN_MS"
  kind_credential_daemon_probe "$environment" success
  assert_kind_credential_no_renewal_since "$environment" "$relay_pod" "$authority_window_from"
  authority_window_from=""
  # Pod replacement admits a new epoch, which serves at once.
  replace_kind_credential_sandbox "$environment"
  printf '%s\n' '{"event":"sandbox_replaced"}' >> "$KIND_DAEMON_PROBE_LOG"
  kind_credential_daemon_probe "$environment" success
  # Revocation refuses the very next request on that epoch.
  kind_credential_cli credentials --platform revoke "$credential_name" --output json
  kind_credential_daemon_probe "$environment" revoked
  assert_kind_credential_authority_changes "$journey_from" "$KIND_DAEMON_PROBE_LOG" \
    "$login_check_seconds"
  # Revocation exposes nothing to the workspace either.
  kind_credential_probe "$environment" selected
  # Revocation is an explicit denial: the daemon removes Codewire's login and
  # restores its proxy config.toml at the next check.
  kind_credential_codex_login "$environment" revoked || return $?
  # Every daemon request the provider served is one more baseline response.
  served="$(jq -s 'map(.served // 0) | add' "$KIND_DAEMON_PROBE_LOG")" || return $?
  assert_kind_credential_provider_counts "$((5 + served))"

  # Do not unbind before destroy: terminal cleanup itself must remove the
  # binding, so a tombstone cannot permanently pin the profile and credential.
  kind_credential_cli env --platform rm "$environment" --yes --output json
  wait_kind_credential_environment "$environment" destroyed
  stage_environment=""
  kind_credential_cli credentials --platform --profile "$profile_name" delete --yes
  stage_profiles=""
  kind_credential_cli credentials --platform delete "$credential_name" --yes
  stage_credentials=""
  log "public synthetic Codex flow, ChatGPT login delivery, native rotation/retry, revocation and terminal cleanup passed"
)

# Fixed, public synthetic Anthropic credentials accepted only by the Kind
# fixture's in-process provider (credential-service runtime/kind/provider.rs).
# They are entered through the public CLI exactly as a user pastes an API key
# or a `claude setup-token` value; claude_session.py proves none reaches a
# Sandbox. The provider answers the refused token with a 401
# `authentication_error`, as a real provider answers an expired or revoked one.
KIND_ANTHROPIC_API_KEY='sk-ant-api03-CW_KIND_SYNTHETIC_ANTHROPIC_KEY-0123456789abcdef'
KIND_CLAUDE_SUBSCRIPTION_TOKEN='sk-ant-oat01-CW_KIND_SYNTHETIC_CLAUDE_TOKEN-0123456789abcdef'
KIND_CLAUDE_REFUSED_TOKEN='sk-ant-oat01-CW_KIND_SYNTHETIC_REFUSED_TOKEN-0123456789abcdef'
# Bound on one daemon-launched Claude Code session reaching a terminal state.
KIND_CLAUDE_SESSION_ATTEMPTS=90
# A managed restart turns the environment running a moment before its start
# releases the setup owner, and a launch in between is refused with exactly
# this message. Only that refusal is retried, once a second, for this long.
KIND_SETUP_NOT_READY='environment setup is not ready; wait for setup to finish'
KIND_LAUNCH_SETUP_SECONDS=60

# The managed client selection recorded for the live binding of one exact
# workspace Pod: the record launch authority reads. Waits briefly for the
# binding writer; prints exactly one value or fails.
kind_credential_managed_clients() {
  local environment="$1" pod_uid="$2" attempt rows
  local -r uuid='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  [[ "$environment" =~ $uuid && "$pod_uid" =~ $uuid ]] || return 1
  for ((attempt = 0; attempt < 30; attempt++)); do
    rows="$(kubectl -n "$NS" exec -i deploy/postgres -- psql -U codewire -d codewire \
      -v ON_ERROR_STOP=1 -v environment="$environment" -v pod_uid="$pod_uid" -At <<'SQL'
SELECT managed_credential_clients FROM sandbox_workspace_bindings
WHERE environment_id = :'environment' AND pod_uid = :'pod_uid' AND released_at IS NULL;
SQL
    )" || return $?
    if [[ "$rows" =~ ^v[12]:[a-z0-9,]{1,40}$ ]]; then
      printf '%s\n' "$rows"
      return 0
    fi
    [ -z "$rows" ] || break
    sleep 2
  done
  echo "::error::environment ${environment} has no single live workspace binding selection" >&2
  return 1
}

# Orchestration recorded the form the bound credential's kind selects: the
# Anthropic client alone, or with GitHub while the creator is connected. Bit
# 0x20 is the subscription form.
assert_kind_credential_claude_selection() {
  local form="$1" clients="$2"
  case "$form:$clients" in
    api_key:v1:anthropic | api_key:v2:14 | subscription_token:v2:24 | subscription_token:v2:34) ;;
    *)
      echo "::error::the ${form} form recorded unexpected managed clients ${clients}" >&2
      return 1
      ;;
  esac
}

# Stage claude_session.py in the exact workspace Pod for a daemon-launched
# session to run. Prints the staged path.
kind_credential_claude_stage() {
  local pod="$1" driver
  [[ "$pod" =~ ^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$ ]] || return 1
  driver="/tmp/codewire-kind-claude-session-${RANDOM}${RANDOM}.py"
  kubectl -n "$SANDBOX_NS" exec -i "$pod" -c workspace -- \
    sh -c 'umask 022 && cat > "$1"' sh "$driver" \
    < "$ROOT/scripts/ci/verify/kind/claude_session.py" || return $?
  printf '%s\n' "$driver"
}

# One claude_session.py run in a session the workspace daemon launches
# through the public `cw run` path, so it sees exactly the environment the
# daemon projects. Launch, terminal state and saved output are all unary
# calls. Its output is closed events only; the run passes only when its
# session exited 0 and its last event is its own completion.
# `cw run` in ENVIRONMENT with the remaining arguments, retried only while it
# is refused because setup is not ready yet; every other failure returns at
# once with the launch's own status and output.
kind_credential_launch() {
  local environment="$1" deadline=$((SECONDS + KIND_LAUNCH_SETUP_SECONDS)) stderr output status
  shift
  stderr="$(mktemp "$RUN_DIR/credential-launch.XXXXXX")" || return $?
  while :; do
    status=0
    output="$(kind_credential_cli run "$environment" "$@" 2>"$stderr")" || status=$?
    if [ "$status" -eq 0 ] || ! grep -Fq -- "$KIND_SETUP_NOT_READY" "$stderr" ||
      [ "$SECONDS" -ge "$deadline" ]; then
      cat -- "$stderr" >&2
      rm -f -- "$stderr"
      [ "$status" -ne 0 ] || printf '%s\n' "$output"
      return "$status"
    fi
    sleep 1
  done
}

kind_credential_claude_run() {
  local environment="$1" driver="$2" form="$3" outcome="$4"
  local launched session attempt state output
  [[ "$driver" =~ ^/tmp/codewire-kind-claude-session-[0-9]{1,12}\.py$ ]] || return 1
  case "$form" in api_key | subscription_token) ;; *) return 1 ;; esac
  case "$outcome" in success | refused) ;; *) return 1 ;; esac
  launched="$(kind_credential_launch "$environment" --no-tty --detach --output json -- \
    python3 -B -u "$driver" "$form" "$outcome")" || return $?
  session="$(jq -er '.session_id | select(type == "string" and test("^[A-Za-z0-9_-]{1,128}$"))' \
    <<<"$launched")" || {
    echo "::error::cw run did not report a launched session for the ${form} form" >&2
    return 1
  }
  for ((attempt = 0; attempt < KIND_CLAUDE_SESSION_ATTEMPTS; attempt++)); do
    state="$(kind_credential_cli list "$environment" --output json | jq -er --arg id "$session" '
      [.[] | select(.session_id == $id)] |
      if length == 1 then .[0] | "\(.state) \(.exit_code // "none")"
      else error("expected one launched session") end')" || return $?
    case "$state" in
      "Starting "* | "Running "*) sleep 2 ;;
      *) break ;;
    esac
  done
  output="$(kind_credential_cli logs "$environment" "$session" --raw)" || return $?
  output="$(jq -Rc 'fromjson? | select(type == "object" and has("event"))' <<<"$output")"
  printf '%s\n' "$output" >> "$RUN_DIR/credential-claude-session.jsonl" || return $?
  printf '%s\n' "$output"
  if [ "$state" != "Exited 0" ] || ! jq -se --arg form "$form" --arg outcome "$outcome" '
      length == 3
      and .[0] == {event: "claude_projection", form: $form, source: "daemon_session"}
      and .[1].event == "claude_session" and .[1].form == $form and .[1].outcome == $outcome
      and (.[1].client_version | type == "string")
      and .[2] == {event: "complete", form: $form, outcome: $outcome}' <<<"$output" >/dev/null; then
    echo "::error::stock Claude Code acceptance failed for the ${form} form (${outcome}); session ${state}" >&2
    return 1
  fi
}

# The fixture's Anthropic events since its pod started. Prints their count
# after asserting that every event after the first `baseline` ones answered
# exactly `form`, with at least one, and all with `status`. The broker's
# Anthropic route is transparent, so Claude Code's own identity headers reach
# the provider in both forms and the closed `client_identity` flag is set on
# every answer. A rejection of any kind, including the Sandbox placeholder
# reaching the provider, fails.
assert_kind_credential_anthropic_events() {
  local baseline="$1" form="$2" status="$3"
  [[ "$baseline" =~ ^[0-9]+$ ]] || return 1
  case "$form" in api_key | subscription_token) ;; *) return 1 ;; esac
  case "$status" in 200 | 401) ;; *) return 1 ;; esac
  kind_credential_fixture_events | jq -er --argjson baseline "$baseline" --arg kind "$form" \
    --argjson status "$status" '
    [.[] | select(.event == "anthropic_response" or .event == "anthropic_rejected")] as $all
    | if ($all | length) > $baseline
        and all($all[$baseline:][]; .event == "anthropic_response" and .kind == $kind
          and .status == $status and .refused == ($status == 401)
          and .client_identity == true
          and (.route == "messages" or .route == "count_tokens"))
      then ($all | length) else error("unexpected Anthropic provider events") end' || {
    echo "::error::the synthetic provider did not see only the ${form} credential answering ${status}" >&2
    return 1
  }
}

# The token's metadata after a provider refusal and after each replacement:
# the provider's anthropic OAuth kind, Active, with a hard expiry one year out.
assert_kind_credential_claude_token() {
  local name="$1" revision="$2"
  [[ "$revision" =~ ^[1-9][0-9]*$ ]] || return 1
  kind_credential_cli credentials --platform get "$name" --output json | jq -e \
    --arg name "$name" --arg revision "$revision" '.[0] as $c
      | ((($c.expiresAtUnix // $c.expires_at_unix) | tonumber) - (now | floor)) as $left
      | length == 1 and $c.name == $name and $c.provider == "anthropic"
        and $c.status == "CREDENTIAL_STATUS_ACTIVE"
        and ($c.authenticationKind // $c.authentication_kind) == "CREDENTIAL_AUTHENTICATION_KIND_OAUTH"
        and (($c.revocationGeneration // $c.revocation_generation) | tostring) == $revision
        and $left > 364 * 86400 and $left <= 365 * 86400' >/dev/null || {
    echo "::error::Claude subscription token ${name} is not Active at revision ${revision}" >&2
    return 1
  }
}

# Stock Claude Code in a hosted workspace through the managed Anthropic route,
# launched as a daemon session: first with an Anthropic API key, then, after
# rebinding the same environment, with a Claude subscription token, both
# entered through the public CLI. The provider accepts only the real
# synthetic credential in each form and refuses the placeholder, so completed
# sessions prove the broker substituted it while the Sandbox held only the
# placeholder. Then failure and recovery: the token is replaced with one the
# provider refuses, Claude Code reports the 401, the credential stays Active,
# and replacing it with a good token makes the next session succeed.
kind_credential_claude_session() (
  if [ "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" = prebuilt-release ]; then
    log "release-image gate: synthetic Claude Code credential composition is not selected"
    return 0
  fi
  log "running public Anthropic API key and Claude subscription token acceptance with stock Claude Code"
  local KIND_CREDENTIAL_CLI_HOME suffix key_name token_name key_profile token_profile environment
  local workspace_image form profile credential update generation pod pod_uid clients baseline
  local driver stage_environment="" stage_profiles="" stage_credentials=""
  set -E
  trap 'echo "::error::Claude Code credential acceptance failed: command=${BASH_COMMAND} status=$?" >&2' ERR
  workspace_image="$(kind_workspace_runtime_image)" || return $?
  KIND_CREDENTIAL_CLI_HOME="$(mktemp -d /dev/shm/codewire-kind-claude.XXXXXX)"
  trap 'cleanup_kind_credential_stage "$stage_environment" "$stage_profiles" "$stage_credentials"; rm -rf -- "$KIND_CREDENTIAL_CLI_HOME"' EXIT
  [ "$(stat -f -c %T "$KIND_CREDENTIAL_CLI_HOME")" = tmpfs ] || return 1
  suffix="${RANDOM}-${RANDOM}"
  key_name="kind-anthropic-key-$suffix"
  token_name="kind-claude-token-$suffix"
  key_profile="kind-claude-key-$suffix"
  token_profile="kind-claude-token-$suffix"
  prepare_kind_credential_cli
  kind_credential_cli org set org_contract_1
  kind_credential_cli org current | awk '
    $1 == "ID:" { id = $2; count++ }
    END { exit !(count == 1 && id == "org_contract_1") }'
  # Material only through stdin, as a user pastes it; never an argument.
  stage_credentials="$key_name $token_name"
  printf '%s' "$KIND_ANTHROPIC_API_KEY" |
    kind_credential_cli credentials --platform add anthropic --name "$key_name"
  printf '%s' "$KIND_CLAUDE_SUBSCRIPTION_TOKEN" |
    kind_credential_cli credentials --platform add claude-subscription --name "$token_name"
  kind_credential_cli credentials --platform get "$key_name" --output json | jq -e \
    --arg name "$key_name" '.[0] as $c | length == 1 and $c.name == $name
      and $c.provider == "anthropic" and $c.status == "CREDENTIAL_STATUS_ACTIVE"
      and ($c.authenticationKind // $c.authentication_kind) == "CREDENTIAL_AUTHENTICATION_KIND_API_KEY"' \
    >/dev/null
  # The subscription token is the provider's OAuth kind with a hard expiry one
  # year after it was added.
  assert_kind_credential_claude_token "$token_name" 1
  stage_profiles="$key_profile $token_profile"
  kind_credential_cli credentials --platform --profile "$key_profile" set anthropic "$key_name"
  kind_credential_cli credentials --platform --profile "$token_profile" set anthropic "$token_name"
  environment="$(kind_credential_cli env --platform create --name "$key_profile" \
    --image "$workspace_image" \
    --cpu 500 --memory 2Gi --disk 2Gi --ttl 1h --no-network --yes --output json | jq -er '.id')"
  [[ "$environment" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1
  stage_environment="$environment"
  wait_kind_credential_environment "$environment" running
  wait_kind_credential_setup_complete "$environment"
  baseline="$(kind_credential_fixture_events | jq -er \
    '[.[] | select(.event == "anthropic_response" or .event == "anthropic_rejected")] | length')"
  for form in api_key subscription_token; do
    profile="$key_profile"
    [ "$form" = api_key ] || profile="$token_profile"
    update="$(kind_credential_cli env --platform update "$environment" \
      --profile "platform:$profile" --yes --output json)"
    generation="$(jq -er '.operation_generation |
      if type == "number" and . > 0 and . == floor then .
      else error("expected a positive operation generation") end' <<<"$update")"
    wait_kind_credential_environment "$environment" running
    pod="$(wait_kind_credential_restarted_workspace "$environment" "$generation")"
    pod_uid="$(kubectl -n "$SANDBOX_NS" get pod "$pod" -o 'jsonpath={.metadata.uid}')"
    clients="$(kind_credential_managed_clients "$environment" "$pod_uid")"
    assert_kind_credential_claude_selection "$form" "$clients"
    driver="$(kind_credential_claude_stage "$pod")"
    kind_credential_claude_run "$environment" "$driver" "$form" success
    baseline="$(assert_kind_credential_anthropic_events "$baseline" "$form" 200)"
  done

  # Failure and recovery on the same bound credential, so no restart: the
  # owner replaces the token with one the provider refuses. Claude Code
  # reports the 401 and the credential stays Active; nothing marks or
  # withholds it. Replacing it with a good token restores the next session.
  printf '%s' "$KIND_CLAUDE_REFUSED_TOKEN" |
    kind_credential_cli credentials --platform rotate "$token_name"
  assert_kind_credential_claude_token "$token_name" 2
  kind_credential_claude_run "$environment" "$driver" subscription_token refused
  baseline="$(assert_kind_credential_anthropic_events "$baseline" subscription_token 401)"
  assert_kind_credential_claude_token "$token_name" 2
  printf '%s' "$KIND_CLAUDE_SUBSCRIPTION_TOKEN" |
    kind_credential_cli credentials --platform rotate "$token_name"
  assert_kind_credential_claude_token "$token_name" 3
  kind_credential_claude_run "$environment" "$driver" subscription_token success
  baseline="$(assert_kind_credential_anthropic_events "$baseline" subscription_token 200)"

  kind_credential_cli env --platform rm "$environment" --yes --output json
  wait_kind_credential_environment "$environment" destroyed
  stage_environment=""
  for profile in "$key_profile" "$token_profile"; do
    kind_credential_cli credentials --platform --profile "$profile" delete --yes
  done
  stage_profiles=""
  for credential in "$key_name" "$token_name"; do
    kind_credential_cli credentials --platform revoke "$credential" --output json
    kind_credential_cli credentials --platform delete "$credential" --yes
  done
  stage_credentials=""
  log "stock Claude Code in daemon sessions passed with an Anthropic API key and a Claude subscription token, through a provider refusal and its replacement; none reached the Sandbox"
)
