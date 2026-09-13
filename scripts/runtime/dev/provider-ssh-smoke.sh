#!/usr/bin/env bash
# Sourced by the existing Dev commodity smoke; never reads credentials itself.
# This opt-in, owner-operated phase uses normal OAuth/public product commands.
# shellcheck disable=SC2034 # State is consumed by the parent smoke entrypoint.

PROVIDER_SSH_CREDENTIAL_NAME=''
PROVIDER_SSH_CREDENTIAL_ID=''
PROVIDER_SSH_PROFILE_NAME=''
PROVIDER_SSH_PROFILE_ID=''
PROVIDER_SSH_DOCUMENT=''
PROVIDER_SSH_CREATE_ATTEMPTED=0
readonly PROVIDER_SSH_SCRIPT=/workspace/.cw-provider-ssh/stock-ssh-workload.sh

provider_ssh_selected() {
  local phase
  for phase in "${SMOKE_ONLY_PHASES[@]}"; do
    [[ "$phase" != provider-ssh ]] || return 0
  done
  return 1
}

validate_provider_ssh_options() {
  [[ "$SMOKE_AUTH_MODE" == admin-oidc &&
     ( -n "$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR" || -n "$DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE" ) &&
     -n "$EXPECTED_CODEWIRE_ADMIN_EMAIL" ]] ||
    die 'provider-ssh requires explicit owner-operated --admin-oidc, an exact login directory and expected identity'
  validate_dev_smoke_browser_auth
  [[ -z "${CODEWIRE_API_KEY:-}" && -z "${CODEWIRE_DEV_SMOKE_API_KEY:-}" &&
     "$ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE" == 0 ]] ||
    die 'provider-ssh never substitutes an organization API key for personal credential authority'
  [[ "$ALLOW_NON_DEV" == 0 && -n "$EXPECTED_CODEWIRE_DEV_SERVER_URL" &&
     "$CODEWIRE_SERVER_URL" == "$EXPECTED_CODEWIRE_DEV_SERVER_URL" ]] ||
    die 'provider-ssh requires the exact configured Dev endpoint'
  [[ -z "$SMOKE_EXISTING_ENV_ID" && "$SMOKE_KEEP_ENV" == 0 && "$SMOKE_SKIP_KUBE" == 0 &&
     -n "$SANDBOX_NAMESPACE" ]] ||
    die 'provider-ssh requires a fresh disposable environment and Kubernetes checks'
  ! application_secrets_selected ||
    die 'provider-ssh and application-secrets use distinct existing authentication modes; run them separately'
}

provider_ssh_metadata_id() {
  local file="$1" name="$2"
  jq -er --arg name "$name" '
    if type != "array" then error("expected metadata array") else . end |
    [.[] | select(.name == $name)] |
    if length == 1 then .[0].id else error("expected one exact owned identity") end |
    select(type == "string" and . != "00000000-0000-0000-0000-000000000000" and
      test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))
  ' "$file"
}

prepare_provider_ssh_identity() {
  local nonce credential_name profile_name public_key
  nonce="$(tr -d '-' </proc/sys/kernel/random/uuid)"
  [[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || die 'cannot generate disposable SSH fixture names'
  cw_with_timeout 30 env --platform list --all --output json >"$TMPDIR_SMOKE/provider-ssh-environments-before.json" ||
    die 'cannot inspect Dev environment ownership before SSH smoke'
  jq -e --arg name "$SMOKE_NAME" 'type == "array" and all(.[]; .name != $name)' \
    "$TMPDIR_SMOKE/provider-ssh-environments-before.json" >/dev/null ||
    die 'provider SSH smoke environment name is already in use'
  credential_name="dev-ssh-$nonce"
  profile_name="dev-ssh-profile-$nonce"
  cw_with_timeout 30 credentials --platform list --output json >"$TMPDIR_SMOKE/provider-ssh-credentials-before.json" ||
    die 'cannot inspect personal credential metadata'
  cw_with_timeout 30 credentials --platform profiles list --output json \
    >"$TMPDIR_SMOKE/provider-ssh-profiles-before.json" || die 'cannot inspect personal profile metadata'
  jq -e --arg name "$credential_name" 'type == "array" and all(.[]; .name != $name)' \
    "$TMPDIR_SMOKE/provider-ssh-credentials-before.json" >/dev/null || die 'disposable SSH credential name collision'
  jq -e --arg name "$profile_name" 'type == "array" and all(.[]; .name != $name)' \
    "$TMPDIR_SMOKE/provider-ssh-profiles-before.json" >/dev/null || die 'disposable SSH profile name collision'

  # Cleanup authority starts only after both names have been proven unused.
  PROVIDER_SSH_CREDENTIAL_NAME="$credential_name"
  PROVIDER_SSH_PROFILE_NAME="$profile_name"

  cw_with_timeout 60 credentials --platform generate ssh --name "$PROVIDER_SSH_CREDENTIAL_NAME" \
    >"$TMPDIR_SMOKE/provider-ssh-generate.out" 2>"$TMPDIR_SMOKE/provider-ssh-generate.err" ||
    die 'normal platform SSH generation failed; no private key was imported'
  cw_with_timeout 30 credentials --platform get "$PROVIDER_SSH_CREDENTIAL_NAME" --output json \
    >"$TMPDIR_SMOKE/provider-ssh-credential.json" || die 'generated SSH metadata is unavailable'
  PROVIDER_SSH_CREDENTIAL_ID="$(provider_ssh_metadata_id "$TMPDIR_SMOKE/provider-ssh-credential.json" "$PROVIDER_SSH_CREDENTIAL_NAME")" ||
    die 'generated SSH identity was not acknowledged exactly'
  public_key="$(jq -er 'select(length == 1) | .[0] |
    select(.provider == "ssh" and .status == "CREDENTIAL_STATUS_ACTIVE" and
      .authenticationKind == "CREDENTIAL_AUTHENTICATION_KIND_SSH_KEY") |
    .sshPublicKey.openssh | select(test("^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$"))' \
    "$TMPDIR_SMOKE/provider-ssh-credential.json")" || die 'generated SSH public metadata is invalid'
  cw_with_timeout 30 credentials --platform --profile "$PROVIDER_SSH_PROFILE_NAME" set ssh "id:$PROVIDER_SSH_CREDENTIAL_ID" \
    >"$TMPDIR_SMOKE/provider-ssh-profile-set.out" 2>"$TMPDIR_SMOKE/provider-ssh-profile-set.err" ||
    die 'cannot select generated SSH identity in its disposable profile'
  cw_with_timeout 30 credentials --platform --profile "$PROVIDER_SSH_PROFILE_NAME" get --output json \
    >"$TMPDIR_SMOKE/provider-ssh-profile.json" || die 'created profile metadata is unavailable'
  PROVIDER_SSH_PROFILE_ID="$(provider_ssh_metadata_id "$TMPDIR_SMOKE/provider-ssh-profile.json" "$PROVIDER_SSH_PROFILE_NAME")" ||
    die 'created profile identity was not acknowledged exactly'
  jq -e --arg id "$PROVIDER_SSH_CREDENTIAL_ID" 'length == 1 and .[0].revision == "1" and
    .[0].entries == [{capabilitySlot:"ssh",credentialId:$id}]' \
    "$TMPDIR_SMOKE/provider-ssh-profile.json" >/dev/null || die 'created SSH profile does not select exactly the generated identity'
}

prepare_provider_ssh() {
  local public_key encoded_fixture encoded_key install startup
  prepare_provider_ssh_identity
  public_key="$(jq -er '.[0].sshPublicKey.openssh' "$TMPDIR_SMOKE/provider-ssh-credential.json")"

  # Both embedded inputs are public: the checked-in fixture and selected public
  # key. The fixture generates its synthetic server host key inside the guest.
  encoded_fixture="$(base64 -w0 "$ROOT/scripts/ci/verify/stock-ssh-workload.sh")"
  encoded_key="$(printf '%s\n' "$public_key" | base64 -w0)"
  install="set -eu; test ! -e /workspace/.cw-provider-ssh; mkdir -m 700 /workspace/.cw-provider-ssh; printf %s '$encoded_fixture' | base64 -d > '$PROVIDER_SSH_SCRIPT'; printf %s '$encoded_key' | base64 -d > /workspace/.cw-provider-ssh/selected.pub; /bin/bash '$PROVIDER_SSH_SCRIPT' install /workspace/.cw-provider-ssh/selected.pub"
  startup="/bin/bash '$PROVIDER_SSH_SCRIPT' startup"
  PROVIDER_SSH_DOCUMENT="$TMPDIR_SMOKE/provider-ssh-codewire.json"
  jq -n --arg profile "platform:id:$PROVIDER_SSH_PROFILE_ID" --arg install "$install" --arg startup "$startup" \
    '{version:1,working_directory:"/workspace",credentials:{profile:$profile},install_command:$install,startup_script:$startup}' \
    >"$PROVIDER_SSH_DOCUMENT"
}

run_provider_ssh_smoke() {
  run_kube_assertions
  wait_for_cw_run
  cw_with_timeout 30 env --platform info "$ENV_ID" --output json \
    >"$TMPDIR_SMOKE/provider-ssh-environment.json" 2>"$TMPDIR_SMOKE/provider-ssh-info.err" ||
    die 'cannot inspect the SSH environment binding'
  jq -e --arg id "$ENV_ID" --arg profile "platform:id:$PROVIDER_SSH_PROFILE_ID" '
    .id == $id and .source_selection.credentials.profile == $profile and
    .source_selection.profile_revision == 1
  ' "$TMPDIR_SMOKE/provider-ssh-environment.json" >/dev/null ||
    die 'SSH environment did not acknowledge the exact selected profile and revision'
  # Host trust comes from the authenticated managed execution channel, never
  # from an unauthenticated first SSH connection or ssh-keyscan.
  cw_with_timeout 30 run --no-tty "$ENV_ID" -- /bin/bash "$PROVIDER_SSH_SCRIPT" public-host-key \
    >"$TMPDIR_SMOKE/provider-ssh-host-key" 2>"$TMPDIR_SMOKE/provider-ssh-host-key.err" ||
    die 'cannot obtain fixture host trust through authenticated execution'
  local host_key
  host_key="$(cat "$TMPDIR_SMOKE/provider-ssh-host-key")"
  [[ "$host_key" =~ ^\[127\.0\.0\.1\]:22222\ ssh-ed25519\ [A-Za-z0-9+/]+={0,2}$ ]] ||
    die 'SSH fixture returned invalid exact loopback host trust'
  if ! cw_with_timeout "$SMOKE_EXEC_TIMEOUT" run --no-tty "$ENV_ID" -- \
      /bin/bash "$PROVIDER_SSH_SCRIPT" prove "$host_key" \
      >"$TMPDIR_SMOKE/provider-ssh-proof.out" 2>"$TMPDIR_SMOKE/provider-ssh-proof.err"; then
    # Preserve the synthetic loopback server's private evidence before normal
    # cleanup removes the environment. It contains public fixture metadata and
    # server diagnostics only, never provider private key material.
    cw_with_timeout 30 run --no-tty "$ENV_ID" -- \
      /bin/cat /workspace/.cw-ssh-smoke/sshd.log \
      >"$TMPDIR_SMOKE/provider-ssh-sshd.log" 2>"$TMPDIR_SMOKE/provider-ssh-sshd-collect.err" || true
    chmod 0600 "$TMPDIR_SMOKE/provider-ssh-sshd.log" 2>/dev/null || true
    die 'placed platform SSH/SCP/SFTP/Git protected-route proof failed'
  fi
  grep -qx stock-ssh-workload-proved "$TMPDIR_SMOKE/provider-ssh-proof.out" ||
    die 'placed stock-client proof omitted its completion marker'
  # Admit this workload while the selected key is active. After revocation,
  # ordinary file upload triggers a fresh SSH connection from that same
  # workload. A new managed launch must be denied, not used as the signer test.
  cw_with_timeout 30 run --no-tty --detach --output json "$ENV_ID" -- \
    /bin/bash "$PROVIDER_SSH_SCRIPT" wait-revoked "$host_key" \
    >"$TMPDIR_SMOKE/provider-ssh-waiter.json" || die 'cannot admit the revocation probe workload'
  local session_id
  session_id="$(jq -er 'select(.state == "Running") | .session_id |
    select(type == "string" and length > 0)' "$TMPDIR_SMOKE/provider-ssh-waiter.json")" ||
    die 'revocation probe workload was not admitted before revocation'
  wait_until 'admitted SSH revocation probe ready' "$(( $(seconds_now) + 30 ))" \
    provider_ssh_waiter_ready "$session_id"
  cw_with_timeout 30 credentials --platform revoke "id:$PROVIDER_SSH_CREDENTIAL_ID" --output json \
    >"$TMPDIR_SMOKE/provider-ssh-revoked.json" || die 'cannot revoke the exact synthetic SSH credential'
  jq -e --arg id "$PROVIDER_SSH_CREDENTIAL_ID" 'length == 1 and .[0].id == $id and
    .[0].status == "CREDENTIAL_STATUS_REVOKED" and .[0].revocationGeneration == "2"' \
    "$TMPDIR_SMOKE/provider-ssh-revoked.json" >/dev/null || die 'SSH revocation acknowledgement drifted'
  printf 'revoked\n' >"$TMPDIR_SMOKE/provider-ssh-revoked-trigger"
  cw_with_timeout 30 env --platform cp "$TMPDIR_SMOKE/provider-ssh-revoked-trigger" \
    "$ENV_ID:/workspace/.cw-ssh-smoke/revoked-trigger" \
    >"$TMPDIR_SMOKE/provider-ssh-trigger.out" 2>"$TMPDIR_SMOKE/provider-ssh-trigger.err" ||
    die 'cannot signal the already-admitted probe through the normal file API'
  wait_until 'fresh SSH denial in admitted workload' "$(( $(seconds_now) + 30 ))" \
    provider_ssh_waiter_complete "$session_id"
  cw_with_timeout 30 logs "$ENV_ID" "$session_id" --raw \
    >"$TMPDIR_SMOKE/provider-ssh-denied.out" || die 'cannot inspect exact revocation probe output'
  grep -qx stock-ssh-workload-revoked "$TMPDIR_SMOKE/provider-ssh-denied.out" ||
    die 'fresh SSH denial omitted its completion marker'
  cw_with_timeout 30 run --no-tty --detach --output json "$ENV_ID" -- /bin/true \
    >"$TMPDIR_SMOKE/provider-ssh-new-launch.json" || die 'new-launch denial omitted its session acknowledgement'
  jq -e '.state == "Failed" and .exit_code == null and
    .status_message == "environment launch denied or expired"' \
    "$TMPDIR_SMOKE/provider-ssh-new-launch.json" >/dev/null ||
    die 'new managed workload was not denied by the revoked profile'
  log 'placed platform SSH/SCP/SFTP/Git and fresh revocation denial passed; separate network/initial-checkout proof is not implied'
}

provider_ssh_waiter_ready() {
  cw_with_timeout 10 logs "$ENV_ID" "$1" --raw >"$TMPDIR_SMOKE/provider-ssh-waiter.out" 2>/dev/null &&
    grep -qx stock-ssh-workload-awaiting-revocation "$TMPDIR_SMOKE/provider-ssh-waiter.out"
}

provider_ssh_waiter_complete() {
  cw_with_timeout 10 list "$ENV_ID" --output json >"$TMPDIR_SMOKE/provider-ssh-sessions.json" 2>/dev/null &&
    jq -e --arg id "$1" '[.[] | select(.session_id == $id)] |
      length == 1 and .[0].state == "Exited" and .[0].exit_code == 0' \
      "$TMPDIR_SMOKE/provider-ssh-sessions.json" >/dev/null
}

cleanup_provider_ssh() {
  local rc=0 deadline status
  if [[ -z "$ENV_ID" && "$PROVIDER_SSH_CREATE_ATTEMPTED" == 1 ]]; then
    cw_with_timeout 30 env --platform list --all --output json >"$TMPDIR_SMOKE/provider-ssh-cleanup-environments.json" 2>/dev/null &&
      ENV_ID="$(provider_ssh_metadata_id "$TMPDIR_SMOKE/provider-ssh-cleanup-environments.json" "$SMOKE_NAME")" || rc=1
  fi
  if [[ -n "$ENV_ID" ]]; then
    cw_with_timeout 60 env --platform rm --yes "$ENV_ID" >"$TMPDIR_SMOKE/provider-ssh-cleanup-env.out" 2>&1 || rc=1
    deadline=$(( $(seconds_now) + SMOKE_TIMEOUT_SECONDS ))
    while :; do
      if application_environment_destroyed; then break; else status=$?; fi
      if [[ "$status" != 1 ]] || (( $(seconds_now) >= deadline )); then rc=1; break; fi
      sleep 5
    done
  fi
  # A failed profile cleanup must not skip revoking the independently owned
  # key. Each surface keeps its own exact-name/exact-ID ownership checks.
  cleanup_provider_ssh_profile || rc=1
  cleanup_provider_ssh_credential || rc=1
  [[ "$rc" == 0 ]] || log 'provider SSH cleanup incomplete; exact owned metadata retained in private smoke evidence'
  return "$rc"
}

cleanup_provider_ssh_profile() {
  local rc=0 resolved
  # A lost publication response can still have created the unique named object.
  # Resolve that exact prechecked name; never delete an ambiguous identity.
  if [[ -n "$PROVIDER_SSH_PROFILE_NAME" ]]; then
    cw_with_timeout 30 credentials --platform profiles list --output json \
      >"$TMPDIR_SMOKE/provider-ssh-cleanup-profiles.json" 2>/dev/null || return 1
    jq -e 'type == "array"' "$TMPDIR_SMOKE/provider-ssh-cleanup-profiles.json" >/dev/null || return 1
    if jq -e --arg name "$PROVIDER_SSH_PROFILE_NAME" 'any(.[]; .name == $name)' \
        "$TMPDIR_SMOKE/provider-ssh-cleanup-profiles.json" >/dev/null; then
      resolved="$(provider_ssh_metadata_id "$TMPDIR_SMOKE/provider-ssh-cleanup-profiles.json" "$PROVIDER_SSH_PROFILE_NAME")" || return 1
      [[ -z "$PROVIDER_SSH_PROFILE_ID" || "$PROVIDER_SSH_PROFILE_ID" == "$resolved" ]] || return 1
      PROVIDER_SSH_PROFILE_ID="$resolved"
      cw_with_timeout 30 credentials --platform --profile "id:$PROVIDER_SSH_PROFILE_ID" delete --yes \
        >"$TMPDIR_SMOKE/provider-ssh-cleanup-profile.out" 2>&1 || rc=1
    fi
    cw_with_timeout 30 credentials --platform profiles list --output json \
      >"$TMPDIR_SMOKE/provider-ssh-cleanup-profiles.json" 2>/dev/null &&
      jq -e --arg name "$PROVIDER_SSH_PROFILE_NAME" --arg id "$PROVIDER_SSH_PROFILE_ID" \
        'type == "array" and all(.[]; .name != $name and .id != $id)' \
        "$TMPDIR_SMOKE/provider-ssh-cleanup-profiles.json" >/dev/null || rc=1
  fi
  return "$rc"
}

cleanup_provider_ssh_credential() {
  local rc=0 resolved
  if [[ -n "$PROVIDER_SSH_CREDENTIAL_NAME" ]]; then
    cw_with_timeout 30 credentials --platform list --output json >"$TMPDIR_SMOKE/provider-ssh-cleanup-credentials.json" 2>/dev/null || return 1
    jq -e 'type == "array"' "$TMPDIR_SMOKE/provider-ssh-cleanup-credentials.json" >/dev/null || return 1
    if jq -e --arg name "$PROVIDER_SSH_CREDENTIAL_NAME" 'any(.[]; .name == $name)' \
        "$TMPDIR_SMOKE/provider-ssh-cleanup-credentials.json" >/dev/null; then
      resolved="$(provider_ssh_metadata_id "$TMPDIR_SMOKE/provider-ssh-cleanup-credentials.json" "$PROVIDER_SSH_CREDENTIAL_NAME")" || return 1
      [[ -z "$PROVIDER_SSH_CREDENTIAL_ID" || "$PROVIDER_SSH_CREDENTIAL_ID" == "$resolved" ]] || return 1
      PROVIDER_SSH_CREDENTIAL_ID="$resolved"
      cw_with_timeout 30 credentials --platform get "id:$PROVIDER_SSH_CREDENTIAL_ID" --output json \
        >"$TMPDIR_SMOKE/provider-ssh-cleanup-credential.json" 2>/dev/null || return 1
      jq -e --arg id "$PROVIDER_SSH_CREDENTIAL_ID" --arg name "$PROVIDER_SSH_CREDENTIAL_NAME" \
        'type == "array" and length == 1 and .[0].id == $id and .[0].name == $name and
          (.[0].status == "CREDENTIAL_STATUS_ACTIVE" or .[0].status == "CREDENTIAL_STATUS_REVOKED")' \
        "$TMPDIR_SMOKE/provider-ssh-cleanup-credential.json" >/dev/null || return 1
      if ! jq -e 'length == 1 and .[0].status == "CREDENTIAL_STATUS_REVOKED"' \
          "$TMPDIR_SMOKE/provider-ssh-cleanup-credential.json" >/dev/null; then
        cw_with_timeout 30 credentials --platform revoke "id:$PROVIDER_SSH_CREDENTIAL_ID" \
          >"$TMPDIR_SMOKE/provider-ssh-cleanup-revoke.out" 2>&1 || rc=1
      fi
      cw_with_timeout 30 credentials --platform delete "id:$PROVIDER_SSH_CREDENTIAL_ID" --yes \
        >"$TMPDIR_SMOKE/provider-ssh-cleanup-key.out" 2>&1 || rc=1
    fi
    cw_with_timeout 30 credentials --platform list --output json >"$TMPDIR_SMOKE/provider-ssh-cleanup-credentials.json" 2>/dev/null &&
      jq -e --arg name "$PROVIDER_SSH_CREDENTIAL_NAME" --arg id "$PROVIDER_SSH_CREDENTIAL_ID" \
        'type == "array" and all(.[]; .name != $name and .id != $id)' \
        "$TMPDIR_SMOKE/provider-ssh-cleanup-credentials.json" >/dev/null || rc=1
  fi
  return "$rc"
}
