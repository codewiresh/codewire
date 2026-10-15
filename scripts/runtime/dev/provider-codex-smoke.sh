#!/usr/bin/env bash
# Sourced by the isolated local-platform entrypoint after its fresh login.
# shellcheck disable=SC2034 # State is consumed by the parent smoke entrypoint.

PROVIDER_CODEX_CREDENTIAL_NAME=''
PROVIDER_CODEX_CREDENTIAL_ID=''
PROVIDER_CODEX_PROFILE_NAME=''
PROVIDER_CODEX_PROFILE_ID=''
PROVIDER_CODEX_DOCUMENT=''
readonly PROVIDER_CODEX_SCRIPT=/workspace/.cw-provider-codex/provider-codex-workload.sh

prepare_provider_codex_identity() {
  local nonce credential_name profile_name
  nonce="$(tr -d '-' </proc/sys/kernel/random/uuid)"
  [[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || die 'cannot generate disposable Codex fixture names'
  credential_name="dev-codex-$nonce"
  profile_name="dev-codex-profile-$nonce"
  cw_with_timeout 30 credentials --cloud list --output json \
    >"$TMPDIR_SMOKE/provider-codex-credentials-before.json" || die 'cannot inspect personal credential metadata'
  cw_with_timeout 30 credentials --cloud profiles list --output json \
    >"$TMPDIR_SMOKE/provider-codex-profiles-before.json" || die 'cannot inspect personal profile metadata'
  jq -e --arg name "$credential_name" 'type == "array" and all(.[]; .name != $name)' \
    "$TMPDIR_SMOKE/provider-codex-credentials-before.json" >/dev/null || die 'disposable Codex credential name collision'
  jq -e --arg name "$profile_name" 'type == "array" and all(.[]; .name != $name)' \
    "$TMPDIR_SMOKE/provider-codex-profiles-before.json" >/dev/null || die 'disposable Codex profile name collision'

  # Cleanup authority begins only after both unique names were confirmed absent.
  PROVIDER_CODEX_CREDENTIAL_NAME="$credential_name"
  PROVIDER_CODEX_PROFILE_NAME="$profile_name"

  # Intentionally inherit the terminal. The device URL/code and owner approval
  # must remain visible and must never be captured in smoke artifacts.
  cw_with_timeout 600 credentials --cloud connect codex --name "$PROVIDER_CODEX_CREDENTIAL_NAME" ||
    die 'fresh owner-operated platform Codex enrollment failed'
  cw_with_timeout 30 credentials --cloud get "$PROVIDER_CODEX_CREDENTIAL_NAME" --output json \
    >"$TMPDIR_SMOKE/provider-codex-credential.json" || die 'created Codex metadata is unavailable'
  PROVIDER_CODEX_CREDENTIAL_ID="$(provider_ssh_metadata_id \
    "$TMPDIR_SMOKE/provider-codex-credential.json" "$PROVIDER_CODEX_CREDENTIAL_NAME")" ||
    die 'created Codex identity was not acknowledged exactly'
  jq -e --arg id "$PROVIDER_CODEX_CREDENTIAL_ID" --arg name "$PROVIDER_CODEX_CREDENTIAL_NAME" '
    type == "array" and length == 1 and .[0].id == $id and .[0].name == $name and
    .[0].provider == "openai" and .[0].status == "CREDENTIAL_STATUS_ACTIVE" and
    .[0].authenticationKind == "CREDENTIAL_AUTHENTICATION_KIND_OAUTH"
  ' "$TMPDIR_SMOKE/provider-codex-credential.json" >/dev/null || die 'created Codex public metadata is invalid'
  cw_with_timeout 30 credentials --cloud --profile "$PROVIDER_CODEX_PROFILE_NAME" \
    set codex "id:$PROVIDER_CODEX_CREDENTIAL_ID" \
    >"$TMPDIR_SMOKE/provider-codex-profile-set.out" 2>"$TMPDIR_SMOKE/provider-codex-profile-set.err" ||
    die 'cannot select the created Codex identity in its disposable profile'
  cw_with_timeout 30 credentials --cloud --profile "$PROVIDER_CODEX_PROFILE_NAME" get --output json \
    >"$TMPDIR_SMOKE/provider-codex-profile.json" || die 'created Codex profile metadata is unavailable'
  PROVIDER_CODEX_PROFILE_ID="$(provider_ssh_metadata_id \
    "$TMPDIR_SMOKE/provider-codex-profile.json" "$PROVIDER_CODEX_PROFILE_NAME")" ||
    die 'created Codex profile was not acknowledged exactly'
  jq -e --arg id "$PROVIDER_CODEX_CREDENTIAL_ID" 'length == 1 and .[0].revision == "1" and
    .[0].entries == [{capabilitySlot:"codex",credentialId:$id}]' \
    "$TMPDIR_SMOKE/provider-codex-profile.json" >/dev/null ||
    die 'created Codex profile does not select exactly the created identity'
}

prepare_provider_codex() {
  local encoded_workload encoded_parser install
  prepare_provider_codex_identity
  encoded_workload="$(base64 -w0 "$ROOT/scripts/runtime/dev/provider-codex-workload.sh")"
  encoded_parser="$(base64 -w0 "$ROOT/scripts/runtime/dev/provider-codex-output.py")"
  install="set -eu; test ! -e /workspace/.cw-provider-codex; mkdir -m 700 /workspace/.cw-provider-codex; printf %s '$encoded_workload' | base64 -d > '$PROVIDER_CODEX_SCRIPT'; printf %s '$encoded_parser' | base64 -d > /workspace/.cw-provider-codex/provider-codex-output.py; chmod 0500 '$PROVIDER_CODEX_SCRIPT' /workspace/.cw-provider-codex/provider-codex-output.py"
  PROVIDER_CODEX_DOCUMENT="$TMPDIR_SMOKE/provider-codex-codewire.json"
  jq -n --arg profile "platform:id:$PROVIDER_CODEX_PROFILE_ID" --arg install "$install" '
    {version:1,working_directory:"/workspace",agents:{tools:["codex"]},
      credentials:{profile:$profile},install_command:$install,startup_script:"/bin/true"}
  ' >"$PROVIDER_CODEX_DOCUMENT"
}

run_provider_codex_smoke() {
  cw_with_timeout 30 env info --local "$ENV_ID" --output json \
    >"$TMPDIR_SMOKE/provider-codex-environment.json" 2>"$TMPDIR_SMOKE/provider-codex-info.err" ||
    die 'cannot inspect the local Codex environment binding'
  jq -e --arg id "$ENV_ID" --arg profile "platform:id:$PROVIDER_CODEX_PROFILE_ID" \
    --arg reference "user/$PROVIDER_CODEX_PROFILE_NAME" '
    .id == $id and .backend == "cloud-hypervisor" and .state == "running" and
    .cpu == 2 and .memory == "16Gi" and
    .source_selection.credentials == {profile:$profile,reference:$reference,revision:1}
  ' "$TMPDIR_SMOKE/provider-codex-environment.json" >/dev/null ||
    die 'local Codex environment did not acknowledge the exact profile revision and topology'
  if ! cw_with_timeout 180 run --no-tty -- /bin/bash "$PROVIDER_CODEX_SCRIPT" run \
      >"$TMPDIR_SMOKE/provider-codex-proof.out" 2>"$TMPDIR_SMOKE/provider-codex-proof.err"; then
    die 'bounded live Codex workload failed; raw provider output remains private inside the disposable VM'
  fi
  assert_managed_run_stderr "$TMPDIR_SMOKE/provider-codex-proof.err" || die 'live Codex workload returned unexpected stderr'
  cmp -s "$TMPDIR_SMOKE/provider-codex-proof.out" <(printf 'CW_LIVE_CODEX_OK\n') ||
    die 'live Codex workload omitted its exact public receipt'
  log 'live platform Codex OAuth request validated in the local 2-vCPU/16-GiB VM; parent cleanup remains pending and other providers are not implied'
}

cleanup_provider_codex() {
  local rc=0
  cleanup_provider_codex_profile || rc=1
  cleanup_provider_codex_credential || rc=1
  [[ "$rc" == 0 ]] || log 'provider Codex cleanup incomplete; exact owned metadata retained in private smoke evidence'
  return "$rc"
}

cleanup_provider_codex_profile() {
  local rc=0 resolved
  if [[ -n "$PROVIDER_CODEX_PROFILE_NAME" ]]; then
    cw_with_timeout 30 credentials --cloud profiles list --output json \
      >"$TMPDIR_SMOKE/provider-codex-cleanup-profiles.json" 2>/dev/null || return 1
    jq -e 'type == "array"' "$TMPDIR_SMOKE/provider-codex-cleanup-profiles.json" >/dev/null || return 1
    if jq -e --arg name "$PROVIDER_CODEX_PROFILE_NAME" 'any(.[]; .name == $name)' \
        "$TMPDIR_SMOKE/provider-codex-cleanup-profiles.json" >/dev/null; then
      resolved="$(provider_ssh_metadata_id "$TMPDIR_SMOKE/provider-codex-cleanup-profiles.json" \
        "$PROVIDER_CODEX_PROFILE_NAME")" || return 1
      [[ -z "$PROVIDER_CODEX_PROFILE_ID" || "$PROVIDER_CODEX_PROFILE_ID" == "$resolved" ]] || return 1
      PROVIDER_CODEX_PROFILE_ID="$resolved"
      cw_with_timeout 30 credentials --cloud --profile "id:$PROVIDER_CODEX_PROFILE_ID" delete --yes \
        >"$TMPDIR_SMOKE/provider-codex-cleanup-profile.out" 2>&1 || rc=1
    fi
    cw_with_timeout 30 credentials --cloud profiles list --output json \
      >"$TMPDIR_SMOKE/provider-codex-cleanup-profiles.json" 2>/dev/null &&
      jq -e --arg name "$PROVIDER_CODEX_PROFILE_NAME" --arg id "$PROVIDER_CODEX_PROFILE_ID" '
        type == "array" and all(.[]; .name != $name and .id != $id)
      ' "$TMPDIR_SMOKE/provider-codex-cleanup-profiles.json" >/dev/null || rc=1
  fi
  return "$rc"
}

cleanup_provider_codex_credential() {
  local rc=0 resolved
  if [[ -n "$PROVIDER_CODEX_CREDENTIAL_NAME" ]]; then
    cw_with_timeout 30 credentials --cloud list --output json \
      >"$TMPDIR_SMOKE/provider-codex-cleanup-credentials.json" 2>/dev/null || return 1
    jq -e 'type == "array"' "$TMPDIR_SMOKE/provider-codex-cleanup-credentials.json" >/dev/null || return 1
    if jq -e --arg name "$PROVIDER_CODEX_CREDENTIAL_NAME" 'any(.[]; .name == $name)' \
        "$TMPDIR_SMOKE/provider-codex-cleanup-credentials.json" >/dev/null; then
      resolved="$(provider_ssh_metadata_id "$TMPDIR_SMOKE/provider-codex-cleanup-credentials.json" \
        "$PROVIDER_CODEX_CREDENTIAL_NAME")" || return 1
      [[ -z "$PROVIDER_CODEX_CREDENTIAL_ID" || "$PROVIDER_CODEX_CREDENTIAL_ID" == "$resolved" ]] || return 1
      PROVIDER_CODEX_CREDENTIAL_ID="$resolved"
      cw_with_timeout 30 credentials --cloud get "id:$PROVIDER_CODEX_CREDENTIAL_ID" --output json \
        >"$TMPDIR_SMOKE/provider-codex-cleanup-credential.json" 2>/dev/null || return 1
      jq -e --arg id "$PROVIDER_CODEX_CREDENTIAL_ID" --arg name "$PROVIDER_CODEX_CREDENTIAL_NAME" '
        type == "array" and length == 1 and .[0].id == $id and .[0].name == $name and
        .[0].provider == "openai" and
        .[0].authenticationKind == "CREDENTIAL_AUTHENTICATION_KIND_OAUTH" and
        (.[0].status == "CREDENTIAL_STATUS_ACTIVE" or .[0].status == "CREDENTIAL_STATUS_REVOKED")
      ' "$TMPDIR_SMOKE/provider-codex-cleanup-credential.json" >/dev/null || return 1
      if ! jq -e 'length == 1 and .[0].status == "CREDENTIAL_STATUS_REVOKED"' \
          "$TMPDIR_SMOKE/provider-codex-cleanup-credential.json" >/dev/null; then
        cw_with_timeout 30 credentials --cloud revoke "id:$PROVIDER_CODEX_CREDENTIAL_ID" \
          >"$TMPDIR_SMOKE/provider-codex-cleanup-revoke.out" 2>&1 || rc=1
      fi
      cw_with_timeout 30 credentials --cloud delete "id:$PROVIDER_CODEX_CREDENTIAL_ID" --yes \
        >"$TMPDIR_SMOKE/provider-codex-cleanup-credential.out" 2>&1 || rc=1
    fi
    cw_with_timeout 30 credentials --cloud list --output json \
      >"$TMPDIR_SMOKE/provider-codex-cleanup-credentials.json" 2>/dev/null &&
      jq -e --arg name "$PROVIDER_CODEX_CREDENTIAL_NAME" --arg id "$PROVIDER_CODEX_CREDENTIAL_ID" '
        type == "array" and all(.[]; .name != $name and .id != $id)
      ' "$TMPDIR_SMOKE/provider-codex-cleanup-credentials.json" >/dev/null || rc=1
  fi
  return "$rc"
}
