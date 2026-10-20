#!/usr/bin/env bash
# Sourced by the isolated local-platform entrypoint after its fresh login.
# shellcheck disable=SC2034 # State is consumed by the parent smoke entrypoint.

PROVIDER_ANTHROPIC_CREDENTIAL_NAME=''
PROVIDER_ANTHROPIC_CREDENTIAL_ID=''
PROVIDER_ANTHROPIC_PROFILE_NAME=''
PROVIDER_ANTHROPIC_PROFILE_ID=''
PROVIDER_ANTHROPIC_DOCUMENT=''
readonly PROVIDER_ANTHROPIC_SCRIPT=/workspace/.cw-provider-anthropic/provider-anthropic-workload.sh

prepare_provider_anthropic_identity() {
  local nonce credential_name profile_name
  nonce="$(tr -d '-' </proc/sys/kernel/random/uuid)"
  [[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || die 'cannot generate disposable Anthropic fixture names'
  credential_name="dev-anthropic-$nonce"
  profile_name="dev-anthropic-profile-$nonce"
  cw_with_timeout 30 credentials --cloud list --output json \
    >"$TMPDIR_SMOKE/provider-anthropic-credentials-before.json" || die 'cannot inspect personal credential metadata'
  cw_with_timeout 30 credentials --cloud profiles list --output json \
    >"$TMPDIR_SMOKE/provider-anthropic-profiles-before.json" || die 'cannot inspect personal profile metadata'
  jq -e --arg name "$credential_name" 'type == "array" and all(.[]; .name != $name)' \
    "$TMPDIR_SMOKE/provider-anthropic-credentials-before.json" >/dev/null || die 'disposable Anthropic credential name collision'
  jq -e --arg name "$profile_name" 'type == "array" and all(.[]; .name != $name)' \
    "$TMPDIR_SMOKE/provider-anthropic-profiles-before.json" >/dev/null || die 'disposable Anthropic profile name collision'

  PROVIDER_ANTHROPIC_CREDENTIAL_NAME="$credential_name"
  PROVIDER_ANTHROPIC_PROFILE_NAME="$profile_name"

  # Inherit the terminal so the existing CLI reads one key through its
  # echo-disabled protected prompt. Neither input nor command output is captured.
  cw_with_timeout 600 credentials --cloud add anthropic --name "$PROVIDER_ANTHROPIC_CREDENTIAL_NAME" ||
    die 'fresh owner-operated platform Anthropic enrollment failed'
  cw_with_timeout 30 credentials --cloud get "$PROVIDER_ANTHROPIC_CREDENTIAL_NAME" --output json \
    >"$TMPDIR_SMOKE/provider-anthropic-credential.json" || die 'created Anthropic metadata is unavailable'
  PROVIDER_ANTHROPIC_CREDENTIAL_ID="$(provider_ssh_metadata_id \
    "$TMPDIR_SMOKE/provider-anthropic-credential.json" "$PROVIDER_ANTHROPIC_CREDENTIAL_NAME")" ||
    die 'created Anthropic identity was not acknowledged exactly'
  jq -e --arg id "$PROVIDER_ANTHROPIC_CREDENTIAL_ID" --arg name "$PROVIDER_ANTHROPIC_CREDENTIAL_NAME" '
    type == "array" and length == 1 and .[0].id == $id and .[0].name == $name and
    .[0].provider == "anthropic" and .[0].status == "CREDENTIAL_STATUS_ACTIVE" and
    .[0].authenticationKind == "CREDENTIAL_AUTHENTICATION_KIND_API_KEY"
  ' "$TMPDIR_SMOKE/provider-anthropic-credential.json" >/dev/null || die 'created Anthropic public metadata is invalid'
  cw_with_timeout 30 credentials --cloud --profile "$PROVIDER_ANTHROPIC_PROFILE_NAME" \
    set anthropic "id:$PROVIDER_ANTHROPIC_CREDENTIAL_ID" \
    >"$TMPDIR_SMOKE/provider-anthropic-profile-set.out" 2>"$TMPDIR_SMOKE/provider-anthropic-profile-set.err" ||
    die 'cannot select the created Anthropic identity in its disposable profile'
  cw_with_timeout 30 credentials --cloud --profile "$PROVIDER_ANTHROPIC_PROFILE_NAME" get --output json \
    >"$TMPDIR_SMOKE/provider-anthropic-profile.json" || die 'created Anthropic profile metadata is unavailable'
  PROVIDER_ANTHROPIC_PROFILE_ID="$(provider_ssh_metadata_id \
    "$TMPDIR_SMOKE/provider-anthropic-profile.json" "$PROVIDER_ANTHROPIC_PROFILE_NAME")" ||
    die 'created Anthropic profile was not acknowledged exactly'
  jq -e --arg id "$PROVIDER_ANTHROPIC_CREDENTIAL_ID" 'length == 1 and .[0].revision == "1" and
    .[0].entries == [{capabilitySlot:"anthropic",credentialId:$id}]' \
    "$TMPDIR_SMOKE/provider-anthropic-profile.json" >/dev/null ||
    die 'created Anthropic profile does not select exactly the created identity'
}

prepare_provider_anthropic() {
  local encoded_workload encoded_parser install
  prepare_provider_anthropic_identity
  encoded_workload="$(base64 -w0 "$ROOT/scripts/runtime/dev/provider-anthropic-workload.sh")"
  encoded_parser="$(base64 -w0 "$ROOT/scripts/runtime/dev/provider-anthropic-output.py")"
  install="set -eu; test ! -e /workspace/.cw-provider-anthropic; mkdir -m 700 /workspace/.cw-provider-anthropic; printf %s '$encoded_workload' | base64 -d > '$PROVIDER_ANTHROPIC_SCRIPT'; printf %s '$encoded_parser' | base64 -d > /workspace/.cw-provider-anthropic/provider-anthropic-output.py; chmod 0500 '$PROVIDER_ANTHROPIC_SCRIPT' /workspace/.cw-provider-anthropic/provider-anthropic-output.py"
  PROVIDER_ANTHROPIC_DOCUMENT="$TMPDIR_SMOKE/provider-anthropic-codewire.json"
  jq -n --arg profile "platform:id:$PROVIDER_ANTHROPIC_PROFILE_ID" --arg install "$install" '
    {version:1,working_directory:"/workspace",agents:{tools:["claude-code"]},
      credentials:{profile:$profile},install_command:$install,startup_script:"/bin/true"}
  ' >"$PROVIDER_ANTHROPIC_DOCUMENT"
}

run_provider_anthropic_smoke() {
  cw_with_timeout 30 info --local "$ENV_ID" --output json \
    >"$TMPDIR_SMOKE/provider-anthropic-environment.json" 2>"$TMPDIR_SMOKE/provider-anthropic-info.err" ||
    die 'cannot inspect the local Anthropic environment binding'
  jq -e --arg id "$ENV_ID" --arg profile "platform:id:$PROVIDER_ANTHROPIC_PROFILE_ID" \
    --arg reference "user/$PROVIDER_ANTHROPIC_PROFILE_NAME" '
    .id == $id and .backend == "cloud-hypervisor" and .state == "running" and
    .cpu == 2 and .memory == "16Gi" and
    .source_selection.credentials == {profile:$profile,reference:$reference,revision:1}
  ' "$TMPDIR_SMOKE/provider-anthropic-environment.json" >/dev/null ||
    die 'local Anthropic environment did not acknowledge the exact profile revision and topology'
  if ! cw_with_timeout 180 run --no-tty -- /bin/bash "$PROVIDER_ANTHROPIC_SCRIPT" run \
      >"$TMPDIR_SMOKE/provider-anthropic-proof.out" 2>"$TMPDIR_SMOKE/provider-anthropic-proof.err"; then
    die 'bounded live Claude workload failed; raw provider output remains private inside the disposable VM'
  fi
  assert_managed_run_stderr "$TMPDIR_SMOKE/provider-anthropic-proof.err" || die 'live Claude workload returned unexpected stderr'
  cmp -s "$TMPDIR_SMOKE/provider-anthropic-proof.out" <(printf 'CW_LIVE_CLAUDE_OK\n') ||
    die 'live Claude workload omitted its exact public receipt'
  log 'live Anthropic API request validated with stock Claude in the local 2-vCPU/16-GiB VM; parent cleanup remains pending and other providers are not implied'
}

cleanup_provider_anthropic() {
  local rc=0
  cleanup_provider_anthropic_profile || rc=1
  cleanup_provider_anthropic_credential || rc=1
  [[ "$rc" == 0 ]] || log 'provider Anthropic cleanup incomplete; exact owned metadata retained in private smoke evidence'
  return "$rc"
}

cleanup_provider_anthropic_profile() {
  local rc=0 resolved
  if [[ -n "$PROVIDER_ANTHROPIC_PROFILE_NAME" ]]; then
    cw_with_timeout 30 credentials --cloud profiles list --output json \
      >"$TMPDIR_SMOKE/provider-anthropic-cleanup-profiles.json" 2>/dev/null || return 1
    jq -e 'type == "array"' "$TMPDIR_SMOKE/provider-anthropic-cleanup-profiles.json" >/dev/null || return 1
    if jq -e --arg name "$PROVIDER_ANTHROPIC_PROFILE_NAME" 'any(.[]; .name == $name)' \
        "$TMPDIR_SMOKE/provider-anthropic-cleanup-profiles.json" >/dev/null; then
      resolved="$(provider_ssh_metadata_id "$TMPDIR_SMOKE/provider-anthropic-cleanup-profiles.json" \
        "$PROVIDER_ANTHROPIC_PROFILE_NAME")" || return 1
      [[ -z "$PROVIDER_ANTHROPIC_PROFILE_ID" || "$PROVIDER_ANTHROPIC_PROFILE_ID" == "$resolved" ]] || return 1
      PROVIDER_ANTHROPIC_PROFILE_ID="$resolved"
      cw_with_timeout 30 credentials --cloud --profile "id:$PROVIDER_ANTHROPIC_PROFILE_ID" delete --yes \
        >"$TMPDIR_SMOKE/provider-anthropic-cleanup-profile.out" 2>&1 || rc=1
    fi
    cw_with_timeout 30 credentials --cloud profiles list --output json \
      >"$TMPDIR_SMOKE/provider-anthropic-cleanup-profiles.json" 2>/dev/null &&
      jq -e --arg name "$PROVIDER_ANTHROPIC_PROFILE_NAME" --arg id "$PROVIDER_ANTHROPIC_PROFILE_ID" '
        type == "array" and all(.[]; .name != $name and .id != $id)
      ' "$TMPDIR_SMOKE/provider-anthropic-cleanup-profiles.json" >/dev/null || rc=1
  fi
  return "$rc"
}

cleanup_provider_anthropic_credential() {
  local rc=0 resolved
  if [[ -n "$PROVIDER_ANTHROPIC_CREDENTIAL_NAME" ]]; then
    cw_with_timeout 30 credentials --cloud list --output json \
      >"$TMPDIR_SMOKE/provider-anthropic-cleanup-credentials.json" 2>/dev/null || return 1
    jq -e 'type == "array"' "$TMPDIR_SMOKE/provider-anthropic-cleanup-credentials.json" >/dev/null || return 1
    if jq -e --arg name "$PROVIDER_ANTHROPIC_CREDENTIAL_NAME" 'any(.[]; .name == $name)' \
        "$TMPDIR_SMOKE/provider-anthropic-cleanup-credentials.json" >/dev/null; then
      resolved="$(provider_ssh_metadata_id "$TMPDIR_SMOKE/provider-anthropic-cleanup-credentials.json" \
        "$PROVIDER_ANTHROPIC_CREDENTIAL_NAME")" || return 1
      [[ -z "$PROVIDER_ANTHROPIC_CREDENTIAL_ID" || "$PROVIDER_ANTHROPIC_CREDENTIAL_ID" == "$resolved" ]] || return 1
      PROVIDER_ANTHROPIC_CREDENTIAL_ID="$resolved"
      cw_with_timeout 30 credentials --cloud get "id:$PROVIDER_ANTHROPIC_CREDENTIAL_ID" --output json \
        >"$TMPDIR_SMOKE/provider-anthropic-cleanup-credential.json" 2>/dev/null || return 1
      jq -e --arg id "$PROVIDER_ANTHROPIC_CREDENTIAL_ID" --arg name "$PROVIDER_ANTHROPIC_CREDENTIAL_NAME" '
        type == "array" and length == 1 and .[0].id == $id and .[0].name == $name and
        .[0].provider == "anthropic" and
        .[0].authenticationKind == "CREDENTIAL_AUTHENTICATION_KIND_API_KEY" and
        (.[0].status == "CREDENTIAL_STATUS_ACTIVE" or .[0].status == "CREDENTIAL_STATUS_REVOKED")
      ' "$TMPDIR_SMOKE/provider-anthropic-cleanup-credential.json" >/dev/null || return 1
      if ! jq -e 'length == 1 and .[0].status == "CREDENTIAL_STATUS_REVOKED"' \
          "$TMPDIR_SMOKE/provider-anthropic-cleanup-credential.json" >/dev/null; then
        cw_with_timeout 30 credentials --cloud revoke "id:$PROVIDER_ANTHROPIC_CREDENTIAL_ID" \
          >"$TMPDIR_SMOKE/provider-anthropic-cleanup-revoke.out" 2>&1 || rc=1
      fi
      cw_with_timeout 30 credentials --cloud delete "id:$PROVIDER_ANTHROPIC_CREDENTIAL_ID" --yes \
        >"$TMPDIR_SMOKE/provider-anthropic-cleanup-credential.out" 2>&1 || rc=1
    fi
    cw_with_timeout 30 credentials --cloud list --output json \
      >"$TMPDIR_SMOKE/provider-anthropic-cleanup-credentials.json" 2>/dev/null &&
      jq -e --arg name "$PROVIDER_ANTHROPIC_CREDENTIAL_NAME" --arg id "$PROVIDER_ANTHROPIC_CREDENTIAL_ID" '
        type == "array" and all(.[]; .name != $name and .id != $id)
      ' "$TMPDIR_SMOKE/provider-anthropic-cleanup-credentials.json" >/dev/null || rc=1
  fi
  return "$rc"
}
