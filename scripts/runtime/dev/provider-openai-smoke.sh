#!/usr/bin/env bash
# Sourced by the isolated local-platform entrypoint after its fresh login.
# shellcheck disable=SC2034 # State is consumed by the parent smoke entrypoint.

PROVIDER_OPENAI_CREDENTIAL_NAME=''
PROVIDER_OPENAI_CREDENTIAL_ID=''
PROVIDER_OPENAI_PROFILE_NAME=''
PROVIDER_OPENAI_PROFILE_ID=''
PROVIDER_OPENAI_DOCUMENT=''
readonly PROVIDER_OPENAI_SCRIPT=/workspace/.cw-provider-openai/provider-openai-workload.py

prepare_provider_openai_identity() {
  local nonce credential_name profile_name
  validate_provider_openai_model || die 'LOCAL_PLATFORM_OPENAI_MODEL must be an explicit bounded model identifier'
  nonce="$(tr -d '-' </proc/sys/kernel/random/uuid)"
  [[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || die 'cannot generate disposable OpenAI fixture names'
  credential_name="dev-openai-$nonce"
  profile_name="dev-openai-profile-$nonce"
  cw_with_timeout 30 credentials --platform list --output json \
    >"$TMPDIR_SMOKE/provider-openai-credentials-before.json" || die 'cannot inspect personal credential metadata'
  cw_with_timeout 30 credentials --platform profiles list --output json \
    >"$TMPDIR_SMOKE/provider-openai-profiles-before.json" || die 'cannot inspect personal profile metadata'
  jq -e --arg name "$credential_name" 'type == "array" and all(.[]; .name != $name)' \
    "$TMPDIR_SMOKE/provider-openai-credentials-before.json" >/dev/null || die 'disposable OpenAI credential name collision'
  jq -e --arg name "$profile_name" 'type == "array" and all(.[]; .name != $name)' \
    "$TMPDIR_SMOKE/provider-openai-profiles-before.json" >/dev/null || die 'disposable OpenAI profile name collision'

  PROVIDER_OPENAI_CREDENTIAL_NAME="$credential_name"
  PROVIDER_OPENAI_PROFILE_NAME="$profile_name"

  # Inherit the terminal so the existing CLI reads one key through its
  # echo-disabled protected prompt. Neither input nor command output is captured.
  cw_with_timeout 600 credentials --platform add openai --name "$PROVIDER_OPENAI_CREDENTIAL_NAME" ||
    die 'fresh owner-operated platform OpenAI enrollment failed'
  cw_with_timeout 30 credentials --platform get "$PROVIDER_OPENAI_CREDENTIAL_NAME" --output json \
    >"$TMPDIR_SMOKE/provider-openai-credential.json" || die 'created OpenAI metadata is unavailable'
  PROVIDER_OPENAI_CREDENTIAL_ID="$(provider_ssh_metadata_id \
    "$TMPDIR_SMOKE/provider-openai-credential.json" "$PROVIDER_OPENAI_CREDENTIAL_NAME")" ||
    die 'created OpenAI identity was not acknowledged exactly'
  jq -e --arg id "$PROVIDER_OPENAI_CREDENTIAL_ID" --arg name "$PROVIDER_OPENAI_CREDENTIAL_NAME" '
    type == "array" and length == 1 and .[0].id == $id and .[0].name == $name and
    .[0].provider == "openai" and .[0].status == "CREDENTIAL_STATUS_ACTIVE" and
    .[0].authenticationKind == "CREDENTIAL_AUTHENTICATION_KIND_API_KEY"
  ' "$TMPDIR_SMOKE/provider-openai-credential.json" >/dev/null || die 'created OpenAI public metadata is invalid'
  cw_with_timeout 30 credentials --platform --profile "$PROVIDER_OPENAI_PROFILE_NAME" \
    set openai "id:$PROVIDER_OPENAI_CREDENTIAL_ID" \
    >"$TMPDIR_SMOKE/provider-openai-profile-set.out" 2>"$TMPDIR_SMOKE/provider-openai-profile-set.err" ||
    die 'cannot select the created OpenAI identity in its disposable profile'
  cw_with_timeout 30 credentials --platform --profile "$PROVIDER_OPENAI_PROFILE_NAME" get --output json \
    >"$TMPDIR_SMOKE/provider-openai-profile.json" || die 'created OpenAI profile metadata is unavailable'
  PROVIDER_OPENAI_PROFILE_ID="$(provider_ssh_metadata_id \
    "$TMPDIR_SMOKE/provider-openai-profile.json" "$PROVIDER_OPENAI_PROFILE_NAME")" ||
    die 'created OpenAI profile was not acknowledged exactly'
  jq -e --arg id "$PROVIDER_OPENAI_CREDENTIAL_ID" 'length == 1 and .[0].revision == "1" and
    .[0].entries == [{capabilitySlot:"openai",credentialId:$id}]' \
    "$TMPDIR_SMOKE/provider-openai-profile.json" >/dev/null ||
    die 'created OpenAI profile does not select exactly the created identity'
}

validate_provider_openai_model() {
  local LC_ALL=C
  [[ "${LOCAL_PLATFORM_OPENAI_MODEL:-}" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]]
}

prepare_provider_openai() {
  local encoded_workload install
  validate_provider_openai_model || die 'LOCAL_PLATFORM_OPENAI_MODEL must be an explicit bounded model identifier'
  prepare_provider_openai_identity
  encoded_workload="$(base64 -w0 "$ROOT/scripts/runtime/dev/provider-openai-workload.py")"
  install="set -eu; test ! -e /workspace/.cw-provider-openai; mkdir -m 700 /workspace/.cw-provider-openai; printf %s '$encoded_workload' | base64 -d > '$PROVIDER_OPENAI_SCRIPT'; chmod 0500 '$PROVIDER_OPENAI_SCRIPT'"
  PROVIDER_OPENAI_DOCUMENT="$TMPDIR_SMOKE/provider-openai-codewire.json"
  jq -n --arg profile "platform:id:$PROVIDER_OPENAI_PROFILE_ID" --arg install "$install" '
    {version:1,working_directory:"/workspace",credentials:{profile:$profile},
      install_command:$install,startup_script:"/bin/true"}
  ' >"$PROVIDER_OPENAI_DOCUMENT"
}

run_provider_openai_smoke() {
  cw_with_timeout 30 env info --local "$ENV_ID" --output json \
    >"$TMPDIR_SMOKE/provider-openai-environment.json" 2>"$TMPDIR_SMOKE/provider-openai-info.err" ||
    die 'cannot inspect the local OpenAI environment binding'
  jq -e --arg id "$ENV_ID" --arg profile "platform:id:$PROVIDER_OPENAI_PROFILE_ID" \
    --arg reference "user/$PROVIDER_OPENAI_PROFILE_NAME" '
    .id == $id and .backend == "cloud-hypervisor" and .state == "running" and
    .cpu == 2 and .memory == "16Gi" and
    .source_selection.credentials == {profile:$profile,reference:$reference,revision:1}
  ' "$TMPDIR_SMOKE/provider-openai-environment.json" >/dev/null ||
    die 'local OpenAI environment did not acknowledge the exact profile revision and topology'
  # shellcheck disable=SC2016 # Fixed guest shell applies limits before exec.
  if ! cw_with_timeout 180 run --no-tty -- /bin/bash -c \
      'ulimit -S -c 0 && ulimit -H -c 0 && exec /usr/bin/timeout --kill-after=5s 120s /usr/bin/python3 -I -B "$1" "$2"' \
      codewire-live-openai "$PROVIDER_OPENAI_SCRIPT" "$LOCAL_PLATFORM_OPENAI_MODEL" \
      >"$TMPDIR_SMOKE/provider-openai-proof.out" 2>"$TMPDIR_SMOKE/provider-openai-proof.err"; then
    die 'bounded live OpenAI workload failed; raw provider output remains private inside the disposable VM'
  fi
  [[ ! -s "$TMPDIR_SMOKE/provider-openai-proof.err" ]] || die 'live OpenAI workload returned a public error receipt'
  cmp -s "$TMPDIR_SMOKE/provider-openai-proof.out" <(printf 'CW_LIVE_OPENAI_OK\n') ||
    die 'live OpenAI workload omitted its exact public receipt'
  log 'live OpenAI Responses HTTP request validated in the local 2-vCPU/16-GiB VM; parent cleanup remains pending and SDK, streaming and other providers are not implied'
}

cleanup_provider_openai() {
  local rc=0
  cleanup_provider_openai_profile || rc=1
  cleanup_provider_openai_credential || rc=1
  [[ "$rc" == 0 ]] || log 'provider OpenAI cleanup incomplete; exact owned metadata retained in private smoke evidence'
  return "$rc"
}
cleanup_provider_openai_profile() {
  local rc=0 resolved
  if [[ -n "$PROVIDER_OPENAI_PROFILE_NAME" ]]; then
    cw_with_timeout 30 credentials --platform profiles list --output json \
      >"$TMPDIR_SMOKE/provider-openai-cleanup-profiles.json" 2>/dev/null || return 1
    jq -e 'type == "array"' "$TMPDIR_SMOKE/provider-openai-cleanup-profiles.json" >/dev/null || return 1
    if jq -e --arg name "$PROVIDER_OPENAI_PROFILE_NAME" 'any(.[]; .name == $name)' \
        "$TMPDIR_SMOKE/provider-openai-cleanup-profiles.json" >/dev/null; then
      resolved="$(provider_ssh_metadata_id "$TMPDIR_SMOKE/provider-openai-cleanup-profiles.json" \
        "$PROVIDER_OPENAI_PROFILE_NAME")" || return 1
      [[ -z "$PROVIDER_OPENAI_PROFILE_ID" || "$PROVIDER_OPENAI_PROFILE_ID" == "$resolved" ]] || return 1
      PROVIDER_OPENAI_PROFILE_ID="$resolved"
      cw_with_timeout 30 credentials --platform --profile "id:$PROVIDER_OPENAI_PROFILE_ID" delete --yes \
        >"$TMPDIR_SMOKE/provider-openai-cleanup-profile.out" 2>&1 || rc=1
    fi
    cw_with_timeout 30 credentials --platform profiles list --output json \
      >"$TMPDIR_SMOKE/provider-openai-cleanup-profiles.json" 2>/dev/null &&
      jq -e --arg name "$PROVIDER_OPENAI_PROFILE_NAME" --arg id "$PROVIDER_OPENAI_PROFILE_ID" '
        type == "array" and all(.[]; .name != $name and .id != $id)
      ' "$TMPDIR_SMOKE/provider-openai-cleanup-profiles.json" >/dev/null || rc=1
  fi
  return "$rc"
}

cleanup_provider_openai_credential() {
  local rc=0 resolved
  if [[ -n "$PROVIDER_OPENAI_CREDENTIAL_NAME" ]]; then
    cw_with_timeout 30 credentials --platform list --output json \
      >"$TMPDIR_SMOKE/provider-openai-cleanup-credentials.json" 2>/dev/null || return 1
    jq -e 'type == "array"' "$TMPDIR_SMOKE/provider-openai-cleanup-credentials.json" >/dev/null || return 1
    if jq -e --arg name "$PROVIDER_OPENAI_CREDENTIAL_NAME" 'any(.[]; .name == $name)' \
        "$TMPDIR_SMOKE/provider-openai-cleanup-credentials.json" >/dev/null; then
      resolved="$(provider_ssh_metadata_id "$TMPDIR_SMOKE/provider-openai-cleanup-credentials.json" \
        "$PROVIDER_OPENAI_CREDENTIAL_NAME")" || return 1
      [[ -z "$PROVIDER_OPENAI_CREDENTIAL_ID" || "$PROVIDER_OPENAI_CREDENTIAL_ID" == "$resolved" ]] || return 1
      PROVIDER_OPENAI_CREDENTIAL_ID="$resolved"
      cw_with_timeout 30 credentials --platform get "id:$PROVIDER_OPENAI_CREDENTIAL_ID" --output json \
        >"$TMPDIR_SMOKE/provider-openai-cleanup-credential.json" 2>/dev/null || return 1
      jq -e --arg id "$PROVIDER_OPENAI_CREDENTIAL_ID" --arg name "$PROVIDER_OPENAI_CREDENTIAL_NAME" '
        type == "array" and length == 1 and .[0].id == $id and .[0].name == $name and
        .[0].provider == "openai" and
        .[0].authenticationKind == "CREDENTIAL_AUTHENTICATION_KIND_API_KEY" and
        (.[0].status == "CREDENTIAL_STATUS_ACTIVE" or .[0].status == "CREDENTIAL_STATUS_REVOKED")
      ' "$TMPDIR_SMOKE/provider-openai-cleanup-credential.json" >/dev/null || return 1
      if ! jq -e 'length == 1 and .[0].status == "CREDENTIAL_STATUS_REVOKED"' \
          "$TMPDIR_SMOKE/provider-openai-cleanup-credential.json" >/dev/null; then
        cw_with_timeout 30 credentials --platform revoke "id:$PROVIDER_OPENAI_CREDENTIAL_ID" \
          >"$TMPDIR_SMOKE/provider-openai-cleanup-revoke.out" 2>&1 || rc=1
      fi
      cw_with_timeout 30 credentials --platform delete "id:$PROVIDER_OPENAI_CREDENTIAL_ID" --yes \
        >"$TMPDIR_SMOKE/provider-openai-cleanup-credential.out" 2>&1 || rc=1
    fi
    cw_with_timeout 30 credentials --platform list --output json \
      >"$TMPDIR_SMOKE/provider-openai-cleanup-credentials.json" 2>/dev/null &&
      jq -e --arg name "$PROVIDER_OPENAI_CREDENTIAL_NAME" --arg id "$PROVIDER_OPENAI_CREDENTIAL_ID" '
        type == "array" and all(.[]; .name != $name and .id != $id)
      ' "$TMPDIR_SMOKE/provider-openai-cleanup-credentials.json" >/dev/null || rc=1
  fi
  return "$rc"
}
