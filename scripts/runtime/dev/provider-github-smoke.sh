#!/usr/bin/env bash
# Sourced by the isolated local-platform entrypoint after its fresh login.
# shellcheck disable=SC2034 # State is consumed by the parent smoke entrypoint.

PROVIDER_GITHUB_CREDENTIAL_NAME=''
PROVIDER_GITHUB_CREDENTIAL_ID=''
PROVIDER_GITHUB_PROFILE_NAME=''
PROVIDER_GITHUB_PROFILE_ID=''
PROVIDER_GITHUB_DOCUMENT=''
readonly PROVIDER_GITHUB_SCRIPT=/workspace/.cw-provider-github/provider-github-workload.py

prepare_provider_github_identity() {
  local nonce credential_name profile_name
  nonce="$(tr -d '-' </proc/sys/kernel/random/uuid)"
  [[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || die 'cannot generate disposable GitHub fixture names'
  credential_name="dev-github-$nonce"
  profile_name="dev-github-profile-$nonce"
  cw_with_timeout 30 credentials --cloud list --output json \
    >"$TMPDIR_SMOKE/provider-github-credentials-before.json" || die 'cannot inspect personal credential metadata'
  cw_with_timeout 30 credentials --cloud profiles list --output json \
    >"$TMPDIR_SMOKE/provider-github-profiles-before.json" || die 'cannot inspect personal profile metadata'
  jq -e --arg name "$credential_name" 'type == "array" and all(.[]; .name != $name)' \
    "$TMPDIR_SMOKE/provider-github-credentials-before.json" >/dev/null || die 'disposable GitHub credential name collision'
  jq -e --arg name "$profile_name" 'type == "array" and all(.[]; .name != $name)' \
    "$TMPDIR_SMOKE/provider-github-profiles-before.json" >/dev/null || die 'disposable GitHub profile name collision'

  # Cleanup authority begins only after both unique names were confirmed absent.
  PROVIDER_GITHUB_CREDENTIAL_NAME="$credential_name"
  PROVIDER_GITHUB_PROFILE_NAME="$profile_name"

  # Intentionally inherit the terminal. The device URL/code and owner approval
  # must remain visible and must never be captured in smoke artifacts.
  cw_with_timeout 600 credentials --cloud connect github --name "$PROVIDER_GITHUB_CREDENTIAL_NAME" ||
    die 'fresh owner-operated platform GitHub enrollment failed'
  cw_with_timeout 30 credentials --cloud get "$PROVIDER_GITHUB_CREDENTIAL_NAME" --output json \
    >"$TMPDIR_SMOKE/provider-github-credential.json" || die 'created GitHub metadata is unavailable'
  PROVIDER_GITHUB_CREDENTIAL_ID="$(provider_ssh_metadata_id \
    "$TMPDIR_SMOKE/provider-github-credential.json" "$PROVIDER_GITHUB_CREDENTIAL_NAME")" ||
    die 'created GitHub identity was not acknowledged exactly'
  jq -e --arg id "$PROVIDER_GITHUB_CREDENTIAL_ID" --arg name "$PROVIDER_GITHUB_CREDENTIAL_NAME" '
    type == "array" and length == 1 and .[0].id == $id and .[0].name == $name and
    .[0].provider == "github" and .[0].status == "CREDENTIAL_STATUS_ACTIVE" and
    .[0].authenticationKind == "CREDENTIAL_AUTHENTICATION_KIND_OAUTH" and
    (.[0].accountHint | type == "string" and test("^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$"))
  ' "$TMPDIR_SMOKE/provider-github-credential.json" >/dev/null || die 'created GitHub public metadata is invalid'
  cw_with_timeout 30 credentials --cloud --profile "$PROVIDER_GITHUB_PROFILE_NAME" \
    set github "id:$PROVIDER_GITHUB_CREDENTIAL_ID" \
    >"$TMPDIR_SMOKE/provider-github-profile-set.out" 2>"$TMPDIR_SMOKE/provider-github-profile-set.err" ||
    die 'cannot select the created GitHub identity in its disposable profile'
  cw_with_timeout 30 credentials --cloud --profile "$PROVIDER_GITHUB_PROFILE_NAME" get --output json \
    >"$TMPDIR_SMOKE/provider-github-profile.json" || die 'created GitHub profile metadata is unavailable'
  PROVIDER_GITHUB_PROFILE_ID="$(provider_ssh_metadata_id \
    "$TMPDIR_SMOKE/provider-github-profile.json" "$PROVIDER_GITHUB_PROFILE_NAME")" ||
    die 'created GitHub profile was not acknowledged exactly'
  jq -e --arg id "$PROVIDER_GITHUB_CREDENTIAL_ID" 'length == 1 and .[0].revision == "1" and
    .[0].entries == [{capabilitySlot:"github",credentialId:$id}]' \
    "$TMPDIR_SMOKE/provider-github-profile.json" >/dev/null ||
    die 'created GitHub profile does not select exactly the created identity'
}

prepare_provider_github() {
  local encoded_workload encoded_login install
  prepare_provider_github_identity
  encoded_workload="$(base64 -w0 "$ROOT/scripts/runtime/dev/provider-github-workload.py")"
  encoded_login="$(jq -jr '.[0].accountHint' "$TMPDIR_SMOKE/provider-github-credential.json" | base64 -w0)"
  install="set -eu; test ! -e /workspace/.cw-provider-github; mkdir -m 700 /workspace/.cw-provider-github; printf %s '$encoded_workload' | base64 -d > '$PROVIDER_GITHUB_SCRIPT'; printf %s '$encoded_login' | base64 -d > /workspace/.cw-provider-github/expected-login; chmod 0500 '$PROVIDER_GITHUB_SCRIPT'; chmod 0400 /workspace/.cw-provider-github/expected-login"
  PROVIDER_GITHUB_DOCUMENT="$TMPDIR_SMOKE/provider-github-codewire.json"
  jq -n --arg profile "platform:id:$PROVIDER_GITHUB_PROFILE_ID" --arg install "$install" '
    {version:1,working_directory:"/workspace",credentials:{profile:$profile},
      install_command:$install,startup_script:"/bin/true"}
  ' >"$PROVIDER_GITHUB_DOCUMENT"
}

run_provider_github_smoke() {
  cw_with_timeout 30 env info --local "$ENV_ID" --output json \
    >"$TMPDIR_SMOKE/provider-github-environment.json" 2>"$TMPDIR_SMOKE/provider-github-info.err" ||
    die 'cannot inspect the local GitHub environment binding'
  jq -e --arg id "$ENV_ID" --arg profile "platform:id:$PROVIDER_GITHUB_PROFILE_ID" \
    --arg reference "user/$PROVIDER_GITHUB_PROFILE_NAME" '
    .id == $id and .backend == "cloud-hypervisor" and .state == "running" and
    .cpu == 2 and .memory == "16Gi" and
    .source_selection.credentials == {profile:$profile,reference:$reference,revision:1}
  ' "$TMPDIR_SMOKE/provider-github-environment.json" >/dev/null ||
    die 'local GitHub environment did not acknowledge the exact profile revision and topology'
  if ! cw_with_timeout 150 run --no-tty -- /usr/bin/python3 "$PROVIDER_GITHUB_SCRIPT" \
      >"$TMPDIR_SMOKE/provider-github-proof.out" 2>"$TMPDIR_SMOKE/provider-github-proof.err"; then
    die 'bounded live GitHub workload failed; raw provider output remains private inside the disposable VM'
  fi
  assert_managed_run_stderr "$TMPDIR_SMOKE/provider-github-proof.err" || die 'live GitHub workload returned unexpected stderr'
  cmp -s "$TMPDIR_SMOKE/provider-github-proof.out" <(printf 'CW_LIVE_GITHUB_OK\n') ||
    die 'live GitHub workload omitted its exact public receipt'
  log 'stock gh read-only account request validated in the local 2-vCPU/16-GiB VM; parent cleanup remains pending and other providers, hosted placement and private checkout are not implied'
}

cleanup_provider_github() {
  local rc=0
  cleanup_provider_github_profile || rc=1
  cleanup_provider_github_credential || rc=1
  [[ "$rc" == 0 ]] || log 'provider GitHub cleanup incomplete; exact owned metadata retained in private smoke evidence'
  return "$rc"
}

cleanup_provider_github_profile() {
  local rc=0 resolved
  if [[ -n "$PROVIDER_GITHUB_PROFILE_NAME" ]]; then
    cw_with_timeout 30 credentials --cloud profiles list --output json \
      >"$TMPDIR_SMOKE/provider-github-cleanup-profiles.json" 2>/dev/null || return 1
    jq -e 'type == "array"' "$TMPDIR_SMOKE/provider-github-cleanup-profiles.json" >/dev/null || return 1
    if jq -e --arg name "$PROVIDER_GITHUB_PROFILE_NAME" 'any(.[]; .name == $name)' \
        "$TMPDIR_SMOKE/provider-github-cleanup-profiles.json" >/dev/null; then
      resolved="$(provider_ssh_metadata_id "$TMPDIR_SMOKE/provider-github-cleanup-profiles.json" \
        "$PROVIDER_GITHUB_PROFILE_NAME")" || return 1
      [[ -z "$PROVIDER_GITHUB_PROFILE_ID" || "$PROVIDER_GITHUB_PROFILE_ID" == "$resolved" ]] || return 1
      PROVIDER_GITHUB_PROFILE_ID="$resolved"
      cw_with_timeout 30 credentials --cloud --profile "id:$PROVIDER_GITHUB_PROFILE_ID" delete --yes \
        >"$TMPDIR_SMOKE/provider-github-cleanup-profile.out" 2>&1 || rc=1
    fi
    cw_with_timeout 30 credentials --cloud profiles list --output json \
      >"$TMPDIR_SMOKE/provider-github-cleanup-profiles.json" 2>/dev/null &&
      jq -e --arg name "$PROVIDER_GITHUB_PROFILE_NAME" --arg id "$PROVIDER_GITHUB_PROFILE_ID" '
        type == "array" and all(.[]; .name != $name and .id != $id)
      ' "$TMPDIR_SMOKE/provider-github-cleanup-profiles.json" >/dev/null || rc=1
  fi
  return "$rc"
}

cleanup_provider_github_credential() {
  local rc=0 resolved
  if [[ -n "$PROVIDER_GITHUB_CREDENTIAL_NAME" ]]; then
    cw_with_timeout 30 credentials --cloud list --output json \
      >"$TMPDIR_SMOKE/provider-github-cleanup-credentials.json" 2>/dev/null || return 1
    jq -e 'type == "array"' "$TMPDIR_SMOKE/provider-github-cleanup-credentials.json" >/dev/null || return 1
    if jq -e --arg name "$PROVIDER_GITHUB_CREDENTIAL_NAME" 'any(.[]; .name == $name)' \
        "$TMPDIR_SMOKE/provider-github-cleanup-credentials.json" >/dev/null; then
      resolved="$(provider_ssh_metadata_id "$TMPDIR_SMOKE/provider-github-cleanup-credentials.json" \
        "$PROVIDER_GITHUB_CREDENTIAL_NAME")" || return 1
      [[ -z "$PROVIDER_GITHUB_CREDENTIAL_ID" || "$PROVIDER_GITHUB_CREDENTIAL_ID" == "$resolved" ]] || return 1
      PROVIDER_GITHUB_CREDENTIAL_ID="$resolved"
      cw_with_timeout 30 credentials --cloud get "id:$PROVIDER_GITHUB_CREDENTIAL_ID" --output json \
        >"$TMPDIR_SMOKE/provider-github-cleanup-credential.json" 2>/dev/null || return 1
      jq -e --arg id "$PROVIDER_GITHUB_CREDENTIAL_ID" --arg name "$PROVIDER_GITHUB_CREDENTIAL_NAME" '
        type == "array" and length == 1 and .[0].id == $id and .[0].name == $name and
        .[0].provider == "github" and
        .[0].authenticationKind == "CREDENTIAL_AUTHENTICATION_KIND_OAUTH" and
        (.[0].status == "CREDENTIAL_STATUS_ACTIVE" or .[0].status == "CREDENTIAL_STATUS_REVOKED")
      ' "$TMPDIR_SMOKE/provider-github-cleanup-credential.json" >/dev/null || return 1
      if ! jq -e 'length == 1 and .[0].status == "CREDENTIAL_STATUS_REVOKED"' \
          "$TMPDIR_SMOKE/provider-github-cleanup-credential.json" >/dev/null; then
        cw_with_timeout 30 credentials --cloud revoke "id:$PROVIDER_GITHUB_CREDENTIAL_ID" \
          >"$TMPDIR_SMOKE/provider-github-cleanup-revoke.out" 2>&1 || rc=1
      fi
      cw_with_timeout 30 credentials --cloud delete "id:$PROVIDER_GITHUB_CREDENTIAL_ID" --yes \
        >"$TMPDIR_SMOKE/provider-github-cleanup-credential.out" 2>&1 || rc=1
    fi
    cw_with_timeout 30 credentials --cloud list --output json \
      >"$TMPDIR_SMOKE/provider-github-cleanup-credentials.json" 2>/dev/null &&
      jq -e --arg name "$PROVIDER_GITHUB_CREDENTIAL_NAME" --arg id "$PROVIDER_GITHUB_CREDENTIAL_ID" '
        type == "array" and all(.[]; .name != $name and .id != $id)
      ' "$TMPDIR_SMOKE/provider-github-cleanup-credentials.json" >/dev/null || rc=1
  fi
  return "$rc"
}
