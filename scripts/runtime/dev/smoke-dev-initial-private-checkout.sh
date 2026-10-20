#!/usr/bin/env bash
# Hosted bootstrap proof using only a separately enrolled dedicated test account.
# shellcheck disable=SC2034 # Sourced auth helpers consume the shared state below.
set -euo pipefail
umask 077
CHECKOUT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
checkout_load_definitions() {
  # No positional arguments: do not run the commodity parser/main journey.
  # shellcheck disable=SC1091
  source "$CHECKOUT_ROOT/scripts/runtime/dev/smoke-dev-commodity.sh"
}
checkout_load_definitions
CHECKOUT_ATTEMPTED=0
CHECKOUT_FIXTURE_STARTED=0
CHECKOUT_SUCCESS=0
CHECKOUT_WORKSPACE=''
CHECKOUT_STATE=''
DEV_CHECKOUT_WORKSPACE_IMAGE="${DEV_CHECKOUT_WORKSPACE_IMAGE:-}"

checkout_fixture_validate() {
  [[ -f "$CHECKOUT_ROOT/scripts/runtime/dev/hosted-checkout-fixture.py" ]] ||
    die 'checked-in hosted fixture is unavailable'
  # The fixture owns the checked-in exact Dev endpoint/TLS/CA guard. Project
  # only selected public cluster fields before any OAuth or provider mutation.
  TMPDIR="$SMOKE_TMP_PARENT" timeout 60 python3 "$CHECKOUT_ROOT/scripts/runtime/dev/hosted-checkout-fixture.py" \
    preflight --context "$KUBE_CONTEXT" --namespace "$SANDBOX_NAMESPACE" \
    --image "$DEV_CHECKOUT_WORKSPACE_IMAGE" --principal-user-id "$EXPECTED_CODEWIRE_ADMIN_USER_ID" \
    --principal-email hello@codewire.sh --organization-id "$EXPECTED_CODEWIRE_ORGANIZATION_ID" \
    >/dev/null 2>/dev/null || die 'hosted fixture Dev topology preflight failed; no login or mutation started'
}

checkout_fixture_command() {
  local command_timeout=300
  case "$1" in
    start) command_timeout=1500 ;;
    stop) command_timeout=750 ;;
  esac
  timeout "$command_timeout" python3 "$CHECKOUT_ROOT/scripts/runtime/dev/hosted-checkout-fixture.py" "$@" \
    >"$TMPDIR_SMOKE/fixture-command.out" 2>"$TMPDIR_SMOKE/fixture-command.err"
}

checkout_fixture_start() {
  checkout_fixture_command start --state-dir "$CHECKOUT_STATE" --context "$KUBE_CONTEXT" \
    --namespace "$SANDBOX_NAMESPACE" --image "$DEV_CHECKOUT_WORKSPACE_IMAGE" \
    --public-key-file "$TMPDIR_SMOKE/checkout-selected.pub" \
    --principal-user-id "$EXPECTED_CODEWIRE_ADMIN_USER_ID" --principal-email hello@codewire.sh \
    --organization-id "$EXPECTED_CODEWIRE_ORGANIZATION_ID" || die 'hosted fixture startup failed; output suppressed'
  local ready="$CHECKOUT_STATE/ready.json"
  checkout_validate_ready "$ready" || die 'hosted fixture ready metadata is invalid'
  CHECKOUT_URL="$(jq -er .url "$ready")"
  CHECKOUT_REVISION="$(jq -er .revision "$ready")"
  CHECKOUT_HOST_PIN="$(jq -er '.known_hosts[0]' "$ready")"
}

checkout_validate_ready() {
  python3 - "$1" <<'PY'
import ipaddress
import json
import re
import sys
from pathlib import Path

try:
    path = Path(sys.argv[1])
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise ValueError()
    value = json.loads(path.read_text())
    if (not isinstance(value, dict)
            or set(value) != {"version", "url", "revision", "known_hosts", "content_path", "content"}
            or type(value["version"]) is not int or value["version"] != 1
            or value["content_path"] != "proof.txt"
            or value["content"] != "initial-private-checkout-synthetic-v1"
            or not isinstance(value["revision"], str)
            or not re.fullmatch(r"[0-9a-f]{40}", value["revision"])
            or not isinstance(value["url"], str)):
        raise ValueError()
    match = re.fullmatch(r"ssh://codewire@([0-9.]+):22222/repository\.git", value["url"])
    if not match:
        raise ValueError()
    address = ipaddress.IPv4Address(match[1])
    if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
        raise ValueError()
    pins = value["known_hosts"]
    if (not isinstance(pins, list) or len(pins) != 1 or not isinstance(pins[0], str)
            or not re.fullmatch(r"\[" + re.escape(str(address))
                               + r"\]:22222 ssh-ed25519 [A-Za-z0-9+/]+={0,2}", pins[0])):
        raise ValueError()
except (ValueError, TypeError, KeyError, OSError):
    sys.exit(1)
PY
}

checkout_fixture_inspect() {
  checkout_fixture_command inspect --state-dir "$CHECKOUT_STATE" || return 1
  CHECKOUT_AUTHENTICATED="$(jq -er 'select(keys == ["authenticated","version"] and .version == 1) |
    .authenticated | select(type == "number" and . >= 0 and . == floor)' "$CHECKOUT_STATE/counter.json")"
}

checkout_fixture_stop() {
  checkout_fixture_command stop --state-dir "$CHECKOUT_STATE" || return 1
  jq -e 'keys == ["deleted","version"] and .version == 1 and .deleted == true' \
    "$CHECKOUT_STATE/finish.json" >/dev/null
}

checkout_admission() {
  local admission="$CHECKOUT_ROOT/scripts/runtime/dev/testdata/acceptance-identity.json"
  [[ -f "$admission" && ! -L "$admission" ]] || die 'dedicated acceptance enrollment is unavailable'
  jq -e --arg user "$EXPECTED_CODEWIRE_ADMIN_USER_ID" --arg org "$EXPECTED_CODEWIRE_ORGANIZATION_ID" \
    --arg email "$EXPECTED_CODEWIRE_ADMIN_EMAIL" '
    keys == ["email","organizationId","status","userId","version"] and
    .version == 1 and .status == "enrolled" and .email == "hello@codewire.sh" and
    .email == $email and .userId == $user and .organizationId == $org and
    ([.userId,.organizationId] | all(.[]; type == "string" and
      test("^[0-9a-f]{32}$") and . != "00000000000000000000000000000000"))
  ' "$admission" >/dev/null 2>&1 || die 'dedicated acceptance enrollment does not match the exact expected identity'
}

checkout_validate_inputs() {
  checkout_admission
  [[ "$CODEWIRE_SERVER_URL" == https://codewire-dev.sh &&
     "$EXPECTED_CODEWIRE_DEV_SERVER_URL" == https://codewire-dev.sh &&
     -n "$DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE" && -z "$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR" &&
     -z "${CW_CONFIG_DIR:-}" && -z "${CODEWIRE_API_KEY:-}" &&
     -z "${CODEWIRE_DEV_SMOKE_API_KEY:-}" && "$ALLOW_NON_DEV" == 0 &&
     "$ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE" == 0 &&
     -z "$SMOKE_EXISTING_ENV_ID" && "$SMOKE_KEEP_ENV" == 0 ]] ||
    die 'hosted checkout requires fresh dedicated browser OAuth without saved login or API-key fallback'
  SMOKE_AUTH_MODE=admin-oidc
  validate_dev_smoke_browser_auth
  [[ "$DEV_CHECKOUT_WORKSPACE_IMAGE" =~ ^[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[0-9a-f]{64}$ &&
     -n "$KUBE_CONTEXT" && -n "$SANDBOX_NAMESPACE" &&
     "${KUBECONFIG:-}" == /* && -f "$KUBECONFIG" && ! -L "$KUBECONFIG" &&
     "$(realpath -e "$KUBECONFIG")" == "$KUBECONFIG" ]] ||
    die 'hosted checkout requires existing immutable workspace image and explicit Dev topology'
  [[ "$CW_BIN" == /* && -f "$CW_BIN" && -x "$CW_BIN" && ! -L "$CW_BIN" &&
     "$(realpath -e "$CW_BIN")" == "$CW_BIN" &&
     "${CW_BIN##*/}" != cw-local-credential-broker-smoke ]] || die 'normal canonical CLI is required'
  [[ "$SMOKE_TMP_PARENT" == "$XDG_RUNTIME_DIR"/* && -d "$SMOKE_TMP_PARENT" &&
     ! -L "$SMOKE_TMP_PARENT" && "$(realpath -e "$SMOKE_TMP_PARENT")" == "$SMOKE_TMP_PARENT" &&
     "$(stat -c '%u:%a' "$SMOKE_TMP_PARENT")" == "$(id -u):700" &&
     "$(findmnt -nro FSTYPE -T "$SMOKE_TMP_PARENT")" == tmpfs ]] ||
    die 'hosted checkout diagnostics require an owned canonical 0700 tmpfs parent'
  [[ "$SMOKE_TIMEOUT_SECONDS" =~ ^[0-9]+$ && "$SMOKE_TIMEOUT_SECONDS" -ge 30 &&
     "$SMOKE_TIMEOUT_SECONDS" -le 1800 ]] || die 'hosted checkout deadline must be 30 through 1800 seconds'
}

checkout_inventory() {
  cw_with_timeout 30 --cloud ls --output json \
    >"$TMPDIR_SMOKE/checkout-inventory.json" 2>"$TMPDIR_SMOKE/checkout-inventory.err" || return 1
  jq -e 'type == "array"' "$TMPDIR_SMOKE/checkout-inventory.json" >/dev/null 2>&1
}

checkout_build_document() {
  local install revision="$CHECKOUT_REVISION"
  [[ "$revision" =~ ^[0-9a-f]{40}$ ]] || die 'hosted checkout revision is invalid'
  install="set -eu; cd /workspace/private-checkout; test \"\$(git rev-parse HEAD)\" = '$revision'; test \"\$(cat proof.txt)\" = initial-private-checkout-synthetic-v1; test ! -e .install-proved; printf '%s\\n' initial-private-checkout-before-install > .install-proved"
  jq -n --arg image "$DEV_CHECKOUT_WORKSPACE_IMAGE" --arg profile "platform:id:$PROVIDER_SSH_PROFILE_ID" \
    --arg url "$CHECKOUT_URL" --arg pin "$CHECKOUT_HOST_PIN" --arg install "$install" '
    {version:1,image:$image,working_directory:"/workspace/private-checkout",credentials:{profile:$profile},
      repositories:[{source:$url,known_hosts:[$pin],destination:"/workspace/private-checkout"}],
      install_command:$install}'
}

checkout_create() {
  local document="$1" phase="$2"
  [[ "$document" == "$CHECKOUT_WORKSPACE/"* && "${document##*/}" != *'/'* &&
     "$(dirname "$document")" == "$CHECKOUT_WORKSPACE" && -f "$document" && ! -L "$document" ]] ||
    die 'checkout document must belong to the owned workspace'
  CHECKOUT_ATTEMPTED=1
  (
    cd "$CHECKOUT_WORKSPACE"
    cw_with_timeout 90 create --cloud --name "$SMOKE_NAME" --cpu 2000 --memory 4096 \
      --ttl 30m --no-network --file "${document##*/}" --no-wait --yes --output json
  ) >"$TMPDIR_SMOKE/checkout-$phase.json" 2>"$TMPDIR_SMOKE/checkout-$phase.err"
}

checkout_reject() {
  local document="$1" phase="$2" reason="$3"
  if checkout_create "$document" "$phase"; then die 'invalid private checkout was accepted'; fi
  grep -Fq "$reason" "$TMPDIR_SMOKE/checkout-$phase.err" || die 'private checkout rejected outside the selected validation boundary'
  checkout_fixture_inspect || die 'cannot inspect hosted checkout fixture after rejection'
  [[ "$CHECKOUT_AUTHENTICATED" == 0 ]] || die 'invalid checkout authenticated to the fixture'
  checkout_inventory || die 'cannot reconcile rejected checkout ownership'
  jq -e --arg name "$SMOKE_NAME" 'all(.[]; .name != $name)' \
    "$TMPDIR_SMOKE/checkout-inventory.json" >/dev/null || die 'rejected checkout published an environment'
  CHECKOUT_ATTEMPTED=0
}

checkout_environment_ready() {
  cw_with_timeout 30 --cloud info "$ENV_ID" --output json \
    >"$TMPDIR_SMOKE/checkout-info.json" 2>"$TMPDIR_SMOKE/checkout-info.err" || return 1
  if jq -e '.setup_error | type == "string" and length > 0' "$TMPDIR_SMOKE/checkout-info.json" >/dev/null; then
    die 'hosted checkout setup failed; private diagnostics retained until cleanup'
  fi
  jq -e --arg id "$ENV_ID" --arg profile "platform:id:$PROVIDER_SSH_PROFILE_ID" '
    .id == $id and .state == "running" and .setup_complete == true and .setup_error == null and
    .source_selection.credentials.profile == $profile and .source_selection.profile_revision == 1
  ' "$TMPDIR_SMOKE/checkout-info.json" >/dev/null
}

checkout_cleanup_environment() {
  local matches deadline
  [[ "$CHECKOUT_ATTEMPTED" == 1 || -n "$ENV_ID" ]] || return 0
  checkout_inventory || return 1
  matches="$(jq -er --arg name "$SMOKE_NAME" '[.[] | select(.name == $name)] | length' \
    "$TMPDIR_SMOKE/checkout-inventory.json")" || return 1
  # An uncertain create with no row is not proof that publication cannot finish.
  [[ "$matches" == 0 ]] && return 1
  [[ "$matches" == 1 ]] || return 1
  local resolved
  resolved="$(provider_ssh_metadata_id "$TMPDIR_SMOKE/checkout-inventory.json" "$SMOKE_NAME")" || return 1
  [[ -z "$ENV_ID" || "$ENV_ID" == "$resolved" ]] || return 1
  ENV_ID="$resolved"
  cw_with_timeout 60 --cloud rm --yes "$ENV_ID" \
    >"$TMPDIR_SMOKE/checkout-delete.out" 2>"$TMPDIR_SMOKE/checkout-delete.err" || return 1
  deadline=$(( $(seconds_now) + SMOKE_TIMEOUT_SECONDS ))
  while (( $(seconds_now) < deadline )); do
    if application_environment_destroyed; then CHECKOUT_ATTEMPTED=0; ENV_ID=''; return 0; fi
    sleep 5
  done
  return 1
}

checkout_cleanup() {
  local rc=$?
  trap - EXIT INT TERM HUP
  [[ "$CHECKOUT_SUCCESS" == 1 ]] || rc=1
  if [[ -n "$TMPDIR_SMOKE" ]]; then
    checkout_cleanup_environment || rc=1
    if [[ "$CHECKOUT_FIXTURE_STARTED" == 1 ]]; then checkout_fixture_stop || rc=1; fi
    cleanup_provider_ssh_profile || rc=1
    cleanup_provider_ssh_credential || rc=1
    if [[ "$SMOKE_OAUTH_LOGIN_ATTEMPTED" == 1 ]]; then cleanup_fresh_oauth_login || rc=1; fi
    if [[ "$rc" == 0 && "$TMPDIR_SMOKE" == "$SMOKE_TMP_PARENT"/codewire-runtime-smoke.?????? ]]; then
      rm -rf -- "$TMPDIR_SMOKE"
    elif [[ "$rc" == 0 ]]; then rc=1; fi
  fi
  if [[ "$rc" == 0 && "$CHECKOUT_SUCCESS" == 1 ]]; then
    printf '[hosted-private-checkout] PASS bootstrap_before_install=true synthetic_ssh=true cleanup=true\n'
  else printf '[hosted-private-checkout] FAIL output_suppressed=true\n' >&2; fi
  exit "$rc"
}

checkout_main() {
  if [[ $# == 2 && "$1" == --cw-bin ]]; then CW_BIN="$2"; shift 2; fi
  [[ $# == 0 ]] || die 'hosted checkout accepts only --cw-bin and fixed input metadata'
  checkout_validate_inputs
  checkout_fixture_validate
  ulimit -c 0
  ulimit -f 8192
  SMOKE_NAME="dev-checkout-$(tr -d '-' </proc/sys/kernel/random/uuid)"
  trap checkout_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  prepare_fresh_oauth_cli
  CHECKOUT_WORKSPACE="$TMPDIR_SMOKE/checkout-workspace"
  mkdir -m 0700 "$CHECKOUT_WORKSPACE"
  CHECKOUT_STATE="$TMPDIR_SMOKE/hosted-checkout-fixture"
  prepare_provider_ssh_identity
  jq -er '.[0].sshPublicKey.openssh' "$TMPDIR_SMOKE/provider-ssh-credential.json" \
    >"$TMPDIR_SMOKE/checkout-selected.pub"
  CHECKOUT_FIXTURE_STARTED=1
  checkout_fixture_start
  local revision
  revision="$CHECKOUT_REVISION"
  checkout_build_document >"$CHECKOUT_WORKSPACE/codewire.yaml"
  jq 'del(.credentials)' "$CHECKOUT_WORKSPACE/codewire.yaml" >"$CHECKOUT_WORKSPACE/unselected.json"
  checkout_reject "$CHECKOUT_WORKSPACE/unselected.json" unselected \
    'SSH repository checkout requires an explicitly selected credential profile containing an SSH identity'
  jq '.repositories[0].known_hosts=[]' "$CHECKOUT_WORKSPACE/codewire.yaml" >"$CHECKOUT_WORKSPACE/untrusted.json"
  checkout_reject "$CHECKOUT_WORKSPACE/untrusted.json" untrusted 'must pin at least one SSH host key'
  checkout_create "$CHECKOUT_WORKSPACE/codewire.yaml" created || die 'hosted private checkout create did not confirm'
  ENV_ID="$(jq -er '.id | select(type == "string" and test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$") and . != "00000000-0000-0000-0000-000000000000")' \
    "$TMPDIR_SMOKE/checkout-created.json")" || die 'hosted checkout identity was not acknowledged exactly'
  wait_until 'hosted checkout setup completion' "$(( $(seconds_now) + SMOKE_TIMEOUT_SECONDS ))" checkout_environment_ready
  checkout_fixture_inspect
  [[ "$CHECKOUT_AUTHENTICATED" -gt 0 ]] || die 'hosted checkout did not authenticate with the selected key'
  cw_with_timeout 60 run --no-tty --in "$ENV_ID" -- /bin/sh -c \
    "set -eu; cd /workspace/private-checkout; test \"\$(git rev-parse HEAD)\" = '$revision'; test \"\$(cat proof.txt)\" = initial-private-checkout-synthetic-v1; test \"\$(cat .install-proved)\" = initial-private-checkout-before-install; printf '%s\\n' hosted-private-checkout-proved" \
    >"$TMPDIR_SMOKE/checkout-proof.out" 2>"$TMPDIR_SMOKE/checkout-proof.err" || die 'hosted initial checkout managed execution failed'
  grep -qx hosted-private-checkout-proved "$TMPDIR_SMOKE/checkout-proof.out" || die 'hosted checkout completion receipt is missing'
  CHECKOUT_SUCCESS=1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then checkout_main "$@"; fi
