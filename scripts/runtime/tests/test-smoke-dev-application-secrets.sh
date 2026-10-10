#!/usr/bin/env bash
# Pure shell/PTY fixtures: no Dev, credential reader, VM or database calls.
# shellcheck disable=SC2034 # Globals are consumed by the sourced product script.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck disable=SC1091 # The tested script is sourced without its main entrypoint.
source "$REPO_ROOT/scripts/runtime/dev/smoke-dev-commodity.sh"
REAL_CW="$(declare -f cw)"
REAL_CW_WITH_TIMEOUT="$(declare -f cw_with_timeout)"
mkdir -p "$REPO_ROOT/.tmp"
APP_TEST_ROOT="$(mktemp -d "$REPO_ROOT/.tmp/cw-dev-app-fixtures.XXXXXXXX")"
APP_TEST_RUNTIME="$(mktemp -d /dev/shm/cw-dev-app-runtime.XXXXXXXX)"
chmod 0700 "$APP_TEST_RUNTIME"
APP_TEST_OWNER="$BASHPID"
trap 'if [[ "$BASHPID" == "$APP_TEST_OWNER" ]]; then rm -rf -- "$APP_TEST_ROOT" "$APP_TEST_RUNTIME"; fi' EXIT
APP_TEST_COUNT=0
REAL_APPLICATION_PTY="$(declare -f run_application_secret_pty)"
fail() { printf 'application smoke fixture: %s\n' "$*" >&2; exit 1; }
pass() { APP_TEST_COUNT=$((APP_TEST_COUNT + 1)); }

# Keep the real polling loop and readiness predicates, but advance its clock
# only on retry sleeps. A one-second synthetic budget must not expire between
# two date invocations before the first predicate runs on a busy CI worker.
seconds_now() { cat "$TMPDIR_SMOKE/clock"; }
sleep() {
  if [[ "$#" == 1 && "$1" == 5 ]]; then
    local current
    read -r current <"$TMPDIR_SMOKE/clock"
    printf '%s\n' "$((current + 5))" >"$TMPDIR_SMOKE/clock"
  else
    command sleep "$@"
  fi
}

fixture() {
  TMPDIR_SMOKE="$(mktemp -d "$APP_TEST_ROOT/case.XXXXXXXX")"
  printf '100\n' >"$TMPDIR_SMOKE/clock"
  APP_SECRET_PROJECTS=(); APP_SECRET_IDS=(); APP_SECRET_VALUES=(); APP_SECRET_HASHES=()
  APP_SECRET_USER_ATTEMPTS=(); APP_SECRET_ORG_ATTEMPTS=(); APP_SECRET_ALL_KEYS=()
  APP_SECRET_ALL_HASHES_A=(); APP_SECRET_ALL_HASHES_B=(); APP_SECRET_ALL_HASHES_CLEAR=()
  SMOKE_OAUTH_ENV=(); APP_SECRET_ALL_SCOPES=0; APP_WORKSPACE_MARKER_SHA256=''; APP_RESTART_WITNESS_SESSION_ID=''
  SMOKE_OAUTH_LOGIN_ATTEMPTED=0
  SMOKE_OAUTH_LOGIN_DIR=''; SMOKE_OAUTH_RUNTIME_PARENT=''; SMOKE_OAUTH_RUNTIME_DIR=''
  APP_SECRET_DOCUMENT=''; APP_SECRET_CREATE_ATTEMPTED=0; ENV_ID=''; CLAIM_NAME=fixture-claim
  SMOKE_NAME=fixture-env; SMOKE_TIMEOUT_SECONDS=1; SMOKE_EXEC_TIMEOUT=5
  SMOKE_KEEP_ENV=0; SMOKE_SKIP_KUBE=0; SMOKE_EXISTING_ENV_ID=''
  SMOKE_AUTH_MODE=api-key; ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE=0; ALLOW_NON_DEV=0
  CODEWIRE_SERVER_URL=https://synthetic.invalid; EXPECTED_CODEWIRE_DEV_SERVER_URL="$CODEWIRE_SERVER_URL"
  CODEWIRE_DEV_SMOKE_API_KEY=synthetic-test-only; EXPECTED_CODEWIRE_SMOKE_USER_EMAIL=synthetic@example.invalid
  EXPECTED_CODEWIRE_ADMIN_EMAIL='owner@example.invalid'
  EXPECTED_CODEWIRE_ADMIN_USER_ID=11111111111111111111111111111111
  EXPECTED_CODEWIRE_ORGANIZATION_ID=22222222222222222222222222222222
  CODEWIRE_ADMIN_OAUTH_CONFIG_DIR=''
  DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE=''
  DEV_SMOKE_BROWSER_AUTH_BUN_BIN=''
  DEV_SMOKE_BROWSER_AUTH_CHROMIUM_BIN=''
  SANDBOX_NAMESPACE=synthetic; APP_FAILURE=''
  APP_KUBE_RESOURCE=''; APP_KUBE_MUTATION='.'; APP_ANNOTATED_POD=0
  printf '[]\n' >"$TMPDIR_SMOKE/projects.db"
  printf '[]\n' >"$TMPDIR_SMOKE/user.db"
  printf '[]\n' >"$TMPDIR_SMOKE/organization.db"
  printf '[]\n' >"$TMPDIR_SMOKE/environments.db"
  printf '[]\n' >"$TMPDIR_SMOKE/sessions.db"
  printf '[]\n' >"$TMPDIR_SMOKE/host-attachments.db"
  printf '1\n' >"$TMPDIR_SMOKE/pod-incarnation"
  : >"$TMPDIR_SMOKE/calls"
}

cw_with_timeout() { shift; cw "$@"; }
cw() {
  [[ "$*" != *cwdevapp* ]] || fail 'synthetic protected value entered CLI argv'
  printf '%q ' "$@" >>"$TMPDIR_SMOKE/calls"; printf '\n' >>"$TMPDIR_SMOKE/calls"
  case "$*" in
    'secrets --platform --user list --output json')
      if [[ "$APP_FAILURE" == cleanup-user-list ]]; then
        printf '[]\n'; printf 'synthetic private list failure\n' >&2; return 23
      fi
      cat "$TMPDIR_SMOKE/user.db" ;;
    'secrets --platform --organization list --output json')
      cat "$TMPDIR_SMOKE/organization.db" ;;
    'secrets --platform --user set '*|'secrets --platform --organization set '*)
      local input='' scope db key
      IFS= read -r input || [[ -n "$input" ]]
      [[ "$input" == cwdevall* ]] || fail 'all-scope protected stdin was not supplied'
      scope="$3"; scope="${scope#--}"; db="$TMPDIR_SMOKE/$scope.db"; key="$5"
      jq --arg key "$key" 'map(select(.key != $key)) + [{key:$key,created_at:"now",updated_at:"now"}]' \
        "$db" >"$TMPDIR_SMOKE/db.next"
      mv "$TMPDIR_SMOKE/db.next" "$db"
      [[ "$APP_FAILURE" != "lost-$scope-write" ]] || return 1 ;;
    'secrets --platform --user delete '*|'secrets --platform --organization delete '*)
      local scope db key
      scope="$3"; scope="${scope#--}"; db="$TMPDIR_SMOKE/$scope.db"; key="$5"
      [[ "$APP_FAILURE" != "cleanup-$scope" ]] || return 1
      jq --arg key "$key" 'map(select(.key != $key))' "$db" >"$TMPDIR_SMOKE/db.next"
      mv "$TMPDIR_SMOKE/db.next" "$db"
      if [[ "$APP_FAILURE" == cleanup-user-delete-lost && "$scope" == user ]]; then
        printf 'synthetic private delete failure\n' >&2; return 24
      fi ;;
    'secrets --platform projects list --output json')
      cat "$TMPDIR_SMOKE/projects.db" ;;
    'secrets --platform projects create '*)
      local count id
      count="$(jq length "$TMPDIR_SMOKE/projects.db")"
      printf -v id '00000000-0000-4000-8000-%012d' "$((count + 1))"
      jq --arg name "$5" --arg id "$id" '. + [{id:$id,name:$name}]' "$TMPDIR_SMOKE/projects.db" >"$TMPDIR_SMOKE/db.next"
      mv "$TMPDIR_SMOKE/db.next" "$TMPDIR_SMOKE/projects.db" ;;
    'secrets --platform projects delete '*)
      [[ "$APP_FAILURE" != cleanup ]] || return 1
      jq --arg selector "$5" 'map(select(if $selector | startswith("id:") then .id != ($selector | ltrimstr("id:")) else .name != $selector end))' "$TMPDIR_SMOKE/projects.db" >"$TMPDIR_SMOKE/db.next"
      mv "$TMPDIR_SMOKE/db.next" "$TMPDIR_SMOKE/projects.db" ;;
    'secrets --platform --project '*" set "*)
      local input=''
      IFS= read -r input || [[ -n "$input" ]]
      if [[ "$APP_SECRET_ALL_SCOPES" == 1 ]]; then
        [[ "$input" == cwdevall* ]]
      else
        [[ "$input" == cwdevapp* && ${#input} == 41 ]]
      fi || fail 'protected stdin was not supplied'
      [[ "$APP_FAILURE" != scope ]] || return 1 ;;
    'secrets --platform --project '*" list --output json")
      if [[ "$APP_FAILURE" == leak ]]; then
        jq -n --arg value "${APP_SECRET_VALUES[0]}" '[{key:"DATABASE_URL",value:$value},{key:"CW_DEV_PRECEDENCE"}]'
      elif [[ "$APP_SECRET_ALL_SCOPES" == 1 ]]; then
        printf '%s\n' "${APP_SECRET_ALL_KEYS[@]:1:1}" "${APP_SECRET_ALL_KEYS[@]:3:3}" |
          jq -Rsc 'split("\n")[:-1] | map({key:.,created_at:"now",updated_at:"now"})'
      else printf '[{"key":"DATABASE_URL"},{"key":"CW_DEV_PRECEDENCE"}]\n'; fi ;;
    'env --platform list --output json') jq 'map(select(.state != "destroying" and .state != "destroyed"))' "$TMPDIR_SMOKE/environments.db" ;;
    'env --platform list --all --output json') cat "$TMPDIR_SMOKE/environments.db" ;;
    'env create --platform --file '*)
      local project
      project="$(jq -r .secrets.project "$APP_SECRET_DOCUMENT")"
      local user organization
      user="$(jq -r '.secrets.user // empty' "$APP_SECRET_DOCUMENT")"
      organization="$(jq -r '.secrets.organization // false' "$APP_SECRET_DOCUMENT")"
      jq -n --arg project "$project" --arg user "$user" --argjson organization "$organization" --arg name "$SMOKE_NAME" \
        '[{id:"00000000-0000-4000-8000-000000000099",name:$name,state:"running",operation_generation:1,
          setup_complete:true,setup_error:null,
          source_selection:{secrets:({project:$project} +
            (if $user == "" then {} else {user:$user} end) +
            (if $organization then {organization:true} else {} end)),credentials:null,profile_revision:null}}]' >"$TMPDIR_SMOKE/environments.db"
      printf 'ID: 00000000-0000-4000-8000-000000000099\n' ;;
    'env --platform info '*" --output json")
      jq -e '.[0].state != "destroying" and .[0].state != "destroyed"' "$TMPDIR_SMOKE/environments.db" >/dev/null || return 1
      jq '.[0]' "$TMPDIR_SMOKE/environments.db" ;;
    'env --platform update '*)
      if [[ " $* " != *' --yes '* ]]; then
        printf 'source selection requires --yes for noninteractive or JSON commands; no source change was submitted\n' >&2
        return 2
      fi
      local project='' before user='' organization=false
      before="$(jq '.[0].operation_generation' "$TMPDIR_SMOKE/environments.db")"
      [[ " $* " != *' --secrets '* ]] || project="$6"
      [[ " $* " != *' --user-secrets platform '* ]] || user=platform
      [[ " $* " != *' --org-secrets '* ]] || organization=true
      # The real workflow retains its generation across source restarts.
      jq --arg project "$project" --arg user "$user" --argjson organization "$organization" '
        .[0].source_selection.secrets=(if $project == "" then {} else
          {project:$project} + (if $user == "" then {} else {user:$user} end) +
          (if $organization then {organization:true} else {} end) end)' \
        "$TMPDIR_SMOKE/environments.db" >"$TMPDIR_SMOKE/db.next"
      mv "$TMPDIR_SMOKE/db.next" "$TMPDIR_SMOKE/environments.db"
      printf '%s\n' "$(( $(<"$TMPDIR_SMOKE/pod-incarnation") + 1 ))" >"$TMPDIR_SMOKE/pod-incarnation"
      # Model the old false-positive mechanism independently: the host-side
      # attachment transport always ends, but that says nothing about whether
      # the durable managed session ended in the guest.
      jq 'map(if .state == "Attached" then .state = "Terminated" else . end)' \
        "$TMPDIR_SMOKE/host-attachments.db" >"$TMPDIR_SMOKE/host-attachments.next"
      mv "$TMPDIR_SMOKE/host-attachments.next" "$TMPDIR_SMOKE/host-attachments.db"
      if [[ "$APP_SECRET_ALL_SCOPES" == 1 &&
            "$APP_FAILURE" != attachment-terminated-session-running ]]; then
        jq 'map(if .state == "Running" then
          .state = "Interrupted" | .status_message = "source update interrupted session"
          else . end)' "$TMPDIR_SMOKE/sessions.db" >"$TMPDIR_SMOKE/sessions.next"
        mv "$TMPDIR_SMOKE/sessions.next" "$TMPDIR_SMOKE/sessions.db"
      fi
      case "$APP_FAILURE" in
        marker-replacement) printf 'replacement-marker\n' >"$TMPDIR_SMOKE/workspace-marker" ;;
        marker-missing) rm -f -- "$TMPDIR_SMOKE/workspace-marker" ;;
      esac
      if [[ "$APP_FAILURE" == bad-update || ( "$APP_FAILURE" == bad-clear && "$project" == '' ) ]]; then
        printf '{"outcome":"restart_required"}\n'
      else
        jq --argjson before "$before" '.[0] | {environment_id:.id,operation_generation:$before,
          outcome:"restart_required",selection:(.source_selection |
            if .secrets.project == "" then .secrets={} else . end)}' "$TMPDIR_SMOKE/environments.db"
      fi ;;
    'env --platform rm --yes '*)
      jq '.[0].state="destroyed"' "$TMPDIR_SMOKE/environments.db" >"$TMPDIR_SMOKE/db.next"
      mv "$TMPDIR_SMOKE/db.next" "$TMPDIR_SMOKE/environments.db" ;;
    'run --no-tty '*'/dev/urandom'*)
      printf 'fixture-random-workspace-marker\n' >"$TMPDIR_SMOKE/workspace-marker"
      sha256sum "$TMPDIR_SMOKE/workspace-marker" | cut -d ' ' -f 1 ;;
    'run --no-tty --output json '*'application-restart-witness-ready'*)
      local session_count session_id guest_command
      [[ -f "$TMPDIR_SMOKE/workspace-marker" ]] || return 1
      [[ "$(sha256sum "$TMPDIR_SMOKE/workspace-marker" | cut -d ' ' -f 1)" == "$APP_WORKSPACE_MARKER_SHA256" ]] || return 1
      session_count="$(jq length "$TMPDIR_SMOKE/sessions.db")"
      printf -v session_id 'fixture-witness-%d' "$((session_count + 1))"
      guest_command="${9-}"
      jq --arg id "$session_id" --arg command "$guest_command" '. + [{
        session_id:$id,state:"Running",command:["/bin/sh","-c",$command],
        working_dir:"/workspace",pty:false,exit_code:null,output_end_offset:36,status_message:""
      }]' "$TMPDIR_SMOKE/sessions.db" >"$TMPDIR_SMOKE/sessions.next"
      mv "$TMPDIR_SMOKE/sessions.next" "$TMPDIR_SMOKE/sessions.db"
      jq --arg id "$session_id" '. + [{session_id:$id,state:"Attached"}]' \
        "$TMPDIR_SMOKE/host-attachments.db" >"$TMPDIR_SMOKE/host-attachments.next"
      mv "$TMPDIR_SMOKE/host-attachments.next" "$TMPDIR_SMOKE/host-attachments.db"
      printf 'application-restart-witness-ready\n' >"$TMPDIR_SMOKE/session-$session_id.log"
      jq --arg id "$session_id" '.[] | select(.session_id == $id)' "$TMPDIR_SMOKE/sessions.db" ;;
    'logs '*' --raw')
      local session_id="$3"
      jq -e --arg id "$session_id" 'any(.[]; .session_id == $id)' "$TMPDIR_SMOKE/sessions.db" >/dev/null || return 1
      cat "$TMPDIR_SMOKE/session-$session_id.log" ;;
    'run --no-tty '*)
      if [[ "$APP_SECRET_ALL_SCOPES" == 1 ]]; then
        [[ -f "$TMPDIR_SMOKE/workspace-marker" ]] || return 1
        [[ "$(sha256sum "$TMPDIR_SMOKE/workspace-marker" | cut -d ' ' -f 1)" == "$APP_WORKSPACE_MARKER_SHA256" ]] || return 1
      fi
      printf 'application-secret-check-ok\n' ;;
    'list '*" --output json") cat "$TMPDIR_SMOKE/sessions.db" ;;
    *) fail "unexpected mock CLI operation: $*" ;;
  esac
}

run_kube_assertions() {
  # The API readiness read must precede Pod discovery. A running Pod may still
  # belong to a setup attempt that recovery is about to replace.
  [[ -f "$TMPDIR_SMOKE/app-environment.json" ]] || fail 'Pod assertions preceded setup readiness'
  jq -e '.setup_complete == true and .setup_error == null' \
    "$TMPDIR_SMOKE/app-environment.json" >/dev/null || fail 'Pod assertions preceded completed setup'
}
kubectl_dev() {
  local generation project pod_uid pod_name=owned-sandbox resource object pod_env
  [[ "$APP_SECRET_ALL_SCOPES" != 1 ]] ||
    fail 'all-scope application smoke invoked Kubernetes'
  printf '%q ' "$@" >>"$TMPDIR_SMOKE/calls"; printf '\n' >>"$TMPDIR_SMOKE/calls"
  generation="$(jq -r '.[0].operation_generation' "$TMPDIR_SMOKE/environments.db")"
  project="$(jq -r '.[0].source_selection.secrets.project // ""' "$TMPDIR_SMOKE/environments.db")"
  pod_uid="pod-$(<"$TMPDIR_SMOKE/pod-incarnation")"
  [[ "$APP_FAILURE" != stale-pod ]] || pod_uid='pod-1'
  [[ "$APP_ANNOTATED_POD" != 1 ]] || pod_name=annotated-pod
  case "$*" in
    '-n synthetic get sandboxclaim fixture-claim -o json')
      resource=claim
      object="$(jq -n --arg id "$ENV_ID" '{metadata:{name:"fixture-claim",namespace:"synthetic",uid:"owned-claim-uid",
        labels:{"codewire.sh/environment-id":$id,"codewire.sh/type":"sandbox"}},status:{sandbox:{name:"owned-sandbox"}}}')" ;;
    '-n synthetic get sandbox owned-sandbox -o json')
      resource=sandbox
      object="$(jq -n --arg pod "$pod_name" --argjson annotated "$APP_ANNOTATED_POD" '
        {metadata:{name:"owned-sandbox",namespace:"synthetic",uid:"owned-sandbox-uid",
          annotations:(if $annotated == 1 then {"agents.x-k8s.io/pod-name":$pod} else {} end),
          ownerReferences:[{apiVersion:"extensions.agents.x-k8s.io/v1beta1",kind:"SandboxClaim",
            name:"fixture-claim",uid:"owned-claim-uid",controller:true}]}}')" ;;
    "-n synthetic get pod $pod_name -o json")
      [[ "$APP_FAILURE" != missing-pod ]] || return 1
      resource=pod
      pod_env='[]'
      if [[ "$APP_SECRET_ALL_SCOPES" == 1 ]]; then
        pod_env="$(jq -n --arg key "${APP_SECRET_ALL_KEYS[5]}" '[{name:$key,value:"ordinary-config"}]')"
      fi
      object="$(jq -n --arg id "$ENV_ID" --arg generation "$generation" --arg project "$project" --arg uid "$pod_uid" --arg name "$pod_name" --argjson pod_env "$pod_env" '
        {metadata:{name:$name,namespace:"synthetic",uid:$uid,
          labels:{"codewire.sh/environment-id":$id,"codewire.sh/type":"workspace","codewire.sh/environment-operation-generation":$generation},
          ownerReferences:[{apiVersion:"agents.x-k8s.io/v1beta1",kind:"Sandbox",name:"owned-sandbox",uid:"owned-sandbox-uid",controller:true}]},
          status:{phase:"Running"},spec:{volumes:[{name:"workspace",persistentVolumeClaim:{claimName:"owned-pvc"}}],containers:[{name:"workspace",env:
            ($pod_env + (if $project == "" then [] else [
              {name:"CODEWIRE_ENVIRONMENT_ID",value:$id},
              {name:"CODEWIRE_ENVIRONMENT_OPERATION_GENERATION",value:$generation},
              {name:"CODEWIRE_ENVIRONMENT_PROJECTION_SHA256",value:("a" * 64)}] end))}]}}')" ;;
    *) fail "unexpected Kubernetes fixture operation: $*" ;;
  esac
  if [[ "$APP_KUBE_RESOURCE" == "$resource" ]]; then jq "$APP_KUBE_MUTATION" <<<"$object";
  else printf '%s\n' "$object"; fi
}
run_application_secret_pty() {
  if [[ "$APP_SECRET_ALL_SCOPES" == 1 ]]; then
    [[ "$1" == *"${APP_SECRET_ALL_KEYS[0]}"* && "$1" == *"${APP_SECRET_ALL_KEYS[5]}"* ]] ||
      fail 'PTY did not receive every all-scope application assertion'
  else
    [[ "$1" == *'DATABASE_URL'* ]] || fail 'PTY did not receive the application assertion'
  fi
  printf 'application-secret-check-ok\n' >"$TMPDIR_SMOKE/app-pty-$2.log"
}
TEST_CW="$(declare -f cw)"
TEST_CW_WITH_TIMEOUT="$(declare -f cw_with_timeout)"

expect_failure() {
  local label="$1"; shift
  if ( "$@" ) >"$APP_TEST_ROOT/failure.out" 2>"$APP_TEST_ROOT/failure.err"; then fail "$label accepted invalid input"; fi
  pass
}

# Exercise the real artifact guard independently of secret provisioning.
fixture
printf 'fixed-benign-receipt\n' >"$TMPDIR_SMOKE/artifact.out"
# Reproduce the old false positive before asserting the repaired zero-pattern path.
if ! grep -Fq -f <(printf '%s\n' "${APP_SECRET_VALUES[@]}") -- "$TMPDIR_SMOKE/artifact.out"; then
  fail 'old zero-pattern mechanism did not match the benign receipt'
fi
assert_application_artifacts_redacted "$TMPDIR_SMOKE/artifact.out" >"$APP_TEST_ROOT/guard.out" 2>"$APP_TEST_ROOT/guard.err"
[[ ! -s "$APP_TEST_ROOT/guard.out" && ! -s "$APP_TEST_ROOT/guard.err" ]] ||
  fail 'zero-pattern inspection was not silent'
pass

APP_SECRET_VALUES=(synthetic-guard-first-canary synthetic-guard-later-canary)
assert_application_artifacts_redacted "$TMPDIR_SMOKE/artifact.out"
pass
inspect_artifact_with_receipt() {
  assert_application_artifacts_redacted "$1"
  printf 'artifact-inspection-success\n'
}
assert_guard_failure_redacted() {
  [[ ! -s "$APP_TEST_ROOT/failure.out" ]] || fail 'failed inspection emitted a success receipt'
  if grep -Fq -e synthetic-guard-first-canary -e synthetic-guard-later-canary \
      "$APP_TEST_ROOT/failure.out" "$APP_TEST_ROOT/failure.err"; then
    fail 'failed inspection printed a synthetic canary'
  fi
}
for index in 0 1; do
  printf '%s\n' "${APP_SECRET_VALUES[$index]}" >"$TMPDIR_SMOKE/artifact.out"
  expect_failure "captured-pattern-$index" inspect_artifact_with_receipt "$TMPDIR_SMOKE/artifact.out"
  assert_guard_failure_redacted
  grep -Fq 'application-secret value entered smoke output or metadata; output suppressed' "$APP_TEST_ROOT/failure.err"
done
printf 'fixed-benign-receipt\n' >"$TMPDIR_SMOKE/artifact.out"
for variant in only first later; do
  case "$variant" in
    only) APP_SECRET_VALUES=('') ;;
    first) APP_SECRET_VALUES=('' synthetic-guard-later-canary) ;;
    later) APP_SECRET_VALUES=(synthetic-guard-first-canary '') ;;
  esac
  expect_failure "empty-pattern-$variant" inspect_artifact_with_receipt "$TMPDIR_SMOKE/artifact.out"
  assert_guard_failure_redacted
  grep -Fq 'application-secret artifact inspection has an empty pattern' "$APP_TEST_ROOT/failure.err"
done
APP_SECRET_VALUES=(synthetic-guard-first-canary synthetic-guard-later-canary)
for artifact in "$TMPDIR_SMOKE/nonexistent.out" "$TMPDIR_SMOKE"; do
  expect_failure artifact-read-error inspect_artifact_with_receipt "$artifact"
  assert_guard_failure_redacted
  grep -Fq 'application-secret artifact inspection failed' "$APP_TEST_ROOT/failure.err"
done

# These exercise the unchanged production wait_until with deterministic time,
# independently of application metadata assertions below. Failed predicates
# still take the real retry branch, and an expired deadline never polls.
fixture
wait_probe() {
  printf 'attempt\n' >>"$TMPDIR_SMOKE/wait-attempts"
  [[ "$APP_TEST_READY_AFTER" -gt 0 &&
     "$(wc -l <"$TMPDIR_SMOKE/wait-attempts")" -ge "$APP_TEST_READY_AFTER" ]]
}
APP_TEST_READY_AFTER=1
: >"$TMPDIR_SMOKE/wait-attempts"
wait_until immediate-ready "$(( $(seconds_now) + SMOKE_TIMEOUT_SECONDS ))" wait_probe
[[ "$(wc -l <"$TMPDIR_SMOKE/wait-attempts")" == 1 && "$(seconds_now)" == 100 ]] ||
  fail 'immediate readiness did not poll exactly once before expiry'
pass

APP_TEST_READY_AFTER=2
: >"$TMPDIR_SMOKE/wait-attempts"
wait_until retry-ready "$(( $(seconds_now) + 6 ))" wait_probe
[[ "$(wc -l <"$TMPDIR_SMOKE/wait-attempts")" == 2 && "$(seconds_now)" == 105 ]] ||
  fail 'readiness retry did not preserve the five-second polling interval'
pass

APP_TEST_READY_AFTER=0
: >"$TMPDIR_SMOKE/wait-attempts"
expect_failure readiness-expired wait_until never-ready "$(( $(seconds_now) + SMOKE_TIMEOUT_SECONDS ))" wait_probe
[[ "$(wc -l <"$TMPDIR_SMOKE/wait-attempts")" == 1 && "$(seconds_now)" == 110 ]] ||
  fail 'failed readiness did not expire after its bounded retry'
grep -Fx '[runtime-smoke] ERROR: timed out waiting for never-ready' "$APP_TEST_ROOT/failure.err" >/dev/null ||
  fail 'expired readiness did not preserve its production diagnostic'

APP_TEST_READY_AFTER=1
: >"$TMPDIR_SMOKE/wait-attempts"
expect_failure deadline-boundary wait_until already-expired "$(seconds_now)" wait_probe
[[ ! -s "$TMPDIR_SMOKE/wait-attempts" && "$(seconds_now)" == 110 ]] ||
  fail 'an already-expired deadline polled or slept'

write_fresh_login_cw() {
  local target="$1"
  cat >"$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state="$(dirname "$0")/fresh-login-state"
mkdir -p "$state"
printf '%s\n' "$*" >>"$state/calls"
case "$*" in
  *' login --org '*)
    env | sort >"$state/login-env"
    mkdir -p "$CW_CONFIG_DIR"
    printf '{}\n' >"$CW_CONFIG_DIR/config.json"
    printf '{}\n' >"$CW_CONFIG_DIR/credentials.json"
    chmod 0600 "$CW_CONFIG_DIR/config.json" "$CW_CONFIG_DIR/credentials.json" ;;
  *' whoami --output json')
    user=11111111111111111111111111111111
    [[ "$(cat "$state/variant" 2>/dev/null || true)" != wrong-user ]] || user=33333333333333333333333333333333
    printf '{"id":"%s","email":"owner@example.invalid"}\n' "$user" ;;
  *' org current')
    role=owner
    [[ "$(cat "$state/variant" 2>/dev/null || true)" != current-role ]] || role=member
    printf 'ID: 22222222222222222222222222222222\nRole: %s\n' "$role" ;;
  *' env list --output json') printf '[]\n' ;;
  *' org list --output json')
    case "$(cat "$state/variant" 2>/dev/null || true)" in
      duplicate) printf '[{"id":"22222222222222222222222222222222","role":"owner"},{"id":"22222222222222222222222222222222","role":"owner"}]\n' ;;
      wrong-target) printf '[{"id":"33333333333333333333333333333333","role":"owner"}]\n' ;;
      wrong-role) printf '[{"id":"22222222222222222222222222222222","role":"member"}]\n' ;;
      *) printf '[{"id":"22222222222222222222222222222222","role":"owner"},{"id":"33333333333333333333333333333333","role":"member"}]\n' ;;
    esac ;;
  *' logout') printf 'logout\n' >>"$state/logout" ;;
  *) exit 97 ;;
esac
EOF
  chmod 0700 "$target"
}

fresh_login_fixture() {
  fixture
  eval "$REAL_CW"
  eval "$REAL_CW_WITH_TIMEOUT"
  SMOKE_ONLY_PHASES=(application-secrets-all-scopes)
  SMOKE_AUTH_MODE=admin-oidc
  APP_SECRET_ALL_SCOPES=1
  ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE=0
  ALLOW_NON_DEV=0
  CODEWIRE_SERVER_URL=https://codewire-dev.sh
  EXPECTED_CODEWIRE_DEV_SERVER_URL=https://codewire-dev.sh
  CODEWIRE_DEV_SMOKE_API_KEY=''
  unset CODEWIRE_API_KEY CW_CONFIG_DIR
  XDG_RUNTIME_DIR="$APP_TEST_RUNTIME"
  SMOKE_TMP_PARENT="$APP_TEST_ROOT"
  CW_BIN="$APP_TEST_ROOT/fresh-login-cw"
  write_fresh_login_cw "$CW_BIN"
  rm -rf -- "$APP_TEST_ROOT/fresh-login-state"
}

fixture
SMOKE_ONLY_PHASES=(exec)
if application_secrets_selected; then fail 'ordinary phase selected application secrets'; fi
SMOKE_ONLY_PHASES=(exec application-secrets)
application_secrets_selected
pass
validate_application_secrets_options
pass
for invalid in existing keep no-kube oauth generic wrong-origin; do
  reject_options() {
    case "$invalid" in
      existing) SMOKE_EXISTING_ENV_ID=unowned ;;
      keep) SMOKE_KEEP_ENV=1 ;;
      no-kube) SMOKE_SKIP_KUBE=1 ;;
      oauth) SMOKE_AUTH_MODE=admin-oidc ;;
      generic) ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE=1 ;;
      wrong-origin) CODEWIRE_SERVER_URL=https://wrong.invalid ;;
    esac
    validate_application_secrets_options
  }
  expect_failure "$invalid" reject_options
done

fixture
SMOKE_ONLY_PHASES=(application-secrets-all-scopes)
application_all_scopes_requested
application_all_scopes_selected
pass
bash -c '
  smoke="$1"
  set -- --admin-oidc --only application-secrets-all-scopes
  source "$smoke"
  [[ "$SMOKE_AUTH_MODE" == admin-oidc && "${SMOKE_ONLY_PHASES[*]}" == application-secrets-all-scopes ]]
' _ "$REPO_ROOT/scripts/runtime/dev/smoke-dev-commodity.sh" ||
  fail 'all-scope phase was not accepted by the public option parser'
pass
SMOKE_ONLY_PHASES=(application-secrets-all-scopes exec)
application_all_scopes_requested
expect_failure mixed-all-scope-phase validate_application_all_scopes_options
SMOKE_ONLY_PHASES=(application-secrets-all-scopes application-secrets-all-scopes)
expect_failure duplicate-all-scope-phase validate_application_all_scopes_options
pass
pass

for invalid in saved-config inherited-config api-key generic-key endpoint existing keep kube-access email user-id org-id relative-cw; do
  reject_all_scope_options() {
    fresh_login_fixture
    SMOKE_SKIP_KUBE=1
    case "$invalid" in
      saved-config) CODEWIRE_ADMIN_OAUTH_CONFIG_DIR="$APP_TEST_ROOT/saved" ;;
      inherited-config) CW_CONFIG_DIR="$APP_TEST_ROOT/saved" ;;
      api-key) CODEWIRE_API_KEY=forbidden ;;
      generic-key) ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE=1 ;;
      endpoint) CODEWIRE_SERVER_URL=https://other.invalid ;;
      existing) SMOKE_EXISTING_ENV_ID=unowned ;;
      keep) SMOKE_KEEP_ENV=1 ;;
      kube-access) SMOKE_SKIP_KUBE=0 ;;
      email) EXPECTED_CODEWIRE_ADMIN_EMAIL='' ;;
      user-id) EXPECTED_CODEWIRE_ADMIN_USER_ID=not-an-id ;;
      org-id) EXPECTED_CODEWIRE_ORGANIZATION_ID=00000000000000000000000000000000 ;;
      relative-cw) CW_BIN=relative-cw ;;
    esac
    validate_application_all_scopes_options
  }
  expect_failure "$invalid" reject_all_scope_options
done

fresh_login_fixture
SMOKE_SKIP_KUBE=1
validate_application_all_scopes_options
export AWS_SECRET_ACCESS_KEY=forbidden-owner-provider SSH_AUTH_SOCK=/forbidden/owner-agent
prepare_fresh_oauth_cli
fresh_runtime="$SMOKE_OAUTH_RUNTIME_DIR"
fresh_login="$SMOKE_OAUTH_LOGIN_DIR"
[[ "$(stat -c %a "$fresh_runtime")" == 700 && "$(stat -c %a "$fresh_login")" == 700 ]]
login_env="$APP_TEST_ROOT/fresh-login-state/login-env"
grep -Fx "HOME=$TMPDIR_SMOKE/auth-home" "$login_env" >/dev/null
grep -Fx "CW_CONFIG_DIR=$fresh_login" "$login_env" >/dev/null
grep -Fx "XDG_RUNTIME_DIR=$fresh_runtime" "$login_env" >/dev/null
grep -Fx "DBUS_SESSION_BUS_ADDRESS=unix:path=$fresh_runtime/no-owner-bus" "$login_env" >/dev/null
if grep -Eq '^(AWS_|SSH_AUTH_SOCK=|CODEWIRE_API_KEY=)' "$login_env"; then
  fail 'fresh login inherited owner provider, SSH or API-key state'
fi
cleanup_fresh_oauth_login
[[ ! -e "$fresh_runtime" ]]
grep -Fx logout "$APP_TEST_ROOT/fresh-login-state/logout" >/dev/null
unset AWS_SECRET_ACCESS_KEY SSH_AUTH_SOCK
pass

for variant in wrong-user duplicate wrong-target wrong-role current-role; do
  fresh_login_fixture
  mkdir -p "$APP_TEST_ROOT/fresh-login-state"
  printf '%s\n' "$variant" >"$APP_TEST_ROOT/fresh-login-state/variant"
  reject_fresh_identity() {
    trap 'cleanup_fresh_oauth_login' EXIT
    prepare_fresh_oauth_cli
  }
  expect_failure "$variant" reject_fresh_identity
  if find "$APP_TEST_RUNTIME" -mindepth 1 -maxdepth 1 -name '.cwapp-*' | grep -q .; then
    fail "$variant retained fresh auth material after failure"
  fi
  grep -Fx logout "$APP_TEST_ROOT/fresh-login-state/logout" >/dev/null ||
    fail "$variant did not attempt logout during failure cleanup"
done
pass

# Exercise the shell integration with a synthetic runtime, not a real browser,
# login, provider or credential reader. The TypeScript helper has its own tests.
browser_login_fixture() {
  fresh_login_fixture
  DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE="$APP_TEST_ROOT/browser-input.json"
  DEV_SMOKE_BROWSER_AUTH_BUN_BIN="$APP_TEST_ROOT/synthetic-bun"
  DEV_SMOKE_BROWSER_AUTH_CHROMIUM_BIN="$CW_BIN"
  printf 'synthetic-browser-input-not-read-by-shell\n' >"$DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE"
  chmod 0600 "$DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE"
  cat >"$DEV_SMOKE_BROWSER_AUTH_BUN_BIN" <<'BROWSER_STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ "$HOME" == /nonexistent && "$PATH" == /usr/bin:/bin &&
   -z "${AWS_SECRET_ACCESS_KEY+x}" && -z "${SSH_AUTH_SOCK+x}" &&
   -z "${CW_CONFIG_DIR+x}" && -z "${BAO_TOKEN+x}" ]] || exit 91
[[ "$1" == --no-env-file && "$2" == --config=/dev/null && "$3" == --no-install &&
   "$4" == */apps/dashboard/scripts/prepare-dev-smoke-browser-auth.ts ]] || exit 92
helper_script="$4"
shift 4
[[ ( $# == 14 || ( $# == 16 && "${15}" == --ux-walkthrough && "${16}" == enabled ) ) && "$1" == --cw-bin && "$3" == --config-dir &&
   "$5" == --credential-file && "$7" == --expected-user-id &&
   "$8" == 11111111111111111111111111111111 && "$9" == --expected-email &&
   "${10}" == owner@example.invalid && "${11}" == --expected-org-id &&
   "${12}" == 22222222222222222222222222222222 && "${13}" == --chromium-executable ]] || exit 93
config_dir="$4"
expected_root="${helper_script%/apps/dashboard/scripts/prepare-dev-smoke-browser-auth.ts}"
[[ "$PWD" == "$expected_root" && "$TMPDIR" == "$(dirname "$config_dir")"/.cw-browser-auth.* &&
   "$(stat -c %a "$TMPDIR")" == 700 && -z "$(ls -A "$TMPDIR")" &&
   "$(stat -c %a "$config_dir")" == 700 && -z "$(ls -A "$config_dir")" ]] || exit 94
printf 'synthetic-bun-workspace\n' >"$TMPDIR/cache-marker"
state="$(dirname "$2")/fresh-login-state"
mkdir -p "$state"
printf 'browser-helper\n' >"$state/browser-called"
printf '%s\n' "${15:-none}" >"$state/ux-mode"
CW_CONFIG_DIR="$config_dir" "$2" --server https://codewire-dev.sh login --org "${12}"
[[ "$(cat "$state/variant" 2>/dev/null || true)" != helper-failed ]] || exit 95
BROWSER_STUB
  chmod 0700 "$DEV_SMOKE_BROWSER_AUTH_BUN_BIN"
}

for phase in application-secrets-all-scopes provider-ssh; do
  browser_login_fixture
  SMOKE_ONLY_PHASES=("$phase")
  [[ "$phase" == application-secrets-all-scopes ]] || APP_SECRET_ALL_SCOPES=0
  validate_dev_smoke_browser_auth
  if [[ "$phase" == provider-ssh ]]; then validate_provider_ssh_options; fi
  export AWS_SECRET_ACCESS_KEY=forbidden-owner-provider SSH_AUTH_SOCK=/forbidden/owner-agent BAO_TOKEN=forbidden
  prepare_fresh_oauth_cli
  grep -qx browser-helper "$APP_TEST_ROOT/fresh-login-state/browser-called" || fail 'browser helper was not selected'
  if [[ "$phase" == application-secrets-all-scopes ]]; then
    grep -qx -- --ux-walkthrough "$APP_TEST_ROOT/fresh-login-state/ux-mode" || fail 'all-scope UX was not selected'
  else
    grep -qx none "$APP_TEST_ROOT/fresh-login-state/ux-mode" || fail 'provider SSH gained UX mutation'
  fi
  [[ -z "$(find "$SMOKE_OAUTH_RUNTIME_DIR" -mindepth 1 -maxdepth 1 -name '.cw-browser-auth-*' -print -quit)" ]] ||
    fail 'browser helper retained its disposable package workspace'
  cleanup_fresh_oauth_login
  [[ ! -e "$SMOKE_OAUTH_RUNTIME_DIR" && -f "$DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE" ]] ||
    fail 'fresh browser cleanup retained login or removed its input credential file'
  unset AWS_SECRET_ACCESS_KEY SSH_AUTH_SOCK BAO_TOKEN
  pass
done

for variant in helper-failed wrong-user; do
  browser_login_fixture
  mkdir -p "$APP_TEST_ROOT/fresh-login-state"
  printf '%s\n' "$variant" >"$APP_TEST_ROOT/fresh-login-state/variant"
  reject_browser_login() {
    trap cleanup_fresh_oauth_login EXIT
    prepare_fresh_oauth_cli
  }
  expect_failure "$variant" reject_browser_login
  [[ -z "$(find "$APP_TEST_RUNTIME" -mindepth 1 -maxdepth 1 -name '.cwapp-*')" ]] ||
    fail 'failed browser helper retained fresh auth state'
  grep -qx logout "$APP_TEST_ROOT/fresh-login-state/logout" || fail 'failed browser helper skipped logout'
  pass
done

for invalid in partial-runtime public-input missing-id saved-login; do
  reject_browser_inputs() {
    browser_login_fixture
    case "$invalid" in
      partial-runtime) DEV_SMOKE_BROWSER_AUTH_BUN_BIN='' ;;
      public-input) chmod 0644 "$DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE" ;;
      missing-id) EXPECTED_CODEWIRE_ADMIN_USER_ID='' ;;
      saved-login) CODEWIRE_ADMIN_OAUTH_CONFIG_DIR=/unowned/login ;;
    esac
    validate_dev_smoke_browser_auth
  }
  expect_failure "$invalid" reject_browser_inputs
done

fresh_login_fixture
prepare_fresh_oauth_cli
forced_runtime="$SMOKE_OAUTH_RUNTIME_DIR"
APP_SECRET_USER_ATTEMPTS=(FORCE_CLEANUP)
SMOKE_COLLECT_FAILURE_DIAGNOSTICS=0
if (
  # shellcheck disable=SC2329 # Called by the EXIT cleanup through the override.
  cleanup_application_secrets() { die 'forced explicit cleanup exit'; }
  trap cleanup EXIT
  false
) >"$TMPDIR_SMOKE/forced-cleanup.out" 2>"$TMPDIR_SMOKE/forced-cleanup.err"; then
  fail 'explicit application cleanup exit did not fail acceptance'
fi
[[ ! -e "$forced_runtime" ]] || fail 'explicit application cleanup exit retained fresh auth material'
grep -Fx logout "$APP_TEST_ROOT/fresh-login-state/logout" >/dev/null ||
  fail 'explicit application cleanup exit skipped logout'
[[ "$(wc -l <"$APP_TEST_ROOT/fresh-login-state/logout")" == 1 ]] ||
  fail 'explicit application cleanup exit logged out more than once'
pass
eval "$TEST_CW"
eval "$TEST_CW_WITH_TIMEOUT"

fixture
prepare_application_secrets
jq -e '.version == 1 and (has("schema_version") | not) and .secrets.project == "platform:id:00000000-0000-4000-8000-000000000001" and
  .environment.CW_DEV_PRECEDENCE == "ordinary-config" and (has("credentials") | not)' "$APP_SECRET_DOCUMENT" >/dev/null
/bin/sh -n < <(jq -r .install_command "$APP_SECRET_DOCUMENT")
/bin/sh -n < <(jq -r .startup_script "$APP_SECRET_DOCUMENT")
pass
create_environment
run_application_secrets_smoke
[[ "$(jq -r '.[0].operation_generation' "$TMPDIR_SMOKE/environments.db")" == 1 ]]
[[ "$(<"$TMPDIR_SMOKE/pod-incarnation")" == 3 ]]
cleanup_application_secrets
[[ "$(jq length "$TMPDIR_SMOKE/projects.db")" == 0 ]]
[[ "$(jq -r '.[0].state' "$TMPDIR_SMOKE/environments.db")" == destroyed ]]
pass
expect_failure terminal-info-hidden cw env --platform info "$ENV_ID" --output json
application_environment_destroyed
grep -Fq 'env --platform list --all --output json' "$TMPDIR_SMOKE/calls"
pass


# Shared scopes must begin empty, and the final metadata read is an ownership
# fence immediately before environment creation.
fixture
APP_SECRET_ALL_SCOPES=1
printf '[{"key":"FOREIGN","created_at":"now","updated_at":"now"}]\n' >"$TMPDIR_SMOKE/user.db"
expect_failure shared-user-nonempty prepare_application_secrets
[[ "$(jq length "$TMPDIR_SMOKE/projects.db")" == 0 ]]
[[ "$(jq length "$TMPDIR_SMOKE/organization.db")" == 0 ]]
pass

fixture
APP_SECRET_ALL_SCOPES=1
printf '[{"key":"FOREIGN","created_at":"now","updated_at":"now"}]\n[]\n' >"$TMPDIR_SMOKE/user.db"
expect_failure multiple-shared-documents prepare_application_secrets
[[ "$(jq -s length "$TMPDIR_SMOKE/user.db")" == 2 ]]
[[ "$(jq length "$TMPDIR_SMOKE/projects.db")" == 0 ]]
pass

fixture
APP_SECRET_ALL_SCOPES=1
prepare_application_secrets
jq '. + [{key:"FOREIGN",created_at:"now",updated_at:"now"}]' "$TMPDIR_SMOKE/user.db" >"$TMPDIR_SMOKE/db.next"
mv "$TMPDIR_SMOKE/db.next" "$TMPDIR_SMOKE/user.db"
expect_failure extra-final-key create_environment
if grep -Fq 'env create' "$TMPDIR_SMOKE/calls"; then fail 'environment create ran after the final scope fence failed'; fi
expect_failure unknown-key-cleanup cleanup_application_secrets
jq -e 'map(.key) == ["FOREIGN"]' "$TMPDIR_SMOKE/user.db" >/dev/null ||
  fail 'cleanup removed an unknown shared-scope key or retained an owned key'
[[ "$(jq length "$TMPDIR_SMOKE/organization.db")" == 0 ]]
pass

fixture
APP_SECRET_ALL_SCOPES=1
APP_FAILURE=lost-organization-write
if (trap 'cleanup_application_secrets' EXIT; prepare_application_secrets) \
    >"$TMPDIR_SMOKE/partial.out" 2>"$TMPDIR_SMOKE/partial.err"; then
  fail 'lost shared-scope write response unexpectedly succeeded'
fi
[[ "$(jq length "$TMPDIR_SMOKE/organization.db")" == 0 ]] ||
  fail 'partial write cleanup did not remove the exact attempted key'
[[ "$(jq length "$TMPDIR_SMOKE/projects.db")" == 0 ]] ||
  fail 'partial shared-scope write unexpectedly reached project creation'
pass

fixture
APP_SECRET_ALL_SCOPES=1
prepare_application_secrets
jq '.[0].value="synthetic-leak"' "$TMPDIR_SMOKE/organization.db" >"$TMPDIR_SMOKE/db.next"
mv "$TMPDIR_SMOKE/db.next" "$TMPDIR_SMOKE/organization.db"
expect_failure leaky-final-metadata create_environment
pass

fixture
APP_SECRET_ALL_SCOPES=1
prepare_application_secrets
APP_FAILURE=cleanup-user
expect_failure shared-cleanup cleanup_application_secrets
pass

fixture
APP_SECRET_ALL_SCOPES=1
prepare_application_secrets
config_key="${APP_SECRET_ALL_KEYS[5]}"
jq -e --arg project "platform:id:${APP_SECRET_IDS[0]}" --arg config "$config_key" '
  .version == 1 and .secrets == {project:$project,organization:true,user:"platform"} and
  (.environment | keys) == [$config] and .environment[$config] == "ordinary-config" and
  (has("credentials") | not)
' "$APP_SECRET_DOCUMENT" >/dev/null
/bin/sh -n < <(jq -r .install_command "$APP_SECRET_DOCUMENT")
/bin/sh -n < <(jq -r .startup_script "$APP_SECRET_DOCUMENT")
if grep -Fq preservation-marker < <(jq -r '.install_command,.startup_script' "$APP_SECRET_DOCUMENT"); then
  fail 'all-scope setup scripts recreate the post-setup workspace marker'
fi
create_environment
run_application_secrets_smoke
[[ "$APP_WORKSPACE_MARKER_SHA256" =~ ^[0-9a-f]{64}$ ]]
[[ "$(sha256sum "$TMPDIR_SMOKE/workspace-marker" | cut -d ' ' -f 1)" == "$APP_WORKSPACE_MARKER_SHA256" ]]
[[ "$(awk '$0 == "application-restart-witness-ready" { count++ } END { print count + 0 }' \
  "$TMPDIR_SMOKE"/app-restart-witness-*.log)" == 2 ]]
jq -e '
  length == 2 and
  ([.[].session_id] | unique | length) == 2 and
  all(.[]; .state == "Interrupted")
' "$TMPDIR_SMOKE/sessions.db" >/dev/null ||
  fail 'all-scope restart witnesses were not distinct durable sessions interrupted by their source updates'
jq -e 'length == 2 and all(.[]; .state == "Terminated")' \
  "$TMPDIR_SMOKE/host-attachments.db" >/dev/null ||
  fail 'all-scope fixture did not terminate each modeled host attachment'
[[ "$(jq -r .session_id "$TMPDIR_SMOKE"/app-restart-witness-*-launch.json | sort -u | wc -l)" == 2 ]] ||
  fail 'JSON witness launches did not capture two distinct session identities'
grep -Fq -- '--secrets platform:id:00000000-0000-4000-8000-000000000002 --user-secrets platform --org-secrets --yes --output json' \
  "$TMPDIR_SMOKE/calls" || fail 'all-scope update did not resubmit every selector'
jq -e '.[0].source_selection.secrets == {}' "$TMPDIR_SMOKE/environments.db" >/dev/null
cleanup_application_secrets
[[ "$(jq length "$TMPDIR_SMOKE/projects.db")" == 0 ]]
[[ "$(jq length "$TMPDIR_SMOKE/user.db")" == 0 ]]
[[ "$(jq length "$TMPDIR_SMOKE/organization.db")" == 0 ]]
pass

# Execute the generated setup scripts with real shell expansion. In particular,
# clear must record absent for every scoped key while retaining ordinary config.
guest_root="$TMPDIR_SMOKE/generated-guest"
mkdir -p "$guest_root/workspace" "$guest_root/home/.codewire/daemon/sessions/one"
install="$(jq -r .install_command "$APP_SECRET_DOCUMENT")"
startup="$(jq -r .startup_script "$APP_SECRET_DOCUMENT")"
install="${install//\/workspace/$guest_root/workspace}"
startup="${startup//\/workspace/$guest_root/workspace}"
all_env_a=(
  "${APP_SECRET_ALL_KEYS[0]}=${APP_SECRET_VALUES[0]}"
  "${APP_SECRET_ALL_KEYS[1]}=${APP_SECRET_VALUES[7]}"
  "${APP_SECRET_ALL_KEYS[2]}=${APP_SECRET_VALUES[4]}"
  "${APP_SECRET_ALL_KEYS[3]}=${APP_SECRET_VALUES[8]}"
  "${APP_SECRET_ALL_KEYS[4]}=${APP_SECRET_VALUES[5]}"
  "${APP_SECRET_ALL_KEYS[5]}=ordinary-config"
)
env "${all_env_a[@]}" /bin/sh -c "$install"
env "${all_env_a[@]}" /bin/sh -c "$startup"
printf 'fixture-random-workspace-marker\n' >"$guest_root/workspace/.cw-app-smoke/preservation-marker"
marker_sha256="$(sha256sum "$guest_root/workspace/.cw-app-smoke/preservation-marker" | cut -d ' ' -f 1)"
jq -n --arg key "${APP_SECRET_ALL_KEYS[5]}" '{($key):"ordinary-config"}' \
  >"$guest_root/home/.codewire/environment.json"
# The daemon never serializes a session's environment (launch values stay
# with the live owner), so a saved record has no env field.
jq -n '{name:"one"}' >"$guest_root/home/.codewire/daemon/sessions/one/session.json"
check="$(application_all_scopes_guest_check APP_SECRET_ALL_HASHES_A "$marker_sha256")"
check="${check//\/workspace/$guest_root/workspace}"
check="${check//\/home\/codewire/$guest_root/home}"
env "${all_env_a[@]}" /bin/sh -c "$check" >"$TMPDIR_SMOKE/all-check-a.out"
grep -qx application-secret-check-ok "$TMPDIR_SMOKE/all-check-a.out"
printf 'replacement-marker\n' >"$guest_root/workspace/.cw-app-smoke/preservation-marker"
expect_failure marker-replacement env "${all_env_a[@]}" /bin/sh -c "$check"
grep -qx 'application check failed: workspace-marker-replaced' "$APP_TEST_ROOT/failure.err"
printf 'fixture-random-workspace-marker\n' >"$guest_root/workspace/.cw-app-smoke/preservation-marker"
rm -f -- "$guest_root/workspace/.cw-app-smoke/preservation-marker"
expect_failure marker-missing env "${all_env_a[@]}" /bin/sh -c "$check"
grep -qx 'application check failed: workspace-marker-missing' "$APP_TEST_ROOT/failure.err"
printf 'fixture-random-workspace-marker\n' >"$guest_root/workspace/.cw-app-smoke/preservation-marker"
all_env_b=(
  "${APP_SECRET_ALL_KEYS[0]}=${APP_SECRET_VALUES[0]}"
  "${APP_SECRET_ALL_KEYS[1]}=${APP_SECRET_VALUES[11]}"
  "${APP_SECRET_ALL_KEYS[2]}=${APP_SECRET_VALUES[4]}"
  "${APP_SECRET_ALL_KEYS[3]}=${APP_SECRET_VALUES[12]}"
  "${APP_SECRET_ALL_KEYS[4]}=${APP_SECRET_VALUES[5]}"
  "${APP_SECRET_ALL_KEYS[5]}=ordinary-config"
)
env "${all_env_b[@]}" /bin/sh -c "$startup"
check="$(application_all_scopes_guest_check APP_SECRET_ALL_HASHES_B "$marker_sha256")"
check="${check//\/workspace/$guest_root/workspace}"
check="${check//\/home\/codewire/$guest_root/home}"
env "${all_env_b[@]}" /bin/sh -c "$check" >"$TMPDIR_SMOKE/all-check-b.out"
grep -qx application-secret-check-ok "$TMPDIR_SMOKE/all-check-b.out"
env "${APP_SECRET_ALL_KEYS[5]}=ordinary-config" /bin/sh -c "$startup"
check="$(application_all_scopes_guest_check APP_SECRET_ALL_HASHES_CLEAR "$marker_sha256")"
check="${check//\/workspace/$guest_root/workspace}"
check="${check//\/home\/codewire/$guest_root/home}"
env "${APP_SECRET_ALL_KEYS[5]}=ordinary-config" /bin/sh -c "$check" >"$TMPDIR_SMOKE/all-check-clear.out"
grep -qx application-secret-check-ok "$TMPDIR_SMOKE/all-check-clear.out"
for value in "${APP_SECRET_VALUES[@]}"; do
  if grep -Fq "$value" <<<"$install$startup$check"; then fail 'generated guest assertion retained a synthetic canary'; fi
done
pass

for failure in attachment-terminated-session-running marker-replacement marker-missing; do
  reject_public_restart_proof() {
    fixture
    trap 'cp "$TMPDIR_SMOKE/sessions.db" "$APP_TEST_ROOT/failure-sessions.json"; cp "$TMPDIR_SMOKE/host-attachments.db" "$APP_TEST_ROOT/failure-host-attachments.json"; cp "$TMPDIR_SMOKE/calls" "$APP_TEST_ROOT/failure-calls"' EXIT
    APP_SECRET_ALL_SCOPES=1
    prepare_application_secrets
    create_environment
    APP_FAILURE="$failure"
    run_application_secrets_smoke
  }
  expect_failure "$failure" reject_public_restart_proof
  case "$failure" in
    attachment-terminated-session-running)
      # `cw run --output json` has already returned on the host. Leaving its
      # exact durable session Running must still fail the restart proof.
      grep -Fq 'timed out waiting for exact managed session fixture-witness-1 to reach a terminal state after source b' \
        "$APP_TEST_ROOT/failure.err"
      jq -e 'length == 1 and .[0].session_id == "fixture-witness-1" and .[0].state == "Running"' \
        "$APP_TEST_ROOT/failure-sessions.json" >/dev/null
      jq -e 'length == 1 and .[0].session_id == "fixture-witness-1" and .[0].state == "Terminated"' \
        "$APP_TEST_ROOT/failure-host-attachments.json" >/dev/null
      grep -Fq 'run --no-tty --output json' "$APP_TEST_ROOT/failure-calls"
      grep -Fq 'logs 00000000-0000-4000-8000-000000000099 fixture-witness-1 --raw' \
        "$APP_TEST_ROOT/failure-calls" ;;
    marker-replacement|marker-missing)
      grep -Fq 'managed application-secret exec failed; output suppressed' "$APP_TEST_ROOT/failure.err" ;;
  esac
done

# A malformed acknowledgement cannot be excused by a later successful restart.
for failure in bad-update bad-clear; do
  reject_update_journey() { fixture; prepare_application_secrets; create_environment; APP_FAILURE="$failure"; run_application_secrets_smoke; }
  expect_failure "$failure" reject_update_journey
done

fixture
ENV_ID=synthetic-env
for project in platform:id:00000000-0000-4000-8000-000000000002 ''; do
  jq -n --arg project "$project" '{environment_id:"synthetic-env",operation_generation:7,outcome:"restart_required",
    selection:{secrets:(if $project == "" then {} else {project:$project} end),credentials:null,profile_revision:null}}' \
    >"$TMPDIR_SMOKE/update-valid.json"
  assert_application_source_update "$TMPDIR_SMOKE/update-valid.json" "$project" 7
  pass
  for variant in wrong-id missing-generation new-generation missing-outcome wrong-outcome missing-selection missing-secrets null-secrets wrong-project null-project extra-user false-user extra-org null-org missing-credentials missing-revision pinned-credentials; do
    case "$variant" in
      wrong-id) filter='.environment_id="other-env"' ;;
      missing-generation) filter='del(.operation_generation)' ;;
      new-generation) filter='.operation_generation=8' ;;
      missing-outcome) filter='del(.outcome)' ;;
      wrong-outcome) filter='.outcome="stored"' ;;
      missing-selection) filter='del(.selection)' ;;
      missing-secrets) filter='del(.selection.secrets)' ;;
      null-secrets) filter='.selection.secrets=null' ;;
      wrong-project) filter='.selection.secrets.project="platform:id:other"' ;;
      null-project) filter='.selection.secrets.project=null' ;;
      extra-user) filter='.selection.secrets.user="platform"' ;;
      false-user) filter='.selection.secrets.user=false' ;;
      extra-org) filter='.selection.secrets.organization=true' ;;
      null-org) filter='.selection.secrets.organization=null' ;;
      missing-credentials) filter='del(.selection.credentials)' ;;
      missing-revision) filter='del(.selection.profile_revision)' ;;
      pinned-credentials) filter='.selection.credentials={profile:"platform:id:other"} | .selection.profile_revision=1' ;;
    esac
    jq "$filter" "$TMPDIR_SMOKE/update-valid.json" >"$TMPDIR_SMOKE/update-invalid.json"
    expect_failure "$variant" assert_application_source_update "$TMPDIR_SMOKE/update-invalid.json" "$project" 7
  done
done
: >"$TMPDIR_SMOKE/update-invalid.json"
expect_failure empty-update assert_application_source_update "$TMPDIR_SMOKE/update-invalid.json" '' 7

for metadata in '[]' '{}' '[{"id":"other","state":"destroyed"}]' '[{"id":"synthetic-env","state":"destroyed"},{"id":"synthetic-env","state":"destroyed"}]' '[{"id":"synthetic-env","state":"destroying"}]'; do
  printf '%s\n' "$metadata" >"$TMPDIR_SMOKE/environments.db"
  expect_failure invalid-terminal-row application_environment_destroyed
done

for variant in scope leak; do
  reject_prepare() { fixture; APP_FAILURE="$variant"; prepare_application_secrets; }
  expect_failure "$variant" reject_prepare
done
reject_stale_pod() { fixture; prepare_application_secrets; create_environment; APP_FAILURE=stale-pod; run_application_secrets_smoke; }
expect_failure stale-pod reject_stale_pod

# Real topology has no claim-uid Pod label. Pin the controller UIDs instead;
# hostile labels, ambiguous controllers and stale incarnations cannot pass.
fixture
prepare_application_secrets
create_environment
capture_application_pod a 1
grep -Fq 'get sandbox owned-sandbox -o json' "$TMPDIR_SMOKE/calls"
grep -Fq 'get pod owned-sandbox -o json' "$TMPDIR_SMOKE/calls"
if grep -Fq 'get pod -l' "$TMPDIR_SMOKE/calls"; then fail 'Pod discovery used label fallback'; fi
pass
APP_ANNOTATED_POD=1
capture_application_pod a 1
grep -Fq 'get pod annotated-pod -o json' "$TMPDIR_SMOKE/calls"
pass
APP_FAILURE=missing-pod
expect_failure missing-annotated-pod capture_application_pod a 1
APP_FAILURE=''; APP_ANNOTATED_POD=0
for variant in \
  'claim|del(.status.sandbox)' \
  'claim|.status.sandbox.name=""' \
  'claim|.metadata.uid=""' \
  'claim|.metadata.name="other"' \
  'claim|.metadata.labels["codewire.sh/environment-id"]="other"' \
  'claim|.metadata.deletionTimestamp="deleting"' \
  'sandbox|.metadata.uid=""' \
  'sandbox|.metadata.deletionTimestamp="deleting"' \
  'sandbox|.metadata.ownerReferences[0].uid="foreign-claim"' \
  'sandbox|.metadata.ownerReferences[0].name="foreign-claim"' \
  'sandbox|.metadata.ownerReferences[0].apiVersion="agents.x-k8s.io/v1beta1"' \
  'sandbox|.metadata.ownerReferences[0].controller=false' \
  'sandbox|.metadata.ownerReferences += .metadata.ownerReferences' \
  'sandbox|.metadata.annotations["agents.x-k8s.io/pod-name"]="wrong-pod"' \
  'pod|.metadata.uid=""' \
  'pod|.metadata.namespace="other"' \
  'pod|.metadata.name="other"' \
  'pod|.metadata.deletionTimestamp="deleting"' \
  'pod|.status.phase="Pending"' \
  'pod|.metadata.ownerReferences[0].uid="foreign-sandbox"' \
  'pod|.metadata.ownerReferences[0].name="foreign-sandbox"' \
  'pod|.metadata.ownerReferences[0].apiVersion="extensions.agents.x-k8s.io/v1beta1"' \
  'pod|.metadata.ownerReferences[0].controller=false' \
  'pod|.metadata.ownerReferences += .metadata.ownerReferences' \
  'pod|.metadata.labels["codewire.sh/environment-id"]="other"' \
  'pod|.metadata.labels["codewire.sh/type"]="gateway"' \
  'pod|.metadata.labels["codewire.sh/environment-operation-generation"]="2"' \
  'pod|.spec.containers += .spec.containers'; do
  APP_KUBE_RESOURCE="${variant%%|*}"; APP_KUBE_MUTATION="${variant#*|}"
  expect_failure "$variant" capture_application_pod a 1
done

reject_cleanup() { fixture; prepare_application_secrets; APP_FAILURE=cleanup; cleanup_application_secrets; }
expect_failure cleanup reject_cleanup

fixture
ENV_ID=synthetic-env
printf '[{"id":"synthetic-env","state":"running","operation_generation":3}]\n' >"$TMPDIR_SMOKE/environments.db"
expect_failure missing-clear-metadata application_environment_ready '' 2

fixture
prepare_application_secrets
create_environment
project="platform:id:${APP_SECRET_IDS[0]}"
application_environment_ready "$project" 0
pass
application_environment_ready "$project" 1
pass
expect_failure stale-workflow-authority application_environment_ready "$project" 2
cp "$TMPDIR_SMOKE/environments.db" "$TMPDIR_SMOKE/setup-complete.json"
for filter in '.[0].setup_complete=false' 'del(.[0].setup_complete)' '.[0].setup_complete="true"' '.[0].setup_error="setup failed"' \
  '.[0].state="stopping"' '.[0].operation_generation=0' '.[0].operation_generation=null' '.[0].operation_generation="1"'; do
  jq "$filter" "$TMPDIR_SMOKE/setup-complete.json" >"$TMPDIR_SMOKE/environments.db"
  expect_failure incomplete-or-failed-setup application_environment_ready "$project" 0
done

# Exercise the generated check against isolated ordinary/session files. Only
# fixed test paths are substituted; the production script never accepts paths.
fixture
guest="$TMPDIR_SMOKE/guest"; mkdir -p "$guest/workspace/.cw-app-smoke" "$guest/home/.codewire/daemon/sessions/one"
printf '1\n' >"$guest/workspace/.cw-app-smoke/install-count"
printf 'workspace-preserved\n' >"$guest/workspace/.cw-app-smoke/preserved"
printf '{"CW_DEV_PRECEDENCE":"ordinary-config"}\n' >"$guest/home/.codewire/environment.json"
printf '{"name":"one"}\n' >"$guest/home/.codewire/daemon/sessions/one/session.json"
expected="$(printf synthetic-application | sha256sum | cut -d ' ' -f 1)"
printf '%s\n' "$expected" >"$guest/workspace/.cw-app-smoke/startup-sha"
check="$(application_guest_check "$expected")"
check="${check//\/workspace/$guest/workspace}"
check="${check//\/home\/codewire/$guest/home}"
DATABASE_URL=synthetic-application CW_DEV_PRECEDENCE=ordinary-config /bin/sh -c "$check" >"$TMPDIR_SMOKE/check.out"
grep -qx application-secret-check-ok "$TMPDIR_SMOKE/check.out"
pass
# A record that persisted any launch environment is refused.
printf '{"name":"one","env":["CW_DEV_PRECEDENCE=ordinary-config"]}\n' \
  >"$guest/home/.codewire/daemon/sessions/one/session.json"
expect_failure persisted-session-environment env DATABASE_URL=synthetic-application \
  CW_DEV_PRECEDENCE=ordinary-config /bin/sh -c "$check"
printf '{"name":"one"}\n' >"$guest/home/.codewire/daemon/sessions/one/session.json"
expect_failure missing-projection env -u DATABASE_URL CW_DEV_PRECEDENCE=ordinary-config /bin/sh -c "$check"
grep -qx 'application check failed: missing-projection' "$APP_TEST_ROOT/failure.err"
expect_failure wrong-projection env DATABASE_URL=wrong-synthetic-value CW_DEV_PRECEDENCE=ordinary-config /bin/sh -c "$check"
grep -qx 'application check failed: current-projection' "$APP_TEST_ROOT/failure.err"
printf 'old-startup\n' >"$guest/workspace/.cw-app-smoke/startup-sha"
expect_failure stale-startup env DATABASE_URL=synthetic-application CW_DEV_PRECEDENCE=ordinary-config /bin/sh -c "$check"
grep -qx 'application check failed: startup-projection' "$APP_TEST_ROOT/failure.err"
printf '%s\n' "$expected" >"$guest/workspace/.cw-app-smoke/startup-sha"
printf '{"DATABASE_URL":"forbidden-ordinary-value","CW_DEV_PRECEDENCE":"ordinary-config"}\n' >"$guest/home/.codewire/environment.json"
expect_failure persisted-ordinary-value env DATABASE_URL=synthetic-application CW_DEV_PRECEDENCE=ordinary-config /bin/sh -c "$check"
printf '{"CW_DEV_PRECEDENCE":"ordinary-config"}\n' >"$guest/home/.codewire/environment.json"
printf '2\n' >"$guest/workspace/.cw-app-smoke/install-count"
expect_failure repeated-install env DATABASE_URL=synthetic-application CW_DEV_PRECEDENCE=ordinary-config /bin/sh -c "$check"
printf '1\n' >"$guest/workspace/.cw-app-smoke/install-count"
printf '{"env":["DATABASE_URL=forbidden-persisted-value"]}\n' >"$guest/home/.codewire/daemon/sessions/one/session.json"
expect_failure persisted-session-value env DATABASE_URL=synthetic-application CW_DEV_PRECEDENCE=ordinary-config /bin/sh -c "$check"
printf '{"name":"one"}\n' >"$guest/home/.codewire/daemon/sessions/one/session.json"
printf 'absent\n' >"$guest/workspace/.cw-app-smoke/startup-sha"
check="$(application_guest_check absent)"; check="${check//\/workspace/$guest/workspace}"; check="${check//\/home\/codewire/$guest/home}"
env -u DATABASE_URL CW_DEV_PRECEDENCE=ordinary-config /bin/sh -c "$check" >"$TMPDIR_SMOKE/check.out"
grep -qx application-secret-check-ok "$TMPDIR_SMOKE/check.out"
pass
expect_failure stale-cleared-value env DATABASE_URL=synthetic-application CW_DEV_PRECEDENCE=ordinary-config /bin/sh -c "$check"

# A synthetic CLI requires terminal stdin for size detection and nonterminal
# stdout for exit propagation, then allocates an actual guest PTY on --tty.
(
  eval "$REAL_APPLICATION_PTY"
  CW_BIN="$TMPDIR_SMOKE/cw-pty-fixture"
  # shellcheck disable=SC2016 # Literal synthetic executable, not host expansion.
  printf '%s\n' '#!/bin/bash' 'set -euo pipefail' 'test -t 0; ! test -t 1; stty size >/dev/null' \
    'tty=0; while (($#)) && [[ "$1" != -- ]]; do [[ "$1" != --tty ]] || tty=1; shift; done' \
    '[[ "$tty" == 1 ]]; shift' \
    'if [[ "${APP_PTY_WITHOUT_TERMINAL:-0}" == 1 ]]; then exec "$@"; fi' \
    'printf -v command "%q " "$@"' 'exec script -qefc "$command" /dev/null </dev/null' >"$CW_BIN"
  chmod 0700 "$CW_BIN"
  unset CODEWIRE_DEV_SMOKE_API_KEY CODEWIRE_API_KEY
  run_application_secret_pty "printf 'application-secret-check-ok\\n'" actual
  expect_failure pty-exit-status run_application_secret_pty "printf 'application-secret-check-ok\\n'; exit 7" failure
  export APP_PTY_WITHOUT_TERMINAL=1
  expect_failure missing-guest-pty run_application_secret_pty "printf 'application-secret-check-ok\\n'" no-pty
)
pass
pass
pass
# One old single check fails while the bounded host convergence succeeds.
(
  fixture
  ENV_ID=synthetic-env
  cw_with_timeout() {
    printf 'attempt\n' >>"$TMPDIR_SMOKE/exec-attempts"
    local count
    count="$(wc -l <"$TMPDIR_SMOKE/exec-attempts")"
    if [[ "$APP_FAILURE" == eventual && "$count" -gt 1 ]]; then
      printf 'application-secret-check-ok\n'; return 0
    fi
    case "$APP_FAILURE" in
      eventual|deadline) printf 'application check failed: startup-projection\n' ;;
      stderr) printf 'application check failed: startup-projection\n' >&2 ;;
      unrelated) printf 'application check failed: current-projection\n' ;;
      mixed) printf 'application check failed: startup-projection\n'; printf 'transport failure\n' >&2 ;;
      malformed) printf 'application check failed: startup-projection\n\n' ;;
    esac
    return 1
  }
  APP_FAILURE=eventual
  if cw_with_timeout 5 run >"$TMPDIR_SMOKE/old.out"; then fail 'old single check unexpectedly passed'; fi
  : >"$TMPDIR_SMOKE/exec-attempts"
  run_application_secret_exec true clear 106
  [[ "$(wc -l <"$TMPDIR_SMOKE/exec-attempts")" == 2 && "$(seconds_now)" == 105 ]] ||
    fail 'startup convergence did not retry the exact fixed failure'
  for variant in deadline stderr unrelated mixed malformed; do
    APP_FAILURE="$variant"
    : >"$TMPDIR_SMOKE/exec-attempts"
    expect_failure "$variant" run_application_secret_exec true clear "$(( $(seconds_now) + 1 ))"
    [[ "$(wc -l <"$TMPDIR_SMOKE/exec-attempts")" == 1 ]] || fail 'failure launched an extra managed check'
    if [[ "$variant" == deadline || "$variant" == stderr ]]; then
      grep -Fq 'timed out waiting for managed application startup projection' "$APP_TEST_ROOT/failure.err"
    else
      grep -Fq 'managed application-secret exec failed' "$APP_TEST_ROOT/failure.err"
    fi
  done
)
pass
pass
pass
pass
pass
pass

for variant in cleanup-user-list cleanup-user-delete-lost; do
  reject_shared_cleanup_command() {
    fixture
    APP_SECRET_ALL_SCOPES=1
    prepare_application_secrets
    APP_FAILURE="$variant"
    if cleanup_application_secrets; then printf 'cleanup-success\n'; fi
    cp "$TMPDIR_SMOKE/organization.db" "$APP_TEST_ROOT/cleanup-organization.json"
    cp "$TMPDIR_SMOKE/user.db" "$APP_TEST_ROOT/cleanup-user.json"
    cp "$TMPDIR_SMOKE/app-cleanup-user-commands.tsv" "$APP_TEST_ROOT/cleanup-commands.tsv"
    cat "$TMPDIR_SMOKE"/app-cleanup-user-*.err >"$APP_TEST_ROOT/cleanup-private.err"
  }
  reject_shared_cleanup_command >"$APP_TEST_ROOT/cleanup-result.out" 2>"$APP_TEST_ROOT/cleanup-result.err"
  [[ ! -s "$APP_TEST_ROOT/cleanup-result.out" ]] || fail 'failed command emitted cleanup success'
  jq -e 'length == 0' "$APP_TEST_ROOT/cleanup-organization.json" >/dev/null || fail 'user failure skipped organization cleanup'
  [[ -s "$APP_TEST_ROOT/cleanup-private.err" ]] || fail 'private command diagnostic was discarded'
  if [[ "$variant" == cleanup-user-list ]]; then
    grep -Fx $'list\tfinal\t23' "$APP_TEST_ROOT/cleanup-commands.tsv" >/dev/null
  else
    jq -e 'length == 0' "$APP_TEST_ROOT/cleanup-user.json" >/dev/null
    grep -Fx $'delete\t0\t24' "$APP_TEST_ROOT/cleanup-commands.tsv" >/dev/null
  fi
  if grep -Fq 'synthetic private' "$APP_TEST_ROOT/cleanup-result.err"; then fail 'cleanup printed raw diagnostic'; fi
  pass
done

printf 'Dev application-source shell fixtures passed: %s\n' "$APP_TEST_COUNT"
