#!/usr/bin/env bash
# Pure shell/PTY fixtures: no Dev, credential reader, VM or database calls.
# shellcheck disable=SC2034 # Globals are consumed by the sourced product script.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck disable=SC1091 # The tested script is sourced without its main entrypoint.
source "$REPO_ROOT/scripts/runtime/dev/smoke-dev-commodity.sh"
mkdir -p "$REPO_ROOT/.tmp"
APP_TEST_ROOT="$(mktemp -d "$REPO_ROOT/.tmp/cw-dev-app-fixtures.XXXXXXXX")"
APP_TEST_OWNER="$BASHPID"
trap 'if [[ "$BASHPID" == "$APP_TEST_OWNER" ]]; then rm -rf -- "$APP_TEST_ROOT"; fi' EXIT
APP_TEST_COUNT=0
REAL_APPLICATION_PTY="$(declare -f run_application_secret_pty)"
fail() { printf 'application smoke fixture: %s\n' "$*" >&2; exit 1; }
pass() { APP_TEST_COUNT=$((APP_TEST_COUNT + 1)); }

fixture() {
  TMPDIR_SMOKE="$(mktemp -d "$APP_TEST_ROOT/case.XXXXXXXX")"
  APP_SECRET_PROJECTS=(); APP_SECRET_IDS=(); APP_SECRET_VALUES=(); APP_SECRET_HASHES=()
  APP_SECRET_DOCUMENT=''; APP_SECRET_CREATE_ATTEMPTED=0; ENV_ID=''; CLAIM_NAME=fixture-claim
  SMOKE_NAME=fixture-env; SMOKE_TIMEOUT_SECONDS=1; SMOKE_EXEC_TIMEOUT=5
  SMOKE_KEEP_ENV=0; SMOKE_SKIP_KUBE=0; SMOKE_EXISTING_ENV_ID=''
  SMOKE_AUTH_MODE=api-key; ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE=0; ALLOW_NON_DEV=0
  CODEWIRE_SERVER_URL=https://synthetic.invalid; EXPECTED_CODEWIRE_DEV_SERVER_URL="$CODEWIRE_SERVER_URL"
  CODEWIRE_DEV_SMOKE_API_KEY=synthetic-test-only; EXPECTED_CODEWIRE_SMOKE_USER_EMAIL=synthetic@example.invalid
  SANDBOX_NAMESPACE=synthetic; APP_FAILURE=''
  APP_KUBE_RESOURCE=''; APP_KUBE_MUTATION='.'; APP_ANNOTATED_POD=0
  printf '[]\n' >"$TMPDIR_SMOKE/projects.db"
  printf '[]\n' >"$TMPDIR_SMOKE/environments.db"
  : >"$TMPDIR_SMOKE/calls"
}

cw_with_timeout() { shift; cw "$@"; }
cw() {
  [[ "$*" != *cwdevapp* ]] || fail 'synthetic protected value entered CLI argv'
  printf '%q ' "$@" >>"$TMPDIR_SMOKE/calls"; printf '\n' >>"$TMPDIR_SMOKE/calls"
  case "$*" in
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
      [[ "$input" == cwdevapp* && ${#input} == 41 ]] || fail 'protected stdin was not supplied'
      [[ "$APP_FAILURE" != scope ]] || return 1 ;;
    'secrets --platform --project '*" list --output json")
      if [[ "$APP_FAILURE" == leak ]]; then
        jq -n --arg value "${APP_SECRET_VALUES[0]}" '[{key:"DATABASE_URL",value:$value},{key:"CW_DEV_PRECEDENCE"}]'
      else printf '[{"key":"DATABASE_URL"},{"key":"CW_DEV_PRECEDENCE"}]\n'; fi ;;
    'env --platform list --output json') jq 'map(select(.state != "destroying" and .state != "destroyed"))' "$TMPDIR_SMOKE/environments.db" ;;
    'env --platform list --all --output json') cat "$TMPDIR_SMOKE/environments.db" ;;
    'env create --platform --file '*)
      local project
      project="$(jq -r .secrets.project "$APP_SECRET_DOCUMENT")"
      jq -n --arg project "$project" --arg name "$SMOKE_NAME" \
        '[{id:"00000000-0000-4000-8000-000000000099",name:$name,state:"running",operation_generation:1,
          setup_complete:true,setup_error:null,
          source_selection:{secrets:{project:$project},credentials:null,profile_revision:null}}]' >"$TMPDIR_SMOKE/environments.db"
      printf 'ID: 00000000-0000-4000-8000-000000000099\n' ;;
    'env --platform info '*" --output json")
      jq -e '.[0].state != "destroying" and .[0].state != "destroyed"' "$TMPDIR_SMOKE/environments.db" >/dev/null || return 1
      jq '.[0]' "$TMPDIR_SMOKE/environments.db" ;;
    'env --platform update '*)
      if [[ " $* " != *' --yes '* ]]; then
        printf 'source selection requires --yes for noninteractive or JSON commands; no source change was submitted\n' >&2
        return 2
      fi
      local project='' before
      before="$(jq '.[0].operation_generation' "$TMPDIR_SMOKE/environments.db")"
      [[ " $* " != *' --secrets '* ]] || project="$6"
      jq --arg project "$project" '.[0].operation_generation += 1 | .[0].source_selection.secrets.project=$project' \
        "$TMPDIR_SMOKE/environments.db" >"$TMPDIR_SMOKE/db.next"
      mv "$TMPDIR_SMOKE/db.next" "$TMPDIR_SMOKE/environments.db"
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
    'run --no-tty '*) printf 'application-secret-check-ok\n' ;;
    'list '*" --output json") printf '[]\n' ;;
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
  local generation project pod_uid pod_name=owned-sandbox resource object
  printf '%q ' "$@" >>"$TMPDIR_SMOKE/calls"; printf '\n' >>"$TMPDIR_SMOKE/calls"
  generation="$(jq -r '.[0].operation_generation' "$TMPDIR_SMOKE/environments.db")"
  project="$(jq -r '.[0].source_selection.secrets.project' "$TMPDIR_SMOKE/environments.db")"
  pod_uid="pod-$generation"
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
      object="$(jq -n --arg id "$ENV_ID" --arg generation "$generation" --arg project "$project" --arg uid "$pod_uid" --arg name "$pod_name" '
        {metadata:{name:$name,namespace:"synthetic",uid:$uid,
          labels:{"codewire.sh/environment-id":$id,"codewire.sh/type":"workspace","codewire.sh/environment-operation-generation":$generation},
          ownerReferences:[{apiVersion:"agents.x-k8s.io/v1beta1",kind:"Sandbox",name:"owned-sandbox",uid:"owned-sandbox-uid",controller:true}]},
          status:{phase:"Running"},spec:{volumes:[{name:"workspace",persistentVolumeClaim:{claimName:"owned-pvc"}}],containers:[{name:"workspace",env:
            (if $project == "" then [] else [
              {name:"CODEWIRE_ENVIRONMENT_ID",value:$id},
              {name:"CODEWIRE_ENVIRONMENT_OPERATION_GENERATION",value:$generation},
              {name:"CODEWIRE_ENVIRONMENT_PROJECTION_SHA256",value:("a" * 64)}] end)}]}}')" ;;
    *) fail "unexpected Kubernetes fixture operation: $*" ;;
  esac
  if [[ "$APP_KUBE_RESOURCE" == "$resource" ]]; then jq "$APP_KUBE_MUTATION" <<<"$object";
  else printf '%s\n' "$object"; fi
}
run_application_secret_pty() {
  [[ "$1" == *'DATABASE_URL'* ]] || fail 'PTY did not receive the application assertion'
  printf 'application-secret-check-ok\n' >"$TMPDIR_SMOKE/app-pty-$2.log"
}

expect_failure() {
  local label="$1"; shift
  if ( "$@" ) >"$APP_TEST_ROOT/failure.out" 2>"$APP_TEST_ROOT/failure.err"; then fail "$label accepted invalid input"; fi
  pass
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
prepare_application_secrets
jq -e '.version == 1 and (has("schema_version") | not) and .secrets.project == "platform:id:00000000-0000-4000-8000-000000000001" and
  .environment.CW_DEV_PRECEDENCE == "ordinary-config" and (has("credentials") | not)' "$APP_SECRET_DOCUMENT" >/dev/null
/bin/sh -n < <(jq -r .install_command "$APP_SECRET_DOCUMENT")
/bin/sh -n < <(jq -r .startup_script "$APP_SECRET_DOCUMENT")
pass
create_environment
run_application_secrets_smoke
[[ "$(jq -r '.[0].operation_generation' "$TMPDIR_SMOKE/environments.db")" == 3 ]]
cleanup_application_secrets
[[ "$(jq length "$TMPDIR_SMOKE/projects.db")" == 0 ]]
[[ "$(jq -r '.[0].state' "$TMPDIR_SMOKE/environments.db")" == destroyed ]]
pass
expect_failure terminal-info-hidden cw env --platform info "$ENV_ID" --output json
application_environment_destroyed
grep -Fq 'env --platform list --all --output json' "$TMPDIR_SMOKE/calls"
pass

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
cp "$TMPDIR_SMOKE/environments.db" "$TMPDIR_SMOKE/setup-complete.json"
for filter in '.[0].setup_complete=false' 'del(.[0].setup_complete)' '.[0].setup_complete="true"' '.[0].setup_error="setup failed"'; do
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
printf '{"env":["CW_DEV_PRECEDENCE=ordinary-config"]}\n' >"$guest/home/.codewire/daemon/sessions/one/session.json"
expected="$(printf synthetic-application | sha256sum | cut -d ' ' -f 1)"
printf '%s\n' "$expected" >"$guest/workspace/.cw-app-smoke/startup-sha"
check="$(application_guest_check "$expected")"
check="${check//\/workspace/$guest/workspace}"
check="${check//\/home\/codewire/$guest/home}"
DATABASE_URL=synthetic-application CW_DEV_PRECEDENCE=ordinary-config /bin/sh -c "$check" >"$TMPDIR_SMOKE/check.out"
grep -qx application-secret-check-ok "$TMPDIR_SMOKE/check.out"
pass
expect_failure missing-projection env -u DATABASE_URL CW_DEV_PRECEDENCE=ordinary-config /bin/sh -c "$check"
printf '{"DATABASE_URL":"forbidden-ordinary-value","CW_DEV_PRECEDENCE":"ordinary-config"}\n' >"$guest/home/.codewire/environment.json"
expect_failure persisted-ordinary-value env DATABASE_URL=synthetic-application CW_DEV_PRECEDENCE=ordinary-config /bin/sh -c "$check"
printf '{"CW_DEV_PRECEDENCE":"ordinary-config"}\n' >"$guest/home/.codewire/environment.json"
printf '2\n' >"$guest/workspace/.cw-app-smoke/install-count"
expect_failure repeated-install env DATABASE_URL=synthetic-application CW_DEV_PRECEDENCE=ordinary-config /bin/sh -c "$check"
printf '1\n' >"$guest/workspace/.cw-app-smoke/install-count"
printf '{"env":["DATABASE_URL=forbidden-persisted-value"]}\n' >"$guest/home/.codewire/daemon/sessions/one/session.json"
expect_failure persisted-session-value env DATABASE_URL=synthetic-application CW_DEV_PRECEDENCE=ordinary-config /bin/sh -c "$check"
printf '{"env":[]}\n' >"$guest/home/.codewire/daemon/sessions/one/session.json"
printf 'absent\n' >"$guest/workspace/.cw-app-smoke/startup-sha"
check="$(application_guest_check absent)"; check="${check//\/workspace/$guest/workspace}"; check="${check//\/home\/codewire/$guest/home}"
env -u DATABASE_URL CW_DEV_PRECEDENCE=ordinary-config /bin/sh -c "$check" >"$TMPDIR_SMOKE/check.out"
grep -qx application-secret-check-ok "$TMPDIR_SMOKE/check.out"
pass
expect_failure stale-cleared-value env DATABASE_URL=synthetic-application CW_DEV_PRECEDENCE=ordinary-config /bin/sh -c "$check"

# Actual local PTY utility plus a synthetic CLI, not a VM or API.
(
  eval "$REAL_APPLICATION_PTY"
  CW_BIN="$TMPDIR_SMOKE/cw-pty-fixture"
  # shellcheck disable=SC2016 # Literal synthetic executable, not host expansion.
  printf '%s\n' '#!/bin/sh' 'while test "$#" -gt 0 && test "$1" != --; do shift; done' 'shift' 'exec "$@"' >"$CW_BIN"
  chmod 0700 "$CW_BIN"
  unset CODEWIRE_DEV_SMOKE_API_KEY CODEWIRE_API_KEY
  run_application_secret_pty "printf 'application-secret-check-ok\\n'" actual
  expect_failure pty-exit-status run_application_secret_pty "printf 'application-secret-check-ok\\n'; exit 7" failure
)
pass
pass
printf 'Dev application-source shell fixtures passed: %s\n' "$APP_TEST_COUNT"
