#!/usr/bin/env bash
set -euo pipefail

# Local verification consumes the same capability selection as Gitea CI. It
# deliberately contains no changed-path classification of its own.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SELECTOR="$REPO_ROOT/scripts/ci/select/select-verification.sh"
PRODUCT_RUNNER="$REPO_ROOT/scripts/ci/verify/run-product-verification.sh"
INTEGRATION_RUNNER="$REPO_ROOT/scripts/ci/verify/run-integration-verification.sh"
ENVIRONMENT_CHECK="$REPO_ROOT/scripts/dev/preflight-environment.sh"
PUSH_CHECK="$REPO_ROOT/scripts/dev/preflight-push.sh"
cd "$REPO_ROOT"

usage() {
  cat <<'EOF'
usage: scripts/dev/preflight.sh [--default|--integration|--full|--explain]
       scripts/dev/preflight.sh --all
       scripts/dev/preflight.sh --for-push

Pull-request CI is the merge gate (#3119 step 2): nothing here qualifies a
merge, and nothing here records a receipt.

--for-push runs the fast pre-push check (environment, formatting, clippy and
unit tests for changed crates, quick checks for changed file types). The
pre-push hook runs it on every branch push.

--all runs every family the change selects, as pull-request CI does: the
environment precheck, then compile first and independent families in
parallel lanes. Kind is never run here; `make kind-test` is the local tool
for behaviour that is tricky or slow to test on Dev.

default runs lightweight selected checks one after another; integration and
full are explicit escalations. --full never publishes, deploys, releases, or
mutates live state.
EOF
}

PREFLIGHT_MODE=default
PREFLIGHT_SCOPE=""
explicit_mode=false
for argument in "$@"; do
  case "$argument" in
    --default) PREFLIGHT_MODE=default; explicit_mode=true ;;
    --integration) PREFLIGHT_MODE=integration; explicit_mode=true ;;
    --full) PREFLIGHT_MODE=full; explicit_mode=true ;;
    --explain) PREFLIGHT_MODE=explain; explicit_mode=true ;;
    --for-push|--all)
      if [ -n "$PREFLIGHT_SCOPE" ]; then
        usage >&2
        exit 2
      fi
      PREFLIGHT_SCOPE="${argument#--}"
      PREFLIGHT_SCOPE="${PREFLIGHT_SCOPE#for-}"
      ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
if [ -n "$PREFLIGHT_SCOPE" ]; then
  if [ "$explicit_mode" = true ]; then
    usage >&2
    exit 2
  fi
  if [ -n "${PREFLIGHT_RELEASE_TAG_REF:-}" ]; then
    printf 'preflight: --%s rejects a release tag push\n' "$PREFLIGHT_SCOPE" >&2
    exit 2
  fi
elif [ "$#" -gt 1 ]; then
  usage >&2
  exit 2
fi
case "$PREFLIGHT_MODE" in
  default|integration|full|explain) ;;
  *)
    printf 'preflight: unsupported mode %s\n' "$PREFLIGHT_MODE" >&2
    exit 2
    ;;
esac
# Compiles and tests run inside the workstation CPU slice, wherever this was
# started from; the pre-push hook starts it from user.slice (#4126).
if [ "$PREFLIGHT_MODE" != explain ]; then
  # shellcheck source=scripts/dev/cpu-slice.sh
  . "$REPO_ROOT/scripts/dev/cpu-slice.sh"
  cpu_slice_enter preflight
  # A full preflight is heavy throughout, so it waits its turn behind any
  # other on this workstation; the push check takes the lock only for its
  # compiling steps (preflight-push.sh, #4215).
  # shellcheck source=scripts/dev/preflight-lock.sh
  . "$REPO_ROOT/scripts/dev/preflight-lock.sh"
  if [ "$PREFLIGHT_SCOPE" != push ]; then
    preflight_lock_acquire "preflight ${PREFLIGHT_SCOPE:-$PREFLIGHT_MODE}" || exit 1
  fi
fi

preflight_git_local_env_names="$(git rev-parse --local-env-vars)"
while IFS= read -r git_env_name; do
  unset "$git_env_name"
done <<<"$preflight_git_local_env_names"
unset preflight_git_local_env_names

PREFLIGHT_TMP="$(mktemp -d)"
PREFLIGHT_CHANGED_PATHS="$PREFLIGHT_TMP/changed-files"
PREFLIGHT_EFFECTIVE_BASE_SHA=""
# Lanes started and not yet reaped. Each leads its own process group.
PREFLIGHT_LANE_PIDS=()
PREFLIGHT_LANE_ENDED=''
stop_lanes() {
  local pid
  for pid in "${PREFLIGHT_LANE_PIDS[@]}"; do
    kill -TERM -- "-$pid" 2>/dev/null || true
  done
  for pid in "${PREFLIGHT_LANE_PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  PREFLIGHT_LANE_PIDS=()
}
preflight_exit() {
  local status=$?
  stop_lanes
  rm -rf "$PREFLIGHT_TMP"
  exit "$status"
}
trap preflight_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
  printf 'preflight: %s FAILED\n' "$*" >&2
  exit 1
}

run_step() {
  local label="$1"
  shift
  printf '==> %s\n' "$label"
  "$@" || fail "$label"
}

ref_exists() {
  git rev-parse --verify --quiet "$1^{commit}" >/dev/null
}

preflight_base_ref() {
  local candidate
  for candidate in gitea/main origin/main main; do
    if ref_exists "$candidate"; then
      printf '%s\n' "$candidate"
      return
    fi
  done
}

is_zero_sha() {
  [[ "${1:-}" =~ ^0+$ ]]
}

collect_changed_paths() {
  local out="$1"

  if [ -n "${PREFLIGHT_CHANGED_FILES:-}" ]; then
    if [ "$PREFLIGHT_CHANGED_FILES" = - ]; then
      cat > "$out"
    else
      cp "$PREFLIGHT_CHANGED_FILES" "$out"
    fi
    sed -i '/^$/d' "$out"
    sort -u -o "$out" "$out"
    return
  fi

  if [ "${PREFLIGHT_FORCE_UNKNOWN:-false}" = true ]; then
    printf '__unknown__\n' > "$out"
    return
  fi

  local head base
  head="${PREFLIGHT_HEAD_SHA:-HEAD}"
  if ! head="$(git rev-parse --verify "$head^{commit}" 2>/dev/null)"; then
    fail "head commit is unavailable"
  fi

  base="${PREFLIGHT_BASE_SHA:-}"
  if [ -n "$base" ] && is_zero_sha "$base"; then
    base=""
  fi
  if [ -z "$base" ]; then
    base="$(preflight_base_ref)"
  fi
  if [ -z "$base" ] || ! ref_exists "$base"; then
    fail "canonical baseline is unavailable"
  fi
  base="$(git rev-parse --verify "$base^{commit}")"
  PREFLIGHT_EFFECTIVE_BASE_SHA="$base"

  if ! git diff --name-only "$base...$head" > "$out" 2>/dev/null \
    && ! git diff --name-only "$base" "$head" > "$out" 2>/dev/null; then
    fail "changed paths cannot be derived from the canonical baseline"
  fi

  # Direct invocation also covers uncommitted work. A real pre-push supplies
  # an exact local object and normally has no such changes.
  if [ "${PREFLIGHT_HEAD_SHA:-HEAD}" = HEAD ]; then
    {
      cat "$out"
      git diff --name-only
      git diff --cached --name-only
      git ls-files --others --exclude-standard
    } | sed '/^$/d' | sort -u > "$out.next"
    mv "$out.next" "$out"
  else
    sed -i '/^$/d' "$out"
    sort -u -o "$out" "$out"
  fi
}

selection_value() {
  sed -n 's/^selection=//p' <<<"$1"
}

classification_value() {
  sed -n 's/^classification=//p' <<<"$1"
}

required_mode_value() {
  sed -n 's/^required_local_mode=//p' <<<"$1"
}

mode_rank() {
  case "$1" in
    default) printf '0\n' ;;
    integration) printf '1\n' ;;
    full) printf '2\n' ;;
    *) return 1 ;;
  esac
}

selection_has() {
  [[ "$VERIFICATION_SELECTION" == *"|$1|"* ]]
}

selection_has_any() {
  local token
  for token in "$@"; do
    if selection_has "$token"; then
      return 0
    fi
  done
  return 1
}

collect_changed_paths "$PREFLIGHT_CHANGED_PATHS"

if [ -n "${PREFLIGHT_RELEASE_TAG_REF:-}" ]; then
  # A release tag push checks only what this checkout can know, so it needs no
  # Forgejo token: just tag and push (owner, 2026-10-23, #2892). deploy-prod's
  # release selection reverifies the tag from main's code before anything is
  # published: the release tagger's signature, main CI, the dry run and Dev
  # acceptance of the exact commit, and Kind while the receipt's
  # RELEASE_REQUIRES_KIND says so (waived, owner, 2026-10-25, #3013).
  printf '==> release tag signature\n'
  release_tag_object="${PREFLIGHT_RELEASE_TAG_OBJECT_SHA:-}"
  [ "$(git -C "$REPO_ROOT" cat-file -t "$release_tag_object" 2>/dev/null)" = tag ] ||
    fail 'release tag is not an annotated tag; create it with git tag -s'
  git -C "$REPO_ROOT" verify-tag "$release_tag_object" ||
    fail 'release tag signature does not verify; sign it with git tag -s and your release key'
  release_commit="$(git -C "$REPO_ROOT" rev-parse --verify --quiet \
    "${release_tag_object}^{commit}")" ||
    fail 'release tag does not name a commit'
  # Only a commit on main is released.
  printf '==> release tag on main\n'
  release_remote="${PREFLIGHT_PUSH_REMOTE_NAME:-}"
  [ -n "$release_remote" ] || fail 'the push remote is unknown'
  release_main="$(git -C "$REPO_ROOT" ls-remote "$release_remote" refs/heads/main |
    awk '$2 == "refs/heads/main" { print $1 }')" || release_main=''
  [[ "$release_main" =~ ^[0-9a-f]{40}$ ]] || fail "$release_remote's main is unavailable"
  if [ "$release_commit" != "$release_main" ]; then
    git -C "$REPO_ROOT" cat-file -e "${release_main}^{commit}" 2>/dev/null ||
      git -C "$REPO_ROOT" fetch --quiet --no-tags "$release_remote" refs/heads/main ||
      fail "could not fetch $release_remote's main"
    git -C "$REPO_ROOT" merge-base --is-ancestor "$release_commit" "$release_main" ||
      fail "release tag names $release_commit, which is not on $release_remote's main"
  fi
  # A release ships the workspace image its tree pins. A changed image
  # definition must first be published and its proposed pin landed; no other
  # verification substitutes for that, so a stale pin refuses the tag.
  printf '==> release tag workspace image pin\n'
  python3 "$REPO_ROOT/scripts/ci/images/workspace-image-pin.py" check --release \
    --commit "$release_commit" ||
    fail 'release commit pins a stale workspace image; land the proposed pin before tagging'
  # deploy-prod reuses the support pair main published for the release commit.
  # A commit support-images never published (base and workspace, linux/amd64
  # and linux/arm64) cannot be tagged.
  printf '==> release tag support pair\n'
  "$REPO_ROOT/scripts/ci/release/verify-release-support-pair.sh" "$release_commit" ||
    fail 'release commit has no published support pair; tag a commit support-images published'
  printf 'preflight: signed release tag on main; deploy-prod verifies the rest before it publishes\n'
  printf 'preflight: OK\n'
  exit 0
fi

printf '==> preflight path selection\n'
if [ -s "$PREFLIGHT_CHANGED_PATHS" ]; then
  sed 's/^/  /' "$PREFLIGHT_CHANGED_PATHS"
else
  printf '  (no changed paths)\n'
fi

# Local runs take the complete selection, Kind included; Kind itself never
# runs here.
selector_output="$(
  env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
    GITHUB_EVENT_NAME=pull_request KIND_E2E_OPT_IN=true \
    "$SELECTOR" "$PREFLIGHT_CHANGED_PATHS"
)"
VERIFICATION_SELECTION="$(selection_value "$selector_output")"
PREFLIGHT_CLASSIFICATION="$(classification_value "$selector_output")"
PREFLIGHT_REQUIRED_MODE="$(required_mode_value "$selector_output")"
export VERIFICATION_SELECTION

if [[ "$VERIFICATION_SELECTION" != '|valid:v3|'* ]] \
  || [[ "$VERIFICATION_SELECTION" != *'|complete|' ]] \
  || [[ ! "$PREFLIGHT_CLASSIFICATION" =~ ^(changed|unchanged|unclassified)$ ]] \
  || [[ ! "$PREFLIGHT_REQUIRED_MODE" =~ ^(default|integration|full)$ ]]; then
  fail "verification selection is missing or malformed"
fi

printf 'preflight classification: %s\n' "$PREFLIGHT_CLASSIFICATION"
printf 'preflight required local mode: %s\n' "$PREFLIGHT_REQUIRED_MODE"
printf 'preflight selection: %s\n' "$VERIFICATION_SELECTION"

if [ "$PREFLIGHT_SCOPE" = push ]; then
  # The push check runs only what the changed files need; pull-request CI
  # runs the selected families.
  printf 'preflight push check: changed files only; pull-request CI runs the selected families\n'
  push_ran="$PREFLIGHT_TMP/push-ran"
  push_started=$SECONDS
  "$PUSH_CHECK" "$PREFLIGHT_CHANGED_PATHS" "$PREFLIGHT_EFFECTIVE_BASE_SHA" "$push_ran" </dev/null \
    || fail "push check"
  printf 'preflight: push check passed in %ss\n' "$((SECONDS - push_started))"
  exit 0
fi

if [ "$PREFLIGHT_SCOPE" = all ]; then
  PREFLIGHT_MODE="$PREFLIGHT_REQUIRED_MODE"
  printf 'preflight all-families mode: %s\n' "$PREFLIGHT_MODE"
fi

if [ "$PREFLIGHT_MODE" = explain ]; then
  printf 'preflight: explanation complete; no checks executed\n'
  exit 0
fi

if [ "$(mode_rank "$PREFLIGHT_MODE")" -lt "$(mode_rank "$PREFLIGHT_REQUIRED_MODE")" ]; then
  printf 'preflight: valid selection is incomplete; retry with scripts/dev/preflight.sh --%s\n' \
    "$PREFLIGHT_REQUIRED_MODE" >&2
  exit 3
fi

if [ "$PREFLIGHT_MODE" = full ]; then
  full_selector_output="$(
    env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
      GITHUB_EVENT_NAME=workflow_dispatch VERIFICATION_REQUEST=all \
      "$SELECTOR"
  )"
  VERIFICATION_SELECTION="$(selection_value "$full_selector_output")"
  export VERIFICATION_SELECTION
  [[ "$VERIFICATION_SELECTION" == '|valid:v3|'* ]] \
    && [[ "$VERIFICATION_SELECTION" == *'|complete|' ]] \
    || fail "full verification selection is missing or malformed"
  printf 'preflight full selection: %s\n' "$VERIFICATION_SELECTION"
fi

# Kind is a local tool (make kind-test) and post-merge CI's, never a step here.
if selection_has kind; then
  printf 'preflight: Kind is not run here; make kind-test is the local tool and post-merge CI runs it\n'
fi

# Changed workflow definitions get the zizmor audit the supply-chain scan runs.
PREFLIGHT_RUNS_WORKFLOW_AUDIT=false
if grep -Eq '^\.(gitea|github)/workflows/' "$PREFLIGHT_CHANGED_PATHS"; then
  PREFLIGHT_RUNS_WORKFLOW_AUDIT=true
  command -v supplychain >/dev/null \
    || fail "workflow audit needs supplychain, the scanner the supply-chain scan runs"
fi

# Fail fast on the workstation conditions the selected families need.
environment_args=()
if selection_has_any rust rust_curated_locks transport transport_derp_contract \
    contracts go_consumer_interop web database service_integration; then
  environment_args+=(--rust)
fi
if selection_has transport && selection_has transport_pkg_codewire_local_vmm; then
  environment_args+=(--darwin-cross)
fi
if selection_has web; then
  environment_args+=(--browser)
fi
if selection_has_any contracts web sdk_ts dev_smoke_script_tests; then
  environment_args+=(--node-modules)
fi
if selection_has contracts; then
  environment_args+=(--proto-venv)
fi
run_step "environment precheck" "$ENVIRONMENT_CHECK" "${environment_args[@]}"

# --all queues each family into a lane; the other modes run each family in
# place, in this order.
declare -a PREFLIGHT_STEPS=()
declare -A PREFLIGHT_STEP_LABEL=() PREFLIGHT_STEP_COMMAND=()

run_family() {
  local id="$1" label="$2"
  shift 2
  if [ "$PREFLIGHT_SCOPE" = all ]; then
    PREFLIGHT_STEPS+=("$id")
    PREFLIGHT_STEP_LABEL["$id"]="$label"
    PREFLIGHT_STEP_COMMAND["$id"]="$(printf '%q ' "$@")"
  else
    run_step "$label" "$@"
  fi
}

# --all runs the policy family as its independent parts, one lane each. The product runner owns the list of parts for the selection; the
# other modes run the policy family in place, which runs the same parts in
# order.
queue_policy_parts() {
  local label="$1" parts part
  parts="$(env VERIFICATION_SELECTION="$VERIFICATION_SELECTION" "$PRODUCT_RUNNER" policy-parts)" \
    || fail "policy parts"
  [ -n "$parts" ] || fail "policy parts are empty"
  while IFS= read -r part; do
    [[ "$part" =~ ^policy-[a-z0-9-]+$ ]] || fail "policy part ${part} is malformed"
    run_family "$part" "${label} (${part#policy-})" env \
      VERIFICATION_SELECTION="$VERIFICATION_SELECTION" \
      VERIFICATION_PR_BASE_SHA="$PREFLIGHT_EFFECTIVE_BASE_SHA" \
      "$PRODUCT_RUNNER" "$part"
  done <<<"$parts"
}

run_selected_family() {
  local token="$1" family="$2" label="$3"
  if selection_has "$token"; then
    if [ "$family" = policy ] && [ "$PREFLIGHT_SCOPE" = all ]; then
      queue_policy_parts "$label"
      return
    fi
    run_family "$family" "$label" env \
      VERIFICATION_SELECTION="$VERIFICATION_SELECTION" \
      VERIFICATION_PR_BASE_SHA="$PREFLIGHT_EFFECTIVE_BASE_SHA" \
      "$PRODUCT_RUNNER" "$family"
  fi
}

# Concurrent integration lanes start their services on separate port ranges.
integration_port_base() {
  if [ "$PREFLIGHT_SCOPE" != all ]; then
    printf '%s\n' "${VERIFICATION_PORT_BASE:-62000}"
    return
  fi
  case "$1" in
    database) printf '62000\n' ;;
    services-control) printf '62020\n' ;;
    services-runtime) printf '62040\n' ;;
  esac
}

run_selected_family policy policy "policy verification"

run_selected_family contracts contracts "contract verification"
# The same fast compile CI runs beside its heavy jobs: every target and
# feature, and each curated image workspace, before the long Rust suites.
# These tokens are the CI selection's rust_transport expected rule.
if selection_has_any rust rust_curated_locks transport transport_derp_contract; then
  run_family rust-compile "every Rust target compiles" env VERIFICATION_SELECTION="$VERIFICATION_SELECTION" \
    "$PRODUCT_RUNNER" rust-compile
fi
run_selected_family rust rust "Rust verification"
run_selected_family rust_curated_locks rust-curated-locks \
  "curated Rust workspace lock verification"
run_selected_family go_support go-support "Go support verification"
run_selected_family web web "web verification"
run_selected_family docs docs "docs site verification"
run_selected_family ios ios "iOS verification"
run_selected_family sdk_go sdk-go "Go SDK verification"
run_selected_family sdk_ts sdk-ts "TypeScript SDK verification"
run_selected_family sdk_python sdk-python "Python SDK verification"
run_selected_family confidential_script_tests confidential-script-tests \
  "confidential runtime tooling verification"
run_selected_family dev_smoke_script_tests dev-smoke-script-tests \
  "Dev smoke script tests"

if selection_has database; then
  run_family database "database verification" env \
    VERIFICATION_SELECTION="$VERIFICATION_SELECTION" \
    VERIFICATION_PORT_BASE="$(integration_port_base database)" \
    "$INTEGRATION_RUNNER" database
fi
if selection_has service_integration; then
  integration_lane_selected=false
  if selection_has_any service_idp service_coordinator service_billing \
      service_connectcore; then
    integration_lane_selected=true
    run_family services-control "service control-plane verification" env \
      VERIFICATION_SELECTION="$VERIFICATION_SELECTION" \
      VERIFICATION_PORT_BASE="$(integration_port_base services-control)" \
      "$INTEGRATION_RUNNER" services-control
  fi
  if selection_has_any service_orchestration service_nats; then
    integration_lane_selected=true
    run_family services-runtime "service runtime-plane verification" env \
      VERIFICATION_SELECTION="$VERIFICATION_SELECTION" \
      VERIFICATION_PORT_BASE="$(integration_port_base services-runtime)" \
      "$INTEGRATION_RUNNER" services-runtime
  fi
  [[ "$integration_lane_selected" == true ]] || \
    fail "service integration selected without a service scope"
fi

run_selected_family transport transport "Rust transport verification"
run_selected_family edge_kind edge "edge static verification and selected Kind tool tests"
run_selected_family release release "delivery script tests"
run_selected_family deploy deploy "deploy verification"
run_selected_family security security "security verification"
if [ "$PREFLIGHT_RUNS_WORKFLOW_AUDIT" = true ]; then
  run_family workflow-audit "workflow audit (zizmor)" supplychain workflows .
fi

if [ "$PREFLIGHT_SCOPE" != all ]; then
  printf 'preflight: OK\n'
  exit 0
fi

# ---------------------------------------------------------------------------
# --all: parallel lanes.
if [ "${BASH_VERSINFO[0]}" -lt 5 ] \
    || { [ "${BASH_VERSINFO[0]}" -eq 5 ] && [ "${BASH_VERSINFO[1]}" -lt 1 ]; }; then
  fail "--all needs Bash 5.1 or newer for lane supervision"
fi
# The lanes already run families side by side and share one CPU budget, so
# each family runs its own tests one at a time here (run_side_by_side); CI
# gives every family its own runner.
export VERIFICATION_TEST_JOBS="${VERIFICATION_TEST_JOBS:-1}"
PREFLIGHT_STATE_DIR="$REPO_ROOT/.tmp/preflight"
if ! git check-ignore -q "$PREFLIGHT_STATE_DIR/logs/probe"; then
  fail "state directory .tmp/ is not ignored by Git"
fi
PREFLIGHT_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
PREFLIGHT_LOG_DIR="$PREFLIGHT_STATE_DIR/logs/$PREFLIGHT_RUN_ID"
PREFLIGHT_RESULT_DIR="$PREFLIGHT_TMP/results"
mkdir -p "$PREFLIGHT_LOG_DIR" "$PREFLIGHT_RESULT_DIR"
printf 'preflight family logs: %s\n' "$PREFLIGHT_LOG_DIR"

run_queued_step() {
  local step="$1" label log started status=0
  label="${PREFLIGHT_STEP_LABEL[$step]}"
  log="$PREFLIGHT_LOG_DIR/$step.log"
  printf '==> %s: started (log %s)\n' "$label" "$log"
  started=$SECONDS
  (eval "${PREFLIGHT_STEP_COMMAND[$step]}") >"$log" 2>&1 </dev/null || status=$?
  if [ "$status" -ne 0 ]; then
    printf 'failed\n' >"$PREFLIGHT_RESULT_DIR/$step"
    {
      printf 'preflight: %s FAILED (exit %s after %ss; log %s)\n' \
        "$label" "$status" "$((SECONDS - started))" "$log"
      tail -n 80 "$log" | sed 's/^/  | /'
    } >&2
    return 1
  fi
  printf 'ran\n' >"$PREFLIGHT_RESULT_DIR/$step"
  printf '==> %s: passed in %ss\n' "$label" "$((SECONDS - started))"
}

lane_of() {
  case "$1" in
    # Each policy part is independent and gets its own lane.
    policy|policy-*) printf '%s\n' "$1" ;;
    contracts) printf 'contracts\n' ;;
    rust-compile) printf 'compile\n' ;;
    rust|transport|rust-curated-locks) printf 'rust\n' ;;
    database|services-control|services-runtime) printf 'integration-%s\n' "$1" ;;
    # One lane owns the shared Bun dependency tree (node_modules).
    web|sdk-ts|dev-smoke-script-tests) printf 'javascript\n' ;;
    *) printf 'support\n' ;;
  esac
}

declare -A PREFLIGHT_LANE_STEPS=()
declare -a PREFLIGHT_LANES=()
for step in "${PREFLIGHT_STEPS[@]}"; do
  lane="$(lane_of "$step")"
  if [ -z "${PREFLIGHT_LANE_STEPS[$lane]:-}" ]; then
    PREFLIGHT_LANES+=("$lane")
  fi
  PREFLIGHT_LANE_STEPS["$lane"]+="$step "
done

run_lane() {
  local lane="$1" step
  for step in ${PREFLIGHT_LANE_STEPS[$lane]}; do
    run_queued_step "$step" || exit 1
  done
}

declare -A PREFLIGHT_LANE_STARTED=()
start_lane() {
  local lane="$1"
  [ -n "${PREFLIGHT_LANE_STEPS[$lane]:-}" ] || return 0
  # Job control gives the lane its own process group, so a failure elsewhere
  # stops every family process it started.
  if [ -z "$PREFLIGHT_LANE_ENDED" ]; then
    # Each lane reports its PID and status on this queue when it ends, so
    # await_lanes never waits on a lane the shell has already reaped: on Bash
    # 5.2, wait -n -p refuses such a lane ("no such job") and names none.
    mkfifo "$PREFLIGHT_TMP/lane-ended"
    exec {PREFLIGHT_LANE_ENDED}<>"$PREFLIGHT_TMP/lane-ended"
  fi
  set -m
  (
    trap - EXIT INT TERM
    exec {PREFLIGHT_LANE_ENDED}>&-
    # Not a condition: the lane keeps errexit.
    set +e
    (set -e; run_lane "$lane")
    printf '%s %s\n' "$BASHPID" "$?" >"$PREFLIGHT_TMP/lane-ended"
  ) &
  set +m
  PREFLIGHT_LANE_PIDS+=("$!")
  PREFLIGHT_LANE_STARTED["$lane"]="$!"
  printf '%s\n' "$lane" >"$PREFLIGHT_TMP/lane-$!"
}

# Wait until the given lanes finish, watching every running lane. The first
# failure stops the others.
await_lanes() {
  local -A waiting=()
  local pid finished status remaining running
  for pid in "$@"; do
    # A lane that already reported has nothing more to say.
    for running in "${PREFLIGHT_LANE_PIDS[@]}"; do
      [ "$running" != "$pid" ] || waiting["$pid"]=1
    done
  done
  while [ "${#waiting[@]}" -gt 0 ]; do
    finished=""
    status=""
    read -r finished status <&"$PREFLIGHT_LANE_ENDED" || fail "lane supervision"
    [[ "$finished" =~ ^[0-9]+$ && "$status" =~ ^[0-9]+$ ]] || fail "lane supervision"
    wait "$finished" 2>/dev/null || true
    remaining=()
    for pid in "${PREFLIGHT_LANE_PIDS[@]}"; do
      [ "$pid" = "$finished" ] || remaining+=("$pid")
    done
    PREFLIGHT_LANE_PIDS=("${remaining[@]}")
    unset 'waiting[$finished]'
    if [ "$status" -ne 0 ]; then
      printf 'preflight: lane %s failed; stopping the other lanes\n' \
        "$(cat "$PREFLIGHT_TMP/lane-$finished")" >&2
      stop_lanes
      fail "all selected families"
    fi
  done
}

for lane in "${PREFLIGHT_LANES[@]}"; do
  printf 'preflight lane %s: %s\n' "$lane" "${PREFLIGHT_LANE_STEPS[$lane]% }"
done
qualification_started=$SECONDS
# Contract generation rewrites tracked generated sources, so it runs alone.
start_lane contracts
await_lanes "${PREFLIGHT_LANE_PIDS[@]}"
# The JavaScript lane holds timing-bound tests (a 50 ms helper deadline in the
# Dev smoke auth tests, browser fixtures) that fail under the CPU load of the
# ShellCheck shards and Cargo, so it also runs alone.
start_lane javascript
await_lanes "${PREFLIGHT_LANE_PIDS[@]}"
# Policy needs no build; its parts run beside the compile gate. Every other
# lane waits for every Rust target to compile, so compile errors fail first.
for lane in "${PREFLIGHT_LANES[@]}"; do
  case "$lane" in
    policy|policy-*) start_lane "$lane" ;;
  esac
done
start_lane compile
compile_pid="${PREFLIGHT_LANE_STARTED[compile]:-}"
if [ -n "$compile_pid" ]; then
  await_lanes "$compile_pid"
fi
for lane in "${PREFLIGHT_LANES[@]}"; do
  case "$lane" in
    contracts|javascript|policy|policy-*|compile) ;;
    *) start_lane "$lane" ;;
  esac
done
await_lanes "${PREFLIGHT_LANE_PIDS[@]}"

for step in "${PREFLIGHT_STEPS[@]}"; do
  [ "$(cat "$PREFLIGHT_RESULT_DIR/$step" 2>/dev/null || true)" = ran ] || fail "result for ${step}"
done
printf 'preflight: every selected family passed in %ss (ran: %s)\n' \
  "$((SECONDS - qualification_started))" "${PREFLIGHT_STEPS[*]:-none}"
printf 'preflight: OK\n'
