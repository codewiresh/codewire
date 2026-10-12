#!/usr/bin/env bash
set -euo pipefail

# Local verification consumes the same capability selection as Gitea CI. It
# deliberately contains no changed-path classification of its own.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SELECTOR="$REPO_ROOT/scripts/ci/select/select-verification.sh"
RELEASE_TAG_RECEIPT="$REPO_ROOT/scripts/ci/receipts/verify-release-tag-receipt.sh"
LOCAL_PREPUSH_RECEIPT="$REPO_ROOT/scripts/ci/receipts/local-prepush-receipt.py"
PRODUCT_RUNNER="$REPO_ROOT/scripts/ci/verify/run-product-verification.sh"
INTEGRATION_RUNNER="$REPO_ROOT/scripts/ci/verify/run-integration-verification.sh"
ENVIRONMENT_CHECK="$REPO_ROOT/scripts/dev/preflight-environment.sh"
PUSH_CHECK="$REPO_ROOT/scripts/dev/preflight-push.sh"
cd "$REPO_ROOT"

usage() {
  cat <<'EOF'
usage: scripts/dev/preflight.sh [--default|--integration|--kind|--full|--explain]
       scripts/dev/preflight.sh --for-push --emit-receipt
       scripts/dev/preflight.sh --for-merge --emit-receipt

--for-push runs the fast pre-push check (environment, formatting, clippy and
unit tests for changed crates, quick checks for changed file types). The
pre-push hook runs it when no receipt for the pushed tree exists.

--for-merge is merge qualification: the environment precheck, then the
families the selection needs, compile first and independent families in
parallel lanes, reusing exact-tree passes. It never runs Kind; run
`make kind-test` for platform or dashboard behaviour. Post-merge CI runs the
rest.

--emit-receipt stores an eight-hour exact-tree receipt recording exactly which
checks ran. default runs lightweight selected checks sequentially;
integration, Kind and full are explicit escalations. --full never publishes,
deploys, releases, or mutates live state.
EOF
}

PREFLIGHT_MODE="${CODEWIRE_PREFLIGHT_MODE:-default}"
PREFLIGHT_SCOPE=""
PREFLIGHT_EMIT_RECEIPT=false
explicit_mode=false
for argument in "$@"; do
  case "$argument" in
    --default) PREFLIGHT_MODE=default; explicit_mode=true ;;
    --integration) PREFLIGHT_MODE=integration; explicit_mode=true ;;
    --kind) PREFLIGHT_MODE=kind; explicit_mode=true ;;
    --full) PREFLIGHT_MODE=full; explicit_mode=true ;;
    --explain) PREFLIGHT_MODE=explain; explicit_mode=true ;;
    --for-push|--for-merge)
      if [ -n "$PREFLIGHT_SCOPE" ]; then
        usage >&2
        exit 2
      fi
      PREFLIGHT_SCOPE="${argument#--for-}"
      ;;
    --emit-receipt) PREFLIGHT_EMIT_RECEIPT=true ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
if [ -n "$PREFLIGHT_SCOPE" ]; then
  if [ "$PREFLIGHT_EMIT_RECEIPT" != true ] || [ "$explicit_mode" = true ] \
      || [ "${CODEWIRE_PREFLIGHT_MODE:-default}" != default ]; then
    usage >&2
    exit 2
  fi
  for diagnostic_input in PREFLIGHT_CHANGED_FILES PREFLIGHT_FORCE_UNKNOWN \
      PREFLIGHT_HEAD_SHA PREFLIGHT_BASE_SHA PREFLIGHT_KIND_OPT_IN \
      PREFLIGHT_RELEASE_TAG_REF; do
    if [ -n "${!diagnostic_input:-}" ]; then
      printf 'preflight: --for-%s rejects diagnostic input %s\n' \
        "$PREFLIGHT_SCOPE" "$diagnostic_input" >&2
      exit 2
    fi
  done
elif [ "$PREFLIGHT_EMIT_RECEIPT" = true ] || [ "$#" -gt 1 ]; then
  usage >&2
  exit 2
fi
case "$PREFLIGHT_MODE" in
  default|integration|kind|full|explain) ;;
  *)
    printf 'preflight: unsupported mode %s\n' "$PREFLIGHT_MODE" >&2
    exit 2
    ;;
esac

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

if [ -n "$PREFLIGHT_SCOPE" ]; then
  if ! receipt_precondition="$($LOCAL_PREPUSH_RECEIPT check-clean 2>&1)"; then
    printf '%s\n' "$receipt_precondition" >&2
    fail "local receipt precondition"
  fi
fi

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
    kind) printf '2\n' ;;
    full) printf '3\n' ;;
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
  # A release ships the workspace image its tree pins. A changed image
  # definition must first be published and its proposed pin landed; no other
  # verification substitutes for that, so a stale pin refuses the tag.
  printf '==> release tag workspace image pin\n'
  release_commit="$(git -C "$REPO_ROOT" rev-parse --verify --quiet \
    "${PREFLIGHT_RELEASE_TAG_OBJECT_SHA:-}^{commit}")" ||
    fail 'release tag does not name a commit'
  python3 "$REPO_ROOT/scripts/ci/images/workspace-image-pin.py" check --release \
    --commit "$release_commit" ||
    fail 'release commit pins a stale workspace image; land the proposed pin before tagging'
  printf '==> release tag tested-tree receipt\n'
  if ! receipt_output="$($RELEASE_TAG_RECEIPT 2>&1)"; then
    printf 'release-tag receipt: checker failed unexpectedly; full local verification required\n' >&2
    receipt_output='release_tag_receipt=fallback
release_tag_reason=checker-failed
release_tag_run='
  fi
  printf '%s\n' "$receipt_output"
  if grep -Fxq 'release_tag_receipt=accepted' <<<"$receipt_output"; then
    printf 'preflight: exact-main CI receipt accepted; signed release tag verified\n'
    printf 'preflight: OK\n'
    exit 0
  fi
  if [ "${PREFLIGHT_RECEIPT_ONLY:-false}" = true ]; then
    fail "exact-main release receipt is unavailable"
  fi
  printf 'preflight: release receipt unavailable; running full fail-closed verification\n'
  printf '__unknown__\n' > "$PREFLIGHT_CHANGED_PATHS"
  PREFLIGHT_MODE=full
fi

printf '==> preflight path selection\n'
if [ -s "$PREFLIGHT_CHANGED_PATHS" ]; then
  sed 's/^/  /' "$PREFLIGHT_CHANGED_PATHS"
else
  printf '  (no changed paths)\n'
fi

# Push and merge qualification mirror pull-request CI without its Kind opt-in:
# Kind is the author's `make kind-test` dev loop and a post-merge CI gate.
# Only the explicit Kind and full escalations select it locally.
selector_kind_opt_in=false
if [ -z "$PREFLIGHT_SCOPE" ] \
    && { [ "$PREFLIGHT_MODE" = kind ] || [ "$PREFLIGHT_MODE" = full ]; }; then
  selector_kind_opt_in=true
fi
selector_output="$(
  env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
    GITHUB_EVENT_NAME=pull_request \
    KIND_E2E_OPT_IN="${PREFLIGHT_KIND_OPT_IN:-$selector_kind_opt_in}" \
    "$SELECTOR" "$PREFLIGHT_CHANGED_PATHS"
)"
VERIFICATION_SELECTION="$(selection_value "$selector_output")"
PREFLIGHT_CLASSIFICATION="$(classification_value "$selector_output")"
PREFLIGHT_REQUIRED_MODE="$(required_mode_value "$selector_output")"
export VERIFICATION_SELECTION

if [[ "$VERIFICATION_SELECTION" != '|valid:v3|'* ]] \
  || [[ "$VERIFICATION_SELECTION" != *'|complete|' ]] \
  || [[ ! "$PREFLIGHT_CLASSIFICATION" =~ ^(changed|unchanged|unclassified)$ ]] \
  || [[ ! "$PREFLIGHT_REQUIRED_MODE" =~ ^(default|integration|kind|full)$ ]]; then
  fail "verification selection is missing or malformed"
fi

printf 'preflight classification: %s\n' "$PREFLIGHT_CLASSIFICATION"
printf 'preflight required local mode: %s\n' "$PREFLIGHT_REQUIRED_MODE"
printf 'preflight selection: %s\n' "$VERIFICATION_SELECTION"

emit_scope_receipt() {
  local ran="$1" reused="$2" not_run="$3"
  run_step "atomic local ${PREFLIGHT_SCOPE} receipt" \
    "$LOCAL_PREPUSH_RECEIPT" emit \
      --verified-base "$PREFLIGHT_EFFECTIVE_BASE_SHA" \
      --verified-mode "$PREFLIGHT_MODE" \
      --verified-selection "$VERIFICATION_SELECTION" \
      --scope "$PREFLIGHT_SCOPE" \
      --ran "$ran" --reused "$reused" --not-run "$not_run"
}

if [ "$PREFLIGHT_SCOPE" = push ]; then
  # The receipt binds the selection that merge qualification would run; the
  # push check itself runs only what the changed files need.
  PREFLIGHT_MODE="$PREFLIGHT_REQUIRED_MODE"
  if [ "$PREFLIGHT_MODE" = full ]; then
    VERIFICATION_SELECTION="$(selection_value "$(
      env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
        GITHUB_EVENT_NAME=workflow_dispatch VERIFICATION_REQUEST=all "$SELECTOR"
    )")"
  fi
  printf 'preflight push check: changed files only; merge qualification is scripts/dev/preflight.sh --for-merge --emit-receipt\n'
  push_ran="$PREFLIGHT_TMP/push-ran"
  push_started=$SECONDS
  "$PUSH_CHECK" "$PREFLIGHT_CHANGED_PATHS" "$PREFLIGHT_EFFECTIVE_BASE_SHA" "$push_ran" </dev/null \
    || fail "push check"
  printf 'preflight: push check passed in %ss\n' "$((SECONDS - push_started))"
  emit_scope_receipt "$(paste -sd, "$push_ran")" "" merge-qualification
  exit 0
fi

if [ "$PREFLIGHT_SCOPE" = merge ]; then
  PREFLIGHT_MODE="$PREFLIGHT_REQUIRED_MODE"
  printf 'preflight merge mode: %s\n' "$PREFLIGHT_MODE"
fi

if [ "$PREFLIGHT_MODE" = explain ]; then
  printf 'preflight: explanation complete; no checks executed\n'
  exit 0
fi

if [ "$(mode_rank "$PREFLIGHT_MODE")" -lt "$(mode_rank "$PREFLIGHT_REQUIRED_MODE")" ]; then
  if [ -n "${PREFLIGHT_HEAD_SHA:-}" ]; then
    printf 'preflight: valid selection is incomplete; retry with CODEWIRE_PREFLIGHT_MODE=%s git push\n' \
      "$PREFLIGHT_REQUIRED_MODE" >&2
  else
    printf 'preflight: valid selection is incomplete; retry with scripts/dev/preflight.sh --%s\n' \
      "$PREFLIGHT_REQUIRED_MODE" >&2
  fi
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

# Kind runs only in the explicit Kind and full escalations. Merge
# qualification records it as not run; post-merge CI owns it.
PREFLIGHT_RUNS_KIND=false
if [ "$PREFLIGHT_SCOPE" != merge ] && selection_has kind; then
  PREFLIGHT_RUNS_KIND=true
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
if [ "$PREFLIGHT_RUNS_KIND" = true ]; then
  environment_args+=(--kind-browser)
fi
if selection_has_any contracts web sdk_ts runtime_dev_smoke; then
  environment_args+=(--node-modules)
fi
if selection_has contracts; then
  environment_args+=(--proto-venv)
fi
run_step "environment precheck" "$ENVIRONMENT_CHECK" "${environment_args[@]}"

# Merge qualification queues each family into a lane; the other modes run
# each family in place, in this order.
declare -a PREFLIGHT_STEPS=()
declare -A PREFLIGHT_STEP_LABEL=() PREFLIGHT_STEP_COMMAND=()

run_family() {
  local id="$1" label="$2"
  shift 2
  if [ "$PREFLIGHT_SCOPE" = merge ]; then
    PREFLIGHT_STEPS+=("$id")
    PREFLIGHT_STEP_LABEL["$id"]="$label"
    PREFLIGHT_STEP_COMMAND["$id"]="$(printf '%q ' "$@")"
  else
    run_step "$label" "$@"
  fi
}

run_selected_family() {
  local token="$1" family="$2" label="$3" step_environment=()
  # The same environment as the family's CI step: release provenance checks
  # a source capsule that Python bytecode caches would pollute.
  [ "$family" != release ] || step_environment=(PYTHONDONTWRITEBYTECODE=1)
  if selection_has "$token"; then
    run_family "$family" "$label" env "${step_environment[@]}" \
      VERIFICATION_SELECTION="$VERIFICATION_SELECTION" \
      VERIFICATION_PR_BASE_SHA="$PREFLIGHT_EFFECTIVE_BASE_SHA" \
      "$PRODUCT_RUNNER" "$family"
  fi
}

# Concurrent integration lanes start their services on separate port ranges.
integration_port_base() {
  if [ "$PREFLIGHT_SCOPE" != merge ]; then
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
run_selected_family ios ios "iOS verification"
run_selected_family sdk_go sdk-go "Go SDK verification"
run_selected_family sdk_ts sdk-ts "TypeScript SDK verification"
run_selected_family sdk_python sdk-python "Python SDK verification"
run_selected_family service_apikey_smoke service-apikey-smoke \
  "API key smoke tooling verification"
run_selected_family runtime_confidential runtime-confidential \
  "confidential runtime tooling verification"
run_selected_family runtime_dev_smoke runtime-dev-smoke \
  "Dev smoke tooling verification"

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
run_selected_family edge_kind edge "edge static verification"
if [ "$PREFLIGHT_RUNS_KIND" = true ]; then
  run_step "Kind e2e verification" scripts/ci/verify/kind-e2e.sh
fi
run_selected_family release release "release provenance verification"
run_selected_family deploy deploy "deploy verification"
run_selected_family security security "security verification"

if [ "$PREFLIGHT_SCOPE" != merge ]; then
  printf 'preflight: OK\n'
  exit 0
fi

# ---------------------------------------------------------------------------
# Merge qualification: exact-tree pass markers and parallel lanes.
#
# A marker records that one family passed for one exact key: the committed
# tree, selection, rustc toolchain and family, plus the canonical base for the
# one family that reads it (contracts compares protos with the base). A rerun
# of the same key reuses it; any other tree, selection or toolchain never
# matches. The selection already binds the change set the base produced.
if [ "${BASH_VERSINFO[0]}" -lt 5 ] \
    || { [ "${BASH_VERSINFO[0]}" -eq 5 ] && [ "${BASH_VERSINFO[1]}" -lt 1 ]; }; then
  fail "merge qualification needs Bash 5.1 or newer for lane supervision"
fi
PREFLIGHT_STATE_DIR="$REPO_ROOT/.tmp/preflight"
if ! git check-ignore -q "$PREFLIGHT_STATE_DIR/passed/probe"; then
  fail "merge state directory .tmp/ is not ignored by Git"
fi
PREFLIGHT_PASS_DIR="$PREFLIGHT_STATE_DIR/passed"
PREFLIGHT_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
PREFLIGHT_LOG_DIR="$PREFLIGHT_STATE_DIR/logs/$PREFLIGHT_RUN_ID"
PREFLIGHT_RESULT_DIR="$PREFLIGHT_TMP/results"
mkdir -p "$PREFLIGHT_PASS_DIR" "$PREFLIGHT_LOG_DIR" "$PREFLIGHT_RESULT_DIR"
PREFLIGHT_TREE="$(git rev-parse 'HEAD^{tree}')"
# Reading the identity never installs a toolchain as a side effect.
PREFLIGHT_TOOLCHAIN="$( (cd "$REPO_ROOT" && RUSTUP_AUTO_INSTALL=0 rustc -vV 2>/dev/null) \
  | sha256sum | cut -c1-64)"
printf 'preflight merge key: tree=%s toolchain=%s\n' "$PREFLIGHT_TREE" "$PREFLIGHT_TOOLCHAIN"
printf 'preflight family logs: %s\n' "$PREFLIGHT_LOG_DIR"

marker_key() {
  local base=-
  [ "$2" != contracts ] || base="$PREFLIGHT_EFFECTIVE_BASE_SHA"
  printf 'codewire-preflight-pass/v1\ntree=%s\nbase=%s\nselection=%s\ntoolchain=%s\nfamily=%s\n' \
    "$1" "$base" "$VERIFICATION_SELECTION" "$PREFLIGHT_TOOLCHAIN" "$2"
}

marker_path() {
  printf '%s/%s\n' "$PREFLIGHT_PASS_DIR" "$(marker_key "$1" "$2" | sha256sum | cut -c1-64)"
}

marker_valid() {
  local tree="$1" step="$2" path
  path="$(marker_path "$tree" "$step")"
  [ -f "$path" ] && [ ! -L "$path" ] \
    && [ "$(cat "$path")" = "$(marker_key "$tree" "$step")" ]
}

worktree_holds_key_tree() {
  # Lanes run concurrently; this read must not take Git's index lock.
  [ -z "$(GIT_OPTIONAL_LOCKS=0 git status --porcelain=v1 --untracked-files=all 2>/dev/null)" ] \
    && [ "$(git rev-parse 'HEAD^{tree}')" = "$PREFLIGHT_TREE" ]
}

# Record a pass only while the worktree still holds the exact key's tree. A
# pass that finishes while another lane briefly dirties the worktree is
# recorded at the end, once the tree is verified again.
write_marker() {
  local step="$1" path temporary
  worktree_holds_key_tree || return 0
  path="$(marker_path "$PREFLIGHT_TREE" "$step")"
  temporary="$(mktemp "$PREFLIGHT_PASS_DIR/.pass.XXXXXX")"
  marker_key "$PREFLIGHT_TREE" "$step" >"$temporary"
  mv -f "$temporary" "$path"
}

run_queued_step() {
  local step="$1" label log started status=0
  label="${PREFLIGHT_STEP_LABEL[$step]}"
  if marker_valid "$PREFLIGHT_TREE" "$step"; then
    printf '==> %s: reused the exact-tree pass\n' "$label"
    printf 'reused\n' >"$PREFLIGHT_RESULT_DIR/$step"
    return 0
  fi
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
  write_marker "$step"
  printf 'ran\n' >"$PREFLIGHT_RESULT_DIR/$step"
  printf '==> %s: passed in %ss\n' "$label" "$((SECONDS - started))"
}

lane_of() {
  case "$1" in
    policy) printf 'policy\n' ;;
    contracts) printf 'contracts\n' ;;
    rust-compile) printf 'compile\n' ;;
    rust|transport|rust-curated-locks) printf 'rust\n' ;;
    database|services-control|services-runtime) printf 'integration-%s\n' "$1" ;;
    # One lane owns the shared Bun dependency tree (node_modules).
    web|sdk-ts|runtime-dev-smoke) printf 'javascript\n' ;;
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
  set -m
  ( trap - EXIT INT TERM; run_lane "$lane" ) &
  set +m
  PREFLIGHT_LANE_PIDS+=("$!")
  PREFLIGHT_LANE_STARTED["$lane"]="$!"
  printf '%s\n' "$lane" >"$PREFLIGHT_TMP/lane-$!"
}

# Wait until the given lanes finish, watching every running lane. The first
# failure stops the others: their families did not finish, so they record no
# pass and a rerun repeats them.
await_lanes() {
  local -A waiting=()
  local pid finished status remaining
  for pid in "$@"; do
    waiting["$pid"]=1
  done
  while [ "${#waiting[@]}" -gt 0 ]; do
    status=0
    finished=""
    wait -n -p finished "${PREFLIGHT_LANE_PIDS[@]}" || status=$?
    [ -n "$finished" ] || fail "lane supervision"
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
      fail "merge qualification"
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
# Policy needs no build; it runs beside the compile gate. Every other lane
# waits for every Rust target to compile, so compile errors fail first.
start_lane policy
start_lane compile
compile_pid="${PREFLIGHT_LANE_STARTED[compile]:-}"
if [ -n "$compile_pid" ]; then
  await_lanes "$compile_pid"
fi
for lane in "${PREFLIGHT_LANES[@]}"; do
  case "$lane" in
    contracts|javascript|policy|compile) ;;
    *) start_lane "$lane" ;;
  esac
done
await_lanes "${PREFLIGHT_LANE_PIDS[@]}"

# Emit only when every queued family passed for this exact key: the
# worktree still holds the tree every family ran against, and each family
# either ran here or holds that key's pass.
worktree_holds_key_tree || fail "exact tree ${PREFLIGHT_TREE} unchanged during qualification"
ran=()
reused=()
for step in "${PREFLIGHT_STEPS[@]}"; do
  case "$(cat "$PREFLIGHT_RESULT_DIR/$step" 2>/dev/null || true)" in
    ran)
      marker_valid "$PREFLIGHT_TREE" "$step" || write_marker "$step"
      ran+=("$step")
      ;;
    reused) reused+=("$step") ;;
    *) fail "result for ${step}" ;;
  esac
  marker_valid "$PREFLIGHT_TREE" "$step" || fail "exact-tree pass for ${step}"
done
not_run=()
if selection_has kind || [ "$PREFLIGHT_REQUIRED_MODE" = kind ] \
    || [ "$PREFLIGHT_REQUIRED_MODE" = full ]; then
  not_run+=(kind)
fi
printf 'preflight: merge qualification passed in %ss (ran: %s; reused: %s)\n' \
  "$((SECONDS - qualification_started))" "${ran[*]:-none}" "${reused[*]:-none}"
if [ "${#not_run[@]}" -gt 0 ]; then
  printf 'preflight: not run locally: %s (post-merge CI owns it; run make kind-test for platform or dashboard behaviour)\n' \
    "${not_run[*]}"
fi
printf 'preflight: OK\n'
join_checks() {
  local IFS=,
  printf '%s' "$*"
}
emit_scope_receipt "$(join_checks "${ran[@]}")" "$(join_checks "${reused[@]}")" \
  "$(join_checks "${not_run[@]}")"
