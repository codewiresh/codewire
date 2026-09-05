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
cd "$REPO_ROOT"

usage() {
  cat <<'EOF'
usage: scripts/dev/preflight.sh [--default|--integration|--kind|--full|--explain]
       scripts/dev/preflight.sh --for-push --emit-receipt

default runs lightweight selected checks. Integration and Kind are explicit
environment escalations. --full runs the complete local-safe verification
universe; it never publishes, deploys, releases, or mutates live state.

--for-push derives the required mode, runs it before Git opens transport, and
--emit-receipt stores an eight-hour exact-tree receipt for the pre-push hook.
EOF
}

PREFLIGHT_MODE="${CODEWIRE_PREFLIGHT_MODE:-default}"
PREFLIGHT_FOR_PUSH=false
PREFLIGHT_EMIT_RECEIPT=false
explicit_mode=false
for argument in "$@"; do
  case "$argument" in
    --default) PREFLIGHT_MODE=default; explicit_mode=true ;;
    --integration) PREFLIGHT_MODE=integration; explicit_mode=true ;;
    --kind) PREFLIGHT_MODE=kind; explicit_mode=true ;;
    --full) PREFLIGHT_MODE=full; explicit_mode=true ;;
    --explain) PREFLIGHT_MODE=explain; explicit_mode=true ;;
    --for-push) PREFLIGHT_FOR_PUSH=true ;;
    --emit-receipt) PREFLIGHT_EMIT_RECEIPT=true ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
if [ "$PREFLIGHT_FOR_PUSH" = true ]; then
  if [ "$PREFLIGHT_EMIT_RECEIPT" != true ] || [ "$explicit_mode" = true ] \
      || [ "${CODEWIRE_PREFLIGHT_MODE:-default}" != default ]; then
    usage >&2
    exit 2
  fi
  for diagnostic_input in PREFLIGHT_CHANGED_FILES PREFLIGHT_FORCE_UNKNOWN \
      PREFLIGHT_HEAD_SHA PREFLIGHT_BASE_SHA PREFLIGHT_KIND_OPT_IN \
      PREFLIGHT_RELEASE_TAG_REF; do
    if [ -n "${!diagnostic_input:-}" ]; then
      printf 'preflight: --for-push rejects diagnostic input %s\n' \
        "$diagnostic_input" >&2
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

while IFS= read -r git_env_name; do
  unset "$git_env_name"
done < <(git rev-parse --local-env-vars)

PREFLIGHT_TMP="$(mktemp -d)"
PREFLIGHT_CHANGED_PATHS="$PREFLIGHT_TMP/changed-files"
PREFLIGHT_EFFECTIVE_BASE_SHA=""
trap 'rm -rf "$PREFLIGHT_TMP"' EXIT

fail() {
  printf 'preflight: %s FAILED\n' "$*" >&2
  exit 1
}

if [ "$PREFLIGHT_FOR_PUSH" = true ]; then
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

run_policy_local() {
  local syntax_files=()
  local candidate
  for candidate in \
      .githooks/pre-push \
      scripts/dev/preflight.sh \
      scripts/dev/install-hooks.sh \
      scripts/ci/select/select-verification.sh \
      scripts/ci/receipts/verify-release-tag-receipt.sh \
      scripts/ci/tests/test-select-verification.sh \
      scripts/ci/tests/test-verify-release-tag-receipt.sh \
      scripts/ci/tests/test-pre-push-worktree.sh \
      scripts/ci/verify/integration-postgres.sh \
      scripts/ci/verify/run-product-verification.sh \
      scripts/ci/verify/check-curated-rust-locks.sh \
      scripts/ci/tests/test-curated-rust-locks.sh \
      scripts/ci/verify/run-integration-verification.sh \
      scripts/ci/tests/test-integration-postgres.sh \
      scripts/ci/verify/rust-stack-rehearsal.sh; do
    [ -f "$candidate" ] && syntax_files+=("$candidate")
  done
  if [ -d scripts/runtime ]; then
    while IFS= read -r -d '' candidate; do
      syntax_files+=("$candidate")
    done < <(find scripts/runtime -type f -name '*.sh' -print0)
  fi
  if [ "${#syntax_files[@]}" -gt 0 ]; then
    run_step "verification shell syntax" bash -n "${syntax_files[@]}"
  fi
  run_step "Rust-owned schema and fixture guard" \
    scripts/ci/tests/test-rust-owned-fixtures.sh
  run_step "package license map" python3 scripts/checks/repo_checks.py license-map
  run_step "Permanent raw surface policy" python3 scripts/checks/repo_checks.py permanent-raw-surface --self-test
  run_step "Rust validation source guard" python3 scripts/checks/repo_checks.py rust-validation-source
  run_step "retired reference guard" python3 scripts/checks/repo_checks.py retired-reference-source
  run_step "native desktop UI guard" \
    python3 scripts/checks/source/check-native-desktop-ui.py
  run_step "Go source classification guard" python3 scripts/checks/repo_checks.py go-source-classification
  run_step "dashboard image network probe contract" \
    scripts/ci/tests/test-dashboard-image-network-probe.sh
}

run_selected_family() {
  local token="$1" family="$2" label="$3"
  if selection_has "$token"; then
    run_step "$label" env VERIFICATION_SELECTION="$VERIFICATION_SELECTION" \
      VERIFICATION_PR_BASE_SHA="$PREFLIGHT_EFFECTIVE_BASE_SHA" \
      "$PRODUCT_RUNNER" "$family"
  fi
}

collect_changed_paths "$PREFLIGHT_CHANGED_PATHS"

if [ -n "${PREFLIGHT_RELEASE_TAG_REF:-}" ]; then
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

selector_kind_opt_in=false
if [ "$PREFLIGHT_FOR_PUSH" = true ] || [ "$PREFLIGHT_MODE" = kind ] \
    || [ "$PREFLIGHT_MODE" = full ]; then
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

if [ "$PREFLIGHT_FOR_PUSH" = true ]; then
  PREFLIGHT_MODE="$PREFLIGHT_REQUIRED_MODE"
  printf 'preflight push mode: %s\n' "$PREFLIGHT_MODE"
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

if selection_has policy; then
  run_policy_local
fi

run_selected_family contracts contracts "contract verification"
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
  run_step "database verification" env \
    VERIFICATION_SELECTION="$VERIFICATION_SELECTION" \
    "$INTEGRATION_RUNNER" database
fi
if selection_has service_integration; then
  integration_lane_selected=false
  if selection_has_any service_idp service_coordinator service_billing \
      service_connectcore; then
    integration_lane_selected=true
    run_step "service control-plane verification" env \
      VERIFICATION_SELECTION="$VERIFICATION_SELECTION" \
      "$INTEGRATION_RUNNER" services-control
  fi
  if selection_has_any service_orchestration service_nats; then
    integration_lane_selected=true
    run_step "service runtime-plane verification" env \
      VERIFICATION_SELECTION="$VERIFICATION_SELECTION" \
      "$INTEGRATION_RUNNER" services-runtime
  fi
  [[ "$integration_lane_selected" == true ]] || \
    fail "service integration selected without a service scope"
fi

run_selected_family transport transport "Rust transport verification"
run_selected_family edge_kind edge "edge static verification"
if selection_has kind; then
  run_step "Kind e2e verification" scripts/ci/verify/kind-e2e.sh
fi
run_selected_family release release "release provenance verification"
run_selected_family deploy deploy "deploy verification"
run_selected_family security security "security verification"

printf 'preflight: OK\n'
if [ "$PREFLIGHT_EMIT_RECEIPT" = true ]; then
  run_step "atomic local pre-push receipt" \
    "$LOCAL_PREPUSH_RECEIPT" emit \
      --verified-base "$PREFLIGHT_EFFECTIVE_BASE_SHA" \
      --verified-mode "$PREFLIGHT_MODE" \
      --verified-selection "$VERIFICATION_SELECTION"
fi
