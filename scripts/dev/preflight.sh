#!/usr/bin/env bash
set -euo pipefail

# Local verification consumes the same capability selection as Gitea CI. It
# deliberately contains no changed-path classification of its own.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SELECTOR="$REPO_ROOT/scripts/ci/select/select-verification.sh"
PRODUCT_RUNNER="$REPO_ROOT/scripts/ci/verify/run-product-verification.sh"
INTEGRATION_RUNNER="$REPO_ROOT/scripts/ci/verify/run-integration-verification.sh"
cd "$REPO_ROOT"

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
    printf '__unknown__\n' > "$out"
    return
  fi

  base="${PREFLIGHT_BASE_SHA:-}"
  if [ -n "$base" ] && is_zero_sha "$base"; then
    base=""
  fi
  if [ -z "$base" ]; then
    base="$(preflight_base_ref)"
  fi
  if [ -z "$base" ] || ! ref_exists "$base"; then
    printf '__unknown__\n' > "$out"
    return
  fi
  base="$(git rev-parse --verify "$base^{commit}")"
  PREFLIGHT_EFFECTIVE_BASE_SHA="$base"

  if ! git diff --name-only "$base...$head" > "$out" 2>/dev/null \
    && ! git diff --name-only "$base" "$head" > "$out" 2>/dev/null; then
    printf '__unknown__\n' > "$out"
    return
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

selection_has() {
  [[ "$VERIFICATION_SELECTION" == *"|$1|"* ]]
}

run_policy_local() {
  local syntax_files=()
  local candidate
  for candidate in \
      .githooks/pre-push \
      scripts/dev/preflight.sh \
      scripts/dev/install-hooks.sh \
      scripts/ci/select/select-verification.sh \
      scripts/ci/tests/test-select-verification.sh \
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
  run_step "package license map" python3 scripts/checks/repo_checks.py license-map
  run_step "REST surface freeze ratchet" python3 scripts/checks/repo_checks.py rest-surface-freeze
  run_step "Rust validation source guard" python3 scripts/checks/repo_checks.py rust-validation-source
  run_step "retired reference guard" python3 scripts/checks/repo_checks.py retired-reference-source
  run_step "native desktop UI guard" \
    python3 scripts/checks/source/check-native-desktop-ui.py
  run_step "Go source classification guard" python3 scripts/checks/repo_checks.py go-source-classification
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

printf '==> preflight path selection\n'
if [ -s "$PREFLIGHT_CHANGED_PATHS" ]; then
  sed 's/^/  /' "$PREFLIGHT_CHANGED_PATHS"
else
  printf '  (no changed paths)\n'
fi

selector_output="$(
  env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
    GITHUB_EVENT_NAME=pull_request \
    KIND_E2E_OPT_IN="${PREFLIGHT_KIND_OPT_IN:-false}" \
    "$SELECTOR" "$PREFLIGHT_CHANGED_PATHS"
)"
VERIFICATION_SELECTION="$(selection_value "$selector_output")"
export VERIFICATION_SELECTION

if [[ "$VERIFICATION_SELECTION" != '|valid:v2|'* ]] \
  || [[ "$VERIFICATION_SELECTION" != *'|complete|' ]]; then
  fail "verification selection is missing or malformed"
fi

printf 'preflight selection: %s\n' "$VERIFICATION_SELECTION"

if selection_has policy; then
  run_policy_local
fi

run_selected_family contracts contracts "contract verification"
run_selected_family rust rust "Rust verification"
run_selected_family rust_curated_locks rust-curated-locks \
  "curated Rust workspace lock verification"
run_selected_family go_support go-support "Go support verification"
run_selected_family web web "web verification"
run_selected_family sdk_go sdk-go "Go SDK verification"
run_selected_family sdk_ts sdk-ts "TypeScript SDK verification"
run_selected_family sdk_python sdk-python "Python SDK verification"
run_selected_family service_apikey_smoke service-apikey-smoke \
  "API key smoke tooling verification"
run_selected_family runtime_confidential runtime-confidential \
  "confidential runtime tooling verification"

if selection_has database; then
  run_step "database verification" env \
    VERIFICATION_SELECTION="$VERIFICATION_SELECTION" \
    "$INTEGRATION_RUNNER" database
fi
if selection_has service_integration; then
  run_step "service integration verification" env \
    VERIFICATION_SELECTION="$VERIFICATION_SELECTION" \
    "$INTEGRATION_RUNNER" services
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
