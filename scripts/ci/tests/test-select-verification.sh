#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SELECTOR="$ROOT/scripts/ci/select/select-verification.sh"
WORKFLOW="$ROOT/.gitea/workflows/ci.yaml"
# The exact runs-on values: runner labels are repository Actions variables.
# shellcheck source=scripts/ci/tests/fixtures/ci-runners.sh
source "$ROOT/scripts/ci/tests/fixtures/ci-runners.sh"
# A main push's Heavy jobs take the trusted runners; every other run takes the
# untrusted ones. Kind still runs on its own unsized pool until it runs in a
# metal guest; every ordinary Heavy group runs on the sized metal pool.
HEAVY_RUNS_ON="$RUNS_ON_KIND"
METAL_MAIN_RUNS_ON="$RUNS_ON_HEAVY"
# Each one bounds cargo by its runner's memory at job start (bound-cargo-jobs.sh).
METAL_CARGO_BOUND='        run: scripts/ci/setup/bound-cargo-jobs.sh'
CLI_RELEASE_WORKFLOW="$ROOT/.gitea/workflows/cli-release.yaml"
TMP_ROOT="$ROOT/.tmp"
mkdir -p "$TMP_ROOT"
TMP="$(mktemp -d "$TMP_ROOT/selector.XXXXXX")"
# Cases that need a path to exist create it in a private root and run the
# selector from there. Nothing is written into the checkout: policy parts run
# side by side, and a file that appeared in the real tree would be seen by
# every tree-reading check beside this one.
cleanup() {
  rm -rf "$TMP"
}
trap cleanup EXIT
# The path-rule cases classify against a Cargo workspace without crate edges,
# so each pins its path rules alone and no case changes when a manifest
# gains a dependency. The crate-graph cases run real Cargo on a fixture
# workspace with edges, and on this repository's.
EDGELESS_CARGO="$TMP/edgeless-cargo"
mkdir -p "$EDGELESS_CARGO"
cat > "$EDGELESS_CARGO/cargo" <<'EOF'
#!/usr/bin/env bash
[ "${1:-}" = metadata ] || { echo "edgeless cargo stub: unexpected cargo $*" >&2; exit 2; }
printf '{"packages":[]}\n'
EOF
chmod +x "$EDGELESS_CARGO/cargo"

# The one switch for what a push to main runs (main-push-switch.sh, owner
# decision 2026-10-20), as checked in. Every case below holds for either
# value: MAIN_PUSH_KIND is the kind token a push to main selects with it.
# Copies of the selector's tree with each value prove both behaviours.
MAIN_PUSH_SWITCH="$ROOT/scripts/ci/select/main-push-switch.sh"
case "$(sed -n 's/^MAIN_PUSH_RUNS_KIND_AND_DRY_RUN=//p' "$MAIN_PUSH_SWITCH")" in
  true) MAIN_PUSH_KIND=kind ;;
  false) MAIN_PUSH_KIND='' ;;
  *) echo 'main-push-switch.sh does not set MAIN_PUSH_RUNS_KIND_AND_DRY_RUN to true or false' >&2; exit 1 ;;
esac
selector_with_switch() {
  # VALUE -> a copy of the selector's tree whose switch is VALUE
  local root="$TMP/switch-$1"
  mkdir -p "$root/scripts/ci/select"
  cp "$ROOT/scripts/ci/select/select-verification.sh" "$ROOT/scripts/ci/select/main-push-switch.sh" \
    "$root/scripts/ci/select/"
  cp "$ROOT/rust-toolchain.toml" "$root/"
  sed -i "s/^MAIN_PUSH_RUNS_KIND_AND_DRY_RUN=.*/MAIN_PUSH_RUNS_KIND_AND_DRY_RUN=$1/" \
    "$root/scripts/ci/select/main-push-switch.sh"
  printf '%s\n' "$root/scripts/ci/select/select-verification.sh"
}
SELECTOR_KIND_ON="$(selector_with_switch true)"
SELECTOR_KIND_OFF="$(selector_with_switch false)"

selection_value() {
  sed -n 's/^selection=//p' <<<"$1"
}

selection_tokens() {
  local selection="$1"
  selection="${selection#|valid:v3|}"
  selection="${selection%complete|}"
  tr '|' '\n' <<<"$selection" | sed '/^$/d' | LC_ALL=C sort
}

expected_tokens() {
  tr ' ' '\n' <<<"$1" | sed '/^$/d' | LC_ALL=C sort
}

# The selector's own CI-script test rule. The path cases below expect
# ci_script_tests wherever it holds; ci_script_tests_cases pins its edges.
eval "$(awk '
  $0 == "ci_script_test_input() {" { capture = 1 }
  capture { print }
  capture && /^}$/ { exit }
' "$ROOT/scripts/ci/select/select-verification.sh")"
declare -F ci_script_test_input >/dev/null || {
  echo 'the selector has no CI-script test rule' >&2
  exit 1
}
# The same for the Kind tool tests that run with Edge (#3119 R8);
# kind_tools_cases pins its edges.
eval "$(awk '
  $0 == "kind_tool_test_input() {" { capture = 1 }
  capture { print }
  capture && /^}$/ { exit }
' "$ROOT/scripts/ci/select/select-verification.sh")"
declare -F kind_tool_test_input >/dev/null || {
  echo 'the selector has no Kind tool test rule' >&2
  exit 1
}

# A path case selects the CI-script tests when one of its paths is their
# input, and the Kind tool tests when it selects Edge and one of its paths is
# theirs.
with_ci_script_tests() {
  local expected="$1" path
  shift
  if [[ " $expected " == *' policy '* && " $expected " != *' ci_script_tests '* ]]; then
    for path in "$@"; do
      if ci_script_test_input "$path"; then
        expected="$expected ci_script_tests"
        break
      fi
    done
  fi
  if [[ " $expected " == *' edge_kind '* && " $expected " != *' kind_tools '* ]]; then
    for path in "$@"; do
      if kind_tool_test_input "$path"; then
        expected="$expected kind_tools"
        break
      fi
    done
  fi
  printf '%s\n' "$expected"
}

assert_tokens() {
  local name="$1" expected="$2" output="$3" actual want selection
  if [[ " $expected " == *' policy '* ]] \
      && [[ " $expected " != *' policy_shell_omittable '* ]]; then
    expected="$expected policy_shell_omittable"
  fi
  if [[ " $expected " == *' policy '* ]] \
      && [[ " $expected " != *' ci_script_tests_omittable '* ]]; then
    expected="$expected ci_script_tests_omittable"
  fi
  if [[ " $expected " == *' edge_kind '* ]] \
      && [[ " $expected " != *' kind_tools_omittable '* ]]; then
    expected="$expected kind_tools_omittable"
  fi
  if [ "$(wc -l <<<"$output")" -ne 4 ] \
      || [ "$(sed -n '1p' <<<"$output")" != 'selector_version=v3' ] \
      || [[ "$(sed -n '2p' <<<"$output")" != classification=* ]] \
      || [[ "$(sed -n '3p' <<<"$output")" != selection='|valid:v3|'* ]] \
      || [[ "$(sed -n '4p' <<<"$output")" != required_local_mode=* ]]; then
    echo "${name}: routine selector output is not compact and versioned" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
  case "$(sed -n '2s/^classification=//p' <<<"$output")" in
    changed|unchanged|unclassified|requested|release|scheduled) ;;
    *) echo "${name}: invalid classification" >&2; exit 1 ;;
  esac
  case "$(sed -n '4s/^required_local_mode=//p' <<<"$output")" in
    default|integration|kind|full) ;;
    *) echo "${name}: invalid required local mode" >&2; exit 1 ;;
  esac
  selection="$(selection_value "$output")"
  if [[ "$selection" != '|valid:v3|'* ]] || [[ "$selection" != *'|complete|' ]]; then
    echo "${name}: invalid selection envelope: ${selection:-missing}" >&2
    exit 1
  fi
  actual="$(selection_tokens "$selection")"
  want="$(expected_tokens "$expected")"
  if [ "$actual" != "$want" ]; then
    echo "${name}: token mismatch" >&2
    echo '--- expected' >&2
    printf '%s\n' "$want" >&2
    echo '--- actual' >&2
    printf '%s\n' "$actual" >&2
    exit 1
  fi
}

run_paths_case() {
  local name="$1" event="$2" ref="$3" opt_in="$4" expected="$5"
  shift 5
  local paths="$TMP/${name}.paths" output path
  for path in "$@"; do
    if [[ "$path" == *.sh ]] && [[ " $expected " != *' policy_shell '* ]]; then
      expected="$expected policy_shell"
      break
    fi
  done
  expected="$(with_ci_script_tests "$expected" "$@")"
  printf '%s\n' "$@" > "$paths"
  # SELECTOR_CASE_ROOT runs the selector where the case's paths exist.
  output="$(cd "${SELECTOR_CASE_ROOT:-$PWD}" && env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
    PATH="$EDGELESS_CARGO:$PATH" GITHUB_EVENT_NAME="$event" GITHUB_REF="$ref" \
    KIND_E2E_OPT_IN="$opt_in" "$SELECTOR" "$paths")"
  assert_tokens "$name" "$expected" "$output"
}

run_present_paths_case() {
  local name="$1" event="$2" ref="$3" opt_in="$4" expected="$5"
  shift 5
  local fixture_root="$TMP/${name}.repo" paths="$TMP/${name}.paths" output path
  expected="$(with_ci_script_tests "$expected" "$@")"
  mkdir -p "$fixture_root"
  for path in "$@"; do
    mkdir -p "$fixture_root/$(dirname "$path")"
    : > "$fixture_root/$path"
  done
  printf '%s\n' "$@" > "$paths"
  output="$(cd "$fixture_root" && env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
    PATH="$EDGELESS_CARGO:$PATH" GITHUB_EVENT_NAME="$event" GITHUB_REF="$ref" \
    KIND_E2E_OPT_IN="$opt_in" "$SELECTOR" "$paths")"
  assert_tokens "$name" "$expected" "$output"
}

assert_contract_field() {
  local name="$1" output="$2" field="$3" expected="$4" actual
  actual="$(sed -n "s/^${field}=//p" <<<"$output")"
  if [ "$actual" != "$expected" ]; then
    echo "${name}: expected ${field}=${expected}, got ${actual:-missing}" >&2
    exit 1
  fi
}

# --- Crate graph ------------------------------------------------------------
# A changed crate selects its workspace reverse dependents' tests. Real Cargo
# reads this fixture workspace, whose edges cover each dependency kind:
#
#   graph-api       -> graph-core   normal, inherited from the workspace table
#   graph-app       -> graph-api    normal; nothing depends on graph-app
#   udp-relay       -> graph-core   build (a transport crate)
#   graph-optional  -> graph-core   optional, renamed and platform-specific
#   graph-tests     -> graph-api    dev only
#   graph-downstream-> graph-tests  normal
#   graph-detached  -> graph-core   excluded from the workspace
#
# Every member takes codewire-workspace-hack as a dev-dependency, as the
# repository's do. The fixture's own toolchain file and Cargo configuration
# name things that do not exist: the selector must use neither.
graph_repo="$TMP/crate-graph.repo"
write_graph_crate() {
  local name="$1" dependencies="${2:-}" dev_dependencies="${3:-}"
  if [ "$name" != codewire-workspace-hack ]; then
    dev_dependencies="codewire-workspace-hack = { path = \"../codewire-workspace-hack\" }
${dev_dependencies}"
  fi
  mkdir -p "$graph_repo/crates/$name/src"
  printf '[package]\nname = "%s"\nversion = "0.0.0"\nedition = "2021"\n\n%s\n\n[dev-dependencies]\n%s\n' \
    "$name" "$dependencies" "$dev_dependencies" > "$graph_repo/crates/$name/Cargo.toml"
  : > "$graph_repo/crates/$name/src/lib.rs"
}
mkdir -p "$graph_repo/.cargo"
cat > "$graph_repo/Cargo.toml" <<'EOF'
[workspace]
resolver = "2"
members = ["crates/*"]
exclude = ["crates/codewire-graph-detached"]

[workspace.dependencies]
codewire-graph-core = { path = "crates/codewire-graph-core" }
EOF
printf '[toolchain]\nchannel = "0.0.0-untrusted-candidate"\n' > "$graph_repo/rust-toolchain.toml"
printf '[build]\nrustc = "/nonexistent/untrusted-rustc"\n' > "$graph_repo/.cargo/config.toml"
write_graph_crate codewire-workspace-hack
write_graph_crate codewire-graph-core
write_graph_crate codewire-graph-api '[dependencies]
codewire-graph-core = { workspace = true }'
write_graph_crate codewire-graph-app '[dependencies]
codewire-graph-api = { path = "../codewire-graph-api" }'
write_graph_crate codewire-udp-relay '[build-dependencies]
codewire-graph-core = { path = "../codewire-graph-core" }'
write_graph_crate codewire-graph-optional "[target.'cfg(unix)'.dependencies]
core-renamed = { package = \"codewire-graph-core\", path = \"../codewire-graph-core\", optional = true }"
write_graph_crate codewire-graph-tests '' \
  'codewire-graph-api = { path = "../codewire-graph-api" }'
write_graph_crate codewire-graph-downstream '[dependencies]
codewire-graph-tests = { path = "../codewire-graph-tests" }'
write_graph_crate codewire-graph-detached '[dependencies]
codewire-graph-core = { path = "../codewire-graph-core" }'
git -C "$graph_repo" init -q

run_graph_case() {
  local name="$1" expected="$2" cargo_path="$3" output stderr="$TMP/$1.stderr"
  shift 3
  expected="$(with_ci_script_tests "$expected" "$@")"
  printf '%s\n' "$@" > "$TMP/${name}.paths"
  output="$(cd "$graph_repo" && env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
    PATH="${cargo_path:+$cargo_path:}$PATH" GITHUB_EVENT_NAME=pull_request \
    GITHUB_REF=refs/pull/1/head KIND_E2E_OPT_IN=false \
    "$SELECTOR" "$TMP/${name}.paths" 2>"$stderr")"
  assert_tokens "$name" "$expected" "$output"
}

graph_core='policy rust rust_pkg_codewire_graph_api rust_pkg_codewire_graph_app rust_pkg_codewire_graph_core rust_pkg_codewire_graph_optional rust_pkg_codewire_graph_tests transport transport_pkg_codewire_udp_relay'
graph_workspace='rust rust_curated_locks rust_workspace transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe'
# A leaf selects only itself.
run_graph_case graph_leaf 'policy rust rust_pkg_codewire_graph_app' '' \
  crates/codewire-graph-app/src/lib.rs
# A core crate selects every reverse dependent through normal, build, optional
# and platform-specific edges, transitively, in the family each one belongs
# to, and the dev-dependents of those. Not graph-downstream, which reaches the
# core only through graph-tests' dev-dependency, and not the detached crate.
run_graph_case graph_core "$graph_core" '' crates/codewire-graph-core/src/lib.rs
run_graph_case graph_core_manifest "$graph_core" '' crates/codewire-graph-core/Cargo.toml
# Another crate may compile a crate's test support (orchestration and the
# credential crates include codewire-platform-credentials/tests/support), so
# a test-only path still selects the reverse dependents.
run_graph_case graph_core_test_support "$graph_core" '' \
  crates/codewire-graph-core/tests/support/mod.rs
# A dev-dependency selects its dependent's tests and stops there.
run_graph_case graph_dev_dependent \
  'policy rust rust_pkg_codewire_graph_api rust_pkg_codewire_graph_app rust_pkg_codewire_graph_tests' '' \
  crates/codewire-graph-api/src/lib.rs
run_graph_case graph_dev_dependent_itself \
  'policy rust rust_pkg_codewire_graph_downstream rust_pkg_codewire_graph_tests' '' \
  crates/codewire-graph-tests/src/lib.rs
# Several changed crates select the union of their reverse dependents.
run_graph_case graph_union \
  "$graph_core rust_pkg_codewire_graph_downstream" '' \
  crates/codewire-graph-core/src/lib.rs crates/codewire-graph-tests/src/lib.rs
# The workspace-hack keeps its whole-workspace mapping, although every member
# dev-depends on it.
run_graph_case graph_workspace_hack "policy $graph_workspace" '' \
  crates/codewire-workspace-hack/Cargo.toml
# A crate the workspace does not list has no workspace dependents.
run_graph_case graph_detached 'policy rust rust_pkg_codewire_graph_detached' '' \
  crates/codewire-graph-detached/src/lib.rs
run_graph_case graph_deleted_crate 'policy rust rust_pkg_codewire_graph_gone' '' \
  crates/codewire-graph-gone/src/lib.rs

# Non-Rust paths, the root manifest and the lockfile keep their rules and
# never read the graph: a Cargo that cannot run changes nothing for them.
failing_cargo="$TMP/failing-cargo"
mkdir -p "$failing_cargo"
printf '#!/usr/bin/env bash\necho "synthetic cargo failure" >&2\nexit 101\n' \
  > "$failing_cargo/cargo"
chmod +x "$failing_cargo/cargo"
run_graph_case graph_ignores_docs policy "$failing_cargo" docs/guide.md
run_graph_case graph_ignores_root_manifest "policy $graph_workspace" "$failing_cargo" \
  Cargo.toml Cargo.lock
run_graph_case graph_ignores_proto \
  'contracts contracts_proto go_consumer_interop go_support policy' "$failing_cargo" \
  proto/codewire/v1/api_key.proto
for name in graph_ignores_docs graph_ignores_root_manifest graph_ignores_proto; do
  if [ -s "$TMP/${name}.stderr" ]; then
    echo "${name}: a path outside crates/ read the crate graph" >&2
    cat "$TMP/${name}.stderr" >&2
    exit 1
  fi
done
# Without a graph a crate change fails closed to the whole workspace, whether
# Cargo fails or prints something that is not metadata, and says why.
assert_graph_warning() {
  local name="$1" expected
  for expected in "${@:2}" \
      'warning: the crate graph is unavailable; selecting the whole Rust workspace'; do
    grep -qF "$expected" "$TMP/${name}.stderr" || {
      echo "${name}: stderr lacks '${expected}'" >&2
      cat "$TMP/${name}.stderr" >&2
      exit 1
    }
  done
}
run_graph_case graph_cargo_fails "policy $graph_workspace rust_pkg_codewire_graph_app" \
  "$failing_cargo" crates/codewire-graph-app/src/lib.rs
assert_graph_warning graph_cargo_fails 'synthetic cargo failure'
garbled_cargo="$TMP/garbled-cargo"
mkdir -p "$garbled_cargo"
printf '#!/usr/bin/env bash\necho "not metadata"\n' > "$garbled_cargo/cargo"
chmod +x "$garbled_cargo/cargo"
run_graph_case graph_cargo_garbled "policy $graph_workspace rust_pkg_codewire_graph_app" \
  "$garbled_cargo" crates/codewire-graph-app/src/lib.rs
assert_graph_warning graph_cargo_garbled

# This repository's own graph, through the same real Cargo. The binary crate
# is a leaf; the platform-credentials test support reaches the crates that
# compile it.
live_paths="$TMP/live-graph.paths"
printf '%s\n' crates/codewire-cli-bin/src/main.rs > "$live_paths"
live_output="$(cd "$ROOT" && env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
  GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/1/head KIND_E2E_OPT_IN=false \
  "$SELECTOR" "$live_paths")"
assert_tokens live_graph_leaf 'policy rust rust_pkg_codewire_cli_bin' "$live_output"
printf '%s\n' crates/codewire-platform-credentials/tests/support/mod.rs > "$live_paths"
live_output="$(cd "$ROOT" && env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
  GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/1/head KIND_E2E_OPT_IN=false \
  "$SELECTOR" "$live_paths")"
for token in rust_pkg_codewire_orchestration rust_pkg_codewire_credential_broker \
    rust_pkg_codewire_credential_service; do
  if [[ "$(selection_value "$live_output")" != *"|${token}|"* ]]; then
    echo "live_graph_test_support: ${token} missing from $(selection_value "$live_output")" >&2
    exit 1
  fi
done
# --- End crate graph ----------------------------------------------------------

policy=policy
run_paths_case shared_provider_enrollment pull_request refs/pull/1/head false \
  'database policy rust rust_pkg_codewire_cli rust_pkg_codewire_credential_broker rust_pkg_codewire_credential_service' \
  crates/codewire-credential-broker/src/provider_enrollment.rs
run_paths_case platform_credential_store pull_request refs/pull/1/head false \
  'database policy rust rust_pkg_codewire_credential_broker rust_pkg_codewire_platform_credentials' \
  crates/codewire-platform-credentials/src/store.rs
run_paths_case platform_credential_store_database_tests pull_request refs/pull/1/head false \
  'database policy rust rust_pkg_codewire_credential_broker rust_pkg_codewire_platform_credentials' \
  crates/codewire-platform-credentials/tests/storage.rs
run_paths_case platform_credential_shared_model pull_request refs/pull/1/head false \
  'database policy rust rust_pkg_codewire_access rust_pkg_codewire_credential_broker rust_pkg_codewire_platform_credentials' \
  crates/codewire-access/src/model.rs
for broker_input in src/platform.rs src/platform/tests.rs src/runtime.rs src/lib.rs Cargo.toml; do
  run_paths_case platform_broker_authority pull_request refs/pull/1/head false \
    'database policy rust rust_pkg_codewire_credential_broker' \
    "crates/codewire-credential-broker/$broker_input"
done
run_paths_case local_broker_adapter pull_request refs/pull/1/head false \
  'policy rust rust_pkg_codewire_credential_broker' \
  crates/codewire-credential-broker/src/local.rs
run_paths_case docs pull_request refs/pull/1/head false "$policy" \
  docs/guide.md README.md AGENTS.md crates/README.md
run_paths_case merge_message_template pull_request refs/pull/1/head false "$policy security security_js" \
  .gitea/default_merge_message/SQUASH_TEMPLATE.md
run_paths_case ios pull_request refs/pull/1/head false 'ios policy' \
  apps/ios/Sources/CodewireKit/Networking/CodewireClient.swift \
  apps/ios/Resources/Info.plist
run_paths_case repository_ignores pull_request refs/pull/10/head false "$policy" \
  .gitignore .dockerignore
run_paths_case repository_attributes pull_request refs/pull/1010/head false "$policy" \
  .gitattributes
run_paths_case gitleaks_policy pull_request refs/pull/10101/head false \
  'policy security' .gitleaks.toml
run_paths_case bun_review_baseline pull_request refs/pull/10102/head false \
  "$policy" .supplychain/bun-baseline.json
# The JavaScript supply-chain audit is grep-only, so every path it scans
# selects it beside that path's own families. #2517 changed a scanned script
# without selecting it, and the violation surfaced only on main.
run_paths_case js_audit_scanned_script pull_request refs/pull/2517/head false \
  'go_consumer_interop go_support policy policy_shell release confidential_script_tests security security_js' \
  scripts/ci/tests/test-support-images-workflow.sh
run_paths_case js_audit_scanned_workflow pull_request refs/pull/10103/head false \
  'deploy policy security security_js' .gitea/workflows/deploy-dev.yaml
run_paths_case js_audit_scanned_dockerfile pull_request refs/pull/10104/head false \
  'deploy go_consumer_interop go_support policy release confidential_script_tests security security_js web' \
  apps/dashboard/Dockerfile
run_paths_case js_audit_scanned_root_package pull_request refs/pull/10105/head false \
  'contracts contracts_proto policy security security_js web' package.json
run_paths_case js_audit_scanned_package_json pull_request refs/pull/10106/head false \
  'contracts contracts_proto policy security security_js' \
  packages/codewire-proto-ts/tsconfig.json
run_paths_case js_audit_unscanned_crate pull_request refs/pull/10107/head false \
  'policy rust rust_pkg_codewire_billing service_billing service_integration' \
  crates/codewire-billing/src/connect/billing.rs

# A wider audit must not outrun its selection: the selector's list covers a
# representative path for every pathspec the audit scans.
mapfile -t selector_js_audit_paths < <(
  sed -n '/^js_audit_paths=(/,/^)/s/^  "\(.*\)"$/\1/p' "$SELECTOR")
js_audit_selected() {
  local pattern
  for pattern in "${selector_js_audit_paths[@]}"; do
    # shellcheck disable=SC2053 # The unquoted side is the glob to match.
    [[ "$1" == $pattern ]] && return 0
  done
  return 1
}
if [ "${#selector_js_audit_paths[@]}" -eq 0 ] \
    || js_audit_selected crates/codewire-billing/src/lib.rs; then
  echo 'js_audit_paths: selector list is missing or matches an unscanned crate' >&2
  exit 1
fi
for audit_array in active_paths web_runtime_paths runtime_template_paths; do
  mapfile -t audit_pathspecs < <(
    sed -n "/^${audit_array}=(/,/^)/s/^  \"\\(.*\\)\"\$/\\1/p" \
      "$ROOT/scripts/checks/security/audit-js-supply-chain.sh")
  if [ "${#audit_pathspecs[@]}" -eq 0 ]; then
    echo "js_audit_paths: audit ${audit_array} not found" >&2
    exit 1
  fi
  for pathspec in "${audit_pathspecs[@]}"; do
    [[ "$pathspec" == ':('* ]] && continue
    example="${pathspec//\*\*/x/y}"
    example="${example//\*/x}"
    if ! js_audit_selected "$example"; then
      echo "js_audit_paths: selector does not cover audit pathspec ${pathspec}" >&2
      exit 1
    fi
  done
done
run_paths_case license_texts pull_request refs/pull/1011/head false "$policy" \
  LICENSE LICENSE-MIT LICENSE-APACHE LICENSE-BSD-3-CLAUSE \
  crates/codewire-cli/LICENSE packages/codewire-proto-ts/LICENSE-APACHE \
  proto/LICENSE-APACHE tests/contract/LICENSE
run_paths_case local_compose pull_request refs/pull/11/head false \
  'database deploy policy web' docker-compose.yml
run_paths_case local_compose_kind_opt_in pull_request refs/pull/111/head true \
  'database deploy edge_kind kind policy web' docker-compose.yml
run_paths_case ci_self pull_request refs/pull/2/head false \
  'go_consumer_interop go_support policy policy_shell release confidential_script_tests dev_smoke_script_tests rust_curated_locks security security_js' \
  .gitea/workflows/ci.yaml .gitea/workflows/manual-diagnostics.yaml \
  .gitea/workflows/source-approval.yml \
  scripts/ci/select/select-verification.sh \
  scripts/ci/select/emit-verification-matrices.sh \
  scripts/ci/select/require-verification-results.sh \
  scripts/ci/receipts/emit-verification-receipt.py \
  scripts/ci/receipts/verify-tested-tree-receipt.sh \
  scripts/ci/receipts/verify-release-tag-receipt.sh \
  scripts/ci/tests/test-require-verification-results.sh \
  scripts/ci/tests/test-emit-verification-matrices.sh \
  scripts/ci/tests/test-verify-tested-tree-receipt.sh \
  scripts/ci/tests/test-verify-release-tag-receipt.sh \
  scripts/ci/tests/test-source-approval-workflow.sh
# The host Rust build fixture selects Policy alone; an unmapped workflow is
# unclassified and qualifies in full.
run_paths_case host_rust_build_fixture pull_request refs/pull/3055/head false \
  'policy security security_js' \
  scripts/ci/tests/test-run-host-rust-build.sh
printf '%s\n' .gitea/workflows/unmapped-neighbour.yaml > "$TMP/unmapped-workflow.paths"
unmapped_workflow="$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
  GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/3055/head \
  KIND_E2E_OPT_IN=false "$SELECTOR" "$TMP/unmapped-workflow.paths" 2>/dev/null)"
assert_contract_field unmapped_workflow "$unmapped_workflow" classification unclassified
assert_contract_field unmapped_workflow "$unmapped_workflow" required_local_mode full
# Deleting the retired local merge gate (#3119 step 2.3) is classified, so its
# removal does not select every family.
run_paths_case retired_local_gate pull_request refs/pull/3119/head false \
  'policy security security_js' \
  .gitea/workflows/merge-check.yaml scripts/ci/plan/verified-base.py \
  scripts/ci/receipts/ci-merge-check.py scripts/ci/receipts/local-prepush-receipt.py \
  scripts/ci/select/merge-gate.py scripts/ci/select/merge-gate.tsv \
  scripts/ci/tests/test-ci-merge-check.py scripts/ci/tests/test-local-prepush-receipt.sh \
  scripts/ci/tests/test-merge-gate.py
# The integration PostgreSQL helper and its test are not tooling alone: the
# harness guard below proves they select database and every service (#3198).
run_paths_case ci_rewrite pull_request refs/pull/20/head false \
  'policy dev_smoke_script_tests rust_curated_locks security security_js' \
  .githooks/pre-push scripts/dev/preflight.sh \
  scripts/ci/verify/resolve-cargo-target-dir.sh \
  scripts/ci/verify/run-product-verification.sh \
  scripts/ci/tests/test-retired-local-sdk-contract.sh \
  scripts/checks/security/audit-rust-only-runtime.sh \
  scripts/ci/verify/rust-stack-rehearsal.sh \
  scripts/ci/tests/test-go-source-ownership.sh \
  scripts/ci/tests/test-resolve-cargo-target-dir.sh \
  scripts/ci/tests/test-cargo-target-runner-failures.sh \
  scripts/ci/tests/test-agent-sandbox-pin.sh \
  scripts/ci/tests/test-rust-owned-fixtures.sh \
  scripts/ci/tests/test-cargo-cache-capacity.sh \
  scripts/ci/tests/fixtures/cargo-cache-df.sh \
  scripts/ci/tests/test-select-verification.sh
# The shared runs-on fixtures feed only CI-script tests.
run_paths_case ci_runner_fixtures pull_request refs/pull/3189/head false \
  'policy security security_js' \
  scripts/ci/tests/fixtures/ci-runners.sh scripts/ci/tests/ci_runner_fixtures.py
run_paths_case retired_cache_surface pull_request refs/pull/200/head false \
  "$policy security security_js" \
  .gitea/workflows/rust-cache-refresh.yaml \
  scripts/ci/cache/prepare-rust-dependency-cache.sh \
  scripts/ci/cache/select-rust-cache-key.sh \
  scripts/ci/receipts/emit-rust-cache-receipt.py \
  scripts/ci/receipts/verify-rust-cache-receipt.sh \
  scripts/ci/tests/test-rust-cache-workflow.sh \
  scripts/ci/tests/test-rust-cache-receipts.sh
run_paths_case shellcheck_policy_domain_future pull_request refs/pull/2001/head false \
  'policy policy_shell security security_js' scripts/ci/tests/test-shellcheck-policy-domain.sh
grep -qF 'scripts/ci/tests/test-shellcheck-policy-domain.sh' "$SELECTOR"
run_paths_case openbao_secret_authority_policy pull_request refs/pull/20011/head false \
  'policy policy_shell security security_js' scripts/ci/tests/test-openbao-only-secret-authority.sh \
  scripts/ci/tests/test-preflight-openbao-native-secrets.sh \
  scripts/ci/tests/test-sync-local-secrets.sh
run_paths_case local_secret_sync_policy pull_request refs/pull/20012/head false \
  'policy policy_shell security security_js' scripts/dev/kind/sync-local-secrets.sh
run_paths_case workstation_cpu_helper pull_request refs/pull/20016/head false \
  'policy policy_shell security security_js' scripts/dev/workstation-cpu.sh docs/dev/AGENT-WORKFLOW.md
run_paths_case kind_runtime_images_fixture pull_request refs/pull/20014/head false \
  'policy policy_shell security security_js' scripts/ci/tests/test-kind-runtime-images.sh
run_paths_case kind_watch_github_app_fixture pull_request refs/pull/20015/head false \
  'policy policy_shell security security_js' scripts/ci/tests/test-kind-watch-github-app.sh
# The retained-cluster helpers are policy even where Kind would run; any other
# scripts/dev/kind helper still selects the Kind gate.
run_paths_case kind_retained_helpers_main push refs/heads/main false \
  'policy policy_shell security security_js' scripts/dev/kind/dev-loop.sh scripts/ci/tests/test-kind-runtime-images.sh \
  scripts/ci/tests/test-kind-watch-github-app.sh
run_paths_case kind_deploy_helper_main push refs/heads/main false \
  'policy policy_shell security security_js' scripts/dev/kind/deploy-service.sh scripts/dev/kind/trust-roots.sh \
  deployments/docker/kind-dev-binary.Dockerfile
run_paths_case kind_dev_helper_main push refs/heads/main false \
  "edge_kind ${MAIN_PUSH_KIND} policy policy_shell security security_js" scripts/dev/kind/kind-forwards.sh
# The retained cluster's database helper runs its hermetic fixture, not Kind.
run_paths_case kind_database_helper_main push refs/heads/main false \
  'edge_kind policy policy_shell security security_js' scripts/dev/kind/database.sh
run_paths_case root_secret_authority_inputs pull_request refs/pull/20013/head false \
  'policy' .env.example secret-authority.example.json
run_paths_case ci_tool_download_contract pull_request refs/pull/2002/head false \
  'deploy policy policy_shell security security_js' scripts/ci/tests/test-ci-tool-downloads.sh
# The local Kind dev-binary Dockerfile is not a product image input.
run_paths_case kind_dev_binary_dockerfile pull_request refs/pull/2091/head false \
  'policy' deployments/docker/kind-dev-binary.Dockerfile
run_paths_case kind_dev_binary_with_product_dockerfile pull_request refs/pull/2092/head false \
  'deploy go_consumer_interop go_support policy release confidential_script_tests' \
  deployments/docker/kind-dev-binary.Dockerfile docker-bake.hcl
run_paths_case product_image_build_graph pull_request refs/pull/2003/head false \
  'deploy go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  docker-bake.hcl scripts/ci/images/build-kind-images.sh \
  scripts/ci/images/run-rust-build.sh
run_paths_case product_image_build_graph_kind pull_request refs/pull/2004/head true \
  'deploy edge_kind go_consumer_interop go_support kind policy release confidential_script_tests security security_js' \
  docker-bake.hcl scripts/ci/images/build-kind-images.sh \
  scripts/ci/images/run-rust-build.sh
# The owned BuildKit builder removal is shared by the workspace verification
# and the Kind image build, so it selects both consumers' families.
run_paths_case buildx_builder_removal pull_request refs/pull/3072/head false \
  'deploy go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/images/buildx-builder.sh scripts/ci/tests/test-buildx-builder.sh
run_paths_case buildx_builder_removal_kind pull_request refs/pull/3073/head true \
  'deploy edge_kind go_consumer_interop go_support kind policy release confidential_script_tests security security_js' \
  scripts/ci/images/buildx-builder.sh scripts/ci/tests/test-buildx-builder.sh
run_paths_case harbor_runtime_pull_contract pull_request refs/pull/2006/head false \
  'go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/tests/test-harbor-runtime-pull-contract.sh
run_paths_case protected_runtime_signing pull_request refs/pull/2005/head false \
  'deploy go_consumer_interop go_support policy policy_shell release confidential_script_tests security security_js' \
  scripts/ci/images/cosign-private-signing-config.json \
  scripts/ci/images/sign-runtime-image-set.sh \
  scripts/ci/tests/test-sign-runtime-image-set.sh \
  scripts/ci/trust/codewire-runtime-signing.pub
# The protected Dev runtime builder and its contract never build a Kind image:
# they select Deploy and release verification, not Kind, even on main.
run_paths_case protected_runtime_builder push refs/heads/main false \
  'deploy go_consumer_interop go_support policy policy_shell release confidential_script_tests security security_js' \
  scripts/ci/images/build-push-runtime-images.sh \
  scripts/ci/tests/test-build-push-runtime-images.sh
# Dev delivery from main CI's verdict (#2892): the descent check runs in
# Deploy, as does the superseded-delivery cancellation with its contract, and
# the trigger CI's final job runs, with its contract, in Deploy and Policy.
run_paths_case dev_delivery_descent_check push refs/heads/main false \
  'deploy policy policy_shell security security_js' \
  scripts/ci/deploy/require-dev-descent.sh
run_paths_case dev_delivery_cancel_superseded push refs/heads/main false \
  'deploy policy security security_js' \
  scripts/ci/deploy/cancel-superseded-deliveries.py \
  scripts/ci/tests/test-cancel-superseded-deliveries.py
run_paths_case dev_delivery_trigger push refs/heads/main false \
  'deploy policy security security_js' \
  scripts/ci/deploy/rerun-dev-publish.py \
  scripts/ci/tests/test-rerun-dev-publish.py
run_paths_case pull_request_fail_fast pull_request refs/pull/3400/head false \
  'deploy policy security security_js' \
  scripts/ci/select/fail-fast-watch.py \
  scripts/ci/tests/test-fail-fast-watch.py
run_paths_case production_signature_reuse pull_request refs/pull/2007/head false \
  'deploy go_consumer_interop go_support policy policy_shell release confidential_script_tests security security_js' \
  scripts/ci/images/verify-runtime-image-signatures.sh \
  scripts/ci/tests/test-verify-runtime-image-signatures.sh
run_paths_case runtime_plan_ci pull_request refs/pull/201/head false \
  'deploy go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/deploy/resolve-deployed-source.sh \
  scripts/ci/plan/apply-deploy-plan.py \
  scripts/ci/images/resolve-published-support-pair.sh \
  scripts/ci/tests/test-resolve-published-support-pair.sh \
  scripts/ci/tests/test-resolve-deployed-source.sh
run_paths_case repo_checks pull_request refs/pull/21/head false \
  'contracts contracts_proto deploy go_consumer_interop go_support policy release confidential_script_tests security security_idp_kek security_js' \
  scripts/checks/repo_checks.py
run_paths_case repo_policy_modules pull_request refs/pull/22/head false \
  'contracts contracts_proto deploy go_consumer_interop go_support policy release confidential_script_tests security security_idp_kek security_js' \
  scripts/checks/repo_policy/mesh.py
run_paths_case repo_license_inventory pull_request refs/pull/2201/head false \
  'policy security security_js' scripts/checks/repo_policy/licensing.py
run_paths_case repo_public_address_guard pull_request refs/pull/2203/head false \
  'policy security security_js' scripts/checks/repo_policy/public_addresses.py
run_paths_case repo_private_host_guard pull_request refs/pull/3189/head false \
  'policy security security_js' scripts/checks/repo_policy/private_hosts.py
run_paths_case repo_license_with_other_policy pull_request refs/pull/2202/head false \
  'contracts contracts_proto deploy go_consumer_interop go_support policy release confidential_script_tests security security_idp_kek security_js' \
  scripts/checks/repo_policy/licensing.py scripts/checks/repo_policy/mesh.py
run_paths_case service_ssh_image_verifier pull_request refs/pull/1922/head false \
  'policy security security_js' scripts/ci/tests/test-service-ssh-image-verifier.sh \
  scripts/ci/verify/service-ssh-image-contract.sh scripts/ci/verify/verify-service-ssh-image.sh
# The public install/update/rollback acceptance journey is release tooling.
run_paths_case release_update_journey pull_request refs/pull/3/head false \
  'go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/dev/test-cw-release-update.py
run_paths_case apt_transactions pull_request refs/pull/3/head false \
  'go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/tests/test-apt-get-with-retry.sh

run_paths_case release pull_request refs/pull/3/head false \
  'go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  .gitea/workflows/cli-release.yaml \
  .gitea/workflows/mirror-github.yaml \
  apps/cli/GPG_PUBLIC_KEY.asc \
  keys/production-release.asc \
  apps/cli/README.md \
  apps/cli/install.sh \
  images/base/Dockerfile \
  images/base/entrypoint.sh \
  scripts/ci/release/mirror-canonical-release-tag.sh \
  scripts/ci/release/mirror-git-tags.sh \
  scripts/ci/tests/test-base-image-source.sh \
  scripts/ci/images/copy-image-to-ghcr.sh \
  scripts/ci/images/publish-image-to-ghcr.sh \
  scripts/ci/images/resolve-published-support-pair.sh \
  scripts/ci/images/run-skopeo-container.sh \
  scripts/ci/release/package-cw-release.sh \
  scripts/ci/release/publish-cw-release.sh \
  scripts/ci/tests/test-copy-image-to-ghcr.sh \
  scripts/ci/tests/test-publish-image-to-ghcr.sh \
  scripts/ci/tests/test-resolve-published-support-pair.sh \
  scripts/ci/tests/test-run-skopeo-container.sh \
  scripts/ci/tests/test-support-images-workflow.sh \
  scripts/ci/tests/test-workspace-image-verify-workflow.sh \
  scripts/ci/tests/test-build-push-image.sh \
  scripts/ci/tests/test-mirror-git-tags.sh \
  scripts/ci/tests/test-publish-cw-release.sh \
  scripts/ci/tests/test-verify-cw-release-signing-key.sh \
  scripts/ci/tests/test-verify-release-tag-ref.sh \
  scripts/ci/release/verify-cw-release-signing-key.sh \
  scripts/ci/release/verify-release-tag-ref.sh \
  scripts/ci/release/confirm-release-checkout.sh \
  scripts/ci/release/require-production-accepted.sh \
  scripts/ci/tests/test-require-production-accepted.sh \
  scripts/ci/release/alias-release-images.sh \
  scripts/ci/release/finish-prod-release.sh \
  scripts/ci/release/find-pending-release.sh \
  scripts/ci/tests/test-find-pending-release.sh \
  scripts/ci/release/release-tags.sh \
  scripts/ci/release/require-current-release.sh \
  scripts/ci/release/confirm-release-checkout.sh \
  install.sh
# Presence matters: an unlisted existing script selects unknown/full, while
# deleted scripts deliberately remain policy-only. Prove each new owner path.
run_present_paths_case bounded_external_downloads \
  pull_request refs/pull/2691/head false \
  'go_consumer_interop go_support policy policy_shell release confidential_script_tests security security_js' \
  scripts/ci/release/fetch-pinned.sh \
  scripts/ci/tests/test-fetch-pinned.sh
run_present_paths_case public_installer_test \
  pull_request refs/pull/952/head false \
  'go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/tests/test-cw-install.py
run_paths_case protected_delivery_credentials pull_request refs/pull/31/head false \
  'deploy go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/setup/curl-transport-retry.sh \
  scripts/ci/setup/fetch-forgejo-deploy-prod-token.sh \
  scripts/ci/setup/fetch-openbao-github-mirror-credentials.sh \
  scripts/ci/setup/release-run-identity.sh \
  scripts/ci/release/mint-github-app-token.sh \
  scripts/ci/release/mirror-github.sh \
  scripts/ci/tests/test-fetch-openbao-github-mirror-credentials.sh \
  scripts/ci/tests/test-mint-github-app-token.sh
run_paths_case sccache_r2_consumer pull_request refs/pull/1749/head false \
  'policy security security_js' \
  scripts/ci/setup/fetch-openbao-sccache-r2-credentials.sh
run_paths_case sccache_r2_consumer_fixture pull_request refs/pull/1750/head false \
  'policy security security_js' \
  scripts/ci/tests/test-fetch-openbao-sccache-r2-credentials.sh
run_paths_case sccache_r2_protected_consumer pull_request refs/pull/2354/head false \
  'deploy go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/setup/fetch-openbao-sccache-r2-protected-credentials.sh
run_paths_case sccache_r2_protected_consumer_fixture pull_request refs/pull/2355/head false \
  'deploy go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/tests/test-fetch-openbao-sccache-r2-protected-credentials.sh
run_paths_case sccache_r2_protected_selector pull_request refs/pull/2356/head false \
  'deploy go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/setup/select-protected-rust-cache.sh
run_paths_case sccache_r2_protected_selector_fixture pull_request refs/pull/2357/head false \
  'deploy go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/tests/test-select-protected-rust-cache.sh
run_paths_case sccache_host_selector pull_request refs/pull/1751/head false \
  'policy rust rust_workspace security security_js' \
  scripts/ci/setup/select-untrusted-rust-cache.sh \
  scripts/ci/setup/finish-untrusted-rust-cache.sh
run_paths_case sccache_host_selector_fixture pull_request refs/pull/1752/head false \
  'policy security security_js' \
  scripts/ci/tests/test-select-untrusted-rust-cache.sh
run_paths_case warm_rust_cache pull_request refs/pull/3094/head false \
  'policy rust rust_workspace security security_js' \
  scripts/ci/setup/select-warm-rust-cache.sh \
  scripts/ci/setup/finish-warm-rust-cache.sh
run_paths_case warm_rust_cache_fixture pull_request refs/pull/3095/head false \
  'policy security security_js' \
  scripts/ci/tests/test-warm-rust-cache.sh
run_paths_case bound_cargo_jobs pull_request refs/pull/3101/head false \
  'policy rust rust_workspace security security_js' \
  scripts/ci/setup/bound-cargo-jobs.sh
run_paths_case bound_cargo_jobs_fixture pull_request refs/pull/3102/head false \
  'policy security security_js' \
  scripts/ci/tests/test-bound-cargo-jobs.sh
# Compile once's build half selects the Rust families it builds for, and the
# guest CPU share also the database and service families whose lanes and
# test threads it sizes (infra#1632).
run_paths_case build_once_builder pull_request refs/pull/3356/head false \
  'policy rust rust_workspace security security_js' \
  scripts/ci/setup/build-once.sh
run_paths_case guest_cpu_share pull_request refs/pull/3413/head false \
  'database policy rust rust_workspace security security_js service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal' \
  scripts/ci/setup/cpu-share.sh
run_paths_case workspace_cache_consumers pull_request refs/pull/2047/head false \
  'policy security security_js' \
  scripts/ci/setup/select-untrusted-workspace-cache.sh \
  scripts/ci/setup/prepare-workspace-cache-measurement.sh \
  scripts/ci/setup/select-workspace-cache-experiment.py \
  scripts/ci/images/workspace-cache.sh \
  scripts/ci/tests/test-select-untrusted-workspace-cache.sh \
  scripts/ci/tests/test-workspace-cache.sh \
  scripts/ci/tests/test-workspace-cache-experiment.py \
  scripts/ci/verify/workspace-cache-report.py \
  scripts/ci/tests/probe-workspace-r2-cache.sh \
  scripts/ci/tests/test-workspace-cache-probes.py \
  scripts/ci/verify/workspace-cache-probes.py \
  scripts/ci/tests/canary-workspace-r2-cache.sh
run_paths_case cw_image_source_consumers pull_request refs/pull/2255/head false \
  'policy security security_js' \
  scripts/ci/images/prepare-cw-source-context.py \
  scripts/ci/images/build-cw-runtime-source.py \
  scripts/ci/images/finalize-cw-runtime-source.py \
  scripts/ci/images/prepare-cw-image-context.py \
  scripts/ci/images/cw-image-consumer.py \
  scripts/ci/images/cw-image-consumer.sh \
  scripts/ci/images/cw-image-source.py \
  scripts/ci/images/build-product-images.sh \
  scripts/ci/tests/test-cw-image-context.py \
  scripts/ci/tests/test-cw-runtime-source.py \
  scripts/ci/tests/test-cw-image-consumer.py \
  scripts/ci/tests/test-cw-image-source.py \
  scripts/ci/tests/cw_image_fixtures.py
run_present_paths_case workspace_cache_experiment_consumers pull_request refs/pull/2047/head false \
  'policy policy_shell security security_js' \
  scripts/ci/setup/select-workspace-cache-experiment.py \
  scripts/ci/tests/probe-workspace-r2-cache.sh \
  scripts/ci/tests/test-workspace-cache-experiment.py \
  scripts/ci/tests/test-workspace-cache-probes.py \
  scripts/ci/verify/workspace-cache-probes.py \
  scripts/ci/verify/workspace-cache-report.py
run_paths_case dev_deploy_contract pull_request refs/pull/30/head false \
  'deploy go_consumer_interop go_support policy release confidential_script_tests security security_js' scripts/ci/tests/test-deploy-dev.sh
run_paths_case dev_smoke_receipt pull_request refs/pull/302/head false \
  'policy security security_js' \
  .gitea/workflows/dev-deployment-smoke-receipt.yaml \
  scripts/ci/tests/test-dev-deployment-smoke-receipt.sh
run_paths_case ci_start_latency pull_request refs/pull/3030/head false \
  'policy security security_js' \
  .gitea/workflows/ci-start-latency.yaml \
  scripts/ci/measure/README.md \
  scripts/ci/measure/forgejo-ci-start-latency \
  scripts/ci/measure/forgejo-ci-start-latency.sha256
run_paths_case ci_done_measures pull_request refs/pull/3144/head false \
  'policy security security_js' \
  .gitea/workflows/ci-done-measures.yaml \
  scripts/ci/measure/ci-done-measures \
  scripts/ci/tests/test-ci-done-measures.py
run_paths_case retired_prod_readonly_smoke pull_request refs/pull/3021/head false \
  'policy security security_js' \
  .gitea/workflows/prod-readonly-smoke.yaml \
  scripts/ci/setup/setup-kubeconfig.sh \
  scripts/ci/tests/test-setup-kubeconfig.sh
run_paths_case retired_promotion_control pull_request refs/pull/300/head false \
  'deploy go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/deprecated-promotion-control.sh \
  scripts/ci/test-deprecated-promotion-control.py
run_paths_case sha_dispatch pull_request refs/pull/301/head false \
  'deploy go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/deploy/dispatch-deploy-dev.sh \
  scripts/ci/tests/test-dispatch-deploy-dev.sh \
  scripts/ci/deploy/dispatch-deploy-prod.sh \
  scripts/ci/tests/test-dispatch-deploy-prod.sh
run_paths_case dev_deploy_oidc pull_request refs/pull/3011/head false \
  'deploy go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/setup/fetch-forgejo-deploy-dev-token.sh \
  scripts/ci/tests/test-fetch-forgejo-deploy-dev-token.sh
run_paths_case idp_kek_boundary pull_request refs/pull/32/head false \
  'deploy policy security security_idp_kek security_js' \
  deployments/k8s/idp/deployment.yaml
run_paths_case orchestration_host_key_authz pull_request refs/pull/910/head false \
  'deploy policy security security_idp_kek security_js' deployments/k8s/orchestration/internal-roots-authz.yaml
run_paths_case leaf_rust pull_request refs/pull/4/head false \
  'policy rust rust_pkg_codewire_cli' \
  crates/codewire-cli/src/commands/info.rs
run_paths_case cli_bin_rust pull_request refs/pull/400/head false \
  'policy rust rust_pkg_codewire_cli_bin' \
  crates/codewire-cli-bin/Cargo.toml
run_paths_case repository_codewire_yaml pull_request refs/pull/404/head false \
  'policy rust rust_pkg_codewire_project' \
  codewire.yaml
run_paths_case detached_desktop pull_request refs/pull/401/head false \
  'policy rust rust_pkg_codewire_desktop' \
  crates/codewire-desktop/src/main.rs
run_paths_case desktop_shared_types pull_request refs/pull/4011/head false \
  'policy rust rust_pkg_codewire_desktop rust_pkg_codewire_types' \
  crates/codewire-types/src/types.rs
run_paths_case retired_platform_native pull_request refs/pull/402/head false \
  'policy rust rust_pkg_codewire_desktop' \
  crates/codewire-platform-native/src/lib.rs
run_paths_case detached_ui pull_request refs/pull/403/head false \
  'policy rust rust_pkg_codewire_desktop' \
  crates/codewire-ui/src/lib.rs
run_paths_case native_desktop_ui_guard pull_request refs/pull/4031/head false \
  'policy rust rust_pkg_codewire_desktop security security_js' \
  scripts/checks/source/check-native-desktop-ui.py \
  scripts/checks/contracts/native-desktop-ui-policy.json
run_paths_case detached_desktop_package pull_request refs/pull/404/head false \
  'policy rust rust_pkg_codewire_desktop security security_js' \
  scripts/ci/release/package-codewire-desktop.sh \
  scripts/ci/tests/test-package-codewire-desktop.sh
run_paths_case retired_desktop_workflow pull_request refs/pull/405/head false \
  'policy security security_js' .gitea/workflows/desktop-package.yaml
run_paths_case artifact_plan_policy pull_request refs/pull/406/head false \
  'policy security security_js' scripts/ci/plan/planner.py scripts/ci/plan/artifact-graph.json
python3 "$ROOT/scripts/ci/plan/tests/test_decision_corpus.py"
run_paths_case rust_root pull_request refs/pull/5/head false \
  'policy rust rust_curated_locks rust_workspace transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  Cargo.lock
run_paths_case rust_root_manifest pull_request refs/pull/50/head false \
  'policy rust rust_curated_locks rust_workspace transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  Cargo.toml
run_paths_case rust_root_toolchain pull_request refs/pull/500/head false \
  'policy rust rust_curated_locks rust_workspace transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  rust-toolchain.toml
run_paths_case rust_workspace_hack_config pull_request refs/pull/5021/head false \
  'policy rust rust_curated_locks rust_workspace transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  .config/hakari.toml
run_paths_case rust_workspace_hack pull_request refs/pull/5022/head false \
  'policy rust rust_curated_locks rust_workspace transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  crates/codewire-workspace-hack/Cargo.toml crates/codewire-workspace-hack/src/lib.rs
run_paths_case curated_gateway_member_manifest pull_request refs/pull/501/head false \
  'policy rust rust_curated_locks rust_pkg_codewire_credential_broker transport transport_pkg_codewire_daemon transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  crates/codewire-daemon/Cargo.toml
run_paths_case local_vmm_host_source pull_request refs/pull/5011/head false \
  'policy transport transport_pkg_codewire_local_vmm' \
  crates/codewire-local-vmm/src/lib.rs
run_paths_case macos_vz_runner_source pull_request refs/pull/50111/head false \
  'policy transport transport_pkg_codewire_local_vmm' \
  crates/codewire-local-vmm/macos-vz-runner/Sources/CodewireVZRunnerRuntime/Runtime.swift
run_paths_case local_vmm_guest_source pull_request refs/pull/5012/head false \
  'policy transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  crates/codewire-vmm-guest-probe/src/lib.rs
run_paths_case local_vmm_network_fixture pull_request refs/pull/50121/head false \
  'policy transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  testdata/local-vm-network/protocol-v1.json
run_paths_case local_vmm_initramfs_builder pull_request refs/pull/5013/head false \
  'policy security security_js transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  scripts/ci/verify/build-local-vmm-initramfs.sh
run_paths_case local_vmm_kvm_smoke pull_request refs/pull/5014/head false \
  'policy security security_js transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  scripts/ci/verify/smoke-local-vmm-cloud-hypervisor.sh
for kernel_input in scripts/ci/verify/build-linux-vmm-kernel.py \
    scripts/ci/verify/linux-vmm-kernel/x86_64.config \
    scripts/ci/verify/linux-vmm-kernel/arm64.config \
    scripts/ci/verify/linux-vmm-kernel/dax.patch \
    scripts/ci/verify/linux-vmm-kernel/provenance.json \
    scripts/ci/tests/test-linux-vmm-kernel.py; do
  run_paths_case "local_vmm_kernel_${kernel_input##*/}" pull_request refs/pull/2255/head false \
    'policy security security_js transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
    "$kernel_input"
done
run_paths_case native_local_environment_smoke pull_request refs/pull/5015/head false \
  'policy security security_js transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  scripts/ci/verify/smoke-native-local-environment.sh
run_paths_case shared_stock_ssh_smoke pull_request refs/pull/5016/head false \
  'policy dev_smoke_script_tests security security_js transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  scripts/ci/verify/stock-ssh-workload.sh
for ssh_input in scripts/runtime/dev/provider-ssh-smoke.sh scripts/runtime/tests/test-provider-ssh-smoke.sh \
    scripts/runtime/dev/provider-codex-smoke.sh scripts/runtime/dev/provider-codex-workload.sh \
    scripts/runtime/dev/provider-codex-output.py scripts/runtime/tests/test-provider-codex-smoke.sh \
    scripts/runtime/tests/test-provider-codex-workload.py \
    scripts/runtime/dev/provider-anthropic-smoke.sh scripts/runtime/dev/provider-anthropic-workload.sh \
    scripts/runtime/dev/provider-anthropic-output.py scripts/runtime/tests/test-provider-anthropic-smoke.sh \
    scripts/runtime/tests/test-provider-anthropic-workload.py \
    scripts/runtime/dev/provider-openai-smoke.sh scripts/runtime/dev/provider-openai-workload.py \
    scripts/runtime/tests/test-provider-openai-smoke.sh scripts/runtime/tests/test-provider-openai-workload.py \
    scripts/runtime/dev/private-checkout-smoke.sh scripts/runtime/tests/test-private-checkout-smoke.sh \
    scripts/runtime/dev/smoke-dev-initial-private-checkout.sh scripts/runtime/tests/test-dev-initial-private-checkout.sh \
    scripts/runtime/dev/hosted-checkout-fixture.py scripts/runtime/dev/hosted-checkout-target.sh \
    scripts/runtime/tests/test-hosted-checkout-fixture.py scripts/runtime/dev/testdata/acceptance-identity.json \
    scripts/runtime/dev/smoke-local-platform-sources.sh scripts/runtime/tests/test-local-platform-sources-smoke.sh \
    scripts/runtime/dev/run-secrets-credentials-acceptance.sh scripts/runtime/tests/test-secrets-credentials-acceptance-runner.sh \
    scripts/runtime/dev/native-mesh-listener.py scripts/runtime/tests/test-native-mesh-listener.py \
    scripts/runtime/tests/fixtures/local-platform/__local-credential-authority; do
  run_paths_case provider_ssh_dev_smoke pull_request refs/pull/5017/head false \
    'policy dev_smoke_script_tests security security_js' "$ssh_input"
done
# Dashboard-owned scripts are outside the JavaScript audit's scanned paths.
for ssh_input in apps/dashboard/scripts/prepare-dev-smoke-browser-auth.ts \
    apps/dashboard/scripts/prepare-dev-smoke-browser-auth.test.ts \
    apps/dashboard/scripts/dev-ux-ownership.ts apps/dashboard/scripts/dev-ux-ownership.test.ts \
    apps/dashboard/scripts/dev-ux-walkthrough.ts; do
  run_paths_case provider_ssh_dev_smoke_dashboard pull_request refs/pull/5017/head false \
    'policy dev_smoke_script_tests' "$ssh_input"
done
run_paths_case application_secret_smoke_fixture pull_request refs/pull/5018/head false \
  'policy dev_smoke_script_tests security security_js' scripts/runtime/tests/test-smoke-dev-application-secrets.sh
run_paths_case curated_derp_member_manifest pull_request refs/pull/502/head false \
  'policy rust_curated_locks transport transport_derp_contract transport_pkg_codewire_derp' \
  crates/codewire-derp/Cargo.toml
run_paths_case curated_derp_lock pull_request refs/pull/504/head false \
  'deploy go_consumer_interop go_support policy release confidential_script_tests rust_curated_locks' \
  deployments/docker/derp.Cargo.lock
run_paths_case curated_lock_guard pull_request refs/pull/505/head false \
  'policy rust_curated_locks security security_js' \
  scripts/ci/verify/check-curated-rust-locks.sh \
  scripts/ci/tests/test-curated-rust-locks.sh \
  scripts/ci/verify/curated_rust_locks.py \
  scripts/dev/sync-curated-rust-locks.sh \
  scripts/ci/verify/compile-all-targets.sh
run_paths_case rust_toolchain_guard pull_request refs/pull/506/head false \
  'policy security security_js' \
  .gitea/workflows/rust-latest-canary.yaml \
  scripts/ci/verify/check-rust-toolchain.sh \
  scripts/ci/tests/test-rust-toolchain.sh
# The one runtime Cargo profile's guard runs in policy core (#2892).
run_paths_case runtime_profile_guard pull_request refs/pull/2892/head false \
  'policy security security_js' \
  scripts/ci/tests/test-runtime-profile.py
run_paths_case local_rust_cache_helper pull_request refs/pull/2753/head false \
  'policy security security_js' \
  scripts/ci/verify/local-rust-cache.sh \
  scripts/ci/tests/test-local-rust-cache.sh
# The side-by-side runner carries policy core and the release family.
run_paths_case side_by_side_runner pull_request refs/pull/2949/head false \
  'go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/verify/side-by-side.sh \
  scripts/ci/tests/test-run-side-by-side.sh
run_paths_case application_migration pull_request refs/pull/6/head false \
  'database policy rust rust_pkg_codewire_server_core service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal' \
  crates/codewire-server-core/migrations/0001_baseline.sql
run_paths_case retired_go_migration_deletion pull_request refs/pull/600/head false \
  'policy' apps/api/db/migrations/0001_baseline.sql
run_paths_case retired_go_harness_deletion pull_request refs/pull/6010/head false \
  'policy' autoagent/agent.py libs/gatewayauth/token.go \
  libs/daemon-proto/gen/daemon/v1/daemon.pb.go
run_paths_case daemon_proto_source pull_request refs/pull/6011/head false \
  'policy rust rust_pkg_codewire_credential_bridge rust_pkg_codewire_credential_broker rust_pkg_codewire_daemon_proto transport transport_pkg_codewire_daemon transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  libs/daemon-proto/proto/daemon/v1/daemon.proto
run_paths_case private_broker_proto_source pull_request refs/pull/6011/head false \
  'policy rust rust_pkg_codewire_credential_bridge rust_pkg_codewire_credential_broker rust_pkg_codewire_daemon_proto transport transport_pkg_codewire_daemon transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  libs/daemon-proto/proto/broker/v1/broker.proto
run_paths_case neutral_credential_bridge_proto_source pull_request refs/pull/6011/head false \
  'contracts contracts_proto go_consumer_interop go_support policy rust rust_pkg_codewire_cli rust_pkg_codewire_credential_bridge rust_pkg_codewire_credential_broker rust_pkg_codewire_credential_service rust_pkg_codewire_daemon rust_pkg_codewire_daemon_proto rust_pkg_codewire_local_credentials rust_pkg_codewire_local_vmm rust_pkg_codewire_proto transport transport_pkg_codewire_daemon transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  proto/codewire/bridge/v1/bridge.proto
run_paths_case private_broker_proto_rust_module pull_request refs/pull/6011/head false \
  'policy rust rust_pkg_codewire_credential_bridge rust_pkg_codewire_credential_broker rust_pkg_codewire_daemon_proto rust_pkg_codewire_server_core transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  crates/codewire-daemon-proto/src/lib.rs
run_paths_case broker_daemon_transport_consumer pull_request refs/pull/6011/head false \
  'policy rust rust_pkg_codewire_credential_broker transport transport_pkg_codewire_daemon transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  crates/codewire-daemon/src/client.rs
run_paths_case material_free_credential_bridge pull_request refs/pull/6011/head false \
  'policy rust rust_pkg_codewire_credential_bridge rust_pkg_codewire_credential_broker transport transport_pkg_codewire_daemon transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  crates/codewire-credential-bridge/src/lib.rs
run_paths_case concrete_platform_credential_service pull_request refs/pull/6011/head false \
  'database policy rust rust_pkg_codewire_credential_service' \
  crates/codewire-credential-service/src/authority.rs
run_paths_case credential_service_kind_entrypoint_without_opt_in pull_request refs/pull/6011/head false \
  'database policy rust rust_pkg_codewire_credential_service' \
  crates/codewire-credential-service/src/runtime/kind.rs
run_paths_case credential_service_kind_entrypoint_with_opt_in pull_request refs/pull/6011/head true \
  'database edge_kind kind policy rust rust_pkg_codewire_credential_service' \
  crates/codewire-credential-service/src/runtime/kind.rs
run_paths_case credential_service_kind_runtime_without_opt_in pull_request refs/pull/6011/head false \
  'database policy rust rust_pkg_codewire_credential_service' \
  crates/codewire-credential-service/src/runtime/kind/provider.rs
run_paths_case credential_service_kind_runtime_with_opt_in pull_request refs/pull/6011/head true \
  'database edge_kind kind policy rust rust_pkg_codewire_credential_service' \
  crates/codewire-credential-service/src/runtime/kind/provider.rs
run_paths_case shared_credential_tls_source pull_request refs/pull/6011/head false \
  'database policy rust rust_pkg_codewire_credential_service rust_pkg_codewire_tls transport' \
  crates/codewire-tls/src/files.rs
run_paths_case shared_credential_tls_manifest pull_request refs/pull/6011/head false \
  'database policy rust rust_curated_locks rust_pkg_codewire_credential_service rust_pkg_codewire_tls transport' \
  crates/codewire-tls/Cargo.toml
run_paths_case self_contained_go_workspace pull_request refs/pull/6012/head false \
  'go_consumer_interop go_support go_tailnet policy sdk_go security security_go' \
  go.work
run_paths_case retired_go_application_deletion pull_request refs/pull/604/head false \
  'policy' apps/api/internal/db/pool.go
run_paths_case billing_seed_fixture pull_request refs/pull/601/head false \
  'policy service_billing service_integration' tests/fixtures/billing/seed.sql
run_paths_case coordinator_seed_fixture pull_request refs/pull/602/head false \
  'policy service_coordinator service_integration' tests/fixtures/coordinator/seed.sql
run_paths_case orchestration_seed_fixture pull_request refs/pull/603/head false \
  'policy service_integration service_orchestration' tests/fixtures/orchestration/seed.sql
run_paths_case application_schema_fingerprint pull_request refs/pull/60/head false \
  'database policy rust rust_pkg_codewire_server_core service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal' \
  crates/codewire-server-core/tests/data/application_schema_fingerprint.sql
run_paths_case server_core_lifecycle_test pull_request refs/pull/6010/head false \
  'database policy rust rust_pkg_codewire_server_core' \
  crates/codewire-server-core/tests/org_deletion_lifecycle.rs
run_paths_case server_core_migration_database_test pull_request refs/pull/6010/head false \
  'database policy rust rust_pkg_codewire_server_core' \
  crates/codewire-server-core/src/migrate/tests/session_mutation.rs
for oauth_input in tests/oauth_bearer_auth.rs tests/oauth_bearer_auth/authority.rs; do
  run_paths_case server_core_oauth_publication_test pull_request refs/pull/6010/head false \
    'database policy rust rust_pkg_codewire_server_core' \
    "crates/codewire-server-core/$oauth_input"
done
for oauth_input in src/auth.rs src/auth/oauth_authority.rs src/connect.rs; do
  run_paths_case server_core_oauth_publication_source pull_request refs/pull/6010/head false \
    'database policy rust rust_pkg_codewire_server_core service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal' \
    "crates/codewire-server-core/$oauth_input"
done
run_paths_case server_core_runtime_source pull_request refs/pull/6011/head false \
  'policy rust rust_pkg_codewire_server_core service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal' \
  crates/codewire-server-core/src/lib.rs
run_paths_case rust_migration_database pull_request refs/pull/61/head false \
  'database policy rust rust_pkg_codewire_billing service_billing service_integration' \
  crates/codewire-billing/src/subscription_migration.rs
run_paths_case orchestration_service pull_request refs/pull/7/head false \
  'policy rust rust_pkg_codewire_orchestration service_integration service_orchestration' \
  crates/codewire-orchestration/src/api/environments.rs
for profile_input in src/access_profiles.rs src/connect/access_profiles.rs tests/access_profiles.rs tests/access_profiles_support/mod.rs tests/access_profiles_timeout/mod.rs tests/access_profiles_destroy/mod.rs src/lifecycle/mod.rs src/credentials.rs src/connect/credentials.rs tests/credentials.rs tests/credentials_support/mod.rs; do
  run_paths_case public_platform_access_profiles pull_request refs/pull/72/head false \
    'database policy rust rust_pkg_codewire_orchestration service_integration service_orchestration' \
    "crates/codewire-orchestration/$profile_input"
done
run_paths_case credential_kind_fixtures pull_request refs/pull/721/head false \
  'policy security security_js' scripts/ci/tests/test-kind-codex-session.py scripts/ci/tests/test-kind-codex-login.py \
  scripts/ci/tests/test-kind-claude-login.py scripts/ci/tests/test-kind-credentials.py
run_paths_case orchestration_wire_contract pull_request refs/pull/71/head false \
  'policy rust rust_pkg_codewire_orchestration service_integration service_orchestration' \
  crates/codewire-orchestration/tests/wire_contract.rs \
  crates/codewire-orchestration/tests/wire_contract/environment.rs
run_paths_case shared_platform_identity pull_request refs/pull/711/head false \
  'database policy rust rust_pkg_codewire_credential_broker rust_pkg_codewire_orchestration rust_pkg_codewire_platform_credentials rust_pkg_codewire_protected_store service_integration service_orchestration' \
  crates/codewire-protected-store/src/openbao_workload_identity.rs
for primitive_input in src/secret_envelope.rs src/lib.rs Cargo.toml; do
  run_paths_case shared_platform_envelope pull_request refs/pull/712/head false \
    'database policy rust rust_pkg_codewire_credential_broker rust_pkg_codewire_orchestration rust_pkg_codewire_platform_credentials rust_pkg_codewire_protected_store service_integration service_orchestration service_temporal' \
    "crates/codewire-protected-store/$primitive_input"
done
for store_consumer in postgres_secrets.rs tenant_secret_teardown.rs; do
  run_paths_case platform_store_consumer pull_request refs/pull/713/head false \
    'database policy rust rust_pkg_codewire_orchestration service_integration service_orchestration service_temporal' \
    "crates/codewire-orchestration/src/worker/$store_consumer"
done
run_paths_case billing_contract pull_request refs/pull/8/head false \
  'policy rust rust_pkg_codewire_billing service_billing service_integration' \
  crates/codewire-billing/src/connect/billing.rs
run_paths_case retired_billing_driver_deletion pull_request refs/pull/800/head false \
  'policy service_billing service_integration' \
  tests/contract/billing/billing_test.go
run_paths_case retired_file_contract_deletion pull_request refs/pull/80/head false \
  'policy' \
  tests/contract/file/file_connect_test.go
run_paths_case idp_service pull_request refs/pull/81/head false \
  'policy rust rust_pkg_codewire_idp service_idp service_integration' \
  crates/codewire-idp/src/routes.rs
run_paths_case coordinator_service pull_request refs/pull/82/head false \
  'policy service_coordinator service_integration transport transport_pkg_codewire_coordinator' \
  crates/codewire-coordinator/src/connect.rs
run_paths_case dormant_coordinator_driver pull_request refs/pull/821/head false \
  'policy' tests/contract/coordinator/connect_test.go
run_paths_case retired_connectcore_deletion pull_request refs/pull/83/head false \
  'policy service_billing service_connectcore service_integration service_orchestration' \
  tests/contract/connectcore/connectcore_test.go
run_paths_case integration_service_harness pull_request refs/pull/831/head false \
  'database policy security security_js service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal' \
  scripts/ci/verify/run-integration-verification.sh
# The integration lane lock and service-ownership helper (#2755) is part of
# the same harness.
run_present_paths_case integration_lane_lock pull_request refs/pull/2755/head false \
  'database policy security security_js service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal' \
  scripts/ci/verify/integration-lane.py
run_paths_case temporal_service pull_request refs/pull/84/head false \
  'policy rust rust_pkg_codewire_orchestration service_integration service_orchestration service_temporal' \
  crates/codewire-orchestration/src/worker/create.rs
run_paths_case temporal_fencing_kind_driver pull_request refs/pull/842/head false \
  'policy rust rust_pkg_codewire_orchestration service_integration service_orchestration' \
  crates/codewire-orchestration/src/bin/temporal-fencing-smoke.rs
run_paths_case file_service_kind_driver pull_request refs/pull/843/head false \
  'policy rust rust_pkg_codewire_orchestration service_integration service_orchestration' \
  crates/codewire-orchestration/src/bin/file-service-smoke.rs
run_paths_case reconciler_ttl_kind_driver pull_request refs/pull/844/head false \
  'policy rust rust_pkg_codewire_orchestration service_integration service_orchestration' \
  crates/codewire-orchestration/src/bin/reconciler-ttl-smoke.rs
run_paths_case kind_harness pull_request refs/pull/845/head false \
  'policy security security_js' \
  scripts/ci/verify/kind-e2e.sh \
  scripts/ci/verify/kind/common.sh \
  scripts/ci/verify/kind/suites/integrated.sh \
  scripts/ci/verify/kind/suites/final-fencing.sh \
  scripts/ci/verify/kind/suites/environment-session.sh \
  scripts/ci/tests/test-kind-e2e-cleanup.sh \
  scripts/ci/tests/test-kind-e2e-suites.sh \
  scripts/ci/tests/test-kind-forwards.sh
run_paths_case kind_harness_opt_in pull_request refs/pull/846/head true \
  'edge_kind kind policy security security_js' \
  scripts/ci/verify/kind/suites/final-fencing.sh \
  scripts/ci/verify/kind/suites/environment-session.sh
run_paths_case kind_fixture_only pull_request refs/pull/847/head false \
  'policy security security_js' \
  scripts/ci/tests/test-kind-e2e-suites.sh \
  scripts/ci/tests/test-kind-forwards.sh \
  scripts/ci/tests/test-kind-trust-roots.sh
for kind_runtime_fixture in test-kind-cw-runtime.py test-kind-cw-runtime-probe.py; do
  run_paths_case "${kind_runtime_fixture%.py}_pr" pull_request refs/pull/8471/head false \
    'policy security security_js' "scripts/ci/tests/$kind_runtime_fixture"
  run_paths_case "${kind_runtime_fixture%.py}_opt_in" pull_request refs/pull/8472/head true \
    'edge_kind policy security security_js' "scripts/ci/tests/$kind_runtime_fixture"
  run_paths_case "${kind_runtime_fixture%.py}_main" push refs/heads/main false \
    'edge_kind policy security security_js' "scripts/ci/tests/$kind_runtime_fixture"
done
run_paths_case kind_runtime_fixture_mixed_opt_in pull_request refs/pull/8473/head true \
  'edge_kind kind policy security security_js' \
  scripts/ci/tests/test-kind-cw-runtime.py \
  scripts/ci/tests/test-kind-cw-runtime-probe.py \
  scripts/ci/verify/kind/suites/integrated.sh
run_paths_case temporal_shared_fixture pull_request refs/pull/841/head false \
  'policy service_billing service_integration service_orchestration service_temporal' \
  tests/e2e/flip-state.env
run_paths_case nats_service pull_request refs/pull/85/head false \
  'policy service_coordinator service_integration service_nats transport transport_pkg_codewire_coordinator' \
  crates/codewire-coordinator/src/nats.rs
run_paths_case retired_apikey_smoke pull_request refs/pull/86/head false \
  'policy security security_js' \
  scripts/runtime/tests/test-apikey-smoke.sh
run_paths_case retired_go_e2e_source pull_request refs/pull/87/head false \
  'policy' \
  apps/api/internal/e2e/env_api_rust_test.go
run_paths_case rust_tailnet pull_request refs/pull/9/head false \
  'policy transport transport_pkg_codewire_tailnet' \
  crates/codewire-tailnet/src/lib.rs
run_paths_case rust_netstack pull_request refs/pull/90/head false \
  'policy transport transport_pkg_codewire_netstack transport_pkg_codewire_tailnet' \
  crates/codewire-netstack/src/lib.rs
run_paths_case rust_derp pull_request refs/pull/91/head false \
  'policy transport transport_derp_contract transport_pkg_codewire_derp' \
  crates/codewire-derp/src/lib.rs
run_paths_case go_tailnet pull_request refs/pull/10/head false \
  'go_support go_tailnet policy' \
  libs/tailnet/peer.go
run_paths_case tailscale_golden pull_request refs/pull/10/head false \
  'go_support go_tailnet policy' \
  tests/contract/tailscalegolden/golden_test.go tests/fixtures/tailnet/tailscale_golden.json
run_paths_case derp_contract pull_request refs/pull/101/head false \
  'policy transport transport_derp_contract transport_pkg_codewire_derp' \
  tests/contract/derp/derp_test.go
run_paths_case proto pull_request refs/pull/11/head false \
  'contracts contracts_proto go_consumer_interop go_support policy' \
  proto/codewire/v1/api_key.proto
run_paths_case common_proto pull_request refs/pull/109/head false \
  'contracts contracts_proto go_consumer_interop go_support policy rust rust_pkg_codewire_cli rust_pkg_codewire_client rust_pkg_codewire_dashboard_web rust_pkg_codewire_orchestration rust_pkg_codewire_project_proto rust_pkg_codewire_proto sdk_go sdk_python sdk_ts transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe web' \
  proto/codewire/v1/common.proto
run_paths_case environment_proto pull_request refs/pull/110/head false \
  'contracts contracts_proto go_consumer_interop go_support policy rust rust_pkg_codewire_cli rust_pkg_codewire_client rust_pkg_codewire_dashboard_web rust_pkg_codewire_orchestration rust_pkg_codewire_proto sdk_go sdk_python sdk_ts transport transport_pkg_codewire_local_vmm web' \
  proto/codewire/v1/environment.proto
run_paths_case preset_proto pull_request refs/pull/1101/head false \
  'contracts contracts_proto go_consumer_interop go_support policy rust rust_pkg_codewire_cli rust_pkg_codewire_client rust_pkg_codewire_dashboard_web rust_pkg_codewire_orchestration rust_pkg_codewire_proto sdk_go sdk_python sdk_ts web' \
  proto/codewire/v1/preset.proto
run_paths_case admin_rust_proto_boundary pull_request refs/pull/1111/head false \
  'contracts contracts_proto policy rust rust_pkg_codewire_admin_proto rust_pkg_codewire_cli_bin security security_js' \
  crates/codewire-admin-proto/Cargo.toml \
  scripts/ci/proto/build-rust-descriptors.sh \
  scripts/ci/tests/test-admin-proto-boundary.sh
run_paths_case admin_boundary_guard pull_request refs/pull/11110/head false \
  'policy rust rust_pkg_codewire_cli_bin security security_js' \
  scripts/ci/tests/test-admin-proto-boundary.sh
run_paths_case rust_descriptor_generator pull_request refs/pull/11113/head false \
  'contracts contracts_proto policy security security_js' \
  scripts/ci/proto/build-rust-descriptors.sh
run_paths_case admin_proto_crate pull_request refs/pull/11111/head false \
  'contracts contracts_proto policy rust rust_pkg_codewire_admin_proto' \
  crates/codewire-admin-proto/build.rs
run_paths_case customer_proto_crate pull_request refs/pull/11112/head false \
  'contracts contracts_proto policy rust rust_pkg_codewire_proto' \
  crates/codewire-proto/build.rs
run_paths_case google_rpc_ts_template pull_request refs/pull/1114/head false \
  'contracts contracts_proto go_consumer_interop go_support policy' \
  proto/buf.gen.google-rpc-ts.yaml
run_paths_case google_rpc_python_template pull_request refs/pull/1115/head false \
  'contracts contracts_proto go_consumer_interop go_support policy' \
  proto/buf.gen.google-rpc-python.yaml
run_paths_case edge_ownership pull_request refs/pull/114/head false \
  'contracts contracts_proto policy security security_js' scripts/checks/contracts/connect-edge-ownership.json
run_paths_case proto_breaking_policy pull_request refs/pull/1141/head false \
  'contracts contracts_proto policy security security_js' \
  scripts/checks/proto_breaking.py \
  scripts/checks/contracts/proto-breaking-preimages.sha256
run_paths_case local_runtime_contract pull_request refs/pull/1143/head false \
  'contracts contracts_proto policy transport transport_pkg_codewire_local_vmm' \
  crates/codewire-local-vmm/proto/buf.yaml \
  crates/codewire-local-vmm/proto/codewire/local/v1/control.proto
run_paths_case local_runtime_oldest_contract pull_request refs/pull/1144/head false \
  'contracts contracts_proto policy security security_js' \
  scripts/checks/contracts/local-runtime-oldest/codewire/local/v1/control.proto
run_paths_case proto_retirement_ledger_transition pull_request refs/pull/1142/head false \
  'contracts contracts_proto policy security security_js' \
  scripts/checks/contracts/proto-retirements.sha256
run_paths_case generated_connect_go pull_request refs/pull/111/head false \
  'contracts contracts_proto go_consumer_interop go_support policy' libs/gen-go/codewire/v1/api_key.pb.go
run_paths_case retired_generated_connect_oracle_go pull_request refs/pull/1110/head false \
  'policy' \
  apps/api/gen/coordinator/v1/coordinator.pb.go
run_paths_case generated_connect_ts pull_request refs/pull/112/head false \
  'contracts contracts_proto policy' \
  packages/codewire-proto-ts/src/gen/codewire/v1/api_key_pb.ts
run_paths_case generated_google_rpc_ts pull_request refs/pull/1124/head false \
  'contracts contracts_proto policy' \
  packages/codewire-proto-ts/src/gen/google/rpc/error_details_pb.ts
run_paths_case generated_connect_python pull_request refs/pull/113/head false \
  'contracts contracts_proto policy' libs/gen-python/codewire/v1/api_key_pb2.py
run_paths_case permanent_raw_policy_guard pull_request refs/pull/117/head false \
  'policy security security_js' scripts/checks/contracts/permanent-raw-surface-policy.json
run_present_paths_case design_token_policy pull_request refs/pull/2203/head false \
  'policy security security_js' scripts/checks/contracts/design-token-policy.json
run_present_paths_case design_token_guard_module pull_request refs/pull/22032/head false \
  'contracts contracts_proto deploy go_consumer_interop go_support policy release confidential_script_tests security security_idp_kek security_js' \
  scripts/checks/repo_policy/design_tokens.py
run_present_paths_case design_system_stylesheets pull_request refs/pull/22034/head false \
  'policy security security_js web' packages/codewire-design/styles.css packages/codewire-design/routes/settings.css
run_paths_case retired_openapi_deletions pull_request refs/pull/1175/head false \
  'policy security security_js' openapi.json crates/codewire-api-contract/src/lib.rs \
  crates/codewire-api-types/src/lib.rs crates/codewire-core/src/lib.rs \
  libs/api-client-go/client_gen.go libs/api-client-python/pyproject.toml \
  libs/api-client-ts/package.json packages/codewire-types/package.json
run_paths_case mesh_policy_guard pull_request refs/pull/1171/head false \
  'policy security security_js' scripts/checks/contracts/mesh-final-surface-policy.json
run_paths_case mesh_policy_go_sdk pull_request refs/pull/1172/head false \
  'go_consumer_interop go_support policy sdk_go security security_js' \
  scripts/checks/contracts/mesh-final-surface-policy.json \
  libs/sdk-go/mesh_networks.go
run_paths_case mesh_policy_rust_client pull_request refs/pull/1173/head false \
  'policy rust rust_pkg_codewire_client security security_js' \
  scripts/checks/contracts/mesh-final-surface-policy.json \
  crates/codewire-client/src/mesh.rs
run_paths_case mesh_policy_runtime pull_request refs/pull/1174/head false \
  'policy security security_js transport transport_pkg_codewire_mesh' \
  scripts/checks/contracts/mesh-final-surface-policy.json \
  crates/codewire-mesh/src/server.rs
run_paths_case mesh_store_database pull_request refs/pull/1175/head false \
  'database policy transport transport_pkg_codewire_mesh' \
  crates/codewire-mesh/src/store.rs
run_paths_case package_contract_tooling pull_request refs/pull/118/head false \
  'contracts contracts_proto policy security security_js web' \
  package.json
run_paths_case generic_package pull_request refs/pull/119/head false \
  'policy web' packages/shared/src/index.ts
run_paths_case dashboard pull_request refs/pull/12/head false \
  'policy security security_js web' apps/dashboard/playwright.config.ts
# Browser specs run only under Edge/Kind: a push to main runs Kind for them,
# and a pull request runs Kind only when opted in.
run_paths_case dashboard_e2e_pull_request pull_request refs/pull/12/head false \
  'policy web' apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts
run_paths_case dashboard_e2e_pull_request_opt_in pull_request refs/pull/12/head true \
  'edge_kind kind policy web' apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts
run_paths_case dashboard_e2e_push push refs/heads/main false \
  "edge_kind ${MAIN_PUSH_KIND} policy web" apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts
run_paths_case dashboard_browser_gate pull_request refs/pull/1202/head false \
  'policy security security_js web' scripts/ci/tests/test-dashboard-browser-gate.sh
run_paths_case dashboard_design_preview pull_request refs/pull/120/head false \
  'policy security security_js web' scripts/dev/design-system-server.py
run_paths_case design_fixture_spec_push push refs/heads/main false \
  'policy web' apps/dashboard/e2e/ssr-dashboard.design-system.ssr.ts
run_paths_case design_fixture_spec_kind_opt_in pull_request refs/pull/2206/head true \
  'policy web' apps/dashboard/e2e/ssr-dashboard.date-picker.ssr.ts
run_paths_case design_fixture_list_push push refs/heads/main false \
  "edge_kind ${MAIN_PUSH_KIND} policy web" apps/dashboard/e2e/helpers/design-fixtures.ts
run_paths_case design_fixture_runner pull_request refs/pull/2203/head false \
  'policy security security_js web' scripts/ci/verify/run-design-fixtures.sh
run_paths_case design_fixture_runner_test pull_request refs/pull/2204/head false \
  'policy security security_js web' scripts/ci/tests/test-run-design-fixtures.sh
run_paths_case design_fixture_browser_runtime pull_request refs/pull/2205/head false \
  'policy security security_js web' scripts/ci/verify/playwright-browser-runtime.sh
run_paths_case marketing_brand_assets pull_request refs/pull/1201/head false \
  'policy web' favicon.svg logo/wordmark.svg
# The Zola docs site selects the docs family (a Zola build and its link
# check), never the dashboard browser gate in web (#3021). The JavaScript
# audit still scans its templates and static script.
run_paths_case docs_site_page pull_request refs/pull/3021/head false \
  'docs policy security security_js' apps/docs/zola/content/cli/overview.md
run_paths_case docs_site_sources push refs/heads/main false \
  'docs policy security security_js' \
  apps/docs/zola/templates/base.html apps/docs/zola/static/search.js \
  apps/docs/zola/routes.toml apps/docs/zola/config.toml
run_paths_case docs_site_outside_zola pull_request refs/pull/3021/head false \
  'docs policy' apps/docs/astro.config.mjs
run_paths_case docs_and_dashboard pull_request refs/pull/3021/head false \
  'docs policy security security_js web' \
  apps/docs/zola/content/_index.md apps/dashboard/playwright.config.ts
run_paths_case dashboard_runtime_inventory pull_request refs/pull/121/head false \
  'deploy go_consumer_interop go_support policy release confidential_script_tests security web' \
  apps/dashboard/runtime-inventory.json
run_paths_case dashboard_rust_route pull_request refs/pull/122/head false \
  'deploy policy rust rust_pkg_codewire_dashboard_web security security_js web' \
  crates/codewire-dashboard-web/src/docs.rs
run_paths_case dashboard_rust_surface pull_request refs/pull/1221/head false \
  'deploy policy rust rust_pkg_codewire_dashboard_web security security_js web' \
  crates/codewire-dashboard-web/src/routes/environments.rs \
  crates/codewire-dashboard-web/templates/dashboard.html \
  crates/codewire-dashboard-web/assets/htmx-2.0.10.min.js
run_paths_case dashboard_image_verifier pull_request refs/pull/123/head false \
  'deploy go_consumer_interop go_support policy release confidential_script_tests security security_js web' \
  scripts/ci/verify/dashboard-image.sh
run_paths_case dashboard_sandbox_image_inputs pull_request refs/pull/1231/head false \
  'policy rust rust_pkg_codewire_orchestration service_integration service_orchestration' \
  crates/codewire-orchestration/src/sandbox/mod.rs \
  crates/codewire-orchestration/src/sandbox/template.rs \
  crates/codewire-orchestration/src/sandbox/template/network.rs
run_paths_case local_image_verifiers pull_request refs/pull/1231/head false \
  'policy security security_js' \
  scripts/ci/images/build-local-image.sh \
  scripts/ci/tests/test-build-local-image.sh \
  scripts/ci/tests/test-workspace-agent-contract.sh \
  scripts/ci/tests/test-workspace-image-artifact.py \
  scripts/ci/verify/workspace-image-artifact.py \
  scripts/ci/verify/rehearse-build-local-image.sh \
  scripts/ci/verify/verify-workspace-image.sh \
  scripts/ci/verify/workspace-agent-contract.sh
run_paths_case javascript_dependency_inputs pull_request refs/pull/120/head false \
  'contracts contracts_proto policy sdk_ts security security_js web' \
  apps/dashboard/package.json \
  packages/codewire-proto-ts/package.json \
  libs/sdk-ts/package-lock.json
run_paths_case vendored_browser_manifest pull_request refs/pull/1201/head false \
  'policy security security_js' .supplychain/vendor-artifacts.json
run_paths_case sdk_go pull_request refs/pull/13/head false \
  'go_consumer_interop go_support policy sdk_go' libs/sdk-go/client.go
run_paths_case go_consumer_interop_harness pull_request refs/pull/131/head false \
  'go_consumer_interop go_support policy rust rust_pkg_codewire_server_core' \
  crates/codewire-server-core/tests/go_consumer_interop.rs
run_paths_case contract_go_module pull_request refs/pull/132/head false \
  'go_support go_tailnet policy security security_go transport transport_derp_contract transport_pkg_codewire_derp' \
  tests/contract/go.mod tests/contract/go.sum
run_paths_case sdk_ts pull_request refs/pull/14/head false \
  'policy sdk_ts' libs/sdk-ts/src/index.ts
run_paths_case sdk_python pull_request refs/pull/15/head false \
  'policy sdk_python' libs/sdk-python/codewire/client.py
run_paths_case sdk_python_runner pull_request refs/pull/151/head false \
  'policy sdk_python security security_js' \
  scripts/runtime/dev/run-sdk-python-e2e.sh \
  scripts/runtime/tests/test-run-sdk-python-e2e.sh
run_paths_case sdk_ts_runner pull_request refs/pull/1511/head false \
  'policy sdk_ts security security_js' \
  scripts/runtime/dev/run-sdk-ts-e2e.sh \
  scripts/runtime/tests/test-run-sdk-ts-e2e.sh
run_paths_case retired_sdk_examples pull_request refs/pull/1512/head false \
  'policy' \
  libs/sdk-examples/run-claude/README.md \
  libs/sdk-examples/run-claude/go/main.go \
  libs/sdk-examples/run-claude/python/run_claude.py \
  libs/sdk-examples/run-claude/typescript/run_claude.ts
run_paths_case retired_cli_assets pull_request refs/pull/1513/head false \
  'policy security security_js' \
  apps/cli/.env.example \
  apps/cli/Caddyfile \
  apps/cli/Dockerfile \
  apps/cli/charts/codewire-mesh/templates/NOTES.txt \
  apps/cli/contrib/codex-turn-watch.sh \
  apps/cli/demo/Dockerfile \
  apps/cli/docker-compose.yml \
  apps/cli/docs/quickstart.md
run_paths_case cli_packaging pull_request refs/pull/1514/head false \
  'go_consumer_interop go_support policy release confidential_script_tests' \
  apps/cli/nfpm.yaml
# Removing the retired manual AUR/Homebrew packaging and the stray root file
# needs only Policy; the same paths reappearing are unclassified again.
run_paths_case retired_packaging_removal pull_request refs/pull/1514/head false \
  'policy' \
  aur/PKGBUILD \
  aur/TODO.md \
  apps/cli/aur/PKGBUILD \
  apps/cli/scripts/update-homebrew-formula.sh \
  .schema-reset-write-test \
  deploy/cwpreview-ingress.yaml
retired_root="$TMP/retired-packaging.repo"
for retired in aur/PKGBUILD apps/cli/aur/PKGBUILD .schema-reset-write-test; do
  [ ! -e "$ROOT/$retired" ] || {
    echo "retired path exists in the checkout: $retired" >&2; exit 1
  }
  mkdir -p "$retired_root/$(dirname "$retired")"
  : > "$retired_root/$retired"
  printf '%s\n' "$retired" > "$TMP/retired-packaging.paths"
  retired_output="$(cd "$retired_root" && env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
    GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/1514/head \
    KIND_E2E_OPT_IN=false "$SELECTOR" "$TMP/retired-packaging.paths" 2>/dev/null)"
  [[ "$retired_output" == *'classification=unclassified'* \
      && "$retired_output" == *'required_local_mode=full'* ]] || {
    echo "a reappearing retired path was classified: $retired" >&2; exit 1
  }
done
run_paths_case cli_deploy_assets pull_request refs/pull/1515/head false \
  'deploy policy' \
  apps/cli/charts/codewire-mesh/values.yaml \
  apps/cli/k8s/demo-site/deployment.yaml
run_paths_case runtime_dev_tooling pull_request refs/pull/1516/head false \
  'policy dev_smoke_script_tests security security_js' \
  scripts/runtime/dev/measure-dev-commodity-overhead.sh \
  scripts/runtime/dev/smoke-dev-commodity.sh \
  scripts/runtime/kata/kata-genpolicy.sh
run_paths_case runtime_dev_proofs pull_request refs/pull/2411/head false \
  'policy dev_smoke_script_tests security security_js' \
  scripts/runtime/dev/prove-dev-workspace-binding.sh \
  scripts/runtime/dev/prove-dev-warm-pools.sh \
  scripts/runtime/tests/test-workspace-binding-proof.sh \
  scripts/runtime/tests/test-warm-pool-proof.sh \
  scripts/runtime/agent-sandbox/drop-crd-conversion.sh \
  scripts/runtime/tests/test-drop-crd-conversion.sh
run_paths_case runtime_dev_auth pull_request refs/pull/1517/head false \
  'policy dev_smoke_script_tests security security_dev_smoke_auth security_js' \
  scripts/runtime/dev/provision-dev-smoke-user.sh \
  scripts/runtime/dev/with-dev-smoke-auth.sh \
  scripts/runtime/tests/test-with-dev-smoke-auth.sh
run_paths_case runtime_prod_auth pull_request refs/pull/1519/head false \
  'policy dev_smoke_script_tests security security_dev_smoke_auth security_js' \
  scripts/runtime/prod/provision-prod-smoke-user.sh \
  scripts/runtime/prod/with-prod-smoke-auth.sh \
  scripts/runtime/tests/test-provision-prod-smoke-user.sh \
  scripts/runtime/tests/test-with-prod-smoke-auth.sh
run_paths_case confidential_script_tests pull_request refs/pull/1518/head false \
  'policy confidential_script_tests security security_js' \
  scripts/runtime/confidential/resolve-coco-support-lock.sh \
  scripts/runtime/tests/test-resolve-coco-support-lock.sh
run_paths_case makefile_only pull_request refs/pull/152/head false \
  'policy security security_js' Makefile
run_paths_case buildx_two_file_replay pull_request refs/pull/1520/head false \
  'deploy go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  Makefile scripts/checks/security/audit-runtime-images.sh
[ ! -e "$ROOT/.gitea/workflows/desktop-package.yaml" ] || {
  echo 'standalone desktop package workflow still exists' >&2
  exit 1
}
if grep -qF '  pull_request:' "$CLI_RELEASE_WORKFLOW" \
    || grep -qF '  package-dry-run:' "$CLI_RELEASE_WORKFLOW" \
    || grep -qF "    tags: ['v*']" "$CLI_RELEASE_WORKFLOW"; then
  echo 'CLI release workflow still exposes candidate- or tag-owned execution' >&2
  exit 1
fi
grep -qF '  workflow_dispatch:' "$CLI_RELEASE_WORKFLOW"
grep -qF '      release_tag:' "$CLI_RELEASE_WORKFLOW"
grep -qF "[ \"\$GITHUB_REF\" = 'refs/heads/main' ]" "$CLI_RELEASE_WORKFLOW"
[ ! -e "$ROOT/.gitea/workflows/workspace-image-verify.yaml" ] || {
  echo 'standalone workspace image workflow still exists' >&2
  exit 1
}
run_paths_case cli_makefile pull_request refs/pull/1521/head false \
  'policy rust rust_pkg_codewire_cli rust_pkg_codewire_cli_bin' \
  apps/cli/Makefile
run_paths_case cli_host_journey pull_request refs/pull/2255/head false \
  'policy rust rust_pkg_codewire_cli rust_pkg_codewire_cli_bin security security_js' \
  scripts/dev/test-cli-host.py
run_paths_case source_approval_policy pull_request refs/pull/2255/head false \
  'policy' .supplychain/source-policy.json
for host_input in scripts/dev/test-cli-host-managed.py scripts/ci/tests/test-cli-host-managed.py scripts/dev/fixtures/host-member-managed-assets.py; do
  run_paths_case "host_managed_${host_input//\//_}" pull_request refs/pull/2255/head false \
    'policy rust rust_pkg_codewire_cli rust_pkg_codewire_cli_bin security security_js' "$host_input"
done
run_paths_case host_managed_and_source_policy pull_request refs/pull/2255/head false \
  'policy rust rust_pkg_codewire_cli rust_pkg_codewire_cli_bin security security_js' \
  .supplychain/source-policy.json scripts/dev/test-cli-host-managed.py \
  scripts/ci/tests/test-cli-host-managed.py
# Nearby unrecognized files retain conservative fallback; do not broaden
# either the protected source-policy name or the exact harness path cases.
neighbor_root="$TMP/host-neighbors.repo"
for neighbor in .supplychain/source-policy-unlisted.json \
    scripts/dev/test-cli-host-managed-unlisted.py scripts/ci/tests/test-cli-host-managed-unlisted.py \
    scripts/dev/fixtures/host-member-managed-assets-unlisted.py; do
  [ ! -e "$ROOT/$neighbor" ] || {
    echo "classification neighbor exists in the checkout: $neighbor" >&2; exit 1
  }
  mkdir -p "$neighbor_root/$(dirname "$neighbor")"
  printf '%s\n' '# classifier fixture, never executed' > "$neighbor_root/$neighbor"
  printf '%s\n' "$neighbor" > "$TMP/host-neighbor.paths"
  neighbor_output="$(cd "$neighbor_root" && env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
    GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/2255/head \
    KIND_E2E_OPT_IN=false "$SELECTOR" "$TMP/host-neighbor.paths" 2>/dev/null)"
  [[ "$neighbor_output" == *'classification=unclassified'* \
      && "$neighbor_output" == *'required_local_mode=full'* ]] || {
    echo "classification neighbor lost conservative fallback: $neighbor" >&2; exit 1
  }
done
run_paths_case cli_host_update_journey pull_request refs/pull/2255/head false \
  'policy rust rust_pkg_codewire_cli rust_pkg_codewire_cli_bin security security_js' \
  scripts/dev/test-cli-update.py
run_paths_case cli_host_update_port_regression pull_request refs/pull/2255/head false \
  'policy rust rust_pkg_codewire_cli rust_pkg_codewire_cli_bin security security_js' \
  scripts/ci/tests/test-cli-update-mesh-endpoints.py
run_paths_case cli_release_dir_producer_fixture pull_request refs/pull/2255/head false \
  'policy rust rust_pkg_codewire_cli rust_pkg_codewire_cli_bin security security_js' \
  scripts/ci/tests/test-build-cw-release-dir.py
run_paths_case cli_agent_peer_fixture pull_request refs/pull/2255/head false \
  'policy rust rust_pkg_codewire_cli rust_pkg_codewire_cli_bin security security_js' \
  scripts/dev/fixtures/agent-peer.py
run_paths_case cli_native_managed_startup pull_request refs/pull/2255/head false \
  'policy rust rust_pkg_codewire_cli rust_pkg_codewire_cli_bin security security_js' \
  scripts/dev/test-native-managed-startup.py
run_paths_case cli_native_managed_journey pull_request refs/pull/2255/head false \
  'policy rust rust_pkg_codewire_cli rust_pkg_codewire_cli_bin security security_js transport transport_pkg_codewire_local_vmm' \
  scripts/dev/test-cli-native-managed.py
run_paths_case cli_native_update_journey pull_request refs/pull/2255/head false \
  'policy rust rust_pkg_codewire_cli rust_pkg_codewire_cli_bin security security_js transport transport_pkg_codewire_local_vmm' \
  scripts/dev/test-cli-native-update.py
run_paths_case cli_native_socket_dir_helper pull_request refs/pull/2255/head false \
  'policy rust rust_pkg_codewire_cli rust_pkg_codewire_cli_bin security security_js transport transport_pkg_codewire_local_vmm' \
  scripts/dev/native_socket_dir.py
run_paths_case cli_native_update_entrypoint_regression pull_request refs/pull/2255/head false \
  'policy rust rust_pkg_codewire_cli rust_pkg_codewire_cli_bin security security_js transport transport_pkg_codewire_local_vmm' \
  scripts/ci/tests/test-native-managed-update-entrypoint.py
run_paths_case cli_native_managed_artifact pull_request refs/pull/2255/head false \
  'go_consumer_interop go_support policy release confidential_script_tests rust rust_pkg_codewire_cli rust_pkg_codewire_cli_bin security security_js transport transport_pkg_codewire_local_vmm' \
  scripts/dev/build-native-managed-agent.py
# Release delivery sources and their proofs were unclassified (all product
# verification) or missed the release suite; each now selects it.
run_paths_case cw_release_delivery_core pull_request refs/pull/2255/head false \
  'go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/release/cw_release.py scripts/ci/release/cw_release_r2.py
run_paths_case cw_release_delivery_shell pull_request refs/pull/2255/head false \
  'go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/release/sign-cw-release.sh \
  scripts/ci/setup/fetch-openbao-releases-r2-credentials.sh \
  scripts/ci/tests/test-fetch-openbao-releases-r2-credentials.sh \
  scripts/ci/setup/fetch-openbao-release-signing-key.sh \
  scripts/ci/tests/test-fetch-openbao-release-signing-key.sh \
  scripts/ci/release/sign-macos-cw.sh scripts/ci/setup/fetch-openbao-macos-signing.sh \
  scripts/ci/tests/test-fetch-openbao-macos-signing.sh scripts/ci/tests/test-sign-macos-cw.sh \
  scripts/ci/release/sign-macos-helper.sh scripts/ci/release/macos-signing.sh \
  scripts/ci/tests/test-sign-macos-helper.sh scripts/ci/tests/fixtures/rcodesign-stand-in.sh
run_paths_case cw_release_delivery_tests pull_request refs/pull/2255/head false \
  'go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/tests/cw_release_fixtures.py scripts/ci/tests/test-cli-release-workflow.py \
  scripts/ci/tests/test-cw-release-delivery.py scripts/ci/tests/test-cw-release-r2.py \
  scripts/ci/tests/test-package-cw-release.py scripts/ci/release/local_runtime_parts.py \
  scripts/ci/release/local_runtime_sources.py scripts/ci/release/local-runtime-sources.json \
  scripts/ci/release/build-runtime-kernel.sh scripts/ci/tests/test-local-runtime-parts.py \
  scripts/ci/release/build-local-runtime.sh scripts/ci/release/build-runtime-guest-root.sh \
  scripts/ci/release/runtime-container.sh scripts/ci/release/dry-run-superseded.sh \
  scripts/ci/tests/test-dry-run-superseded.sh scripts/ci/release/build-runtime-cw.sh
# The published workspace pin alone is the workspace-pin change class
# (owner, 2026-10-24): Policy's pin check proves the file is the generator's
# exact output, so no consumer compiles it again and its artifact facts build
# nothing; the CI-script tests that read it still run. With any other path it
# selects every consumer that compiles it, as before. Its tool and
# post-publish proposal select the release proofs that run them.
run_paths_case workspace_image_pin pull_request refs/pull/2255/head false \
  'policy change_class_workspace_pin' \
  crates/codewire-workspace-image/src/pin.rs
run_paths_case workspace_image_pin_push push refs/heads/main false \
  'policy change_class_workspace_pin' \
  crates/codewire-workspace-image/src/pin.rs
run_paths_case workspace_image_pin_with_source pull_request refs/pull/2255/head false \
  'policy rust rust_pkg_codewire_cli rust_pkg_codewire_dashboard_web rust_pkg_codewire_orchestration rust_pkg_codewire_server_core rust_pkg_codewire_workspace_image' \
  crates/codewire-workspace-image/src/pin.rs crates/codewire-workspace-image/src/lib.rs
# The workspace image's agent manifest and lockfile alone are the
# workspace-agents-lock class: the workspace agents check installs the
# lockfile and starts each agent. Any other path makes the change general.
run_paths_case workspace_agents_lock pull_request refs/pull/3274/head false \
  'policy workspace_agents' \
  images/workspace/agents/package.json images/workspace/agents/package-lock.json
run_paths_case workspace_agents_lockfile_only pull_request refs/pull/3274/head false \
  'policy workspace_agents' \
  images/workspace/agents/package-lock.json
run_paths_case workspace_agents_with_license pull_request refs/pull/3274/head false \
  'confidential_script_tests go_consumer_interop go_support policy release' \
  images/workspace/agents/package.json images/workspace/agents/LICENSE
run_paths_case workspace_image_pin_tool pull_request refs/pull/2255/head false \
  'deploy go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/images/workspace-image-pin.py
run_paths_case workspace_image_pin_proposal pull_request refs/pull/2255/head false \
  'go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/images/propose-workspace-image-pin.sh \
  scripts/ci/tests/test-propose-workspace-image-pin.sh \
  scripts/ci/setup/fetch-openbao-workspace-pin-bot-token.sh \
  scripts/ci/tests/test-fetch-openbao-workspace-pin-bot-token.sh
# The per-platform support build selects the release proofs, like the build helper.
run_paths_case support_pair_platform_build pull_request refs/pull/2255/head false \
  'go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/images/build-support-platform.sh scripts/ci/setup/fetch-openbao-arm64-buildkit-client.sh \
  scripts/ci/tests/test-fetch-openbao-arm64-buildkit-client.sh
# The exact-image contract runner gates support publication like the build.
run_paths_case workspace_contract_on_image pull_request refs/pull/2892/head false \
  'go_consumer_interop go_support policy release confidential_script_tests security security_js' \
  scripts/ci/images/run-workspace-contract-on-image.sh scripts/ci/tests/test-run-workspace-contract-on-image.sh
run_paths_case cw_runtime_image_tool pull_request refs/pull/2255/head false \
  'go_consumer_interop go_support policy release confidential_script_tests security security_js transport transport_pkg_codewire_local_vmm' \
  scripts/dev/cw-runtime-image.py scripts/dev/test-cw-runtime-image.py
run_paths_case cw_host_build_tool pull_request refs/pull/2255/head false \
  'go_consumer_interop go_support policy release confidential_script_tests rust rust_pkg_codewire_cli rust_pkg_codewire_cli_bin security security_js' \
  scripts/dev/build-cw.py
run_paths_case cw_build_record_producer pull_request refs/pull/2255/head false \
  'go_consumer_interop go_support policy release confidential_script_tests rust rust_pkg_codewire_cli' \
  crates/codewire-cli/build.rs crates/codewire-cli/src/build_record.rs
run_paths_case edge_harness pull_request refs/pull/153/head false \
  'policy security security_js' scripts/ci/verify/kind-e2e.sh
run_paths_case edge_host_runtime pull_request refs/pull/1529/head true \
  'edge_kind kind policy security security_js' scripts/ci/verify/kind-host-runtime.sh
run_paths_case edge_browser_runtime pull_request refs/pull/1530/head true \
  'edge_kind kind policy security security_js web' scripts/ci/verify/playwright-browser-runtime.sh
run_paths_case pinned_browser_installer pull_request refs/pull/1531/head true \
  'edge_kind kind policy security security_js web' scripts/ci/install-pinned-playwright-chromium.sh
run_paths_case mixed_sdk_and_runtime pull_request refs/pull/154/head false \
  'policy rust rust_pkg_codewire_server_core sdk_python service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal' \
  libs/sdk-python/codewire/client.py crates/codewire-server-core/src/lib.rs
run_paths_case edge_without_kind pull_request refs/pull/16/head false \
  'policy' Caddyfile
run_paths_case edge_with_kind pull_request refs/pull/17/head true \
  'edge_kind kind policy' Caddyfile
run_paths_case temporal_installer_without_kind pull_request refs/pull/171/head false \
  'policy security security_js' scripts/dev/kind/install-temporal.sh scripts/ci/tests/test-install-temporal.sh
run_paths_case temporal_installer_with_kind pull_request refs/pull/172/head true \
  'edge_kind kind policy security security_js' scripts/dev/kind/install-temporal.sh scripts/ci/tests/test-install-temporal.sh
run_paths_case ws17_wi_c3 pull_request refs/pull/173/head false \
  'docs go_consumer_interop go_support policy release confidential_script_tests dev_smoke_script_tests rust rust_pkg_codewire_cli rust_pkg_codewire_cli_bin rust_pkg_codewire_desktop rust_pkg_codewire_orchestration sdk_go sdk_python sdk_ts security security_js service_integration service_orchestration service_temporal web' \
  CONTRIBUTING.md \
  README.md \
  apps/cli/.env.example \
  apps/cli/.gitignore \
  apps/cli/Caddyfile \
  apps/cli/Dockerfile \
  apps/cli/Makefile \
  apps/cli/README.md \
  apps/cli/charts/codewire-mesh/templates/NOTES.txt \
  apps/cli/codewire.yaml \
  apps/cli/contrib/codex-turn-watch.sh \
  apps/cli/contrib/protocol-watch.py \
  apps/cli/contrib/protocols/codex.json \
  apps/cli/demo/Dockerfile \
  apps/cli/demo/Makefile \
  apps/cli/demo/bashrc \
  apps/cli/demo/showcase.sh \
  apps/cli/demo/site/Dockerfile \
  apps/cli/demo/site/index.html \
  apps/cli/demo/tmux-claude-msg-inbox.sh \
  apps/cli/docker-compose.yml \
  apps/cli/docs/agent-to-agent.md \
  apps/cli/docs/codex-app-server.md \
  apps/cli/docs/llm-ux-notes.md \
  apps/cli/docs/llms-full.txt \
  apps/cli/docs/llms.txt \
  apps/cli/docs/local-json-schema.md \
  apps/cli/docs/mcp.md \
  apps/cli/docs/quickstart.md \
  apps/cli/docs/skills/cw-gateway.md \
  apps/cli/docs/skills/cw.md \
  apps/dashboard/src/routes/index.tsx \
  apps/docs/astro.config.mjs \
  apps/docs/src/content/docs/cli/configuration.mdx \
  apps/docs/src/content/docs/cli/mcp.mdx \
  apps/docs/src/content/docs/cli/mesh.mdx \
  apps/docs/src/content/docs/cli/messaging.mdx \
  apps/docs/src/content/docs/cli/orchestration.mdx \
  apps/docs/src/content/docs/cli/overview.mdx \
  apps/docs/src/content/docs/cli/platform.mdx \
  apps/docs/src/content/docs/cli/sessions.mdx \
  apps/docs/src/content/docs/reference/faq.mdx \
  crates/codewire-cli/src/access_cache.rs \
  crates/codewire-cli/src/commands/collaboration.rs \
  crates/codewire-cli/src/commands/core.rs \
  crates/codewire-cli/src/commands/environment.rs \
  crates/codewire-cli/src/commands/mesh_commands.rs \
  crates/codewire-cli/src/commands/mod.rs \
  crates/codewire-cli/src/commands/platform_commands.rs \
  crates/codewire-cli/src/commands/sessions.rs \
  crates/codewire-cli/src/commands/tests/collaboration.rs \
  crates/codewire-cli/src/commands/tests/core.rs \
  crates/codewire-cli/src/commands/tests/environment.rs \
  crates/codewire-cli/src/commands/tests/run.rs \
  crates/codewire-cli/src/commands/tests/sessions.rs \
  crates/codewire-cli/src/environment_client.rs \
  crates/codewire-cli/src/http_policy.rs \
  crates/codewire-cli/src/lib.rs \
  crates/codewire-cli/src/local_client.rs \
  crates/codewire-cli/src/local_node.rs \
  crates/codewire-cli/src/local_session.rs \
  crates/codewire-cli/src/mcp.rs \
  crates/codewire-cli/src/mesh.rs \
  crates/codewire-cli/src/node_tailnet.rs \
  crates/codewire-cli/src/peer_server.rs \
  crates/codewire-cli/src/platform_run.rs \
  crates/codewire-cli/src/presentation.rs \
  crates/codewire-cli/src/protocol.rs \
  crates/codewire-cli/src/remote_session.rs \
  crates/codewire-cli/src/terminal_attach.rs \
  crates/codewire-desktop/src/pane_tree.rs \
  crates/codewire-desktop/src/terminal/view.rs \
  crates/codewire-orchestration/src/worker/setup.rs \
  docs/dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md \
  docs/dev/CODEWIRE-MESH-MIGRATION.md \
  docs/dev/DERP-STUN.md \
  docs/dev/KIND-E2E.md \
  docs/dev/LOCAL-DEV.md \
  libs/sdk-go/local.go \
  libs/sdk-go/local_files.go \
  libs/sdk-python/codewire/__init__.py \
  libs/sdk-python/codewire/local.py \
  libs/sdk-ts/src/index.ts \
  libs/sdk-ts/src/local.ts \
  scripts/ci/tests/test-retired-local-sdk-contract.sh \
  scripts/ci/verify/smoke-prod.sh \
  scripts/runtime/dev/measure-dev-commodity-overhead.sh \
  scripts/runtime/dev/smoke-dev-commodity.sh
run_paths_case tag push refs/tags/v1.2.3 false \
  'deploy go_consumer_interop go_support release confidential_script_tests' docs/tag-path-is-ignored.md

all_product='ci_script_tests kind_tools contracts contracts_proto database deploy docs edge_kind go_consumer_interop go_support go_tailnet kind policy policy_shell release confidential_script_tests dev_smoke_script_tests rust rust_curated_locks rust_workspace sdk_go sdk_python sdk_ts security security_dev_smoke_auth security_go security_idp_kek security_js service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal transport transport_derp_contract transport_pkg_codewire_coordinator transport_pkg_codewire_daemon transport_pkg_codewire_derp transport_pkg_codewire_local_vmm transport_pkg_codewire_mesh transport_pkg_codewire_netstack transport_pkg_codewire_tailnet transport_pkg_codewire_udp_relay transport_pkg_codewire_vmm_guest_probe web'
# A pull request without the Kind opt-in never selects Kind.
all_product_pr='ci_script_tests contracts contracts_proto database deploy docs go_consumer_interop go_support go_tailnet policy policy_shell release confidential_script_tests dev_smoke_script_tests rust rust_curated_locks rust_workspace sdk_go sdk_python sdk_ts security security_dev_smoke_auth security_go security_idp_kek security_js service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal transport transport_derp_contract transport_pkg_codewire_coordinator transport_pkg_codewire_daemon transport_pkg_codewire_derp transport_pkg_codewire_local_vmm transport_pkg_codewire_mesh transport_pkg_codewire_netstack transport_pkg_codewire_tailnet transport_pkg_codewire_udp_relay transport_pkg_codewire_vmm_guest_probe web'
run_present_paths_case dashboard_watch pull_request refs/pull/2002/head false \
  "$policy security security_js" scripts/dev/dashboard-watch.py
run_present_paths_case macos_developer_loop pull_request refs/pull/2064/head false \
  "$policy security security_js" scripts/dev/macos-cli.py scripts/dev/test-macos-cli.py
run_present_paths_case macos_command_owner pull_request refs/pull/2064/head false \
  "$policy security security_js" scripts/dev/macos-command-owner.py
run_present_paths_case macos_formatter_developer_tool pull_request refs/pull/2064/head false \
  "$policy security security_js" scripts/dev/macos-ext4-tool.py scripts/dev/test-macos-ext4-tool.py
run_present_paths_case macos_git_developer_tool pull_request refs/pull/2064/head false \
  "$policy security security_js" scripts/dev/macos-git-tool.py scripts/dev/test-macos-git-tool.py
run_present_paths_case macos_local_runtime_installer pull_request refs/pull/2064/head false \
  "$policy security security_js" Makefile scripts/dev/macos-local-runtime.py scripts/dev/test-macos-local-runtime.py
run_present_paths_case linux_local_runtime_packer pull_request refs/pull/2733/head false \
  "$policy security security_js" scripts/dev/linux-local-runtime.py scripts/dev/test-linux-local-runtime.py
run_present_paths_case macos_formatter_with_runtime_source pull_request refs/pull/2064/head false \
  'policy security security_js transport transport_pkg_codewire_local_vmm' \
  scripts/dev/macos-ext4-tool.py crates/codewire-local-vmm/src/lib.rs
run_present_paths_case macos_formatter_unknown pull_request refs/pull/2064/head false \
  "$all_product_pr" scripts/dev/macos-ext4-tool-future.py
# The --cli mode compile-checks the macOS cw in Compile every Rust target when
# the cw package changes (#3119 A13); the script still selects the release group.
run_present_paths_case darwin_cross_check pull_request refs/pull/20655/head false \
  'go_consumer_interop go_support policy policy_shell release confidential_script_tests security security_js transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  scripts/ci/verify/check-darwin-cross.sh
run_present_paths_case darwin_cross_check_tests pull_request refs/pull/20656/head false \
  "$policy policy_shell security security_js" scripts/ci/tests/test-darwin-cross-check.sh
# The selection job runs the runner image contract on every run.
run_present_paths_case ci_runner_image_contract_tests pull_request refs/pull/20657/head false \
  "$policy policy_shell security security_js" scripts/ci/tests/test-ci-runner-image-contract.sh
run_present_paths_case darwin_cross_test_unknown pull_request refs/pull/20656/head false \
  "$all_product_pr" scripts/ci/tests/test-darwin-cross-check-future.sh
run_present_paths_case mesh_ingress_protocol_guard pull_request refs/pull/1902/head false \
  'deploy policy policy_shell security security_js' scripts/ci/tests/test-deploy-mesh-ingress-protocol.sh
run_present_paths_case mesh_ingress_protocol_unknown pull_request refs/pull/1902/head false \
  "$all_product_pr" scripts/ci/tests/test-mesh-ingress-protocol-future.sh
# Developer-only Apple silicon journeys start real VMs on a Mac and never run
# in CI; their source selects only policy, and an unknown sibling stays full.
run_present_paths_case macos_local_vm_journeys pull_request refs/pull/20660/head false \
  'policy security security_js' \
  scripts/dev/test-cli-local-vm-macos.py scripts/dev/test-cli-local-vm-docker-macos.py \
  scripts/dev/test-cli-local-vm-inputs-macos.py \
  scripts/dev/test-local-vm-hostile-guest-macos.py scripts/dev/hostile-guest-probe.py \
  scripts/dev/test-local-vm-hostile-guest.py
run_present_paths_case macos_local_vm_journey_unknown pull_request refs/pull/20661/head false \
  "$all_product_pr" scripts/dev/test-local-vm-future-macos.py
run_paths_case macos_workload_network_native pull_request refs/pull/20650/head true \
  'policy transport transport_pkg_codewire_local_vmm' \
  crates/codewire-local-vmm/macos-vz-runner/Sources/CodewireVZRunnerProtocol/WorkloadNetwork.swift \
  crates/codewire-local-vmm/macos-vz-runner/Sources/CodewireVZRunnerRuntime/WorkloadNetworkRuntime.swift \
  crates/codewire-local-vmm/macos-vz-runner/Sources/CodewireVZRunnerRuntime/WorkloadNetworkMachine.swift \
  crates/codewire-local-vmm/macos-vz-runner/Sources/CodewireVZRunnerRuntime/WorkloadNetworkLifecycle.swift \
  crates/codewire-local-vmm/macos-vz-runner/Sources/CodewireVZRunnerRuntime/WorkloadNetworkWire.swift \
  crates/codewire-local-vmm/macos-vz-runner/Tests/CodewireVZRunnerTests/WorkloadNetworkTests.swift
run_present_paths_case dashboard_watch_unlisted pull_request refs/pull/2003/head false \
  "$all_product_pr" scripts/dev/unlisted-dashboard-helper.py
if grep -Fq 'scripts/ci/cache/*.sh' "$SELECTOR"; then
  echo 'Rust cache policy must not admit future cache helpers by wildcard' >&2
  exit 1
fi
[ ! -e "$ROOT/scripts/ci/cache/unlisted-cache-helper.sh" ] \
  || { echo 'negative cache fixture path exists in the checkout' >&2; exit 1; }
negative_cache_root="$TMP/rust_cache_unlisted.repo"
mkdir -p "$negative_cache_root/scripts/ci/cache"
: > "$negative_cache_root/scripts/ci/cache/unlisted-cache-helper.sh"
SELECTOR_CASE_ROOT="$negative_cache_root" \
  run_paths_case rust_cache_unlisted pull_request refs/pull/201/head false "$all_product_pr" \
  scripts/ci/cache/unlisted-cache-helper.sh
run_present_paths_case kind_runtime_fixture_unknown pull_request refs/pull/1801/head false \
  "$all_product_pr" scripts/ci/tests/test-kind-cw-runtime-future.py
run_paths_case unknown pull_request refs/pull/18/head false "$all_product_pr" \
  unexplained/new-surface.txt

# The CI-script tests (#3119 A6) run for their own scripts, workflows and
# hooks and for the product files they read from the tree, the workspace
# manifests among them: the live-graph cases above read the crate graph from
# those (#3225), never from Cargo.lock. Any other path leaves only the
# always-on repository rules, and an unclassified one fails closed. Every
# policy selection says the omission is authoritative.
ci_script_tests_case() {
  local want="$1" path="$2" paths="$TMP/ci-script-tests.paths" selection
  printf '%s\n' "$path" > "$paths"
  selection="$(selection_value "$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
    PATH="$EDGELESS_CARGO:$PATH" GITHUB_EVENT_NAME=pull_request \
    GITHUB_REF=refs/pull/3119/head KIND_E2E_OPT_IN=false "$SELECTOR" "$paths")")"
  [[ "$selection" == *'|policy|'* && "$selection" == *'|ci_script_tests_omittable|'* ]] || {
    echo "ci_script_tests_${path}: policy does not mark CI-script tests omittable: $selection" >&2
    exit 1
  }
  if [ "$want" = run ] && [[ "$selection" != *'|ci_script_tests|'* ]]; then
    echo "ci_script_tests: $path does not run the CI-script tests" >&2
    exit 1
  fi
  if [ "$want" = omit ] && [[ "$selection" == *'|ci_script_tests|'* ]]; then
    echo "ci_script_tests: $path runs the CI-script tests" >&2
    exit 1
  fi
}
for ci_script_path in \
    scripts/ci/select/emit-verification-matrices.sh \
    scripts/ci/tests/test-select-verification.sh \
    scripts/dev/preflight.sh \
    scripts/dev/test-macos-local-runtime.py \
    scripts/checks/repo_checks.py \
    .gitea/workflows/ci.yaml \
    .gitea/workflows/source-approval.yml \
    .githooks/pre-push \
    scripts/runtime/dev/preflight-openbao-native-secrets.sh \
    crates/codewire-local-vmm/macos-vz-runner/Tests/test_static_contract.py \
    Makefile \
    .gitleaks.toml \
    images/workspace/Dockerfile \
    deployments/docker/daemon.Dockerfile \
    crates/codewire-local-vmm/src/artifact.rs \
    crates/codewire-cw-release/src/local_runtime.rs \
    crates/codewire-workspace-image/src/pin.rs \
    Cargo.toml \
    crates/codewire-cli-bin/Cargo.toml \
    crates/codewire-platform-credentials/Cargo.toml \
    unexplained/new-surface.txt; do
  ci_script_tests_case run "$ci_script_path"
done
for product_path in \
    docs/dev/AGENT-WORKFLOW.md \
    crates/codewire-cli/src/main.rs \
    crates/codewire-local-vmm/src/lib.rs \
    crates/codewire-cw-release/src/lib.rs \
    crates/codewire-dashboard-web/templates/admin-accounts.html \
    deployments/k8s/coordinator/deployment.yaml \
    scripts/runtime/dev/smoke-dev-candidate.sh \
    Cargo.lock; do
  ci_script_tests_case omit "$product_path"
done

# The Kind tool tests (#3119 R8) run with Edge static verification only when
# a Kind tool or a product file they read changes. On a push to main, Edge
# runs for Kind-relevant paths; a pull request without ci-full selects neither.
kind_tools_case() {
  local want="$1" path="$2" paths="$TMP/kind-tools.paths" selection
  printf '%s\n' "$path" > "$paths"
  selection="$(selection_value "$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
    PATH="$EDGELESS_CARGO:$PATH" GITHUB_EVENT_NAME=push GITHUB_REF=refs/heads/main \
    "$SELECTOR" "$paths")")"
  [[ "$selection" == *'|edge_kind|'* && "$selection" == *'|kind_tools_omittable|'* ]] || {
    echo "kind_tools: $path does not run Edge with an authoritative Kind tool choice: $selection" >&2
    exit 1
  }
  if [ "$want" = run ] && [[ "$selection" != *'|kind_tools|'* ]]; then
    echo "kind_tools: $path does not run the Kind tool tests" >&2
    exit 1
  fi
  if [ "$want" = omit ] && [[ "$selection" == *'|kind_tools|'* ]]; then
    echo "kind_tools: $path runs the Kind tool tests" >&2
    exit 1
  fi
  selection="$(selection_value "$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
    PATH="$EDGELESS_CARGO:$PATH" GITHUB_EVENT_NAME=pull_request \
    GITHUB_REF=refs/pull/3119/head KIND_E2E_OPT_IN=false "$SELECTOR" "$paths")")"
  if [[ "$selection" == *'|kind_tools'* ]]; then
    echo "kind_tools: a pull request without Edge kept a Kind tool token for $path" >&2
    exit 1
  fi
}
for kind_tool_path in \
    scripts/ci/verify/kind-e2e.sh \
    tests/e2e/kind/kind-config.yaml \
    apps/dashboard/e2e/auth.setup.ts; do
  kind_tools_case run "$kind_tool_path"
done
for edge_only_path in \
    crates/codewire-dashboard-web/src/lib.rs \
    crates/codewire-dashboard-web/templates/admin-accounts.html \
    Caddyfile \
    proto/codewire/v1/environment.proto; do
  kind_tools_case omit "$edge_only_path"
done
run_paths_case mesh_policy_unknown pull_request refs/pull/181/head false "$all_product_pr" \
  scripts/checks/contracts/mesh-final-surface-policy.json \
  unexplained/new-surface.txt
run_present_paths_case design_token_unknown_contract pull_request refs/pull/22033/head false \
  "$all_product_pr" scripts/checks/contracts/design-token-unknown.json
run_paths_case empty pull_request refs/pull/19/head false "$policy" ''

contract_paths="$TMP/contract-fields.paths"
printf '%s\n' docs/guide.md > "$contract_paths"
contract_output="$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
  GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/190/head \
  KIND_E2E_OPT_IN=false "$SELECTOR" "$contract_paths")"
assert_contract_field docs "$contract_output" classification changed
assert_contract_field docs "$contract_output" required_local_mode default
printf '%s\n' crates/codewire-server-core/tests/org_deletion_lifecycle.rs \
  > "$contract_paths"
contract_output="$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
  GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/191/head \
  KIND_E2E_OPT_IN=false "$SELECTOR" "$contract_paths")"
assert_contract_field database "$contract_output" required_local_mode integration
printf '%s\n' Caddyfile > "$contract_paths"
contract_output="$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
  GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/1911/head \
  KIND_E2E_OPT_IN=false "$SELECTOR" "$contract_paths")"
assert_contract_field edge "$contract_output" required_local_mode default
printf '%s\n' scripts/ci/images/build-push-runtime-images.sh > "$contract_paths"
contract_output="$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
  GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/1914/head \
  KIND_E2E_OPT_IN=false "$SELECTOR" "$contract_paths")"
assert_contract_field protected_runtime_builder "$contract_output" required_local_mode default
printf '%s\n' scripts/ci/tests/test-kind-e2e-suites.sh > "$contract_paths"
contract_output="$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
  GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/1912/head \
  KIND_E2E_OPT_IN=false "$SELECTOR" "$contract_paths")"
assert_contract_field kind_fixture "$contract_output" required_local_mode default
printf '%s\n' scripts/ci/tests/test-kind-e2e-suites.sh \
  scripts/ci/verify/kind/suites/integrated.sh > "$contract_paths"
contract_output="$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
  GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/1913/head \
  KIND_E2E_OPT_IN=false "$SELECTOR" "$contract_paths")"
assert_contract_field kind_fixture_mixed "$contract_output" required_local_mode default
printf '%s\n' scripts/ci/tests/test-kind-cw-runtime.py \
  scripts/ci/tests/test-kind-cw-runtime-probe.py > "$contract_paths"
contract_output="$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
  GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/19131/head \
  KIND_E2E_OPT_IN=false "$SELECTOR" "$contract_paths")"
assert_contract_field kind_runtime_fixtures "$contract_output" classification changed
assert_contract_field kind_runtime_fixtures "$contract_output" required_local_mode default
printf '%s\n' scripts/ci/tests/test-kind-cw-runtime.py \
  scripts/ci/tests/test-kind-cw-runtime-probe.py \
  scripts/ci/verify/kind/suites/integrated.sh > "$contract_paths"
contract_output="$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
  GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/19132/head \
  KIND_E2E_OPT_IN=false "$SELECTOR" "$contract_paths")"
assert_contract_field kind_runtime_fixtures_mixed "$contract_output" classification changed
assert_contract_field kind_runtime_fixtures_mixed "$contract_output" required_local_mode default
printf '%s\n' scripts/ci/tests/test-dashboard-browser-gate.sh \
  scripts/ci/verify/kind/suites/dashboard-browser.sh > "$contract_paths"
contract_output="$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
  GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/1914/head \
  KIND_E2E_OPT_IN=false "$SELECTOR" "$contract_paths")"
assert_contract_field dashboard_browser_gate_mixed "$contract_output" classification changed
assert_contract_field dashboard_browser_gate_mixed "$contract_output" required_local_mode default
printf '%s\n' unexplained/new-surface.txt > "$contract_paths"
contract_output="$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
  GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/192/head \
  KIND_E2E_OPT_IN=false "$SELECTOR" "$contract_paths" 2>/dev/null)"
assert_contract_field unknown "$contract_output" classification unclassified
assert_contract_field unknown "$contract_output" required_local_mode full

diagnostic_paths="$TMP/diagnostic-output.paths"
printf '%s\n' Makefile scripts/checks/security/audit-runtime-images.sh \
  > "$diagnostic_paths"
diagnostic_output="$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
  GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/1520/head \
  KIND_E2E_OPT_IN=false \
  "$SELECTOR" --diagnostic-changed-files "$diagnostic_paths")"
if [ "$(sed -n '1p' <<<"$diagnostic_output")" != 'selector_version=v3' ] \
    || [ "$(sed -n '2p' <<<"$diagnostic_output")" != 'classification=changed' ] \
    || [[ "$(sed -n '3p' <<<"$diagnostic_output")" != selection='|valid:v3|'* ]] \
    || [ "$(sed -n '4p' <<<"$diagnostic_output")" != 'required_local_mode=default' ] \
    || [ "$(sed -n '5p' <<<"$diagnostic_output")" != 'changed_files<<EOF' ] \
    || [ "$(sed -n '6p' <<<"$diagnostic_output")" != 'Makefile' ] \
    || [ "$(sed -n '7p' <<<"$diagnostic_output")" != \
      'scripts/checks/security/audit-runtime-images.sh' ] \
    || [ "$(sed -n '8p' <<<"$diagnostic_output")" != 'EOF' ] \
    || [ "$(wc -l <<<"$diagnostic_output")" -ne 8 ]; then
  echo 'explicit changed-file diagnostic output contract is malformed' >&2
  printf '%s\n' "$diagnostic_output" >&2
  exit 1
fi
dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=rust "$SELECTOR")"
assert_tokens dispatch_rust \
  'rust rust_curated_locks rust_workspace' "$dispatch_output"
dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=transport "$SELECTOR")"
assert_tokens dispatch_transport \
  'transport transport_derp_contract transport_pkg_codewire_coordinator transport_pkg_codewire_daemon transport_pkg_codewire_derp transport_pkg_codewire_local_vmm transport_pkg_codewire_mesh transport_pkg_codewire_netstack transport_pkg_codewire_tailnet transport_pkg_codewire_udp_relay transport_pkg_codewire_vmm_guest_probe' \
  "$dispatch_output"
dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=contracts "$SELECTOR")"
assert_tokens dispatch_contracts \
  'contracts contracts_proto' "$dispatch_output"
dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=go_support "$SELECTOR")"
assert_tokens dispatch_go_support \
  'go_consumer_interop go_support go_tailnet' "$dispatch_output"
dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=ios "$SELECTOR")"
assert_tokens dispatch_ios 'ios' "$dispatch_output"
dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=docs "$SELECTOR")"
assert_tokens dispatch_docs 'docs' "$dispatch_output"
dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=policy "$SELECTOR")"
assert_tokens dispatch_policy 'ci_script_tests policy policy_shell' "$dispatch_output"
grep -Fq '|policy_shell_omittable|' <<<"$dispatch_output"
grep -Fq '|ci_script_tests_omittable|' <<<"$dispatch_output"
dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=all "$SELECTOR")"
assert_tokens dispatch_all "${all_product} ios" "$dispatch_output"
dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=release "$SELECTOR")"
assert_tokens dispatch_release \
  'go_consumer_interop go_support release confidential_script_tests' "$dispatch_output"
# A release candidate dispatches Kind with edge_kind (Kind and Edge static
# verification) or all; a push to main may defer Kind to it.
dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=edge_kind "$SELECTOR")"
assert_tokens dispatch_edge_kind 'edge_kind kind kind_tools' "$dispatch_output"

grep -qF "contains(needs.verification-selection.outputs.selection, '|rust_curated_locks|')" \
  "$WORKFLOW"
grep -qF 'run-product-verification.sh rust-curated-locks' "$WORKFLOW"
grep -qF '"$CARGO_BIN" fetch --locked --manifest-path "$stage/Cargo.toml"' \
  "$ROOT/scripts/ci/verify/check-curated-rust-locks.sh"

contracts_proto_runner="$TMP/contracts-proto.sh"
contracts_dispatcher="$TMP/contracts-dispatcher.sh"
go_support_runner="$TMP/go-support.sh"
awk '
  /^run_contracts_proto\(\) \{/ { capture = 1 }
  capture && /^run_contracts\(\) \{/ { exit }
  capture { print }
' "$ROOT/scripts/ci/verify/run-product-verification.sh" > "$contracts_proto_runner"
awk '
  /^run_contracts\(\) \{/ { capture = 1 }
  capture && /^run_go_support\(\) \{/ { exit }
  capture { print }
' "$ROOT/scripts/ci/verify/run-product-verification.sh" > "$contracts_dispatcher"
awk '
  /^run_go_support\(\) \{/ { capture = 1 }
  capture && /^run_web\(\) \{/ { exit }
  capture { print }
' "$ROOT/scripts/ci/verify/run-product-verification.sh" > "$go_support_runner"

grep -qF 'buf lint' "$contracts_proto_runner"
grep -qF 'proto_breaking.py --self-test' "$contracts_proto_runner"
grep -qF 'proto_breaking.py --base-sha "$base_sha"' "$contracts_proto_runner"
grep -qF 'buf generate --template buf.gen.codewire.yaml' "$contracts_proto_runner"
grep -qF 'buf generate --template buf.gen.google-rpc-ts.yaml' "$contracts_proto_runner"
grep -qF 'buf generate --template buf.gen.google-rpc-python.yaml' "$contracts_proto_runner"
grep -qF 'build-rust-descriptors.sh' "$contracts_proto_runner"
grep -qF 'crates/codewire-proto/codewire_descriptor.bin' "$contracts_proto_runner"
grep -qF 'crates/codewire-admin-proto/codewire_admin_descriptor.bin' "$contracts_proto_runner"
grep -qF 'libs/gen-go' "$contracts_proto_runner"
grep -qF 'git ls-files --others --exclude-standard' "$contracts_proto_runner"
grep -qF 'PYTHONPATH=libs/gen-python' "$contracts_proto_runner"
grep -qF 'py_compile.compile' "$contracts_proto_runner"
grep -qF '@codewire/proto-ts typecheck' "$contracts_proto_runner"
grep -qF '../libs/gen-go/codewire' "$contracts_proto_runner"
grep -qF '../libs/gen-python/codewire' "$contracts_proto_runner"
grep -qF '../packages/codewire-proto-ts/src/gen/codewire' "$contracts_proto_runner"
grep -qF 'proto-package-boundaries --self-test' "$contracts_proto_runner"
grep -qF 'cargo test --locked -p codewire-proto -p codewire-admin-proto' "$contracts_proto_runner"
rust_descriptor_builder="$ROOT/scripts/ci/proto/build-rust-descriptors.sh"
grep -qF -- '--path codewire/admin/v1/admin.proto' "$rust_descriptor_builder"
grep -qF -- '--path codewire/admin/v1/billing_catalog.proto' "$rust_descriptor_builder"
grep -qF -- '--path codewire/v1/environment.proto' "$rust_descriptor_builder"
grep -qF 'codewire-admin-proto/codewire_admin_descriptor.bin' "$rust_descriptor_builder"
grep -qF 'test-admin-proto-boundary.sh' "$ROOT/scripts/ci/verify/run-product-verification.sh"
grep -qF 'github.com/bufbuild/buf/cmd/buf@v1.50.0' "$ROOT/Makefile"
if rg -n 'tests/contract' "$contracts_proto_runner"; then
  echo 'Proto regeneration runs a general Go service-driver suite' >&2
  exit 1
fi
grep -qF 'selected go_consumer_interop' "$go_support_runner"
grep -qF 'selected go_tailnet' "$go_support_runner"
grep -qF 'scripts/ci/verify/tailnet-parity.sh' "$go_support_runner"
if grep -qF 'cd libs/tailnet' "$go_support_runner"; then
  echo 'go_tailnet still runs the retired Go tailnet oracle' >&2
  exit 1
fi
grep -qF 'cargo test --locked -p codewire-server-core' "$go_support_runner"
grep -qF -- '--test go_consumer_interop generated_go_client_consumes_rust_connect' \
  "$go_support_runner"
grep -qF -- '--exact --ignored --nocapture' "$go_support_runner"
for retired_path in \
    apps/api \
    autoagent \
    libs/gen-go/coordinator \
    libs/gatewayauth \
    libs/daemon-proto/gen \
    tests/contract/coordinator \
    tests/contract/file \
    tests/contract/orchestration; do
  if [ -e "$ROOT/$retired_path" ]; then
    echo "retired former-Go implementation path remains: $retired_path" >&2
    exit 1
  fi
done
if rg -n 'apps/api/gen' \
    "$ROOT/Makefile" \
    "$ROOT/proto/buf.gen.codewire.yaml" \
    "$ROOT/proto/buf.gen.google-rpc-ts.yaml" \
    "$ROOT/proto/buf.gen.google-rpc-python.yaml" \
    "$ROOT/proto/README.md" \
    "$ROOT/docs/dev/PROTO-STYLE.md" \
    "$ROOT/scripts/ci/verify/run-product-verification.sh"; then
  echo 'active proto generation still references apps/api/gen' >&2
  exit 1
fi
if rg -n 'prepare_go_workspace|agent-sandbox|AGENT_SANDBOX' \
    "$ROOT/scripts/ci/verify/run-product-verification.sh"; then
  echo 'automatic verification still constructs the former external Go workspace' >&2
  exit 1
fi
grep -qF 'CoordinatorServiceName = "codewire.internal.v1.CoordinatorService"' \
  "$ROOT/libs/gen-go/codewire/internal/v1/internalv1connect/coordinate.connect.go"
if grep -qF 'replace github.com/codewiresh/codewire =>' \
    "$ROOT/tests/contract/go.mod"; then
  echo 'contract module still resolves through the retired apps/api module' >&2
  exit 1
fi
grep -qF "'protobuf==7.35.1'" "$ROOT/scripts/ci/verify/run-product-verification.sh"
grep -qF "'connectrpc==0.11.1'" \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
grep -qF "'protoc-gen-connectrpc==0.11.1'" \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
if rg -n 'openapi:|rest:freeze|validation:check-source|types:generate|api-client-go' \
    "$contracts_proto_runner"; then
  echo 'Proto/Connect contract mode contains transitional REST work' >&2
  exit 1
fi

grep -qF 'if ! selected contracts_proto; then' "$contracts_dispatcher"
grep -qF 'Contracts selected without contracts_proto' "$contracts_dispatcher"
[[ "$(grep -c 'install_bun_dependencies' "$contracts_dispatcher")" -eq 1 ]] || {
  echo 'Contracts dispatcher must install shared Bun dependencies exactly once' >&2
  exit 1
}
if missing_mode_output="$(VERIFICATION_SELECTION='|valid:v3|contracts|complete|' \
    "$ROOT/scripts/ci/verify/run-product-verification.sh" contracts 2>&1)"; then
  echo 'Contracts runner accepted a selected family without a sub-mode' >&2
  exit 1
fi
grep -qF 'Contracts selected without contracts_proto' \
  <<<"$missing_mode_output"

# Every test the database family runs lives in a source file whose change
# selects that family (#3194): main commits c2b844b9a and 1f4c5898a changed the
# preview database matrix, which is ignored without TEST_DATABASE_URL, and it
# ran nowhere. Each database_lane_* cargo test names its package and either a
# --lib module filter (resolved to the deepest module file it names) or a
# --test target.
database_lane_sources="$(python3 - "$ROOT" <<'PY'
import os
import re
import sys

root = sys.argv[1]
runner = open(os.path.join(root, "scripts/ci/verify/run-integration-verification.sh")).read()
bodies = re.findall(r"^database_lane_[a-z_]+\(\) \{\n(.*?)^\}", runner, re.S | re.M)
if len(bodies) < 4:
    sys.exit("database lanes not found")
sources = set()
for body in bodies:
    for line in body.replace("\\\n", " ").splitlines():
        if "cargo test" not in line:
            continue
        words = line.split()
        package = os.path.join("crates", words[words.index("-p") + 1])
        if "--lib" in words:
            segments = [s for s in words[words.index("--lib") + 1].strip("'\"").split("::") if s]
            found = None
            for depth in range(1, len(segments) + 1):
                stem = os.path.join(package, "src", *segments[:depth])
                for candidate in (stem + ".rs", os.path.join(stem, "mod.rs")):
                    if os.path.exists(os.path.join(root, candidate)):
                        found = candidate
            if found is None:
                sys.exit(f"unresolved database lane module: {line.strip()}")
            sources.add(found)
        elif "--test" in words:
            target = os.path.join(package, "tests", words[words.index("--test") + 1] + ".rs")
            if not os.path.exists(os.path.join(root, target)):
                sys.exit(f"unresolved database lane test: {line.strip()}")
            sources.add(target)
        else:
            sys.exit(f"database lane test names neither --lib nor --test: {line.strip()}")
print("\n".join(sorted(sources)))
PY
)"
[ "$(wc -l <<<"$database_lane_sources")" -ge 40 ] || {
  echo 'database lane sources: fewer than expected; the runner parse drifted' >&2
  exit 1
}
while IFS= read -r source; do
  printf '%s\n' "$source" > "$TMP/database-lane-source.paths"
  for event in push pull_request; do
    output="$(cd "$ROOT" && env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
      PATH="$EDGELESS_CARGO:$PATH" GITHUB_EVENT_NAME="$event" GITHUB_REF=refs/heads/main \
      KIND_E2E_OPT_IN=false "$SELECTOR" "$TMP/database-lane-source.paths")"
    [[ "$(selection_value "$output")" == *'|database|'* ]] || {
      echo "database lane source ${source} does not select the database family on ${event}" >&2
      exit 1
    }
  done
done <<<"$database_lane_sources"
# The preview matrix, exactly: the orchestration families and database.
run_paths_case preview_database_tests_select_database push refs/heads/main false \
  'database policy rust rust_pkg_codewire_orchestration service_integration service_orchestration' \
  crates/codewire-orchestration/src/api/preview/authorization/database_tests.rs

# The integration runner's PostgreSQL harness, the helpers it sources that
# start PostgreSQL, and their tests qualify every family that runs against
# that PostgreSQL: database and all services (#3198). The helper list comes
# from the runner, so a new PostgreSQL helper needs this rule too.
integration_harness_sources="$(python3 - "$ROOT" <<'PY'
import os
import re
import sys

root = sys.argv[1]
runner_path = "scripts/ci/verify/run-integration-verification.sh"
runner = open(os.path.join(root, runner_path)).read()
sources = {runner_path}
for helper in re.findall(r'^\s*(?:source|\.)\s+"\$ROOT/([^"]+)"', runner, re.M):
    text = open(os.path.join(root, helper)).read()
    if re.search(r"postgres:[0-9]", text):
        sources.add(helper)
        test = os.path.join("scripts/ci/tests", "test-" + os.path.basename(helper))
        if os.path.exists(os.path.join(root, test)):
            sources.add(test)
if "scripts/ci/verify/integration-postgres.sh" not in sources:
    sys.exit("the runner no longer sources its PostgreSQL helper")
print("\n".join(sorted(sources)))
PY
)"
while IFS= read -r source; do
  printf '%s\n' "$source" > "$TMP/integration-harness.paths"
  for event in push pull_request; do
    output="$(cd "$ROOT" && env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
      PATH="$EDGELESS_CARGO:$PATH" GITHUB_EVENT_NAME="$event" GITHUB_REF=refs/heads/main \
      KIND_E2E_OPT_IN=false "$SELECTOR" "$TMP/integration-harness.paths")"
    for token in database service_integration service_idp service_billing service_orchestration \
        service_coordinator service_temporal service_nats service_connectcore; do
      [[ "$(selection_value "$output")" == *"|${token}|"* ]] || {
        echo "integration harness ${source} does not select ${token} on ${event}" >&2
        exit 1
      }
    done
  done
done <<<"$integration_harness_sources"

integration_runner="$ROOT/scripts/ci/verify/run-integration-verification.sh"
# Database owns the destroy-hint regression. The activity-fencing lane must
# retain its exact two tests instead of also selecting this ignored worker test.
activity_fencing_block="$(sed -n '/^run_orchestration() {/,/^  start_orchestration$/p' "$integration_runner")"
# The orchestration service and its smokes come from the wire contract's own
# test build. A separate binary build compiled the crate one more time.
orchestration_build_block="$(sed -n '/^build_selected_services() {/,/^}$/p' "$integration_runner")"
grep -qF -- '--features kind-e2e --test wire_contract --no-run' <<<"$orchestration_build_block"
if grep -Eq 'cargo_ci build .*-p codewire-orchestration' <<<"$orchestration_build_block"; then
  echo 'services build the orchestration binaries apart from the wire contract test build' >&2
  exit 1
fi
grep -qF "'worker::' -- --ignored" <<<"$activity_fencing_block"
grep -qF -- "--skip 'worker::postgres_secrets::tests::encrypted_store_reencrypts_renames_and_deletes_final_dek'" <<<"$activity_fencing_block"
grep -qF -- "--skip 'worker::lifecycle::tests::destroy_template_hint_allows_missing_creation_config_but_not_database_failure'" <<<"$activity_fencing_block"
grep -qF -- "--skip 'worker::create::projection_database_tests::'" <<<"$activity_fencing_block"
grep -qF -- "--skip 'worker::workspace_binding::database_tests::'" <<<"$activity_fencing_block"
grep -qF -- "--skip 'worker::billing_sessions::database_tests::'" <<<"$activity_fencing_block"
grep -qF -- "--skip 'worker::credential_relay::database_tests::'" <<<"$activity_fencing_block"
grep -qF 'assert_passed_count "orchestration activity fencing matrix" "$logfile" 2' <<<"$activity_fencing_block"
destroy_hint_block="$(sed -n '/logfile="$RUN_DIR\/environment-destroy-template-hint.log"/,/assert_passed_count "environment destroy template hint matrix"/p' "$integration_runner")"
grep -qF 'worker::lifecycle::tests::destroy_template_hint_allows_missing_creation_config_but_not_database_failure' <<<"$destroy_hint_block"
grep -qF -- '-- --ignored --exact --nocapture' <<<"$destroy_hint_block"
grep -qF 'assert_passed_count "environment destroy template hint matrix" "$logfile" 1' <<<"$destroy_hint_block"
grep -qF 'cargo test --locked -p codewire-credential-broker --no-default-features --features platform' "$integration_runner"
grep -qF -- '--lib platform::tests:: -- --ignored --nocapture --test-threads=1' "$integration_runner"
grep -qF 'assert_passed_count "platform broker admission matrix" "$logfile" 50' "$integration_runner"
grep -qF -- '--features platform,ssh-agent --lib platform::tests::ssh::' "$integration_runner"
grep -qF 'assert_passed_count "platform broker SSH matrix" "$logfile" 5' "$integration_runner"
grep -qF -- '--lib platform::bridge::tests::rotation:: -- --ignored --nocapture --test-threads=1' "$integration_runner"
grep -qF 'assert_passed_count "platform broker gRPC rotation drain matrix" "$logfile" 4' "$integration_runner"
grep -qF 'cargo test --locked -p codewire-credential-service' "$integration_runner"
grep -qF -- '--skip tests::database::projection::' "$integration_runner"
grep -qF 'assert_passed_count "platform runtime restricted identity matrix" "$logfile" 6' "$integration_runner"
grep -qF -- '--lib tests::database::projection::' "$integration_runner"
grep -qF 'assert_passed_count "platform runtime projection matrix" "$logfile" 13' "$integration_runner"
grep -qF -- '--lib delegation::authority::tests::' "$integration_runner"
grep -qF 'assert_passed_count "owner-local delegation authority matrix" "$logfile" 8' "$integration_runner"
grep -qF 'cargo test --locked -p codewire-orchestration --test access_profiles' "$integration_runner"
grep -qF 'assert_passed_count "public access profile restricted API matrix" "$logfile" 8' "$integration_runner"
grep -qF 'assert_passed_count "public credential metadata matrix" "$logfile" 3' "$integration_runner"
grep -qF 'assert_passed_count "public credential mutation matrix" "$logfile" 28' "$integration_runner"
grep -qF -- '--lib runtime::tests:: -- --ignored --nocapture --test-threads=1' "$integration_runner"
grep -qF 'assert_passed_count "isolated credential runtime matrix" "$logfile" 5' "$integration_runner"
grep -qF -- '--lib runtime::kind::config::tests::effective_acl_guard_rejects_direct_column_and_membership_authority' "$integration_runner"
grep -qF 'assert_passed_count "Kind credential effective ACL matrix" "$logfile" 1' "$integration_runner"
grep -qF 'cargo test --locked -p codewire-credential-service --features enrollment' "$integration_runner"
grep -qF 'cargo clippy --locked -p codewire-credential-service --features enrollment --all-targets -- -D warnings' "$ROOT/scripts/ci/verify/run-product-verification.sh"
grep -qF 'cargo test --locked -p codewire-server-core --test oauth_bearer_auth' "$integration_runner"
grep -qF 'assert_passed_count "OAuth-only restricted identity matrix" "$logfile" 6' "$integration_runner"
grep -qF 'assert_passed_count "server-core migration matrix" "$logfile" 22' "$integration_runner"
grep -qF 'assert_passed_count "idp db_flow" "$logfile" 13' "$integration_runner"
grep -qF 'assert_passed_count "idp two-factor replacement" "$logfile" 11' "$integration_runner"
grep -qF 'assert_passed_count "platform credential storage matrix" "$logfile" 24' "$integration_runner"
grep -qF 'assert_passed_count "platform access profile matrix" "$logfile" 15' "$integration_runner"
grep -qF 'cargo test --locked -p codewire-platform-credentials --test owner_sources' "$integration_runner"
grep -qF 'assert_passed_count "platform owner-source authority matrix" "$logfile" 5' "$integration_runner"
grep -qF -- "'worker::create::projection_database_tests::'" "$integration_runner"
grep -qF 'assert_passed_count "environment projection capture matrix" "$logfile" 5' "$integration_runner"
grep -qF -- "'api::admin::startup_database_tests::'" "$integration_runner"
grep -qF 'assert_passed_count "admin startup summary matrix" "$logfile" 2' "$integration_runner"
grep -qF -- "'worker::workspace_binding::database_tests::'" "$integration_runner"
grep -qF 'assert_passed_count "workspace binding recorder matrix" "$logfile" 20' "$integration_runner"
grep -qF -- "'workspace_binding::store::database_tests::'" "$integration_runner"
grep -qF 'assert_passed_count "workspace binding access store matrix" "$logfile" 4' "$integration_runner"
grep -qF -- "'api::environment_resize::tests::db_'" "$integration_runner"
grep -qF 'assert_passed_count "environment resize admission matrix" "$logfile" 3' "$integration_runner"
grep -qF -- "'api::ssh_proxy::database_tests::'" "$integration_runner"
grep -qF 'assert_passed_count "SSH proxy runtime lease matrix" "$logfile" 2' "$integration_runner"
grep -qF -- "'api::environment_daemon::repair_database_tests::'" "$integration_runner"
grep -qF 'assert_passed_count "environment daemon repair lease matrix" "$logfile" 2' "$integration_runner"
grep -qF -- "'worker::billing_sessions::database_tests::'" "$integration_runner"
grep -qF 'assert_passed_count "billing session bind matrix" "$logfile" 4' "$integration_runner"
grep -qF -- "'worker::credential_relay::database_tests::'" "$integration_runner"
grep -qF 'assert_passed_count "credential relay target matrix" "$logfile" 1' "$integration_runner"
grep -qF 'selected service_connectcore && run_connect_auth_matrix' \
  "$integration_runner"
if rg -n 'run_connectcore|CONNECTCORE_BASE_URLS|go test.*connectcore' \
    "$integration_runner"; then
  echo 'Service integration still invokes the retired Go connectcore driver' >&2
  exit 1
fi
if rg -n 'CONNECTCORE_BASE_URLS|go test.*connectcore|./connectcore/' \
    "$ROOT/scripts/ci/verify/rust-stack-rehearsal.sh"; then
  echo 'Manual Rust rehearsal still invokes the retired Go connectcore driver' >&2
  exit 1
fi
grep -qF 'run_connect_auth_matrix' \
  "$ROOT/scripts/ci/verify/rust-stack-rehearsal.sh"

grep -qF -- '--test wire_contract --features kind-e2e' "$integration_runner"
grep -qF 'ORCHESTRATION_CONTRACT_SCOPE=complete' "$integration_runner"
grep -qF 'ORCHESTRATION_CONTRACT_SCOPE=runtime' "$integration_runner"
grep -qF -- '--test wire_contract --features kind-e2e' \
  "$ROOT/scripts/ci/verify/rust-stack-rehearsal.sh"
grep -qF 'ORCHESTRATION_CONTRACT_SCOPE=runtime' \
  "$ROOT/scripts/ci/verify/rust-stack-rehearsal.sh"
for orchestration_runner in \
    "$integration_runner" \
    "$ROOT/scripts/ci/verify/rust-stack-rehearsal.sh"; do
  if rg -n '(^|[[:space:]])go test.*orchestration|\./orchestration/\.\.\.' \
      "$orchestration_runner"; then
    echo "Gate still invokes the retired Go orchestration driver: $orchestration_runner" >&2
    exit 1
  fi
done

for rust_owner_runner in \
    "$integration_runner" \
    "$ROOT/scripts/ci/verify/kind-e2e.sh" \
    "$ROOT/scripts/ci/verify/kind/common.sh" \
    "$ROOT/scripts/ci/verify/kind/suites/integrated.sh" \
    "$ROOT/scripts/ci/verify/kind/suites/final-fencing.sh" \
    "$ROOT/scripts/ci/verify/kind/suites/environment-session.sh" \
    "$ROOT/scripts/dev/dev-stack.sh"; do
  if rg -n '(^|[[:space:]])go (test|run|build)|apps/api/internal/e2e' \
      "$rust_owner_runner"; then
    echo "Rust-owned product runner still invokes a general Go driver: $rust_owner_runner" >&2
    exit 1
  fi
done

all_up_runner="$ROOT/scripts/ci/verify/rust-stack-rehearsal.sh"
[[ "$(grep -Ec '(^|[[:space:]])go test' "$all_up_runner")" -eq 2 ]] || {
  echo 'All-up diagnostic must retain exactly two Go/Tailscale DERP interop calls' >&2
  exit 1
}
grep -qF -- "-run '^TestRawHTTPUpgradeRelaysTailscaleGoClients$' ./derp/..." \
  "$all_up_runner"
grep -qF -- "-run '^TestWebSocketFallbackRelaysTailscaleGoClients$' ./derp/..." \
  "$all_up_runner"
if rg -n 'apps/api/internal/e2e|test-e2e-kind|test-worker-kind' \
    "$ROOT/Makefile" "$ROOT/package.json"; then
  echo 'Active developer commands still expose the retired general Go product suite' >&2
  exit 1
fi

for billing_runner in \
    "$integration_runner" \
    "$ROOT/scripts/ci/verify/rust-stack-rehearsal.sh" \
    "$ROOT/scripts/ci/verify/kind/common.sh"; do
  if [[ "$billing_runner" == */kind/common.sh ]]; then
    # Kind executes the exact libtest produced by the separate build job.
    grep -qF -- '"$binary" configured_billing_wire_contract' "$billing_runner"
    grep -qF -- '"$RUN_DIR/billing-contract-build.jsonl"' "$billing_runner"
  else
    grep -qF -- '--test wire_contract configured_billing_wire_contract' "$billing_runner"
  fi
  if rg -n '(^|[[:space:]])go test.*billing|\./billing/\.\.\.|BILLING_STRIPE_CONFIGURED.*absent|billing is not enabled' \
      "$billing_runner"; then
    echo "Automatic gate still carries a retired Go or Stripe-disabled billing contract: $billing_runner" >&2
    exit 1
  fi
done
if [ -d "$ROOT/tests/contract/billing" ] \
    && find "$ROOT/tests/contract/billing" -maxdepth 1 -type f -name '*.go' \
      -print -quit | grep -q .; then
  echo 'Retired Go billing contract driver still exists' >&2
  exit 1
fi
if rg -n 'run_go_with_allowed_skip|go-output-policy|allowed_skip' \
    "$integration_runner" "$ROOT/scripts/ci/verify/run-product-verification.sh"; then
  echo 'Retired billing allowed-skip policy still exists' >&2
  exit 1
fi

database_go_setup="$TMP/database-go-setup.txt"
awk '
  /^  database:$/ { group = 1 }
  group && /- name: Set up Go 1\.26\.5$/ { capture = 1 }
  capture { print }
  capture && /run: scripts\/ci\/setup\/setup-go\.sh/ { exit }
' "$WORKFLOW" > "$database_go_setup"
if [[ -s "$database_go_setup" ]]; then
  echo 'Database/service integration still installs Go despite having no Go driver' >&2
  exit 1
fi

derp_runner="$TMP/run-derp-contract.sh"
awk '
  /^run_derp_contract\(\) \{/ { capture = 1 }
  capture && /^run_transport\(\) \{/ { exit }
  capture { print }
' "$ROOT/scripts/ci/verify/run-product-verification.sh" > "$derp_runner"
[[ "$(grep -c 'go test' "$derp_runner")" -eq 2 ]] || {
  echo 'DERP runner must execute exactly two focused Go contracts' >&2
  exit 1
}
[[ "$(grep -c -- "-run '" "$derp_runner")" -eq 2 ]] || {
  echo 'DERP runner has a broad or additional Go contract invocation' >&2
  exit 1
}
grep -qF -- \
  "-run '^TestRawHTTPUpgradeRelaysTailscaleGoClients$' ./derp/..." \
  "$derp_runner"
grep -qF -- \
  "-run '^TestWebSocketFallbackRelaysTailscaleGoClients$' ./derp/..." \
  "$derp_runner"
grep -qF 'DERP_WEBSOCKET=1' "$derp_runner"
# The local-vmm shard runs apart from the packages shard that builds binaries.
grep -qF 'cargo build --locked -p codewire-derp --bin codewire-derp' "$derp_runner" || {
  echo 'DERP runner must build the relay binary it starts' >&2
  exit 1
}
grep -qF "if grep -Eq -- '--- SKIP'" "$derp_runner"
grep -qF "|| ! grep -Eq -- '^[[:space:]]*--- PASS:'" "$derp_runner"
grep -qF 'if selected transport_pkg_codewire_vmm_guest_probe; then' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
grep -qF 'if selected transport_pkg_codewire_local_vmm; then' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
[[ "$(grep -cFx '    scripts/ci/verify/check-darwin-cross.sh' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh")" == 1 ]]
grep -qF 'exec "$zigbuild_bin" clippy --locked -p codewire-local-vmm -p codewire-vmm-guest-probe \' \
  "$ROOT/scripts/ci/verify/check-darwin-cross.sh"
grep -qF -- '--target aarch64-apple-darwin -- -D warnings' \
  "$ROOT/scripts/ci/verify/check-darwin-cross.sh"
grep -qF 'scripts/ci/verify/build-local-vmm-initramfs.sh --verify' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"

dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=service_integration "$SELECTOR")"
assert_tokens dispatch_services \
  'service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal' \
  "$dispatch_output"

output_file="$TMP/github-output"
paths_file="$TMP/github-output.paths"
printf '%s\n' proto/codewire/v1/common.proto > "$paths_file"
# Clear any real event payload: a CI run's own pull request text must not
# opt this fixture into Kind.
env -u GITHUB_EVENT_PATH GITHUB_OUTPUT="$output_file" GITHUB_EVENT_NAME=pull_request \
  "$SELECTOR" "$paths_file" >/dev/null
assert_tokens github_output \
  'contracts contracts_proto go_consumer_interop go_support policy rust rust_pkg_codewire_cli rust_pkg_codewire_client rust_pkg_codewire_dashboard_web rust_pkg_codewire_orchestration rust_pkg_codewire_project_proto rust_pkg_codewire_proto sdk_go sdk_python sdk_ts transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe web' \
  "$(cat "$output_file")"

# Exercise changed-range discovery, including fail-closed missing PR state.
repo="$TMP/ranges"
git init -q -b main "$repo"
git -C "$repo" config maintenance.auto false
git -C "$repo" config gc.auto 0
git -C "$repo" config user.name 'Selector Test'
git -C "$repo" config user.email selector@example.invalid
mkdir -p "$repo/docs"
printf 'base\n' > "$repo/docs/range.md"
git -C "$repo" add docs/range.md
git -C "$repo" -c commit.gpgsign=false commit -q -m base
base="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" switch -q -c feature
mkdir -p "$repo/crates/codewire-cli/src"
printf 'pub fn selected() {}\n' > "$repo/crates/codewire-cli/src/lib.rs"
git -C "$repo" add crates/codewire-cli/src/lib.rs
git -C "$repo" -c commit.gpgsign=false commit -q -m feature
git -C "$repo" remote add origin .
output="$(cd "$repo" && env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
  GITHUB_EVENT_NAME=pull_request GITHUB_BASE_REF=main \
  VERIFICATION_REMOTE=origin KIND_E2E_OPT_IN=false "$SELECTOR")"
assert_tokens discovered_pr 'policy rust rust_pkg_codewire_cli' "$output"
missing_stdout="$TMP/missing-pr.stdout"
missing_stderr="$TMP/missing-pr.stderr"
if (cd "$repo" && env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
    GITHUB_EVENT_NAME=pull_request GITHUB_BASE_REF= \
    VERIFICATION_REMOTE=origin KIND_E2E_OPT_IN=false \
    "$SELECTOR" >"$missing_stdout" 2>"$missing_stderr"); then
  echo 'selector accepted a pull request without a baseline' >&2
  exit 1
fi
[ ! -s "$missing_stdout" ] || {
  echo 'failed baseline discovery emitted machine-readable output' >&2
  exit 1
}
grep -qF 'pull-request baseline is unavailable' "$missing_stderr"

git -C "$repo" switch -q main
printf 'main update\n' >> "$repo/docs/range.md"
git -C "$repo" add docs/range.md
git -C "$repo" -c commit.gpgsign=false commit -q -m docs
head="$(git -C "$repo" rev-parse HEAD)"
output="$(cd "$repo" && env -u GITHUB_OUTPUT \
  GITHUB_EVENT_NAME=push GITHUB_REF=refs/heads/main \
  PUSH_BEFORE_SHA="$base" PUSH_AFTER_SHA="$head" "$SELECTOR")"
assert_tokens discovered_push policy "$output"

# A superseded main run verifies nothing (#3176). The push that superseded it
# compares with the newest commit main CI verified (main-ci-verdict.py base),
# which ci.yaml passes as PUSH_BEFORE_SHA, so the cumulative change selects
# what each commit would have; the push's own docs change alone selects only
# policy. Without a verified commit the push selects all product verification.
git -C "$repo" switch -q -c superseded-chain
mkdir -p "$repo/crates/codewire-cli/src"
printf 'pub fn superseded() {}\n' > "$repo/crates/codewire-cli/src/lib.rs"
git -C "$repo" add crates/codewire-cli/src/lib.rs
git -C "$repo" -c commit.gpgsign=false commit -q -m 'superseded rust change'
superseded="$(git -C "$repo" rev-parse HEAD)"
printf 'tip docs\n' >> "$repo/docs/range.md"
git -C "$repo" add docs/range.md
git -C "$repo" -c commit.gpgsign=false commit -q -m 'tip docs'
chain_tip="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" switch -q main
chain_push() { # BEFORE [UNVERIFIED] -> selector output
  (cd "$repo" && env -u GITHUB_OUTPUT \
    GITHUB_EVENT_NAME=push GITHUB_REF=refs/heads/main \
    PUSH_BEFORE_SHA="$1" PUSH_AFTER_SHA="$chain_tip" \
    PUSH_BASE_UNVERIFIED="${2:-false}" "$SELECTOR" 2>"$TMP/chain.stderr")
}
assert_tokens chain_tip_alone policy "$(chain_push "$superseded")"
output="$(chain_push "$head")"
assert_tokens chain_from_verified_base 'policy rust rust_pkg_codewire_cli' "$output"
output="$(chain_push "$superseded" true)"
assert_contract_field chain_unverified "$output" classification unclassified
for token in policy rust rust_workspace transport database service_integration \
    web docs release deploy security edge_kind; do
  [[ "$(selection_value "$output")" == *"|${token}|"* ]] || {
    echo "chain_unverified: a push without a verified base did not select ${token}" >&2
    exit 1
  }
done
grep -Fxq 'main push: no verified main commit to compare with; selecting all product verification' \
  "$TMP/chain.stderr"
# Only a push to main reads it; a value other than false selects everything.
output="$(chain_push "$superseded" yes)"
assert_contract_field chain_unverified_any_value "$output" classification unclassified
output="$(cd "$repo" && env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=push GITHUB_REF=refs/heads/other \
  PUSH_BEFORE_SHA="$superseded" PUSH_AFTER_SHA="$chain_tip" PUSH_BASE_UNVERIFIED=true "$SELECTOR")"
assert_tokens chain_other_branch policy "$output"
missing_stdout="$TMP/zero-push.stdout"
missing_stderr="$TMP/zero-push.stderr"
if (cd "$repo" && env -u GITHUB_OUTPUT \
    GITHUB_EVENT_NAME=push GITHUB_REF=refs/heads/main \
    PUSH_BEFORE_SHA=0000000000000000000000000000000000000000 \
    PUSH_AFTER_SHA="$head" "$SELECTOR" >"$missing_stdout" 2>"$missing_stderr"); then
  echo 'selector accepted a push without a baseline' >&2
  exit 1
fi
[ ! -s "$missing_stdout" ] || {
  echo 'failed push baseline discovery emitted machine-readable output' >&2
  exit 1
}
grep -qF 'push baseline is unavailable' "$missing_stderr"

# A scheduled run (owner decision 2026-10-20) checks Kind alone against the
# commit the last successful scheduled run checked (SCHEDULE_BASELINE_SHA),
# while the switch defers Kind on a push to main; these cases use that copy.
# The scheduled marker keeps artifact facts from dispatching other groups.
feature="$(git -C "$repo" rev-parse feature)"
schedule_discover() { # BASELINE -> selector output; stderr in $TMP/schedule.stderr
  (cd "$repo" && env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
    GITHUB_EVENT_NAME=schedule GITHUB_REF=refs/heads/main GITHUB_SHA="$head" \
    SCHEDULE_BASELINE_SHA="$1" "$SELECTOR_KIND_OFF" 2>"$TMP/schedule.stderr")
}
output="$(schedule_discover "$base")"
assert_tokens schedule_unchanged_kind scheduled "$output"
assert_contract_field schedule_unchanged_kind "$output" classification scheduled
grep -Fxq "schedule: no Kind input changed since $base; Kind does not run" "$TMP/schedule.stderr"
for unknown_baseline in '' "$feature" 0000000000000000000000000000000000000000 not-a-commit; do
  output="$(schedule_discover "$unknown_baseline")"
  assert_tokens "schedule_unknown_${unknown_baseline:-empty}" 'kind scheduled' "$output"
  grep -Fxq 'schedule: no successful scheduled run to compare with; Kind runs' "$TMP/schedule.stderr"
done
schedule_paths() { # SELECTOR PATH... -> output; explicit paths stand for a known baseline
  local selector="$1"
  shift
  printf '%s\n' "$@" > "$TMP/schedule.paths"
  env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH PATH="$EDGELESS_CARGO:$PATH" \
    GITHUB_EVENT_NAME=schedule GITHUB_REF=refs/heads/main \
    "$selector" "$TMP/schedule.paths" 2>"$TMP/schedule.stderr"
}
output="$(schedule_paths "$SELECTOR_KIND_OFF" apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts \
  crates/codewire-cli/src/main.rs docs/dev/AGENT-WORKFLOW.md)"
assert_tokens schedule_kind_input 'kind scheduled' "$output"
grep -Fq 'schedule: a Kind input changed since' "$TMP/schedule.stderr"
assert_tokens schedule_no_kind_input scheduled \
  "$(schedule_paths "$SELECTOR_KIND_OFF" crates/codewire-cli/src/main.rs docs/dev/AGENT-WORKFLOW.md)"
assert_tokens schedule_unclassified 'kind scheduled' \
  "$(schedule_paths "$SELECTOR_KIND_OFF" unclassified-schedule-fixture.bin)"
# While the switch gives pushes to main their Kind again, a schedule runs
# nothing, changed Kind inputs or not, and says why.
assert_tokens schedule_switch_on scheduled \
  "$(schedule_paths "$SELECTOR_KIND_ON" apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts)"
grep -Fxq 'schedule: a push to main runs Kind (main-push-switch.sh); the schedule runs nothing' \
  "$TMP/schedule.stderr"
# The checked-in tree schedules as its own switch says.
if [ -n "$MAIN_PUSH_KIND" ]; then
  schedule_twin="$SELECTOR_KIND_ON"
else
  schedule_twin="$SELECTOR_KIND_OFF"
fi
[ "$(schedule_paths "$SELECTOR" apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts)" \
  = "$(schedule_paths "$schedule_twin" apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts)" ] || {
  echo 'the checked-in selector does not schedule as its switch says' >&2
  exit 1
}
# Dispatch: a scheduled selection dispatches the Kind shards alone, even with
# every artifact fact affected, and an unchanged one dispatches nothing.
for scheduled_selection in '|valid:v3|kind|scheduled|complete|' '|valid:v3|scheduled|complete|'; do
  : > "$TMP/schedule-dispatch.out"
  VERIFICATION_SELECTION="$scheduled_selection" VERIFICATION_TESTED_TREE_RECEIPT=fallback \
    CW_PACKAGE_SELECTED=true DESKTOP_PACKAGE_SELECTED=true \
    GITHUB_OUTPUT="$TMP/schedule-dispatch.out" \
    "$ROOT/scripts/ci/select/emit-verification-matrices.sh"
  dispatched_groups="$({ grep '=true$' "$TMP/schedule-dispatch.out" || true; } | tr '\n' ' ')"
  if [[ "$scheduled_selection" == *'|kind|'* ]]; then
    [ "$dispatched_groups" = 'edge_kind_expected=true ' ] || {
      echo "a scheduled Kind run dispatched more than Kind: $dispatched_groups" >&2; exit 1; }
  else
    [ -z "$dispatched_groups" ] || {
      echo "an unchanged scheduled run dispatched $dispatched_groups" >&2; exit 1; }
  fi
done

# The one switch (main-push-switch.sh, owner decision 2026-10-20). False: a
# push to main selects no Kind and says so in one plain line; Edge static
# verification and the local mode stay. True: today's selection, Kind
# included. Nothing else differs, and no other event reads it.
deferred_line='main push: Kind deferred to the scheduled or dispatched Kind run (owner decision 2026-10-20)'
switch_push() { # SELECTOR PATH... -> output; stderr in $TMP/switch.stderr
  local selector="$1"
  shift
  printf '%s\n' "$@" > "$TMP/switch.paths"
  env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH PATH="$EDGELESS_CARGO:$PATH" \
    GITHUB_EVENT_NAME=push GITHUB_REF=refs/heads/main KIND_E2E_OPT_IN=false \
    "$selector" "$TMP/switch.paths" 2>"$TMP/switch.stderr"
}
output="$(switch_push "$SELECTOR_KIND_OFF" apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts)"
assert_tokens main_push_switch_off 'edge_kind kind_tools policy web' "$output"
assert_contract_field main_push_switch_off "$output" required_local_mode default
[ "$(grep -Fxc "$deferred_line" "$TMP/switch.stderr")" = 1 ] || {
  echo 'a main push that deferred Kind did not say so in one line' >&2; exit 1; }
output="$(switch_push "$SELECTOR_KIND_ON" apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts)"
assert_tokens main_push_switch_on 'edge_kind kind kind_tools policy web' "$output"
assert_contract_field main_push_switch_on "$output" required_local_mode default
! grep -Fq 'Kind deferred' "$TMP/switch.stderr" || {
  echo 'a main push that runs Kind said it deferred Kind' >&2; exit 1; }
# A push that selects no Kind defers nothing and says nothing.
assert_tokens main_push_switch_off_docs policy \
  "$(switch_push "$SELECTOR_KIND_OFF" docs/dev/AGENT-WORKFLOW.md)"
! grep -Fq 'Kind deferred' "$TMP/switch.stderr" || {
  echo 'a main push without Kind said it deferred Kind' >&2; exit 1; }
# The checked-in tree behaves as its own switch says.
assert_tokens main_push_switch_checked_in "edge_kind ${MAIN_PUSH_KIND} kind_tools policy web" \
  "$(switch_push "$SELECTOR" apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts)"
# Pull requests (ci-full, kind-e2e) and dispatches read no switch.
for switch_selector in "$SELECTOR_KIND_ON" "$SELECTOR_KIND_OFF"; do
  [ "$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH PATH="$EDGELESS_CARGO:$PATH" \
      GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/7/head KIND_E2E_OPT_IN=true \
      "$switch_selector" "$TMP/switch.paths" 2>/dev/null)" \
    = "$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH PATH="$EDGELESS_CARGO:$PATH" \
      GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/7/head KIND_E2E_OPT_IN=true \
      "$SELECTOR" "$TMP/switch.paths" 2>/dev/null)" ] || {
    echo 'the main-push switch changed a pull request' >&2; exit 1; }
  assert_tokens "dispatch_edge_kind_${switch_selector##*/switch-}" 'edge_kind kind kind_tools' \
    "$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch VERIFICATION_REQUEST=edge_kind \
      "$switch_selector")"
done
# Any other value fails without a machine-readable selection.
invalid_switch_selector="$(selector_with_switch maybe)"
if switch_push "$invalid_switch_selector" docs/dev/AGENT-WORKFLOW.md >"$TMP/switch-invalid.out"; then
  echo 'the selector accepted an invalid main-push switch' >&2
  exit 1
fi
[ ! -s "$TMP/switch-invalid.out" ] && grep -Fq 'MAIN_PUSH_RUNS_KIND_AND_DRY_RUN must be true or false' "$TMP/switch.stderr"

# Workflow contract: ten bounded capability groups use trusted server-side job
# conditions. Forgejo therefore gives an omitted group a terminal skipped result
# without assigning its fixed-profile runner.
while IFS='|' read -r job_id job_name runner expectation_name; do
  block="$TMP/${job_id}.yaml"
  awk -v wanted="$job_id" '
    $0 == "  " wanted ":" { capture = 1 }
    capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ && $0 != "  " wanted ":" { exit }
    capture { print }
  ' "$WORKFLOW" > "$block"
  grep -qF "  ${job_id}:" "$block"
  grep -qF "    name: ${job_name}" "$block"
  if [ "$runner" = heavy ]; then runner="$HEAVY_RUNS_ON"; fi
  if [ "$runner" = metal-main ]; then
    runner="$METAL_MAIN_RUNS_ON"
    grep -qxF "$METAL_CARGO_BOUND" "$block"
  fi
  if [ "$runner" = build-main ]; then
    runner="$RUNS_ON_BUILD"
    grep -qxF "$METAL_CARGO_BOUND" "$block"
  fi
  grep -qxF "    runs-on: ${runner}" "$block"
  if [ "$job_id" = edge-kind ]; then
    # Its optional producer dependencies need an always() condition so edge-
    # only selection still runs. The executable workflow fixture also proves
    # every selected Kind producer must succeed before this job can run.
    grep -qF "needs.verification-selection.outputs.edge_kind_expected == 'true'" "$block"
    python3 -B "$ROOT/scripts/ci/tests/test-kind-build-workflow.py"
  elif [ "$job_id" = database ]; then
    # Compile once (infra#1632): it runs the compile job's database archives
    # when that job built them, and compiles itself when it was not dispatched.
    grep -qF "    needs: [verification-selection, rust-compile]" "$block"
    grep -qF "needs.verification-selection.outputs.database_expected == 'true'" "$block"
    grep -qF "needs.rust-compile.result != 'failure' && needs.rust-compile.result != 'cancelled'" "$block"
    # A fetch miss (no archive built, no store, or evicted) builds in place:
    # the fetch never fails on a miss, the compile steps run when the archives
    # are not ready, and the lanes take the archives only when they are.
    # shellcheck disable=SC2016 # The workflow text holds literal shell variables.
    grep -qF 'run: scripts/ci/setup/fetch-test-archive.sh --or-build "$ARCHIVE_SHA256" "$RUNNER_TEMP/database.tar"' "$block"
    [ "$(grep -cF "steps.database-archives.outputs.ready != 'true' }}" "$block")" -eq 3 ]
    grep -qF "RUST_DATABASE_ARCHIVES: \${{ steps.database-archives.outputs.ready == 'true' && format('{0}/database-archives', runner.temp) || '' }}" "$block"
    if grep -qF 'BUILD_ONCE' "$block"; then
      echo 'database: the archive path must follow the fetch, not the compile job alone' >&2
      exit 1
    fi
  elif [ "$job_id" = rust-packages ]; then
    # Compile once (infra#1632): it runs the compile job's test archive, so it
    # needs that job's success, except on a main push, which compiles here.
    grep -qF "    needs: [verification-selection, rust-compile]" "$block"
    grep -qF "needs.verification-selection.outputs.rust_shards_expected == 'true'" "$block"
    grep -qF "(needs.rust-compile.result == 'success' || (github.event_name == 'push' && github.ref == 'refs/heads/main'))" "$block"
  else
    grep -qF \
      "    if: \${{ needs.verification-selection.outputs.${expectation_name}_expected == 'true' }}" \
      "$block"
  fi
  if [ "$job_id" = edge-kind ]; then
    # The Kind gate shards its suites across one four-leg matrix (proven in
    # detail by the executable workflow fixture below); every other capability
    # group stays a single dispatch with no empty-matrix dependency.
    grep -qF '    strategy:' "$block" || {
      echo 'edge-kind: the Kind shard matrix is missing' >&2
      exit 1
    }
  elif grep -qF '    strategy:' "$block"; then
    echo "${job_id}: capability dispatch retained an empty-matrix dependency" >&2
    exit 1
  fi
done <<'EOF'
policy|Policy verification|metal-main|policy
standard|Standard verification|metal-main|standard
tooling|Tooling / delivery contract verification|metal-main|tooling
rust-compile|Compile every Rust target|build-main|rust_compile
rust-packages|Rust / transport packages|metal-main|rust_shards
rust-features|Rust / transport feature graphs|metal-main|rust_shards
rust-transport|Rust / transport verification|metal-main|rust_transport
database|Database verification|metal-main|database
services-control|Service control-plane verification|metal-main|services_control
services-runtime|Service runtime-plane verification|metal-main|services_runtime
edge-kind|Edge / Kind verification|heavy|edge_kind
EOF

policy_block="$TMP/policy.yaml"
tooling_block="$TMP/tooling.yaml"
grep -Fq 'run-product-verification.sh policy-core' "$policy_block" || {
  echo 'policy job does not own only the fast policy core' >&2
  exit 1
}
# shellcheck disable=SC2016 # Match the workflow's literal expression.
grep -Fq 'VERIFICATION_SELECTION: ${{ needs.verification-selection.outputs.selection }}' \
    "$policy_block" || {
  echo 'policy core does not see the trusted selection, so it cannot omit CI-script tests' >&2
  exit 1
}
grep -Fq 'run-product-verification.sh policy-shell' "$tooling_block" || {
  echo 'heavy tooling job does not own selected ShellCheck' >&2
  exit 1
}
grep -Fq "contains(needs.verification-selection.outputs.selection, '|policy_shell|')" \
  "$tooling_block" || {
  echo 'heavy ShellCheck lacks trusted policy_shell dispatch' >&2
  exit 1
}

selection_block="$TMP/verification-selection.yaml"
awk '
  $0 == "  verification-selection:" { capture = 1 }
  capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ && $0 != "  verification-selection:" { exit }
  capture { print }
' "$WORKFLOW" > "$selection_block"
grep -qF 'name: Emit trusted capability dispatch decisions' "$selection_block"
grep -qF "trusted_dispatch_selector='.trusted-ci-policy/scripts/ci/select/emit-verification-matrices.sh'" \
  "$selection_block"
grep -qF 'run every group so candidate code cannot omit required work' \
  "$selection_block"
grep -qF 'policy standard tooling rust_compile rust_shards rust_transport database' "$selection_block" || {
  echo 'the dispatch bootstrap does not run the compile and shard groups' >&2
  exit 1
}
# shellcheck disable=SC2016 # Match the literal Actions expression.
grep -qxF '      rust_shards_expected: ${{ steps.dispatch.outputs.rust_shards_expected || steps.dispatch.outputs.rust_transport_expected }}' \
  "$selection_block" || {
  echo 'rust_shards_expected must fall back to the Rust group for an older trusted base' >&2
  exit 1
}
for expectation_name in policy standard tooling rust_compile rust_transport database \
    services_control services_runtime edge_kind; do
  grep -qF "${expectation_name}_expected: \${{ steps.dispatch.outputs.${expectation_name}_expected }}" \
    "$selection_block"
  if grep -qF "${expectation_name}_matrix:" "$selection_block"; then
    echo "${expectation_name}: selection output retained empty-matrix transport" >&2
    exit 1
  fi
done

# Heavy jobs share the queue-driven disposable DinD runner pool. Keep ordinary
# task ceilings at 30 minutes. The selected workspace path performs two cold
# image builds, while Rust/transport may seed the complete workspace and
# desktop compiler cache. Those two jobs retain 55-minute ceilings. The Kind
# gate shards its suites across four parallel per-cluster legs; each shard's
# 45-minute ceiling holds the longest leg (setup plus dashboard browser) far
# below the 90-minute heavy budget.
for job_id in standard tooling rust-compile rust-packages rust-features database services-control services-runtime; do
  block="$TMP/${job_id}.yaml"
  if [ ! -s "$block" ]; then
    awk -v wanted="$job_id" '
      $0 == "  " wanted ":" { capture = 1 }
      capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ && $0 != "  " wanted ":" { exit }
      capture { print }
    ' "$WORKFLOW" > "$block"
  fi
  grep -qF '    timeout-minutes: 30' "$block" || {
    echo "${job_id}: heavy job must retain the 30-minute task ceiling" >&2
    exit 1
  }
done

rust_transport_block="$TMP/rust-transport.yaml"
grep -qF '    timeout-minutes: 55' "$rust_transport_block" || {
  echo 'rust-transport: cold-cache ceiling must remain 55 minutes' >&2
  exit 1
}

edge_kind_block="$TMP/edge-kind.yaml"
edge_kind_timeout_valid() {
  # Exact equality also rejects duplicate, absent and nonnumeric declarations.
  [ "$(sed -n 's/^    timeout-minutes: //p' "$1")" = 45 ]
}
edge_kind_timeout_valid "$edge_kind_block" || {
  echo 'edge-kind: every shard must retain the 45-minute ceiling within the 90-minute worker cleanup margin' >&2
  exit 1
}
# Protect the observed old deadline failure and both missing/unbounded limits.
# These are mutations of the actual job block, not a second workflow fixture.
for invalid_timeout in 55 85 90 120 0 null; do
  sed "s/^    timeout-minutes: 45$/    timeout-minutes: $invalid_timeout/" \
    "$edge_kind_block" > "$TMP/edge-kind-invalid.yaml"
  if edge_kind_timeout_valid "$TMP/edge-kind-invalid.yaml"; then
    echo "edge-kind: timeout guard accepted $invalid_timeout" >&2
    exit 1
  fi
done
sed '/^    timeout-minutes:/d' "$edge_kind_block" > "$TMP/edge-kind-invalid.yaml"
if edge_kind_timeout_valid "$TMP/edge-kind-invalid.yaml"; then
  echo 'edge-kind: timeout guard accepted an absent deadline' >&2
  exit 1
fi
sed '/^    timeout-minutes: 45$/p' "$edge_kind_block" > "$TMP/edge-kind-invalid.yaml"
if edge_kind_timeout_valid "$TMP/edge-kind-invalid.yaml"; then
  echo 'edge-kind: timeout guard accepted a duplicate deadline' >&2
  exit 1
fi

policy_block="$TMP/policy.yaml"
grep -qF '    timeout-minutes: 30' "$policy_block"
grep -qF 'name: Verify sealed policy tools' "$policy_block"
grep -qF 'name: Run Policy' "$policy_block"
grep -A1 -F 'name: Run Policy' "$policy_block" \
  | grep -qF "contains(needs.verification-selection.outputs.selection, '|policy|')"
if grep -Eq 'run:.*docker|setup-bun|setup-go|curl |wget ' "$policy_block"; then
  echo 'policy: sealed policy job gained a Docker or network-tool setup dependency' >&2
  exit 1
fi

grep -qF '    timeout-minutes: 30' "$TMP/policy.yaml" || {
  echo 'policy: heavy job lost its measured bounded task ceiling' >&2
  exit 1
}

for job_id in policy standard tooling rust-compile rust-packages rust-features rust-transport database services-control services-runtime edge-kind; do
  block="$TMP/${job_id}.yaml"
  grep -qF 'name: Reuse exact PR-head content verification' "$block"
  grep -qF "if: \${{ needs.verification-selection.outputs.tested_tree_receipt == 'accepted' }}" \
    "$block"
  step_count="$(grep -Ec '^      - (name:|uses:)' "$block")"
  guard_count="$(grep -Ec '^        if:' "$block")"
  if [ "$step_count" != "$guard_count" ]; then
    echo "${job_id}: every capability step must have a tested-tree guard" >&2
    exit 1
  fi
  if grep -E '^        if:' "$block" \
      | grep -vF 'needs.verification-selection.outputs.tested_tree_receipt' \
      >/dev/null; then
    echo "${job_id}: capability step omits the tested-tree guard" >&2
    exit 1
  fi
done

# The shards are dispatched by rust_shards_expected, exactly the rust or
# transport selection their run step requires.
for job_id in rust-packages rust-features; do
  block="$TMP/${job_id}.yaml"
  run_guard="$(awk '/^      - name: Run the Rust .* shard$/ { getline; print; exit }' "$block")"
  for token in rust transport; do
    grep -qF "contains(needs.verification-selection.outputs.selection, '|${token}|')" <<<"$run_guard" || {
      echo "${job_id}: shard run step must require a ${token} selection" >&2
      exit 1
    }
  done
done

# A failed group reports "failure" with its whole log: no job cancels its own
# run. A cancel turned failures into "cancelled" and cut the failing job's log
# (infra#1229, #3119).
if grep -qE '/actions/runs/[^ ]*/cancel' "$WORKFLOW"; then
  echo 'ci.yaml: a job cancels its own run' >&2
  exit 1
fi

# Closing or merging a pull request cancels its CI in flight: the workflow
# takes the closed event into the same concurrency group, and the run it
# starts takes no runner (#2892). Old behaviour: a merged pull request's run
# kept its metal guests until it finished.
python3 - "$WORKFLOW" <<'PY'
import sys
import yaml

ci_path = sys.argv[1]
workflow = yaml.safe_load(open(ci_path, encoding="utf-8"))
# PyYAML reads the bare key `on` as True.
trigger = (workflow.get("on") or workflow.get(True))["pull_request"]
if "closed" not in trigger["types"]:
    raise SystemExit(f"{ci_path}: a closed pull request does not cancel its run")
ci = yaml.safe_load(open(ci_path, encoding="utf-8"))
if not ci["concurrency"]["cancel-in-progress"].startswith("${{ github.event_name == 'pull_request'"):
    raise SystemExit("ci.yaml: pull request runs no longer cancel their predecessor")
jobs = ci["jobs"]
if jobs["verification-selection"].get("if") != "${{ github.event.action != 'closed' }}":
    raise SystemExit("ci.yaml: a closed pull request must start no verification")
if jobs["required-verification"].get("if") != "${{ always() && github.event.action != 'closed' }}":
    raise SystemExit("ci.yaml: Required verification must not run for a closed pull request")
for job_id, job in jobs.items():
    if job_id in ("verification-selection", "required-verification"):
        continue
    if "verification-selection" not in job.get("needs", []):
        raise SystemExit(f"ci.yaml: {job_id} could run for a closed pull request")
    if "always()" in str(job.get("if", "")) and "needs.verification-selection.result == 'success'" not in job["if"]:
        raise SystemExit(f"ci.yaml: {job_id} runs always() without a successful selection")
PY
# The local merge check and its workflow are gone (#3119 step 2.3): pull-request
# CI is the merge gate.
for retired in .gitea/workflows/merge-check.yaml scripts/ci/receipts/local-prepush-receipt.py \
    scripts/ci/receipts/ci-merge-check.py scripts/ci/select/merge-gate.tsv \
    scripts/ci/select/merge-gate.py scripts/ci/plan/verified-base.py; do
  [ ! -e "$ROOT/$retired" ] || {
    echo "the retired local merge gate remains: $retired" >&2
    exit 1
  }
done
if rg -n -- '--for-merge|--emit-receipt|CODEWIRE_PREFLIGHT_MODE' "$ROOT/scripts/dev" "$ROOT/.githooks"; then
  echo 'the local merge gate or its receipts remain' >&2
  exit 1
fi

control_block="$TMP/services-control.yaml"
runtime_block="$TMP/services-runtime.yaml"
grep -qF 'name: Resolve service control-plane scope' "$control_block"
grep -qF 'name: Service control-plane integration not selected' "$control_block"
grep -qF 'name: Resolve service runtime-plane scope' "$runtime_block"
grep -qF 'name: Service runtime-plane integration not selected' "$runtime_block"
for block in "$control_block" "$runtime_block"; do
  grep -qF 'id: service-scope' "$block"
  grep -qF 'VERIFICATION_SELECTION: ${{ needs.verification-selection.outputs.selection }}' "$block"
  grep -qF "steps.service-scope.outputs.selected == 'true'" "$block"
  if grep -qF "contains(needs.verification-selection.outputs.selection, '|service_integration|')" "$block"; then
    echo "$(basename "$block"): coarse service_integration gating remains" >&2
    exit 1
  fi
done
for token in service_idp service_coordinator service_billing service_connectcore; do
  grep -qF "*'|${token}|'*" "$control_block" || {
    echo "services-control: scope resolver omits ${token}" >&2
    exit 1
  }
  grep -qF "$token" "$ROOT/scripts/dev/preflight.sh" || {
    echo "preflight: control-plane scope omits ${token}" >&2
    exit 1
  }
done
for token in service_orchestration service_nats; do
  grep -qF "*'|${token}|'*" "$runtime_block" || {
    echo "services-runtime: scope resolver omits ${token}" >&2
    exit 1
  }
  grep -qF "$token" "$ROOT/scripts/dev/preflight.sh" || {
    echo "preflight: runtime-plane scope omits ${token}" >&2
    exit 1
  }
done
for token in service_orchestration service_nats; do
  if grep -qF "*'|${token}|'*" "$control_block"; then
    echo "services-control: scope resolver includes runtime-only ${token}" >&2
    exit 1
  fi
done
for token in service_idp service_coordinator service_billing service_connectcore; do
  if grep -qF "*'|${token}|'*" "$runtime_block"; then
    echo "services-runtime: scope resolver includes control-only ${token}" >&2
    exit 1
  fi
done

extract_service_scope_script() {
  local block="$1" script="$2"
  awk '
    /name: Resolve service .* scope/ { resolver = 1 }
    resolver && /^        run: \|$/ { capture = 1; next }
    capture && /^      - / { exit }
    capture { sub(/^          /, ""); print }
  ' "$block" > "$script"
  [ -s "$script" ] || {
    echo "$(basename "$block"): scope resolver script is absent" >&2
    exit 1
  }
  bash -n "$script"
}

run_service_scope_case() {
  local name="$1" script="$2" selection="$3" expected="$4"
  local output="$TMP/${name}.scope-output"
  : > "$output"
  VERIFICATION_SELECTION="$selection" GITHUB_OUTPUT="$output" bash "$script"
  grep -Fxq "selected=${expected}" "$output" || {
    echo "${name}: expected selected=${expected}" >&2
    exit 1
  }
}

control_scope_script="$TMP/services-control-scope.sh"
runtime_scope_script="$TMP/services-runtime-scope.sh"
extract_service_scope_script "$control_block" "$control_scope_script"
extract_service_scope_script "$runtime_block" "$runtime_scope_script"
run_service_scope_case control_selected "$control_scope_script" \
  '|valid:v3|service_billing|service_integration|complete|' true
run_service_scope_case control_rejects_runtime "$control_scope_script" \
  '|valid:v3|service_integration|service_orchestration|complete|' false
run_service_scope_case runtime_selected "$runtime_scope_script" \
  '|valid:v3|service_integration|service_orchestration|complete|' true
run_service_scope_case runtime_rejects_control "$runtime_scope_script" \
  '|valid:v3|service_billing|service_integration|complete|' false
run_service_scope_case both_reject_unscoped "$control_scope_script" \
  '|valid:v3|service_integration|complete|' false
run_service_scope_case both_reject_unscoped_runtime "$runtime_scope_script" \
  '|valid:v3|service_integration|complete|' false
run_service_scope_case temporal_modifier_rejects_control "$control_scope_script" \
  '|valid:v3|service_integration|service_temporal|complete|' false
run_service_scope_case temporal_modifier_rejects_runtime "$runtime_scope_script" \
  '|valid:v3|service_integration|service_temporal|complete|' false
run_service_scope_case billing_temporal_selects_control "$control_scope_script" \
  '|valid:v3|service_billing|service_integration|service_temporal|complete|' true
run_service_scope_case orchestration_temporal_selects_runtime "$runtime_scope_script" \
  '|valid:v3|service_integration|service_orchestration|service_temporal|complete|' true

selection_block="$TMP/verification-selection.yaml"
awk '
  $0 == "  verification-selection:" { capture = 1 }
  capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ && $0 != "  verification-selection:" { exit }
  capture { print }
' "$WORKFLOW" > "$selection_block"
grep -qxF "    runs-on: ${RUNS_ON_UNTRUSTED_LIGHT}" "$selection_block" || {
  echo 'verification selection does not use the live non-privileged validation profile' >&2
  exit 1
}
if grep -Eq '^    runs-on: (ubuntu-latest|untrusted-validation|ci-kind|kind-e2e|trusted-plan|protected-delivery|protected-dev-observer)$' "$WORKFLOW"; then
  echo 'Codewire CI still depends on a legacy compatibility label' >&2
  exit 1
fi
# Nine heavy groups on the metal labels, and Rust compilation on the build
# runner except on a main push (compile once, infra#1632).
[[ "$(grep -Fxc "    runs-on: ${RUNS_ON_BUILD}" "$WORKFLOW")" -eq 1 ]] || {
  echo 'Codewire CI requires Rust compilation on the build runner' >&2
  exit 1
}
[[ "$(grep -Fxc "    runs-on: ${METAL_MAIN_RUNS_ON}" "$WORKFLOW")" -eq 9 ]] || {
  echo 'Codewire CI requires its nine ordinary heavy groups (policy included) on the metal labels' >&2
  exit 1
}
[[ "$(grep -Fxc "$METAL_CARGO_BOUND" "$WORKFLOW")" -eq 10 ]] || {
  echo 'each metal group must bound its cargo jobs to its guest memory' >&2
  exit 1
}
[[ "$(grep -Fxc "    runs-on: ${HEAVY_RUNS_ON}" "$WORKFLOW")" -eq 5 ]] || {
  echo 'Codewire CI requires Edge / Kind and four parallel Kind producers, each selecting the main-first cloud Heavy label until Kind runs in a metal guest' >&2
  exit 1
}
if grep -Eq '^ *runs-on: [^$]' "$WORKFLOW"; then
  echo 'a Codewire CI job names a literal runner label instead of its repository Actions variable (docs/dev/CI-CONFIGURATION.md)' >&2
  exit 1
fi
# Selection, aggregation, the final Dev delivery trigger (#2892) and the four
# links of the fail-fast watcher chain (infra#1632; owner, 2026-10-25).
[[ "$(grep -Fxc "    runs-on: ${RUNS_ON_UNTRUSTED_LIGHT}" "$WORKFLOW")" -eq 7 ]] || {
  echo 'Codewire CI has not assigned selection, aggregation, the Dev delivery trigger and the four fail-fast watcher links to the untrusted light runner' >&2
  exit 1
}
for output in selector_version classification selection required_local_mode \
    ci_head_commit ci_head_tree \
    cw_package_state cw_package_selected desktop_package_state \
    desktop_package_selected \
    kind_workspace_source \
    tested_tree_receipt tested_tree_reason \
    tested_tree_pr tested_tree_head tested_tree_run; do
  grep -qF "      ${output}:" "$selection_block" || {
    echo "verification selection omits ${output}" >&2
    exit 1
  }
done
grep -qF 'name: Verify exact tested-tree receipt' "$selection_block"
grep -qF 'GITEA_TOKEN: ${{ github.token }}' "$selection_block"
grep -qF "receipt_checker='.trusted-ci-policy/scripts/ci/receipts/verify-tested-tree-receipt.sh'" \
  "$selection_block"
grep -qF 'ref: ${{ github.event.pull_request.base.sha }}' "$selection_block"
grep -qF 'path: .trusted-ci-policy' "$selection_block"
grep -qF 'persist-credentials: false' "$selection_block"
grep -qF "trusted_planner='.trusted-ci-policy/scripts/ci/plan/planner.py'" \
  "$selection_block"
grep -qF "capability_selector='.trusted-ci-policy/scripts/ci/select/select-verification.sh'" \
  "$selection_block"
grep -qF 'ref: ${{ github.event.before }}' "$selection_block"
planner_toolchain_line="$(grep -n -m1 'name: Verify sealed Rust toolchain for trusted artifact planning' \
  "$selection_block" | cut -d: -f1)"
planner_select_line="$(grep -n -m1 'name: Select capabilities and artifact facts' \
  "$selection_block" | cut -d: -f1)"
test -n "$planner_toolchain_line"
test -n "$planner_select_line"
test "$planner_toolchain_line" -lt "$planner_select_line"
grep -A2 -F 'name: Verify sealed Rust toolchain for trusted artifact planning' \
  "$selection_block" | grep -qF "if: \${{ github.event_name == 'pull_request' }}"
grep -A2 -F 'name: Verify sealed Rust toolchain for trusted artifact planning' \
  "$selection_block" | grep -qF 'run: scripts/ci/setup/assert-ci-runner-image.sh'
grep -qF "jq -e '.degraded_reasons | length > 0'" "$selection_block"
grep -qF "jq -c '.degraded_reasons'" "$selection_block"
grep -qF "trusted_adapter='.trusted-ci-policy/scripts/ci/plan/apply-verification-plan.py'" \
  "$selection_block"
grep -qF 'python3 "$trusted_adapter" --plan "$plan_output"' \
  "$selection_block"
# A main push plans its artifact facts with the previous main's trusted
# policy (#2897); a dispatch, an older policy or a planner failure keeps every
# artifact selected, and only a push receives the job token for that.
grep -qF "main_push_planner='.trusted-ci-policy/scripts/ci/plan/plan-main-push.py'" \
  "$selection_block"
grep -qF 'if [ "$GITHUB_EVENT_NAME" = push ] && [ -f "$main_push_planner" ]' "$selection_block"
grep -qF -- '--before "$PUSH_BEFORE_SHA"' "$selection_block"
# A push to main selects from the newest verified main commit, or everything,
# and a receipt stands only on that commit (#3176).
grep -qF 'python3 -I -B scripts/ci/plan/main-ci-verdict.py base' "$selection_block"
grep -qF 'PUSH_BEFORE_SHA="$selector_before" PUSH_BASE_UNVERIFIED="$push_base_unverified"' "$selection_block"
grep -qF "printf 'push_verified_base=%s\\n' \"\$verified_base\" >> \"\$workflow_output\"" "$selection_block"
grep -qF 'PUSH_VERIFIED_BASE: ${{ steps.select.outputs.push_verified_base }}' "$selection_block"
grep -A4 -F 'python3 scripts/ci/plan/apply-verification-plan.py' "$selection_block" \
  | grep -qF -- '--unclassified'
grep -qF "GITEA_TOKEN: \${{ github.event_name == 'push' && github.token || '' }}" "$selection_block"
python3 "$ROOT/scripts/ci/plan/tests/test_plan_main_push.py"
# Main CI's verdict, and the final job that starts Dev delivery from it (#2892).
python3 -B "$ROOT/scripts/ci/plan/tests/test_main_ci_verdict.py"
python3 -B "$ROOT/scripts/ci/tests/test-rerun-dev-publish.py"
python3 -B "$ROOT/scripts/ci/tests/test-cancel-superseded-deliveries.py"
# A pull request's run stops at its first failed job (infra#1632).
python3 -B "$ROOT/scripts/ci/tests/test-fail-fast-watch.py"
grep -qF "grep -Fxq 'selector_version=v3'" "$selection_block"
if grep -qF 'selector_version=v2' "$selection_block" \
    || grep -qF 'One-time contract bridge' "$selection_block"; then
  echo 'verification selection retains a superseded v2 transition bridge' >&2
  exit 1
fi
grep -qF 'name: Run artifact-selected desktop package' "$WORKFLOW"
grep -qF "VERIFICATION_SELECTION: '|valid:v3|rust_pkg_codewire_desktop|complete|'" \
  "$WORKFLOW"

python3 "$ROOT/scripts/ci/plan/tests/test_planner.py" \
  PlannerFixtureTests.test_go_sdk_only_change_emits_unselected_cw_and_desktop_outputs \
  PlannerFixtureTests.test_missing_cargo_fails_closed_with_diagnostic

tooling_block="$TMP/tooling.yaml"
deploy_toolchain_line="$(grep -n -m1 'name: Verify sealed delivery-contract tools' \
  "$tooling_block" | cut -d: -f1)"
deploy_run_line="$(grep -n -m1 'name: Run Deploy' "$tooling_block" | cut -d: -f1)"
test -n "$deploy_toolchain_line"
test -n "$deploy_run_line"
test "$deploy_toolchain_line" -lt "$deploy_run_line"
grep -A2 -F 'name: Verify sealed delivery-contract tools' \
  "$tooling_block" | grep -qF "contains(needs.verification-selection.outputs.selection, '|deploy|')"

if grep -qE '^[[:space:]]*permissions:' "$WORKFLOW"; then
  echo 'product CI must not declare GitHub-only permissions ignored by Forgejo' >&2
  exit 1
fi

top_level_jobs="$(awk '
  /^jobs:$/ { in_jobs = 1; next }
  in_jobs && /^  [A-Za-z0-9_-]+:$/ { count++ }
  END { print count + 0 }
' "$WORKFLOW")"
if [ "$top_level_jobs" != 22 ]; then
  echo "product CI defines ${top_level_jobs} jobs; expected selector, eleven groups, four Kind producers, aggregate, the Dev delivery trigger and four fail-fast watcher links" >&2
  exit 1
fi
for legacy_job in contracts rust go-support web sdk-go sdk-ts sdk-python \
    service-integration transport release deploy security; do
  if grep -qF "  ${legacy_job}:" "$WORKFLOW"; then
    echo "legacy per-family runner job remains: ${legacy_job}" >&2
    exit 1
  fi
done

# CI packages no cw release asset: the release workflows build and package
# every target (#3119 A13).
if grep -qE '^  cw-release-assets:$|package-cw-release\.sh' "$WORKFLOW"; then
  echo 'product CI still packages cw release assets' >&2
  exit 1
fi

standard_block="$TMP/standard.yaml"
bun_setup_condition="$(grep -A1 -F \
  'uses: noel/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6' \
  "$standard_block")"
if grep -qF "contains(needs.verification-selection.outputs.selection, '|policy|')" \
    <<<"$bun_setup_condition"; then
  echo 'standard: policy-only verification still installs Bun' >&2
  exit 1
fi
for token in contracts web; do
  grep -qF "contains(needs.verification-selection.outputs.selection, '|${token}|')" \
    <<<"$bun_setup_condition" || {
    echo "standard: Bun setup omits ${token}" >&2
    exit 1
  }
done

web_run_line="$(grep -n -m1 'name: Run Web' "$standard_block" | cut -d: -f1)"
web_run_block="$(sed -n "${web_run_line},$((web_run_line + 6))p" "$standard_block")"
grep -qF 'VERIFICATION_SELECTION: ${{ needs.verification-selection.outputs.selection }}' \
  <<<"$web_run_block" || {
  echo 'standard: Web does not receive its exact selection' >&2
  exit 1
}
grep -qF 'CODEWIRE_DASHBOARD_IMAGE_DEFERRED:-false' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh" || {
  echo 'standard: Web cannot leave image work to Dev delivery' >&2
  exit 1
}
grep -qF '    run_dashboard_image' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh" || {
  echo 'local Web verification lost its standalone image gate' >&2
  exit 1
}
grep -A4 -F 'name: Run Web' "$WORKFLOW" \
  | grep -qF 'CODEWIRE_DASHBOARD_IMAGE_DEFERRED: "true"'

for contract in \
    'Run Contracts|contracts' \
    'Run Go support|go_support' \
    'Run Web|web' \
    'Run Docs|docs' \
    'Run SDK Go|sdk_go' \
    'Run SDK TypeScript|sdk_ts' \
    'Run SDK Python|sdk_python' \
    'Run iOS package tests in the pinned Swift image|ios'; do
  step_name="${contract%%|*}"
  token="${contract##*|}"
  step_condition="$(grep -A1 -F -- "- name: ${step_name}" "$standard_block")"
  grep -qF "contains(needs.verification-selection.outputs.selection, '|${token}|')" \
    <<<"$step_condition" || {
    echo "standard: ${step_name} is not isolated to ${token}" >&2
    exit 1
  }
done

tooling_block="$TMP/tooling.yaml"
tooling_bun_setup="$(grep -A3 -F \
  'uses: noel/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6' \
  "$tooling_block" || true)"
if ! grep -qF "tested_tree_receipt != 'accepted' && contains(needs.verification-selection.outputs.selection, '|dev_smoke_script_tests|')" \
    <<<"$tooling_bun_setup" ||
   ! grep -qF "bun-version: '1.3.9'" <<<"$tooling_bun_setup"; then
  echo 'tooling: Dev smoke must provision pinned Bun in its own selected job' >&2
  exit 1
fi
tooling_bun_line="$(grep -n -m1 'uses: noel/setup-bun@' "$tooling_block" | cut -d: -f1)"
tooling_dev_smoke_line="$(grep -n -m1 'name: Run Dev smoke script tests' "$tooling_block" | cut -d: -f1)"
if [ "$tooling_bun_line" -ge "$tooling_dev_smoke_line" ]; then
  echo 'tooling: pinned Bun setup must precede Dev smoke execution' >&2
  exit 1
fi
for contract in \
    'Run confidential script tests|confidential_script_tests' \
    'Run Dev smoke script tests|dev_smoke_script_tests' \
    'Run delivery script tests|release' \
    'Run Deploy|deploy' \
    'Run Security|security'; do
  step_name="${contract%%|*}"
  token="${contract##*|}"
  step_condition="$(grep -A1 -F -- "- name: ${step_name}" "$tooling_block")"
  grep -qF "contains(needs.verification-selection.outputs.selection, '|${token}|')" \
    <<<"$step_condition" || {
    echo "tooling: ${step_name} is not isolated to ${token}" >&2
    exit 1
  }
done

ios_run_line="$(grep -n -m1 'name: Run iOS package tests' \
  "$standard_block" | cut -d: -f1)"
ios_run_block="$(sed -n "${ios_run_line},$((ios_run_line + 10))p" "$standard_block")"
grep -qF "contains(needs.verification-selection.outputs.selection, '|ios|')" \
  <<<"$ios_run_block" || {
  echo 'standard: iOS verification is not isolated to the iOS selection' >&2
  exit 1
}
grep -qF 'scripts/ci/verify/run-product-verification.sh ios-config' \
  <<<"$ios_run_block" || {
  echo 'standard: iOS callback configuration is not verified before package tests' >&2
  exit 1
}
grep -qF "docker build --file - apps/ios <<'DOCKERFILE'" <<<"$ios_run_block" || {
  echo 'standard: iOS package tests do not stream their package context to Docker' >&2
  exit 1
}
grep -qF 'swift@sha256:0ff707a48519cf1473616c759e019bcff21cfbafa3d2687bf8fd41a2757adc9a' \
  <<<"$ios_run_block" || {
  echo 'standard: iOS package tests do not use the pinned Swift image' >&2
  exit 1
}
grep -qF 'RUN swift test --scratch-path /tmp/codewire-ios-build' <<<"$ios_run_block" || {
  echo 'standard: iOS package tests must build outside the checkout' >&2
  exit 1
}
if grep -qF -- '--mount "type=bind' <<<"$ios_run_block"; then
  echo 'standard: iOS package tests must not assume the nested runner host path' >&2
  exit 1
fi
if grep -qF 'swift-actions/setup-swift@' "$standard_block"; then
  echo 'standard: iOS verification must not depend on an external Swift keyserver' >&2
  exit 1
fi

grep -qF '      - name: Verify sealed Rust toolchain' \
  "$standard_block" || {
  echo 'standard: Rust-backed transitional checks do not verify the sealed Rust toolchain' >&2
  exit 1
}
standard_toolchain_line="$(grep -n -m1 'name: Verify sealed Rust toolchain' \
  "$standard_block" | cut -d: -f1)"
contracts_run_line="$(grep -n -m1 'name: Run Contracts' \
  "$standard_block" | cut -d: -f1)"
if [ "$standard_toolchain_line" -ge "$contracts_run_line" ]; then
  echo 'standard: Rust toolchain must be verified before contract verification' >&2
  exit 1
fi
policy_toolchain_condition="$(grep -A1 -F \
  'name: Verify sealed policy tools' \
  "$policy_block")"
grep -qF "contains(needs.verification-selection.outputs.selection, '|policy|')" \
  <<<"$policy_toolchain_condition" || {
  echo 'policy: sealed tool check omits policy planner fixtures' >&2
  exit 1
}
standard_toolchain_condition="$(grep -A1 -F \
  'name: Verify sealed Rust toolchain' \
  "$standard_block")"
grep -qF "contains(needs.verification-selection.outputs.selection, '|contracts_proto|')" \
  <<<"$standard_toolchain_condition" || {
  echo 'standard: Rust toolchain omits Proto/Connect mode' >&2
  exit 1
}
go_support_run_line="$(grep -n -m1 'name: Run Go support' \
  "$standard_block" | cut -d: -f1)"
if [ "$standard_toolchain_line" -ge "$go_support_run_line" ]; then
  echo 'go-support: Rust toolchain must be verified before tailnet parity verification' >&2
  exit 1
fi
grep -qF "contains(needs.verification-selection.outputs.selection, '|go_tailnet|')" \
  <<<"$standard_toolchain_condition" || {
  echo 'standard: Rust toolchain omits Go tailnet parity mode' >&2
  exit 1
}
grep -qF "contains(needs.verification-selection.outputs.selection, '|go_consumer_interop|')" \
  <<<"$standard_toolchain_condition" || {
  echo 'standard: Rust toolchain omits generated-Go consumer interop' >&2
  exit 1
}
standard_protoc_line="$(grep -n -m1 \
  'name: Install pinned protoc for Rust-backed standard checks' \
  "$standard_block" | cut -d: -f1)"
if [ -z "$standard_protoc_line" ] || [ "$standard_protoc_line" -ge "$contracts_run_line" ] \
    || [ "$standard_protoc_line" -ge "$go_support_run_line" ]; then
  echo 'standard: pinned protoc must be installed before Rust-backed checks' >&2
  exit 1
fi
standard_protoc_condition="$(grep -A1 -F \
  'name: Install pinned protoc for Rust-backed standard checks' \
  "$standard_block")"
for token in contracts_proto go_tailnet go_consumer_interop; do
  grep -qF "contains(needs.verification-selection.outputs.selection, '|${token}|')" \
    <<<"$standard_protoc_condition" || {
    echo "standard: pinned protoc omits ${token}" >&2
    exit 1
  }
done
grep -qF 'protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip' \
  "$standard_block" || {
  echo 'standard: protoc archive is not pinned to the reviewed release' >&2
  exit 1
}
grep -qF \
  '6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7  /tmp/protoc.zip' \
  "$standard_block" || {
  echo 'standard: protoc archive checksum is not verified' >&2
  exit 1
}

rust_transport_block="$TMP/rust-transport.yaml"
for contract in 'Run selected Rust and transport|rust' 'Run selected Rust and transport|transport'; do
  step_name="${contract%%|*}"
  token="${contract##*|}"
  step_condition="$(grep -A1 -F -- "- name: ${step_name}" "$rust_transport_block")"
  grep -qF "contains(needs.verification-selection.outputs.selection, '|${token}|')" \
    <<<"$step_condition" || {
    echo "rust-transport: ${step_name} does not select ${token}" >&2
    exit 1
  }
done
rust_transport_protoc_line="$(grep -n -m1 \
  'name: Install pinned protoc for Rust and guest builds' \
  "$rust_transport_block" | cut -d: -f1)"
rust_transport_run_line="$(grep -n -m1 'name: Run selected Rust and transport' \
  "$rust_transport_block" | cut -d: -f1)"
if [ -z "$rust_transport_protoc_line" ] \
    || [ "$rust_transport_protoc_line" -ge "$rust_transport_run_line" ]; then
  echo 'rust-transport: pinned protoc must be installed before transport verification' >&2
  exit 1
fi
rust_transport_protoc_condition="$(grep -A1 -F \
  'name: Install pinned protoc for Rust and guest builds' \
  "$rust_transport_block")"
for token in rust transport transport_pkg_codewire_vmm_guest_probe; do
  grep -qF "contains(needs.verification-selection.outputs.selection, '|${token}|')" \
    <<<"$rust_transport_protoc_condition" || {
    echo "rust-transport: pinned protoc omits ${token} compilation" >&2
    exit 1
  }
done
grep -qF "needs.verification-selection.outputs.desktop_package_selected == 'true'" \
  <<<"$rust_transport_protoc_condition" || {
  echo 'rust-transport: pinned protoc omits desktop compilation' >&2
  exit 1
}
grep -qF 'protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip' \
  "$rust_transport_block" || {
  echo 'rust-transport: protoc archive is not pinned to the reviewed release' >&2
  exit 1
}
grep -qF \
  '6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7  /tmp/protoc.zip' \
  "$rust_transport_block" || {
  echo 'rust-transport: protoc archive checksum is not verified' >&2
  exit 1
}
grep -qF 'echo "$HOME/.proto-tools/protoc/bin" >> "$GITHUB_PATH"' \
  "$rust_transport_block" || {
  echo 'rust-transport: pinned protoc is not exported to later steps' >&2
  exit 1
}
grep -qF '"$HOME/.proto-tools/protoc/bin/protoc" --version' \
  "$rust_transport_block" || {
  echo 'rust-transport: pinned protoc is not verified through its exact path' >&2
  exit 1
}

database_block="$TMP/database.yaml"
services_control_block="$TMP/services-control.yaml"
services_runtime_block="$TMP/services-runtime.yaml"
for integration_block in "$database_block" "$services_control_block" "$services_runtime_block"; do
  grep -qF 'name: Start integration Postgres' "$integration_block"
  grep -qF "docker inspect --format '{{json .NetworkSettings.Networks}}'" \
    "$integration_block"
  grep -qF "| jq -er 'keys[]'" "$integration_block"
  if grep -qF '{{println $name}}' "$integration_block"; then
    echo 'integration network discovery can emit a phantom blank network' >&2
    exit 1
  fi
  grep -qF -- '--network-alias "$postgres_host"' "$integration_block"
  grep -qF 'echo "INTEGRATION_DOCKER_NETWORK=${networks[0]}" >> "$GITHUB_ENV"' \
    "$integration_block"
  if grep -qF -- '-p 127.0.0.1::5432' "$integration_block"; then
    echo 'integration job publishes Postgres onto the DinD sidecar loopback' >&2
    exit 1
  fi
  grep -qF 'name: Stop integration Postgres' "$integration_block"
done

# Match the workflow's value-blind JSON-key extraction. Docker appends a
# newline after its Go-template output; JSON parsing must still produce exactly
# one array element for one bounded network and reject zero or multiple names.
assert_network_count() {
  local payload="$1" expected="$2"
  local -a parsed=()
  mapfile -t parsed < <(printf '%s\n' "$payload" | jq -er 'keys[]')
  if [ "${#parsed[@]}" -ne "$expected" ]; then
    echo "network discovery count mismatch: expected=$expected actual=${#parsed[@]}" >&2
    exit 1
  fi
}
assert_network_count '{"WORKFLOW-bounded":{}}' 1
assert_network_count '{}' 0
assert_network_count '{"bridge":{},"WORKFLOW-bounded":{}}' 2
grep -qF 'name: Run Database' "$database_block"
grep -qF 'run: scripts/ci/verify/run-integration-verification.sh database' \
  "$database_block"
grep -qF 'name: Run Service integration' "$services_control_block"
grep -qF 'run: scripts/ci/verify/run-integration-verification.sh services-control' \
  "$services_control_block"
grep -qF 'name: Run Service integration' "$services_runtime_block"
grep -qF 'run: scripts/ci/verify/run-integration-verification.sh services-runtime' \
  "$services_runtime_block"

integration_runner="$ROOT/scripts/ci/verify/run-integration-verification.sh"
grep -qF -- '--network "$INTEGRATION_DOCKER_NETWORK"' "$integration_runner"
grep -qF -- '--network-alias "$INTEGRATION_NATS_HOST"' "$integration_runner"
grep -qF 'NATS_MONITOR_URL="http://${INTEGRATION_NATS_HOST}:8222/healthz"' \
  "$integration_runner"
grep -qF 'service_idp service_coordinator service_billing' \
  "$integration_runner"
grep -qF 'service_connectcore service_temporal)' "$integration_runner"
grep -qF 'service_orchestration service_nats service_temporal)' \
  "$integration_runner"
if rg -n 'run-integration-verification\.sh services([^_-]|$)|"\$INTEGRATION_RUNNER" services([^_-]|$)' \
    "$WORKFLOW" "$ROOT/scripts/dev"; then
  echo 'automatic verification retains the oversized combined service integration mode' >&2
  exit 1
fi

edge_kind_block="$TMP/edge-kind.yaml"
# Static edge checks run in tooling, so an edge-only selection starts no Kind leg.
grep -qF 'run: scripts/ci/verify/run-product-verification.sh edge' "$TMP/tooling.yaml"
if grep -qF 'run-product-verification.sh edge' "$edge_kind_block"; then
  echo 'edge-kind: static edge checks moved back into a Kind shard' >&2
  exit 1
fi
grep -qF 'scripts/ci/verify/kind-e2e.sh shard "${suites[@]}"' "$edge_kind_block"
edge_fixture_runner="$TMP/edge-fixture-runner.sh"
# The Kind tool tests own these fixtures; Edge runs them when selected (R8).
awk '
  /^run_kind_tools\(\) \{/ { capture = 1 }
  capture { print }
  capture && $0 == "}" { exit }
' "$ROOT/scripts/ci/verify/run-product-verification.sh" > "$edge_fixture_runner"
for edge_fixture_command in \
    '  scripts/ci/tests/test-kind-e2e-suites.sh' \
    '  run_kind_cw_runtime_probe_fixture'; do
  [ "$(grep -cFx "$edge_fixture_command" "$edge_fixture_runner")" -eq 1 ] || {
    echo "the Kind tool tests must invoke the owning fixture once: $edge_fixture_command" >&2
    exit 1
  }
done
# The probe fixture runs as the workspace user: directly for a developer, and
# through a privilege drop where the hosted job is root. Execute the checked-in
# helper against a stub tree for both identities.
probe_fixture_runner="$TMP/probe-fixture-runner.sh"
awk '
  /^run_kind_cw_runtime_probe_fixture\(\) \{/ { capture = 1 }
  capture { print }
  capture && $0 == "}" { exit }
' "$ROOT/scripts/ci/verify/run-product-verification.sh" > "$probe_fixture_runner"
[ "$(grep -cF 'python3 -B scripts/ci/tests/test-kind-cw-runtime-probe.py' "$probe_fixture_runner")" -eq 2 ] || {
  echo 'probe fixture helper must run the owning fixture on both identity paths' >&2
  exit 1
}
# Hosted, the copy sits in a fresh directory under the filesystem root: the
# probe refuses any group- or world-writable ancestor, such as /tmp.
grep -Fxq '  local parent="${1:-/}"' "$probe_fixture_runner" || {
  echo 'hosted probe fixture must copy the tree directly under the filesystem root' >&2
  exit 1
}
probe_fixture_tree="$TMP/probe-fixture-tree"
mkdir -p "$probe_fixture_tree/bin" "$probe_fixture_tree/scripts/ci/tests"
git -C "$probe_fixture_tree" init -q
printf 'fixture\n' > "$probe_fixture_tree/scripts/ci/tests/test-kind-cw-runtime-probe.py"
git -C "$probe_fixture_tree" add -A
git -C "$probe_fixture_tree" -c user.name=fixture -c user.email=fixture@example.invalid \
  commit -q -m fixture
for probe_tool in id python3 chown setpriv; do
  cat > "$probe_fixture_tree/bin/$probe_tool" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
tool="$(basename "$0")"
case "$tool" in
  id) printf '%s\n' "$PROBE_FIXTURE_UID"; exit 0 ;;
  python3)
    printf 'python3 cwd=%s uid=%s args=%s\n' "$PWD" "${PROBE_FIXTURE_DROPPED:-direct}" "$*" >> "$PROBE_FIXTURE_CALLS"
    [ -d .tmp ] || [ "${PROBE_FIXTURE_DROPPED:-direct}" = direct ]
    exit "${PROBE_FIXTURE_STATUS:-0}" ;;
  chown) printf 'chown %s\n' "$*" >> "$PROBE_FIXTURE_CALLS"; exit 0 ;;
  setpriv)
    printf 'setpriv %s %s %s\n' "$1" "$2" "$3" >> "$PROBE_FIXTURE_CALLS"
    shift 3
    PROBE_FIXTURE_DROPPED=1000 exec "$@" ;;
esac
SH
  chmod +x "$probe_fixture_tree/bin/$probe_tool"
done
run_probe_fixture_case() {
  local uid="$1" status="$2"
  : > "$TMP/probe-fixture-calls"
  (
    cd "$probe_fixture_tree"
    env PATH="$probe_fixture_tree/bin:$PATH" PROBE_FIXTURE_UID="$uid" PROBE_FIXTURE_STATUS="$status" \
      PROBE_FIXTURE_CALLS="$TMP/probe-fixture-calls" \
      bash -euo pipefail -c 'source "$1"; run_kind_cw_runtime_probe_fixture "$2"' _ "$probe_fixture_runner" "$TMP"
  )
}
run_probe_fixture_case 1000 0
[ "$(cat "$TMP/probe-fixture-calls")" = "python3 cwd=$probe_fixture_tree uid=direct args=-B scripts/ci/tests/test-kind-cw-runtime-probe.py" ] || {
  echo 'workspace-user probe fixture must run directly in the checkout' >&2
  exit 1
}
run_probe_fixture_case 0 0
grep -Eq '^chown -R 1000:1000 .*/codewire-cw-probe-fixture\.[A-Za-z0-9]+/tree$' "$TMP/probe-fixture-calls" || {
  echo 'root probe fixture must own a private copy as the workspace user' >&2
  exit 1
}
grep -Fxq 'setpriv --reuid=1000 --regid=1000 --clear-groups' "$TMP/probe-fixture-calls" || {
  echo 'root probe fixture must drop to the workspace user' >&2
  exit 1
}
grep -Eq '^python3 cwd=.*/codewire-cw-probe-fixture\.[A-Za-z0-9]+/tree uid=1000 args=-B scripts/ci/tests/test-kind-cw-runtime-probe.py$' \
  "$TMP/probe-fixture-calls" || {
  echo 'root probe fixture must run the committed copy as the workspace user' >&2
  exit 1
}
if run_probe_fixture_case 0 7; then
  echo 'root probe fixture accepted a failed fixture' >&2
  exit 1
fi
if run_probe_fixture_case 1000 7; then
  echo 'workspace-user probe fixture accepted a failed fixture' >&2
  exit 1
fi
[ -z "$(find "$TMP" -maxdepth 1 -name 'codewire-cw-probe-fixture.*' -print -quit)" ] || {
  echo 'root probe fixture left its private copy behind' >&2
  exit 1
}

if grep -qF '    name: Manual diagnostics' "$WORKFLOW" \
  || grep -qF '  diagnostics:' "$WORKFLOW" \
  || grep -qF 'DIAGNOSTICS_RESULT' "$WORKFLOW" \
  || grep -qF '      - diagnostics' "$WORKFLOW"; then
  echo 'product CI must not contain or depend on manual diagnostics' >&2
  exit 1
fi
grep -qF 'manual diagnostics are retired; run scripts/ci/verify/rust-stack-rehearsal.sh or scripts/ci/verify/tailnet-parity.sh locally' "$WORKFLOW"

if rg -n 'cr-golden|diagnostic_cr_golden|go_cr_golden|TestGolden.*-update' \
    "$WORKFLOW" "$SELECTOR" \
    "$ROOT/scripts/ci/verify/run-product-verification.sh"; then
  echo 'retired Go CR-golden diagnostic remains wired' >&2
  exit 1
fi

# The start-latency measurement is dispatch-only, reads with its own job token
# on the Lite pool, and runs only the vendored collector its checksum names.
START_LATENCY_WORKFLOW="$ROOT/.gitea/workflows/ci-start-latency.yaml"
(cd "$ROOT/scripts/ci/measure" &&
  sha256sum --check --strict --quiet forgejo-ci-start-latency.sha256) || {
  echo 'vendored start-latency collector does not match its recorded sha256' >&2
  exit 1
}
grep -qF '  workflow_dispatch:' "$START_LATENCY_WORKFLOW"
if grep -Eq '^  (push|pull_request|pull_request_target|schedule|workflow_run):' \
    "$START_LATENCY_WORKFLOW" \
  || grep -Eq '^permissions:|enable-openid-connect|secrets\.' "$START_LATENCY_WORKFLOW"; then
  echo 'start-latency measurement must stay dispatch-only and credential-free' >&2
  exit 1
fi
grep -qxF "    runs-on: ${RUNS_ON_UNTRUSTED_LIGHT}" "$START_LATENCY_WORKFLOW"
grep -qF 'run: sha256sum --check --strict forgejo-ci-start-latency.sha256' \
  "$START_LATENCY_WORKFLOW"
grep -qF 'echo "::group::rows.jsonl"' "$START_LATENCY_WORKFLOW"

# The #3144 done measures are dispatch-only and read with their own job token
# on the Lite pool, from a full checkout for merge ancestry.
DONE_MEASURES_WORKFLOW="$ROOT/.gitea/workflows/ci-done-measures.yaml"
grep -qF '  workflow_dispatch:' "$DONE_MEASURES_WORKFLOW"
if grep -Eq '^  (push|pull_request|pull_request_target|schedule|workflow_run):' \
    "$DONE_MEASURES_WORKFLOW" \
  || grep -Eq '^permissions:|enable-openid-connect|secrets\.' "$DONE_MEASURES_WORKFLOW"; then
  echo 'done measures must stay dispatch-only and credential-free' >&2
  exit 1
fi
grep -qxF "    runs-on: ${RUNS_ON_UNTRUSTED_LIGHT}" "$DONE_MEASURES_WORKFLOW"
grep -qF 'scripts/ci/measure/ci-done-measures collect' "$DONE_MEASURES_WORKFLOW"

required_block="$TMP/required-verification.yaml"
awk '
  $0 == "  required-verification:" { capture = 1 }
  capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ && $0 != "  required-verification:" { exit }
  capture { print }
' "$WORKFLOW" > "$required_block"
if grep -Eq 'promotion-receipt-(publish|consume)|RECEIPT_(PUBLISH|CONSUME)_RESULT' \
    "$WORKFLOW"; then
  echo 'required CI retains synthetic promotion receipt transport' >&2
  exit 1
fi

if rg -ni 'migration[ _-](static|integration)' "$WORKFLOW"; then
  echo 'automatic workflow retains historical migration terminology' >&2
  exit 1
fi
grep -qF '  required-verification:' "$WORKFLOW"
grep -qF '    name: Required verification' "$WORKFLOW"
grep -qxF "    runs-on: ${RUNS_ON_UNTRUSTED_LIGHT}" "$required_block" || {
  echo 'required coordination consumes the heavy compatibility pool' >&2
  exit 1
}
# shellcheck disable=SC2016 # Match the literal Actions expression.
grep -qF '    if: ${{ always() }}' "$WORKFLOW"
grep -qF 'scripts/ci/select/require-verification-results.sh' "$required_block"
for group in standard rust-compile rust-packages rust-features rust-transport database services-control services-runtime edge-kind; do
  grep -qF "      - ${group}" "$required_block" || {
    echo "required CI does not wait on ${group}" >&2
    exit 1
  }
done
for result in VERIFICATION_STANDARD_RESULT \
    VERIFICATION_RUST_COMPILE_RESULT VERIFICATION_RUST_PACKAGES_RESULT \
    VERIFICATION_RUST_FEATURES_RESULT VERIFICATION_RUST_TRANSPORT_RESULT \
    VERIFICATION_DATABASE_RESULT \
    VERIFICATION_SERVICES_CONTROL_RESULT VERIFICATION_SERVICES_RUNTIME_RESULT \
    VERIFICATION_EDGE_KIND_RESULT; do
  grep -qF "${result}:" "$required_block" || {
    echo "required CI omits ${result}" >&2
    exit 1
  }
done
for expected in VERIFICATION_POLICY_EXPECTED VERIFICATION_STANDARD_EXPECTED \
    VERIFICATION_TOOLING_EXPECTED VERIFICATION_RUST_COMPILE_EXPECTED \
    VERIFICATION_RUST_SHARDS_EXPECTED VERIFICATION_RUST_TRANSPORT_EXPECTED \
    VERIFICATION_DATABASE_EXPECTED VERIFICATION_SERVICES_CONTROL_EXPECTED \
    VERIFICATION_SERVICES_RUNTIME_EXPECTED VERIFICATION_EDGE_KIND_EXPECTED; do
  grep -qF "${expected}:" "$required_block" || {
    echo "required CI omits ${expected}" >&2
    exit 1
  }
done
for receipt_input in VERIFICATION_TESTED_TREE_RECEIPT \
    VERIFICATION_TESTED_TREE_REASON VERIFICATION_TESTED_TREE_PR \
    VERIFICATION_TESTED_TREE_HEAD VERIFICATION_TESTED_TREE_RUN; do
  grep -qF "${receipt_input}:" "$required_block" || {
    echo "required CI omits ${receipt_input}" >&2
    exit 1
  }
done
grep -qF 'name: Emit exact-head verification receipt' "$required_block"
grep -qF 'run: scripts/ci/receipts/emit-verification-receipt.py' "$required_block"
# shellcheck disable=SC2016 # Match the literal Actions expression.
grep -A12 -F 'name: Emit exact-head verification receipt' "$required_block" \
  | grep -qF 'VERIFICATION_SELECTION: ${{ needs.verification-selection.outputs.selection }}' || {
  echo 'the receipt step cannot validate its run selection' >&2
  exit 1
}
for receipt_input in CODEWIRE_PR_NUMBER CODEWIRE_BASE_COMMIT \
    CODEWIRE_HEAD_COMMIT CODEWIRE_HEAD_TREE; do
  grep -qF "${receipt_input}:" "$required_block" || {
    echo "verification receipt omits ${receipt_input}" >&2
    exit 1
  }
done
if grep -qF 'diagnostics' "$required_block" \
  || grep -qF 'DIAGNOSTICS_RESULT' "$required_block"; then
  echo 'required CI must not wait on manual diagnostics' >&2
  exit 1
fi
grep -qF 'scripts/ci/select/select-verification.sh' "$ROOT/scripts/dev/preflight.sh"
if [ "$(grep -cE '^[[:space:]]*run_selected_family policy policy ' \
    "$ROOT/scripts/dev/preflight.sh")" -ne 1 ]; then
  echo 'local preflight must invoke the shared policy family exactly once' >&2
  exit 1
fi
if grep -Eq 'run_policy_local|scripts/checks/repo_checks.py|test-rust-owned-fixtures.sh|test-dashboard-image-network-probe.sh' \
    "$ROOT/scripts/dev/preflight.sh"; then
  echo 'local preflight still owns a private policy checklist' >&2
  exit 1
fi
# Policy core is two parts that local merge qualification runs side by side:
# the repository rules, which run on every change, and the CI-script tests,
# which run when the trusted selection asks for them (#3119 A6). Together they
# are the shared core: every step is in exactly one part, the aggregate runs
# the core parts the runner lists, and the policy family runs exactly the
# parts the runner lists for the selection.
shared_policy_core="$TMP/shared-policy-core.sh"
product_runner="$ROOT/scripts/ci/verify/run-product-verification.sh"
policy_function() {
  awk -v name="$1" '
    $0 == name "() {" { capture = 1 }
    capture { print }
    capture && /^}$/ { exit }
  ' "$product_runner"
}
{ policy_function run_repo_rules; policy_function run_ci_script_tests; } > "$shared_policy_core"
policy_steps() {
  grep -E '^  (scripts/|crates/|python3 )' | LC_ALL=C sort
}
[ -z "$(policy_function run_repo_rules | policy_steps | uniq -d)" ] \
  && [ -z "$(policy_function run_ci_script_tests | policy_steps | uniq -d)" ] \
  && [ -z "$(comm -12 <(policy_function run_repo_rules | policy_steps) \
      <(policy_function run_ci_script_tests | policy_steps))" ] || {
  echo 'a policy core step is repeated or belongs to both parts' >&2
  exit 1
}
[ -n "$(policy_function run_repo_rules | policy_steps)" ] \
  && [ -n "$(policy_function run_ci_script_tests | policy_steps)" ] || {
  echo 'a policy core part has no steps' >&2
  exit 1
}
# The always-on part owns the private-content tree scan and every repository
# rule, the two secret-isolation rules included (#3119 M5).
for repo_rule in \
    'scripts/ci/release/check-mirror-content.sh --tree' \
    'scripts/ci/verify/check-rust-toolchain.sh' \
    'python3 scripts/checks/repo_checks.py ses-email-isolation' \
    'python3 scripts/checks/repo_checks.py turnstile-access-projection --self-test'; do
  grep -qxF "  $repo_rule" <(policy_function run_repo_rules) || {
    echo "repository rules do not run $repo_rule" >&2
    exit 1
  }
done
if policy_function run_ci_script_tests | grep -qF 'scripts/checks/repo_checks.py '; then
  echo 'a repository rule runs only with the CI-script tests' >&2
  exit 1
fi
[ "$(policy_function run_policy_part | grep -E '^    policy-')" = "$(printf '    %s\n' \
    'policy-shell) run_shell_policy ;;' \
    'policy-repo-rules) run_repo_rules ;;' \
    'policy-ci-script-tests) run_ci_script_tests ;;')" ] || {
  echo 'policy parts are not exactly ShellCheck, repository rules and CI-script tests' >&2
  exit 1
}
grep -qxF '    [ "$part" = policy-shell ] || parts+=("$part")' <(policy_function run_policy_core) \
  && grep -qxF '  done < <(policy_parts)' <(policy_function run_policy_core) || {
  echo 'policy core does not run the listed parts other than ShellCheck' >&2
  exit 1
}
# CI's policy core runs its parts side by side and fails when either fails,
# including a failure in the middle of a part. The repository rules here pass
# only if the CI-script tests start while they run, so a serial aggregate fails
# this fixture. ShellCheck is its own job and never runs in policy core.
policy_core_fixture() {
  local dir="$1" parts="$2" one="$3" two="$4"
  bash -c '
    set -euo pipefail
    dir="$1" listed="$3" one_mode="$4" two_mode="$5"
    eval "$2"
    policy_parts() { tr " " "\n" <<<"$listed"; }
    run_policy_part() {
      case "$1" in
        policy-shell) echo shell-ran-in-core ;;
        policy-repo-rules) (
          if [[ " $listed " == *" policy-ci-script-tests "* ]]; then
            for _ in $(seq 1 100); do
              [ -e "$dir/two-started" ] && break
              sleep 0.05
            done
            [ -e "$dir/two-started" ]
          fi
          [ "$one_mode" = pass ] || false
          echo one-finished
        ) ;;
        policy-ci-script-tests) (
          touch "$dir/two-started"
          [ "$two_mode" = pass ] || false
          echo two-finished
        ) ;;
      esac
    }
    run_policy_core
  ' policy-core-fixture "$dir" "$(policy_function run_policy_core)" "$parts" "$one" "$two"
}
for policy_core_case in \
    'policy-shell policy-repo-rules policy-ci-script-tests:pass:pass:0' \
    'policy-repo-rules policy-ci-script-tests:fail:pass:1' \
    'policy-repo-rules policy-ci-script-tests:pass:fail:1' \
    'policy-repo-rules policy-ci-script-tests:fail:fail:1' \
    'policy-shell policy-repo-rules:pass:pass:0' \
    'policy-repo-rules:fail:pass:1'; do
  IFS=: read -r policy_listed policy_one policy_two policy_expected <<<"$policy_core_case"
  policy_core_dir="$(mktemp -d "$TMP/policy-core.XXXXXX")"
  policy_core_status=0
  policy_core_output="$(policy_core_fixture "$policy_core_dir" "$policy_listed" \
    "$policy_one" "$policy_two" 2>&1)" || policy_core_status=$?
  if grep -qx shell-ran-in-core <<<"$policy_core_output"; then
    echo 'policy core ran ShellCheck, which is its own job' >&2
    exit 1
  fi
  if [[ " $policy_listed " != *' policy-ci-script-tests '* ]] \
      && grep -qx two-finished <<<"$policy_core_output"; then
    echo 'policy core ran CI-script tests the selection did not list' >&2
    exit 1
  fi
  if [ "$policy_expected" = 0 ]; then
    [ "$policy_core_status" -eq 0 ] \
      && grep -qx one-finished <<<"$policy_core_output" || {
      echo "policy core did not run its parts side by side: $policy_core_output" >&2
      exit 1
    }
    if [[ " $policy_listed " == *' policy-ci-script-tests '* ]] \
        && ! grep -qx two-finished <<<"$policy_core_output"; then
      echo "policy core skipped its listed CI-script tests: $policy_core_output" >&2
      exit 1
    fi
  else
    [ "$policy_core_status" -ne 0 ] || {
      echo "policy core passed with part one $policy_one and part two $policy_two" >&2
      exit 1
    }
    if [ "$policy_one" = fail ] && grep -qx one-finished <<<"$policy_core_output"; then
      echo 'a failed policy core part kept running past its failing step' >&2
      exit 1
    fi
    if [ "$policy_two" = fail ] && grep -qx two-finished <<<"$policy_core_output"; then
      echo 'a failed policy core part kept running past its failing step' >&2
      exit 1
    fi
  fi
done
grep -qxF '  for part in $(policy_parts); do' <(policy_function run_policy) \
  && grep -qxF '    run_policy_part "$part"' <(policy_function run_policy) || {
  echo 'the policy family does not run the listed policy parts' >&2
  exit 1
}
# A selector that predates a part's omission marker keeps that part.
for selection_and_parts in \
    '|valid:v3|policy|policy_shell_omittable|complete|=policy-repo-rules policy-ci-script-tests' \
    '|valid:v3|policy|policy_shell|policy_shell_omittable|complete|=policy-shell policy-repo-rules policy-ci-script-tests' \
    '|valid:v3|policy|complete|=policy-shell policy-repo-rules policy-ci-script-tests' \
    '|valid:v3|ci_script_tests_omittable|policy|policy_shell_omittable|complete|=policy-repo-rules' \
    '|valid:v3|ci_script_tests|ci_script_tests_omittable|policy|policy_shell_omittable|complete|=policy-repo-rules policy-ci-script-tests' \
    '|valid:v3|ci_script_tests_omittable|policy|policy_shell|policy_shell_omittable|complete|=policy-shell policy-repo-rules'; do
  listed_parts="$(VERIFICATION_SELECTION="${selection_and_parts%%=*}" "$product_runner" policy-parts | paste -sd' ')"
  [ "$listed_parts" = "${selection_and_parts#*=}" ] || {
    echo "policy parts for ${selection_and_parts%%=*} are: ${listed_parts}" >&2
    exit 1
  }
done
# Edge runs the Kind tool tests only when the selection names them, or when
# an older trusted selector cannot say (#3119 R8).
edge_family_fixture() {
  SELECTION="$1" bash -c '
    set -euo pipefail
    selected() { [[ "$SELECTION" == *"|$1|"* ]]; }
    run_edge() { echo edge; }
    run_kind_tools() { echo kind-tools; }
    eval "$1"
    eval "$2"
    run_edge_family
  ' edge-family-fixture "$(policy_function kind_tools_selected)" \
    "$(policy_function run_edge_family)"
}
[ "$(edge_family_fixture '|valid:v3|edge_kind|complete|')" = $'edge\nkind-tools' ] || {
  echo 'Edge from an older trusted selector skipped the Kind tool tests' >&2
  exit 1
}
[ "$(edge_family_fixture '|valid:v3|edge_kind|kind_tools|kind_tools_omittable|complete|')" \
    = $'edge\nkind-tools' ] || {
  echo 'Edge skipped the selected Kind tool tests' >&2
  exit 1
}
[ "$(edge_family_fixture '|valid:v3|edge_kind|kind_tools_omittable|complete|')" \
    = $'edge\nKind tool tests: not selected; no Kind tool or input they read changed' ] || {
  echo 'Edge ran Kind tool tests the selection omitted' >&2
  exit 1
}
grep -qxF '  edge) run_edge_family ;;' "$product_runner" || {
  echo 'the edge family does not decide on the Kind tool tests' >&2
  exit 1
}
grep -qF '"$PRODUCT_RUNNER" policy-parts' "$ROOT/scripts/dev/preflight.sh" || {
  echo 'local merge qualification does not take policy parts from the product runner' >&2
  exit 1
}
for policy_owner in \
    'run_verification_shell_syntax' \
    'scripts/ci/tests/test-rust-owned-fixtures.sh' \
    'scripts/ci/tests/test-dashboard-image-network-probe.sh' \
    'scripts/ci/tests/test-admin-proto-boundary.sh' \
    'scripts/checks/repo_checks.py license-map' \
    'scripts/checks/repo_checks.py permanent-raw-surface --self-test' \
    'scripts/checks/repo_checks.py design-tokens --self-test' \
    'scripts/checks/repo_checks.py epoch-material-cache-owner --self-test' \
    'scripts/checks/repo_checks.py rust-validation-source' \
    'scripts/checks/repo_checks.py retired-reference-source' \
    'scripts/checks/repo_checks.py go-source-classification'; do
  if [ "$(grep -cF "$policy_owner" "$shared_policy_core")" -ne 1 ]; then
    echo "shared policy core must own exactly one $policy_owner" >&2
    exit 1
  fi
done
if grep -qF -- '--cli-dependencies' "$shared_policy_core"; then
  echo 'shared Policy must not resolve the CLI dependency graph' >&2
  exit 1
fi
desktop_package_args="$TMP/desktop-package-args.sh"
# The lightweight policy lane must not resolve Rust dependencies. Exercise the
# actual authority guard with a Cargo stub, then the actual Rust dispatch body
# with terminal package commands so this fixture cannot launch a nested build.
primitive_probe="$TMP/primitive-routing"
mkdir -p "$primitive_probe/bin"
cat > "$primitive_probe/bin/cargo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$PRIMITIVE_CARGO_LOG"
if [[ "${PRIMITIVE_CARGO_FAIL:-}" == all || "${PRIMITIVE_CARGO_FAIL:-}" == "$1" ]]; then
  exit 86
fi
if [[ "$1" == tree ]]; then
  if [[ " $* " == *' -p codewire-cli-bin '* ]]; then
    case "${PRIMITIVE_CLI_GRAPH:-allowed}" in
      allowed) printf 'codewire-cli-bin v0.0.0\ncodewire-proto v0.0.0\n' ;;
      forbidden) printf 'codewire-cli-bin v0.0.0\ncodewire-admin-proto v0.0.0\n' ;;
      missing_root) printf 'codewire-proto v0.0.0\n' ;;
      *) exit 87 ;;
    esac
  elif [[ " $* " == *' -p codewire-credential-service '* ]]; then
    printf 'codewire-credential-service v0.0.0|\n'
    printf 'codewire-credential-broker v0.0.0|%s\n' "${PRIMITIVE_SERVICE_FEATURES-platform}"
    printf 'codewire-protected-store v0.0.0|%s\n' "${PRIMITIVE_SERVICE_FEATURES-platform}"
  else
    printf 'codewire-protected-store v0.0.0|%s\n' "${PRIMITIVE_GRAPH_FEATURES-platform}"
  fi
fi
SH
chmod +x "$primitive_probe/bin/cargo"
primitive_cargo_stub="$primitive_probe/bin/cargo"
primitive_cargo_command="$(PATH="$primitive_probe/bin:$PATH" bash -c 'command -v cargo')"
[[ -x "$primitive_cargo_stub" && "$primitive_cargo_command" == "$primitive_cargo_stub" ]] || {
  echo 'primitive routing requires an executable TMPDIR and must resolve only its Cargo stub' >&2
  printf 'expected %s; resolved %s\n' "$primitive_cargo_stub" "$primitive_cargo_command" >&2
  exit 1
}
primitive_guard="$ROOT/scripts/ci/tests/test-openbao-only-secret-authority.sh"
: > "$primitive_probe/default.log"
PATH="$primitive_probe/bin:$PATH" PRIMITIVE_CARGO_LOG="$primitive_probe/default.log" \
  PRIMITIVE_CARGO_FAIL=all "$primitive_guard" > "$primitive_probe/default.out" 2>&1 || {
  status=$?
  cat "$primitive_probe/default.out" >&2
  exit "$status"
}
[[ ! -s "$primitive_probe/default.log" ]] || {
  echo 'default authority policy must not invoke Cargo' >&2
  exit 1
}
admin_guard="$ROOT/scripts/ci/tests/test-admin-proto-boundary.sh"
: > "$primitive_probe/admin-default.log"
PATH="$primitive_probe/bin:$PATH" PRIMITIVE_CARGO_LOG="$primitive_probe/admin-default.log" \
  PRIMITIVE_CARGO_FAIL=all "$admin_guard" > "$primitive_probe/admin-default.out" 2>&1
[[ ! -s "$primitive_probe/admin-default.log" ]] || {
  echo 'default administrator boundary Policy must not invoke Cargo' >&2
  exit 1
}
grep -qF 'static customer and administrator contract boundaries passed' \
  "$primitive_probe/admin-default.out"

# Exercise every existing source/descriptor assertion against isolated copies.
# The guard is unchanged, and even its failure cases must never invoke Cargo.
admin_fixture="$primitive_probe/admin-static"
mkdir -p "$admin_fixture/scripts/ci/tests" \
  "$admin_fixture/crates/codewire-proto" "$admin_fixture/crates/codewire-admin-proto"
cp "$admin_guard" "$admin_fixture/scripts/ci/tests/test-admin-proto-boundary.sh"
run_admin_static_negative() {
  local name="$1" path="$2" before="$3" after="$4" error="$5" status=0
  local input
  for input in crates/codewire-proto/build.rs crates/codewire-admin-proto/build.rs \
      crates/codewire-proto/codewire_descriptor.bin \
      crates/codewire-admin-proto/codewire_admin_descriptor.bin; do
    cp "$ROOT/$input" "$admin_fixture/$input"
  done
  python3 - "$admin_fixture/$path" "$before" "$after" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
before, after = (value.encode() for value in sys.argv[2:])
data = path.read_bytes()
if before:
    assert before in data, "static boundary fixture mutation no longer applies"
    data = data.replace(before, after)
else:
    data += after
path.write_bytes(data)
PY
  : > "$primitive_probe/admin-$name.log"
  PATH="$primitive_probe/bin:$PATH" PRIMITIVE_CARGO_LOG="$primitive_probe/admin-$name.log" \
    PRIMITIVE_CARGO_FAIL=all "$admin_fixture/scripts/ci/tests/test-admin-proto-boundary.sh" \
    > "$primitive_probe/admin-$name.out" 2>&1 || status=$?
  [[ "$status" == 1 && ! -s "$primitive_probe/admin-$name.log" ]] || {
    echo "$name: static administrator boundary did not fail without Cargo ($status)" >&2
    exit 1
  }
  grep -qF "$error" "$primitive_probe/admin-$name.out"
  if grep -qF 'boundaries passed' "$primitive_probe/admin-$name.out"; then
    echo "$name: static administrator boundary printed success after failure" >&2
    exit 1
  fi
}
run_admin_static_negative customer_build crates/codewire-proto/build.rs \
  '' 'codewire/admin/v1/admin.proto' \
  'customer descriptor build includes a global-administrator proto'
run_admin_static_negative admin_build_service crates/codewire-admin-proto/build.rs \
  'codewire/admin/v1/admin.proto' 'removed.proto' 'admin descriptor omits AdminService'
run_admin_static_negative admin_build_billing crates/codewire-admin-proto/build.rs \
  'codewire/admin/v1/billing_catalog.proto' 'removed.proto' \
  'admin descriptor omits BillingCatalogService'
run_admin_static_negative admin_build_descriptor crates/codewire-admin-proto/build.rs \
  'codewire_admin_descriptor.bin' 'removed.bin' \
  'admin crate lacks a distinct checked-in descriptor input'
run_admin_static_negative customer_descriptor crates/codewire-proto/codewire_descriptor.bin \
  '' 'codewire.admin.v1' 'customer descriptor contains global-administrator contracts'
run_admin_static_negative admin_descriptor_service \
  crates/codewire-admin-proto/codewire_admin_descriptor.bin \
  'AdminService' 'RemovedService' 'administrator descriptor omits AdminService'
run_admin_static_negative admin_descriptor_billing \
  crates/codewire-admin-proto/codewire_admin_descriptor.bin \
  'BillingCatalogService' 'RemovedService' 'administrator descriptor omits BillingCatalogService'

primitive_rust_body="$primitive_probe/run-rust.sh"
awk '
  /^(rust_shard|run_rust)\(\) \{/ { capture = 1 }
  capture { print }
  capture && /^}$/ { capture = 0 }
' "$ROOT/scripts/ci/verify/run-product-verification.sh" > "$primitive_rust_body"
if ! grep -q '^rust_shard() {' "$primitive_rust_body" \
    || ! grep -q '^run_rust() {' "$primitive_rust_body"; then
  echo 'primitive Rust dispatch must capture rust_shard and run_rust' >&2
  exit 1
fi
cat > "$primitive_probe/dispatch.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ -x "$PRIMITIVE_CARGO_STUB" && "$(command -v cargo)" == "$PRIMITIVE_CARGO_STUB" ]] || {
  echo 'primitive Rust dispatch must resolve only its Cargo stub' >&2
  type -a cargo >&2
  exit 1
}
selected() { [[ "$SELECTION" == *"|$1|"* ]]; }
has_root_rust_selection() { return 0; }
run_rust_packages() { printf '%s\n' "$*" > "$PRIMITIVE_PACKAGE_LOG"; }
python3() {
  if [[ "$*" == '-B scripts/ci/tests/test-cli-host-managed.py' ]]; then
    if [[ -n "${PRIMITIVE_HOST_ROUTING_LOG:-}" ]]; then
      printf '%s\n' host-fixture >> "$PRIMITIVE_HOST_ROUTING_LOG"
    fi
    return "${PRIMITIVE_HOST_FIXTURE_EXIT:-0}"
  fi
  if [[ -n "${PRIMITIVE_HOST_ROUTING_LOG:-}" ]] \
      && [[ "$*" == '-B scripts/ci/tests/test-cli-update-mesh-endpoints.py' ]]; then
    printf '%s\n' mesh-fixture >> "$PRIMITIVE_HOST_ROUTING_LOG"
    return 0
  fi
  command python3 "$@"
}
source "$PRIMITIVE_RUST_BODY"
if [[ "${PRIMITIVE_HOST_EXPLICIT_STATUS:-false}" == true ]]; then
  status=0
  run_rust || status=$?
  if [[ "$status" == 0 ]]; then
    printf '%s\n' success-receipt >> "$PRIMITIVE_HOST_ROUTING_LOG"
  fi
  exit "$status"
fi
run_rust
SH
# The actual feature dispatcher must run this fixture once, preserve its
# failure even under explicit status capture, and omit it on unrelated shards.
run_host_fixture_routing_case() {
  local name="$1" tokens="$2" shard="$3" expected_calls="$4" fixture_exit="$5" expected_exit="$6"
  local log="$primitive_probe/host-$name.log" output="$primitive_probe/host-$name.out" status=0
  : > "$log"
  PATH="$primitive_probe/bin:$PATH" PRIMITIVE_CARGO_STUB="$primitive_cargo_stub" \
    PRIMITIVE_CARGO_LOG="$primitive_probe/host-$name.cargo" \
    PRIMITIVE_PACKAGE_LOG="$primitive_probe/host-$name.packages" \
    PRIMITIVE_RUST_BODY="$primitive_rust_body" PRIMITIVE_HOST_ROUTING_LOG="$log" \
    PRIMITIVE_HOST_FIXTURE_EXIT="$fixture_exit" PRIMITIVE_HOST_EXPLICIT_STATUS=true \
    RUST_TRANSPORT_SHARD="$shard" SELECTION="|valid:v3|$tokens|complete|" \
    bash "$primitive_probe/dispatch.sh" > "$output" 2>&1 || status=$?
  [[ "$status" == "$expected_exit" ]] || { cat "$output" >&2; exit 1; }
  [[ "$(grep -cxF host-fixture "$log" || true)" == "$expected_calls" ]] || {
    echo "$name: host fixture routing count changed" >&2; exit 1;
  }
  if [[ "$expected_exit" != 0 ]]; then
    [[ "$(wc -l < "$log")" == 1 ]] || {
      echo "$name: verification continued or emitted success after host fixture failure" >&2; exit 1;
    }
  else
    [[ "$(grep -cxF success-receipt "$log" || true)" == 1 ]] || exit 1
  fi
}
run_host_fixture_routing_case workspace rust_workspace features 1 0 0
run_host_fixture_routing_case cli rust_pkg_codewire_cli features 1 0 0
run_host_fixture_routing_case cli_bin rust_pkg_codewire_cli_bin features 1 0 0
run_host_fixture_routing_case combined 'rust_pkg_codewire_cli|rust_pkg_codewire_cli_bin' features 1 0 0
run_host_fixture_routing_case unrelated rust_pkg_codewire_client features 0 0 0
run_host_fixture_routing_case packages rust_pkg_codewire_cli packages 0 0 0
run_host_fixture_routing_case local_vmm rust_pkg_codewire_cli local-vmm 0 0 0
run_host_fixture_routing_case refused rust_pkg_codewire_cli features 1 79 79
run_primitive_rust_case() {
  local name="$1" token="$2" graph="$3" platform="$4" fail="${5:-}" features="${6:-platform}"
  local log="$primitive_probe/$name.log" status=0 graph_count cli_count clippy_count test_count
  : > "$log"
  PATH="$primitive_probe/bin:$PATH" PRIMITIVE_CARGO_LOG="$log" \
    PRIMITIVE_CARGO_STUB="$primitive_cargo_stub" \
    PRIMITIVE_PACKAGE_LOG="$primitive_probe/$name.packages" \
    PRIMITIVE_RUST_BODY="$primitive_rust_body" PRIMITIVE_CARGO_FAIL="$fail" \
    PRIMITIVE_GRAPH_FEATURES="$features" SELECTION="|valid:v3|$token|complete|" \
    bash -x "$primitive_probe/dispatch.sh" > "$primitive_probe/$name.out" 2>&1 || status=$?
  if [[ -n "$fail" ]]; then
    [[ "$status" == 86 ]] || { echo "$name: lost Cargo failure ($status)" >&2; exit 1; }
  elif [[ "$features" == *platform-test-support* ]]; then
    [[ "$status" == 1 ]] || { echo "$name: accepted synthetic production provider" >&2; exit 1; }
  else
    [[ "$status" == 0 ]] || { cat "$primitive_probe/$name.out" >&2; exit 1; }
  fi
  grep -qxF rust_pkg_ "$primitive_probe/$name.packages"
  graph_count="$(grep -c '^tree --locked -p codewire-orchestration --edges normal,build ' "$log" || true)"
  cli_count="$(grep -cxF 'tree --locked -p codewire-cli-bin --prefix none' "$log" || true)"
  if [[ "$token" == rust_workspace ]]; then
    [[ "$cli_count" == 1 ]] || { echo "$name: missing or duplicate CLI graph" >&2; exit 1; }
  else
    [[ "$cli_count" == 0 ]] || { echo "$name: unrelated CLI graph selected" >&2; exit 1; }
  fi
  clippy_count="$(grep -cxF 'clippy --locked -p codewire-protected-store --features platform --all-targets -- -D warnings' "$log" || true)"
  test_count="$(grep -cxF 'test --locked -p codewire-protected-store --features platform --all-targets' "$log" || true)"
  [[ "$graph_count" == "$graph" && "$clippy_count" == "$platform" ]] || {
    echo "$name: missing or duplicate protected-store verification" >&2
    cat "$primitive_probe/$name.out" >&2
    cat "$primitive_rust_body" >&2
    cat "$log" >&2
    exit 1
  }
  if [[ "$fail" == clippy ]]; then
    [[ "$test_count" == 0 ]] || { echo "$name: ran tests after failed Clippy" >&2; exit 1; }
  else
    [[ "$test_count" == "$platform" ]] || { echo "$name: missing platform tests" >&2; exit 1; }
  fi
}
run_primitive_rust_case protected_store rust_pkg_codewire_protected_store 1 1
run_primitive_rust_case workspace rust_workspace 1 1
run_primitive_rust_case orchestration rust_pkg_codewire_orchestration 1 0
run_primitive_rust_case unrelated rust_pkg_codewire_client 0 0
run_primitive_rust_case graph_failure rust_pkg_codewire_protected_store 1 0 tree
run_primitive_rust_case forbidden_provider rust_pkg_codewire_protected_store 1 0 '' platform,platform-test-support
run_primitive_rust_case clippy_failure rust_pkg_codewire_protected_store 1 1 clippy

run_admin_rust_case() {
  local name="$1" tokens="$2" graph="$3" expected_status="$4" fail="${5:-}"
  local log="$primitive_probe/admin-rust-$name.log" output="$primitive_probe/admin-rust-$name.out"
  local status=0
  : > "$log"
  PATH="$primitive_probe/bin:$PATH" PRIMITIVE_CARGO_LOG="$log" \
    PRIMITIVE_CARGO_STUB="$primitive_cargo_stub" PRIMITIVE_CARGO_FAIL="$fail" \
    PRIMITIVE_PACKAGE_LOG="$primitive_probe/admin-rust-$name.packages" \
    PRIMITIVE_RUST_BODY="$primitive_rust_body" PRIMITIVE_CLI_GRAPH="$graph" \
    SELECTION="|valid:v3|$tokens|complete|" \
    bash "$primitive_probe/dispatch.sh" > "$output" 2>&1 || status=$?
  [[ "$status" == "$expected_status" ]] || {
    echo "$name: wrong CLI dependency boundary status ($status)" >&2
    cat "$output" >&2
    exit 1
  }
  [[ "$(grep -cxF 'tree --locked -p codewire-cli-bin --prefix none' "$log" || true)" == 1 ]] || {
    echo "$name: missing or duplicate CLI dependency graph" >&2
    exit 1
  }
  if [[ "$status" == 0 ]]; then
    grep -qF 'customer CLI dependency boundary passed' "$output"
  else
    if grep -qF 'customer CLI dependency boundary passed' "$output"; then
      echo "$name: CLI dependency boundary printed success after failure" >&2
      exit 1
    fi
    [[ "$(wc -l < "$log")" == 1 ]] || {
      echo "$name: Rust verification continued after failed CLI dependency graph" >&2
      exit 1
    }
    case "$graph:$fail" in
      *:tree) grep -qF 'CLI dependency graph failed (status=86)' "$output" ;;
      forbidden:) grep -qF 'customer CLI transitively depends on administrator-only contracts' "$output" ;;
      missing_root:) grep -qF 'dependency graph omits the customer CLI root' "$output" ;;
    esac
  fi
}
run_admin_rust_case cli rust_pkg_codewire_cli allowed 0
run_admin_rust_case cli_bin rust_pkg_codewire_cli_bin allowed 0
run_admin_rust_case admin_proto rust_pkg_codewire_admin_proto allowed 0
run_admin_rust_case customer_proto rust_pkg_codewire_proto allowed 0
run_admin_rust_case combined \
  'rust_workspace|rust_pkg_codewire_cli|rust_pkg_codewire_cli_bin|rust_pkg_codewire_admin_proto|rust_pkg_codewire_proto' \
  allowed 0
run_admin_rust_case forbidden rust_workspace forbidden 1
run_admin_rust_case missing_root rust_workspace missing_root 1
run_admin_rust_case cargo_failure rust_workspace allowed 86 tree

# The broker's optional platform adapter must have a production-only graph and
# warning-denied tests even when the default local feature is not enabled.
run_platform_broker_rust_case() {
  local name="$1" token="$2" expected="$3" fail="${4:-}" features="${5-platform}"
  local log="$primitive_probe/broker-$name.log" status=0 graph_count clippy_count test_count
  : > "$log"
  PATH="$primitive_probe/bin:$PATH" PRIMITIVE_CARGO_LOG="$log" \
    PRIMITIVE_CARGO_STUB="$primitive_cargo_stub" \
    PRIMITIVE_PACKAGE_LOG="$primitive_probe/broker-$name.packages" \
    PRIMITIVE_RUST_BODY="$primitive_rust_body" PRIMITIVE_CARGO_FAIL="$fail" \
    PRIMITIVE_GRAPH_FEATURES="$features" SELECTION="|valid:v3|$token|complete|" \
    bash "$primitive_probe/dispatch.sh" > "$primitive_probe/broker-$name.out" 2>&1 || status=$?
  if [[ -n "$fail" ]]; then
    [[ "$status" == 86 ]] || { echo "$name: lost broker Cargo failure ($status)" >&2; exit 1; }
  elif [[ "$features" != platform ]]; then
    [[ "$status" == 1 ]] || { echo "$name: accepted invalid broker production graph" >&2; exit 1; }
  else
    [[ "$status" == 0 ]] || { cat "$primitive_probe/broker-$name.out" >&2; exit 1; }
  fi
  graph_count="$(grep -c '^tree --locked -p codewire-credential-broker --no-default-features --features platform --edges normal,build ' "$log" || true)"
  clippy_count="$(grep -cxF 'clippy --locked -p codewire-credential-broker --no-default-features --features platform --all-targets -- -D warnings' "$log" || true)"
  test_count="$(grep -cxF 'test --locked -p codewire-credential-broker --no-default-features --features platform --all-targets' "$log" || true)"
  [[ "$graph_count" == "$expected" ]] || { echo "$name: missing or duplicate broker graph check" >&2; exit 1; }
  if [[ "$fail" == tree || "$features" != platform ]]; then
    [[ "$clippy_count" == 0 && "$test_count" == 0 ]] || { echo "$name: broker checks followed invalid graph" >&2; exit 1; }
  elif [[ "$fail" == clippy ]]; then
    [[ "$clippy_count" == "$expected" && "$test_count" == 0 ]] || { echo "$name: tests followed failed broker Clippy" >&2; exit 1; }
  else
    [[ "$clippy_count" == "$expected" && "$test_count" == "$expected" ]] || { echo "$name: missing or duplicate optional broker checks" >&2; exit 1; }
  fi
}
run_platform_broker_rust_case broker rust_pkg_codewire_credential_broker 1
run_platform_broker_rust_case workspace rust_workspace 1
run_platform_broker_rust_case local_dependency rust_pkg_codewire_local_credentials 0
run_platform_broker_rust_case unrelated rust_pkg_codewire_client 0
run_platform_broker_rust_case graph_failure rust_pkg_codewire_credential_broker 1 tree
run_platform_broker_rust_case missing_platform rust_pkg_codewire_credential_broker 1 '' ''
run_platform_broker_rust_case forbidden_provider rust_pkg_codewire_credential_broker 1 '' platform,platform-test-support
run_platform_broker_rust_case clippy_failure rust_pkg_codewire_credential_broker 1 clippy
run_platform_broker_rust_case test_failure rust_pkg_codewire_credential_broker 1 test

# Projected-Pod identity is opt-in and must be qualified when either its shared
# implementation or the orchestration consumer is selected, without relying on
# unrelated workspace feature unification.
run_pod_identity_rust_case() {
  local name="$1" token="$2" expected="$3" fail="${4:-}"
  local log="$primitive_probe/pod-identity-$name.log" status=0 clippy_count test_count
  : > "$log"
  PATH="$primitive_probe/bin:$PATH" PRIMITIVE_CARGO_LOG="$log" \
    PRIMITIVE_CARGO_STUB="$primitive_cargo_stub" PRIMITIVE_CARGO_FAIL="$fail" \
    PRIMITIVE_PACKAGE_LOG="$primitive_probe/pod-identity-$name.packages" \
    PRIMITIVE_RUST_BODY="$primitive_rust_body" SELECTION="|valid:v3|$token|complete|" \
    bash "$primitive_probe/dispatch.sh" > "$primitive_probe/pod-identity-$name.out" 2>&1 || status=$?
  if [[ -n "$fail" ]]; then
    [[ "$status" == 86 ]] || { echo "$name: lost Pod identity Cargo failure ($status)" >&2; exit 1; }
  else
    [[ "$status" == 0 ]] || { cat "$primitive_probe/pod-identity-$name.out" >&2; exit 1; }
  fi
  clippy_count="$(grep -cxF 'clippy --locked -p codewire-server-core --features kubernetes-identity --all-targets -- -D warnings' "$log" || true)"
  test_count="$(grep -cxF 'test --locked -p codewire-server-core --features kubernetes-identity --lib pod_identity::' "$log" || true)"
  [[ "$clippy_count" == "$expected" ]] || { echo "$name: missing or duplicate Pod identity Clippy" >&2; exit 1; }
  if [[ "$fail" == clippy ]]; then
    [[ "$test_count" == 0 ]] || { echo "$name: tests followed failed Pod identity Clippy" >&2; exit 1; }
  else
    [[ "$test_count" == "$expected" ]] || { echo "$name: missing or duplicate Pod identity tests" >&2; exit 1; }
  fi
}
run_pod_identity_rust_case shared rust_pkg_codewire_server_core 1
run_pod_identity_rust_case consumer rust_pkg_codewire_orchestration 1
run_pod_identity_rust_case workspace rust_workspace 1
run_pod_identity_rust_case unrelated rust_pkg_codewire_client 0
run_pod_identity_rust_case clippy_failure rust_pkg_codewire_server_core 1 clippy
run_pod_identity_rust_case test_failure rust_pkg_codewire_server_core 1 test

# A dedicated service may not accidentally inherit the broker's local default
# or enable test-only protected material providers through a transitive edge.
run_credential_service_graph_case() {
  local name="$1" token="$2" expected="$3" fail="${4:-}" features="${5:-platform}"
  local log="$primitive_probe/service-$name.log" status=0
  : > "$log"
  PATH="$primitive_probe/bin:$PATH" PRIMITIVE_CARGO_LOG="$log" \
    PRIMITIVE_CARGO_STUB="$primitive_cargo_stub" \
    PRIMITIVE_PACKAGE_LOG="$primitive_probe/service-$name.packages" \
    PRIMITIVE_RUST_BODY="$primitive_rust_body" PRIMITIVE_CARGO_FAIL="$fail" \
    PRIMITIVE_SERVICE_FEATURES="$features" SELECTION="|valid:v3|$token|complete|" \
    bash "$primitive_probe/dispatch.sh" > "$primitive_probe/service-$name.out" 2>&1 || status=$?
  if [[ -n "$fail" ]]; then
    [[ "$status" == 86 ]] || { echo "$name: lost service graph failure" >&2; exit 1; }
  elif [[ "$features" != platform ]]; then
    [[ "$status" == 1 ]] || { echo "$name: accepted unsafe service graph" >&2; exit 1; }
  else
    [[ "$status" == 0 ]] || { cat "$primitive_probe/service-$name.out" >&2; exit 1; }
  fi
  [[ "$(grep -c '^tree --locked -p codewire-credential-service --edges normal,build ' "$log" || true)" == "$expected" ]] || {
    echo "$name: missing or duplicate service graph proof" >&2; exit 1;
  }
}
run_credential_service_graph_case service rust_pkg_codewire_credential_service 1
run_credential_service_graph_case workspace rust_workspace 1
run_credential_service_graph_case unrelated rust_pkg_codewire_client 0
run_credential_service_graph_case cargo_failure rust_pkg_codewire_credential_service 1 tree
run_credential_service_graph_case local_default rust_pkg_codewire_credential_service 1 '' default,local,platform
run_credential_service_graph_case synthetic_provider rust_pkg_codewire_credential_service 1 '' platform,platform-test-support

awk '
  /^rust_package_args\(\) \{/ { capture = 1 }
  /^run_rust_packages\(\) \{/ { exit }
  capture { print }
' "$ROOT/scripts/ci/verify/run-product-verification.sh" > "$desktop_package_args"
desktop_packages="$(
  cd "$ROOT"
  bash -c '
    set -euo pipefail
    selected() {
      [ "$1" = rust_pkg_codewire_client ] || [ "$1" = rust_pkg_codewire_desktop ]
    }
    RUST_PACKAGE_ARGS=()
    source "$1"
    rust_package_args rust_pkg_
    printf "%s\\n" "${RUST_PACKAGE_ARGS[@]}"
  ' bash "$desktop_package_args"
)"
if ! grep -qx -- '-p' <<<"$desktop_packages" \
    || ! grep -qx -- 'codewire-client' <<<"$desktop_packages" \
    || grep -qx -- 'codewire-desktop' <<<"$desktop_packages"; then
  echo 'detached desktop package leaked into root Cargo workspace arguments' >&2
  exit 1
fi
if [ "$(grep -c '^run_selected_family edge_kind edge ' \
    "$ROOT/scripts/dev/preflight.sh")" -ne 1 ]; then
  echo 'local preflight must invoke edge static verification exactly once' >&2
  exit 1
fi
if grep -qF "find scripts/runtime -type f -name '*.sh'" \
    "$ROOT/scripts/dev/preflight.sh"; then
  echo 'local preflight duplicates the shared runtime syntax owner' >&2
  exit 1
fi
grep -qF "find scripts/runtime -type f -name '*.sh' -exec bash -c '" \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
shared_shell_policy="$TMP/shared-shell-policy.sh"
awk '
  /^run_shell_policy\(\) \{/ { capture = 1 }
  capture { print }
  capture && /^}$/ { exit }
' "$ROOT/scripts/ci/verify/run-product-verification.sh" > "$shared_shell_policy"
if grep -Eq 'run_verification_shell_syntax|bash -n|find scripts/runtime|run_policy_core' \
    "$shared_shell_policy"; then
  echo 'selected ShellCheck duplicates shared core or syntax verification' >&2
  exit 1
fi
grep -qxF '  scripts/ci/verify/check-shell-scripts.sh --self-test' "$shared_shell_policy"
# shellcheck disable=SC2016 # Match the runner's literal shell variable.
grep -qxF '    scripts/ci/verify/check-shell-scripts.sh --changed-since "$CODEWIRE_SHELL_POLICY_BASE"' \
  "$shared_shell_policy"
grep -qxF '    scripts/ci/verify/check-shell-scripts.sh' "$shared_shell_policy"
grep -qF 'scripts/runtime/tests/test-run-sdk-python-e2e.sh' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
grep -qF 'Python SDK wheel leaked generated codewire/$forbidden_package' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
grep -qF 'scripts/runtime/tests/test-run-sdk-ts-e2e.sh' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
grep -qF 'scripts/runtime/tests/test-with-dev-smoke-auth.sh' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
grep -qF 'scripts/runtime/tests/test-provision-dev-smoke-user.sh' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
grep -qF 'scripts/runtime/tests/test-provision-prod-smoke-user.sh' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
grep -qF 'scripts/runtime/tests/test-with-prod-smoke-auth.sh' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
grep -qF 'scripts/runtime/tests/test-smoke-dev-commodity.sh' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
grep -qF 'scripts/runtime/tests/test-secrets-credentials-acceptance-runner.sh' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
grep -qF 'run_selected_family dev_smoke_script_tests dev-smoke-script-tests' \
  "$ROOT/scripts/dev/preflight.sh"
grep -qF "contains(needs.verification-selection.outputs.selection, '|dev_smoke_script_tests|')" \
  "$WORKFLOW"
grep -qF 'run: scripts/ci/verify/run-product-verification.sh dev-smoke-script-tests' \
  "$WORKFLOW"
if grep -qF 'select-migration-gates' "$WORKFLOW"; then
  echo 'workflow still calls the retired selector' >&2
  exit 1
fi

bash -n \
  "$SELECTOR" \
  "$ROOT/scripts/ci/select/emit-verification-matrices.sh" \
  "$ROOT/scripts/ci/select/require-verification-results.sh" \
  "$ROOT/scripts/ci/receipts/verify-tested-tree-receipt.sh" \
  "$ROOT/scripts/ci/receipts/verify-release-tag-receipt.sh" \
  "$ROOT/scripts/ci/tests/test-require-verification-results.sh" \
  "$ROOT/scripts/ci/tests/test-emit-verification-matrices.sh" \
  "$ROOT/scripts/ci/tests/test-verify-tested-tree-receipt.sh" \
  "$ROOT/scripts/ci/tests/test-verify-release-tag-receipt.sh" \
  "$ROOT/scripts/ci/verify/run-product-verification.sh" \
  "$ROOT/scripts/ci/verify/integration-postgres.sh" \
  "$ROOT/scripts/ci/verify/run-integration-verification.sh" \
  "$ROOT/scripts/ci/tests/test-integration-postgres.sh" \
  "$ROOT/scripts/ci/tests/test-rust-owned-fixtures.sh" \
  "$ROOT/scripts/ci/verify/rust-stack-rehearsal.sh" \
  "$ROOT/scripts/dev/preflight.sh" \
  "$ROOT/.githooks/pre-push"

"$ROOT/scripts/ci/tests/test-pre-push-worktree.sh"
"$ROOT/scripts/ci/tests/test-push-check-shellcheck.sh"
"$ROOT/scripts/ci/tests/test-emit-verification-matrices.sh"

# Main CI runs start at once, one group per commit. A main push whose
# selection starts after main moved on says which commit superseded it, and
# dispatches nothing; main's tip runs everything selected.
# Execute the checked-in step against a stub remote.
selection_block="$(awk '
  $0 == "  verification-selection:" { capture = 1 }
  capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ && $0 != "  verification-selection:" { exit }
  capture { print }
' "$WORKFLOW")"
for expected in \
    '      superseded: ${{ steps.superseded.outputs.superseded }}' \
    '      superseded_by: ${{ steps.superseded.outputs.superseded_by }}' \
    '          VERIFICATION_SUPERSEDED: ${{ steps.superseded.outputs.superseded }}'; do
  grep -qxF -- "$expected" <<<"$selection_block" || {
    echo "verification selection omits: $expected" >&2
    exit 1
  }
done
superseded_line="$(grep -n -m1 'name: Skip a superseded main commit' <<<"$selection_block" | cut -d: -f1)"
dispatch_line="$(grep -n -m1 'name: Emit trusted capability dispatch decisions' <<<"$selection_block" | cut -d: -f1)"
[[ -n "$superseded_line" && "$superseded_line" -lt "$dispatch_line" ]] || {
  echo 'CI dispatches before it knows whether its main commit was superseded' >&2
  exit 1
}
producer_gate="    if: \${{ needs.verification-selection.outputs.tested_tree_receipt != 'accepted' && needs.verification-selection.outputs.superseded != 'true' && contains(needs.verification-selection.outputs.selection, '|kind|') }}"
# The workspace producer adds one clause: a pinned workspace has no producer.
workspace_producer_gate="${producer_gate% \}\}} && needs.verification-selection.outputs.kind_workspace_source != 'pinned' }}"
[[ "$(grep -cxF -- "$producer_gate" "$WORKFLOW")" -eq 3 &&
  "$(grep -cxF -- "$workspace_producer_gate" "$WORKFLOW")" -eq 1 ]] || {
  echo 'a superseded main run still builds a Kind producer' >&2
  exit 1
}
superseded_step="$TMP/ci-superseded-step.sh"
awk '
  /- name: Skip a superseded main commit/ { scope = 1 }
  scope && /^        run: \|$/ { run = 1; next }
  run && /^          / { print substr($0, 11); next }
  run { exit }
' "$WORKFLOW" >"$superseded_step"
[[ -s "$superseded_step" ]] || { echo 'superseded main step was not extracted' >&2; exit 1; }
mkdir -p "$TMP/superseded-bin"
cat >"$TMP/superseded-bin/git" <<'GIT'
#!/usr/bin/env bash
printf 'git %s\n' "$*" >>"$FAKE_GIT_CALLS"
[[ "$*" == 'ls-remote origin refs/heads/main' ]] || exit 64
[[ -n "${FAKE_MAIN_SHA:-}" ]] || exit 1
printf '%s\trefs/heads/main\n' "$FAKE_MAIN_SHA"
GIT
chmod +x "$TMP/superseded-bin/git"
# superseded_case EVENT REF MAIN -> outputs, then "summary:" lines, or "failed"
superseded_case() {
  local event="$1" ref="$2" main="$3"
  : >"$TMP/superseded-output"; : >"$TMP/superseded-summary"; : >"$TMP/git-calls"
  if env PATH="$TMP/superseded-bin:$PATH" FAKE_MAIN_SHA="$main" FAKE_GIT_CALLS="$TMP/git-calls" \
      EVENT_NAME="$event" EVENT_REF="$ref" GITHUB_SHA=1111111111111111111111111111111111111111 \
      GITHUB_OUTPUT="$TMP/superseded-output" GITHUB_STEP_SUMMARY="$TMP/superseded-summary" \
      bash "$superseded_step" >/dev/null 2>&1; then
    cat "$TMP/superseded-output"
    sed 's/^/summary: /' "$TMP/superseded-summary"
  else
    echo failed
  fi
}
tip=1111111111111111111111111111111111111111
newer=2222222222222222222222222222222222222222
[[ "$(superseded_case push refs/heads/main "$tip")" == superseded=false ]] || {
  echo "main's tip run was treated as superseded" >&2; exit 1; }
[[ "$(superseded_case push refs/heads/main "$newer")" == "superseded=true
superseded_by=$newer
summary: superseded by $newer: main's queued run verifies this commit's changes" ]] || {
  echo 'a main run behind main'"'"'s tip did not record its supersession' >&2; exit 1; }
for not_main in 'pull_request refs/pull/7/head' 'workflow_dispatch refs/heads/main' 'push refs/heads/feature'; do
  read -r event ref <<<"$not_main"
  [[ "$(superseded_case "$event" "$ref" "$newer")" == superseded=false && ! -s "$TMP/git-calls" ]] || {
    echo "a $event run on $ref was judged against main" >&2; exit 1; }
done
[[ "$(superseded_case push refs/heads/main '')" == failed ]] || {
  echo 'an unreadable canonical main did not fail closed' >&2; exit 1; }
[[ "$(superseded_case push refs/heads/main not-a-commit)" == failed ]] || {
  echo 'a malformed canonical main did not fail closed' >&2; exit 1; }

# Pull-request scope (#3119 step 2.1, owner decision 2026-10-21): a pull
# request runs every family its paths select, as a push to main does, except
# Kind, which only the ci-full label adds.
scope_event() {
  # NAME TITLE LABEL... -> a pull_request event payload as Forgejo sends it
  local name="$1" title="$2" labels='' label
  shift 2
  for label in "$@"; do
    labels="${labels:+$labels,}{\"id\":7,\"name\":\"${label}\",\"color\":\"0366d6\"}"
  done
  printf '{"action":"labeled","number":7,"pull_request":{"number":7,"title":"%s","body":"","labels":[%s],"base":{"label":"main","ref":"main"},"head":{"label":"feature","ref":"feature"}},"repository":{"name":"codewire","full_name":"codewire/codewire"},"sender":{"login":"noel","full_name":"Noel"}}\n' \
    "$title" "$labels" > "$TMP/${name}.event.json"
  printf '%s\n' "$TMP/${name}.event.json"
}

scope_select() {
  # EVENT EVENT_PATH PATHS_FILE (EVENT_PATH may be empty)
  local event="$1" event_path="$2" paths="$3" ref=refs/pull/7/head
  local -a inputs=()
  if [ "$event" = push ]; then ref=refs/heads/main; fi
  if [ -n "$event_path" ]; then inputs+=("GITHUB_EVENT_PATH=$event_path"); fi
  env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH -u KIND_E2E_OPT_IN \
    "${inputs[@]}" GITHUB_EVENT_NAME="$event" GITHUB_REF="$ref" \
    "${SCOPE_SELECTOR:-$SELECTOR}" "$paths" </dev/null
}

no_labels="$(scope_event no_labels 'feat: change')"
ci_full="$(scope_event ci_full 'feat: change' ci-full)"
kind_label="$(scope_event kind_label 'feat: change' kind-e2e)"
kind_marker="$(scope_event kind_marker 'feat: change [kind-e2e]')"
lookalike="$(scope_event lookalike 'feat: ci-full is not a label' ci ci/r2-cache-canary ci-fuller)"

# NAME|PATHS (space separated)
while IFS='|' read -r name paths_list; do
  paths="$TMP/scope-${name}.paths"
  tr ' ' '\n' <<<"$paths_list" > "$paths"
  # A push to main as it selects with Kind (the switch true); ci-full
  # compares against it.
  push_output="$(SCOPE_SELECTOR="$SELECTOR_KIND_ON" scope_select push '' "$paths")"
  pr_output="$(scope_select pull_request "$no_labels" "$paths")"

  # The checked-in switch keeps that selection on a push to main, less kind
  # while it defers Kind, and nothing else.
  main_output="$(scope_select push '' "$paths")"
  main_tokens="$(selection_tokens "$(selection_value "$push_output")")"
  if [ -z "$MAIN_PUSH_KIND" ]; then
    main_tokens="$(grep -vx kind <<<"$main_tokens" || true)"
  fi
  [ "$(selection_tokens "$(selection_value "$main_output")")" = "$main_tokens" ] || {
    echo "${name}: the switch changed a push to main beyond Kind" >&2
    exit 1
  }
  # A pull request without a label selects what main does, without Kind.
  push_tokens="$(selection_tokens "$(selection_value "$push_output")" | grep -Evx 'edge_kind|kind|kind_tools|kind_tools_omittable' || true)"
  [ "$(selection_tokens "$(selection_value "$pr_output")")" = "$push_tokens" ] || {
    echo "${name}: a pull request no longer selects main's families" >&2
    exit 1
  }
  if grep -Fq '|pr_quick|' <<<"$pr_output"; then
    echo "${name}: a pull request still carries the retired quick marker" >&2
    exit 1
  fi
  # Labels that only resemble ci-full, and ci-full in the title, add nothing.
  [ "$(scope_select pull_request "$lookalike" "$paths")" = "$pr_output" ] || {
    echo "${name}: a lookalike label or title changed a pull request's selection" >&2
    exit 1
  }
  # ci-full gets exactly what a push to main selects with Kind, even while
  # the switch defers Kind on the push.
  [ "$(scope_select pull_request "$ci_full" "$paths")" = "$push_output" ] || {
    echo "${name}: ci-full does not select what a push to main does" >&2
    scope_select pull_request "$ci_full" "$paths" >&2
    exit 1
  }
  # Kind runs only on the schedule and ci-full (owner, 2026-10-21): the
  # retired kind-e2e label and title marker add nothing.
  for kind_event in "$kind_label" "$kind_marker"; do
    [ "$(scope_select pull_request "$kind_event" "$paths")" = "$pr_output" ] || {
      echo "${name}: the retired kind-e2e opt-in still selects Kind" >&2
      exit 1
    }
  done
done <<'CASES'
docs|docs/dev/AGENT-WORKFLOW.md
rust_cli|crates/codewire-cli/src/main.rs
broker_database|crates/codewire-credential-broker/src/provider_enrollment.rs
transport|crates/codewire-daemon/src/lib.rs
dashboard_kind|crates/codewire-dashboard-web/src/lib.rs
browser_spec|apps/dashboard/e2e/sandbox-lifecycle.spec.ts
release_shell|scripts/ci/release/package-cw-release.sh
selector_policy|scripts/ci/select/select-verification.sh .gitea/workflows/ci.yaml
mixed|docs/dev/CI-ARCHITECTURE.md crates/codewire-cli/src/main.rs scripts/ci/release/package-cw-release.sh
CASES

# The Kind cases above must really exercise Kind, and the Rust cases their
# crate tests on a pull request.
for kind_case in dashboard_kind browser_spec; do
  kind_case_output="$(SCOPE_SELECTOR="$SELECTOR_KIND_ON" scope_select push '' "$TMP/scope-${kind_case}.paths")"
  grep -Fq '|kind|' <<<"$kind_case_output" || {
    echo "${kind_case}: fixture no longer selects Kind on main" >&2
    exit 1
  }
done
for rust_case in rust_cli broker_database transport mixed; do
  grep -Eq '\|(rust|transport)\|' <<<"$(selection_value \
      "$(scope_select pull_request "$no_labels" "$TMP/scope-${rust_case}.paths")")" || {
    echo "${rust_case}: a pull request does not run its Rust tests" >&2
    exit 1
  }
done

# An unchanged pull request runs policy alone.
: > "$TMP/scope-empty.paths"
assert_tokens scope_unchanged 'policy' \
  "$(scope_select pull_request "$no_labels" "$TMP/scope-empty.paths")"

# An unclassified path fails closed: a pull request selects all product
# verification, Kind still only with ci-full.
printf 'unclassified-scope-fixture.bin\n' > "$TMP/scope-unclassified.paths"
unclassified_pr="$(scope_select pull_request "$no_labels" "$TMP/scope-unclassified.paths" 2>/dev/null)"
assert_contract_field scope_unclassified "$unclassified_pr" classification unclassified
assert_contract_field scope_unclassified "$unclassified_pr" required_local_mode full
if grep -Fq '|kind|' <<<"$unclassified_pr"; then
  echo 'an unclassified pull request ran Kind without ci-full' >&2
  exit 1
fi
[ "$(scope_select pull_request "$ci_full" "$TMP/scope-unclassified.paths" 2>/dev/null)" \
  = "$(SCOPE_SELECTOR="$SELECTOR_KIND_ON" scope_select push '' "$TMP/scope-unclassified.paths" 2>/dev/null)" ] || {
  echo 'ci-full on an unclassified pull request differs from main' >&2
  exit 1
}

# Required verification passes a pull request with exactly its dispatched
# groups, even when every artifact fact says affected, and fails it when one
# of them does not run.
pr_dispatch_and_require() {
  local selection="$1" missing="${2:-}" output="$TMP/scope-dispatch.out" group value job
  local -a results=()
  : > "$output"
  VERIFICATION_SELECTION="$selection" VERIFICATION_TESTED_TREE_RECEIPT=fallback \
    CW_PACKAGE_SELECTED=true DESKTOP_PACKAGE_SELECTED=true WORKSPACE_IMAGE_SELECTED=true \
    GITHUB_OUTPUT="$output" "$ROOT/scripts/ci/select/emit-verification-matrices.sh"
  local -a jobs
  while IFS='=' read -r group value; do
    group="${group%_expected}"
    results+=("VERIFICATION_${group^^}_EXPECTED=$value")
    jobs=("${group^^}")
    if [ "$group" = rust_shards ]; then
      jobs=(RUST_PACKAGES RUST_FEATURES)
    fi
    for job in "${jobs[@]}"; do
      if [ "$value" = true ] && [ "$job" != "$missing" ]; then
        results+=("VERIFICATION_${job}_RESULT=success")
      else
        results+=("VERIFICATION_${job}_RESULT=skipped")
      fi
    done
  done < "$output"
  env VERIFICATION_SELECTION="$selection" VERIFICATION_SELECTION_RESULT=success \
    VERIFICATION_TESTED_TREE_RECEIPT=fallback "${results[@]}" \
    "$ROOT/scripts/ci/select/require-verification-results.sh" >/dev/null 2>&1
}
for scope_case in rust_cli dashboard_kind release_shell selector_policy mixed; do
  pr_selection="$(selection_value "$(scope_select pull_request "$no_labels" "$TMP/scope-${scope_case}.paths")")"
  pr_dispatch_and_require "$pr_selection" || {
    echo "${scope_case}: Required verification rejected a green pull request" >&2
    exit 1
  }
  if grep -Fq '|rust|' <<<"$pr_selection" \
      && pr_dispatch_and_require "$pr_selection" RUST_PACKAGES; then
    echo "${scope_case}: Required verification accepted a pull request without its crate tests" >&2
    exit 1
  fi
done
# Policy always runs on main, so the release-tag receipt finds a green
# capability group in every main run.
for scope_case in docs rust_cli broker_database transport release_shell selector_policy; do
  main_selection="$(selection_value "$(scope_select push '' "$TMP/scope-${scope_case}.paths")")"
  grep -Fq '|policy|' <<<"$main_selection" || {
    echo "${scope_case}: a main push selects no policy group" >&2
    exit 1
  }
done
# A pull request's run carries the receipt main may reuse.
receipt_env=(GITHUB_EVENT_NAME=pull_request GITHUB_REPOSITORY=codewire/codewire
  GITHUB_RUN_ID=501 GITHUB_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb CODEWIRE_PR_NUMBER=7
  CODEWIRE_BASE_COMMIT=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  CODEWIRE_HEAD_COMMIT=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  CODEWIRE_HEAD_TREE=cccccccccccccccccccccccccccccccccccccccc)
receipt_for() {
  env -i PATH="$PATH" "${receipt_env[@]}" VERIFICATION_SELECTION="$1" \
    python3 -I -B "$ROOT/scripts/ci/receipts/emit-verification-receipt.py"
}
receipt_for "$(selection_value "$(scope_select pull_request "$no_labels" "$TMP/scope-rust_cli.paths")")" \
  | grep -Fq 'CODEWIRE_CI_VERIFICATION_RECEIPT=' || {
  echo 'a pull-request run did not emit its receipt' >&2
  exit 1
}

# Branch protection requires two status contexts on main (#3119 step 2.2;
# infra's forgejo-codewire-branch-protection.json pins the same names).
# Forgejo names a status "<workflow> / <job> (<event>)", so renaming either
# workflow or job, or dropping its trigger, would block every merge.
python3 - "$WORKFLOW" "$ROOT/.gitea/workflows/source-approval.yml" <<'PY'
import sys
import yaml

REQUIRED = {
    "CI / Required verification (pull_request)",
    "Supply-chain scan / Supply-chain scan (pull_request_target)",
}
contexts = set()
for path in sys.argv[1:]:
    workflow = yaml.safe_load(open(path, encoding="utf-8"))
    triggers = workflow.get("on", workflow.get(True))
    for job in workflow["jobs"].values():
        for event in triggers:
            contexts.add(f"{workflow['name']} / {job.get('name', '')} ({event})")
missing = REQUIRED - contexts
if missing:
    raise SystemExit(f"required status contexts no workflow produces: {sorted(missing)}")
PY

# The workflow re-runs on label changes and no longer reduces a pull request.
python3 - "$WORKFLOW" <<'PY'
import sys
import yaml

workflow = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
triggers = workflow.get("on", workflow.get(True))
types = set(triggers["pull_request"].get("types", []))
wanted = {"opened", "synchronize", "reopened", "labeled", "unlabeled", "closed"}
if types != wanted:
    raise SystemExit(f"pull_request types {sorted(types)} != {sorted(wanted)}")
steps = workflow["jobs"]["verification-selection"]["steps"]
select = [step for step in steps if step.get("id") == "select"]
if len(select) != 1 or "VERIFICATION_PR_SCOPE" in select[0].get("env", {}):
    raise SystemExit("the selection step still sets the retired pull-request scope")
PY
if rg -n 'VERIFICATION_PR_SCOPE|pr_quick' "$ROOT/scripts/ci/select" "$ROOT/scripts/dev/preflight.sh" \
    "$ROOT/scripts/ci/receipts" "$WORKFLOW"; then
  echo 'the retired quick pull-request scope remains' >&2
  exit 1
fi

# A dispatched heavy job always has work, and selected work is always
# dispatched: the emitter's decisions are evaluated against the workflow's own
# step conditions, for realistic selections and for every token alone, with
# policy, Kind or Edge, under every artifact fact.
job_work_selections="$TMP/job-work-selections.txt"
: > "$job_work_selections"
for scope_case in docs rust_cli broker_database transport dashboard_kind browser_spec \
    release_shell selector_policy mixed; do
  for scope_event_name in push pull_request; do
    if [ "$scope_event_name" = push ]; then
      scope_output="$(scope_select push '' "$TMP/scope-${scope_case}.paths")"
      selection_value "$(SCOPE_SELECTOR="$SELECTOR_KIND_ON" \
        scope_select push '' "$TMP/scope-${scope_case}.paths")" >> "$job_work_selections"
    else
      scope_output="$(scope_select pull_request "$no_labels" "$TMP/scope-${scope_case}.paths")"
    fi
    selection_value "$scope_output" >> "$job_work_selections"
  done
done
selection_value "$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=all "$SELECTOR")" >> "$job_work_selections"
# Scheduled runs: Kind alone, or nothing.
selection_value "$(schedule_paths "$SELECTOR_KIND_OFF" apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts)" \
  >> "$job_work_selections"
selection_value "$(schedule_paths "$SELECTOR_KIND_OFF" docs/dev/AGENT-WORKFLOW.md)" >> "$job_work_selections"
python3 -B - "$WORKFLOW" "$ROOT/scripts/ci/select/emit-verification-matrices.sh" \
    "$job_work_selections" <<'PY'
import itertools
import os
import re
import subprocess
import sys
import tempfile

import yaml

workflow_path, emitter, realistic_path = sys.argv[1:4]
workflow = yaml.safe_load(open(workflow_path, encoding="utf-8"))
jobs = workflow["jobs"]

# The steps that verify something. Every other step of a checked job must be
# a named support step (setup, guard or cleanup), so a new step is classified
# before this fixture accepts it.
WORK = {
    "policy": {"Run Policy"},
    "standard": {
        "Run Contracts", "Run Go support", "Run Web", "Run Docs", "Run SDK Go",
        "Run SDK TypeScript typecheck and unit suite", "Run SDK Python",
        "Run iOS package tests in the pinned Swift image",
    },
    "tooling": {
        "Run Shell policy", "Run confidential script tests",
        "Run Dev smoke script tests", "Run delivery script tests", "Run Deploy", "Run Security",
        "Run the workspace agents check",
        "Run Edge static verification and selected Kind tool tests",
    },
    "rust-compile": {"Compile every Rust target", "Run the build legs",
                     "Compile the macOS cw for both Mac targets"},
    "rust-packages": {"Run the Rust packages shard"},
    "rust-features": {"Run the Rust features shard"},
    "rust-transport": {
        "Verify curated Rust image workspace locks", "Run selected Rust and transport",
        "Run artifact-selected desktop package",
    },
    "database": {"Run Database"},
    "services-control": {"Run Service integration"},
    "services-runtime": {"Run Service integration"},
    "kind-workspace": {"Build and verify exact source workspace"},
    "kind-product": {"Build exact Kind service images"},
    "kind-daemon": {"Build exact Kind daemon image"},
    "kind-smokes": {"Build all host smoke and contract binaries"},
    "edge-kind": {"Run the shard Kind gate"},
}
SUPPORT = {
    "Reuse exact PR-head content verification",
    "Service control-plane integration not selected", "Service runtime-plane integration not selected",
    "Resolve service control-plane scope",
    "Resolve service runtime-plane scope",
    "Verify sealed Rust toolchain", "Verify sealed policy tools", "Verify sealed delivery-contract tools",
    "Verify sealed producer tools", "Verify sealed producer tools and isolated Buildx load",
    "Verify Rust cache capacity", "Verify Rust protobuf compiler", "Verify GPUI and Wry build prerequisites",
    "Verify Kind runner tools", "Select best-effort shared Rust cache", "Select existing compiler cache",
    "Select the warm Rust cache", "Report the warm Rust cache", "Bound cargo jobs by memory",
    "Declare a metal Kata guest",
    "Bring the warm build folder to this commit", "Publish the test archives",
    "Fetch and verify the test archive", "Install pinned cargo-nextest",
    "Fetch and verify the database archives", "Unpack the database archives",
    "Select independent workspace caches",
    "Install pinned protoc for Rust builds", "Install pinned protoc for Rust-backed standard checks",
    "Install pinned protoc for Rust and guest builds", "Install pinned protoc for Rust compilation",
    "Install locked dashboard browser-test dependencies",
    "Set up Go 1.27.3", "Set up Go 1.27.3 for security checks", "Set up Go 1.27.3 for DERP interop",
    "Set up pinned Darwin C cross-check tools",
    "Clean workspace cache credentials",
    "Clean compiler cache credentials", "Report and clean Rust cache", "Start integration Postgres",
    "Wait for integration Postgres", "Stop integration Postgres",
    "Require fresh artifact download directories outside the checkout",
    "Download exact workspace producer output", "Download exact product producer output",
    "Download exact smoke producer output", "Download exact daemon producer output",
    "Write the pinned workspace record",
    "Upload dashboard browser test results on failure",
    "Upload dashboard browser JSON report",
    "Delete the shard Kind cluster", "Export verified workspace", "Upload successful workspace output",
    "Export non-promotable product images", "Upload successful product output",
    "Export non-promotable daemon image", "Upload successful daemon output",
    "Export only completed smoke executables", "Upload successful smoke output",
}

TOKEN_RE = re.compile(r"\s*(&&|\|\||==|!=|!|\(|\)|,|'(?:[^']|'')*'|[A-Za-z_][A-Za-z0-9_.-]*)")


def tokenize(text):
    tokens, position = [], 0
    while position < len(text):
        match = TOKEN_RE.match(text, position)
        if not match:
            if text[position:].strip() == "":
                break
            raise SystemExit(f"unsupported expression syntax at {text[position:]!r}")
        tokens.append(match.group(1))
        position = match.end()
    return tokens


def expression_value(expression, context):
    text = expression.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2]
    tokens = tokenize(text)
    position = 0

    def peek():
        return tokens[position] if position < len(tokens) else None

    def take(expected=None):
        nonlocal position
        token = peek()
        if expected is not None and token != expected:
            raise SystemExit(f"expected {expected!r}, found {token!r} in {expression!r}")
        position += 1
        return token

    def truthy(value):
        return value not in ("", False, None)

    def primary():
        token = take()
        if token == "(":
            value = disjunction()
            take(")")
            return value
        if token == "!":
            return not truthy(primary())
        if token.startswith("'"):
            return token[1:-1].replace("''", "'")
        if peek() == "(":
            take("(")
            arguments = []
            while peek() != ")":
                arguments.append(disjunction())
                if peek() == ",":
                    take(",")
            take(")")
            if token == "contains":
                return str(arguments[1]) in str(arguments[0])
            if token in ("always", "success"):
                return True
            if token in ("failure", "cancelled"):
                return False
            raise SystemExit(f"unsupported function {token}")
        return context.get(token, "")

    def comparison():
        left = primary()
        while peek() in ("==", "!="):
            operator = take()
            right = primary()
            left = (str(left) == str(right)) if operator == "==" else (str(left) != str(right))
        return left

    # Like Actions, && and || yield an operand, so `a && 'x' || 'y'` is a value.
    def conjunction():
        value = comparison()
        while peek() == "&&":
            take()
            right = comparison()
            value = right if truthy(value) else value
        return value

    def disjunction():
        value = conjunction()
        while peek() == "||":
            take()
            right = conjunction()
            value = value if truthy(value) else right
        return value

    result = disjunction()
    if position != len(tokens):
        raise SystemExit(f"trailing tokens in {expression!r}")
    return result


def evaluate(expression, context):
    return expression_value(expression, context) not in ("", False, None)


def env_value(expression, context):
    """An env entry as the runner passes it: a string."""
    if "${{" not in str(expression):
        return str(expression)
    result = expression_value(expression, context)
    if isinstance(result, bool):
        return "true" if result else "false"
    return str(result)


def dispatch(selection, cw, desktop):
    with tempfile.NamedTemporaryFile("r") as output:
        environment = dict(
            os.environ, VERIFICATION_SELECTION=selection, VERIFICATION_TESTED_TREE_RECEIPT="fallback",
            CW_PACKAGE_SELECTED=cw, DESKTOP_PACKAGE_SELECTED=desktop,
            VERIFICATION_SUPERSEDED="false", GITHUB_OUTPUT=output.name,
        )
        subprocess.run([emitter], env=environment, check=True, stderr=subprocess.DEVNULL)
        return dict(line.strip().split("=", 1) for line in open(output.name) if line.strip())


scope_cache = {}


def run_scope_step(step, context):
    environment = {key: env_value(entry, context) for key, entry in step.get("env", {}).items()}
    key = (step["run"], tuple(sorted(environment.items())))
    if key not in scope_cache:
        with tempfile.NamedTemporaryFile("r") as output:
            subprocess.run(["bash", "-c", step["run"]], check=True,
                           env=dict(PATH=os.environ["PATH"], GITHUB_OUTPUT=output.name, **environment))
            scope_cache[key] = dict(line.strip().split("=", 1) for line in open(output.name) if line.strip())
    return scope_cache[key]


def legs(job):
    matrix = job.get("strategy", {}).get("matrix")
    if not matrix:
        return [{}]
    return [{"matrix.shard.slug": shard["slug"]} for shard in matrix["shard"]]


def job_work(job_id, base_context):
    """Per leg, the work steps that would run."""
    job = jobs[job_id]
    # Only scope steps whose outputs a later step condition reads are run.
    read_ids = set(re.findall(r"steps\.([A-Za-z0-9_-]+)\.outputs\.",
                              " ".join(str(step.get("if", "")) for step in job["steps"])))
    result = []
    for leg in legs(job):
        context = dict(base_context, **leg)
        # Step conditions read the job's BUILD_ONCE (compile once, infra#1632).
        if "BUILD_ONCE" in (job.get("env") or {}):
            context["env.BUILD_ONCE"] = env_value(job["env"]["BUILD_ONCE"], context)
        ran = []
        for step in job["steps"]:
            name = step.get("name") or step.get("uses", "")
            if "if" not in step or evaluate(step["if"], context):
                if step.get("id") in read_ids and "run" in step:
                    for key, value in run_scope_step(step, context).items():
                        context[f"steps.{step['id']}.outputs.{key}"] = value
                if name in WORK[job_id]:
                    ran.append(name)
        result.append(ran)
    return result


# Every step of a checked job is classified as work or support.
for job_id, work in WORK.items():
    names = {step.get("name") for step in jobs[job_id]["steps"] if "name" in step}
    if not work <= names:
        raise SystemExit(f"{job_id}: work steps no longer exist: {sorted(work - names)}")
    unclassified = names - work - SUPPORT
    if unclassified:
        raise SystemExit(f"{job_id}: classify these steps as work or support: {sorted(unclassified)}")
# A work step that carries its own selection condition must also never be
# left undispatched: when it would run, its job starts. Unconditional work
# (Kind builders, the compile) runs whenever its job is dispatched.
SELECTION_GATED = {
    job_id: {step["name"] for step in jobs[job_id]["steps"]
             if step.get("name") in work
             and re.search(r"outputs\.selection|_selected|steps\.", str(step.get("if", "")))}
    for job_id, work in WORK.items()
}
capability_jobs = {job_id for job_id, job in jobs.items()
                   if re.search(r"outputs\.[a-z_]+_expected == 'true'", job.get("if", ""))}
if capability_jobs - set(WORK):
    raise SystemExit(f"capability jobs without work classification: {sorted(capability_jobs - set(WORK))}")

# The events that reach these jobs.
EVENTS = {
    "push to main": {"github.event_name": "push", "github.ref": "refs/heads/main"},
    "pull request": {"github.event_name": "pull_request", "github.ref": "refs/pull/7/head"},
    "dispatch": {"github.event_name": "workflow_dispatch", "github.ref": "refs/heads/main"},
    "schedule": {"github.event_name": "schedule", "github.ref": "refs/heads/main"},
}

realistic = [line.strip() for line in open(realistic_path) if line.strip()]
universe = sorted({token for selection in realistic for token in selection.strip("|").split("|")}
                  - {"valid:v3", "complete"} | {"ios", "rust_pkg_codewire_desktop",
                                                "transport_derp_contract", "contracts_proto", "go_tailnet",
                                                "security_go", "go_consumer_interop",
                                                "workspace_agents", "change_class_workspace_pin"})
synthetic = set()
for token in universe:
    for extra in ((), ("policy", "policy_shell_omittable"), ("kind",), ("edge_kind",)):
        synthetic.add("|valid:v3|" + "|".join(sorted({token, *extra})) + "|complete|")
synthetic.add("|valid:v3|complete|")
checked = 0
for selection in sorted(set(realistic) | synthetic):
    # A scheduled selection dispatches no artifact group.
    scheduled_only = "|scheduled|" in selection
    for event, cw, desktop, kind_workspace in itertools.product(
            ("push to main", "pull request"),
            ("true", "false"), ("true", "false"), ("source", "pinned")):
        expected = dispatch(selection, cw, desktop)
        # A scheduled selection deliberately ignores artifact facts; its steps
        # see what dispatch saw.
        # The workspace-pin change class clears the cw and desktop facts in
        # the selection step (owner, 2026-10-24).
        pin_class = "|change_class_workspace_pin|" in selection
        facts = ("false", "false") if scheduled_only or pin_class else (cw, desktop)
        context = {
            **EVENTS[event],
            "needs.verification-selection.result": "success",
            # A pinned workspace dispatches no Kind workspace job.
            "needs.kind-workspace.result": "skipped" if kind_workspace == "pinned" else "success",
            "needs.verification-selection.outputs.kind_workspace_source": kind_workspace,
            "needs.kind-product.result": "success",
            "needs.kind-daemon.result": "success",
            "needs.kind-smokes.result": "success",
            # The packages shard runs the compile job's test archive; the
            # compile job is dispatched whenever the shards are.
            "needs.rust-compile.result": "success",
            "needs.verification-selection.outputs.selection": selection,
            "needs.verification-selection.outputs.tested_tree_receipt": "fallback",
            "needs.verification-selection.outputs.superseded": "false",
            "needs.verification-selection.outputs.cw_package_selected": facts[0],
            "needs.verification-selection.outputs.desktop_package_selected": facts[1],
        }
        for name, value in expected.items():
            context[f"needs.verification-selection.outputs.{name}"] = value
        for job_id in WORK:
            dispatched = evaluate(jobs[job_id]["if"], context)
            work = job_work(job_id, context)
            if dispatched and not all(work):
                raise SystemExit(
                    f"{job_id} would start with no work for {selection} "
                    f"(cw={cw} desktop={desktop}): legs={work}")
            gated = [sorted(set(leg) & SELECTION_GATED[job_id]) for leg in work]
            if not dispatched and any(gated):
                raise SystemExit(
                    f"{job_id} has selected work but is not dispatched for {selection} "
                    f"(cw={cw} desktop={desktop}): {gated}")
        checked += 1

# A scheduled run dispatches the Kind builds and shards alone, whatever the
# artifact facts say, and an unchanged one dispatches nothing.
KIND_JOBS = {"kind-workspace", "kind-product", "kind-daemon", "kind-smokes", "edge-kind"}
scheduled = [selection for selection in realistic if "|scheduled|" in selection]
if sorted(scheduled) != ["|valid:v3|kind|scheduled|complete|", "|valid:v3|scheduled|complete|"]:
    raise SystemExit(f"scheduled selections are {scheduled}")
for selection in scheduled:
    for cw, desktop, kind_workspace in itertools.product(
            ("true", "false"), ("true", "false"), ("source", "pinned")):
        expected = dispatch(selection, cw, desktop)
        context = {
            **EVENTS["schedule"],
            "needs.verification-selection.result": "success",
            "needs.kind-workspace.result": "skipped" if kind_workspace == "pinned" else "success",
            "needs.verification-selection.outputs.kind_workspace_source": kind_workspace,
            "needs.kind-product.result": "success",
            "needs.kind-daemon.result": "success",
            "needs.kind-smokes.result": "success",
            # The packages shard runs the compile job's test archive; the
            # compile job is dispatched whenever the shards are.
            "needs.rust-compile.result": "success",
            "needs.verification-selection.outputs.selection": selection,
            "needs.verification-selection.outputs.tested_tree_receipt": "fallback",
            "needs.verification-selection.outputs.superseded": "false",
            "needs.verification-selection.outputs.cw_package_selected": cw,
            "needs.verification-selection.outputs.desktop_package_selected": desktop,
        }
        for name, value in expected.items():
            context[f"needs.verification-selection.outputs.{name}"] = value
        started = {job_id for job_id in WORK if evaluate(jobs[job_id]["if"], context)}
        wanted = KIND_JOBS if "|kind|" in selection else set()
        if kind_workspace == "pinned":
            wanted = wanted - {"kind-workspace"}
        if started != wanted:
            raise SystemExit(f"a scheduled run with {selection} starts {sorted(started)}, "
                             f"not {sorted(wanted)} (cw={cw} desktop={desktop} kind={kind_workspace})")
        for job_id in started:
            if not all(job_work(job_id, context)):
                raise SystemExit(f"a scheduled run starts {job_id} with no work for {selection}")
        checked += 1
print(f"dispatched jobs always have work: {checked} event, selection and artifact combinations")
PY

echo 'select-verification fixtures: OK'

# Preflight runs the fast compile for exactly the selections that make CI run
# its rust-compile job (the emitter's rust_transport expectation).
compile_tokens='rust rust_curated_locks transport transport_derp_contract'
grep -qF "selected_any ${compile_tokens}" "$ROOT/scripts/ci/select/emit-verification-matrices.sh" || {
  echo 'rust_transport expectation no longer uses the fast-compile token set' >&2
  exit 1
}
grep -qF "selection_has_any ${compile_tokens}; then" "$ROOT/scripts/dev/preflight.sh" || {
  echo 'preflight fast compile drifted from the CI rust-compile selection' >&2
  exit 1
}
