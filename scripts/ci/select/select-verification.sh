#!/usr/bin/env bash
# Select product verification capabilities from one changed-path contract.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: select-verification.sh [--diagnostic-changed-files] [changed-files]

changed-files may be a file containing one path per line, or "-" for stdin.
Without an argument the script discovers pull-request or main-push changes.

Writes one versioned classification, capability token set, and required local
mode to stdout and to $GITHUB_OUTPUT. A failed discovery or malformed input
emits no machine-readable output. Use
--diagnostic-changed-files to append the classified path set to stdout.
Pull requests run Kind for a Kind-relevant path with explicit opt-in. Changes
to direct in-cluster fixture owners select their mandatory Kind proof directly.
Set VERIFICATION_REQUEST for product workflow_dispatch to a family token or
all.

A pull request selects what a push to main would for the same paths, less
Kind; the ci-full label adds Kind (#3119 step 2.1).

While main-push-switch.sh says so, a push to main selects no Kind. A schedule
event then selects Kind alone, and only when a path changed since
SCHEDULE_BASELINE_SHA (the last successful scheduled run's commit) selects it,
or when that baseline is unknown; otherwise it selects nothing.
EOF
}

selector_version=v3
classification=changed
diagnostic_changed_files=false
case "${1:-}" in
  --help|-h)
    usage
    exit 0
    ;;
  --diagnostic-changed-files)
    diagnostic_changed_files=true
    shift
    ;;
esac

if [ $# -gt 1 ]; then
  usage >&2
  exit 2
fi

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd -P)"
# The tree this selector came from. A pull request runs the trusted base's
# selector against the candidate checkout, so the two can differ.
selector_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"

tmp="$(mktemp)"
tokens_tmp="$(mktemp)"
graph_tmp="$(mktemp -d)"
trap 'rm -f "$tmp" "$tokens_tmp"; rm -rf "$graph_tmp"' EXIT

event="${GITHUB_EVENT_NAME:-}"
explicit_paths=false

# The one switch for what a push to main runs (owner decision 2026-10-20),
# read from this selector's own tree. Without the file a push keeps Kind.
MAIN_PUSH_RUNS_KIND_AND_DRY_RUN=true
main_push_switch="$selector_root/scripts/ci/select/main-push-switch.sh"
if [ -f "$main_push_switch" ]; then
  # shellcheck source=scripts/ci/select/main-push-switch.sh
  source "$main_push_switch"
fi
case "$MAIN_PUSH_RUNS_KIND_AND_DRY_RUN" in
  true|false) ;;
  *)
    echo "selector: MAIN_PUSH_RUNS_KIND_AND_DRY_RUN must be true or false" >&2
    exit 2
    ;;
esac

is_zero_sha() {
  [[ "${1:-}" =~ ^0+$ ]]
}

discover_pr_changed_files() {
  local out="$1"
  local base_ref="${GITHUB_BASE_REF:-}"
  local remote="${VERIFICATION_REMOTE:-origin}"

  base_ref="${base_ref#refs/heads/}"
  base_ref="${base_ref#heads/}"
  [ -n "$base_ref" ] || return 1

  if ! git remote get-url "$remote" >/dev/null 2>&1; then
    remote=gitea
  fi
  git remote get-url "$remote" >/dev/null 2>&1 || return 1

  local fetched_ref="refs/tmp/select-verification/${base_ref}"
  local existing_ref="refs/remotes/${remote}/${base_ref}"
  if ! git fetch --no-tags --depth=128 "$remote" \
      "+refs/heads/${base_ref}:${fetched_ref}" >/dev/null 2>&1 \
    && ! git fetch --no-tags "$remote" \
      "+refs/heads/${base_ref}:${fetched_ref}" >/dev/null 2>&1; then
    if git show-ref --verify --quiet "$existing_ref"; then
      echo "warning: unable to refresh ${remote}/${base_ref}; using ${existing_ref}" >&2
      fetched_ref="$existing_ref"
    else
      return 1
    fi
  fi

  local base
  base="$(git merge-base HEAD "$fetched_ref")" || return 1
  [ -n "$base" ] || return 1
  git diff --name-only "${base}...HEAD" > "$out"
}

discover_push_changed_files() {
  local out="$1"
  local before="${PUSH_BEFORE_SHA:-}"
  local after="${PUSH_AFTER_SHA:-${GITHUB_SHA:-HEAD}}"

  after="$(git rev-parse --verify "${after}^{commit}" 2>/dev/null)" || return 1
  if [ -n "$before" ]; then
    is_zero_sha "$before" && return 1
    before="$(git rev-parse --verify "${before}^{commit}" 2>/dev/null)" || return 1
    git merge-base --is-ancestor "$before" "$after" || return 1
    git diff --name-only "$before" "$after" > "$out"
    return
  fi

  if git rev-parse --verify "${after}^" >/dev/null 2>&1; then
    git diff --name-only "${after}^" "$after" > "$out"
    return
  fi
  return 1
}

# What changed since the last successful scheduled run's commit
# (SCHEDULE_BASELINE_SHA). Fails when there is no such commit on this one's
# history; the caller then treats the baseline as unknown.
discover_schedule_changed_files() {
  local out="$1"
  local baseline="${SCHEDULE_BASELINE_SHA:-}"
  local head="${GITHUB_SHA:-HEAD}"

  [[ "$baseline" =~ ^[0-9a-f]{40}$ ]] || return 1
  is_zero_sha "$baseline" && return 1
  head="$(git rev-parse --verify "${head}^{commit}" 2>/dev/null)" || return 1
  baseline="$(git rev-parse --verify "${baseline}^{commit}" 2>/dev/null)" || return 1
  git merge-base --is-ancestor "$baseline" "$head" || return 1
  git diff --name-only "$baseline" "$head" > "$out"
}

# Explicit changed paths stand for a known schedule baseline.
schedule_baseline_known=false
if [ $# -gt 0 ]; then
  explicit_paths=true
  schedule_baseline_known=true
  if [ "$1" = "-" ]; then
    cat > "$tmp"
  else
    cp "$1" "$tmp"
  fi
fi

declare -A selected=()
declare -A changed_crates=()

select_token() {
  selected["$1"]=1
}

token_selected() {
  [ "${selected[$1]:-}" = 1 ]
}

select_js_security() {
  select_token security
  select_token security_js
}

# Every path scripts/checks/security/audit-js-supply-chain.sh scans: its
# active_paths and web_runtime_paths pathspecs, plus the vendored browser
# assets it hashes. Without glob magic a Git pathspec `*` also matches `/`, as
# a [[ == ]] pattern does. test-select-verification.sh fails when the audit
# scans a pathspec that this list does not cover.
js_audit_paths=(
  ".gitea/**"
  "apps/**/Dockerfile"
  "apps/**/Dockerfile.*"
  "apps/dashboard/playwright.config.ts"
  "deployments/**/*.yaml"
  "deployments/**/*.yml"
  "Dockerfile"
  "Dockerfile.*"
  "Makefile"
  "package.json"
  "packages/**/*.json"
  "scripts/**"
  "apps/docs/zola/**"
  "crates/codewire-dashboard-web/src/**"
  "crates/codewire-dashboard-web/templates/**"
  "docs/homepage/**"
  "packages/codewire-design/**"
  "crates/codewire-dashboard-web/assets/**"
)

js_audit_scans() {
  local pattern
  for pattern in "${js_audit_paths[@]}"; do
    # shellcheck disable=SC2053 # The unquoted side is the glob to match.
    [[ "$1" == $pattern ]] && return 0
  done
  return 1
}

# The CI-script tests (policy-ci-script-tests) run for their own scripts,
# workflows and hooks, and for every product file one of them reads from the
# tree rather than from a fixture (#3119 A6). A CI-script test that starts
# reading another product file adds it here.
ci_script_test_input() {
  case "$1" in
    scripts/ci/*|scripts/dev/*|scripts/checks/*|.gitea/*|.githooks/*|\
    scripts/runtime/dev/preflight-openbao-native-secrets.sh|\
    Makefile|package.json|rust-toolchain.toml|.dockerignore|docker-bake.hcl|.gitleaks.toml|\
    images/*|deployments/docker/*.Dockerfile|apps/dashboard/Dockerfile|\
    proto/buf.gen.*.yaml|proto/README.md|docs/dev/PROTO-STYLE.md|\
    libs/gen-go/codewire/internal/v1/internalv1connect/coordinate.connect.go|\
    tests/contract/go.mod|tests/contract/billing/*|\
    crates/codewire-workspace-image/src/pin.rs|\
    crates/codewire-orchestration/src/sandbox/template/mod.rs|\
    crates/codewire-cw-release/src/local_runtime.rs|\
    crates/codewire-local-vmm/src/artifact.rs|crates/codewire-local-vmm/src/cw_runtime.rs|\
    crates/codewire-local-vmm/src/darwin/mod.rs|crates/codewire-local-vmm/src/runtime_install.rs|\
    crates/codewire-local-vmm/src/supervisor_config.rs|\
    crates/codewire-local-vmm/src/darwin/path/*.py|\
    crates/codewire-local-vmm/macos-vz-runner/*|\
    crates/codewire-vmm-guest-probe/src/cw_runtime.rs|\
    crates/codewire-vmm-guest-probe/src/cw_runtime_live.rs|\
    crates/codewire-vmm-guest-probe/src/newc.rs)
      return 0
      ;;
  esac
  return 1
}

# The Kind tool tests run with Edge static verification only when one of
# their inputs changes (#3119 R8): the CI and developer scripts, and every
# product file one of them reads from the tree rather than from a fixture.
# A Kind tool test that starts reading another product file adds it here.
kind_tool_test_input() {
  case "$1" in
    scripts/ci/*|scripts/dev/*|.gitea/*|.githooks/*|\
    Makefile|Cargo.toml|docker-bake.hcl|deployments/docker/kind-dev-binary.Dockerfile|\
    deployments/k8s/*|tests/e2e/kind/*|tests/fixtures/orchestration/*|\
    apps/dashboard/e2e/*|\
    crates/codewire-client/examples/*|\
    crates/codewire-orchestration/src/bin/*|\
    crates/codewire-orchestration/src/sandbox/template/workspace.rs|\
    crates/codewire-orchestration/src/worker/credential_relay/epoch.rs|\
    crates/codewire-credential-service/src/runtime/kind/*|\
    crates/codewire-daemon/src/config.rs|\
    crates/codewire-daemon-proto/src/lib.rs|\
    crates/codewire-workspace-image/src/pin.rs)
      return 0
      ;;
  esac
  return 1
}

select_services() {
  select_token service_integration
  select_token service_idp
  select_token service_billing
  select_token service_orchestration
  select_token service_coordinator
  select_token service_temporal
  select_token service_nats
  select_token service_connectcore
}

select_all_transport() {
  local package
  select_token transport
  select_token transport_derp_contract
  for package in \
      codewire_netstack codewire_tailnet codewire_daemon codewire_local_vmm \
      codewire_mesh codewire_derp codewire_udp_relay codewire_coordinator \
      codewire_vmm_guest_probe; do
    select_token "transport_pkg_${package}"
  done
}

select_all_contracts() {
  select_token contracts
  select_token contracts_proto
}

# The whole Rust workspace graph: what a root manifest, lockfile or toolchain
# change selects. Workspace graph, resolution, and toolchain changes can alter
# both the host VMM and the statically packaged guest probe, so their
# cross-target and reproducible-initramfs checks come too.
select_rust_workspace() {
  select_token rust
  select_token rust_workspace
  select_token rust_curated_locks
  select_token transport
  select_token transport_pkg_codewire_local_vmm
  select_token transport_pkg_codewire_vmm_guest_probe
}

# One workspace crate's own tests, in the family that owns its feature graph.
select_crate_tests() {
  case "$1" in
    codewire-netstack|codewire-tailnet|codewire-daemon|codewire-local-vmm|\
    codewire-mesh|codewire-derp|codewire-udp-relay|codewire-coordinator|\
    codewire-vmm-guest-probe)
      select_token transport
      select_token "transport_pkg_${1//-/_}"
      ;;
    *)
      select_token rust
      select_token "rust_pkg_${1//-/_}"
      ;;
  esac
}

# Prints the workspace crates under crates/ whose tests can break when the
# named crates change: every crate that reaches one of them through normal or
# build dependencies, transitively, plus each crate that takes one of those as
# a dev-dependency. A dev-dependency compiles only into its dependent's tests,
# so it selects that crate without reaching the crates that depend on it.
# Optional and platform-specific dependencies count.
#
# Cargo reads the classified tree's manifests offline, with --no-deps, which
# resolves nothing and runs no build script. It runs from an empty directory
# on the toolchain this selector's own tree names, so a candidate's toolchain
# file or Cargo configuration cannot choose what runs. A crate the workspace
# does not list (a deleted, detached or new crate) has no dependents. Any
# failure returns non-zero, and the caller selects the whole workspace.
crate_graph_dependents() {
  local channel metadata="$graph_tmp/metadata.json" cargo_env=()
  [ -f "$repo_root/Cargo.toml" ] || return 0
  channel="$(sed -nE 's/^channel[[:space:]]*=[[:space:]]*"([^"]+)".*$/\1/p' \
    "$selector_root/rust-toolchain.toml" 2>/dev/null | head -n 1)"
  if [ -n "$channel" ]; then
    cargo_env+=("RUSTUP_TOOLCHAIN=$channel")
  fi
  (
    cd "$graph_tmp" &&
      env "${cargo_env[@]}" RUSTUP_AUTO_INSTALL=0 CARGO_NET_OFFLINE=true \
        cargo metadata --offline --no-deps --format-version 1 \
        --manifest-path "$repo_root/Cargo.toml"
  ) > "$metadata" 2> "$graph_tmp/cargo.stderr" || {
    sed 's/^/  /' "$graph_tmp/cargo.stderr" | head -n 20 >&2
    return 1
  }
  python3 - "$metadata" "$repo_root" "$@" <<'PY'
import json
import os
import sys

metadata_path, repo_root, *changed = sys.argv[1:]
try:
    with open(metadata_path, encoding="utf-8") as handle:
        packages = json.load(handle)["packages"]
except (OSError, ValueError, KeyError, TypeError) as error:
    sys.exit(f"  cargo metadata is unreadable: {error!r}")
crates_root = os.path.join(os.path.realpath(repo_root), "crates")


def crate_name(directory):
    directory = os.path.realpath(directory)
    if os.path.dirname(directory) != crates_root:
        return None
    return os.path.basename(directory)


members = {}
for package in packages:
    name = crate_name(os.path.dirname(package["manifest_path"]))
    if name is not None:
        members[name] = package

builds_into = {name: set() for name in members}
tests_against = {name: set() for name in members}
for name, package in members.items():
    for dependency in package["dependencies"]:
        target = crate_name(dependency["path"]) if dependency.get("path") else None
        if target not in members or target == name:
            continue
        if dependency.get("kind") == "dev":
            tests_against[target].add(name)
        else:
            builds_into[target].add(name)

built = {name for name in changed if name in members}
pending = list(built)
while pending:
    for dependent in builds_into[pending.pop()]:
        if dependent not in built:
            built.add(dependent)
            pending.append(dependent)
tested = set(built)
for name in built:
    tested |= tests_against[name]
for name in sorted(tested):
    print(name)
PY
}

select_all_product() {
  local include_ios="${1:-false}" family
  for family in \
      policy policy_shell ci_script_tests rust go_support web docs sdk_go sdk_ts \
      sdk_python database \
      service_integration edge_kind kind_tools release deploy security \
      confidential_script_tests dev_smoke_script_tests; do
    select_token "$family"
  done
  # The iOS package is independently hermetic and comparatively expensive.
  # Only its own paths, or an operator's explicit all request, select it.
  if [ "$include_ios" = true ]; then
    select_token ios
  fi
  select_all_contracts
  select_all_transport
  select_token rust_workspace
  select_token rust_curated_locks
  select_token go_tailnet
  select_token go_consumer_interop
  select_token security_go
  select_token security_dev_smoke_auth
  select_token security_idp_kek
  select_token security_js
  select_token kind
  select_services
}

select_dispatch_request() {
  local request="${VERIFICATION_REQUEST:-policy}"
  case "$request" in
    all)
      select_all_product true
      ;;
    service_integration)
      select_services
      ;;
    edge_kind)
      select_token edge_kind
      select_token kind_tools
      select_token kind
      ;;
    rust)
      select_token rust
      select_token rust_workspace
      select_token rust_curated_locks
      ;;
    go_support)
      select_token go_support
      select_token go_tailnet
      select_token go_consumer_interop
      ;;
    security)
      select_token security
      select_token security_go
      select_token security_dev_smoke_auth
      select_token security_idp_kek
      select_token security_js
      ;;
    transport)
      select_all_transport
      ;;
    contracts)
      select_all_contracts
      ;;
    policy)
      select_token policy
      select_token policy_shell
      select_token ci_script_tests
      ;;
    web|docs|sdk_go|sdk_ts|sdk_python|database|release|deploy|ios)
      select_token "$request"
      ;;
    *)
      echo "warning: unsupported verification request '${request}'; selecting all product verification" >&2
      select_all_product
      ;;
  esac
}

truthy() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

# The ci-full label asks a pull request for the verification a push to main
# would run for the same paths, Kind included.
pr_ci_full=false
if [ -n "${GITHUB_EVENT_PATH:-}" ] && [ -f "$GITHUB_EVENT_PATH" ] \
    && grep -Eq '"name"[[:space:]]*:[[:space:]]*"ci-full"' "$GITHUB_EVENT_PATH"; then
  pr_ci_full=true
fi

# Hosted, a pull request runs Kind only with ci-full (owner, 2026-10-21);
# local tooling that needs Kind's selection asks with KIND_E2E_OPT_IN.
pr_kind_opt_in=false
if truthy "${KIND_E2E_OPT_IN:-}" || [ "$pr_ci_full" = true ]; then
  pr_kind_opt_in=true
fi

event_selected=false
if [ "$event" = workflow_dispatch ] && [ "$explicit_paths" = false ]; then
  select_dispatch_request
  event_selected=true
elif [ "$event" = push ] \
  && { [[ "${GITHUB_REF:-}" == refs/tags/v* ]] \
    || { [ "${GITHUB_REF_TYPE:-}" = tag ] && [[ "${GITHUB_REF_NAME:-}" == v* ]]; }; }; then
  select_token release
  select_token deploy
  event_selected=true
fi

if [ "$event_selected" = false ] && [ "$explicit_paths" = false ]; then
  case "$event" in
    pull_request)
      if ! discover_pr_changed_files "$tmp"; then
        echo "selector: pull-request baseline is unavailable" >&2
        exit 2
      fi
      ;;
    push)
      if ! discover_push_changed_files "$tmp"; then
        echo "selector: push baseline is unavailable" >&2
        exit 2
      fi
      ;;
    workflow_dispatch)
      select_dispatch_request
      event_selected=true
      ;;
    schedule)
      if discover_schedule_changed_files "$tmp"; then
        schedule_baseline_known=true
      else
        : > "$tmp"
      fi
      ;;
    *)
      echo "selector: unsupported event '${event:-unset}'" >&2
      exit 2
      ;;
  esac
fi

kind_relevant=false
saw_path=false

if [ "$event_selected" = false ]; then
  # Policy is the lightweight invariant for every path-selected PR/main run.
  select_token policy

  while IFS= read -r path; do
    [ -n "$path" ] || continue
    saw_path=true
    recognized=false

    # Shell analysis is its own policy domain. The trusted selector owns this
    # token, so a candidate selector cannot avoid ShellCheck by changing its
    # own routing. Deleted shell inputs remain selected by their path suffix.
    case "$path" in
      *.sh|.gitea/workflows/ci.yaml)
        select_token policy_shell
        ;;
    esac

    # The CI-script tests are their own policy part, which the trusted
    # selector owns as it owns the shell domain (#3119 A6). They run when a
    # script, workflow or hook changes, or a product file one of them reads
    # from the tree. Deleted inputs stay selected by their path.
    if ci_script_test_input "$path"; then
      select_token ci_script_tests
    fi
    if kind_tool_test_input "$path"; then
      select_token kind_tools
    fi

    # The JavaScript supply-chain audit is grep-only. Run it for any path it
    # scans, in addition to that path's own classification.
    if js_audit_scans "$path"; then
      select_js_security
    fi

    # The Kind dev-binary build is local-only (`make kind-deploy`): no CI,
    # release or deploy workflow and no bake group builds it, so it is not a
    # product image input and needs only Policy.
    case "$path" in
      deployments/docker/kind-dev-binary.Dockerfile)
        recognized=true
        continue
        ;;
    esac

    # These frozen pre-Rust CLI assets are documentation or retirement inputs,
    # not deployable image, edge, database, or Kind inputs. Keep this before
    # generic Dockerfile and compose classification so their deletion stays
    # narrow during the clean CLI cutover.
    case "$path" in
      apps/cli/.env.example|apps/cli/.gitignore|apps/cli/Caddyfile|\
      apps/cli/Dockerfile|apps/cli/LICENSE|apps/cli/codewire.yaml|\
      apps/cli/contrib/*|apps/cli/demo/*|apps/cli/docker-compose.yml|\
      apps/cli/docs/*|apps/cli/charts/*/templates/NOTES.txt)
        select_token policy
        continue
        ;;
    esac

    # License texts are validated as package payloads by the exact license-map
    # policy check. Their contents do not alter product compilation or runtime
    # behavior, even when they live below a product-owned directory.
    case "$path" in
      LICENSE|LICENSE-*|*/LICENSE|*/LICENSE-*)
        select_token policy
        continue
        ;;
    esac

    if [[ "$path" != */* && "$path" == *.md ]]; then
      recognized=true
    fi
    case "$path" in
      docs/*|AGENTS.md|CLAUDE.md|crates/README.md|scripts/README.md|\
      .agents/*|.claude/*|.github/*|.gitea/default_merge_message/*)
        recognized=true
        ;;
    esac

    if [ ! -e "$path" ]; then
      case "$path" in
        scripts/*)
          # Deleted script paths are validated by the remaining moved path and
          # by policy self-tests. Keep the selector from fail-closing solely
          # because a cleanup PR removes an old script entrypoint.
          select_token policy
          recognized=true
          ;;
        aur/*|apps/cli/aur/*|apps/cli/scripts/update-homebrew-formula.sh|\
        .schema-reset-write-test|deploy/cwpreview-ingress.yaml)
          # Retired manual AUR/Homebrew packaging, a stray root file and a
          # hand-applied preview Ingress (deployments/k8s owns it) feed no
          # build, test or package. Their removal needs only Policy; a path
          # that reappears is unclassified again.
          select_token policy
          recognized=true
          continue
          ;;
      esac
    fi

    # CI policy changes validate only the workflow/selector contract. Product
    # files in the same PR still add their own families below.
    case "$path" in
      .gitea/workflows/ci.yaml|.gitea/workflows/manual-diagnostics.yaml|\
      .gitea/workflows/ci-start-latency.yaml|\
      .gitea/workflows/ci-done-measures.yaml|\
      .gitea/workflows/rust-latest-canary.yaml|\
      .gitea/workflows/rust-cache-refresh.yaml|\
      .gitea/workflows/connect-apikey-smoke.yaml|\
      .gitea/workflows/source-approval.yml|\
      .gitea/workflows/dev-deployment-smoke-receipt.yaml|\
      .gitea/workflows/prod-readonly-smoke.yaml|\
      .gitea/workflows/runtime-dev-commodity-smoke.yaml|\
      .gitea/workflows/merge-check.yaml|\
      .githooks/pre-push|Makefile|scripts/dev/install-hooks.sh|\
      scripts/dev/dashboard-watch.py|\
      scripts/dev/macos-cli.py|scripts/dev/test-macos-cli.py|\
      scripts/dev/macos-command-owner.py|\
      scripts/dev/macos-ext4-tool.py|scripts/dev/test-macos-ext4-tool.py|\
      scripts/dev/macos-git-tool.py|scripts/dev/test-macos-git-tool.py|\
      scripts/dev/macos-local-runtime.py|scripts/dev/test-macos-local-runtime.py|\
      scripts/dev/linux-local-runtime.py|scripts/dev/test-linux-local-runtime.py|\
      scripts/dev/preflight.sh|scripts/ci/select/select-verification.sh|\
      scripts/dev/pre-push.sh|scripts/dev/preflight-push.sh|\
      scripts/dev/preflight-environment.sh|\
      scripts/ci/select/emit-verification-matrices.sh|\
      scripts/ci/select/require-verification-results.sh|\
      scripts/ci/select/main-push-switch.sh|\
      scripts/ci/select/last-scheduled-run.py|\
      scripts/ci/tests/test-last-scheduled-run.py|\
      scripts/ci/tests/test-ci-done-measures.py|\
      scripts/ci/receipts/emit-verification-receipt.py|\
      scripts/ci/receipts/verify-tested-tree-receipt.sh|\
      scripts/ci/receipts/verify-release-tag-receipt.sh|\
      scripts/ci/receipts/emit-rust-cache-receipt.py|\
      scripts/ci/receipts/verify-rust-cache-receipt.sh|\
      scripts/ci/cache/prepare-rust-dependency-cache.sh|\
      scripts/ci/cache/select-rust-cache-key.sh|\
      scripts/ci/images/resolve-published-support-pair.sh|\
      scripts/ci/plan/*|scripts/ci/measure/*|\
      scripts/ci/tests/test-select-verification.sh|\
      scripts/ci/tests/test-source-approval-workflow.sh|\
      scripts/ci/tests/test-resolve-published-support-pair.sh|\
      scripts/ci/tests/test-resolve-deployed-source.sh|\
      scripts/ci/tests/test-require-verification-results.sh|\
      scripts/ci/tests/test-emit-verification-matrices.sh|\
      scripts/ci/tests/test-verify-tested-tree-receipt.sh|\
      scripts/ci/tests/test-verify-release-tag-receipt.sh|\
      scripts/ci/tests/test-pre-push-worktree.sh|\
      scripts/ci/tests/test-push-check-shellcheck.sh|\
      scripts/ci/tests/test-go-source-ownership.sh|\
      scripts/ci/tests/test-dev-deployment-smoke-receipt.sh|\
      scripts/ci/tests/test-agent-sandbox-pin.sh|\
      scripts/ci/tests/test-rust-owned-fixtures.sh|\
      scripts/ci/tests/test-rust-toolchain.sh|\
      scripts/ci/tests/test-runtime-profile.py|\
      scripts/ci/tests/test-cargo-cache-capacity.sh|\
      scripts/ci/tests/test-rust-cache-workflow.sh|\
      scripts/ci/tests/test-rust-cache-receipts.sh|\
      scripts/ci/tests/test-shellcheck-policy-domain.sh|\
      scripts/ci/tests/test-openbao-only-secret-authority.sh|\
      scripts/ci/tests/test-preflight-openbao-native-secrets.sh|\
      scripts/ci/tests/test-sync-local-secrets.sh|\
      scripts/ci/tests/test-kind-runtime-images.sh|\
      scripts/ci/tests/test-kind-watch-github-app.sh|\
      scripts/ci/tests/fixtures/cargo-cache-df.sh|\
      scripts/ci/verify/integration-postgres.sh|scripts/ci/tests/test-integration-postgres.sh|\
      scripts/ci/tests/test-integration-lane.py|\
      scripts/ci/verify/resolve-cargo-target-dir.sh|\
      scripts/ci/tests/test-resolve-cargo-target-dir.sh|\
      scripts/ci/tests/test-cargo-target-runner-failures.sh|\
      scripts/ci/tests/test-local-rust-cache.sh|\
      scripts/ci/tests/test-run-host-rust-build.sh|\
      scripts/ci/tests/test-run-side-by-side.sh|\
      scripts/ci/tests/test-darwin-cross-check.sh|\
      scripts/ci/tests/test-ci-runner-image-contract.sh|\
      scripts/ci/tests/test-ci-tool-downloads.sh|\
      scripts/ci/tests/test-service-ssh-image-verifier.sh|\
      scripts/ci/verify/run-product-verification.sh|\
      scripts/ci/tests/test-retired-local-sdk-contract.sh|\
      scripts/checks/security/audit-rust-only-runtime.sh|\
      scripts/ci/setup/*.sh|scripts/ci/verify/*.sh|\
      scripts/ci/verify/rust-stack-rehearsal.sh)
        select_token policy
        recognized=true
        ;;
    esac

    case "$path" in
      .gitea/workflows/desktop-package.yaml)
        # Deletion-only tombstone. The canonical artifact plan now owns the
        # desktop package decision inside the Rust capability group.
        select_token policy
        recognized=true
        ;;
    esac

    case "$path" in
      scripts/ci/release/package-codewire-desktop.sh|\
      scripts/ci/tests/test-package-codewire-desktop.sh|\
      scripts/checks/source/check-native-desktop-ui.py|\
      scripts/checks/contracts/native-desktop-ui-policy.json)
        select_token policy
        select_token rust
        select_token rust_pkg_codewire_desktop
        recognized=true
        ;;
    esac

    case "$path" in
      .gitea/workflows/ci.yaml|scripts/dev/preflight.sh|\
      scripts/ci/select/select-verification.sh|\
      scripts/ci/tests/test-select-verification.sh|\
      scripts/ci/verify/run-product-verification.sh|\
      scripts/ci/verify/check-curated-rust-locks.sh|\
      scripts/ci/tests/test-curated-rust-locks.sh|\
      scripts/ci/verify/curated_rust_locks.py|\
      scripts/dev/sync-curated-rust-locks.sh|\
      scripts/ci/verify/compile-all-targets.sh)
        select_token rust_curated_locks
        recognized=true
        ;;
    esac

    case "$path" in
      .gitea/workflows/ci.yaml|scripts/dev/preflight.sh|\
      scripts/ci/select/select-verification.sh|\
      scripts/ci/tests/test-select-verification.sh|\
      scripts/ci/verify/run-product-verification.sh)
        # Changes to the capability's routing must execute the capability on
        # the candidate tree, not merely assert that its token is present.
        select_token dev_smoke_script_tests
        recognized=true
        ;;
    esac

    case "$path" in
      scripts/ci/verify/side-by-side.sh)
        # The release family runs its steps through it; policy core does too,
        # and every scripts/ci/verify helper already selects policy.
        select_token release
        recognized=true
        ;;
    esac

    case "$path" in
      scripts/ci/verify/run-integration-verification.sh|scripts/ci/verify/integration-lane.py|\
      scripts/ci/verify/integration-postgres.sh|scripts/ci/tests/test-integration-postgres.sh)
        # These files own database execution and every service's integration
        # harness, including the PostgreSQL both run against (#3198). Their
        # changes must qualify both executable families.
        select_token policy
        select_token database
        select_services
        recognized=true
        ;;
    esac

    if [[ "$path" != */* && "$path" == *.example.json ]]; then
      select_token policy
      recognized=true
    fi

    case "$path" in
      codewire.yaml)
        # The repository's own environment file. codewire-project's tests
        # parse it, so a schema change cannot leave it invalid.
        select_token policy
        select_token rust
        select_token rust_pkg_codewire_project
        recognized=true
        ;;
    esac

    case "$path" in
      .gitattributes|.gitignore|.dockerignore|.env.example|.envrc.example|turbo.json)
        select_token policy
        recognized=true
        ;;
      .gitleaks.toml)
        # Gitea runs the instance source scan independently. Repository CI
        # needs only its policy contract and security capability, not every
        # product family, for a scanner-configuration-only change.
        select_token security
        recognized=true
        ;;
      docker-compose.yml)
        select_token database
        select_token deploy
        select_token edge_kind
        select_token web
        kind_relevant=true
        recognized=true
        ;;
      Cargo.toml|Cargo.lock|rust-toolchain.toml|.config/hakari.toml)
        select_rust_workspace
        recognized=true
        ;;
      go.mod|go.sum|go.work|go.work.sum)
        select_token go_support
        select_token go_tailnet
        select_token go_consumer_interop
        select_token sdk_go
        select_token security
        select_token security_go
        recognized=true
        ;;
      package.json|bun.lock|bunfig.toml)
        select_all_contracts
        select_token web
        select_js_security
        recognized=true
        ;;
      scripts/checks/repo_policy/licensing.py|scripts/checks/repo_policy/public_addresses.py|scripts/checks/repo_policy/private_hosts.py)
        # The package inventory and the public address and private host guards run only in
        # policy-core; they do not execute contracts, deployments, releases,
        # or runtime security.
        select_token policy
        recognized=true
        ;;
      scripts/checks/repo_checks.py|scripts/checks/repo_policy/*.py)
        select_token contracts
        select_token contracts_proto
        select_token deploy
        select_token edge_kind
        select_token policy
        select_token release
        select_token security
        select_token security_idp_kek
        recognized=true
        ;;
    esac

    case "$path" in
      scripts/ci/tests/test-admin-proto-boundary.sh)
        # A guard change must exercise its real dependency graph in provisioned
        # Rust, while shared Policy retains only its static descriptor checks.
        select_token rust
        select_token rust_pkg_codewire_cli_bin
        recognized=true
        ;;
    esac

    case "$path" in
      proto/*|buf.yaml|buf.gen*.yaml)
        select_token contracts
        select_token contracts_proto
        select_token edge_kind
        select_token go_support
        select_token go_consumer_interop
        recognized=true
        ;;
      crates/codewire-proto/*|crates/codewire-admin-proto/*)
        select_token contracts
        select_token contracts_proto
        recognized=true
        ;;
      crates/codewire-local-vmm/proto/*)
        # The local VM runtime contract stays wire compatible with the oldest
        # supported release; its Rust consumers select through the crate.
        select_token contracts
        select_token contracts_proto
        ;;
      scripts/checks/contracts/local-runtime-oldest/*|\
      scripts/ci/proto/build-rust-descriptors.sh|\
      scripts/checks/proto_breaking.py|\
      scripts/checks/contracts/proto-retirements.sha256|\
      scripts/checks/contracts/proto-breaking-preimages.sha256)
        # The Rust audience-descriptor builder and the exact clean-break
        # preimage policy alter contract verification rather than runtime
        # behavior.
        select_token contracts
        select_token contracts_proto
        recognized=true
        ;;
      scripts/checks/contracts/mesh-final-surface-policy.json)
        # The final Mesh guard is a lightweight policy check. Product paths in
        # the same change continue through the independent classifiers below.
        recognized=true
        ;;
      scripts/checks/contracts/connect-edge-ownership.json)
        select_token contracts
        select_token contracts_proto
        select_token edge_kind
        recognized=true
        ;;
      libs/gen-go/*)
        select_token contracts
        select_token contracts_proto
        select_token go_support
        select_token go_consumer_interop
        recognized=true
        ;;
      scripts/checks/contracts/permanent-raw-surface-policy.json)
        # The permanent raw-surface policy is checked in Policy; product paths
        # in the same change continue through their own classifiers.
        recognized=true
        ;;
      scripts/checks/contracts/design-token-policy.json)
        # The design-system guard reads only this contract and runs in
        # Policy; product paths in the same change keep their own classifiers.
        recognized=true
        ;;
      openapi.json|crates/codewire-api-contract/*|crates/codewire-api-types/*|\
      crates/codewire-core/*|libs/api-client-go/*|libs/api-client-python/*|\
      libs/api-client-ts/*|packages/codewire-types/*)
        # These paths are deletion-only migration tombstones. A future
        # recreation is rejected by the permanent raw-surface policy.
        if [ -e "$repo_root/$path" ]; then
          echo "::error::retired OpenAPI source path recreated: $path" >&2
          exit 1
        fi
        recognized=true
        ;;
      packages/codewire-proto-ts/*)
        select_token contracts
        select_token contracts_proto
        recognized=true
        ;;
      libs/gen-python/*)
        select_token contracts
        select_token contracts_proto
        recognized=true
        ;;
    esac

    case "$path" in
      proto/codewire/v1/common.proto|proto/codewire/v1/environment.proto|\
      proto/codewire/v1/preset.proto)
        # These public adapters are hand-owned in every SDK. Run all three
        # whenever their canonical request/response schema changes.
        select_token sdk_go
        select_token sdk_python
        select_token sdk_ts
        recognized=true
        ;;
    esac

    case "$path" in
      proto/codewire/bridge/v1/bridge.proto)
        # Neutral credential bridge frames are generated publicly and consumed
        # by both private native and platform Rust transports.
        select_token rust
        select_token rust_pkg_codewire_cli
        select_token rust_pkg_codewire_credential_bridge
        select_token rust_pkg_codewire_credential_broker
        select_token rust_pkg_codewire_credential_service
        select_token rust_pkg_codewire_daemon
        select_token rust_pkg_codewire_daemon_proto
        select_token rust_pkg_codewire_local_credentials
        select_token rust_pkg_codewire_local_vmm
        select_token rust_pkg_codewire_proto
        select_token transport
        select_token transport_pkg_codewire_daemon
        select_token transport_pkg_codewire_local_vmm
        select_token transport_pkg_codewire_vmm_guest_probe
        recognized=true
        ;;
      proto/codewire/v1/environment.proto)
        # Environment requests are consumed directly by the platform clients,
        # dashboard, orchestration adapter, and local VMM public API.
        select_token rust
        select_token rust_pkg_codewire_cli
        select_token rust_pkg_codewire_client
        select_token rust_pkg_codewire_dashboard_web
        select_token rust_pkg_codewire_orchestration
        select_token rust_pkg_codewire_proto
        select_token transport
        select_token transport_pkg_codewire_local_vmm
        select_token web
        recognized=true
        ;;
      proto/codewire/v1/preset.proto)
        # Preset requests are consumed directly by the platform clients,
        # dashboard, and orchestration adapter.
        select_token rust
        select_token rust_pkg_codewire_cli
        select_token rust_pkg_codewire_client
        select_token rust_pkg_codewire_dashboard_web
        select_token rust_pkg_codewire_orchestration
        select_token rust_pkg_codewire_proto
        select_token web
        recognized=true
        ;;
      proto/codewire/v1/common.proto)
        # The shared setup and project messages also have handwritten Rust and
        # dashboard consumers outside the generated-proto crate.
        select_token rust
        select_token rust_pkg_codewire_cli
        select_token rust_pkg_codewire_client
        select_token rust_pkg_codewire_dashboard_web
        select_token rust_pkg_codewire_orchestration
        select_token rust_pkg_codewire_project_proto
        select_token rust_pkg_codewire_proto
        select_token transport
        select_token transport_pkg_codewire_local_vmm
        select_token transport_pkg_codewire_vmm_guest_probe
        select_token web
        recognized=true
        ;;
    esac

    case "$path" in
      apps/api/*|autoagent/*|libs/gatewayauth/*|\
      libs/daemon-proto/gen/*|libs/daemon-proto/buf.gen.yaml|\
      libs/daemon-proto/go.mod|libs/daemon-proto/go.sum|\
      tests/contract/coordinator/*|tests/contract/file/*|\
      tests/contract/orchestration/*)
        if [ -e "$repo_root/$path" ]; then
          echo "::error::retired former-Go implementation path recreated: $path" >&2
          exit 1
        fi
        recognized=true
        ;;
      libs/daemon-proto/proto/*|libs/daemon-proto/buf.yaml)
        select_token rust
        # Both daemon-initiated local and gateway-initiated platform brokerage
        # consume these private frames. Rust owns both broker feature graphs.
        select_token rust_pkg_codewire_credential_bridge
        select_token rust_pkg_codewire_credential_broker
        select_token rust_pkg_codewire_daemon_proto
        select_token transport
        select_token transport_pkg_codewire_daemon
        select_token transport_pkg_codewire_local_vmm
        select_token transport_pkg_codewire_vmm_guest_probe
        recognized=true
        ;;
      libs/tailnet/*|scripts/ci/verify/tailnet-parity.sh)
        select_token go_support
        select_token go_tailnet
        recognized=true
        ;;
    esac

    case "$path" in
      libs/sdk-go/*)
        select_token sdk_go
        select_token go_support
        select_token go_consumer_interop
        recognized=true
        ;;
      libs/sdk-ts/*)
        select_token sdk_ts
        recognized=true
        ;;
      libs/sdk-python/*)
        select_token sdk_python
        recognized=true
        ;;
      libs/sdk-examples/run-claude/*)
        # Deletion-only tombstone for the retired Docker/Lima SDK example.
        # The policy guard fails if this source tree is reintroduced.
        recognized=true
        ;;
    esac

    case "$path" in
      .supplychain/vendor-artifacts.json)
        # The external instance-scoped scanner verifies the package registry
        # signature, tarball, and exact local bytes. Repository CI still runs
        # the focused JavaScript security policy without fanning a provenance-
        # only edit out to unrelated product families.
        select_js_security
        recognized=true
        ;;
      .supplychain/bun-baseline.json|.supplychain/source-policy.json)
        # The independent source-approval job verifies the registry baseline
        # and source policy against the protected base. Repository CI keeps
        # its static policy contract; these inputs cannot change a product
        # image or Kind topology by themselves.
        select_token policy
        recognized=true
        ;;
      packages/codewire-types/package.json)
        # Deletion-only tombstone; no JavaScript package remains here.
        recognized=true
        ;;
      apps/dashboard/package.json|\
      packages/*/package.json|\
      libs/sdk-ts/package.json|libs/sdk-ts/package-lock.json)
        select_js_security
        recognized=true
        ;;
    esac

    case "$path" in
      apps/dashboard/runtime-inventory.json|apps/dashboard/rollback.json)
        select_token deploy
        select_token edge_kind
        select_token release
        select_token security
        select_token web
        kind_relevant=true
        recognized=true
        ;;
      apps/dashboard/scripts/prepare-dev-smoke-browser-auth.ts|\
      apps/dashboard/scripts/dev-ux-ownership.ts|\
      apps/dashboard/scripts/dev-ux-ownership.test.ts|\
      apps/dashboard/scripts/dev-ux-walkthrough.ts|\
      apps/dashboard/scripts/prepare-dev-smoke-browser-auth.test.ts)
        # Dedicated Dev smoke tooling uses dashboard's pinned browser libraries,
        # but does not change product templates or require rebuilding Kind.
        select_token dev_smoke_script_tests
        recognized=true
        ;;
      apps/docs/*)
        # The Zola docs site. The docs family builds and checks it (internal
        # links included) with the image's pinned Zola; the dashboard browser
        # gate in web never reads it.
        select_token docs
        recognized=true
        ;;
      apps/dashboard/*|favicon.svg|logo/*|\
      scripts/dev/design-system-server.py|scripts/ci/tests/test-dashboard-browser-gate.sh|\
      scripts/ci/verify/run-design-fixtures.sh|scripts/ci/tests/test-run-design-fixtures.sh|\
      scripts/ci/verify/playwright-browser-runtime.sh|scripts/ci/install-pinned-playwright-chromium.sh)
        # The design-fixture browser gate in run_web runs the pinned Chromium
        # through the shared browser runtime, so its inputs also select web.
        select_token web
        recognized=true
        ;;
      apps/ios/*)
        select_token ios
        recognized=true
        ;;
      apps/cli/Makefile|scripts/dev/test-cli-host.py|scripts/dev/test-cli-host-managed.py|scripts/ci/tests/test-cli-host-managed.py|scripts/dev/test-cli-update.py|scripts/ci/tests/test-cli-update-mesh-endpoints.py|scripts/ci/tests/test-build-cw-release-dir.py|scripts/dev/test-native-managed-startup.py|scripts/dev/fixtures/agent-peer.py|scripts/dev/fixtures/host-member-managed-assets.py)
        select_token rust
        select_token rust_pkg_codewire_cli
        select_token rust_pkg_codewire_cli_bin
        recognized=true
        ;;
      scripts/dev/test-cli-native-managed.py|scripts/dev/test-cli-native-update.py|scripts/ci/tests/test-native-managed-update-entrypoint.py|scripts/dev/build-native-managed-agent.py|scripts/dev/native_socket_dir.py)
        select_token rust
        select_token rust_pkg_codewire_cli
        select_token rust_pkg_codewire_cli_bin
        select_token transport
        select_token transport_pkg_codewire_local_vmm
        recognized=true
        ;;
      scripts/dev/cw-runtime-image.py|scripts/dev/test-cw-runtime-image.py)
        # The OCI/runtime-pack tool runs with the local VMM transport suite
        # and backs the release delivery's raw/OCI/pack equality proof.
        select_token transport
        select_token transport_pkg_codewire_local_vmm
        select_token release
        recognized=true
        ;;
      scripts/dev/build-cw.py)
        # The `make cli-build` entrypoint admits cw through the shared
        # release identity producer.
        select_token rust
        select_token rust_pkg_codewire_cli
        select_token rust_pkg_codewire_cli_bin
        select_token release
        recognized=true
        ;;
      packages/codewire-proto-ts/*)
        ;;
      packages/codewire-types/*)
        # Deletion-only tombstone; the earlier OpenAPI case rejects revival.
        ;;
      packages/*)
        select_token web
        recognized=true
        ;;
    esac

    case "$path" in
      apps/dashboard/e2e/ssr-dashboard.account-dialogs.ssr.ts|\
      apps/dashboard/e2e/ssr-dashboard.create-help.ssr.ts|\
      apps/dashboard/e2e/ssr-dashboard.creation-disclosure.ssr.ts|\
      apps/dashboard/e2e/ssr-dashboard.credential-dialogs.ssr.ts|\
      apps/dashboard/e2e/ssr-dashboard.date-picker.ssr.ts|\
      apps/dashboard/e2e/ssr-dashboard.design-system.ssr.ts|\
      apps/dashboard/e2e/ssr-dashboard.durable-terminal.ssr.ts|\
      apps/dashboard/e2e/ssr-dashboard.organization-layout.ssr.ts|\
      apps/dashboard/e2e/ssr-dashboard.personal-api-keys.ssr.ts|\
      apps/dashboard/e2e/ssr-dashboard.personal-secrets.ssr.ts|\
      apps/dashboard/e2e/ssr-dashboard.preview-ports.ssr.ts|\
      apps/dashboard/e2e/ssr-dashboard.repository-picker.ssr.ts|\
      apps/dashboard/e2e/ssr-dashboard.resize.ssr.ts|\
      apps/dashboard/e2e/ssr-dashboard.sandbox-inventory.ssr.ts|\
      apps/dashboard/e2e/ssr-dashboard.setup-progress.ssr.ts|\
      apps/dashboard/e2e/ssr-dashboard.source-recovery.ssr.ts|\
      apps/dashboard/e2e/ssr-dashboard.terminal-renderer.ssr.ts)
        # Design-fixture specs run in the web gate's fixture runner and never
        # in Kind, whose dashboard projects ignore them. Keep this list equal
        # to apps/dashboard/e2e/helpers/design-fixtures.ts; its unit test checks.
        ;;
      apps/dashboard/e2e/*)
        # Browser specs run only under Edge/Kind. A push to main runs them
        # post-merge so an edited spec cannot reach main unexecuted; a pull
        # request runs them only when it opts into Kind.
        if [ "$event" != pull_request ] || [ "$pr_kind_opt_in" = true ]; then
          select_token edge_kind
          kind_relevant=true
        fi
        ;;
    esac

    if [[ "$path" == crates/*/* ]] && [[ "$path" != crates/codewire-api-contract/* ]] \
        && [[ "$path" != crates/codewire-api-types/* ]] \
        && [[ "$path" != crates/codewire-core/* ]]; then
      crate="${path#crates/}"
      crate="${crate%%/*}"
      case "$crate" in
        codewire-desktop|codewire-ui)
          select_token policy
          select_token rust
          select_token rust_pkg_codewire_desktop
          ;;
        codewire-types)
          # The retained shared types are a compiled desktop input and are also
          # covered by the native desktop no-legacy policy.
          select_token policy
          select_token rust
          select_token rust_pkg_codewire_desktop
          select_token rust_pkg_codewire_types
          ;;
        codewire-workspace-hack)
          # cargo-hakari's feature unification is a dependency of every other
          # member: a change rebuilds the whole graph like the root manifest.
          select_rust_workspace
          ;;
        codewire-workspace-image)
          # The published workspace pin: every consumer compiles its constants,
          # and a post-publish proposal changes nothing else.
          select_token rust
          select_token rust_pkg_codewire_workspace_image
          select_token rust_pkg_codewire_server_core
          select_token rust_pkg_codewire_orchestration
          select_token rust_pkg_codewire_dashboard_web
          select_token rust_pkg_codewire_cli
          ;;
        codewire-platform-native)
          # Deletion-only tombstone: a revival of the retired ambient-SSH
          # adapter must still run the detached desktop verification.
          select_token policy
          select_token rust
          select_token rust_pkg_codewire_desktop
          ;;
        *)
          select_crate_tests "$crate"
          ;;
      esac
      # Its workspace reverse dependents join after every path is read. The
      # workspace-hack already selects the whole workspace.
      if [ "$crate" != codewire-workspace-hack ]; then
        changed_crates["$crate"]=1
      fi
      if [ "$crate" = codewire-dashboard-web ]; then
        select_token deploy
        select_token edge_kind
        select_token web
        kind_relevant=true
      fi
      if [ "$path" = "crates/$crate/Cargo.toml" ]; then
        case "$crate" in
          codewire-daemon|codewire-daemon-proto|codewire-tls|\
          codewire-local-vmm|codewire-netstack|codewire-proto|codewire-tailnet|codewire-derp|\
          codewire-vmm-guest-probe)
            select_token rust_curated_locks
            ;;
        esac
      fi
      recognized=true
    fi

    case "$path" in
      testdata/local-vm-network/*)
        # Shared authenticated packet fixtures are consumed by the guest probe
        # and therefore by its local VMM host runner.
        select_token transport
        select_token transport_pkg_codewire_local_vmm
        select_token transport_pkg_codewire_vmm_guest_probe
        recognized=true
        ;;
      scripts/dev/test-cli-local-vm-macos.py|scripts/dev/test-cli-local-vm-docker-macos.py|\
      scripts/dev/test-cli-local-vm-inputs-macos.py|\
      scripts/dev/test-local-vm-hostile-guest-macos.py|scripts/dev/hostile-guest-probe.py|\
      scripts/dev/test-local-vm-hostile-guest.py)
        # Developer-only local VM journeys and the hostile-guest battery: they
        # run against real local VMs and never in CI.
        select_token policy
        recognized=true
        ;;
      crates/codewire-netstack/*)
        # The tailnet wrapper consumes the shared userspace TCP/IP engine.
        select_token transport
        select_token transport_pkg_codewire_tailnet
        ;;
      crates/codewire-tls/*)
        # Mounted TLS identities serve both the gateway HTTPS boundary and
        # the isolated credential service's real private gRPC listener.
        select_token rust
        select_token rust_pkg_codewire_credential_service
        select_token database
        select_token transport
        ;;
      crates/codewire-credential-bridge/*)
        # Material-free HTTP/frame handling is shared with daemon and gateway;
        # prove its reverse consumers as well as the extracted unit tests.
        select_token rust
        select_token rust_pkg_codewire_credential_broker
        select_token transport
        select_token transport_pkg_codewire_daemon
        select_token transport_pkg_codewire_local_vmm
        select_token transport_pkg_codewire_vmm_guest_probe
        ;;
      crates/codewire-daemon-proto/*)
        # The extracted state machine has direct private-frame unit coverage.
        select_token rust
        select_token rust_pkg_codewire_credential_bridge
        select_token rust_pkg_codewire_credential_broker
        select_token transport
        select_token transport_pkg_codewire_local_vmm
        select_token transport_pkg_codewire_vmm_guest_probe
        ;;
      crates/codewire-daemon/*)
        # The local VMM host and guest link the private daemon contract
        # directly; changes must verify those reverse dependencies too.
        select_token rust
        select_token rust_pkg_codewire_credential_broker
        select_token transport
        select_token transport_pkg_codewire_local_vmm
        select_token transport_pkg_codewire_vmm_guest_probe
        ;;
      crates/codewire-vmm-guest-probe/*)
        # The host runner consumes the guest seed/newc contract directly.
        select_token transport
        select_token transport_pkg_codewire_local_vmm
        ;;
      crates/codewire-idp/*)
        select_token service_integration
        select_token service_idp
        ;;
      crates/codewire-billing/*)
        select_token service_integration
        select_token service_billing
        ;;
      crates/codewire-orchestration/*)
        select_token service_integration
        select_token service_orchestration
        ;;
      crates/codewire-protected-store/src/openbao_workload_identity.rs|\
      crates/codewire-protected-store/src/secret_envelope.rs|\
      crates/codewire-protected-store/src/lib.rs|\
      crates/codewire-protected-store/Cargo.toml)
        # Shared primitives retain both placement-store and orchestration
        # consumer proof, including their exposing feature gates.
        select_token rust
        select_token rust_pkg_codewire_credential_broker
        select_token rust_pkg_codewire_orchestration
        select_token rust_pkg_codewire_platform_credentials
        select_token database
        select_token service_integration
        select_token service_orchestration
        ;;
      crates/codewire-coordinator/*)
        select_token service_integration
        select_token service_coordinator
        ;;
      crates/codewire-server-core/tests/go_consumer_interop.rs)
        select_token go_support
        select_token go_consumer_interop
        ;;
      crates/codewire-platform-credentials/*)
        # Compilation cannot prove owner fencing, atomic material publication,
        # least-privilege metadata access or deletion races in PostgreSQL.
        select_token database
        select_token rust_pkg_codewire_credential_broker
        ;;
      crates/codewire-credential-service/src/runtime/kind.rs|\
      crates/codewire-credential-service/src/runtime/kind/*)
        # This is the real in-cluster credential-service fixture, rather than
        # a unit-only helper. Like the direct Kind smoke owners, its changes
        # must always exercise their canonical in-cluster proof.
        select_token database
        select_token edge_kind
        select_token kind
        kind_relevant=true
        ;;
      crates/codewire-credential-service/*)
        # Runtime identity and consent admission need the restricted PostgreSQL
        # matrix in addition to the material-free Kubernetes unit fixtures.
        select_token database
        ;;
      crates/codewire-credential-broker/src/provider_enrollment.rs)
        # Shared by CLI and the isolated platform mutation service (its SSH
        # runtime); package-default tests alone do not cover these features.
        select_token rust
        select_token rust_pkg_codewire_cli
        select_token rust_pkg_codewire_credential_service
        select_token database
        ;;
      crates/codewire-credential-broker/src/platform.rs|\
      crates/codewire-credential-broker/src/platform/*|\
      crates/codewire-credential-broker/src/runtime.rs|\
      crates/codewire-credential-broker/src/lib.rs|\
      crates/codewire-credential-broker/Cargo.toml)
        # Optional platform admission and the shared runtime are exercised
        # against restricted PostgreSQL roles, not by default local tests.
        select_token database
        ;;
      crates/codewire-access/*)
        # The shared credential model is also interpreted by platform storage.
        select_token rust
        select_token rust_pkg_codewire_credential_broker
        select_token rust_pkg_codewire_platform_credentials
        select_token database
        ;;
      crates/codewire-server-core/tests/org_deletion_lifecycle.rs|\
      crates/codewire-server-core/tests/oauth_bearer_auth.rs|\
      crates/codewire-server-core/tests/oauth_bearer_auth/*)
        # This PostgreSQL-backed lifecycle test exercises no service process,
        # edge, or deployable runtime input. Its focused database verifier and
        # server-core Rust closure are selected by the exact test path.
        select_token database
        ;;
      crates/codewire-mesh/src/store.rs)
        # Mesh's PostgreSQL store owns its embedded SQLx ledger and transactional
        # product state. Compile-only transport checks cannot exercise those
        # database state transitions.
        select_token database
        ;;
      crates/codewire-server-core/src/migrate/tests/*)
        # Ignored PostgreSQL migration tests run in the database lane; this
        # private test directory contains no deployable service/runtime input.
        select_token database
        ;;
      crates/codewire-server-core/*)
        select_services
        ;;
    esac

    case "$path" in
      crates/codewire-daemon-proto/src/lib.rs)
        # Shared fixed Pod-token audiences are consumed by the optional
        # server-core verifier, not just by the private protocol endpoints.
        select_token rust_pkg_codewire_server_core
        ;;
      scripts/ci/verify/check-darwin-cross.sh|\
      scripts/ci/verify/build-local-vmm-initramfs.sh|\
      scripts/ci/verify/build-linux-vmm-kernel.py|\
      scripts/ci/verify/linux-vmm-kernel/*|\
      scripts/ci/tests/test-linux-vmm-kernel.py|\
      scripts/ci/verify/smoke-local-vmm-cloud-hypervisor.sh|\
      scripts/ci/verify/smoke-native-local-environment.sh|\
      scripts/ci/verify/stock-ssh-workload.sh)
        select_token transport
        select_token transport_pkg_codewire_local_vmm
        select_token transport_pkg_codewire_vmm_guest_probe
        if [[ "$path" == scripts/ci/verify/stock-ssh-workload.sh ]]; then
          select_token dev_smoke_script_tests
        fi
        recognized=true
        ;;
      crates/*/migrations/*)
        select_token database
        recognized=true
        ;;
      crates/codewire-server-core/src/migrate.rs|\
      crates/codewire-server-core/src/bin/codewire-db-migrate.rs|\
      crates/codewire-server-core/tests/data/application_schema_fingerprint.sql|\
      crates/codewire-server-core/tests/session_auth.rs|\
      crates/codewire-server-core/src/auth.rs|\
      crates/codewire-server-core/src/auth/*|\
      crates/codewire-server-core/src/connect.rs|\
      crates/codewire-protected-store/src/secret_envelope.rs|\
      crates/codewire-protected-store/src/lib.rs|\
      crates/codewire-protected-store/Cargo.toml|\
      crates/codewire-orchestration/src/worker/postgres_secrets.rs|\
      crates/codewire-orchestration/src/worker/tenant_secret_teardown.rs|\
      crates/codewire-orchestration/src/access_profiles.rs|\
      crates/codewire-orchestration/src/connect/access_profiles.rs|\
      crates/codewire-orchestration/tests/access_profiles.rs|\
      crates/codewire-orchestration/tests/access_profiles_support/*|\
      crates/codewire-orchestration/tests/access_profiles_timeout/*|\
      crates/codewire-orchestration/tests/access_profiles_destroy/*|\
      crates/codewire-orchestration/src/lifecycle/mod.rs|\
      crates/codewire-orchestration/src/credentials.rs|\
      crates/codewire-orchestration/src/connect/credentials.rs|\
      crates/codewire-orchestration/tests/credentials.rs|\
      crates/codewire-orchestration/tests/credentials_support/*|\
      crates/codewire-billing/src/subscription_migration.rs)
        # Store/teardown and restricted public-profile tests need PostgreSQL;
        # the ordinary orchestration and Temporal lanes do not execute them.
        select_token database
        recognized=true
        ;;
      crates/*/src/*database_tests.rs|\
      crates/*/src/*/database_tests/*|\
      crates/codewire-billing/src/billing_teardown.rs|\
      crates/codewire-orchestration/src/api/cw_runtime/owner.rs|\
      crates/codewire-orchestration/src/api/environment_daemon/session_mutation/tests.rs|\
      crates/codewire-orchestration/src/api/environment_resize.rs|\
      crates/codewire-orchestration/src/api/platform_agents/journal.rs|\
      crates/codewire-orchestration/src/connect/mesh_authorization.rs|\
      crates/codewire-orchestration/src/worker/lifecycle.rs|\
      crates/codewire-orchestration/src/workspace_binding/store.rs|\
      crates/codewire-orchestration/tests/environment_external_cleanup.rs|\
      crates/codewire-orchestration/tests/environment_sources.rs)
        # The database family (run-integration-verification.sh database_lane_*)
        # runs these files' ignored PostgreSQL tests; no other family does, so a
        # change to one must select it (#3194). test-select-verification.sh
        # proves every test the database lanes run has its source path here or
        # in another rule that selects database.
        select_token database
        recognized=true
        ;;
      tests/contract/README.md)
        recognized=true
        ;;
      tests/fixtures/accepted-bytes.sha256)
        recognized=true
        ;;
      tests/fixtures/billing/*)
        select_token service_integration
        select_token service_billing
        recognized=true
        ;;
      tests/fixtures/coordinator/*)
        select_token service_integration
        select_token service_coordinator
        recognized=true
        ;;
      tests/fixtures/orchestration/*)
        select_token service_integration
        select_token service_orchestration
        recognized=true
        ;;
      tests/contract/go.mod|tests/contract/go.sum)
        select_token security
        select_token security_go
        select_token transport
        select_token transport_derp_contract
        select_token transport_pkg_codewire_derp
        recognized=true
        ;;
      tests/contract/idp/*)
        select_token service_integration
        select_token service_idp
        recognized=true
        ;;
      tests/contract/billing/*.go)
        # Retired by WI-C11B. General Go billing drivers must not return.
        if [ -e "$repo_root/$path" ]; then
          echo "::error::retired Go billing contract driver recreated: $path" >&2
          exit 1
        fi
        select_token service_integration
        select_token service_billing
        recognized=true
        ;;
      tests/contract/billing/*)
        select_token service_integration
        select_token service_billing
        recognized=true
        ;;
      tests/contract/connectcore/*)
        # Retired by WI-C11A. Recognize its deletion in the WI diff while
        # rejecting any later attempt to recreate the general Go driver.
        if [ -e "$repo_root/$path" ]; then
          echo "::error::retired Go connectcore driver path recreated: $path" >&2
          exit 1
        fi
        select_token service_integration
        select_token service_connectcore
        select_token service_billing
        select_token service_orchestration
        recognized=true
        ;;
      tests/contract/derp/*)
        select_token transport
        select_token transport_pkg_codewire_derp
        select_token transport_derp_contract
        recognized=true
        ;;
      scripts/dev/dev-stack.sh)
        select_services
        recognized=true
        ;;
      scripts/dev/workstation-cpu.sh)
        # Owner-workstation CPU limits; neither CI nor Kind runs the helper.
        select_token policy
        recognized=true
        ;;
      scripts/dev/kind/sync-local-secrets.sh)
        # The local credential bridge has a hermetic policy fixture and does
        # not provision or exercise a Kind cluster.
        select_token policy
        recognized=true
        ;;
      scripts/dev/kind/dev-loop.sh|scripts/dev/kind/deploy-service.sh|\
      scripts/dev/kind/trust-roots.sh)
        # Retained-cluster review helpers (`make kind-*`) that the Kind gate
        # never runs. The runtime-image table has a hermetic policy fixture.
        select_token policy
        recognized=true
        ;;
      scripts/dev/kind/database.sh)
        # The retained cluster's database upgrade, reset and restore. The Kind
        # gate never runs it; its hermetic fixture runs with the edge family.
        select_token edge_kind
        recognized=true
        ;;
      scripts/dev/kind/*)
        select_token edge_kind
        kind_relevant=true
        recognized=true
        ;;
      scripts/runtime/*apikey*)
        # The retired API key smoke tooling (#3119 E4): its deletion needs
        # only Policy.
        select_token policy
        recognized=true
        ;;
      scripts/runtime/dev/run-sdk-python-e2e.sh|\
      scripts/runtime/tests/test-run-sdk-python-e2e.sh)
        # Fixed SDK test plumbing: it owns no product runtime behavior.
        select_token sdk_python
        recognized=true
        ;;
      scripts/runtime/dev/run-sdk-ts-e2e.sh|\
      scripts/runtime/tests/test-run-sdk-ts-e2e.sh)
        # Fixed SDK test plumbing: it owns no product runtime behavior.
        select_token sdk_ts
        recognized=true
        ;;
      scripts/runtime/confidential/*|\
      scripts/runtime/tests/test-confidential-snp-smoke-contract.sh|\
      scripts/runtime/tests/test-resolve-coco-support-lock.sh)
        # This lightweight capability owns confidential image provenance and
        # its fail-closed offline contract fixtures.
        select_token confidential_script_tests
        recognized=true
        ;;
      scripts/runtime/dev/provision-dev-smoke-user.sh|\
      scripts/runtime/dev/smoke-dev-commodity.sh|\
      scripts/runtime/dev/provider-ssh-smoke.sh|\
      scripts/runtime/dev/provider-codex-smoke.sh|\
      scripts/runtime/dev/provider-codex-workload.sh|\
      scripts/runtime/dev/provider-codex-output.py|\
      scripts/runtime/dev/provider-anthropic-smoke.sh|\
      scripts/runtime/dev/provider-anthropic-workload.sh|\
      scripts/runtime/dev/provider-anthropic-output.py|\
      scripts/runtime/dev/provider-openai-smoke.sh|\
      scripts/runtime/dev/provider-openai-workload.py|\
      scripts/runtime/dev/private-checkout-smoke.sh|\
      scripts/runtime/dev/smoke-dev-initial-private-checkout.sh|\
      scripts/runtime/dev/hosted-checkout-fixture.py|\
      scripts/runtime/dev/hosted-checkout-target.sh|\
      scripts/runtime/dev/testdata/acceptance-identity.json|\
      scripts/runtime/dev/smoke-local-platform-sources.sh|\
      scripts/runtime/dev/run-secrets-credentials-acceptance.sh|\
      scripts/runtime/dev/native-mesh-listener.py|\
      scripts/runtime/dev/with-dev-smoke-auth.sh|\
      scripts/runtime/tests/test-provision-dev-smoke-user.sh|\
      scripts/runtime/tests/test-provider-ssh-smoke.sh|\
      scripts/runtime/tests/test-provider-codex-smoke.sh|\
      scripts/runtime/tests/test-provider-codex-workload.py|\
      scripts/runtime/tests/test-provider-anthropic-smoke.sh|\
      scripts/runtime/tests/test-provider-anthropic-workload.py|\
      scripts/runtime/tests/test-provider-openai-smoke.sh|\
      scripts/runtime/tests/test-provider-openai-workload.py|\
      scripts/runtime/tests/test-private-checkout-smoke.sh|\
      scripts/runtime/tests/test-dev-initial-private-checkout.sh|\
      scripts/runtime/tests/test-hosted-checkout-fixture.py|\
      scripts/runtime/tests/test-local-platform-sources-smoke.sh|\
      scripts/runtime/tests/test-secrets-credentials-acceptance-runner.sh|\
      scripts/runtime/tests/test-native-mesh-listener.py|\
      scripts/runtime/tests/fixtures/local-platform/__local-credential-authority|\
      scripts/runtime/tests/test-smoke-dev-commodity.sh|\
      scripts/runtime/tests/test-smoke-dev-application-secrets.sh|\
      scripts/runtime/dev/prove-dev-workspace-binding.sh|\
      scripts/runtime/tests/test-workspace-binding-proof.sh|\
      scripts/runtime/dev/prove-dev-warm-pools.sh|\
      scripts/runtime/tests/test-warm-pool-proof.sh|\
      scripts/runtime/agent-sandbox/drop-crd-conversion.sh|\
      scripts/runtime/tests/test-drop-crd-conversion.sh|\
      scripts/runtime/tests/test-with-dev-smoke-auth.sh)
        select_token dev_smoke_script_tests
        case "$path" in
          scripts/runtime/dev/provision-dev-smoke-user.sh|\
          scripts/runtime/dev/with-dev-smoke-auth.sh|\
          scripts/runtime/tests/test-with-dev-smoke-auth.sh)
            select_token security
            select_token security_dev_smoke_auth
            ;;
        esac
        recognized=true
        ;;
      scripts/runtime/*)
        # Live dev/Kata harnesses are operator tooling. Policy supplies shell
        # syntax for every runtime script; product families are selected only
        # by an implementation or fixture path that they can actually verify.
        select_token policy
        recognized=true
        ;;
    esac

    case "$path" in
      crates/codewire-orchestration/src/temporal*|\
      crates/codewire-orchestration/src/worker/*|\
      crates/codewire-protected-store/src/secret_envelope.rs|\
      crates/codewire-protected-store/src/lib.rs|\
      crates/codewire-protected-store/Cargo.toml|\
      crates/codewire-billing/src/temporal*)
        select_token service_integration
        select_token service_temporal
        recognized=true
        ;;
      tests/e2e/flip-state.env)
        select_token service_integration
        select_token service_billing
        select_token service_orchestration
        select_token service_temporal
        recognized=true
        ;;
      crates/codewire-coordinator/src/nats*|crates/codewire-mesh/src/nats*)
        select_token service_integration
        select_token service_nats
        recognized=true
        ;;
    esac

    case "$path" in
      crates/codewire-derp/*)
        select_token transport_derp_contract
        ;;
    esac

    case "$path" in
      crates/codewire-orchestration/src/bin/temporal-fencing-smoke.rs|\
      crates/codewire-orchestration/src/bin/file-service-smoke.rs|\
      crates/codewire-orchestration/src/bin/reconciler-ttl-smoke.rs)
        select_token edge_kind
        select_token kind
        recognized=true
        ;;
      Caddyfile|Caddyfile.docker|tests/e2e/kind/*|tests/e2e/*kind*|\
      scripts/ci/install-pinned-playwright-chromium.sh|\
      scripts/ci/verify/kind-host-runtime.sh|\
      scripts/ci/verify/playwright-browser-runtime.sh|\
      scripts/ci/verify/kind-e2e.sh|scripts/ci/verify/kind/*|\
      scripts/ci/verify/kind-build-artifacts.py|\
      scripts/ci/images/build-kind-smokes.sh|\
      scripts/ci/tests/test-kind-build-artifacts.py|\
      scripts/ci/tests/test-kind-build-workflow.py|\
      scripts/ci/tests/test-build-kind-smokes.sh|\
      scripts/dev/kind/install-temporal.sh|scripts/ci/tests/test-install-temporal.sh|\
      deployments/k8s/*ingress*|\
      deployments/k8s/overlays/local-kind/*|deployments/k8s/overlays/local-kind-static/*)
        select_token edge_kind
        kind_relevant=true
        recognized=true
        ;;
      scripts/ci/tests/test-kind-e2e-*.sh|scripts/ci/tests/test-kind-forwards.sh|\
      scripts/ci/tests/test-kind-trust-roots.sh|\
      scripts/ci/tests/test-kind-codex-session.py|scripts/ci/tests/test-kind-codex-login.py|\
      scripts/ci/tests/test-kind-claude-login.py|\
      scripts/ci/tests/test-kind-credentials.py|scripts/ci/tests/test-kind-cluster-profiles.py|\
      scripts/ci/tests/test-kind-dev-profile.py|scripts/ci/tests/test-kind-profile-artifacts.py|\
      scripts/ci/tests/test-kind-cw-runtime.py|scripts/ci/tests/test-kind-cw-runtime-probe.py|\
      scripts/ci/tests/test-kind-profile-gate.py)
        # These hermetic fixtures exercise the dispatcher and cleanup contract
        # without provisioning a cluster. A real harness/runtime path in the
        # same change still marks the selection Kind-relevant above.
        select_token edge_kind
        recognized=true
        ;;
      scripts/checks/contracts/connect-edge-ownership.json)
        select_token edge_kind
        recognized=true
        ;;
      scripts/ci/setup/fetch-openbao-sccache-r2-credentials.sh)
        select_token edge_kind
        select_token policy
        select_token security
        kind_relevant=true
        recognized=true
        ;;
      scripts/ci/setup/select-untrusted-rust-cache.sh|\
      scripts/ci/setup/finish-untrusted-rust-cache.sh|\
      scripts/ci/setup/select-warm-rust-cache.sh|\
      scripts/ci/setup/finish-warm-rust-cache.sh|\
      scripts/ci/setup/bound-cargo-jobs.sh)
        select_token policy
        select_token rust
        select_token rust_workspace
        select_token security
        recognized=true
        ;;
      scripts/ci/tests/test-select-untrusted-rust-cache.sh|\
      scripts/ci/tests/test-warm-rust-cache.sh|\
      scripts/ci/tests/test-bound-cargo-jobs.sh)
        select_token policy
        select_token security
        recognized=true
        ;;
      scripts/ci/images/prepare-cw-source-context.py|\
      scripts/ci/images/build-cw-runtime-source.py|\
      scripts/ci/images/finalize-cw-runtime-source.py|\
      scripts/ci/images/prepare-cw-image-context.py|\
      scripts/ci/images/cw-image-consumer.py|\
      scripts/ci/images/cw-image-consumer.sh|\
      scripts/ci/images/cw-image-source.py|\
      scripts/ci/images/build-product-images.sh|\
      scripts/ci/tests/test-cw-image-context.py|\
      scripts/ci/tests/test-cw-runtime-source.py|\
      scripts/ci/tests/test-cw-image-consumer.py|\
      scripts/ci/tests/test-cw-image-source.py|\
      scripts/ci/tests/cw_image_fixtures.py)
        # Image consumers are selected by the artifact graph. Their source,
        # process and asset admission boundaries also require policy guards.
        select_token policy
        select_token security
        recognized=true
        ;;
      scripts/ci/images/buildx-builder.sh|\
      scripts/ci/tests/test-buildx-builder.sh)
        # The owned BuildKit builder removal is shared by the workspace
        # verification (workspace-cache.sh: policy, security) and the Kind image
        # build (build-kind-images.sh: Kind, release, deploy), so it selects both.
        select_token policy
        select_token security
        select_token edge_kind
        select_token release
        select_token deploy
        kind_relevant=true
        recognized=true
        ;;
      scripts/ci/setup/select-untrusted-workspace-cache.sh|\
      scripts/ci/images/workspace-cache.sh|\
      scripts/ci/tests/test-select-untrusted-workspace-cache.sh|\
      scripts/ci/tests/test-workspace-cache.sh|\
      scripts/ci/tests/canary-workspace-r2-cache.sh|\
      scripts/ci/setup/select-workspace-cache-experiment.py|\
      scripts/ci/tests/probe-workspace-r2-cache.sh|\
      scripts/ci/tests/test-workspace-cache-experiment.py|\
      scripts/ci/tests/test-workspace-cache-probes.py|\
      scripts/ci/verify/workspace-cache-probes.py|\
      scripts/ci/verify/workspace-cache-report.py)
        # The artifact graph owns workspace build selection. These exact
        # credential/cache consumers also run their policy and security guards.
        select_token policy
        select_token security
        recognized=true
        ;;
      scripts/ci/tests/test-fetch-openbao-sccache-r2-credentials.sh)
        select_token edge_kind
        select_token policy
        select_token security
        recognized=true
        ;;
      scripts/ci/setup/fetch-openbao-sccache-r2-protected-credentials.sh|\
      scripts/ci/setup/select-protected-rust-cache.sh|\
      scripts/ci/tests/test-fetch-openbao-sccache-r2-protected-credentials.sh|\
      scripts/ci/tests/test-select-protected-rust-cache.sh)
        select_token deploy
        select_token policy
        select_token release
        select_token security
        recognized=true
        ;;
      # The protected Dev runtime builder never builds a Kind image: Kind
      # builds through build-kind-images.sh. Its contract runs in Deploy.
      scripts/ci/images/build-push-runtime-images.sh|\
      scripts/ci/setup/trusted-buildkit.sh|\
      scripts/ci/tests/test-build-push-runtime-images.sh)
        select_token deploy
        select_token release
        recognized=true
        ;;
      # Main CI's final job starts Dev delivery (#2892); its contract, with
      # the ci.yaml job that runs it, runs in Policy and Deploy.
      scripts/ci/deploy/rerun-dev-publish.py|\
      scripts/ci/tests/test-rerun-dev-publish.py|\
      scripts/ci/deploy/cancel-superseded-deliveries.py|\
      scripts/ci/tests/test-cancel-superseded-deliveries.py)
        select_token deploy
        select_token policy
        recognized=true
        ;;
      Dockerfile|docker-bake.hcl|apps/*/Dockerfile*|deployments/docker/*|\
      scripts/ci/images/build-kind-images.sh|\
      scripts/ci/images/run-rust-build.sh|scripts/ci/tests/test-run-rust-build.sh)
        select_token edge_kind
        select_token release
        select_token deploy
        case "$path" in
          deployments/docker/*.Cargo.toml|\
          deployments/docker/*.Cargo.lock)
            select_token rust_curated_locks
            ;;
        esac
        kind_relevant=true
        recognized=true
        ;;
    esac

    case "$path" in
      scripts/ci/images/cosign-private-signing-config.json|\
      scripts/ci/images/pipeline-identity.sh|\
      scripts/ci/images/sign-runtime-image-set.sh|\
      scripts/ci/tests/test-sign-runtime-image-set.sh|\
      scripts/ci/images/verify-runtime-image-signatures.sh|\
      scripts/ci/tests/test-verify-runtime-image-signatures.sh|\
      scripts/ci/trust/codewire-runtime-signing.pub)
        select_token deploy
        select_token policy
        select_token release
        select_token security
        recognized=true
        ;;
    esac

    case "$path" in
      deployments/*|apps/cli/charts/*|.gitea/workflows/deploy-*.yaml|\
      apps/cli/k8s/*|\
      .gitea/workflows/observe-*.yaml|\
      .gitea/workflows/prod-temporal-preflight.yaml|\
      scripts/ci/deploy/*.sh|scripts/ci/*observe*.sh|scripts/ci/*observe*.py|\
      scripts/ci/*observer*.tsv|\
      scripts/ci/*promot*.sh|scripts/ci/*promot*.py|\
      scripts/ci/setup/fetch-forgejo-deploy-dev-token.sh|\
      scripts/ci/setup/fetch-forgejo-deploy-prod-token.sh|\
      scripts/ci/deploy/dispatch-deploy-dev.sh|scripts/ci/deploy/dispatch-deploy-prod.sh|\
      scripts/ci/tests/test-ci-tool-downloads.sh|\
      scripts/ci/tests/test-deploy-*.sh|scripts/ci/tests/test-dispatch-deploy-*.sh)
        select_token deploy
        recognized=true
        ;;
    esac

    case "$path" in
      deployments/k8s/*.yaml)
        select_token security
        select_token security_idp_kek
        recognized=true
        ;;
    esac

    case "$path" in
      scripts/dev/build-native-managed-agent.py|\
      crates/codewire-cli/build.rs|crates/codewire-cli/src/build_record.rs)
        # Producers of the embedded cw build record and native identity that
        # the shared release identity producer admits.
        select_token release
        recognized=true
        ;;
    esac

    case "$path" in
      images/*|\
      .gitea/workflows/cli-release.yaml|\
      .gitea/workflows/cw-release-dry-run.yaml|\
      .gitea/workflows/mirror-github.yaml|\
      .gitea/workflows/support-images.yaml|\
      keys/production-release.asc|\
      .gitea/workflows/observe-*.yaml|\
      scripts/ci/images/build-push-image.sh|scripts/ci/images/build-push-runtime-images.sh|\
      scripts/ci/images/pipeline-identity.sh|\
      scripts/ci/images/build-support-platform.sh|\
      scripts/ci/setup/trusted-buildkit.sh|\
      scripts/ci/images/run-workspace-contract-on-image.sh|\
      scripts/ci/tests/test-run-workspace-contract-on-image.sh|\
      scripts/ci/images/release-support-pair-state.sh|scripts/ci/images/join-release-support-image.sh|\
      scripts/ci/images/compute-image-tags.sh|\
      scripts/ci/images/copy-image-to-ghcr.sh|\
      scripts/ci/images/publish-image-to-harbor.sh|\
      scripts/ci/deploy/dispatch-deploy-dev.sh|scripts/ci/deploy/dispatch-deploy-prod.sh|\
      scripts/ci/setup/fetch-forgejo-deploy-dev-token.sh|\
      scripts/ci/setup/fetch-forgejo-deploy-prod-token.sh|\
      scripts/ci/setup/curl-transport-retry.sh|\
      scripts/ci/setup/fetch-openbao-ghcr-credentials.sh|\
      scripts/ci/setup/fetch-openbao-harbor-credentials.sh|\
      scripts/ci/setup/fetch-openbao-arm64-buildkit-client.sh|\
      scripts/ci/setup/fetch-openbao-trusted-buildkit-client.sh|\
      scripts/ci/setup/fetch-openbao-github-mirror-credentials.sh|\
      scripts/ci/images/publish-image-to-ghcr.sh|\
      scripts/ci/images/resolve-published-support-pair.sh|\
      scripts/ci/images/run-skopeo-container.sh|\
      scripts/ci/images/image-bundle.py|scripts/ci/release/mirror-canonical-release-tag.sh|\
      scripts/ci/release/mirror-git-tags.sh|\
      scripts/ci/*promot*.sh|scripts/ci/*promot*.py|\
      scripts/ci/verify/check-darwin-cross.sh|\
      scripts/ci/release/mint-github-app-token.sh|\
      scripts/ci/release/mirror-github.sh|\
      scripts/ci/release/check-mirror-content.sh|\
      scripts/ci/release/public-content-patterns.txt|\
      scripts/ci/tests/test-check-mirror-content.sh|\
      scripts/ci/release/package-cw-release.sh|scripts/ci/release/publish-cw-release.sh|\
      scripts/ci/release/build-cw-linux.sh|scripts/ci/release/cw-release-linux-build.sh|\
      scripts/ci/release/cw-release-linux.Dockerfile|scripts/ci/release/cw-release-linux.Dockerfile.dockerignore|\
      scripts/ci/release/cw-release-linux.hcl|scripts/ci/tests/test-build-cw-linux.sh|\
      scripts/ci/release/cw_release.py|scripts/ci/release/cw_release_r2.py|\
      scripts/ci/release/sign-cw-release.sh|scripts/ci/release/sign-macos-cw.sh|\
      scripts/ci/release/sign-macos-helper.sh|scripts/ci/release/macos-signing.sh|\
      scripts/ci/setup/fetch-openbao-releases-r2-credentials.sh|\
      scripts/ci/setup/fetch-openbao-release-signing-key.sh|\
      scripts/ci/setup/fetch-openbao-macos-signing.sh|\
      scripts/ci/tests/cw_release_fixtures.py|scripts/ci/tests/test-cli-release-workflow.py|\
      scripts/ci/tests/test-cw-release-delivery.py|scripts/ci/tests/test-cw-release-r2.py|\
      scripts/ci/tests/test-package-cw-release.py|\
      scripts/ci/release/local_runtime_parts.py|scripts/ci/release/local_runtime_sources.py|\
      scripts/ci/release/local-runtime-sources.json|scripts/ci/release/build-runtime-kernel.sh|\
      scripts/ci/release/build-local-runtime.sh|\
      scripts/ci/release/fetch-pinned.sh|scripts/ci/tests/test-fetch-pinned.sh|\
      scripts/ci/release/build-runtime-guest-root.sh|scripts/ci/release/runtime-container.sh|\
      scripts/ci/release/build-runtime-cw.sh|\
      scripts/ci/tests/test-local-runtime-parts.py|\
      scripts/ci/release/dry-run-superseded.sh|scripts/ci/tests/test-dry-run-superseded.sh|\
      scripts/ci/release/dry-run-deferral.sh|scripts/ci/tests/test-dry-run-deferral.sh|\
      scripts/ci/select/main-push-switch.sh|scripts/ci/select/last-scheduled-run.py|\
      scripts/ci/tests/test-cw-install.py|\
      scripts/ci/tests/test-fetch-openbao-releases-r2-credentials.sh|\
      scripts/ci/tests/test-fetch-openbao-release-signing-key.sh|\
      scripts/ci/tests/test-fetch-openbao-macos-signing.sh|scripts/ci/tests/test-sign-macos-cw.sh|\
      scripts/ci/tests/test-sign-macos-helper.sh|\
      scripts/ci/tests/fixtures/rcodesign-stand-in.sh|\
      scripts/ci/tests/test-copy-image-to-ghcr.sh|\
      scripts/ci/tests/test-dispatch-deploy-dev.sh|scripts/ci/tests/test-dispatch-deploy-prod.sh|\
      scripts/ci/tests/test-publish-image-to-ghcr.sh|\
      scripts/ci/tests/test-publish-image-to-harbor.sh|\
      scripts/ci/tests/test-resolve-published-support-pair.sh|\
      scripts/ci/tests/test-run-skopeo-container.sh|\
      scripts/ci/tests/test-support-images-workflow.sh|\
      scripts/ci/images/propose-workspace-image-pin.sh|\
      scripts/ci/tests/test-propose-workspace-image-pin.sh|\
      scripts/ci/setup/fetch-openbao-workspace-pin-bot-token.sh|\
      scripts/ci/tests/test-fetch-openbao-workspace-pin-bot-token.sh|\
      scripts/ci/tests/test-workspace-image-verify-workflow.sh|\
      scripts/ci/tests/test-base-image-source.sh|\
      scripts/ci/tests/test-apt-get-with-retry.sh|\
      scripts/ci/tests/test-build-push-image.sh|\
      scripts/ci/tests/test-build-push-runtime-images.sh|\
      scripts/ci/tests/test-run-rust-build.sh|\
      scripts/ci/tests/test-fetch-forgejo-deploy-dev-token.sh|\
      scripts/ci/tests/test-fetch-openbao-ghcr-credentials.sh|\
      scripts/ci/tests/test-fetch-openbao-harbor-credentials.sh|\
      scripts/ci/tests/test-fetch-openbao-arm64-buildkit-client.sh|\
      scripts/ci/tests/test-fetch-openbao-trusted-buildkit-client.sh|\
      scripts/ci/tests/test-fetch-openbao-github-mirror-credentials.sh|\
      scripts/ci/tests/test-forgejo-action-mirrors.sh|\
      scripts/ci/tests/test-harbor-runtime-pull-contract.sh|\
      scripts/ci/tests/test-image-bundle.py|\
      scripts/ci/tests/test-mirror-git-tags.sh|scripts/ci/tests/test-publish-cw-release.sh|\
      scripts/ci/tests/test-mint-github-app-token.sh|\
      scripts/ci/tests/test-deploy-prod-workflow.sh|\
      scripts/ci/tests/test-deploy-dev.sh|\
      scripts/ci/tests/test-verify-cw-release-signing-key.sh|\
      scripts/ci/tests/test-verify-release-tag-ref.sh|\
      scripts/ci/receipts/verify-release-tag-receipt.sh|\
      scripts/ci/tests/test-verify-release-tag-receipt.sh|\
      scripts/ci/*observe*.sh|scripts/ci/*observe*.py|\
      scripts/ci/*observer*.tsv|\
      scripts/ci/release/verify-cw-release-signing-key.sh|scripts/ci/release/verify-release-tag-ref.sh|\
      scripts/ci/release/confirm-release-checkout.sh|\
      scripts/ci/release/verify-release-support-pair.sh|scripts/ci/tests/test-verify-release-support-pair.sh|\
      apps/cli/GPG_PUBLIC_KEY.asc|\
      apps/cli/README.md|apps/cli/install.sh|scripts/dev/test-cw-release-update.py|\
      apps/cli/nfpm.yaml|install.sh)
        select_token release
        recognized=true
        ;;
    esac

    case "$path" in
      scripts/ci/setup/fetch-forgejo-deploy-dev-token.sh|\
      scripts/ci/tests/test-fetch-forgejo-deploy-dev-token.sh|\
      scripts/ci/setup/fetch-forgejo-deploy-prod-token.sh|\
      scripts/ci/setup/fetch-openbao-github-mirror-credentials.sh|\
      scripts/ci/release/mint-github-app-token.sh|\
      scripts/ci/release/mirror-github.sh|\
      scripts/ci/release/check-mirror-content.sh|\
      scripts/ci/release/public-content-patterns.txt|\
      scripts/ci/tests/test-check-mirror-content.sh|\
      scripts/ci/tests/test-fetch-openbao-github-mirror-credentials.sh|\
      scripts/ci/tests/test-mint-github-app-token.sh)
        select_token deploy
        select_token security
        recognized=true
        ;;
    esac

    case "$path" in
      scripts/checks/security/audit-js-supply-chain.sh)
        select_token security
        select_token security_js
        recognized=true
        ;;
      scripts/checks/security/audit-runtime-images.sh|\
      scripts/ci/images/workspace-image-pin.py)
        select_token security
        select_token deploy
        select_token edge_kind
        select_token release
        recognized=true
        ;;
      scripts/ci/verify/dashboard-image.sh|\
      scripts/ci/verify/build-dashboard-image.sh|\
      scripts/ci/tests/test-dashboard-image-network-probe.sh|\
      scripts/ci/tests/test-build-dashboard-image.sh)
        select_token security
        select_token deploy
        select_token edge_kind
        select_token release
        select_token web
        kind_relevant=true
        recognized=true
        ;;
      scripts/ci/images/build-local-image.sh|\
      scripts/ci/tests/test-build-local-image.sh|\
      scripts/ci/tests/test-workspace-agent-contract.sh|\
      scripts/ci/tests/test-workspace-image-artifact.py|\
      scripts/ci/verify/workspace-image-artifact.py|\
      scripts/ci/verify/rehearse-build-local-image.sh|\
      scripts/ci/verify/verify-workspace-image.sh|\
      scripts/ci/verify/workspace-agent-contract.sh)
        select_token policy
        recognized=true
        ;;
      crates/codewire-orchestration/src/sandbox/mod.rs|\
      crates/codewire-orchestration/src/sandbox/template.rs|\
      crates/codewire-orchestration/src/sandbox/template/*)
        select_token edge_kind
        recognized=true
        ;;
    esac

    if [ "$recognized" = false ]; then
      echo "warning: unclassified path '${path}'; selecting all product verification" >&2
      select_all_product
      classification=unclassified
    fi
  done < "$tmp"

  # A changed crate's reverse dependents run their tests too; see
  # crate_graph_dependents. Runtime families (services, Kind, web) stay with
  # the paths that select them.
  if [ "${#changed_crates[@]}" -gt 0 ]; then
    if dependents="$(crate_graph_dependents "${!changed_crates[@]}")"; then
      while IFS= read -r dependent; do
        [ -n "$dependent" ] || continue
        select_crate_tests "$dependent"
      done <<<"$dependents"
    else
      echo "warning: the crate graph is unavailable; selecting the whole Rust workspace" >&2
      select_rust_workspace
    fi
  fi

  if [ "$saw_path" = false ]; then
    classification=unchanged
  elif [ "$kind_relevant" = true ]; then
    if [ "$event" = pull_request ]; then
      if [ "$pr_kind_opt_in" = true ]; then
        select_token kind
      fi
    else
      select_token kind
    fi
  fi
fi

if [ "$event_selected" = true ]; then
  if [ "$event" = workflow_dispatch ]; then
    classification=requested
  else
    classification=release
  fi
fi

# A signed release must prove the supported generated Go consumer against the
# Rust owner. This is the bounded consumer smoke, not a retired Go oracle or a
# general Go service-driver suite.
if token_selected release; then
  select_token confidential_script_tests
  select_token go_support
  select_token go_consumer_interop
elif token_selected sdk_go; then
  select_token go_support
  select_token go_consumer_interop
fi

# This marker means absence of policy_shell is an authoritative decision from
# a selector that knows the shell-policy domain. Older trusted selectors omit
# it, so candidate runners must keep executing ShellCheck for legacy output.
# ci_script_tests_omittable says the same of the CI-script tests.
if token_selected policy; then
  select_token policy_shell_omittable
  select_token ci_script_tests_omittable
fi

# Kind takes over an hour. A pull request runs it only with the ci-full
# label.
# Dispatched and scheduled runs keep it, and so does a push to main unless
# main-push-switch.sh defers it (below).
if [ "$event" = pull_request ] && [ "$pr_kind_opt_in" != true ]; then
  unset 'selected[kind]' 'selected[edge_kind]'
fi

# kind_tools picks the Edge selections that also run the Kind tool tests, so
# it means nothing without edge_kind. kind_tools_omittable says the omission is
# authoritative; a selection from an older trusted selector lacks it and still
# runs them.
if token_selected edge_kind; then
  select_token kind_tools_omittable
else
  unset 'selected[kind_tools]'
fi

# The local mode says how far scripts/dev/preflight.sh must escalate to run
# this change's families. Kind is never a local mode (owner, 2026-10-21).
required_local_mode=default
if [ "$classification" = unclassified ] \
  || [ "$classification" = release ] \
  || { [ "$classification" = requested ] && [ "${VERIFICATION_REQUEST:-policy}" = all ]; }; then
  required_local_mode=full
elif token_selected database || token_selected service_integration; then
  required_local_mode=integration
fi

# A push to main compares with the newest main commit main CI verified, which
# ci.yaml passes as PUSH_BEFORE_SHA (main-ci-verdict.py base). When there is
# none, or it cannot be read, PUSH_BASE_UNVERIFIED=true: nothing bounds what
# went unverified, so the push selects all product verification (#3176).
if [ "$event" = push ] && [ "${GITHUB_REF:-}" = refs/heads/main ] \
    && [ "${PUSH_BASE_UNVERIFIED:-false}" != false ]; then
  echo 'main push: no verified main commit to compare with; selecting all product verification' >&2
  select_all_product
  classification=unclassified
fi

# Temporary (owner decision 2026-10-20): while main-push-switch.sh says so, a
# push to main defers Kind to the scheduled or dispatched Kind run. Edge
# static verification (edge_kind) stays. The local mode above keeps Kind.
if [ "$event" = push ] && [ "${GITHUB_REF:-}" = refs/heads/main ] \
    && [ "$MAIN_PUSH_RUNS_KIND_AND_DRY_RUN" = false ] && token_selected kind; then
  unset 'selected[kind]'
  echo 'main push: Kind deferred to the scheduled or dispatched Kind run (owner decision 2026-10-20)' >&2
fi

# A scheduled run checks only Kind: the pushes to main ran everything else.
# It runs Kind when a path changed since the last successful scheduled run
# would select Kind on a push, or when there is no such run to compare with.
# While the switch gives pushes to main their Kind again, it runs nothing.
# The scheduled marker keeps artifact facts from dispatching any other group.
if [ "$event" = schedule ]; then
  classification=scheduled
  schedule_kind=false
  if [ "$MAIN_PUSH_RUNS_KIND_AND_DRY_RUN" = true ]; then
    echo 'schedule: a push to main runs Kind (main-push-switch.sh); the schedule runs nothing' >&2
  elif [ "$schedule_baseline_known" != true ]; then
    schedule_kind=true
    echo 'schedule: no successful scheduled run to compare with; Kind runs' >&2
  elif token_selected kind; then
    schedule_kind=true
    echo "schedule: a Kind input changed since ${SCHEDULE_BASELINE_SHA:-the baseline}; Kind runs" >&2
  else
    echo "schedule: no Kind input changed since ${SCHEDULE_BASELINE_SHA:-the baseline}; Kind does not run" >&2
  fi
  for token in "${!selected[@]}"; do
    unset "selected[$token]"
  done
  if [ "$schedule_kind" = true ]; then
    select_token kind
  fi
  select_token scheduled
fi

for token in "${!selected[@]}"; do
  printf '%s\n' "$token"
done | LC_ALL=C sort > "$tokens_tmp"

selection="|valid:${selector_version}|"
while IFS= read -r token; do
  [ -n "$token" ] || continue
  selection="${selection}${token}|"
done < "$tokens_tmp"
selection="${selection}complete|"

emit_outputs() {
  printf 'selector_version=%s\n' "$selector_version"
  printf 'classification=%s\n' "$classification"
  printf 'selection=%s\n' "$selection"
  printf 'required_local_mode=%s\n' "$required_local_mode"
}

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  emit_outputs | tee -a "$GITHUB_OUTPUT"
else
  emit_outputs
fi

if [ "$diagnostic_changed_files" = true ]; then
  printf 'changed_files<<EOF\n'
  cat "$tmp"
  printf 'EOF\n'
fi
