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
Pull requests run Kind only for a Kind-relevant path with explicit opt-in.
Set VERIFICATION_REQUEST for product workflow_dispatch to a family token or
all. The separate Manual diagnostics workflow uses rust-stack or go-tailnet.
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

tmp="$(mktemp)"
tokens_tmp="$(mktemp)"
trap 'rm -f "$tmp" "$tokens_tmp"' EXIT

event="${GITHUB_EVENT_NAME:-}"
explicit_paths=false

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

if [ $# -gt 0 ]; then
  explicit_paths=true
  if [ "$1" = "-" ]; then
    cat > "$tmp"
  else
    cp "$1" "$tmp"
  fi
fi

declare -A selected=()

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

select_services() {
  select_token service_integration
  select_token service_apikey_smoke
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
      codewire_netstack codewire_tailnet codewire_gateway codewire_daemon codewire_local_vmm \
      codewire_mesh codewire_derp codewire_udp_relay codewire_coordinator \
      codewire_vmm_guest_probe; do
    select_token "transport_pkg_${package}"
  done
}

select_all_contracts() {
  select_token contracts
  select_token contracts_proto
}

select_all_product() {
  local include_ios="${1:-false}" family
  for family in \
      policy policy_shell rust go_support web sdk_go sdk_ts sdk_python database \
      service_integration edge_kind release deploy security \
      runtime_confidential runtime_dev_smoke; do
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
      ;;
    web|sdk_go|sdk_ts|sdk_python|database|release|deploy|ios)
      select_token "$request"
      ;;
    rust-stack)
      select_token diagnostic_rust_stack
      ;;
    go-tailnet)
      select_token diagnostic_go_tailnet
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

pr_kind_opt_in=false
if truthy "${KIND_E2E_OPT_IN:-}"; then
  pr_kind_opt_in=true
elif [ -n "${GITHUB_EVENT_PATH:-}" ] && [ -f "$GITHUB_EVENT_PATH" ]; then
  if grep -Eiq '(\[kind-e2e\]|\[run-kind-e2e\]|"name"[[:space:]]*:[[:space:]]*"kind-e2e")' \
      "$GITHUB_EVENT_PATH"; then
    pr_kind_opt_in=true
  fi
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
      .agents/*|.claude/*|.github/*)
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
      esac
    fi

    # CI policy changes validate only the workflow/selector contract. Product
    # files in the same PR still add their own families below.
    case "$path" in
      .gitea/workflows/ci.yaml|.gitea/workflows/manual-diagnostics.yaml|\
      .gitea/workflows/rust-latest-canary.yaml|\
      .gitea/workflows/rust-cache-refresh.yaml|\
      .gitea/workflows/connect-apikey-smoke.yaml|\
      .gitea/workflows/source-approval.yml|\
      .gitea/workflows/dev-deployment-smoke-receipt.yaml|\
      .gitea/workflows/prod-readonly-smoke.yaml|\
      .gitea/workflows/runtime-dev-commodity-smoke.yaml|\
      .githooks/pre-push|Makefile|scripts/dev/install-hooks.sh|\
      scripts/dev/dashboard-watch.py|\
      scripts/dev/preflight.sh|scripts/ci/select/select-verification.sh|\
      scripts/ci/select/emit-verification-matrices.sh|\
      scripts/ci/select/require-verification-results.sh|\
      scripts/ci/receipts/local-prepush-receipt.py|\
      scripts/ci/receipts/emit-verification-receipt.py|\
      scripts/ci/receipts/verify-tested-tree-receipt.sh|\
      scripts/ci/receipts/verify-release-tag-receipt.sh|\
      scripts/ci/receipts/emit-rust-cache-receipt.py|\
      scripts/ci/receipts/verify-rust-cache-receipt.sh|\
      scripts/ci/cache/prepare-rust-dependency-cache.sh|\
      scripts/ci/cache/select-rust-cache-key.sh|\
      scripts/ci/images/resolve-published-support-pair.sh|\
      scripts/ci/plan/*|\
      scripts/ci/tests/test-select-verification.sh|\
      scripts/ci/tests/test-source-approval-workflow.sh|\
      scripts/ci/tests/test-setup-kubeconfig.sh|\
      scripts/ci/tests/test-resolve-published-support-pair.sh|\
      scripts/ci/tests/test-resolve-deployed-source.sh|\
      scripts/ci/tests/test-require-verification-results.sh|\
      scripts/ci/tests/test-emit-verification-matrices.sh|\
      scripts/ci/tests/test-verify-tested-tree-receipt.sh|\
      scripts/ci/tests/test-verify-release-tag-receipt.sh|\
      scripts/ci/tests/test-local-prepush-receipt.sh|\
      scripts/ci/tests/test-pre-push-worktree.sh|\
      scripts/ci/tests/test-go-source-ownership.sh|\
      scripts/ci/tests/test-dev-deployment-smoke-receipt.sh|\
      scripts/ci/tests/test-agent-sandbox-pin.sh|\
      scripts/ci/tests/test-rust-owned-fixtures.sh|\
      scripts/ci/tests/test-rust-toolchain.sh|\
      scripts/ci/tests/test-cargo-cache-capacity.sh|\
      scripts/ci/tests/test-rust-cache-workflow.sh|\
      scripts/ci/tests/test-rust-cache-receipts.sh|\
      scripts/ci/tests/test-shellcheck-policy-domain.sh|\
      scripts/ci/tests/test-openbao-only-secret-authority.sh|\
      scripts/ci/tests/test-preflight-openbao-native-secrets.sh|\
      scripts/ci/tests/test-sync-local-secrets.sh|\
      scripts/ci/tests/fixtures/cargo-cache-df.sh|\
      scripts/ci/verify/integration-postgres.sh|scripts/ci/tests/test-integration-postgres.sh|\
      scripts/ci/verify/resolve-cargo-target-dir.sh|\
      scripts/ci/tests/test-resolve-cargo-target-dir.sh|\
      scripts/ci/tests/test-cargo-target-runner-failures.sh|\
      scripts/ci/tests/test-ci-tool-downloads.sh|\
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
      scripts/ci/tests/test-curated-rust-locks.sh)
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
        select_token runtime_dev_smoke
        recognized=true
        ;;
    esac

    case "$path" in
      scripts/ci/verify/run-integration-verification.sh)
        # This file owns database execution and every service's integration
        # harness. Its changes must qualify both executable families.
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
      .gitattributes|.gitignore|.dockerignore|.env.example|turbo.json)
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
      Cargo.toml|Cargo.lock|rust-toolchain.toml)
        select_token rust
        select_token rust_workspace
        select_token rust_curated_locks
        # Workspace graph, resolution, and toolchain changes can alter both
        # the host VMM and the statically packaged guest probe. Keep their
        # cross-target and reproducible-initramfs checks attached to every
        # root Rust build input.
        select_token transport
        select_token transport_pkg_codewire_local_vmm
        select_token transport_pkg_codewire_vmm_guest_probe
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
      scripts/checks/repo_policy/licensing.py)
        # The package inventory is enforced by policy-core; it does not
        # execute contracts, deployments, releases, or runtime security.
        select_token policy
        recognized=true
        ;;
      scripts/checks/repo_checks.py|scripts/checks/repo_policy/*.py|\
      scripts/ci/tests/test-repo-checks-modules.py)
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
      libs/gateway-proto/gen/*|libs/gateway-proto/buf.gen.yaml|\
      libs/gateway-proto/go.mod|libs/gateway-proto/go.sum|\
      tests/contract/coordinator/*|tests/contract/file/*|\
      tests/contract/orchestration/*)
        if [ -e "$repo_root/$path" ]; then
          echo "::error::retired former-Go implementation path recreated: $path" >&2
          exit 1
        fi
        recognized=true
        ;;
      libs/gateway-proto/proto/*|libs/gateway-proto/buf.yaml)
        select_token rust
        # Both daemon-initiated local and gateway-initiated platform brokerage
        # consume these private frames. Rust owns both broker feature graphs.
        select_token rust_pkg_codewire_credential_bridge
        select_token rust_pkg_codewire_credential_broker
        select_token rust_pkg_codewire_gateway_proto
        select_token transport
        select_token transport_pkg_codewire_daemon
        select_token transport_pkg_codewire_gateway
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
      apps/dashboard/*|apps/docs/*|favicon.svg|logo/*|\
      scripts/dev/design-system-server.py)
        select_token web
        recognized=true
        ;;
      apps/ios/*)
        select_token ios
        recognized=true
        ;;
      apps/cli/Makefile)
        select_token rust
        select_token rust_pkg_codewire_cli
        select_token rust_pkg_codewire_cli_bin
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

    if [[ "$path" == crates/*/* ]] && [[ "$path" != crates/codewire-api-contract/* ]] \
        && [[ "$path" != crates/codewire-api-types/* ]] \
        && [[ "$path" != crates/codewire-core/* ]]; then
      crate="${path#crates/}"
      crate="${crate%%/*}"
      crate_token="${crate//-/_}"
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
        codewire-platform-native)
          # Deletion-only tombstone: a revival of the retired ambient-SSH
          # adapter must still run the detached desktop verification.
          select_token policy
          select_token rust
          select_token rust_pkg_codewire_desktop
          ;;
        codewire-netstack|codewire-tailnet|codewire-gateway|codewire-daemon|codewire-local-vmm|\
        codewire-mesh|codewire-derp|codewire-udp-relay|codewire-coordinator|\
        codewire-vmm-guest-probe)
          select_token transport
          select_token "transport_pkg_${crate_token}"
          ;;
        *)
          select_token rust
          select_token "rust_pkg_${crate_token}"
          ;;
      esac
      if [ "$crate" = codewire-dashboard-web ]; then
        select_token deploy
        select_token edge_kind
        select_token web
        kind_relevant=true
      fi
      if [ "$path" = "crates/$crate/Cargo.toml" ]; then
        case "$crate" in
          codewire-daemon|codewire-gateway|codewire-gateway-proto|codewire-tls|\
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
        select_token transport_pkg_codewire_gateway
        ;;
      crates/codewire-credential-bridge/*)
        # Material-free HTTP/frame handling is shared with daemon and gateway;
        # prove its reverse consumers as well as the extracted unit tests.
        select_token rust
        select_token rust_pkg_codewire_credential_broker
        select_token transport
        select_token transport_pkg_codewire_daemon
        select_token transport_pkg_codewire_gateway
        select_token transport_pkg_codewire_local_vmm
        select_token transport_pkg_codewire_vmm_guest_probe
        ;;
      crates/codewire-gateway-proto/*)
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
      crates/codewire-credential-service/*)
        # Runtime identity and consent admission need the restricted PostgreSQL
        # matrix in addition to the material-free Kubernetes unit fixtures.
        select_token database
        ;;
      crates/codewire-credential-broker/src/provider_enrollment.rs|\
      crates/codewire-credential-broker/src/codex_enrollment/*)
        # Shared by CLI and the isolated platform mutation service;
        # package-default tests alone do not cover this opt-in feature.
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
      crates/codewire-server-core/*)
        select_services
        ;;
    esac

    case "$path" in
      crates/codewire-gateway-proto/src/lib.rs)
        # Shared fixed Pod-token audiences are consumed by the optional
        # server-core verifier, not just by the private protocol endpoints.
        select_token rust_pkg_codewire_server_core
        ;;
      scripts/ci/verify/build-local-vmm-initramfs.sh|\
      scripts/ci/verify/smoke-local-vmm-cloud-hypervisor.sh|\
      scripts/ci/verify/smoke-native-local-environment.sh)
        select_token transport
        select_token transport_pkg_codewire_local_vmm
        select_token transport_pkg_codewire_vmm_guest_probe
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
      scripts/dev/kind/sync-local-secrets.sh)
        # The local credential bridge has a hermetic policy fixture and does
        # not provision or exercise a Kind cluster.
        select_token policy
        recognized=true
        ;;
      scripts/dev/kind/*)
        select_token edge_kind
        kind_relevant=true
        recognized=true
        ;;
      scripts/runtime/*apikey*|docs/runbooks/connect-apikey-lifecycle-smoke.md)
        select_token service_apikey_smoke
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
        select_token runtime_confidential
        recognized=true
        ;;
      scripts/runtime/dev/provision-dev-smoke-user.sh|\
      scripts/runtime/dev/smoke-dev-commodity.sh|\
      scripts/runtime/dev/with-dev-smoke-auth.sh|\
      scripts/runtime/tests/test-provision-dev-smoke-user.sh|\
      scripts/runtime/tests/test-smoke-dev-commodity.sh|\
      scripts/runtime/tests/test-with-dev-smoke-auth.sh)
        select_token runtime_dev_smoke
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
      scripts/dev/kind/install-temporal.sh|scripts/ci/tests/test-install-temporal.sh|\
      deployments/k8s/*ingress*|\
      deployments/k8s/overlays/local-kind/*|deployments/k8s/overlays/local-kind-static/*)
        select_token edge_kind
        kind_relevant=true
        recognized=true
        ;;
      scripts/ci/tests/test-kind-e2e-*.sh|scripts/ci/tests/test-kind-forwards.sh|\
      scripts/ci/tests/test-kind-codex-session.py|scripts/ci/tests/test-kind-credentials.py)
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
      scripts/ci/setup/finish-untrusted-rust-cache.sh)
        select_token policy
        select_token rust
        select_token rust_workspace
        select_token security
        recognized=true
        ;;
      scripts/ci/tests/test-select-untrusted-rust-cache.sh)
        select_token policy
        select_token security
        recognized=true
        ;;
      scripts/ci/setup/select-untrusted-workspace-cache.sh|\
      scripts/ci/images/workspace-cache.sh|\
      scripts/ci/tests/test-select-untrusted-workspace-cache.sh|\
      scripts/ci/tests/test-workspace-cache.sh|\
      scripts/ci/tests/canary-workspace-r2-cache.sh)
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
      Dockerfile|docker-bake.hcl|apps/*/Dockerfile*|deployments/docker/*|\
      scripts/ci/images/build-kind-images.sh|scripts/ci/images/build-push-runtime-images.sh|\
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
      scripts/ci/images/sign-runtime-image-set.sh|\
      scripts/ci/tests/test-sign-runtime-image-set.sh|\
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
      images/*|\
      .gitea/workflows/cli-release.yaml|\
      .gitea/workflows/mirror-github.yaml|\
      .gitea/workflows/support-images.yaml|\
      keys/production-release.asc|\
      .gitea/workflows/observe-*.yaml|\
      scripts/ci/images/build-push-image.sh|scripts/ci/images/build-push-runtime-images.sh|\
      scripts/ci/images/nexus-publication-retry-contract.sh|\
      scripts/ci/images/compute-image-tags.sh|\
      scripts/ci/images/copy-image-to-ghcr.sh|\
      scripts/ci/deploy/dispatch-deploy-dev.sh|scripts/ci/deploy/dispatch-deploy-prod.sh|\
      scripts/ci/setup/fetch-forgejo-deploy-dev-token.sh|\
      scripts/ci/setup/fetch-forgejo-deploy-prod-token.sh|\
      scripts/ci/setup/curl-transport-retry.sh|\
      scripts/ci/setup/fetch-openbao-ghcr-credentials.sh|\
      scripts/ci/setup/fetch-openbao-github-mirror-credentials.sh|\
      scripts/ci/setup/fetch-openbao-nexus-credentials.sh|\
      scripts/ci/images/publish-image-to-ghcr.sh|\
      scripts/ci/images/resolve-published-support-pair.sh|\
      scripts/ci/images/run-skopeo-container.sh|\
      scripts/ci/images/image-bundle.py|scripts/ci/release/mirror-canonical-release-tag.sh|\
      scripts/ci/release/mirror-git-tags.sh|\
      scripts/ci/*promot*.sh|scripts/ci/*promot*.py|\
      scripts/ci/release/check-cw-darwin-sdkless.sh|\
      scripts/ci/release/mint-github-app-token.sh|\
      scripts/ci/release/mirror-github.sh|\
      scripts/ci/release/package-cw-release.sh|scripts/ci/release/publish-cw-release.sh|\
      scripts/ci/tests/test-copy-image-to-ghcr.sh|\
      scripts/ci/tests/test-dispatch-deploy-dev.sh|scripts/ci/tests/test-dispatch-deploy-prod.sh|\
      scripts/ci/tests/test-publish-image-to-ghcr.sh|\
      scripts/ci/tests/test-resolve-published-support-pair.sh|\
      scripts/ci/tests/test-run-skopeo-container.sh|\
      scripts/ci/tests/test-support-images-workflow.sh|\
      scripts/ci/tests/test-workspace-image-verify-workflow.sh|\
      scripts/ci/tests/test-base-image-source.sh|\
      scripts/ci/tests/test-build-push-image.sh|\
      scripts/ci/tests/test-build-push-runtime-images.sh|\
      scripts/ci/tests/test-run-rust-build.sh|\
      scripts/ci/tests/test-fetch-forgejo-deploy-dev-token.sh|\
      scripts/ci/tests/test-fetch-openbao-ghcr-credentials.sh|\
      scripts/ci/tests/test-fetch-openbao-github-mirror-credentials.sh|\
      scripts/ci/tests/test-fetch-openbao-nexus-credentials.sh|\
      scripts/ci/tests/test-forgejo-action-mirrors.sh|\
      scripts/ci/tests/test-nexus-runtime-pull-contract.sh|\
      scripts/ci/tests/test-cw-install-signature.sh|scripts/ci/tests/test-image-bundle.py|\
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
      apps/cli/GPG_PUBLIC_KEY.asc|\
      apps/cli/README.md|apps/cli/install.sh|\
      apps/cli/aur/PKGBUILD|apps/cli/nfpm.yaml|\
      apps/cli/scripts/update-homebrew-formula.sh|install.sh)
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
      scripts/ci/tests/test-fetch-openbao-github-mirror-credentials.sh|\
      scripts/ci/tests/test-mint-github-app-token.sh)
        select_token deploy
        select_token security
        recognized=true
        ;;
    esac

    case "$path" in
      deployments/k8s/overlays/production/kustomization.yaml|\
      deployments/k8s/overlays/production/config-images.yaml|\
      deployments/k8s/flux/production/mesh-helmrelease.yaml)
        select_token deploy
        select_token release
        recognized=true
        ;;
    esac

    case "$path" in
      scripts/checks/security/audit-js-supply-chain.sh)
        select_token security
        select_token security_js
        recognized=true
        ;;
      scripts/checks/security/audit-runtime-images.sh)
        select_token security
        select_token deploy
        select_token edge_kind
        select_token release
        recognized=true
        ;;
      scripts/ci/verify/dashboard-image.sh|\
      scripts/ci/tests/test-dashboard-image-network-probe.sh)
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
  select_token runtime_confidential
  select_token go_support
  select_token go_consumer_interop
elif token_selected sdk_go; then
  select_token go_support
  select_token go_consumer_interop
fi

# This marker means absence of policy_shell is an authoritative decision from
# a selector that knows the shell-policy domain. Older trusted selectors omit
# it, so candidate runners must keep executing ShellCheck for legacy output.
if token_selected policy; then
  select_token policy_shell_omittable
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

required_local_mode=default
if [ "$classification" = unclassified ] \
  || [ "$classification" = release ] \
  || { [ "$classification" = requested ] && [ "${VERIFICATION_REQUEST:-policy}" = all ]; }; then
  required_local_mode=full
elif [ "$kind_relevant" = true ] || token_selected kind; then
  required_local_mode=kind
elif token_selected database || token_selected service_integration; then
  required_local_mode=integration
fi

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
