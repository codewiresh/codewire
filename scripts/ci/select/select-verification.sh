#!/usr/bin/env bash
# Select product verification capabilities from one changed-path contract.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: select-verification.sh [--diagnostic-changed-files] [changed-files]

changed-files may be a file containing one path per line, or "-" for stdin.
Without an argument the script discovers pull-request or main-push changes.

Writes one versioned selection token set to stdout and to $GITHUB_OUTPUT.
Routine output is limited to selector_version and selection. Use
--diagnostic-changed-files to append the classified path set to stdout.
Pull requests run Kind only for a Kind-relevant path with explicit opt-in.
Set VERIFICATION_REQUEST for product workflow_dispatch to a family token or
all. The separate Manual diagnostics workflow uses rust-stack or go-tailnet.
EOF
}

selector_version=v2
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
      codewire_tailnet codewire_gateway codewire_daemon codewire_mesh \
      codewire_derp codewire_udp_relay codewire_coordinator; do
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
      policy rust go_support web sdk_go sdk_ts sdk_python database \
      service_integration edge_kind release deploy security \
      runtime_confidential; do
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
    policy|web|sdk_go|sdk_ts|sdk_python|database|release|deploy|ios)
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

force_all=false
if [ "$event_selected" = false ] && [ "$explicit_paths" = false ]; then
  case "$event" in
    pull_request)
      if ! discover_pr_changed_files "$tmp"; then
        echo "warning: unable to discover pull-request changes; selecting all product verification" >&2
        force_all=true
      fi
      ;;
    push)
      if ! discover_push_changed_files "$tmp"; then
        echo "warning: unable to discover push changes; selecting all product verification" >&2
        force_all=true
      fi
      ;;
    workflow_dispatch)
      select_dispatch_request
      event_selected=true
      ;;
    *)
      echo "warning: unsupported event '${event:-unset}'; selecting all product verification" >&2
      force_all=true
      ;;
  esac
fi

kind_relevant=false
saw_path=false

if [ "$force_all" = true ]; then
  select_all_product
elif [ "$event_selected" = false ]; then
  # Policy is the lightweight invariant for every path-selected PR/main run.
  select_token policy

  while IFS= read -r path; do
    [ -n "$path" ] || continue
    saw_path=true
    recognized=false

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
      .gitea/workflows/connect-apikey-smoke.yaml|\
      .gitea/workflows/dev-deployment-smoke-receipt.yaml|\
      .gitea/workflows/prod-readonly-smoke.yaml|\
      .gitea/workflows/runtime-dev-commodity-smoke.yaml|\
      .githooks/pre-push|Makefile|scripts/dev/install-hooks.sh|\
      scripts/dev/preflight.sh|scripts/ci/select/select-verification.sh|\
      scripts/ci/select/require-verification-results.sh|\
      scripts/ci/select/verify-tested-tree-receipt.sh|\
      scripts/ci/select/verify-release-tag-receipt.sh|\
      scripts/ci/select/artifact-impact.py|\
      scripts/ci/select/select-support-images.sh|\
      scripts/ci/tests/test-select-verification.sh|scripts/ci/tests/test-select-deploy-dev.sh|\
      scripts/ci/tests/test-artifact-impact.py|\
      scripts/ci/tests/test-resolve-deployed-source.sh|\
      scripts/ci/tests/test-require-verification-results.sh|\
      scripts/ci/tests/test-verify-tested-tree-receipt.sh|\
      scripts/ci/tests/test-verify-release-tag-receipt.sh|\
      scripts/ci/tests/test-pre-push-worktree.sh|\
      scripts/ci/tests/test-go-source-ownership.sh|\
      scripts/ci/tests/test-dev-deployment-smoke-receipt.sh|\
      scripts/ci/tests/test-rust-owned-fixtures.sh|\
      scripts/ci/verify/integration-postgres.sh|scripts/ci/tests/test-integration-postgres.sh|\
      scripts/ci/verify/resolve-cargo-target-dir.sh|\
      scripts/ci/tests/test-resolve-cargo-target-dir.sh|\
      scripts/ci/verify/run-product-verification.sh|\
      scripts/ci/tests/test-sdk-local-cli-contract.sh|\
      scripts/checks/security/audit-rust-only-runtime.sh|\
      scripts/ci/setup/*.sh|scripts/ci/verify/*.sh|\
      scripts/ci/verify/rust-stack-rehearsal.sh|scripts/ci/select/select-deploy-dev.sh)
        select_token policy
        recognized=true
        ;;
    esac

    case "$path" in
      .gitea/workflows/desktop-package.yaml|\
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
      scripts/ci/verify/run-integration-verification.sh)
        # This file owns every service's executable integration harness. Its
        # own changes must run the combined family, not policy alone.
        select_token policy
        select_services
        recognized=true
        ;;
    esac

    case "$path" in
      .gitattributes|.gitignore|.dockerignore|turbo.json)
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
      scripts/checks/repo_checks.py)
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
      proto/*|buf.yaml|buf.gen*.yaml)
        select_token contracts
        select_token contracts_proto
        select_token edge_kind
        select_token go_support
        select_token go_consumer_interop
        recognized=true
        ;;
      crates/codewire-proto/*)
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
        select_token rust_pkg_codewire_gateway_proto
        select_token transport
        select_token transport_pkg_codewire_daemon
        select_token transport_pkg_codewire_gateway
        recognized=true
        ;;
      libs/tailnet/*|scripts/ci/verify/tailnet-parity.sh)
        select_token go_support
        select_token go_tailnet
        recognized=true
        ;;
    esac

    case "$path" in
      libs/sdk-go/*|\
      libs/sdk-examples/run-claude/go/*)
        select_token sdk_go
        select_token go_support
        select_token go_consumer_interop
        recognized=true
        ;;
      libs/sdk-ts/*|\
      libs/sdk-examples/run-claude/typescript/*)
        select_token sdk_ts
        recognized=true
        ;;
      libs/sdk-python/*|libs/sdk-examples/run-claude/python/*)
        select_token sdk_python
        recognized=true
        ;;
      libs/sdk-examples/run-claude/.gitignore|\
      libs/sdk-examples/run-claude/README.md)
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
      apps/dashboard/package.json|apps/docs/package.json|\
      packages/*/package.json|\
      libs/sdk-ts/package.json|libs/sdk-ts/package-lock.json|\
      libs/sdk-examples/run-claude/typescript/package.json|\
      libs/sdk-examples/run-claude/typescript/package-lock.json)
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
      apps/dashboard/*|apps/docs/*)
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
        codewire-desktop|codewire-platform-native|codewire-ui)
          select_token policy
          select_token rust
          select_token rust_pkg_codewire_desktop
          ;;
        codewire-tailnet|codewire-gateway|codewire-daemon|codewire-mesh|\
        codewire-derp|codewire-udp-relay|codewire-coordinator)
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
          codewire-daemon|codewire-gateway|codewire-gateway-proto|\
          codewire-proto|codewire-tailnet|codewire-derp)
            select_token rust_curated_locks
            ;;
        esac
      fi
      recognized=true
    fi

    case "$path" in
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
      crates/codewire-coordinator/*)
        select_token service_integration
        select_token service_coordinator
        ;;
      crates/codewire-server-core/tests/go_consumer_interop.rs)
        select_token go_support
        select_token go_consumer_interop
        ;;
      crates/codewire-server-core/tests/org_deletion_lifecycle.rs)
        # This PostgreSQL-backed lifecycle test exercises no service process,
        # edge, or deployable runtime input. Its focused database verifier and
        # server-core Rust closure are selected by the exact test path.
        select_token database
        ;;
      crates/codewire-mesh/src/store.rs)
        # Mesh's PostgreSQL store owns its embedded SQLx ledger and the
        # fail-closed prelaunch retirement path. Compile-only transport checks
        # cannot exercise those database state transitions.
        select_token database
        ;;
      crates/codewire-server-core/*)
        select_services
        ;;
    esac

    case "$path" in
      crates/*/migrations/*)
        select_token database
        recognized=true
        ;;
      crates/codewire-server-core/src/migrate.rs|\
      crates/codewire-server-core/src/bin/codewire-db-migrate.rs|\
      crates/codewire-server-core/tests/data/application_schema_fingerprint.sql|\
      crates/codewire-server-core/tests/session_auth.rs|\
      crates/codewire-billing/src/subscription_migration.rs)
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
      scripts/runtime/dev/with-dev-smoke-auth.sh|\
      scripts/runtime/tests/test-with-dev-smoke-auth.sh)
        select_token security
        select_token security_dev_smoke_auth
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
      scripts/ci/verify/kind-e2e.sh|scripts/ci/verify/kind/*|\
      scripts/ci/tests/test-kind-e2e-*.sh|scripts/ci/tests/test-kind-forwards.sh|\
      scripts/dev/kind/install-temporal.sh|scripts/ci/tests/test-install-temporal.sh|\
      deployments/k8s/*ingress*|\
      deployments/k8s/overlays/local-kind/*|deployments/k8s/overlays/local-kind-static/*)
        select_token edge_kind
        kind_relevant=true
        recognized=true
        ;;
      scripts/checks/contracts/connect-edge-ownership.json)
        select_token edge_kind
        recognized=true
        ;;
      Dockerfile|apps/*/Dockerfile*|deployments/docker/*)
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
      deployments/*|apps/cli/charts/*|.gitea/workflows/deploy-*.yaml|\
      apps/cli/k8s/*|\
      .gitea/workflows/observe-*.yaml|\
      .gitea/workflows/prod-temporal-preflight.yaml|\
      scripts/ci/deploy/*.sh|scripts/ci/*observe*.sh|scripts/ci/*observe*.py|\
      scripts/ci/*observer*.tsv|\
      scripts/ci/*promot*.sh|scripts/ci/*promot*.py|\
      scripts/ci/deploy/dispatch-deploy-dev.sh|scripts/ci/deploy/dispatch-deploy-prod.sh|\
      scripts/ci/select/artifact-impact.py|scripts/ci/select/select-deploy-dev.sh|\
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
      .gitea/workflows/claude-e2e.yaml|.gitea/workflows/cli-release.yaml|\
      .gitea/workflows/mirror-github.yaml|\
      .gitea/workflows/workspace-image-verify.yaml|\
      .gitea/workflows/support-images.yaml|\
      scripts/ci/select/artifact-impact.py|\
      scripts/ci/select/select-support-images.sh|\
      keys/production-release.asc|\
      .gitea/workflows/observe-*.yaml|\
      scripts/ci/images/build-push-image.sh|scripts/ci/images/compute-image-tags.sh|\
      scripts/ci/images/copy-image-to-ghcr.sh|\
      scripts/ci/deploy/dispatch-deploy-dev.sh|scripts/ci/deploy/dispatch-deploy-prod.sh|\
      scripts/ci/setup/fetch-infisical-ci-secret.sh|\
      scripts/ci/images/publish-image-to-ghcr.sh|\
      scripts/ci/images/run-skopeo-container.sh|\
      scripts/ci/images/image-bundle.py|scripts/ci/release/mirror-canonical-release-tag.sh|\
      scripts/ci/release/mirror-git-tags.sh|\
      scripts/ci/*promot*.sh|scripts/ci/*promot*.py|\
      scripts/ci/release/check-cw-darwin-sdkless.sh|\
      scripts/ci/release/package-cw-release.sh|scripts/ci/release/publish-cw-release.sh|\
      scripts/ci/tests/test-copy-image-to-ghcr.sh|\
      scripts/ci/tests/test-dispatch-deploy-dev.sh|scripts/ci/tests/test-dispatch-deploy-prod.sh|\
      scripts/ci/tests/test-publish-image-to-ghcr.sh|\
      scripts/ci/tests/test-run-skopeo-container.sh|\
      scripts/ci/tests/test-support-images-workflow.sh|\
      scripts/ci/tests/test-workspace-image-verify-workflow.sh|\
      scripts/ci/tests/test-base-image-source.sh|\
      scripts/ci/tests/test-build-push-image.sh|\
      scripts/ci/tests/test-claude-e2e-workflow.sh|\
      scripts/ci/tests/test-fetch-infisical-ci-secret.sh|\
      scripts/ci/tests/test-cw-install-signature.sh|scripts/ci/tests/test-image-bundle.py|\
      scripts/ci/tests/test-mirror-git-tags.sh|scripts/ci/tests/test-publish-cw-release.sh|\
      scripts/ci/tests/test-deploy-prod-workflow.sh|\
      scripts/ci/tests/test-deploy-dev.sh|\
      scripts/ci/tests/test-verify-cw-release-signing-key.sh|\
      scripts/ci/tests/test-verify-release-tag-ref.sh|\
      scripts/ci/select/verify-release-tag-receipt.sh|\
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
      scripts/ci/verify/dashboard-image.sh)
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
      scripts/ci/verify/rehearse-build-local-image.sh|\
      scripts/ci/verify/verify-workspace-image.sh|\
      scripts/ci/verify/workspace-agent-contract.sh)
        select_token policy
        recognized=true
        ;;
      crates/codewire-orchestration/src/sandbox/mod.rs|\
      crates/codewire-orchestration/src/sandbox/template.rs)
        select_token edge_kind
        recognized=true
        ;;
    esac

    if [ "$recognized" = false ]; then
      echo "warning: unclassified path '${path}'; selecting all product verification" >&2
      select_all_product
    fi
  done < "$tmp"

  if [ "$saw_path" = false ]; then
    echo "warning: empty changed path set; selecting all product verification" >&2
    select_all_product
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
  printf 'selection=%s\n' "$selection"
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
