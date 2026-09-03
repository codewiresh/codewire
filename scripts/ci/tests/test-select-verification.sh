#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SELECTOR="$ROOT/scripts/ci/select/select-verification.sh"
WORKFLOW="$ROOT/.gitea/workflows/ci.yaml"
DIAGNOSTICS_WORKFLOW="$ROOT/.gitea/workflows/manual-diagnostics.yaml"
CLI_RELEASE_WORKFLOW="$ROOT/.gitea/workflows/cli-release.yaml"
TMP="$(mktemp -d)"
NEGATIVE_CACHE_PATH="$ROOT/scripts/ci/cache/unlisted-cache-helper.sh"
cleanup() {
  rm -f "$NEGATIVE_CACHE_PATH"
  rmdir "$ROOT/scripts/ci/cache" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

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

assert_tokens() {
  local name="$1" expected="$2" output="$3" actual want selection
  if [[ " $expected " == *' policy '* ]] \
      && [[ " $expected " != *' policy_shell_omittable '* ]]; then
    expected="$expected policy_shell_omittable"
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
    changed|unchanged|unclassified|requested|release) ;;
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
  printf '%s\n' "$@" > "$paths"
  output="$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
    GITHUB_EVENT_NAME="$event" GITHUB_REF="$ref" \
    KIND_E2E_OPT_IN="$opt_in" "$SELECTOR" "$paths")"
  assert_tokens "$name" "$expected" "$output"
}

run_present_paths_case() {
  local name="$1" event="$2" ref="$3" opt_in="$4" expected="$5"
  shift 5
  local fixture_root="$TMP/${name}.repo" paths="$TMP/${name}.paths" output path
  mkdir -p "$fixture_root"
  for path in "$@"; do
    mkdir -p "$fixture_root/$(dirname "$path")"
    : > "$fixture_root/$path"
  done
  printf '%s\n' "$@" > "$paths"
  output="$(cd "$fixture_root" && env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
    GITHUB_EVENT_NAME="$event" GITHUB_REF="$ref" \
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

policy=policy
run_paths_case docs pull_request refs/pull/1/head false "$policy" \
  docs/guide.md README.md AGENTS.md crates/README.md
run_paths_case ios pull_request refs/pull/1/head false 'ios policy' \
  apps/ios/Sources/CodewireKit/Networking/CodewireClient.swift \
  apps/ios/Resources/Info.plist
run_paths_case repository_ignores pull_request refs/pull/10/head false "$policy" \
  .gitignore .dockerignore
run_paths_case repository_attributes pull_request refs/pull/1010/head false "$policy" \
  .gitattributes
run_paths_case gitleaks_policy pull_request refs/pull/10101/head false \
  'policy security' .gitleaks.toml
run_paths_case license_texts pull_request refs/pull/1011/head false "$policy" \
  LICENSE LICENSE-MIT LICENSE-APACHE LICENSE-BSD-3-CLAUSE \
  crates/codewire-cli/LICENSE packages/codewire-proto-ts/LICENSE-APACHE \
  proto/LICENSE-APACHE tests/contract/LICENSE
run_paths_case local_compose pull_request refs/pull/11/head false \
  'database deploy edge_kind policy web' docker-compose.yml
run_paths_case local_compose_kind_opt_in pull_request refs/pull/111/head true \
  'database deploy edge_kind kind policy web' docker-compose.yml
run_paths_case ci_self pull_request refs/pull/2/head false \
  'go_consumer_interop go_support policy policy_shell release runtime_confidential runtime_dev_smoke rust_curated_locks' \
  .gitea/workflows/ci.yaml .gitea/workflows/manual-diagnostics.yaml \
  .gitea/workflows/source-approval.yml \
  scripts/ci/select/select-verification.sh \
  scripts/ci/select/emit-verification-matrices.sh \
  scripts/ci/select/require-verification-results.sh \
  scripts/ci/receipts/local-prepush-receipt.py \
  scripts/ci/receipts/emit-verification-receipt.py \
  scripts/ci/receipts/verify-tested-tree-receipt.sh \
  scripts/ci/receipts/verify-release-tag-receipt.sh \
  scripts/ci/tests/test-require-verification-results.sh \
  scripts/ci/tests/test-emit-verification-matrices.sh \
  scripts/ci/tests/test-verify-tested-tree-receipt.sh \
  scripts/ci/tests/test-verify-release-tag-receipt.sh \
  scripts/ci/tests/test-local-prepush-receipt.sh \
  scripts/ci/tests/test-source-approval-workflow.sh
run_paths_case ci_rewrite pull_request refs/pull/20/head false \
  'policy runtime_dev_smoke rust_curated_locks' \
  .githooks/pre-push scripts/dev/preflight.sh \
  scripts/ci/receipts/local-prepush-receipt.py \
  scripts/ci/tests/test-local-prepush-receipt.sh \
  scripts/ci/verify/integration-postgres.sh \
  scripts/ci/verify/resolve-cargo-target-dir.sh \
  scripts/ci/verify/run-product-verification.sh \
  scripts/ci/tests/test-sdk-local-cli-contract.sh \
  scripts/checks/security/audit-rust-only-runtime.sh \
  scripts/ci/verify/rust-stack-rehearsal.sh \
  scripts/ci/tests/test-integration-postgres.sh \
  scripts/ci/tests/test-go-source-ownership.sh \
  scripts/ci/tests/test-resolve-cargo-target-dir.sh \
  scripts/ci/tests/test-cargo-target-runner-failures.sh \
  scripts/ci/tests/test-agent-sandbox-pin.sh \
  scripts/ci/tests/test-rust-owned-fixtures.sh \
  scripts/ci/tests/test-cargo-cache-capacity.sh \
  scripts/ci/tests/fixtures/cargo-cache-df.sh \
  scripts/ci/tests/test-select-verification.sh
run_paths_case retired_cache_surface pull_request refs/pull/200/head false \
  "$policy" \
  .gitea/workflows/rust-cache-refresh.yaml \
  scripts/ci/cache/prepare-rust-dependency-cache.sh \
  scripts/ci/cache/select-rust-cache-key.sh \
  scripts/ci/receipts/emit-rust-cache-receipt.py \
  scripts/ci/receipts/verify-rust-cache-receipt.sh \
  scripts/ci/tests/test-rust-cache-workflow.sh \
  scripts/ci/tests/test-rust-cache-receipts.sh
run_paths_case shellcheck_policy_domain_future pull_request refs/pull/2001/head false \
  'policy policy_shell' scripts/ci/tests/test-shellcheck-policy-domain.sh
grep -qF 'scripts/ci/tests/test-shellcheck-policy-domain.sh' "$SELECTOR"
run_paths_case openbao_secret_authority_policy pull_request refs/pull/20011/head false \
  'policy policy_shell' scripts/ci/tests/test-openbao-only-secret-authority.sh \
  scripts/ci/tests/test-preflight-openbao-native-secrets.sh \
  scripts/ci/tests/test-sync-local-secrets.sh
run_paths_case local_secret_sync_policy pull_request refs/pull/20012/head false \
  'policy policy_shell' scripts/dev/kind/sync-local-secrets.sh
run_paths_case root_secret_authority_inputs pull_request refs/pull/20013/head false \
  'policy' .env.example secret-authority.example.json
run_paths_case ci_tool_download_contract pull_request refs/pull/2002/head false \
  'deploy policy policy_shell' scripts/ci/tests/test-ci-tool-downloads.sh
run_paths_case product_image_build_graph pull_request refs/pull/2003/head false \
  'deploy edge_kind go_consumer_interop go_support policy release runtime_confidential' \
  docker-bake.hcl scripts/ci/images/build-kind-images.sh \
  scripts/ci/images/run-rust-build.sh
run_paths_case product_image_build_graph_kind pull_request refs/pull/2004/head true \
  'deploy edge_kind go_consumer_interop go_support kind policy release runtime_confidential' \
  docker-bake.hcl scripts/ci/images/build-kind-images.sh \
  scripts/ci/images/run-rust-build.sh
run_paths_case nexus_publication_retry pull_request refs/pull/2006/head false \
  'go_consumer_interop go_support policy release runtime_confidential' \
  scripts/ci/images/nexus-publication-retry-contract.sh
run_paths_case protected_runtime_signing pull_request refs/pull/2005/head false \
  'deploy go_consumer_interop go_support policy policy_shell release runtime_confidential security' \
  scripts/ci/images/cosign-private-signing-config.json \
  scripts/ci/images/sign-runtime-image-set.sh \
  scripts/ci/tests/test-sign-runtime-image-set.sh \
  scripts/ci/trust/codewire-runtime-signing.pub
run_paths_case runtime_plan_ci pull_request refs/pull/201/head false \
  'deploy go_consumer_interop go_support policy release runtime_confidential' \
  scripts/ci/deploy/resolve-deployed-source.sh \
  scripts/ci/plan/apply-deploy-plan.py \
  scripts/ci/images/resolve-published-support-pair.sh \
  scripts/ci/tests/test-resolve-published-support-pair.sh \
  scripts/ci/tests/test-resolve-deployed-source.sh
run_paths_case repo_checks pull_request refs/pull/21/head false \
  'contracts contracts_proto deploy edge_kind go_consumer_interop go_support policy release runtime_confidential security security_idp_kek' \
  scripts/checks/repo_checks.py
run_paths_case repo_policy_modules pull_request refs/pull/22/head false \
  'contracts contracts_proto deploy edge_kind go_consumer_interop go_support policy release runtime_confidential security security_idp_kek' \
  scripts/checks/repo_policy/mesh.py
run_paths_case repo_policy_fixture pull_request refs/pull/23/head false \
  'contracts contracts_proto deploy edge_kind go_consumer_interop go_support policy release runtime_confidential security security_idp_kek' \
  scripts/ci/tests/test-repo-checks-modules.py
run_paths_case release pull_request refs/pull/3/head false \
  'go_consumer_interop go_support policy release runtime_confidential' \
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
  scripts/ci/tests/test-cw-install-signature.sh \
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
  install.sh
run_paths_case protected_delivery_credentials pull_request refs/pull/31/head false \
  'deploy go_consumer_interop go_support policy release runtime_confidential security' \
  scripts/ci/setup/curl-transport-retry.sh \
  scripts/ci/setup/fetch-forgejo-deploy-prod-token.sh \
  scripts/ci/setup/fetch-openbao-github-mirror-credentials.sh \
  scripts/ci/release/mint-github-app-token.sh \
  scripts/ci/release/mirror-github.sh \
  scripts/ci/tests/test-fetch-openbao-github-mirror-credentials.sh \
  scripts/ci/tests/test-mint-github-app-token.sh
run_paths_case sccache_r2_consumer pull_request refs/pull/1749/head false \
  'edge_kind policy security' \
  scripts/ci/setup/fetch-openbao-sccache-r2-credentials.sh
run_paths_case sccache_r2_consumer_fixture pull_request refs/pull/1750/head false \
  'edge_kind policy security' \
  scripts/ci/tests/test-fetch-openbao-sccache-r2-credentials.sh
run_paths_case sccache_host_selector pull_request refs/pull/1751/head false \
  'policy rust rust_workspace security' \
  scripts/ci/setup/select-untrusted-rust-cache.sh \
  scripts/ci/setup/finish-untrusted-rust-cache.sh
run_paths_case sccache_host_selector_fixture pull_request refs/pull/1752/head false \
  'policy security' \
  scripts/ci/tests/test-select-untrusted-rust-cache.sh
run_paths_case dev_deploy_contract pull_request refs/pull/30/head false \
  'deploy go_consumer_interop go_support policy release runtime_confidential' scripts/ci/tests/test-deploy-dev.sh
run_paths_case dev_smoke_receipt pull_request refs/pull/302/head false \
  'policy' \
  .gitea/workflows/dev-deployment-smoke-receipt.yaml \
  scripts/ci/tests/test-dev-deployment-smoke-receipt.sh
run_paths_case setup_kubeconfig pull_request refs/pull/3021/head false \
  'policy' scripts/ci/tests/test-setup-kubeconfig.sh
run_paths_case retired_promotion_control pull_request refs/pull/300/head false \
  'deploy go_consumer_interop go_support policy release runtime_confidential' \
  scripts/ci/deprecated-promotion-control.sh \
  scripts/ci/test-deprecated-promotion-control.py
run_paths_case sha_dispatch pull_request refs/pull/301/head false \
  'deploy go_consumer_interop go_support policy release runtime_confidential' \
  scripts/ci/deploy/dispatch-deploy-dev.sh \
  scripts/ci/tests/test-dispatch-deploy-dev.sh \
  scripts/ci/deploy/dispatch-deploy-prod.sh \
  scripts/ci/tests/test-dispatch-deploy-prod.sh
run_paths_case dev_deploy_oidc pull_request refs/pull/3011/head false \
  'deploy go_consumer_interop go_support policy release runtime_confidential security' \
  scripts/ci/setup/fetch-forgejo-deploy-dev-token.sh \
  scripts/ci/tests/test-fetch-forgejo-deploy-dev-token.sh
run_paths_case production_source_ownership pull_request refs/pull/31/head false \
  'deploy go_consumer_interop go_support policy release runtime_confidential security security_idp_kek' \
  deployments/k8s/overlays/production/config-images.yaml
run_paths_case idp_kek_boundary pull_request refs/pull/32/head false \
  'deploy policy security security_idp_kek' \
  deployments/k8s/idp/deployment.yaml
run_paths_case orchestration_host_key_authz pull_request refs/pull/910/head false \
  'deploy policy security security_idp_kek' deployments/k8s/orchestration/gateway-host-key-authz.yaml
run_paths_case leaf_rust pull_request refs/pull/4/head false \
  'policy rust rust_pkg_codewire_cli' \
  crates/codewire-cli/src/commands/info.rs
run_paths_case detached_desktop pull_request refs/pull/401/head false \
  'policy rust rust_pkg_codewire_desktop' \
  crates/codewire-desktop/src/main.rs
run_paths_case detached_platform_native pull_request refs/pull/402/head false \
  'policy rust rust_pkg_codewire_desktop' \
  crates/codewire-platform-native/src/lib.rs
run_paths_case detached_ui pull_request refs/pull/403/head false \
  'policy rust rust_pkg_codewire_desktop' \
  crates/codewire-ui/src/lib.rs
run_paths_case native_desktop_ui_guard pull_request refs/pull/4031/head false \
  'policy rust rust_pkg_codewire_desktop' \
  scripts/checks/source/check-native-desktop-ui.py \
  scripts/checks/contracts/native-desktop-ui-policy.json
run_paths_case detached_desktop_package pull_request refs/pull/404/head false \
  'policy rust rust_pkg_codewire_desktop' \
  scripts/ci/release/package-codewire-desktop.sh \
  scripts/ci/tests/test-package-codewire-desktop.sh
run_paths_case retired_desktop_workflow pull_request refs/pull/405/head false \
  'policy' .gitea/workflows/desktop-package.yaml
run_paths_case artifact_plan_policy pull_request refs/pull/406/head false \
  'policy' scripts/ci/plan/planner.py scripts/ci/plan/artifact-graph.json
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
run_paths_case curated_gateway_member_manifest pull_request refs/pull/501/head false \
  'policy rust_curated_locks transport transport_pkg_codewire_daemon transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  crates/codewire-daemon/Cargo.toml
run_paths_case local_vmm_host_source pull_request refs/pull/5011/head false \
  'policy transport transport_pkg_codewire_local_vmm' \
  crates/codewire-local-vmm/src/lib.rs
run_paths_case local_vmm_guest_source pull_request refs/pull/5012/head false \
  'policy transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  crates/codewire-vmm-guest-probe/src/lib.rs
run_paths_case local_vmm_network_fixture pull_request refs/pull/50121/head false \
  'policy transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  testdata/local-vm-network/protocol-v1.json
run_paths_case local_vmm_initramfs_builder pull_request refs/pull/5013/head false \
  'policy transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  scripts/ci/verify/build-local-vmm-initramfs.sh
run_paths_case local_vmm_kvm_smoke pull_request refs/pull/5014/head false \
  'policy transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  scripts/ci/verify/smoke-local-vmm-cloud-hypervisor.sh
run_paths_case native_local_environment_smoke pull_request refs/pull/5015/head false \
  'policy transport transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  scripts/ci/verify/smoke-native-local-environment.sh
run_paths_case curated_derp_member_manifest pull_request refs/pull/502/head false \
  'policy rust_curated_locks transport transport_derp_contract transport_pkg_codewire_derp' \
  crates/codewire-derp/Cargo.toml
run_paths_case curated_gateway_lock pull_request refs/pull/503/head false \
  'deploy edge_kind go_consumer_interop go_support policy release runtime_confidential rust_curated_locks' \
  deployments/docker/gateway.Cargo.lock
run_paths_case curated_derp_lock pull_request refs/pull/504/head false \
  'deploy edge_kind go_consumer_interop go_support policy release runtime_confidential rust_curated_locks' \
  deployments/docker/derp.Cargo.lock
run_paths_case curated_lock_guard pull_request refs/pull/505/head false \
  'policy rust_curated_locks' \
  scripts/ci/verify/check-curated-rust-locks.sh \
  scripts/ci/tests/test-curated-rust-locks.sh
run_paths_case rust_toolchain_guard pull_request refs/pull/506/head false \
  'policy' \
  .gitea/workflows/rust-latest-canary.yaml \
  scripts/ci/verify/check-rust-toolchain.sh \
  scripts/ci/tests/test-rust-toolchain.sh
run_paths_case application_migration pull_request refs/pull/6/head false \
  'database policy rust rust_pkg_codewire_server_core service_apikey_smoke service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal' \
  crates/codewire-server-core/migrations/0001_baseline.sql
run_paths_case retired_go_migration_deletion pull_request refs/pull/600/head false \
  'policy' apps/api/db/migrations/0001_baseline.sql
run_paths_case retired_go_harness_deletion pull_request refs/pull/6010/head false \
  'policy' autoagent/agent.py libs/gatewayauth/token.go \
  libs/gateway-proto/gen/daemon/v1/daemon.pb.go
run_paths_case gateway_proto_source pull_request refs/pull/6011/head false \
  'policy rust rust_pkg_codewire_gateway_proto transport transport_pkg_codewire_daemon transport_pkg_codewire_gateway transport_pkg_codewire_local_vmm transport_pkg_codewire_vmm_guest_probe' \
  libs/gateway-proto/proto/daemon/v1/daemon.proto
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
  'database policy rust rust_pkg_codewire_server_core service_apikey_smoke service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal' \
  crates/codewire-server-core/tests/data/application_schema_fingerprint.sql
run_paths_case server_core_lifecycle_test pull_request refs/pull/6010/head false \
  'database policy rust rust_pkg_codewire_server_core' \
  crates/codewire-server-core/tests/org_deletion_lifecycle.rs
run_paths_case server_core_runtime_source pull_request refs/pull/6011/head false \
  'policy rust rust_pkg_codewire_server_core service_apikey_smoke service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal' \
  crates/codewire-server-core/src/lib.rs
run_paths_case rust_migration_database pull_request refs/pull/61/head false \
  'database policy rust rust_pkg_codewire_billing service_billing service_integration' \
  crates/codewire-billing/src/subscription_migration.rs
run_paths_case orchestration_service pull_request refs/pull/7/head false \
  'policy rust rust_pkg_codewire_orchestration service_integration service_orchestration' \
  crates/codewire-orchestration/src/api/environments.rs
run_paths_case orchestration_wire_contract pull_request refs/pull/71/head false \
  'policy rust rust_pkg_codewire_orchestration service_integration service_orchestration' \
  crates/codewire-orchestration/tests/wire_contract.rs \
  crates/codewire-orchestration/tests/wire_contract/environment.rs
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
  'policy service_apikey_smoke service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal' \
  scripts/ci/verify/run-integration-verification.sh
run_paths_case temporal_service pull_request refs/pull/84/head false \
  'policy rust rust_pkg_codewire_orchestration service_integration service_orchestration service_temporal' \
  crates/codewire-orchestration/src/worker/create.rs
run_paths_case temporal_fencing_kind_driver pull_request refs/pull/842/head false \
  'edge_kind kind policy rust rust_pkg_codewire_orchestration service_integration service_orchestration' \
  crates/codewire-orchestration/src/bin/temporal-fencing-smoke.rs
run_paths_case file_service_kind_driver pull_request refs/pull/843/head false \
  'edge_kind kind policy rust rust_pkg_codewire_orchestration service_integration service_orchestration' \
  crates/codewire-orchestration/src/bin/file-service-smoke.rs
run_paths_case reconciler_ttl_kind_driver pull_request refs/pull/844/head false \
  'edge_kind kind policy rust rust_pkg_codewire_orchestration service_integration service_orchestration' \
  crates/codewire-orchestration/src/bin/reconciler-ttl-smoke.rs
run_paths_case kind_harness pull_request refs/pull/845/head false \
  'edge_kind policy' \
  scripts/ci/verify/kind-e2e.sh \
  scripts/ci/verify/kind/common.sh \
  scripts/ci/verify/kind/suites/integrated.sh \
  scripts/ci/verify/kind/suites/final-fencing.sh \
  scripts/ci/verify/kind/suites/environment-session.sh \
  scripts/ci/tests/test-kind-e2e-cleanup.sh \
  scripts/ci/tests/test-kind-e2e-suites.sh \
  scripts/ci/tests/test-kind-forwards.sh
run_paths_case kind_harness_opt_in pull_request refs/pull/846/head true \
  'edge_kind kind policy' \
  scripts/ci/verify/kind/suites/final-fencing.sh \
  scripts/ci/verify/kind/suites/environment-session.sh
run_paths_case kind_fixture_only pull_request refs/pull/847/head false \
  'edge_kind policy' \
  scripts/ci/tests/test-kind-e2e-suites.sh \
  scripts/ci/tests/test-kind-forwards.sh
run_paths_case temporal_shared_fixture pull_request refs/pull/841/head false \
  'policy service_billing service_integration service_orchestration service_temporal' \
  tests/e2e/flip-state.env
run_paths_case nats_service pull_request refs/pull/85/head false \
  'policy service_coordinator service_integration service_nats transport transport_pkg_codewire_coordinator' \
  crates/codewire-coordinator/src/nats.rs
run_paths_case apikey_smoke pull_request refs/pull/86/head false \
  'policy service_apikey_smoke' \
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
run_paths_case derp_contract pull_request refs/pull/101/head false \
  'policy transport transport_derp_contract transport_pkg_codewire_derp' \
  tests/contract/derp/derp_test.go
run_paths_case proto pull_request refs/pull/11/head false \
  'contracts contracts_proto edge_kind go_consumer_interop go_support policy' \
  proto/codewire/v1/api_key.proto
run_paths_case environment_proto pull_request refs/pull/110/head false \
  'contracts contracts_proto edge_kind go_consumer_interop go_support policy sdk_go sdk_python sdk_ts' \
  proto/codewire/v1/environment.proto
run_paths_case admin_rust_proto_boundary pull_request refs/pull/1111/head false \
  'contracts contracts_proto policy rust rust_pkg_codewire_admin_proto' \
  crates/codewire-admin-proto/Cargo.toml \
  scripts/ci/proto/build-rust-descriptors.sh \
  scripts/ci/tests/test-admin-proto-boundary.sh
run_paths_case google_rpc_ts_template pull_request refs/pull/1114/head false \
  'contracts contracts_proto edge_kind go_consumer_interop go_support policy' \
  proto/buf.gen.google-rpc-ts.yaml
run_paths_case google_rpc_python_template pull_request refs/pull/1115/head false \
  'contracts contracts_proto edge_kind go_consumer_interop go_support policy' \
  proto/buf.gen.google-rpc-python.yaml
run_paths_case edge_ownership pull_request refs/pull/114/head false \
  'contracts contracts_proto edge_kind policy' scripts/checks/contracts/connect-edge-ownership.json
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
  'policy' scripts/checks/contracts/permanent-raw-surface-policy.json
run_paths_case retired_openapi_deletions pull_request refs/pull/1175/head false \
  'policy' openapi.json crates/codewire-api-contract/src/lib.rs \
  crates/codewire-api-types/src/lib.rs crates/codewire-core/src/lib.rs \
  libs/api-client-go/client_gen.go libs/api-client-python/pyproject.toml \
  libs/api-client-ts/package.json packages/codewire-types/package.json
run_paths_case mesh_policy_guard pull_request refs/pull/1171/head false \
  'policy' scripts/checks/contracts/mesh-final-surface-policy.json
run_paths_case mesh_policy_go_sdk pull_request refs/pull/1172/head false \
  'go_consumer_interop go_support policy sdk_go' \
  scripts/checks/contracts/mesh-final-surface-policy.json \
  libs/sdk-go/mesh_networks.go
run_paths_case mesh_policy_rust_client pull_request refs/pull/1173/head false \
  'policy rust rust_pkg_codewire_client' \
  scripts/checks/contracts/mesh-final-surface-policy.json \
  crates/codewire-client/src/mesh.rs
run_paths_case mesh_policy_runtime pull_request refs/pull/1174/head false \
  'policy transport transport_pkg_codewire_mesh' \
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
  'policy web' apps/dashboard/playwright.config.ts
run_paths_case dashboard_design_preview pull_request refs/pull/120/head false \
  'policy web' scripts/dev/design-system-server.py
run_paths_case marketing_brand_assets pull_request refs/pull/1201/head false \
  'policy web' favicon.svg logo/wordmark.svg
run_paths_case dashboard_runtime_inventory pull_request refs/pull/121/head false \
  'deploy edge_kind go_consumer_interop go_support policy release runtime_confidential security web' \
  apps/dashboard/runtime-inventory.json
run_paths_case dashboard_rust_route pull_request refs/pull/122/head false \
  'deploy edge_kind policy rust rust_pkg_codewire_dashboard_web web' \
  crates/codewire-dashboard-web/src/docs.rs
run_paths_case dashboard_rust_surface pull_request refs/pull/1221/head false \
  'deploy edge_kind policy rust rust_pkg_codewire_dashboard_web web' \
  crates/codewire-dashboard-web/src/routes/environments.rs \
  crates/codewire-dashboard-web/templates/dashboard.html \
  crates/codewire-dashboard-web/assets/htmx-2.0.10.min.js
run_paths_case dashboard_image_verifier pull_request refs/pull/123/head false \
  'deploy edge_kind go_consumer_interop go_support policy release runtime_confidential security web' \
  scripts/ci/verify/dashboard-image.sh
run_paths_case dashboard_sandbox_image_inputs pull_request refs/pull/1231/head false \
  'edge_kind policy rust rust_pkg_codewire_orchestration service_integration service_orchestration' \
  crates/codewire-orchestration/src/sandbox/mod.rs \
  crates/codewire-orchestration/src/sandbox/template.rs \
  crates/codewire-orchestration/src/sandbox/template/network.rs
run_paths_case local_image_verifiers pull_request refs/pull/1231/head false \
  'policy' \
  scripts/ci/images/build-local-image.sh \
  scripts/ci/tests/test-build-local-image.sh \
  scripts/ci/tests/test-workspace-agent-contract.sh \
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
  'policy security security_go transport transport_derp_contract transport_pkg_codewire_derp' \
  tests/contract/go.mod tests/contract/go.sum
run_paths_case sdk_ts pull_request refs/pull/14/head false \
  'policy sdk_ts' libs/sdk-ts/src/index.ts
run_paths_case sdk_python pull_request refs/pull/15/head false \
  'policy sdk_python' libs/sdk-python/codewire/client.py
run_paths_case sdk_python_runner pull_request refs/pull/151/head false \
  'policy sdk_python' \
  scripts/runtime/dev/run-sdk-python-e2e.sh \
  scripts/runtime/tests/test-run-sdk-python-e2e.sh
run_paths_case sdk_ts_runner pull_request refs/pull/1511/head false \
  'policy sdk_ts' \
  scripts/runtime/dev/run-sdk-ts-e2e.sh \
  scripts/runtime/tests/test-run-sdk-ts-e2e.sh
run_paths_case sdk_examples pull_request refs/pull/1512/head false \
  'go_consumer_interop go_support policy sdk_go sdk_python sdk_ts' \
  libs/sdk-examples/run-claude/README.md \
  libs/sdk-examples/run-claude/go/main.go \
  libs/sdk-examples/run-claude/python/run_claude.py \
  libs/sdk-examples/run-claude/typescript/run_claude.ts
run_paths_case retired_cli_assets pull_request refs/pull/1513/head false \
  'policy' \
  apps/cli/.env.example \
  apps/cli/Caddyfile \
  apps/cli/Dockerfile \
  apps/cli/charts/codewire-mesh/templates/NOTES.txt \
  apps/cli/contrib/codex-turn-watch.sh \
  apps/cli/demo/Dockerfile \
  apps/cli/docker-compose.yml \
  apps/cli/docs/quickstart.md
run_paths_case cli_packaging pull_request refs/pull/1514/head false \
  'go_consumer_interop go_support policy release runtime_confidential' \
  apps/cli/aur/PKGBUILD \
  apps/cli/nfpm.yaml \
  apps/cli/scripts/update-homebrew-formula.sh
run_paths_case cli_deploy_assets pull_request refs/pull/1515/head false \
  'deploy policy' \
  apps/cli/charts/codewire-mesh/values.yaml \
  apps/cli/k8s/demo-site/deployment.yaml
run_paths_case runtime_dev_tooling pull_request refs/pull/1516/head false \
  'policy runtime_dev_smoke' \
  scripts/runtime/dev/measure-dev-commodity-overhead.sh \
  scripts/runtime/dev/smoke-dev-commodity.sh \
  scripts/runtime/kata/kata-genpolicy.sh
run_paths_case runtime_dev_auth pull_request refs/pull/1517/head false \
  'policy runtime_dev_smoke security security_dev_smoke_auth' \
  scripts/runtime/dev/provision-dev-smoke-user.sh \
  scripts/runtime/dev/with-dev-smoke-auth.sh \
  scripts/runtime/tests/test-with-dev-smoke-auth.sh
run_paths_case runtime_confidential pull_request refs/pull/1518/head false \
  'policy runtime_confidential' \
  scripts/runtime/confidential/resolve-coco-support-lock.sh \
  scripts/runtime/tests/test-resolve-coco-support-lock.sh
run_paths_case makefile_only pull_request refs/pull/152/head false \
  'policy' Makefile
run_paths_case buildx_two_file_replay pull_request refs/pull/1520/head false \
  'deploy edge_kind go_consumer_interop go_support policy release runtime_confidential security' \
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
run_paths_case edge_harness pull_request refs/pull/153/head false \
  'edge_kind policy' scripts/ci/verify/kind-e2e.sh
run_paths_case edge_host_runtime pull_request refs/pull/1529/head true \
  'edge_kind kind policy' scripts/ci/verify/kind-host-runtime.sh
run_paths_case edge_browser_runtime pull_request refs/pull/1530/head true \
  'edge_kind kind policy' scripts/ci/verify/playwright-browser-runtime.sh
run_paths_case pinned_browser_installer pull_request refs/pull/1531/head true \
  'edge_kind kind policy' scripts/ci/install-pinned-playwright-chromium.sh
run_paths_case mixed_sdk_and_runtime pull_request refs/pull/154/head false \
  'policy rust rust_pkg_codewire_server_core sdk_python service_apikey_smoke service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal' \
  libs/sdk-python/codewire/client.py crates/codewire-server-core/src/lib.rs
run_paths_case edge_without_kind pull_request refs/pull/16/head false \
  'edge_kind policy' Caddyfile
run_paths_case edge_with_kind pull_request refs/pull/17/head true \
  'edge_kind kind policy' Caddyfile
run_paths_case temporal_installer_without_kind pull_request refs/pull/171/head false \
  'edge_kind policy' scripts/dev/kind/install-temporal.sh scripts/ci/tests/test-install-temporal.sh
run_paths_case temporal_installer_with_kind pull_request refs/pull/172/head true \
  'edge_kind kind policy' scripts/dev/kind/install-temporal.sh scripts/ci/tests/test-install-temporal.sh
run_paths_case ws17_wi_c3 pull_request refs/pull/173/head false \
  'go_consumer_interop go_support policy release runtime_confidential runtime_dev_smoke rust rust_pkg_codewire_cli rust_pkg_codewire_cli_bin rust_pkg_codewire_desktop rust_pkg_codewire_orchestration sdk_go sdk_python sdk_ts service_integration service_orchestration service_temporal web' \
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
  docs/dev/MESH-PROD-OPS.md \
  docs/dev/SANDBOX-CAPACITY-OPS.md \
  docs/dev/TAILNET-PARITY-HARNESS.md \
  docs/runbooks/kata-dev-runtime-validation.md \
  docs/runbooks/runtime-coco-trustee-test-resource.md \
  docs/runbooks/runtime-dev-commodity-smoke.md \
  docs/runbooks/rust-release-candidate-staging.md \
  libs/sdk-examples/run-claude/README.md \
  libs/sdk-examples/run-claude/go/main.go \
  libs/sdk-examples/run-claude/python/run_claude.py \
  libs/sdk-examples/run-claude/typescript/run_claude.ts \
  libs/sdk-go/local.go \
  libs/sdk-go/local_files.go \
  libs/sdk-python/codewire/__init__.py \
  libs/sdk-python/codewire/local.py \
  libs/sdk-ts/src/index.ts \
  libs/sdk-ts/src/local.ts \
  scripts/ci/tests/test-sdk-local-cli-contract.sh \
  scripts/ci/verify/smoke-prod.sh \
  scripts/runtime/dev/measure-dev-commodity-overhead.sh \
  scripts/runtime/dev/smoke-dev-commodity.sh
run_paths_case tag push refs/tags/v1.2.3 false \
  'deploy go_consumer_interop go_support release runtime_confidential' docs/tag-path-is-ignored.md

all_product='contracts contracts_proto database deploy edge_kind go_consumer_interop go_support go_tailnet kind policy policy_shell release runtime_confidential runtime_dev_smoke rust rust_curated_locks rust_workspace sdk_go sdk_python sdk_ts security security_dev_smoke_auth security_go security_idp_kek security_js service_apikey_smoke service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal transport transport_derp_contract transport_pkg_codewire_coordinator transport_pkg_codewire_daemon transport_pkg_codewire_derp transport_pkg_codewire_gateway transport_pkg_codewire_local_vmm transport_pkg_codewire_mesh transport_pkg_codewire_netstack transport_pkg_codewire_tailnet transport_pkg_codewire_udp_relay transport_pkg_codewire_vmm_guest_probe web'
run_present_paths_case dashboard_watch pull_request refs/pull/2002/head false \
  "$policy" scripts/dev/dashboard-watch.py
run_present_paths_case dashboard_watch_unlisted pull_request refs/pull/2003/head false \
  "$all_product" scripts/dev/unlisted-dashboard-helper.py
if grep -Fq 'scripts/ci/cache/*.sh' "$SELECTOR"; then
  echo 'Rust cache policy must not admit future cache helpers by wildcard' >&2
  exit 1
fi
[ ! -e "$NEGATIVE_CACHE_PATH" ] \
  || { echo "negative cache fixture path already exists: $NEGATIVE_CACHE_PATH" >&2; exit 1; }
mkdir -p "${NEGATIVE_CACHE_PATH%/*}"
: > "$NEGATIVE_CACHE_PATH"
run_paths_case rust_cache_unlisted pull_request refs/pull/201/head false "$all_product" \
  scripts/ci/cache/unlisted-cache-helper.sh
rm -f "$NEGATIVE_CACHE_PATH"
rmdir "$ROOT/scripts/ci/cache" 2>/dev/null || true
run_paths_case unknown pull_request refs/pull/18/head false "$all_product" \
  unexplained/new-surface.txt
run_paths_case mesh_policy_unknown pull_request refs/pull/181/head false "$all_product" \
  scripts/checks/contracts/mesh-final-surface-policy.json \
  unexplained/new-surface.txt
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
assert_contract_field edge "$contract_output" required_local_mode kind
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
assert_contract_field kind_fixture_mixed "$contract_output" required_local_mode kind
printf '%s\n' unexplained/new-surface.txt > "$contract_paths"
contract_output="$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
  GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/192/head \
  KIND_E2E_OPT_IN=false "$SELECTOR" "$contract_paths" 2>/dev/null)"
assert_contract_field unknown "$contract_output" classification unclassified
assert_contract_field unknown "$contract_output" required_local_mode full

dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=rust-stack "$SELECTOR")"
assert_tokens dispatch_rust_stack diagnostic_rust_stack "$dispatch_output"

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
  'transport transport_derp_contract transport_pkg_codewire_coordinator transport_pkg_codewire_daemon transport_pkg_codewire_derp transport_pkg_codewire_gateway transport_pkg_codewire_local_vmm transport_pkg_codewire_mesh transport_pkg_codewire_netstack transport_pkg_codewire_tailnet transport_pkg_codewire_udp_relay transport_pkg_codewire_vmm_guest_probe' \
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
  VERIFICATION_REQUEST=policy "$SELECTOR")"
assert_tokens dispatch_policy 'policy policy_shell' "$dispatch_output"
grep -Fq '|policy_shell_omittable|' <<<"$dispatch_output"
dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=all "$SELECTOR")"
assert_tokens dispatch_all "${all_product} ios" "$dispatch_output"
dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=release "$SELECTOR")"
assert_tokens dispatch_release \
  'go_consumer_interop go_support release runtime_confidential' "$dispatch_output"

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
grep -qF 'buf breaking' "$contracts_proto_runner"
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
grep -qF 'GOWORK=off go vet ./...' "$go_support_runner"
grep -qF 'GOWORK=off go test -short ./...' "$go_support_runner"
grep -qF 'cargo test --locked -p codewire-server-core' "$go_support_runner"
grep -qF -- '--test go_consumer_interop generated_go_client_consumes_rust_connect' \
  "$go_support_runner"
grep -qF -- '--exact --ignored --nocapture' "$go_support_runner"
for retired_path in \
    apps/api \
    autoagent \
    libs/gen-go/coordinator \
    libs/gatewayauth \
    libs/gateway-proto/gen \
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

integration_runner="$ROOT/scripts/ci/verify/run-integration-verification.sh"
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
  grep -qF -- '--test wire_contract configured_billing_wire_contract' "$billing_runner"
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
grep -qF "if grep -Eq -- '--- SKIP'" "$derp_runner"
grep -qF "|| ! grep -Eq -- '^[[:space:]]*--- PASS:'" "$derp_runner"
grep -qF 'if selected transport_pkg_codewire_vmm_guest_probe; then' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
grep -qF 'if selected transport_pkg_codewire_local_vmm; then' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
grep -qF 'cargo check --locked -p codewire-local-vmm -p codewire-vmm-guest-probe \' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
grep -qF -- '--target aarch64-apple-darwin' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
grep -qF 'scripts/ci/verify/build-local-vmm-initramfs.sh --verify' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"

dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=service_integration "$SELECTOR")"
assert_tokens dispatch_services \
  'service_apikey_smoke service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal' \
  "$dispatch_output"

output_file="$TMP/github-output"
paths_file="$TMP/github-output.paths"
printf '%s\n' proto/codewire/v1/common.proto > "$paths_file"
GITHUB_OUTPUT="$output_file" GITHUB_EVENT_NAME=pull_request \
  "$SELECTOR" "$paths_file" >/dev/null
assert_tokens github_output \
  'contracts contracts_proto edge_kind go_consumer_interop go_support policy' \
  "$(cat "$output_file")"

# Exercise changed-range discovery, including fail-closed missing PR state.
repo="$TMP/ranges"
git init -q -b main "$repo"
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
  grep -qF "    runs-on: ${runner}" "$block"
  grep -qF \
    "    if: \${{ needs.verification-selection.outputs.${expectation_name}_expected == 'true' }}" \
    "$block"
  if grep -qF '    strategy:' "$block"; then
    echo "${job_id}: capability dispatch retained an empty-matrix dependency" >&2
    exit 1
  fi
done <<'EOF'
cw-release-assets|CW release-assets verification|ci-heavy|cw_release_assets
workspace-image|Container contract verification|ci-heavy|workspace_image
policy|Policy verification|ci-lite|policy
standard|Standard verification|ci-heavy|standard
tooling|Tooling / delivery contract verification|ci-heavy|tooling
rust-transport|Rust / transport verification|ci-heavy|rust_transport
database|Database verification|ci-heavy|database
services-control|Service control-plane verification|ci-heavy|services_control
services-runtime|Service runtime-plane verification|ci-heavy|services_runtime
edge-kind|Edge / Kind verification|ci-heavy|edge_kind
EOF

policy_block="$TMP/policy.yaml"
tooling_block="$TMP/tooling.yaml"
grep -Fq 'run-product-verification.sh policy-core' "$policy_block" || {
  echo 'ci-lite policy job does not own only the fast policy core' >&2
  exit 1
}
grep -Fq 'run-product-verification.sh policy-shell' "$tooling_block" || {
  echo 'ci-heavy tooling job does not own selected ShellCheck' >&2
  exit 1
}
grep -Fq "contains(needs.verification-selection.outputs.selection, '|policy_shell|')" \
  "$tooling_block" || {
  echo 'ci-heavy ShellCheck lacks trusted policy_shell dispatch' >&2
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
for expectation_name in policy standard tooling rust_transport database \
    services_control services_runtime edge_kind cw_release_assets workspace_image; do
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
# desktop compiler cache. Those two jobs have bounded 55-minute exceptions
# beneath the runner's independently managed 60-minute task lifetime.
for job_id in cw-release-assets standard tooling database services-control services-runtime; do
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
  echo 'rust-transport: cold-cache ceiling must remain below the 60-minute runner lifetime' >&2
  exit 1
}

edge_kind_block="$TMP/edge-kind.yaml"
grep -qF '    timeout-minutes: 55' "$edge_kind_block" || {
  echo 'edge-kind: diagnostic ceiling must remain below the 60-minute runner lifetime' >&2
  exit 1
}

workspace_block="$TMP/workspace-image.yaml"
awk '
  $0 == "  workspace-image:" { capture = 1 }
  capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ && $0 != "  workspace-image:" { exit }
  capture { print }
' "$WORKFLOW" > "$workspace_block"
grep -qF '    timeout-minutes: 55' "$workspace_block" || {
  echo 'workspace-image: cold-build ceiling must remain below the 60-minute runner lifetime' >&2
  exit 1
}

policy_block="$TMP/policy.yaml"
grep -qF '    timeout-minutes: 13' "$policy_block"
grep -qF 'name: Verify sealed policy tools' "$policy_block"
grep -qF 'name: Run Policy' "$policy_block"
grep -A1 -F 'name: Run Policy' "$policy_block" \
  | grep -qF "contains(needs.verification-selection.outputs.selection, '|policy|')"
if grep -Eq 'run:.*docker|setup-bun|setup-go|curl |wget ' "$policy_block"; then
  echo 'policy: sealed policy job gained a Docker or network-tool setup dependency' >&2
  exit 1
fi

grep -qF '    timeout-minutes: 13' "$TMP/policy.yaml" || {
  echo 'policy: heavy job lost its measured bounded task ceiling' >&2
  exit 1
}

for job_id in policy standard tooling rust-transport database services-control services-runtime edge-kind; do
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
run_service_scope_case apikey_tooling_rejects_control "$control_scope_script" \
  '|valid:v3|service_apikey_smoke|complete|' false
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
grep -qF '    runs-on: ci-lite' "$selection_block" || {
  echo 'verification selection does not use the live non-privileged validation profile' >&2
  exit 1
}
if grep -Eq '^    runs-on: (ubuntu-latest|untrusted-validation|ci-kind|kind-e2e|trusted-plan|protected-delivery|protected-dev-observer)$' "$WORKFLOW"; then
  echo 'Codewire CI still depends on a legacy compatibility label' >&2
  exit 1
fi
[[ "$(grep -Fc '    runs-on: ci-heavy' "$WORKFLOW")" -eq 9 ]] || {
  echo 'Codewire CI heavy capability groups are not explicit' >&2
  exit 1
}
[[ "$(grep -Fc '    runs-on: ci-lite' "$WORKFLOW")" -eq 3 ]] || {
  echo 'Codewire CI has not assigned selection, policy, and aggregation to ci-lite' >&2
  exit 1
}
[[ "$(grep -Fc '    runs-on: ci-light' "$WORKFLOW")" -eq 0 ]] || {
  echo 'Codewire CI still uses the retired ci-light label' >&2
  exit 1
}
for output in selector_version classification selection required_local_mode \
    ci_head_commit ci_head_tree \
    cw_package_state cw_package_selected desktop_package_state \
    desktop_package_selected workspace_image_state workspace_image_selected \
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
if [ "$top_level_jobs" != 12 ]; then
  echo "product CI defines ${top_level_jobs} jobs; expected selector, two artifact jobs, eight groups, and aggregate" >&2
  exit 1
fi
for legacy_job in contracts rust go-support web sdk-go sdk-ts sdk-python \
    service-integration transport release deploy security; do
  if grep -qF "  ${legacy_job}:" "$WORKFLOW"; then
    echo "legacy per-family runner job remains: ${legacy_job}" >&2
    exit 1
  fi
done

cw_block="$TMP/cw-release-assets.yaml"
awk '
  $0 == "  cw-release-assets:" { capture = 1 }
  capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ && $0 != "  cw-release-assets:" { exit }
  capture { print }
' "$WORKFLOW" > "$cw_block"
grep -qF '  cw-release-assets:' "$cw_block"
grep -qF '    name: CW release-assets verification' "$cw_block"
grep -qF '    runs-on: ci-heavy' "$cw_block"
grep -qF 'name: CW release assets not selected' "$cw_block"
grep -qF "needs.verification-selection.outputs.cw_package_selected != 'true'" \
  "$cw_block"
grep -qF "needs.verification-selection.outputs.cw_package_selected == 'true'" \
  "$cw_block"
grep -qF "CW_RELEASE_TARGETS='x86_64-unknown-linux-musl aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin'" \
  "$cw_block"
grep -qF 'scripts/ci/release/package-cw-release.sh v0.0.0-ci' "$cw_block"
jq -e '
  .artifacts.cw_cli_release_assets.release_targets == [
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin"
  ]
' "$ROOT/scripts/ci/plan/artifact-graph.json" >/dev/null
if grep -Eiq 'publish|contents: write|secrets\.' "$cw_block"; then
  echo 'PR CW release-assets verification crosses a publication boundary' >&2
  exit 1
fi
cw_selected_steps="$(grep -Ec '^      - (name:|uses:)' "$cw_block")"
cw_guarded_steps="$(grep -Ec '^        if:' "$cw_block")"
if [ "$cw_selected_steps" != "$cw_guarded_steps" ]; then
  echo 'every CW verification step must be guarded by receipt/package selection' >&2
  exit 1
fi

workspace_block="$TMP/workspace-image.yaml"
awk '
  $0 == "  workspace-image:" { capture = 1 }
  capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ && $0 != "  workspace-image:" { exit }
  capture { print }
' "$WORKFLOW" > "$workspace_block"
grep -qF '  workspace-image:' "$workspace_block"
grep -qF '    name: Container contract verification' "$workspace_block"
grep -qF '    runs-on: ci-heavy' "$workspace_block"
grep -qF '    needs: [verification-selection]' "$workspace_block"
grep -qF 'name: Container contracts not selected' "$workspace_block"
grep -qF 'no checkout, download, installation, or build required' "$workspace_block"
grep -qF 'name: Resolve container contract scope' "$workspace_block"
grep -qF 'WORKSPACE_IMAGE_SELECTED: ${{ needs.verification-selection.outputs.workspace_image_selected }}' \
  "$workspace_block"
grep -qF "steps.container-scope.outputs.selected != 'true'" "$workspace_block"
grep -qF "steps.container-scope.outputs.selected == 'true'" "$workspace_block"
grep -qF "needs.verification-selection.outputs.workspace_image_selected == 'true'" \
  "$workspace_block"
for command in \
    scripts/ci/tests/test-build-local-image.sh \
    scripts/ci/tests/test-workspace-agent-contract.sh \
    scripts/ci/verify/rehearse-build-local-image.sh \
    scripts/ci/verify/verify-workspace-image.sh; do
  grep -qF "$command" "$workspace_block" || {
    echo "workspace image verification omits ${command}" >&2
    exit 1
  }
done
workspace_steps="$(grep -Ec '^      - (name:|uses:)' "$workspace_block")"
workspace_guards="$(grep -Ec '^        if:' "$workspace_block")"
if [ "$workspace_steps" != "$workspace_guards" ]; then
  echo 'every workspace verification step must be guarded by receipt/artifact selection' >&2
  exit 1
fi
if grep -Eiq 'docker push|--push|contents: write|secrets\.' "$workspace_block"; then
  echo 'PR workspace image verification crosses a publication boundary' >&2
  exit 1
fi

standard_block="$TMP/standard.yaml"
bun_setup_condition="$(grep -A1 -F \
  'uses: https://git.example.invalid/noel/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6' \
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
  echo 'standard: Web cannot defer image work to the container transaction' >&2
  exit 1
}
grep -qF '    run_dashboard_image' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh" || {
  echo 'local Web verification lost its standalone image gate' >&2
  exit 1
}
grep -qF 'name: Build and inspect the standalone dashboard image' \
  "$workspace_block" || {
  echo 'container contracts: standalone Web changes omit dashboard image verification' >&2
  exit 1
}
dashboard_step="$(grep -A2 -F 'name: Build and inspect the standalone dashboard image' \
  "$workspace_block")"
for token in web kind; do
  grep -qF "contains(needs.verification-selection.outputs.selection, '|${token}|')" \
    <<<"$dashboard_step" || {
    echo "container contracts: dashboard selection guard omits ${token}" >&2
    exit 1
  }
done
grep -qF 'run-product-verification.sh dashboard-image' <<<"$dashboard_step"
grep -A4 -F 'name: Run Web' "$WORKFLOW" \
  | grep -qF 'CODEWIRE_DASHBOARD_IMAGE_DEFERRED: "true"'

for contract in \
    'Run Contracts|contracts' \
    'Run Go support|go_support' \
    'Run Web|web' \
    'Run SDK Go|sdk_go' \
    'Run SDK TypeScript|sdk_ts' \
    'Run SDK Python|sdk_python'; do
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
for contract in \
    'Run API key smoke tooling|service_apikey_smoke' \
    'Run Confidential runtime tooling|runtime_confidential' \
    'Run Dev smoke tooling|runtime_dev_smoke' \
    'Run Release provenance|release' \
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
  "$workspace_block" | cut -d: -f1)"
ios_run_block="$(sed -n "${ios_run_line},$((ios_run_line + 10))p" "$workspace_block")"
grep -qF "contains(needs.verification-selection.outputs.selection, '|ios|')" \
  <<<"$ios_run_block" || {
  echo 'container contracts: iOS verification is not isolated to the iOS selection' >&2
  exit 1
}
grep -qF 'scripts/ci/verify/run-product-verification.sh ios-config' \
  <<<"$ios_run_block" || {
  echo 'container contracts: iOS callback configuration is not verified before package tests' >&2
  exit 1
}
grep -qF "docker build --file - apps/ios <<'DOCKERFILE'" <<<"$ios_run_block" || {
  echo 'container contracts: iOS package tests do not stream their package context to Docker' >&2
  exit 1
}
grep -qF 'swift@sha256:0ff707a48519cf1473616c759e019bcff21cfbafa3d2687bf8fd41a2757adc9a' \
  <<<"$ios_run_block" || {
  echo 'container contracts: iOS package tests do not use the pinned Swift image' >&2
  exit 1
}
grep -qF 'RUN swift test --scratch-path /tmp/codewire-ios-build' <<<"$ios_run_block" || {
  echo 'container contracts: iOS package tests must build outside the checkout' >&2
  exit 1
}
if grep -qF -- '--mount "type=bind' <<<"$ios_run_block"; then
  echo 'container contracts: iOS package tests must not assume the nested runner host path' >&2
  exit 1
fi
if grep -qF 'swift-actions/setup-swift@' "$workspace_block"; then
  echo 'container contracts: iOS verification must not depend on an external Swift keyserver' >&2
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
for contract in 'Run Rust|rust' 'Run Rust transport|transport'; do
  step_name="${contract%%|*}"
  token="${contract##*|}"
  step_condition="$(grep -A1 -F -- "- name: ${step_name}" "$rust_transport_block")"
  grep -qF "contains(needs.verification-selection.outputs.selection, '|${token}|')" \
    <<<"$step_condition" || {
    echo "rust-transport: ${step_name} is not isolated to ${token}" >&2
    exit 1
  }
done
rust_transport_protoc_line="$(grep -n -m1 \
  'name: Install pinned protoc for guest initramfs reproduction' \
  "$rust_transport_block" | cut -d: -f1)"
rust_transport_run_line="$(grep -n -m1 'name: Run Rust transport' \
  "$rust_transport_block" | cut -d: -f1)"
if [ -z "$rust_transport_protoc_line" ] \
    || [ "$rust_transport_protoc_line" -ge "$rust_transport_run_line" ]; then
  echo 'rust-transport: pinned protoc must be installed before transport verification' >&2
  exit 1
fi
rust_transport_protoc_condition="$(grep -A1 -F \
  'name: Install pinned protoc for guest initramfs reproduction' \
  "$rust_transport_block")"
grep -qF \
  "contains(needs.verification-selection.outputs.selection, '|transport_pkg_codewire_vmm_guest_probe|')" \
  <<<"$rust_transport_protoc_condition" || {
  echo 'rust-transport: pinned protoc is not isolated to guest-probe reproduction' >&2
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
grep -qF 'service_apikey_smoke service_idp service_coordinator service_billing' \
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
grep -qF 'run: scripts/ci/verify/run-product-verification.sh edge' "$edge_kind_block"
grep -qF 'run: scripts/ci/verify/kind-e2e.sh' "$edge_kind_block"

if grep -qF '    name: Manual diagnostics' "$WORKFLOW" \
  || grep -qF '  diagnostics:' "$WORKFLOW" \
  || grep -qF 'DIAGNOSTICS_RESULT' "$WORKFLOW" \
  || grep -qF '      - diagnostics' "$WORKFLOW"; then
  echo 'product CI must not contain or depend on manual diagnostics' >&2
  exit 1
fi
grep -qF 'manual diagnostics moved to the Manual diagnostics workflow' "$WORKFLOW"

grep -qF 'name: Manual diagnostics' "$DIAGNOSTICS_WORKFLOW"
grep -qF '  workflow_dispatch:' "$DIAGNOSTICS_WORKFLOW"
grep -qF '        description: rust-stack or go-tailnet' "$DIAGNOSTICS_WORKFLOW"
grep -qF 'manual diagnostics require diagnostic=rust-stack or go-tailnet' \
  "$DIAGNOSTICS_WORKFLOW"
grep -qF "github.event.inputs.diagnostic == 'rust-stack'" "$DIAGNOSTICS_WORKFLOW"
grep -qF "github.event.inputs.diagnostic == 'go-tailnet'" "$DIAGNOSTICS_WORKFLOW"
if grep -qF 'select-verification.sh' "$DIAGNOSTICS_WORKFLOW"; then
  echo 'manual diagnostics must validate its bounded input directly' >&2
  exit 1
fi
grep -qF 'scripts/ci/verify/tailnet-parity.sh' "$DIAGNOSTICS_WORKFLOW"
grep -qF 'scripts/ci/verify/rust-stack-rehearsal.sh' "$DIAGNOSTICS_WORKFLOW"
if rg -n 'cr-golden|diagnostic_cr_golden|go_cr_golden|TestGolden.*-update' \
    "$WORKFLOW" "$DIAGNOSTICS_WORKFLOW" "$SELECTOR" \
    "$ROOT/scripts/ci/verify/run-product-verification.sh"; then
  echo 'retired Go CR-golden diagnostic remains wired' >&2
  exit 1
fi
grep -qF 'name: Verify sealed Rust toolchain' \
  "$DIAGNOSTICS_WORKFLOW"

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
grep -qF '    runs-on: ci-lite' "$required_block" || {
  echo 'required coordination consumes the heavy compatibility pool' >&2
  exit 1
}
# shellcheck disable=SC2016 # Match the literal Actions expression.
grep -qF '    if: ${{ always() }}' "$WORKFLOW"
grep -qF 'scripts/ci/select/require-verification-results.sh' "$required_block"
for group in cw-release-assets workspace-image standard rust-transport database services-control services-runtime edge-kind; do
  grep -qF "      - ${group}" "$required_block" || {
    echo "required CI does not wait on ${group}" >&2
    exit 1
  }
done
for result in VERIFICATION_CW_RELEASE_ASSETS_RESULT VERIFICATION_STANDARD_RESULT \
    VERIFICATION_RUST_TRANSPORT_RESULT VERIFICATION_DATABASE_RESULT \
    VERIFICATION_SERVICES_CONTROL_RESULT VERIFICATION_SERVICES_RUNTIME_RESULT \
    VERIFICATION_EDGE_KIND_RESULT VERIFICATION_WORKSPACE_IMAGE_RESULT; do
  grep -qF "${result}:" "$required_block" || {
    echo "required CI omits ${result}" >&2
    exit 1
  }
done
for expected in VERIFICATION_POLICY_EXPECTED VERIFICATION_STANDARD_EXPECTED \
    VERIFICATION_TOOLING_EXPECTED VERIFICATION_RUST_TRANSPORT_EXPECTED \
    VERIFICATION_DATABASE_EXPECTED VERIFICATION_SERVICES_CONTROL_EXPECTED \
    VERIFICATION_SERVICES_RUNTIME_EXPECTED VERIFICATION_EDGE_KIND_EXPECTED \
    VERIFICATION_CW_RELEASE_ASSETS_EXPECTED VERIFICATION_WORKSPACE_IMAGE_EXPECTED; do
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
grep -qF 'scripts/checks/source/check-native-desktop-ui.py' \
  "$ROOT/scripts/dev/preflight.sh"
grep -qF 'scripts/checks/source/check-native-desktop-ui.py' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
desktop_package_args="$TMP/desktop-package-args.sh"
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
grep -qF "find scripts/runtime -type f -name '*.sh' -print0" \
  "$ROOT/scripts/dev/preflight.sh"
grep -qF "find scripts/runtime -type f -name '*.sh' -print0" \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
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
grep -qF 'scripts/runtime/tests/test-smoke-dev-commodity.sh' \
  "$ROOT/scripts/ci/verify/run-product-verification.sh"
grep -qF 'run_selected_family runtime_dev_smoke runtime-dev-smoke' \
  "$ROOT/scripts/dev/preflight.sh"
grep -qF "contains(needs.verification-selection.outputs.selection, '|runtime_dev_smoke|')" \
  "$WORKFLOW"
grep -qF 'run: scripts/ci/verify/run-product-verification.sh runtime-dev-smoke' \
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
  "$ROOT/scripts/ci/tests/test-local-prepush-receipt.sh" \
  "$ROOT/scripts/ci/verify/run-product-verification.sh" \
  "$ROOT/scripts/ci/tests/test-sdk-local-cli-contract.sh" \
  "$ROOT/scripts/ci/verify/integration-postgres.sh" \
  "$ROOT/scripts/ci/verify/run-integration-verification.sh" \
  "$ROOT/scripts/ci/tests/test-integration-postgres.sh" \
  "$ROOT/scripts/ci/tests/test-rust-owned-fixtures.sh" \
  "$ROOT/scripts/ci/verify/rust-stack-rehearsal.sh" \
  "$ROOT/scripts/dev/preflight.sh" \
  "$ROOT/.githooks/pre-push"

"$ROOT/scripts/ci/tests/test-local-prepush-receipt.sh"
"$ROOT/scripts/ci/tests/test-pre-push-worktree.sh"
"$ROOT/scripts/ci/tests/test-emit-verification-matrices.sh"

echo 'select-verification fixtures: OK'
