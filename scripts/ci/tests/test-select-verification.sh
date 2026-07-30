#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SELECTOR="$ROOT/scripts/ci/select/select-verification.sh"
WORKFLOW="$ROOT/.gitea/workflows/ci.yaml"
DIAGNOSTICS_WORKFLOW="$ROOT/.gitea/workflows/manual-diagnostics.yaml"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

selection_value() {
  sed -n 's/^selection=//p' <<<"$1"
}

selection_tokens() {
  local selection="$1"
  selection="${selection#|valid:v2|}"
  selection="${selection%complete|}"
  tr '|' '\n' <<<"$selection" | sed '/^$/d' | LC_ALL=C sort
}

expected_tokens() {
  tr ' ' '\n' <<<"$1" | sed '/^$/d' | LC_ALL=C sort
}

assert_tokens() {
  local name="$1" expected="$2" output="$3" actual want selection
  selection="$(selection_value "$output")"
  if [[ "$selection" != '|valid:v2|'* ]] || [[ "$selection" != *'|complete|' ]]; then
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
  local paths="$TMP/${name}.paths" output
  printf '%s\n' "$@" > "$paths"
  output="$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
    GITHUB_EVENT_NAME="$event" GITHUB_REF="$ref" \
    KIND_E2E_OPT_IN="$opt_in" "$SELECTOR" "$paths")"
  assert_tokens "$name" "$expected" "$output"
}

policy=policy
run_paths_case docs pull_request refs/pull/1/head false "$policy" \
  docs/guide.md README.md AGENTS.md crates/README.md
run_paths_case repository_ignores pull_request refs/pull/10/head false "$policy" \
  .gitignore .dockerignore
run_paths_case repository_attributes pull_request refs/pull/1010/head false "$policy" \
  .gitattributes
run_paths_case license_texts pull_request refs/pull/1011/head false "$policy" \
  LICENSE LICENSE-MIT LICENSE-APACHE LICENSE-BSD-3-CLAUSE \
  crates/codewire-cli/LICENSE packages/codewire-proto-ts/LICENSE-APACHE \
  proto/LICENSE-APACHE tests/contract/LICENSE
run_paths_case local_compose pull_request refs/pull/11/head false \
  'database policy' docker-compose.yml
run_paths_case ci_self pull_request refs/pull/2/head false \
  'policy rust_curated_locks' \
  .gitea/workflows/ci.yaml .gitea/workflows/manual-diagnostics.yaml \
  scripts/ci/select/select-verification.sh \
  scripts/ci/select/require-verification-results.sh \
  scripts/ci/select/verify-tested-tree-receipt.sh \
  scripts/ci/tests/test-require-verification-results.sh \
  scripts/ci/tests/test-verify-tested-tree-receipt.sh
run_paths_case ci_rewrite pull_request refs/pull/20/head false \
  'policy rust_curated_locks' \
  .githooks/pre-push scripts/dev/preflight.sh scripts/ci/select/select-deploy-dev.sh \
  scripts/ci/verify/integration-postgres.sh \
  scripts/ci/verify/resolve-cargo-target-dir.sh \
  scripts/ci/verify/run-product-verification.sh \
  scripts/ci/tests/test-sdk-local-cli-contract.sh \
  scripts/checks/security/audit-rust-only-runtime.sh \
  scripts/ci/verify/rust-stack-rehearsal.sh \
  scripts/ci/tests/test-integration-postgres.sh \
  scripts/ci/tests/test-go-source-ownership.sh \
  scripts/ci/tests/test-resolve-cargo-target-dir.sh \
  scripts/ci/tests/test-rust-owned-fixtures.sh \
  scripts/ci/tests/test-select-deploy-dev.sh \
  scripts/ci/tests/test-select-verification.sh
run_paths_case repo_checks pull_request refs/pull/21/head false \
  'contracts contracts_rest deploy edge_kind go_consumer_interop go_support policy release runtime_confidential security security_idp_kek' \
  scripts/checks/repo_checks.py
run_paths_case release pull_request refs/pull/3/head false \
  'go_consumer_interop go_support policy release runtime_confidential' \
  .gitea/workflows/claude-e2e.yaml \
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
  scripts/ci/setup/fetch-infisical-ci-secret.sh \
  scripts/ci/images/publish-image-to-ghcr.sh \
  scripts/ci/images/run-skopeo-container.sh \
  scripts/ci/release/package-cw-release.sh \
  scripts/ci/release/publish-cw-release.sh \
  scripts/ci/tests/test-cw-install-signature.sh \
  scripts/ci/tests/test-copy-image-to-ghcr.sh \
  scripts/ci/tests/test-publish-image-to-ghcr.sh \
  scripts/ci/tests/test-run-skopeo-container.sh \
  scripts/ci/tests/test-support-images-workflow.sh \
  scripts/ci/tests/test-build-push-image.sh \
  scripts/ci/tests/test-claude-e2e-workflow.sh \
  scripts/ci/tests/test-fetch-infisical-ci-secret.sh \
  scripts/ci/tests/test-mirror-git-tags.sh \
  scripts/ci/tests/test-publish-cw-release.sh \
  scripts/ci/tests/test-verify-cw-release-signing-key.sh \
  scripts/ci/tests/test-verify-release-tag-ref.sh \
  scripts/ci/release/verify-cw-release-signing-key.sh \
  scripts/ci/release/verify-release-tag-ref.sh \
  install.sh
run_paths_case dev_deploy_contract pull_request refs/pull/30/head false \
  'deploy go_consumer_interop go_support policy release runtime_confidential' scripts/ci/tests/test-deploy-dev.sh
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
run_paths_case detached_desktop_package pull_request refs/pull/404/head false \
  'policy rust rust_pkg_codewire_desktop' \
  .gitea/workflows/desktop-package.yaml \
  scripts/ci/release/package-codewire-desktop.sh \
  scripts/ci/tests/test-package-codewire-desktop.sh
run_paths_case rust_root pull_request refs/pull/5/head false \
  'policy rust rust_curated_locks rust_workspace' Cargo.lock
run_paths_case curated_gateway_member_manifest pull_request refs/pull/501/head false \
  'policy rust_curated_locks transport transport_pkg_codewire_daemon' \
  crates/codewire-daemon/Cargo.toml
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
run_paths_case application_migration pull_request refs/pull/6/head false \
  'database policy rust rust_pkg_codewire_server_core service_apikey_smoke service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal' \
  crates/codewire-server-core/migrations/0001_baseline.sql
run_paths_case retired_go_migration_deletion pull_request refs/pull/600/head false \
  'policy' apps/api/db/migrations/0001_baseline.sql
run_paths_case retired_go_harness_deletion pull_request refs/pull/6010/head false \
  'policy' autoagent/agent.py libs/gatewayauth/token.go \
  libs/gateway-proto/gen/daemon/v1/daemon.pb.go
run_paths_case gateway_proto_source pull_request refs/pull/6011/head false \
  'policy rust rust_pkg_codewire_gateway_proto transport transport_pkg_codewire_daemon transport_pkg_codewire_gateway' \
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
  crates/codewire-billing/tests/wire_contract.rs
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
run_paths_case generated_rest_go pull_request refs/pull/1111/head false \
  'contracts contracts_rest go_consumer_interop go_support policy sdk_go' libs/api-client-go/client.gen.go
run_paths_case generated_rest_python pull_request refs/pull/1112/head false \
  'contracts contracts_rest policy sdk_python' \
  libs/api-client-python/codewire_api_client/models/organization_deletion_response.py
run_paths_case generated_connect_ts pull_request refs/pull/112/head false \
  'contracts contracts_proto policy' \
  packages/codewire-proto-ts/src/gen/codewire/v1/api_key_pb.ts
run_paths_case generated_google_rpc_ts pull_request refs/pull/1124/head false \
  'contracts contracts_proto policy' \
  packages/codewire-proto-ts/src/gen/google/rpc/error_details_pb.ts
run_paths_case generated_rest_ts pull_request refs/pull/1121/head false \
  'contracts contracts_rest policy sdk_ts web' \
  libs/api-client-ts/src/schema.gen.ts \
  packages/codewire-types/generated/api.d.ts
run_paths_case generated_connect_python pull_request refs/pull/113/head false \
  'contracts contracts_proto policy' libs/gen-python/codewire/v1/api_key_pb2.py
run_paths_case rest_contract_sources pull_request refs/pull/1131/head false \
  'contracts contracts_rest policy rust rust_pkg_codewire_api_contract rust_pkg_codewire_api_types' \
  crates/codewire-api-contract/src/lib.rs crates/codewire-api-types/src/lib.rs
run_paths_case rest_generators pull_request refs/pull/1132/head false \
  'contracts contracts_rest deploy edge_kind go_consumer_interop go_support policy release runtime_confidential security security_idp_kek' \
  scripts/checks/repo_checks.py
run_paths_case openapi pull_request refs/pull/115/head false \
  'contracts contracts_rest go_consumer_interop go_support policy sdk_go sdk_python sdk_ts' openapi.json
run_paths_case mixed_contracts pull_request refs/pull/116/head false \
  'contracts contracts_proto contracts_rest edge_kind go_consumer_interop go_support policy sdk_go sdk_python sdk_ts' \
  proto/codewire/v1/api_key.proto openapi.json
run_paths_case rest_policy_guard pull_request refs/pull/117/head false \
  'policy' scripts/checks/contracts/rest-surface-baseline.json
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
run_paths_case package_contract_tooling pull_request refs/pull/118/head false \
  'contracts contracts_proto contracts_rest policy security security_js web' \
  package.json
run_paths_case generic_package pull_request refs/pull/119/head false \
  'policy web' packages/shared/src/index.ts
run_paths_case dashboard pull_request refs/pull/12/head false \
  'policy web' apps/dashboard/src/app.tsx
run_paths_case javascript_dependency_inputs pull_request refs/pull/120/head false \
  'policy sdk_ts security security_js web' \
  apps/dashboard/package.json \
  packages/auth/package.json \
  libs/sdk-ts/package-lock.json
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
run_paths_case sdk_tooling pull_request refs/pull/155/head false \
  'go_consumer_interop go_support policy sdk_go sdk_python sdk_ts' \
  libs/sdk-scripts/filter-openapi.py
run_paths_case sdk_tooling_wi12_paths pull_request refs/pull/156/head false \
  'go_consumer_interop go_support policy sdk_go sdk_python sdk_ts' \
  Makefile libs/sdk-scripts/filter-openapi.py \
  docs/plans/connect-rpc/13-rest-sunset-and-openapi-removal.md
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
  'policy' \
  scripts/runtime/dev/measure-dev-commodity-overhead.sh \
  scripts/runtime/dev/smoke-dev-commodity.sh \
  scripts/runtime/kata/kata-genpolicy.sh
run_paths_case runtime_dev_auth pull_request refs/pull/1517/head false \
  'policy security security_dev_smoke_auth' \
  scripts/runtime/dev/provision-dev-smoke-user.sh \
  scripts/runtime/dev/with-dev-smoke-auth.sh \
  scripts/runtime/tests/test-with-dev-smoke-auth.sh
run_paths_case runtime_confidential pull_request refs/pull/1518/head false \
  'policy runtime_confidential' \
  scripts/runtime/confidential/resolve-coco-support-lock.sh \
  scripts/runtime/tests/test-resolve-coco-support-lock.sh
run_paths_case makefile_only pull_request refs/pull/152/head false \
  'policy' Makefile
run_paths_case cli_makefile pull_request refs/pull/1521/head false \
  'policy rust rust_pkg_codewire_cli rust_pkg_codewire_cli_bin' \
  apps/cli/Makefile
run_paths_case edge_harness pull_request refs/pull/153/head false \
  'edge_kind policy' scripts/ci/verify/kind-e2e.sh
run_paths_case mixed_sdk_and_runtime pull_request refs/pull/154/head false \
  'policy rust rust_pkg_codewire_server_core sdk_python service_apikey_smoke service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal' \
  libs/sdk-python/codewire/client.py crates/codewire-server-core/src/lib.rs
run_paths_case mixed_sdk_tooling_and_runtime pull_request refs/pull/157/head false \
  'go_consumer_interop go_support policy rust rust_pkg_codewire_server_core sdk_go sdk_python sdk_ts service_apikey_smoke service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal' \
  libs/sdk-scripts/filter-openapi.py crates/codewire-server-core/src/lib.rs
run_paths_case edge_without_kind pull_request refs/pull/16/head false \
  'edge_kind policy' Caddyfile
run_paths_case edge_with_kind pull_request refs/pull/17/head true \
  'edge_kind kind policy' Caddyfile
run_paths_case temporal_installer_without_kind pull_request refs/pull/171/head false \
  'edge_kind policy' scripts/dev/kind/install-temporal.sh scripts/ci/tests/test-install-temporal.sh
run_paths_case temporal_installer_with_kind pull_request refs/pull/172/head true \
  'edge_kind kind policy' scripts/dev/kind/install-temporal.sh scripts/ci/tests/test-install-temporal.sh
run_paths_case ws17_wi_c3 pull_request refs/pull/173/head false \
  'go_consumer_interop go_support policy release runtime_confidential rust rust_pkg_codewire_cli rust_pkg_codewire_cli_bin rust_pkg_codewire_desktop rust_pkg_codewire_orchestration sdk_go sdk_python sdk_ts service_integration service_orchestration service_temporal web' \
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
  crates/codewire-cli/src/commands/local.rs \
  crates/codewire-cli/src/commands/mesh_commands.rs \
  crates/codewire-cli/src/commands/mod.rs \
  crates/codewire-cli/src/commands/platform_commands.rs \
  crates/codewire-cli/src/commands/sessions.rs \
  crates/codewire-cli/src/commands/tests/collaboration.rs \
  crates/codewire-cli/src/commands/tests/core.rs \
  crates/codewire-cli/src/commands/tests/environment.rs \
  crates/codewire-cli/src/commands/tests/local.rs \
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
  scripts/ci/verify/smoke-local-environment.sh \
  scripts/ci/verify/smoke-prod.sh \
  scripts/runtime/dev/measure-dev-commodity-overhead.sh \
  scripts/runtime/dev/smoke-dev-commodity.sh
run_paths_case tag push refs/tags/v1.2.3 false \
  'deploy go_consumer_interop go_support release runtime_confidential' docs/tag-path-is-ignored.md

all_product='contracts contracts_proto contracts_rest database deploy edge_kind go_consumer_interop go_support go_tailnet kind policy release runtime_confidential rust rust_curated_locks rust_workspace sdk_go sdk_python sdk_ts security security_dev_smoke_auth security_go security_idp_kek security_js service_apikey_smoke service_billing service_connectcore service_coordinator service_idp service_integration service_nats service_orchestration service_temporal transport transport_derp_contract transport_pkg_codewire_coordinator transport_pkg_codewire_daemon transport_pkg_codewire_derp transport_pkg_codewire_gateway transport_pkg_codewire_mesh transport_pkg_codewire_tailnet transport_pkg_codewire_udp_relay web'
run_paths_case unknown pull_request refs/pull/18/head false "$all_product" \
  unexplained/new-surface.txt
run_paths_case mesh_policy_unknown pull_request refs/pull/181/head false "$all_product" \
  scripts/checks/contracts/mesh-final-surface-policy.json \
  unexplained/new-surface.txt
run_paths_case empty pull_request refs/pull/19/head false "$all_product" ''

dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=rust-stack "$SELECTOR")"
assert_tokens dispatch_rust_stack diagnostic_rust_stack "$dispatch_output"
dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=rust "$SELECTOR")"
assert_tokens dispatch_rust \
  'rust rust_curated_locks rust_workspace' "$dispatch_output"
dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=transport "$SELECTOR")"
assert_tokens dispatch_transport \
  'transport transport_derp_contract transport_pkg_codewire_coordinator transport_pkg_codewire_daemon transport_pkg_codewire_derp transport_pkg_codewire_gateway transport_pkg_codewire_mesh transport_pkg_codewire_tailnet transport_pkg_codewire_udp_relay' \
  "$dispatch_output"
dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=contracts "$SELECTOR")"
assert_tokens dispatch_contracts \
  'contracts contracts_proto contracts_rest' "$dispatch_output"
dispatch_output="$(env -u GITHUB_OUTPUT GITHUB_EVENT_NAME=workflow_dispatch \
  VERIFICATION_REQUEST=go_support "$SELECTOR")"
assert_tokens dispatch_go_support \
  'go_consumer_interop go_support go_tailnet' "$dispatch_output"
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
contracts_rest_runner="$TMP/contracts-rest.sh"
contracts_dispatcher="$TMP/contracts-dispatcher.sh"
go_support_runner="$TMP/go-support.sh"
awk '
  /^run_contracts_proto\(\) \{/ { capture = 1 }
  capture && /^run_contracts_rest\(\) \{/ { exit }
  capture { print }
' "$ROOT/scripts/ci/verify/run-product-verification.sh" > "$contracts_proto_runner"
awk '
  /^run_contracts_rest\(\) \{/ { capture = 1 }
  capture && /^run_contracts\(\) \{/ { exit }
  capture { print }
' "$ROOT/scripts/ci/verify/run-product-verification.sh" > "$contracts_rest_runner"
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
grep -qF 'buf build --as-file-descriptor-set' "$contracts_proto_runner"
grep -qF 'crates/codewire-proto/codewire_descriptor.bin' "$contracts_proto_runner"
grep -qF 'libs/gen-go' "$contracts_proto_runner"
grep -qF 'git ls-files --others --exclude-standard' "$contracts_proto_runner"
grep -qF 'PYTHONPATH=libs/gen-python' "$contracts_proto_runner"
grep -qF 'py_compile.compile' "$contracts_proto_runner"
grep -qF '@codewire/proto-ts typecheck' "$contracts_proto_runner"
grep -qF '../libs/gen-go/codewire' "$contracts_proto_runner"
grep -qF '../libs/gen-python/codewire' "$contracts_proto_runner"
grep -qF '../packages/codewire-proto-ts/src/gen/codewire' "$contracts_proto_runner"
grep -qF 'proto-package-boundaries --self-test' "$contracts_proto_runner"
grep -qF 'cargo test --locked -p codewire-proto' "$contracts_proto_runner"
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

grep -qF 'libs/api-client-go' "$contracts_rest_runner"
grep -qF 'openapi:check-source' "$contracts_rest_runner"
grep -qF 'openapi:check-rust-source' "$contracts_rest_runner"
grep -qF 'types:generate:ts' "$contracts_rest_runner"
if rg -n 'buf (lint|breaking|generate)|libs/gen-(go|python)|proto-ts|tests/contract|rest:freeze|validation:check-source' \
    "$contracts_rest_runner"; then
  echo 'Transitional REST contract mode contains Proto/Connect or duplicate Policy work' >&2
  exit 1
fi

grep -qF 'selected contracts_proto && run_proto=true' "$contracts_dispatcher"
grep -qF 'selected contracts_rest && run_rest=true' "$contracts_dispatcher"
grep -qF 'Contracts selected without contracts_proto or contracts_rest' \
  "$contracts_dispatcher"
[[ "$(grep -c 'install_bun_dependencies' "$contracts_dispatcher")" -eq 1 ]] || {
  echo 'Contracts dispatcher must install shared Bun dependencies exactly once' >&2
  exit 1
}
if missing_mode_output="$(VERIFICATION_SELECTION='|valid:v2|contracts|complete|' \
    "$ROOT/scripts/ci/verify/run-product-verification.sh" contracts 2>&1)"; then
  echo 'Contracts runner accepted a selected family without a sub-mode' >&2
  exit 1
fi
grep -qF 'Contracts selected without contracts_proto or contracts_rest' \
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
  grep -qF -- '--test wire_contract configured_billing_wire_contract' \
    "$billing_runner"
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
  /^  database-services:$/ { group = 1 }
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
output="$(cd "$repo" && env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
  GITHUB_EVENT_NAME=pull_request GITHUB_BASE_REF= \
  VERIFICATION_REMOTE=origin KIND_E2E_OPT_IN=false "$SELECTOR")"
assert_tokens missing_pr_base "$all_product" "$output"

git -C "$repo" switch -q main
printf 'main update\n' >> "$repo/docs/range.md"
git -C "$repo" add docs/range.md
git -C "$repo" -c commit.gpgsign=false commit -q -m docs
head="$(git -C "$repo" rev-parse HEAD)"
output="$(cd "$repo" && env -u GITHUB_OUTPUT \
  GITHUB_EVENT_NAME=push GITHUB_REF=refs/heads/main \
  PUSH_BEFORE_SHA="$base" PUSH_AFTER_SHA="$head" "$SELECTOR")"
assert_tokens discovered_push policy "$output"
output="$(cd "$repo" && env -u GITHUB_OUTPUT \
  GITHUB_EVENT_NAME=push GITHUB_REF=refs/heads/main \
  PUSH_BEFORE_SHA=0000000000000000000000000000000000000000 \
  PUSH_AFTER_SHA="$head" "$SELECTOR")"
assert_tokens zero_push_base "$all_product" "$output"

# Workflow contract: four fixed capability groups. Gitea assigns static jobs
# before evaluating job-level conditions, so family-level fan-out is forbidden.
while IFS='|' read -r job_id job_name runner; do
  block="$TMP/${job_id}.yaml"
  awk -v wanted="$job_id" '
    $0 == "  " wanted ":" { capture = 1 }
    capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ && $0 != "  " wanted ":" { exit }
    capture { print }
  ' "$WORKFLOW" > "$block"
  grep -qF "  ${job_id}:" "$block"
  grep -qF "    name: ${job_name}" "$block"
  grep -qF "    runs-on: ${runner}" "$block"
  if grep -qF '      - name: Skip ' "$block" \
    || grep -qE '^    if:.*verification-selection' "$block"; then
    echo "${job_id}: capability group must be a fixed runner task" >&2
    exit 1
  fi
done <<'EOF'
standard|Standard verification|ubuntu-latest
rust-transport|Rust / transport verification|ubuntu-latest
database-services|Database / service verification|ubuntu-latest
edge-kind|Edge / Kind verification|kind-e2e
EOF

for job_id in standard rust-transport database-services edge-kind; do
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

selection_block="$TMP/verification-selection.yaml"
awk '
  $0 == "  verification-selection:" { capture = 1 }
  capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ && $0 != "  verification-selection:" { exit }
  capture { print }
' "$WORKFLOW" > "$selection_block"
for output in tested_tree_receipt tested_tree_reason tested_tree_pr \
    tested_tree_head tested_tree_run; do
  grep -qF "      ${output}:" "$selection_block" || {
    echo "verification selection omits ${output}" >&2
    exit 1
  }
done
grep -qF 'name: Verify exact tested-tree receipt' "$selection_block"
grep -qF 'GITEA_TOKEN: ${{ github.token }}' "$selection_block"
grep -qF 'run: scripts/ci/select/verify-tested-tree-receipt.sh' "$selection_block"

permissions_block="$(awk '
  $0 == "permissions:" { capture = 1 }
  capture && $0 != "permissions:" && $0 ~ /^[^[:space:]]/ { exit }
  capture { print }
' "$WORKFLOW")"
expected_permissions="$(printf '%s\n' \
  'permissions:' \
  '  contents: read' \
  '  actions: read')"
if [ "$permissions_block" != "$expected_permissions" ]; then
  echo 'product CI permissions must be exactly contents: read and actions: read' >&2
  exit 1
fi

top_level_jobs="$(awk '
  /^jobs:$/ { in_jobs = 1; next }
  in_jobs && /^  [A-Za-z0-9_-]+:$/ { count++ }
  END { print count + 0 }
' "$WORKFLOW")"
if [ "$top_level_jobs" != 6 ]; then
  echo "product CI defines ${top_level_jobs} jobs; expected selector, four groups, and aggregate" >&2
  exit 1
fi
for legacy_job in policy contracts rust go-support web sdk-go sdk-ts sdk-python \
    database service-integration transport release deploy security; do
  if grep -qF "  ${legacy_job}:" "$WORKFLOW"; then
    echo "legacy per-family runner job remains: ${legacy_job}" >&2
    exit 1
  fi
done

standard_block="$TMP/standard.yaml"
bun_setup_condition="$(grep -A1 -F \
  'uses: oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6' \
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

for contract in \
    'Run Policy|policy' \
    'Run Contracts|contracts' \
    'Run Go support|go_support' \
    'Run Web|web' \
    'Run SDK Go|sdk_go' \
    'Run SDK TypeScript|sdk_ts' \
    'Run SDK Python|sdk_python' \
    'Run API key smoke tooling|service_apikey_smoke' \
    'Run Confidential runtime tooling|runtime_confidential' \
    'Run Release provenance|release' \
    'Run Deploy|deploy' \
    'Run Security|security'; do
  step_name="${contract%%|*}"
  token="${contract##*|}"
  step_condition="$(grep -A1 -F -- "- name: ${step_name}" "$standard_block")"
  grep -qF "contains(needs.verification-selection.outputs.selection, '|${token}|')" \
    <<<"$step_condition" || {
    echo "standard: ${step_name} is not isolated to ${token}" >&2
    exit 1
  }
done

grep -qF '      - uses: dtolnay/rust-toolchain@b3b07ba8b418998c39fb20f53e8b695cdcc8de1b' \
  "$standard_block" || {
  echo 'standard: Rust-backed transitional checks have no pinned Rust toolchain' >&2
  exit 1
}
standard_toolchain_line="$(grep -n -m1 'uses: dtolnay/rust-toolchain@' \
  "$standard_block" | cut -d: -f1)"
contracts_run_line="$(grep -n -m1 'name: Run Contracts' \
  "$standard_block" | cut -d: -f1)"
if [ "$standard_toolchain_line" -ge "$contracts_run_line" ]; then
  echo 'standard: Rust toolchain must be installed before contract verification' >&2
  exit 1
fi
standard_toolchain_condition="$(grep -A1 -F \
  'uses: dtolnay/rust-toolchain@b3b07ba8b418998c39fb20f53e8b695cdcc8de1b' \
  "$standard_block")"
grep -qF "contains(needs.verification-selection.outputs.selection, '|contracts_rest|')" \
  <<<"$standard_toolchain_condition" || {
  echo 'standard: Rust toolchain omits transitional REST mode' >&2
  exit 1
}
go_support_run_line="$(grep -n -m1 'name: Run Go support' \
  "$standard_block" | cut -d: -f1)"
if [ "$standard_toolchain_line" -ge "$go_support_run_line" ]; then
  echo 'go-support: Rust toolchain must be installed before tailnet parity verification' >&2
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
for token in contracts_rest go_tailnet go_consumer_interop; do
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

database_services_block="$TMP/database-services.yaml"
grep -qF 'name: Start integration Postgres' "$database_services_block"
grep -qF 'name: Run Database' "$database_services_block"
grep -qF 'run: scripts/ci/verify/run-integration-verification.sh database' \
  "$database_services_block"
grep -qF 'name: Run Service integration' "$database_services_block"
grep -qF 'run: scripts/ci/verify/run-integration-verification.sh services' \
  "$database_services_block"
grep -qF 'name: Stop integration Postgres' "$database_services_block"

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
grep -qF 'scripts/ci/select/select-verification.sh' "$DIAGNOSTICS_WORKFLOW"
grep -qF 'manual diagnostics require diagnostic=rust-stack or go-tailnet' \
  "$DIAGNOSTICS_WORKFLOW"
grep -qF 'scripts/ci/verify/tailnet-parity.sh' "$DIAGNOSTICS_WORKFLOW"
grep -qF 'scripts/ci/verify/rust-stack-rehearsal.sh' "$DIAGNOSTICS_WORKFLOW"
if rg -n 'cr-golden|diagnostic_cr_golden|go_cr_golden|TestGolden.*-update' \
    "$WORKFLOW" "$DIAGNOSTICS_WORKFLOW" "$SELECTOR" \
    "$ROOT/scripts/ci/verify/run-product-verification.sh"; then
  echo 'retired Go CR-golden diagnostic remains wired' >&2
  exit 1
fi
grep -qF 'dtolnay/rust-toolchain@b3b07ba8b418998c39fb20f53e8b695cdcc8de1b' \
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
# shellcheck disable=SC2016 # Match the literal Actions expression.
grep -qF '    if: ${{ always() }}' "$WORKFLOW"
grep -qF 'scripts/ci/select/require-verification-results.sh' "$required_block"
for group in standard rust-transport database-services edge-kind; do
  grep -qF "      - ${group}" "$required_block" || {
    echo "required CI does not wait on ${group}" >&2
    exit 1
  }
done
for result in VERIFICATION_STANDARD_RESULT VERIFICATION_RUST_TRANSPORT_RESULT \
    VERIFICATION_DATABASE_SERVICES_RESULT VERIFICATION_EDGE_KIND_RESULT; do
  grep -qF "${result}:" "$required_block" || {
    echo "required CI omits ${result}" >&2
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
if grep -qF 'diagnostics' "$required_block" \
  || grep -qF 'DIAGNOSTICS_RESULT' "$required_block"; then
  echo 'required CI must not wait on manual diagnostics' >&2
  exit 1
fi
grep -qF 'scripts/ci/select/select-verification.sh' "$ROOT/scripts/dev/preflight.sh"
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
if grep -qF 'select-migration-gates' "$WORKFLOW"; then
  echo 'workflow still calls the retired selector' >&2
  exit 1
fi

bash -n \
  "$SELECTOR" \
  "$ROOT/scripts/ci/select/require-verification-results.sh" \
  "$ROOT/scripts/ci/select/verify-tested-tree-receipt.sh" \
  "$ROOT/scripts/ci/tests/test-require-verification-results.sh" \
  "$ROOT/scripts/ci/tests/test-verify-tested-tree-receipt.sh" \
  "$ROOT/scripts/ci/verify/run-product-verification.sh" \
  "$ROOT/scripts/ci/tests/test-sdk-local-cli-contract.sh" \
  "$ROOT/scripts/ci/verify/integration-postgres.sh" \
  "$ROOT/scripts/ci/verify/run-integration-verification.sh" \
  "$ROOT/scripts/ci/tests/test-integration-postgres.sh" \
  "$ROOT/scripts/ci/tests/test-rust-owned-fixtures.sh" \
  "$ROOT/scripts/ci/verify/rust-stack-rehearsal.sh" \
  "$ROOT/scripts/dev/preflight.sh" \
  "$ROOT/.githooks/pre-push"

"$ROOT/scripts/ci/tests/test-pre-push-worktree.sh"

echo 'select-verification fixtures: OK'
