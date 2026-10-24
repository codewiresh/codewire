#!/usr/bin/env bash
set -euo pipefail

# Rust has two audience boundaries: customer/control-plane contracts and
# global-administrator contracts. Keep their checked-in descriptor inputs
# separate so a customer binary cannot accidentally compile the billing-admin
# surface merely by depending on `codewire-proto`.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly BUF_BIN="${BUF:-buf}"

cd "$ROOT/proto"

"$BUF_BIN" build --as-file-descriptor-set \
  --path codewire/admin/v1/admin.proto \
  --path codewire/admin/v1/billing_catalog.proto \
  -o ../crates/codewire-admin-proto/codewire_admin_descriptor.bin

"$BUF_BIN" build --as-file-descriptor-set \
  --path codewire/bridge/v1/bridge.proto \
  --path codewire/console/v1/account.proto \
  --path codewire/console/v1/billing.proto \
  --path codewire/console/v1/environment_setup.proto \
  --path codewire/internal/v1/coordinate.proto \
  --path codewire/internal/v1/derp_admission.proto \
  --path codewire/internal/v1/mesh_authorization.proto \
  --path codewire/internal/v1/workspace_binding.proto \
  --path codewire/v1/access_profile.proto \
  --path codewire/v1/api_key.proto \
  --path codewire/v1/common.proto \
  --path codewire/v1/credential.proto \
  --path codewire/v1/credential_delegation.proto \
  --path codewire/v1/environment.proto \
  --path codewire/v1/environment_agent.proto \
  --path codewire/v1/environment_cw_runtime.proto \
  --path codewire/v1/environment_session.proto \
  --path codewire/v1/exec.proto \
  --path codewire/v1/file.proto \
  --path codewire/v1/mesh_group.proto \
  --path codewire/v1/mesh_invite.proto \
  --path codewire/v1/mesh_kv.proto \
  --path codewire/v1/mesh_network.proto \
  --path codewire/v1/mesh_node.proto \
  --path codewire/v1/organization.proto \
  --path codewire/v1/port.proto \
  --path codewire/v1/preset.proto \
  --path codewire/v1/secret.proto \
  --path codewire/testing/v1/ping.proto \
  --path google/rpc/error_details.proto \
  -o ../crates/codewire-proto/codewire_descriptor.bin
