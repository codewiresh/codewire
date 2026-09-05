#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
cd "$ROOT"

fail() {
  printf '[test-admin-proto-boundary] ERROR: %s\n' "$*" >&2
  exit 1
}

# Policy uses only checked-in source/descriptor inputs. Resolve the real CLI
# dependency graph only in the separately provisioned Rust capability.
if [[ "$#" -gt 0 ]]; then
  [[ "$#" -eq 1 && "$1" == --cli-dependencies ]] || {
    printf 'usage: %s [--cli-dependencies]\n' "$0" >&2
    exit 2
  }
  # Capture the complete command before matching: an if-pipeline both masks a
  # Cargo failure and permits grep -q to SIGPIPE a successful graph producer.
  if cli_tree="$(cargo tree --locked -p codewire-cli-bin --prefix none)"; then
    :
  else
    cargo_status=$?
    printf '[test-admin-proto-boundary] ERROR: CLI dependency graph failed (status=%s)\n' \
      "$cargo_status" >&2
    exit "$cargo_status"
  fi
  grep -q '^codewire-cli-bin ' <<<"$cli_tree" ||
    fail 'dependency graph omits the customer CLI root'
  if grep -q '^codewire-admin-proto ' <<<"$cli_tree"; then
    fail 'customer CLI transitively depends on administrator-only contracts'
  fi
  printf '[test-admin-proto-boundary] customer CLI dependency boundary passed\n'
  exit 0
fi

readonly CUSTOMER_BUILD='crates/codewire-proto/build.rs'
readonly ADMIN_BUILD='crates/codewire-admin-proto/build.rs'

if rg -q 'codewire/admin/v1/' "$CUSTOMER_BUILD"; then
  fail 'customer descriptor build includes a global-administrator proto'
fi

rg -qF 'codewire/admin/v1/admin.proto' "$ADMIN_BUILD" ||
  fail 'admin descriptor omits AdminService'
rg -qF 'codewire/admin/v1/billing_catalog.proto' "$ADMIN_BUILD" ||
  fail 'admin descriptor omits BillingCatalogService'
rg -qF 'codewire_admin_descriptor.bin' "$ADMIN_BUILD" ||
  fail 'admin crate lacks a distinct checked-in descriptor input'

if rg -a -qF 'codewire.admin.v1' crates/codewire-proto/codewire_descriptor.bin; then
  fail 'customer descriptor contains global-administrator contracts'
fi
rg -a -qF 'AdminService' \
  crates/codewire-admin-proto/codewire_admin_descriptor.bin ||
  fail 'administrator descriptor omits AdminService'
rg -a -qF 'BillingCatalogService' \
  crates/codewire-admin-proto/codewire_admin_descriptor.bin ||
  fail 'administrator descriptor omits BillingCatalogService'

printf '[test-admin-proto-boundary] static customer and administrator contract boundaries passed\n'
