#!/usr/bin/env bash
set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

fail() {
  printf '[test-admin-proto-boundary] ERROR: %s\n' "$*" >&2
  exit 1
}

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

if cargo tree --locked -p codewire-cli-bin --prefix none | grep -q '^codewire-admin-proto '; then
  fail 'customer CLI transitively depends on administrator-only contracts'
fi

printf '[test-admin-proto-boundary] customer and administrator contract boundaries passed\n'
