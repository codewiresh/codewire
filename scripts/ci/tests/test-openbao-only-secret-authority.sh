#!/usr/bin/env bash
# Prevent the retired external secret provider from returning to an active
# Codewire surface. Applied migrations and dated design/evidence records remain
# historically accurate; they are not runtime or developer instructions.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

readonly SELF="scripts/ci/tests/test-openbao-only-secret-authority.sh"
readonly PATTERN='infisical'
readonly -a ALLOWED=(
  crates/codewire-server-core/migrations/0009_confidential_storage_keys.sql
  crates/codewire-server-core/migrations/0010_tenant_secret_envelopes.sql
  crates/codewire-server-core/migrations/0012_expand_openbao_secret_authority.sql
  crates/codewire-server-core/src/migrate.rs
)

is_allowed() {
  local candidate="$1" allowed
  case "$candidate" in
    apps/cli/docs/plans/*|docs/plans/*|\
    docs/runbooks/runtime-dev-commodity-evidence-*) return 0 ;;
  esac
  for allowed in "${ALLOWED[@]}"; do
    [[ "$candidate" == "$allowed" ]] && return 0
  done
  return 1
}

violations=0
while IFS= read -r -d '' path; do
  [[ -f "$path" && "$path" != "$SELF" ]] || continue
  is_allowed "$path" && continue
  if LC_ALL=C rg -n -i --with-filename -- "$PATTERN" "$path"; then
    violations=1
  fi
done < <(git ls-files -co --exclude-standard -z)

[[ "$violations" == 0 ]] || {
  printf 'active source still references the retired secret provider\n' >&2
  exit 1
}

# Bound the exceptions so an allowlisted file cannot become a new dependency.
[[ "$(LC_ALL=C rg -i -c -- "$PATTERN" \
  crates/codewire-server-core/migrations/0009_confidential_storage_keys.sql)" == 2 ]]
[[ "$(LC_ALL=C rg -i -c -- "$PATTERN" \
  crates/codewire-server-core/migrations/0010_tenant_secret_envelopes.sql)" == 5 ]]
[[ "$(LC_ALL=C rg -i -c -- "$PATTERN" \
  crates/codewire-server-core/migrations/0012_expand_openbao_secret_authority.sql)" == 4 ]]
[[ "$(LC_ALL=C rg -i -c -- "$PATTERN" \
  crates/codewire-server-core/src/migrate.rs)" == 8 ]]

# The consuming source is OpenBao-only, but the additive rollout deliberately
# retains the previous column and control state until live acceptance closes
# the rollback window. A later cleanup migration owns their removal.
grep -Fq 'ADD COLUMN openbao_path text;' \
  crates/codewire-server-core/migrations/0012_expand_openbao_secret_authority.sql
grep -Fq 'CREATE TRIGGER confidential_storage_openbao_path_compat' \
  crates/codewire-server-core/migrations/0012_expand_openbao_secret_authority.sql
grep -Fq "state IN ('infisical', 'local', 'importing', 'postgres-readonly', 'postgres')" \
  crates/codewire-server-core/migrations/0012_expand_openbao_secret_authority.sql
grep -Fq "column_name = 'infisical_path' AND data_type = 'text'" \
  crates/codewire-server-core/src/migrate.rs
if rg -n --fixed-strings -- 'DROP COLUMN infisical_path' \
  crates/codewire-server-core/migrations; then
  printf 'rollback-compatible column was removed before live acceptance\n' >&2
  exit 1
fi

printf 'OpenBao-only secret authority contract: OK\n'
