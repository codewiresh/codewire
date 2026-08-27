#!/usr/bin/env bash
# Prove the destructive pre-GA OpenBao finalization is safe without reading a
# secret value. Invoke beneath Infra's scoped kube-access wrapper.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly NAMESPACE="${CODEWIRE_DEV_NAMESPACE:-dev}"
readonly POSTGRES_CLUSTER="${CODEWIRE_DEV_POSTGRES_CLUSTER:-codewire-db}"
readonly KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"

die() {
  printf 'openbao-native-secret-preflight: %s\n' "$*" >&2
  exit 1
}

command -v "$KUBECTL_BIN" >/dev/null 2>&1 || die "missing kubectl: $KUBECTL_BIN"
command -v jq >/dev/null 2>&1 || die 'missing jq'
[[ -n "${INFRA_KUBECONFIG_DIR:-}" ]] ||
  die 'invoke beneath Infra scripts/kube-access'

install -d -m 0700 "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/openbao-native-secret-preflight.XXXXXX")"
readonly work
receipt="$work/counts.json"
trap 'if command -v shred >/dev/null 2>&1; then shred -u "$receipt" 2>/dev/null || true; fi; rm -rf "$work"' EXIT

primary="$($KUBECTL_BIN -n "$NAMESPACE" get cluster.postgresql.cnpg.io \
  "$POSTGRES_CLUSTER" -o jsonpath='{.status.currentPrimary}')"
[[ "$primary" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] ||
  die 'CNPG currentPrimary is absent or malformed'

$KUBECTL_BIN -n "$NAMESPACE" exec -i "pod/$primary" -c postgres -- \
  psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d codewire >"$receipt" <<'SQL'
SELECT json_build_object(
    'local_secrets', (SELECT count(*) FROM public.local_secrets),
    'tenant_secrets', (SELECT count(*) FROM public.tenant_secrets),
    'tenant_secret_deks', (SELECT count(*) FROM public.tenant_secret_deks),
    'confidential_storage_keys', (SELECT count(*) FROM public.confidential_storage_keys),
    'tenant_secret_control', (SELECT count(*) FROM public.tenant_secret_control),
    'tenant_secret_kek_canary', (SELECT count(*) FROM public.tenant_secret_kek_canary)
);
SQL
chmod 0600 "$receipt"

if ! jq -e '
  type == "object"
  and keys == [
    "confidential_storage_keys",
    "local_secrets",
    "tenant_secret_control",
    "tenant_secret_deks",
    "tenant_secret_kek_canary",
    "tenant_secrets"
  ]
  and all(.[]; type == "number" and . >= 0 and floor == .)
' "$receipt" >/dev/null; then
  die 'count receipt is malformed'
fi

print_counts() {
  jq -jS '
    "counts=local:", .local_secrets,
    ",tenant:", .tenant_secrets,
    ",deks:", .tenant_secret_deks,
    ",confidential:", .confidential_storage_keys,
    ",control:", .tenant_secret_control,
    ",canary:", .tenant_secret_kek_canary,
    "\n"
  ' "$receipt"
}

if ! jq -e '
  .local_secrets == 0
  and .tenant_secrets == 0
  and .tenant_secret_deks == 0
  and .tenant_secret_control == 1
  and .tenant_secret_kek_canary <= 1
' "$receipt" >/dev/null; then
  printf 'openbao-native-secret-preflight: REJECT '
  print_counts
  exit 1
fi

printf 'openbao-native-secret-preflight: PASS '
print_counts
