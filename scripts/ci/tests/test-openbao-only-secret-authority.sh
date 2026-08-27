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
  crates/codewire-server-core/migrations/0013_finalize_openbao_native_secrets.sql
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
  crates/codewire-server-core/migrations/0012_expand_openbao_secret_authority.sql)" == 2 ]]
[[ "$(LC_ALL=C rg -i -c -- "$PATTERN" \
  crates/codewire-server-core/migrations/0013_finalize_openbao_native_secrets.sql)" == 1 ]]

# Migration 12 is already applied in Dev. Bind its exact SQLx checksum so a
# compatibility edit cannot silently rewrite the immutable ledger contract.
readonly MIGRATION_12=crates/codewire-server-core/migrations/0012_expand_openbao_secret_authority.sql
readonly MIGRATION_12_SHA384=cbd3494fde9235aaf507236bd18440f2d0c87fe6c42f9b1ce3af78f327b044aa968149229acd1bf064b6d4e67c54ed40
[[ "$(sha384sum "$MIGRATION_12" | awk '{print $1}')" == "$MIGRATION_12_SHA384" ]]

# The final pre-GA migration removes every runtime fallback only after a
# zero-row preflight. Historical applied migrations remain immutable.
readonly FINALIZATION=crates/codewire-server-core/migrations/0013_finalize_openbao_native_secrets.sql
for required in \
  'requires local_secrets=0' \
  'requires tenant_secrets=0' \
  'requires tenant_secret_deks=0' \
  'DROP TABLE public.local_secrets' \
  'DROP TABLE public.tenant_secret_control' \
  'DROP COLUMN infisical_path' \
  "provider = 'openbao-transit'"; do
  grep -Fq "$required" "$FINALIZATION"
done

if rg -n \
  'TENANT_SECRET_(STORE|KEK_PROVIDER|KEYRING)|LocalSecretStore|tenant-secret-operator|tenant_secret_control|local_secrets|KekProviderKind::Keyring' \
  crates/codewire-orchestration/src deployments docs/SECRETS.md; then
  printf 'retired tenant-secret runtime choice remains active\n' >&2
  exit 1
fi
if rg -n --glob '!migrate.rs' \
  'tenant_secret_control|local_secrets' crates/codewire-server-core/src; then
  printf 'retired tenant-secret runtime choice remains active\n' >&2
  exit 1
fi

# The synthetic KEK is a deliberate, two-part Kind contract: only the
# non-promotable image is compiled with it, and every repository-owned Kind
# topology opts into it explicitly. Production images and manifests must not.
grep -Fq 'CODEWIRE_ORCHESTRATION_FEATURES = "kind-e2e"' docker-bake.hcl
grep -Fq 'CODEWIRE_KIND_TENANT_SECRET_TEST_PROVIDER: "true"' \
  deployments/k8s/overlays/local-kind/configmap-patch.yaml
grep -Fq 'CODEWIRE_KIND_TENANT_SECRET_TEST_PROVIDER: "true"' \
  deployments/k8s/overlays/local-kind-static/configmap-patch.yaml
grep -Fq 'CODEWIRE_KIND_TENANT_SECRET_TEST_PROVIDER: "true"' \
  tests/e2e/kind/support.yaml
if rg -n 'CODEWIRE_KIND_TENANT_SECRET_TEST_PROVIDER' \
  deployments/k8s/base deployments/k8s/overlays/dev deployments/k8s/overlays/production \
  deployments/docker/services.Dockerfile; then
  printf 'Kind-only tenant-secret provider leaked into a promotable surface\n' >&2
  exit 1
fi

# Decide from the rendered workload rather than source fragments. Dev must
# receive two independent exact-audience projected identities while the
# reusable/Production render remains inert.
render_root="$(mktemp -d)"
trap 'rm -rf -- "$render_root"' EXIT
kubectl kustomize deployments/k8s/overlays/dev >"$render_root/dev.yaml"
kubectl kustomize deployments/k8s/overlays/production >"$render_root/production.yaml"
yq ea -o=json -I=0 \
  'select(.kind == "ConfigMap") | .data' \
  "$render_root/dev.yaml" >"$render_root/dev-config.json"
yq ea -o=json -I=0 \
  'select(.kind == "Deployment" and .metadata.name == "codewire-orchestration")' \
  "$render_root/dev.yaml" >"$render_root/dev-orchestration.json"
yq ea -o=json -I=0 \
  'select(.kind == "Deployment" and .metadata.name == "codewire-orchestration")' \
  "$render_root/production.yaml" >"$render_root/production-orchestration.json"
yq ea -o=json -I=0 \
  'select(.kind == "ConfigMap") | .data' \
  "$render_root/production.yaml" >"$render_root/production-config.json"

jq -e '
  .BAO_ADDR == "https://openbao.example.invalid" and
  .TENANT_SECRET_BAO_AUTH_MOUNT == "dev-cluster-k8s" and
  .TENANT_SECRET_BAO_ROLE == "codewire-tenant-dev-cluster" and
  .TENANT_SECRET_BAO_TRANSIT_MOUNT == "codewire-tenant-dev" and
  .TENANT_SECRET_BAO_TRANSIT_KEY == "tenant-dek" and
  .TENANT_SECRET_BAO_EXPECTED_CLUSTER_ID == "00000000-0000-0000-0000-000000000000"
' "$render_root/dev-config.json" >/dev/null

jq -e '
  def named($items; $name): [$items[] | select(.name == $name)];
  .spec.template.spec as $pod |
  $pod.securityContext == {
    "fsGroup": 65532,
    "fsGroupChangePolicy": "OnRootMismatch",
    "runAsGroup": 65532,
    "runAsNonRoot": true,
    "runAsUser": 65532
  } and
  named($pod.containers[0].volumeMounts; "tenant-secret-openbao-token") == [{
    "mountPath": "/var/run/secrets/codewire-tenant-bao",
    "name": "tenant-secret-openbao-token",
    "readOnly": true
  }] and
  named($pod.containers[0].volumeMounts; "confidential-storage-openbao-token") == [{
    "mountPath": "/var/run/secrets/codewire-confidential-openbao",
    "name": "confidential-storage-openbao-token",
    "readOnly": true
  }] and
  named($pod.volumes; "tenant-secret-openbao-token")[0].projected == {
    "defaultMode": 288,
    "sources": [{"serviceAccountToken": {
      "audience": "openbao-codewire-tenant-dev-cluster",
      "expirationSeconds": 600,
      "path": "token"
    }}]
  } and
  named($pod.volumes; "confidential-storage-openbao-token")[0].projected == {
    "defaultMode": 288,
    "sources": [{"serviceAccountToken": {
      "audience": "openbao-codewire-confidential-storage-dev-cluster",
      "expirationSeconds": 600,
      "path": "token"
    }}]
  }
' "$render_root/dev-orchestration.json" >/dev/null

jq -e '
  .BAO_ADDR == "" and
  .TENANT_SECRET_BAO_ROLE == "" and
  .TENANT_SECRET_BAO_EXPECTED_CLUSTER_ID == "" and
  .CONFIDENTIAL_STORAGE_BAO_ADDR == "" and
  .CONFIDENTIAL_STORAGE_BAO_ROLE == "" and
  .CONFIDENTIAL_STORAGE_BAO_EXPECTED_CLUSTER_ID == ""
' "$render_root/production-config.json" >/dev/null

jq -e '
  [
    .spec.template.spec.volumes[]?.name,
    .spec.template.spec.containers[].volumeMounts[]?.name
  ] |
  all(. != "tenant-secret-openbao-token" and . != "confidential-storage-openbao-token")
' "$render_root/production-orchestration.json" >/dev/null

printf 'OpenBao-only secret authority contract: OK\n'
