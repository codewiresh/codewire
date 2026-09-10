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

check_production_primitive_features() {
  local production_tree primitive_features
  production_tree="$(cargo tree --locked "$@" \
    --edges normal,build --depth 1 --prefix none --format '{p}|{f}')"
  primitive_features="$(sed -n 's/^codewire-protected-store .*|//p' <<<"$production_tree")"
  if [[ -z "$primitive_features" ]] \
      || ! grep -Eq '(^|,)platform(,|$)' <<<"$primitive_features" \
      || grep -Eq '(^|,)platform-test-support(,|$)' <<<"$primitive_features"; then
    printf 'production protected-store graph must enable platform without synthetic providers\n' >&2
    return 1
  fi
}

check_production_service_features() {
  local production_tree broker_features
  production_tree="$(cargo tree --locked -p codewire-credential-service "$@" \
    --edges normal,build --prefix none --format '{p}|{f}')"
  broker_features="$(sed -n 's/^codewire-credential-broker .*|//p' <<<"$production_tree")"
  if [[ -z "$broker_features" ]] \
      || ! grep -Eq '(^|,)platform(,|$)' <<<"$broker_features" \
      || grep -Eq '(^|,)(default|local|local-broker-synthetic-smoke)(,|$)' <<<"$broker_features" \
      || grep -Eq '^codewire-local-credentials |\|[^[:space:]]*platform-test-support' <<<"$production_tree"; then
    printf 'production credential service must use platform brokerage without local or synthetic authority\n' >&2
    return 1
  fi
}

# Shared policy needs only static source and rendered-manifest checks. Cargo's
# resolved graph belongs to the separately provisioned Rust capability.
if [[ "$#" -gt 0 ]]; then
  if [[ "$#" -ne 1 ]]; then
    printf 'usage: %s [--production-features|--production-broker-features|--production-service-features]\n' "$SELF" >&2
    exit 2
  fi
  # Resolver-v2 normal/build edges exclude dev feature unification and expose
  # any transitive feature that would enable the synthetic provider.
  case "$1" in
    --production-features)
      check_production_primitive_features -p codewire-orchestration
      ;;
    --production-broker-features)
      check_production_primitive_features -p codewire-credential-broker \
        --no-default-features --features platform
      ;;
    --production-service-features)
      check_production_service_features
      check_production_service_features --features enrollment
      ;;
    *)
      printf 'usage: %s [--production-features|--production-broker-features|--production-service-features]\n' "$SELF" >&2
      exit 2
      ;;
  esac
  printf 'Production protected-store feature graph: OK\n'
  exit 0
fi

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
  crates/codewire-orchestration/src crates/codewire-protected-store/src \
  deployments docs/SECRETS.md; then
  printf 'retired tenant-secret runtime choice remains active\n' >&2
  exit 1
fi
if rg -n --glob '!migrate.rs' \
  'tenant_secret_control|local_secrets' crates/codewire-server-core/src; then
  printf 'retired tenant-secret runtime choice remains active\n' >&2
  exit 1
fi
if rg -n \
  'TENANT_SECRET_BAO_SA_TOKEN_PATH|CONFIDENTIAL_STORAGE_BAO_SA_TOKEN_PATH|/var/run/secrets/codewire-(tenant-bao|confidential-openbao)' \
  crates deployments docs/SECRETS.md; then
  printf 'obsolete file-backed OpenBao workload identity remains active\n' >&2
  exit 1
fi

# Shared primitives have one owner, with no orchestration compatibility path.
for retired_copy in \
  crates/codewire-orchestration/src/openbao_workload_identity.rs \
  crates/codewire-orchestration/src/worker/secret_envelope.rs; do
  [[ ! -e "$retired_copy" ]] || {
    printf 'orchestration retains a duplicate protected-store primitive: %s\n' "$retired_copy" >&2
    exit 1
  }
done
if rg -n \
  '(crate|super)(::super)*::(secret_envelope|openbao_workload_identity)|mod (secret_envelope|openbao_workload_identity);' \
  crates/codewire-orchestration/src; then
  printf 'orchestration must consume protected-store primitives directly\n' >&2
  exit 1
fi

# Production receives only platform primitives. Synthetic providers are an
# explicit dev/Kind feature, never a default or a normal dependency feature.
python3 - <<'PY'
from pathlib import Path
import tomllib

root = Path.cwd()
protected = tomllib.loads((root / "crates/codewire-protected-store/Cargo.toml").read_text())
orchestration = tomllib.loads((root / "crates/codewire-orchestration/Cargo.toml").read_text())
broker = tomllib.loads((root / "crates/codewire-credential-broker/Cargo.toml").read_text())
assert protected["features"]["default"] == []
assert protected["features"]["platform-test-support"] == ["platform"]
assert all(feature.startswith("dep:") for feature in protected["features"]["platform"])
assert orchestration["dependencies"]["codewire-protected-store"]["features"] == ["platform"]
assert orchestration["dev-dependencies"]["codewire-protected-store"]["features"] == ["platform-test-support"]
assert orchestration["features"]["kind-e2e"].count("codewire-protected-store/platform-test-support") == 1
assert broker["features"]["default"] == ["local"]
assert set(broker["features"]["platform"]) == {"dep:codewire-platform-credentials", "dep:codewire-protected-store", "dep:tonic"}
assert broker["dependencies"]["codewire-platform-credentials"]["optional"] is True

manifests = [root / "Cargo.toml", *sorted((root / "crates").glob("*/Cargo.toml"))]
for path in manifests:
    manifest = tomllib.loads(path.read_text())
    tables = [manifest, manifest.get("workspace", {}), *manifest.get("target", {}).values()]
    for table in tables:
        for kind in ("dependencies", "build-dependencies"):
            for dependency in table.get(kind, {}).values():
                if isinstance(dependency, dict):
                    assert "platform-test-support" not in dependency.get("features", []), path
    for feature, members in manifest.get("features", {}).items():
        if any("platform-test-support" in member for member in members):
            assert path == root / "crates/codewire-orchestration/Cargo.toml" and feature == "kind-e2e", path

envelope = (root / "crates/codewire-protected-store/src/secret_envelope.rs").read_text()
identity = (root / "crates/codewire-protected-store/src/openbao_workload_identity.rs").read_text()
gate = '#[cfg(any(test, feature = "platform-test-support"))]'
assert gate + "\npub struct TestKekProvider;" in envelope
assert gate + "\n#[async_trait]\nimpl KekProvider for TestKekProvider" in envelope
assert gate + "\npub fn static_workload_identity" in identity
PY

# The synthetic KEK is a deliberate, two-part Kind contract: only the
# non-promotable image is compiled with it, and every repository-owned Kind
# topology opts into it explicitly. Production images and manifests must not.
grep -Fq 'CODEWIRE_ORCHESTRATION_FEATURES = "kind-e2e"' docker-bake.hcl
grep -Fq -- \
  "--set 'services-ci.tags=codewire-services:local' services-ci" \
  Makefile
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

# Decide from the rendered workload rather than source fragments. Dev uses a
# Pod-bound TokenRequest identity with two exact audiences per OpenBao client;
# the reusable/Production render remains unconfigured.
render_root="$(mktemp -d)"
trap 'rm -rf -- "$render_root"' EXIT
kubectl kustomize deployments/k8s/overlays/dev >"$render_root/dev.yaml"
kubectl kustomize deployments/k8s/overlays/local-kind >"$render_root/local-kind.yaml"
kubectl kustomize deployments/k8s/overlays/local-kind-static >"$render_root/local-kind-static.yaml"
kubectl kustomize deployments/k8s/overlays/production >"$render_root/production.yaml"
yq ea -o=json -I=0 \
  'select(.kind == "ConfigMap" and (.metadata.name | test("^codewire-config-"))) | .data' \
  "$render_root/dev.yaml" >"$render_root/dev-config.json"
yq ea -o=json -I=0 \
  'select(.kind == "Deployment" and .metadata.name == "codewire-orchestration")' \
  "$render_root/dev.yaml" >"$render_root/dev-orchestration.json"
for topology in local-kind local-kind-static; do
  yq ea -o=json -I=0 \
    'select(.kind == "Deployment" and .metadata.name == "codewire-orchestration")' \
    "$render_root/$topology.yaml" >"$render_root/$topology-orchestration.json"
done
yq ea -o=json -I=0 \
  'select(.kind == "Role" and .metadata.name == "codewire-orchestration-tokenrequest")' \
  "$render_root/dev.yaml" >"$render_root/dev-tokenrequest-role.json"
yq ea -o=json -I=0 \
  'select(.kind == "RoleBinding" and .metadata.name == "codewire-orchestration-tokenrequest")' \
  "$render_root/dev.yaml" >"$render_root/dev-tokenrequest-binding.json"
yq ea -o=json -I=0 \
  'select(.kind == "Deployment" and .metadata.name == "codewire-orchestration")' \
  "$render_root/production.yaml" >"$render_root/production-orchestration.json"
yq ea -o=json -I=0 \
  'select(.kind == "ConfigMap" and (.metadata.name | test("^codewire-config-"))) | .data' \
  "$render_root/production.yaml" >"$render_root/production-config.json"

jq -e '
  .BAO_ADDR == "https://openbao.example.invalid" and
  .OPENBAO_KUBERNETES_API_AUDIENCE == "https://10.60.0.100:6443" and
  .TENANT_SECRET_BAO_AUTH_MOUNT == "dev-cluster-k8s" and
  .TENANT_SECRET_BAO_ROLE == "codewire-tenant-dev-cluster" and
  .TENANT_SECRET_BAO_AUDIENCE == "openbao-codewire-tenant-dev-cluster" and
  .CONFIDENTIAL_STORAGE_BAO_AUDIENCE == "openbao-codewire-confidential-storage-dev-cluster" and
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
  $pod.serviceAccountName == "codewire-orchestration" and
  $pod.automountServiceAccountToken != false and
  named($pod.containers[0].env; "POD_NAMESPACE")[0].valueFrom.fieldRef.fieldPath == "metadata.namespace" and
  named($pod.containers[0].env; "POD_NAME")[0].valueFrom.fieldRef.fieldPath == "metadata.name" and
  named($pod.containers[0].env; "POD_UID")[0].valueFrom.fieldRef.fieldPath == "metadata.uid" and
  named($pod.containers[0].env; "POD_SERVICE_ACCOUNT_NAME")[0].valueFrom.fieldRef.fieldPath == "spec.serviceAccountName" and
  named($pod.containers[0].volumeMounts; "tenant-secret-openbao-token") == [] and
  named($pod.containers[0].volumeMounts; "confidential-storage-openbao-token") == [] and
  named($pod.volumes; "tenant-secret-openbao-token") == [] and
  named($pod.volumes; "confidential-storage-openbao-token") == []
' "$render_root/dev-orchestration.json" >/dev/null

for topology in local-kind local-kind-static; do
  jq -e '
    def named($items; $name): [$items[] | select(.name == $name)];
    .spec.template.spec.containers[0].env as $env |
    named($env; "ORCHESTRATION_INTERNAL_CONNECT_PORT")[0].value == "8085" and
    named($env; "POD_NAMESPACE")[0].valueFrom.fieldRef.fieldPath == "metadata.namespace" and
    named($env; "POD_NAME")[0].valueFrom.fieldRef.fieldPath == "metadata.name" and
    named($env; "POD_UID")[0].valueFrom.fieldRef.fieldPath == "metadata.uid" and
    named($env; "POD_SERVICE_ACCOUNT_NAME")[0].valueFrom.fieldRef.fieldPath == "spec.serviceAccountName"
  ' "$render_root/$topology-orchestration.json" >/dev/null
done

jq -e '
  .metadata.namespace == "dev" and
  .rules == [{
    "apiGroups": [""],
    "resourceNames": ["codewire-orchestration"],
    "resources": ["serviceaccounts/token"],
    "verbs": ["create"]
  }]
' "$render_root/dev-tokenrequest-role.json" >/dev/null

jq -e '
  .metadata.namespace == "dev" and
  .roleRef == {
    "apiGroup": "rbac.authorization.k8s.io",
    "kind": "Role",
    "name": "codewire-orchestration-tokenrequest"
  } and
  .subjects == [{
    "kind": "ServiceAccount",
    "name": "codewire-orchestration",
    "namespace": "dev"
  }]
' "$render_root/dev-tokenrequest-binding.json" >/dev/null

jq -e '
  .BAO_ADDR == "" and
  .OPENBAO_KUBERNETES_API_AUDIENCE == "" and
  .TENANT_SECRET_BAO_ROLE == "" and
  .TENANT_SECRET_BAO_AUDIENCE == "" and
  .TENANT_SECRET_BAO_EXPECTED_CLUSTER_ID == "" and
  .CONFIDENTIAL_STORAGE_BAO_ADDR == "" and
  .CONFIDENTIAL_STORAGE_BAO_ROLE == "" and
  .CONFIDENTIAL_STORAGE_BAO_AUDIENCE == "" and
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
