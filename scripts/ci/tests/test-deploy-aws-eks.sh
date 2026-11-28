#!/usr/bin/env bash
# Static verification for the self-hosted Amazon EKS CloudFormation template,
# bootstrap scripts, and Helm values matrix (#6706).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

echo "==> aws-eks-cfn policy self-test and check"
python3 -B scripts/checks/repo_checks.py aws-eks-cfn --self-test
python3 -B scripts/checks/repo_checks.py aws-eks-cfn

if command -v cfn-lint >/dev/null 2>&1; then
  echo "==> cfn-lint deployments/aws-eks/template.yaml"
  cfn-lint deployments/aws-eks/template.yaml
else
  echo "==> cfn-lint not installed on PATH; skipping optional cfn-lint pass"
fi

if command -v shellcheck >/dev/null 2>&1; then
  echo "==> shellcheck deployments/aws-eks/{install,uninstall}.sh"
  shellcheck deployments/aws-eks/install.sh deployments/aws-eks/uninstall.sh
fi

echo "==> Helm render matrix for deployments/aws-eks/values-eks.yaml.tmpl"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "$WORK_DIR"' EXIT

render_case() {
  local name="$1"
  local replicas="$2"
  local direct_access="$3"
  local temporal_in_cluster="$4"
  local temporal_host="$5"
  local admin_enabled="$6"
  local admin_email="$7"
  local agent_sandbox="${8:-false}"
  local derp_host=""
  local stun_host=""
  local derp_tls=""
  if [ "$direct_access" = "true" ]; then
    derp_host="derp.codewire.example.test"
    stun_host="derp.codewire.example.test"
    derp_tls="codewire-derp-tls"
  fi
  local values_file="${WORK_DIR}/values-${name}.yaml"
  local out_file="${WORK_DIR}/render-${name}.yaml"

  python3 - deployments/aws-eks/values-eks.yaml.tmpl "$values_file" \
    "__DOMAIN_NAME__=codewire.example.test" \
    "__DERP_HOST__=${derp_host}" \
    "__STUN_HOST__=${stun_host}" \
    "__PREVIEW_BASE_DOMAIN__=preview.codewire.example.test" \
    "__PREVIEW_WILDCARD_HOST__=*.preview.codewire.example.test" \
    "__PREVIEW_TLS_SECRET__=codewire-preview-tls" \
    "__DERP_TLS_SECRET__=${derp_tls}" \
    "__TEMPORAL_HOST_PORT__=${temporal_host}" \
    "__TEMPORAL_NAMESPACE__=default" \
    "__RDS_ENDPOINT__=codewire-postgres.internal.test" \
    "__IMAGE_REGISTRY__=ghcr.io/codewiresh" \
    "__IMAGE_TAG__=v0.4.0-test" \
    "__STATELESS_REPLICAS__=${replicas}" \
    "__DIRECT_ACCESS_ENABLED__=${direct_access}" \
    "__LOCAL_KEYRING_ENABLED__=true" \
    "__AGENT_SANDBOX_ENABLED__=${agent_sandbox}" \
    "__TEMPORAL_IN_CLUSTER__=${temporal_in_cluster}" \
    "__DATABASE_INIT_ENABLED__=true" \
    "__ADMIN_BOOTSTRAP_ENABLED__=${admin_enabled}" \
    "__ADMIN_EMAIL__=${admin_email}" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src, encoding="utf-8").read()
for pair in sys.argv[3:]:
    k, v = pair.split("=", 1)
    text = text.replace(k, v)
leftover = sorted(set(re.findall(r"__[A-Z0-9_]+__", text)))
if leftover:
    raise SystemExit(f"unsubstituted placeholders: {leftover}")
open(dst, "w", encoding="utf-8").write(text)
PY

  helm template codewire deployments/helm/codewire --namespace codewire -f "$values_file" >"$out_file"

  python3 - "$out_file" "$direct_access" "$temporal_in_cluster" "$admin_enabled" <<'PY'
import sys, yaml
path, direct, temporal, admin = sys.argv[1], sys.argv[2] == "true", sys.argv[3] == "true", sys.argv[4] == "true"
docs = [d for d in yaml.safe_load_all(open(path, encoding="utf-8")) if d]
kn = {(d["kind"], d["metadata"]["name"]) for d in docs}

for required in (
    ("Deployment", "codewire-orchestration"),
    ("Deployment", "codewire-idp"),
    ("Deployment", "codewire-billing"),
    ("Deployment", "codewire-dashboard"),
    ("Gateway", "codewire-public"),
    ("Backend", "orchestration-h2c"),
    ("HTTPRoute", "codewire-apex"),
    ("HTTPRoute", "codewire-preview"),
    ("BackendTrafficPolicy", "codewire-long-lived"),
    ("Job", "codewire-database-init"),
    ("Issuer", "codewire-orchestration-internal"),
):
    assert required in kn, f"missing {required} in {path}"

orch = next(d for d in docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "codewire-orchestration")
env = {e["name"]: e.get("value") for e in orch["spec"]["template"]["spec"]["containers"][0]["env"]}
assert env.get("CODEWIRE_SECRET_KEK_PROVIDER") == "local-keyring", "local-keyring env missing"

apex = next(d for d in docs if d["kind"] == "HTTPRoute" and d["metadata"]["name"] == "codewire-apex")
grpc_rule = next(r for r in apex["spec"]["rules"] if r["name"] == "environment-session-grpc")
matches = {m["path"]["value"] for m in grpc_rule["matches"]}
assert "^/codewire[.]v1[.]HostAgentService/.*" in matches, "HostAgentService route missing"

assert (("Deployment", "codewire-temporal") in kn) == temporal, f"temporal mismatch in {path}"
assert (("Deployment", "codewire-derp") in kn) == direct, f"derp mismatch in {path}"
assert (("Deployment", "codewire-coordinator") in kn) == direct, f"coordinator mismatch in {path}"
assert (("Deployment", "codewire-udp-relay") in kn) == direct, f"udp-relay mismatch in {path}"
assert (("Job", "codewire-admin-bootstrap") in kn) == admin, f"admin-bootstrap mismatch in {path}"
assert ("Deployment", "codewire-credential-service") not in kn, "credential-service must be off in Phase 1"
PY
  echo "  [OK] matrix case: ${name}"
}

render_case "minimal" "1" "false" "true" "temporal-frontend.codewire.svc.cluster.local:7233" "true" "admin@example.test" "false"
render_case "kvm-default" "1" "false" "true" "temporal-frontend.codewire.svc.cluster.local:7233" "true" "admin@example.test" "true"
render_case "ha" "2" "false" "true" "temporal-frontend.codewire.svc.cluster.local:7233" "false" "" "true"
render_case "direct-access" "2" "true" "true" "temporal-frontend.codewire.svc.cluster.local:7233" "false" "" "true"
render_case "external-temporal" "1" "false" "false" "example.tmprl.cloud:7233" "false" "" "false"

echo "test-deploy-aws-eks: OK"
