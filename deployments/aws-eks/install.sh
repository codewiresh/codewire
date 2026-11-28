#!/usr/bin/env bash
# Idempotent bootstrap for self-hosted Codewire on Amazon EKS (#6706).
# Reads outputs from the deployed CloudFormation stack, installs pinned
# cluster controllers (AWS Load Balancer Controller, External Secrets Operator,
# cert-manager, Envoy Gateway), syncs stack Secrets Manager secrets, configures
# TLS and GP3 storage, and deploys deployments/helm/codewire.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CHART_DIR="${REPO_ROOT}/deployments/helm/codewire"
VALUES_TMPL="${SCRIPT_DIR}/values-eks.yaml.tmpl"

# Pinned cluster controller chart versions (bump deliberately via PR).
readonly AWS_LB_CONTROLLER_CHART_VERSION="1.11.0"
readonly EXTERNAL_SECRETS_CHART_VERSION="0.14.3"
readonly CERT_MANAGER_CHART_VERSION="v1.17.1"
readonly ENVOY_GATEWAY_CHART_VERSION="v1.3.2"

STACK_NAME=""
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
NAMESPACE="codewire"
IMAGE_REGISTRY="ghcr.io/codewiresh"
IMAGE_TAG="latest"
ACME_EMAIL=""
ADMIN_EMAIL=""
TEMPORAL_EXTERNAL_HOST=""
TEMPORAL_EXTERNAL_NAMESPACE="default"
DRY_RUN="false"

usage() {
  cat <<'EOF'
Usage: install.sh --stack-name <name> --region <aws-region> [options]

Options:
  --stack-name <name>             CloudFormation stack name (required)
  --region <aws-region>           AWS region (required, or set AWS_REGION)
  --namespace <ns>                Kubernetes namespace (default: codewire)
  --image-registry <registry>     Container registry (default: ghcr.io/codewiresh)
  --image-tag <tag>               Image release tag (default: latest)
  --acme-email <email>            Email for Let's Encrypt Route53 DNS-01 issuer
  --admin-email <email>           Email for first admin bootstrap Job
  --temporal-host <host:port>     External Temporal endpoint (when TemporalMode=External)
  --temporal-namespace <ns>       External Temporal namespace (default: default)
  --dry-run                       Render values and manifests without applying
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --stack-name) STACK_NAME="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --namespace) NAMESPACE="$2"; shift 2 ;;
    --image-registry) IMAGE_REGISTRY="$2"; shift 2 ;;
    --image-tag) IMAGE_TAG="$2"; shift 2 ;;
    --acme-email) ACME_EMAIL="$2"; shift 2 ;;
    --admin-email) ADMIN_EMAIL="$2"; shift 2 ;;
    --temporal-host) TEMPORAL_EXTERNAL_HOST="$2"; shift 2 ;;
    --temporal-namespace) TEMPORAL_EXTERNAL_NAMESPACE="$2"; shift 2 ;;
    --dry-run) DRY_RUN="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$STACK_NAME" ] || { echo "error: --stack-name is required" >&2; exit 2; }
[ -n "$REGION" ] || { echo "error: --region is required" >&2; exit 2; }

for tool in aws kubectl helm jq python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: required tool not found: $tool" >&2; exit 1; }
done

log() { printf '[aws-eks-install] %s\n' "$*" >&2; }

log "Reading CloudFormation outputs for stack ${STACK_NAME} (${REGION})"
STACK_JSON="$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK_NAME" --output json)"
get_output() {
  jq -r --arg k "$1" '.Stacks[0].Outputs[] | select(.OutputKey == $k) | .OutputValue' <<<"$STACK_JSON"
}

CLUSTER_NAME="$(get_output ClusterName)"
VPC_ID="$(get_output VpcId)"
RDS_ENDPOINT="$(get_output RdsEndpoint)"
KMS_KEY_ARN="$(get_output KmsKeyArn)"
SECRETS_PREFIX="$(get_output SecretsPrefix)"
PARAM_NAME="$(get_output ValuesParameterName)"

META_JSON="$(aws ssm get-parameter --region "$REGION" --name "$PARAM_NAME" --query 'Parameter.Value' --output text)"
get_meta() {
  jq -r --arg k "$1" '.[$k] // ""' <<<"$META_JSON"
}

DOMAIN_NAME="$(get_meta domainName)"
HOSTED_ZONE_ID="$(get_meta hostedZoneId)"
DEPLOYMENT_PROFILE="$(get_meta deploymentProfile)"
SANDBOX_COMPUTE_MODE="$(get_meta sandboxComputeMode)"
SECRET_KEK_MODE="$(get_meta secretKekMode)"
TEMPORAL_MODE="$(get_meta temporalMode)"
ENABLE_DIRECT_ACCESS="$(get_meta enableDirectAccess)"

[ -n "$CLUSTER_NAME" ] || { echo "error: ClusterName output is empty" >&2; exit 1; }
[ -n "$DOMAIN_NAME" ] || { echo "error: domainName metadata is empty" >&2; exit 1; }

STATELESS_REPLICAS="1"
[ "$DEPLOYMENT_PROFILE" = "HA" ] && STATELESS_REPLICAS="2"

TEMPORAL_IN_CLUSTER="true"
TEMPORAL_HOST_PORT="temporal-frontend.${NAMESPACE}.svc.cluster.local:7233"
TEMPORAL_NAMESPACE="default"
DATABASE_INIT_ENABLED="true"
if [ "$TEMPORAL_MODE" = "External" ]; then
  [ -n "$TEMPORAL_EXTERNAL_HOST" ] || { echo "error: --temporal-host is required when TemporalMode=External" >&2; exit 2; }
  TEMPORAL_IN_CLUSTER="false"
  TEMPORAL_HOST_PORT="$TEMPORAL_EXTERNAL_HOST"
  TEMPORAL_NAMESPACE="$TEMPORAL_EXTERNAL_NAMESPACE"
fi

LOCAL_KEYRING_ENABLED="false"
[ "$SECRET_KEK_MODE" = "SecretsManagerLocalKeyring" ] && LOCAL_KEYRING_ENABLED="true"

AGENT_SANDBOX_ENABLED="false"
[ "$SANDBOX_COMPUTE_MODE" = "EksKvmStandard" ] && AGENT_SANDBOX_ENABLED="true"

PREVIEW_BASE_DOMAIN="preview.${DOMAIN_NAME}"
PREVIEW_WILDCARD_HOST="*.${PREVIEW_BASE_DOMAIN}"
PREVIEW_TLS_SECRET="codewire-preview-tls"

DERP_HOST=""
STUN_HOST=""
DERP_TLS_SECRET=""
if [ "$ENABLE_DIRECT_ACCESS" = "true" ]; then
  DERP_HOST="derp.${DOMAIN_NAME}"
  STUN_HOST="derp.${DOMAIN_NAME}"
  DERP_TLS_SECRET="codewire-derp-tls"
fi

ADMIN_BOOTSTRAP_ENABLED="false"
if [ -n "$ADMIN_EMAIL" ]; then
  ADMIN_BOOTSTRAP_ENABLED="true"
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "$WORK_DIR"' EXIT
RENDERED_VALUES="${WORK_DIR}/values-eks.yaml"

python3 - "$VALUES_TMPL" "$RENDERED_VALUES" \
  "__DOMAIN_NAME__=${DOMAIN_NAME}" \
  "__DERP_HOST__=${DERP_HOST}" \
  "__STUN_HOST__=${STUN_HOST}" \
  "__PREVIEW_BASE_DOMAIN__=${PREVIEW_BASE_DOMAIN}" \
  "__PREVIEW_WILDCARD_HOST__=${PREVIEW_WILDCARD_HOST}" \
  "__PREVIEW_TLS_SECRET__=${PREVIEW_TLS_SECRET}" \
  "__DERP_TLS_SECRET__=${DERP_TLS_SECRET}" \
  "__TEMPORAL_HOST_PORT__=${TEMPORAL_HOST_PORT}" \
  "__TEMPORAL_NAMESPACE__=${TEMPORAL_NAMESPACE}" \
  "__RDS_ENDPOINT__=${RDS_ENDPOINT}" \
  "__IMAGE_REGISTRY__=${IMAGE_REGISTRY}" \
  "__IMAGE_TAG__=${IMAGE_TAG}" \
  "__STATELESS_REPLICAS__=${STATELESS_REPLICAS}" \
  "__DIRECT_ACCESS_ENABLED__=${ENABLE_DIRECT_ACCESS}" \
  "__LOCAL_KEYRING_ENABLED__=${LOCAL_KEYRING_ENABLED}" \
  "__AGENT_SANDBOX_ENABLED__=${AGENT_SANDBOX_ENABLED}" \
  "__TEMPORAL_IN_CLUSTER__=${TEMPORAL_IN_CLUSTER}" \
  "__DATABASE_INIT_ENABLED__=${DATABASE_INIT_ENABLED}" \
  "__ADMIN_BOOTSTRAP_ENABLED__=${ADMIN_BOOTSTRAP_ENABLED}" \
  "__ADMIN_EMAIL__=${ADMIN_EMAIL}" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src, encoding="utf-8").read()
for pair in sys.argv[3:]:
    key, value = pair.split("=", 1)
    text = text.replace(key, value)
if "__" in text:
    import re
    leftover = sorted(set(re.findall(r"__[A-Z0-9_]+__", text)))
    if leftover:
        raise SystemExit(f"unsubstituted template placeholders: {leftover}")
with open(dst, "w", encoding="utf-8") as fh:
    fh.write(text)
PY

if [ "$DRY_RUN" = "true" ]; then
  log "Dry run: rendering Codewire Helm chart with generated EKS values"
  helm template codewire "$CHART_DIR" --namespace "$NAMESPACE" -f "$RENDERED_VALUES" >/dev/null
  log "Dry run succeeded"
  exit 0
fi

log "Configuring kubeconfig for ${CLUSTER_NAME}"
aws eks update-kubeconfig --region "$REGION" --name "$CLUSTER_NAME" >/dev/null

log "Ensuring namespace ${NAMESPACE}"
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

log "Installing pinned cluster controllers"
helm repo add eks https://aws.github.io/eks-charts >/dev/null 2>&1 || true
helm repo add external-secrets https://charts.external-secrets.io >/dev/null 2>&1 || true
helm repo add jetstack https://charts.jetstack.io >/dev/null 2>&1 || true
helm repo update >/dev/null

helm upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller \
  --namespace kube-system \
  --version "$AWS_LB_CONTROLLER_CHART_VERSION" \
  --set clusterName="$CLUSTER_NAME" \
  --set region="$REGION" \
  --set vpcId="$VPC_ID" \
  --wait

helm upgrade --install external-secrets external-secrets/external-secrets \
  --namespace external-secrets --create-namespace \
  --version "$EXTERNAL_SECRETS_CHART_VERSION" \
  --set installCRDs=true \
  --wait

helm upgrade --install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --version "$CERT_MANAGER_CHART_VERSION" \
  --set crds.enabled=true \
  --wait

helm upgrade --install eg oci://docker.io/envoyproxy/gateway-helm \
  --namespace envoy-gateway-system --create-namespace \
  --version "$ENVOY_GATEWAY_CHART_VERSION" \
  --wait

log "Applying encrypted GP3 StorageClass, EnvoyProxy NLB config, and ExternalSecrets"
cat <<EOF | kubectl apply -f -
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: codewire-gp3
provisioner: ebs.csi.aws.com
volumeBindingMode: WaitForFirstConsumer
allowVolumeExpansion: true
parameters:
  type: gp3
  encrypted: "true"
  kmsKeyId: "${KMS_KEY_ARN}"
---
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: eg
spec:
  controllerName: gateway.envoyproxy.io/gatewayclass-controller
---
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyProxy
metadata:
  name: codewire-nlb
  namespace: ${NAMESPACE}
spec:
  provider:
    type: Kubernetes
    kubernetes:
      envoyService:
        type: LoadBalancer
        externalTrafficPolicy: Local
        annotations:
          service.beta.kubernetes.io/aws-load-balancer-type: external
          service.beta.kubernetes.io/aws-load-balancer-nlb-target-type: ip
          service.beta.kubernetes.io/aws-load-balancer-scheme: internet-facing
---
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: codewire-aws-secrets
  namespace: ${NAMESPACE}
spec:
  provider:
    aws:
      service: SecretsManager
      region: ${REGION}
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: codewire-db-app
  namespace: ${NAMESPACE}
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: codewire-aws-secrets
    kind: SecretStore
  target:
    name: codewire-db-app
  data:
    - secretKey: password
      remoteRef:
        key: "${SECRETS_PREFIX}/db-app"
        property: password
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: codewire-secrets
  namespace: ${NAMESPACE}
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: codewire-aws-secrets
    kind: SecretStore
  target:
    name: codewire-secrets
  data:
    - secretKey: SESSION_SECRET
      remoteRef:
        key: "${SECRETS_PREFIX}/session-secret"
        property: SESSION_SECRET
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: codewire-idp-signing-keks
  namespace: ${NAMESPACE}
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: codewire-aws-secrets
    kind: SecretStore
  target:
    name: codewire-idp-signing-keks
  data:
    - secretKey: v1
      remoteRef:
        key: "${SECRETS_PREFIX}/idp-signing-keks"
        property: v1
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: codewire-admin-init
  namespace: ${NAMESPACE}
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: codewire-aws-secrets
    kind: SecretStore
  target:
    name: codewire-admin-init
  data:
    - secretKey: password
      remoteRef:
        key: "${SECRETS_PREFIX}/admin-bootstrap"
        property: password
EOF

if [ "$LOCAL_KEYRING_ENABLED" = "true" ]; then
  cat <<EOF | kubectl apply -f -
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: codewire-tenant-keks
  namespace: ${NAMESPACE}
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: codewire-aws-secrets
    kind: SecretStore
  target:
    name: codewire-tenant-keks
  data:
    - secretKey: v1
      remoteRef:
        key: "${SECRETS_PREFIX}/tenant-keks"
        property: v1
EOF
fi

log "Waiting for ExternalSecrets in ${NAMESPACE} to sync before Helm install"
kubectl -n "$NAMESPACE" wait --for=condition=Ready externalsecret --all --timeout=120s

if [ -n "$HOSTED_ZONE_ID" ]; then
  [ -n "$ACME_EMAIL" ] || { echo "error: --acme-email is required when HostedZoneId is set" >&2; exit 2; }
  log "Configuring cert-manager Route53 DNS-01 ClusterIssuer and TLS Certificates"
  cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-codewire
spec:
  acme:
    email: "${ACME_EMAIL}"
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-codewire-account
    solvers:
      - dns01:
          route53:
            region: "${REGION}"
            hostedZoneID: "${HOSTED_ZONE_ID}"
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: codewire-edge-tls
  namespace: ${NAMESPACE}
spec:
  secretName: codewire-edge-tls
  issuerRef:
    name: letsencrypt-codewire
    kind: ClusterIssuer
  dnsNames:
    - "${DOMAIN_NAME}"
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: codewire-preview-tls
  namespace: ${NAMESPACE}
spec:
  secretName: codewire-preview-tls
  issuerRef:
    name: letsencrypt-codewire
    kind: ClusterIssuer
  dnsNames:
    - "${PREVIEW_WILDCARD_HOST}"
EOF
  if [ "$ENABLE_DIRECT_ACCESS" = "true" ]; then
    cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: codewire-derp-tls
  namespace: ${NAMESPACE}
spec:
  secretName: codewire-derp-tls
  issuerRef:
    name: letsencrypt-codewire
    kind: ClusterIssuer
  dnsNames:
    - "${DERP_HOST}"
EOF
  fi
fi

log "Deploying Codewire Helm release into namespace ${NAMESPACE}"
helm upgrade --install codewire "$CHART_DIR" \
  --namespace "$NAMESPACE" \
  -f "$RENDERED_VALUES" \
  --wait \
  --timeout 15m

log "Codewire deployed on EKS (${CLUSTER_NAME}). Point DNS for ${DOMAIN_NAME} (and ${PREVIEW_WILDCARD_HOST}) to the Envoy Gateway NLB:"
kubectl -n envoy-gateway-system get svc -l gateway.envoyproxy.io/owning-gateway-name=codewire-public -o wide || true
