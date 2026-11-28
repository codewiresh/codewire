#!/usr/bin/env bash
# Safe teardown for self-hosted Codewire on Amazon EKS (#6706).
# Removes Kubernetes Gateway/LoadBalancer Services and PVCs before deleting
# the CloudFormation stack so AWS NLB ENIs and EBS volumes do not orphan and
# stall VPC teardown.
set -euo pipefail

STACK_NAME=""
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
NAMESPACE="codewire"
DELETE_STACK="false"

usage() {
  cat <<'EOF'
Usage: uninstall.sh --stack-name <name> --region <aws-region> [options]

Options:
  --stack-name <name>   CloudFormation stack name (required)
  --region <aws-region> AWS region (required, or set AWS_REGION)
  --namespace <ns>      Kubernetes namespace (default: codewire)
  --delete-stack        Also run `aws cloudformation delete-stack` after draining K8s resources
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --stack-name) STACK_NAME="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --namespace) NAMESPACE="$2"; shift 2 ;;
    --delete-stack) DELETE_STACK="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$STACK_NAME" ] || { echo "error: --stack-name is required" >&2; exit 2; }
[ -n "$REGION" ] || { echo "error: --region is required" >&2; exit 2; }

for tool in aws kubectl helm jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: required tool not found: $tool" >&2; exit 1; }
done

log() { printf '[aws-eks-uninstall] %s\n' "$*" >&2; }

CLUSTER_NAME="$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK_NAME" --output json \
  | jq -r '.Stacks[0].Outputs[] | select(.OutputKey == "ClusterName") | .OutputValue')"
[ -n "$CLUSTER_NAME" ] || { echo "error: could not resolve ClusterName from stack ${STACK_NAME}" >&2; exit 1; }

log "Configuring kubeconfig for ${CLUSTER_NAME}"
aws eks update-kubeconfig --region "$REGION" --name "$CLUSTER_NAME" >/dev/null

log "Uninstalling Codewire Helm release from ${NAMESPACE}"
helm uninstall codewire --namespace "$NAMESPACE" --ignore-not-found --wait || true

log "Removing Gateways and LoadBalancer Services so AWS NLBs deregister cleanly"
kubectl -n "$NAMESPACE" delete gateway --all --ignore-not-found --wait=true || true
kubectl -n envoy-gateway-system delete svc -l gateway.envoyproxy.io/owning-gateway-name=codewire-public --ignore-not-found --wait=true || true
kubectl -n "$NAMESPACE" delete pvc --all --ignore-not-found --wait=true || true

log "Waiting 30s for AWS NLB target groups and ENIs to finish releasing"
sleep 30

log "Uninstalling cluster controllers"
helm uninstall eg --namespace envoy-gateway-system --ignore-not-found --wait || true
helm uninstall cert-manager --namespace cert-manager --ignore-not-found --wait || true
helm uninstall external-secrets --namespace external-secrets --ignore-not-found --wait || true
helm uninstall aws-load-balancer-controller --namespace kube-system --ignore-not-found --wait || true

if [ "$DELETE_STACK" = "true" ]; then
  log "Deleting CloudFormation stack ${STACK_NAME} (${REGION})"
  aws cloudformation delete-stack --region "$REGION" --stack-name "$STACK_NAME"
  aws cloudformation wait stack-delete-complete --region "$REGION" --stack-name "$STACK_NAME"
  log "Stack ${STACK_NAME} reached DELETE_COMPLETE"
else
  log "Kubernetes workloads drained. To delete AWS resources, run:"
  log "  aws cloudformation delete-stack --region ${REGION} --stack-name ${STACK_NAME}"
fi
