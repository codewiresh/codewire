#!/usr/bin/env bash
set -euo pipefail

die() {
  printf '[ci-kubeconfig] ERROR: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[ci-kubeconfig] %s\n' "$*" >&2
}

TOKEN_PATH_ENV="${KUBE_TOKEN_PATH_ENV:-CODEWIRE_DEV_TOKEN_PATH}"
SERVER_ENV="${KUBE_SERVER_ENV:-CODEWIRE_DEV_K8S_SERVER}"
KUBE_CLUSTER="${KUBE_CLUSTER:-csrke2-dev}"
KUBE_CONTEXT="${KUBE_CONTEXT:-$KUBE_CLUSTER}"
KUBE_USER="${KUBE_USER:-ci-deployer}"

TOKEN_PATH="${!TOKEN_PATH_ENV:-}"
RAW_K8S_SERVER="${!SERVER_ENV:-}"

[[ -n "$TOKEN_PATH" ]] || die "$TOKEN_PATH_ENV is required"
[[ -f "$TOKEN_PATH" ]] || die "$TOKEN_PATH_ENV does not point to a file"
[[ -n "$RAW_K8S_SERVER" ]] || die "$SERVER_ENV is required"

case "$-" in
  *x*) die "shell tracing is enabled; rerun without set -x" ;;
esac

case "${RAW_K8S_SERVER%/}" in
  https://*) K8S_SCHEME="https://"; K8S_REST="${RAW_K8S_SERVER%/}"; K8S_REST="${K8S_REST#https://}" ;;
  http://*) K8S_SCHEME="http://"; K8S_REST="${RAW_K8S_SERVER%/}"; K8S_REST="${K8S_REST#http://}" ;;
  "") die "$SERVER_ENV is empty" ;;
  *) K8S_SCHEME="https://"; K8S_REST="${RAW_K8S_SERVER%/}" ;;
esac

K8S_HOSTPORT="${K8S_REST%%/*}"
if [[ "$K8S_HOSTPORT" == *:9345 ]]; then
  K8S_HOSTPORT="${K8S_HOSTPORT%:9345}:6443"
fi
K8S_SERVER="${K8S_SCHEME}${K8S_HOSTPORT}"

if [[ -z "${KUBECONFIG:-}" ]]; then
  mkdir -p "$HOME/.kube"
else
  mkdir -p "$(dirname "$KUBECONFIG")"
fi

kubectl config set-cluster "$KUBE_CLUSTER" \
  --server="$K8S_SERVER" \
  --insecure-skip-tls-verify=true >/dev/null
kubectl config set "users.${KUBE_USER}.user.tokenFile" "$TOKEN_PATH" >/dev/null
kubectl config set-context "$KUBE_CONTEXT" \
  --cluster="$KUBE_CLUSTER" \
  --user="$KUBE_USER" >/dev/null
kubectl config use-context "$KUBE_CONTEXT" >/dev/null
kubectl get --raw /api >/dev/null

log "configured Kubernetes context $KUBE_CONTEXT for cluster $KUBE_CLUSTER"
