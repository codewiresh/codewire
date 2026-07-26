#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TOOLS_DIR="${ROOT_DIR}/.tmp/tools"
HELM_VERSION="${HELM_VERSION:-v3.18.4}"
HELM_BIN="${HELM_BIN:-}"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-codewire}"

install_helm() {
  mkdir -p "$TOOLS_DIR"
  local archive="${TOOLS_DIR}/helm-${HELM_VERSION}-linux-amd64.tar.gz"
  local extract_dir="${TOOLS_DIR}/helm-${HELM_VERSION}"
  curl -fsSL "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" -o "$archive"
  rm -rf "$extract_dir"
  mkdir -p "$extract_dir"
  tar -C "$extract_dir" -xzf "$archive"
  mv "$extract_dir/linux-amd64/helm" "$TOOLS_DIR/helm"
  chmod +x "$TOOLS_DIR/helm"
}

if [ -z "$HELM_BIN" ]; then
  if command -v helm >/dev/null 2>&1; then
    HELM_BIN="$(command -v helm)"
  else
    HELM_BIN="${TOOLS_DIR}/helm"
  fi
fi

if [ ! -x "$HELM_BIN" ]; then
  install_helm
  HELM_BIN="${TOOLS_DIR}/helm"
fi

TARGET="${1:-local-kind}"
RELEASE_NAME="${TEMPORAL_HELM_RELEASE:-temporal}"
NAMESPACE="${TEMPORAL_HELM_NAMESPACE:-temporal-system}"
CHART_VERSION="${TEMPORAL_HELM_CHART_VERSION:-1.0.0}"
CHART_REF="${TEMPORAL_HELM_CHART_REF:-temporal/temporal}"
REPO_UPDATE_MODE="${TEMPORAL_HELM_REPO_UPDATE:-auto}"
REPO_UPDATE_TIMEOUT="${TEMPORAL_HELM_REPO_UPDATE_TIMEOUT:-30s}"
CREATE_NAMESPACE="${TEMPORAL_HELM_CREATE_NAMESPACE:-auto}"

case "$TARGET" in
  local-kind|local-kind-static)
    VALUES_FILE="$ROOT_DIR/deployments/k8s/temporal/local-kind-values.yaml"
    DEFAULT_CREATE_NAMESPACE=true
    ;;
  *)
    echo "unknown Temporal install target: $TARGET" >&2
    exit 1
    ;;
esac

if [ ! -f "$VALUES_FILE" ]; then
  echo "Temporal values file not found: $VALUES_FILE" >&2
  exit 1
fi

case "$CREATE_NAMESPACE" in
  auto)
    CREATE_NAMESPACE="$DEFAULT_CREATE_NAMESPACE"
    ;;
  true|false)
    ;;
  *)
    echo "unknown TEMPORAL_HELM_CREATE_NAMESPACE mode: $CREATE_NAMESPACE" >&2
    exit 1
    ;;
esac

chart_available() {
  "$HELM_BIN" show chart "$CHART_REF" --version "$CHART_VERSION" >/dev/null 2>&1
}

repo_update() {
  if command -v timeout >/dev/null 2>&1; then
    timeout "$REPO_UPDATE_TIMEOUT" "$HELM_BIN" repo update temporal >/dev/null
  else
    "$HELM_BIN" repo update temporal >/dev/null
  fi
}

"$HELM_BIN" repo add temporal https://go.temporal.io/helm-charts >/dev/null 2>&1 || true
case "$REPO_UPDATE_MODE" in
  always)
    repo_update
    ;;
  never)
    if ! chart_available; then
      echo "Temporal chart $CHART_REF@$CHART_VERSION is not available and TEMPORAL_HELM_REPO_UPDATE=never" >&2
      exit 1
    fi
    ;;
  auto)
    if ! repo_update; then
      if chart_available; then
        echo "Temporal Helm repo update failed or timed out; using cached $CHART_REF@$CHART_VERSION" >&2
      else
        echo "Temporal Helm repo update failed or timed out and $CHART_REF@$CHART_VERSION is not cached" >&2
        exit 1
      fi
    fi
    ;;
  *)
    echo "unknown TEMPORAL_HELM_REPO_UPDATE mode: $REPO_UPDATE_MODE" >&2
    exit 1
    ;;
esac

helm_args=(
  upgrade --install "$RELEASE_NAME" "$CHART_REF"
  --kube-context "$KUBE_CONTEXT"
  --namespace "$NAMESPACE"
  --version "$CHART_VERSION"
  --values "$VALUES_FILE"
  --wait
  --timeout 10m
)

if [ "$CREATE_NAMESPACE" = true ]; then
  helm_args+=(--create-namespace)
fi

"$HELM_BIN" "${helm_args[@]}"
