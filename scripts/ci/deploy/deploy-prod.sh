#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/ci/deploy/deploy-prod.sh --render-only <tag-or-sha> [output-dir]

The --render-only mode writes the production Codewire, DERP, and Mesh manifests
for the exact Gitea-built image tag without configuring kubeconfig or touching
the cluster. Direct production mutation is retired; signed release tags are
promoted atomically through the deploy repository and reconciled by Flux.
EOF
}

RENDER_OUT_DIR=""
case "${1:-}" in
  --help|-h)
    usage
    exit 0
    ;;
  --render-only)
    shift
    if [ -z "${1:-}" ]; then
      usage >&2
      exit 1
    fi
    DEPLOY_TAG="$1"
    shift
    RENDER_OUT_DIR="${1:-}"
    ;;
  *)
    usage >&2
    echo "direct production mutation is retired; use --render-only or the signed aggregate release workflow" >&2
    exit 2
    ;;
esac

: "${REGISTRY_HOST:?REGISTRY_HOST is required}"

deploy_tag_slug() {
  local value="$1"
  local max_len="${2:-64}"
  printf '%s' "$value" |
    tr '[:upper:]' '[:lower:]' |
    tr -cs 'a-z0-9-' '-' |
    sed 's/^-//; s/-$//' |
    cut -c1-"$max_len"
}

render_prod_manifests() {
  local out_dir="$1"
  local tmp_dir
  local bad=0

  if [ -z "$out_dir" ]; then
    out_dir="/tmp/codewire-prod-rc-$(deploy_tag_slug "$DEPLOY_TAG" 40)"
  fi

  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' RETURN

  mkdir -p "$out_dir"
  cp -a deployments "$tmp_dir/deployments"

  (
    cd "$tmp_dir/deployments/k8s/overlays/production"
    kustomize edit set image \
      "git.example.com/codewire/services=${REGISTRY_HOST}/codewire/services:${DEPLOY_TAG}"
    sed -i "s|^  SANDBOX_DAEMON_IMAGE:.*|  SANDBOX_DAEMON_IMAGE: ${REGISTRY_HOST}/codewire/daemon:${DEPLOY_TAG}|" config-images.yaml
    kubectl kustomize . > "$out_dir/production.yaml"
  )

  (
    cd "$tmp_dir/deployments/k8s/derp"
    kustomize edit set image \
      "git.example.com/codewire/derp=${REGISTRY_HOST}/codewire/derp:${DEPLOY_TAG}"
    kubectl kustomize . > "$out_dir/derp.yaml"
  )

  helm template codewire-mesh apps/cli/charts/codewire-mesh \
    --namespace prod \
    -f "$tmp_dir/deployments/k8s/mesh-production/values.yaml" \
    --set "image.repository=${REGISTRY_HOST}/codewire/mesh" \
    --set "image.tag=${DEPLOY_TAG}" \
    --set-string "image.digest=" \
    > "$out_dir/mesh.yaml"

  {
    printf 'tag=%s\n' "$DEPLOY_TAG"
    printf 'registry=%s\n' "$REGISTRY_HOST"
    printf 'services=%s/codewire/services:%s\n' "$REGISTRY_HOST" "$DEPLOY_TAG"
    printf 'daemon=%s/codewire/daemon:%s\n' "$REGISTRY_HOST" "$DEPLOY_TAG"
    printf 'derp=%s/codewire/derp:%s\n' "$REGISTRY_HOST" "$DEPLOY_TAG"
    printf 'mesh=%s/codewire/mesh:%s\n' "$REGISTRY_HOST" "$DEPLOY_TAG"
  } > "$out_dir/images.env"

  if grep -REn 'codewire-server|WORKER_ENABLED|WORKER_URL' "$out_dir"; then
    bad=1
  fi
  if grep -REn 'git\.example\.com/codewire/(services|daemon|derp)|codewire/(services|daemon|derp|mesh):latest' "$out_dir"; then
    bad=1
  fi
  if [ "$bad" != "0" ]; then
    echo "rendered production release-candidate manifests contain rejected runtime or image references" >&2
    exit 1
  fi

  printf 'rendered production release-candidate manifests to %s\n' "$out_dir"
}

render_prod_manifests "$RENDER_OUT_DIR"
