#!/usr/bin/env bash
# Rebuild one binary incrementally, layer it onto the retained Kind cluster's
# image, load that image, and restart only what runs it.
#
#   KIND_CLUSTER_NAME=<cluster> scripts/dev/kind/deploy-service.sh <service>
#
# Services: idp, orchestration, credential-service, billing, coordinator, and
# daemon (the in-workspace `cw` carried by the gateway image; sandboxes created
# afterwards run it). The dashboard is served from source by `make kind-watch`
# instead. Each image is always the gate-built base plus every binary deployed
# since, so repeated deploys never stack layers; a new base from the gate or
# `up` resets it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-codewire-e2e-ci}"
SERVICE="${1:-}"
BUILDER="codewire-kind-dev"
NAMESPACE=codewire-e2e
BASE_LABEL="dev.codewire.kind-dev-base"

log() { printf '[kind-deploy] %s\n' "$*" >&2; }
die() { printf '[kind-deploy] error: %s\n' "$*" >&2; exit 1; }

image=codewire-services
crate="codewire-${SERVICE}"
bin="$crate"
destination=/
features=""
case "$SERVICE" in
  idp | billing | coordinator) ;;
  orchestration) features="kind-e2e" ;;
  credential-service) features="enrollment,kind-e2e" ;;
  daemon)
    image=codewire-gateway
    crate=codewire-cli-bin
    bin=cw
    destination=/usr/local/bin/
    ;;
  *) die "usage: $0 <idp|orchestration|credential-service|billing|coordinator|daemon>" ;;
esac
IMAGE="${image}:e2e"
BASE_IMAGE="${image}:kind-dev-base"
STATE="$ROOT/.tmp/kind-dev/${KIND_CLUSTER_NAME}"
if [ "$image" != codewire-services ]; then
  STATE="$STATE/$image"
fi

kind get clusters 2>/dev/null | grep -Fxq "$KIND_CLUSTER_NAME" \
  || die "cluster ${KIND_CLUSTER_NAME} does not exist; create it with make kind-up"
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "${IMAGE} is missing; run make kind-up first"

current="$(docker image inspect --format '{{.Id}}' "$IMAGE")"
base="$(docker image inspect --format "{{ index .Config.Labels \"${BASE_LABEL}\" }}" "$IMAGE")"
if [ -z "$base" ] || [ "$base" = "<no value>" ]; then
  base="$current"
fi
mkdir -p "$STATE/bin"
if [ "$(cat "$STATE/base" 2>/dev/null || true)" != "$base" ]; then
  log "new base image ${base:7:12}; forgetting earlier dev binaries"
  rm -f "$STATE/bin/"*
  printf '%s\n' "$base" >"$STATE/base"
fi

docker buildx inspect "$BUILDER" >/dev/null 2>&1 \
  || docker buildx create --name "$BUILDER" --driver docker-container >/dev/null
log "compiling ${crate} ${bin}${features:+ (features ${features})}"
out="$(mktemp -d "$STATE/out.XXXXXX")"
trap 'rm -rf "$out"' EXIT
KIND_DEV_CRATE="$crate" KIND_DEV_BIN="$bin" KIND_DEV_FEATURES="$features" \
  docker buildx bake --builder "$BUILDER" --file "$ROOT/docker-bake.hcl" \
    --set "kind-dev-binary.output=type=local,dest=${out}" kind-dev-binary
[ -x "$out/$bin" ] || die "the build produced no ${bin} binary"
install -m 0755 "$out/$bin" "$STATE/bin/$bin"

log "layering $(cd "$STATE/bin" && echo *) onto the base image"
docker tag "$base" "$BASE_IMAGE"
{
  printf 'FROM %s\n' "$BASE_IMAGE"
  for binary in "$STATE/bin/"*; do
    printf 'COPY %s %s%s\n' "$(basename "$binary")" "$destination" "$(basename "$binary")"
  done
  printf 'LABEL %s=%s\n' "$BASE_LABEL" "$base"
} | docker buildx build --builder default --load --quiet -t "$IMAGE" -f - "$STATE/bin" >/dev/null

log "loading ${IMAGE} into ${KIND_CLUSTER_NAME}"
kind load docker-image "$IMAGE" --name "$KIND_CLUSTER_NAME" >/dev/null
if [ "$SERVICE" = daemon ]; then
  log "sandboxes created from now on run the current daemon"
  exit 0
fi
kubectl --context "kind-${KIND_CLUSTER_NAME}" -n "$NAMESPACE" \
  rollout restart "deployment/${crate}" >/dev/null
kubectl --context "kind-${KIND_CLUSTER_NAME}" -n "$NAMESPACE" \
  rollout status "deployment/${crate}" --timeout=180s
log "${SERVICE} is running the current source"
