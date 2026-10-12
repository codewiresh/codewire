#!/usr/bin/env bash
# Rebuild one binary incrementally, layer it onto the retained Kind cluster's
# image, load that image, and restart only what runs it.
#
#   KIND_CLUSTER_NAME=<cluster> scripts/dev/kind/deploy-service.sh <service>
#
# Services: idp, orchestration, credential-service, billing, coordinator, mesh,
# dashboard (what the cluster ingress serves, so `make kind-test` exercises the
# current dashboard source; `make kind-watch` serves it for review), and daemon
# (the in-workspace `cw` carried by the daemon image; sandboxes created
# afterwards run it). Each image is always the gate-built base plus every
# binary deployed since, so repeated deploys never stack layers; a new base
# from the gate or `up` resets it. credential-service also rebuilds the
# synthetic fixture (/codewire-kind-fixtures/credential-service) that the
# gate's fake credential mode runs, so both modes run the current source.
#
# Each deploy records on the Deployment that runs the binary the digest of the
# source it was built from (scripts/dev/kind/service-sources.py) and the image
# its Pods then run. KIND_DEPLOY_SKIP_CURRENT=1 (what `make kind-test` uses)
# skips the build when the cluster still runs exactly that: an unchanged
# digest and the recorded image. KIND_DEPLOY_RECORD_ONLY=1 builds nothing and
# records the running image as this tree's source; a new retained cluster does
# that for the images it was just built from.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=scripts/dev/kind/profile.sh
source "$ROOT/scripts/dev/kind/profile.sh"
kind_profile_load "$ROOT" || exit $?
# shellcheck source=scripts/ci/verify/kind/credentials.sh
source "$ROOT/scripts/ci/verify/kind/credentials.sh"
# shellcheck source=scripts/dev/kind/dev-builder.sh
source "$ROOT/scripts/dev/kind/dev-builder.sh"
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
fixture=""
fixture_features=""
case "$SERVICE" in
  idp | billing | coordinator) ;;
  mesh)
    image=codewire-mesh
    destination=/usr/local/bin/
    ;;
  orchestration) features="kind-e2e" ;;
  credential-service)
    features="enrollment,kind-e2e"
    # Built exactly as services.Dockerfile builds the fake-mode fixture.
    fixture="credential-service"
    fixture_features=enrollment,kind-e2e
    ;;
  dashboard)
    image=codewire-dashboard
    crate=codewire-dashboard-web
    bin="$crate"
    destination=/srv/codewire/
    ;;
  daemon)
    image=codewire-daemon
    crate=codewire-cli-bin
    bin=cw
    destination=/usr/local/bin/
    ;;
  *) die "usage: $0 <idp|orchestration|credential-service|billing|coordinator|mesh|dashboard|daemon>" ;;
esac
deployment="codewire-${SERVICE}"
if [ "$SERVICE" = daemon ]; then
  # The renderer reads this Deployment environment for future sandboxes.
  # Loading a new tag alone would leave it using the original daemon image.
  deployment=codewire-orchestration
fi
IMAGE="${image}:e2e"
STATE="$ROOT/.tmp/kind-dev/${KIND_CLUSTER_NAME}"
if [ "$image" != codewire-services ]; then
  STATE="$STATE/$image"
fi
if [ "$KIND_PROFILE" = 1 ]; then
  kind_profile_lock "$ROOT" || exit $?
  kind_profile_verify_node "$ROOT" || exit $?
  kind_profile_verify_artifacts "$ROOT" || exit $?
  BUILDER="${KIND_PROFILE_IMAGE_PREFIX}-dev"
  STATE="$(dirname "$KIND_PROFILE_PATH")/dev/$image"
fi

kind get clusters 2>/dev/null | grep -Fxq "$KIND_CLUSTER_NAME" \
  || die "cluster ${KIND_CLUSTER_NAME} does not exist; create it with make kind-up"
kube() { kubectl --context "kind-${KIND_CLUSTER_NAME}" -n "$NAMESPACE" "$@"; }
RECORD_KEY="dev.codewire.kind-dev/source-${SERVICE}"

source_digest() {
  local digest
  digest="$(python3 -B "$ROOT/scripts/dev/kind/service-sources.py" digest "$SERVICE")" || return 0
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 0
  # The build parameters belong to the binary as much as its source.
  printf '%s %s %s %s\n' "$digest" "$crate" "$features" "$fixture_features" | sha256sum | cut -c1-64
}

# What the cluster runs for this service now: the daemon image future
# sandboxes get, or the one image ID every live Pod of the Deployment reports.
running_identity() {
  local ids selector
  if [ "$SERVICE" = daemon ]; then
    if [ "$KIND_PROFILE" = 1 ]; then
      kube get "deployment/${deployment}" \
        -o 'jsonpath={.spec.template.spec.containers[?(@.name=="orchestration")].env[?(@.name=="SANDBOX_DAEMON_IMAGE")].value}'
    else
      docker image inspect --format '{{.Id}}' "$IMAGE"
    fi
    return
  fi
  selector="$(deployment_selector)" || return 1
  # shellcheck disable=SC2016 # a Go template, expanded by kubectl
  ids="$(kube get pods -l "$selector" -o go-template='{{range .items}}{{if not .metadata.deletionTimestamp}}{{range .status.containerStatuses}}{{.imageID}}{{"\n"}}{{end}}{{end}}{{end}}' \
    | sort -u)" || return $?
  # A Deployment scaled to zero (Mesh until a suite needs it) runs nothing.
  if [ -z "$ids" ]; then
    printf 'none\n'
  elif [ "$(wc -l <<<"$ids")" = 1 ]; then
    printf '%s\n' "$ids"
  fi
}

# Record what the cluster now runs for this service, only when the source did
# not change meanwhile and its Pods agree on one image.
record_deploy() {
  local identity
  [ -n "$digest" ] && [ "$(source_digest)" = "$digest" ] || return 1
  identity="$(running_identity)" && [ -n "$identity" ] || return 1
  kube annotate --overwrite "deployment/${deployment}" "${RECORD_KEY}=${digest} ${identity}" >/dev/null
}

deployment_selector() {
  local selector
  # shellcheck disable=SC2016 # a Go template, expanded by kubectl
  selector="$(kube get "deployment/${deployment}" \
    -o go-template='{{range $k, $v := .spec.selector.matchLabels}}{{$k}}={{$v}},{{end}}')" || return $?
  [ -n "$selector" ] || die "deployment/${deployment} has no label selector"
  printf '%s\n' "${selector%,}"
}

digest="$(source_digest)"
[ -n "$digest" ] || log 'cannot compute the source digest; this deploy will not be recorded'
if [ "${KIND_DEPLOY_RECORD_ONLY:-0}" = 1 ]; then
  record_deploy || die "cannot record ${SERVICE}: no source digest, or its Pods run more than one image"
  log "recorded ${SERVICE}'s running image as this tree's source (${digest:0:12})"
  exit 0
fi
if [ "${KIND_DEPLOY_SKIP_CURRENT:-0}" = 1 ] && [ -n "$digest" ]; then
  recorded="$(kube get "deployment/${deployment}" -o "go-template={{index .metadata.annotations \"${RECORD_KEY}\"}}" 2>/dev/null || true)"
  identity="$(running_identity 2>/dev/null || true)"
  if [ -n "$identity" ] && [ "$recorded" = "${digest} ${identity}" ]; then
    log "${SERVICE} already runs this tree's source (${digest:0:12}); not rebuilding"
    exit 0
  fi
fi
if [ "$KIND_PROFILE" = 1 ]; then
  base="$(kind_profile_image_base "$image")" || exit $?
  current="$(docker image inspect --format '{{.Id}}' "$base")" \
    || die 'the sealed product base is missing from this Docker daemon; import the selected profile artifacts first'
  [ "$current" = "$base" ] || die 'the Docker product base differs from its saved identity'
else
  docker image inspect "$IMAGE" >/dev/null 2>&1 || die "${IMAGE} is missing; run make kind-up first"
  current="$(docker image inspect --format '{{.Id}}' "$IMAGE")"
  base="$(docker image inspect --format "{{ index .Config.Labels \"${BASE_LABEL}\" }}" "$IMAGE")"
  if [ -z "$base" ] || [ "$base" = "<no value>" ]; then
    base="$current"
  fi
fi
[[ "$base" =~ ^sha256:[0-9a-f]{64}$ ]] || die 'the product base is not one exact Docker image ID'
umask 077
kind_profile_private_dir "$STATE/bin" || exit $?
kind_profile_private_dir "$STATE/fixtures" || exit $?
[ ! -L "$STATE" ] && [ ! -L "$STATE/bin" ] && [ ! -L "$STATE/fixtures" ] \
  || die 'dev binary state must not be a symlink'
mkdir -p "$STATE/bin" "$STATE/fixtures"
if [ -e "$STATE/base" ] || [ -L "$STATE/base" ]; then
  [ -f "$STATE/base" ] && [ ! -L "$STATE/base" ] \
    && [ "$(stat -c '%h' "$STATE/base")" = 1 ] || die 'dev base state must be one regular owned file'
fi
for binary in "$STATE/bin/"*; do
  [ -e "$binary" ] || [ -L "$binary" ] || continue
  [ -f "$binary" ] && [ ! -L "$binary" ] || die 'dev binary state contains an unowned file'
  if [ "$KIND_PROFILE" = 1 ]; then
    [ "$(stat -c '%u:%h' "$binary")" = "$(id -u):1" ] \
      || die 'dev binary state contains a foreign or multiply linked file'
  fi
  case "${binary##*/}" in
    codewire-idp|codewire-billing|codewire-coordinator|codewire-orchestration|\
    codewire-credential-service|codewire-mesh|codewire-dashboard-web|cw) ;;
    *) die 'dev binary state contains an unknown binary' ;;
  esac
done
for fixture_file in "$STATE/fixtures/"*; do
  [ -e "$fixture_file" ] || [ -L "$fixture_file" ] || continue
  [ -f "$fixture_file" ] && [ ! -L "$fixture_file" ] \
    || die 'dev fixture state contains an unowned file'
  if [ "$KIND_PROFILE" = 1 ]; then
    [ "$(stat -c '%u:%h' "$fixture_file")" = "$(id -u):1" ] \
      || die 'dev fixture state contains a foreign or multiply linked file'
  fi
  [ "${fixture_file##*/}" = credential-service ] || die 'dev fixture state contains an unknown fixture'
done
if [ "$(cat "$STATE/base" 2>/dev/null || true)" != "$base" ]; then
  log "new base image ${base:7:12}; forgetting earlier dev binaries"
  rm -f "$STATE/bin/"* "$STATE/fixtures/"*
  printf '%s\n' "$base" >"$STATE/base"
fi

BUILDER="$(kind_dev_builder "$BUILDER" "$STATE")"
log "compiling ${crate} ${bin}${features:+ (features ${features})}${fixture:+ and the ${fixture} fixture}"
out="$(mktemp -d "$STATE/out.XXXXXX")"
trap 'rm -rf "$out"' EXIT
tree="$(kind_dev_tree "$ROOT")"
# Bake resolves the build context against the working directory, not the bake
# file: build this worktree's source into this worktree's target.
(cd "$ROOT" && KIND_DEV_CRATE="$crate" KIND_DEV_BIN="$bin" KIND_DEV_FEATURES="$features" \
  docker buildx bake --builder "$BUILDER" --file "$ROOT/docker-bake.hcl" \
    --set "kind-dev-binary.args.KIND_DEV_TREE=${tree}" \
    --set "kind-dev-binary.args.KIND_DEV_FIXTURE_FEATURES=${fixture_features}" \
    --set "kind-dev-binary.output=type=local,dest=${out}" kind-dev-binary)
[ -x "$out/$bin" ] || die "the build produced no ${bin} binary"
install -m 0755 "$out/$bin" "$STATE/bin/$bin"
if [ -n "$fixture" ]; then
  [ -x "$out/kind-fixtures/$bin" ] || die "the build produced no ${fixture} fixture"
  install -m 0755 "$out/kind-fixtures/$bin" "$STATE/fixtures/$fixture"
fi

shopt -s nullglob
fixtures=("$STATE/fixtures/"*)
shopt -u nullglob
log "layering $(cd "$STATE/bin" && echo *)${fixtures[*]:+ and fixtures $(cd "$STATE/fixtures" && echo *)} onto the base image"
if [ "$KIND_PROFILE" = 1 ]; then
  content="$( {
    printf '%s\n' "$base"
    sha256sum "$STATE/bin/"*
    if [ "${#fixtures[@]}" -gt 0 ]; then
      sha256sum "${fixtures[@]}"
    fi
  } | sha256sum)"
  content="${content%% *}"
  IMAGE="${KIND_PROFILE_IMAGE_PREFIX}-${image#codewire-}:dev-${content}"
  BASE_IMAGE="${KIND_PROFILE_IMAGE_PREFIX}-${image#codewire-}:base-${base#sha256:}"
else
  BASE_IMAGE="${image}:kind-dev-base-${base#sha256:}"
fi
if docker image inspect "$BASE_IMAGE" >/dev/null 2>&1; then
  [ "$(docker image inspect --format '{{.Id}}' "$BASE_IMAGE")" = "$base" ] \
    || die 'source-qualified base alias names a different image'
else
  docker tag "$base" "$BASE_IMAGE"
fi
{
  printf 'FROM %s\n' "$BASE_IMAGE"
  for binary in "$STATE/bin/"*; do
    printf 'COPY %s %s%s\n' "$(basename "$binary")" "$destination" "$(basename "$binary")"
  done
  for binary in "${fixtures[@]}"; do
    printf 'COPY --from=fixtures %s /codewire-kind-fixtures/%s\n' "$(basename "$binary")" "$(basename "$binary")"
  done
  printf 'LABEL %s=%s\n' "$BASE_LABEL" "$base"
} | docker buildx build --builder default --load --quiet -t "$IMAGE" -f - \
  --build-context "fixtures=$STATE/fixtures" "$STATE/bin" >/dev/null

log "loading ${IMAGE} into ${KIND_CLUSTER_NAME}"
kind load docker-image "$IMAGE" --name "$KIND_CLUSTER_NAME" >/dev/null
# Republish the synthetic trust roots before anything restarts, so a cluster
# past its 72-hour root renewal still trusts the leaves its services present.
publish_kind_trust_roots --context "kind-${KIND_CLUSTER_NAME}"

unrecorded() { log "${SERVICE}'s source or running image changed meanwhile; this deploy is not recorded"; }
if [ "$SERVICE" = daemon ] && [ "$KIND_PROFILE" != 1 ]; then
  record_deploy || unrecorded
  log "sandboxes created from now on run the current daemon"
  exit 0
fi
# A rollout reports done while the previous pods are still terminating and can
# still answer requests; wait for them to go so the next request, such as
# `make kind-test`, reaches the current source.
selector="$(deployment_selector)"
previous="$(kube get pods -l "$selector" -o name)"
if [ "$KIND_PROFILE" = 1 ]; then
  if [ "$SERVICE" = daemon ]; then
    current_image="$(kube get "deployment/${deployment}" \
      -o 'jsonpath={.spec.template.spec.containers[?(@.name=="orchestration")].env[?(@.name=="SANDBOX_DAEMON_IMAGE")].value}')"
    kube set env "deployment/${deployment}" --containers=orchestration "SANDBOX_DAEMON_IMAGE=$IMAGE" >/dev/null
  else
    current_image="$(kube get "deployment/${deployment}" \
      -o "jsonpath={.spec.template.spec.containers[?(@.name==\"${SERVICE}\")].image}")"
    kube set image "deployment/${deployment}" "${SERVICE}=$IMAGE" >/dev/null
  fi
  # A changed image/env already starts one rollout. An identical repeated
  # deployment still needs a restart before waiting for the captured old Pods.
  if [ "$current_image" = "$IMAGE" ]; then
    kube rollout restart "deployment/${deployment}" >/dev/null
  fi
else
  kube rollout restart "deployment/${deployment}" >/dev/null
fi
kube rollout status "deployment/${deployment}" --timeout=180s
if [ -n "$previous" ]; then
  # shellcheck disable=SC2086 # one argument for each captured Pod
  kube wait --for=delete $previous --timeout=120s >/dev/null
fi
record_deploy || unrecorded
if [ "$SERVICE" = daemon ]; then
  log 'sandboxes created from now on run the current daemon'
fi
log "${SERVICE} is running the current source"
