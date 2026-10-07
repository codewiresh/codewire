#!/usr/bin/env bash
# Keep live CodeWire Flux inputs and the Dev sandbox smoke on the infra-owned
# Harbor pull Secret, and on no other registry credential.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly PULL_SECRET='harbor-registry'

fail() {
  printf '[test-harbor-runtime-pull-contract] ERROR: %s\n' "$*" >&2
  exit 1
}

# Print every imagePullSecrets entry name in a YAML stream, one per line.
pull_secret_names() {
  awk '
    /^[[:space:]]*imagePullSecrets:[[:space:]]*$/ { in_list = 1; next }
    in_list && /^[[:space:]]*- name:[[:space:]]*/ {
      sub(/^[[:space:]]*- name:[[:space:]]*/, "")
      print
      next
    }
    { in_list = 0 }
  ' "$1"
}

# Require at least one imagePullSecrets entry, all of them the Harbor Secret.
require_harbor_only() {
  local source="$1" label="$2" names
  names="$(pull_secret_names "$source")"
  [[ -n "$names" ]] || fail "$label lists no imagePullSecrets"
  if grep -vxF "$PULL_SECRET" <<<"$names" >/dev/null; then
    fail "$label lists a pull Secret other than $PULL_SECRET"
  fi
}

[[ ! -e "$ROOT/deployments/k8s/base/registry-secret.yaml" ]] ||
  fail "legacy application-owned registry secret generator remains"

render_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-harbor-pull.XXXXXX")"
cleanup() {
  rm -rf -- "$render_dir"
}
trap cleanup EXIT

for environment in dev production; do
  output="$render_dir/$environment.yaml"
  kubectl kustomize "$ROOT/deployments/k8s/overlays/$environment" >"$output"
  require_harbor_only "$output" "$environment render"
  if grep -Eq 'gitea-registry|GITEA_REGISTRY_TOKEN' "$output"; then
    fail "$environment render retains legacy Gitea credential ownership"
  fi
done

for mesh in \
  "$ROOT/deployments/k8s/flux/mesh-dev/helmrelease.yaml" \
  "$ROOT/deployments/k8s/flux/production/mesh-helmrelease.yaml" \
  "$ROOT/deployments/k8s/mesh-dev/values.yaml"; do
  require_harbor_only "$mesh" "${mesh#"$ROOT"/}"
done

smoke="$ROOT/scripts/runtime/dev/smoke-dev-candidate.sh"
grep -Fq "wait --for=create secret/$PULL_SECRET" "$smoke" ||
  fail "sandbox smoke does not wait for the cloned Harbor secret"
grep -Fq "imagePullSecrets\":[{\"name\":\"$PULL_SECRET\"}]" "$smoke" ||
  fail "sandbox ServiceAccount does not select $PULL_SECRET"
grep -Fq ".name == \"$PULL_SECRET\"" "$smoke" ||
  fail "existing sandbox ServiceAccount is not checked for $PULL_SECRET"
if grep -Eo 'secret/[a-z0-9-]+|get secret [a-z0-9-]+|\.name == "[a-z0-9-]+"' "$smoke" |
    grep -Ev "(/| |\")${PULL_SECRET}\"?\$" >/dev/null; then
  fail "sandbox smoke names a pull Secret other than $PULL_SECRET"
fi

printf '[test-harbor-runtime-pull-contract] Harbor pull boundary accepted\n'
