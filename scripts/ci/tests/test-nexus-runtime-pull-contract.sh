#!/usr/bin/env bash
# Keep live CodeWire Flux inputs on the infra-owned OpenBao Nexus pull Secret.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

fail() {
  printf '[test-nexus-runtime-pull-contract] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ ! -e "$ROOT/deployments/k8s/base/registry-secret.yaml" ]] ||
  fail "legacy application-owned registry secret generator remains"

render_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-nexus-pull.XXXXXX")"
cleanup() {
  rm -rf -- "$render_dir"
}
trap cleanup EXIT

for environment in dev production; do
  output="$render_dir/$environment.yaml"
  kubectl kustomize "$ROOT/deployments/k8s/overlays/$environment" >"$output"
  grep -Fq 'name: nexus-registry' "$output" ||
    fail "$environment render does not consume nexus-registry"
  if grep -Eq 'gitea-registry|GITEA_REGISTRY_TOKEN' "$output"; then
    fail "$environment render retains legacy Gitea credential ownership"
  fi
done

for mesh in \
  "$ROOT/deployments/k8s/flux/mesh-dev/helmrelease.yaml" \
  "$ROOT/deployments/k8s/flux/production/mesh-helmrelease.yaml"; do
  grep -Fq '      - name: nexus-registry' "$mesh" ||
    fail "$mesh does not consume nexus-registry"
done

smoke="$ROOT/scripts/runtime/dev/smoke-dev-candidate.sh"
grep -Fq 'wait --for=create secret/nexus-registry' "$smoke" ||
  fail "sandbox smoke does not wait for the cloned Nexus secret"
grep -Fq 'imagePullSecrets":[{"name":"nexus-registry"}]' "$smoke" ||
  fail "sandbox ServiceAccount does not select nexus-registry"

printf '[test-nexus-runtime-pull-contract] OpenBao Nexus pull boundary accepted\n'
