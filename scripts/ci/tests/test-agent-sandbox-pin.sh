#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
EXPECTED_SOURCE='aacf9ba1069569da19cf4f6af5c4e83c0ae6a308'
EXPECTED_IMAGE='ghcr.io/noeljackson/agent-sandbox-controller@sha256:199efbb13e4af3fff69eaba218e5d36d3103568b2fa73e8606e7ad7da8c28609'

actual_source="$(awk '/AGENT_SANDBOX_SHA:/ {print $2; exit}' "$ROOT/.gitea/workflows/ci.yaml")"
if [ "$actual_source" != "$EXPECTED_SOURCE" ]; then
  echo "agent-sandbox source pin drifted: expected $EXPECTED_SOURCE, got ${actual_source:-missing}" >&2
  exit 1
fi

actual_image="$(awk '/^[[:space:]]*image: ghcr.io\/noeljackson\/agent-sandbox-controller@sha256:/ {print $2; exit}' \
  "$ROOT/deployments/k8s/agent-sandbox/base/controller.yaml")"
if [ "$actual_image" != "$EXPECTED_IMAGE" ]; then
  echo "agent-sandbox image pin drifted: expected $EXPECTED_IMAGE, got ${actual_image:-missing}" >&2
  exit 1
fi

expected_manifests="$(cat <<'EOF'
0043f26d89cd76e74ad32d4c58e09011e5c5cf9d40063787662602696bbf3f79  deployments/k8s/agent-sandbox/base/crds/agents.x-k8s.io_sandboxes.yaml
68de77fe0e3d4170b5009866ab506c0d4e4ff0a73d20de7b4c777807c31b17d8  deployments/k8s/agent-sandbox/base/crds/extensions.agents.x-k8s.io_sandboxclaims.yaml
0f7981df269b7359e4f23167ca4f425e54aa9505cd846b79bdec70b38465778a  deployments/k8s/agent-sandbox/base/rbac.generated.yaml
EOF
)"
actual_manifests="$(
  cd "$ROOT"
  sha256sum \
    deployments/k8s/agent-sandbox/base/crds/agents.x-k8s.io_sandboxes.yaml \
    deployments/k8s/agent-sandbox/base/crds/extensions.agents.x-k8s.io_sandboxclaims.yaml \
    deployments/k8s/agent-sandbox/base/rbac.generated.yaml
)"
if [ "$actual_manifests" != "$expected_manifests" ]; then
  echo 'vendored agent-sandbox CRD/RBAC content does not match the pinned source revision' >&2
  diff -u <(printf '%s\n' "$expected_manifests") <(printf '%s\n' "$actual_manifests") >&2 || true
  exit 1
fi

echo 'agent-sandbox source, image, CRD, and RBAC pins: OK'
