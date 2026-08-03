#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
EXPECTED_SOURCE='4c528d3940ac5eb7c0194ce537fc4f4067417c72'
EXPECTED_IMAGE='ghcr.io/noeljackson/agent-sandbox-controller@sha256:555146af2337dd5d8baf0844d7f5de9a3cd8fc7b032b85756ae244bc2583fb41'

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
c1c8816327ee2d854ad60613159321276f9c8840a0acd71a8a56d56bd1fc5a53  deployments/k8s/agent-sandbox/base/crds/agents.x-k8s.io_sandboxes.yaml
586afb7916fda14a9e970faa619b1382a746478ee5ac1703c840c49156ec1e26  deployments/k8s/agent-sandbox/base/crds/extensions.agents.x-k8s.io_sandboxclaims.yaml
21390687cb23996853ebda698a07337132b34786dfc5b4da9a691d8409c18d13  deployments/k8s/agent-sandbox/base/rbac.generated.yaml
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
