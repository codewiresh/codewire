#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

readonly workspace_image='ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467'
readonly dind_image='docker.io/library/docker:29.7.1-dind@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c'
readonly dashboard_runtime='gcr.io/distroless/cc-debian12:nonroot@sha256:fccdbb0a547c14e23fcf4ce8ad62ca5d43b4faae8d22cd292f490fef9946c96e'
readonly dashboard_dockerfile='apps/dashboard/Dockerfile'

fail=0

if moving_workspace="$(git grep -nF 'ghcr.io/codewiresh/workspace:latest' -- \
    ':!docs/**' ':!scripts/checks/security/audit-runtime-images.sh' || true)" \
  && [[ -n "$moving_workspace" ]]; then
  echo "runtime image audit: moving canonical workspace references are forbidden" >&2
  echo "$moving_workspace" >&2
  fail=1
fi
if moving_dind="$(git grep -nF 'docker:dind' -- \
    ':!docs/**' ':!scripts/checks/security/audit-runtime-images.sh' || true)" \
  && [[ -n "$moving_dind" ]]; then
  echo "runtime image audit: upstream moving DinD references are forbidden" >&2
  echo "$moving_dind" >&2
  fail=1
fi
if retired_dind="$(git grep -nF 'ghcr.io/codewiresh/dind' -- \
    ':!docs/**' ':!scripts/checks/security/audit-runtime-images.sh' || true)" \
  && [[ -n "$retired_dind" ]]; then
  echo "runtime image audit: retired custom DinD references are forbidden" >&2
  echo "$retired_dind" >&2
  fail=1
fi

for assertion in \
  "crates/codewire-orchestration/src/sandbox/mod.rs:$workspace_image" \
  "crates/codewire-orchestration/src/api/detect.rs:$workspace_image" \
  "crates/codewire-cli/src/commands/collaboration.rs:$workspace_image" \
  "crates/codewire-orchestration/src/sandbox/template.rs:$dind_image"; do
  path="${assertion%%:*}"
  expected="${assertion#*:}"
  if ! grep -Fq "$expected" "$path"; then
    echo "runtime image audit: canonical runtime default is missing from $path" >&2
    fail=1
  fi
done

if ! grep -Fq 'request.image = CANONICAL_WORKSPACE_IMAGE.to_string();' \
    crates/codewire-cli/src/commands/environment.rs; then
  echo "runtime image audit: platform create no longer consumes the canonical workspace default" >&2
  fail=1
fi

while IFS= read -r declaration; do
  [[ -z "$declaration" ]] && continue
  value="${declaration#*=}"
  if [[ ! "$value" =~ @sha256:[0-9a-f]{64}$ ]]; then
    echo "runtime image audit: dashboard build image is not digest-pinned: $declaration" >&2
    fail=1
  fi
done < <(sed -nE '/^ARG [A-Z_]+_IMAGE=/p' "$dashboard_dockerfile")

if ! grep -Fq "ARG RUNTIME_IMAGE=$dashboard_runtime" "$dashboard_dockerfile"; then
  echo "runtime image audit: dashboard runtime digest drifted from the accepted inventory" >&2
  fail=1
fi
if ! grep -Fq 'cargo metadata --locked --offline --no-deps --format-version 1' \
    "$dashboard_dockerfile"; then
  echo "runtime image audit: dashboard metadata collection must stay locked, offline, and dependency-free" >&2
  fail=1
fi
if ! grep -Fq 'docker buildx build --pull --load --tag "$(DASHBOARD_VERIFY_IMAGE)" -f apps/dashboard/Dockerfile .' \
    Makefile; then
  echo "runtime image audit: dashboard verification must load the exact Buildx result before inspection" >&2
  fail=1
fi
for inventory in \
    'usr/share/codewire/Cargo.lock' \
    'usr/share/codewire/rust-workspace-metadata.json' \
    'usr/share/codewire/runtime-files.sha256'; do
  if ! grep -Fq "$inventory" scripts/ci/verify/dashboard-image.sh; then
    echo "runtime image audit: final-image verifier does not require $inventory" >&2
    fail=1
  fi
done
if ! jq -e --arg runtime "$dashboard_runtime" '
  .schema_version == 1 and
  .runtime.base == $runtime and
  .runtime.uid == 65532 and
  .runtime.gid == 65532 and
  (.forbidden | index("node") != null) and
  (.forbidden | index("shell") != null) and
  (.forbidden | index("zola") != null)
' apps/dashboard/runtime-inventory.json >/dev/null; then
  echo "runtime image audit: invalid dashboard runtime inventory" >&2
  fail=1
fi

if ! grep -Eq 'newTag: main-[0-9a-f]{7,40}-[0-9]+' deployments/k8s/overlays/dev/kustomization.yaml; then
  echo "runtime image audit: dev dashboard source is not an immutable source tag" >&2
  fail=1
fi
if ! awk '
  /name: git\.example\.com\/codewire\/dashboard/ { dashboard = 1; next }
  dashboard && /digest: sha256:[0-9a-f]{64}/ { found = 1; exit }
  dashboard && /name: / { exit }
  END { exit found ? 0 : 1 }
' deployments/k8s/overlays/production/kustomization.yaml; then
  echo "runtime image audit: production dashboard render input lacks an exact digest" >&2
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi

echo "runtime image audit: OK"
