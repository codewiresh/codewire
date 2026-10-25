#!/usr/bin/env bash
# Require all Forgejo workflows to resolve reviewed actions from local mirrors.
# A short noel/<mirror>@<full SHA> reference resolves on the job's own Forgejo,
# whose [actions] DEFAULT_ACTIONS_URL is self (docs/dev/CI-CONFIGURATION.md),
# so no workflow names the forge host.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORKFLOWS="$ROOT/.gitea/workflows"

fail() {
  printf '[test-forgejo-action-mirrors] ERROR: %s\n' "$*" >&2
  exit 1
}

mapfile -t references < <(
  sed -nE 's/^[[:space:]]*-?[[:space:]]*uses:[[:space:]]+([^[:space:]]+).*$/\1/p' \
    "$WORKFLOWS"/*.yaml "$WORKFLOWS"/*.yml
)
((${#references[@]} > 0)) || fail "no action references found"

expected=(
  'noel/actions-checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'
  'noel/actions-upload-artifact@c6a366c94c3e0affe28c06c8df20a878f24da3cf'
  'noel/actions-download-artifact@a9bc5e6ef2cb54c177f32aa5726adaa15e7e2d59'
  'noel/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6'
)

for reference in "${references[@]}"; do
  [[ "$reference" =~ ^noel/[a-z0-9-]+@[0-9a-f]{40}$ ]] ||
    fail "workflow action is not one exact short mirror reference: $reference"
  accepted=false
  for approved in "${expected[@]}"; do
    if [[ "$reference" == "$approved" ]]; then
      accepted=true
      break
    fi
  done
  [[ "$accepted" == true ]] || fail "workflow action is outside the reviewed mirror set"
done

for approved in "${expected[@]}"; do
  used=false
  for reference in "${references[@]}"; do
    if [[ "$reference" == "$approved" ]]; then
      used=true
      break
    fi
  done
  [[ "$used" == true ]] ||
    fail "reviewed action pin is unexpectedly unused: $approved"
done

printf '[test-forgejo-action-mirrors] local full-SHA action boundary accepted\n'
