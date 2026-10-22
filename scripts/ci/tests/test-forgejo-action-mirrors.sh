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
  'noel/actions-checkout@34e114876b0b11c390a56381ad16ebd13914f8d5'
  'noel/actions-checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0'
  'noel/actions-checkout@11bd71901bbe5b1630ceea73d27597364c9af683'
  'noel/actions-upload-artifact@c6a3b2bd78b3985e4b2f15397fec357f0fd808de'
  'noel/actions-download-artifact@ad191675b41f6a5b46da9a048cb6893812da158b'
  'noel/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6'
  'noel/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020'
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
