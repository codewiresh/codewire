#!/usr/bin/env bash
# Require all Forgejo workflows to resolve reviewed actions from local mirrors.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORKFLOWS="$ROOT/.gitea/workflows"

fail() {
  printf '[test-forgejo-action-mirrors] ERROR: %s\n' "$*" >&2
  exit 1
}

mapfile -t references < <(sed -nE 's/^[[:space:]]*-?[[:space:]]*uses:[[:space:]]+([^[:space:]]+).*$/\1/p' "$WORKFLOWS"/*.yaml)
((${#references[@]} > 0)) || fail "no action references found"

expected=(
  'https://forgejo.example.invalid/noel/actions-checkout@34e114876b0b11c390a56381ad16ebd13914f8d5'
  'https://forgejo.example.invalid/noel/actions-checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0'
  'https://forgejo.example.invalid/noel/rust-toolchain@b3b07ba8b418998c39fb20f53e8b695cdcc8de1b'
  'https://forgejo.example.invalid/noel/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6'
  'https://forgejo.example.invalid/noel/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff'
  'https://forgejo.example.invalid/noel/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020'
  'https://forgejo.example.invalid/noel/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065'
)

for reference in "${references[@]}"; do
  [[ "$reference" =~ ^https://forgejo\.example\.invalid/noel/[a-z0-9-]+@[0-9a-f]{40}$ ]] ||
    fail "workflow action is not one exact local Forgejo commit"
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
