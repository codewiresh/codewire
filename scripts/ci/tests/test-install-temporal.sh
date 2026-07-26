#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for target in dev prod production; do
  output="$work/$target.out"
  if HELM_BIN=/bin/echo \
      "$ROOT/scripts/dev/kind/install-temporal.sh" "$target" >"$output" 2>&1; then
    printf 'non-local Temporal target unexpectedly succeeded: %s\n' "$target" >&2
    exit 1
  fi
  grep -Fq "unknown Temporal install target: $target" "$output"
  if grep -Eq '^(repo|upgrade) ' "$output"; then
    printf 'non-local Temporal target invoked Helm: %s\n' "$target" >&2
    exit 1
  fi
done

mkdir -p "$work/non-root"
values_file="$ROOT/deployments/k8s/temporal/local-kind-values.yaml"
[ -f "$values_file" ]
for target in local-kind local-kind-static; do
  output="$work/$target.out"
  (
    cd "$work/non-root"
    HELM_BIN=/bin/echo \
      TEMPORAL_HELM_REPO_UPDATE=always \
      "$ROOT/scripts/dev/kind/install-temporal.sh" "$target"
  ) >"$output" 2>&1

  grep -Fq \
    "upgrade --install temporal temporal/temporal --kube-context kind-codewire --namespace temporal-system --version 1.0.0 --values $values_file --wait --timeout 10m --create-namespace" \
    "$output"
done

printf 'Temporal installer target guard passed\n'
