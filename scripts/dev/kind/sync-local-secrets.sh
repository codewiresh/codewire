#!/usr/bin/env bash
set -euo pipefail

case "$-" in
  *x*)
    printf '[local-secrets] ERROR: shell tracing must be disabled\n' >&2
    exit 1
    ;;
esac

readonly kube_context="${KUBE_CONTEXT:-kind-codewire}"
readonly kube_namespace="${KUBE_NAMESPACE:-default}"
readonly secret_name="codewire-local-anthropic"

command -v kubectl >/dev/null 2>&1 || {
  printf '[local-secrets] ERROR: kubectl is required\n' >&2
  exit 1
}

credential_env() {
  if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
    printf 'ANTHROPIC_API_KEY=%s\n' "$ANTHROPIC_API_KEY"
    return
  fi

  command -v infisical >/dev/null 2>&1 || return 1
  infisical secrets get ANTHROPIC_API_KEY \
    --env=local \
    --path=/ \
    --plain \
    --silent |
    {
      local value
      IFS= read -r value
      [[ -n "$value" ]] || exit 1
      printf 'ANTHROPIC_API_KEY=%s\n' "$value"
      unset value
    }
}

if ! credential_env |
  kubectl --context "$kube_context" --namespace "$kube_namespace" \
    create secret generic "$secret_name" \
    --from-env-file=/dev/stdin \
    --dry-run=client \
    -o json |
  kubectl --context "$kube_context" --namespace "$kube_namespace" \
    apply -f - >/dev/null; then
  printf '%s\n' \
    '[local-secrets] ANTHROPIC_API_KEY is unavailable; existing local credential state was left unchanged.' >&2
  exit 0
fi

kubectl --context "$kube_context" --namespace "$kube_namespace" \
  label secret "$secret_name" \
  app.kubernetes.io/managed-by=codewire-local \
  app.kubernetes.io/component=orchestration \
  --overwrite >/dev/null

printf '%s\n' \
  '[local-secrets] Synced the Anthropic credential reference for local orchestration.'
