#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://127.0.0.1:8080}"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-codewire}"
POSTGRES_NAMESPACE="${POSTGRES_NAMESPACE:-default}"
POSTGRES_POD="${POSTGRES_POD:-}"
DB_USER="${DB_USER:-codewire}"
DB_NAME="${DB_NAME:-codewire}"
INVITE_CODE="${INVITE_CODE:-BETA-001}"
PASSWORD="${PASSWORD:-SecureTestPass9#}"

if [[ -z "${POSTGRES_POD}" ]]; then
  POSTGRES_POD="$(kubectl --context "${KUBE_CONTEXT}" -n "${POSTGRES_NAMESPACE}" get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
fi

if [[ -z "${POSTGRES_POD}" ]]; then
  echo "could not find postgres pod in ${POSTGRES_NAMESPACE} for context ${KUBE_CONTEXT}" >&2
  exit 1
fi

declare -a USERS=(
  "e2e-master@codewire.sh|E2E Master|false"
  "e2e-owner@codewire.sh|E2E Owner|false"
  "e2e-member@codewire.sh|E2E Member|false"
  "e2e-outsider@codewire.sh|E2E Outsider|false"
  "e2e-admin@codewire.sh|E2E Admin|true"
  "e2e-billing@codewire.sh|E2E Billing|false"
)

psql_exec() {
  kubectl --context "${KUBE_CONTEXT}" -n "${POSTGRES_NAMESPACE}" exec "${POSTGRES_POD}" -- \
    psql -U "${DB_USER}" -d "${DB_NAME}" -v ON_ERROR_STOP=1 -qAt -c "$1"
}

echo "seeding e2e users against ${API_URL}"
psql_exec "DELETE FROM rate_limit;"

for entry in "${USERS[@]}"; do
  IFS="|" read -r email name is_admin <<<"${entry}"

  body="$(printf '{"email":"%s","password":"%s","name":"%s","invite_code":"%s"}' \
    "${email}" "${PASSWORD}" "${name}" "${INVITE_CODE}")"

  http_code="$(curl -sS -o /tmp/codewire-seed-user.json -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    -X POST \
    "${API_URL}/api/auth/sign-up" \
    --data "${body}")"

  case "${http_code}" in
    200|201|202)
      echo "created ${email}"
      ;;
    409)
      echo "exists ${email}"
      ;;
    *)
      echo "failed to seed ${email}: status ${http_code}" >&2
      cat /tmp/codewire-seed-user.json >&2 || true
      exit 1
      ;;
  esac

  psql_exec "UPDATE users SET email_verified = true, two_factor_enabled = false, is_admin = ${is_admin}, updated_at = NOW() WHERE email = '${email}';"
  psql_exec "DELETE FROM two_factor WHERE user_id = (SELECT id FROM users WHERE email = '${email}');"
  psql_exec "DELETE FROM rate_limit;"
done

echo "seeded e2e users"
