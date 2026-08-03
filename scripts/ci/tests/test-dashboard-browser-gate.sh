#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
AUTH_SETUP="$ROOT/apps/dashboard/e2e/auth.setup.ts"
AUTH_FLOWS="$ROOT/apps/dashboard/e2e/ssr-dashboard.auth.ssr.ts"
PLAYWRIGHT_CONFIG="$ROOT/apps/dashboard/playwright.config.ts"
ENVIRONMENTS="$ROOT/apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts"
GOVERNANCE="$ROOT/apps/dashboard/e2e/ssr-dashboard.governance.ssr.ts"
INTEGRATED="$ROOT/scripts/ci/verify/kind/suites/integrated.sh"
COMMON="$ROOT/scripts/ci/verify/kind/common.sh"
KUSTOMIZATION="$ROOT/tests/e2e/kind/kustomization.yaml"
MAKEFILE="$ROOT/Makefile"

fail() {
  printf '[test-dashboard-browser-gate] ERROR: %s\n' "$*" >&2
  exit 1
}

assert_sandbox_namespace_precedes_overlay() {
  local target="$1"
  local body namespace_line overlay_line

  body="$(awk -v target="$target" '
    $0 ~ "^" target ":" { in_target = 1; next }
    in_target && $0 ~ /^[[:alnum:]_.-]+:/ { exit }
    in_target { print }
  ' "$MAKEFILE")"
  namespace_line="$(printf '%s\n' "$body" | grep -nF '@$(MAKE) kind-sandbox-namespace' | cut -d: -f1 || true)"
  overlay_line="$(printf '%s\n' "$body" | grep -nF '$(KUBECTL) apply -k deployments/k8s/overlays/' | cut -d: -f1 || true)"

  [ -n "$namespace_line" ] ||
    fail "$target does not ensure the sandbox namespace"
  [ -n "$overlay_line" ] ||
    fail "$target does not apply a local Kind overlay"
  [ "$namespace_line" -lt "$overlay_line" ] ||
    fail "$target applies cross-namespace RBAC before creating dev-sandboxes"
}

grep -Fq '/login/_actions/sign-in' "$AUTH_SETUP" ||
  fail 'authentication setup does not observe the real Rust sign-in action'
grep -Fq 'name: "Dashboard", exact: true' "$AUTH_SETUP" ||
  fail 'authentication setup does not prove the authenticated dashboard'
grep -Fq 'codewire.session_token' "$AUTH_SETUP" ||
  fail 'authentication setup does not prove the HttpOnly session cookie'
grep -Fq 'completes browser OIDC PKCE and verifies the issued ID token' "$AUTH_FLOWS" ||
  fail 'browser OIDC PKCE proof is missing'
grep -Fq 'grant_type: "refresh_token"' "$AUTH_FLOWS" ||
  fail 'OAuth refresh-token proof is missing'
grep -Fq '/api/oauth/revoke' "$AUTH_FLOWS" ||
  fail 'OAuth token-revocation proof is missing'
grep -Fq 'through login, 2FA enrollment, and acceptance' "$GOVERNANCE" ||
  fail 'invitation acceptance proof is missing'
grep -Fq 'enrolls a seeded login in 2FA and reveals recovery codes only after verification' \
  "$AUTH_FLOWS" || fail 'manual 2FA enrollment regression proof is missing'
grep -Fq 'expect(secretAfterRejection === secret).toBe(true)' "$AUTH_FLOWS" ||
  fail 'pending 2FA secret-stability assertion is missing'
grep -Fq 'expect(await page.getByTestId("recovery-code").count()).toBe(0)' "$AUTH_FLOWS" ||
  fail 'pre-verification recovery-code secrecy assertion is missing'
grep -Fq 'PLAYWRIGHT_SKIP_SHARED_SETUP' "$PLAYWRIGHT_CONFIG" ||
  fail 'focused disposable-identity browser mode is missing'

grep -Fq 'creates, runs, exposes a port, stops, starts, and destroys through real Kind' \
  "$ENVIRONMENTS" || fail 'real environment lifecycle browser proof is missing'
if rg -n 'SSR_ENVIRONMENT_LIFECYCLE|requires the coherent local Kind sandbox worker' \
    "$ENVIRONMENTS"; then
  fail 'real environment lifecycle browser proof is still opt-in'
fi

[ "$(grep -Fc 'dashboard_browser_e2e' "$INTEGRATED")" -eq 1 ] ||
  fail 'integrated Kind gate must invoke dashboard browser E2E exactly once'
grep -Fq 'require_get_code /login 200 "dashboard login page"' "$COMMON" ||
  fail 'dashboard browser preflight does not use the shared edge-probe contract'
grep -Fq '../../../deployments/k8s/dashboard' "$KUSTOMIZATION" ||
  fail 'isolated Kind overlay does not deploy the production dashboard resource'
grep -Fq 'image: codewire-dashboard:e2e' "$KUSTOMIZATION" ||
  fail 'isolated Kind dashboard does not use the exact locally built E2E image'

for target in deploy-local deploy-local-static up; do
  assert_sandbox_namespace_precedes_overlay "$target"
done

for spec in \
  ssr-dashboard.auth.ssr.ts \
  ssr-dashboard.settings.ssr.ts \
  ssr-dashboard.organization.ssr.ts \
  ssr-dashboard.governance.ssr.ts \
  ssr-dashboard.environments.ssr.ts \
  ssr-dashboard.secrets-presets.ssr.ts \
  ssr-dashboard.billing-admin.ssr.ts; do
  [ -f "$ROOT/apps/dashboard/e2e/$spec" ] ||
    fail "required Rust dashboard parity spec is missing: $spec"
done

printf '[test-dashboard-browser-gate] full-stack login and product parity wiring passed\n'
