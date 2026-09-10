#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
AUTH_SETUP="$ROOT/apps/dashboard/e2e/auth.setup.ts"
AUTH_FLOWS="$ROOT/apps/dashboard/e2e/ssr-dashboard.auth.ssr.ts"
PLAYWRIGHT_CONFIG="$ROOT/apps/dashboard/playwright.config.ts"
ENVIRONMENTS="$ROOT/apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts"
SECRETS_PRESETS="$ROOT/apps/dashboard/e2e/ssr-dashboard.secrets-presets.ssr.ts"
GOVERNANCE="$ROOT/apps/dashboard/e2e/ssr-dashboard.governance.ssr.ts"
CREDENTIALS="$ROOT/apps/dashboard/e2e/ssr-dashboard.credentials.ssr.ts"
INTEGRATED="$ROOT/scripts/ci/verify/kind/suites/integrated.sh"
COMMON="$ROOT/scripts/ci/verify/kind/common.sh"
BROWSER_RUNTIME="$ROOT/scripts/ci/verify/playwright-browser-runtime.sh"
HOST_RUNTIME="$ROOT/scripts/ci/verify/kind-host-runtime.sh"
INTERACTIVE_BROWSER="$ROOT/scripts/dev/kind/test-dashboard-kind.sh"
KUSTOMIZATION="$ROOT/tests/e2e/kind/kustomization.yaml"
MAKEFILE="$ROOT/Makefile"

fail() {
  printf '[test-dashboard-browser-gate] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
test_root="$(mktemp -d "$ROOT/.tmp/browser-runtime-test.XXXXXX")"
short_runtime_root="$(mktemp -d /tmp/cwk.XXXXXX)"
trap 'rm -rf -- "$test_root" "$short_runtime_root"' EXIT
pinned_version="$(sed -n "s/^readonly chromium_version='\([^']*\)'/\1/p" \
  "$ROOT/scripts/ci/install-pinned-playwright-chromium.sh")"
printf '#!/bin/sh\nprintf "Chromium %%s\\n" "%s"\n' "$pinned_version" >"$test_root/chromium"
printf '#!/bin/sh\nprintf "Chromium 1.2.3.4\\n"\n' >"$test_root/wrong-chromium"
chmod +x "$test_root/chromium" "$test_root/wrong-chromium"

(
  # shellcheck source=scripts/ci/verify/playwright-browser-runtime.sh
  source "$BROWSER_RUNTIME"
  df() {
    printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
    printf 'fixture 4194304 1048576 3145728 25%% /fixture\n'
  }
  export TMPDIR=/tmp
  unset CODEWIRE_PLAYWRIGHT_SNAPSHOT_ENV
  prepare_playwright_browser_runtime "$test_root/chromium" "$ROOT" >/dev/null
  [ "$CODEWIRE_PLAYWRIGHT_USE_DEV_SHM" = 1 ]
) || fail 'adequate /dev/shm runtime fixture was rejected'

(
  # shellcheck source=scripts/ci/verify/playwright-browser-runtime.sh
  source "$BROWSER_RUNTIME"
  playwright_snapshot_os_release() { printf 'ubuntu-24.04\n'; }
  playwright_snapshot_package_version() {
    case "$1" in
      fontconfig | libfontconfig1) printf '2.15.0-1.1ubuntu2' ;;
      libfreetype6) printf '2.13.2+dfsg-1ubuntu0.1' ;;
      *) return 1 ;;
    esac
  }
  playwright_snapshot_fonts_config_sha256() {
    printf '93a23ba073996edb8b42d6c89ebc2ec5fd2101ce82cb65ba0db358dabf55ca22\n'
  }
  playwright_snapshot_font_files_sha256() {
    printf '1b870a4e39c927334f6efc08fdd849094ac4f1eeb47209636c43e6c89feb6084\n'
  }
  df() {
    printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
    printf 'fixture 4194304 1048576 3145728 25%% /fixture\n'
  }
  export CODEWIRE_PLAYWRIGHT_SNAPSHOT_ENV=ubuntu24-cft145 TMPDIR=/tmp
  prepare_playwright_browser_runtime "$test_root/chromium" "$ROOT" >/dev/null
) || fail 'exact Ubuntu snapshot renderer fixture was rejected'

if (
  # shellcheck source=scripts/ci/verify/playwright-browser-runtime.sh
  source "$BROWSER_RUNTIME"
  playwright_snapshot_os_release() { printf 'arch-rolling\n'; }
  export CODEWIRE_PLAYWRIGHT_SNAPSHOT_ENV=ubuntu24-cft145 TMPDIR=/tmp
  prepare_playwright_browser_runtime "$test_root/chromium" "$ROOT"
) >/dev/null 2>&1; then
  fail 'non-Ubuntu runtime was allowed to claim the Ubuntu snapshot environment'
fi

if (
  # shellcheck source=scripts/ci/verify/playwright-browser-runtime.sh
  source "$BROWSER_RUNTIME"
  playwright_snapshot_os_release() { printf 'ubuntu-24.04\n'; }
  playwright_snapshot_package_version() { printf 'unexpected-version'; }
  export CODEWIRE_PLAYWRIGHT_SNAPSHOT_ENV=ubuntu24-cft145 TMPDIR=/tmp
  prepare_playwright_browser_runtime "$test_root/chromium" "$ROOT"
) >/dev/null 2>&1; then
  fail 'mismatched Ubuntu renderer packages were accepted'
fi

if (
  # shellcheck source=scripts/ci/verify/playwright-browser-runtime.sh
  source "$BROWSER_RUNTIME"
  export CODEWIRE_PLAYWRIGHT_SNAPSHOT_ENV=future-unpinned-renderer TMPDIR=/tmp
  prepare_playwright_browser_runtime "$test_root/chromium" "$ROOT"
) >/dev/null 2>&1; then
  fail 'unknown explicit snapshot environment was accepted'
fi

if (
  # shellcheck source=scripts/ci/verify/playwright-browser-runtime.sh
  source "$BROWSER_RUNTIME"
  df() {
    printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
    printf 'fixture 4194304 4190208 4096 100%% /fixture\n'
  }
  export TMPDIR=/tmp
  unset CODEWIRE_PLAYWRIGHT_SNAPSHOT_ENV
  prepare_playwright_browser_runtime "$test_root/chromium" "$ROOT"
) >/dev/null 2>&1; then
  fail 'low-capacity browser backing fixture was accepted'
fi

if (
  # shellcheck source=scripts/ci/verify/playwright-browser-runtime.sh
  source "$BROWSER_RUNTIME"
  export TMPDIR=/tmp
  unset CODEWIRE_PLAYWRIGHT_SNAPSHOT_ENV
  prepare_playwright_browser_runtime "$test_root/wrong-chromium" "$ROOT"
) >/dev/null 2>&1; then
  fail 'wrong Chromium version fixture was accepted'
fi

(
  # shellcheck source=scripts/ci/verify/kind-host-runtime.sh
  source "$HOST_RUNTIME"
  df() {
    printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
    if [ "${*: -1}" = /tmp ]; then
      printf 'fixture 4194304 4190208 4096 100%% /tmp\n'
    else
      printf 'fixture 4194304 1048576 3145728 25%% /fixture\n'
    fi
  }
  unset TMPDIR
  export XDG_RUNTIME_DIR="$short_runtime_root"
  prepare_kind_temp_runtime >/dev/null
  [ "$TMPDIR" = "$short_runtime_root" ]
) || fail 'Kind temp runtime did not replace a saturated default'

if (
  # shellcheck source=scripts/ci/verify/kind-host-runtime.sh
  source "$HOST_RUNTIME"
  df() {
    printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
    printf 'fixture 4194304 4190208 4096 100%% /fixture\n'
  }
  export TMPDIR="$short_runtime_root"
  prepare_kind_temp_runtime
) >/dev/null 2>&1; then
  fail 'explicit low-capacity Kind temp root was silently replaced'
fi

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
grep -Fq -- '--host-resolver-rules=MAP * ^NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1' "$PLAYWRIGHT_CONFIG" ||
  fail 'dashboard browser is not isolated from public DNS'
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
grep -Fq 'ignoreDefaultArgs: useDevShm ? ["--disable-dev-shm-usage"] : undefined' \
  "$PLAYWRIGHT_CONFIG" || fail 'adequate /dev/shm does not replace the constrained tmpfs backing'
grep -Fq 'page.waitForURL(`${ssrUrl}${bucketPath}?message=secret-renamed`)' \
  "$SECRETS_PRESETS" || fail 'secret rename does not wait for redirect completion'
grep -Fq 'page.waitForURL(`${ssrUrl}${bucketPath}?message=secret-deleted`)' \
  "$SECRETS_PRESETS" || fail 'secret deletion does not wait for redirect completion'
grep -Fq 'PLAYWRIGHT_KIND_CREDENTIAL_FIXTURE !== "1"' "$CREDENTIALS" ||
  fail 'managed credential browser journey is not fixture-only'
grep -Fq 'responseBody.indexOf("ABCD-EFGH")' "$CREDENTIALS" ||
  fail 'managed credential browser journey does not prove challenge-before-commit ordering'
grep -Fq 'PLAYWRIGHT_KIND_CREDENTIAL_FIXTURE="$credential_fixture"' "$COMMON" ||
  fail 'Kind browser wrapper does not overwrite the credential fixture selection'
grep -Fq 'runtime::kind::serve_kind_credential_fixture' "$COMMON" ||
  fail 'Kind browser wrapper does not verify the selected synthetic credential runtime'

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
grep -Fq 'prepare_playwright_browser_runtime "$chromium" "$ROOT"' "$COMMON" ||
  fail 'isolated dashboard browser gate bypasses the shared runtime preflight'
grep -Fq 'prepare_playwright_browser_runtime "$chromium" "$ROOT"' "$INTERACTIVE_BROWSER" ||
  fail 'interactive dashboard browser gate bypasses the shared runtime preflight'
grep -Fq 'prepare_kind_temp_runtime' "$INTEGRATED" ||
  fail 'integrated Kind gate bypasses host temp-capacity preflight'
grep -Fq 'at least 1048576 KiB is required' "$BROWSER_RUNTIME" ||
  fail 'dashboard browser gate does not fail before Chromium on low backing capacity'
grep -Fq 'dashboard browser temp root is too long for Chromium IPC paths' "$BROWSER_RUNTIME" ||
  fail 'dashboard browser gate does not reject overlong Chromium temp paths'
grep -Fq 'expected pinned Chromium' "$BROWSER_RUNTIME" ||
  fail 'dashboard browser gate does not require the Playwright-pinned Chromium version'
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
