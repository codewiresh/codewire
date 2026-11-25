#!/usr/bin/env bash
# scripts/ci/images/scan-runtime-image-os.sh with a stand-in supplychain: it
# scans only an exact digest reference, only with the pinned scanner, with the
# fixable-High policy and the database freshness checks. No network is used.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCAN="$ROOT/scripts/ci/images/scan-runtime-image-os.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/scan-runtime-image-os-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
fail() { echo "[test-scan-runtime-image-os] ERROR: $*" >&2; exit 1; }

mkdir "$work/bin" "$work/temp"
cat >"$work/bin/supplychain" <<'STUB'
#!/usr/bin/env bash
if [[ "$1" == version ]]; then echo "supplychain ${STUB_VERSION}"; exit 0; fi
printf '%s\n' "$*" >"$STUB_CALL"
env | grep '^GRYPE_' | sort >"$STUB_ENV"
exit "${STUB_EXIT:-0}"
STUB
chmod +x "$work/bin/supplychain"
pinned="$(sed -nE 's/^readonly EXPECTED_SUPPLYCHAIN=([0-9a-f]{40})$/\1/p' "$SCAN")"
[[ -n "$pinned" ]] || fail "the scanner pin is not one full commit"
digest="registry.example.com/codewire/dashboard@sha256:$(printf '%064d' 1)"
scan() {
  PATH="$work/bin:$PATH" RUNNER_TEMP="$work/temp" STUB_CALL="$work/call" STUB_ENV="$work/env" \
    STUB_VERSION="${version:-$pinned}" "$SCAN" "$@"
}

scan dashboard "$digest" >/dev/null
[[ "$(<"$work/call")" == "image -only-fixed -fail-on high -sbom $work/temp/os-scan-dashboard.spdx.json $digest" ]] ||
  fail "the scan call is not the fixable-High scan of the digest: $(<"$work/call")"
grep -qx 'GRYPE_DB_REQUIRE_UPDATE_CHECK=true' "$work/env" && grep -qx 'GRYPE_DB_AUTO_UPDATE=true' "$work/env" &&
  grep -qx 'GRYPE_DB_MAX_ALLOWED_BUILT_AGE=120h' "$work/env" || fail "the database freshness checks are not set"

if STUB_EXIT=1 scan dashboard "$digest" >/dev/null 2>&1; then fail "a failing scan passed"; fi
rm -f "$work/call"
for reference in registry.example.com/codewire/dashboard:latest "registry.example.com/codewire/dashboard@sha256:abc" \
    "https://registry.example.com/codewire/dashboard@sha256:$(printf '%064d' 1)"; do
  if scan dashboard "$reference" >/dev/null 2>&1; then fail "a non-digest reference was scanned: $reference"; fi
done
if scan 'Dash board' "$digest" >/dev/null 2>&1; then fail "a malformed name was accepted"; fi
if version="$(printf '%040d' 0)" scan dashboard "$digest" >/dev/null 2>&1; then fail "another scanner version was used"; fi
[[ ! -e "$work/call" ]] || fail "a refused call still ran the scanner"

echo '[test-scan-runtime-image-os] digest-only, pinned scanner, fixable-High policy and fresh database'
