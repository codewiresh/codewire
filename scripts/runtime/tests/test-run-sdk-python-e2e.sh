#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUNNER="$ROOT/scripts/runtime/dev/run-sdk-python-e2e.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-sdk-python-e2e-tests.XXXXXX")"
chmod 0700 "$TEST_TMP"

cleanup() {
  rm -rf -- "$TEST_TMP"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

fail() {
  printf 'sdk-python e2e runner tests: %s\n' "$*" >&2
  exit 1
}

BIN="$TEST_TMP/bin"
STATE="$TEST_TMP/state"
mkdir -p "$BIN" "$STATE"

# The fixture must not rely on a developer's or parent runner's control-plane
# inputs; each case supplies only the values it means to exercise.
unset CODEWIRE_API_KEY CODEWIRE_ORG_ID CODEWIRE_BASE_URL CODEWIRE_SERVER_URL

cat >"$BIN/cw" <<'CW'
#!/usr/bin/env bash
set -euo pipefail

[[ "$*" == "org list --output json" ]] || exit 61
[[ "${CODEWIRE_SERVER_URL:-}" == "https://codewire-dev.sh" ]] || exit 62
[[ "${CODEWIRE_API_KEY:-}" == "cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ]] || exit 63
[[ -n "${CW_CONFIG_DIR:-}" && -d "$CW_CONFIG_DIR" ]] || exit 64
[[ -z "${INFISICAL_TOKEN+x}" && -z "${KUBECONFIG+x}" && -z "${KUBE_CONTEXT+x}" ]] || exit 65
STATE="$(cd "$(dirname "$0")/../state" && pwd)"
printf '%s\n' "$CW_CONFIG_DIR" >"$STATE/cw-config-dir"
case "${FAKE_ORGS:-one}" in
  one) printf '[{"id":"org_test_123"}]\n' ;;
  empty) printf '[]\n' ;;
  many) printf '[{"id":"org_one"},{"id":"org_two"}]\n' ;;
  malformed) printf '{}\n' ;;
  *) exit 66 ;;
esac
CW
chmod 0755 "$BIN/cw"

cat >"$BIN/make" <<'MAKE'
#!/usr/bin/env bash
set -euo pipefail

[[ "$#" == 3 && "$1" == "-C" && -f "$2/Makefile" && -d "$2/libs/sdk-python" && "$3" == "sdk-e2e-python" ]] || exit 71
[[ "${CODEWIRE_API_KEY:-}" == "cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ]] || exit 72
[[ "${CODEWIRE_ORG_ID:-}" == "org_test_123" ]] || exit 73
[[ "${CODEWIRE_BASE_URL:-}" == "https://codewire-dev.sh" ]] || exit 74
[[ -z "${CODEWIRE_DEV_SMOKE_API_KEY+x}" ]] || exit 75
[[ -z "${EXPECTED_CODEWIRE_SMOKE_USER_EMAIL+x}" ]] || exit 76
[[ -z "${INFISICAL_TOKEN+x}" && -z "${KUBECONFIG+x}" && -z "${KUBE_CONTEXT+x}" ]] || exit 77
STATE="$(cd "$(dirname "$0")/../state" && pwd)"
env | sort >"$STATE/child-env"
printf 'fixed child invoked\n'
MAKE
chmod 0755 "$BIN/make"

run_case() {
  local name="$1"
  local expected_rc="$2"
  shift 2

  rm -f "$STATE/cw-config-dir" "$STATE/child-env"
  set +e
  PATH="$BIN:$PATH" \
    CW_BIN=cw \
    CODEWIRE_DEV_SMOKE_API_KEY="cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    EXPECTED_CODEWIRE_SMOKE_USER_EMAIL="smoke@example.test" \
    INFISICAL_TOKEN="must-not-reach-child" \
    KUBECONFIG="must-not-reach-child" \
    KUBE_CONTEXT="must-not-reach-child" \
    "$@" "$RUNNER" >"$TEST_TMP/$name.out" 2>"$TEST_TMP/$name.err"
  local rc=$?
  set -e
  [[ "$rc" == "$expected_rc" ]] || fail "$name returned $rc, expected $expected_rc"
}

run_case success 0 env FAKE_ORGS=one
[[ -f "$STATE/child-env" ]] || fail "success did not invoke the fixed child"
[[ -f "$STATE/cw-config-dir" ]] || fail "success did not use an isolated cw config"
[[ ! -e "$(<"$STATE/cw-config-dir")" ]] || fail "success did not remove the private cw config"
grep -Fxq 'CODEWIRE_ORG_ID=org_test_123' "$STATE/child-env" || fail "child org ID drifted"
grep -Fxq 'CODEWIRE_BASE_URL=https://codewire-dev.sh' "$STATE/child-env" || fail "child target drifted"
! grep -qE '^(CODEWIRE_DEV_SMOKE_API_KEY|EXPECTED_CODEWIRE_SMOKE_USER_EMAIL|INFISICAL_|KUBECONFIG=|KUBE_CONTEXT=)' "$STATE/child-env" || \
  fail "child received a platform credential"

run_case rejected-target 1 env CODEWIRE_BASE_URL=https://codewire.sh
[[ ! -e "$STATE/cw-config-dir" && ! -e "$STATE/child-env" ]] || fail "rejected target started work"

rm -f "$STATE/cw-config-dir" "$STATE/child-env"
set +e
PATH="$BIN:$PATH" \
  CW_BIN=cw \
  CODEWIRE_DEV_SMOKE_API_KEY="cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  "$RUNNER" unexpected-child >"$TEST_TMP/rejected-child.out" 2>"$TEST_TMP/rejected-child.err"
rc=$?
set -e
[[ "$rc" == 1 ]] || fail "rejected child returned $rc, expected 1"
[[ ! -e "$STATE/cw-config-dir" && ! -e "$STATE/child-env" ]] || fail "rejected child started work"

for orgs_case in empty many malformed; do
  run_case "orgs-$orgs_case" 1 env FAKE_ORGS="$orgs_case"
  [[ ! -e "$STATE/child-env" ]] || fail "$orgs_case org output invoked the child"
done

rm -f "$STATE/cw-config-dir" "$STATE/child-env"
set +e
PATH="$BIN:$PATH" \
  CW_BIN=cw \
  "$RUNNER" >"$TEST_TMP/missing-key.out" 2>"$TEST_TMP/missing-key.err"
rc=$?
set -e
[[ "$rc" == 1 ]] || fail "missing key returned $rc, expected 1"
[[ ! -e "$STATE/cw-config-dir" && ! -e "$STATE/child-env" ]] || fail "missing key started work"

printf 'sdk-python e2e runner tests: OK\n'
