#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-apikey-smoke-tests.XXXXXX")"
cleanup_test_tmp() {
  if [[ "${KEEP_APIKEY_SMOKE_TEST_TMP:-0}" == "1" ]]; then
    printf 'apikey smoke tests: kept %s\n' "$TEST_TMP" >&2
  else
    rm -rf "$TEST_TMP"
  fi
}
trap cleanup_test_tmp EXIT
trap 'exit 130' HUP INT TERM

DEV_BOOTSTRAP="cw_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
PROD_BOOTSTRAP="cw_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
EVIDENCE_BOOTSTRAP="cw_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
NEW_KEY="cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

fail() {
  printf 'apikey smoke tests: %s\n' "$*" >&2
  exit 1
}

assert_secret_absent() {
  local file="$1"
  for secret in "$DEV_BOOTSTRAP" "$PROD_BOOTSTRAP" "$EVIDENCE_BOOTSTRAP" "$NEW_KEY"; do
    if grep -F "$secret" "$file" >/dev/null; then
      fail "secret appeared in captured output: $file"
    fi
  done
}

make_fake_infisical() {
  local bin_dir="$1"
  mkdir -p "$bin_dir"
  cat >"$bin_dir/infisical" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"$FAKE_INFISICAL_LOG"
printf '\n' >>"$FAKE_INFISICAL_LOG"
if [[ "${1:-}" == "secrets" && "${2:-}" == "get" ]]; then
  case "${3:-}" in
    CODEWIRE_APIKEY_DEV_SMOKE_BOOTSTRAP_KEY) printf '%s\n' "$FAKE_DEV_BOOTSTRAP" ;;
    CODEWIRE_APIKEY_PROD_SMOKE_BOOTSTRAP_KEY) printf '%s\n' "$FAKE_PROD_BOOTSTRAP" ;;
    CODEWIRE_APIKEY_PROD_EVIDENCE_SECONDARY_BOOTSTRAP_KEY) printf '%s\n' "$FAKE_EVIDENCE_BOOTSTRAP" ;;
    *) exit 40 ;;
  esac
  exit 0
fi
if [[ "${1:-}" == "secrets" && "${2:-}" == "set" ]]; then
  while (($# > 0)); do
    if [[ "$1" == "--file" ]]; then
      cp "$2" "$FAKE_INFISICAL_CAPTURE"
      exit 0
    fi
    shift
  done
fi
exit 41
FAKE
  chmod +x "$bin_dir/infisical"
}

make_fake_oidc_curl() {
  local path="$1"
  cat >"$path" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"$FAKE_CURL_LOG"
printf '\n' >>"$FAKE_CURL_LOG"

if [[ "$*" == *'/v1/auth/oidc-auth/login'* ]]; then
  output=""
  payload=""
  while (($# > 0)); do
    if [[ "$1" == "-o" ]]; then
      output="$2"
      shift 2
      continue
    fi
    if [[ "$1" == "--data-binary" ]]; then
      payload="${2#@}"
      shift 2
      continue
    fi
    shift
  done
  [[ -n "$output" && -n "$payload" ]]
  [[ "$(stat -c '%a' "$(dirname "$output")")" == "700" ]]
  [[ "$(stat -c '%a' "$payload")" == "600" ]]
  printf '{"accessToken":"fake-access-token"}\n' >"$output"
  [[ "$(stat -c '%a' "$output")" == "600" ]]
  printf '200'
  exit 0
fi

if [[ "${1:-}" == "--config" ]]; then
  config="$2"
  [[ -f "$config" ]]
  [[ "$(stat -c '%a' "$config")" == "600" ]]
  output="$(awk -F'"' '$1 ~ /^output = / { print $2; exit }' "$config")"
  [[ -n "$output" ]]
  printf '{"secret":{"secretValue":"%s"}}\n' "$FAKE_DEV_BOOTSTRAP" >"$output"
  [[ "$(stat -c '%a' "$output")" == "600" ]]
  printf '200'
  exit 0
fi

exit 42
FAKE
  chmod +x "$path"
}

test_secret_wrapper() {
  local case_dir="$TEST_TMP/wrapper"
  local bin_dir="$case_dir/bin"
  mkdir -p "$case_dir"
  make_fake_infisical "$bin_dir"
  cat >"$case_dir/child" <<'CHILD'
#!/usr/bin/env bash
set -euo pipefail
[[ "$CODEWIRE_API_KEY" =~ ^cw_[0-9a-f]{64}$ ]]
[[ -z "${INFISICAL_TOKEN+x}" ]]
[[ -z "${INFISICAL_ACCESS_TOKEN+x}" ]]
printf 'child-safe\n'
CHILD
  chmod +x "$case_dir/child"

  : >"$case_dir/infisical.log"
  if ! PATH="$bin_dir:$PATH" \
    FAKE_INFISICAL_LOG="$case_dir/infisical.log" \
    FAKE_DEV_BOOTSTRAP="$DEV_BOOTSTRAP" \
    FAKE_PROD_BOOTSTRAP="$PROD_BOOTSTRAP" \
    FAKE_EVIDENCE_BOOTSTRAP="$EVIDENCE_BOOTSTRAP" \
    INFISICAL_TOKEN="test-platform-token" \
    INFISICAL_API_URL='' \
    INFISICAL_IDENTITY_ID='' \
    INFISICAL_SA_TOKEN_PATH='' \
    "$ROOT/scripts/runtime/apikey/with-apikey-smoke-auth.sh" \
      --target dev -- "$case_dir/child" \
      >"$case_dir/dev.out" 2>"$case_dir/dev.err"; then
    sed 's/^/[wrapper-dev] /' "$case_dir/dev.err" >&2
    sed 's/^/[wrapper-dev-infisical] /' "$case_dir/infisical.log" >&2
    fail "dev secret wrapper failed"
  fi
  grep -Fx 'child-safe' "$case_dir/dev.out" >/dev/null
  grep -F 'CODEWIRE_APIKEY_DEV_SMOKE_BOOTSTRAP_KEY' "$case_dir/infisical.log" >/dev/null
  assert_secret_absent "$case_dir/dev.out"
  assert_secret_absent "$case_dir/dev.err"
  assert_secret_absent "$case_dir/infisical.log"

  : >"$case_dir/infisical.log"
  if ! PATH="$bin_dir:$PATH" \
    FAKE_INFISICAL_LOG="$case_dir/infisical.log" \
    FAKE_DEV_BOOTSTRAP="$DEV_BOOTSTRAP" \
    FAKE_PROD_BOOTSTRAP="$PROD_BOOTSTRAP" \
    FAKE_EVIDENCE_BOOTSTRAP="$EVIDENCE_BOOTSTRAP" \
    INFISICAL_API_URL='' \
    INFISICAL_IDENTITY_ID='' \
    INFISICAL_SA_TOKEN_PATH='' \
    "$ROOT/scripts/runtime/apikey/with-apikey-smoke-auth.sh" \
      --target prod -- "$case_dir/child" \
      >"$case_dir/prod.out" 2>"$case_dir/prod.err"; then
    sed 's/^/[wrapper-prod] /' "$case_dir/prod.err" >&2
    sed 's/^/[wrapper-prod-infisical] /' "$case_dir/infisical.log" >&2
    fail "prod secret wrapper failed"
  fi
  grep -F 'CODEWIRE_APIKEY_PROD_SMOKE_BOOTSTRAP_KEY' "$case_dir/infisical.log" >/dev/null
  assert_secret_absent "$case_dir/prod.out"
  assert_secret_absent "$case_dir/prod.err"
  assert_secret_absent "$case_dir/infisical.log"

  : >"$case_dir/infisical.log"
  if ! PATH="$bin_dir:$PATH" \
    FAKE_INFISICAL_LOG="$case_dir/infisical.log" \
    FAKE_DEV_BOOTSTRAP="$DEV_BOOTSTRAP" \
    FAKE_PROD_BOOTSTRAP="$PROD_BOOTSTRAP" \
    FAKE_EVIDENCE_BOOTSTRAP="$EVIDENCE_BOOTSTRAP" \
    INFISICAL_API_URL='' \
    INFISICAL_IDENTITY_ID='' \
    INFISICAL_SA_TOKEN_PATH='' \
    "$ROOT/scripts/runtime/apikey/with-apikey-smoke-auth.sh" \
      --target prod-evidence-secondary -- "$case_dir/child" \
      >"$case_dir/evidence.out" 2>"$case_dir/evidence.err"; then
    sed 's/^/[wrapper-evidence] /' "$case_dir/evidence.err" >&2
    sed 's/^/[wrapper-evidence-infisical] /' "$case_dir/infisical.log" >&2
    fail "secondary production evidence secret wrapper failed"
  fi
  grep -F 'CODEWIRE_APIKEY_PROD_EVIDENCE_SECONDARY_BOOTSTRAP_KEY' \
    "$case_dir/infisical.log" >/dev/null
  assert_secret_absent "$case_dir/evidence.out"
  assert_secret_absent "$case_dir/evidence.err"
  assert_secret_absent "$case_dir/infisical.log"

  local oidc_dir="$TEST_TMP/wrapper-oidc"
  local oidc_bin="$oidc_dir/bin"
  mkdir -p "$oidc_bin"
  make_fake_oidc_curl "$oidc_bin/curl"
  printf 'fake-runner-jwt\n' >"$oidc_dir/runner.jwt"
  : >"$oidc_dir/curl.log"
  if ! PATH="$oidc_bin:$PATH" \
    FAKE_CURL_LOG="$oidc_dir/curl.log" \
    FAKE_DEV_BOOTSTRAP="$DEV_BOOTSTRAP" \
    INFISICAL_API_URL="https://infisical.test/api" \
    INFISICAL_IDENTITY_ID="fake-identity" \
    INFISICAL_SA_TOKEN_PATH="$oidc_dir/runner.jwt" \
    "$ROOT/scripts/runtime/apikey/with-apikey-smoke-auth.sh" \
      --target dev -- "$case_dir/child" \
      >"$oidc_dir/out" 2>"$oidc_dir/err"; then
    sed 's/^/[wrapper-oidc] /' "$oidc_dir/err" >&2
    fail "OIDC secret wrapper failed"
  fi
  grep -Fx 'child-safe' "$oidc_dir/out" >/dev/null
  grep -F '/v1/auth/oidc-auth/login' "$oidc_dir/curl.log" >/dev/null
  grep -F -- '--config' "$oidc_dir/curl.log" >/dev/null
  assert_secret_absent "$oidc_dir/out"
  assert_secret_absent "$oidc_dir/err"
  assert_secret_absent "$oidc_dir/curl.log"
}

make_fake_cw() {
  local path="$1"
  cat >"$path" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$1" >>"$FAKE_CW_STATE/operations"
case "${1:-}" in
  --version)
    printf 'cw %s\n' "${FAKE_CW_VERSION:-0.3.359-test}"
    ;;
  whoami)
    case "$CODEWIRE_SERVER_URL" in
      https://codewire-dev.sh) email='connect-apikey-smoke-dev@codewire-dev.sh' ;;
      https://codewire.sh)
        case "$CODEWIRE_API_KEY" in
          "$FAKE_PROD_BOOTSTRAP") email='connect-apikey-smoke-prod@codewire.sh' ;;
          "$FAKE_EVIDENCE_BOOTSTRAP") email='connect-apikey-evidence-prod-secondary@codewire.sh' ;;
          *) exit 60 ;;
        esac
        ;;
      *) exit 60 ;;
    esac
    printf '{"email":"%s","name":"smoke"}\n' "$email"
    ;;
  api-keys)
    case "${2:-}" in
      create)
        [[ "${4:-}" == "--expires" && "${5:-}" == "1" ]] || exit 61
        printf '%s' "$3" >"$FAKE_CW_STATE/name"
        printf 'key-test-id' >"$FAKE_CW_STATE/id"
        printf '%s' "$CODEWIRE_API_KEY" >"$FAKE_CW_STATE/bootstrap"
        : >"$FAKE_CW_STATE/exists"
        printf '%s\n' "$FAKE_NEW_KEY"
        ;;
      list)
        if [[ "$CODEWIRE_API_KEY" == "$FAKE_NEW_KEY" && "${FAKE_CW_FAIL_NEW_LIST:-0}" == "1" ]]; then
          exit 62
        fi
        [[ "$CODEWIRE_API_KEY" == "$(<"$FAKE_CW_STATE/bootstrap")" || "$CODEWIRE_API_KEY" == "$FAKE_NEW_KEY" ]] || exit 63
        printf '%-16s %-24s %-36s CREATED\n' PREFIX NAME ID
        if [[ -f "$FAKE_CW_STATE/exists" ]]; then
          printf '%-16s %-24s %-36s %s\n' aaaaaaaa "$(<"$FAKE_CW_STATE/name")" "$(<"$FAKE_CW_STATE/id")" 2026-07-12T00:00:00Z
        fi
        ;;
      delete)
        [[ "$CODEWIRE_API_KEY" == "$(<"$FAKE_CW_STATE/bootstrap")" ]] || exit 64
        if [[ "${FAKE_CW_FAIL_DELETE:-0}" == "1" ]]; then
          exit 65
        fi
        [[ "$3" == "$(<"$FAKE_CW_STATE/id")" ]] || exit 66
        rm -f "$FAKE_CW_STATE/exists"
        printf 'API key deleted.\n' >&2
        ;;
      *) exit 67 ;;
    esac
    ;;
  *) exit 68 ;;
esac
FAKE
  chmod +x "$path"
}

run_lifecycle_case() {
  local name="$1"
  local expected_rc="$2"
  local fail_new_list="$3"
  local fail_delete="$4"
  local case_dir="$TEST_TMP/$name"
  mkdir -p "$case_dir/state" "$case_dir/bin"
  make_fake_cw "$case_dir/cw"
  : >"$case_dir/state/operations"

  set +e
  PATH="$case_dir/bin:$PATH" \
    CODEWIRE_API_KEY="$DEV_BOOTSTRAP" \
    CW_BIN="$case_dir/cw" \
    FAKE_CW_STATE="$case_dir/state" \
    FAKE_BOOTSTRAP="$DEV_BOOTSTRAP" \
    FAKE_PROD_BOOTSTRAP="$PROD_BOOTSTRAP" \
    FAKE_EVIDENCE_BOOTSTRAP="$EVIDENCE_BOOTSTRAP" \
    FAKE_NEW_KEY="$NEW_KEY" \
    FAKE_CW_FAIL_NEW_LIST="$fail_new_list" \
    FAKE_CW_FAIL_DELETE="$fail_delete" \
    GITHUB_RUN_ID=1234 \
    "$ROOT/scripts/runtime/apikey/smoke-apikey-lifecycle.sh" --target dev \
    >"$case_dir/out" 2>"$case_dir/err"
  rc=$?
  set -e
  [[ "$rc" == "$expected_rc" ]] || fail "$name returned $rc, expected $expected_rc"
  assert_secret_absent "$case_dir/out"
  assert_secret_absent "$case_dir/err"
}

run_secondary_lifecycle_case() {
  local case_dir="$TEST_TMP/lifecycle-secondary"
  mkdir -p "$case_dir/state" "$case_dir/bin"
  make_fake_cw "$case_dir/cw"
  : >"$case_dir/state/operations"

  PATH="$case_dir/bin:$PATH" \
    CODEWIRE_API_KEY="$EVIDENCE_BOOTSTRAP" \
    CW_BIN="$case_dir/cw" \
    FAKE_CW_STATE="$case_dir/state" \
    FAKE_PROD_BOOTSTRAP="$PROD_BOOTSTRAP" \
    FAKE_EVIDENCE_BOOTSTRAP="$EVIDENCE_BOOTSTRAP" \
    FAKE_NEW_KEY="$NEW_KEY" \
    "$ROOT/scripts/runtime/apikey/smoke-apikey-lifecycle.sh" \
      --target prod-evidence-secondary \
      >"$case_dir/out" 2>"$case_dir/err"

  grep -F 'target=prod-evidence-secondary lifecycle passed' "$case_dir/err" >/dev/null
  [[ ! -f "$case_dir/state/exists" ]] || fail "secondary lifecycle left a key"
  assert_secret_absent "$case_dir/out"
  assert_secret_absent "$case_dir/err"
}

test_lifecycle() {
  run_lifecycle_case lifecycle-success 0 0 0
  [[ ! -f "$TEST_TMP/lifecycle-success/state/exists" ]] || fail "successful smoke left a key"
  grep -F 'target=dev lifecycle passed' "$TEST_TMP/lifecycle-success/err" >/dev/null

  run_lifecycle_case lifecycle-cleanup 1 1 0
  [[ ! -f "$TEST_TMP/lifecycle-cleanup/state/exists" ]] || fail "failure trap did not remove key"
  grep -F 'attempting leftover key cleanup' "$TEST_TMP/lifecycle-cleanup/err" >/dev/null

  run_lifecycle_case lifecycle-cleanup-fails 1 1 1
  [[ -f "$TEST_TMP/lifecycle-cleanup-fails/state/exists" ]] || fail "cleanup-failure fixture unexpectedly disappeared"
  grep -F 'leftover key cleanup failed' "$TEST_TMP/lifecycle-cleanup-fails/err" >/dev/null

  run_secondary_lifecycle_case
}

make_fake_kubectl() {
  local path="$1"
  cat >"$path" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"$FAKE_KUBECTL_LOG"
printf '\n' >>"$FAKE_KUBECTL_LOG"
if [[ "$*" == *'get cluster.postgresql.cnpg.io codewire-db'* ]]; then
  printf 'codewire-db-1'
  exit 0
fi
input="$(</dev/stdin)"
count=0
[[ -f "$FAKE_PSQL_COUNT" ]] && count="$(<"$FAKE_PSQL_COUNT")"
count=$((count + 1))
printf '%s' "$count" >"$FAKE_PSQL_COUNT"
case "$count" in
  1)
    [[ "$input" == *"FROM admin_invoice_credits WHERE org_id = :'org_id'"* ]]
    printf '0\n'
    ;;
  2)
    [[ "$input" == *"WHERE (user_id = :'user_id' OR org_id = :'org_id')"* ]]
    printf '%s\n' "$FAKE_ROTATED_KEY"
    ;;
  3)
    [[ "$input" == *"COUNT(*) FROM org_members WHERE org_id = o.id"* ]]
    if [[ "$*" == *'258099727105fa93538769d4e3498b24'* ]]; then
      printf '258099727105fa93538769d4e3498b24|connect-apikey-evidence-prod-secondary@codewire.sh|f|63742e203ad7e3c65f25af8e221ccf21|connect-apikey-evidence-prod-secondary|1|1|1|0|1|dddddddd\n'
    elif [[ "$*" == *'admin@dev-cluster'* ]]; then
      printf 'f23d1c4a5ed665e62094d9d106c0d13b|connect-apikey-smoke-dev@codewire-dev.sh|f|9bef2654d4ac6824ead235fdb9bb8598|connect-apikey-smoke-dev|1|1|1|0|1|dddddddd\n'
    else
      printf '627a3c7cad1f50a7b44c00de1e054df9|connect-apikey-smoke-prod@codewire.sh|f|3289cbf3e0ca05c5ef2ac7cb696d5318|connect-apikey-smoke-prod|1|1|1|0|1|dddddddd\n'
    fi
    ;;
  *) exit 71 ;;
esac
test -n "$input"
FAKE
  chmod +x "$path"
}

run_provision_case() {
  local target="$1"
  local case_dir="$TEST_TMP/provision-$target"
  local bin_dir="$case_dir/bin"
  local fake_home="$case_dir/home"
  mkdir -p "$bin_dir" "$fake_home/src/infra"
  touch "$fake_home/src/infra/kubeconfig-dev-cluster.yaml"
  touch "$fake_home/src/infra/kubeconfig-prod-cluster.yaml"
  make_fake_kubectl "$bin_dir/kubectl"
  make_fake_infisical "$bin_dir"
  : >"$case_dir/kubectl.log"
  : >"$case_dir/infisical.log"
  local rotated="cw_dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  local -a args=(--target "$target")
  local expected_secret expected_context
  case "$target" in
    dev)
      expected_secret="CODEWIRE_APIKEY_DEV_SMOKE_BOOTSTRAP_KEY"
      expected_context="admin@dev-cluster"
      ;;
    prod)
      args+=(--allow-prod-mutation)
      expected_secret="CODEWIRE_APIKEY_PROD_SMOKE_BOOTSTRAP_KEY"
      expected_context="admin@prod-cluster"
      ;;
    prod-evidence-secondary)
      args+=(--allow-prod-mutation)
      expected_secret="CODEWIRE_APIKEY_PROD_EVIDENCE_SECONDARY_BOOTSTRAP_KEY"
      expected_context="admin@prod-cluster"
      ;;
    *) fail "unsupported provision test target: $target" ;;
  esac

  PATH="$bin_dir:$PATH" \
    HOME="$fake_home" \
    FAKE_KUBECTL_LOG="$case_dir/kubectl.log" \
    FAKE_PSQL_COUNT="$case_dir/psql-count" \
    FAKE_ROTATED_KEY="$rotated" \
    FAKE_INFISICAL_LOG="$case_dir/infisical.log" \
    FAKE_INFISICAL_CAPTURE="$case_dir/infisical.env" \
    FAKE_DEV_BOOTSTRAP="$DEV_BOOTSTRAP" \
    FAKE_PROD_BOOTSTRAP="$PROD_BOOTSTRAP" \
    FAKE_EVIDENCE_BOOTSTRAP="$EVIDENCE_BOOTSTRAP" \
    "$ROOT/scripts/runtime/apikey/provision-apikey-smoke-user.sh" "${args[@]}" \
    >"$case_dir/out" 2>"$case_dir/err"

  assert_secret_absent "$case_dir/out"
  assert_secret_absent "$case_dir/err"
  if grep -F "$rotated" "$case_dir/kubectl.log" "$case_dir/infisical.log" >/dev/null; then
    fail "rotated key appeared in a command argument log"
  fi
  grep -F "$expected_secret=" "$case_dir/infisical.env" >/dev/null
  grep -F "$expected_context" "$case_dir/kubectl.log" >/dev/null
}

test_provisioner() {
  local case_dir="$TEST_TMP/prod-guard"
  mkdir -p "$case_dir"
  set +e
  "$ROOT/scripts/runtime/apikey/provision-apikey-smoke-user.sh" --target prod \
    >"$case_dir/out" 2>"$case_dir/err"
  rc=$?
  set -e
  [[ "$rc" != "0" ]] || fail "prod provisioning guard accepted a single opt-in"
  grep -F 'requires --allow-prod-mutation' "$case_dir/err" >/dev/null

  set +e
  "$ROOT/scripts/runtime/apikey/provision-apikey-smoke-user.sh" \
    --target prod-evidence-secondary \
    >"$case_dir/evidence.out" 2>"$case_dir/evidence.err"
  rc=$?
  set -e
  [[ "$rc" != "0" ]] || fail "secondary provisioning guard accepted a single opt-in"
  grep -F 'requires --allow-prod-mutation' "$case_dir/evidence.err" >/dev/null

  run_provision_case dev
  run_provision_case prod
  run_provision_case prod-evidence-secondary
}

test_g4_evidence_runner() {
  local case_dir="$TEST_TMP/g4-evidence"
  local bin_dir="$case_dir/bin"
  mkdir -p "$case_dir/state"
  make_fake_infisical "$bin_dir"
  make_fake_cw "$case_dir/cw"
  : >"$case_dir/infisical.log"
  : >"$case_dir/state/operations"

  if ! PATH="$bin_dir:$PATH" \
    CW_BIN="$case_dir/cw" \
    FAKE_CW_VERSION="v0.3.360" \
    FAKE_CW_STATE="$case_dir/state" \
    FAKE_NEW_KEY="$NEW_KEY" \
    FAKE_DEV_BOOTSTRAP="$DEV_BOOTSTRAP" \
    FAKE_PROD_BOOTSTRAP="$PROD_BOOTSTRAP" \
    FAKE_EVIDENCE_BOOTSTRAP="$EVIDENCE_BOOTSTRAP" \
    FAKE_INFISICAL_LOG="$case_dir/infisical.log" \
    INFISICAL_API_URL='' \
    INFISICAL_IDENTITY_ID='' \
    INFISICAL_SA_TOKEN_PATH='' \
    "$ROOT/scripts/runtime/apikey/run-apikey-g4-evidence.sh" \
      --release-tag v0.3.360 \
      --confirm 'RUN APIKEY PROD EVIDENCE' \
      >"$case_dir/out" 2>"$case_dir/err"; then
    sed 's/^/[g4-evidence] /' "$case_dir/err" >&2
    fail "fixed G4 evidence runner failed"
  fi

  [[ "$(grep -c '^api-keys$' "$case_dir/state/operations")" == "50" ]] || \
    fail "G4 evidence runner did not execute exactly 50 ApiKeyService CLI operations"
  [[ "$(grep -c '^whoami$' "$case_dir/state/operations")" == "10" ]] || \
    fail "G4 evidence runner did not execute exactly ten identity checks"
  [[ "$(grep -c 'CODEWIRE_APIKEY_PROD_SMOKE_BOOTSTRAP_KEY' "$case_dir/infisical.log")" == "5" ]] || \
    fail "G4 evidence runner did not load the primary fixture exactly five times"
  [[ "$(grep -c 'CODEWIRE_APIKEY_PROD_EVIDENCE_SECONDARY_BOOTSTRAP_KEY' "$case_dir/infisical.log")" == "5" ]] || \
    fail "G4 evidence runner did not load the secondary fixture exactly five times"
  grep -F 'principals=2 cycles_each=5' "$case_dir/err" >/dev/null
  grep -F 'expected_rpc_minimum=50' "$case_dir/err" >/dev/null
  assert_secret_absent "$case_dir/out"
  assert_secret_absent "$case_dir/err"
  assert_secret_absent "$case_dir/infisical.log"

  set +e
  PATH="$bin_dir:$PATH" \
    CW_BIN="$case_dir/cw" \
    FAKE_CW_VERSION="v0.3.360" \
    FAKE_CW_STATE="$case_dir/state" \
    FAKE_PROD_BOOTSTRAP="$PROD_BOOTSTRAP" \
    FAKE_EVIDENCE_BOOTSTRAP="$EVIDENCE_BOOTSTRAP" \
    FAKE_NEW_KEY="$NEW_KEY" \
    "$ROOT/scripts/runtime/apikey/run-apikey-g4-evidence.sh" \
      --release-tag v0.3.360 --confirm WRONG \
      >"$case_dir/reject.out" 2>"$case_dir/reject.err"
  rc=$?
  set -e
  [[ "$rc" != "0" ]] || fail "G4 evidence runner accepted an incorrect confirmation"
  grep -F 'requires the exact confirmation phrase' "$case_dir/reject.err" >/dev/null
}

write_g4_event_fixture() {
  local output="$1"
  local bad_kind="${2:-none}"
  local shape="${3:-flat}"
  local primary="40d8b5abc54058a49b91a0c4c64aeaf6"
  local secondary="253db3f72f82d2d63293548fef910309"
  local fingerprint code
  : >"$output"

  for index in $(seq 1 50); do
    if ((index <= 25)); then
      fingerprint="$primary"
    else
      fingerprint="$secondary"
    fi
    code="ok"
    if [[ "$bad_kind" == "severe" && "$index" == "1" ]]; then
      code="internal"
    elif [[ "$bad_kind" == "missing-code" && "$index" == "1" ]]; then
      code=""
    elif [[ "$bad_kind" == "principal" && "$index" == "50" ]]; then
      fingerprint="11111111111111111111111111111111"
    fi
    if [[ "$shape" == "tracing" ]]; then
      jq -cn \
        --arg timestamp "2026-07-13T12:00:30.123456Z" \
        --arg code "$code" \
        --arg fingerprint "$fingerprint" \
        '{
          timestamp: $timestamp,
          level: "INFO",
          target: "connect_rpc",
          fields: {
            message: "connect rpc",
            service: "codewire.v1.ApiKeyService",
            method: "ListApiKeys",
            code: $code,
            synthetic: true,
            principal_fingerprint: $fingerprint,
            user_agent: "codewire-cli/v0.3.360"
          }
        }' >>"$output"
    else
      jq -cn \
        --arg timestamp "2026-07-13T12:00:30.123456Z" \
        --arg code "$code" \
        --arg fingerprint "$fingerprint" \
        '{
          timestamp: $timestamp,
          target: "connect_rpc",
          service: "codewire.v1.ApiKeyService",
          method: "ListApiKeys",
          code: $code,
          synthetic: true,
          principal_fingerprint: $fingerprint,
          user_agent: "codewire-cli/v0.3.360"
        }' >>"$output"
    fi
  done
}

test_g4_event_verifier() {
  local case_dir="$TEST_TMP/g4-verifier"
  local expected
  mkdir -p "$case_dir"

  expected="$(printf 'codewire.connect_rpc.principal.v1\0%s' \
    '627a3c7cad1f50a7b44c00de1e054df9' | sha256sum | cut -c1-32)"
  [[ "$expected" == "40d8b5abc54058a49b91a0c4c64aeaf6" ]] || \
    fail "primary production evidence fingerprint drifted"
  expected="$(printf 'codewire.connect_rpc.principal.v1\0%s' \
    '258099727105fa93538769d4e3498b24' | sha256sum | cut -c1-32)"
  [[ "$expected" == "253db3f72f82d2d63293548fef910309" ]] || \
    fail "secondary production evidence fingerprint drifted"

  write_g4_event_fixture "$case_dir/good.ndjson"
  "$ROOT/scripts/runtime/apikey/verify-apikey-g4-events.sh" \
    --release-tag v0.3.360 \
    --started-at 2026-07-13T12:00:00Z \
    --completed-at 2026-07-13T12:00:59Z \
    <"$case_dir/good.ndjson" >"$case_dir/good.json" 2>"$case_dir/good.err"
  [[ "$(jq -r '.api_key_rpc_events' "$case_dir/good.json")" == "50" ]] || \
    fail "G4 verifier reported an incorrect event count"
  [[ "$(jq -r '.principal_counts | length' "$case_dir/good.json")" == "2" ]] || \
    fail "G4 verifier reported an incorrect principal count"

  write_g4_event_fixture "$case_dir/good-tracing.ndjson" none tracing
  "$ROOT/scripts/runtime/apikey/verify-apikey-g4-events.sh" \
    --release-tag v0.3.360 \
    --started-at 2026-07-13T12:00:00Z \
    --completed-at 2026-07-13T12:00:59Z \
    <"$case_dir/good-tracing.ndjson" \
    >"$case_dir/good-tracing.json" 2>"$case_dir/good-tracing.err"
  [[ "$(jq -r '.api_key_rpc_events' "$case_dir/good-tracing.json")" == "50" ]] || \
    fail "G4 verifier did not unwrap the live tracing JSON envelope"

  for bad_kind in severe missing-code principal; do
    write_g4_event_fixture "$case_dir/$bad_kind.ndjson" "$bad_kind"
    set +e
    "$ROOT/scripts/runtime/apikey/verify-apikey-g4-events.sh" \
      --release-tag v0.3.360 \
      --started-at 2026-07-13T12:00:00Z \
      --completed-at 2026-07-13T12:00:59Z \
      <"$case_dir/$bad_kind.ndjson" \
      >"$case_dir/$bad_kind.out" 2>"$case_dir/$bad_kind.err"
    rc=$?
    set -e
    [[ "$rc" != "0" ]] || fail "G4 verifier accepted $bad_kind evidence"
    grep -F 'did not satisfy G4' "$case_dir/$bad_kind.err" >/dev/null
  done
}

test_g4_runbook_collection_contract() {
  local runbook="$ROOT/docs/runbooks/connect-apikey-lifecycle-smoke.md"

  grep -F -- '--tail=-1 \' "$runbook" >/dev/null || \
    fail "G4 runbook collector can silently accept kubectl selector tail truncation"
}

test_workflow_protoc_pin() {
  local workflow="$ROOT/.gitea/workflows/connect-apikey-smoke.yaml"
  local version checksum
  version="$(awk '$1 == "PROTOC_VERSION" && $2 == ":=" { print $3; exit }' "$ROOT/Makefile")"
  checksum="$(awk '$1 == "PROTOC_SHA256_LINUX_X86_64" && $2 == ":=" { print $3; exit }' "$ROOT/Makefile")"

  [[ -n "$version" && -n "$checksum" ]] || fail "could not read the canonical protoc pin"
  grep -F "protobuf/releases/download/v${version}/protoc-${version}-linux-x86_64.zip" \
    "$workflow" >/dev/null || fail "workflow protoc version drifted from Makefile"
  grep -F "${checksum}  /tmp/protoc.zip" "$workflow" >/dev/null || \
    fail "workflow protoc checksum drifted from Makefile"
  grep -F "echo \"\$HOME/.proto-tools/protoc/bin\" >> \"\$GITHUB_PATH\"" \
    "$workflow" >/dev/null || fail "workflow does not export pinned protoc to later steps"
}

test_workflow_g4_evidence_contract() {
  local workflow="$ROOT/.gitea/workflows/connect-apikey-smoke.yaml"
  local release_line evidence_line

  grep -F '          - prod-evidence' "$workflow" >/dev/null || \
    fail "workflow is missing the fixed production evidence target"
  grep -F "test \"\$PRODUCTION_CONFIRMATION\" = 'RUN APIKEY PROD EVIDENCE'" \
    "$workflow" >/dev/null || fail "workflow is missing the exact evidence confirmation"
  grep -F "[[ \"\$RELEASE_TAG\" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+\$ ]]" \
    "$workflow" >/dev/null || fail "workflow does not require an exact stable release tag"
  grep -F "group: connect-apikey-production-fixtures" "$workflow" >/dev/null || \
    fail "workflow does not serialize all production fixture access"
  grep -F "if: \${{ inputs.target == 'prod-evidence' }}" "$workflow" >/dev/null || \
    fail "workflow has no evidence-only release verification step"
  grep -F 'scripts/ci/release/verify-release-tag-ref.sh' "$workflow" >/dev/null || \
    fail "workflow does not verify canonical release tag provenance"
  grep -F "for asset in SHA256SUMS SHA256SUMS.asc \"\$binary\"" "$workflow" >/dev/null || \
    fail "workflow does not fetch the binary and signed checksum manifest"
  grep -F "gpg --batch --verify \"\$work/SHA256SUMS.asc\" \"\$work/SHA256SUMS\"" \
    "$workflow" >/dev/null || fail "workflow does not verify the release signature"
  grep -F "(cd \"\$work\" && sha256sum --check expected)" "$workflow" >/dev/null || \
    fail "workflow does not verify the exact binary checksum"
  grep -F 'scripts/runtime/apikey/run-apikey-g4-evidence.sh' "$workflow" >/dev/null || \
    fail "workflow does not invoke the fixed evidence runner"

  release_line="$(grep -n -m1 'name: Download and verify exact signed release CLI' "$workflow" | cut -d: -f1)"
  evidence_line="$(grep -n -m1 'name: Run fixed two-principal G4 evidence sequence' "$workflow" | cut -d: -f1)"
  [[ -n "$release_line" && -n "$evidence_line" && "$release_line" -lt "$evidence_line" ]] || \
    fail "workflow must verify the release before loading evidence credentials"
}

test_secret_wrapper
test_lifecycle
test_provisioner
test_g4_evidence_runner
test_g4_event_verifier
test_g4_runbook_collection_contract
test_workflow_protoc_pin
"$ROOT/scripts/runtime/tests/test-with-dev-smoke-auth.sh"
test_workflow_g4_evidence_contract
printf 'apikey operational smoke shell tests: OK\n'
