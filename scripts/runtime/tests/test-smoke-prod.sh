#!/usr/bin/env bash
# The authenticated Production smoke (scripts/ci/verify/smoke-prod.sh) against
# a fake cw (#4135): as the Production smoke identity it needs no preset or
# repository, and a key that is not that identity's stops it before anything is
# created.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SMOKE="$ROOT/scripts/ci/verify/smoke-prod.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/smoke-prod-tests.XXXXXX")"
trap 'rm -rf -- "$TEST_TMP"' EXIT

readonly API_KEY="cw_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
readonly SMOKE_EMAIL="prod-smoke@example.invalid"

fail() { printf 'smoke-prod tests: %s\n' "$*" >&2; exit 1; }

# The fake cw: logs each call, and answers as a healthy Production would, with
# whoami naming FAKE_WHOAMI_EMAIL.
mkdir "$TEST_TMP/bin"
cat >"$TEST_TMP/bin/cw" <<'FAKE_CW'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == --server ]] && shift 2
printf '%s\n' "$*" >>"$FAKE_CALLS"
[[ "${CODEWIRE_API_KEY:-}" == cw_* ]] || exit 90
case "$1" in
  whoami) printf '{"id":"user-smoke","email":"%s"}\n' "$FAKE_WHOAMI_EMAIL" ;;
  create) printf '{"id":"env-smoke"}\n' ;;
  info) printf '{"state":"running"}\n' ;;
  run) if [[ "$*" == *' -- pwd' ]]; then printf '/workspace\n'; fi ;;
  cp|doctor|rm) ;;
  *) exit 91 ;;
esac
FAKE_CW
chmod +x "$TEST_TMP/bin/cw"

smoke() { # WHOAMI_EMAIL ARG...: the authenticated smoke only, as the smoke identity
  local email="$1"
  shift
  : >"$TEST_TMP/calls"
  env -u CODEWIRE_API_KEY FAKE_CALLS="$TEST_TMP/calls" FAKE_WHOAMI_EMAIL="$email" \
    CODEWIRE_PROD_SMOKE_API_KEY="$API_KEY" EXPECTED_CODEWIRE_PROD_SMOKE_USER_EMAIL="$SMOKE_EMAIL" \
    "$SMOKE" --authenticated --allow-prod-mutation --skip-kube --skip-public \
    --cw-bin "$TEST_TMP/bin/cw" --name smoke-test "$@" >"$TEST_TMP/out" 2>&1
}

# The smoke identity needs neither --preset nor --repo: the environment is bare.
smoke "$SMOKE_EMAIL" || fail "the bare smoke failed: $(cat "$TEST_TMP/out")"
create="$(grep '^create ' "$TEST_TMP/calls")" || fail 'the bare smoke created nothing'
for flag in --no-file --no-profile --no-network; do
  [[ " $create " == *" $flag "* ]] || fail "the bare create lacks $flag: $create"
done
[[ " $create " != *' --preset '* && " $create " != *' --repo '* ]] ||
  fail "the bare create named a preset or repository: $create"
grep -qx 'rm env-smoke --yes' "$TEST_TMP/calls" || fail 'the bare smoke did not remove its environment'

# A key that is not the smoke identity's fails loudly, before any create.
if smoke someone-else@example.invalid; then
  fail 'the smoke accepted another user'
fi
grep -qF 'cw whoami names another user than EXPECTED_CODEWIRE_PROD_SMOKE_USER_EMAIL' "$TEST_TMP/out" ||
  fail "another user was not named as the failure: $(cat "$TEST_TMP/out")"
! grep -q '^create ' "$TEST_TMP/calls" || fail 'the smoke created an environment as another user'
! grep -qF "$API_KEY" "$TEST_TMP/out" || fail 'the smoke printed its API key'

# A whoami with no user stops it too.
if smoke ''; then
  fail 'the smoke accepted a whoami with no user'
fi
grep -qF 'cw whoami named no user' "$TEST_TMP/out" || fail "an empty whoami was not named: $(cat "$TEST_TMP/out")"

# A preset and a repository, when given, reach the create.
smoke "$SMOKE_EMAIL" --preset node --repo https://example.invalid/app.git ||
  fail "the smoke with a preset failed: $(cat "$TEST_TMP/out")"
create="$(grep '^create ' "$TEST_TMP/calls")"
[[ " $create " == *' --preset node '* && " $create " == *' --repo https://example.invalid/app.git '* ]] ||
  fail "the preset and repository did not reach the create: $create"

# The public checks (#4155): the dashboard's /healthz answers 204 and
# orchestration's /readyz 200; a fake curl answers as Production does.
cat >"$TEST_TMP/bin/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail
url="${*: -1}"
case "$url" in
  */.well-known/openid-configuration) printf '{"issuer":"%s"}\n' "${url%/.well-known/openid-configuration}" ;;
  */healthz) printf '%s' "${FAKE_HEALTHZ:-204}" ;;
  */readyz|*/derp/latency-check) printf '200' ;;
  *) exit 92 ;;
esac
FAKE_CURL
chmod +x "$TEST_TMP/bin/curl"
public() { # the public checks only, with the fake curl
  env PATH="$TEST_TMP/bin:$PATH" "$SMOKE" --skip-kube >"$TEST_TMP/out" 2>&1
}
public || fail "the public checks refused Production's answers: $(cat "$TEST_TMP/out")"
grep -q '^dashboard healthz *204 ' "$TEST_TMP/out" || fail "the dashboard healthz was not checked: $(cat "$TEST_TMP/out")"
# A 200 there means /healthz no longer reaches the dashboard.
if FAKE_HEALTHZ=200 public; then
  fail 'the public checks accepted a healthz that is not the dashboard'
fi
grep -qF 'dashboard healthz returned HTTP 200' "$TEST_TMP/out" || fail "a wrong healthz was not named: $(cat "$TEST_TMP/out")"

printf 'smoke-prod tests: bare smoke, wrong user, empty whoami, preset passthrough and public checks checked\n'
