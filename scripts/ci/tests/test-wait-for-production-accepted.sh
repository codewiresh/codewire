#!/usr/bin/env bash
# Fixtures for wait-for-production-accepted.sh: a cli-release signing job
# waits until Production accepted the release, passes once it has, and fails
# at the deadline without going on (#4492).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/production-wait.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  printf '[test-wait-for-production-accepted] ERROR: %s\n' "$*" >&2
  exit 1
}

readonly TAG=v1.2.3
readonly OBJECT=3333333333333333333333333333333333333333
readonly SHA=1111111111111111111111111111111111111111
readonly TOKEN=forgejo-production-token-canary-5c19

# The wait runs the check beside it, so each case runs a copy of the script
# next to a stub check. The stub accepts on call FIXTURE_ACCEPT_ON (never
# when 0), records each call's arguments, and records whether the token
# reached it.
mkdir "$TMP/release"
cp "$ROOT/scripts/ci/release/wait-for-production-accepted.sh" "$TMP/release/"
cat >"$TMP/release/require-production-accepted.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
calls=$(( $(wc -l <"$FIXTURE_CALLS") + 1 ))
printf '%s %s\n' "$*" "${GITEA_TOKEN:-no-token}" >>"$FIXTURE_CALLS"
if [ "$FIXTURE_ACCEPT_ON" -ne 0 ] && [ "$calls" -ge "$FIXTURE_ACCEPT_ON" ]; then
  echo 'production acceptance proven: deploy-prod run 500'
  exit 0
fi
echo "production acceptance not proven: no deploy-prod run accepted $1 yet (call $calls)" >&2
exit 1
EOF
chmod +x "$TMP/release/require-production-accepted.sh"

run_wait() { # NAME ACCEPT_ON WAIT_SECONDS
  : >"$TMP/$1.calls"
  env -u GITEA_TOKEN FIXTURE_CALLS="$TMP/$1.calls" FIXTURE_ACCEPT_ON="$2" \
    GITEA_TOKEN="$TOKEN" PRODUCTION_WAIT_SECONDS="$3" PRODUCTION_POLL_SECONDS=0 \
    RUNNER_TEMP="$TMP" \
    "$TMP/release/wait-for-production-accepted.sh" "$TAG" "$OBJECT" "$SHA" >"$TMP/$1.out" 2>&1
}

# Already accepted: one check, and it passes.
run_wait accepted 1 60 || fail "an accepted release was refused: $(cat "$TMP/accepted.out")"
[ "$(wc -l <"$TMP/accepted.calls")" -eq 1 ] || fail 'an accepted release was checked more than once'
grep -Fxq "$TAG $OBJECT $SHA $TOKEN" "$TMP/accepted.calls" ||
  fail 'the check did not get the exact tag, object, commit and token'
grep -Fq "production acceptance: Production accepted $TAG after" "$TMP/accepted.out" ||
  fail 'the wait did not say Production accepted the release'

# Accepted on the third check: it waits, says why, and then passes.
run_wait later 3 60 || fail "a release accepted while waiting was refused: $(cat "$TMP/later.out")"
[ "$(wc -l <"$TMP/later.calls")" -eq 3 ] || fail 'the wait did not check until Production accepted'
[ "$(grep -c 'production acceptance: waiting for Production to accept v1.2.3' "$TMP/later.out")" -eq 2 ] ||
  fail 'the wait did not report each check that found no acceptance'
grep -Fq 'no deploy-prod run accepted v1.2.3 yet (call 2)' "$TMP/later.out" ||
  fail "the wait did not show the check's reason"

# Never accepted: it fails at the deadline, saying nothing was signed.
if run_wait never 0 1; then
  fail 'a release Production never accepted passed the wait'
fi
grep -Fq "Production did not accept $TAG within 1s; nothing was signed or published" "$TMP/never.out" ||
  fail "the deadline was not explained: $(cat "$TMP/never.out")"
[ "$(wc -l <"$TMP/never.calls")" -ge 1 ] || fail 'the wait gave up without checking'

# Without the job token it refuses before checking anything.
: >"$TMP/notoken.calls"
if env -u GITEA_TOKEN FIXTURE_CALLS="$TMP/notoken.calls" FIXTURE_ACCEPT_ON=1 RUNNER_TEMP="$TMP" \
    "$TMP/release/wait-for-production-accepted.sh" "$TAG" "$OBJECT" "$SHA" >"$TMP/notoken.out" 2>&1; then
  fail 'the wait ran without a token'
fi
[ ! -s "$TMP/notoken.calls" ] || fail 'the wait checked without a token'

# The token never reaches the output.
! grep -Fq "$TOKEN" "$TMP/accepted.out" "$TMP/later.out" "$TMP/never.out" ||
  fail 'the token reached the output'

echo '[test-wait-for-production-accepted] waits for Production, passes once it accepts, fails at the deadline'
