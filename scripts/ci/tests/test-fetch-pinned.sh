#!/usr/bin/env bash
# fetch-pinned.sh bounds every attempt, retries only transient failures with a
# logged marker, and never leaves a file that differs from its pin (#2691).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly FETCH="$ROOT/scripts/ci/release/fetch-pinned.sh"
readonly URL='https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip'

fail() {
  printf 'fetch-pinned contract: %s\n' "$*" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/bin"
# The fake curl answers each call from FAKE_CURL_PLAN: one "exit:http_code"
# entry per attempt; exit 0 writes FAKE_CURL_BODY to the --output file.
cat >"$work/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_CURL_CALLS:?}"
call="$(wc -l <"$FAKE_CURL_CALLS")"
entry="$(sed -n "${call}p" "${FAKE_CURL_PLAN:?}")"
status="${entry%%:*}" code="${entry#*:}"
output=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [ "$status" = 0 ]; then
  printf '%s' "${FAKE_CURL_BODY:?}" >"$output"
else
  printf 'partial' >"$output"
  echo "curl: ($status) synthetic failure" >&2
fi
printf '%s' "$code"
exit "$status"
EOF
chmod +x "$work/bin/curl"

body='pinned bytes'
digest="$(printf '%s' "$body" | sha256sum | cut -c1-64)"
export PATH="$work/bin:$PATH" FAKE_CURL_BODY="$body" FETCH_PINNED_RETRY_DELAY_SECONDS=0

# run NAME PLAN...: runs one fetch with that plan; sets status and out.
run() {
  local name="$1"
  shift
  printf '%s\n' "$@" >"$work/$name.plan"
  : >"$work/$name.calls"
  status=0
  FAKE_CURL_PLAN="$work/$name.plan" FAKE_CURL_CALLS="$work/$name.calls" \
    "$FETCH" "$URL" "$digest" "$work/$name.out" >"$work/$name.log" 2>&1 || status=$?
  out="$work/$name.out"
}
calls() { wc -l <"$work/$1.calls"; }

# A stalled TLS handshake, a reset and a 503 are retried, then the pinned file
# lands with a marker for each retry.
run recover 28:000 35:000 22:503 0:200
[ "$status" = 0 ] || fail "transient failures did not recover: $(cat "$work/recover.log")"
[ "$(calls recover)" = 4 ] || fail 'transient failures did not use four attempts'
[ "$(cat "$out")" = "$body" ] || fail 'the recovered download is not the pinned file'
[ "$(grep -c '^\[external-download\] transient failure ' "$work/recover.log")" = 3 ] ||
  fail 'each retry is not logged with its fixed marker'
grep -qF 'reason="curl exit 28"; retrying in 0s (attempt 2/5)' "$work/recover.log" ||
  fail 'a retry does not name its reason and bound'
grep -qF 'reason="HTTP 503"' "$work/recover.log" || fail 'a 503 retry does not name its status'
grep -qF "[external-download] fetched url=$URL sha256=$digest attempt=4" "$work/recover.log" ||
  fail 'the fetched marker does not name the attempt'
[ ! -e "$out.partial" ] || fail 'a partial download was left behind'

# Every attempt carries the connect, speed and total bounds, https only.
for flag in "--connect-timeout 20" "--speed-limit 1024 --speed-time 30" "--max-time 900" \
    "--proto =https --proto-redir =https"; do
  [ "$(grep -cF -- "$flag" "$work/recover.calls")" = 4 ] || fail "an attempt lacks $flag"
done

# Five attempts at most, then a fixed exhaustion marker and no file.
run exhausted 7:000 7:000 7:000 7:000 7:000 0:200
[ "$status" = 7 ] || fail "exhausted retries returned $status"
[ "$(calls exhausted)" = 5 ] || fail 'retries exceeded five attempts'
grep -qF "[external-download] class=transient-exhausted url=$URL reason=\"curl exit 7\" attempts=5" \
  "$work/exhausted.log" || fail 'exhausted retries lack their fixed marker'
[ ! -e "$out" ] && [ ! -e "$out.partial" ] || fail 'an exhausted download left a file'

# A 404 and an unknown curl failure fail at once.
run missing 22:404 0:200
[ "$status" = 22 ] && [ "$(calls missing)" = 1 ] || fail 'a 404 was retried'
grep -qF 'answered HTTP 404' "$work/missing.log" || fail 'a 404 does not name its status'
run usage 3:000 0:200
[ "$status" = 3 ] && [ "$(calls usage)" = 1 ] || fail 'a non-transient curl failure was retried'

# Bytes that differ from the pin fail without a retry and leave nothing.
FAKE_CURL_BODY='other bytes' run mismatch 0:200 0:200
[ "$status" = 1 ] && [ "$(calls mismatch)" = 1 ] || fail 'a checksum mismatch was retried or accepted'
grep -qF 'does not match its pinned SHA-256' "$work/mismatch.log" || fail 'a mismatch is not reported'
[ ! -e "$out" ] && [ ! -e "$out.partial" ] || fail 'a mismatched download left a file'

# Only an https URL and a SHA-256 pin are accepted.
for args in "http://example.invalid/x $digest" "$URL ${digest:0:63}" "$URL ${digest^^}"; do
  # shellcheck disable=SC2086
  if "$FETCH" $args "$work/refused.out" >/dev/null 2>&1; then
    fail "refused arguments were accepted: $args"
  fi
done

printf 'fetch-pinned contract: OK\n'
