#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly SELECTOR="$ROOT/scripts/ci/setup/select-untrusted-rust-cache.sh"
readonly FINISHER="$ROOT/scripts/ci/setup/finish-untrusted-rust-cache.sh"

fail() {
  printf '[test-select-untrusted-rust-cache] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/host-sccache.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/runner"

cat >"$work/bin/sccache" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${SCCACHE_CALLS:?}"
case "${1:-}" in
  --version) printf '%s\n' 'sccache 0.17.0' ;;
  --start-server)
    printf 'start bucket=%s uds=%s conf=%s idle=%s\n' "${SCCACHE_BUCKET:-none}" \
      "${SCCACHE_SERVER_UDS:-none}" "${SCCACHE_CONF:-none}" "${SCCACHE_IDLE_TIMEOUT:-none}" \
      >>"$SCCACHE_CALLS"
    # Model a server whose startup times out against an unreachable R2, or
    # one that cannot start at all.
    case "${FAKE_SCCACHE_START:-ok}" in
      ok) ;;
      fail-r2) [[ -z "${SCCACHE_BUCKET:-}" ]] || exit 2 ;;
      *) exit 2 ;;
    esac
    ;;
  --stop-server) printf 'stop uds=%s\n' "${SCCACHE_SERVER_UDS:-none}" >>"$SCCACHE_CALLS" ;;
  --zero-stats|--show-stats) ;;
  *) exit 64 ;;
esac
SH
cat >"$work/bin/fetch-success" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "${CODEWIRE_R2_CACHE_TRUST:-unset}" >>"${FETCH_TRUST:?}"
printf '%s\n' '[default]' 'aws_access_key_id = synthetic-access' \
  'aws_secret_access_key = synthetic-secret' >"$1"
chmod 0600 "$1"
SH
cat >"$work/bin/fetch-failure" <<'SH'
#!/usr/bin/env bash
exit 1
SH
chmod 0755 "$work/bin/sccache" "$work/bin/fetch-success" "$work/bin/fetch-failure"

run_selector() {
  local request="$1" fetcher="$2" env_file="$3" credentials="$4"
  : >"$env_file"
  PATH="$work/bin:$PATH" \
    RUNNER_TEMP="$work/runner" \
    GITHUB_WORKSPACE="$ROOT" \
    GITHUB_ENV="$env_file" \
    SCCACHE_CALLS="$work/sccache.calls" \
    FETCH_TRUST="$work/fetch.trust" \
    GITHUB_EVENT_NAME="${SELECT_EVENT:-pull_request}" \
    GITHUB_REF="${SELECT_REF:-refs/pull/1748/head}" \
    CODEWIRE_SCCACHE_REQUEST="$request" \
    OPENBAO_SCCACHE_FETCHER="$fetcher" \
    "$SELECTOR" "$credentials"
}

: >"$work/sccache.calls"
r2_env="$work/r2.env"
r2_credentials="$work/runner/r2.aws"
run_selector auto "$work/bin/fetch-success" "$r2_env" "$r2_credentials" \
  >"$work/r2.out"
grep -Fxq 'CODEWIRE_SCCACHE_MODE=r2' "$r2_env" || fail 'R2 mode was not selected'
grep -Fxq 'RUSTC_WRAPPER=/usr/local/bin/sccache' "$r2_env" || fail 'host rustc wrapper is missing'
grep -Fxq "SCCACHE_BASEDIRS=$ROOT" "$r2_env" || fail 'checkout path is not normalized'
grep -Fxq 'SCCACHE_IGNORE_SERVER_IO_ERROR=1' "$r2_env" || fail 'cache failure is not best effort'
# A pull request reads main's caches read-only and writes nothing remote.
grep -Fxq 'SCCACHE_BUCKET=example-ci-cache-main' "$r2_env" || fail 'R2 bucket is not exact'
grep -Fxq 'SCCACHE_S3_KEY_PREFIX=main/codewire/v1' "$r2_env" || fail 'main prefix is not exact'
grep -Fxq 'SCCACHE_S3_RW_MODE=READ_ONLY' "$r2_env" || fail 'a pull request may write the main cache'
grep -Fxq 'CODEWIRE_R2_CACHE_TRUST=main-read' "$r2_env" || fail 'pull-request trust is not main-read'
[[ "$(tail -n 1 "$work/fetch.trust")" == main-read ]] || fail 'fetcher was not asked for the main-read token'
if grep -Fq untrusted "$r2_env"; then fail 'a pull request selected the untrusted cache'; fi
grep -Fxq "AWS_SHARED_CREDENTIALS_FILE=$r2_credentials" "$r2_env" || fail 'private credential path is not selected'
# The server starts during selection, with the minute-long startup wait and an
# idle timeout longer than any job, on the R2 mode's own socket.
grep -Fxq "start bucket=example-ci-cache-main uds=$work/runner/codewire-sccache-r2.sock conf=$work/runner/codewire-sccache.conf idle=3600" \
  "$work/sccache.calls" || fail 'R2 server was not started during selection'
grep -Fxq "SCCACHE_SERVER_UDS=$work/runner/codewire-sccache-r2.sock" "$r2_env" || fail 'R2 socket is not selected'
grep -Fxq "SCCACHE_CONF=$work/runner/codewire-sccache.conf" "$r2_env" || fail 'startup timeout config is not selected'
grep -Fxq 'SCCACHE_IDLE_TIMEOUT=3600' "$r2_env" || fail 'server may idle out within a job'
[[ "$(cat "$work/runner/codewire-sccache.conf")" == 'server_startup_timeout_ms = 60000' ]] ||
  fail 'startup timeout config is not exact'
grep -Fxq 'CODEWIRE_CI_CACHE state=remote-selected backend=r2 trust=main-read' "$work/r2.out" ||
  fail 'R2 selection did not report its state'
[[ "$(stat -c '%a' "$r2_credentials")" == 600 ]] || fail 'R2 credential is not private'
if rg -n 'synthetic-(access|secret)' "$r2_env" "$work/r2.out"; then
  fail 'credential value escaped into job environment or output'
fi

PATH="$work/bin:$PATH" RUNNER_TEMP="$work/runner" SCCACHE_CALLS="$work/sccache.calls" \
  CODEWIRE_SCCACHE_MODE=r2 "$FINISHER" "$r2_credentials" >"$work/finish.out"

# A canonical-main push selects only the main bucket and prefix.
main_env="$work/main.env"
main_credentials="$work/runner/main.aws"
SELECT_EVENT=push SELECT_REF=refs/heads/main \
  run_selector auto "$work/bin/fetch-success" "$main_env" "$main_credentials" >"$work/main.out"
grep -Fxq 'SCCACHE_BUCKET=example-ci-cache-main' "$main_env" || fail 'main bucket is not exact'
grep -Fxq 'SCCACHE_S3_KEY_PREFIX=main/codewire/v1' "$main_env" || fail 'main prefix is not exact'
if grep -Eq 'untrusted|READ_ONLY' "$main_env"; then
  fail 'canonical main selected an untrusted or read-only cache'
fi
[[ "$(tail -n 1 "$work/fetch.trust")" == main ]] || fail 'fetcher was not asked for the main token'
grep -Fxq 'CODEWIRE_CI_CACHE state=remote-selected backend=r2 trust=main' "$work/main.out" ||
  fail 'main selection did not report its trust'
PATH="$work/bin:$PATH" RUNNER_TEMP="$work/runner" SCCACHE_CALLS="$work/sccache.calls" \
  CODEWIRE_SCCACHE_MODE=r2 "$FINISHER" "$main_credentials" >/dev/null
[[ ! -e "$r2_credentials" ]] || fail 'cleanup retained the private R2 credential'
grep -Fxq -- '--show-stats' "$work/sccache.calls" || fail 'cleanup omitted cache statistics'
grep -Fxq -- '--stop-server' "$work/sccache.calls" || fail 'cleanup omitted daemon shutdown'

local_env="$work/local.env"
local_credentials="$work/runner/local.aws"
run_selector auto "$work/bin/fetch-failure" "$local_env" "$local_credentials" \
  >"$work/local.out"
grep -Fxq 'CODEWIRE_SCCACHE_MODE=local' "$local_env" || fail 'failed identity did not fall back locally'
if grep -q '^SCCACHE_BUCKET=' "$local_env"; then
  fail 'local fallback retained a remote bucket'
fi
[[ ! -e "$local_credentials" ]] || fail 'local fallback retained a credential file'

# An R2 server that cannot start falls back to the local disk cache, with no
# remote variable or credential left for later steps.
: >"$work/sccache.calls"
fallback_env="$work/fallback.env"
fallback_credentials="$work/runner/fallback.aws"
FAKE_SCCACHE_START=fail-r2 run_selector auto "$work/bin/fetch-success" "$fallback_env" \
  "$fallback_credentials" >"$work/fallback.out"
grep -Fxq 'CODEWIRE_SCCACHE_MODE=local' "$fallback_env" || fail 'R2 start failure did not fall back locally'
grep -Fxq "SCCACHE_SERVER_UDS=$work/runner/codewire-sccache-local.sock" "$fallback_env" ||
  fail 'local fallback shares the R2 socket'
if grep -Eq '^(SCCACHE_BUCKET|SCCACHE_ENDPOINT|SCCACHE_MULTILEVEL_CHAIN|AWS_SHARED_CREDENTIALS_FILE|CODEWIRE_SCCACHE_CREDENTIALS_FILE)=' \
    "$fallback_env"; then
  fail 'local fallback retained remote cache configuration'
fi
[[ ! -e "$fallback_credentials" ]] || fail 'local fallback retained the R2 credential'
[[ "$(grep -c '^start ' "$work/sccache.calls")" == 2 ]] || fail 'fallback did not retry once locally'
grep -Fxq '::warning::The R2 sccache server did not start; continuing with the job-local cache' \
  "$work/fallback.out" || fail 'R2 start failure was not warned'
[[ "$(grep -c '^CODEWIRE_CI_CACHE ' "$work/fallback.out")" == 1 ]] &&
  grep -Fxq 'CODEWIRE_CI_CACHE state=server-unavailable backend=r2 fallback=local' "$work/fallback.out" ||
  fail 'R2 start failure did not report exactly one status line'
if rg -n 'synthetic-(access|secret)' "$fallback_env" "$work/fallback.out"; then
  fail 'credential value escaped during fallback'
fi

# When no server starts, the job compiles without a compiler cache.
none_env="$work/none.env"
none_credentials="$work/runner/none.aws"
FAKE_SCCACHE_START=fail run_selector auto "$work/bin/fetch-success" "$none_env" \
  "$none_credentials" >"$work/none.out"
grep -Fxq 'CODEWIRE_SCCACHE_MODE=disabled' "$none_env" || fail 'unstartable sccache was not disabled'
if grep -q '^RUSTC_WRAPPER=' "$none_env"; then
  fail 'an unstartable sccache left the rustc wrapper installed'
fi
[[ ! -e "$none_credentials" ]] || fail 'disabled fallback retained the R2 credential'
[[ "$(grep -c '^CODEWIRE_CI_CACHE ' "$work/none.out")" == 2 ]] &&
  grep -Fxq 'CODEWIRE_CI_CACHE state=server-unavailable backend=local fallback=disabled' "$work/none.out" &&
  [[ "$(grep -c '^::warning::' "$work/none.out")" == 2 ]] ||
  fail 'each fallback did not report one warning and one status line'

explicit_env="$work/explicit.env"
FAKE_SCCACHE_START=fail run_selector local "$work/bin/fetch-success" "$explicit_env" \
  "$work/runner/explicit.aws" >"$work/explicit.out"
grep -Fxq 'CODEWIRE_SCCACHE_MODE=disabled' "$explicit_env" || fail 'explicit local start failure was not disabled'
if grep -Fq 'state=explicit backend=local' "$work/explicit.out"; then
  fail 'explicit local reported success after its server failed'
fi

# Cleanup also stops a late R2 server that came up after its start timed out.
# A Unix socket path is limited to 108 bytes, so this runner directory is short.
late_runner="$(mktemp -d /tmp/cw-sccache.XXXXXX)"
trap 'rm -rf "$work" "$late_runner"' EXIT
: >"$work/sccache.calls"
python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' \
  "$late_runner/codewire-sccache-r2.sock"
PATH="$work/bin:$PATH" RUNNER_TEMP="$late_runner" SCCACHE_CALLS="$work/sccache.calls" \
  CODEWIRE_SCCACHE_MODE=local SCCACHE_SERVER_UDS="$late_runner/codewire-sccache-local.sock" \
  "$FINISHER" "$late_runner/late.aws" >/dev/null
grep -Fxq "stop uds=$late_runner/codewire-sccache-local.sock" "$work/sccache.calls" ||
  fail 'cleanup did not stop the selected server'
grep -Fxq "stop uds=$late_runner/codewire-sccache-r2.sock" "$work/sccache.calls" ||
  fail 'cleanup left a late R2 server running'

disabled_env="$work/disabled.env"
disabled_credentials="$work/runner/disabled.aws"
run_selector disabled "$work/bin/fetch-success" "$disabled_env" "$disabled_credentials" \
  >"$work/disabled.out"
grep -Fxq 'CODEWIRE_SCCACHE_MODE=disabled' "$disabled_env" || fail 'explicit disable was ignored'
if grep -q '^RUSTC_WRAPPER=' "$disabled_env"; then
  fail 'disabled mode installed a rustc wrapper'
fi

if RUNNER_TEMP="$work/runner" GITHUB_WORKSPACE="$ROOT" GITHUB_ENV="$work/escape.env" \
    "$SELECTOR" "$work/escape.aws" >/dev/null 2>&1; then
  fail 'selector accepted a credential path outside RUNNER_TEMP'
fi
if RUNNER_TEMP="$work/runner" "$FINISHER" "$work/escape.aws" >/dev/null 2>&1; then
  fail 'cleanup accepted a credential path outside RUNNER_TEMP'
fi

printf '[test-select-untrusted-rust-cache] host cache selection contract passed\n'
