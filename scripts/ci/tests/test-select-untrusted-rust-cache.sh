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
  --zero-stats|--show-stats|--stop-server) ;;
  *) exit 64 ;;
esac
SH
cat >"$work/bin/fetch-success" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
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
grep -Fxq 'SCCACHE_BUCKET=example-ci-cache-untrusted' "$r2_env" || fail 'R2 bucket is not exact'
grep -Fxq 'SCCACHE_S3_KEY_PREFIX=untrusted/codewire/v1' "$r2_env" || fail 'untrusted prefix is not exact'
grep -Fxq "AWS_SHARED_CREDENTIALS_FILE=$r2_credentials" "$r2_env" || fail 'private credential path is not selected'
[[ "$(stat -c '%a' "$r2_credentials")" == 600 ]] || fail 'R2 credential is not private'
if rg -n 'synthetic-(access|secret)' "$r2_env" "$work/r2.out"; then
  fail 'credential value escaped into job environment or output'
fi

PATH="$work/bin:$PATH" RUNNER_TEMP="$work/runner" SCCACHE_CALLS="$work/sccache.calls" \
  CODEWIRE_SCCACHE_MODE=r2 "$FINISHER" "$r2_credentials" >"$work/finish.out"
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
