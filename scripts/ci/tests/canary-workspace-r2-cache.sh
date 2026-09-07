#!/usr/bin/env bash
# Explicit, bounded live experiment. Never called by policy tests or ordinary
# verification. The caller supplies an already-authorized untrusted cache file.
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: canary-workspace-r2-cache.sh AWS_CREDENTIALS_FILE NEW_REPORT_DIRECTORY' >&2; exit 2; }
if [[ "${CODEWIRE_R2_CANARY_BOUNDED_CHILD:-}" != 1 ]]; then
  exec timeout --signal=TERM --kill-after=45s 300s \
    env CODEWIRE_R2_CANARY_BOUNDED_CHILD=1 "$0" "$@"
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "$ROOT/scripts/ci/images/workspace-cache.sh"
export CODEWIRE_SCCACHE_CREDENTIALS_FILE="$1"
export CODEWIRE_SCCACHE_MODE=disabled CODEWIRE_BUILDKIT_CACHE_MODE=r2
export SCCACHE_BUCKET="$WORKSPACE_CACHE_BUCKET" SCCACHE_ENDPOINT="$WORKSPACE_CACHE_ENDPOINT"
export CODEWIRE_SCCACHE_PREFIX=untrusted/codewire/v1
workspace_cache_validate
report="$2"
[[ "$report" == /* && ! -e "$report" && ! -L "$report" \
    && "$(realpath -m -- "$report")" == "$report" ]] || { echo 'report path must be new and canonical' >&2; exit 2; }
umask 077
mkdir -m 0700 "$report"
work="$(mktemp -d "${TMPDIR:-/tmp}/codewire-r2-canary.XXXXXX")"
cleanup() {
  local status=$? cleanup_status=0
  trap - EXIT INT TERM
  workspace_cache_cleanup_builder || cleanup_status=$?
  rm -rf "$work"
  [[ "$status" != 0 || "$cleanup_status" == 0 ]] || status="$cleanup_status"
  # A late signal or report-write failure must not leave a success marker.
  [[ "$status" == 0 ]] || rm -f -- "$report/result.txt"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
case "$(uname -m)" in
  x86_64) architecture=amd64 ;;
  aarch64) architecture=arm64 ;;
  *) echo 'canary requires native amd64 or arm64' >&2; exit 2 ;;
esac
mkdir "$work/context"
printf 'FROM scratch\nCOPY payload /payload\n' >"$work/context/Dockerfile"
# Incompressible >5 MiB data exercises S3 multipart upload as well as ordinary
# manifest writes, HEAD and GET. It contains no repository or credential data.
python3 - "$work/context/payload" <<'PY'
import os, sys
from pathlib import Path
Path(sys.argv[1]).write_bytes(os.urandom(8 * 1024 * 1024))
PY
payload_sha="$(sha256sum "$work/context/payload" | cut -d ' ' -f 1)"
target="canary-${payload_sha:0:24}"
unset GITHUB_REF
cold_container=''
for phase in cold warm; do
  phase_work="$(mktemp -d "$work/$phase.XXXXXX")"
  workspace_cache_create_builder "$phase_work"
  if [[ "$phase" == cold ]]; then
    cold_container="$builder_container"
  else
    [[ "$builder_container" != "$cold_container" ]] || { echo 'canary reused the first daemon' >&2; exit 1; }
  fi
  started_at="$(date +%s)"
  # Two distinct daemons and state volumes; a warm hit must come from R2.
  workspace_cache_build "$target" "${payload_sha:0:40}" "$architecture" "$report/$phase.log" \
    --output "type=local,dest=$work/$phase-output" "$work/context"
  elapsed="$(( $(date +%s) - started_at ))"
  [[ "$workspace_cache_fallback" == false ]] || { echo 'R2 canary used a local fallback' >&2; exit 1; }
  cmp "$work/context/payload" "$work/$phase-output/payload"
  # Export is best effort in normal CI, but this experiment must prove it.
  if grep -Eqi '(ERROR|ignoring error|failed to (export|write|upload))' "$report/$phase.log"; then
    echo 'R2 canary did not complete a clean import/export' >&2; exit 1
  fi
  workspace_cache_cleanup_builder
  builder_created=false daemon_credentials=false
  printf '%s\t%s\n' "$phase" "$elapsed" >>"$report/timing.tsv"
  printf 'CODEWIRE_CI_PHASE name=workspace-r2-cache-canary phase=%s seconds=%s architecture=%s\n' \
    "$phase" "$elapsed" "$architecture"
done
if awk '/COPY payload \/payload/ { vertex=$1 } $1 == vertex && $2 == "CACHED" { hit=1 } END { exit !hit }' \
    "$report/cold.log"; then
  echo 'unique cold payload unexpectedly reused a COPY layer' >&2; exit 1
fi
awk '/COPY payload \/payload/ { vertex=$1 } $1 == vertex && $2 == "CACHED" { hit=1 } END { exit !hit }' \
  "$report/warm.log" || { echo 'second daemon did not reuse the exported COPY layer' >&2; exit 1; }
printf 'R2 compatibility passed: pinned BuildKit, distinct daemons, exact 8 MiB payload, remote layer hit, cleanup\n' \
  >"$report/result.txt"
cat "$report/result.txt"
