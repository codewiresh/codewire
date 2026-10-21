#!/usr/bin/env bash
# Build the standalone dashboard image for verification with only the compiler
# cache this job may use:
# - a push to main that holds the protected writer reads and writes the one
#   protected cache;
# - every other job reads that cache only with the protected-read token, so it
#   never needs, and never receives, a write credential;
# - a job without a usable token compiles with BuildKit's local cache.
# The job's host Rust cache selection (select-untrusted-rust-cache.sh) exports
# the mode, trust and credential file read here.
set -euo pipefail

[[ $# -eq 1 && -n "$1" ]] || {
  echo 'usage: build-dashboard-image.sh IMAGE_TAG' >&2
  exit 2
}
readonly tag="$1"

mode="${CODEWIRE_SCCACHE_MODE:-disabled}"
trust="${CODEWIRE_R2_CACHE_TRUST:-}"
credentials="${AWS_SHARED_CREDENTIALS_FILE:-}"
bucket="${SCCACHE_BUCKET:-}"
endpoint="${SCCACHE_ENDPOINT:-}"
prefix="${CODEWIRE_SCCACHE_PREFIX:-}"
expected_trust=protected-read
[[ "${GITHUB_EVENT_NAME:-}|${GITHUB_REF:-}" != 'push|refs/heads/main' ]] || expected_trust=main
readonly expected_trust

case "$mode" in
  disabled|local) ;;
  r2)
    if [[ "$trust" != "$expected_trust" ]]; then
      echo "::warning::The dashboard image compiles with the local cache: R2 trust '$trust' is not this job's '$expected_trust'"
      mode=local
    elif [[ "$credentials" != /* || -L "$credentials" || ! -f "$credentials" || ! -s "$credentials" ]]; then
      echo '::warning::The dashboard image compiles with the local cache: no private R2 credential file'
      mode=local
    elif [[ -z "$bucket" || "$endpoint" != https://* || -z "$prefix" ]]; then
      echo '::warning::The dashboard image compiles with the local cache: incomplete R2 cache settings'
      mode=local
    fi
    ;;
  *)
    printf 'build-dashboard-image: invalid CODEWIRE_SCCACHE_MODE: %s\n' "$mode" >&2
    exit 2
    ;;
esac

flags=(--set "dashboard.tags=$tag" --set "dashboard.args.CODEWIRE_SCCACHE_MODE=$mode")
if [[ "$mode" == r2 ]]; then
  flags+=(
    --set "dashboard.args.SCCACHE_BUCKET=$bucket"
    --set "dashboard.args.SCCACHE_ENDPOINT=$endpoint"
    --set "dashboard.args.CODEWIRE_SCCACHE_PREFIX=$prefix"
    --set "dashboard.secrets=id=aws_shared_credentials,src=$credentials"
  )
  printf 'CODEWIRE_DASHBOARD_IMAGE_CACHE mode=r2 trust=%s\n' "$trust"
else
  printf 'CODEWIRE_DASHBOARD_IMAGE_CACHE mode=%s\n' "$mode"
fi

# Bake reads these variables from the environment; only the flags above choose
# the cache.
exec env -u CODEWIRE_SCCACHE_MODE -u SCCACHE_BUCKET -u SCCACHE_ENDPOINT -u CODEWIRE_SCCACHE_PREFIX \
  docker buildx bake --file docker-bake.hcl --pull --load "${flags[@]}" dashboard
