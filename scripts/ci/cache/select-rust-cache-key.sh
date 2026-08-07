#!/usr/bin/env bash
# Reuse one exact canonical key only when its complete compatibility binding matches.
set -euo pipefail

flavor="${1:-}"
pool="${2:-}"
compatibility="${3:-}"
previous_compatibility="${4:-}"
previous_key="${5:-}"

die() {
  printf 'select-rust-cache-key: %s\n' "$*" >&2
  exit 2
}

case "$flavor" in
  host-debug|host-ci|kind-ci|cw-cross-ci|desktop-release) ;;
  *) die 'invalid cache flavor' ;;
esac
case "$pool:$flavor" in
  generic:host-debug|generic:host-ci|kind:kind-ci|\
  generic:cw-cross-ci|generic:desktop-release) ;;
  *) die 'cache flavor is bound to a different runner pool' ;;
esac
[[ "$compatibility" =~ ^[0-9a-f]{64}$ ]] \
  || die 'compatibility must be a lowercase SHA-256'

prefix="codewire-rust-deps-v1-${pool}-${flavor}-${compatibility}-"
refresh=true
key=''
if [ "$previous_compatibility" = "$compatibility" ] \
    && [[ "$previous_key" =~ ^${prefix}[0-9a-f]{32}$ ]]; then
  refresh=false
  key="$previous_key"
else
  nonce="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
  [[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || die 'unable to create cache nonce'
  key="${prefix}${nonce}"
fi

rendered="refresh=${refresh}
key=${key}"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  printf '%s\n' "$rendered" >> "$GITHUB_OUTPUT"
fi
printf '%s\n' "$rendered"
