#!/usr/bin/env bash
# image-scan-login.sh prepare HARBOR_REF | remove DOCKER_CONFIG_DIR
#
# The OS-package scan of the published runtime images (codewire#5402) reads
# each pushed digest from Harbor. prepare writes the job's pull-only Harbor
# identity, the one Dev, Prod and sandbox consumers use, to a private registry
# config for HARBOR_REF's host, and prints docker_config=DIR to GITHUB_OUTPUT.
# No credential reaches the log, an environment variable or a step output.
# remove shreds that config once the scans have ended.
set -euo pipefail

fail() {
  printf 'image-scan-login: %s\n' "$*" >&2
  exit 1
}

readonly fetcher="${OPENBAO_HARBOR_CREDENTIAL_FETCHER:-scripts/ci/setup/fetch-openbao-harbor-credentials.sh}"
readonly temp_root="${RUNNER_TEMP:?RUNNER_TEMP is required}"

prepare() {
  local ref="$1" host dir auth
  host="${ref%%/*}"
  [[ "$ref" == */*@sha256:* && "$host" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$ ]] ||
    fail 'the reference is not a registry digest'
  umask 077
  dir="$(mktemp -d "$temp_root/image-scan-auth.XXXXXX")"
  if ! "$fetcher" --pull "$dir/username" "$dir/password"; then
    rm -rf -- "$dir"
    fail 'the Harbor pull identity could not be fetched'
  fi
  auth="$(printf '%s:%s' "$(<"$dir/username")" "$(<"$dir/password")" | base64 -w0)"
  shred -u "$dir/username" "$dir/password" 2>/dev/null || rm -f -- "$dir/username" "$dir/password"
  printf '{"auths":{"%s":{"auth":"%s"}}}\n' "$host" "$auth" >"$dir/config.json"
  auth=''
  printf 'docker_config=%s\n' "$dir" >>"${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
  printf 'image-scan-login: a pull login for %s is ready\n' "$host"
}

remove() {
  local dir="$1"
  [[ "$dir" == "$temp_root"/image-scan-auth.* && -d "$dir" && ! -L "$dir" ]] ||
    fail 'not an image scan login folder'
  find "$dir" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf -- "$dir"
  printf 'image-scan-login: the pull login is removed\n'
}

case "${1:-}|$#" in
  prepare\|2) prepare "$2" ;;
  remove\|2) remove "$2" ;;
  *) echo 'usage: image-scan-login.sh prepare HARBOR_REF | remove DOCKER_CONFIG_DIR' >&2; exit 2 ;;
esac
