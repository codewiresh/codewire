#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly DOCKERFILE="$ROOT/images/base/Dockerfile"
readonly ENTRYPOINT="$ROOT/images/base/entrypoint.sh"
readonly SOURCES="$ROOT/images/base/ubuntu.sources"
readonly APT_TRANSPORT="$ROOT/images/base/apt-transport.conf"
readonly APT_RETRY="$ROOT/images/base/apt-get-with-retry"

fail() {
  printf '[test-base-image-source] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -f "$DOCKERFILE" ]] || fail 'base Dockerfile is missing'
[[ -x "$ENTRYPOINT" ]] || fail 'base entrypoint is not executable'
[[ -f "$SOURCES" ]] || fail 'base Ubuntu snapshot definition is missing'
[[ -f "$APT_TRANSPORT" ]] || fail 'base APT transport contract is missing'
[[ -x "$APT_RETRY" ]] || fail 'base APT retry helper is missing or not executable'
bash -n "$ENTRYPOINT" "$APT_RETRY"

grep -Eq '^FROM ubuntu:noble@sha256:[0-9a-f]{64}$' "$DOCKERFILE" ||
  fail 'base image is not rooted in a digest-pinned Ubuntu Noble definition'
grep -qF 'snapshot.ubuntu.com/ubuntu/20260803T000000Z/' "$SOURCES" ||
  fail 'base image does not use the reviewed Ubuntu snapshot'
grep -qxF 'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' "$SOURCES" ||
  fail 'base Ubuntu snapshot does not require archive signature verification'
grep -qxF 'Acquire::http::Timeout "30";' "$APT_TRANSPORT" ||
  fail 'base APT HTTP timeout is not bounded at 30 seconds'
grep -qxF 'Acquire::https::Timeout "30";' "$APT_TRANSPORT" ||
  fail 'base APT HTTPS timeout is not bounded at 30 seconds'
grep -qF 'COPY --chmod=0755 apt-get-with-retry /usr/local/sbin/apt-get-with-retry' "$DOCKERFILE" ||
  fail 'base image does not install the bounded APT transaction helper'
grep -qF 'COPY --chmod=0755 images/base/apt-get-with-retry /usr/local/sbin/apt-get-with-retry' \
  "$ROOT/images/workspace/Dockerfile" ||
  fail 'workspace build stage does not install the bounded APT transaction helper'
grep -qxF 'USER codewire' "$DOCKERFILE" ||
  fail 'base image does not drop to the codewire runtime user'
grep -qxF 'ENTRYPOINT ["/entrypoint.sh"]' "$DOCKERFILE" ||
  fail 'base image entrypoint contract is missing'
grep -qF 'HostKey /etc/codewire/ssh/ssh_host_ed25519_key' "$DOCKERFILE" ||
  fail 'base image does not preserve the platform SSH host-key path'
grep -qF 'AuthorizedKeysFile /etc/codewire/ssh/authorized_keys .ssh/authorized_keys' \
  "$DOCKERFILE" || fail 'base image does not preserve authorized-key lookup'
grep -qF 'exec "$@"' "$ENTRYPOINT" ||
  fail 'base image entrypoint does not delegate to the supervised runtime command'
if grep -qE '(^|[[:space:]])cw[[:space:]]+node([[:space:]]|$)' "$ENTRYPOINT"; then
  fail 'base image still starts the duplicate legacy Codewire node runtime'
fi

echo 'base image source contract: OK'
