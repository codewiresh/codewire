#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly DOCKERFILE="$ROOT/images/base/Dockerfile"
readonly ENTRYPOINT="$ROOT/images/base/entrypoint.sh"
readonly SOURCES="$ROOT/images/base/ubuntu.sources"

fail() {
  printf '[test-base-image-source] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -f "$DOCKERFILE" ]] || fail 'base Dockerfile is missing'
[[ -x "$ENTRYPOINT" ]] || fail 'base entrypoint is not executable'
[[ -f "$SOURCES" ]] || fail 'base Ubuntu snapshot definition is missing'
bash -n "$ENTRYPOINT"

grep -Eq '^FROM ubuntu:noble@sha256:[0-9a-f]{64}$' "$DOCKERFILE" ||
  fail 'base image is not rooted in a digest-pinned Ubuntu Noble definition'
grep -qF 'snapshot.ubuntu.com/ubuntu/20260803T000000Z/' "$SOURCES" ||
  fail 'base image does not use the reviewed Ubuntu snapshot'
grep -qxF 'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' "$SOURCES" ||
  fail 'base Ubuntu snapshot does not require archive signature verification'
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
