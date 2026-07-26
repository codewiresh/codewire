#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly DOCKERFILE="$ROOT/images/base/Dockerfile"
readonly ENTRYPOINT="$ROOT/images/base/entrypoint.sh"

fail() {
  printf '[test-base-image-source] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -f "$DOCKERFILE" ]] || fail 'base Dockerfile is missing'
[[ -x "$ENTRYPOINT" ]] || fail 'base entrypoint is not executable'
bash -n "$ENTRYPOINT"

grep -qxF 'FROM ubuntu:noble' "$DOCKERFILE" ||
  fail 'base image is not rooted in the reviewed Ubuntu Noble definition'
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
