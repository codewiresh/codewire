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
grep -qF 'groupadd --gid 1000 codewire &&' "$DOCKERFILE" ||
  fail 'base image does not reserve the platform primary GID before docker'
grep -qF 'useradd codewire --create-home --shell=/bin/bash --uid=1000 --gid=1000 &&' "$DOCKERFILE" ||
  fail 'base image does not bind the codewire passwd identity to platform UID:GID 1000:1000'
grep -qxF 'ENTRYPOINT ["/entrypoint.sh"]' "$DOCKERFILE" ||
  fail 'base image entrypoint contract is missing'
grep -qF 'openssh-client postgresql-client' "$DOCKERFILE" ||
  fail 'base image does not retain the SSH client needed by git clone'
entrypoint_contract="$(sed '/^[[:space:]]*$/d' "$ENTRYPOINT")"
readonly entrypoint_contract
[[ "$entrypoint_contract" == $'#!/usr/bin/env bash\nset -euo pipefail\nexec "$@"' ]] ||
  fail 'base image entrypoint is not the plain supervised-command delegate'
for retired_ssh_surface in \
  openssh-server \
  /run/sshd \
  /etc/codewire/ssh \
  authorized_keys \
  AuthorizedKeysFile \
  'EXPOSE 2222' \
  CODEWIRE_SSH_AUTHORIZED_KEYS \
  ssh-keygen \
  /usr/sbin/sshd; do
  if grep -qF "$retired_ssh_surface" "$DOCKERFILE" "$ENTRYPOINT"; then
    fail "base image retains retired raw SSH surface: $retired_ssh_surface"
  fi
done
# The shared native/Dev SSH target is prepared by the workspace build, never by
# the base runtime or a live package transaction during environment creation.
workspace_dockerfile="$ROOT/images/workspace/Dockerfile"
stock_ssh="$ROOT/scripts/ci/verify/stock-ssh-workload.sh"
# Workspace cw compiles the same schemas as product images, including the
# standard debug_redact field option unsupported by Bookworm's protoc.
grep -qF 'https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip' \
  "$workspace_dockerfile" || fail 'workspace builder lacks the shared pinned protobuf compiler'
grep -qF 'ADD --checksum=sha256:6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7' \
  "$workspace_dockerfile" || fail 'workspace protobuf compiler checksum is not pinned'
grep -qxF 'ENV PROTOC=/opt/protoc/bin/protoc' "$workspace_dockerfile" ||
  fail 'workspace cw build does not select the pinned protobuf compiler'
# shellcheck disable=SC2016 # Match the literal Dockerfile build argument.
grep -qxF 'FROM ${BASE_IMAGE_REF} AS stock-ssh-fixture' "$workspace_dockerfile" ||
  fail 'workspace SSH fixture does not inherit the exact verified base'
grep -qF 'download openssh-server=1:9.6p1-3ubuntu13.18 libwrap0=7.6.q-33' "$workspace_dockerfile" ||
  fail 'workspace SSH fixture package versions are not pinned'
# Codex's Linux sandbox needs the system bubblewrap, from the same snapshot.
grep -qF '      bubblewrap=0.9.0-1ubuntu0.1 ' "$workspace_dockerfile" ||
  fail 'workspace image does not install the pinned bubblewrap for the Codex sandbox'
grep -qF 'APT::Update::Error-Mode=any' "$workspace_dockerfile" ||
  fail 'SSH artifact preparation tolerates partial package-index failures'
# shellcheck disable=SC2016 # Match the literal package loop, not this test's environment.
grep -qF 'dpkg-deb --extract "$package" /out' "$workspace_dockerfile" ||
  fail 'SSH artifact preparation no longer uses inert extraction'
grep -qxF 'COPY --from=stock-ssh-fixture /out/ /opt/codewire/fixtures/openssh/' "$workspace_dockerfile" ||
  fail 'workspace does not ship the prepared SSH artifact'
grep -qxF "readonly SERVER_ROOT='/opt/codewire/fixtures/openssh'" "$stock_ssh" ||
  fail 'SSH smoke does not use the image artifact'
if grep -Eq 'apt-get|dpkg-deb|snapshot\.ubuntu\.com|curl|wget' "$stock_ssh"; then
  fail 'SSH smoke retains a runtime package download or extraction dependency'
fi
if grep -qE '(^|[[:space:]])cw[[:space:]]+node([[:space:]]|$)' "$ENTRYPOINT"; then
  fail 'base image still starts the duplicate legacy Codewire node runtime'
fi

echo 'base image source contract: OK'
