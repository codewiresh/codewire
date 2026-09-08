#!/usr/bin/env bash
# Qualify the exact services SSH runtime stage without rebuilding the product.
# This is packaged-tool/helper proof, not broker authorization or Dev acceptance.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
[[ "$#" -eq 1 ]] || { echo 'usage: verify-service-ssh-image.sh IMAGE' >&2; exit 2; }
: "${DOCKER_CONFIG:?select an isolated Docker configuration for image verification}"
image_id="$(docker image inspect --format '{{.Id}}' "$1")"
[[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 1
container_id=''
read -r ownership_token </proc/sys/kernel/random/uuid
[[ "$ownership_token" =~ ^[0-9a-f-]{36}$ ]] || exit 1
container_name="codewire-service-ssh-$ownership_token"
remove_owned_container() {
  local matches metadata actual_id actual_image actual_owner
  matches="$(docker container ls --all --no-trunc \
    --filter "name=^/$container_name\$" --format '{{.ID}}')" || return 1
  [[ -n "$matches" ]] || return 0
  [[ "$matches" =~ ^[0-9a-f]{64}$ ]] || return 1
  metadata="$(docker inspect --format '{{.Id}} {{.Config.Image}} {{index .Config.Labels "dev.codewire.verification.ssh"}}' "$matches")" || return 1
  read -r actual_id actual_image actual_owner <<<"$metadata"
  if [[ "$actual_id" != "$matches" || "$actual_image" != "$image_id" || "$actual_owner" != "$ownership_token" ]]; then
    echo 'SSH verifier refuses to remove an object with different ownership' >&2
    return 1
  fi
  docker rm --force "$actual_id" >/dev/null
}
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if ! remove_owned_container; then
    printf 'SSH verifier cleanup is incomplete: %s\n' "$container_name" >&2
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Only public synthetic test fixtures are mounted. No host home, agent socket,
# network, Docker socket, credentials, or writable disk reaches this container.
fixtures="$ROOT/crates/codewire-protected-store/src/ssh_material/fixtures"
container_id="$(docker create --pull=never --network=none --read-only \
  --name "$container_name" --label "dev.codewire.verification.ssh=$ownership_token" \
  --user=65532:65532 --cap-drop=ALL --security-opt=no-new-privileges \
  --cpus=1 --memory=128m --pids-limit=32 \
  --tmpfs /run/codewire-credentials:rw,nosuid,nodev,noexec,size=64m,uid=65532,gid=65532,mode=0700 \
  --mount "type=bind,src=$fixtures/ed25519-aes256-ctr.openssh,dst=/fixture/key,readonly" \
  --mount "type=bind,src=$fixtures/ed25519-aes256-ctr.pub,dst=/fixture/key.pub,readonly" \
  --mount "type=bind,src=$ROOT/scripts/ci/verify/service-ssh-image-contract.sh,dst=/fixture/contract.sh,readonly" \
  --entrypoint /usr/bin/env "$image_id" -i PATH=/usr/bin:/bin \
  HOME=/run/codewire-credentials LC_ALL=C /bin/sh /fixture/contract.sh)"
[[ "$container_id" =~ ^[0-9a-f]{64}$ ]] || exit 1
timeout --foreground --kill-after=5s 40s docker start --attach "$container_id"
status="$(docker inspect --format '{{.State.ExitCode}}' "$container_id")"
[[ "$status" == 0 ]] || exit 1
remove_owned_container
trap - EXIT INT TERM
printf 'services SSH packaged tools/helper passed: %s\n' "$image_id"
