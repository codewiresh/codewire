#!/usr/bin/env bash
# Run the workspace agent contract on one exact workspace image before anything
# publishes it (#2892). The linux/amd64 build job of support-images.yaml and of
# deploy-prod.yaml calls this with the digest its build pushed, after the
# compiler-cache credential is gone. Its workspace_digest output comes from
# here, so a digest leaves the job only through a passing contract.
#
# The image is pulled with the pull-only Harbor robot into a private Docker
# configuration, which is deleted before any image code runs. The pulled image
# must be recorded under exactly that reference (RepoDigests), be linux/amd64
# and carry the expected revision label. Both contract modes then run with the
# flags verify-workspace-image.sh uses: the PID limit, the unprivileged user, a
# fresh tmpfs home for the mounted-home mode, and the contract on stdin. No bind
# mount, volume, environment variable, privilege or host network reaches the
# container, and the contract never runs on the host.
#
# Usage: run-workspace-contract-on-image.sh [--source ghcr] IMAGE_REF REVISION CONTRACT
#   IMAGE_REF  $CODEWIRE_IMAGE_REGISTRY/codewire/workspace@sha256:<64 hex>
#   REVISION   the full commit the image's revision label must name
#   CONTRACT   the workspace-agent-contract.sh streamed into the image
# On success it writes workspace_digest=<digest> to $GITHUB_OUTPUT, or prints
# it when GITHUB_OUTPUT is unset.
#
# --source ghcr is for a local run only. It pulls the same digest anonymously
# from the public mirror and reads no credential; CI refuses it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly HARBOR_HOST="${CODEWIRE_IMAGE_REGISTRY:?set to the image registry host}"
readonly GHCR_REPOSITORY='ghcr.io/codewiresh/workspace'
readonly PULL_ATTEMPTS=3 PULL_TIMEOUT=600s
readonly CONTRACT_TIMEOUT=600s
readonly HOME_TMPFS='/home/codewire:rw,exec,uid=1000,gid=1000,mode=0700,size=256m'

fail() {
  printf '[run-workspace-contract-on-image] ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  echo "usage: run-workspace-contract-on-image.sh [--source ghcr] $HARBOR_HOST/codewire/workspace@sha256:DIGEST REVISION CONTRACT" >&2
  exit 2
}

source_kind=harbor
if [[ "${1:-}" == --source ]]; then
  [[ "${2:-}" == ghcr ]] || usage
  source_kind=ghcr
  shift 2
fi
[[ $# -eq 3 ]] || usage
readonly image_ref="$1" revision="$2" contract="$3"
[[ "$image_ref" =~ ^"$HARBOR_HOST"/codewire/workspace@(sha256:[0-9a-f]{64})$ ]] ||
  fail "the image must be one exact Harbor workspace digest, not: $image_ref"
readonly digest="${BASH_REMATCH[1]}"
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || fail "the expected revision is not a full commit: $revision"
[[ -f "$contract" && ! -L "$contract" && -r "$contract" ]] ||
  fail "the contract is not a readable regular file: $contract"
if [[ "$source_kind" == ghcr ]]; then
  [[ -z "${GITHUB_ACTIONS:-}${FORGEJO_ACTIONS:-}${GITEA_ACTIONS:-}" ]] ||
    fail 'CI runs the contract on the Harbor image; --source ghcr is for local runs only'
  pull_ref="$GHCR_REPOSITORY@$digest"
else
  pull_ref="$image_ref"
fi
readonly source_kind pull_ref

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/codewire-workspace-contract.XXXXXX")"
readonly work docker_config="$work/docker-config"
containers=()
remove_image=false
cleanup() {
  local status=$? name
  trap - EXIT
  for name in "${containers[@]}"; do
    timeout 30 docker rm --force "$name" >/dev/null 2>&1 || true
  done
  if [[ "$remove_image" == true ]]; then
    timeout 120 docker image rm "$pull_ref" >/dev/null 2>&1 || true
  fi
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf -- "$work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

remove_docker_config() {
  if [[ -e "$docker_config" ]]; then
    find "$docker_config" -type f -exec shred -u {} + 2>/dev/null || true
    rm -rf -- "$docker_config"
  fi
  [[ ! -e "$docker_config" ]] || fail 'the private Docker configuration survived the pull'
}

# An image this run did not bring is left in place afterwards.
docker image inspect "$pull_ref" >/dev/null 2>&1 || remove_image=true

# Only this private configuration holds the pull robot; the ghcr source pulls
# with it empty, anonymously.
mkdir -m 0700 "$docker_config"
if [[ "$source_kind" == harbor ]]; then
  "${OPENBAO_HARBOR_CREDENTIAL_FETCHER:-$ROOT/scripts/ci/setup/fetch-openbao-harbor-credentials.sh}" --pull \
    "$work/harbor-username" "$work/harbor-password" || fail 'the Harbor pull credential could not be read'
  DOCKER_CONFIG="$docker_config" docker login "$HARBOR_HOST" --username "$(<"$work/harbor-username")" \
    --password-stdin <"$work/harbor-password" >/dev/null 2>"$work/login.err" || {
    sed -n '1,20p' "$work/login.err" >&2
    remove_docker_config
    fail "Harbor refused the pull robot at $HARBOR_HOST"
  }
  shred -u -- "$work/harbor-password" "$work/harbor-username" 2>/dev/null ||
    rm -f -- "$work/harbor-password" "$work/harbor-username"
fi
pulled=false
for ((attempt = 1; attempt <= PULL_ATTEMPTS; attempt += 1)); do
  if DOCKER_CONFIG="$docker_config" timeout --signal=TERM --kill-after=30s "$PULL_TIMEOUT" \
      docker pull --quiet "$pull_ref" >/dev/null 2>"$work/pull.err"; then
    pulled=true
    break
  fi
  sed -n '1,20p' "$work/pull.err" >&2
  [[ "$attempt" -eq "$PULL_ATTEMPTS" ]] || sleep "$((attempt * 10))"
done
# The credential is gone before the outcome is judged and before any image code runs.
remove_docker_config
[[ "$pulled" == true ]] || fail "could not pull $pull_ref after $PULL_ATTEMPTS attempts"

docker image inspect "$pull_ref" >"$work/inspect.json" || fail "could not inspect the pulled $pull_ref"
image_id="$(jq -er 'select(length == 1) | .[0].Id | select(test("^sha256:[0-9a-f]{64}$"))' \
  "$work/inspect.json")" || fail "the pulled $pull_ref has no exact local image ID"
jq -e --arg ref "$pull_ref" 'any(.[0].RepoDigests[]?; . == $ref)' "$work/inspect.json" >/dev/null ||
  fail "the local image is not recorded as exactly $pull_ref"
platform="$(jq -r '"\(.[0].Os // "")/\(.[0].Architecture // "")"' "$work/inspect.json")"
[[ "$platform" == linux/amd64 ]] || fail "the image is $platform, not linux/amd64"
label="$(jq -r '.[0].Config.Labels["org.opencontainers.image.revision"] // ""' "$work/inspect.json")"
[[ "$label" == "$revision" ]] || fail "the image revision label is '$label', not $revision"
readonly image_id

# run_contract MODE runs one contract mode in a fresh container of the image.
run_contract() {
  local mode="$1" name status=0
  local -a docker_args contract_args=(-eu -s)
  name="codewire-workspace-contract-$$-$mode"
  docker_args=(run --rm --interactive --pull=never --pids-limit=2048 --name "$name" --user 1000:1000)
  if [[ "$mode" == mounted-home ]]; then
    docker_args+=(--tmpfs "$HOME_TMPFS")
    contract_args+=(-- --mounted-home-agents)
  fi
  containers+=("$name")
  printf 'Running the %s workspace contract on %s (%s)\n' "$mode" "$pull_ref" "$image_id"
  timeout --signal=TERM --kill-after=30s "$CONTRACT_TIMEOUT" \
    docker "${docker_args[@]}" --entrypoint bash "$image_id" "${contract_args[@]}" <"$contract" || status=$?
  [[ "$status" -eq 0 ]] || fail "the $mode workspace contract failed with status $status on $pull_ref"
}
run_contract full
run_contract mounted-home

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf 'workspace_digest=%s\n' "$digest" >>"$GITHUB_OUTPUT"
else
  printf 'workspace_digest=%s\n' "$digest"
fi
printf 'The workspace contract passed on %s, revision %s\n' "$pull_ref" "$revision"
