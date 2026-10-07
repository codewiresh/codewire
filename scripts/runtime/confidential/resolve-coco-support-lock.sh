#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LOCK_PATH="$ROOT/deployments/k8s/runtime-profiles/confidential/coco-support-images.lock.json"
DAEMON_IMAGE=""
SOURCE_SHA=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/confidential/resolve-coco-support-lock.sh \
    --daemon-image IMAGE --source-sha SHA [--lock PATH]

Validates the committed confidential-runtime support-image lock and derives the
public daemon/workspace references for the exact active Flux source SHA. This
is release evidence, not a mechanism for selecting mutable image tags.
USAGE
}

die() {
  printf '[coco-support-lock] ERROR: %s\n' "$*" >&2
  exit 1
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --lock)
      [[ "$#" -ge 2 ]] || die "--lock requires a path"
      LOCK_PATH="$2"
      shift 2
      ;;
    --daemon-image)
      [[ "$#" -ge 2 ]] || die "--daemon-image requires a value"
      DAEMON_IMAGE="$2"
      shift 2
      ;;
    --source-sha)
      [[ "$#" -ge 2 ]] || die "--source-sha requires a value"
      SOURCE_SHA="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) die "unknown option: $1" ;;
  esac
done

command -v jq >/dev/null 2>&1 || die "missing required command: jq"
command -v skopeo >/dev/null 2>&1 || die "missing required command: skopeo"
[[ -f "$LOCK_PATH" ]] || die "lock file does not exist: $LOCK_PATH"
[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ && "$SOURCE_SHA" != "0000000000000000000000000000000000000000" ]] || \
  die "--source-sha must be one exact non-zero lowercase object ID"
# The active input comes from Deploy's Harbor registry overlay. GHCR below is
# only an independently readable digest/revision oracle for that same image.
[[ "$DAEMON_IMAGE" =~ ^registry\.example\.invalid/codewire/daemon@sha256:[0-9a-f]{64}$ ]] || \
  die "--daemon-image must be the digest-pinned canonical Dev daemon reference"

jq -e '
  type == "object" and
  .schemaVersion == 2 and
  (.images | type == "object" and (keys | sort) == ["dind"]) and
  (.images.dind | type == "string" and test("^docker\\.io/library/docker:[0-9]+\\.[0-9]+\\.[0-9]+-dind@sha256:[0-9a-f]{64}$"))
' "$LOCK_PATH" >/dev/null || \
  die "lock must contain schemaVersion 2 and exactly one versioned, digest-pinned official Docker DinD image"

dind_image="$(jq -r '.images.dind' "$LOCK_PATH")"
daemon_digest="${DAEMON_IMAGE##*@}"
daemon_public_image="ghcr.io/codewiresh/daemon@$daemon_digest"
workspace_tag="ghcr.io/codewiresh/workspace:$SOURCE_SHA"

inspect_image() {
  local name="$1"
  local image="$2"
  local inspect_image="$image"
  local inspect_json

  # The lock keeps the human-readable version tag alongside the immutable
  # digest. Skopeo's docker transport rejects tag-plus-digest references, so
  # remove only the tag for the remote digest lookup.
  if [[ "$image" =~ ^(.+):([^/@]+)@(sha256:[0-9a-f]{64})$ ]]; then
    inspect_image="${BASH_REMATCH[1]}@${BASH_REMATCH[3]}"
  fi

  if ! inspect_json="$(skopeo inspect --no-creds --no-tags "docker://$inspect_image")"; then
    die "$name image is not anonymously resolvable: $image"
  fi
  printf '%s' "$inspect_json"
}

daemon_inspect="$(inspect_image daemon "$daemon_public_image")"
daemon_actual_digest="$(jq -r '.Digest // empty' <<<"$daemon_inspect")"
[[ "$daemon_actual_digest" == "$daemon_digest" ]] || \
  die "daemon image resolved to $daemon_actual_digest, expected $daemon_digest"
daemon_revision="$(jq -r '.Labels["org.opencontainers.image.revision"] // empty' <<<"$daemon_inspect")"
[[ "$daemon_revision" == "$SOURCE_SHA" ]] || \
  die "daemon OCI revision $daemon_revision does not match active Flux source $SOURCE_SHA"

workspace_inspect="$(inspect_image workspace "$workspace_tag")"
workspace_digest="$(jq -r '.Digest // empty' <<<"$workspace_inspect")"
[[ "$workspace_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || \
  die "workspace source tag did not resolve to an immutable digest"
workspace_revision="$(jq -r '.Labels["org.opencontainers.image.revision"] // empty' <<<"$workspace_inspect")"
[[ "$workspace_revision" == "$SOURCE_SHA" ]] || \
  die "workspace OCI revision $workspace_revision does not match active Flux source $SOURCE_SHA"

dind_inspect="$(inspect_image dind "$dind_image")"
dind_digest="${dind_image##*@}"
dind_actual_digest="$(jq -r '.Digest // empty' <<<"$dind_inspect")"
[[ "$dind_actual_digest" == "$dind_digest" ]] || \
  die "dind image resolved to $dind_actual_digest, expected $dind_digest"

printf 'source_sha=%s\n' "$SOURCE_SHA"
printf 'daemon_image=%s\n' "$DAEMON_IMAGE"
printf 'daemon_public_image=%s\n' "$daemon_public_image"
printf 'workspace_image=ghcr.io/codewiresh/workspace@%s\n' "$workspace_digest"
printf 'dind_image=%s\n' "$dind_image"
