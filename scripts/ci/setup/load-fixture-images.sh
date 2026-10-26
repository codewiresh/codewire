#!/usr/bin/env bash
# Make the integration jobs' fixture images present in the job's Docker daemon
# without pulling them from Docker Hub in every job (infra#1534). Each job
# pulled PostgreSQL there (6-9 s) and the runtime plane NATS too (main runs
# 23934 and 23971).
#
# Usage: load-fixture-images.sh NAME...   (postgres, nats)
#
# For each image, pinned in scripts/ci/verify/integration-postgres.sh by its
# digest and by its ID in an overlay2 image store:
# - an image the daemon already holds with that ID is used as it is;
# - otherwise, with CODEWIRE_TOOL_CACHE (a folder of a metal guest's warm
#   cache, which outlives the guest), a kept archive of it is loaded and used
#   only when the daemon then holds that ID. docker load checks every layer
#   against the image's config, whose digest the ID is, so an archive that
#   was changed loads as some other image, or not at all;
# - otherwise it is pulled by its digest, as before, and kept in the cache
#   when it has the pinned ID. A kept archive that loaded no such image is
#   replaced. Failing to keep one never fails the job.
# The pull is the only step that can fail the job, as before. With GITHUB_ENV,
# INTEGRATION_<NAME>_IMAGE names what the job runs: the pinned ID, or the
# pinned reference on a daemon whose store names the image otherwise.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=scripts/ci/verify/integration-postgres.sh
source "$ROOT/scripts/ci/verify/integration-postgres.sh"

log() {
  printf 'load-fixture-images: %s\n' "$*"
}

die() {
  printf 'load-fixture-images: %s\n' "$*" >&2
  exit 1
}

# holds REFERENCE ID: the daemon holds REFERENCE (an image ID or a reference)
# as the image with ID.
holds() {
  [ "$(docker image inspect -f '{{.Id}}' "$1" 2>/dev/null)" = "$2" ]
}

load_image() {
  local name="$1" reference id variable cache="${CODEWIRE_TOOL_CACHE:-}" archive="" tmp
  local started="$SECONDS" run_as how
  case "$name" in
    postgres) reference="$INTEGRATION_POSTGRES_PINNED_IMAGE" id="$INTEGRATION_POSTGRES_PINNED_ID" ;;
    nats) reference="$INTEGRATION_NATS_PINNED_IMAGE" id="$INTEGRATION_NATS_PINNED_ID" ;;
    *) die "unknown fixture image: $name" ;;
  esac
  [[ "$id" =~ ^sha256:[0-9a-f]{64}$ ]] || die "the $name pin has no image ID"
  variable="INTEGRATION_${name^^}_IMAGE"
  if [ -n "$cache" ]; then
    archive="$cache/fixture-images/${id#sha256:}.tar"
  fi
  run_as="$id"
  if holds "$id" "$id"; then
    how='already present'
  elif [ -n "$archive" ] && [ -f "$archive" ] &&
      docker load -q -i "$archive" >/dev/null 2>&1 && holds "$id" "$id"; then
    how='loaded from the kept archive'
  else
    if [ -n "$archive" ] && [ -f "$archive" ]; then
      log "the kept $name archive did not load as $id; pulling it again"
      rm -f -- "$archive"
    fi
    docker pull -q "$reference" >/dev/null || die "could not pull $reference"
    how="pulled by digest"
    if holds "$reference" "$id"; then
      if [ -n "$archive" ]; then
        tmp="$archive.$$.tmp"
        if mkdir -p "${archive%/*}" && docker save -o "$tmp" "$id" && mv -f -- "$tmp" "$archive"; then
          how+=' and kept'
        else
          rm -f -- "$tmp"
          log "could not keep the $name archive; the next job pulls it again"
        fi
      fi
    else
      # A daemon whose image store names it otherwise (a containerd store
      # names an image by its manifest digest): run it by the pinned
      # reference, which it now holds.
      run_as="$reference"
    fi
  fi
  log "$name: $how in $((SECONDS - started)) s ($run_as)"
  if [ -n "${GITHUB_ENV:-}" ]; then
    printf '%s=%s\n' "$variable" "$run_as" >> "$GITHUB_ENV"
  fi
}

[ "$#" -gt 0 ] || die 'usage: load-fixture-images.sh NAME...'
for name in "$@"; do
  load_image "$name"
done
