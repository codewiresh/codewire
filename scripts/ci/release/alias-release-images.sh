#!/usr/bin/env bash
# alias-release-images.sh: alias the release's five runtime images at once.
# Each image already exists for the release's exact source (Production reuses
# what the protected Dev delivery built); build-push-image.sh, with
# REQUIRE_EXISTING_SOURCE_IMAGE=1, verifies it and adds the release alias. They
# are independent registry calls, so they run side by side in one job instead
# of five jobs that each wait for a protected runner (#3246).
#
# Writes <image>_source_sha and <image>_candidate_ref to GITHUB_OUTPUT for
# daemon, derp, services, mesh and dashboard, and fails when any image fails.
# Every image's output is printed under its name once all have finished.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
output="${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
source_dir="${CODEWIRE_SOURCE_DIR:?CODEWIRE_SOURCE_DIR names the release checkout}"
[[ "${REQUIRE_EXISTING_SOURCE_IMAGE:-}" == 1 ]] ||
  { echo 'alias-release-images: a release only aliases existing images' >&2; exit 1; }

# image and Dockerfile, relative to the release checkout.
readonly IMAGES=(
  'daemon deployments/docker/daemon.Dockerfile'
  'derp deployments/docker/derp.Dockerfile'
  'services deployments/docker/services.Dockerfile'
  'mesh deployments/docker/mesh.Dockerfile'
  'dashboard apps/dashboard/Dockerfile'
)

source_url="${CODEWIRE_SOURCE_URL:?CODEWIRE_SOURCE_URL names the canonical source repository}"

# build-push-image.sh points the checkout's origin at the canonical source URL
# when it differs, and restores it on exit. Five runs on one checkout would
# race on its git config, so the origin is set once, here, before they start,
# and restored after; the index is refreshed once for the same reason.
original_origin="$(git -C "$source_dir" remote get-url origin)"
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-release-aliases.XXXXXX")"
restore() {
  rm -rf "$work"
  if [[ "$original_origin" != "$source_url" ]]; then
    git -C "$source_dir" remote set-url origin "$original_origin" || true
  fi
}
trap restore EXIT
if [[ "$original_origin" != "$source_url" ]]; then
  git -C "$source_dir" remote set-url origin "$source_url"
fi
git -C "$source_dir" status --porcelain --untracked-files=all >/dev/null
declare -A pids=()
for entry in "${IMAGES[@]}"; do
  read -r image dockerfile <<<"$entry"
  GITHUB_OUTPUT="$work/$image.output" \
    "$ROOT/scripts/ci/images/build-push-image.sh" "$image" "$source_dir/$dockerfile" "$source_dir" \
    >"$work/$image.log" 2>&1 &
  pids[$image]=$!
done

failed=()
for entry in "${IMAGES[@]}"; do
  read -r image _ <<<"$entry"
  status=0
  wait "${pids[$image]}" || status=$?
  printf '::group::%s (exit %s)\n' "$image" "$status"
  cat "$work/$image.log"
  printf '::endgroup::\n'
  if [[ "$status" -ne 0 ]]; then
    failed+=("$image")
    continue
  fi
  for field in source_sha candidate_ref; do
    value="$(sed -n "s/^$field=//p" "$work/$image.output" | tail -1)"
    if [[ -z "$value" ]]; then
      printf 'alias-release-images: %s reported no %s\n' "$image" "$field" >&2
      failed+=("$image")
      continue 2
    fi
    printf '%s_%s=%s\n' "$image" "$field" "$value" >>"$output"
  done
done
if [[ ${#failed[@]} -gt 0 ]]; then
  printf 'alias-release-images: failed: %s\n' "${failed[*]}" >&2
  exit 1
fi
printf 'alias-release-images: aliased %s\n' "${#IMAGES[@]}"
