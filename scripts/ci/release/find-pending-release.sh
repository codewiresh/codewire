#!/usr/bin/env bash
# find-pending-release.sh deploy-prod|cli-release: the release this run
# delivers, as GITHUB_OUTPUT release_tag (empty when there is none), plus
# cli-release's r2_publication and r2_promote_channel.
#
# A dispatch (the owner's recovery path) delivers the tag it names. A scheduled
# run picks up a pushed release tag (owner, 2026-10-23, #2892): the newest
# canonical v* tag on origin that Forgejo verifies as signed by the release
# tagger (CODEWIRE_RELEASE_TAGGER), when
#   - it was signed within the last 24 hours (its tagger time is part of the
#     signed tag, so it cannot be forged); an older tag is delivered only by
#     the owner's dispatch, so the schedule never redelivers or downgrades;
#   - it is exactly the next version after the previous tagger-signed tag;
#   - this workflow has not picked it up yet: a commit status
#     "release/<workflow> <tag>" on the tagged commit marks a pickup, written
#     before the tag is named, so a failed release is never retried by the
#     schedule. When the run the newest marker names ended without success,
#     the schedule fails loudly with the dispatch that recovers it (#4444);
#     a dispatch marks the tag too, so its outcome is the one that counts;
#   - for cli-release only, Production has accepted it, so the CLI follows
#     Production.
# Tags that are not signed by the release tagger are ignored, so an unsigned
# tag cannot stand in a release's way. Release selection then verifies the tag
# fully from main's code. This job holds only the job token and runs before
# any credentialed job.
set -euo pipefail

fail() {
  printf 'pending release: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 && ( "$1" == deploy-prod || "$1" == cli-release ) ]] ||
  fail 'usage: find-pending-release.sh deploy-prod|cli-release'
readonly workflow="$1"
readonly semver='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
readonly pickup_window_seconds=86400
output="${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

emit() { # TAG [PUBLICATION CHANNEL]
  printf 'release_tag=%s\n' "$1" >>"$output"
  if [[ "$workflow" == cli-release ]]; then
    printf 'r2_publication=%s\nr2_promote_channel=%s\n' "${2:-none}" "${3:-none}" >>"$output"
  fi
}

case "${GITHUB_EVENT_NAME:-}" in
  workflow_dispatch)
    tag="${DISPATCHED_TAG:-}"
    [[ "$tag" =~ $semver ]] || fail "the dispatched release tag '$tag' is not exact semver"
    if [[ "$workflow" == cli-release ]]; then
      [[ "${DISPATCHED_R2_PUBLICATION:-none}" =~ ^(none|immutable)$ ]] ||
        fail 'the dispatched r2_publication must be none or immutable'
      [[ "${DISPATCHED_R2_PROMOTE_CHANNEL:-none}" =~ ^(none|stable)$ ]] ||
        fail 'the dispatched r2_promote_channel must be none or stable'
    fi
    printf 'dispatched release: %s\n' "$tag"
    emit "$tag" "${DISPATCHED_R2_PUBLICATION:-none}" "${DISPATCHED_R2_PROMOTE_CHANNEL:-none}"
    dispatched=true
    ;;
  schedule) dispatched=false ;;
  *) fail "unsupported event '${GITHUB_EVENT_NAME:-}'" ;;
esac

# A dispatch delivers whatever happens next: its record below is best effort.
setup_failed() {
  if [[ "$dispatched" == true ]]; then
    printf 'notice: this dispatch was not recorded on its commit (%s); the schedule may report an earlier run\n' "$*"
    exit 0
  fi
  fail "$@"
}
server_url="${GITHUB_SERVER_URL:-}"
server_url="${server_url%/}"
[[ "$server_url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || setup_failed 'GITHUB_SERVER_URL is unset or invalid'
[[ -n "${GITEA_TOKEN:-}" ]] || setup_failed 'GITEA_TOKEN is required'
release_tagger="${CODEWIRE_RELEASE_TAGGER:-}"
[[ "$dispatched" == true || "$release_tagger" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] ||
  fail 'CODEWIRE_RELEASE_TAGGER must name the release tagger'
release_api="$server_url/api/v1/repos/codewire/codewire"
release_tmp="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-pending-release.XXXXXX")"
trap 'rm -rf "$release_tmp"' EXIT
release_token="$GITEA_TOKEN"
unset GITEA_TOKEN
# shellcheck source=scripts/ci/release/release-tags.sh
. "$(dirname "$0")/release-tags.sh"

# api METHOD PATH OUTPUT [BODY]: one call to this repository's API; prints the
# HTTP status. The token reaches curl only through a pipe.
api() {
  local data=()
  [[ $# -lt 4 ]] || data=(--header 'Content-Type: application/json' --data-binary "$4")
  printf 'header = "Authorization: token %s"\n' "$release_token" |
    curl --disable --config - --silent --show-error \
      --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 60 \
      --request "$1" --header 'Accept: application/json' "${data[@]}" \
      --output "$3" --write-out '%{http_code}' "$release_api/$2" 2>/dev/null || printf 'transport-error'
}

# mark STATE DESCRIPTION: record this run's pickup of the tag on its commit.
# The description ends with the run's ID, which the schedule reads back.
mark() {
  local body status
  body="$(jq -cn --arg state "$1" --arg context "release/$workflow $tag" \
    --arg description "$2 ${GITHUB_RUN_NUMBER:-?} (id ${GITHUB_RUN_ID:-?})" \
    --arg target "$server_url/codewire/codewire/actions/runs/${GITHUB_RUN_NUMBER:-}" \
    '{state: $state, context: $context, description: $description, target_url: $target}')"
  status="$(api POST "statuses/$tag_commit" "$release_tmp/mark.json" "$body")"
  [[ "$status" == 201 ]] || fail "could not mark $tag as picked up (HTTP $status); nothing is released"
}

# A dispatch marks the tag's commit too, so the schedule judges this run,
# not the one it recovers.
if [[ "$dispatched" == true ]]; then
  release_tag_list >"$release_tmp/releases" || setup_failed 'the release tags on origin are unavailable'
  tag_commit="$(awk -v tag="$tag" '$1 == tag { print $3 }' "$release_tmp/releases")"
  [[ -n "$tag_commit" ]] || setup_failed "$tag is not a release tag on origin"
  (mark pending 'delivered by dispatch run') || setup_failed 'the commit status could not be written'
  printf 'recorded: dispatch run %s delivers %s\n' "${GITHUB_RUN_NUMBER:-?}" "$tag"
  exit 0
fi

release_tag_list >"$release_tmp/releases" || fail 'the release tags on origin are unavailable'

# The newest tagger-signed release tag, then the one before it.
tag='' previous='' release_tag_date=''
while read -r name object commit; do
  release_tag_signed "$name" "$object" "$commit" && signed=0 || signed=$?
  [[ "$signed" -ne 2 ]] || fail "Forgejo's verification of $name is unavailable"
  [[ "$signed" -eq 0 ]] || { printf 'ignored: %s is not signed by the release tagger %s\n' "$name" "$release_tagger"; continue; }
  if [[ -z "$tag" ]]; then
    tag="$name" tag_object="$object" tag_commit="$commit" tag_date="$release_tag_date"
  else
    previous="$name"
    break
  fi
done <"$release_tmp/releases"
[[ -n "$tag" ]] || { printf 'no release tag signed by %s\n' "$release_tagger"; emit ''; exit 0; }
if (( $(date +%s) - tag_date > pickup_window_seconds )); then
  printf 'nothing pending: %s was signed more than 24 hours ago; deliver an older tag by dispatch\n' "$tag"
  emit ''
  exit 0
fi
readonly context="release/$workflow $tag"

# markers: this workflow's pickup markers on the tag's commit, as one JSON
# array in $release_tmp/markers.json. A main commit carries a status for every
# CI job, so every page is read.
markers() {
  local page status
  printf '[]' >"$release_tmp/markers.json"
  for ((page = 1; page <= 40; page++)); do
    status="$(api GET "commits/$tag_commit/statuses?page=$page&limit=50" "$release_tmp/statuses.json")"
    [[ "$status" == 200 ]] || fail "the statuses of $tag's commit are unavailable (HTTP $status)"
    jq -e 'type == "array"' "$release_tmp/statuses.json" >/dev/null || fail "the statuses of $tag's commit are malformed"
    jq -s --arg context "$context" '.[0] + [.[1][] | select(.context == $context)]' \
      "$release_tmp/markers.json" "$release_tmp/statuses.json" >"$release_tmp/markers.next"
    mv "$release_tmp/markers.next" "$release_tmp/markers.json"
    [[ "$(jq length "$release_tmp/statuses.json")" -ge 50 ]] || return 0
  done
  fail "$tag's commit has more statuses than this check reads"
}

# run_outcome ID: running, success or stopped, from the run's jobs; empty when
# they cannot be read.
run_outcome() {
  local status
  status="$(api GET "actions/runs/$1/jobs?page=1&limit=100" "$release_tmp/jobs.json")"
  [[ "$status" == 200 ]] || return 0
  jq -r '(.jobs // []) as $jobs |
    if ($jobs | length) == 0 then empty
    elif any($jobs[]; .status == "waiting" or .status == "running" or .status == "blocked" or .status == "unknown") then "running"
    elif all($jobs[]; .status == "success" or .status == "skipped") then "success"
    else "stopped" end' "$release_tmp/jobs.json" 2>/dev/null || true
}

markers
if [[ "$(jq length "$release_tmp/markers.json")" -gt 0 ]]; then
  jq -c 'max_by(.id // 0)' "$release_tmp/markers.json" >"$release_tmp/marker.json"
  state="$(jq -r '.state // ""' "$release_tmp/marker.json")"
  description="$(jq -r '.description // ""' "$release_tmp/marker.json")"
  run_id="$(sed -nE 's/.* \(id ([0-9]+)\)$/\1/p' <<<"$description")"
  outcome=''
  [[ "$state" != pending || -z "$run_id" ]] || outcome="$(run_outcome "$run_id")"
  if [[ "$outcome" == stopped ]]; then
    printf '::error::%s was picked up by %s, whose run ended without delivering it (%s); recover it with a dispatch of %s.yaml on main with release_tag=%s\n' \
      "$tag" "$workflow" "$description" "$workflow" "$tag"
    emit ''
    exit 1
  fi
  printf 'nothing pending: %s was already picked up by %s (%s%s)\n' "$tag" "$workflow" "$description" "${outcome:+, $outcome}"
  emit ''
  exit 0
fi

# Only the next version is released; anything else is refused once, visibly.
if [[ -n "$previous" ]]; then
  IFS=. read -r major minor patch <<<"${previous#v}"
  case "$tag" in
    "v$major.$minor.$((patch + 1))"|"v$major.$((minor + 1)).0"|"v$((major + 1)).0.0") ;;
    *)
      mark failure "not released: $tag is not the next version after $previous; run"
      printf 'not released: %s is not the next version after %s\n' "$tag" "$previous"
      emit ''
      exit 0
      ;;
  esac
fi

if [[ "$workflow" == cli-release ]]; then
  if ! GITEA_TOKEN="$release_token" "$(dirname "$0")/require-production-accepted.sh" \
      "$tag" "$tag_object" "$tag_commit" >"$release_tmp/production.log" 2>&1; then
    printf 'nothing pending yet: Production has not accepted %s\n' "$tag"
    emit ''
    exit 0
  fi
fi

mark pending 'picked up by run'
printf 'pending release: %s (%s on %s)\n' "$tag" "$tag_object" "$tag_commit"
emit "$tag" immutable stable
