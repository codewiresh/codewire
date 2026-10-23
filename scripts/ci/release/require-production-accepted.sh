#!/usr/bin/env bash
# require-production-accepted.sh TAG TAG_OBJECT_SHA SOURCE_SHA: refuse a CLI
# release until Production accepted the same release, tag object and commit. One tag drives web and CLI, and only
# Production acceptance proves Dev acceptance for it: deploy-prod succeeds only
# when its promote-prod run accepted the release (dispatch-deploy-prod.sh), and
# promote-prod verified Dev acceptance first (#2892). Reads this repository's
# deploy-prod runs with GITEA_TOKEN, the job's own token.
set -euo pipefail

fail() {
  printf 'production acceptance not proven: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 3 ]] || {
  printf 'usage: require-production-accepted.sh TAG TAG_OBJECT_SHA SOURCE_SHA\n' >&2
  exit 2
}
readonly tag="$1" tag_object_sha="$2" source_sha="$3"
valid_object_id() {
  [[ "$1" =~ ^[0-9a-f]{40}$ || "$1" =~ ^[0-9a-f]{64}$ ]]
}
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "release tag '$tag' is not exact semver"
valid_object_id "$tag_object_sha" || fail 'release tag object is not an object ID'
valid_object_id "$source_sha" || fail 'release source is not a commit ID'
server_url="${GITHUB_SERVER_URL:-}"
server_url="${server_url%/}"
[[ "$server_url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || fail 'GITHUB_SERVER_URL is unset or invalid'
[[ -n "${GITEA_TOKEN:-}" ]] || fail 'GITEA_TOKEN is required to read deploy-prod runs'

tmp="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-production-accepted.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
# The token leaves the environment at once and reaches curl only through a
# pipe: never argv, a file or output.
forgejo_token="$GITEA_TOKEN"
unset GITEA_TOKEN

# api_get PATH FILE: one read of this repository's Actions API; anything but
# HTTP 200 fails. --disable comes first so no curlrc can reuse the token, and
# the header arrives on curl's stdin from the printf builtin.
api_get() {
  local status
  status="$(printf 'header = "Authorization: token %s"\n' "$forgejo_token" |
    curl --disable --config - --silent --show-error \
    --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 \
    --output "$2" --write-out '%{http_code}' \
    "$server_url/api/v1/repos/codewire/codewire/actions/$1" 2>/dev/null)" || return 1
  [ "$status" = 200 ]
}

# job_log VIEW NAME FILE: the log of the run's one job called NAME, at the
# attempt the job list shows, carriage returns removed.
job_log() {
  local job attempt
  read -r job attempt < <(jq -r --arg name "$2" '
      [.[] | select(.name == $name)] | select(length == 1) | .[0] | "\(.id) \(.attempt)"
    ' "$1") || return 1
  [[ "$job" =~ ^[1-9][0-9]*$ && "$attempt" =~ ^[1-9][0-9]*$ ]] || return 1
  api_get "jobs/$job/logs?attempt=$attempt" "$3.raw" || return 1
  tr -d '\r' <"$3.raw" >"$3"
}

api_get 'runs?workflow_id=deploy-prod.yaml&status=success&page=1&limit=50' "$tmp/runs.json" ||
  fail 'the deploy-prod runs are unavailable'
# The release's run: successful, dispatched on main, whose selection verified
# this exact tag, tag object and commit and whose dispatch saw Production
# accept it.
selected="^[0-9T:.-]+Z release tag verified: tag=${tag//./\\.} object=${tag_object_sha} commit=${source_sha} forgejo_signer=[^ ]+\$"
accepted="^[0-9T:.-]+Z \\[dispatch-deploy-prod\\] deploy run [1-9][0-9]* succeeded: Production accepted ${tag//./\\.}\$"
while read -r run; do
  [[ "$run" =~ ^[1-9][0-9]*$ ]] || continue
  api_get "runs/$run/jobs" "$tmp/jobs-$run.json" || continue
  jq -e '
      ([.[] | select(.name == "Verify canonical release tag")] | length == 1 and .[0].status == "success")
      and ([.[] | select(.name == "Dispatch Signed Tag to Deploy")] | length == 1 and .[0].status == "success")
    ' "$tmp/jobs-$run.json" >/dev/null 2>&1 || continue
  job_log "$tmp/jobs-$run.json" 'Verify canonical release tag' "$tmp/selection-$run.log" || continue
  grep -Eq "$selected" "$tmp/selection-$run.log" || continue
  job_log "$tmp/jobs-$run.json" 'Dispatch Signed Tag to Deploy' "$tmp/dispatch-$run.log" || continue
  grep -Eq "$accepted" "$tmp/dispatch-$run.log" || continue
  printf 'Production accepted %s (%s) in deploy-prod run %s\n' "$tag" "$source_sha" "$run"
  exit 0
done < <(jq -r '
    [.workflow_runs[]
      | select(.workflow_id == "deploy-prod.yaml" and .status == "success"
          and .event == "workflow_dispatch" and .prettyref == "main")
      | .id]
    | sort | reverse | .[]
  ' "$tmp/runs.json" 2>/dev/null)
fail "no successful deploy-prod run shows Production accepting $tag ($source_sha). Deliver it to Production first: if its deploy-prod run is still going, dispatch cli-release after it succeeds; if that run predates the wait for promote-prod or its logs have expired, rerun deploy-prod for $tag, then dispatch cli-release again"
