#!/usr/bin/env bash
# Propose the workspace image pin for an image support-images.yaml just
# published from main: rewrite crates/codewire-workspace-image/src/pin.rs on one
# automation branch and open or update its pull request.
#
# The only capability is the token of the restricted Forgejo user
# codewire-workspace-pin-bot: write:repository on codewire/codewire, which
# pushes this branch and opens the pull request but cannot merge it. It is
# read from a private file and travels in git and curl configuration, never in
# arguments or output. Its pushes and pull requests start CI like a person's;
# the workflow's own job token is refused because its events start none.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly BRANCH='automation/workspace-image-pin'
readonly PIN='crates/codewire-workspace-image/src/pin.rs'
readonly TOOL="$ROOT/scripts/ci/images/workspace-image-pin.py"
readonly -a CURL_BOUNDS=(--connect-timeout 10 --max-time 30)
readonly BOT_NAME='Codewire'
readonly BOT_EMAIL='hello@codewire.sh'

die() {
  printf '[propose-workspace-image-pin] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || {
  echo 'usage: propose-workspace-image-pin.sh HARBOR_WORKSPACE_DIGEST_REF' >&2
  exit 2
}
[[ "$1" =~ ^registry\.example\.invalid/codewire/workspace@(sha256:[0-9a-f]{64})$ ]] ||
  die 'the published image is not an exact Harbor workspace digest reference'
readonly digest="${BASH_REMATCH[1]}"
: "${GITHUB_SHA:?}" "${GITHUB_REPOSITORY:?}" "${GITHUB_SERVER_URL:?}"
[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]] || die 'the published commit is not a full object ID'
[[ "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || die 'malformed repository'
[[ -z "${GITEA_TOKEN:-}" ]] ||
  die 'GITEA_TOKEN is set; the proposal uses only the workspace-pin bot token'
token_file="${WORKSPACE_PIN_BOT_TOKEN_FILE:?the workspace-pin bot token file is required}"
[[ -f "$token_file" && ! -L "$token_file" && -O "$token_file" && "$(stat -c '%a' "$token_file")" == 600 ]] ||
  die 'the workspace-pin bot token must be a private regular file'
token="$(<"$token_file")"
[[ "$token" =~ ^[A-Za-z0-9_-]{20,255}$ ]] || {
  token=''
  die 'the workspace-pin bot token is malformed'
}

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/workspace-image-pin.XXXXXX")"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

cd "$ROOT"
# Git reads the credential from its environment configuration, never argv.
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0="http.${GITHUB_SERVER_URL}/.extraheader"
GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $(printf 'x-access-token:%s' "$token" | base64 -w0)"
export GIT_CONFIG_VALUE_0
printf 'header = "Authorization: token %s"\nsilent\nshow-error\nfail\n' "$token" >"$work/api.curl"
token=''
api="${GITHUB_SERVER_URL}/api/v1/repos/${GITHUB_REPOSITORY}"

git fetch -q origin main
main_sha="$(git rev-parse --verify origin/main)"
pin() { python3 "$TOOL" "$@"; }

# A newer main with another image definition publishes its own image, and
# that proposal is the one to land.
if [[ "$(pin inputs-sha256 --commit "$main_sha")" != "$(pin inputs-sha256 --commit "$GITHUB_SHA")" ]]; then
  echo 'workspace image pin: main has moved to another image definition; its own publication proposes the pin'
  exit 0
fi
if [[ "$(pin show --commit "$main_sha" digest)" == "$digest" ]]; then
  echo "workspace image pin: main already pins $digest"
  exit 0
fi
# The pin follows the image definition. An image rebuilt from the definition
# main already pins (only the cw it carries changed, or the pin itself) needs
# no new pin: that cw is refreshed through its own runtime asset.
if [[ "$(pin show --commit "$main_sha" inputs-sha256)" == "$(pin inputs-sha256 --commit "$GITHUB_SHA")" ]]; then
  echo 'workspace image pin: main already pins an image of this definition'
  exit 0
fi

# The published image must be one index serving linux/amd64 (Dev and Production
# Sandboxes) and linux/arm64 (local VMs on Apple silicon). This job runs only
# after the public GHCR mirror succeeded, so the index is read there with the
# pinned Skopeo runner and no credentials, and must hash to the digest.
index="$work/index.json"
skopeo_runner="${SKOPEO_RUNNER:-$ROOT/scripts/ci/images/run-skopeo-container.sh}"
"$skopeo_runner" inspect --raw --no-creds "docker://ghcr.io/codewiresh/workspace@${digest}" >"$index" ||
  die 'cannot read the published image index from the public mirror'
[[ "sha256:$(sha256sum "$index" | cut -d' ' -f1)" == "$digest" ]] ||
  die 'the image index read from the public mirror does not hash to the published digest'
platforms="$(pin index-platforms <"$index")" || die 'the published image is not a valid image index'
[[ "$platforms" == 'linux/amd64,linux/arm64' ]] ||
  die "the published image serves ${platforms:-no image platform}, not linux/amd64 and linux/arm64"

git switch -q --force-create "$BRANCH" "$main_sha"
pin render --digest "$digest" --source-sha "$GITHUB_SHA" --platforms "$platforms"
pin check
[[ "$(git status --porcelain)" == " M $PIN" ]] || die 'the proposal changed more than the pin'
git add "$PIN"
GIT_AUTHOR_NAME="$BOT_NAME" GIT_AUTHOR_EMAIL="$BOT_EMAIL" \
  GIT_COMMITTER_NAME="$BOT_NAME" GIT_COMMITTER_EMAIL="$BOT_EMAIL" \
  git -c commit.gpgsign=false commit -q \
  -m "chore(workspace): pin the workspace image published from ${GITHUB_SHA:0:12}" \
  -m "support-images.yaml published ${digest} from ${GITHUB_SHA}."
git push -q --force origin "HEAD:refs/heads/${BRANCH}"

curl --config "$work/api.curl" "${CURL_BOUNDS[@]}" --output "$work/open.json" \
  "${api}/pulls?state=open&limit=50"
if jq -e --arg branch "$BRANCH" 'any(.[]; .head.ref == $branch)' "$work/open.json" >/dev/null; then
  echo "workspace image pin: updated the open proposal on ${BRANCH} to ${digest}"
  exit 0
fi
agents="$(pin show agents | jq -r 'to_entries | map("\(.key) \(.value)") | join(", ")')"
jq -n --arg branch "$BRANCH" --arg digest "$digest" --arg source "$GITHUB_SHA" --arg agents "$agents" '{
  head: $branch,
  base: "main",
  title: "chore(workspace): pin the published workspace image",
  body: ("support-images.yaml published `\($digest)` from `\($source)`. This pull request changes only `crates/codewire-workspace-image/src/pin.rs`; every consumer reads the pin.\n\nAgent versions in the image definition: \($agents).\n\nThe workspace-pin bot opened this pull request, so CI runs on it like any other. Merge on green; the bot cannot merge. Later publications update this branch.")
}' >"$work/pull.json"
curl --config "$work/api.curl" "${CURL_BOUNDS[@]}" --output "$work/created.json" \
  --header 'Content-Type: application/json' --data-binary @"$work/pull.json" "${api}/pulls"
jq -er '.number | numbers' "$work/created.json" >/dev/null || die 'Forgejo did not open the proposal'
echo "workspace image pin: opened proposal #$(jq -r .number "$work/created.json") for ${digest}"
