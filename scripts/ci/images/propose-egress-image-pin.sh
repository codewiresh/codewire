#!/usr/bin/env bash
# Propose the cw-egress image pin (private-docs designs/hosted-egress.md, "The
# image and its deployment"): when Dev delivery has signed an image of main's
# current egress inputs, rewrite the egress component's pin on one automation
# branch and open or update its pull request.
#
# It proposes nothing it has not verified. The digest comes from the
# fp-<fingerprint> tag of main's current egress_image fingerprint, and is
# proposed only when a main-CI-verified signature of it names a source commit
# that main contains and whose egress_image fingerprint is main's. A tag alone
# is never enough.
#
# The only capability is the workspace-pin bot's token (the restricted Forgejo
# user codewire-workspace-pin-bot, write:repository on codewire/codewire): it
# pushes this branch and opens the pull request but cannot merge it. It is read
# from a private file and travels in git and curl configuration, never in
# arguments or output. A signed image waits for the next main push to be
# proposed: this runs in support-images.yaml, which Dev delivery's signing
# never triggers.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly BRANCH='automation/egress-image-pin'
readonly COMPONENT='deployments/k8s/egress/kustomization.yaml'
readonly TOOL="$ROOT/scripts/ci/images/egress-image-pin.py"
readonly TAGS="$ROOT/scripts/ci/images/egress-image-tag.sh"
readonly VERIFIER="$ROOT/scripts/ci/images/verify-runtime-image-signatures.sh"
readonly PUBLIC_KEY="$ROOT/scripts/ci/trust/codewire-runtime-signing.pub"
readonly -a CURL_BOUNDS=(--connect-timeout 10 --max-time 30)
readonly BOT_NAME='Codewire'
readonly BOT_EMAIL='hello@codewire.sh'

die() {
  printf '[propose-egress-image-pin] ERROR: %s\n' "$*" >&2
  exit 1
}
say() {
  printf 'egress image pin: %s\n' "$*"
}

[[ $# -eq 0 ]] || {
  echo 'usage: propose-egress-image-pin.sh' >&2
  exit 2
}
: "${GITHUB_SHA:?}" "${GITHUB_REPOSITORY:?}" "${GITHUB_SERVER_URL:?}" "${CODEWIRE_IMAGE_REGISTRY:?}"
[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]] || die 'the commit is not a full object ID'
[[ "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || die 'malformed repository'
[[ -z "${GITEA_TOKEN:-}" ]] ||
  die 'GITEA_TOKEN is set; the proposal uses only the workspace-pin bot token'
token_file="${WORKSPACE_PIN_BOT_TOKEN_FILE:?the workspace-pin bot token file is required}"
[[ -f "$token_file" && ! -L "$token_file" && -O "$token_file" && "$(stat -c '%a' "$token_file")" == 600 ]] ||
  die 'the workspace-pin bot token must be a private regular file'

pin() { python3 "$TOOL" "$@"; }

# The checkout keeps no credential, so git and the API both carry the bot's
# from here on, before the first fetch, as the workspace pin proposer does.
token="$(<"$token_file")"
[[ "$token" =~ ^[A-Za-z0-9_-]{20,255}$ ]] || {
  token=''
  die 'the workspace-pin bot token is malformed'
}
umask 077
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/egress-image-pin.XXXXXX")"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
# Git reads the credential from its environment configuration, never argv.
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0="http.${GITHUB_SERVER_URL}/.extraheader"
GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $(printf 'x-access-token:%s' "$token" | base64 -w0)"
export GIT_CONFIG_VALUE_0
printf 'header = "Authorization: token %s"\nsilent\nshow-error\nfail\n' "$token" >"$work/api.curl"
token=''
api="${GITHUB_SERVER_URL}/api/v1/repos/${GITHUB_REPOSITORY}"

cd "$ROOT"
git fetch -q origin main
main_sha="$(git rev-parse --verify origin/main)"
# Only main's newest commit proposes: a newer commit may carry other inputs.
if [[ "$main_sha" != "$GITHUB_SHA" ]]; then
  say "main has moved past ${GITHUB_SHA:0:12}; its newest push proposes"
  exit 0
fi

fingerprint="$(pin fingerprint --commit "$main_sha")" || die 'cannot compute the egress_image fingerprint'
if digest="$("$TAGS" fp-digest "$fingerprint")"; then
  :
else
  status=$?
  [[ "$status" -eq 3 ]] || die 'cannot read the signed image of these inputs'
  say "no signed image of fingerprint $fingerprint yet; Dev delivery signs one after main CI verifies it"
  exit 0
fi
if [[ "$(pin show --commit "$main_sha")" == "$digest" ]]; then
  say "main already pins $digest"
  exit 0
fi

reference="$CODEWIRE_IMAGE_REGISTRY/codewire/egress@$digest"
sources="$("$VERIFIER" --egress "$reference" "$PUBLIC_KEY")" ||
  die "$reference has no valid main-CI-verified signature"
accepted=''
while read -r source; do
  [[ "$source" =~ ^[0-9a-f]{40}$ ]] || continue
  git merge-base --is-ancestor "$source" "$main_sha" 2>/dev/null || continue
  [[ "$(pin fingerprint --commit "$source")" == "$fingerprint" ]] || continue
  accepted="$source"
  break
done <<<"$sources"
[[ -n "$accepted" ]] ||
  die "no verified signature of $reference names a source on main with fingerprint $fingerprint"


curl --config "$work/api.curl" "${CURL_BOUNDS[@]}" --output "$work/open.json" \
  "${api}/pulls?state=open&page=1&limit=50"
proposal_open=false
if jq -e --arg branch "$BRANCH" 'any(.[]; .head.ref == $branch)' "$work/open.json" >/dev/null; then
  proposal_open=true
fi
if [[ "$proposal_open" == true ]] && git fetch -q origin "refs/heads/${BRANCH}" 2>/dev/null &&
    [[ "$(pin show --commit "$(git rev-parse FETCH_HEAD)")" == "$digest" ]]; then
  say "the open proposal already pins $digest; its CI runs on"
  exit 0
fi

git switch -q --force-create "$BRANCH" "$main_sha"
pin render --digest "$digest"
pin check
[[ "$(git status --porcelain)" == " M $COMPONENT" ]] || die 'the proposal changed more than the pin'
git add "$COMPONENT"
GIT_AUTHOR_NAME="$BOT_NAME" GIT_AUTHOR_EMAIL="$BOT_EMAIL" \
  GIT_COMMITTER_NAME="$BOT_NAME" GIT_COMMITTER_EMAIL="$BOT_EMAIL" \
  git -c commit.gpgsign=false commit -q \
  -m "chore(egress): pin the cw-egress image signed from ${accepted:0:12}" \
  -m "Dev delivery signed ${digest} (main-CI verified) from ${accepted}, whose egress inputs are main's (fingerprint ${fingerprint})."
git push -q --force origin "HEAD:refs/heads/${BRANCH}"

if [[ "$proposal_open" == true ]]; then
  say "updated the open proposal on ${BRANCH} to ${digest}"
  exit 0
fi
jq -n --arg branch "$BRANCH" --arg digest "$digest" --arg source "$accepted" --arg fingerprint "$fingerprint" '{
  head: $branch,
  base: "main",
  title: "chore(egress): bump cw-egress",
  body: ("Dev delivery signed `\($digest)` from `\($source)` after main CI verified it; that commit is on main and its egress inputs are main'"'"'s (fingerprint `\($fingerprint)`). This pull request changes only `deployments/k8s/egress/kustomization.yaml`, the one place the cw-egress digest is chosen.\n\nThe workspace-pin bot opened it, so CI runs on it like any other. It needs review: cw-security reviews the first bump and any bump that changes more than the digest. The bot cannot merge. Later signed images update this branch.")
}' >"$work/pull.json"
curl --config "$work/api.curl" "${CURL_BOUNDS[@]}" --output "$work/created.json" \
  --header 'Content-Type: application/json' --data-binary @"$work/pull.json" "${api}/pulls"
jq -er '.number | numbers' "$work/created.json" >/dev/null || die 'Forgejo did not open the proposal'
say "opened proposal #$(jq -r .number "$work/created.json") for ${digest}"
