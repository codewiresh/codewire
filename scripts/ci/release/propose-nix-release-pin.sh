#!/usr/bin/env bash
# Propose the Nix flake's release pin for a release cli-release just published
# (docs/dev/CLI-NIX-INSTALL.md, "How a release moves the flake"): recompute
# nix/release.json from the signed release the stable channel names, put it on
# one automation branch, and open or update its pull request. The pull
# request's body is the recomputation, so a reviewer compares hashes rather
# than trusting this job.
#
# The only capability is the token of the restricted Forgejo user
# codewire-release-pin-bot: write on codewire/codewire, which pushes this
# branch and opens the pull request but cannot merge it. It is read from a
# private file and travels in git and curl configuration, never in arguments
# or output. Its pushes and pull requests start CI like a person's.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly BRANCH='automation/nix-release-pin'
readonly PIN='nix/release.json'
readonly SUMS='nix/SHA256SUMS'
readonly SUMS_SIG='nix/SHA256SUMS.asc'
readonly TOOL="${NIX_RELEASE_PIN_TOOL:-$ROOT/scripts/ci/release/nix_release_pin.py}"
readonly -a CURL_BOUNDS=(--connect-timeout 10 --max-time 30)
readonly BOT_NAME='Codewire'
readonly BOT_EMAIL='hello@codewire.sh'

die() {
  printf '[propose-nix-release-pin] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || {
  echo 'usage: propose-nix-release-pin.sh RELEASE_TAG' >&2
  exit 2
}
[[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'the release tag is not vMAJOR.MINOR.PATCH'
readonly tag="$1"
: "${GITHUB_REPOSITORY:?}" "${GITHUB_SERVER_URL:?}"
[[ "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || die 'malformed repository'
[[ -z "${GITEA_TOKEN:-}" ]] ||
  die 'GITEA_TOKEN is set; the proposal uses only the release-pin bot token'
token_file="${RELEASE_PIN_BOT_TOKEN_FILE:?the release-pin bot token file is required}"
[[ -f "$token_file" && ! -L "$token_file" && -O "$token_file" && "$(stat -c '%a' "$token_file")" == 600 ]] ||
  die 'the release-pin bot token must be a private regular file'
token="$(<"$token_file")"
[[ "$token" =~ ^[A-Za-z0-9_-]{20,255}$ ]] || {
  token=''
  die 'the release-pin bot token is malformed'
}

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/nix-release-pin.XXXXXX")"
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

# The pin and its report come from the signed release, read as cw upgrade
# reads it. A channel already on a newer release writes nothing: that
# release's own run proposes its pin, and the flake never moves backwards.
python3 -I -B "$TOOL" render --version "$tag" --output "$work/release.json" --report "$work/report.md" \
  --sums "$work/SHA256SUMS" --sums-signature "$work/SHA256SUMS.asc"
if [[ ! -f "$work/release.json" ]]; then
  echo "nix release pin: a newer release than ${tag} is stable; its own run proposes the pin"
  exit 0
fi

git fetch -q origin main
main_sha="$(git rev-parse --verify origin/main)"
if git show "${main_sha}:${PIN}" 2>/dev/null | cmp -s - "$work/release.json" &&
    git show "${main_sha}:${SUMS}" 2>/dev/null | cmp -s - "$work/SHA256SUMS" &&
    git show "${main_sha}:${SUMS_SIG}" 2>/dev/null | cmp -s - "$work/SHA256SUMS.asc"; then
  echo "nix release pin: main already pins ${tag}"
  exit 0
fi

curl --config "$work/api.curl" "${CURL_BOUNDS[@]}" --output "$work/open.json" \
  "${api}/pulls?state=open&page=1&limit=50"
proposal="$(jq -r --arg branch "$BRANCH" '[.[] | select(.head.ref == $branch) | .number] | first // empty' \
  "$work/open.json")"
[[ -z "$proposal" || "$proposal" =~ ^[1-9][0-9]*$ ]] || die 'Forgejo listed a malformed pull request number'

git switch -q --force-create "$BRANCH" "$main_sha"
install -m 0644 "$work/release.json" "$PIN"
install -m 0644 "$work/SHA256SUMS" "$SUMS"
install -m 0644 "$work/SHA256SUMS.asc" "$SUMS_SIG"
# Only the pin and the signed checksums that prove it may change.
changed="$(git status --porcelain --untracked-files=all | sort)"
while IFS= read -r line; do
  case "$line" in
    " M $PIN" | " M $SUMS" | " M $SUMS_SIG" | "?? $SUMS" | "?? $SUMS_SIG") ;;
    *) die 'the proposal changed more than the pin' ;;
  esac
done <<<"$changed"
git add "$PIN" "$SUMS" "$SUMS_SIG"
GIT_AUTHOR_NAME="$BOT_NAME" GIT_AUTHOR_EMAIL="$BOT_EMAIL" \
  GIT_COMMITTER_NAME="$BOT_NAME" GIT_COMMITTER_EMAIL="$BOT_EMAIL" \
  git -c commit.gpgsign=false commit -q \
  -m "chore(nix): pin the flake to cw ${tag}" \
  -m "nix/release.json now names the executables of the signed release ${tag}; nix/SHA256SUMS and its signature prove it."
git push -q --force origin "HEAD:refs/heads/${BRANCH}"

# The body is this head's recomputation, so an updated proposal gets a new one.
jq -n --arg branch "$BRANCH" --arg tag "$tag" --rawfile report "$work/report.md" '{
  head: $branch,
  base: "main",
  title: "chore(nix): pin the flake to cw \($tag)",
  body: ($report + "\nThe release-pin bot opened this pull request after cli-release published `\($tag)`. It cannot merge; review the table and queue it. A later release updates this branch and this body.\n")
}' >"$work/pull.json"
if [[ -n "$proposal" ]]; then
  jq '{title, body}' "$work/pull.json" >"$work/edit.json"
  curl --config "$work/api.curl" "${CURL_BOUNDS[@]}" --output "$work/edited.json" --request PATCH \
    --header 'Content-Type: application/json' --data-binary @"$work/edit.json" "${api}/pulls/${proposal}"
  echo "nix release pin: updated proposal #${proposal} to ${tag}"
  exit 0
fi
curl --config "$work/api.curl" "${CURL_BOUNDS[@]}" --output "$work/created.json" \
  --header 'Content-Type: application/json' --data-binary @"$work/pull.json" "${api}/pulls"
jq -er '.number | numbers' "$work/created.json" >/dev/null || die 'Forgejo did not open the proposal'
echo "nix release pin: opened proposal #$(jq -r .number "$work/created.json") for ${tag}"
