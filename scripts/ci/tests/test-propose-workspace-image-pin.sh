#!/usr/bin/env bash
# Synthetic proof for the post-publish workspace pin proposal: one automation
# branch, one pull request, only the pin changes, only the workspace-pin bot's
# private token file is used, and the token never reaches arguments or output.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
CASES=0

fail() {
  printf '[test-propose-workspace-image-pin] ERROR: %s\n' "$*" >&2
  exit 1
}
pass() { CASES=$((CASES + 1)); }

work="$(mktemp -d "${TMPDIR:-/tmp}/propose-workspace-image-pin.XXXXXX")"
trap 'rm -rf "$work"' EXIT
readonly TOKEN='synthetic-workspace-pin-bot-token-0123456789'
printf '%s' "$TOKEN" >"$work/bot-token"
chmod 0600 "$work/bot-token"
OLD="sha256:$(printf '1%.0s' {1..64})"
readonly OLD

# A fixture repository with the real tool, script and pin layout.
repo="$work/repo"
origin="$work/origin.git"
git init -q -b main "$repo"
git init -q --bare -b main "$origin"
git -C "$repo" config user.name fixture
git -C "$repo" config user.email fixture@example.invalid
git -C "$repo" config commit.gpgsign false
mkdir -p "$repo/scripts/ci/images" "$repo/images/workspace" "$repo/images/base" \
  "$repo/crates/codewire-workspace-image/src"
install -m 755 "$ROOT/scripts/ci/images/workspace-image-pin.py" "$repo/scripts/ci/images/"
install -m 755 "$ROOT/scripts/ci/images/propose-workspace-image-pin.sh" "$repo/scripts/ci/images/"
printf 'base\n' >"$repo/images/base/apt"
write_definition() {
  : >"$repo/images/workspace/Dockerfile"
  for package in @anthropic-ai/claude-code @openai/codex @google/gemini-cli \
      @moonshot-ai/kimi-code @earendil-works/pi-coding-agent; do
    printf 'RUN npm install -g %s@%s\n' "$package" "$1" >>"$repo/images/workspace/Dockerfile"
  done
}
write_definition 1.0.0
git -C "$repo" add -A
git -C "$repo" commit -qm definition
old_source="$(git -C "$repo" rev-parse HEAD)"
python3 - "$repo" "$OLD" "$old_source" <<'PY'
import importlib.util, pathlib, sys
root = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("pin", root / "scripts/ci/images/workspace-image-pin.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
pin = tool.validate({"digest": sys.argv[2], "platforms": ["linux/amd64"], "source_sha": sys.argv[3],
                     "inputs_sha256": tool.inputs_sha256(root, sys.argv[3]),
                     "agents": dict(sorted(tool.agent_versions(root, sys.argv[3]).items())),
                     "previous_digests": []})
(root / tool.PIN).write_text(tool.render(pin))
PY
git -C "$repo" add -A
git -C "$repo" commit -qm 'pin the old image'
# The published image comes from a commit that changes the definition.
write_definition 2.0.0
git -C "$repo" commit -qam 'change the definition'
published="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" remote add origin "$origin"
git -C "$repo" push -q origin main

mkdir -p "$work/bin"
cat >"$work/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${FAKE_CURL_CALLS:?}"
printf '\n' >>"$FAKE_CURL_CALLS"
output=''
data=''
url=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --data-binary) data="${2#@}"; shift 2 ;;
    --config|--header|--connect-timeout|--max-time) shift 2 ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  https://forgejo.invalid/api/v1/repos/codewire/codewire/pulls\?state=open\&limit=50)
    printf '%s\n' "${FAKE_OPEN_PULLS:-[]}" >"$output" ;;
  https://forgejo.invalid/api/v1/repos/codewire/codewire/pulls)
    cp "$data" "${FAKE_CREATED_BODY:?}"
    printf '{"number":7}\n' >"$output" ;;
  *) exit 91 ;;
esac
MOCK
chmod +x "$work/bin/curl"

# The published index, as `docker buildx imagetools inspect --raw` prints it:
# two images and BuildKit's attestation manifest.
platform_entry() {
  printf '{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%s","size":1,"platform":{"os":"%s","architecture":"%s"}}' \
    "$(printf "${1}%.0s" {1..64})" "$2" "$3"
}
attestation='{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:'"$(printf '9%.0s' {1..64})"'","size":1,"platform":{"os":"unknown","architecture":"unknown"},"annotations":{"vnd.docker.reference.digest":"sha256:'"$(printf 'a%.0s' {1..64})"'","vnd.docker.reference.type":"attestation-manifest"}}'
index_with() {
  local IFS=,
  printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[%s]}' "$*"
}
TWO_PLATFORMS="$(index_with "$(platform_entry a linux amd64)" "$(platform_entry b linux arm64)" "$attestation")"
digest_of() { printf 'sha256:%s' "$(printf '%s' "$1" | sha256sum | cut -d' ' -f1)"; }
NEW="$(digest_of "$TWO_PLATFORMS")"
readonly NEW
# The pinned Skopeo runner prints the raw index bytes the registry serves.
cat >"$work/bin/skopeo-runner" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${FAKE_SKOPEO_CALLS:?}"
printf '\n' >>"$FAKE_SKOPEO_CALLS"
[[ "$1 $2 $3" == 'inspect --raw --no-creds' ]] || exit 92
printf '%s' "${FAKE_INDEX:?}"
MOCK
chmod +x "$work/bin/skopeo-runner"

# propose REF [NAME=VALUE...]: run the proposal for REF with extra environment.
propose() {
  local ref="$1"
  shift
  (
    cd "$repo"
    env -u GITEA_TOKEN PATH="$work/bin:$PATH" WORKSPACE_PIN_BOT_TOKEN_FILE="$work/bot-token" \
      GITHUB_SHA="$published" \
      GITHUB_REPOSITORY=codewire/codewire GITHUB_SERVER_URL=https://forgejo.invalid \
      RUNNER_TEMP="$work" FAKE_CURL_CALLS="$work/curl-calls" FAKE_SKOPEO_CALLS="$work/skopeo-calls" \
      SKOPEO_RUNNER="$work/bin/skopeo-runner" \
      FAKE_INDEX="$TWO_PLATFORMS" \
      FAKE_CREATED_BODY="$work/created-body.json" "$@" \
      scripts/ci/images/propose-workspace-image-pin.sh "$ref"
  )
}

# The published image is proposed on the automation branch, changing only the pin.
: >"$work/curl-calls"
propose "registry.example.invalid/codewire/workspace@$NEW" >"$work/propose.out" 2>&1 ||
  fail "proposal failed: $(cat "$work/propose.out")"
grep -Fq 'opened proposal #7' "$work/propose.out" || fail 'the proposal was not opened'
[[ "$(git -C "$origin" diff --name-only main automation/workspace-image-pin)" == \
  crates/codewire-workspace-image/src/pin.rs ]] || fail 'the proposal changed more than the pin'
proposed="$(git -C "$origin" show automation/workspace-image-pin:crates/codewire-workspace-image/src/pin.rs)"
grep -Fq "pub const DIGEST: &str = \"$NEW\";" <<<"$proposed" || fail 'the proposal does not pin the published digest'
grep -Fq "pub const SOURCE_SHA: &str = \"$published\";" <<<"$proposed" || fail 'the proposal does not record its source'
grep -Fq "    \"$OLD\"," <<<"$proposed" || fail 'the replaced digest is not kept as previous'
grep -Fq '("codex", "2.0.0")' <<<"$proposed" || fail 'the proposal does not record the published agent versions'
grep -Fq 'pub const PLATFORMS: &[&str] = &["linux/amd64", "linux/arm64"];' <<<"$proposed" ||
  fail 'the proposal does not record both published platforms'
grep -Fq "inspect --raw --no-creds docker://ghcr.io/codewiresh/workspace@$NEW" "$work/skopeo-calls" ||
  fail 'the proposal did not read the published index anonymously from the public mirror'
jq -e '.head == "automation/workspace-image-pin" and .base == "main"' "$work/created-body.json" >/dev/null ||
  fail 'the pull request does not target main from the automation branch'
jq -e '(.body | contains("workspace-pin bot opened this pull request")) and
  (.body | test("reopen"; "i") | not)' "$work/created-body.json" >/dev/null ||
  fail 'the pull request body does not say the bot opened it, or still asks for a reopen'
[[ "$(git -C "$origin" log -1 --format='%an <%ae>' automation/workspace-image-pin)" == \
  'Codewire workspace pin bot <codewire-workspace-pin-bot@noreply.example.invalid>' ]] ||
  fail 'the proposal commit is not authored by the workspace-pin bot'
if grep -rqF "$TOKEN" "$work/curl-calls" "$work/propose.out" "$work/created-body.json"; then
  fail 'the token reached curl arguments, output or the request body'
fi
pass

# An open proposal is updated in place; no second pull request is opened.
rm -f "$work/created-body.json"
propose "registry.example.invalid/codewire/workspace@$NEW" \
  FAKE_OPEN_PULLS='[{"number":7,"head":{"ref":"automation/workspace-image-pin"}}]' \
  >"$work/update.out" 2>&1 || fail "update failed: $(cat "$work/update.out")"
grep -Fq 'updated the open proposal' "$work/update.out" || fail 'the open proposal was not updated'
[[ ! -e "$work/created-body.json" ]] || fail 'a second pull request was opened'
pass

# Main already pinning the digest proposes nothing.
git -C "$repo" switch -q main
git -C "$repo" merge -q --ff-only "$(git -C "$origin" rev-parse automation/workspace-image-pin)"
git -C "$repo" push -q origin main
before="$(git -C "$origin" rev-parse automation/workspace-image-pin)"
propose "registry.example.invalid/codewire/workspace@$NEW" >"$work/same.out" 2>&1 || fail 'a pinned digest failed'
grep -Fq "main already pins $NEW" "$work/same.out" || fail 'a pinned digest was proposed again'
[[ "$(git -C "$origin" rev-parse automation/workspace-image-pin)" == "$before" ]] ||
  fail 'a pinned digest rewrote the automation branch'
pass

# A main that moved to another definition leaves the proposal to its own publication.
git -C "$repo" switch -q main
write_definition 3.0.0
git -C "$repo" commit -qam 'change the definition again'
git -C "$repo" push -q origin main
propose "registry.example.invalid/codewire/workspace@sha256:$(printf '3%.0s' {1..64})" \
  >"$work/moved.out" 2>&1 || fail 'a moved main failed'
grep -Fq 'its own publication proposes the pin' "$work/moved.out" || fail 'an outdated image was proposed'
pass

# Only the bot's private token file is a credential; the job token and any
# other file are refused before git or the API is touched.
ln -s "$work/bot-token" "$work/bot-token-link"
install -m 0644 "$work/bot-token" "$work/bot-token-shared"
printf 'not a token' >"$work/bot-token-malformed"
chmod 0600 "$work/bot-token-malformed"
before="$(git -C "$origin" rev-parse automation/workspace-image-pin)"
for override in GITEA_TOKEN="$TOKEN" WORKSPACE_PIN_BOT_TOKEN_FILE="$work/absent" \
    WORKSPACE_PIN_BOT_TOKEN_FILE="$work/bot-token-link" WORKSPACE_PIN_BOT_TOKEN_FILE="$work/bot-token-shared" \
    WORKSPACE_PIN_BOT_TOKEN_FILE="$work/bot-token-malformed"; do
  calls_before="$(wc -l <"$work/curl-calls")"
  if propose "registry.example.invalid/codewire/workspace@sha256:$(printf '4%.0s' {1..64})" "$override" \
      >"$work/credential.out" 2>&1; then
    fail "an unapproved credential was accepted: ${override%%=*}"
  fi
  [[ "$(wc -l <"$work/curl-calls")" -eq "$calls_before" ]] || fail "${override%%=*} reached the API"
  [[ "$(git -C "$origin" rev-parse automation/workspace-image-pin)" == "$before" ]] ||
    fail "${override%%=*} pushed the automation branch"
  if grep -qF "$TOKEN" "$work/credential.out"; then
    fail 'a refused credential was printed'
  fi
  pass
done

# An image that is not one index serving both platforms is refused before
# anything is pushed or opened.
before="$(git -C "$origin" rev-parse automation/workspace-image-pin)"
current="$(git -C "$origin" rev-parse main)"
for case in amd64-only plain-manifest unexpected-platform wrong-bytes; do
  case "$case" in
    amd64-only) index="$(index_with "$(platform_entry a linux amd64)" "$attestation")" ;;
    plain-manifest) index='{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}' ;;
    unexpected-platform) index="$(index_with "$(platform_entry a linux amd64)" "$(platform_entry b linux arm64)" \
      "$(platform_entry c linux s390x)")" ;;
    wrong-bytes) index="$TWO_PLATFORMS " ;;
  esac
  published_digest="$(digest_of "$index")"
  # Bytes that are not what the published digest names.
  [[ "$case" != wrong-bytes ]] ||
    published_digest="$(digest_of "$(index_with "$(platform_entry c linux amd64)" "$(platform_entry d linux arm64)")")"
  calls_before="$(wc -l <"$work/curl-calls")"
  if propose "registry.example.invalid/codewire/workspace@$published_digest" FAKE_INDEX="$index" \
      GITHUB_SHA="$current" >"$work/platforms.out" 2>&1; then
    fail "an image that is not a two-platform index was proposed: $case"
  fi
  grep -Eq 'not linux/amd64 and linux/arm64|not a valid image index|does not hash to the published digest' "$work/platforms.out" ||
    fail "the $case refusal does not say why: $(cat "$work/platforms.out")"
  [[ "$(wc -l <"$work/curl-calls")" -eq "$calls_before" ]] || fail "$case reached the API"
  [[ "$(git -C "$origin" rev-parse automation/workspace-image-pin)" == "$before" ]] ||
    fail "$case pushed the automation branch"
  pass
done

# Only an exact Harbor workspace digest is accepted.
for ref in "ghcr.io/codewiresh/workspace@$NEW" "registry.example.invalid/codewire/workspace:latest" \
    "registry.example.invalid/codewire/base@$NEW"; do
  if propose "$ref" >"$work/refused.out" 2>&1; then
    fail "malformed reference was accepted: $ref"
  fi
  pass
done

printf 'test-propose-workspace-image-pin: PASS cases=%s\n' "$CASES"
