#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly RESOLVER="$ROOT/scripts/ci/images/resolve-published-support-pair.sh"
readonly SOURCE_SHA='1111111111111111111111111111111111111111'

fail() {
  printf '[test-resolve-published-support-pair] ERROR: %s\n' "$*" >&2
  exit 1
}

# mkdir, not install -d: install would reset the mode of an existing shared
# directory that checks running beside this one hold open.
mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/support-baseline-test.XXXXXX")"
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT
mkdir -p "$work/bin" "$work/capture"

cat >"$work/bin/skopeo" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$MOCK_CAPTURE_DIR/skopeo-calls"
case "$1" in
  inspect)
    [[ "$*" == *'inspect --no-creds --override-os linux --override-arch amd64 docker://'* ]]
    [[ -z "${SKOPEO_AUTH_VOLUME:-}" ]]
    ref="${*: -1}"
    tag="${ref##*:}"
    revision="$SOURCE_SHA"
    [[ "$tag" == latest ]] || revision="$tag"
    case "$ref" in
      *'/base:'*) image=base; digest="sha256:$(printf '1%.0s' {1..64})" ;;
      *'/workspace:'*) image=workspace; digest="sha256:$(printf '2%.0s' {1..64})" ;;
      *) exit 2 ;;
    esac
    [[ "${FAIL_IMAGE:-}" != "$image" ]] || exit 1
    if [[ "${MALFORMED_IMAGE:-}" == "$image" ]]; then
      printf '%s\n' 'not-json'
      exit 0
    fi
    printf '{"Name":"ghcr.io/codewiresh/%s","Digest":"%s","Labels":{"org.opencontainers.image.revision":"%s"}}\n' \
      "$image" "$digest" "$revision"
    ;;
  list-tags)
    [[ "$2" == --no-creds ]]
    [[ -z "${SKOPEO_AUTH_VOLUME:-}" ]]
    case "$3" in
      docker://ghcr.io/codewiresh/base) image=base ;;
      docker://ghcr.io/codewiresh/workspace) image=workspace ;;
      *) exit 2 ;;
    esac
    [[ "${FAIL_TAGS:-}" != "$image" ]] || exit 1
    variable="${image^^}_TAGS"
    jq -n --arg repository "ghcr.io/codewiresh/$image" --arg tags "${!variable:-}" \
      '{Repository: $repository, Tags: (["latest"] + ($tags | split(" ") | map(select(length > 0))))}'
    ;;
  *) exit 2 ;;
esac
MOCK
chmod +x "$work/bin/skopeo"

run_resolver() {
  local output="$1"
  shift
  env \
    SKOPEO_RUNNER="$work/bin/skopeo" \
    MOCK_CAPTURE_DIR="$work/capture" \
    SOURCE_SHA="$SOURCE_SHA" \
    "$@" \
    "$RESOLVER" "$output"
}

success="$work/success.json"
run_resolver "$success"
if ! jq -e --arg source "$SOURCE_SHA" '
  .schema == "codewire.ci-published-support-candidate/v1"
  and .retrieval == {valid: true, reasons: []}
  and .images.base.repository == "ghcr.io/codewiresh/base"
  and .images.workspace.repository == "ghcr.io/codewiresh/workspace"
  and .images.base.tag == "latest"
  and .images.workspace.tag == "latest"
  and .images.base.revision == $source
  and .images.workspace.revision == $source
  and (.images.base.digest | test("^sha256:[0-9a-f]{64}$"))
  and (.images.workspace.digest | test("^sha256:[0-9a-f]{64}$"))
' "$success" >/dev/null; then
  jq . "$success" >&2
  fail 'matching registry response was not preserved'
fi
if grep -Eq 'login|authfile|username|password' "$work/capture/skopeo-calls"; then
  fail 'public support resolution attempted authenticated registry access'
fi

lookup_failure="$work/lookup-failure.json"
run_resolver "$lookup_failure" FAIL_IMAGE=workspace
jq -e '.retrieval == {valid: false, reasons: ["workspace_registry_lookup_failed"]} and .images == {}' \
  "$lookup_failure" >/dev/null || fail 'partial publication did not fail closed'

malformed="$work/malformed.json"
run_resolver "$malformed" MALFORMED_IMAGE=base
jq -e '.retrieval == {valid: false, reasons: ["base_registry_response_malformed"]}' \
  "$malformed" >/dev/null || fail 'malformed registry response did not fail closed'

# A dispatch for an earlier commit reads the pair of its newest first-parent
# ancestor (itself included) that GHCR serves under that commit's tag.
history="$work/history"
git init --quiet --initial-branch=main "$history"
commit() {
  git -C "$history" -c user.name=fixture -c user.email=fixture@example.invalid \
    commit --quiet --allow-empty -m "$1"
  git -C "$history" rev-parse HEAD
}
oldest="$(commit oldest)"
older="$(commit older)"
git -C "$history" checkout --quiet -b side
side="$(commit side)"
git -C "$history" checkout --quiet main
git -C "$history" -c user.name=fixture -c user.email=fixture@example.invalid \
  merge --quiet --no-ff -m merge side
merged="$(git -C "$history" rev-parse HEAD)"
source="$(commit source)"
newer="$(commit newer)"

# ancestor_case NAME BASE_TAGS WORKSPACE_TAGS [ENV...] prints the chosen tag,
# or the failure reason.
ancestor_case() {
  local base_tags="$2" workspace_tags="$3" output="$work/$1.json"
  shift 3
  (cd "$history" && env \
    SKOPEO_RUNNER="$work/bin/skopeo" \
    MOCK_CAPTURE_DIR="$work/capture" \
    SOURCE_SHA="$SOURCE_SHA" \
    BASE_TAGS="$base_tags" WORKSPACE_TAGS="$workspace_tags" \
    "$@" \
    "$RESOLVER" "$output" "$source" 2>/dev/null)
  jq -r 'if .retrieval.valid then
      (if .images.base.tag == .images.base.revision and .images.workspace.tag == .images.workspace.revision
          and .images.base.tag == .images.workspace.tag then .images.base.tag else "inconsistent" end)
    else .retrieval.reasons[0] end' "$output"
}
[[ "$(ancestor_case newest "$oldest $older $newer" "$oldest $older $newer")" == "$older" ]] ||
  fail 'a dispatch did not read its newest published ancestor, or read a descendant'
[[ "$(ancestor_case own "$older $source" "$older $source")" == "$source" ]] ||
  fail 'a dispatch for a commit with its own pair did not read that pair'
[[ "$(ancestor_case pair-only "$oldest $older" "$oldest")" == "$oldest" ]] ||
  fail 'a dispatch read an ancestor with only half a pair'
[[ "$(ancestor_case first-parent "$oldest $side" "$oldest $side")" == "$oldest" ]] ||
  fail 'a dispatch read a merged branch commit that was never main'
[[ "$(ancestor_case merge "$merged" "$merged")" == "$merged" ]] ||
  fail 'a dispatch did not read a first-parent merge commit'
[[ "$(ancestor_case none "$newer" "$newer")" == no_published_ancestor_pair ]] ||
  fail 'a dispatch without a published ancestor did not fail closed'
[[ "$(ancestor_case tags-failed "$older" "$older" FAIL_TAGS=workspace)" == workspace_registry_tags_failed ]] ||
  fail 'an unreadable tag list did not fail closed'
[[ "$(ancestor_case inspect-failed "$older" "$older" FAIL_IMAGE=base)" == base_registry_lookup_failed ]] ||
  fail 'an unreadable ancestor pair did not fail closed'
if "$RESOLVER" "$work/bad.json" "${source:0:12}" 2>/dev/null; then
  fail 'a short source commit was accepted'
fi
if grep -Eq 'login|authfile|username|password' "$work/capture/skopeo-calls"; then
  fail 'ancestor support resolution attempted authenticated registry access'
fi

printf '[test-resolve-published-support-pair] anonymous matching, partial, malformed and ancestor cases passed\n'
