#!/usr/bin/env bash
# Fixtures for deploy-prod's two release helpers (#3246):
#   alias-release-images.sh   five existing images aliased side by side;
#   finish-prod-release.sh    support pair joined, published, mirrored, then
#                             the release delivered.
# The image, registry and dispatch scripts they call are stand-ins that log.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/deploy-prod-helpers.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  printf '[test-deploy-prod-helpers] ERROR: %s\n' "$*" >&2
  exit 1
}

readonly SHA=1111111111111111111111111111111111111111
tree="$TMP/tree"
mkdir -p "$tree/scripts/ci/release" "$tree/scripts/ci/images" "$tree/scripts/ci/deploy"
cp "$ROOT/scripts/ci/release/alias-release-images.sh" "$ROOT/scripts/ci/release/finish-prod-release.sh" \
  "$tree/scripts/ci/release/"
log="$TMP/calls.log"
stub() { # PATH BODY: a stand-in that logs its name and arguments, then runs BODY
  printf '#!/usr/bin/env bash\nset -euo pipefail\nprintf "%%s %%s\\n" "%s" "$*" >>"%s"\n%s\n' \
    "$(basename "$1")" "$log" "$2" >"$tree/$1"
  chmod +x "$tree/$1"
}
# build-push-image.sh IMAGE ...: sleeps so the five overlap, fails for
# FIXTURE_FAIL_IMAGE, and reports the image's candidate.
stub scripts/ci/images/build-push-image.sh '
[ "$REQUIRE_EXISTING_SOURCE_IMAGE" = 1 ] || exit 90
printf "origin %s\n" "$(git -C "$CODEWIRE_SOURCE_DIR" remote get-url origin)" >>"'"$TMP"'/origins.log"
printf "%s start\n" "$1" >>"'"$TMP"'/order.log"
sleep 0.3
printf "%s end\n" "$1" >>"'"$TMP"'/order.log"
[ "$1" != "${FIXTURE_FAIL_IMAGE:-}" ] || { echo "$1 is not published for this source" >&2; exit 1; }
printf "source_sha=%s\ncandidate_ref=registry.example.invalid/codewire/%s@sha256:%064d\n" "$CODEWIRE_SOURCE_SHA" "$1" 1 >>"$GITHUB_OUTPUT"'
# join-release-support-image.sh IMAGE ...: records the digests it was given.
stub scripts/ci/images/join-release-support-image.sh '
printf "join %s pair=%s amd64=%s arm64=%s\n" "$1" "$BUILD_SUPPORT_PAIR" "${AMD64_DIGEST:-}" "${ARM64_DIGEST:-}" >>"'"$TMP"'/joins.log"
printf "provenance %s %s\n" "$1" "${CODEWIRE_PROVENANCE_REVISION:-}" >>"'"$TMP"'/provenance.log"
printf "source_sha=%s\ncandidate_ref=registry.example.invalid/codewire/%s@sha256:%064d\n" "${FIXTURE_JOIN_SOURCE:-$CODEWIRE_SOURCE_SHA}" "$1" 2 >>"$GITHUB_OUTPUT"'
stub scripts/ci/images/publish-image-to-harbor.sh '[ "${FIXTURE_HARBOR:-ok}" = ok ]'
stub scripts/ci/images/publish-image-to-ghcr.sh '[ "${FIXTURE_GHCR:-ok}" = ok ]'
stub scripts/ci/deploy/dispatch-deploy-prod.sh ''

reset() {
  rm -f "$log" "$TMP/order.log" "$TMP/joins.log" "$TMP/origins.log" "$TMP/provenance.log"
  : >"$TMP/output"
}

# --- alias-release-images.sh --------------------------------------------------------
# The release checkout, whose origin is not the canonical URL, as
# actions-checkout leaves it.
git init -q "$TMP/release-source"
git -C "$TMP/release-source" remote add origin https://git.internal.example.invalid/codewire/codewire
aliases() {
  env GITHUB_OUTPUT="$TMP/output" RUNNER_TEMP="$TMP" CODEWIRE_SOURCE_DIR="$TMP/release-source" \
    CODEWIRE_SOURCE_URL=https://git.example.invalid/codewire/codewire.git \
    CODEWIRE_SOURCE_SHA="$SHA" REQUIRE_EXISTING_SOURCE_IMAGE="${CASE_REQUIRE-1}" \
    "$tree/scripts/ci/release/alias-release-images.sh" >"$TMP/aliases.out" 2>&1
}
origin_now() { git -C "$TMP/release-source" remote get-url origin; }
reset
aliases || fail "the aliases failed: $(cat "$TMP/aliases.out")"
for image in daemon derp services mesh dashboard; do
  grep -Fxq "${image}_source_sha=$SHA" "$TMP/output" || fail "no $image source"
  grep -Fxq "${image}_candidate_ref=registry.example.invalid/codewire/$image@sha256:$(printf '%064d' 1)" "$TMP/output" ||
    fail "no $image candidate"
  grep -Fxq "build-push-image.sh $image $TMP/release-source/$( case $image in
      dashboard) echo apps/dashboard/Dockerfile ;; *) echo "deployments/docker/$image.Dockerfile" ;; esac) $TMP/release-source" "$log" ||
    fail "$image was aliased from another Dockerfile"
done
[ "$(wc -l <"$TMP/output")" = 10 ] || fail 'the aliases reported other outputs'
# The aliases ran against the canonical origin, set once, and the checkout's
# own origin is back afterwards.
grep -Fxq 'origin https://git.example.invalid/codewire/codewire.git' "$TMP/origins.log" ||
  fail "the aliases did not see the canonical origin: $(sort -u "$TMP/origins.log")"
[ "$(sort -u "$TMP/origins.log" | wc -l)" = 1 ] || fail 'an alias saw another origin'
[ "$(origin_now)" = https://git.internal.example.invalid/codewire/codewire ] || fail 'the checkout origin was not restored'
# Side by side: every alias started before the first one ended.
first_end="$(grep -n ' end$' "$TMP/order.log" | head -1 | cut -d: -f1)"
[ "$(head -n "$((first_end - 1))" "$TMP/order.log" | grep -c ' start$')" = 5 ] ||
  fail "the aliases ran one after another: $(tr '\n' ' ' <"$TMP/order.log")"
# One missing image fails the step after all five finish, and names it.
reset
if FIXTURE_FAIL_IMAGE=mesh aliases; then fail 'a missing image was accepted'; fi
grep -Fq 'alias-release-images: failed: mesh' "$TMP/aliases.out" || fail "the failed image was not named: $(cat "$TMP/aliases.out")"
grep -Fq 'mesh is not published for this source' "$TMP/aliases.out" || fail "the failing image's output was hidden"
grep -q '^mesh_' "$TMP/output" && fail 'a failed image reported a candidate'
[ "$(grep -c ' end$' "$TMP/order.log")" = 5 ] || fail 'a failure stopped the other aliases mid-flight'
# Without REQUIRE_EXISTING_SOURCE_IMAGE=1 nothing runs: a release never builds.
reset
if CASE_REQUIRE='' aliases; then fail 'the aliases ran without requiring existing images'; fi
[ ! -e "$log" ] || fail 'an image ran without requiring its existing source image'

# --- finish-prod-release.sh ---------------------------------------------------------
finish() {
  env RUNNER_TEMP="$TMP" RELEASE_TAG=v1.2.3 SOURCE_SHA="$SHA" CODEWIRE_SOURCE_DIR=.release-source \
    CODEWIRE_IMAGE_REGISTRY=registry.example.invalid "$@" \
    "$tree/scripts/ci/release/finish-prod-release.sh" >"$TMP/finish.out" 2>&1
}
calls() { cut -d' ' -f1 "$log" | tr '\n' ' '; }
D1="sha256:$(printf '%064d' 11)"
D2="sha256:$(printf '%064d' 12)"
D3="sha256:$(printf '%064d' 13)"
D4="sha256:$(printf '%064d' 14)"
readonly D1 D2 D3 D4
# A reused pair: no digests, joined, published, mirrored, then delivered.
reset
finish BUILD_SUPPORT_PAIR=false || fail "a reused pair did not finish: $(cat "$TMP/finish.out")"
[ "$(calls)" = 'join-release-support-image.sh join-release-support-image.sh publish-image-to-harbor.sh publish-image-to-harbor.sh publish-image-to-ghcr.sh publish-image-to-ghcr.sh dispatch-deploy-prod.sh ' ] ||
  fail "a reused pair finished in another order: $(calls)"
grep -Fxq 'join base pair=false amd64= arm64=' "$TMP/joins.log" || fail 'a reused base was joined with digests'
grep -Fxq 'join workspace pair=false amd64= arm64=' "$TMP/joins.log" || fail 'a reused workspace was joined with digests'
grep -Fxq "publish-image-to-harbor.sh registry.example.invalid/codewire/workspace@sha256:$(printf '%064d' 2) registry.example.invalid/codewire/workspace $SHA v1.2.3" "$log" ||
  fail 'the workspace was published with other arguments'
grep -Fxq 'dispatch-deploy-prod.sh v1.2.3' "$log" || fail 'the release was not dispatched with its tag alone'
[ "$(cat "$TMP/provenance.log")" = "provenance base $SHA
provenance workspace $SHA" ] || fail "a pair built for the release was verified against another commit: $(cat "$TMP/provenance.log")"
# A pair main aliased from an earlier commit (#3504) is verified against the
# commit that built it, which the pair step proved has the same support inputs.
readonly ORIGIN=3333333333333333333333333333333333333333
reset
finish BUILD_SUPPORT_PAIR=false SUPPORT_PROVENANCE_REVISION="$ORIGIN" ||
  fail "an aliased pair did not finish: $(cat "$TMP/finish.out")"
[ "$(cat "$TMP/provenance.log")" = "provenance base $ORIGIN
provenance workspace $ORIGIN" ] || fail "an aliased pair was not verified against its building commit: $(cat "$TMP/provenance.log")"
grep -Fxq "publish-image-to-harbor.sh registry.example.invalid/codewire/base@sha256:$(printf '%064d' 2) registry.example.invalid/codewire/base $SHA v1.2.3" "$log" ||
  fail 'an aliased base was not published under the release source'
grep -Fxq 'dispatch-deploy-prod.sh v1.2.3' "$log" || fail 'an aliased pair was not delivered'
# A built pair: each image joined from exactly its two platform digests.
reset
finish BUILD_SUPPORT_PAIR=true BASE_AMD64_DIGEST="$D1" BASE_ARM64_DIGEST="$D2" \
  WORKSPACE_AMD64_DIGEST="$D3" WORKSPACE_ARM64_DIGEST="$D4" || fail "a built pair did not finish: $(cat "$TMP/finish.out")"
grep -Fxq "join base pair=true amd64=$D1 arm64=$D2" "$TMP/joins.log" || fail 'the base joined other digests'
grep -Fxq "join workspace pair=true amd64=$D3 arm64=$D4" "$TMP/joins.log" || fail 'the workspace joined other digests'
# A pair the release builds is its own: it never takes another commit's
# provenance, and a malformed commit is refused before anything runs.
for bad in "BUILD_SUPPORT_PAIR=true SUPPORT_PROVENANCE_REVISION=$ORIGIN BASE_AMD64_DIGEST=$D1 BASE_ARM64_DIGEST=$D2 WORKSPACE_AMD64_DIGEST=$D3 WORKSPACE_ARM64_DIGEST=$D4" \
    'BUILD_SUPPORT_PAIR=false SUPPORT_PROVENANCE_REVISION=3333'; do
  reset
  read -r -a bad_env <<<"$bad"
  if finish "${bad_env[@]}"; then fail "the finish accepted: $bad"; fi
  [ ! -e "$log" ] || fail "the finish ran something for: $bad"
done
grep -Fq 'SUPPORT_PROVENANCE_REVISION must be a full lowercase commit ID' "$TMP/finish.out" ||
  fail "a malformed provenance commit was not named: $(cat "$TMP/finish.out")"
# A GHCR mirror failure warns and still delivers; Harbor gates.
reset
FIXTURE_GHCR=fail finish BUILD_SUPPORT_PAIR=false || fail "a GHCR failure stopped the release: $(cat "$TMP/finish.out")"
grep -Fq 'GHCR mirror failed; Harbor holds the release' "$TMP/finish.out" || fail 'a GHCR failure was not warned'
grep -Fxq 'dispatch-deploy-prod.sh v1.2.3' "$log" || fail 'a GHCR failure stopped the delivery'
# A failed Harbor publication stops the release before it is delivered.
reset
if FIXTURE_HARBOR=fail finish BUILD_SUPPORT_PAIR=false; then fail 'a failed Harbor publication was delivered'; fi
grep -q 'dispatch-deploy-prod' "$log" && fail 'a failed Harbor publication was delivered'
# An index from another source is refused before anything is published.
reset
if FIXTURE_JOIN_SOURCE=2222222222222222222222222222222222222222 finish BUILD_SUPPORT_PAIR=false; then
  fail 'a support index from another source was published'
fi
grep -Fq 'the base index is from 2222222222222222222222222222222222222222' "$TMP/finish.out" ||
  fail "the source mismatch was not named: $(cat "$TMP/finish.out")"
grep -q 'publish-image-to-\|dispatch-deploy-prod' "$log" && fail 'a mismatched index was published or delivered'
# The pair mode is explicit.
reset
if finish BUILD_SUPPORT_PAIR=maybe; then fail 'an unknown pair mode was accepted'; fi
[ ! -e "$log" ] || fail 'an unknown pair mode ran anything'

echo 'deploy-prod helper fixtures: green'
