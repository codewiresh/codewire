#!/usr/bin/env bash
# shellcheck disable=SC2016 # Literal GitHub expression strings are test fixtures.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

# This isolated fixture owns the helpers started by its original nested tests.
# The existing kernel owner supplies Linux subreaper admission and initial ECHILD.
fixture_owner_marker='codewire.release-tag-fixture-owner/v1'
fixture_body_argument='--codewire-release-tag-fixture-body-v1'
if [[ ${CW_RELEASE_TAG_FIXTURE_OWNER+x} || ${CW_RELEASE_TAG_FIXTURE_OWNER_PID+x} ||
      ${CW_RELEASE_TAG_FIXTURE_OWNER_ARGC+x} ]]; then
  if [[ ${CW_RELEASE_TAG_FIXTURE_OWNER:-} != "$fixture_owner_marker" ||
        ${CW_RELEASE_TAG_FIXTURE_OWNER_PID:-} != "$PPID" ||
        ${CW_RELEASE_TAG_FIXTURE_OWNER_ARGC:-} != "$#" ||
        ${1:-} != "$fixture_body_argument" ||
        ${BASH_SOURCE[0]} != "$ROOT/scripts/ci/tests/test-verify-release-tag-ref.sh" ]]; then
    echo 'release tag fixture owner marker/argv is invalid' >&2
    exit 1
  fi
  shift
  unset CW_RELEASE_TAG_FIXTURE_OWNER CW_RELEASE_TAG_FIXTURE_OWNER_PID CW_RELEASE_TAG_FIXTURE_OWNER_ARGC
else
  if [[ ${1:-} == "$fixture_body_argument" ]]; then
    echo 'release tag fixture body requires its owning process' >&2
    exit 1
  fi
  exec python3 -I -B - "$ROOT" "$ROOT/scripts/ci/tests/test-verify-release-tag-ref.sh" "$@" <<'PY_OWNER'
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import time

root = Path(sys.argv[1]).resolve(strict=True)
script = root / "scripts/ci/tests/test-verify-release-tag-ref.sh"
if Path(sys.argv[2]).resolve(strict=True) != script:
    raise SystemExit("release tag fixture script identity is wrong")
spec = importlib.util.spec_from_file_location(
    "release_tag_fixture_custody", root / "scripts/ci/verify/build-linux-vmm-kernel.py")
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
owner.arm_custody()

environment = dict(os.environ)
environment.update({"CW_RELEASE_TAG_FIXTURE_OWNER": "codewire.release-tag-fixture-owner/v1",
                    "CW_RELEASE_TAG_FIXTURE_OWNER_PID": str(os.getpid()),
                    "CW_RELEASE_TAG_FIXTURE_OWNER_ARGC": str(len(sys.argv[3:]) + 1)})
body = subprocess.Popen(["/bin/bash", str(script), "--codewire-release-tag-fixture-body-v1",
                         *sys.argv[3:]], env=environment)
status = body.wait()  # Preserve the original body's direct-child wait and exit.

# Original traps, nested direct waits and Signer.close have all finished.
# Reap only this isolated owner's adopted helpers; no cleanup signals are sent.
deadline = time.monotonic() + 5
try:
    while True:
        if time.monotonic() >= deadline:
            raise RuntimeError("release tag fixture cleanup did not reach ECHILD")
        try:
            reaped, _ = os.waitpid(-1, os.WNOHANG | owner.WALL)
        except ChildProcessError:
            break
        except InterruptedError:
            continue
        if not reaped:
            time.sleep(0.01)
except (OSError, RuntimeError) as error:
    print(str(error), file=sys.stderr)
    raise SystemExit(status if status > 0 else 1)

if status < 0:
    print(f"release tag fixture body terminated by signal {-status}", file=sys.stderr)
if status == 0:
    print("release tag dispatch guard tests: OK", flush=True)
# Preserve normal exits; a signaled child remains an explicit shell-style refusal.
raise SystemExit(status if status >= 0 else 128 - status)
PY_OWNER
fi
unset fixture_owner_marker fixture_body_argument
VERIFY="$ROOT/scripts/ci/release/verify-release-tag-ref.sh"
COMPUTE_TAGS="$ROOT/scripts/ci/images/compute-image-tags.sh"

fixture="$(mktemp -d)"
cleanup() {
  rm -rf "$fixture"
}
trap cleanup EXIT

# Forgejo decides whether a release tag's signature belongs to a key on the
# tagger's account. The synthetic API below answers from the fixture's real tag
# objects; FAKE_TAG_API_MODE selects the response under test.
fake_curl="$fixture/fake-curl"
cat >"$fake_curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_CURL_ARGV_LOG"
config='' output='' url=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) config="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    --proto|--connect-timeout|--max-time|--write-out) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
grep -Fqx "header = \"Authorization: token ${FAKE_EXPECTED_TOKEN}\"" "$config" || exit 99
[[ "$url" =~ ^https://(git\.example\.invalid|forgejo-system-cluster\.private\.invalid)/api/v1/repos/codewire/codewire/git/tags/([0-9a-f]{40})$ ]] || exit 98
object="${BASH_REMATCH[2]}"
name="$(git cat-file tag "$object" | awk '$1 == "tag" { print $2; exit }')"
commit="$(git cat-file tag "$object" | awk '$1 == "object" { print $2; exit }')"
record() {
  jq -cn --arg tag "$name" --arg sha "$1" --arg commit "$commit" --argjson verified "$2" \
    '{tag: $tag, sha: $sha, object: {type: "commit", sha: $commit},
      verification: {verified: $verified, reason: "", signer: {username: "release-guard"}}}'
}
case "${FAKE_TAG_API_MODE:-verified}" in
  verified) record "$object" true >"$output"; printf 200 ;;
  unverified) record "$object" false >"$output"; printf 200 ;;
  sha-mismatch) record "$(printf '0%.0s' {1..40})" true >"$output"; printf 200 ;;
  malformed) printf 'not json' >"$output"; printf 200 ;;
  not-found) printf '{"message":"not found"}' >"$output"; printf 404 ;;
  server-error) printf '{"message":"boom"}' >"$output"; printf 500 ;;
  transport) exit 7 ;;
  *) exit 97 ;;
esac
SH
chmod 0755 "$fake_curl"
token_canary='forgejo-release-token-canary-7d1f'
export CODEWIRE_RELEASE_TAG_TEST_MODE=1
export CODEWIRE_RELEASE_TAG_CURL="$fake_curl"
export FAKE_CURL_ARGV_LOG="$fixture/curl-argv.log"
export FAKE_EXPECTED_TOKEN="$token_canary"
export GITEA_TOKEN="$token_canary"

git -C "$fixture" init -q
git -C "$fixture" config user.name 'Release Guard Test'
git -C "$fixture" config user.email release-guard@example.invalid
git -C "$fixture" config commit.gpgsign false
# Signature trust comes from Forgejo; the fixture tags stay unsigned so host
# signing defaults cannot change them.
git -C "$fixture" config tag.gpgSign false
git -C "$fixture" commit -q --allow-empty -m base
git -C "$fixture" branch -M main
git -C "$fixture" commit -q --allow-empty -m release
source_sha="$(git -C "$fixture" rev-parse HEAD)"
canonical_main_sha="$source_sha"
git -C "$fixture" tag -a v0.3.359 -m v0.3.359
tag_object_sha="$(git -C "$fixture" rev-parse v0.3.359)"

git -C "$fixture" switch -q -c unmerged HEAD~1
git -C "$fixture" commit -q --allow-empty -m unmerged
unmerged_sha="$(git -C "$fixture" rev-parse HEAD)"
git -C "$fixture" tag -a v0.3.360 -m v0.3.360
unmerged_tag_object="$(git -C "$fixture" rev-parse v0.3.360)"
git -C "$fixture" switch -q main

git -C "$fixture" tag -a v0.3.362 -m v0.3.362
embedded_name_tag_object="$(git -C "$fixture" rev-parse v0.3.362)"
git -C "$fixture" update-ref refs/tags/v0.3.363 "$embedded_name_tag_object"

run_verify() {
  (cd "$fixture" && "$VERIFY" "$@")
}

expect_failure() {
  local name="$1"
  shift
  if run_verify "$@" >/dev/null 2>&1; then
    printf 'release tag guard test failed: %s unexpectedly passed\n' "$name" >&2
    exit 1
  fi
}

verified_output="$(run_verify \
  push refs/tags/v0.3.359 v0.3.359 '' \
  https://git.example.invalid codewire/codewire \
  "$source_sha" "$tag_object_sha" "$source_sha" "$canonical_main_sha" 2>&1)"
grep -Fq "release tag verified: tag=v0.3.359 commit=$source_sha forgejo_signer=release-guard" \
  <<<"$verified_output"

run_verify \
  workflow_dispatch refs/heads/main main v0.3.359 \
  https://git.example.invalid/ codewire/codewire \
  "$source_sha" "$tag_object_sha" "$source_sha" "$canonical_main_sha" >/dev/null

# Runners register against the same instance's internal Tailnet name.
run_verify \
  workflow_dispatch refs/heads/main main v0.3.359 \
  https://forgejo.example.invalid codewire/codewire \
  "$source_sha" "$tag_object_sha" "$source_sha" "$canonical_main_sha" >/dev/null

# Forgejo's verdict is required; every other response fails closed.
for mode in unverified sha-mismatch malformed not-found server-error transport; do
  if FAKE_TAG_API_MODE="$mode" run_verify \
      workflow_dispatch refs/heads/main main v0.3.359 \
      https://git.example.invalid codewire/codewire \
      "$source_sha" "$tag_object_sha" "$source_sha" "$canonical_main_sha" >/dev/null 2>&1; then
    printf 'release tag guard test failed: Forgejo %s response was accepted\n' "$mode" >&2
    exit 1
  fi
done
if (unset GITEA_TOKEN; run_verify \
    workflow_dispatch refs/heads/main main v0.3.359 \
    https://git.example.invalid codewire/codewire \
    "$source_sha" "$tag_object_sha" "$source_sha" "$canonical_main_sha") >/dev/null 2>&1; then
  echo 'release tag guard test failed: verification ran without a Forgejo token' >&2
  exit 1
fi
if (unset CODEWIRE_RELEASE_TAG_TEST_MODE; run_verify \
    workflow_dispatch refs/heads/main main v0.3.359 \
    https://git.example.invalid codewire/codewire \
    "$source_sha" "$tag_object_sha" "$source_sha" "$canonical_main_sha") >/dev/null 2>&1; then
  echo 'release tag guard test failed: HTTP client override accepted outside test mode' >&2
  exit 1
fi
# The token reaches only a private curl config, never arguments or output.
all_output="$(for mode in verified unverified not-found; do
  FAKE_TAG_API_MODE="$mode" run_verify \
    workflow_dispatch refs/heads/main main v0.3.359 \
    https://git.example.invalid codewire/codewire \
    "$source_sha" "$tag_object_sha" "$source_sha" "$canonical_main_sha" 2>&1 || true
done)"
if grep -Fq "$token_canary" <<<"$all_output" || grep -Fq "$token_canary" "$FAKE_CURL_ARGV_LOG"; then
  echo 'release tag guard test failed: Forgejo token leaked into output or arguments' >&2
  exit 1
fi

expect_failure unmerged-tag-source \
  workflow_dispatch refs/heads/main main v0.3.360 \
  https://git.example.invalid codewire/codewire \
  "$unmerged_sha" "$unmerged_tag_object" "$unmerged_sha" "$canonical_main_sha"
expect_failure branch-recovery-dispatch \
  workflow_dispatch refs/heads/feature feature v0.3.359 \
  https://git.example.invalid codewire/codewire \
  "$source_sha" "$tag_object_sha" "$source_sha" "$canonical_main_sha"
expect_failure missing-recovery-tag \
  workflow_dispatch refs/heads/main main '' \
  https://git.example.invalid codewire/codewire \
  "$source_sha" "$tag_object_sha" "$source_sha" "$canonical_main_sha"
expect_failure non-semver-recovery-tag \
  workflow_dispatch refs/heads/main main v0.3.359-rc1 \
  https://git.example.invalid codewire/codewire \
  "$source_sha" "$tag_object_sha" "$source_sha" "$canonical_main_sha"
expect_failure recovery-input-on-push \
  push refs/tags/v0.3.359 v0.3.359 v0.3.359 \
  https://git.example.invalid codewire/codewire \
  "$source_sha" "$tag_object_sha" "$source_sha" "$canonical_main_sha"
expect_failure branch-push \
  push refs/heads/main main '' \
  https://git.example.invalid codewire/codewire \
  "$source_sha" "$tag_object_sha" "$source_sha" "$canonical_main_sha"
expect_failure mismatched-push-ref-name \
  push refs/tags/v0.3.359 v0.3.358 '' \
  https://git.example.invalid codewire/codewire \
  "$source_sha" "$tag_object_sha" "$source_sha" "$canonical_main_sha"
expect_failure lookalike-internal-server \
  workflow_dispatch refs/heads/main main v0.3.359 \
  https://forgejo.example.invalid.evil.example codewire/codewire \
  "$source_sha" "$tag_object_sha" "$source_sha" "$canonical_main_sha"
expect_failure wrong-server \
  workflow_dispatch refs/heads/main main v0.3.359 \
  https://github.com codewire/codewire \
  "$source_sha" "$tag_object_sha" "$source_sha" "$canonical_main_sha"
expect_failure wrong-repository \
  workflow_dispatch refs/heads/main main v0.3.359 \
  https://git.example.invalid codewire/other \
  "$source_sha" "$tag_object_sha" "$source_sha" "$canonical_main_sha"
expect_failure missing-canonical-tag \
  workflow_dispatch refs/heads/main main v0.3.359 \
  https://git.example.invalid codewire/codewire \
  "$source_sha" '' '' "$canonical_main_sha"
expect_failure lightweight-tag \
  workflow_dispatch refs/heads/main main v0.3.359 \
  https://git.example.invalid codewire/codewire \
  "$source_sha" "$source_sha" '' "$canonical_main_sha"
expect_failure non-distinct-tag-object \
  workflow_dispatch refs/heads/main main v0.3.359 \
  https://git.example.invalid codewire/codewire \
  "$source_sha" "$source_sha" "$source_sha" "$canonical_main_sha"
expect_failure mismatched-peeled-commit \
  workflow_dispatch refs/heads/main main v0.3.359 \
  https://git.example.invalid codewire/codewire \
  "$source_sha" "$tag_object_sha" "$unmerged_sha" "$canonical_main_sha"
expect_failure invalid-source \
  workflow_dispatch refs/heads/main main v0.3.359 \
  https://git.example.invalid codewire/codewire \
  not-a-sha "$tag_object_sha" "$source_sha" "$canonical_main_sha"
expect_failure unavailable-main \
  workflow_dispatch refs/heads/main main v0.3.359 \
  https://git.example.invalid codewire/codewire \
  "$source_sha" "$tag_object_sha" "$source_sha" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
expect_failure unsupported-event \
  pull_request refs/pull/1/head main v0.3.359 \
  https://git.example.invalid codewire/codewire \
  "$source_sha" "$tag_object_sha" "$source_sha" "$canonical_main_sha"
expect_failure mismatched-signed-tag-name \
  workflow_dispatch refs/heads/main main v0.3.363 \
  https://git.example.invalid codewire/codewire \
  "$source_sha" "$embedded_name_tag_object" "$source_sha" "$canonical_main_sha"

mapfile -t recovery_tags < <(
  "$COMPUTE_TAGS" registry.example.invalid/codewire services "$source_sha" v0.3.359 \
    refs/heads/main main
)
[[ "${recovery_tags[*]}" == \
  "registry.example.invalid/codewire/services:${source_sha} registry.example.invalid/codewire/services:v0.3.359" ]]

mapfile -t push_tags < <(
  "$COMPUTE_TAGS" registry.example.invalid/codewire services "$source_sha" v0.3.359 \
    refs/tags/v0.3.359 v0.3.359
)
[[ "${push_tags[*]}" == \
  "registry.example.invalid/codewire/services:${source_sha} registry.example.invalid/codewire/services:v0.3.359" ]]

mapfile -t dev_tags < <(
  "$COMPUTE_TAGS" registry.example.invalid/codewire services "$source_sha" '' \
    refs/heads/main main
)
[[ "${dev_tags[*]}" == \
  "registry.example.invalid/codewire/services:${source_sha}" ]]

mapfile -t direct_tag_tags < <(
  "$COMPUTE_TAGS" registry.example.invalid/codewire services "$source_sha" '' \
    refs/tags/v0.3.359 v0.3.359
)
[[ "${direct_tag_tags[*]}" == \
  "registry.example.invalid/codewire/services:${source_sha} registry.example.invalid/codewire/services:v0.3.359" ]]

deploy_workflow="$ROOT/.gitea/workflows/deploy-prod.yaml"
cli_workflow="$ROOT/.gitea/workflows/cli-release.yaml"
image_builder="$ROOT/scripts/ci/images/build-push-image.sh"
signing_key_test="$ROOT/scripts/ci/tests/test-verify-cw-release-signing-key.sh"
installer_test="$ROOT/scripts/ci/tests/test-cw-install.py"
publish_release_test="$ROOT/scripts/ci/tests/test-publish-cw-release.sh"
installer="$ROOT/apps/cli/install.sh"
cli_readme="$ROOT/apps/cli/README.md"
release_public_key="$ROOT/apps/cli/GPG_PUBLIC_KEY.asc"
package_script="$ROOT/scripts/ci/release/package-cw-release.sh"
sign_script="$ROOT/scripts/ci/release/sign-cw-release.sh"

grep -Fq '  workflow_dispatch:' "$deploy_workflow"
grep -Fq '  release-selection:' "$deploy_workflow"
for workflow in "$deploy_workflow" "$cli_workflow"; do
  sed -n '/- name: Select exact canonical release source/,/scripts\/ci\/release\/verify-release-tag-ref\.sh/p' \
    "$workflow" | grep -Fq '          GITEA_TOKEN: ${{ github.token }}' || {
    printf '%s does not pass the Forgejo token to release tag verification\n' "$workflow" >&2
    exit 1
  }
done
grep -Fq "[ \"\$GITHUB_REF\" = 'refs/heads/main' ]" "$deploy_workflow"
grep -Fq '          path: .release-source' "$deploy_workflow"
grep -Fq '+refs/heads/main:refs/remotes/origin/main' "$deploy_workflow"
if grep -Fq '.release-control' "$deploy_workflow"; then
  echo 'deploy workflow must not load recovery control from the selected tag' >&2
  exit 1
fi
[[ "$(grep -Fc '    needs: [release-selection]' "$deploy_workflow")" -eq 6 ]]
if grep -Eq 'build-(base|workspace)-support-image' "$deploy_workflow"; then
  echo 'production support publication still crosses a runner job-output boundary' >&2
  exit 1
fi
# shellcheck disable=SC2016
grep -Fq 'CODEWIRE_BASE_IMAGE_REF: ${{ steps.base.outputs.candidate_ref }}' \
  "$deploy_workflow"
[[ "$(grep -Fc '          ref: refs/tags/${{ needs.release-selection.outputs.release_tag }}' "$deploy_workflow")" -eq 7 ]]
[[ "$(grep -Fc '          CODEWIRE_RELEASE_TAG: ${{ needs.release-selection.outputs.release_tag }}' "$deploy_workflow")" -eq 7 ]]
[[ "$(grep -Fc '          CODEWIRE_SOURCE_SHA: ${{ needs.release-selection.outputs.source_sha }}' "$deploy_workflow")" -eq 7 ]]
[[ "$(grep -Fc '          CODEWIRE_SOURCE_DIR: .release-source' "$deploy_workflow")" -eq 7 ]]
[[ "$(grep -Fc "          REQUIRE_EXISTING_SOURCE_IMAGE: '1'" "$deploy_workflow")" -eq 5 ]]
if grep -Fq 'CODEWIRE_PUBLISH_LATEST' "$deploy_workflow"; then
  echo 'production image workflow still publishes a moving latest alias' >&2
  exit 1
fi
[[ "$(grep -Fc '        run: scripts/ci/images/build-push-image.sh' "$deploy_workflow")" -eq 7 ]]
[[ "$(grep -Fc 'Dockerfile .release-source' "$deploy_workflow")" -eq 7 ]]
grep -Fq '  publish-runtime-images:' "$deploy_workflow"
grep -Fq 'scripts/ci/images/image-bundle.py create' "$deploy_workflow"
grep -Fq -- '--environment prod' "$deploy_workflow"
# shellcheck disable=SC2016
grep -Fq -- '--source-sha "$SOURCE_SHA"' "$deploy_workflow"
[[ "$(grep -Fc 'scripts/ci/images/publish-image-to-ghcr.sh' "$deploy_workflow")" -eq 7 ]]
grep -Fq '  publish-support-release-images:' "$deploy_workflow"
grep -Fq '      - publish-support-release-images' "$deploy_workflow"
grep -Fq '  dispatch-deploy-prod:' "$deploy_workflow"
# shellcheck disable=SC2016
grep -Fq 'run: scripts/ci/deploy/dispatch-deploy-prod.sh "$RELEASE_TAG"' "$deploy_workflow"
if grep -Fq 'CODEWIRE_DEPLOY_PROMOTION_TOKEN' "$deploy_workflow"; then
  echo 'production dispatch retains the static deploy credential' >&2
  exit 1
fi
grep -Fq '    runs-on: ci-protected' \
  <(sed -n '/^  dispatch-deploy-prod:/,$p' "$deploy_workflow")
if grep -Eq 'CODEWIRE_DEPLOY_PROMOTION_USERNAME|promote-image-bundle|promote \.release-source|promotion-receipt|observe-production:|deploy-prod-observer\.sh|gitea-(upload|download)-artifact|kubectl|helm' \
  "$deploy_workflow"; then
  echo 'production workflow still contains direct deploy writes, receipt transport, or observation' >&2
  exit 1
fi

grep -Fq '  workflow_dispatch:' "$cli_workflow"
if grep -Fq "    tags: ['v*']" "$cli_workflow"; then
  echo 'CLI publication still grants release behavior to tag-owned workflow code' >&2
  exit 1
fi
grep -Fq '    enable-openid-connect: true' "$cli_workflow"
if grep -q '^enable-openid-connect:' "$cli_workflow"; then
  echo 'CLI release exposes Forgejo OIDC to the compilation job' >&2
  exit 1
fi
grep -Fq '  OPENBAO_GITHUB_ROLE: codewire-source-cli-github-mirror' "$cli_workflow"
grep -Fq '  OPENBAO_GITHUB_AUDIENCE: openbao-codewire-source-cli-github-mirror' "$cli_workflow"
grep -Fq '  release-selection:' "$cli_workflow"
grep -Fq '  build-release:' "$cli_workflow"
grep -Fq '  package-release:' "$cli_workflow"
grep -Fq '    needs: [release-selection]' "$cli_workflow"
grep -Fq '    needs: [release-selection, pack-runtime, build-release]' "$cli_workflow"
grep -Fq "[ \"\$GITHUB_REF\" = 'refs/heads/main' ]" "$cli_workflow"
grep -Fq '          path: .release-source' "$cli_workflow"
grep -Fq '+refs/heads/main:refs/remotes/origin/main' "$cli_workflow"
grep -Fq '          ref: refs/tags/${{ needs.release-selection.outputs.release_tag }}' "$cli_workflow"
grep -Fq '        working-directory: .release-source' "$cli_workflow"
grep -Fq '../scripts/ci/release/verify-cw-release-signing-key.sh apps/cli/GPG_PUBLIC_KEY.asc' "$cli_workflow"
grep -Fq '        run: scripts/ci/setup/assert-ci-runner-image.sh' "$cli_workflow"
grep -Fq '../scripts/ci/release/package-cw-release.sh "$RELEASE_TAG"' "$cli_workflow"
grep -Fq '../scripts/ci/release/sign-cw-release.sh dist/cw-release' "$cli_workflow"
grep -Fq '../scripts/ci/release/publish-cw-release.sh "$RELEASE_TAG" dist/cw-release' "$cli_workflow"
grep -Fq 'CW_RELEASE_TAG_OBJECT_SHA: ${{ needs.release-selection.outputs.tag_object_sha }}' "$cli_workflow"
if grep -Fq '.release-control' "$cli_workflow"; then
  echo 'CLI workflow must not load recovery control from the selected tag' >&2
  exit 1
fi
grep -Fq '          CW_RELEASE_SOURCE_SHA: ${{ needs.release-selection.outputs.source_sha }}' "$cli_workflow"
build_release="$(sed -n '/^  build-release:/,/^  package-release:/p' "$cli_workflow")"
package_release="$(sed -n '/^  package-release:/,$p' "$cli_workflow")"
assert_release_publication_boundary() {
  local workflow="$1"
  local publish_step
  publish_step="$(awk '
    /^      - name: Publish signed release assets$/ { in_step = 1 }
    in_step && /^      - / && $0 !~ /^      - name: Publish signed release assets$/ { exit }
    in_step { print }
  ' "$workflow")"

  grep -Fq '          gpg --verify dist/cw-release/SHA256SUMS.asc dist/cw-release/SHA256SUMS' <<<"$publish_step" || return 1
  grep -Fq '          GITEA_TOKEN: ${{ github.token }}' <<<"$publish_step" || return 1
  grep -Fq '../scripts/ci/setup/fetch-openbao-github-mirror-credentials.sh' <<<"$publish_step" || return 1
  grep -Fq '../scripts/ci/release/mint-github-app-token.sh' <<<"$publish_step" || return 1
  grep -Fq '          export GH_MIRROR_TOKEN_FILE="$github_work/token"' <<<"$publish_step" || return 1
  if grep -Eq 'MIRROR_GITHUB_(APP_ID|INSTALLATION_ID|PRIVATE_KEY).*secrets\.' <<<"$publish_step"; then
    echo 'CLI release still reads the retired Forgejo GitHub App secret tuple' >&2
    return 1
  fi
  grep -Fq "          CW_REQUIRE_GITHUB_MIRROR: '1'" <<<"$publish_step" || return 1
  grep -Fq '          CW_RELEASE_SOURCE_SHA: ${{ needs.release-selection.outputs.source_sha }}' <<<"$publish_step" || return 1
  grep -Fq '          CW_RELEASE_TAG_OBJECT_SHA: ${{ needs.release-selection.outputs.tag_object_sha }}' <<<"$publish_step" || return 1
  grep -Fq '          ../scripts/ci/release/publish-cw-release.sh "$RELEASE_TAG" dist/cw-release' <<<"$publish_step" || return 1
  if grep -Eq "node <<'NODE'|api\.github\.com/app/installations/|mirror_token=|token_json=" <<<"$publish_step"; then
    echo 'CLI release workflow still implements GitHub publication instead of invoking the publication script' >&2
    return 1
  fi
  if ! awk '
    /^      - name: Publish signed release assets$/ { in_step = 1 }
    in_step && /^      - / && $0 !~ /^      - name: Publish signed release assets$/ { exit }
    in_step && /\.\.\/scripts\/ci\/release\/publish-cw-release\.sh "\$RELEASE_TAG" dist\/cw-release/ { seen = 1; next }
    seen && /^[[:space:]]*$/ { next }
    seen && /^          / { trailing_command = 1; exit }
    END { exit (seen && !trailing_command) ? 0 : 1 }
  ' "$workflow"; then
    echo 'CLI release workflow performs work after publication inside the publication boundary' >&2
    return 1
  fi
  if grep -Fq '      - name: Publish release assets' "$workflow"; then
    echo 'CLI release workflow leaves publication outside the publication boundary' >&2
    return 1
  fi
  return 0
}

assert_release_publication_boundary "$cli_workflow"
package_only_workflow="$fixture/package-only-cli-release.yaml"
sed '/publish-cw-release\.sh/d' "$cli_workflow" >"$package_only_workflow"
if assert_release_publication_boundary "$package_only_workflow"; then
  echo 'CLI release workflow fixture accepted packaging without publication' >&2
  exit 1
fi
trailing_publication_workflow="$fixture/trailing-publication-cli-release.yaml"
sed '/publish-cw-release\.sh "\$RELEASE_TAG" dist\/cw-release/a\
          echo unexpected-after-publication' "$cli_workflow" >"$trailing_publication_workflow"
if assert_release_publication_boundary "$trailing_publication_workflow" >/dev/null 2>&1; then
  echo 'CLI release workflow fixture accepted work after publication' >&2
  exit 1
fi

# The signing key is read from OpenBao only inside the signing step, after a
# successful credential-free build. No step receives a Forgejo Actions secret,
# and compilation never receives signing material.
sign_step="$(sed -n '/- name: Sign release delivery/,/- name: /p' <<<"$package_release")"
grep -Fq '../scripts/ci/setup/fetch-openbao-release-signing-key.sh "$signing_work/key"' <<<"$sign_step" || {
  echo 'CLI release signing does not read its key from OpenBao' >&2
  exit 1
}
key_readers="$(grep -c 'fetch-openbao-release-signing-key\.sh' "$cli_workflow" || true)"
[ "$key_readers" -eq 1 ] || {
  echo 'CLI release workflow reads the signing key outside the signing step' >&2
  exit 1
}
if grep -Fq 'secrets.' "$cli_workflow"; then
  echo 'CLI release workflow reads a Forgejo Actions secret' >&2
  exit 1
fi
for name in \
  CW_RELEASE_GPG_PRIVATE_KEY \
  CW_RELEASE_GPG_PASSPHRASE \
  CW_RELEASE_GPG_KEY_ID \
  fetch-openbao-release-signing-key \
  fetch-openbao-macos-signing; do
  if grep -Fq "$name" <<<"$build_release"; then
    printf 'CLI compilation receives %s\n' "$name" >&2
    exit 1
  fi
done

"$signing_key_test"
python3 -B "$installer_test" >/dev/null 2>&1 || {
  echo 'public installer tests failed' >&2
  exit 1
}
"$publish_release_test"
python3 -B "$ROOT/scripts/ci/tests/test-cli-release-workflow.py"
python3 -B "$ROOT/scripts/ci/tests/test-cw-release-delivery.py" >/dev/null 2>&1 || {
  echo 'cw release delivery tests failed' >&2
  exit 1
}
python3 -B "$ROOT/scripts/ci/tests/test-cw-release-r2.py" >/dev/null 2>&1 || {
  echo 'cw release R2 publisher tests failed' >&2
  exit 1
}
python3 -B "$ROOT/scripts/ci/tests/test-package-cw-release.py" >/dev/null 2>&1 || {
  echo 'cw release packaging tests failed' >&2
  exit 1
}
python3 -B "$ROOT/scripts/ci/tests/test-local-runtime-parts.py" >/dev/null 2>&1 || {
  echo 'local runtime parts and source pin tests failed' >&2
  exit 1
}
"$ROOT/scripts/ci/tests/test-dry-run-superseded.sh" >/dev/null
"$ROOT/scripts/ci/tests/test-fetch-openbao-releases-r2-credentials.sh"
"$ROOT/scripts/ci/tests/test-fetch-openbao-release-signing-key.sh"
"$ROOT/scripts/ci/tests/test-fetch-openbao-macos-signing.sh"
"$ROOT/scripts/ci/tests/test-sign-macos-cw.sh"
"$ROOT/scripts/ci/tests/test-sign-macos-helper.sh"

compiled_fingerprint="$(
  sed -n 's/^const TRUST_FINGERPRINT: &str = "\([0-9A-F]*\)";$/\1/p' \
    "$ROOT/crates/codewire-cli/src/public_fetch.rs"
)"
public_key_fingerprint="$(
  gpg --batch --show-keys --with-colons "$release_public_key" 2>/dev/null |
    awk -F: '$1 == "fpr" { print $10; exit }'
)"
[ -n "$compiled_fingerprint" ] && [ "$compiled_fingerprint" = "$public_key_fingerprint" ] || {
  echo 'cw compiled release fingerprint does not match the checked-in release key' >&2
  exit 1
}
# The first install trusts HTTPS to the release origin and SHA256SUMS; the
# installer proof above covers its refusals. cw verifies every update.
grep -Fq "ORIGIN='https://releases.codewire.sh/'" "$installer"
if grep -Eq 'https://(api\.)?github\.com|raw\.githubusercontent\.com' "$installer"; then
  echo 'installer still downloads release assets or trust from GitHub' >&2
  exit 1
fi
grep -Fq 'gpg --import apps/cli/GPG_PUBLIC_KEY.asc' "$cli_readme"
grep -Fq -- '--passphrase-fd 0' "$sign_script"
if grep -Fq -- '--passphrase "$CW_RELEASE_GPG_PASSPHRASE"' "$sign_script"; then
  echo 'release signer exposes the passphrase through process arguments' >&2
  exit 1
fi
if grep -Fq 'CW_RELEASE_GPG' "$package_script" &&
  ! grep -Fq 'must not reach release compilation' "$package_script"; then
  echo 'release packager handles signing material' >&2
  exit 1
fi

grep -Fq 'source_sha="${CODEWIRE_SOURCE_SHA:-${GITHUB_SHA:-}}"' "$image_builder"
grep -Fq 'release_tag="${CODEWIRE_RELEASE_TAG:-}"' "$image_builder"
grep -Fq 'tags_output="$(' "$image_builder"
if grep -Fq 'latest' "$COMPUTE_TAGS" || grep -Fq 'CODEWIRE_PUBLISH_LATEST' "$image_builder"; then
  echo 'image publication still contains a moving latest-tag control' >&2
  exit 1
fi
if grep -Fq ':main-' "$COMPUTE_TAGS"; then
  echo 'image tag computation still emits policy-visible ordinary-main tags' >&2
  exit 1
fi
if grep -Fq 'date +%s' "$image_builder"; then
  echo 'image builder still constructs epoch-based ordinary-main tags' >&2
  exit 1
fi
grep -Fq 'source_dir="${CODEWIRE_SOURCE_DIR:-.}"' "$image_builder"
grep -Fq '    DOCKER_CONFIG="$docker_config"' "$image_builder"
grep -Fq '    image_command=(docker buildx build --builder "$buildx_builder" --progress plain' \
  "$image_builder"
grep -Fq '    output_args=(--push --tag "$source_tag")' "$image_builder"
grep -Fq -- '--provenance="$provenance"' "$image_builder"
grep -Fq -- '--metadata-file "$build_metadata"' "$image_builder"
grep -Fq '"$credential_fetcher" "$registry_username_file" "$registry_password_file"' \
  "$image_builder"
grep -Fq "readonly REGISTRY_HOST='registry.example.invalid'" \
  "$image_builder"
if grep -Fq 'GITEA_REGISTRY_TOKEN' "$image_builder"; then
  echo 'image builder still accepts a direct registry token' >&2
  exit 1
fi
grep -Fq 'python3 scripts/ci/images/image-bundle.py candidate' "$image_builder"
grep -Fq 'git -C "$source_dir" rev-parse HEAD' "$image_builder"
grep -Fq 'checkout $checked_out_sha does not match selected source $source_sha' "$image_builder"

if [[ -e "$ROOT/keys/production-release.asc" ]]; then
  echo 'release tags are trusted through Forgejo; no pinned production key file may remain' >&2
  exit 1
fi

