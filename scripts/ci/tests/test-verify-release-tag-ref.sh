#!/usr/bin/env bash
# shellcheck disable=SC2016 # Literal GitHub expression strings are test fixtures.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VERIFY="$ROOT/scripts/ci/release/verify-release-tag-ref.sh"
COMPUTE_TAGS="$ROOT/scripts/ci/images/compute-image-tags.sh"

fixture="$(mktemp -d)"
cleanup() {
  rm -rf "$fixture"
}
trap cleanup EXIT

signer_home="$fixture/signer"
wrong_signer_home="$fixture/wrong-signer"
mkdir -m 0700 "$signer_home" "$wrong_signer_home"
GNUPGHOME="$signer_home" gpg --batch --passphrase '' \
  --quick-generate-key 'Release Guard Test <release-guard@example.invalid>' \
  rsa2048 sign 0 >/dev/null 2>&1
signing_fingerprint="$(GNUPGHOME="$signer_home" gpg --batch --with-colons --list-secret-keys |
  awk -F: '$1 == "fpr" { print $10; exit }')"
GNUPGHOME="$signer_home" gpg --batch --armor --export "$signing_fingerprint" \
  >"$fixture/release-tag-public.asc"
GNUPGHOME="$wrong_signer_home" gpg --batch --passphrase '' \
  --quick-generate-key 'Wrong Release Guard <wrong@example.invalid>' \
  rsa2048 sign 0 >/dev/null 2>&1
wrong_signing_fingerprint="$(GNUPGHOME="$wrong_signer_home" gpg --batch --with-colons --list-secret-keys |
  awk -F: '$1 == "fpr" { print $10; exit }')"
export CODEWIRE_RELEASE_TAG_TEST_MODE=1
export CODEWIRE_RELEASE_TAG_PUBLIC_KEY="$fixture/release-tag-public.asc"
export CODEWIRE_RELEASE_TAG_SIGNING_FINGERPRINT="$signing_fingerprint"

git -C "$fixture" init -q
git -C "$fixture" config user.name 'Release Guard Test'
git -C "$fixture" config user.email release-guard@example.invalid
git -C "$fixture" config commit.gpgsign false
git -C "$fixture" commit -q --allow-empty -m base
git -C "$fixture" branch -M main
git -C "$fixture" commit -q --allow-empty -m release
source_sha="$(git -C "$fixture" rev-parse HEAD)"
canonical_main_sha="$source_sha"
GNUPGHOME="$signer_home" git -C "$fixture" \
  -c gpg.format=openpgp -c gpg.program=gpg \
  tag -s -u "$signing_fingerprint" \
  v0.3.359 -m v0.3.359
tag_object_sha="$(git -C "$fixture" rev-parse v0.3.359)"

git -C "$fixture" switch -q -c unmerged HEAD~1
git -C "$fixture" commit -q --allow-empty -m unmerged
unmerged_sha="$(git -C "$fixture" rev-parse HEAD)"
GNUPGHOME="$signer_home" git -C "$fixture" \
  -c gpg.format=openpgp -c gpg.program=gpg \
  tag -s -u "$signing_fingerprint" \
  v0.3.360 -m v0.3.360
unmerged_tag_object="$(git -C "$fixture" rev-parse v0.3.360)"
git -C "$fixture" switch -q main

GNUPGHOME="$wrong_signer_home" git -C "$fixture" \
  -c gpg.format=openpgp -c gpg.program=gpg tag -s \
  -u "$wrong_signing_fingerprint" v0.3.361 -m v0.3.361
wrong_signer_tag_object="$(git -C "$fixture" rev-parse v0.3.361)"
GNUPGHOME="$signer_home" git -C "$fixture" \
  -c gpg.format=openpgp -c gpg.program=gpg \
  tag -s -u "$signing_fingerprint" \
  v0.3.362 -m v0.3.362
embedded_name_tag_object="$(git -C "$fixture" rev-parse v0.3.362)"
git -C "$fixture" update-ref refs/tags/v0.3.363 "$embedded_name_tag_object"
git -C "$fixture" tag -a v0.3.364 -m v0.3.364
unsigned_tag_object="$(git -C "$fixture" rev-parse v0.3.364)"

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

run_verify \
  push refs/tags/v0.3.359 v0.3.359 '' \
  https://git.example.invalid codewire/codewire \
  "$source_sha" "$tag_object_sha" "$source_sha" "$canonical_main_sha" >/dev/null

run_verify \
  workflow_dispatch refs/heads/main main v0.3.359 \
  https://git.example.invalid/ codewire/codewire \
  "$source_sha" "$tag_object_sha" "$source_sha" "$canonical_main_sha" >/dev/null

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
expect_failure unexpected-signer \
  workflow_dispatch refs/heads/main main v0.3.361 \
  https://git.example.invalid codewire/codewire \
  "$source_sha" "$wrong_signer_tag_object" "$source_sha" "$canonical_main_sha"
expect_failure mismatched-signed-tag-name \
  workflow_dispatch refs/heads/main main v0.3.363 \
  https://git.example.invalid codewire/codewire \
  "$source_sha" "$embedded_name_tag_object" "$source_sha" "$canonical_main_sha"
expect_failure unsigned-annotated-tag \
  workflow_dispatch refs/heads/main main v0.3.364 \
  https://git.example.invalid codewire/codewire \
  "$source_sha" "$unsigned_tag_object" "$source_sha" "$canonical_main_sha"

mapfile -t recovery_tags < <(
  "$COMPUTE_TAGS" nexus-system-cluster.example.invalid/oci-promoted/codewire services "$source_sha" v0.3.359 \
    refs/heads/main main
)
[[ "${recovery_tags[*]}" == \
  "nexus-system-cluster.example.invalid/oci-promoted/codewire/services:${source_sha} nexus-system-cluster.example.invalid/oci-promoted/codewire/services:v0.3.359" ]]

mapfile -t push_tags < <(
  "$COMPUTE_TAGS" nexus-system-cluster.example.invalid/oci-promoted/codewire services "$source_sha" v0.3.359 \
    refs/tags/v0.3.359 v0.3.359
)
[[ "${push_tags[*]}" == \
  "nexus-system-cluster.example.invalid/oci-promoted/codewire/services:${source_sha} nexus-system-cluster.example.invalid/oci-promoted/codewire/services:v0.3.359" ]]

mapfile -t dev_tags < <(
  "$COMPUTE_TAGS" nexus-system-cluster.example.invalid/oci-promoted/codewire services "$source_sha" '' \
    refs/heads/main main
)
[[ "${dev_tags[*]}" == \
  "nexus-system-cluster.example.invalid/oci-promoted/codewire/services:${source_sha}" ]]

mapfile -t direct_tag_tags < <(
  "$COMPUTE_TAGS" nexus-system-cluster.example.invalid/oci-promoted/codewire services "$source_sha" '' \
    refs/tags/v0.3.359 v0.3.359
)
[[ "${direct_tag_tags[*]}" == \
  "nexus-system-cluster.example.invalid/oci-promoted/codewire/services:${source_sha} nexus-system-cluster.example.invalid/oci-promoted/codewire/services:v0.3.359" ]]

deploy_workflow="$ROOT/.gitea/workflows/deploy-prod.yaml"
cli_workflow="$ROOT/.gitea/workflows/cli-release.yaml"
image_builder="$ROOT/scripts/ci/images/build-push-image.sh"
signing_key_test="$ROOT/scripts/ci/tests/test-verify-cw-release-signing-key.sh"
installer_signature_test="$ROOT/scripts/ci/tests/test-cw-install-signature.sh"
publish_release_test="$ROOT/scripts/ci/tests/test-publish-cw-release.sh"
installer="$ROOT/apps/cli/install.sh"
cli_readme="$ROOT/apps/cli/README.md"
release_public_key="$ROOT/apps/cli/GPG_PUBLIC_KEY.asc"
production_tag_public_key="$ROOT/keys/production-release.asc"
package_script="$ROOT/scripts/ci/release/package-cw-release.sh"

grep -Fq '  workflow_dispatch:' "$deploy_workflow"
grep -Fq '  release-selection:' "$deploy_workflow"
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
[[ "$(grep -Fc '          CODEWIRE_DEPLOY_PROMOTION_TOKEN:' "$deploy_workflow")" -eq 1 ]]
if grep -Eq 'CODEWIRE_DEPLOY_PROMOTION_USERNAME|promote-image-bundle|promote \.release-source|promotion-receipt|observe-production:|deploy-prod-observer\.sh|gitea-(upload|download)-artifact|kubectl|helm' \
  "$deploy_workflow"; then
  echo 'production workflow still contains direct deploy writes, receipt transport, or observation' >&2
  exit 1
fi

grep -Fq '  workflow_dispatch:' "$cli_workflow"
grep -Fq '  release-selection:' "$cli_workflow"
grep -Fq '  package-release:' "$cli_workflow"
grep -Fq '    needs: [release-selection]' "$cli_workflow"
grep -Fq "[ \"\$GITHUB_REF\" = 'refs/heads/main' ]" "$cli_workflow"
grep -Fq '          path: .release-source' "$cli_workflow"
grep -Fq '+refs/heads/main:refs/remotes/origin/main' "$cli_workflow"
grep -Fq '          ref: refs/tags/${{ needs.release-selection.outputs.release_tag }}' "$cli_workflow"
grep -Fq '        working-directory: .release-source' "$cli_workflow"
grep -Fq '../scripts/ci/release/verify-cw-release-signing-key.sh apps/cli/GPG_PUBLIC_KEY.asc' "$cli_workflow"
grep -Fq '../scripts/ci/release/package-cw-release.sh "$RELEASE_TAG"' "$cli_workflow"
grep -Fq '../scripts/ci/release/publish-cw-release.sh "$RELEASE_TAG" dist/cw-release' "$cli_workflow"
grep -Fq 'CW_RELEASE_TAG_OBJECT_SHA: ${{ needs.release-selection.outputs.tag_object_sha }}' "$cli_workflow"
if grep -Fq '.release-control' "$cli_workflow"; then
  echo 'CLI workflow must not load recovery control from the selected tag' >&2
  exit 1
fi
grep -Fq '          CW_RELEASE_SOURCE_SHA: ${{ needs.release-selection.outputs.source_sha }}' "$cli_workflow"
package_release="$(sed -n '/^  package-release:/,$p' "$cli_workflow")"
assert_release_publication_boundary() {
  local workflow="$1"
  local package_step
  package_step="$(awk '
    /^      - name: Package signed release assets$/ { in_step = 1 }
    in_step && /^      - / && $0 !~ /^      - name: Package signed release assets$/ { exit }
    in_step { print }
  ' "$workflow")"

  grep -Fq '          ../scripts/ci/release/package-cw-release.sh "$RELEASE_TAG"' <<<"$package_step" || return 1
  grep -Fq '          gpg --verify dist/cw-release/SHA256SUMS.asc dist/cw-release/SHA256SUMS' <<<"$package_step" || return 1
  grep -Fq '          GITEA_TOKEN: ${{ github.token }}' <<<"$package_step" || return 1
  grep -Fq '          MIRROR_GITHUB_APP_ID: ${{ secrets.MIRROR_GITHUB_APP_ID }}' <<<"$package_step" || return 1
  grep -Fq '          MIRROR_GITHUB_INSTALLATION_ID: ${{ secrets.MIRROR_GITHUB_INSTALLATION_ID }}' <<<"$package_step" || return 1
  grep -Fq '          MIRROR_GITHUB_PRIVATE_KEY: ${{ secrets.MIRROR_GITHUB_PRIVATE_KEY }}' <<<"$package_step" || return 1
  grep -Fq "          CW_REQUIRE_GITHUB_MIRROR: '1'" <<<"$package_step" || return 1
  grep -Fq '          CW_RELEASE_SOURCE_SHA: ${{ needs.release-selection.outputs.source_sha }}' <<<"$package_step" || return 1
  grep -Fq '          CW_RELEASE_TAG_OBJECT_SHA: ${{ needs.release-selection.outputs.tag_object_sha }}' <<<"$package_step" || return 1
  grep -Fq '          ../scripts/ci/release/publish-cw-release.sh "$RELEASE_TAG" dist/cw-release' <<<"$package_step" || return 1
  if grep -Eq "node <<'NODE'|api\.github\.com/app/installations/|mirror_token=|token_json=" <<<"$package_step"; then
    echo 'CLI release workflow still implements GitHub publication instead of invoking the publication script' >&2
    return 1
  fi
  if ! awk '
    /^      - name: Package signed release assets$/ { in_step = 1 }
    in_step && /^      - / && $0 !~ /^      - name: Package signed release assets$/ { exit }
    in_step && /\.\.\/scripts\/ci\/release\/publish-cw-release\.sh "\$RELEASE_TAG" dist\/cw-release/ { seen = 1; next }
    seen && /^[[:space:]]*$/ { next }
    seen && /^          / { trailing_command = 1; exit }
    END { exit (seen && !trailing_command) ? 0 : 1 }
  ' "$workflow"; then
    echo 'CLI release workflow performs work after publication inside the package completion boundary' >&2
    return 1
  fi
  if grep -Fq '      - name: Publish release assets' "$workflow"; then
    echo 'CLI release workflow leaves publication outside the package completion boundary' >&2
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

signing_preflight_line="$(grep -n 'name: Verify release signing key' <<<"$package_release" | cut -d: -f1)"
toolchain_line="$(grep -n 'name: Verify sealed Rust toolchain and release targets' <<<"$package_release" | head -1 | cut -d: -f1)"
[[ -n "$signing_preflight_line" && -n "$toolchain_line" &&
  "$signing_preflight_line" -lt "$toolchain_line" ]] || {
  echo 'CLI signing preflight must run before cross-target toolchain setup' >&2
  exit 1
}
for name in \
  CW_RELEASE_GPG_PRIVATE_KEY \
  CW_RELEASE_GPG_PASSPHRASE \
  CW_RELEASE_GPG_KEY_ID; do
  [ "$(grep -Fc "          ${name}: \${{ secrets.${name} }}" <<<"$package_release")" -eq 2 ] || {
    printf 'CLI workflow does not pass %s to both preflight and packaging\n' "$name" >&2
    exit 1
  }
done

"$signing_key_test"
"$installer_signature_test"
"$publish_release_test"

installer_fingerprint="$(
  sed -n 's/^GPG_KEY_ID="\([0-9A-F]*\)"$/\1/p' "$installer"
)"
public_key_fingerprint="$(
  gpg --batch --show-keys --with-colons "$release_public_key" 2>/dev/null |
    awk -F: '$1 == "fpr" { print $10; exit }'
)"
[ "$installer_fingerprint" = "$public_key_fingerprint" ] || {
  echo 'installer fingerprint does not match the checked-in release key' >&2
  exit 1
}
grep -Fq 'downloaded_key_count="$(' "$installer"
grep -Fq '[ "$downloaded_key_count" -eq 1 ]' "$installer"
grep -Fq '[ "$downloaded_key_id" = "$GPG_KEY_ID" ]' "$installer"
grep -Fq 'release_gnupg_home="${tmp_dir}/gnupg"' "$installer"
grep -Fq 'GNUPGHOME="$release_gnupg_home"' "$installer"
grep -Fq '[ "$valid_signature_count" -eq 1 ] && [ "$valid_signature_id" = "$GPG_KEY_ID" ]' "$installer"
grep -Fq 'main/apps/cli/GPG_PUBLIC_KEY.asc' "$installer"
grep -Fq 'gpg --import apps/cli/GPG_PUBLIC_KEY.asc' "$cli_readme"
grep -Fq -- '--passphrase-fd 0' "$package_script"
if grep -Fq -- '--passphrase "$CW_RELEASE_GPG_PASSPHRASE"' "$package_script"; then
  echo 'release packager still exposes the passphrase through process arguments' >&2
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
grep -Fq 'DOCKER_CONFIG="$docker_config" docker buildx build --push' "$image_builder"
grep -Fq -- '--metadata-file "$build_metadata"' "$image_builder"
grep -Fq '"$credential_fetcher" "$registry_username_file" "$registry_password_file"' \
  "$image_builder"
grep -Fq "readonly REGISTRY_HOST='nexus-system-cluster.example.invalid'" \
  "$image_builder"
if grep -Fq 'GITEA_REGISTRY_TOKEN' "$image_builder" \
  || grep -Fq 'INFISICAL_SECRET_FETCHER' "$image_builder"; then
  echo 'image builder still obtains its canonical registry credential from Infisical' >&2
  exit 1
fi
grep -Fq 'python3 scripts/ci/images/image-bundle.py candidate' "$image_builder"
grep -Fq 'git -C "$source_dir" rev-parse HEAD' "$image_builder"
grep -Fq 'checkout $checked_out_sha does not match selected source $source_sha' "$image_builder"

production_tag_fingerprint="$(
  gpg --batch --show-keys --with-colons "$production_tag_public_key" 2>/dev/null |
    awk -F: '$1 == "fpr" { print $10; exit }'
)"
[[ "$production_tag_fingerprint" == \
  'E66EACD85E979D3A10C5744AACB59B76E29853EA' ]] || {
  echo 'production Git-tag key does not match the pinned release identity' >&2
  exit 1
}

printf 'release tag dispatch guard tests: OK\n'
