#!/usr/bin/env bash
# shellcheck disable=SC2016 # Literal GitHub expression strings are workflow fixtures.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
# shellcheck source=scripts/ci/tests/fixtures/ci-runners.sh
source "$ROOT/scripts/ci/tests/fixtures/ci-runners.sh"
MIRROR="$ROOT/scripts/ci/release/mirror-git-tags.sh"
MIRROR_CANONICAL="$ROOT/scripts/ci/release/mirror-canonical-release-tag.sh"
MIRROR_WORKFLOW="$ROOT/.gitea/workflows/mirror-github.yaml"
GITHUB_WORKFLOW_ROOT="$ROOT/.github/workflows"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# npm and PyPI trust hosted CI for trusted SDK publishing (#3512), OpenSSF
# accepts signed Scorecard results only from GitHub's hosted runner, and the
# cargo-fuzz targets run on GitHub's hosted runners (docs/dev/FUZZING.md).
# These GitHub-only workflows are allowed; any other stays retired.
if [ -d "$GITHUB_WORKFLOW_ROOT" ] &&
  find "$GITHUB_WORKFLOW_ROOT" -type f \
    ! -path "$GITHUB_WORKFLOW_ROOT/sdk-release.yml" \
    ! -path "$GITHUB_WORKFLOW_ROOT/scorecard.yml" \
    ! -path "$GITHUB_WORKFLOW_ROOT/fuzz.yml" -print -quit | grep -q .; then
  echo 'repository-authored GitHub Actions workflows other than sdk-release.yml, scorecard.yml and fuzz.yml must remain retired' >&2
  find "$GITHUB_WORKFLOW_ROOT" -type f \
    ! -path "$GITHUB_WORKFLOW_ROOT/sdk-release.yml" \
    ! -path "$GITHUB_WORKFLOW_ROOT/scorecard.yml" \
    ! -path "$GITHUB_WORKFLOW_ROOT/fuzz.yml" -print >&2
  exit 1
fi

source_repo="$TMP/source"
remote_repo="$TMP/remote.git"

git init -q "$source_repo"
git init -q --bare "$remote_repo"
git -C "$source_repo" config user.name 'Mirror Test'
git -C "$source_repo" config user.email 'mirror-test@example.invalid'
git -C "$source_repo" config commit.gpgsign false
git -C "$source_repo" config tag.gpgSign false
git -C "$source_repo" remote add mirror "$remote_repo"

printf 'first\n' > "$source_repo/state"
git -C "$source_repo" add state
git -C "$source_repo" commit -q -m first
first_commit="$(git -C "$source_repo" rev-parse HEAD)"
git -C "$source_repo" tag -a v1.0.0 -m 'annotated release'
git -C "$source_repo" tag v1.0.1

(
  cd "$source_repo"
  "$MIRROR" mirror
)

[ "$(git --git-dir="$remote_repo" rev-parse refs/tags/v1.0.0)" = \
  "$(git -C "$source_repo" rev-parse refs/tags/v1.0.0)" ]
[ "$(git --git-dir="$remote_repo" rev-parse refs/tags/v1.0.1)" = "$first_commit" ]

# GitHub already has this release as a lightweight tag. The canonical source
# has an annotated tag, but both identify the same release commit.
git --git-dir="$remote_repo" update-ref refs/tags/v1.0.0 "$first_commit"
(
  cd "$source_repo"
  "$MIRROR" mirror
)
[ "$(git --git-dir="$remote_repo" cat-file -t refs/tags/v1.0.0)" = commit ]

printf 'second\n' >> "$source_repo/state"
git -C "$source_repo" add state
git -C "$source_repo" commit -q -m second
second_commit="$(git -C "$source_repo" rev-parse HEAD)"
git -C "$source_repo" push -q mirror "$second_commit:refs/heads/divergent-test"

# A genuinely different target must fail without moving the remote ref.
git --git-dir="$remote_repo" update-ref refs/tags/v1.0.1 "$second_commit"
if (
  cd "$source_repo"
  "$MIRROR" mirror > "$TMP/divergent.out" 2>&1
); then
  echo 'expected a divergent remote tag to fail' >&2
  exit 1
fi
grep -F 'refusing to overwrite refs/tags/v1.0.1' "$TMP/divergent.out"
[ "$(git --git-dir="$remote_repo" rev-parse refs/tags/v1.0.1)" = "$second_commit" ]

# Restore parity and prove a later annotated tag is pushed with its tag object.
git --git-dir="$remote_repo" update-ref refs/tags/v1.0.1 "$first_commit"
git -C "$source_repo" tag -a v1.0.2 -m 'second annotated release'
(
  cd "$source_repo"
  "$MIRROR" mirror
)
[ "$(git --git-dir="$remote_repo" rev-parse refs/tags/v1.0.2)" = \
  "$(git -C "$source_repo" rev-parse refs/tags/v1.0.2)" ]

# A tag-triggered Actions checkout may have replaced its local tag ref with the
# peeled commit. The release mirror must fetch the canonical Gitea tag object
# into an isolated ref instead of trusting that checkout-created ref.
canonical_author="$TMP/canonical-author"
canonical_origin="$TMP/canonical-origin.git"
canonical_checkout="$TMP/canonical-checkout"
canonical_mirror="$TMP/canonical-mirror.git"
git init -q "$canonical_author"
git init -q --bare "$canonical_origin"
git init -q --bare "$canonical_mirror"
git -C "$canonical_author" config user.name 'Canonical Tag Test'
git -C "$canonical_author" config user.email canonical-tag@example.invalid
git -C "$canonical_author" config commit.gpgsign false
git -C "$canonical_author" config tag.gpgSign false
printf 'canonical\n' >"$canonical_author/state"
git -C "$canonical_author" add state
git -C "$canonical_author" commit -q -m canonical
canonical_commit="$(git -C "$canonical_author" rev-parse HEAD)"
git -C "$canonical_author" branch -M main
git -C "$canonical_author" tag -a v2.0.0 -m 'canonical annotated release'
canonical_object="$(git -C "$canonical_author" rev-parse refs/tags/v2.0.0)"
git -C "$canonical_author" remote add origin "$canonical_origin"
git -C "$canonical_author" push -q origin main refs/tags/v2.0.0
git clone -q "$canonical_origin" "$canonical_checkout"
git -C "$canonical_checkout" remote add github "$canonical_mirror"
git -C "$canonical_checkout" update-ref refs/tags/v2.0.0 "$canonical_commit"
[ "$(git -C "$canonical_checkout" cat-file -t refs/tags/v2.0.0)" = commit ]
(
  cd "$canonical_checkout"
  "$MIRROR_CANONICAL" origin github refs/tags/v2.0.0
)
[ "$(git --git-dir="$canonical_mirror" cat-file -t refs/tags/v2.0.0)" = tag ]
[ "$(git --git-dir="$canonical_mirror" rev-parse refs/tags/v2.0.0)" = \
  "$canonical_object" ]
[ "$(git --git-dir="$canonical_mirror" rev-parse 'refs/tags/v2.0.0^{}')" = \
  "$canonical_commit" ]
[ "$(git -C "$canonical_checkout" cat-file -t refs/tags/v2.0.0)" = commit ]

# Exact canonical parity is idempotent.
(
  cd "$canonical_checkout"
  "$MIRROR_CANONICAL" origin github refs/tags/v2.0.0
)

# Never force-rewrite an existing mirror tag, even when a flattened tag points
# at the same commit. Future tag events must publish the exact object first.
git -C "$canonical_author" tag -a v2.0.1 -m 'second canonical release'
git -C "$canonical_author" push -q origin refs/tags/v2.0.1
git --git-dir="$canonical_mirror" update-ref refs/tags/v2.0.1 "$canonical_commit"
if (
  cd "$canonical_checkout"
  "$MIRROR_CANONICAL" origin github refs/tags/v2.0.1 \
    >"$TMP/flattened.out" 2>&1
); then
  echo 'expected a flattened mirror tag to fail closed' >&2
  exit 1
fi
grep -F 'mirror does not contain the canonical annotated tag object' \
  "$TMP/flattened.out"
[ "$(git --git-dir="$canonical_mirror" cat-file -t refs/tags/v2.0.1)" = commit ]

# A canonical tag whose target differs from an existing mirror tag must fail
# without moving the mirror ref.
printf 'next canonical\n' >>"$canonical_author/state"
git -C "$canonical_author" add state
git -C "$canonical_author" commit -q -m 'next canonical'
next_canonical_commit="$(git -C "$canonical_author" rev-parse HEAD)"
git -C "$canonical_author" tag -a v2.0.3 -m 'divergent canonical release'
git -C "$canonical_author" push -q origin main refs/tags/v2.0.3
git --git-dir="$canonical_mirror" update-ref refs/tags/v2.0.3 "$canonical_commit"
if (
  cd "$canonical_checkout"
  "$MIRROR_CANONICAL" origin github refs/tags/v2.0.3 \
    >"$TMP/canonical-divergent.out" 2>&1
); then
  echo 'expected a divergent canonical mirror tag to fail closed' >&2
  exit 1
fi
grep -F "canonical target $next_canonical_commit differs from mirror target $canonical_commit" \
  "$TMP/canonical-divergent.out"
[ "$(git --git-dir="$canonical_mirror" rev-parse refs/tags/v2.0.3)" = \
  "$canonical_commit" ]

# A lightweight canonical source tag is not acceptable release provenance.
git -C "$canonical_author" tag v2.0.2
git -C "$canonical_author" push -q origin refs/tags/v2.0.2
if (
  cd "$canonical_checkout"
  "$MIRROR_CANONICAL" origin github refs/tags/v2.0.2 \
    >"$TMP/lightweight.out" 2>&1
); then
  echo 'expected a lightweight canonical release tag to fail' >&2
  exit 1
fi
grep -F 'canonical tag is not annotated' "$TMP/lightweight.out"

grep -Fq 'enable-openid-connect: true' "$MIRROR_WORKFLOW"
grep -Fq 'OPENBAO_GITHUB_ROLE: codewire-source-github-mirror' "$MIRROR_WORKFLOW"
grep -Fq 'OPENBAO_GITHUB_AUDIENCE: openbao-codewire-source-github-mirror' "$MIRROR_WORKFLOW"
grep -Fq "    runs-on: ${RUNS_ON_TRUSTED_LIGHT}" "$MIRROR_WORKFLOW"
grep -Fq 'run: scripts/ci/release/mirror-github.sh "${GITHUB_REF:?}"' "$MIRROR_WORKFLOW"
if grep -Eq "tags:|workflow_dispatch:" "$MIRROR_WORKFLOW"; then
  echo 'mirror workflow has a trigger outside its protected-main OpenBao role' >&2
  exit 1
fi
if grep -Eq 'MIRROR_GITHUB_(APP_ID|INSTALLATION_ID|PRIVATE_KEY)|secrets\.|x-access-token:|bootstrap-openbao-github-mirror-credentials' \
    "$MIRROR_WORKFLOW"; then
  echo 'actual mirror step exposes a reusable GitHub credential surface' >&2
  exit 1
fi
if grep -Fq 'git push github "${GITHUB_REF}:${GITHUB_REF}"' "$MIRROR_WORKFLOW"; then
  echo 'tag workflow still trusts the checkout-created local tag ref' >&2
  exit 1
fi

echo 'mirror git tag tests passed'
