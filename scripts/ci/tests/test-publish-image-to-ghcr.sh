#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly PUBLISH_IMAGE="$ROOT/scripts/ci/images/publish-image-to-ghcr.sh"

fail() {
  printf '[test-publish-image-to-ghcr] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/publish-image-to-ghcr.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"

expected_digest="sha256:$(printf 'a%.0s' {1..64})"
other_digest="sha256:$(printf 'b%.0s' {1..64})"
source_sha="$(printf 'c%.0s' {1..40})"
source_ref="git.example.invalid/codewire/gateway@$expected_digest"
target_repository='ghcr.io/codewiresh/gateway'
gitea_token='gitea-wrapper-test-token'
ghcr_token='ghcr-wrapper-test-token'

cat >"$work/bin/fetch-secret" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${FAKE_FETCH_FAIL_NAME:-}" = "$1" ]; then
  exit 1
fi
case "$1" in
  GITEA_REGISTRY_TOKEN) value="${FAKE_GITEA_TOKEN:?}" ;;
  GHCR_PUBLISH_TOKEN) value="${FAKE_GHCR_TOKEN:?}" ;;
  *) exit 1 ;;
esac
printf '%s' "$value" >"$2"
chmod 0600 "$2"
printf '%s\t%s\n' "$1" "$2" >>"${FAKE_FETCH_CALLS:?}"
EOF

cat >"$work/bin/copy-image" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "${FAKE_COPY_FAIL:-0}" != 1 ] || exit 1
[[ "${GHCR_PUBLISH_USERNAME:?}" == codewire-package-publisher ]]
[[ "$(<"${GITEA_REGISTRY_TOKEN_FILE:?}")" == "${FAKE_GITEA_TOKEN:?}" ]]
[[ "$(<"${GHCR_PUBLISH_TOKEN_FILE:?}")" == "${FAKE_GHCR_TOKEN:?}" ]]
[[ "$(stat -c '%a' "$GITEA_REGISTRY_TOKEN_FILE")" == 600 ]]
[[ "$(stat -c '%a' "$GHCR_PUBLISH_TOKEN_FILE")" == 600 ]]
printf '%s\n' "$*" >>"${FAKE_COPY_CALLS:?}"
EOF

cat >"$work/bin/skopeo-runner" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ -z "${SKOPEO_AUTH_VOLUME:-}" ]]
printf '%s\n' "$*" >>"${FAKE_SKOPEO_CALLS:?}"
[ "${FAKE_ANON_FAIL:-0}" != 1 ] || exit 1
[[ "$*" == *'inspect --no-creds --format {{.Digest}} docker://'* ]]
printf '%s\n' "${FAKE_ANON_DIGEST:?}"
EOF
chmod +x "$work/bin/fetch-secret" "$work/bin/copy-image" "$work/bin/skopeo-runner"

export INFISICAL_SECRET_FETCHER="$work/bin/fetch-secret"
export GHCR_COPY_HELPER="$work/bin/copy-image"
export SKOPEO_RUNNER="$work/bin/skopeo-runner"
export GHCR_PUBLISH_USERNAME='codewire-package-publisher'
export FAKE_GITEA_TOKEN="$gitea_token"
export FAKE_GHCR_TOKEN="$ghcr_token"
export FAKE_FETCH_CALLS="$work/fetch-calls"
export FAKE_COPY_CALLS="$work/copy-calls"
export FAKE_SKOPEO_CALLS="$work/skopeo-calls"
export FAKE_ANON_DIGEST="$expected_digest"
export GITHUB_OUTPUT="$work/output"

"$PUBLISH_IMAGE" "$source_ref" "$target_repository" "$source_sha"

grep -qxF "GITEA_REGISTRY_TOKEN"$'\t'"$(awk -F '\t' 'NR == 1 { print $2 }' "$FAKE_FETCH_CALLS")" \
  "$FAKE_FETCH_CALLS" || fail 'Gitea credential was not fetched first'
grep -q '^GHCR_PUBLISH_TOKEN'$'\t' "$FAKE_FETCH_CALLS" ||
  fail 'GHCR credential was not fetched'
grep -qxF "$source_ref $target_repository $source_sha" "$FAKE_COPY_CALLS" ||
  fail 'exact copy arguments changed'
grep -qxF "inspect --no-creds --format {{.Digest}} docker://$target_repository@$expected_digest" \
  "$FAKE_SKOPEO_CALLS" || fail 'anonymous digest verification is absent'
grep -qxF "ghcr_public_ref=$target_repository@$expected_digest" "$GITHUB_OUTPUT" ||
  fail 'public digest output is absent'
while IFS=$'\t' read -r _ token_file; do
  [ ! -e "$token_file" ] || fail 'private credential file survived publication'
done <"$FAKE_FETCH_CALLS"
if grep -qF "$gitea_token" "$FAKE_FETCH_CALLS" "$FAKE_COPY_CALLS" \
  || grep -qF "$ghcr_token" "$FAKE_FETCH_CALLS" "$FAKE_COPY_CALLS"; then
  fail 'a registry token reached command arguments'
fi

if FAKE_ANON_DIGEST="$other_digest" "$PUBLISH_IMAGE" "$source_ref" \
    "$target_repository" "$source_sha" >"$work/mismatch.out" 2>&1; then
  fail 'anonymous digest mismatch was accepted'
fi

skopeo_calls_before="$(wc -l <"$FAKE_SKOPEO_CALLS")"
if FAKE_COPY_FAIL=1 "$PUBLISH_IMAGE" "$source_ref" "$target_repository" \
    "$source_sha" >"$work/copy-failure.out" 2>&1; then
  fail 'copy failure was accepted'
fi
[[ "$(wc -l <"$FAKE_SKOPEO_CALLS")" -eq "$skopeo_calls_before" ]] ||
  fail 'copy failure reached anonymous verification'

copy_calls_before="$(wc -l <"$FAKE_COPY_CALLS")"
if FAKE_FETCH_FAIL_NAME=GHCR_PUBLISH_TOKEN "$PUBLISH_IMAGE" "$source_ref" \
    "$target_repository" "$source_sha" >"$work/fetch-failure.out" 2>&1; then
  fail 'credential fetch failure was accepted'
fi
[[ "$(wc -l <"$FAKE_COPY_CALLS")" -eq "$copy_calls_before" ]] ||
  fail 'credential fetch failure reached the copy helper'

fetch_calls_before="$(wc -l <"$FAKE_FETCH_CALLS")"
if "$PUBLISH_IMAGE" 'git.example.invalid/codewire/gateway:latest' \
    "$target_repository" "$source_sha" >"$work/moving-source.out" 2>&1; then
  fail 'moving source reference was accepted'
fi
[[ "$(wc -l <"$FAKE_FETCH_CALLS")" -eq "$fetch_calls_before" ]] ||
  fail 'invalid source reference reached credential retrieval'

if "$PUBLISH_IMAGE" "$source_ref" 'ghcr.io/codewiresh/services' \
    "$source_sha" >"$work/family-mismatch.out" 2>&1; then
  fail 'source and destination family mismatch was accepted'
fi
[[ "$(wc -l <"$FAKE_FETCH_CALLS")" -eq "$fetch_calls_before" ]] ||
  fail 'family mismatch reached credential retrieval'

echo 'publish-image-to-ghcr tests passed'
