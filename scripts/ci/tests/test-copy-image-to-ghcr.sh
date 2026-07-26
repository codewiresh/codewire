#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly COPY_IMAGE="$ROOT/scripts/ci/images/copy-image-to-ghcr.sh"

fail() {
  printf '[test-copy-image-to-ghcr] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/copy-image-to-ghcr.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/state"

expected_digest="sha256:$(printf 'a%.0s' {1..64})"
other_digest="sha256:$(printf 'b%.0s' {1..64})"
source_sha="$(printf 'c%.0s' {1..40})"
release_tag="v1.2.3"
source_ref="git.example.invalid/codewire/gateway@$expected_digest"
target_repository="ghcr.io/codewiresh/gateway"

printf 'gitea-test-token' >"$work/gitea-token"
printf 'ghcr-test-token' >"$work/ghcr-token"
chmod 600 "$work/gitea-token" "$work/ghcr-token"

cat >"$work/bin/skopeo-runner" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

[[ "${SKOPEO_AUTH_VOLUME:?}" == fake-auth-volume ]]

printf '%q ' "$@" >>"${FAKE_CALLS:?}"
printf '\n' >>"$FAKE_CALLS"

command="$1"
shift
case "$command" in
  login)
    credential="$(cat)"
    [ -n "$credential" ]
    ;;
  inspect)
    ref="${!#}"
    ref="${ref#docker://}"
    if [[ "$ref" == git.example.invalid/* ]]; then
      printf '%s\n' "${FAKE_SOURCE_DIGEST:?}"
      exit 0
    fi
    if [ "${FAKE_INSPECT_ERROR:-0}" = 1 ]; then
      echo 'temporary registry transport failure' >&2
      exit 1
    fi
    tag="${ref##*:}"
    state="${FAKE_STATE:?}/$tag"
    if [ ! -f "$state" ]; then
      echo 'manifest unknown' >&2
      exit 1
    fi
    cat "$state"
    ;;
  copy)
    args=("$@")
    destination="${args[${#args[@]}-1]}"
    tag="${destination##*:}"
    printf '%s\n' "${FAKE_SOURCE_DIGEST:?}" >"${FAKE_STATE:?}/$tag"
    ;;
  *)
    echo "unexpected fake skopeo command: $command" >&2
    exit 1
    ;;
esac
EOF
cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"${FAKE_DOCKER_CALLS:?}"
case "$*" in
  'volume create') printf 'fake-auth-volume\n' ;;
  'volume rm fake-auth-volume') ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$work/bin/skopeo-runner" "$work/bin/docker"

export SKOPEO_RUNNER="$work/bin/skopeo-runner"
export DOCKER_BIN="$work/bin/docker"
export FAKE_CALLS="$work/calls"
export FAKE_DOCKER_CALLS="$work/docker-calls"
export FAKE_STATE="$work/state"
export FAKE_SOURCE_DIGEST="$expected_digest"
export GITEA_REGISTRY_TOKEN_FILE="$work/gitea-token"
export GHCR_PUBLISH_USERNAME="codewire-package-publisher"
export GHCR_PUBLISH_TOKEN_FILE="$work/ghcr-token"
export GITHUB_OUTPUT="$work/output"

"$COPY_IMAGE" "$source_ref" "$target_repository" "$source_sha" "$release_tag"

for tag in "$source_sha" "$release_tag"; do
  [[ "$(<"$work/state/$tag")" == "$expected_digest" ]] ||
    fail "copied $tag does not have the canonical digest"
done
[[ "$(grep -c '^copy ' "$FAKE_CALLS")" -eq 2 ]] ||
  fail "first publication did not copy both immutable tags"
grep -qxF "source_digest=$expected_digest" "$GITHUB_OUTPUT" ||
  fail "source digest output is absent"
grep -qxF "ghcr_ref=$target_repository:$source_sha" "$GITHUB_OUTPUT" ||
  fail "first GHCR ref output is absent"
grep -qxF "ghcr_digest=$expected_digest" "$GITHUB_OUTPUT" ||
  fail "GHCR digest output is absent"
if grep -qF 'gitea-test-token' "$FAKE_CALLS" \
  || grep -qF 'ghcr-test-token' "$FAKE_CALLS"; then
  fail "a registry token reached the command arguments"
fi
[[ "$(grep -c '^volume create$' "$FAKE_DOCKER_CALLS")" -eq 1 ]] ||
  fail "publication did not create exactly one private auth volume"
[[ "$(grep -c '^volume rm fake-auth-volume$' "$FAKE_DOCKER_CALLS")" -eq 1 ]] ||
  fail "publication did not delete its private auth volume"

"$COPY_IMAGE" "$source_ref" "$target_repository" "$source_sha" "$release_tag" >/dev/null
[[ "$(grep -c '^copy ' "$FAKE_CALLS")" -eq 2 ]] ||
  fail "idempotent publication copied an existing matching tag"

printf '%s\n' "$other_digest" >"$work/state/$source_sha"
if "$COPY_IMAGE" "$source_ref" "$target_repository" "$source_sha" \
    >"$work/conflict.out" 2>&1; then
  fail "conflicting immutable destination tag was replaced"
fi
[[ "$(<"$work/state/$source_sha")" == "$other_digest" ]] ||
  fail "conflicting immutable destination state changed"

rm -f "$work/state/$source_sha"
if FAKE_INSPECT_ERROR=1 "$COPY_IMAGE" "$source_ref" "$target_repository" \
    "$source_sha" >"$work/transport.out" 2>&1; then
  fail "a transient destination inspection failure was treated as absence"
fi
[[ "$(grep -c '^copy ' "$FAKE_CALLS")" -eq 2 ]] ||
  fail "transport failure attempted a copy"

if FAKE_SOURCE_DIGEST="$other_digest" "$COPY_IMAGE" "$source_ref" \
    "$target_repository" "$source_sha" >"$work/source-mismatch.out" 2>&1; then
  fail "source digest mismatch was accepted"
fi

if "$COPY_IMAGE" "$source_ref" 'ghcr.io/codewiresh/services' "$source_sha" \
    >"$work/family-mismatch.out" 2>&1; then
  fail "source and destination image family mismatch was accepted"
fi
if "$COPY_IMAGE" "$source_ref" "$target_repository" latest \
    >"$work/moving-tag.out" 2>&1; then
  fail "runtime moving destination tag was accepted"
fi

support_source_ref="git.example.invalid/codewire/base@$expected_digest"
support_target_repository='ghcr.io/codewiresh/base'
printf '%s\n' "$other_digest" >"$work/state/latest"
copy_calls_before="$(grep -c '^copy ' "$FAKE_CALLS")"
"$COPY_IMAGE" "$support_source_ref" "$support_target_repository" \
  "$source_sha" latest >"$work/support-latest.out"
[[ "$(<"$work/state/latest")" == "$expected_digest" ]] ||
  fail "support compatibility alias did not advance to the canonical digest"
[[ "$(grep -c '^copy ' "$FAKE_CALLS")" -eq $((copy_calls_before + 2)) ]] ||
  fail "support publication did not copy the immutable and compatibility aliases"
grep -qF 'Updating support-image compatibility alias' "$work/support-latest.out" ||
  fail "support compatibility update was not reported"

copy_calls_before="$(grep -c '^copy ' "$FAKE_CALLS")"
"$COPY_IMAGE" "$support_source_ref" "$support_target_repository" \
  "$source_sha" latest >/dev/null
[[ "$(grep -c '^copy ' "$FAKE_CALLS")" -eq "$copy_calls_before" ]] ||
  fail "matching support compatibility aliases were copied again"

"$COPY_IMAGE" "git.example.invalid/codewire/workspace@$expected_digest" \
  'ghcr.io/codewiresh/workspace' latest >/dev/null ||
  fail "workspace compatibility alias was rejected"

if "$COPY_IMAGE" 'git.example.invalid/codewire/gateway:latest' "$target_repository" \
    "$source_sha" >"$work/moving-source.out" 2>&1; then
  fail "moving source reference was accepted"
fi
if GHCR_PUBLISH_TOKEN_FILE="$work/missing" "$COPY_IMAGE" "$source_ref" \
    "$target_repository" "$source_sha" >"$work/missing-token.out" 2>&1; then
  fail "missing credential file was accepted"
fi

echo 'copy-image-to-ghcr tests passed'
