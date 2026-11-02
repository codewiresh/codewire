#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RESOLVER="$ROOT/scripts/runtime/confidential/resolve-coco-support-lock.sh"
LOCK="$ROOT/deployments/k8s/runtime-profiles/confidential/coco-support-images.lock.json"
SOURCE_SHA="c0a265c6eb6cea7353a632b92e7c5819f0629583"
export CODEWIRE_IMAGE_REGISTRY=registry.example.invalid
DAEMON_IMAGE="$CODEWIRE_IMAGE_REGISTRY/codewire/daemon@sha256:b606b5e4b119c4117b9163943702ff3fcea56d1c0e2f85a6ad3bf2ffa3dfc1c1"
mkdir -p "$ROOT/.tmp"
TMPDIR_TEST="$(mktemp -d "$ROOT/.tmp/codewire-coco-support-lock.XXXXXX")"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

mkdir -p "$TMPDIR_TEST/bin"
cat >"$TMPDIR_TEST/bin/skopeo" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

case "$*" in
  *'ghcr.io/codewiresh/daemon@sha256:b606b5e4b119c4117b9163943702ff3fcea56d1c0e2f85a6ad3bf2ffa3dfc1c1'*)
    printf '{"Digest":"sha256:b606b5e4b119c4117b9163943702ff3fcea56d1c0e2f85a6ad3bf2ffa3dfc1c1","Labels":{"org.opencontainers.image.revision":"%s"}}\n' "${MOCK_DAEMON_REVISION:-c0a265c6eb6cea7353a632b92e7c5819f0629583}"
    ;;
  *"ghcr.io/codewiresh/workspace:${MOCK_SOURCE:-c0a265c6eb6cea7353a632b92e7c5819f0629583}"*)
    printf '{"Digest":"sha256:7645bc90934a603724751a2363657933f673eaf469857e64e3462c7042fd1808","Labels":{"org.opencontainers.image.revision":"%s"}}\n' "${MOCK_WORKSPACE_REVISION:-c0a265c6eb6cea7353a632b92e7c5819f0629583}"
    ;;
  *'docker.io/library/docker@sha256:9e79b879b177fbd72c34376a3dd3d91747da5db49e1f560f76aea59561471977'*)
    printf '%s\n' '{"Digest":"sha256:9e79b879b177fbd72c34376a3dd3d91747da5db49e1f560f76aea59561471977","Labels":{}}'
    ;;
  *)
    exit 1
    ;;
esac
SCRIPT
chmod +x "$TMPDIR_TEST/bin/skopeo"

run_resolver() {
  PATH="$TMPDIR_TEST/bin:$PATH" "$RESOLVER" \
    --lock "$1" \
    --daemon-image "$DAEMON_IMAGE" \
    --source-sha "$SOURCE_SHA"
}

expect_failure() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    printf 'expected failure: %s\n' "$name" >&2
    exit 1
  fi
}

output="$(run_resolver "$LOCK")"
grep -Fx "source_sha=$SOURCE_SHA" <<<"$output" >/dev/null
grep -Fx "daemon_image=$DAEMON_IMAGE" <<<"$output" >/dev/null
grep -Fx 'daemon_public_image=ghcr.io/codewiresh/daemon@sha256:b606b5e4b119c4117b9163943702ff3fcea56d1c0e2f85a6ad3bf2ffa3dfc1c1' <<<"$output" >/dev/null
grep -Fx 'workspace_image=ghcr.io/codewiresh/workspace@sha256:7645bc90934a603724751a2363657933f673eaf469857e64e3462c7042fd1808' <<<"$output" >/dev/null
grep -Fx 'dind_image=docker.io/library/docker:29.9.2-dind@sha256:9e79b879b177fbd72c34376a3dd3d91747da5db49e1f560f76aea59561471977' <<<"$output" >/dev/null

jq '.images.dind = "docker.io/library/docker:29.9.2-dind@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' "$LOCK" >"$TMPDIR_TEST/wrong-digest.json"
expect_failure "resolved dind digest mismatch" run_resolver "$TMPDIR_TEST/wrong-digest.json"

expect_failure "daemon revision mismatch" env MOCK_DAEMON_REVISION=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa PATH="$TMPDIR_TEST/bin:$PATH" "$RESOLVER" --lock "$LOCK" --daemon-image "$DAEMON_IMAGE" --source-sha "$SOURCE_SHA"
expect_failure "workspace revision mismatch" env MOCK_WORKSPACE_REVISION=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa PATH="$TMPDIR_TEST/bin:$PATH" "$RESOLVER" --lock "$LOCK" --daemon-image "$DAEMON_IMAGE" --source-sha "$SOURCE_SHA"

expect_failure "daemon image from another registry" env CODEWIRE_IMAGE_REGISTRY=other.example.invalid PATH="$TMPDIR_TEST/bin:$PATH" "$RESOLVER" --lock "$LOCK" --daemon-image "$DAEMON_IMAGE" --source-sha "$SOURCE_SHA"
if missing_registry="$(env -u CODEWIRE_IMAGE_REGISTRY PATH="$TMPDIR_TEST/bin:$PATH" "$RESOLVER" --lock "$LOCK" --daemon-image "$DAEMON_IMAGE" --source-sha "$SOURCE_SHA" 2>&1)"; then
  printf 'expected failure: missing image registry\n' >&2
  exit 1
fi
grep -Fq 'CODEWIRE_IMAGE_REGISTRY: set to the image registry host' <<<"$missing_registry"

# A release that doesn't change an image re-tags the one built from an earlier
# source: its revision is accepted when it is an ancestor of the active source,
# and refused when it is not (here a sibling).
repo="$TMPDIR_TEST/source"
git init -q "$repo"
git -C "$repo" -c user.name=t -c user.email=t@example.invalid commit -q --allow-empty -m base
base="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" -c user.name=t -c user.email=t@example.invalid commit -q --allow-empty -m active
active="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" checkout -q -b side "$base"
git -C "$repo" -c user.name=t -c user.email=t@example.invalid commit -q --allow-empty -m sibling
sibling="$(git -C "$repo" rev-parse HEAD)"
resolve_at() { # DAEMON_REVISION WORKSPACE_REVISION
  env CODEWIRE_SOURCE_REPO="$repo" MOCK_SOURCE="$active" MOCK_DAEMON_REVISION="$1" MOCK_WORKSPACE_REVISION="$2" \
    PATH="$TMPDIR_TEST/bin:$PATH" "$RESOLVER" --lock "$LOCK" --daemon-image "$DAEMON_IMAGE" --source-sha "$active"
}
output="$(resolve_at "$base" "$base")"
grep -Fx "source_sha=$active" <<<"$output" >/dev/null
expect_failure "workspace revision on a sibling branch" resolve_at "$active" "$sibling"
expect_failure "daemon revision on a sibling branch" resolve_at "$sibling" "$active"

printf 'CoCo support lock resolver tests passed\n'
