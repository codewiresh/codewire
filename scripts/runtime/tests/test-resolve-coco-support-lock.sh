#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RESOLVER="$ROOT/scripts/runtime/confidential/resolve-coco-support-lock.sh"
LOCK="$ROOT/deployments/k8s/runtime-profiles/confidential/coco-support-images.lock.json"
SOURCE_SHA="c0a265c6eb6cea7353a632b92e7c5819f0629583"
GATEWAY_IMAGE="registry.example.invalid/codewire/gateway@sha256:b606b5e4b119c4117b9163943702ff3fcea56d1c0e2f85a6ad3bf2ffa3dfc1c1"
mkdir -p "$ROOT/.tmp"
TMPDIR_TEST="$(mktemp -d "$ROOT/.tmp/codewire-coco-support-lock.XXXXXX")"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

mkdir -p "$TMPDIR_TEST/bin"
cat >"$TMPDIR_TEST/bin/skopeo" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

case "$*" in
  *'ghcr.io/codewiresh/gateway@sha256:b606b5e4b119c4117b9163943702ff3fcea56d1c0e2f85a6ad3bf2ffa3dfc1c1'*)
    printf '{"Digest":"sha256:b606b5e4b119c4117b9163943702ff3fcea56d1c0e2f85a6ad3bf2ffa3dfc1c1","Labels":{"org.opencontainers.image.revision":"%s"}}\n' "${MOCK_GATEWAY_REVISION:-c0a265c6eb6cea7353a632b92e7c5819f0629583}"
    ;;
  *'ghcr.io/codewiresh/workspace:c0a265c6eb6cea7353a632b92e7c5819f0629583'*)
    printf '{"Digest":"sha256:7645bc90934a603724751a2363657933f673eaf469857e64e3462c7042fd1808","Labels":{"org.opencontainers.image.revision":"%s"}}\n' "${MOCK_WORKSPACE_REVISION:-c0a265c6eb6cea7353a632b92e7c5819f0629583}"
    ;;
  *'docker.io/library/docker@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c'*)
    printf '%s\n' '{"Digest":"sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c","Labels":{}}'
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
    --gateway-image "$GATEWAY_IMAGE" \
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
grep -Fx "gateway_image=$GATEWAY_IMAGE" <<<"$output" >/dev/null
grep -Fx 'gateway_public_image=ghcr.io/codewiresh/gateway@sha256:b606b5e4b119c4117b9163943702ff3fcea56d1c0e2f85a6ad3bf2ffa3dfc1c1' <<<"$output" >/dev/null
grep -Fx 'workspace_image=ghcr.io/codewiresh/workspace@sha256:7645bc90934a603724751a2363657933f673eaf469857e64e3462c7042fd1808' <<<"$output" >/dev/null
grep -Fx 'dind_image=docker.io/library/docker:29.7.1-dind@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c' <<<"$output" >/dev/null

jq '.images.dind = "docker.io/library/docker:29.7.1-dind@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' "$LOCK" >"$TMPDIR_TEST/wrong-digest.json"
expect_failure "resolved dind digest mismatch" run_resolver "$TMPDIR_TEST/wrong-digest.json"

expect_failure "gateway revision mismatch" env MOCK_GATEWAY_REVISION=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa PATH="$TMPDIR_TEST/bin:$PATH" "$RESOLVER" --lock "$LOCK" --gateway-image "$GATEWAY_IMAGE" --source-sha "$SOURCE_SHA"
expect_failure "workspace revision mismatch" env MOCK_WORKSPACE_REVISION=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa PATH="$TMPDIR_TEST/bin:$PATH" "$RESOLVER" --lock "$LOCK" --gateway-image "$GATEWAY_IMAGE" --source-sha "$SOURCE_SHA"

printf 'CoCo support lock resolver tests passed\n'
