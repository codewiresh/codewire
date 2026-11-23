#!/usr/bin/env bash
# The standard pod-runtime image pin (pod-runtime-image-pin.py, #5602): the pin
# file holds `unpinned` or one digest, render writes only a digest, and the
# trusted verify passes only the pinned digest of the delivered commit with a
# main-CI-verified pod-runtime signature naming a source that commit contains.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT

fail() {
  printf '[test-pod-runtime-image-pin] ERROR: %s\n' "$*" >&2
  exit 1
}

work="$(mktemp -d "${TMPDIR:-/tmp}/pod-runtime-image-pin.XXXXXX")"
trap 'rm -rf "$work"' EXIT
DIGEST="sha256:$(printf 'a%.0s' {1..64})"
OTHER_DIGEST="sha256:$(printf 'b%.0s' {1..64})"

# A fixture repository with the real pin tools (the pod-runtime pin reuses the
# egress pin's helpers) and a fake signature verifier at the path they call.
repo="$work/repo"
git init -q -b main "$repo"
git -C "$repo" config user.name fixture
git -C "$repo" config user.email fixture@example.invalid
git -C "$repo" config commit.gpgsign false
mkdir -p "$repo/scripts/ci/images" "$repo/scripts/ci/trust" "$repo/deployments/k8s/orchestration"
install -m 755 "$ROOT/scripts/ci/images/pod-runtime-image-pin.py" "$ROOT/scripts/ci/images/egress-image-pin.py" \
  "$repo/scripts/ci/images/"
install -m 644 "$ROOT/deployments/k8s/orchestration/pod-runtime-image.digest" "$repo/deployments/k8s/orchestration/"
[[ "$(cat "$repo/deployments/k8s/orchestration/pod-runtime-image.digest")" == unpinned ]] ||
  fail 'main already pins a pod-runtime image; start the fixture from unpinned'
printf 'synthetic public key\n' >"$repo/scripts/ci/trust/codewire-runtime-signing.pub"
cat >"$repo/scripts/ci/images/verify-runtime-image-signatures.sh" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == --pod-runtime && $# -eq 3 ]] || exit 64
printf '%s\n' "$2" >>"${FAKE_VERIFY_CALLS:?}"
[[ -n "${FAKE_SIGNED_SOURCES:-}" ]] || { echo 'no valid signature' >&2; exit 1; }
printf 'not a commit\n'
printf '%s\n' $FAKE_SIGNED_SOURCES
MOCK
chmod 0755 "$repo/scripts/ci/images/verify-runtime-image-signatures.sh"
tool="$repo/scripts/ci/images/pod-runtime-image-pin.py"
git -C "$repo" add -A
git -C "$repo" commit -qm 'no pod-runtime pin'
unpinned="$(git -C "$repo" rev-parse HEAD)"
python3 "$tool" check || fail 'the unpinned file failed its check'
[[ -z "$(python3 "$tool" show --commit "$unpinned")" ]] || fail 'an unpinned commit showed a digest'

# render writes exactly one digest line, and only a digest.
python3 "$tool" render --digest "$DIGEST"
[[ "$(cat "$repo/deployments/k8s/orchestration/pod-runtime-image.digest")" == "$DIGEST" ]] ||
  fail 'render did not write the digest'
python3 "$tool" check || fail 'a rendered pin failed its check'
if python3 "$tool" render --digest latest 2>/dev/null; then fail 'render accepted a tag'; fi
git -C "$repo" commit -qam 'pin the signed image'
pinned="$(git -C "$repo" rev-parse HEAD)"
[[ "$(python3 "$tool" show --commit "$pinned")" == "$DIGEST" ]] || fail 'show did not read the pin'
for bad in "$DIGEST"$'\n'"$DIGEST" 'sha256:abc' "${DIGEST^^}" ''; do
  printf '%s\n' "$bad" >"$repo/deployments/k8s/orchestration/pod-runtime-image.digest"
  if python3 "$tool" check 2>/dev/null; then fail "check accepted a pin of: $bad"; fi
done
git -C "$repo" checkout -q -- deployments/k8s/orchestration/pod-runtime-image.digest

git -C "$repo" switch -q -c side "$unpinned"
printf 'side\n' >"$repo/side.txt"
git -C "$repo" add -A
git -C "$repo" commit -qm 'a commit the pinned one does not contain'
side="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" switch -q main

export CODEWIRE_IMAGE_REGISTRY=registry.example.invalid
export FAKE_VERIFY_CALLS="$work/verify.calls"
verify() {
  : >"$FAKE_VERIFY_CALLS"
  python3 "$tool" verify "$@"
}
refuse() {
  local name="$1" expected="$2"
  shift 2
  if verify "$@" >"$work/$name.out" 2>"$work/$name.err"; then
    fail "$name: the check passed"
  fi
  grep -Fq -- "$expected" "$work/$name.err" || fail "$name: the refusal does not say why: $(cat "$work/$name.err")"
}

export FAKE_SIGNED_SOURCES="$side $unpinned"
verify --commit "$pinned" --digest "$DIGEST" >"$work/pass.out" 2>"$work/pass.err" ||
  fail "the pinned, signed digest was refused: $(cat "$work/pass.err")"
grep -Fq "signed by main CI from $unpinned" "$work/pass.out" || fail 'the accepted source is not named'
[[ "$(cat "$FAKE_VERIFY_CALLS")" == "registry.example.invalid/codewire/pod-runtime@$DIGEST" ]] ||
  fail "the verifier did not check exactly the delivered image: $(cat "$FAKE_VERIFY_CALLS")"

refuse other-digest "but $pinned pins $DIGEST" --commit "$pinned" --digest "$OTHER_DIGEST"
refuse no-pin 'pins no pod-runtime image' --commit "$unpinned" --digest "$DIGEST"
FAKE_SIGNED_SOURCES='' refuse unsigned 'is missing or has no valid main-CI-verified signature' \
  --commit "$pinned" --digest "$DIGEST"
FAKE_SIGNED_SOURCES="$side" refuse outside 'names a source that' --commit "$pinned" --digest "$DIGEST"
refuse bad-digest 'not a sha256 digest' --commit "$pinned" --digest "${DIGEST%?}"
refuse bad-commit 'not an exact commit' --commit "${pinned:0:12}" --digest "$DIGEST"
CODEWIRE_IMAGE_REGISTRY='' refuse no-registry 'not a registry host' --commit "$pinned" --digest "$DIGEST"
[[ ! -s "$FAKE_VERIFY_CALLS" ]] || fail 'malformed input reached the verifier'

printf '[test-pod-runtime-image-pin] the pin holds one digest and verify passes only a pinned, main-CI-signed one\n'
