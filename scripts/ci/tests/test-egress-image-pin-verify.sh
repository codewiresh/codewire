#!/usr/bin/env bash
# The trusted cw-egress pin check (egress-image-pin.py verify) passes only the
# pinned digest of the delivered commit, with a main-CI-verified signature
# naming a source that commit contains, and fails closed on everything else:
# another digest, no pin, a missing or unsigned image, a signature from outside
# the commit's history, a verifier or git call that hangs, or malformed input.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT

fail() {
  printf '[test-egress-image-pin-verify] ERROR: %s\n' "$*" >&2
  exit 1
}

work="$(mktemp -d "${TMPDIR:-/tmp}/egress-image-pin-verify.XXXXXX")"
trap 'rm -rf "$work"' EXIT
DIGEST="sha256:$(printf 'a%.0s' {1..64})"
OTHER_DIGEST="sha256:$(printf 'b%.0s' {1..64})"

# A fixture repository with the real pin tool and a fake signature verifier at
# the path it calls.
repo="$work/repo"
git init -q -b main "$repo"
git -C "$repo" config user.name fixture
git -C "$repo" config user.email fixture@example.invalid
git -C "$repo" config commit.gpgsign false
mkdir -p "$repo/scripts/ci/images" "$repo/scripts/ci/trust" "$repo/deployments/k8s/egress"
install -m 755 "$ROOT/scripts/ci/images/egress-image-pin.py" "$repo/scripts/ci/images/"
install -m 644 "$ROOT/deployments/k8s/egress/kustomization.yaml" "$repo/deployments/k8s/egress/"
# The fixture starts from the component with no pin, whatever main pins now
# (#5550 pinned main's): its images block, always last, is cut off.
python3 - "$repo/deployments/k8s/egress/kustomization.yaml" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
path.write_text(path.read_text().split("\nimages:\n", 1)[0].rstrip("\n") + "\n")
PY
! grep -q '^images:' "$repo/deployments/k8s/egress/kustomization.yaml" || fail 'the fixture component still pins an image'
printf 'synthetic public key\n' >"$repo/scripts/ci/trust/codewire-runtime-signing.pub"
cat >"$repo/scripts/ci/images/verify-runtime-image-signatures.sh" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == --egress && $# -eq 3 ]] || exit 64
printf '%s\n' "$2" >>"${FAKE_VERIFY_CALLS:?}"
[[ -z "${FAKE_VERIFY_HANG:-}" ]] || exec sleep 30
[[ -n "${FAKE_SIGNED_SOURCES:-}" ]] || { echo 'no valid signature' >&2; exit 1; }
printf 'not a commit\n'
printf '%s\n' $FAKE_SIGNED_SOURCES
MOCK
chmod 0755 "$repo/scripts/ci/images/verify-runtime-image-signatures.sh"
git -C "$repo" add -A
git -C "$repo" commit -qm 'egress component with no pin'
unpinned="$(git -C "$repo" rev-parse HEAD)"
signed_source="$unpinned"
python3 "$repo/scripts/ci/images/egress-image-pin.py" render --digest "$DIGEST"
git -C "$repo" commit -qam 'pin the signed image'
pinned="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" switch -q -c side "$unpinned"
printf 'side\n' >"$repo/side.txt"
git -C "$repo" add -A
git -C "$repo" commit -qm 'a commit the pinned one does not contain'
side="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" switch -q main
foreign="$(printf '7%.0s' {1..40})"

export CODEWIRE_IMAGE_REGISTRY=registry.example.invalid
export FAKE_VERIFY_CALLS="$work/verify.calls"
verify() {
  : >"$FAKE_VERIFY_CALLS"
  python3 "$repo/scripts/ci/images/egress-image-pin.py" verify "$@"
}
refuse() {
  local name="$1" expected="$2"
  shift 2
  if verify "$@" >"$work/$name.out" 2>"$work/$name.err"; then
    fail "$name: the check passed"
  fi
  grep -Fq -- "$expected" "$work/$name.err" || fail "$name: the refusal does not say why: $(cat "$work/$name.err")"
}

# The pinned digest, signed by main CI from a source the commit contains, passes.
export FAKE_SIGNED_SOURCES="$foreign $side $signed_source"
verify --commit "$pinned" --digest "$DIGEST" >"$work/pass.out" 2>"$work/pass.err" ||
  fail "the pinned, signed digest was refused: $(cat "$work/pass.err")"
grep -Fq "signed by main CI from $signed_source" "$work/pass.out" || fail 'the accepted source is not named'
[[ "$(cat "$FAKE_VERIFY_CALLS")" == "registry.example.invalid/codewire/egress@$DIGEST" ]] ||
  fail "the verifier did not check exactly the delivered image: $(cat "$FAKE_VERIFY_CALLS")"

# Every other case fails closed and says why.
refuse other-digest "but $pinned pins $DIGEST" --commit "$pinned" --digest "$OTHER_DIGEST"
refuse no-pin 'pins no cw-egress image' --commit "$unpinned" --digest "$DIGEST"
FAKE_SIGNED_SOURCES='' refuse unsigned 'is missing or has no valid main-CI-verified signature' \
  --commit "$pinned" --digest "$DIGEST"
FAKE_SIGNED_SOURCES="$foreign $side" refuse outside 'names a source that' --commit "$pinned" --digest "$DIGEST"
refuse bad-digest 'not a sha256 digest' --commit "$pinned" --digest "${DIGEST%?}"
refuse tag 'not a sha256 digest' --commit "$pinned" --digest latest
refuse bad-commit 'not an exact commit' --commit "${pinned:0:12}" --digest "$DIGEST"
CODEWIRE_IMAGE_REGISTRY='' refuse no-registry 'not a registry host' --commit "$pinned" --digest "$DIGEST"
CODEWIRE_IMAGE_REGISTRY='registry.example.invalid/x' refuse bad-registry 'not a registry host' \
  --commit "$pinned" --digest "$DIGEST"
[[ ! -s "$FAKE_VERIFY_CALLS" ]] || fail 'malformed input reached the verifier'

# A hung verifier or git call is a refusal, not a traceback. The tool runs with
# the timeout of the call meant to hang (the verifier, or git merge-base) cut to
# one second, so the hang is real but short; every other call keeps its limit.
real_git="$(command -v git)"
mkdir -p "$work/hung-git"
cat >"$work/hung-git/git" <<MOCK
#!/usr/bin/env bash
for arg in "\$@"; do [[ "\$arg" == merge-base ]] && exec sleep 30; done
exec "$real_git" "\$@"
MOCK
chmod 0755 "$work/hung-git/git"
# hurried CALL ARGS...: run the tool with ARGS, cutting to one second only the
# timeout of the subprocess whose command line contains CALL.
hurried() {
  python3 - "$repo/scripts/ci/images/egress-image-pin.py" "$@" <<'PY'
import importlib.util, subprocess, sys
tool_path, call, *args = sys.argv[1:]
spec = importlib.util.spec_from_file_location("egress_image_pin", tool_path)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
run = subprocess.run
subprocess.run = lambda command, *a, timeout, **k: run(
    command, *a, timeout=1 if call in " ".join(command) else timeout, **k)
raise SystemExit(tool.main(args))
PY
}
for hang in 'verifier verify-runtime-image-signatures.sh --egress' 'git merge-base --is-ancestor'; do
  expected="${hang#* }" hang="${hang%% *}"
  : >"$FAKE_VERIFY_CALLS"
  if [[ "$hang" == verifier ]]; then
    FAKE_VERIFY_HANG=1 hurried "$expected" verify --commit "$pinned" --digest "$DIGEST" >"$work/hang.out" 2>"$work/hang.err" &&
      fail "hung $hang: the check passed"
  else
    PATH="$work/hung-git:$PATH" hurried "$expected" verify --commit "$pinned" --digest "$DIGEST" \
      >"$work/hang.out" 2>"$work/hang.err" && fail "hung $hang: the check passed"
  fi
  grep -q "$expected.* took over [0-9]* s$" "$work/hang.err" || fail "hung $hang: the refusal does not say why: $(cat "$work/hang.err")"
  ! grep -Fq Traceback "$work/hang.err" || fail "hung $hang: a traceback, not a refusal"
done

printf '[test-egress-image-pin-verify] the trusted pin check passes only a pinned, main-CI-signed digest\n'
