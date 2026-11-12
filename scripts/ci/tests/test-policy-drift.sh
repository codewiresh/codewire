#!/usr/bin/env bash
# Offline contract for the pre-merge policy drift check (#3821): the Pod
# builder, the check's verdicts, the token helper and the source clone, with
# fake deploy guards, a fake kyverno and a fake git. No network or credential.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BUILDER="$ROOT/scripts/ci/verify/kyverno-pods-from-goldens.py"
CHECK="$ROOT/scripts/ci/verify/check-policy-drift.sh"
TOKEN="$ROOT/scripts/ci/setup/fetch-forgejo-policy-drift-token.sh"
CLONE="$ROOT/scripts/ci/verify/clone-policy-drift-sources.sh"
GOLDENS="$ROOT/crates/codewire-orchestration/tests/fixtures/sandbox"
REGISTRY=registry.example.com

fail() {
  printf '[test-policy-drift] ERROR: %s\n' "$*" >&2
  exit 1
}

work="$(mktemp -d "${TMPDIR:-/tmp}/test-policy-drift.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

# A policy carrying only what the builder reads: the approved DinD images.
cat >"$work/policy.yaml" <<'EOF'
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: fixture
spec:
  rules:
  - name: enforce-baseline-except-approved-dind
    validate:
      podSecurity:
        exclude:
        - controlName: Privileged Containers
          images:
          - docker.io/library/docker:29.7.1-dind@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c
          - docker.io/library/docker:29.9.2-dind@sha256:9e79b879b177fbd72c34376a3dd3d91747da5db49e1f560f76aea59561471977
EOF

# --- the Pod builder ---
cases="$(python3 -I -B "$BUILDER" "$GOLDENS" "$work/policy.yaml" "$REGISTRY" "$work/pods")"
for name in pass-warm-pool-sandboxtemplate pass-warm-pool-subfolder-sandboxtemplate \
  pass-identity-free-sandboxtemplate pass-confidential-sandboxtemplate \
  deny-mount-registry deny-mount-renamed deny-mount-script deny-runc deny-dind-digest \
  deny-privileged-workspace; do
  grep -qw -- "$name" <<<"$cases" || fail "the builder made no $name case"
done
python3 -I - "$work/pods" "$REGISTRY" <<'PY'
import json, pathlib, re, sys
pods = pathlib.Path(sys.argv[1])
hosted = 0
for path in pods.glob("pass-*.json"):
    pod = json.loads(path.read_text())
    assert pod["metadata"]["namespace"] == "dev-sandboxes", path
    assert pod["metadata"]["labels"]["agents.x-k8s.io/sandbox-name-hash"], path
    for container in pod["spec"].get("initContainers", []) + pod["spec"]["containers"]:
        image = container["image"]
        assert "registry.example.invalid" not in image and not image.endswith(":golden"), (path, image)
        hosted += image.startswith(sys.argv[2] + "/codewire/")
        if container["name"] == "dind":
            # Each DinD image is the policy's approved image of its version.
            assert re.fullmatch(r"docker\.io/library/docker:29\.(7\.1|9\.2)-dind@sha256:(e8faad5a|9e79b879)[0-9a-f]{56}", image), image
# The placeholder registry becomes the configured hosted one.
assert hosted, "no image names the hosted registry"
warm = json.loads((pods / "deny-mount-script.json").read_text())
mount = next(c for c in warm["spec"]["initContainers"] if c["name"] == "mount-workspace")
assert mount["command"][-1] == "true"
PY

# A SandboxTemplate golden nobody classified, or a hosted one gone, is refused.
mkdir "$work/goldens"
cp "$GOLDENS"/*sandboxtemplate*.golden.json "$work/goldens/"
cp "$work/goldens/warm-pool-sandboxtemplate.golden.json" "$work/goldens/new-sandboxtemplate.golden.json"
python3 -I -B "$BUILDER" "$work/goldens" "$work/policy.yaml" "$REGISTRY" "$work/unknown" 2>"$work/err" &&
  fail 'an unclassified golden was accepted'
grep -q 'unclassified SandboxTemplate goldens: new-sandboxtemplate' "$work/err" || fail 'unclassified golden not named'
rm "$work/goldens/new-sandboxtemplate.golden.json" "$work/goldens/confidential-sandboxtemplate.golden.json"
python3 -I -B "$BUILDER" "$work/goldens" "$work/policy.yaml" "$REGISTRY" "$work/missing" 2>"$work/err" &&
  fail 'a missing hosted golden was accepted'
grep -q 'missing hosted SandboxTemplate goldens: confidential-sandboxtemplate' "$work/err" ||
  fail 'missing golden not named'
# A golden committed as a symlink names a file outside the tree: refused, not read.
mkdir "$work/linked"
cp "$GOLDENS"/*sandboxtemplate*.golden.json "$work/linked/"
printf '{"spec":{"podTemplate":{"spec":{"containers":[{"name":"runner-secret","image":"x"}]}}}}\n' >"$work/outside.json"
rm "$work/linked/confidential-sandboxtemplate.golden.json"
ln -s "$work/outside.json" "$work/linked/confidential-sandboxtemplate.golden.json"
python3 -I -B "$BUILDER" "$work/linked" "$work/policy.yaml" "$REGISTRY" "$work/linked-out" 2>"$work/err" &&
  fail 'a symlinked golden was read'
grep -q 'confidential-sandboxtemplate.golden.json is not a regular file of the tree' "$work/err" ||
  fail 'the symlinked golden is not named'
ln -s "$GOLDENS" "$work/linked-dir"
python3 -I -B "$BUILDER" "$work/linked-dir" "$work/policy.yaml" "$REGISTRY" "$work/linked-dir-out" 2>"$work/err" &&
  fail 'a symlinked goldens directory was read'
printf 'kind: ConfigMap\n' >"$work/no-dind.yaml"
python3 -I -B "$BUILDER" "$GOLDENS" "$work/no-dind.yaml" "$REGISTRY" "$work/nodind" 2>"$work/err" &&
  fail 'a policy approving no DinD image was accepted'
python3 -I -B "$BUILDER" "$GOLDENS" "$work/policy.yaml" "https://$REGISTRY/x" "$work/badregistry" 2>"$work/err" &&
  fail 'a registry that is not a host was accepted'
grep -q 'REGISTRY must be a registry host' "$work/err" || fail 'the bad registry is not named'

# --- the check's verdicts, with fake deploy guards and a fake kyverno ---
mkdir -p "$work/source" "$work/deploy/scripts" "$work/infra/clusters"
git -C "$work/source" init --quiet
mkdir -p "$work/source/crates/codewire-orchestration/tests/fixtures"
cp -R "$GOLDENS" "$work/source/crates/codewire-orchestration/tests/fixtures/sandbox"
for cluster in example-dev example-prod; do
  mkdir -p "$work/infra/clusters/$cluster/infrastructure/kyverno-policies"
  cp "$work/policy.yaml" "$work/infra/clusters/$cluster/infrastructure/kyverno-policies/sandbox-runtime-security.yaml"
done
cat >"$work/deploy/scripts/render.py" <<'PY'
import os, sys
assert sys.argv[1:] == ["check-source-policy", "--source-directory", sys.argv[3], "--deploy-directory", sys.argv[5]]
if os.environ.get("FAKE_GUARD_REFUSES"):
    print("render error: hosted policy refused the source:\n  dev: workloads: synthetic", file=sys.stderr)
    sys.exit(1)
print("hosted policy passed for every environment at hosted commit " + "a" * 40)
PY
# The fake kyverno refuses every deny-* case, admits every pass-* case, and
# flips one named case when told to.
cat >"$work/kyverno" <<'SH'
#!/usr/bin/env bash
case_file="$4"
name="$(basename "$case_file" .json)"
refused=0
[[ "$name" == deny-* ]] && refused=1
[[ "$name" == "${FAKE_FLIP:-}" ]] && refused=$((1 - refused))
[[ "$name" == "${FAKE_ERROR:-}" ]] && { echo 'pass: 0, fail: 0, warn: 0, error: 1, skip: 0'; exit 1; }
if [[ "$refused" -eq 1 ]]; then
  printf '1 - deny-privileged validation failure: synthetic\npass: 5, fail: 1, warn: 0, error: 0, skip: 0\n'
  exit 1
fi
echo 'pass: 6, fail: 0, warn: 0, error: 0, skip: 0'
SH
chmod +x "$work/kyverno"
run_check() {
  CODEWIRE_IMAGE_REGISTRY="${FAKE_REGISTRY-$REGISTRY}" \
    "$CHECK" "$work/source" "$work/deploy" "$work/infra" "$work/kyverno" >"$work/out" 2>&1
}

run_check || { cat "$work/out" >&2; fail 'a tree every policy admits failed'; }
grep -q 'passed: deploy guards and all 2 clusters admit this tree' "$work/out" || fail 'no pass line'
FAKE_REGISTRY='' run_check && fail 'a check with no registry passed'
grep -q 'CODEWIRE_IMAGE_REGISTRY is not set' "$work/out" || fail 'the missing registry is not named'

# The tree's goldens directory replaced by a link to elsewhere is refused.
mv "$work/source/crates/codewire-orchestration/tests/fixtures/sandbox" "$work/elsewhere"
ln -s "$work/elsewhere" "$work/source/crates/codewire-orchestration/tests/fixtures/sandbox"
run_check && fail 'a linked goldens directory passed'
grep -q 'not a directory of the tree under test' "$work/out" || fail 'the linked directory is not named'
rm "$work/source/crates/codewire-orchestration/tests/fixtures/sandbox"
mv "$work/elsewhere" "$work/source/crates/codewire-orchestration/tests/fixtures/sandbox"

FAKE_GUARD_REFUSES=1 run_check && fail 'a deploy guard refusal passed'
grep -q 'REFUSED by codewire/deploy' "$work/out" || fail 'the deploy refusal does not name deploy'

FAKE_FLIP=pass-confidential-sandboxtemplate run_check && fail 'an inadmissible Pod passed'
grep -q 'REFUSED by infrastructure clusters/example-dev/' "$work/out" || fail 'the infra refusal does not name the policy'
grep -q 'land the infra pull request' "$work/out" || fail 'the infra refusal gives no next step'

FAKE_FLIP=deny-mount-script run_check && fail 'an admitted control case passed'
grep -q 'admitted the control case deny-mount-script' "$work/out" || fail 'the control failure is not named'

FAKE_ERROR=pass-warm-pool-sandboxtemplate run_check && fail 'a kyverno error passed'
grep -q 'kyverno errored' "$work/out" || fail 'the kyverno error is not named'

# The clusters come from the infrastructure checkout. One policy is not Dev and
# Production, so the check refuses to pass on it.
mv "$work/infra/clusters/example-prod" "$work/example-prod"
run_check && fail 'a checkout with one sandbox policy passed'
grep -q 'has a sandbox policy for 1 clusters' "$work/out" || fail 'the missing cluster policy is not named'
mv "$work/example-prod" "$work/infra/clusters/example-prod"

# --- the token helper refuses until the integration has an audience ---
grep -q "^readonly audience=''$" "$TOKEN" && {
  ACTIONS_ID_TOKEN_REQUEST_URL='https://forgejo.invalid/x?y=1' ACTIONS_ID_TOKEN_REQUEST_TOKEN=abcdefghijklmnopqrstuvwxyz \
    "$TOKEN" "$work/token-out" 2>"$work/err" && fail 'the token helper ran with no audience'
  grep -q 'no recorded audience yet' "$work/err" || fail 'the missing audience is not named'
  [[ ! -e "$work/token-out" ]] || fail 'the token helper wrote a token with no audience'
}

# --- the source clone keeps no credential ---
cat >"$work/git" <<'SH'
#!/usr/bin/env bash
if [[ "$1" == clone ]]; then
  target="${!#}"
  printf '%s\n' "${@: -2:1}" >>"$CLONE_LOG"
  # The credential is only in the private configuration git was handed.
  grep -q 'extraHeader = Authorization: Bearer aaa.bbb.ccc' "$GIT_CONFIG_GLOBAL" || exit 9
  mkdir -p "$target/.git"
  [[ -n "${FAKE_LEAK:-}" ]] && printf 'leak\n' >"$target/.git/leaked"
  exit 0
fi
if [[ "$1" == -C && "$3" == config ]]; then
  [[ -e "$2/.git/leaked" ]] && { echo 'http.https://forge.example.com/.extraheader x'; exit 0; }
  exit 1
fi
if [[ "$1" == -C && "$3" == rev-parse ]]; then echo "$(printf 'b%.0s' {1..40})"; exit 0; fi
exit 3
SH
chmod +x "$work/git"
mkdir "$work/clones"
printf 'aaa.bbb.ccc\n' >"$work/jwt"
export GITHUB_SERVER_URL=https://forge.example.com CODEWIRE_POLICY_DRIFT_INFRA_REPOSITORY=example/infra
export CLONE_LOG="$work/clone-urls"
GIT_BIN="$work/git" "$CLONE" "$work/jwt" "$work/clones" >"$work/out" 2>&1 || { cat "$work/out" >&2; fail 'the clone failed'; }
[[ "$(cat "$CLONE_LOG")" == $'https://forge.example.com/codewire/deploy.git\nhttps://forge.example.com/example/infra.git' ]] ||
  fail "the clones did not come from the configured forge and repository: $(cat "$CLONE_LOG")"
[[ ! -e "$work/jwt" ]] || fail 'the token file survived the clone'
[[ -d "$work/clones/deploy/.git" && -d "$work/clones/infra/.git" ]] || fail 'both repositories were not cloned'
! grep -rq 'aaa.bbb.ccc' "$work/clones" || fail 'a clone holds the token'
mkdir "$work/leaky"
printf 'aaa.bbb.ccc\n' >"$work/jwt"
FAKE_LEAK=1 GIT_BIN="$work/git" "$CLONE" "$work/jwt" "$work/leaky" >"$work/out" 2>&1 && fail 'a clone that kept a credential passed'
grep -q 'kept a credential' "$work/out" || fail 'the kept credential is not named'
printf 'not-a-jwt\n' >"$work/jwt"
mkdir "$work/bad"
GIT_BIN="$work/git" "$CLONE" "$work/jwt" "$work/bad" >"$work/out" 2>&1 && fail 'a malformed token was used'
# With no infrastructure repository configured, nothing is read or cloned.
printf 'aaa.bbb.ccc\n' >"$work/jwt"
mkdir "$work/unconfigured"
CODEWIRE_POLICY_DRIFT_INFRA_REPOSITORY='' GIT_BIN="$work/git" "$CLONE" "$work/jwt" "$work/unconfigured" >"$work/out" 2>&1 &&
  fail 'a clone with no infrastructure repository ran'
grep -q 'CODEWIRE_POLICY_DRIFT_INFRA_REPOSITORY must be OWNER/NAME' "$work/out" || fail 'the missing repository is not named'
[[ -e "$work/jwt" ]] || fail 'an unconfigured clone consumed the token'

printf '[test-policy-drift] builder, verdicts, token and clone contracts passed\n'
