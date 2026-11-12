#!/usr/bin/env bash
# The pre-merge policy drift check (#3821): a Codewire tree against the
# boundaries other repositories own, before it merges, so a change one of them
# would refuse fails here and not at the next promotion or admission:
#   1. deploy main's hosted guards (render.py check-source-policy);
#   2. the sandbox Kyverno policy of every cluster the infrastructure
#      repository gives one, over the Pods the tree's sandbox goldens render
#      (kyverno-pods-from-goldens.py, beside this script). There must be at
#      least two, Dev and Production; this tree does not name them.
#
# SOURCE is a clean git checkout of the tree under test and is only read: the
# Pod builder is this script's sibling, never the tree's copy, and render.py
# refuses Kustomize inputs that are not local. DEPLOY and INFRA are checkouts of
# codewire/deploy main with full history and of the infrastructure
# repository's main, and KYVERNO the pinned CLI. CODEWIRE_IMAGE_REGISTRY is the
# hosted image registry a real render names.
#
# Usage: check-policy-drift.sh SOURCE DEPLOY INFRA KYVERNO
set -euo pipefail

fail() {
  printf '[check-policy-drift] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 4 ]] || {
  printf 'usage: check-policy-drift.sh SOURCE DEPLOY INFRA KYVERNO\n' >&2
  exit 2
}
readonly source_tree="$1" deploy="$2" infra="$3" kyverno="$4"
readonly registry="${CODEWIRE_IMAGE_REGISTRY:-}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly here
readonly goldens="$source_tree/crates/codewire-orchestration/tests/fixtures/sandbox"

[[ -d "$source_tree/.git" || -f "$source_tree/.git" ]] || fail 'SOURCE must be a git checkout'
[[ -f "$deploy/scripts/render.py" ]] || fail 'DEPLOY must be a codewire/deploy checkout'
[[ -x "$kyverno" ]] || fail 'KYVERNO must be the pinned kyverno CLI'
[[ -n "$registry" ]] || fail 'CODEWIRE_IMAGE_REGISTRY is not set'
# The goldens are read from a pull request's tree: their directory must be
# that exact path in it, not a link to somewhere else on the runner. The
# builder opens each golden without following links.
[[ "$(realpath -e "$goldens")" == "$(realpath -e "$source_tree")/crates/codewire-orchestration/tests/fixtures/sandbox" ]] ||
  fail 'the sandbox goldens directory is not a directory of the tree under test'

work="$(mktemp -d "${TMPDIR:-/tmp}/check-policy-drift.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

# The Pods land in dev-sandboxes, which both clusters label as a shared
# sandbox namespace; that label is what selects the policy's rules.
cat >"$work/values.yaml" <<'VALUES'
apiVersion: cli.kyverno.io/v1alpha1
kind: Value
metadata:
  name: values
namespaceSelector:
- name: dev-sandboxes
  labels:
    codewire.sh/runtime-scope: shared
VALUES

failed=0

printf '[check-policy-drift] deploy hosted guards (codewire/deploy main)\n'
if ! python3 -I -B "$deploy/scripts/render.py" check-source-policy \
  --source-directory "$source_tree" --deploy-directory "$deploy"; then
  printf '[check-policy-drift] REFUSED by codewire/deploy scripts/hosted_policy: land the deploy pull request that admits this change first, then rerun.\n' >&2
  failed=1
fi

clusters=()
for policy in "$infra"/clusters/*/infrastructure/kyverno-policies/sandbox-runtime-security.yaml; do
  [[ -f "$policy" ]] || continue
  cluster="${policy#"$infra"/clusters/}"
  clusters+=("${cluster%%/*}")
done
[[ "${#clusters[@]}" -ge 2 ]] ||
  fail "the infrastructure repository has a sandbox policy for ${#clusters[@]} clusters; Dev and Production each need one"

for cluster in "${clusters[@]}"; do
  policy="$infra/clusters/$cluster/infrastructure/kyverno-policies/sandbox-runtime-security.yaml"
  printf '[check-policy-drift] %s sandbox Kyverno policy (infrastructure main)\n' "$cluster"
  pods="$work/$cluster"
  python3 -I -B "$here/kyverno-pods-from-goldens.py" "$goldens" "$policy" "$registry" "$pods" >/dev/null ||
    fail "cannot build Pods from the sandbox goldens for $cluster"
  for case in "$pods"/*.json; do
    name="$(basename "$case" .json)"
    output="$("$kyverno" apply "$policy" --resource "$case" --values-file "$work/values.yaml" 2>&1 || true)"
    summary="$(grep -oE 'pass: [0-9]+, fail: [0-9]+, warn: [0-9]+, error: [0-9]+, skip: [0-9]+' <<<"$output" | tail -n 1)"
    [[ -n "$summary" ]] || fail "kyverno gave no result for $cluster/$name"
    read -r passed refused errors < <(sed -E 's/pass: ([0-9]+), fail: ([0-9]+), warn: [0-9]+, error: ([0-9]+).*/\1 \2 \3/' <<<"$summary")
    [[ "$errors" -eq 0 ]] || fail "kyverno errored on $cluster/$name"
    case "$name" in
      pass-*)
        if [[ "$refused" -ne 0 || "$passed" -eq 0 ]]; then
          printf '[check-policy-drift] REFUSED by infrastructure %s: %s is not admitted:\n%s\n' \
            "${policy#"$infra"/}" "${name#pass-}" "$(grep -E '^[0-9]+ - ' <<<"$output")" >&2
          printf '[check-policy-drift] land the infra pull request that admits this change first, then rerun.\n' >&2
          failed=1
        fi
        ;;
      deny-*)
        # A mutation the policy admits means the CLI is not evaluating it:
        # the check proves nothing, so it fails rather than passing.
        [[ "$refused" -gt 0 ]] || fail "$cluster admitted the control case $name; the policy evaluation is not trustworthy"
        ;;
      *) fail "unexpected case $name" ;;
    esac
  done
done

[[ "$failed" -eq 0 ]] || exit 1
printf '[check-policy-drift] passed: deploy guards and all %d clusters admit this tree\n' "${#clusters[@]}"
