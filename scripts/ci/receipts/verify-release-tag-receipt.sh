#!/usr/bin/env bash
# Permit a release tag push to reuse successful exact-main CI. Every
# uncertainty returns a fallback receipt so pre-push can run its full gate.
set -euo pipefail

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

receipt='fallback'
reason='unverified'
run_id=''
dev_run_id=''

emit_outputs() {
  printf 'release_tag_receipt=%s\nrelease_tag_reason=%s\nrelease_tag_run=%s\nrelease_tag_dev_acceptance_run=%s\n' \
    "$receipt" "$reason" "$run_id" "$dev_run_id"
}

fallback() {
  reason="$1"
  printf 'release-tag receipt: full local verification required (%s)\n' "$reason" >&2
  emit_outputs
  exit 0
}

tag_ref="${PREFLIGHT_RELEASE_TAG_REF:-}"
tag_object="${PREFLIGHT_RELEASE_TAG_OBJECT_SHA:-}"
remote="${PREFLIGHT_PUSH_REMOTE_NAME:-}"

[[ "$tag_ref" =~ ^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || fallback 'invalid-release-tag-ref'
[[ "$tag_object" =~ ^[0-9a-f]{40}$ ]] || fallback 'invalid-tag-object-sha'
[ -n "$remote" ] || fallback 'push-remote-unavailable'

for required_tool in git jq fj; do
  command -v "$required_tool" >/dev/null 2>&1 \
    || fallback "${required_tool}-unavailable"
done

remote_url="$(git remote get-url "$remote" 2>/dev/null)" \
  || fallback 'push-remote-unavailable'
case "$remote_url" in
  git@git.example.invalid:codewire/codewire.git|ssh://git@git.example.invalid/codewire/codewire.git|https://git.example.invalid/codewire/codewire.git)
    ;;
  *) fallback 'push-remote-not-canonical-gitea' ;;
esac

resolved_object="$(git rev-parse --verify "$tag_ref" 2>/dev/null)" \
  || fallback 'release-tag-unavailable'
[ "$resolved_object" = "$tag_object" ] || fallback 'release-tag-object-mismatch'
[ "$(git cat-file -t "$tag_object" 2>/dev/null)" = tag ] \
  || fallback 'release-tag-not-annotated'
git verify-tag "$tag_object" >/dev/null 2>&1 \
  || fallback 'release-tag-signature-invalid'
tag_commit="$(git rev-parse --verify "${tag_object}^{commit}" 2>/dev/null)" \
  || fallback 'release-tag-commit-unavailable'

main_lines="$tmp/main-lines"
git ls-remote "$remote" refs/heads/main >"$main_lines" 2>/dev/null \
  || fallback 'canonical-main-unavailable'
[ "$(wc -l <"$main_lines")" -eq 1 ] || fallback 'canonical-main-ambiguous'
read -r main_sha main_ref <"$main_lines"
[[ "$main_sha" =~ ^[0-9a-f]{40}$ ]] && [ "$main_ref" = refs/heads/main ] \
  || fallback 'canonical-main-invalid'
[ "$tag_commit" = "$main_sha" ] || fallback 'release-tag-not-current-main'

# Forgejo evidence comes from the supported fj CLI. Main CI must be the
# latest exact-main push run of ci.yaml with a green Required verification
# job. Dev evidence is read from the deploy-owned promotion itself: a green
# promote-dev run whose release commit job and acceptance job both checked
# out this exact source.
runs_json="$tmp/runs.json"
fj actions runs list -R "$remote" --head "$main_sha" --workflow ci.yaml \
  --event push -L 50 --output json >"$runs_json" 2>/dev/null \
  || fallback 'exact-main-runs-unavailable'
jq -e '.schema_version == 1 and (.runs | type == "array")' \
  "$runs_json" >/dev/null 2>&1 || fallback 'exact-main-runs-ambiguous'
if ! run_id="$(jq -er --arg head "$main_sha" '
    [
      .runs[]
      | select(
          .head_sha == $head
          and .workflow == "ci.yaml"
          and .event == "push"
          and .ref == "main"
        )
    ]
    | sort_by(.id)
    | last
    | select(.status == "success")
    | .id
    | select(type == "number" and . > 0)
    | tostring
  ' "$runs_json")"; then
  fallback 'exact-main-ci-not-successful'
fi

run_view="$tmp/run-view.json"
fj actions runs view "$run_id" -R "$remote" --output json >"$run_view" 2>/dev/null \
  || fallback 'exact-main-jobs-unavailable'
if ! jq -e --arg head "$main_sha" --argjson id "$run_id" '
    .schema_version == 1
    and .run.id == $id
    and .run.head_sha == $head
    and .run.workflow == "ci.yaml"
    and .run.event == "push"
    and .run.status == "success"
    and ([.jobs[] | select(.name == "Required verification")]
      | length == 1 and .[0].status == "success")
  ' "$run_view" >/dev/null 2>&1; then
  fallback 'required-verification-not-successful'
fi

deploy_repo=(-r codewire/deploy -H git.example.invalid)
deploy_runs="$tmp/deploy-runs.json"
fj actions runs list "${deploy_repo[@]}" --workflow promote-dev.yaml \
  --status success -L 30 --output json >"$deploy_runs" 2>/dev/null \
  || fallback 'dev-acceptance-runs-unavailable'
jq -e '.schema_version == 1 and (.runs | type == "array")' \
  "$deploy_runs" >/dev/null 2>&1 || fallback 'dev-acceptance-runs-ambiguous'
# Both the release commit job and the acceptance job check out the exact
# source they use; the workflow requires the smoke source to equal the
# promoted runtime source. Re-dispatches of an existing release keep both.
checkout_line="^[0-9T:.-]+Z Checked out exact Codewire source ${main_sha}\$"
while read -r candidate; do
  [[ "$candidate" =~ ^[1-9][0-9]*$ ]] || continue
  view="$tmp/deploy-view-$candidate.json"
  fj actions runs view "$candidate" "${deploy_repo[@]}" --output json \
    >"$view" 2>/dev/null || continue
  jq -e --argjson id "$candidate" '
      .schema_version == 1
      and .run.id == $id
      and .run.workflow == "promote-dev.yaml"
      and .run.ref == "main"
      and .run.status == "success"
      and (.jobs | length > 0)
      and all(.jobs[]; .status == "success")
      and ([.jobs[] | select(.name == "Commit one complete dev release")] | length == 1)
      and ([.jobs[] | select(.name == "Run exact-source Dev acceptance smokes")] | length == 1)
    ' "$view" >/dev/null 2>&1 || continue
  commit_job="$(jq -r '.jobs[] | select(.name == "Commit one complete dev release") | .id' "$view")"
  acceptance_job="$(jq -r '.jobs[] | select(.name == "Run exact-source Dev acceptance smokes") | .id' "$view")"
  [[ "$commit_job" =~ ^[1-9][0-9]*$ && "$acceptance_job" =~ ^[1-9][0-9]*$ ]] || continue
  # Read each whole log into a file before matching. A pipeline ending in
  # grep -q can stop reading early and fail the writer under pipefail.
  job_log="$tmp/deploy-$candidate-job.log"
  job_text="$tmp/deploy-$candidate-job.txt"
  proven=true
  for job in "$commit_job" "$acceptance_job"; do
    if ! fj actions runs logs "$candidate" "${deploy_repo[@]}" --job "$job" \
        >"$job_log" 2>/dev/null \
      || ! tr -d '\r' <"$job_log" >"$job_text" \
      || ! grep -Eq "$checkout_line" "$job_text"; then
      proven=false
      break
    fi
  done
  [ "$proven" = true ] || continue
  dev_run_id="$candidate"
  break
done < <(jq -r '
    [.runs[] | select(.workflow == "promote-dev.yaml" and .status == "success") | .id]
    | sort | reverse | .[]
  ' "$deploy_runs")
[ -n "$dev_run_id" ] || fallback 'exact-source-dev-acceptance-not-successful'

receipt='accepted'
reason='signed-tag-at-exact-green-deployed-main'
printf 'release-tag receipt: %s peels to green canonical main %s (CI run %s; Dev acceptance run %s)\n' \
  "$tag_ref" "$main_sha" "$run_id" "$dev_run_id"
emit_outputs
