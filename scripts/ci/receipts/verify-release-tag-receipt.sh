#!/usr/bin/env bash
# Permit a release tag push to reuse successful exact-commit main CI. The
# tagged commit is canonical main or an ancestor of it, so main may move on
# while a release is cut. It also needs a green Kind run and a green release
# dry run of the exact commit, which a push to main may defer to a dispatch or
# the schedule. Every uncertainty returns a fallback receipt so pre-push can
# run its full gate.
set -euo pipefail

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

receipt='fallback'
reason='unverified'
run_id=''
kind_run_id=''
dry_run_id=''
dev_run_id=''

emit_outputs() {
  printf 'release_tag_receipt=%s\nrelease_tag_reason=%s\nrelease_tag_run=%s\n' \
    "$receipt" "$reason" "$run_id"
  printf 'release_tag_kind_run=%s\nrelease_tag_dry_run=%s\nrelease_tag_dev_acceptance_run=%s\n' \
    "$kind_run_id" "$dry_run_id" "$dev_run_id"
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

# The canonical forge is GITHUB_SERVER_URL, set in every Forgejo job; a local
# tag push sets it to the same Forgejo base URL.
server_url="${GITHUB_SERVER_URL:-}"
server_url="${server_url%/}"
[[ "$server_url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] \
  || fallback 'GITHUB_SERVER_URL-unset-or-invalid'
forge_host="${server_url#https://}"

for required_tool in git jq fj; do
  command -v "$required_tool" >/dev/null 2>&1 \
    || fallback "${required_tool}-unavailable"
done

remote_url="$(git remote get-url "$remote" 2>/dev/null)" \
  || fallback 'push-remote-unavailable'
case "$remote_url" in
  "git@$forge_host:codewire/codewire.git"|"ssh://git@$forge_host/codewire/codewire.git"|"https://$forge_host/codewire/codewire.git")
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
# The tag names canonical main or a commit main already contains.
if [ "$tag_commit" != "$main_sha" ]; then
  if ! git cat-file -e "${main_sha}^{commit}" 2>/dev/null; then
    git fetch --quiet --no-tags "$remote" refs/heads/main >/dev/null 2>&1 \
      || fallback 'canonical-main-commit-unavailable'
    git cat-file -e "${main_sha}^{commit}" 2>/dev/null \
      || fallback 'canonical-main-commit-unavailable'
  fi
  git merge-base --is-ancestor "$tag_commit" "$main_sha" 2>/dev/null \
    || fallback 'release-tag-not-on-canonical-main'
fi

# Forgejo evidence comes from the supported fj CLI. Main CI must be the
# tagged commit's latest push run of ci.yaml on main, with a green Required
# verification job, and it must have verified: a run that started after main
# moved on is superseded, dispatches no capability group and still reports
# green. A scheduled run that a push to main registered is listed with event
# push too; its selection log says classification=scheduled, and it is never
# the push run. While a push to main defers Kind and the release dry run
# (owner decision 2026-10-20, scripts/ci/select/main-push-switch.sh), the
# exact commit also needs a green Kind run of ci.yaml and a green four-target
# dry run, from a push, a dispatch or a schedule. Dev evidence is read from
# the deploy-owned promotion itself: a green promote-dev run whose release
# commit job and acceptance job both checked out this exact source.
runs_json="$tmp/runs.json"
fj actions runs list -R "$remote" --head "$tag_commit" --workflow ci.yaml \
  -L 50 --output json >"$runs_json" 2>/dev/null \
  || fallback 'exact-main-runs-unavailable'
jq -e '.schema_version == 1 and (.runs | type == "array")' \
  "$runs_json" >/dev/null 2>&1 || fallback 'exact-main-runs-ambiguous'

# view_run RUN FILE: the run and its jobs, read once into FILE.
view_run() {
  local run="$1" file="$2"
  [ -s "$file" ] && return 0
  fj actions runs view "$run" -R "$remote" --output json >"$file" 2>/dev/null
}

# job_log RUN VIEW NAME FILE: the whole log of the run's one job called NAME,
# carriage returns removed. Read into a file before matching: a pipeline
# ending in grep -q can stop reading early and fail the writer under pipefail.
job_log() {
  local run="$1" view="$2" name="$3" file="$4" job
  job="$(jq -r --arg name "$name" '
      [.jobs[] | select(.name == $name)] | select(length == 1) | .[0].id
    ' "$view")"
  [[ "$job" =~ ^[1-9][0-9]*$ ]] || return 1
  fj actions runs logs "$run" -R "$remote" --job "$job" >"$file.raw" 2>/dev/null || return 1
  tr -d '\r' <"$file.raw" >"$file"
}

# The latest push run: the newest run listed with event push whose selection
# log does not show a scheduled run.
run_view=''
selection_log=''
while read -r candidate; do
  [[ "$candidate" =~ ^[1-9][0-9]*$ ]] || continue
  candidate_view="$tmp/ci-view-$candidate.json"
  view_run "$candidate" "$candidate_view" || fallback 'exact-main-jobs-unavailable'
  candidate_log="$tmp/ci-selection-$candidate.log"
  job_log "$candidate" "$candidate_view" 'Verification selection' "$candidate_log" \
    || fallback 'exact-main-selection-unavailable'
  if grep -Eq '^[0-9T:.-]+Z classification=scheduled$' "$candidate_log"; then
    continue
  fi
  run_id="$candidate"
  run_view="$candidate_view"
  selection_log="$candidate_log"
  break
done < <(jq -r --arg head "$tag_commit" '
    [
      .runs[]
      | select(
          .head_sha == $head
          and .workflow == "ci.yaml"
          and .event == "push"
          and .ref == "main"
          and (.id | type == "number" and . > 0)
        )
      | .id
    ]
    | sort | reverse | .[]
  ' "$runs_json")
[ -n "$run_id" ] || fallback 'exact-main-ci-not-successful'
jq -e --arg id "$run_id" '
    [.runs[] | select((.id | tostring) == $id)] | length == 1 and .[0].status == "success"
  ' "$runs_json" >/dev/null 2>&1 || fallback 'exact-main-ci-not-successful'

if ! jq -e --arg head "$tag_commit" --argjson id "$run_id" '
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

# Not superseded: the selection job's own log is readable (it records the
# selection it made) and names no superseding commit.
grep -Eq '^[0-9T:.-]+Z selection=\|valid:v3\|' "$selection_log" \
  || fallback 'exact-main-selection-unavailable'
if grep -Eq "^[0-9T:.-]+Z (superseded by [0-9a-f]{40}: main's queued run verifies|superseded main commit: no capability group is dispatched)" \
    "$selection_log"; then
  fallback 'exact-main-ci-superseded'
fi
# And it verified: a selected capability group ran green, or Required
# verification accepted the exact tree an earlier PR run verified.
if ! jq -e '
    [.jobs[]
      | select(.status == "success")
      | select(
          (.name | IN(
            "CW release-assets verification", "Container contract verification",
            "Policy verification", "Standard verification",
            "Tooling / delivery contract verification", "Compile every Rust target",
            "Rust / transport packages", "Rust / transport feature graphs",
            "Rust / transport verification", "Database verification",
            "Service control-plane verification", "Service runtime-plane verification"))
          or (.name | startswith("Edge / Kind verification ("))
        )]
    | length > 0
  ' "$run_view" >/dev/null 2>&1; then
  required_log="$tmp/required.log"
  if ! { job_log "$run_id" "$run_view" 'Required verification' "$required_log" \
      && grep -Eq '^[0-9T:.-]+Z required verification: exact tested tree from PR #[1-9][0-9]* run [1-9][0-9]* accepted$' \
        "$required_log"; }; then
    fallback 'exact-main-ci-verified-nothing'
  fi
fi

# successful_runs FILE WORKFLOW: the exact commit's successful runs of
# WORKFLOW on main from a push, a dispatch or a schedule, newest first.
successful_runs() {
  jq -r --arg head "$tag_commit" --arg workflow "$2" '
      [
        .runs[]
        | select(
            .head_sha == $head
            and .workflow == $workflow
            and (.event | IN("push", "workflow_dispatch", "schedule"))
            and .ref == "main"
            and .status == "success"
            and (.id | type == "number" and . > 0)
          )
        | .id
      ]
      | sort | reverse | .[]
    ' "$1"
}

# Kind: a successful ci.yaml run of the exact commit in which at least one
# Edge / Kind verification shard ran and every shard that ran succeeded.
while read -r candidate; do
  [[ "$candidate" =~ ^[1-9][0-9]*$ ]] || continue
  candidate_view="$tmp/ci-view-$candidate.json"
  view_run "$candidate" "$candidate_view" || continue
  jq -e --arg head "$tag_commit" --argjson id "$candidate" '
      .schema_version == 1
      and .run.id == $id
      and .run.head_sha == $head
      and .run.workflow == "ci.yaml"
      and .run.status == "success"
      and ([.jobs[]
          | select(.name | startswith("Edge / Kind verification ("))
          | select(.status != "skipped")]
        | length > 0 and all(.[]; .status == "success"))
    ' "$candidate_view" >/dev/null 2>&1 || continue
  kind_run_id="$candidate"
  break
done < <(successful_runs "$runs_json" ci.yaml)
[ -n "$kind_run_id" ] || fallback 'exact-commit-kind-not-verified'

# The release dry run: a successful cw-release-dry-run.yaml run of the exact
# commit whose assembly job verified the unsigned four-target delivery. A
# superseded or deferred run skips that verification and does not count.
dry_runs_json="$tmp/dry-runs.json"
fj actions runs list -R "$remote" --head "$tag_commit" --workflow cw-release-dry-run.yaml \
  -L 50 --output json >"$dry_runs_json" 2>/dev/null \
  || fallback 'exact-commit-dry-runs-unavailable'
jq -e '.schema_version == 1 and (.runs | type == "array")' \
  "$dry_runs_json" >/dev/null 2>&1 || fallback 'exact-commit-dry-runs-unavailable'
while read -r candidate; do
  [[ "$candidate" =~ ^[1-9][0-9]*$ ]] || continue
  candidate_view="$tmp/dry-view-$candidate.json"
  view_run "$candidate" "$candidate_view" || continue
  jq -e --arg head "$tag_commit" --argjson id "$candidate" '
      .schema_version == 1
      and .run.id == $id
      and .run.head_sha == $head
      and .run.workflow == "cw-release-dry-run.yaml"
      and .run.status == "success"
      and ([.jobs[] | select(.name == "Assemble and verify the unsigned four-target delivery")]
        | length == 1 and .[0].status == "success")
    ' "$candidate_view" >/dev/null 2>&1 || continue
  assemble_log="$tmp/dry-assemble-$candidate.log"
  job_log "$candidate" "$candidate_view" 'Assemble and verify the unsigned four-target delivery' \
    "$assemble_log" || continue
  grep -Eq '^[0-9T:.-]+Z cw-release: verified targets=4 version=v[0-9.]+ runtime_equal=true signed=false$' \
    "$assemble_log" || continue
  if grep -Eq "^[0-9T:.-]+Z main is now [0-9a-f]{40}; the queued dry run of [0-9a-f]{40} builds this commit's changes$" \
      "$assemble_log"; then
    continue
  fi
  dry_run_id="$candidate"
  break
done < <(successful_runs "$dry_runs_json" cw-release-dry-run.yaml)
[ -n "$dry_run_id" ] || fallback 'exact-commit-dry-run-not-verified'

deploy_repo=(-r codewire/deploy -H "$forge_host")
deploy_runs="$tmp/deploy-runs.json"
fj actions runs list "${deploy_repo[@]}" --workflow promote-dev.yaml \
  --status success -L 30 --output json >"$deploy_runs" 2>/dev/null \
  || fallback 'dev-acceptance-runs-unavailable'
jq -e '.schema_version == 1 and (.runs | type == "array")' \
  "$deploy_runs" >/dev/null 2>&1 || fallback 'dev-acceptance-runs-ambiguous'
# Both the release commit job and the acceptance job check out the exact
# source they use; the workflow requires the smoke source to equal the
# promoted runtime source. Re-dispatches of an existing release keep both.
checkout_line="^[0-9T:.-]+Z Checked out exact Codewire source ${tag_commit}\$"
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
if [ "$tag_commit" = "$main_sha" ]; then
  reason='signed-tag-at-exact-green-deployed-main'
  printf 'release-tag receipt: %s peels to green canonical main %s (CI run %s; Kind run %s; dry run %s; Dev acceptance run %s)\n' \
    "$tag_ref" "$main_sha" "$run_id" "$kind_run_id" "$dry_run_id" "$dev_run_id"
else
  reason='signed-tag-on-main-at-exact-green-deployed-commit'
  printf 'release-tag receipt: %s peels to %s, green and deployed, on canonical main %s (CI run %s; Kind run %s; dry run %s; Dev acceptance run %s)\n' \
    "$tag_ref" "$tag_commit" "$main_sha" "$run_id" "$kind_run_id" "$dry_run_id" "$dev_run_id"
fi
emit_outputs
