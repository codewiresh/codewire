#!/usr/bin/env bash
# Permit a release tag push to reuse successful exact-main CI. Every
# uncertainty returns a fallback receipt so pre-push can run its full gate.
set -euo pipefail

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

receipt='fallback'
reason='unverified'
run_id=''
dev_smoke_run_id=''

emit_outputs() {
  printf 'release_tag_receipt=%s\nrelease_tag_reason=%s\nrelease_tag_run=%s\nrelease_tag_dev_smoke_run=%s\n' \
    "$receipt" "$reason" "$run_id" "$dev_smoke_run_id"
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

for required_tool in git jq tea; do
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

api_get() {
  local endpoint="$1" output="$2"
  tea api --login "${PREFLIGHT_TEA_LOGIN:-noel}" --remote "$remote" \
    --output "$output" "$endpoint" >/dev/null
}

runs_json="$tmp/runs.json"
api_get "/repos/{owner}/{repo}/actions/runs?event=push&head_sha=${main_sha}&page=1&limit=100" \
  "$runs_json" 2>/dev/null || fallback 'exact-main-runs-unavailable'
jq -e '.total_count | type == "number" and . >= 0 and . <= 100' \
  "$runs_json" >/dev/null 2>&1 || fallback 'exact-main-runs-ambiguous'

if ! run_id="$(jq -er --arg head "$main_sha" '
    [
      .workflow_runs[]
      | select(
          .head_sha == $head
          and .event == "push"
          and .path == "ci.yaml@refs/heads/main"
        )
    ]
    | sort_by(.id)
    | last
    | select(.status == "completed" and .conclusion == "success")
    | .id
    | select(type == "number" and . > 0)
    | tostring
  ' "$runs_json")"; then
  fallback 'exact-main-ci-not-successful'
fi

run_attempt="$(jq -er --arg head "$main_sha" --argjson id "$run_id" '
    .workflow_runs[]
    | select(
        .id == $id
        and .head_sha == $head
        and .event == "push"
        and .path == "ci.yaml@refs/heads/main"
      )
    | .run_attempt
    | select(type == "number" and . > 0)
  ' "$runs_json")" || fallback 'exact-main-run-attempt-unavailable'

jobs_json="$tmp/jobs.json"
api_get "/repos/{owner}/{repo}/actions/runs/${run_id}/jobs?page=1&limit=100" \
  "$jobs_json" 2>/dev/null || fallback 'exact-main-jobs-unavailable'
if ! jq -e --arg head "$main_sha" --argjson attempt "$run_attempt" '
    select(.total_count | type == "number" and . >= 0 and . <= 100)
    | [
        .jobs[]
        | select(
            .name == "Required verification"
            and .head_sha == $head
            and .run_attempt == $attempt
          )
      ]
    | length == 1
      and .[0].status == "completed"
      and .[0].conclusion == "success"
  ' "$jobs_json" >/dev/null; then
  fallback 'required-verification-not-successful'
fi

dev_runs_json="$tmp/dev-runs.json"
api_get "/repos/{owner}/{repo}/actions/runs?event=workflow_dispatch&head_sha=${main_sha}&page=1&limit=100" \
  "$dev_runs_json" 2>/dev/null || fallback 'dev-smoke-runs-unavailable'
jq -e '.total_count | type == "number" and . >= 0 and . <= 100' \
  "$dev_runs_json" >/dev/null 2>&1 || fallback 'dev-smoke-runs-ambiguous'
if ! dev_smoke_run_id="$(jq -er --arg head "$main_sha" '
    [
      .workflow_runs[]
      | select(
          .head_sha == $head
          and .event == "workflow_dispatch"
          and .path == "dev-deployment-smoke-receipt.yaml@refs/heads/main"
          and .actor.login == "codewire-deploy-smoke"
        )
    ]
    | sort_by(.id)
    | last
    | select(.status == "completed" and .conclusion == "success")
    | .id
    | select(type == "number" and . > 0)
    | tostring
  ' "$dev_runs_json")"; then
  fallback 'exact-source-dev-smoke-not-successful'
fi

dev_run_attempt="$(jq -er --arg head "$main_sha" --argjson id "$dev_smoke_run_id" '
    .workflow_runs[]
    | select(
        .id == $id
        and .head_sha == $head
        and .event == "workflow_dispatch"
        and .path == "dev-deployment-smoke-receipt.yaml@refs/heads/main"
        and .actor.login == "codewire-deploy-smoke"
      )
    | .run_attempt
    | select(type == "number" and . > 0)
  ' "$dev_runs_json")" || fallback 'dev-smoke-run-attempt-unavailable'

dev_jobs_json="$tmp/dev-jobs.json"
api_get "/repos/{owner}/{repo}/actions/runs/${dev_smoke_run_id}/jobs?page=1&limit=100" \
  "$dev_jobs_json" 2>/dev/null || fallback 'dev-smoke-jobs-unavailable'
if ! jq -e --arg head "$main_sha" --argjson attempt "$dev_run_attempt" '
    select(.total_count | type == "number" and . >= 0 and . <= 100)
    | [
        .jobs[]
        | select(
            .name == "Record deploy-owned dev smoke result"
            and .head_sha == $head
            and .run_attempt == $attempt
          )
      ]
    | length == 1
      and .[0].status == "completed"
      and .[0].conclusion == "success"
  ' "$dev_jobs_json" >/dev/null; then
  fallback 'dev-smoke-receipt-not-successful'
fi

receipt='accepted'
reason='signed-tag-at-exact-green-deployed-main'
printf 'release-tag receipt: %s peels to green canonical main %s (CI run %s; dev smoke run %s)\n' \
  "$tag_ref" "$main_sha" "$run_id" "$dev_smoke_run_id"
emit_outputs
