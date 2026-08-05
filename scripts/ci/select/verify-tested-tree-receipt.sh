#!/usr/bin/env bash
# Reuse exact PR-head content verification only for an identical squash tree.
set -euo pipefail

tmp="$(mktemp -d)"
receipt_ref=''
trap 'rm -rf "$tmp"; if [ -n "$receipt_ref" ]; then git update-ref -d "$receipt_ref" >/dev/null 2>&1 || true; fi' EXIT

receipt='fallback'
reason='unverified'
pr_number=''
tested_head=''
tested_run=''
tested_policy_commit=''
tested_policy_sha256=''
tested_plan_sha256=''

emit_outputs() {
  local output
  output="tested_tree_receipt=${receipt}
tested_tree_reason=${reason}
tested_tree_pr=${pr_number}
tested_tree_head=${tested_head}
tested_tree_run=${tested_run}
tested_tree_policy_commit=${tested_policy_commit}
tested_tree_policy_sha256=${tested_policy_sha256}
tested_tree_plan_sha256=${tested_plan_sha256}"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s\n' "$output" >> "$GITHUB_OUTPUT"
  fi
  printf '%s\n' "$output"
}

fallback() {
  reason="$1"
  printf 'tested-tree receipt: full main verification required (%s)\n' "$reason" >&2
  emit_outputs
  exit 0
}

case "${GITHUB_EVENT_NAME:-}" in
  push) ;;
  *) fallback 'not-main-push' ;;
esac
[ "${GITHUB_REF:-}" = 'refs/heads/main' ] || fallback 'not-main-push'

canonical_sha="${GITHUB_SHA:-}"
[[ "$canonical_sha" =~ ^[0-9a-f]{40}$ ]] || fallback 'invalid-canonical-sha'

repository="${GITHUB_REPOSITORY:-}"
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
  || fallback 'invalid-repository'

server_url="${GITHUB_SERVER_URL:-}"
[[ "$server_url" =~ ^https?://[^/]+$ ]] || fallback 'invalid-server-url'

resolved_sha="$(git rev-parse --verify "${canonical_sha}^{commit}" 2>/dev/null)" \
  || fallback 'canonical-commit-unavailable'
[ "$resolved_sha" = "$canonical_sha" ] || fallback 'canonical-sha-mismatch'
checkout_sha="$(git rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
  || fallback 'checkout-commit-unavailable'
[ "$checkout_sha" = "$canonical_sha" ] || fallback 'checkout-sha-mismatch'

read -r -a commit_line <<< "$(git rev-list --parents -n 1 "$canonical_sha")"
[ "${#commit_line[@]}" -eq 2 ] || fallback 'canonical-commit-not-single-parent'
parent_sha="${commit_line[1]}"

changed_paths="$tmp/changed-paths"
git diff --name-only "$parent_sha" "$canonical_sha" > "$changed_paths" \
  || fallback 'canonical-diff-unavailable'

while IFS= read -r path; do
  case "$path" in
    .gitea/workflows/ci.yaml|\
    scripts/ci/select/select-verification.sh|\
    scripts/ci/select/require-verification-results.sh|\
    scripts/ci/select/verify-tested-tree-receipt.sh|\
    scripts/ci/plan/*|\
    scripts/ci/tests/test-select-verification.sh|\
    scripts/ci/tests/test-require-verification-results.sh|\
    scripts/ci/tests/test-verify-tested-tree-receipt.sh)
      fallback 'receipt-control-change'
      ;;
  esac
done < "$changed_paths"

for required_tool in base64 curl jq; do
  command -v "$required_tool" >/dev/null 2>&1 \
    || fallback "${required_tool}-unavailable"
done

token="${GITEA_TOKEN:-}"
[ -n "$token" ] || fallback 'gitea-token-unavailable'
case "$token" in
  *$'\n'*|*$'\r'*|*'"'*) fallback 'invalid-gitea-token' ;;
esac

auth_config="$tmp/curl-auth"
umask 077
printf 'header = "Authorization: token %s"\n' "$token" > "$auth_config"
unset token GITEA_TOKEN

api_base="${server_url%/}/api/v1/repos/${repository}"
api_get() {
  local path="$1" output="$2" status
  if ! status="$(curl --silent --show-error --config "$auth_config" \
      --output "$output" --write-out '%{http_code}' "${api_base}${path}")"; then
    return 1
  fi
  [ "$status" = 200 ]
}

pull_json="$tmp/pull.json"
api_get "/commits/${canonical_sha}/pull" "$pull_json" \
  || fallback 'merged-pr-unavailable'

if ! pr_number="$(jq -er \
    --arg sha "$canonical_sha" --arg repo "$repository" '
      select(type == "object")
      | select(.merged == true and .state == "closed")
      | select(.merge_commit_sha == $sha)
      | select(.base.ref == "main" and .base.repo.full_name == $repo)
      | select(.head.repo.full_name == $repo)
      | .number
      | select(type == "number" and . > 0)
      | tostring
    ' "$pull_json")"; then
  fallback 'merged-pr-provenance-mismatch'
fi
[[ "$pr_number" =~ ^[1-9][0-9]*$ ]] || fallback 'invalid-pr-number'

if ! tested_head="$(jq -er '.head.sha' "$pull_json")"; then
  fallback 'tested-head-unavailable'
fi
[[ "$tested_head" =~ ^[0-9a-f]{40}$ ]] || fallback 'invalid-tested-head'

remote="${VERIFICATION_REMOTE:-origin}"
git remote get-url "$remote" >/dev/null 2>&1 || fallback 'verification-remote-unavailable'
receipt_ref="refs/tmp/tested-tree-receipt/${pr_number}"
if ! git fetch --quiet --no-tags --force "$remote" \
    "refs/pull/${pr_number}/head:${receipt_ref}"; then
  fallback 'tested-head-ref-unavailable'
fi
fetched_head="$(git rev-parse --verify "${receipt_ref}^{commit}" 2>/dev/null)" \
  || fallback 'tested-head-commit-unavailable'
[ "$fetched_head" = "$tested_head" ] || fallback 'stale-tested-head'

merge_base="$(git merge-base "$tested_head" "$parent_sha" 2>/dev/null)" \
  || fallback 'tested-base-unavailable'
[ "$merge_base" = "$parent_sha" ] || fallback 'tested-base-parent-mismatch'

canonical_tree="$(git rev-parse "${canonical_sha}^{tree}")" \
  || fallback 'canonical-tree-unavailable'
tested_tree="$(git rev-parse "${tested_head}^{tree}")" \
  || fallback 'tested-tree-unavailable'
[ "$canonical_tree" = "$tested_tree" ] || fallback 'tested-tree-mismatch'

runs_json="$tmp/runs.json"
api_get "/actions/runs?event=pull_request&head_sha=${tested_head}&page=1&limit=100" \
  "$runs_json" || fallback 'tested-runs-unavailable'

if ! jq -e '
    .total_count | type == "number" and . >= 0 and . <= 100
  ' "$runs_json" >/dev/null; then
  fallback 'tested-runs-ambiguous'
fi

workflow_path="ci.yaml@refs/pull/${pr_number}/head"
if ! tested_run="$(jq -er --arg head "$tested_head" --arg path "$workflow_path" '
    [
      .workflow_runs[]
      | select(.head_sha == $head and .event == "pull_request" and .path == $path)
    ]
    | sort_by(.id)
    | last
    | select(.status == "completed" and .conclusion == "success")
    | .id
    | select(type == "number" and . > 0)
    | tostring
  ' "$runs_json")"; then
  fallback 'exact-head-run-not-successful'
fi

run_attempt="$(jq -er --arg head "$tested_head" --arg path "$workflow_path" \
  --argjson id "$tested_run" '
    .workflow_runs[]
    | select(.id == $id and .head_sha == $head and .path == $path)
    | .run_attempt
    | select(type == "number" and . > 0)
  ' "$runs_json")" || fallback 'tested-run-attempt-unavailable'

jobs_json="$tmp/jobs.json"
api_get "/actions/runs/${tested_run}/jobs?page=1&limit=100" "$jobs_json" \
  || fallback 'tested-run-jobs-unavailable'

if ! required_job_id="$(jq -er --arg head "$tested_head" --argjson attempt "$run_attempt" '
    select(.total_count | type == "number" and . >= 0 and . <= 100)
    | [
        .jobs[]
        | select(
            .name == "Required verification"
            and .head_sha == $head
            and .run_attempt == $attempt
          )
      ]
    | select(length == 1)
    | .[0]
    | select(.status == "completed" and .conclusion == "success")
    | .id
    | select(type == "number" and . > 0)
  ' "$jobs_json")"; then
  fallback 'required-verification-not-successful'
fi
[[ "$required_job_id" =~ ^[1-9][0-9]*$ ]] \
  || fallback 'required-verification-job-invalid'

job_log="$tmp/required-verification.log"
api_get "/actions/jobs/${required_job_id}/logs" "$job_log" \
  || fallback 'required-verification-log-unavailable'

mapfile -t encoded_receipts < <(
  grep -oE 'CODEWIRE_CI_VERIFICATION_RECEIPT=[A-Za-z0-9+/=]+' "$job_log" \
    || true
)
[ "${#encoded_receipts[@]}" -eq 1 ] \
  || fallback 'verification-receipt-count-invalid'
encoded_receipt="${encoded_receipts[0]#CODEWIRE_CI_VERIFICATION_RECEIPT=}"
receipt_json="$tmp/verification-receipt.json"
if ! printf '%s' "$encoded_receipt" | base64 --decode > "$receipt_json" 2>/dev/null; then
  fallback 'verification-receipt-encoding-invalid'
fi

if ! jq -e \
    --arg repository "$repository" \
    --arg workflow "$workflow_path" \
    --argjson pr "$pr_number" \
    --argjson run "$tested_run" \
    --argjson attempt "$run_attempt" \
    --arg base "$parent_sha" \
    --arg head "$tested_head" \
    --arg tree "$tested_tree" '
      select(type == "object")
      | select(.schema == "codewire.ci-verification-receipt/v1")
      | select(.repository == $repository and .event == "pull_request")
      | select(.pull_request == $pr and .workflow_path == $workflow)
      | select(.run == {id: $run, attempt: $attempt, job: "Required verification"})
      | select(.source == {base_commit: $base, head_commit: $head, head_tree: $tree})
      | select(.plan.schema == "codewire.ci-plan/v1" and .plan.status == "trusted")
      | select(.plan.trusted_policy_commit == $base and .plan.baseline_commit == $base)
      | select(.plan.sha256 | test("^[0-9a-f]{64}$"))
      | select(.plan.policy_sha256 | test("^[0-9a-f]{64}$"))
      | select(.plan.graph_sha256 | test("^[0-9a-f]{64}$"))
      | select((.plan.artifacts | keys | sort) == ["cw_cli_release_assets", "desktop_package", "workspace_image"])
      | select([.plan.artifacts[]] | all(. == "affected" or . == "unaffected" or . == "unclassified"))
      | select(.selection | startswith("|valid:v3|") and endswith("|complete|"))
      | select(.results == {
          selection: "success",
          standard: "success",
          rust_transport: "success",
          database_services: "success",
          edge_kind: "success",
          cw_release_assets: "success",
          workspace_image: "success"
        })
    ' "$receipt_json" >/dev/null; then
  fallback 'verification-receipt-mismatch'
fi

tested_policy_commit="$(jq -r '.plan.trusted_policy_commit' "$receipt_json")"
tested_policy_sha256="$(jq -r '.plan.policy_sha256' "$receipt_json")"
tested_plan_sha256="$(jq -r '.plan.sha256' "$receipt_json")"

receipt='accepted'
reason='exact-tested-tree'
printf 'tested-tree receipt: PR #%s head %s run %s base %s tree %s accepted for %s\n' \
  "$pr_number" "$tested_head" "$tested_run" "$parent_sha" "$tested_tree" \
  "$canonical_sha"
emit_outputs
