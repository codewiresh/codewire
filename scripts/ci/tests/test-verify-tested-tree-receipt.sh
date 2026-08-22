#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHECK="$ROOT/scripts/ci/receipts/verify-tested-tree-receipt.sh"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/tested-tree-receipt.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

repo="$TMP/repo"
remote="$TMP/remote.git"
mock_bin="$TMP/bin"
mkdir -p "$repo" "$mock_bin"
git init -q "$repo"
git -C "$repo" config user.name 'Receipt Test'
git -C "$repo" config user.email 'receipt@test.invalid'

printf 'base\n' > "$repo/product.txt"
git -C "$repo" add product.txt
git -C "$repo" commit -q -m base
base_sha="$(git -C "$repo" rev-parse HEAD)"
base_tree="$(git -C "$repo" rev-parse 'HEAD^{tree}')"

git -C "$repo" checkout -q -b feature
printf 'feature\n' > "$repo/product.txt"
git -C "$repo" commit -qam feature
tested_head="$(git -C "$repo" rev-parse HEAD)"
tested_tree="$(git -C "$repo" rev-parse 'HEAD^{tree}')"

good_merge="$(printf 'squash\n' | git -C "$repo" commit-tree "$tested_tree" -p "$base_sha")"
good_merge_commit="$(printf 'merge\n' | git -C "$repo" commit-tree "$tested_tree" \
  -p "$base_sha" -p "$tested_head")"
tree_mismatch_merge="$(printf 'wrong tree\n' | git -C "$repo" commit-tree "$base_tree" -p "$base_sha")"
unrelated_parent="$(printf 'unrelated\n' | git -C "$repo" commit-tree "$base_tree")"
wrong_parent_merge="$(printf 'wrong parent\n' | git -C "$repo" commit-tree "$tested_tree" -p "$unrelated_parent")"
wrong_merge_head="$(printf 'wrong merge head\n' | git -C "$repo" commit-tree "$tested_tree" \
  -p "$base_sha" -p "$unrelated_parent")"
too_many_parents="$(printf 'too many parents\n' | git -C "$repo" commit-tree "$tested_tree" \
  -p "$base_sha" -p "$tested_head" -p "$unrelated_parent")"
direct_commit="$(printf 'direct main\n' | git -C "$repo" commit-tree "$tested_tree" -p "$base_sha")"

git -C "$repo" checkout -q --detach "$base_sha"
mkdir -p "$repo/.gitea/workflows"
printf 'name: changed\n' > "$repo/.gitea/workflows/ci.yaml"
git -C "$repo" add .gitea/workflows/ci.yaml
git -C "$repo" commit -q -m control
control_head="$(git -C "$repo" rev-parse HEAD)"
control_tree="$(git -C "$repo" rev-parse 'HEAD^{tree}')"
control_merge="$(printf 'control squash\n' | git -C "$repo" commit-tree "$control_tree" -p "$base_sha")"

git init -q --bare "$remote"
git -C "$repo" remote add origin "$remote"
git -C "$repo" push -q origin \
  "${tested_head}:refs/pull/42/head" \
  "${control_head}:refs/pull/43/head"

cat > "$mock_bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail

output=''
url=''
while [ $# -gt 0 ]; do
  case "$1" in
    --config|--output|--write-out)
      if [ "$1" = --output ]; then output="$2"; fi
      shift 2
      ;;
    --silent|--show-error)
      shift
      ;;
    http://*|https://*)
      url="$1"
      shift
      ;;
    *)
      echo "unexpected curl argument: $1" >&2
      exit 2
      ;;
  esac
done

[ -n "$output" ] && [ -n "$url" ]
mode="${FIXTURE_MODE:?}"
if [ "$mode" = api_unavailable ]; then
  exit 7
fi

status=200
case "$url" in
  */commits/*/pull)
    case "$mode" in
      missing_pr)
        status=404
        body='{"message":"not found"}'
        ;;
      malformed)
        body='{'
        ;;
      ambiguous_pr)
        body='[{"number":42},{"number":43}]'
        ;;
      *)
        head_sha="$FIXTURE_HEAD_SHA"
        if [ "$mode" = stale_head ]; then head_sha="$FIXTURE_BASE_SHA"; fi
        body="{\"number\":${FIXTURE_PR_NUMBER},\"merged\":true,\"state\":\"closed\",\"merge_commit_sha\":\"${FIXTURE_MERGE_SHA}\",\"base\":{\"ref\":\"main\",\"repo\":{\"full_name\":\"codewire/codewire\"}},\"head\":{\"sha\":\"${head_sha}\",\"repo\":{\"full_name\":\"codewire/codewire\"}}}"
        ;;
    esac
    ;;
  */actions/runs\?*)
    case "$mode" in
      missing_run)
        body='{"workflow_runs":[],"total_count":0}'
        ;;
      ambiguous_runs)
        body='{"workflow_runs":[],"total_count":101}'
        ;;
      run_failed)
        body="{\"workflow_runs\":[{\"id\":501,\"path\":\"ci.yaml@refs/pull/${FIXTURE_PR_NUMBER}/head\",\"event\":\"pull_request\",\"run_attempt\":1,\"head_sha\":\"${FIXTURE_HEAD_SHA}\",\"status\":\"completed\",\"conclusion\":\"failure\"}],\"total_count\":1}"
        ;;
      native_success)
        body="{\"workflow_runs\":[{\"id\":501,\"workflow_id\":\"ci.yaml\",\"event\":\"pull_request\",\"commit_sha\":\"${FIXTURE_HEAD_SHA}\",\"prettyref\":\"#${FIXTURE_PR_NUMBER}\",\"status\":\"success\"}],\"total_count\":1}"
        ;;
      *)
        body="{\"workflow_runs\":[{\"id\":501,\"path\":\"ci.yaml@refs/pull/${FIXTURE_PR_NUMBER}/head\",\"event\":\"pull_request\",\"run_attempt\":1,\"head_sha\":\"${FIXTURE_HEAD_SHA}\",\"status\":\"completed\",\"conclusion\":\"success\"}],\"total_count\":1}"
        ;;
    esac
    ;;
  */actions/runs/501/jobs\?*)
    conclusion=success
    name='Required verification'
    case "$mode" in
      missing_required) name='Standard verification' ;;
      required_failed) conclusion=failure ;;
      required_skipped) conclusion=skipped ;;
    esac
    if [ "$mode" = native_success ]; then
      body="{\"jobs\":[{\"id\":601,\"run_id\":501,\"name\":\"${name}\",\"attempt\":1,\"status\":\"success\"}],\"total_count\":1}"
    else
      body="{\"jobs\":[{\"id\":601,\"name\":\"${name}\",\"run_attempt\":1,\"head_sha\":\"${FIXTURE_HEAD_SHA}\",\"status\":\"completed\",\"conclusion\":\"${conclusion}\"}],\"total_count\":1}"
    fi
    ;;
  */actions/jobs/601/logs)
    case "$mode" in
      missing_receipt)
        body='required verification completed without a receipt'
        ;;
      duplicate_receipt)
        body="CODEWIRE_CI_VERIFICATION_RECEIPT=${FIXTURE_RECEIPT_B64}
CODEWIRE_CI_VERIFICATION_RECEIPT=${FIXTURE_RECEIPT_B64}"
        ;;
      *)
        body="2026-01-01T00:00:00Z CODEWIRE_CI_VERIFICATION_RECEIPT=${FIXTURE_RECEIPT_B64}"
        ;;
    esac
    ;;
  *)
    echo "unexpected API URL: $url" >&2
    exit 2
    ;;
esac

printf '%s' "$body" > "$output"
printf '%s' "$status"
MOCK
chmod +x "$mock_bin/curl"

run_case() {
  local name="$1" expected="$2" merge_sha="$3" pr="$4" head="$5" mode="$6"
  local output="$TMP/${name}.output" log="$TMP/${name}.log"
  local receipt_base="$base_sha" receipt_json receipt_b64
  if [ "$mode" = receipt_mismatch ]; then receipt_base="$unrelated_parent"; fi
  receipt_json="$(jq -cn \
    --arg repository codewire/codewire \
    --argjson pr "$pr" \
    --arg workflow "ci.yaml@refs/pull/${pr}/head" \
    --arg base "$receipt_base" \
    --arg head "$head" \
    --arg tree "$tested_tree" '
      {
        schema: "codewire.ci-verification-receipt/v1",
        repository: $repository,
        event: "pull_request",
        pull_request: $pr,
        workflow_path: $workflow,
        run: {id: 501, attempt: 1, job: "Required verification"},
        source: {base_commit: $base, head_commit: $head, head_tree: $tree}
      }
    ')"
  receipt_b64="$(printf '%s' "$receipt_json" | base64 -w0)"
  git -C "$repo" checkout -q --detach "$merge_sha"
  : > "$output"
  if ! (cd "$repo" && env \
      PATH="$mock_bin:$PATH" \
      FIXTURE_MODE="$mode" \
      FIXTURE_MERGE_SHA="$merge_sha" \
      FIXTURE_HEAD_SHA="$head" \
      FIXTURE_BASE_SHA="$base_sha" \
      FIXTURE_PR_NUMBER="$pr" \
      FIXTURE_RECEIPT_B64="$receipt_b64" \
      GITEA_TOKEN=fixture-token \
      GITHUB_EVENT_NAME=push \
      GITHUB_REF=refs/heads/main \
      GITHUB_SHA="$merge_sha" \
      GITHUB_REPOSITORY=codewire/codewire \
      GITHUB_SERVER_URL=https://git.test \
      GITHUB_OUTPUT="$output" \
      VERIFICATION_REMOTE=origin \
      "$CHECK") >"$log" 2>&1; then
    echo "$name: receipt checker returned failure" >&2
    cat "$log" >&2
    exit 1
  fi
  grep -Fxq "tested_tree_receipt=${expected}" "$output" || {
    echo "$name: expected ${expected}" >&2
    cat "$output" >&2
    cat "$log" >&2
    exit 1
  }
  if [ "$expected" = accepted ]; then
    grep -Fxq "tested_tree_pr=${pr}" "$output"
    grep -Fxq "tested_tree_head=${head}" "$output"
    grep -Fxq 'tested_tree_run=501' "$output"
  fi
}

run_case accepted accepted "$good_merge" 42 "$tested_head" success
run_case accepted_merge accepted "$good_merge_commit" 42 "$tested_head" success
run_case accepted_native accepted "$good_merge_commit" 42 "$tested_head" native_success
run_case tree_mismatch fallback "$tree_mismatch_merge" 42 "$tested_head" success
run_case wrong_parent fallback "$wrong_parent_merge" 42 "$tested_head" success
run_case wrong_merge_head fallback "$wrong_merge_head" 42 "$tested_head" success
run_case too_many_parents fallback "$too_many_parents" 42 "$tested_head" success
run_case missing_pr fallback "$direct_commit" 42 "$tested_head" missing_pr
run_case api_unavailable fallback "$good_merge" 42 "$tested_head" api_unavailable
run_case malformed fallback "$good_merge" 42 "$tested_head" malformed
run_case ambiguous_pr fallback "$good_merge" 42 "$tested_head" ambiguous_pr
run_case stale_head fallback "$good_merge" 42 "$tested_head" stale_head
run_case missing_run fallback "$good_merge" 42 "$tested_head" missing_run
run_case ambiguous_runs fallback "$good_merge" 42 "$tested_head" ambiguous_runs
run_case run_failed fallback "$good_merge" 42 "$tested_head" run_failed
run_case missing_required fallback "$good_merge" 42 "$tested_head" missing_required
run_case required_failed fallback "$good_merge" 42 "$tested_head" required_failed
run_case required_skipped fallback "$good_merge" 42 "$tested_head" required_skipped
run_case missing_receipt fallback "$good_merge" 42 "$tested_head" missing_receipt
run_case duplicate_receipt fallback "$good_merge" 42 "$tested_head" duplicate_receipt
run_case receipt_mismatch fallback "$good_merge" 42 "$tested_head" receipt_mismatch
run_case control_self_certification fallback "$control_merge" 43 "$control_head" success

echo 'tested-tree receipt fixtures: green'
