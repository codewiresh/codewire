#!/usr/bin/env bash
# Resolve only an exact canonical-main Rust cache receipt; uncertainty runs cold.
set -euo pipefail

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

receipt='fallback'
reason='unverified'
cache_run=''
declare -A cache_keys=()
declare -A cache_compatibilities=()
declare -A cache_availability=()
flavors=(host_debug host_ci kind_ci cw_cross_ci desktop_release)

emit_outputs() {
  local rendered
  rendered="rust_cache_receipt=${receipt}
rust_cache_reason=${reason}
rust_cache_run=${cache_run}"
  local flavor
  for flavor in "${flavors[@]}"; do
    rendered+=$'\n'"rust_cache_${flavor}_key=${cache_keys[$flavor]:-}"
    rendered+=$'\n'"rust_cache_${flavor}_compatibility=${cache_compatibilities[$flavor]:-}"
    rendered+=$'\n'"rust_cache_${flavor}_available=${cache_availability[$flavor]:-}"
  done
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s\n' "$rendered" >> "$GITHUB_OUTPUT"
  fi
  printf '%s\n' "$rendered"
}

fallback() {
  reason="$1"
  printf 'Rust cache receipt: cold fallback (%s)\n' "$reason" >&2
  emit_outputs
  exit 0
}

source_sha="${CODEWIRE_CACHE_SOURCE_SHA:-}"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || fallback 'invalid-source-sha'
[[ "$source_sha" != 0000000000000000000000000000000000000000 ]] \
  || fallback 'source-sha-unavailable'
repository="${GITHUB_REPOSITORY:-}"
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
  || fallback 'invalid-repository'
server_url="${GITHUB_SERVER_URL:-}"
[[ "$server_url" =~ ^https?://[^/]+$ ]] || fallback 'invalid-server-url'
source_commit="$(git rev-parse --verify "${source_sha}^{commit}" 2>/dev/null)" \
  || fallback 'source-commit-unavailable'
[ "$source_commit" = "$source_sha" ] || fallback 'source-commit-mismatch'
source_tree="$(git rev-parse "${source_sha}^{tree}" 2>/dev/null)" \
  || fallback 'source-tree-unavailable'

for tool in base64 jq; do
  command -v "$tool" >/dev/null 2>&1 || fallback "${tool}-unavailable"
done
curl_bin="${CODEWIRE_CURL_BIN:-curl}"
if [[ "$curl_bin" == */* ]]; then
  [ -x "$curl_bin" ] || fallback 'curl-unavailable'
else
  command -v "$curl_bin" >/dev/null 2>&1 || fallback 'curl-unavailable'
fi
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
  status="$("$curl_bin" --silent --show-error --config "$auth_config" \
    --output "$output" --write-out '%{http_code}' "${api_base}${path}")" || return 1
  [ "$status" = 200 ]
}

runs_json="$tmp/runs.json"
api_get "/actions/runs?head_sha=${source_sha}&page=1&limit=100" "$runs_json" \
  || fallback 'cache-runs-unavailable'
jq -e '.total_count | type == "number" and . >= 0 and . <= 100' \
  "$runs_json" >/dev/null || fallback 'cache-runs-ambiguous'
workflow_path='rust-cache-refresh.yaml@refs/heads/main'
cache_run="$(jq -er --arg head "$source_sha" --arg path "$workflow_path" '
  [
    .workflow_runs[]
    | select(
        .head_sha == $head
        and .path == $path
        and (.event == "push" or .event == "workflow_dispatch")
      )
  ]
  | sort_by(.id)
  | last
  | select(.status == "completed" and .conclusion == "success")
  | .id
  | select(type == "number" and . > 0)
  | tostring
' "$runs_json")" || fallback 'cache-run-not-successful'
run_attempt="$(jq -er --arg head "$source_sha" --arg path "$workflow_path" \
  --argjson id "$cache_run" '
    .workflow_runs[]
    | select(.id == $id and .head_sha == $head and .path == $path)
    | .run_attempt
    | select(type == "number" and . > 0)
  ' "$runs_json")" || fallback 'cache-run-attempt-unavailable'

jobs_json="$tmp/jobs.json"
api_get "/actions/runs/${cache_run}/jobs?page=1&limit=100" "$jobs_json" \
  || fallback 'cache-jobs-unavailable'
receipt_job_id="$(jq -er --arg head "$source_sha" --argjson attempt "$run_attempt" '
  select(.total_count | type == "number" and . >= 0 and . <= 100)
  | [
      .jobs[]
      | select(
          .name == "Publish Rust cache receipt"
          and .head_sha == $head
          and .run_attempt == $attempt
        )
    ]
  | select(length == 1)
  | .[0]
  | select(.status == "completed" and .conclusion == "success")
  | .id
  | select(type == "number" and . > 0)
' "$jobs_json")" || fallback 'cache-receipt-job-not-successful'

job_log="$tmp/cache-receipt.log"
api_get "/actions/jobs/${receipt_job_id}/logs" "$job_log" \
  || fallback 'cache-receipt-log-unavailable'
mapfile -t encoded_receipts < <(
  grep -oE 'CODEWIRE_CI_RUST_CACHE_RECEIPT=[A-Za-z0-9+/=]+' "$job_log" || true
)
[ "${#encoded_receipts[@]}" -eq 1 ] || fallback 'cache-receipt-count-invalid'
receipt_json="$tmp/cache-receipt.json"
printf '%s' "${encoded_receipts[0]#CODEWIRE_CI_RUST_CACHE_RECEIPT=}" \
  | base64 --decode > "$receipt_json" 2>/dev/null \
  || fallback 'cache-receipt-encoding-invalid'

jq -e \
  --arg repository "$repository" \
  --arg workflow "$workflow_path" \
  --argjson run "$cache_run" \
  --argjson attempt "$run_attempt" \
  --arg head "$source_sha" \
  --arg tree "$source_tree" '
    select(type == "object")
    | select(.schema == "codewire.ci-rust-cache-receipt/v1" or .schema == "codewire.ci-rust-cache-receipt/v2")
    | select(.repository == $repository)
    | select(.event == "push" or .event == "workflow_dispatch")
    | select(.workflow_path == $workflow)
    | select(.run == {id: $run, attempt: $attempt, job: "Publish Rust cache receipt"})
    | select(.source == {head_commit: $head, head_tree: $tree})
    | select((keys | sort) == ["caches", "event", "repository", "run", "schema", "source", "workflow_path"])
    | select(.caches | type == "array" and length == 5)
    | select([.caches[].flavor] | sort == ["cw-cross-ci", "desktop-release", "host-ci", "host-debug", "kind-ci"])
    | if .schema == "codewire.ci-rust-cache-receipt/v1" then
        select([.caches[].key] | unique | length == 5)
        | select(.caches | all(.[];
            (keys | sort) == ["compatibility", "flavor", "key", "max_bytes", "path", "runner_pool"]
            and (.compatibility | type == "string" and test("^[0-9a-f]{64}$"))
            and (.key | type == "string" and test("^codewire-rust-deps-v1-(generic|kind)-(host-debug|host-ci|kind-ci|cw-cross-ci|desktop-release)-[0-9a-f]{64}-[0-9a-f]{32}$"))
            and .max_bytes == 4294967296
          ))
      else
        select(
          ([.caches[] | select(.available == true) | .key] | unique | length)
          == ([.caches[] | select(.available == true)] | length)
        )
        | select(.caches | all(.[];
            (keys | sort) == ["available", "compatibility", "flavor", "key", "max_bytes", "path", "runner_pool"]
            and (.available | type == "boolean")
            and (.compatibility | type == "string" and test("^[0-9a-f]{64}$"))
            and (
              if .available then
                (.key | type == "string" and test("^codewire-rust-deps-v1-(generic|kind)-(host-debug|host-ci|kind-ci|cw-cross-ci|desktop-release)-[0-9a-f]{64}-[0-9a-f]{32}$"))
              else .key == null
              end
            )
            and .max_bytes == 4294967296
          ))
      end
  ' "$receipt_json" >/dev/null || fallback 'cache-receipt-mismatch'

validate_flavor() {
  local flavor="$1" pool="$2" path="$3" shell_name="$4" row key compatibility availability schema
  row="$(jq -cer --arg flavor "$flavor" '
    [.caches[] | select(.flavor == $flavor)] | select(length == 1) | .[0]
  ' "$receipt_json")" || fallback "cache-${shell_name}-missing"
  jq -e --arg pool "$pool" --arg path "$path" '
    select(.runner_pool == $pool and .path == $path)
  ' <<< "$row" >/dev/null || fallback "cache-${shell_name}-binding-invalid"
  compatibility="$(jq -er '.compatibility' <<< "$row")" \
    || fallback "cache-${shell_name}-compatibility-invalid"
  schema="$(jq -er '.schema' "$receipt_json")" || fallback 'cache-schema-invalid'
  if [ "$schema" = 'codewire.ci-rust-cache-receipt/v1' ]; then
    # v1 was an identity-only receipt. Preserve it for canonical producer reuse,
    # but do not let consumers treat it as a proof that an archive exists.
    availability=''
    key="$(jq -er '.key' <<< "$row")" || fallback "cache-${shell_name}-key-invalid"
  else
    availability="$(jq -er '.available | if type == "boolean" then tostring else error("availability") end' <<< "$row")" \
      || fallback "cache-${shell_name}-availability-invalid"
    if [ "$availability" = true ]; then
      key="$(jq -er '.key' <<< "$row")" || fallback "cache-${shell_name}-key-invalid"
    else
      key=''
    fi
  fi
  if [ -n "$key" ]; then
    expected="codewire-rust-deps-v1-${pool}-${flavor}-${compatibility}-"
    [[ "$key" == "$expected"* ]] \
      || fallback "cache-${shell_name}-key-binding-invalid"
  fi
  cache_keys[$shell_name]="$key"
  cache_compatibilities[$shell_name]="$compatibility"
  cache_availability[$shell_name]="$availability"
}

validate_flavor host-debug generic target/ci-cache/host-debug host_debug
validate_flavor host-ci generic target/ci-cache/host-ci host_ci
validate_flavor kind-ci kind target/ci-cache/kind-ci kind_ci
validate_flavor cw-cross-ci generic target/ci-cache/cw-cross-ci cw_cross_ci
validate_flavor desktop-release generic target/ci-cache/desktop-release desktop_release

receipt='accepted'
reason='exact-canonical-main-cache'
printf 'Rust cache receipt: run %s source %s accepted\n' "$cache_run" "$source_sha"
emit_outputs
