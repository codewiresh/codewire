#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/rust-cache-receipts.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
repo="$TMP/repo"
mkdir -p "$repo" "$TMP/bin"
git -C "$repo" init -q
git -C "$repo" config user.name 'Receipt fixture'
git -C "$repo" config user.email 'receipt@codewire.invalid'
printf 'fixture\n' > "$repo/file"
git -C "$repo" add file
git -C "$repo" commit -qm fixture
head_sha="$(git -C "$repo" rev-parse HEAD)"
head_tree="$(git -C "$repo" rev-parse 'HEAD^{tree}')"

compatibility="$(printf compatibility | sha256sum | cut -d' ' -f1)"
key() {
  printf 'codewire-rust-deps-v1-%s-%s-%s-0123456789abcdef0123456789abcdef' \
    "$1" "$2" "$compatibility"
}

receipt_line="$(env \
  GITHUB_EVENT_NAME=push \
  GITHUB_REF=refs/heads/main \
  GITHUB_REPOSITORY=codewire/codewire \
  GITHUB_SHA="$head_sha" \
  GITHUB_RUN_ID=501 \
  GITHUB_RUN_ATTEMPT=1 \
  CODEWIRE_CACHE_HEAD_COMMIT="$head_sha" \
  CODEWIRE_CACHE_HEAD_TREE="$head_tree" \
  CODEWIRE_RUST_CACHE_HOST_DEBUG_COMPATIBILITY="$compatibility" \
  CODEWIRE_RUST_CACHE_HOST_DEBUG_KEY="$(key generic host-debug)" \
  CODEWIRE_RUST_CACHE_HOST_CI_COMPATIBILITY="$compatibility" \
  CODEWIRE_RUST_CACHE_HOST_CI_KEY="$(key generic host-ci)" \
  CODEWIRE_RUST_CACHE_KIND_CI_COMPATIBILITY="$compatibility" \
  CODEWIRE_RUST_CACHE_KIND_CI_KEY="$(key kind kind-ci)" \
  CODEWIRE_RUST_CACHE_CW_CROSS_CI_COMPATIBILITY="$compatibility" \
  CODEWIRE_RUST_CACHE_CW_CROSS_CI_KEY="$(key generic cw-cross-ci)" \
  CODEWIRE_RUST_CACHE_DESKTOP_RELEASE_COMPATIBILITY="$compatibility" \
  CODEWIRE_RUST_CACHE_DESKTOP_RELEASE_KEY="$(key generic desktop-release)" \
  python3 "$ROOT/scripts/ci/receipts/emit-rust-cache-receipt.py")"
[[ "$receipt_line" == CODEWIRE_CI_RUST_CACHE_RECEIPT=* ]] \
  || { echo 'emitter omitted receipt' >&2; exit 1; }
tampered_json="$(printf '%s' "${receipt_line#CODEWIRE_CI_RUST_CACHE_RECEIPT=}" \
  | base64 --decode | jq -c '.caches[0].max_bytes = 1')"
tampered_line="CODEWIRE_CI_RUST_CACHE_RECEIPT=$(printf '%s' "$tampered_json" | base64 -w0)"

cat > "$TMP/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
output=''
url=''
while (($#)); do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --write-out|--config) shift 2 ;;
    --silent|--show-error) shift ;;
    http*) url="$1"; shift ;;
    *) echo "unexpected curl argument: $1" >&2; exit 2 ;;
  esac
done
case "$url" in
  */actions/runs\?*)
    conclusion=success
    [ "${FIXTURE_MODE:-valid}" != failed ] || conclusion=failure
    body="{\"workflow_runs\":[{\"id\":501,\"path\":\"rust-cache-refresh.yaml@refs/heads/main\",\"event\":\"push\",\"run_attempt\":1,\"head_sha\":\"${FIXTURE_HEAD_SHA}\",\"status\":\"completed\",\"conclusion\":\"${conclusion}\"}],\"total_count\":1}"
    ;;
  */actions/runs/501/jobs\?*)
    body="{\"jobs\":[{\"id\":601,\"name\":\"Publish Rust cache receipt\",\"run_attempt\":1,\"head_sha\":\"${FIXTURE_HEAD_SHA}\",\"status\":\"completed\",\"conclusion\":\"success\"}],\"total_count\":1}"
    ;;
  */actions/jobs/601/logs) body="${FIXTURE_RECEIPT_LINE}" ;;
  *) echo "unexpected API URL: $url" >&2; exit 2 ;;
esac
printf '%s' "$body" > "$output"
printf 200
MOCK
chmod +x "$TMP/bin/curl"
[ -x "$TMP/bin/curl" ] || { echo 'fake curl is not executable' >&2; exit 1; }

run_verifier() {
  local mode="$1" output="$2"
  local selected_receipt="$receipt_line"
  [ "$mode" != tampered ] || selected_receipt="$tampered_line"
  [ -x "$TMP/bin/curl" ] || { echo 'fake curl disappeared' >&2; exit 1; }
  (cd "$repo" && env \
    CODEWIRE_CURL_BIN="$TMP/bin/curl" \
    FIXTURE_MODE="$mode" \
    FIXTURE_HEAD_SHA="$head_sha" \
    FIXTURE_RECEIPT_LINE="$selected_receipt" \
    CODEWIRE_CACHE_SOURCE_SHA="$head_sha" \
    GITHUB_REPOSITORY=codewire/codewire \
    GITHUB_SERVER_URL=https://git.example.invalid \
    GITEA_TOKEN=fixture-token \
    "$ROOT/scripts/ci/receipts/verify-rust-cache-receipt.sh") > "$output"
}

run_verifier valid "$TMP/accepted"
grep -Fxq 'rust_cache_receipt=accepted' "$TMP/accepted"
grep -Fxq "rust_cache_host_ci_key=$(key generic host-ci)" "$TMP/accepted"

run_verifier failed "$TMP/fallback"
grep -Fxq 'rust_cache_receipt=fallback' "$TMP/fallback"
grep -Fxq 'rust_cache_reason=cache-run-not-successful' "$TMP/fallback"

run_verifier tampered "$TMP/tampered"
grep -Fxq 'rust_cache_receipt=fallback' "$TMP/tampered"
grep -Fxq 'rust_cache_reason=cache-receipt-mismatch' "$TMP/tampered"

if env \
  GITHUB_EVENT_NAME=pull_request \
  GITHUB_REF=refs/pull/1/head \
  GITHUB_REPOSITORY=codewire/codewire \
  GITHUB_SHA="$head_sha" \
  GITHUB_RUN_ID=501 \
  CODEWIRE_CACHE_HEAD_COMMIT="$head_sha" \
  CODEWIRE_CACHE_HEAD_TREE="$head_tree" \
  python3 "$ROOT/scripts/ci/receipts/emit-rust-cache-receipt.py" >/dev/null 2>&1; then
  echo 'emitter accepted an untrusted PR event' >&2
  exit 1
fi

echo 'Rust cache receipt contracts: OK'
