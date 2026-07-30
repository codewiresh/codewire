#!/usr/bin/env bash
# Resolve only the dev release source SHA from the private deploy repository.
set -euo pipefail

fail_safe() {
  local reason="$1"
  printf '[resolve-deployed-source] baseline unavailable: %s\n' "$reason" >&2
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'baseline_available=false\nbaseline_sha=\nbaseline_reason=%s\n' \
      "$reason" >>"$GITHUB_OUTPUT"
  fi
  exit 0
}

deploy_token="${CODEWIRE_DEPLOY_PROMOTION_TOKEN:-}"
unset CODEWIRE_DEPLOY_PROMOTION_TOKEN
[[ "$deploy_token" =~ ^[A-Za-z0-9._~-]{20,512}$ ]] || {
  deploy_token=''
  fail_safe token_unavailable
}

curl_bin="${CURL_BIN:-curl}"
if [[ "$curl_bin" == */* ]]; then
  [[ -x "$curl_bin" ]] || fail_safe curl_unavailable
elif ! command -v "$curl_bin" >/dev/null 2>&1; then
  fail_safe curl_unavailable
fi

umask 077
work="$(mktemp -d)"
auth_header="$work/auth-header"
response_body="$work/response.json"
cleanup() {
  deploy_token=''
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

printf 'Authorization: token %s\n' "$deploy_token" >"$auth_header"
deploy_token=''
readonly release_url='https://git.example.invalid/api/v1/repos/codewire/deploy/contents/environments/dev/release.json?ref=main'

if ! status="$(
  "$curl_bin" --silent --show-error \
    --proto '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 60 \
    --output "$response_body" --write-out '%{http_code}' \
    --request GET "$release_url" \
    --header "@$auth_header" \
    --header 'Accept: application/json'
)"; then
  fail_safe api_unavailable
fi
[[ "$status" == 200 ]] || fail_safe "api_http_$status"
response_size="$(wc -c <"$response_body")"
[[ "$response_size" -le 1048576 ]] || fail_safe manifest_oversized

if ! source_sha="$(
  python3 - "$response_body" <<'PY'
import base64
import json
from pathlib import Path
import re
import sys

try:
    envelope = json.loads(Path(sys.argv[1]).read_bytes())
    encoded = envelope["content"]
    if envelope.get("encoding") != "base64" or not isinstance(encoded, str):
        raise ValueError
    compact = "".join(encoded.split())
    release = json.loads(base64.b64decode(compact, validate=True))
    source = release["source"]
    sha = source["sha"]
    if (
        source.get("repository") != "codewire/codewire"
        or not isinstance(sha, str)
        or not re.fullmatch(r"[0-9a-f]{40}", sha)
        or sha == "0" * 40
    ):
        raise ValueError
except (KeyError, TypeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
print(sha)
PY
)"; then
  fail_safe manifest_invalid
fi

printf '[resolve-deployed-source] resolved dev source %s\n' "$source_sha"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf 'baseline_available=true\nbaseline_sha=%s\nbaseline_reason=resolved\n' \
    "$source_sha" >>"$GITHUB_OUTPUT"
fi
