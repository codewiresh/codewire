#!/usr/bin/env bash
# Resolve untrusted Dev release metadata. The credential-free planner validates
# repository identity, exact-head binding, Git presence, and ancestry later.
set -euo pipefail

readonly CANDIDATE_SCHEMA='codewire.ci-deployed-source-candidate/v1'
readonly RELEASE_URL='https://git.example.invalid/api/v1/repos/codewire/deploy/contents/environments/dev/release.json?ref=main'

[[ $# -eq 2 ]] || {
  echo 'Usage: resolve-deployed-source.sh OUTPUT_JSON EXPECTED_HEAD_SHA' >&2
  exit 2
}
output="$1"
expected_head="$2"
[[ "$expected_head" =~ ^[0-9a-f]{40}$ && "$expected_head" != 0000000000000000000000000000000000000000 ]] || {
  echo '[resolve-deployed-source] expected head is invalid' >&2
  exit 2
}
[[ ! -L "$output" ]] || {
  echo '[resolve-deployed-source] candidate output must not be a symlink' >&2
  exit 2
}
umask 077

write_candidate() {
  local valid="$1" reason="$2" source_sha="${3:-}"
  python3 - "$output" "$CANDIDATE_SCHEMA" "$expected_head" "$valid" "$reason" "$source_sha" <<'PY'
import json
from pathlib import Path
import sys

path, schema, head, valid_text, reason, source_sha = sys.argv[1:]
valid = valid_text == "true"
document = {
    "schema": schema,
    "retrieval": {"valid": valid, "reasons": [] if valid else [reason]},
    "target": {"repository": "codewire/codewire", "head_sha": head},
    "release": {
        "repository": "codewire/deploy",
        "path": "environments/dev/release.json",
        "ref": "main",
    },
    "source": (
        {"repository": "codewire/codewire", "sha": source_sha}
        if valid
        else {}
    ),
}
Path(path).write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
  chmod 600 "$output"
}

fail_safe() {
  local reason="$1"
  printf '[resolve-deployed-source] candidate unavailable: %s\n' "$reason" >&2
  write_candidate false "$reason"
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

if ! status="$(
  "$curl_bin" --silent --show-error \
    --proto '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 60 \
    --output "$response_body" --write-out '%{http_code}' \
    --request GET "$RELEASE_URL" \
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


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


try:
    envelope = json.loads(
        Path(sys.argv[1]).read_bytes(), object_pairs_hook=reject_duplicate_keys
    )
    encoded = envelope["content"]
    if envelope.get("encoding") != "base64" or not isinstance(encoded, str):
        raise ValueError
    compact = "".join(encoded.split())
    release = json.loads(
        base64.b64decode(compact, validate=True),
        object_pairs_hook=reject_duplicate_keys,
    )
    source = release["source"]
    sha = source["sha"]
    if (
        not isinstance(source, dict)
        or source.get("repository") != "codewire/codewire"
        or set(source) != {"repository", "sha"}
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

printf '[resolve-deployed-source] resolved Dev source %s for head %s\n' \
  "$source_sha" "$expected_head"
write_candidate true resolved "$source_sha"
