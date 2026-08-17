#!/usr/bin/env bash
# Mint one GitHub App installation token from private files without placing
# the App key, JWT, or installation token in command arguments.
set -euo pipefail

fail() {
  printf '[mint-github-app-token] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 4 ]] || {
  printf 'usage: mint-github-app-token.sh APP_ID_FILE INSTALLATION_ID_FILE PRIVATE_KEY_FILE TOKEN_FILE\n' >&2
  exit 2
}
readonly app_id_file="$1"
readonly installation_id_file="$2"
readonly private_key_file="$3"
readonly token_file="$4"
for input in "$app_id_file" "$installation_id_file" "$private_key_file"; do
  [[ -f "$input" && ! -L "$input" && -s "$input" ]] ||
    fail 'GitHub App input must be one nonempty regular file'
  case "$(stat -c '%a' -- "$input")" in
    400|600) ;;
    *) fail 'GitHub App input must have mode 0400 or 0600' ;;
  esac
done
[[ -d "$(dirname "$token_file")" && ! -e "$token_file" && ! -L "$token_file" ]] ||
  fail 'token output must be a new nonsymlink path in an existing directory'

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-github-app.XXXXXX")"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT

node - "$app_id_file" "$private_key_file" "$work/app.jwt" <<'NODE'
const crypto = require("crypto");
const fs = require("fs");

function b64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

const appId = fs.readFileSync(process.argv[2], "utf8").trim();
const privateKey = fs.readFileSync(process.argv[3], "utf8").replace(/\\n/g, "\n");
if (!/^[0-9]+$/.test(appId) || !privateKey.includes("PRIVATE KEY")) process.exit(2);
const now = Math.floor(Date.now() / 1000);
const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
const payload = b64url(JSON.stringify({ iat: now - 60, exp: now + 540, iss: appId }));
const unsigned = `${header}.${payload}`;
const signature = crypto.createSign("RSA-SHA256").update(unsigned).sign(privateKey);
fs.writeFileSync(process.argv[4], `${unsigned}.${b64url(signature)}\n`, { mode: 0o600 });
NODE

installation_id="$(tr -d '\n' <"$installation_id_file")"
[[ "$installation_id" =~ ^[0-9]+$ ]] || fail 'GitHub installation ID is malformed'
{
  printf 'header = "Authorization: Bearer '
  tr -d '\n' <"$work/app.jwt"
  printf '"\nheader = "Accept: application/vnd.github+json"\n'
  printf 'header = "X-GitHub-Api-Version: 2022-11-28"\n'
  printf 'silent\nshow-error\nfail\nrequest = "POST"\n'
} >"$work/github.curl"
chmod 0600 "$work/github.curl"
curl --config "$work/github.curl" \
  --connect-timeout 10 --max-time 30 \
  --output "$work/installation-token.json" \
  "https://api.github.com/app/installations/${installation_id}/access_tokens"
jq -er '.token | strings | select(length > 0)' \
  "$work/installation-token.json" >"$work/token"
chmod 0600 "$work/token"
mv "$work/token" "$token_file"
printf '[mint-github-app-token] wrote one private installation token\n'
