#!/usr/bin/env bash
# image-scan-login.sh writes the pull-only Harbor login to a private registry
# config, prints no credential, refuses a reference that is not a digest, and
# removes only its own folder (codewire#5402).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SCRIPT="$ROOT/scripts/ci/images/image-scan-login.sh"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/image-scan-login-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  printf '[test-image-scan-login] ERROR: %s\n' "$*" >&2
  exit 1
}

# shellcheck disable=SC2016 # A Harbor robot name carries a literal $.
readonly USER_CANARY='robot$scan-user-canary'
readonly PASSWORD_CANARY='scan-password-canary-0123456789'
cat >"$TMP/fetcher" <<EOF
#!/usr/bin/env bash
[ "\$1" = --pull ] || exit 3
printf '%s' '$USER_CANARY' >"\$2"
printf '%s' '$PASSWORD_CANARY' >"\$3"
EOF
chmod +x "$TMP/fetcher"
mkdir "$TMP/runner"
export RUNNER_TEMP="$TMP/runner" GITHUB_OUTPUT="$TMP/output" OPENBAO_HARBOR_CREDENTIAL_FETCHER="$TMP/fetcher"
: >"$GITHUB_OUTPUT"

ref='harbor.example.test/codewire/services@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
log="$("$SCRIPT" prepare "$ref" 2>&1)" || fail "prepare refused a digest: $log"
dir="$(sed -n 's/^docker_config=//p' "$GITHUB_OUTPUT")"
[[ "$dir" == "$RUNNER_TEMP"/image-scan-auth.* && -d "$dir" ]] || fail "no login folder in the step output: $dir"
[ "$(stat -c %a "$dir")" = 700 ] && [ "$(stat -c %a "$dir/config.json")" = 600 ] || fail 'the login is not private'
[ "$(find "$dir" -type f | wc -l)" = 1 ] || fail 'the fetched credential files were not removed'
python3 - "$dir/config.json" "$USER_CANARY:$PASSWORD_CANARY" <<'PY' || fail 'the registry config does not hold the pull login for the host'
import base64, json, sys
auths = json.load(open(sys.argv[1]))["auths"]
assert list(auths) == ["harbor.example.test"], auths
assert base64.b64decode(auths["harbor.example.test"]["auth"]).decode() == sys.argv[2]
PY
for canary in "$USER_CANARY" "$PASSWORD_CANARY"; do
  if grep -qF -- "$canary" <<<"$log" || grep -qF -- "$canary" "$GITHUB_OUTPUT"; then
    fail 'a credential reached the log or the step output'
  fi
done

for bad in 'harbor.example.test/codewire/services:latest' 'not a ref' 'Harbor.Example/x@sha256:00'; do
  if "$SCRIPT" prepare "$bad" >/dev/null 2>&1; then
    fail "prepare accepted a reference that is not a registry digest: $bad"
  fi
done

if "$SCRIPT" remove "$TMP" >/dev/null 2>&1; then
  fail 'remove accepted a folder that is not an image scan login'
fi
"$SCRIPT" remove "$dir" >/dev/null || fail 'remove refused its own folder'
[ ! -e "$dir" ] || fail 'the login folder outlived remove'

printf '[test-image-scan-login] the pull login stays private, digests only, and is removed\n'
