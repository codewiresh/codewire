#!/usr/bin/env bash
# Prove a GitHub App is the one expected, with exactly the expected
# permissions, on exactly the expected repository (docs/dev/CLI-HOMEBREW-INSTALL.md,
# "The credential"). It reads the App with its JWT (GET /app) and the
# installation's repositories with its installation token, and prints only the
# slug, whether the App ID matches, the permissions, the repository count and
# the repositories' full names. Any difference fails. Neither credential is
# printed or placed in arguments.
set -euo pipefail

fail() {
  printf '::error::[github-app-scope] %s\n' "$*" >&2
  exit 1
}
[[ $# -eq 6 ]] || {
  printf 'usage: github-app-scope.sh APP_ID_FILE JWT_FILE TOKEN_FILE SLUG PERMISSIONS REPOSITORY\n' >&2
  printf '  PERMISSIONS is name=level pairs in name order, such as actions=write,metadata=read\n' >&2
  exit 2
}
readonly app_id_file="$1" jwt_file="$2" token_file="$3"
readonly want_slug="$4" want_permissions="$5" want_repository="$6"
for input in "$app_id_file" "$jwt_file" "$token_file"; do
  [[ -f "$input" && ! -L "$input" && -s "$input" ]] ||
    fail 'each GitHub App input must be one nonempty regular file'
  case "$(stat -c '%a' -- "$input")" in
    400|600) ;;
    *) fail 'each GitHub App input must have mode 0400 or 0600' ;;
  esac
done
app_id="$(tr -d '\n' <"$app_id_file")"
[[ "$app_id" =~ ^[0-9]+$ ]] || fail 'the App ID is malformed'

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/github-app-scope.XXXXXX")"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

# The host is fixed: either credential is only ever sent to GitHub's API.
request() {
  local credential_file="$1" path="$2" output="$3"
  {
    printf 'header = "Authorization: Bearer '
    tr -d '\n' <"$credential_file"
    printf '"\nheader = "Accept: application/vnd.github+json"\n'
    printf 'header = "X-GitHub-Api-Version: 2022-11-28"\n'
    printf 'silent\nshow-error\nfail\n'
  } >"$work/github.curl"
  curl --config "$work/github.curl" --connect-timeout 10 --max-time 30 \
    --output "$output" "https://api.github.com$path" ||
    fail "GitHub refused GET $path"
  shred -u "$work/github.curl"
}

request "$jwt_file" /app "$work/app.json"
request "$token_file" '/installation/repositories?per_page=100' "$work/repositories.json"

slug="$(jq -er '.slug | strings' "$work/app.json")" || fail 'GET /app named no slug'
id_matches=differs
[[ "$(jq -r '.id' "$work/app.json")" == "$app_id" ]] && id_matches=matches
permissions="$(jq -er '.permissions | to_entries | sort_by(.key) | map("\(.key)=\(.value)") | join(",")' \
  "$work/app.json")" || fail 'GET /app named no permissions'
count="$(jq -er '.total_count | numbers' "$work/repositories.json")" ||
  fail 'GET /installation/repositories named no total_count'
repositories="$(jq -er '[.repositories[].full_name] | sort | join(",")' "$work/repositories.json")" ||
  fail 'GET /installation/repositories named no repositories'

printf '[github-app-scope] app slug=%s app_id=%s permissions=%s\n' "$slug" "$id_matches" "$permissions"
printf '[github-app-scope] installation total_count=%s repositories=%s\n' "$count" "$repositories"

[[ "$slug" == "$want_slug" ]] || fail "the App is $slug, not $want_slug"
[[ "$id_matches" == matches ]] || fail 'the App answering is not the one whose ID is stored'
[[ "$permissions" == "$want_permissions" ]] ||
  fail "the App's permissions are $permissions, not exactly $want_permissions"
[[ "$count" == 1 && "$repositories" == "$want_repository" ]] ||
  fail "the installation reaches $count repositories ($repositories), not only $want_repository"
printf '[github-app-scope] %s holds exactly %s on %s\n' "$slug" "$want_permissions" "$want_repository"
