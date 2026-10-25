#!/usr/bin/env bash
# build-once.sh (compile once, infra#1632) brings its persistent clone to a
# depth-1 job checkout: the first fetch into an empty clone and a later one
# to a newer commit both land on the checkout's commit. Bad input is refused
# before the build folder is touched.
# shellcheck disable=SC2016 # The checks match literal shell text.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly SCRIPT="$ROOT/scripts/ci/setup/build-once.sh"

fail() {
  echo "test-build-once: $*" >&2
  exit 1
}

work="$(mktemp -d "${TMPDIR:-/tmp}/test-build-once.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
git init -q "$work/origin"
commit() {
  echo "$1" > "$work/origin/file"
  git -C "$work/origin" add file
  git -C "$work/origin" -c user.name=t -c user.email=t@example.invalid commit -q -m "$1"
  git -C "$work/origin" rev-parse HEAD
}
first="$(commit one)"
git clone -q --depth 1 "file://$work/origin" "$work/checkout1"
second="$(commit two)"
git clone -q --depth 1 "file://$work/origin" "$work/checkout2"

# The git half of prepare, as the script runs it.
sync_clone() {
  # shellcheck disable=SC2034 # The fetch line read from the script uses it.
  local checkout="$1" src="$work/root/pr/src"
  local git_src=(git -c core.hooksPath=/dev/null -C "$src")
  [ -d "$src/.git" ] || git init -q "$src"
  eval "$(sed -nE 's/^  "\$\{git_src\[@\]\}" (fetch .*)$/"${git_src[@]}" \1/p' "$SCRIPT")"
  "${git_src[@]}" checkout -q --force --detach FETCH_HEAD
  "${git_src[@]}" rev-parse HEAD
}
mkdir -p "$work/root/pr"
[ "$(sync_clone "$work/checkout1")" = "$first" ] || fail 'the first fetch into an empty clone did not land on the commit'
[ "$(sync_clone "$work/checkout2")" = "$second" ] || fail 'a later fetch did not land on the newer commit'
grep -Fq -- '--update-shallow "$checkout" HEAD' "$SCRIPT" || fail 'the fetch must update the shallow boundary'

for args in '' 'archive' 'publish x' 'publish x Bad-Name' 'leg nothing x' 'nothing'; do
  # shellcheck disable=SC2086 # Word splitting builds each case's arguments.
  if BUILD_ONCE_ROOT="$work/root" "$SCRIPT" $args >/dev/null 2>&1; then
    fail "build-once.sh accepted: ${args:-no arguments}"
  fi
done
# The leg table: both lanes' legs, in build order.
[ "$("$SCRIPT" legs | tr '\n' ' ')" = 'archive compile ' ] || fail 'unexpected wanted legs'
[ "$("$SCRIPT" legs tests | tr '\n' ' ')" = 'archive ' ] || fail 'unexpected tests lane'
[ "$("$SCRIPT" legs checks | tr '\n' ' ')" = 'compile ' ] || fail 'unexpected checks lane'
grep -Eq '^  "[a-z0-9_]+ (tests|checks) (always|selected:[a-z0-9_-]+|env:[A-Z0-9_]+)"$' "$SCRIPT" ||
  fail 'the leg table is missing'
while read -r name; do
  grep -q "^leg_$name() {" "$SCRIPT" || fail "the $name leg has no function"
done < <("$SCRIPT" legs)

# publish uploads every leg output and names its job output after the leg.
mkdir -p "$work/out" "$work/store/v1/archives"
printf 'one' > "$work/out/archive.tar.zst"
printf 'two' > "$work/out/database.tar.zst"
GITHUB_OUTPUT="$work/outputs" ARCHIVE_STORE_URL="file://$work/store" "$SCRIPT" publish "$work/out" >/dev/null
for leg in archive:one database:two; do
  digest="$(printf '%s' "${leg#*:}" | sha256sum | cut -d' ' -f1)"
  grep -qx "${leg%%:*}_sha256=$digest" "$work/outputs" || fail "no ${leg%%:*}_sha256 output"
  [ "$(cat "$work/store/v1/archives/$digest")" = "${leg#*:}" ] || fail "${leg%%:*} was not uploaded"
done
printf 'x' > "$work/out/Bad-Name.tar.zst"
if ARCHIVE_STORE_URL="file://$work/store" "$SCRIPT" publish "$work/out" >/dev/null 2>&1; then
  fail 'publish accepted an invalid leg output name'
fi

echo 'test-build-once: shallow checkouts sync into the persistent clone; the leg table and publish hold; bad input refused'
