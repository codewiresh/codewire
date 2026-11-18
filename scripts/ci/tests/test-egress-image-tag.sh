#!/usr/bin/env bash
# egress-image-tag.sh against a fake registry: a fp- tag is created only when
# absent and never moved, a registry error is never read as "absent", reading
# uses the pull robot and only tagging the publisher, and malformed arguments
# do nothing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly SCRIPT="$ROOT/scripts/ci/images/egress-image-tag.sh"

fail() {
  printf '[test-egress-image-tag] %s\n' "$*" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin" "$work/registry"

# The fake registry is a directory: one file per tag holding its digest.
cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"
case "$1" in
  login) cat >/dev/null; exit 0 ;;
  buildx) shift ;;
  *) exit 64 ;;
esac
[[ "$1" == imagetools ]] || exit 64
shift
case "$1" in
  inspect)
    reference="${*: -1}"
    [[ -z "${FAKE_REGISTRY_ERROR:-}" ]] || { echo 'connection reset by peer' >&2; exit 1; }
    file="$FAKE_REGISTRY/$(printf '%s' "${reference##*/}" | tr ':/' '__')"
    [[ -f "$file" ]] || { echo "ERROR: $reference: not found" >&2; exit 1; }
    printf '{"digest":"%s"}\n' "$(cat "$file")"
    ;;
  create)
    [[ "$2" == --tag ]] || exit 64
    tag="$3" source="$4"
    printf '%s\n' "${source##*@}" >"$FAKE_REGISTRY/$(printf '%s' "${tag##*/}" | tr ':/' '__')"
    ;;
  *) exit 64 ;;
esac
EOF
cat >"$work/bin/fetch" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
role=publisher
if [[ "$1" == --pull ]]; then role=pull; shift; fi
printf '%s\n' "$role" >>"$FAKE_FETCH_LOG"
printf 'robot-%s\n' "$role" >"$1"
printf 'synthetic\n' >"$2"
EOF
chmod 0755 "$work/bin/docker" "$work/bin/fetch"

export CODEWIRE_IMAGE_REGISTRY=registry.example.invalid
export OPENBAO_HARBOR_CREDENTIAL_FETCHER="$work/bin/fetch"
export DOCKER_BIN="$work/bin/docker"
export FAKE_REGISTRY="$work/registry"
export FAKE_DOCKER_LOG="$work/docker.log"
export FAKE_FETCH_LOG="$work/fetch.log"
fingerprint="$(printf 'f%.0s' {1..64})"
first="registry.example.invalid/codewire/egress@sha256:$(printf 'a%.0s' {1..64})"
second="registry.example.invalid/codewire/egress@sha256:$(printf 'b%.0s' {1..64})"
source_sha="$(printf '1%.0s' {1..40})"

[[ "$("$SCRIPT" exists "$fingerprint")" == absent ]] || fail 'a missing tag was not reported absent'
[[ "$(cat "$FAKE_FETCH_LOG")" == pull ]] || fail 'reading did not use the pull robot alone'

"$SCRIPT" tag "$first" "$fingerprint" >"$work/tag.out"
grep -Fq "Tagged $first" "$work/tag.out" || fail 'the first signed image was not tagged'
[[ "$(tail -1 "$FAKE_FETCH_LOG")" == publisher ]] || fail 'tagging did not use the publisher robot'
[[ "$("$SCRIPT" exists "$fingerprint" 2>"$work/exists.err")" == present ]] || fail 'a created tag was not reported present'
grep -Fq "fp-$fingerprint names ${first##*@}" "$work/exists.err" || fail 'a present tag did not log its digest'

# Another signed build of the same inputs leaves the tag where it is.
"$SCRIPT" tag "$second" "$fingerprint" >"$work/again.out"
grep -Fq 'left as it is' "$work/again.out" || fail 'a second build did not leave the tag'
[[ "$(cat "$FAKE_REGISTRY/egress_fp-$fingerprint")" == "${first##*@}" ]] ||
  fail 'the tag was moved onto another digest'
"$SCRIPT" tag "$first" "$fingerprint" | grep -Fq "already names $first" ||
  fail 'retagging the same digest was not a no-op'

printf '%s\n' "${second##*@}" >"$FAKE_REGISTRY/egress_$source_sha"
[[ "$("$SCRIPT" source-digest "$source_sha")" == "${second##*@}" ]] ||
  fail 'the source tag digest was not read'

# A registry error is never read as absent.
if FAKE_REGISTRY_ERROR=1 "$SCRIPT" exists "$fingerprint" >"$work/error.out" 2>"$work/error.err"; then
  fail 'a registry error was read as an answer'
fi
grep -Fq 'Unable to read' "$work/error.err" || fail 'the registry error was not attributable'

# Malformed arguments touch nothing.
: >"$FAKE_DOCKER_LOG"
for arguments in \
    "exists ${fingerprint:1}" \
    "exists ${fingerprint^^}" \
    "source-digest ${source_sha:1}" \
    "tag registry.example.invalid/codewire/mesh@${first##*@} $fingerprint" \
    "tag registry.example.invalid/codewire/egress:$source_sha $fingerprint" \
    "tag $first" \
    "move $first $fingerprint"; do
  # shellcheck disable=SC2086 # each case is its argument words
  if "$SCRIPT" $arguments >/dev/null 2>&1; then
    fail "accepted: $arguments"
  fi
done
[[ ! -s "$FAKE_DOCKER_LOG" ]] || fail 'malformed arguments reached the registry'

printf '[test-egress-image-tag] create-only fingerprint tags passed\n'
