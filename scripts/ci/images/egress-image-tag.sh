#!/usr/bin/env bash
# The cw-egress image's tags in Harbor (private-docs designs/hosted-egress.md,
# "The image and its deployment"). Dev delivery builds and signs cw-egress
# but never delivers it; its image is keyed by the planner's egress_image
# fingerprint.
#
#   egress-image-tag.sh exists FINGERPRINT         prints present or absent
#   egress-image-tag.sh fp-digest FINGERPRINT      prints the digest of :fp-FINGERPRINT, or exits 3
#   egress-image-tag.sh source-digest SOURCE_SHA   prints the digest of :SOURCE_SHA
#   egress-image-tag.sh tag DIGEST_REF FINGERPRINT creates :fp-FINGERPRINT, once
#
# Only the sign job runs `tag`, and only after it signed DIGEST_REF, so a
# fp- tag only ever names a signed image. The tag is created only when it is
# absent and is never moved: when two runs race, the first signed image keeps
# it and the other is left as it is. A present tag lets a later build skip; it
# never makes anything signed, and the pin proposal verifies the signature,
# source and fingerprint itself before it proposes the digest.
#
# The standard pod-runtime image (#5602) is built, signed and keyed the same
# way; pod-runtime-image-tag.sh runs this with CODEWIRE_SIGNED_IMAGE_REPOSITORY
# naming its repository. Nothing else may be named.
set -euo pipefail

usage() {
  echo 'Usage: egress-image-tag.sh exists|fp-digest FINGERPRINT | source-digest SOURCE_SHA | tag DIGEST_REF FINGERPRINT' >&2
  exit 2
}

readonly REGISTRY="${CODEWIRE_IMAGE_REGISTRY:?set to the image registry host}"
case "${CODEWIRE_SIGNED_IMAGE_REPOSITORY:-codewire/egress}" in
  codewire/egress|codewire/pod-runtime) ;;
  *)
    echo 'CODEWIRE_SIGNED_IMAGE_REPOSITORY must be codewire/egress or codewire/pod-runtime' >&2
    exit 2
    ;;
esac
readonly REPOSITORY="$REGISTRY/${CODEWIRE_SIGNED_IMAGE_REPOSITORY:-codewire/egress}"
fetcher="${OPENBAO_HARBOR_CREDENTIAL_FETCHER:-scripts/ci/setup/fetch-openbao-harbor-credentials.sh}"
docker_bin="${DOCKER_BIN:-docker}"

[[ $# -ge 2 ]] || usage
command="$1"
shift
case "$command" in
  exists|fp-digest)
    [[ $# -eq 1 && "$1" =~ ^[0-9a-f]{64}$ ]] || usage
    ;;
  source-digest)
    [[ $# -eq 1 && "$1" =~ ^[0-9a-f]{40}$ ]] || usage
    ;;
  tag)
    [[ $# -eq 2 && "$1" =~ ^"$REPOSITORY"@sha256:[0-9a-f]{64}$ && "$2" =~ ^[0-9a-f]{64}$ ]] || usage
    ;;
  *) usage ;;
esac

umask 077
work="$(mktemp -d)"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
docker_config="$work/docker-config"
mkdir -m 0700 "$docker_config"

# Reading needs only the pull robot; creating a tag needs the publisher. The
# fetcher's progress line goes to stderr: callers capture this script's stdout
# as its answer, which is exactly one line.
if [[ "$command" == tag ]]; then
  "$fetcher" "$work/username" "$work/password" >&2
else
  "$fetcher" --pull "$work/username" "$work/password" >&2
fi
DOCKER_CONFIG="$docker_config" "$docker_bin" login "$REGISTRY" \
  --username "$(cat "$work/username")" --password-stdin <"$work/password" >/dev/null

# The digest a reference names; status 3 when the registry has no such tag.
manifest_digest() {
  local reference="$1" output="$work/inspect.out" error="$work/inspect.err" digest
  if DOCKER_CONFIG="$docker_config" "$docker_bin" buildx imagetools inspect \
      --format '{{json .Manifest}}' "$reference" >"$output" 2>"$error"; then
    if ! digest="$(jq -er '.digest | select(type == "string")' "$output")" \
        || [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
      echo "Registry returned an invalid manifest digest for $reference" >&2
      return 1
    fi
    printf '%s\n' "$digest"
    return 0
  fi
  if grep -Eqi '(manifest unknown|manifest[^[:cntrl:]]*not found|name unknown|: not found|status code: 404)' "$error"; then
    return 3
  fi
  echo "Unable to read $reference" >&2
  sed -n '1,20p' "$error" >&2
  return 1
}

case "$command" in
  exists)
    # The digest goes to the job log: until Harbor's immutable rule for
    # the repository lands, a fp- tag nobody signed would stall builds of
    # these inputs, and the log names what it points at.
    if digest="$(manifest_digest "$REPOSITORY:fp-$1")"; then
      echo "$REPOSITORY:fp-$1 names $digest" >&2
      echo present
    else
      status=$?
      [[ "$status" -eq 3 ]] || exit "$status"
      echo absent
    fi
    ;;
  fp-digest)
    manifest_digest "$REPOSITORY:fp-$1"
    ;;
  source-digest)
    manifest_digest "$REPOSITORY:$1"
    ;;
  tag)
    reference="$1"
    tag="$REPOSITORY:fp-$2"
    if existing="$(manifest_digest "$tag")"; then
      if [[ "$existing" == "${reference##*@}" ]]; then
        echo "$tag already names $reference"
      else
        echo "$tag already names $existing, another signed build of the same inputs; left as it is"
      fi
      exit 0
    else
      status=$?
      [[ "$status" -eq 3 ]] || exit "$status"
    fi
    DOCKER_CONFIG="$docker_config" "$docker_bin" buildx imagetools create --tag "$tag" "$reference"
    echo "Tagged $reference as $tag"
    ;;
esac
