#!/usr/bin/env bash
# Each browser file vendored out of a container image is that image's file and
# nothing else. Every pin is in .supplychain/vendor-images.json: the image by
# digest, the platform manifest and the layer that holds the file, the path in
# the image, and the committed copy's size and SHA-384.
#
# It fetches the image index, the platform manifest and only that layer from
# the registry, checks each against its digest, extracts the member and fails
# unless it is byte-equal to the committed copy. The licence beside it is held
# to its size and SHA-384.
#
#   check-vendor-images.sh              check every committed copy
#   check-vendor-images.sh --write      extract them in place (after a pin bump)
#   check-vendor-images.sh --self-test  prove a one-byte change fails the check
set -euo pipefail

readonly manifest=".supplychain/vendor-images.json"
# Every file this check makes, removed when it exits.
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT

die() {
  echo "vendored image files: $*" >&2
  exit 1
}

sha384_of() {
  echo "sha384-$(openssl dgst -sha384 -binary "$1" | openssl base64 -A)"
}

sha256_of() {
  echo "sha256:$(sha256sum "$1" | cut -d' ' -f1)"
}

# GET a registry object into FILE with an anonymous pull token; blobs redirect
# to storage, which must not see the token, and curl drops it across hosts.
registry_get() {
  local token="$1" accept="$2" url="$3" file="$4"
  curl --fail --silent --show-error --location --proto '=https' \
    --connect-timeout 10 --max-time 120 \
    -H "Authorization: Bearer $token" -H "Accept: $accept" -o "$file" "$url"
}

# Extract entry INDEX's member into OUT, every hop checked against its digest.
extract() {
  local index="$1" out="$2" image repository digest platform token
  local wanted_manifest wanted_layer member found
  image="$(jq -er ".images[$index].image" "$manifest")"
  [[ "$image" =~ ^ghcr\.io/([a-z0-9._/-]+)@(sha256:[0-9a-f]{64})$ ]] ||
    die "$image is not a ghcr.io image pinned by digest"
  repository="${BASH_REMATCH[1]}"
  digest="${BASH_REMATCH[2]}"
  platform="$(jq -er ".images[$index].platform" "$manifest")"
  wanted_manifest="$(jq -er ".images[$index].manifest" "$manifest")"
  wanted_layer="$(jq -er ".images[$index].layer" "$manifest")"
  member="$(jq -er ".images[$index].member" "$manifest")"

  token="$(curl --fail --silent --show-error --proto '=https' --max-time 30 \
    "https://ghcr.io/token?scope=repository:${repository}:pull" | jq -er .token)"
  registry_get "$token" 'application/vnd.oci.image.index.v1+json' \
    "https://ghcr.io/v2/$repository/manifests/$digest" "$scratch/index.json"
  [[ "$(sha256_of "$scratch/index.json")" == "$digest" ]] || die "the index for $image is not $digest"
  found="$(jq -r --arg os "${platform%/*}" --arg arch "${platform#*/}" \
    '[.manifests[] | select(.platform.os == $os and .platform.architecture == $arch) | .digest] | if length == 1 then .[0] else empty end' \
    "$scratch/index.json")"
  [[ "$found" == "$wanted_manifest" ]] || die "$image's $platform manifest is ${found:-missing}, not $wanted_manifest"

  registry_get "$token" 'application/vnd.oci.image.manifest.v1+json' \
    "https://ghcr.io/v2/$repository/manifests/$wanted_manifest" "$scratch/manifest.json"
  [[ "$(sha256_of "$scratch/manifest.json")" == "$wanted_manifest" ]] || die "the $platform manifest is not $wanted_manifest"
  jq -e --arg layer "$wanted_layer" 'any(.layers[]; .digest == $layer)' "$scratch/manifest.json" >/dev/null ||
    die "$wanted_layer is not a layer of $image ($platform)"

  registry_get "$token" 'application/octet-stream' \
    "https://ghcr.io/v2/$repository/blobs/$wanted_layer" "$scratch/layer.tar.gz"
  [[ "$(sha256_of "$scratch/layer.tar.gz")" == "$wanted_layer" ]] || die "the layer is not $wanted_layer"
  tar -xzOf "$scratch/layer.tar.gz" "$member" >"$out" || die "$member is not in $wanted_layer"
}

check_copy() {
  local index="$1" path="$2" extracted="$3"
  [[ "$(wc -c <"$path" | tr -d '[:space:]')" == "$(jq -er ".images[$index].size" "$manifest")" ]] ||
    die "size mismatch for $path"
  [[ "$(sha384_of "$path")" == "$(jq -er ".images[$index].sha384" "$manifest")" ]] ||
    die "SHA-384 mismatch for $path"
  cmp -s "$path" "$extracted" || die "$path is not $(jq -er ".images[$index].member" "$manifest") from the pinned layer"
}

check_license() {
  local index="$1" path
  path="$(jq -er ".images[$index].license.path" "$manifest")"
  [[ -f "$path" ]] || die "missing licence $path"
  [[ "$(wc -c <"$path" | tr -d '[:space:]')" == "$(jq -er ".images[$index].license.size" "$manifest")" ]] ||
    die "size mismatch for $path"
  [[ "$(sha384_of "$path")" == "$(jq -er ".images[$index].license.sha384" "$manifest")" ]] ||
    die "SHA-384 mismatch for $path"
}

main() {
  local count index path
  [[ -f "$manifest" ]] || die "run from the repository root"
  count="$(jq -er '.images | length' "$manifest")"
  for ((index = 0; index < count; index++)); do
    path="$(jq -er ".images[$index].path" "$manifest")"
    check_license "$index"
    extract "$index" "$scratch/extracted"
    case "${1:-}" in
      --write)
        cp "$scratch/extracted" "$path"
        echo "$path: size $(wc -c <"$path" | tr -d '[:space:]') $(sha384_of "$path")"
        ;;
      --self-test)
        ( check_copy "$index" "$path" "$scratch/extracted" ) || die "self-test: the committed $path does not pass"
        cp "$path" "$scratch/changed"
        printf 'x' | dd of="$scratch/changed" bs=1 seek=100 conv=notrunc status=none
        if cmp -s "$scratch/changed" "$path"; then die "self-test: the one-byte change made no change"; fi
        if ( check_copy "$index" "$scratch/changed" "$scratch/extracted" ) 2>/dev/null; then
          die "self-test: a one-byte change to $path passed"
        fi
        echo "vendored image files: self-test passed for $path"
        ;;
      "")
        check_copy "$index" "$path" "$scratch/extracted"
        echo "vendored image files: OK $path ($(jq -er ".images[$index].package" "$manifest") $(jq -er ".images[$index].version" "$manifest"), byte-equal to the pinned layer)"
        ;;
      *)
        die "usage: $0 [--write|--self-test]"
        ;;
    esac
  done
}

main "$@"
