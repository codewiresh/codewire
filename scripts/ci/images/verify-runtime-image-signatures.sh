#!/usr/bin/env bash
# Require the protected Dev delivery's Cosign signature on every image of one
# exact runtime bundle before Production reuses it.
#
#   verify-runtime-image-signatures.sh IMAGE_BUNDLE PUBLIC_KEY
#
# Production never builds a runtime image: it reuses the source-SHA images the
# protected Dev delivery built and signed. A Dev build can push images and then
# stop before signing (a failed or superseded delivery), so provenance and SBOM
# alone do not prove an image completed delivery. Each image must carry a valid
# signature from the non-exportable codewire-runtime key that binds its image
# family and the bundle's exact source SHA. This only verifies: it never signs.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo 'Usage: verify-runtime-image-signatures.sh IMAGE_BUNDLE PUBLIC_KEY' >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly BUNDLE_INPUT="$1"
readonly PUBLIC_KEY_INPUT="$2"
readonly HARBOR_HOST='registry.example.invalid'
readonly COSIGN_IMAGE='registry.example.invalid/oci-approved/sigstore/cosign/cosign@sha256:6ca1127dc1e9ff19f3f2bfa214936813a86fbbf52919652eda49d393c888ad3c'
readonly ref_pattern='^registry\.example\.invalid/codewire/(dashboard|derp|daemon|services|mesh)@sha256:[0-9a-f]{64}$'

for input in "$BUNDLE_INPUT" "$PUBLIC_KEY_INPUT"; do
  [[ -f "$input" && -r "$input" && ! -L "$input" ]] || {
    echo "Runtime signature input is missing, unreadable, or a symbolic link: $input" >&2
    exit 1
  }
done

umask 077
mkdir -p "${RUNNER_TEMP:-$ROOT/.tmp}"
work="$(mktemp -d "${RUNNER_TEMP:-$ROOT/.tmp}/codewire-runtime-signature-check.XXXXXX")"
docker_config="$work/docker-config"
bundle="$work/image-bundle.json"
public_key="$work/codewire-runtime-signing.pub"
cosign_binary="$work/cosign"
cosign_container=''

cleanup() {
  if [[ -n "$cosign_container" ]]; then
    docker rm -f "$cosign_container" >/dev/null 2>&1 || true
  fi
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

mkdir -m 0700 "$docker_config"
install -m 0400 "$BUNDLE_INPUT" "$bundle"
install -m 0400 "$PUBLIC_KEY_INPUT" "$public_key"
openssl pkey -pubin -in "$public_key" -noout >/dev/null 2>&1 || {
  echo 'Runtime signing public key is invalid' >&2
  exit 1
}
python3 "$ROOT/scripts/ci/images/image-bundle.py" validate "$bundle"
source_sha="$(jq -er '.source.sha' "$bundle")"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ && "$source_sha" != 0000000000000000000000000000000000000000 ]] || {
  echo 'Runtime image bundle has no exact source SHA' >&2
  exit 1
}
entries="$(jq -r '.images[] | [.family, .ref] | @tsv' "$bundle")"
[[ "$(wc -l <<<"$entries")" -eq 5 ]] || {
  echo 'Runtime image bundle must name exactly five images' >&2
  exit 1
}

# Verification needs only read access: use the pull identity every deployment
# uses, never the publisher.
"${OPENBAO_HARBOR_CREDENTIAL_FETCHER:-$ROOT/scripts/ci/setup/fetch-openbao-harbor-credentials.sh}" --pull \
  "$work/harbor-username" "$work/harbor-password"
DOCKER_CONFIG="$docker_config" docker login "$HARBOR_HOST" \
  --username "$(<"$work/harbor-username")" \
  --password-stdin <"$work/harbor-password" >/dev/null
shred -u "$work/harbor-password" 2>/dev/null || rm -f "$work/harbor-password"

docker image inspect --format '{{.Id}}' "$COSIGN_IMAGE" >/dev/null 2>&1 || {
  echo 'Approved Cosign image was not preloaded by protected infrastructure' >&2
  exit 1
}
cosign_container="$(docker create --pull=never "$COSIGN_IMAGE" version)"
[[ "$cosign_container" =~ ^[a-f0-9]{12,64}$ ]] || {
  echo 'Approved Cosign extraction container has an invalid identity' >&2
  exit 1
}
docker cp "$cosign_container:/ko-app/cosign" "$cosign_binary"
docker rm -f "$cosign_container" >/dev/null
cosign_container=''
[[ -f "$cosign_binary" && ! -L "$cosign_binary" && -s "$cosign_binary" ]] || {
  echo 'Approved Cosign binary could not be extracted from the preloaded image' >&2
  exit 1
}
chmod 0500 "$cosign_binary"

failed=()
while IFS=$'\t' read -r family reference; do
  if [[ ! "$reference" =~ $ref_pattern || "${BASH_REMATCH[1]}" != "$family" ]]; then
    echo "Runtime image reference is not an exact Harbor digest for $family" >&2
    exit 1
  fi
  if env -u BAO_ADDR -u BAO_TOKEN DOCKER_CONFIG="$docker_config" GOMAXPROCS=2 \
      "$cosign_binary" verify \
        --key "$public_key" \
        --insecure-ignore-tlog \
        --new-bundle-format=true \
        --annotations "dev.codewire.image-family=$family" \
        --annotations "dev.codewire.source-sha=$source_sha" \
        "$reference" >/dev/null 2>"$work/$family.verify.err"; then
    printf 'Runtime signature accepted: family=%s ref=%s\n' "$family" "$reference"
  else
    printf 'Runtime image has no valid delivery signature for source %s: %s\n' \
      "$source_sha" "$reference" >&2
    sed -n '1,5p' "$work/$family.verify.err" >&2
    failed+=("$family")
  fi
done <<<"$entries"
if [[ "${#failed[@]}" -gt 0 ]]; then
  printf 'Refusing to reuse unsigned runtime images: %s\n' "${failed[*]}" >&2
  exit 1
fi
echo "Every runtime image carries the delivery signature for source $source_sha"
