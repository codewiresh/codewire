#!/usr/bin/env bash
# Verify and sign one complete protected runtime image set. The required mode
# signs the Nexus build references and the Harbor references every deployment
# pulls; --ghcr-mirror separately signs the public GHCR copies, which never
# gate delivery.
set -euo pipefail

sign_target=delivery
if [[ "${1:-}" == --ghcr-mirror ]]; then
  sign_target=ghcr-mirror
  shift
fi
if [[ $# -ne 2 ]]; then
  echo 'Usage: sign-runtime-image-set.sh [--ghcr-mirror] IMAGE_BUNDLE PUBLIC_KEY' >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly BUNDLE_INPUT="$1"
readonly PUBLIC_KEY_INPUT="$2"
readonly OPENBAO_ADDR='https://openbao.example.invalid'
readonly OPENBAO_ROLE='codewire-source-dev-publisher'
readonly OPENBAO_AUDIENCE='openbao-codewire-source-dev-publisher'
readonly OPENBAO_KEY='openbao://codewire-runtime'
readonly NEXUS_HOST='nexus-system-cluster.example.invalid'
readonly GHCR_HOST='ghcr.io'
readonly HARBOR_HOST='registry.example.invalid'
readonly PROVENANCE_SOURCE_URL='https://git.example.invalid/codewire/codewire.git'
readonly PROVENANCE_BUILDER_ID='https://git.example.invalid/infra/ci/builders/protected-delivery/v1'
readonly COSIGN_IMAGE='nexus-system-cluster.example.invalid/oci-approved/sigstore/cosign/cosign@sha256:6ca1127dc1e9ff19f3f2bfa214936813a86fbbf52919652eda49d393c888ad3c'
readonly SIGNING_CONFIG_SOURCE="$ROOT/scripts/ci/images/cosign-private-signing-config.json"
readonly -a CURL_BOUNDS=(--connect-timeout 10 --max-time 30)

: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${GITHUB_REF:?GITHUB_REF is required}"
: "${ACTIONS_ID_TOKEN_REQUEST_URL:?Forgejo OIDC request URL is required}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?Forgejo OIDC request token is required}"

[[ "$GITHUB_REF" == refs/heads/main ]] || {
  echo 'Runtime signing is restricted to canonical main' >&2
  exit 1
}
[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ && "$GITHUB_SHA" != 0000000000000000000000000000000000000000 ]] || {
  echo 'Runtime signing requires an exact Git object ID' >&2
  exit 1
}
for input in "$BUNDLE_INPUT" "$PUBLIC_KEY_INPUT" "$SIGNING_CONFIG_SOURCE"; do
  [[ -f "$input" && -r "$input" && ! -L "$input" ]] || {
    echo "Runtime signing input is missing, unreadable, or a symbolic link: $input" >&2
    exit 1
  }
done

umask 077
mkdir -p "${RUNNER_TEMP:-$ROOT/.tmp}"
work="$(mktemp -d "${RUNNER_TEMP:-$ROOT/.tmp}/codewire-runtime-signing.XXXXXX")"
docker_config="$work/docker-config"
bundle="$work/image-bundle.json"
public_key="$work/codewire-runtime-signing.pub"
signing_config="$work/signing-config.json"
openbao_token="$work/openbao.token"
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
install -m 0400 "$SIGNING_CONFIG_SOURCE" "$signing_config"
openssl pkey -pubin -in "$public_key" -noout >/dev/null 2>&1 || {
  echo 'Runtime signing public key is invalid' >&2
  exit 1
}
jq -e '
  .mediaType == "application/vnd.dev.sigstore.signingconfig.v0.2+json"
  and .rekorTlogConfig == {}
  and .tsaConfig == {}
  and (keys | sort) == ["mediaType", "rekorTlogConfig", "tsaConfig"]
' "$signing_config" >/dev/null || {
  echo 'Private Cosign signing configuration is invalid' >&2
  exit 1
}
python3 "$ROOT/scripts/ci/images/image-bundle.py" validate "$bundle"
jq -e --arg sha "$GITHUB_SHA" '.source.sha == $sha' "$bundle" >/dev/null || {
  echo 'Runtime image bundle source does not match the workflow source' >&2
  exit 1
}

refresh_openbao_token() {
  {
    printf 'header = "Authorization: bearer '
    printf '%s' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN"
    printf '"\nsilent\nshow-error\nfail\n'
  } >"$work/forgejo.curl"
  chmod 0600 "$work/forgejo.curl"
  curl --config "$work/forgejo.curl" "${CURL_BOUNDS[@]}" \
    --output "$work/forgejo-response.json" \
    "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${OPENBAO_AUDIENCE}"
  jq -er '.value | strings | select(length > 0)' \
    "$work/forgejo-response.json" >"$work/forgejo.jwt"
  chmod 0600 "$work/forgejo.jwt"

  jq -n --arg role "$OPENBAO_ROLE" --rawfile jwt "$work/forgejo.jwt" \
    '{role:$role, jwt:($jwt | rtrimstr("\n"))}' >"$work/openbao-login.json"
  curl --silent --show-error --fail "${CURL_BOUNDS[@]}" \
    --header 'Content-Type: application/json' \
    --data-binary @"$work/openbao-login.json" \
    --output "$work/openbao-response.json" \
    "$OPENBAO_ADDR/v1/auth/forgejo-jwt/login"
  jq -er '.auth.client_token | strings | select(length > 0)' \
    "$work/openbao-response.json" >"$openbao_token"
  chmod 0600 "$openbao_token"

  {
    printf 'header = "X-Vault-Token: '
    tr -d '\n' <"$openbao_token"
    printf '"\nsilent\nshow-error\nfail\n'
  } >"$work/openbao.curl"
  chmod 0600 "$work/openbao.curl"
}

# Log in to one registry with an OpenBao KV credential: PATH HOST SECRET_FIELD.
registry_login() {
  local path="$1" host="$2" secret_field="$3" name="${2%%.*}"
  curl --config "$work/openbao.curl" "${CURL_BOUNDS[@]}" \
    --output "$work/$name.json" "$OPENBAO_ADDR/v1/$path"
  jq -er '.data.data.username | strings | select(length > 0)' \
    "$work/$name.json" >"$work/$name.username"
  jq -er --arg field "$secret_field" '.data.data[$field] | strings | select(length > 0)' \
    "$work/$name.json" >"$work/$name.secret"
  chmod 0600 "$work/$name.username" "$work/$name.secret"
  DOCKER_CONFIG="$docker_config" docker login "$host" \
    --username "$(<"$work/$name.username")" \
    --password-stdin <"$work/$name.secret" >/dev/null
}

refresh_openbao_token
if [[ "$sign_target" == delivery ]]; then
  registry_login platform/data/nexus/oci-promoter "$NEXUS_HOST" password
  registry_login platform/data/ci/codewire/harbor-publisher "$HARBOR_HOST" password
else
  registry_login platform/data/ci/codewire/ghcr-publisher "$GHCR_HOST" token
fi
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
"$cosign_binary" version >/dev/null

verify_native_attestations() {
  local family="$1" reference="$2" provenance_output sbom_output
  provenance_output="$work/${family}.$(printf '%s' "$reference" | sha256sum | cut -d' ' -f1).provenance.json"
  sbom_output="$work/${family}.$(printf '%s' "$reference" | sha256sum | cut -d' ' -f1).sbom.json"
  DOCKER_CONFIG="$docker_config" docker buildx imagetools inspect \
    --format '{{json .Provenance.SLSA}}' "$reference" >"$provenance_output"
  jq -e \
    --arg builder "$PROVENANCE_BUILDER_ID" \
    --arg revision "$GITHUB_SHA" \
    --arg source "$PROVENANCE_SOURCE_URL" '
      .buildDefinition.buildType
        == "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md"
      and .runDetails.builder.id == $builder
      and .runDetails.metadata.buildkit_metadata.vcs.revision == $revision
      and .runDetails.metadata.buildkit_metadata.vcs.source == $source
      and ([((.buildDefinition.internalParameters // {}) | keys[])
        | select(startswith("github_"))] | length == 0)
    ' "$provenance_output" >/dev/null || {
    echo "Runtime provenance is invalid for $family in $reference" >&2
    return 1
  }
  DOCKER_CONFIG="$docker_config" docker buildx imagetools inspect \
    --format '{{json .SBOM.SPDX}}' "$reference" >"$sbom_output"
  jq -e '
    .spdxVersion == "SPDX-2.3"
    and (.documentNamespace | type == "string" and length > 0)
    and (.packages | type == "array" and length > 0)
  ' "$sbom_output" >/dev/null || {
    echo "Runtime SBOM is invalid for $family in $reference" >&2
    return 1
  }
}

run_cosign() {
  local with_openbao="$1"
  shift
  if [[ "$with_openbao" == true ]]; then
    BAO_ADDR="$OPENBAO_ADDR" \
      BAO_TOKEN="$(<"$openbao_token")" \
      DOCKER_CONFIG="$docker_config" \
      GOMAXPROCS=2 \
      "$cosign_binary" "$@"
  else
    env -u BAO_ADDR -u BAO_TOKEN \
      DOCKER_CONFIG="$docker_config" \
      GOMAXPROCS=2 \
      "$cosign_binary" "$@"
  fi
}

verify_signature() {
  local family="$1" reference="$2"
  run_cosign false verify \
    --key "$public_key" \
    --insecure-ignore-tlog \
    --new-bundle-format=true \
    --annotations "dev.codewire.image-family=$family" \
    --annotations "dev.codewire.source-sha=$GITHUB_SHA" \
    "$reference"
}

sign_reference() {
  local family="$1" reference="$2"
  if verify_signature "$family" "$reference" >/dev/null 2>&1; then
    printf 'Runtime signature already accepted: family=%s ref=%s\n' "$family" "$reference"
    return
  fi
  # The publisher role deliberately issues short-lived tokens. A complete
  # runtime set contains ten registry references, and Cosign trust discovery
  # can consume a material part of that lease. Bind a fresh job OIDC exchange
  # to each required signature instead of sharing one token across the set.
  refresh_openbao_token
  run_cosign true sign --yes \
    --key "$OPENBAO_KEY" \
    --signing-config "$signing_config" \
    --new-bundle-format=true \
    --annotations "dev.codewire.image-family=$family" \
    --annotations "dev.codewire.source-sha=$GITHUB_SHA" \
    "$reference" >/dev/null
  verify_signature "$family" "$reference" >/dev/null
  printf 'Runtime signature accepted: family=%s ref=%s\n' "$family" "$reference"
}

while IFS=$'\t' read -r family nexus_ref; do
  digest="${nexus_ref##*@}"
  if [[ "$sign_target" == delivery ]]; then
    references=("$nexus_ref" "$HARBOR_HOST/codewire/${family}@${digest}")
  else
    references=("$GHCR_HOST/codewiresh/${family}@${digest}")
  fi
  for reference in "${references[@]}"; do
    verify_native_attestations "$family" "$reference"
    sign_reference "$family" "$reference"
  done
done < <(jq -r '.images[] | [.family, .ref] | @tsv' "$bundle")

if [[ "$sign_target" == delivery ]]; then
  echo 'Verified and signed the exact five-image runtime set in Nexus and Harbor'
else
  echo 'Verified and signed the exact five-image runtime set in the GHCR mirror'
fi
