#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "Usage: $0 IMAGE_NAME DOCKERFILE [CONTEXT]" >&2
  exit 2
fi

image_name="$1"
dockerfile="$2"
context="${3:-.}"
source_sha="${CODEWIRE_SOURCE_SHA:-${GITHUB_SHA:-}}"
release_tag="${CODEWIRE_RELEASE_TAG:-}"
source_dir="${CODEWIRE_SOURCE_DIR:-.}"
public_source_url='https://github.com/codewiresh/codewire'
base_image_ref="${CODEWIRE_BASE_IMAGE_REF:-}"
require_existing_source_image="${REQUIRE_EXISTING_SOURCE_IMAGE:-0}"
sccache_mode="${CODEWIRE_SCCACHE_MODE:-disabled}"

: "${GITHUB_SHA:?GITHUB_SHA is required}"
readonly REGISTRY_HOST='nexus-system-cluster.example.invalid'
readonly REGISTRY_REPOSITORY_PREFIX="${REGISTRY_HOST}/oci-promoted/codewire"
readonly APPROVED_REGISTRY_HOST='nexus.example.invalid'
readonly BUILDKIT_IMAGE='docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5'
# Docker keys credentials by registry hostname. The protected publisher keeps
# its write-only promoted-repository login, while this canonical hostname uses
# the separate read-only approved-input identity for the pinned SBOM tool.
readonly SBOM_GENERATOR_IMAGE='nexus.example.invalid/oci-approved/docker/buildkit-syft-scanner@sha256:13864237fb990943433f89d698590aad1de38d4a7e13d38e7b12f2488c1952e7'
readonly PROVENANCE_SOURCE_URL='https://git.example.invalid/codewire/codewire.git'
readonly EXPECTED_PROVENANCE_BUILDER_ID='https://git.example.invalid/infra/ci/builders/protected-delivery/v1'

provenance_builder_id="${CODEWIRE_PROVENANCE_BUILDER_ID:-$EXPECTED_PROVENANCE_BUILDER_ID}"
if [ "$provenance_builder_id" != "$EXPECTED_PROVENANCE_BUILDER_ID" ]; then
  echo 'Protected image build received an unrecognized provenance builder identity' >&2
  exit 2
fi
readonly provenance_builder_id
# BuildKit defaults to the legacy SLSA v0.2 predicate. Protected verification
# binds v1's runDetails fields, so request that version explicitly instead of
# silently accepting a weaker, differently shaped predicate.
readonly provenance="mode=min,version=v1,builder-id=${provenance_builder_id}"

case "$require_existing_source_image" in
  0|1) ;;
  *)
    echo "REQUIRE_EXISTING_SOURCE_IMAGE must be 0 or 1" >&2
    exit 1
    ;;
esac

case "$sccache_mode" in
  disabled|local) ;;
  r2)
    : "${SCCACHE_BUCKET:?SCCACHE_BUCKET is required in r2 mode}"
    : "${SCCACHE_ENDPOINT:?SCCACHE_ENDPOINT is required in r2 mode}"
    : "${CODEWIRE_SCCACHE_PREFIX:?CODEWIRE_SCCACHE_PREFIX is required in r2 mode}"
    credentials_file="${CODEWIRE_SCCACHE_CREDENTIALS_FILE:?CODEWIRE_SCCACHE_CREDENTIALS_FILE is required in r2 mode}"
    case "$credentials_file" in
      /*) ;;
      *)
        echo 'Published-image sccache credentials file must be an absolute path' >&2
        exit 2
        ;;
    esac
    [ -f "$credentials_file" ] && [ -r "$credentials_file" ] && [ -s "$credentials_file" ] || {
      echo 'Published-image sccache credentials file must be a readable nonempty regular file' >&2
      exit 2
    }
    case "$(stat -c '%a' -- "$credentials_file")" in
      400|600) ;;
      *)
        echo 'Published-image sccache credentials file must have mode 0400 or 0600' >&2
        exit 2
        ;;
    esac
    case "$credentials_file" in
      *','*|*$'\n'*)
        echo 'Published-image sccache credentials file path contains an unsupported character' >&2
        exit 2
        ;;
    esac
    case "$CODEWIRE_SCCACHE_PREFIX" in
      protected/codewire/*) ;;
      *)
        echo 'Published-image sccache prefix must remain below protected/codewire/' >&2
        exit 2
        ;;
    esac
    ;;
  *)
    printf 'Invalid CODEWIRE_SCCACHE_MODE: %s\n' "$sccache_mode" >&2
    exit 2
    ;;
esac

if [ -n "$base_image_ref" ]; then
  if [ "$image_name" != workspace ]; then
    echo "An exact base image may only be supplied to the workspace build" >&2
    exit 1
  fi
  if [[ ! "$base_image_ref" =~ ^(nexus-system-cluster\.private\.invalid/oci-promoted/codewire/base|ghcr\.io/codewiresh/base)@sha256:[0-9a-f]{64}$ ]]; then
    echo "Workspace base image must be an exact supported digest reference" >&2
    exit 1
  fi
fi

tags_output="$(
  scripts/ci/images/compute-image-tags.sh \
    "$REGISTRY_REPOSITORY_PREFIX" "$image_name" "$source_sha" "$release_tag" \
    "${GITHUB_REF:-}" "${GITHUB_REF_NAME:-}"
)"
mapfile -t tags <<<"$tags_output"
[ "${#tags[@]}" -gt 0 ] || {
  echo "Refusing image build without computed tags" >&2
  exit 1
}
canonical_repository="${REGISTRY_REPOSITORY_PREFIX}/${image_name}"
source_tag="${canonical_repository}:${source_sha}"
source_tag_computed=0
for tag in "${tags[@]}"; do
  if [ "$tag" = "$source_tag" ]; then
    source_tag_computed=1
    break
  fi
done
[ "$source_tag_computed" = 1 ] || {
  echo "Image tags do not contain the canonical source-SHA tag" >&2
  exit 1
}
if [ -n "${CODEWIRE_SOURCE_SHA:-}" ]; then
  checked_out_sha="$(git -C "$source_dir" rev-parse HEAD)"
  if [ "$checked_out_sha" != "$source_sha" ]; then
    echo "Refusing image build: checkout $checked_out_sha does not match selected source $source_sha" >&2
    exit 1
  fi
fi

if [ -z "$release_tag" ]; then
  case "${GITHUB_REF:-}" in
    refs/heads/main|refs/tags/v*) ;;
    *)
      if [ "${ALLOW_NON_MAIN_IMAGE_BUILD:-0}" != "1" ]; then
        echo "Skipping image build for ref ${GITHUB_REF:-unknown}"
        exit 0
      fi
      echo "Allowing image build for non-main ref ${GITHUB_REF:-unknown}"
      ;;
  esac
fi

umask 077
work="$(mktemp -d)"
registry_username_file="$work/nexus-username"
registry_password_file="$work/nexus-password"
approved_registry_username_file="$work/nexus-approved-username"
approved_registry_password_file="$work/nexus-approved-password"
build_metadata="$work/build-metadata.json"
bake_metadata="$work/bake-metadata.json"
docker_config="${CODEWIRE_EXTERNAL_DOCKER_CONFIG:-$work/docker-config}"
credential_fetcher="${OPENBAO_NEXUS_CREDENTIAL_FETCHER:-scripts/ci/setup/fetch-openbao-nexus-credentials.sh}"
buildx_builder=''
buildx_builder_owned=0
cleanup() {
  if [ "$buildx_builder_owned" = 1 ] && [ -n "$buildx_builder" ]; then
    DOCKER_CONFIG="$docker_config" docker buildx rm --force "$buildx_builder" \
      >/dev/null 2>&1 || true
  fi
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
case "$docker_config" in
  /*) ;;
  *)
    echo 'Docker configuration directory must be an absolute path' >&2
    exit 2
    ;;
esac
if [ -d "$docker_config" ]; then
  [ "$(stat -c '%a' -- "$docker_config")" = 700 ] || {
    echo 'Docker configuration directory must have mode 0700' >&2
    exit 2
  }
else
  mkdir -m 0700 "$docker_config"
fi
if [ ! -x "$credential_fetcher" ]; then
  echo "OpenBao Nexus credential fetcher is missing or not executable" >&2
  exit 1
fi
"$credential_fetcher" "$registry_username_file" "$registry_password_file"
"$credential_fetcher" --approved \
  "$approved_registry_username_file" "$approved_registry_password_file"

registry_auth_error() {
  grep -Eqi \
    '(unauthorized|authorization failed|failed to authorize|status[^[:cntrl:]]*401|status code: 401)' \
    "$1"
}

registry_login_host() {
  local registry_host="$1" username_file="$2" password_file="$3"
  local login_error attempt registry_username
  for attempt in 1 2 3; do
    login_error="$(mktemp "$work/login-error.XXXXXX")"
    registry_username="$(<"$username_file")"
    [[ -n "$registry_username" && "$registry_username" != *$'\n'* ]] || {
      echo 'Nexus username is malformed' >&2
      return 1
    }
    if DOCKER_CONFIG="$docker_config" docker login "$registry_host" \
      -u "$registry_username" --password-stdin <"$password_file" \
      >/dev/null 2>"$login_error"; then
      return 0
    fi
    if registry_auth_error "$login_error" && [ "$attempt" -lt 3 ]; then
      echo "Registry login was rejected; retrying authentication (attempt $((attempt + 1))/3)" >&2
      continue
    fi
    echo "Unable to authenticate to registry $registry_host" >&2
    sed -n '1,20p' "$login_error" >&2
    return 1
  done
}

registry_login() {
  registry_login_host "$REGISTRY_HOST" "$registry_username_file" "$registry_password_file"
}

approved_registry_login() {
  registry_login_host "$APPROVED_REGISTRY_HOST" \
    "$approved_registry_username_file" "$approved_registry_password_file"
}

registry_login
approved_registry_login

create_buildx_builder() {
  [ -z "$buildx_builder" ] || return 0
  if [ -n "${CODEWIRE_EXTERNAL_BUILDX_BUILDER:-}" ]; then
    if [[ ! "$CODEWIRE_EXTERNAL_BUILDX_BUILDER" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$ ]]; then
      echo 'External Buildx builder name is malformed' >&2
      exit 2
    fi
    buildx_builder="$CODEWIRE_EXTERNAL_BUILDX_BUILDER"
    DOCKER_CONFIG="$docker_config" docker buildx inspect "$buildx_builder" \
      --bootstrap >/dev/null
    return
  fi
  buildx_builder="codewire-publish-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-${image_name}-${BASHPID}"
  DOCKER_CONFIG="$docker_config" docker buildx create \
    --name "$buildx_builder" \
    --driver docker-container \
    --driver-opt "image=$BUILDKIT_IMAGE" \
    --driver-opt provenance-add-gha=false \
    --bootstrap >/dev/null
  buildx_builder_owned=1
}

inspect_manifest_digest() {
  local reference="$1"
  local inspect_output inspect_error digest attempt
  for attempt in 1 2 3; do
    inspect_output="$(mktemp "$work/inspect-output.XXXXXX")"
    inspect_error="$(mktemp "$work/inspect-error.XXXXXX")"

    if DOCKER_CONFIG="$docker_config" docker buildx imagetools inspect \
      --format '{{json .Manifest}}' "$reference" \
      >"$inspect_output" 2>"$inspect_error"; then
      if ! digest="$(jq -er '.digest | select(type == "string")' "$inspect_output")" \
        || [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        echo "Registry returned an invalid manifest digest for $reference" >&2
        return 1
      fi
      printf '%s\n' "$digest"
      return 0
    fi

    if grep -Eqi \
      '(manifest unknown|manifest[^[:cntrl:]]*not found|name unknown|: not found|status code: 404|unexpected status[^[:cntrl:]]*404)' \
      "$inspect_error"; then
      return 3
    fi

    if registry_auth_error "$inspect_error" && [ "$attempt" -lt 3 ]; then
      echo "Registry authentication expired while inspecting $reference; re-authenticating (attempt $((attempt + 1))/3)" >&2
      if ! registry_login; then
        echo "Unable to refresh registry authentication for $reference" >&2
        return 1
      fi
      continue
    fi

    echo "Unable to determine whether immutable image tag exists: $reference" >&2
    sed -n '1,20p' "$inspect_error" >&2
    return 1
  done
}

create_immutable_tag() {
  local tag="$1" expected_digest="$2"
  local create_error attempt
  for attempt in 1 2 3; do
    create_error="$(mktemp "$work/create-error.XXXXXX")"
    if DOCKER_CONFIG="$docker_config" docker buildx imagetools create \
      --tag "$tag" "${canonical_repository}@${expected_digest}" \
      2>"$create_error"; then
      return 0
    fi
    if registry_auth_error "$create_error" && [ "$attempt" -lt 3 ]; then
      echo "Registry authentication expired while creating $tag; re-authenticating (attempt $((attempt + 1))/3)" >&2
      if ! registry_login; then
        echo "Unable to refresh registry authentication for $tag" >&2
        return 1
      fi
      continue
    fi
    echo "Unable to create immutable image tag: $tag" >&2
    sed -n '1,20p' "$create_error" >&2
    return 1
  done
}

ensure_immutable_tag() {
  local tag="$1"
  local expected_digest="$2"
  local actual_digest inspect_status

  if actual_digest="$(inspect_manifest_digest "$tag")"; then
    if [ "$actual_digest" != "$expected_digest" ]; then
      echo "Refusing to replace immutable image tag $tag: expected $expected_digest, found $actual_digest" >&2
      return 1
    fi
    return 0
  else
    inspect_status=$?
  fi
  if [ "$inspect_status" -ne 3 ]; then
    return "$inspect_status"
  fi

  create_immutable_tag "$tag" "$expected_digest"
  if ! actual_digest="$(inspect_manifest_digest "$tag")"; then
    echo "Unable to verify immutable image tag after creation: $tag" >&2
    return 1
  fi
  if [ "$actual_digest" != "$expected_digest" ]; then
    echo "Immutable image tag $tag does not preserve source digest $expected_digest" >&2
    return 1
  fi
}

verify_build_provenance() {
  local reference="${canonical_repository}@${source_digest}"
  local provenance_output provenance_error attempt
  for attempt in 1 2 3; do
    provenance_output="$(mktemp "$work/provenance-output.XXXXXX")"
    provenance_error="$(mktemp "$work/provenance-error.XXXXXX")"
    if DOCKER_CONFIG="$docker_config" docker buildx imagetools inspect \
      --format '{{json .Provenance.SLSA}}' "$reference" \
      >"$provenance_output" 2>"$provenance_error"; then
      if jq -e \
        --arg builder "$provenance_builder_id" \
        --arg revision "$source_sha" \
        --arg source "$PROVENANCE_SOURCE_URL" '
          (.predicate // .) as $predicate
          | (if has("predicate") then
               ._type == "https://in-toto.io/Statement/v1"
               and .predicateType == "https://slsa.dev/provenance/v1"
             else true
             end)
          and ($predicate | type == "object")
          and $predicate.buildDefinition.buildType
            == "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md"
          and $predicate.runDetails.builder.id == $builder
          and $predicate.runDetails.metadata.buildkit_metadata.vcs.revision == $revision
          and $predicate.runDetails.metadata.buildkit_metadata.vcs.source == $source
          and ([($predicate.buildDefinition.internalParameters // {}) | keys[]
            | select(startswith("github_"))] | length == 0)
        ' "$provenance_output" >/dev/null; then
        return 0
      fi
      echo "Protected image provenance is invalid for $reference" >&2
      return 1
    fi
    if registry_auth_error "$provenance_error" && [ "$attempt" -lt 3 ]; then
      echo "Registry authentication expired while verifying provenance for $reference; re-authenticating (attempt $((attempt + 1))/3)" >&2
      if ! registry_login; then
        echo "Unable to refresh registry authentication for $reference" >&2
        return 1
      fi
      continue
    fi
    echo "Unable to inspect protected image provenance for $reference" >&2
    sed -n '1,20p' "$provenance_error" >&2
    return 1
  done
}

verify_build_sbom() {
  local reference="${canonical_repository}@${source_digest}"
  local sbom_output sbom_error attempt
  for attempt in 1 2 3; do
    sbom_output="$(mktemp "$work/sbom-output.XXXXXX")"
    sbom_error="$(mktemp "$work/sbom-error.XXXXXX")"
    if DOCKER_CONFIG="$docker_config" docker buildx imagetools inspect \
      --format '{{json .SBOM.SPDX}}' "$reference" \
      >"$sbom_output" 2>"$sbom_error"; then
      if jq -e '
        .spdxVersion == "SPDX-2.3"
        and (.documentNamespace | type == "string" and length > 0)
        and (.packages | type == "array" and length > 0)
      ' "$sbom_output" >/dev/null; then
        return 0
      fi
      echo "Protected image SBOM is invalid for $reference" >&2
      return 1
    fi
    if registry_auth_error "$sbom_error" && [ "$attempt" -lt 3 ]; then
      echo "Registry authentication expired while verifying SBOM for $reference; re-authenticating (attempt $((attempt + 1))/3)" >&2
      if ! registry_login; then
        echo "Unable to refresh registry authentication for $reference" >&2
        return 1
      fi
      continue
    fi
    echo "Unable to inspect protected image SBOM for $reference" >&2
    sed -n '1,20p' "$sbom_error" >&2
    return 1
  done
}

label_args=(
  "--label" "org.opencontainers.image.source=$public_source_url"
  "--label" "org.opencontainers.image.revision=$source_sha"
  "--label" "org.opencontainers.image.title=codewire-$image_name"
  "--label" "dev.codewire.build.profile=release"
  "--label" "dev.codewire.promotable=true"
)
build_args=()
if [ -n "$base_image_ref" ]; then
  build_args+=("--build-arg" "BASE_IMAGE_REF=$base_image_ref")
fi

product_bake_target=''
dockerfile_from_context="$dockerfile"
if [ "$context" != . ]; then
  case "$dockerfile" in
    "$context"/*) dockerfile_from_context="${dockerfile#"$context"/}" ;;
  esac
fi
case "$image_name:$dockerfile_from_context" in
  dashboard:apps/dashboard/Dockerfile) product_bake_target=dashboard ;;
  derp:deployments/docker/derp.Dockerfile) product_bake_target=derp ;;
  gateway:deployments/docker/gateway.Dockerfile) product_bake_target=gateway ;;
  mesh:deployments/docker/mesh.Dockerfile) product_bake_target=mesh ;;
  services:deployments/docker/services.Dockerfile) product_bake_target=services ;;
esac

if source_digest="$(inspect_manifest_digest "$source_tag")"; then
  jq -n --arg digest "$source_digest" \
    '{"containerimage.digest": $digest}' >"$build_metadata"
  echo "Reusing immutable source image $source_tag@$source_digest"
else
  inspect_status=$?
  if [ "$inspect_status" -ne 3 ]; then
    exit "$inspect_status"
  fi
  if [ "$require_existing_source_image" = 1 ]; then
    echo "Required immutable source image is missing: $source_tag" >&2
    exit 1
  fi
  create_buildx_builder
  if [ -n "$product_bake_target" ]; then
    bake_file="$context/docker-bake.hcl"
    [ -f "$bake_file" ] || {
      echo "Canonical product Bake definition is missing: $bake_file" >&2
      exit 1
    }
    [ "${#build_args[@]}" -eq 0 ] || {
      echo "Product Bake target does not accept ad-hoc build arguments" >&2
      exit 1
    }
    bake_args=(
      --push
      --provenance "$provenance"
      --sbom="generator=$SBOM_GENERATOR_IMAGE"
      --file "$bake_file"
      --metadata-file "$bake_metadata"
      --set "rust-base.context=$context"
      --set "$product_bake_target.context=$context"
      --set "$product_bake_target.tags=$source_tag"
    )
    if [ "$sccache_mode" = r2 ]; then
      bake_args+=(
        --set "$product_bake_target.secrets+=id=aws_shared_credentials,src=$credentials_file"
      )
    fi
    DOCKER_CONFIG="$docker_config" \
      CODEWIRE_IMAGE_SOURCE_SHA="$source_sha" \
      CODEWIRE_IMAGE_SOURCE_URL="$public_source_url" \
      CODEWIRE_RUST_PROFILE=release \
      CODEWIRE_SCCACHE_MODE="$sccache_mode" \
      BUILDX_GIT_CHECK_DIRTY=1 \
      GIT_CONFIG_COUNT=1 \
      GIT_CONFIG_KEY_0=remote.origin.url \
      GIT_CONFIG_VALUE_0="$PROVENANCE_SOURCE_URL" \
      docker buildx bake --builder "$buildx_builder" "${bake_args[@]}" \
        "$product_bake_target"
    jq -e --arg target "$product_bake_target" '
      .[$target]["containerimage.digest"] as $digest
      | select($digest | type == "string" and test("^sha256:[0-9a-f]{64}$"))
      | {"containerimage.digest": $digest}
    ' "$bake_metadata" > "$build_metadata" || {
      echo "Bake metadata is missing an immutable image digest" >&2
      exit 1
    }
  else
    DOCKER_CONFIG="$docker_config" \
      BUILDX_GIT_CHECK_DIRTY=1 \
      GIT_CONFIG_COUNT=1 \
      GIT_CONFIG_KEY_0=remote.origin.url \
      GIT_CONFIG_VALUE_0="$PROVENANCE_SOURCE_URL" \
      docker buildx build --builder "$buildx_builder" --push \
      --provenance="$provenance" \
      --sbom="generator=$SBOM_GENERATOR_IMAGE" \
      --metadata-file "$build_metadata" "${build_args[@]}" \
      -f "$dockerfile" --tag "$source_tag" "${label_args[@]}" "$context"
  fi
  if ! source_digest="$(jq -er '."containerimage.digest" | select(type == "string")' "$build_metadata")" \
    || [[ ! "$source_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "Buildx metadata is missing an immutable image digest" >&2
    exit 1
  fi
fi

verify_build_provenance
verify_build_sbom

for tag in "${tags[@]}"; do
  ensure_immutable_tag "$tag" "$source_digest"
done

python3 scripts/ci/images/image-bundle.py candidate \
  "$image_name" "$source_sha" "$REGISTRY_REPOSITORY_PREFIX" "$build_metadata"
