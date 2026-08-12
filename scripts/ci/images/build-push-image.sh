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

: "${GITHUB_SHA:?GITHUB_SHA is required}"
readonly REGISTRY_HOST='nexus-system-cluster.example.invalid'
readonly REGISTRY_REPOSITORY_PREFIX="${REGISTRY_HOST}/oci-promoted/codewire"

case "$require_existing_source_image" in
  0|1) ;;
  *)
    echo "REQUIRE_EXISTING_SOURCE_IMAGE must be 0 or 1" >&2
    exit 1
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
build_metadata="$work/build-metadata.json"
docker_config="$work/docker-config"
credential_fetcher="${OPENBAO_NEXUS_CREDENTIAL_FETCHER:-scripts/ci/setup/fetch-openbao-nexus-credentials.sh}"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
mkdir -m 0700 "$docker_config"
if [ ! -x "$credential_fetcher" ]; then
  echo "OpenBao Nexus credential fetcher is missing or not executable" >&2
  exit 1
fi
"$credential_fetcher" "$registry_username_file" "$registry_password_file"

registry_auth_error() {
  grep -Eqi \
    '(unauthorized|authorization failed|failed to authorize|status[^[:cntrl:]]*401|status code: 401)' \
    "$1"
}

registry_login() {
  local login_error attempt
  for attempt in 1 2 3; do
    login_error="$(mktemp "$work/login-error.XXXXXX")"
    registry_username="$(<"$registry_username_file")"
    [[ -n "$registry_username" && "$registry_username" != *$'\n'* ]] || {
      echo 'Nexus username is malformed' >&2
      return 1
    }
    if DOCKER_CONFIG="$docker_config" docker login "${REGISTRY_HOST}" \
      -u "$registry_username" --password-stdin <"$registry_password_file" \
      >/dev/null 2>"$login_error"; then
      return 0
    fi
    if registry_auth_error "$login_error" && [ "$attempt" -lt 3 ]; then
      echo "Registry login was rejected; retrying authentication (attempt $((attempt + 1))/3)" >&2
      continue
    fi
    echo "Unable to authenticate to registry ${REGISTRY_HOST}" >&2
    sed -n '1,20p' "$login_error" >&2
    return 1
  done
}

registry_login

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

label_args=(
  "--label" "org.opencontainers.image.source=$public_source_url"
  "--label" "org.opencontainers.image.revision=$source_sha"
  "--label" "org.opencontainers.image.title=codewire-$image_name"
)
build_args=()
if [ -n "$base_image_ref" ]; then
  build_args+=("--build-arg" "BASE_IMAGE_REF=$base_image_ref")
fi

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
  DOCKER_CONFIG="$docker_config" docker buildx build --push \
    --metadata-file "$build_metadata" "${build_args[@]}" \
    -f "$dockerfile" --tag "$source_tag" "${label_args[@]}" "$context"
  if ! source_digest="$(jq -er '."containerimage.digest" | select(type == "string")' "$build_metadata")" \
    || [[ ! "$source_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "Buildx metadata is missing an immutable image digest" >&2
    exit 1
  fi
fi

for tag in "${tags[@]}"; do
  ensure_immutable_tag "$tag" "$source_digest"
done

python3 scripts/ci/images/image-bundle.py candidate \
  "$image_name" "$source_sha" "$REGISTRY_REPOSITORY_PREFIX" "$build_metadata"
