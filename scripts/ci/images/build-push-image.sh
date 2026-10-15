#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT

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
layer_cache_mode="${CODEWIRE_BUILDKIT_CACHE_MODE:-local}"
build_runtime_set="${CODEWIRE_BUILD_RUNTIME_SET:-0}"

: "${GITHUB_SHA:?GITHUB_SHA is required}"
# Harbor is the only registry: publication targets the codewire/ project and
# every digest-pinned approved third-party input lives in its oci-approved/
# project.
readonly REGISTRY_HOST='registry.example.invalid'
readonly REGISTRY_REPOSITORY_PREFIX="${REGISTRY_HOST}/codewire"
readonly BUILDKIT_IMAGE='docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5'
# Docker keys credentials by registry hostname. The single Harbor publisher
# login below both pushes codewire/ images and pulls oci-approved/ inputs such
# as the pinned SBOM tool; a second login on the same host would replace it.
# BuildKit runs the SBOM scanner on the build node, so it is pinned by its
# multi-platform index (docker/buildkit-syft-scanner 1.12.0, promoted by
# infra#1383): the native arm64 support build runs its arm64 variant.
readonly SBOM_GENERATOR_IMAGE='registry.example.invalid/oci-approved/docker/buildkit-syft-scanner@sha256:ae4f3b554449e7e25548e7d8ccc029d17357348e30c6e3df01b92bc93654d6a9'
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

# Publication has no candidate layer-cache interface. Preserve the existing
# protected compiler-cache API above, while rejecting all new remote imports.
case "$layer_cache_mode" in
  local|disabled) ;;
  *) echo 'Published images accept only local or disabled BuildKit cache mode' >&2; exit 2 ;;
esac

case "$build_runtime_set" in
  0|1) ;;
  *)
    echo 'CODEWIRE_BUILD_RUNTIME_SET must be 0 or 1' >&2
    exit 2
    ;;
esac

if [ -n "$base_image_ref" ]; then
  if [ "$image_name" != workspace ]; then
    echo "An exact base image may only be supplied to the workspace build" >&2
    exit 1
  fi
  if [[ ! "$base_image_ref" =~ ^(registry\.example\.invalid/codewire/base|ghcr\.io/codewiresh/base)@sha256:[0-9a-f]{64}$ ]]; then
    echo "Workspace base image must be an exact supported digest reference" >&2
    exit 1
  fi
fi

# The support pair publishes one index for every supported architecture, so a
# native environment on either host pulls the same digest. The workspace
# cross-compiles its arm64 cw on the build platform; BuildKit's bundled
# emulator runs only the arm64 package installs, so runners need no binfmt
# registration. Historical release recipes compiled that cw under emulation
# with the x86-64 protoc and cannot build arm64; they keep their native platform.
readonly SUPPORT_IMAGE_PLATFORMS='linux/amd64,linux/arm64'
image_platforms=''
case "$image_name" in
  base|workspace)
    workspace_recipe="$source_dir/images/workspace/Dockerfile"
    [ "$image_name" != workspace ] || workspace_recipe="$dockerfile"
    if grep -Fqx 'FROM cw-cross-compiler AS cw-builder-arm64' "$workspace_recipe" 2>/dev/null; then
      image_platforms="$SUPPORT_IMAGE_PLATFORMS"
    fi
    ;;
esac
readonly image_platforms

# support-images.yaml builds each platform of the support pair in its own job,
# with its own time budget, and joins them into the same index. A per-platform
# build (CODEWIRE_IMAGE_PLATFORM) builds exactly one platform of a
# multi-platform support image, pushes it by digest without any tag, verifies
# that image's own provenance and SBOM, and reports platform_digest. A join
# (CODEWIRE_IMAGE_JOIN, the amd64 then the arm64 digest) creates the source-SHA
# index from those two images, then verifies, tags and reports it exactly as
# one multi-platform build: every platform, and only those, with its own
# provenance and SBOM.
readonly image_platform="${CODEWIRE_IMAGE_PLATFORM:-}"
readonly image_join="${CODEWIRE_IMAGE_JOIN:-}"
join_digests=()
if [ -n "$image_platform" ] || [ -n "$image_join" ]; then
  [ -n "$image_platforms" ] || {
    echo 'Per-platform builds and joins apply only to a multi-platform support image' >&2
    exit 2
  }
  [ -z "$image_platform" ] || [ -z "$image_join" ] || {
    echo 'A support image is either built for one platform or joined, not both' >&2
    exit 2
  }
  [ "$require_existing_source_image" = 0 ] || {
    echo 'Per-platform builds and joins cannot require an existing source image' >&2
    exit 2
  }
fi
if [ -n "$image_platform" ]; then
  case ",$image_platforms," in
    *",$image_platform,"*) ;;
    *) echo "Per-platform build names an unsupported platform: $image_platform" >&2; exit 2 ;;
  esac
fi
if [ -n "$image_join" ]; then
  read -r -a join_digests <<<"$image_join"
  [ "${#join_digests[@]}" -eq 2 ] \
    && [[ "${join_digests[0]}" =~ ^sha256:[0-9a-f]{64}$ ]] \
    && [[ "${join_digests[1]}" =~ ^sha256:[0-9a-f]{64}$ ]] \
    && [ "${join_digests[0]}" != "${join_digests[1]}" ] || {
      echo 'A support join needs two distinct exact platform digests, amd64 then arm64' >&2
      exit 2
    }
fi
# A per-platform image is verified as the single-platform image it is.
verify_platforms="$image_platforms"
[ -z "$image_platform" ] || verify_platforms=''
readonly verify_platforms

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
cw_image_work="${CODEWIRE_CW_IMAGE_WORK:-$work/cw-images}"
registry_username_file="$work/harbor-username"
registry_password_file="$work/harbor-password"
build_metadata="$work/build-metadata.json"
bake_metadata="$work/bake-metadata.json"
docker_config="${CODEWIRE_EXTERNAL_DOCKER_CONFIG:-$work/docker-config}"
credential_fetcher="${OPENBAO_HARBOR_CREDENTIAL_FETCHER:-scripts/ci/setup/fetch-openbao-harbor-credentials.sh}"
buildx_builder=''
buildx_builder_owned=0
source_remote_url=''
source_remote_changed=0
cleanup() {
  if [ -n "${owned_log_follower:-}" ]; then
    kill -TERM "$owned_log_follower" 2>/dev/null || true
    wait "$owned_log_follower" 2>/dev/null || true
  fi
  if [ "$source_remote_changed" = 1 ] && [ -n "$source_remote_url" ]; then
    git -C "$source_dir" remote set-url origin "$source_remote_url" >/dev/null 2>&1 || true
  fi
  if [ "$buildx_builder_owned" = 1 ] && [ -n "$buildx_builder" ]; then
    DOCKER_CONFIG="$docker_config" docker buildx rm --force "$buildx_builder" \
      >/dev/null 2>&1 || true
  fi
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

require_clean_canonical_source() {
  local source_status
  git -C "$source_dir" diff --quiet || {
    echo 'Protected image build requires a clean source worktree' >&2
    exit 1
  }
  git -C "$source_dir" diff --cached --quiet || {
    echo 'Protected image build requires a clean source index' >&2
    exit 1
  }
  source_status="$(git -C "$source_dir" status --porcelain --untracked-files=all)"
  [ -z "$source_status" ] || {
    echo 'Protected image build requires no untracked source files' >&2
    exit 1
  }
  source_remote_url="$(git -C "$source_dir" remote get-url origin)" || {
    echo 'Protected image build requires an origin remote' >&2
    exit 1
  }
  [ -n "$source_remote_url" ] || {
    echo 'Protected image build received an empty origin remote' >&2
    exit 1
  }
  if [ "$source_remote_url" != "$PROVENANCE_SOURCE_URL" ]; then
    git -C "$source_dir" remote set-url origin "$PROVENANCE_SOURCE_URL"
    source_remote_changed=1
  fi
}

require_clean_canonical_source
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
  echo "OpenBao Harbor credential fetcher is missing or not executable" >&2
  exit 1
fi
"$credential_fetcher" "$registry_username_file" "$registry_password_file"

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
      echo 'Registry username is malformed' >&2
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

registry_login

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

join_support_index() {
  local create_error attempt
  for attempt in 1 2 3; do
    create_error="$(mktemp "$work/join-error.XXXXXX")"
    if DOCKER_CONFIG="$docker_config" docker buildx imagetools create \
      --tag "$source_tag" \
      "${canonical_repository}@${join_digests[0]}" "${canonical_repository}@${join_digests[1]}" \
      2>"$create_error"; then
      return 0
    fi
    if registry_auth_error "$create_error" && [ "$attempt" -lt 3 ]; then
      echo "Registry authentication expired while joining $source_tag; re-authenticating (attempt $((attempt + 1))/3)" >&2
      if ! registry_login; then
        echo "Unable to refresh registry authentication for $source_tag" >&2
        return 1
      fi
      continue
    fi
    echo "Unable to join the support index $source_tag" >&2
    sed -n '1,20p' "$create_error" >&2
    return 1
  done
}

# A support image build fetches external inputs: github.com release assets
# through ADD and curl, and Alpine and Debian packages (#2691). A build that
# fails on a transient network error is retried up to three attempts, after
# 30 and then 60 seconds, so a later attempt resolves the host again. The
# builder keeps every finished step, so a retry resumes at the failed fetch.
# Any other failure ends the build at once.
readonly BUILD_NETWORK_ATTEMPTS=3
build_network_retry_delay="${CODEWIRE_BUILD_NETWORK_RETRY_DELAY_SECONDS:-30}"
[[ "$build_network_retry_delay" =~ ^[0-9]{1,3}$ ]] || {
  echo 'CODEWIRE_BUILD_NETWORK_RETRY_DELAY_SECONDS must be 0-999' >&2
  exit 2
}
build_attempt_log="$work/build-attempt.log"

# Run one build attempt, keeping its stderr (where the build streams its
# steps) for diagnosis while it still reaches the job log.
run_logged_build() {
  : >"$build_attempt_log"
  { "$@" 2>&1 1>&3 3>&- | tee -a "$build_attempt_log" >&2 3>&-; } 3>&1
}

build_network_failure() {
  grep -Eqi \
    '(tls handshake timeout|connection reset by peer|connection timed out|dial (tcp|udp)[^[:cntrl:]]*(i/o timeout|connection refused|network is unreachable)|temporary failure in name resolution|no such host|curl: \((5|6|7|16|18|28|35|52|55|56|92)\)|failed to connect to [^[:space:]]+ port [0-9]+)' \
    "$build_attempt_log"
}

# retry_network_build ATTEMPT STATUS: returns 0 after logging and waiting when
# the failed attempt may be retried.
retry_network_build() {
  local attempt="$1" status="$2" wait_seconds
  if ! build_network_failure; then
    return 1
  fi
  if [ "$attempt" -ge "$BUILD_NETWORK_ATTEMPTS" ]; then
    printf '[build-network] class=transient-exhausted image=%s status=%s attempts=%s\n' \
      "$image_name" "$status" "$BUILD_NETWORK_ATTEMPTS" >&2
    return 1
  fi
  wait_seconds=$((build_network_retry_delay * attempt))
  printf '[build-network] transient network failure image=%s status=%s; retrying in %ss (attempt %s/%s)\n' \
    "$image_name" "$status" "$wait_seconds" "$((attempt + 1))" "$BUILD_NETWORK_ATTEMPTS" >&2
  sleep "$wait_seconds"
}

# The CW producer and the consumer's solve write their logs to files and print
# them only when that step ends. Follow them while they grow, so a slow or
# killed build still shows which step it was in and how long each one took.
owned_log_follower=''
follow_owned_logs() {
  python3 -B -u - "$1" <<'PY' &
import pathlib, signal, sys, time
root = pathlib.Path(sys.argv[1])
offsets, partial = {}, {}
stopping = False
def stop(*_):
    global stopping
    stopping = True
signal.signal(signal.SIGTERM, stop)
def drain():
    for path in sorted(root.rglob("*.log")):
        try:
            with path.open("rb") as log:
                log.seek(offsets.get(path, 0))
                data = log.read()
                offsets[path] = log.tell()
        except OSError:
            continue
        lines = (partial.pop(path, b"") + data).split(b"\n")
        partial[path] = lines.pop()
        name = path.relative_to(root)
        for line in lines:
            sys.stdout.write(f"[cw-owned {name}] {line.decode('utf-8', 'replace')}\n")
    sys.stdout.flush()
while not stopping:
    drain()
    time.sleep(5)
drain()
PY
  owned_log_follower=$!
}
stop_owned_logs() {
  [ -n "$owned_log_follower" ] || return 0
  kill -TERM "$owned_log_follower" 2>/dev/null || true
  wait "$owned_log_follower" 2>/dev/null || true
  owned_log_follower=''
}

# A single-platform image exposes one attestation. A multi-platform index
# exposes a map keyed by platform: every requested platform, and only those,
# must carry its own valid attestation.
attestation_format() {
  local field="$1" member="$2"
  if [ -n "$verify_platforms" ]; then
    printf '{{json .%s}}' "$field"
  else
    printf '{{json .%s.%s}}' "$field" "$member"
  fi
}

attestation_selection() {
  local member="$1" validator="$2"
  if [ -n "$verify_platforms" ]; then
    # shellcheck disable=SC2016 # $platforms is a jq variable.
    printf 'type == "object" and keys == $platforms and all(.[]; .%s | %s)' \
      "$member" "$validator"
  else
    printf '%s' "$validator"
  fi
}

expected_platforms_json() {
  jq -cn --arg platforms "$verify_platforms" \
    'if $platforms == "" then [] else $platforms | split(",") | sort end'
}

verify_build_provenance() {
  local reference="${canonical_repository}@${source_digest}"
  local provenance_output provenance_error attempt
  for attempt in 1 2 3; do
    provenance_output="$(mktemp "$work/provenance-output.XXXXXX")"
    provenance_error="$(mktemp "$work/provenance-error.XXXXXX")"
    if DOCKER_CONFIG="$docker_config" docker buildx imagetools inspect \
      --format "$(attestation_format Provenance SLSA)" "$reference" \
      >"$provenance_output" 2>"$provenance_error"; then
      if jq -e \
        --arg builder "$provenance_builder_id" \
        --arg revision "$source_sha" \
        --arg source "$PROVENANCE_SOURCE_URL" \
        --argjson platforms "$(expected_platforms_json)" '
          def valid_slsa:
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
              | select(startswith("github_"))] | length == 0);
          '"$(attestation_selection SLSA valid_slsa)"'
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
      --format "$(attestation_format SBOM SPDX)" "$reference" \
      >"$sbom_output" 2>"$sbom_error"; then
      if jq -e --argjson platforms "$(expected_platforms_json)" '
        def valid_spdx:
          .spdxVersion == "SPDX-2.3"
          and (.documentNamespace | type == "string" and length > 0)
          and (.packages | type == "array" and length > 0);
        '"$(attestation_selection SPDX valid_spdx)"'
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
platform_args=()
if [ -n "$image_platform" ]; then
  platform_args=(--platform "$image_platform")
elif [ -n "$image_platforms" ]; then
  platform_args=(--platform "$image_platforms")
fi
if [ "$image_name" = workspace ]; then
  # Every actual build refreshes moving tool channels. Historical release
  # sources without the named stage need the conservative whole-build bypass.
  if [ "$layer_cache_mode" = disabled ] \
      || ! grep -Eqi '^FROM .+ AS workspace-floating-tools$' "$dockerfile"; then
    build_args+=(--no-cache)
  else
    build_args+=(--no-cache-filter workspace-floating-tools)
    # The Go tools cross-compile in their own build-platform stage.
    if grep -Eqi '^FROM .+ AS workspace-floating-go$' "$dockerfile"; then
      build_args+=(--no-cache-filter workspace-floating-go)
    fi
  fi
  build_args+=(--build-arg "CODEWIRE_SCCACHE_MODE=$sccache_mode")
  if [ "$sccache_mode" = r2 ]; then
    build_args+=(--secret "id=aws_shared_credentials,src=$credentials_file"
      --build-arg "SCCACHE_BUCKET=$SCCACHE_BUCKET" --build-arg "SCCACHE_ENDPOINT=$SCCACHE_ENDPOINT"
      --build-arg "CODEWIRE_SCCACHE_PREFIX=$CODEWIRE_SCCACHE_PREFIX")
  fi
fi

# CI may name an internal HTTP cache of the dated apt snapshots used by the base
# and workspace images. BuildKit receives it only as an optional secret, so
# layer cache keys and image history do not depend on it.
apt_mirror_args=()
if [ -n "${CODEWIRE_APT_SNAPSHOT_MIRROR:-}" ]; then
  case "$image_name" in
    base|workspace)
      apt_mirror_args=(--secret "id=codewire-apt-mirror,env=CODEWIRE_APT_SNAPSHOT_MIRROR")
      ;;
  esac
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
  daemon:deployments/docker/daemon.Dockerfile) product_bake_target=daemon ;;
  mesh:deployments/docker/mesh.Dockerfile) product_bake_target=mesh ;;
  services:deployments/docker/services.Dockerfile) product_bake_target=services ;;
esac
if [ "$build_runtime_set" = 1 ] && [ "$product_bake_target" != services ]; then
  echo 'The protected runtime-set Bake transaction must be anchored by services' >&2
  exit 2
fi

# Build every missing service runtime target in one Bake transaction. The
# daemon is not part of it: its static CW producer is the longest build, so
# the daemon builds alone on its own protected worker and the two jobs never
# race for the same immutable tag. Inspect exact source tags first so a retry
# never overwrites an immutable target that a partially successful attempt
# already published.
readonly SERVICE_RUNTIME_TARGETS=(dashboard services mesh derp)
if [ "$build_runtime_set" = 1 ]; then
  missing_runtime_targets=()
  for runtime_target in "${SERVICE_RUNTIME_TARGETS[@]}"; do
    runtime_source_tag="${REGISTRY_REPOSITORY_PREFIX}/${runtime_target}:${source_sha}"
    if inspect_manifest_digest "$runtime_source_tag" >/dev/null; then
      continue
    else
      inspect_status=$?
    fi
    if [ "$inspect_status" -ne 3 ]; then
      exit "$inspect_status"
    fi
    missing_runtime_targets+=("$runtime_target")
  done

  if [ "${#missing_runtime_targets[@]}" -gt 0 ]; then
    if [ "$require_existing_source_image" = 1 ]; then
      printf 'Required immutable runtime-set source images are missing: %s\n' \
        "${missing_runtime_targets[*]}" >&2
      exit 1
    fi
    bake_file="$context/docker-bake.hcl"
    [ -f "$bake_file" ] || {
      echo "Canonical product Bake definition is missing: $bake_file" >&2
      exit 1
    }
    create_buildx_builder
    bake_args=(
      --push
      --provenance "$provenance"
      --sbom="generator=$SBOM_GENERATOR_IMAGE"
      --file "$bake_file"
      --metadata-file "$bake_metadata"
      --set "rust-base.context=$context"
    )
    for runtime_target in "${missing_runtime_targets[@]}"; do
      bake_args+=(
        --set "$runtime_target.context=$context"
        --set "$runtime_target.tags=${REGISTRY_REPOSITORY_PREFIX}/${runtime_target}:${source_sha}"
      )
      if [ "$sccache_mode" = r2 ]; then
        bake_args+=(
          --set "$runtime_target.secrets+=id=aws_shared_credentials,src=$credentials_file"
        )
      fi
    done
    bake_targets=("${missing_runtime_targets[@]}")
    cw_selected_source_dir="$(cd "$source_dir" && pwd -P)"
    [ "$(cd "$context" && pwd -P)" = "$cw_selected_source_dir" ] || {
      echo 'Protected CW image context differs from the selected release source' >&2
      exit 2
    }
    mkdir -p -- "$cw_image_work"
    DOCKER_CONFIG="$docker_config" \
      CODEWIRE_IMAGE_SOURCE_SHA="$source_sha" \
      CODEWIRE_IMAGE_SOURCE_URL="$public_source_url" \
      CODEWIRE_RUST_PROFILE=runtime \
      CODEWIRE_SCCACHE_MODE="$sccache_mode" \
      bash "$ROOT/scripts/ci/images/cw-image-consumer.sh" runtime "$cw_selected_source_dir" "$cw_image_work" -- \
      docker buildx bake --builder "$buildx_builder" "${bake_args[@]}" \
        "${bake_targets[@]}"

    for runtime_target in "${missing_runtime_targets[@]}"; do
      if ! runtime_digest="$(jq -er --arg target "$runtime_target" '
        .[$target]["containerimage.digest"]
        | select(type == "string" and test("^sha256:[0-9a-f]{64}$"))
      ' "$bake_metadata")"; then
        echo "Bake metadata is missing the immutable $runtime_target image digest" >&2
        exit 1
      fi
      runtime_source_tag="${REGISTRY_REPOSITORY_PREFIX}/${runtime_target}:${source_sha}"
      if ! published_runtime_digest="$(inspect_manifest_digest "$runtime_source_tag")" \
          || [ "$published_runtime_digest" != "$runtime_digest" ]; then
        echo "Published $runtime_target source tag does not match its Bake digest" >&2
        exit 1
      fi
    done
  fi
fi

# A per-platform image is never the source-SHA index, so it is always built.
if [ -z "$image_platform" ] && source_digest="$(inspect_manifest_digest "$source_tag")"; then
  jq -n --arg digest "$source_digest" \
    '{"containerimage.digest": $digest}' >"$build_metadata"
  echo "Reusing immutable source image $source_tag@$source_digest"
else
  inspect_status=$?
  if [ -z "$image_platform" ] && [ "$inspect_status" -ne 3 ]; then
    exit "$inspect_status"
  fi
  if [ "$require_existing_source_image" = 1 ]; then
    echo "Required immutable source image is missing: $source_tag" >&2
    exit 1
  fi
  [ -n "$image_join" ] || create_buildx_builder
  if [ -n "$image_join" ]; then
    join_support_index
    if ! source_digest="$(inspect_manifest_digest "$source_tag")"; then
      echo "Unable to read the joined support index $source_tag" >&2
      exit 1
    fi
    jq -n --arg digest "$source_digest" \
      '{"containerimage.digest": $digest}' >"$build_metadata"
    echo "Joined ${join_digests[*]} into $source_tag@$source_digest"
  elif [ -n "$product_bake_target" ]; then
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
    )
    bake_args+=(
      --set "$product_bake_target.context=$context"
      --set "$product_bake_target.tags=$source_tag"
    )
    if [ "$sccache_mode" = r2 ]; then
      bake_args+=(
        --set "$product_bake_target.secrets+=id=aws_shared_credentials,src=$credentials_file"
      )
    fi
    cw_selected_source_dir="$(cd "$source_dir" && pwd -P)"
    [ "$(cd "$context" && pwd -P)" = "$cw_selected_source_dir" ] || {
      echo 'Protected CW image context differs from the selected release source' >&2
      exit 2
    }
    mkdir -p -- "$cw_image_work"
    DOCKER_CONFIG="$docker_config" \
      CODEWIRE_IMAGE_SOURCE_SHA="$source_sha" \
      CODEWIRE_IMAGE_SOURCE_URL="$public_source_url" \
      CODEWIRE_RUST_PROFILE=runtime \
      CODEWIRE_SCCACHE_MODE="$sccache_mode" \
      bash "$ROOT/scripts/ci/images/cw-image-consumer.sh" runtime "$cw_selected_source_dir" "$cw_image_work" -- \
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
    output_args=(--push --tag "$source_tag")
    if [ -n "$image_platform" ]; then
      output_args=(--output "type=image,name=$canonical_repository,push-by-digest=true,name-canonical=true,push=true")
    fi
    image_command=(docker buildx build --builder "$buildx_builder" --progress plain
      --provenance="$provenance" \
      --sbom="generator=$SBOM_GENERATOR_IMAGE" \
      --metadata-file "$build_metadata" "${platform_args[@]}" "${build_args[@]}" "${apt_mirror_args[@]}" \
      -f "$dockerfile" "${output_args[@]}" "${label_args[@]}" "$context")
    # The consumer runs the CW producer only when the build includes amd64,
    # the one platform that carries the admitted static asset.
    if [ "$image_name:$dockerfile_from_context" = workspace:images/workspace/Dockerfile ]; then
      cw_selected_source_dir="$(cd "$source_dir" && pwd -P)"
      [ "$(cd "$context" && pwd -P)" = "$cw_selected_source_dir" ] || {
        echo 'Protected CW image context differs from the selected release source' >&2
        exit 2
      }
      mkdir -p -- "$cw_image_work"
      follow_owned_logs "$cw_image_work"
    fi
    build_attempt=1
    while :; do
      build_status=0
      if [ "$image_name:$dockerfile_from_context" = workspace:images/workspace/Dockerfile ]; then
        # A retry reuses an admitted CW producer result and gets a fresh
        # consumer task (cw-image-consumer.sh).
        run_logged_build env DOCKER_CONFIG="$docker_config" \
          bash "$ROOT/scripts/ci/images/cw-image-consumer.sh" release "$cw_selected_source_dir" "$cw_image_work" -- \
          "${image_command[@]}" || build_status=$?
      else
        run_logged_build env DOCKER_CONFIG="$docker_config" "${image_command[@]}" || build_status=$?
      fi
      [ "$build_status" -ne 0 ] || break
      retry_network_build "$build_attempt" "$build_status" || exit "$build_status"
      build_attempt=$((build_attempt + 1))
    done
    stop_owned_logs
  fi
  if ! source_digest="$(jq -er '."containerimage.digest" | select(type == "string")' "$build_metadata")" \
    || [[ ! "$source_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "Buildx metadata is missing an immutable image digest" >&2
    exit 1
  fi
fi

verify_build_provenance
verify_build_sbom

if [ -n "$image_platform" ]; then
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf 'platform_digest=%s\n' "$source_digest" >>"$GITHUB_OUTPUT"
  else
    printf 'platform_digest=%s\n' "$source_digest"
  fi
  echo "Built and verified $image_platform $canonical_repository@$source_digest"
  exit 0
fi

for tag in "${tags[@]}"; do
  ensure_immutable_tag "$tag" "$source_digest"
done

python3 scripts/ci/images/image-bundle.py candidate \
  "$image_name" "$source_sha" "$REGISTRY_REPOSITORY_PREFIX" "$build_metadata"
