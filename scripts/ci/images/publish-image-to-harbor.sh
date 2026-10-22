#!/usr/bin/env bash
# Finish publication of images the build already pushed to Harbor, the registry
# every Codewire deployment pulls from: apply the requested tags without
# rebuilding, then prove each digest with the pull-only identity that Dev,
# Prod and sandbox consumers use.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly HARBOR_HOST="${CODEWIRE_IMAGE_REGISTRY:?set to the image registry host}"
readonly HARBOR_HOST_PATTERN="${HARBOR_HOST//./\\.}"
readonly source_pattern="^$HARBOR_HOST_PATTERN/codewire/(dashboard|derp|daemon|services|mesh|base|workspace|confidential-probe)@sha256:([0-9a-f]{64})\$"
readonly HARBOR_PROJECT="$HARBOR_HOST/codewire"
readonly PUBLIC_MIRROR='ghcr.io/codewiresh'

usage() {
  echo "Usage: $0 HARBOR_DIGEST_REF HARBOR_REPOSITORY TAG [TAG...]" >&2
  echo "       $0 --support-pair BASE_DIGEST_REF WORKSPACE_DIGEST_REF SOURCE_SHA" >&2
  echo "       $0 --runtime-bundle IMAGE_BUNDLE" >&2
  echo "       $0 --keep HARBOR_DIGEST_REF [HARBOR_DIGEST_REF...]" >&2
  echo "       $0 --pinned-defaults" >&2
  exit 2
}

# Each copy is (source_ref, repository, tags...) encoded as one tab-separated
# line; verification refs are (family, repository@digest, digest).
copies=()
verifications=()
# Compiled-in defaults absent from Harbor are imported once from the public
# mirror by exact digest: (family, digest).
imports=()

family_of() {
  local ref="$1"
  [[ "$ref" =~ $source_pattern ]] || return 1
  printf '%s\t%s\n' "${BASH_REMATCH[1]}" "sha256:${BASH_REMATCH[2]}"
}

add_copy() {
  local source_ref="$1" family digest parsed repository
  shift
  parsed="$(family_of "$source_ref")" || {
    echo "Source must be an exact supported Harbor digest reference" >&2
    exit 1
  }
  IFS=$'\t' read -r family digest <<<"$parsed"
  repository="$HARBOR_PROJECT/$family"
  copies+=("$(printf '%s\t%s' "$source_ref" "$repository"; printf '\t%s' "$@")")
  verifications+=("$(printf '%s\t%s@%s\t%s' "$family" "$repository" "$digest" "$digest")")
}

mode=single
case "${1:-}" in
  --runtime-bundle)
    [ "$#" -eq 2 ] || usage
    mode=runtime
    bundle_file="$2"
    bundle_tool="$ROOT/scripts/ci/images/image-bundle.py"
    [[ -x "$bundle_tool" && -f "$bundle_file" && ! -L "$bundle_file" ]] || {
      echo 'Runtime bundle must be a regular nonsymlink file and the validator must be executable' >&2
      exit 1
    }
    "$bundle_tool" validate "$bundle_file"
    runtime_source_sha="$(jq -er '.source.sha' "$bundle_file")"
    runtime_entries_text="$(jq -er '.images[] | [.family, .ref] | @tsv' "$bundle_file")"
    mapfile -t runtime_entries <<<"$runtime_entries_text"
    [[ "${#runtime_entries[@]}" -eq 5 ]] || {
      echo 'Runtime bundle must contain exactly five validated image entries' >&2
      exit 1
    }
    for entry in "${runtime_entries[@]}"; do
      IFS=$'\t' read -r runtime_family runtime_source_ref runtime_extra <<<"$entry"
      parsed="$(family_of "$runtime_source_ref")" || parsed=''
      if [[ -n "$runtime_extra" || "${parsed%%$'\t'*}" != "$runtime_family" ]]; then
        echo 'Runtime bundle entry does not preserve its validated image family' >&2
        exit 1
      fi
      add_copy "$runtime_source_ref" "$runtime_source_sha"
    done
    ;;
  --support-pair)
    [ "$#" -eq 4 ] || usage
    mode=support
    [[ "$4" =~ ^[0-9a-f]{40}$ ]] || {
      echo "Support image source must be an exact Git object ID" >&2
      exit 1
    }
    [[ "$(family_of "$2" | cut -f1)" == base ]] || {
      echo "Support base must be an exact Harbor base digest reference" >&2
      exit 1
    }
    [[ "$(family_of "$3" | cut -f1)" == workspace ]] || {
      echo "Support workspace must be an exact Harbor workspace digest reference" >&2
      exit 1
    }
    add_copy "$2" "$4" latest
    add_copy "$3" "$4" latest
    ;;
  --keep)
    [ "$#" -ge 2 ] || usage
    shift
    mode=keep
    for keep_ref in "$@"; do
      parsed="$(family_of "$keep_ref")" || {
        echo "Keep source must be an exact supported Harbor digest reference" >&2
        exit 1
      }
      keep_digest="${parsed#*$'\t'}"
      add_copy "$keep_ref" "keep-${keep_digest/:/-}"
    done
    ;;
  --pinned-defaults)
    [ "$#" -eq 1 ] || usage
    mode=keep
    # Sandboxes default to the published workspace pin. Keep it in Harbor
    # before any deployment references it. The daemon has no compiled-in
    # default: each deployment names its support image (SANDBOX_DAEMON_IMAGE,
    # docs/CONFIGURATION.md), which its own release publishes.
    mapfile -t keep_refs < <(
      python3 "$ROOT/scripts/ci/images/workspace-image-pin.py" show harbor-image
    )
    [ "${#keep_refs[@]}" -eq 1 ] || {
      echo 'The pinned Harbor workspace default was not found in source' >&2
      exit 1
    }
    for keep_ref in "${keep_refs[@]}"; do
      parsed="$(family_of "$keep_ref")" || {
        echo "Pinned default must be an exact supported Harbor digest reference" >&2
        exit 1
      }
      IFS=$'\t' read -r keep_family keep_digest <<<"$parsed"
      imports+=("$(printf '%s\t%s' "$keep_family" "$keep_digest")")
      add_copy "$keep_ref" "keep-${keep_digest/:/-}"
    done
    ;;
  *)
    [ "$#" -ge 3 ] || usage
    parsed="$(family_of "$1")" || {
      echo "Source must be an exact supported Harbor digest reference" >&2
      exit 1
    }
    if [ "$2" != "$HARBOR_PROJECT/${parsed%%$'\t'*}" ]; then
      echo "Harbor repository must match the supported source image family" >&2
      exit 1
    fi
    single_source="$1"
    shift 2
    add_copy "$single_source" "$@"
    ;;
esac

harbor_fetcher="${OPENBAO_HARBOR_CREDENTIAL_FETCHER:-scripts/ci/setup/fetch-openbao-harbor-credentials.sh}"
copy_helper="${HARBOR_COPY_HELPER:-scripts/ci/images/copy-image-to-ghcr.sh}"
skopeo_runner="${SKOPEO_RUNNER:-scripts/ci/images/run-skopeo-container.sh}"
docker_bin="${DOCKER_BIN:-docker}"
for helper in "$harbor_fetcher" "$copy_helper" "$skopeo_runner"; do
  if [ ! -x "$helper" ]; then
    echo "Required Harbor publication helper is missing or not executable" >&2
    exit 1
  fi
done
if ! "$skopeo_runner" --check; then
  echo "Pinned Skopeo runtime is unavailable" >&2
  exit 1
fi

umask 077
work="$(mktemp -d)"
pull_auth_volume=''
import_auth_volume=''
cleanup() {
  local volume
  for volume in "$pull_auth_volume" "$import_auth_volume"; do
    if [ -n "$volume" ]; then
      "$docker_bin" volume rm "$volume" >/dev/null 2>&1 || true
    fi
  done
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

new_auth_volume() {
  local volume
  volume="$("$docker_bin" volume create)"
  [[ "$volume" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || {
    echo "Docker returned a malformed auth volume name" >&2
    exit 1
  }
  printf '%s\n' "$volume"
}

"$harbor_fetcher" "$work/harbor-username" "$work/harbor-password"
"$harbor_fetcher" --pull "$work/harbor-pull-username" "$work/harbor-pull-password"

pull_auth_volume="$(new_auth_volume)"
SKOPEO_AUTH_VOLUME="$pull_auth_volume" \
  "$skopeo_runner" login --authfile /auth/auth.json \
  --username "$(<"$work/harbor-pull-username")" --password-stdin \
  "$HARBOR_HOST" <"$work/harbor-pull-password" >/dev/null
shred -u "$work/harbor-pull-password" 2>/dev/null || rm -f "$work/harbor-pull-password"

harbor_digest() {
  SKOPEO_AUTH_VOLUME="$pull_auth_volume" \
    "$skopeo_runner" inspect --authfile /auth/auth.json \
    --format '{{.Digest}}' "docker://$1"
}

# A default already in Harbor never touches the public mirror again.
for import in "${imports[@]}"; do
  IFS=$'\t' read -r import_family import_digest <<<"$import"
  harbor_ref="$HARBOR_PROJECT/$import_family@$import_digest"
  : >"$work/import.error"
  if present="$(harbor_digest "$harbor_ref" 2>"$work/import.error")" \
      && [ "$present" = "$import_digest" ]; then
    printf 'Pinned default already in Harbor: %s\n' "$harbor_ref"
    continue
  fi
  if ! grep -Eiq 'manifest unknown|name unknown|not found|status code: 404|status: 404' \
      "$work/import.error"; then
    echo "Unable to determine whether pinned default is in Harbor: $harbor_ref" >&2
    sed -n '1,20p' "$work/import.error" >&2
    exit 1
  fi
  if [ -z "$import_auth_volume" ]; then
    import_auth_volume="$(new_auth_volume)"
    SKOPEO_AUTH_VOLUME="$import_auth_volume" \
      "$skopeo_runner" login --authfile /auth/auth.json \
      --username "$(<"$work/harbor-username")" --password-stdin \
      "$HARBOR_HOST" <"$work/harbor-password" >/dev/null
  fi
  SKOPEO_AUTH_VOLUME="$import_auth_volume" \
    "$skopeo_runner" copy --all --preserve-digests --retry-times 3 \
    --src-no-creds --dest-authfile /auth/auth.json \
    "docker://$PUBLIC_MIRROR/$import_family@$import_digest" \
    "docker://$HARBOR_PROJECT/$import_family:keep-${import_digest/:/-}"
  printf 'Imported pinned default into Harbor: %s\n' "$harbor_ref"
done

for copy in "${copies[@]}"; do
  IFS=$'\t' read -r -a copy_args <<<"$copy"
  HARBOR_PUBLISH_USERNAME="$(<"$work/harbor-username")" \
  HARBOR_PUBLISH_PASSWORD_FILE="$work/harbor-password" \
    "$copy_helper" "${copy_args[@]}"
done
for token_file in "$work/harbor-username" "$work/harbor-password"; do
  shred -u "$token_file" 2>/dev/null || rm -f "$token_file"
done

# Prove the consumer path: the pull-only robot must read every exact digest.
for verification in "${verifications[@]}"; do
  IFS=$'\t' read -r family harbor_ref digest <<<"$verification"
  pulled_digest="$(harbor_digest "$harbor_ref")"
  if [ "$pulled_digest" != "$digest" ]; then
    echo "Harbor pull identity does not read the canonical digest: $harbor_ref" >&2
    exit 1
  fi
  printf 'Harbor pull identity accepted: %s\n' "$harbor_ref"
  if [ -n "${GITHUB_OUTPUT:-}" ] && [ "$mode" != keep ]; then
    printf '%s_harbor_ref=%s\n' "${family//-/_}" "$harbor_ref" >>"$GITHUB_OUTPUT"
  fi
done
