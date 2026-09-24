#!/usr/bin/env bash
# Publish exact promoted Nexus manifests to Harbor, the registry every Codewire
# deployment pulls from, then prove each digest with the pull-only identity
# that Dev, Prod and sandbox consumers use. Nothing is rebuilt.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly source_pattern='^nexus-system-cluster\.private\.invalid/oci-promoted/codewire/(dashboard|derp|gateway|services|mesh|base|workspace|confidential-probe)@sha256:([0-9a-f]{64})$'
readonly HARBOR_HOST='registry.example.invalid'
readonly HARBOR_PROJECT="$HARBOR_HOST/codewire"

usage() {
  echo "Usage: $0 SOURCE_DIGEST_REF HARBOR_REPOSITORY TAG [TAG...]" >&2
  echo "       $0 --support-pair BASE_DIGEST_REF WORKSPACE_DIGEST_REF SOURCE_SHA" >&2
  echo "       $0 --runtime-bundle IMAGE_BUNDLE" >&2
  echo "       $0 --keep SOURCE_DIGEST_REF [SOURCE_DIGEST_REF...]" >&2
  echo "       $0 --pinned-defaults" >&2
  exit 2
}

# Each copy is (source_ref, repository, tags...) encoded as one tab-separated
# line; verification refs are (family, repository@digest, digest).
copies=()
verifications=()

family_of() {
  local ref="$1"
  [[ "$ref" =~ $source_pattern ]] || return 1
  printf '%s\t%s\n' "${BASH_REMATCH[1]}" "sha256:${BASH_REMATCH[2]}"
}

add_copy() {
  local source_ref="$1" family digest parsed repository
  shift
  parsed="$(family_of "$source_ref")" || {
    echo "Source must be an exact supported promoted Nexus digest reference" >&2
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
      echo "Support base must be an exact promoted Nexus base digest reference" >&2
      exit 1
    }
    [[ "$(family_of "$3" | cut -f1)" == workspace ]] || {
      echo "Support workspace must be an exact promoted Nexus workspace digest reference" >&2
      exit 1
    }
    add_copy "$2" "$4" latest
    add_copy "$3" "$4" latest
    ;;
  --keep|--pinned-defaults)
    if [ "$1" = --pinned-defaults ]; then
      [ "$#" -eq 1 ] || usage
      # Sandboxes and gateways default to Harbor digests compiled into the
      # product. Keep each one in Harbor before any deployment references it.
      mapfile -t keep_refs < <(
        grep -ohE 'registry\.example\.invalid/codewire/(workspace|gateway)@sha256:[0-9a-f]{64}' \
          "$ROOT/crates/codewire-orchestration/src/sandbox/mod.rs" \
          "$ROOT/crates/codewire-orchestration/src/sandbox/template/mod.rs" \
          "$ROOT/crates/codewire-orchestration/src/worker/create.rs" \
          "$ROOT/deployments/k8s/base/config.env" |
          sort -u |
          sed 's#^registry\.example\.invalid/codewire/#nexus-system-cluster.example.invalid/oci-promoted/codewire/#'
      )
      [ "${#keep_refs[@]}" -ge 2 ] || {
        echo 'Pinned Harbor workspace and gateway defaults were not found in source' >&2
        exit 1
      }
    else
      [ "$#" -ge 2 ] || usage
      shift
      keep_refs=("$@")
    fi
    mode=keep
    for keep_ref in "${keep_refs[@]}"; do
      parsed="$(family_of "$keep_ref")" || {
        echo "Keep source must be an exact supported promoted Nexus digest reference" >&2
        exit 1
      }
      keep_digest="${parsed#*$'\t'}"
      add_copy "$keep_ref" "keep-${keep_digest/:/-}"
    done
    ;;
  *)
    [ "$#" -ge 3 ] || usage
    parsed="$(family_of "$1")" || {
      echo "Source must be an exact supported promoted Nexus digest reference" >&2
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

nexus_fetcher="${OPENBAO_NEXUS_CREDENTIAL_FETCHER:-scripts/ci/setup/fetch-openbao-nexus-credentials.sh}"
harbor_fetcher="${OPENBAO_HARBOR_CREDENTIAL_FETCHER:-scripts/ci/setup/fetch-openbao-harbor-credentials.sh}"
copy_helper="${HARBOR_COPY_HELPER:-scripts/ci/images/copy-image-to-ghcr.sh}"
skopeo_runner="${SKOPEO_RUNNER:-scripts/ci/images/run-skopeo-container.sh}"
docker_bin="${DOCKER_BIN:-docker}"
for helper in "$nexus_fetcher" "$harbor_fetcher" "$copy_helper" "$skopeo_runner"; do
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
cleanup() {
  if [ -n "$pull_auth_volume" ]; then
    "$docker_bin" volume rm "$pull_auth_volume" >/dev/null 2>&1 || true
  fi
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

"$nexus_fetcher" "$work/nexus-username" "$work/nexus-password"
"$harbor_fetcher" "$work/harbor-username" "$work/harbor-password"
"$harbor_fetcher" --pull "$work/harbor-pull-username" "$work/harbor-pull-password"

for copy in "${copies[@]}"; do
  IFS=$'\t' read -r -a copy_args <<<"$copy"
  NEXUS_REGISTRY_USERNAME_FILE="$work/nexus-username" \
  NEXUS_REGISTRY_PASSWORD_FILE="$work/nexus-password" \
  HARBOR_PUBLISH_USERNAME="$(<"$work/harbor-username")" \
  HARBOR_PUBLISH_PASSWORD_FILE="$work/harbor-password" \
    "$copy_helper" "${copy_args[@]}"
done
for token_file in "$work/nexus-username" "$work/nexus-password" \
    "$work/harbor-username" "$work/harbor-password"; do
  shred -u "$token_file" 2>/dev/null || rm -f "$token_file"
done

# Prove the consumer path: the pull-only robot must read every exact digest.
pull_auth_volume="$("$docker_bin" volume create)"
[[ "$pull_auth_volume" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || {
  echo "Docker returned a malformed auth volume name" >&2
  exit 1
}
SKOPEO_AUTH_VOLUME="$pull_auth_volume" \
  "$skopeo_runner" login --authfile /auth/auth.json \
  --username "$(<"$work/harbor-pull-username")" --password-stdin \
  "$HARBOR_HOST" <"$work/harbor-pull-password" >/dev/null
shred -u "$work/harbor-pull-password" 2>/dev/null || rm -f "$work/harbor-pull-password"

for verification in "${verifications[@]}"; do
  IFS=$'\t' read -r family harbor_ref digest <<<"$verification"
  pulled_digest="$(
    SKOPEO_AUTH_VOLUME="$pull_auth_volume" \
      "$skopeo_runner" inspect --authfile /auth/auth.json \
      --format '{{.Digest}}' "docker://$harbor_ref"
  )"
  if [ "$pulled_digest" != "$digest" ]; then
    echo "Harbor pull identity does not read the canonical digest: $harbor_ref" >&2
    exit 1
  fi
  printf 'Harbor pull identity accepted: %s\n' "$harbor_ref"
  if [ -n "${GITHUB_OUTPUT:-}" ] && [ "$mode" != keep ]; then
    printf '%s_harbor_ref=%s\n' "${family//-/_}" "$harbor_ref" >>"$GITHUB_OUTPUT"
  fi
done
