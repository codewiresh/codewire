#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
# Mirror exact Harbor manifests to the public GHCR copy. Callers run this
# after delivery; it never gates a deployment.
readonly source_pattern='^registry\.example\.invalid/codewire/(dashboard|derp|daemon|services|mesh|base|workspace|confidential-probe)@sha256:([0-9a-f]{64})$'

usage() {
  echo "Usage: $0 SOURCE_DIGEST_REF GHCR_REPOSITORY TAG [TAG...]" >&2
  echo "       $0 --support-pair BASE_DIGEST_REF WORKSPACE_DIGEST_REF SOURCE_SHA" >&2
  echo "       $0 --runtime-bundle IMAGE_BUNDLE" >&2
  exit 2
}

support_pair=false
runtime_bundle=false
runtime_entries=()
if [ "${1:-}" = --runtime-bundle ]; then
  [ "$#" -eq 2 ] || usage
  runtime_bundle=true
  bundle_file="$2"
  bundle_tool="$ROOT/scripts/ci/images/image-bundle.py"
  [[ -x "$bundle_tool" && -f "$bundle_file" && ! -L "$bundle_file" ]] || {
    echo 'Runtime bundle must be a regular nonsymlink file and the validator must be executable' >&2
    exit 1
  }
  "$bundle_tool" validate "$bundle_file"
  runtime_source_sha="$(jq -er '.source.sha' "$bundle_file")"
  runtime_entries_text="$(
    jq -er '.images[] | [.family, .ref] | @tsv' "$bundle_file"
  )"
  mapfile -t runtime_entries <<<"$runtime_entries_text"
  [[ "${#runtime_entries[@]}" -eq 5 ]] || {
    echo 'Runtime bundle must contain exactly five validated image entries' >&2
    exit 1
  }
  for entry in "${runtime_entries[@]}"; do
    IFS=$'\t' read -r runtime_family runtime_source_ref runtime_extra <<<"$entry"
    if [[ -n "$runtime_extra" || ! "$runtime_source_ref" =~ $source_pattern ]]; then
      echo 'Runtime bundle entry does not preserve its validated image family' >&2
      exit 1
    fi
    if [[ "${BASH_REMATCH[1]}" != "$runtime_family" ]]; then
      echo 'Runtime bundle entry does not preserve its validated image family' >&2
      exit 1
    fi
  done
elif [ "${1:-}" = --support-pair ]; then
  [ "$#" -eq 4 ] || usage
  support_pair=true
  base_source_ref="$2"
  workspace_source_ref="$3"
  source_sha="$4"
  [[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || {
    echo "Support image source must be an exact Git object ID" >&2
    exit 1
  }
  if [[ ! "$base_source_ref" =~ $source_pattern ]] \
      || [ "${BASH_REMATCH[1]:-}" != base ]; then
    echo "Support base must be an exact Harbor base digest reference" >&2
    exit 1
  fi
  base_digest="sha256:${BASH_REMATCH[2]}"
  if [[ ! "$workspace_source_ref" =~ $source_pattern ]] \
      || [ "${BASH_REMATCH[1]:-}" != workspace ]; then
    echo "Support workspace must be an exact Harbor workspace digest reference" >&2
    exit 1
  fi
  workspace_digest="sha256:${BASH_REMATCH[2]}"
  base_repository='ghcr.io/codewiresh/base'
  workspace_repository='ghcr.io/codewiresh/workspace'
else
  [ "$#" -ge 3 ] || usage
  source_ref="$1"
  target_repository="$2"
  if [[ ! "$source_ref" =~ $source_pattern ]]; then
    echo "Source must be an exact supported Harbor digest reference" >&2
    exit 1
  fi
  image_name="${BASH_REMATCH[1]}"
  expected_digest="sha256:${BASH_REMATCH[2]}"
  if [ "$target_repository" != "ghcr.io/codewiresh/$image_name" ]; then
    echo "GHCR repository must match the supported source image family" >&2
    exit 1
  fi
fi

harbor_fetcher="${OPENBAO_HARBOR_CREDENTIAL_FETCHER:-scripts/ci/setup/fetch-openbao-harbor-credentials.sh}"
ghcr_fetcher="${OPENBAO_GHCR_CREDENTIAL_FETCHER:-scripts/ci/setup/fetch-openbao-ghcr-credentials.sh}"
copy_helper="${GHCR_COPY_HELPER:-scripts/ci/images/copy-image-to-ghcr.sh}"
skopeo_runner="${SKOPEO_RUNNER:-scripts/ci/images/run-skopeo-container.sh}"
for helper in "$harbor_fetcher" "$ghcr_fetcher" "$copy_helper"; do
  if [ ! -x "$helper" ]; then
    echo "Required GHCR publication helper is missing or not executable" >&2
    exit 1
  fi
done
if [ ! -x "$skopeo_runner" ]; then
  echo "Pinned Skopeo container runner is required for GHCR verification" >&2
  exit 1
fi
if ! "$skopeo_runner" --check; then
  echo "Pinned Skopeo runtime is unavailable" >&2
  exit 1
fi

if [ "$support_pair" = true ]; then
  for public_repository in "$base_repository" "$workspace_repository"; do
    if ! "$skopeo_runner" list-tags --no-creds \
        "docker://$public_repository" >/dev/null; then
      echo "Support package must be anonymously readable before GHCR mutation: $public_repository" >&2
      exit 1
    fi
  done
fi

umask 077
work="$(mktemp -d)"
harbor_username_file="$work/harbor-username"
harbor_password_file="$work/harbor-password"
ghcr_username_file="$work/ghcr-publish-username"
ghcr_token_file="$work/ghcr-publish-token"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

"$harbor_fetcher" "$harbor_username_file" "$harbor_password_file"
"$ghcr_fetcher" "$ghcr_username_file" "$ghcr_token_file"

copy_image() {
  HARBOR_PUBLISH_USERNAME="$(<"$harbor_username_file")" \
  HARBOR_PUBLISH_PASSWORD_FILE="$harbor_password_file" \
  GHCR_PUBLISH_USERNAME="$(<"$ghcr_username_file")" \
  GHCR_PUBLISH_TOKEN_FILE="$ghcr_token_file" \
    "$copy_helper" "$@"
}

anonymous_digest() {
  local public_ref="$1"
  "$skopeo_runner" inspect --no-creds --format '{{.Digest}}' \
    "docker://$public_ref"
}

verify_anonymous_digest() {
  local public_ref="$1" expected="$2" public_digest
  public_digest="$(anonymous_digest "$public_ref")"
  if [ "$public_digest" != "$expected" ]; then
    echo "Anonymous GHCR manifest digest does not match the canonical image: $public_ref" >&2
    exit 1
  fi
  printf 'Anonymous GHCR digest accepted: %s\n' "$public_ref"
}

if [ "$runtime_bundle" = true ]; then
  runtime_public_refs=()
  runtime_digests=()
  runtime_families=()
  for entry in "${runtime_entries[@]}"; do
    IFS=$'\t' read -r runtime_family runtime_source_ref <<<"$entry"
    runtime_repository="ghcr.io/codewiresh/$runtime_family"
    runtime_digest="${runtime_source_ref##*@}"
    copy_image "$runtime_source_ref" "$runtime_repository" "$runtime_source_sha"
    runtime_families+=("$runtime_family")
    runtime_public_refs+=("$runtime_repository@$runtime_digest")
    runtime_digests+=("$runtime_digest")
  done

  for token_file in "$harbor_username_file" "$harbor_password_file" \
      "$ghcr_username_file" "$ghcr_token_file"; do
    shred -u "$token_file" 2>/dev/null || rm -f "$token_file"
  done

  for index in "${!runtime_public_refs[@]}"; do
    verify_anonymous_digest \
      "${runtime_public_refs[$index]}" "${runtime_digests[$index]}"
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
      printf '%s_ghcr_public_ref=%s\n' \
        "${runtime_families[$index]}" "${runtime_public_refs[$index]}" \
        >>"$GITHUB_OUTPUT"
    fi
  done
  exit 0
fi

if [ "$support_pair" = true ]; then
  base_public_ref="$base_repository@$base_digest"
  workspace_public_ref="$workspace_repository@$workspace_digest"

  copy_image "$base_source_ref" "$base_repository" "$source_sha"
  verify_anonymous_digest "$base_public_ref" "$base_digest"
  copy_image "$workspace_source_ref" "$workspace_repository" "$source_sha"
  verify_anonymous_digest "$workspace_public_ref" "$workspace_digest"

  copy_image "$base_source_ref" "$base_repository" latest
  copy_image "$workspace_source_ref" "$workspace_repository" latest

  for token_file in "$harbor_username_file" "$harbor_password_file" \
      "$ghcr_username_file" "$ghcr_token_file"; do
    shred -u "$token_file" 2>/dev/null || rm -f "$token_file"
  done

  verify_anonymous_digest "$base_repository:latest" "$base_digest"
  verify_anonymous_digest "$workspace_repository:latest" "$workspace_digest"

  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
      printf 'base_ghcr_public_ref=%s\n' "$base_public_ref"
      printf 'workspace_ghcr_public_ref=%s\n' "$workspace_public_ref"
    } >>"$GITHUB_OUTPUT"
  fi
  exit 0
fi

copy_image "$@"

for token_file in "$harbor_username_file" "$harbor_password_file" \
    "$ghcr_username_file" "$ghcr_token_file"; do
  shred -u "$token_file" 2>/dev/null || rm -f "$token_file"
done

public_ref="$target_repository@$expected_digest"
verify_anonymous_digest "$public_ref" "$expected_digest"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  printf 'ghcr_public_ref=%s\n' "$public_ref" >>"$GITHUB_OUTPUT"
fi
