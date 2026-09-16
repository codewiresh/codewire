#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

readonly SNAPSHOT_ENVIRONMENT='ubuntu24-cft145'
readonly FIXTURE_RUN_ID='ubuntu24-cft145'
readonly BASE_IMAGE='docker.io/noeljackson/act-node-docker@sha256:62d111bd4fe0603bddebdc68deddeafefdb04a443ce5cfd048ed86f11d3b8050'
readonly REFERENCE_RUNNER_IMAGE='nexus-system-cluster.example.invalid/oci-approved/act-node-docker@sha256:2cbc40c091b1e5e3b48214e208d9fdff30a4f0afda5e661b5c6cde977b7f3bca'
readonly RENDERER_IMAGE='codewire/playwright-snapshot-renderer:ubuntu24-cft145'
readonly RENDERER_PATH='/opt/acttoolcache/node/24.18.1/x64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin'
readonly CHROMIUM_SHA256='b5e3195041af345a668d110f5daf5581961fa3608626ea588c97dd0fe81c4e38'
readonly KUBE_CONTEXT='kind-codewire'
readonly KUBE_NAMESPACE='default'
readonly PLAYWRIGHT_BASE_URL='http://127.0.0.1:8080'
readonly DATABASE_URL='postgres://codewire:codewire@127.0.0.1:25432/codewire?sslmode=disable'
readonly PREPARED_KIND_CONTEXT='kind-codewire-e2e-ci'
readonly PREPARED_KIND_NAMESPACE='codewire-e2e'
readonly PREPARED_KIND_PLAYWRIGHT_BASE_URL='http://127.0.0.1:8090'
readonly PREPARED_KIND_DATABASE_URL='postgres://codewire:codewire@127.0.0.1:25432/codewire?sslmode=disable'
readonly SNAPSHOT_RELATIVE_DIR='apps/dashboard/e2e'

SNAPSHOT_CLEANUP_RUN_ROOT=''
SNAPSHOT_CLEANUP_RUNTIME_PARENT=''
SNAPSHOT_CLEANUP_DOCKER_CONFIG=''
SNAPSHOT_CLEANUP_CONTAINER_CIDFILE=''
SNAPSHOT_CLEANUP_SNAPSHOT_DIR=''
SNAPSHOT_CLEANUP_PROFILE='default'
SNAPSHOT_CLEANUP_PID="$$"

usage() {
  cat <<'EOF'
Usage: update-playwright-ubuntu24-snapshots.sh --chromium-archive ABSOLUTE_PATH [--prepared-kind-management-secrets-mobile | --prepared-kind-terminal]

Regenerate the five affected dashboard snapshots whose checked-in suffix is
ubuntu24-cft145. The local Kind stack must already be running through `make up`.

With --prepared-kind-management-secrets-mobile, regenerate only the two mobile
Secrets snapshots and the mobile Security settings snapshot against the
already-running codewire-e2e-ci Kind topology. This profile never creates,
deploys, or forwards that topology and does not qualify the full runtime suite.

With --prepared-kind-terminal, regenerate only the existing desktop terminal
drawer and mobile terminal page goldens, using the desktop real-Kind lifecycle
test on that same prepared topology. Runtime assertions remain enabled. This
profile also never creates, deploys, or forwards the topology.

The Chromium archive must be chrome-linux64.zip for version 145.0.7632.6 with
the checksum pinned by scripts/ci/install-pinned-playwright-chromium.sh.
EOF
}

fail() {
  printf '[playwright-snapshots] ERROR: %s\n' "$*" >&2
  return 1
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    fail "missing required tool: $1"
    return 1
  }
}

isolated_docker_client() (
  local client_config="$1"
  shift

  unset DOCKER_AUTH_CONFIG DOCKER_CERT_PATH DOCKER_CONTEXT DOCKER_TLS_VERIFY \
    REGISTRY_AUTH_FILE
  export DOCKER_CONFIG="$client_config"
  export DOCKER_HOST='unix:///var/run/docker.sock'
  export HOME="$client_config/empty-home"
  export XDG_CONFIG_HOME="$client_config/empty-xdg"
  command "$@"
)

expected_snapshots() {
  case "${1:-default}" in
    default)
      cat <<'EOF'
ssr-dashboard.environments.ssr.ts-snapshots/environments-create-desktop-dashboard-ssr-desktop-ubuntu24-cft145.png
ssr-dashboard.environments.ssr.ts-snapshots/environments-create-mobile-dashboard-ssr-mobile-ubuntu24-cft145.png
ssr-dashboard.management-visual.ssr.ts-snapshots/management-settings-desktop-dashboard-ssr-desktop-ubuntu24-cft145.png
ssr-dashboard.management-visual.ssr.ts-snapshots/management-settings-mobile-dashboard-ssr-mobile-ubuntu24-cft145.png
ssr-dashboard.read.ssr.ts-snapshots/dashboard-desktop-dashboard-ssr-desktop-ubuntu24-cft145.png
EOF
      ;;
    prepared-kind-management-secrets-mobile)
      cat <<'EOF'
ssr-dashboard.management-visual.ssr.ts-snapshots/management-secrets-mobile-dashboard-ssr-mobile-ubuntu24-cft145.png
ssr-dashboard.management-visual.ssr.ts-snapshots/management-secret-bucket-mobile-dashboard-ssr-mobile-ubuntu24-cft145.png
ssr-dashboard.management-visual.ssr.ts-snapshots/management-security-mobile-dashboard-ssr-mobile-ubuntu24-cft145.png
EOF
      ;;
    prepared-kind-terminal)
      cat <<'EOF'
ssr-dashboard.environments.ssr.ts-snapshots/terminal-drawer-desktop-dashboard-ssr-desktop-ubuntu24-cft145.png
ssr-dashboard.environments.ssr.ts-snapshots/terminal-full-mobile-dashboard-ssr-desktop-ubuntu24-cft145.png
EOF
      ;;
    *)
      fail "unknown snapshot profile: $1"
      return 2
      ;;
  esac
}

retired_snapshots() {
  cat <<'EOF'
ssr-dashboard.environments.ssr.ts-snapshots/environments-prepared-image-desktop-dashboard-ssr-desktop-linux.png
ssr-dashboard.environments.ssr.ts-snapshots/environments-prepared-image-desktop-dashboard-ssr-desktop-ubuntu24-cft145.png
ssr-dashboard.environments.ssr.ts-snapshots/environments-prepared-image-mobile-dashboard-ssr-mobile-linux.png
ssr-dashboard.environments.ssr.ts-snapshots/environments-prepared-image-mobile-dashboard-ssr-mobile-ubuntu24-cft145.png
EOF
}

is_retired_snapshot() {
  local candidate="$1" expected

  while IFS= read -r expected; do
    [ "$candidate" = "$expected" ] && return 0
  done < <(retired_snapshots)
  return 1
}

validate_snapshot_worktree() {
  local source_root="$1" snapshot_relative_dir="$2"
  local record status path relative invalid=''

  while IFS= read -r -d '' record; do
    status="${record:0:2}"
    path="${record:3}"
    relative="${path#"$snapshot_relative_dir/"}"
    if [ "$path" = "$snapshot_relative_dir/$relative" ] &&
        { [ "$status" = ' D' ] || [ "$status" = 'D ' ]; } &&
        is_retired_snapshot "$relative"; then
      continue
    fi
    invalid="$status $path"
    break
  done < <(git -C "$source_root" status --porcelain=v1 -z --untracked-files=all -- \
    ":(glob)$snapshot_relative_dir/*-snapshots/*.png")

  [ -z "$invalid" ] || {
    fail "the dashboard snapshot tree has an unapproved change: $invalid"
    return 1
  }
}

snapshot_temporary_path() {
  local target="$1" relative="$2" directory basename

  directory="$(dirname "$relative")"
  basename="$(basename "$relative")"
  printf '%s/%s/.%s.new.%s\n' "$target" "$directory" "$basename" \
    "$SNAPSHOT_CLEANUP_PID"
}

snapshot_run_cleanup() {
  local status=$? relative container_id

  if [ -n "$SNAPSHOT_CLEANUP_DOCKER_CONFIG" ] &&
      [ -n "$SNAPSHOT_CLEANUP_CONTAINER_CIDFILE" ] &&
      container_id="$(read_container_id "$SNAPSHOT_CLEANUP_CONTAINER_CIDFILE" 2>/dev/null)"; then
    isolated_docker_client "$SNAPSHOT_CLEANUP_DOCKER_CONFIG" docker rm --force \
      "$container_id" >/dev/null 2>&1 || true
  fi
  if [ -n "$SNAPSHOT_CLEANUP_SNAPSHOT_DIR" ]; then
    while IFS= read -r relative; do
      rm -f -- "$(snapshot_temporary_path "$SNAPSHOT_CLEANUP_SNAPSHOT_DIR" "$relative")"
    done < <(expected_snapshots "$SNAPSHOT_CLEANUP_PROFILE")
  fi
  case "$SNAPSHOT_CLEANUP_RUN_ROOT" in
    "$SNAPSHOT_CLEANUP_RUNTIME_PARENT"/codewire-playwright-snapshots.*)
      [ -d "$SNAPSHOT_CLEANUP_RUN_ROOT" ] &&
        rm -rf -- "$SNAPSHOT_CLEANUP_RUN_ROOT"
      ;;
  esac
  return "$status"
}

read_container_id() {
  local cidfile="$1" container_id file_size final_byte

  [ -f "$cidfile" ] && [ ! -L "$cidfile" ] || {
    fail "Docker container ID file is missing or not a regular file: $cidfile"
    return 1
  }
  file_size="$(stat -c '%s' "$cidfile")"
  case "$file_size" in
    64) ;;
    65)
      final_byte="$(od -An -tx1 -j64 -N1 "$cidfile" | tr -d '[:space:]')"
      [ "$final_byte" = 0a ] || {
        fail 'Docker container ID file has invalid trailing content'
        return 1
      }
      ;;
    *)
      fail "Docker container ID file has invalid length: $file_size"
      return 1
      ;;
  esac
  container_id="$(head -c 64 "$cidfile")"
  [[ "$container_id" =~ ^[0-9a-f]{64}$ ]] || {
    fail "Docker returned an invalid container ID: ${container_id:-missing}"
    return 1
  }
  printf '%s\n' "$container_id"
}

is_expected_snapshot() {
  local profile="$1" candidate="$2" expected

  while IFS= read -r expected; do
    [ "$candidate" = "$expected" ] && return 0
  done < <(expected_snapshots "$profile")
  return 1
}

renderer_deb_manifest() {
  # These are the only browser-runtime packages added between BASE_IMAGE and
  # REFERENCE_RUNNER_IMAGE by its reviewed hermetic build recipe.
  cat <<'EOF'
libasound2-data_1.2.11-1ubuntu0.3_all.deb|0c26896193480d9dbb055e85e8ddfb9c9f34cf19afee340987cd6311e2886fc1|https://security.ubuntu.com/ubuntu/pool/main/a/alsa-lib/libasound2-data_1.2.11-1ubuntu0.3_all.deb
libasound2t64_1.2.11-1ubuntu0.3_amd64.deb|5d17bfb5683eb99f1be951fe48e1be5bf3c52391913b6b74a8aecf9b4f5e779f|https://security.ubuntu.com/ubuntu/pool/main/a/alsa-lib/libasound2t64_1.2.11-1ubuntu0.3_amd64.deb
libnspr4_4.35-1.1build1_amd64.deb|e579e72d091f6c7a13f5a756c31065b15aae5b81840d61b069355aa2283c07b4|https://archive.ubuntu.com/ubuntu/pool/main/n/nspr/libnspr4_4.35-1.1build1_amd64.deb
libnss3_3.98-1ubuntu0.2_amd64.deb|4254f11d782dfb970e78113519a59d440112ed43c4b56f709da0aef81da8651a|https://security.ubuntu.com/ubuntu/pool/main/n/nss/libnss3_3.98-1ubuntu0.2_amd64.deb
EOF
}

emit_renderer_dockerfile() {
  cat <<EOF
FROM ${BASE_IMAGE}

USER root

COPY libasound2-data_1.2.11-1ubuntu0.3_all.deb /tmp/codewire-renderer-debs/
COPY libasound2t64_1.2.11-1ubuntu0.3_amd64.deb /tmp/codewire-renderer-debs/
COPY libnspr4_4.35-1.1build1_amd64.deb /tmp/codewire-renderer-debs/
COPY libnss3_3.98-1ubuntu0.2_amd64.deb /tmp/codewire-renderer-debs/

RUN --network=none set -eux; \
    printf '%s  %s\n' '0c26896193480d9dbb055e85e8ddfb9c9f34cf19afee340987cd6311e2886fc1' '/tmp/codewire-renderer-debs/libasound2-data_1.2.11-1ubuntu0.3_all.deb' | sha256sum --check --strict -; \
    printf '%s  %s\n' '5d17bfb5683eb99f1be951fe48e1be5bf3c52391913b6b74a8aecf9b4f5e779f' '/tmp/codewire-renderer-debs/libasound2t64_1.2.11-1ubuntu0.3_amd64.deb' | sha256sum --check --strict -; \
    printf '%s  %s\n' 'e579e72d091f6c7a13f5a756c31065b15aae5b81840d61b069355aa2283c07b4' '/tmp/codewire-renderer-debs/libnspr4_4.35-1.1build1_amd64.deb' | sha256sum --check --strict -; \
    printf '%s  %s\n' '4254f11d782dfb970e78113519a59d440112ed43c4b56f709da0aef81da8651a' '/tmp/codewire-renderer-debs/libnss3_3.98-1ubuntu0.2_amd64.deb' | sha256sum --check --strict -; \
    dpkg --install /tmp/codewire-renderer-debs/*.deb; \
    test "\$(dpkg-query -W -f='\${Version}' libasound2-data)" = '1.2.11-1ubuntu0.3'; \
    test "\$(dpkg-query -W -f='\${Version}' libasound2t64)" = '1.2.11-1ubuntu0.3'; \
    test "\$(dpkg-query -W -f='\${Version}' libnspr4)" = '2:4.35-1.1build1'; \
    test "\$(dpkg-query -W -f='\${Version}' libnss3)" = '2:3.98-1ubuntu0.2'; \
    ldconfig; \
    rm -rf /tmp/codewire-renderer-debs

LABEL org.codewire.playwright.snapshot-environment="${SNAPSHOT_ENVIRONMENT}"
LABEL org.codewire.playwright.reference-runner="${REFERENCE_RUNNER_IMAGE}"
EOF
}

validate_chromium_archive() {
  local archive="$1" expected_sha256="${2:-$CHROMIUM_SHA256}"
  local actual_sha256

  [[ "$archive" = /* ]] || {
    fail 'Chromium archive path must be absolute'
    return 1
  }
  [[ "$archive" != *','* && "$archive" != *$'\n'* ]] ||
    {
      fail 'Chromium archive path contains a character unsupported by Docker bind mounts'
      return 1
    }
  [ ! -L "$archive" ] || {
    fail 'Chromium archive must not be a symlink'
    return 1
  }
  [ -f "$archive" ] || {
    fail "Chromium archive is not a regular file: $archive"
    return 1
  }
  [ -r "$archive" ] || {
    fail "Chromium archive is not readable: $archive"
    return 1
  }
  actual_sha256="$(sha256sum "$archive" | awk '{ print $1 }')"
  [ "$actual_sha256" = "$expected_sha256" ] ||
    {
      fail "Chromium archive checksum mismatch: expected $expected_sha256, found $actual_sha256"
      return 1
    }
}

validate_docker_mount_path() {
  local path="$1"

  [[ "$path" = /* ]] || {
    fail "Docker bind source is not absolute: $path"
    return 1
  }
  [[ "$path" != *','* && "$path" != *$'\n'* ]] || {
    fail "Docker bind source contains an unsupported character: $path"
    return 1
  }
}

read_renderer_image_id() {
  local iidfile="$1" image_id

  [ -f "$iidfile" ] || {
    fail "Docker renderer image ID file is missing: $iidfile"
    return 1
  }
  image_id="$(<"$iidfile")"
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    fail "Docker returned an invalid renderer image ID: ${image_id:-missing}"
    return 1
  }
  printf '%s\n' "$image_id"
}

validate_png() {
  local path="$1" magic
  [ -f "$path" ] && [ ! -L "$path" ] || {
    fail "snapshot is not a regular file: $path"
    return 1
  }
  magic="$(head -c 8 "$path" | od -An -tx1 | tr -d '[:space:]')"
  [ "$magic" = '89504e470d0a1a0a' ] || {
    fail "snapshot is not a PNG: $path"
    return 1
  }
}

validate_snapshot_stage() {
  local baseline="$1" stage="$2" profile="${3:-default}"
  local relative unexpected unapproved=''
  local paths_file

  unexpected="$(find "$stage" -mindepth 1 ! -type d ! -type f -print -quit)"
  [ -z "$unexpected" ] || {
    fail "snapshot staging contains a non-file entry: $unexpected"
    return 1
  }

  paths_file="$(mktemp)"
  {
    find "$baseline" -mindepth 1 -type f -printf '%P\n'
    find "$stage" -mindepth 1 -type f -printf '%P\n'
  } | LC_ALL=C sort -u >"$paths_file"

  while IFS= read -r relative; do
    if [ ! -f "$baseline/$relative" ] || [ ! -f "$stage/$relative" ] ||
        ! cmp -s "$baseline/$relative" "$stage/$relative"; then
      if ! is_expected_snapshot "$profile" "$relative"; then
        unapproved="$relative"
        break
      fi
    fi
  done <"$paths_file"
  rm -f "$paths_file"
  [ -z "$unapproved" ] || {
    fail "renderer changed an unapproved snapshot: $unapproved"
    return 1
  }

  while IFS= read -r relative; do
    validate_png "$stage/$relative"
  done < <(expected_snapshots "$profile")
}

promote_snapshots() {
  local stage="$1" target="$2" profile="${3:-default}" relative temporary

  while IFS= read -r relative; do
    mkdir -p "$target/$(dirname "$relative")"
    temporary="$(snapshot_temporary_path "$target" "$relative")"
    install -m 0644 "$stage/$relative" "$temporary"
  done < <(expected_snapshots "$profile")
  while IFS= read -r relative; do
    temporary="$(snapshot_temporary_path "$target" "$relative")"
    mv -f "$temporary" "$target/$relative"
  done < <(expected_snapshots "$profile")
}

snapshot_profile_context() {
  case "$1" in
    default) printf '%s\n' "$KUBE_CONTEXT" ;;
    prepared-kind-management-secrets-mobile|prepared-kind-terminal) printf '%s\n' "$PREPARED_KIND_CONTEXT" ;;
    *) fail "unknown snapshot profile: $1"; return 2 ;;
  esac
}

snapshot_profile_namespace() {
  case "$1" in
    default) printf '%s\n' "$KUBE_NAMESPACE" ;;
    prepared-kind-management-secrets-mobile|prepared-kind-terminal) printf '%s\n' "$PREPARED_KIND_NAMESPACE" ;;
    *) fail "unknown snapshot profile: $1"; return 2 ;;
  esac
}

snapshot_profile_origin() {
  case "$1" in
    default) printf '%s\n' "$PLAYWRIGHT_BASE_URL" ;;
    prepared-kind-management-secrets-mobile|prepared-kind-terminal) printf '%s\n' "$PREPARED_KIND_PLAYWRIGHT_BASE_URL" ;;
    *) fail "unknown snapshot profile: $1"; return 2 ;;
  esac
}

snapshot_profile_database_url() {
  case "$1" in
    default) printf '%s\n' "$DATABASE_URL" ;;
    prepared-kind-management-secrets-mobile|prepared-kind-terminal) printf '%s\n' "$PREPARED_KIND_DATABASE_URL" ;;
    *) fail "unknown snapshot profile: $1"; return 2 ;;
  esac
}

validate_snapshot_topology() {
  local profile="$1" docker_config="$2"
  local kube_context namespace expected_origin cluster deployment actual_origin dashboard_image

  kube_context="$(snapshot_profile_context "$profile")"
  namespace="$(snapshot_profile_namespace "$profile")"
  expected_origin="$(snapshot_profile_origin "$profile")"
  cluster="${kube_context#kind-}"
  if ! isolated_docker_client "$docker_config" kind get clusters | grep -Fxq "$cluster"; then
    if [ "$profile" = default ]; then
      fail 'local Kind cluster codewire is not running; run make up first'
    else
      fail "required prepared Kind cluster is not running: $cluster"
    fi
    return 1
  fi
  for deployment in codewire-dashboard codewire-idp codewire-orchestration; do
    kubectl --context "$kube_context" -n "$namespace" rollout status \
      "deployment/$deployment" --timeout=120s || {
        fail "required dashboard dependency is not Ready: deployment/$deployment"
        return 1
      }
  done
  if [ "$profile" = prepared-kind-management-secrets-mobile ] || [ "$profile" = prepared-kind-terminal ]; then
    kubectl --context "$kube_context" -n "$namespace" rollout status \
      deployment/codewire-credential-service --timeout=120s || {
        fail 'required dashboard dependency is not Ready: deployment/codewire-credential-service'
        return 1
      }
    dashboard_image="$(kubectl --context "$kube_context" -n "$namespace" get \
      deployment/codewire-dashboard \
      -o 'jsonpath={.spec.template.spec.containers[0].image}')" || {
        fail 'could not read the prepared Kind dashboard image'
        return 1
      }
    [ "$dashboard_image" = codewire-dashboard:e2e ] || {
      fail "prepared Kind dashboard image mismatch: expected codewire-dashboard:e2e, found ${dashboard_image:-missing}"
      return 1
    }
  fi
  actual_origin="$(kubectl --context "$kube_context" -n "$namespace" get \
    deployment/codewire-dashboard \
    -o 'jsonpath={.spec.template.spec.containers[0].env[?(@.name=="CODEWIRE_PUBLIC_ORIGIN")].value}')" || {
      fail 'could not read the dashboard public origin'
      return 1
    }
  [ "$actual_origin" = "$expected_origin" ] || {
    fail "dashboard origin mismatch: expected $expected_origin, found ${actual_origin:-missing}"
    return 1
  }
}

prepared_terminal_workspace_image() {
  local docker_config="$1" expected marker
  # Use the same source/image/archive proof as Kind's browser gate. Never
  # accept a caller-supplied image or a cluster marker without that proof.
  expected="$(isolated_docker_client "$docker_config" python3 \
    "$ROOT/scripts/ci/verify/workspace-image-artifact.py" reuse "$ROOT" \
    "$ROOT/.tmp/codewire-workspace-image-verification.json")" || {
      fail 'terminal renderer requires the source-verified workspace image'
      return 1
    }
  marker="$(kubectl --context "$PREPARED_KIND_CONTEXT" \
    -n "$PREPARED_KIND_NAMESPACE" get configmap/codewire-kind-e2e-prepared \
    -o 'jsonpath={.data.compatibility-version}{"\n"}{.data.cluster-name}{"\n"}{.data.workspace-image}')" || {
      fail 'could not read the prepared terminal workspace identity'
      return 1
    }
  [ "$marker" = "$(printf '1\ncodewire-e2e-ci\n%s' "$expected")" ] || {
    fail 'prepared terminal workspace does not match source-verified image'
    return 1
  }
  printf '%s\n' "$expected"
}

assert_kubectl_not_invoked() {
  [ -f "$1" ] || {
    fail 'renderer log is missing; snapshots were not promoted'
    return 1
  }
  if grep -Fq 'CODEWIRE_KUBECTL_SENTINEL_INVOKED' "$1"; then
    fail 'the renderer attempted to invoke kubectl; snapshots were not promoted'
  fi
}

download_renderer_debs() {
  local destination="$1" filename sha256 url

  while IFS='|' read -r filename sha256 url; do
    HOME="$destination/empty-home" \
      env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy \
      curl --disable --fail --location --silent --show-error --retry 3 --retry-all-errors \
        --proto '=https' --tlsv1.2 --output "$destination/$filename" "$url"
    printf '%s  %s\n' "$sha256" "$destination/$filename" |
      sha256sum --check --strict --status
  done < <(renderer_deb_manifest)
}

tracked_source_archive_sha256() {
  local source_root="$1" tracked_paths="$2"

  (
    cd "$source_root"
    tar -cf - --null --no-recursion --files-from="$tracked_paths"
  ) | sha256sum | awk '{ print $1 }'
}

existing_tracked_paths() {
  local source_root="$1" relative

  while IFS= read -r -d '' relative; do
    if [ -f "$source_root/$relative" ] || [ -L "$source_root/$relative" ]; then
      printf '%s\0' "$relative"
    elif [ -e "$source_root/$relative" ]; then
      fail "tracked path has an unsupported filesystem type: $relative"
      return 1
    fi
  done < <(git -C "$source_root" ls-files -z)
}

copy_tracked_source() {
  local destination="$1" tracked_paths="$2"

  mkdir -p "$destination"
  (
    cd "$ROOT"
    tar -cf - --null --no-recursion --files-from="$tracked_paths"
  ) | tar -C "$destination" -xf -

  # Keep every runtime write outside the read-only repository projection.
  ln -s /tmp/codewire-run/chromium "$destination/.tmp"
  ln -s /tmp/codewire-run/playwright "$destination/apps/dashboard/playwright"
}

validate_private_owned_directory() {
  local directory="$1" description="$2" owner mode

  [ ! -L "$directory" ] && [ -d "$directory" ] || {
    fail "$description is not a real directory: $directory"
    return 1
  }
  owner="$(stat -c '%u' "$directory")"
  mode="$(stat -c '%a' "$directory")"
  [ "$owner" = "$(id -u)" ] || {
    fail "$description is not owned by the current user: $directory"
    return 1
  }
  [ "$mode" = 700 ] || {
    fail "$description must have mode 0700, found $mode: $directory"
    return 1
  }
}

prepare_private_runtime_directory() {
  local runtime_base="${1:-}" runtime_directory

  if [ -n "$runtime_base" ]; then
    validate_private_owned_directory "$runtime_base" 'XDG runtime directory' || return 1
    runtime_directory="$runtime_base/codewire-playwright-snapshots"
  else
    runtime_directory="/tmp/codewire-playwright-snapshots-$(id -u)"
  fi
  (umask 077; mkdir "$runtime_directory") 2>/dev/null || true
  validate_private_owned_directory "$runtime_directory" 'snapshot runtime directory' || return 1
  printf '%s\n' "$runtime_directory"
}

install_projection_dependencies() {
  local source_tree="$1" environment_root="$2" bun_bin="${3:-}"

  [ -n "$bun_bin" ] || bun_bin="$(command -v bun)"
  [[ "$bun_bin" = /* ]] && [ -x "$bun_bin" ] || {
    fail "Bun executable is not an absolute executable path: ${bun_bin:-missing}"
    return 1
  }
  mkdir -p "$environment_root/home" "$environment_root/cache" \
    "$environment_root/config" "$environment_root/data" \
    "$environment_root/runtime" "$environment_root/tmp" \
    "$environment_root/bun-cache"
  chmod 0700 "$environment_root" "$environment_root/home" \
    "$environment_root/cache" "$environment_root/config" \
    "$environment_root/data" "$environment_root/runtime" \
    "$environment_root/tmp" "$environment_root/bun-cache"
  (
    cd "$source_tree"
    env -i \
      PATH=/usr/bin:/bin \
      HOME="$environment_root/home" \
      XDG_CACHE_HOME="$environment_root/cache" \
      XDG_CONFIG_HOME="$environment_root/config" \
      XDG_DATA_HOME="$environment_root/data" \
      XDG_RUNTIME_DIR="$environment_root/runtime" \
      BUN_INSTALL_CACHE_DIR="$environment_root/bun-cache" \
      TMPDIR="$environment_root/tmp" \
      PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
      "$bun_bin" install --frozen-lockfile --ignore-scripts
  )
  [ -e "$source_tree/apps/dashboard/node_modules/.bin/playwright" ] || {
    fail 'isolated dependency install did not produce the Playwright CLI'
    return 1
  }
}

main() {
  local chromium_archive='' runtime_parent run_root docker_config build_context
  local source_tree dependency_environment snapshot_dir snapshot_baseline snapshot_stage target_manifest
  local tracked_paths current_tracked_paths source_fingerprint projection_fingerprint
  local renderer_log renderer_iid renderer_image_id container_cidfile container_id
  local snapshot_profile='default' kube_context namespace playwright_base_url database_url
  local stale_count bun_bin runtime_workspace_image=''
  local docker_status=0 relative
  local lock_fd=''

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --chromium-archive)
        [ "$#" -ge 2 ] || {
          usage >&2
          return 2
        }
        chromium_archive="$2"
        shift 2
        ;;
      --prepared-kind-management-secrets-mobile|--prepared-kind-terminal)
        [ "$snapshot_profile" = default ] || {
          fail 'only one prepared Kind snapshot profile may be specified'
          return 2
        }
        snapshot_profile="${1#--}"
        shift
        ;;
      --help|-h)
        usage
        return 0
        ;;
      *)
        usage >&2
        fail "unknown argument: $1"
        return 2
        ;;
    esac
  done

  [ -n "$chromium_archive" ] || {
    usage >&2
    fail '--chromium-archive is required'
    return 2
  }
  [ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] ||
    fail 'the ubuntu24-cft145 renderer requires a Linux x86_64 host'

  for tool in awk bun cmp curl docker find flock git grep head id install kind kubectl mv od psql python3 \
      sha256sum sort stat tar tee tr; do
    require_tool "$tool"
  done
  validate_chromium_archive "$chromium_archive"
  bun_bin="$(command -v bun)"
  kube_context="$(snapshot_profile_context "$snapshot_profile")"
  namespace="$(snapshot_profile_namespace "$snapshot_profile")"
  playwright_base_url="$(snapshot_profile_origin "$snapshot_profile")"
  database_url="$(snapshot_profile_database_url "$snapshot_profile")"

  snapshot_dir="$ROOT/$SNAPSHOT_RELATIVE_DIR"
  [ -d "$snapshot_dir" ] || fail "snapshot directory is missing: $snapshot_dir"
  while IFS= read -r relative; do
    [ -f "$snapshot_dir/$relative" ] || fail "required baseline is missing: $relative"
  done < <(expected_snapshots "$snapshot_profile")
  validate_snapshot_worktree "$ROOT" "$SNAPSHOT_RELATIVE_DIR"

  runtime_parent="$(prepare_private_runtime_directory "${XDG_RUNTIME_DIR:-}")"
  validate_docker_mount_path "$ROOT"
  validate_docker_mount_path "$runtime_parent"
  run_root="$(mktemp -d "$runtime_parent/codewire-playwright-snapshots.XXXXXX")"
  chmod 0700 "$run_root"
  docker_config="$run_root/docker-config"
  build_context="$run_root/build-context"
  source_tree="$run_root/source"
  dependency_environment="$run_root/dependency-environment"
  snapshot_baseline="$run_root/snapshot-baseline"
  snapshot_stage="$run_root/snapshot-stage"
  target_manifest="$run_root/target.sha256"
  tracked_paths="$run_root/tracked-paths"
  current_tracked_paths="$run_root/current-tracked-paths"
  renderer_log="$run_root/renderer.log"
  renderer_iid="$run_root/renderer.iid"
  container_cidfile="$run_root/renderer.cid"

  SNAPSHOT_CLEANUP_RUN_ROOT="$run_root"
  SNAPSHOT_CLEANUP_RUNTIME_PARENT="$runtime_parent"
  SNAPSHOT_CLEANUP_DOCKER_CONFIG="$docker_config"
  SNAPSHOT_CLEANUP_CONTAINER_CIDFILE="$container_cidfile"
  SNAPSHOT_CLEANUP_SNAPSHOT_DIR="$snapshot_dir"
  SNAPSHOT_CLEANUP_PROFILE="$snapshot_profile"
  trap snapshot_run_cleanup EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  exec {lock_fd}<"$runtime_parent"
  if ! flock -w 120 "$lock_fd"; then
    fail 'timed out waiting for the local snapshot-renderer lock'
    return 1
  fi

  mkdir -p "$docker_config/empty-home" "$docker_config/empty-xdg" \
    "$build_context/empty-home" \
    "$snapshot_baseline" "$snapshot_stage"
  chmod 0700 "$docker_config" "$docker_config/empty-home" \
    "$docker_config/empty-xdg" "$build_context/empty-home"
  printf '{}\n' >"$docker_config/config.json"

  cp -a "$snapshot_dir/." "$snapshot_baseline/"
  cp -a "$snapshot_dir/." "$snapshot_stage/"
  while IFS= read -r relative; do
    sha256sum "$snapshot_dir/$relative"
    # Requiring Playwright to recreate every allowlisted file prevents a
    # renamed or newly skipped test from silently retaining a stale baseline.
    rm -f -- "$snapshot_stage/$relative"
  done < <(expected_snapshots "$snapshot_profile") >"$target_manifest"
  existing_tracked_paths "$ROOT" >"$tracked_paths"
  source_fingerprint="$(tracked_source_archive_sha256 "$ROOT" "$tracked_paths")"
  copy_tracked_source "$source_tree" "$tracked_paths"
  projection_fingerprint="$(tracked_source_archive_sha256 "$source_tree" "$tracked_paths")"
  [ "$projection_fingerprint" = "$source_fingerprint" ] ||
    fail 'tracked source changed while the read-only renderer projection was copied'
  install_projection_dependencies "$source_tree" "$dependency_environment" "$bun_bin"
  [ "$(tracked_source_archive_sha256 "$source_tree" "$tracked_paths")" = "$source_fingerprint" ] ||
    fail 'isolated dependency installation modified tracked source content'

  validate_snapshot_topology "$snapshot_profile" "$docker_config"
  if [ "$snapshot_profile" = prepared-kind-terminal ]; then
    runtime_workspace_image="$(prepared_terminal_workspace_image "$docker_config")" || return $?
  fi

  if [ "$snapshot_profile" = default ]; then
    env -u STATE_DIR KUBE_CONTEXT="$kube_context" NAMESPACE="$namespace" \
      "$ROOT/scripts/dev/kind/kind-forwards.sh" start postgres
  fi
  curl --disable --fail --silent --show-error "$playwright_base_url/login" >/dev/null
  PGPASSFILE=/dev/null psql -X "$database_url" -v ON_ERROR_STOP=1 -Atqc 'SELECT 1' >/dev/null
  stale_count="$(PGPASSFILE=/dev/null psql -X "$database_url" -v ON_ERROR_STOP=1 -Atqc \
    "SELECT COUNT(*) FROM environments e JOIN organizations o ON o.id = e.org_id WHERE o.slug LIKE 'e2e-%';")"
  stale_count="$(tr -d '[:space:]' <<<"$stale_count")"
  [ "$stale_count" = 0 ] ||
    fail "found $stale_count stale e2e environment row(s); clean them from the host before rendering"

  download_renderer_debs "$build_context"
  emit_renderer_dockerfile >"$build_context/Dockerfile"
  isolated_docker_client "$docker_config" docker pull --platform linux/amd64 "$BASE_IMAGE"
  isolated_docker_client "$docker_config" docker build --network=none --pull=false \
    --platform linux/amd64 --iidfile "$renderer_iid" \
    --tag "$RENDERER_IMAGE" "$build_context"
  renderer_image_id="$(read_renderer_image_id "$renderer_iid")"

  set +e
  # The command body is intentionally single-quoted so its variables expand
  # only inside the isolated renderer.
  # shellcheck disable=SC2016
  isolated_docker_client "$docker_config" docker run --rm --pull=never \
      --cidfile "$container_cidfile" --platform linux/amd64 \
      --network host --read-only --user "$(id -u):$(id -g)" \
      --cap-drop=ALL --security-opt=no-new-privileges:true \
      --pids-limit 1024 --cpus 2 --memory 4g --shm-size 2g \
      --tmpfs /tmp:rw,nosuid,nodev,exec,size=2g,mode=1777 \
      --mount "type=bind,src=$source_tree,dst=/workspace,readonly" \
      --mount "type=bind,src=$snapshot_stage,dst=/workspace/$SNAPSHOT_RELATIVE_DIR" \
      --mount "type=bind,src=$chromium_archive,dst=/inputs/chrome-linux64.zip,readonly" \
      --env HOME=/tmp/codewire-home \
      --env XDG_CACHE_HOME=/tmp/codewire-cache \
      --env XDG_CONFIG_HOME=/tmp/codewire-config \
      --env XDG_DATA_HOME=/tmp/codewire-data \
      --env XDG_RUNTIME_DIR=/tmp/codewire-runtime \
      --env KUBECONFIG=/nonexistent \
      --env DOCKER_HOST=unix:///nonexistent \
      --env HTTP_PROXY= --env HTTPS_PROXY= --env ALL_PROXY= \
      --env http_proxy= --env https_proxy= --env all_proxy= \
      --env NO_PROXY=localhost,127.0.0.1 \
      --env CI=1 \
      --env CODEWIRE_PLAYWRIGHT_SNAPSHOT_PROFILE="$snapshot_profile" \
      --env CODEWIRE_PLAYWRIGHT_SNAPSHOT_ENV="$SNAPSHOT_ENVIRONMENT" \
      --env CODEWIRE_PLAYWRIGHT_ENVIRONMENTS_FIXTURE_RUN_ID="$FIXTURE_RUN_ID" \
      --env DATABASE_URL="$database_url" \
      --env SERVER_URL="$playwright_base_url" \
      --env PLAYWRIGHT_BASE_URL="$playwright_base_url" \
      --env PLAYWRIGHT_RUNTIME_WORKSPACE_IMAGE="$runtime_workspace_image" \
      --env PATH="$RENDERER_PATH" \
      --workdir /workspace --entrypoint /bin/bash "$renderer_image_id" \
      -euo pipefail -c '
        mkdir -p /tmp/codewire-home /tmp/codewire-cache /tmp/codewire-config \
          /tmp/codewire-data /tmp/codewire-runtime /tmp/codewire-run/chromium \
          /tmp/codewire-run/playwright/.auth /tmp/codewire-run/test-results \
          /tmp/codewire-run/sentinel-bin
        printf "%s\n" "#!/usr/bin/env bash" \
          "echo CODEWIRE_KUBECTL_SENTINEL_INVOKED: kubectl is unavailable inside the snapshot renderer >&2" \
          "exit 97" > /tmp/codewire-run/sentinel-bin/kubectl
        chmod 0755 /tmp/codewire-run/sentinel-bin/kubectl
        export PATH="/tmp/codewire-run/sentinel-bin:$PATH"
        test "$(command -v node)" = /opt/acttoolcache/node/24.18.1/x64/bin/node
        test "$(node --version)" = v24.18.1
        test "$(./apps/dashboard/node_modules/.bin/playwright --version)" = "Version 1.58.1"
        chromium="$(CODEWIRE_CHROMIUM_ARCHIVE=/inputs/chrome-linux64.zip \
          bash /workspace/scripts/ci/install-pinned-playwright-chromium.sh)"
        source /workspace/scripts/ci/verify/playwright-browser-runtime.sh
        export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$chromium"
        prepare_playwright_browser_runtime "$chromium" /workspace
        case "$CODEWIRE_PLAYWRIGHT_SNAPSHOT_PROFILE" in
          default)
            ./apps/dashboard/node_modules/.bin/playwright test \
              --config apps/dashboard/playwright.config.ts \
              --project=dashboard-ssr-desktop \
              --project=dashboard-ssr-mobile \
              apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts \
              apps/dashboard/e2e/ssr-dashboard.management-visual.ssr.ts \
              apps/dashboard/e2e/ssr-dashboard.read.ssr.ts \
              --grep "renders server-owned create options and resources with no browser service caller|keeps environment create and inventory usable on mobile|renders account, security, and session surfaces in the selected context|renders the shared console shell and operational overview" \
              --output /tmp/codewire-run/test-results \
              --update-snapshots=changed --retries=0 --workers=1 --reporter=line
            ;;
          prepared-kind-management-secrets-mobile)
            ./apps/dashboard/node_modules/.bin/playwright test \
              --config apps/dashboard/playwright.config.ts \
              --project=dashboard-ssr-mobile \
              apps/dashboard/e2e/ssr-dashboard.management-visual.ssr.ts \
              --grep "renders every organization management surface without page overflow|renders account, security, and session surfaces in the selected context" \
              --output /tmp/codewire-run/test-results \
              --update-snapshots=changed --retries=0 --workers=1 --reporter=line
            ;;
          prepared-kind-terminal)
            ./apps/dashboard/node_modules/.bin/playwright test \
              --config apps/dashboard/playwright.config.ts \
              --project=dashboard-ssr-desktop \
              apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts \
              --grep "creates, runs, exposes a port, stops, starts, and destroys through real Kind" \
              --output /tmp/codewire-run/test-results \
              --update-snapshots=changed --retries=0 --workers=1 --reporter=line
            ;;
          *)
            printf "unknown snapshot profile: %s\n" "$CODEWIRE_PLAYWRIGHT_SNAPSHOT_PROFILE" >&2
            exit 98
            ;;
        esac
      ' 2>&1 | tee "$renderer_log"
  docker_status="${PIPESTATUS[0]}"
  set -e

  assert_kubectl_not_invoked "$renderer_log"
  [ "$docker_status" -eq 0 ] || fail "snapshot renderer exited with status $docker_status"
  container_id="$(read_container_id "$container_cidfile")"
  [ -n "$container_id" ] || fail 'Docker did not record the snapshot renderer container ID'
  validate_snapshot_stage "$snapshot_baseline" "$snapshot_stage" "$snapshot_profile"
  existing_tracked_paths "$ROOT" >"$current_tracked_paths"
  cmp -s "$tracked_paths" "$current_tracked_paths" ||
    fail 'the tracked source set changed while snapshots were rendered'
  [ "$(tracked_source_archive_sha256 "$ROOT" "$tracked_paths")" = "$source_fingerprint" ] ||
    fail 'tracked source content changed while snapshots were rendered'
  sha256sum --check --strict --status "$target_manifest" ||
    fail 'a target snapshot changed concurrently; refusing promotion'
  promote_snapshots "$snapshot_stage" "$snapshot_dir" "$snapshot_profile"

  printf '[playwright-snapshots] updated %s snapshots with %s\n' \
    "$(expected_snapshots "$snapshot_profile" | wc -l | tr -d '[:space:]')" "$SNAPSHOT_ENVIRONMENT"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
