#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUNNER="$ROOT/scripts/ci/verify/update-playwright-ubuntu24-snapshots.sh"
PRODUCT_VERIFY="$ROOT/scripts/ci/verify/run-product-verification.sh"
ENVIRONMENT_SPEC="$ROOT/apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts"
MANAGEMENT_SPEC="$ROOT/apps/dashboard/e2e/ssr-dashboard.management-visual.ssr.ts"
DASHBOARD_SPEC="$ROOT/apps/dashboard/e2e/ssr-dashboard.read.ssr.ts"
CHROMIUM_INSTALLER="$ROOT/scripts/ci/install-pinned-playwright-chromium.sh"

die() {
  printf '[test-kind-e2e-ubuntu-snapshot-runner] ERROR: %s\n' "$*" >&2
  exit 1
}

# shellcheck source=scripts/ci/verify/update-playwright-ubuntu24-snapshots.sh
source "$RUNNER"

fixture="$(mktemp -d)"
trap 'rm -rf -- "$fixture"' EXIT

dockerfile="$fixture/Dockerfile"
emit_renderer_dockerfile >"$dockerfile"

[ "$BASE_IMAGE" = 'docker.io/noeljackson/act-node-docker@sha256:62d111bd4fe0603bddebdc68deddeafefdb04a443ce5cfd048ed86f11d3b8050' ] ||
  die 'public renderer base changed without updating its contract'
[ "$REFERENCE_RUNNER_IMAGE" = 'nexus-system-cluster.example.invalid/oci-approved/act-node-docker@sha256:2cbc40c091b1e5e3b48214e208d9fdff30a4f0afda5e661b5c6cde977b7f3bca' ] ||
  die 'reference ci-heavy runner changed without updating its contract'
[ "$RENDERER_PATH" = '/opt/acttoolcache/node/24.18.1/x64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin' ] ||
  die 'renderer PATH changed without updating its immutable-base contract'
[ "$FIXTURE_RUN_ID" = 'ubuntu24-cft145' ] ||
  die 'Ubuntu snapshot fixture run ID changed without updating its contract'
# shellcheck disable=SC2153 # Set by the sourced updater.
[ "$SNAPSHOT_RELATIVE_DIR" = 'apps/dashboard/e2e' ] ||
  die 'snapshot staging root changed without updating its contract'
[ "$(expected_snapshots)" = "$(cat <<'EOF'
ssr-dashboard.environments.ssr.ts-snapshots/environments-create-desktop-dashboard-ssr-desktop-ubuntu24-cft145.png
ssr-dashboard.environments.ssr.ts-snapshots/environments-create-mobile-dashboard-ssr-mobile-ubuntu24-cft145.png
ssr-dashboard.management-visual.ssr.ts-snapshots/management-settings-desktop-dashboard-ssr-desktop-ubuntu24-cft145.png
ssr-dashboard.management-visual.ssr.ts-snapshots/management-settings-mobile-dashboard-ssr-mobile-ubuntu24-cft145.png
ssr-dashboard.read.ssr.ts-snapshots/dashboard-desktop-dashboard-ssr-desktop-ubuntu24-cft145.png
EOF
)" ] || die 'expected snapshot allowlist changed without updating its contract'
[ "$(expected_snapshots prepared-kind-management-secrets-mobile)" = "$(cat <<'EOF'
ssr-dashboard.management-visual.ssr.ts-snapshots/management-secrets-mobile-dashboard-ssr-mobile-ubuntu24-cft145.png
ssr-dashboard.management-visual.ssr.ts-snapshots/management-secret-bucket-mobile-dashboard-ssr-mobile-ubuntu24-cft145.png
ssr-dashboard.management-visual.ssr.ts-snapshots/management-security-mobile-dashboard-ssr-mobile-ubuntu24-cft145.png
EOF
)" ] || die 'prepared Kind snapshot profile does not select exactly the three affected mobile surfaces'
[ "$(expected_snapshots prepared-kind-creation)" = "$(cat <<'EOF'
ssr-dashboard.environments.ssr.ts-snapshots/environments-create-desktop-dashboard-ssr-desktop-ubuntu24-cft145.png
ssr-dashboard.environments.ssr.ts-snapshots/environments-create-mobile-dashboard-ssr-mobile-ubuntu24-cft145.png
EOF
)" ] || die 'creation snapshot profile does not select exactly the two existing creation goldens'
if expected_snapshots unknown-profile >/dev/null 2>&1; then
  die 'unknown snapshot profile was accepted'
fi
[ "$(snapshot_profile_context default)" = kind-codewire ] &&
  [ "$(snapshot_profile_namespace default)" = default ] &&
  [ "$(snapshot_profile_origin default)" = http://127.0.0.1:8080 ] &&
  [ "$(snapshot_profile_database_url default)" = \
    'postgres://codewire:codewire@127.0.0.1:25432/codewire?sslmode=disable' ] ||
  die 'default snapshot topology changed'
[ "$(snapshot_profile_context prepared-kind-management-secrets-mobile)" = \
    kind-codewire-e2e-ci ] &&
  [ "$(snapshot_profile_namespace prepared-kind-management-secrets-mobile)" = \
    codewire-e2e ] &&
  [ "$(snapshot_profile_origin prepared-kind-management-secrets-mobile)" = \
    http://127.0.0.1:8090 ] &&
  [ "$(snapshot_profile_database_url prepared-kind-management-secrets-mobile)" = \
    'postgres://codewire:codewire@127.0.0.1:25432/codewire?sslmode=disable' ] ||
  die 'prepared Kind snapshot topology changed'
[ "$(snapshot_profile_context prepared-kind-creation)" = kind-codewire-e2e-ci ] &&
  [ "$(snapshot_profile_namespace prepared-kind-creation)" = codewire-e2e ] &&
  [ "$(snapshot_profile_origin prepared-kind-creation)" = http://127.0.0.1:8090 ] &&
  [ "$(snapshot_profile_database_url prepared-kind-creation)" = \
    'postgres://codewire:codewire@127.0.0.1:25432/codewire?sslmode=disable' ] ||
  die 'creation snapshot profile changed the prepared Kind topology'
creation_renderer="$(sed -n '/^          prepared-kind-creation)/,/;;/p' "$RUNNER")"
for creation_contract in \
    '--project=dashboard-ssr-desktop --project=dashboard-ssr-mobile' \
    'apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts' \
    '--grep "renders server-owned create options and resources with no browser service caller|keeps environment create and inventory usable on mobile"' \
    '--update-snapshots=changed --retries=0 --workers=1 --reporter=line'; do
  grep -Fq -- "$creation_contract" <<<"$creation_renderer" ||
    die "creation renderer is missing its bounded selection: $creation_contract"
done
if grep -Eq -- '--grep-invert|--no-deps|management-visual\.ssr|read\.ssr|destroys through real Kind' <<<"$creation_renderer"; then
  die 'creation renderer skips dependencies or selects unrelated surfaces'
fi
desktop_creation_owner="$(sed -n '/  test("renders server-owned create options and resources with no browser service caller"/,/^  });/p' "$ENVIRONMENT_SPEC")"
mobile_creation_owner="$(sed -n '/  test("keeps environment create and inventory usable on mobile"/,/^  });/p' "$ENVIRONMENT_SPEC")"
if ! grep -Fq 'toHaveScreenshot("environments-create-desktop.png")' <<<"$desktop_creation_owner" ||
    ! grep -Fq 'toHaveScreenshot("environments-create-mobile.png")' <<<"$mobile_creation_owner"; then
  die 'creation profile selections do not own their required screenshots'
fi
[ "$(retired_snapshots)" = "$(cat <<'EOF'
ssr-dashboard.environments.ssr.ts-snapshots/environments-prepared-image-desktop-dashboard-ssr-desktop-linux.png
ssr-dashboard.environments.ssr.ts-snapshots/environments-prepared-image-desktop-dashboard-ssr-desktop-ubuntu24-cft145.png
ssr-dashboard.environments.ssr.ts-snapshots/environments-prepared-image-mobile-dashboard-ssr-mobile-linux.png
ssr-dashboard.environments.ssr.ts-snapshots/environments-prepared-image-mobile-dashboard-ssr-mobile-ubuntu24-cft145.png
EOF
)" ] || die 'retired snapshot deletion allowlist changed without updating its contract'
[ "$CHROMIUM_SHA256" = "$(sed -n "s/^readonly chromium_sha256='\([^']*\)'/\1/p" "$CHROMIUM_INSTALLER")" ] ||
  die 'snapshot updater Chromium checksum drifted from the pinned installer'
[ "$(renderer_deb_manifest | wc -l | tr -d '[:space:]')" = 4 ] ||
  die 'renderer manifest does not contain exactly four Ubuntu packages'
grep -Fxq "FROM $BASE_IMAGE" "$dockerfile" ||
  die 'renderer Dockerfile does not use the public immutable base'
grep -Fq "$REFERENCE_RUNNER_IMAGE" "$dockerfile" ||
  die 'renderer does not record the exact CI runner it reproduces'
[ "$(grep -c '^COPY .*\.deb ' "$dockerfile")" = 4 ] ||
  die 'renderer Dockerfile copies something other than the four pinned debs'
grep -Fq 'RUN --network=none' "$dockerfile" ||
  die 'renderer package installation is not networkless'

while IFS='|' read -r filename sha256 url; do
  grep -Fq "$filename" "$dockerfile" || die "renderer omits $filename"
  grep -Fq "$sha256" "$dockerfile" || die "renderer does not verify $filename"
  [[ "$url" = https://archive.ubuntu.com/ubuntu/* ||
      "$url" = https://security.ubuntu.com/ubuntu/* ]] ||
    die "renderer package does not use an official Ubuntu origin: $filename"
done < <(renderer_deb_manifest)

# These are literal source contracts, including the shell variables expanded by
# the runner rather than this fixture.
# shellcheck disable=SC2016
for required in \
    'docker build --network=none --pull=false' \
    '--platform linux/amd64 --iidfile "$renderer_iid"' \
    'docker run --rm --pull=never' \
    '--cidfile "$container_cidfile" --platform linux/amd64' \
    '--network host --read-only --user "$(id -u):$(id -g)"' \
    '--cap-drop=ALL --security-opt=no-new-privileges:true' \
    '--pids-limit 1024 --cpus 2 --memory 4g --shm-size 2g' \
    '--tmpfs /tmp:rw,nosuid,nodev,exec,size=2g,mode=1777' \
    'src=$source_tree,dst=/workspace,readonly' \
    'src=$snapshot_stage,dst=/workspace/$SNAPSHOT_RELATIVE_DIR' \
    'src=$chromium_archive,dst=/inputs/chrome-linux64.zip,readonly' \
    '--env PATH="$RENDERER_PATH"' \
    'export PATH="/tmp/codewire-run/sentinel-bin:$PATH"' \
    'test "$(command -v node)" = /opt/acttoolcache/node/24.18.1/x64/bin/node' \
    'test "$(node --version)" = v24.18.1' \
    'test "$(./apps/dashboard/node_modules/.bin/playwright --version)" = "Version 1.58.1"' \
    '--env KUBECONFIG=/nonexistent' \
    '--env DOCKER_HOST=unix:///nonexistent' \
    '--env HTTP_PROXY= --env HTTPS_PROXY= --env ALL_PROXY=' \
    '--env NO_PROXY=localhost,127.0.0.1' \
    '--env CODEWIRE_PLAYWRIGHT_ENVIRONMENTS_FIXTURE_RUN_ID="$FIXTURE_RUN_ID"' \
    '--env CODEWIRE_PLAYWRIGHT_SNAPSHOT_PROFILE="$snapshot_profile"' \
    'validate_snapshot_worktree "$ROOT" "$SNAPSHOT_RELATIVE_DIR"' \
    'existing_tracked_paths "$ROOT" >"$tracked_paths"' \
    'rm -f -- "$snapshot_stage/$relative"' \
    '--project=dashboard-ssr-desktop' \
    '--project=dashboard-ssr-mobile' \
    '--output /tmp/codewire-run/test-results' \
    '--update-snapshots=changed --retries=0 --workers=1 --reporter=line'; do
  grep -Fq -- "$required" "$RUNNER" || die "runner is missing contract: $required"
done

for prepared_contract in \
    '--prepared-kind-management-secrets-mobile' \
    '--project=dashboard-ssr-mobile' \
    'renders every organization management surface without page overflow' \
    'renders account, security, and session surfaces in the selected context' \
    'deployment/codewire-credential-service' \
    'codewire-dashboard:e2e'; do
  grep -Fq -- "$prepared_contract" "$RUNNER" ||
    die "prepared Kind profile is missing contract: $prepared_contract"
done
if grep -Fq -- '--project=dashboard-ssr-desktop' \
    <(sed -n '/prepared-kind-management-secrets-mobile)/,/;;/p' "$RUNNER"); then
  die 'prepared Kind profile unexpectedly selects the desktop renderer'
fi
# shellcheck disable=SC2016
for fixture_id_contract in \
    'process.env.CODEWIRE_PLAYWRIGHT_ENVIRONMENTS_FIXTURE_RUN_ID' \
    'fixtureRunIdOverride !== undefined' \
    '/^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/.test(fixtureRunIdOverride)' \
    'fixtureRunIdOverride ?? `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`'; do
  grep -Fq -- "$fixture_id_contract" "$ENVIRONMENT_SPEC" ||
    die "environment fixture run ID is missing contract: $fixture_id_contract"
done
# shellcheck disable=SC2016
for dependency_contract in \
    'install_projection_dependencies "$source_tree" "$dependency_environment" "$bun_bin"' \
    'env -i' \
    'PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1' \
    'install --frozen-lockfile --ignore-scripts' \
    'BUN_INSTALL_CACHE_DIR="$environment_root/bun-cache"'; do
  grep -Fq -- "$dependency_contract" "$RUNNER" ||
    die "isolated dependency install is missing contract: $dependency_contract"
done
for credential_variable in DOCKER_AUTH_CONFIG DOCKER_CERT_PATH DOCKER_CONTEXT \
    DOCKER_TLS_VERIFY REGISTRY_AUTH_FILE; do
  grep -Fq "$credential_variable" "$RUNNER" ||
    die "isolated Docker client does not clear $credential_variable"
done

mkdir -p "$fixture/docker-client"
probe="$fixture/docker-environment-probe"
cat >"$probe" <<'EOF'
#!/usr/bin/env bash
printf '%s|%s|%s|%s|%s|%s\n' \
  "$DOCKER_CONFIG" "$DOCKER_HOST" "$HOME" "$XDG_CONFIG_HOME" \
  "${DOCKER_AUTH_CONFIG-unset}" "${DOCKER_CONTEXT-unset}"
EOF
chmod 0755 "$probe"
docker_environment="$(
  DOCKER_AUTH_CONFIG=owner-auth DOCKER_CONTEXT=owner-context HOME=/owner/home \
    isolated_docker_client "$fixture/docker-client" bash "$probe"
)"
[ "$docker_environment" = "$fixture/docker-client|unix:///var/run/docker.sock|$fixture/docker-client/empty-home|$fixture/docker-client/empty-xdg|unset|unset" ] ||
  die 'Docker client isolation retained ambient owner configuration'

source_repo="$fixture/source-repo"
source_projection="$fixture/source-projection"
tracked_paths="$fixture/tracked-paths"
mkdir -p "$source_repo/apps/dashboard/e2e"
git -C "$source_repo" init -q
printf 'tracked source\n' >"$source_repo/apps/dashboard/e2e/example.ts"
printf 'retired source\n' >"$source_repo/apps/dashboard/e2e/retired.ts"
ln -s apps/dashboard/e2e/example.ts "$source_repo/example-link"
git -C "$source_repo" add apps/dashboard/e2e/example.ts \
  apps/dashboard/e2e/retired.ts example-link
rm "$source_repo/apps/dashboard/e2e/retired.ts"
existing_tracked_paths "$source_repo" >"$tracked_paths"
if tr '\0' '\n' <"$tracked_paths" | grep -Fxq 'apps/dashboard/e2e/retired.ts'; then
  die 'tracked-source projection retained a deleted tracked path'
fi
source_fingerprint="$(tracked_source_archive_sha256 "$source_repo" "$tracked_paths")"
saved_root="$ROOT"
ROOT="$source_repo"
copy_tracked_source "$source_projection" "$tracked_paths"
ROOT="$saved_root"
[ "$(tracked_source_archive_sha256 "$source_projection" "$tracked_paths")" = "$source_fingerprint" ] ||
  die 'tracked-source projection does not preserve the selected source tree'
[ -L "$source_projection/.tmp" ] &&
  [ -L "$source_projection/apps/dashboard/playwright" ] ||
  die 'tracked-source projection does not redirect renderer writes to tmpfs'
[ ! -e "$source_projection/test-results" ] &&
  [ ! -e "$source_projection/apps/dashboard/test-results" ] ||
  die 'tracked-source projection uses a removable symlink for Playwright output'

fake_bun_script="$source_projection/install"
cat >"$fake_bun_script" <<'EOF'
#!/bin/bash
set -euo pipefail
for forbidden in HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy \
    NPM_TOKEN NODE_AUTH_TOKEN NPM_CONFIG_USERCONFIG BUN_AUTH_TOKEN; do
  if [[ -v "$forbidden" ]]; then
    printf 'ambient variable survived env -i: %s\n' "$forbidden" >&2
    exit 31
  fi
done
[ "$PATH" = /usr/bin:/bin ]
[ "$PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD" = 1 ]
printf 'install %s\n' "$*" >.bun-install-arguments
printf '%s\n' "$HOME" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" \
  "$XDG_RUNTIME_DIR" "$BUN_INSTALL_CACHE_DIR" "$TMPDIR" >.bun-install-paths
mkdir -p apps/dashboard/node_modules/.bin
printf '#!/bin/sh\nprintf "Version 1.58.1\\n"\n' >apps/dashboard/node_modules/.bin/playwright
chmod 0755 apps/dashboard/node_modules/.bin/playwright
EOF
dependency_environment="$fixture/dependency-environment"
HTTP_PROXY=http://owner-proxy.invalid NODE_AUTH_TOKEN=owner-token \
  NPM_CONFIG_USERCONFIG=/owner/.npmrc \
  install_projection_dependencies "$source_projection" "$dependency_environment" /bin/bash
[ "$(<"$source_projection/.bun-install-arguments")" = \
    'install --frozen-lockfile --ignore-scripts' ] ||
  die 'isolated dependency install did not use the frozen scriptless command'
expected_dependency_paths="$(printf '%s\n' \
  "$dependency_environment/home" "$dependency_environment/cache" \
  "$dependency_environment/config" "$dependency_environment/data" \
  "$dependency_environment/runtime" "$dependency_environment/bun-cache" \
  "$dependency_environment/tmp")"
[ "$(<"$source_projection/.bun-install-paths")" = "$expected_dependency_paths" ] ||
  die 'isolated dependency install did not use only private state directories'
[ "$(tracked_source_archive_sha256 "$source_projection" "$tracked_paths")" = "$source_fingerprint" ] ||
  die 'isolated dependency install modified tracked source content'

early_run_root="$fixture/codewire-playwright-snapshots.early-failure"
mkdir -p "$early_run_root"
if RUNNER="$RUNNER" EARLY_RUN_ROOT="$early_run_root" bash -c '
  source "$RUNNER"
  fail_after_main_locals_unwind() {
    local discarded_local=proof
    SNAPSHOT_CLEANUP_RUN_ROOT="$EARLY_RUN_ROOT"
    SNAPSHOT_CLEANUP_RUNTIME_PARENT="$(dirname "$EARLY_RUN_ROOT")"
    trap snapshot_run_cleanup EXIT
    return 23
  }
  fail_after_main_locals_unwind
' >/dev/null 2>&1; then
  die 'early-failure cleanup fixture unexpectedly succeeded'
fi
[ ! -e "$early_run_root" ] ||
  die 'EXIT cleanup lost its paths after the calling function locals unwound'

# shellcheck disable=SC2016
grep -Fq -- '--entrypoint /bin/bash "$renderer_image_id"' "$RUNNER" ||
  die 'runtime does not use the immutable ID returned by the renderer build'

if grep -Eq -- '(^|[[:space:]])--name([=[:space:]]|$)' "$RUNNER"; then
  die 'renderer cleanup still relies on a predictable Docker container name'
fi
# shellcheck disable=SC2016
grep -Fq 'exec {lock_fd}<"$runtime_parent"' "$RUNNER" ||
  die 'snapshot concurrency lock is not held on the private runtime directory FD'
if grep -Fq '.lock' "$RUNNER"; then
  die 'snapshot concurrency lock still follows a predictable lock-file path'
fi

if grep -Eq -- '--privileged|--env-file|src=.*/\.kube|src=.*/\.docker|src=/var/run/docker\.sock|dst=/var/run/docker\.sock' "$RUNNER"; then
  die 'renderer mounts credentials, kubeconfig, or the Docker socket'
fi
[ "$(grep -c -- '--mount ' "$RUNNER")" = 3 ] ||
  die 'renderer gained an unreviewed bind mount'
[ "$(grep -- '--mount ' "$RUNNER" | grep -c 'node_modules')" = 0 ] ||
  die 'renderer still mounts ambient host dependencies'
[ "$(grep -- '--mount ' "$RUNNER" | grep -vc 'readonly')" = 1 ] ||
  die 'more than the snapshot staging directory is writable through a bind mount'
# shellcheck disable=SC2016
grep -- '--mount ' "$RUNNER" | grep -v 'readonly' |
  grep -Fq 'src=$snapshot_stage,dst=/workspace/$SNAPSHOT_RELATIVE_DIR' ||
  die 'the sole writable bind mount is not the snapshot staging directory'

while IFS='|' read -r title spec_relative spec; do
  grep -Fq "$title" "$RUNNER" || die "focused visual test is not selected: $title"
  grep -Fq "$spec_relative" "$RUNNER" ||
    die "focused visual spec is not selected: $spec_relative"
  grep -Fq "test(\"$title\"" "$spec" ||
    die "focused visual test no longer exists: $title"
done <<EOF
renders server-owned create options and resources with no browser service caller|apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts|$ENVIRONMENT_SPEC
keeps environment create and inventory usable on mobile|apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts|$ENVIRONMENT_SPEC
renders account, security, and session surfaces in the selected context|apps/dashboard/e2e/ssr-dashboard.management-visual.ssr.ts|$MANAGEMENT_SPEC
renders the shared console shell and operational overview|apps/dashboard/e2e/ssr-dashboard.read.ssr.ts|$DASHBOARD_SPEC
EOF

archive="$fixture/chrome-linux64.zip"
printf 'synthetic archive\n' >"$archive"
archive_sha256="$(sha256sum "$archive" | awk '{ print $1 }')"
validate_chromium_archive "$archive" "$archive_sha256" ||
  die 'valid absolute archive fixture was rejected'
if (cd "$fixture" && validate_chromium_archive chrome-linux64.zip "$archive_sha256") >/dev/null 2>&1; then
  die 'relative Chromium archive path was accepted'
fi
ln -s "$archive" "$fixture/chrome-link.zip"
if validate_chromium_archive "$fixture/chrome-link.zip" "$archive_sha256" >/dev/null 2>&1; then
  die 'symlinked Chromium archive was accepted'
fi
if validate_chromium_archive "$archive" "${archive_sha256%?}0" >/dev/null 2>&1; then
  die 'Chromium archive with a mismatched checksum was accepted'
fi
validate_docker_mount_path "$fixture" || die 'valid Docker bind source was rejected'
if validate_docker_mount_path 'relative/path' >/dev/null 2>&1; then
  die 'relative Docker bind source was accepted'
fi
if validate_docker_mount_path "$fixture/with,comma" >/dev/null 2>&1; then
  die 'ambiguous Docker bind source was accepted'
fi
iidfile="$fixture/renderer.iid"
printf 'sha256:%064d' 0 >"$iidfile"
[ "$(read_renderer_image_id "$iidfile")" = "sha256:$(printf '%064d' 0)" ] ||
  die 'valid Docker buildx iidfile without a trailing newline was rejected'
printf 'sha256:%064d\nunexpected\n' 0 >"$iidfile"
if read_renderer_image_id "$iidfile" >/dev/null 2>&1; then
  die 'multi-line Docker image ID was accepted'
fi

cidfile="$fixture/renderer.cid"
if read_container_id "$cidfile" >/dev/null 2>&1; then
  die 'missing Docker container ID file was accepted'
fi

for topology_profile in prepared-kind-management-secrets-mobile prepared-kind-creation; do
topology_calls="$fixture/$topology_profile-topology-calls"
(
  isolated_docker_client() {
    printf '%s\n' codewire-e2e-ci
  }
  kubectl() {
    printf '%s\n' "$*" >>"$topology_calls"
    case "$*" in
      *'rollout status '*) return 0 ;;
      *'jsonpath={.spec.template.spec.containers[0].image}'*)
        printf '%s\n' codewire-dashboard:e2e
        ;;
      *'CODEWIRE_PUBLIC_ORIGIN'*) printf '%s\n' http://127.0.0.1:8090 ;;
      *) return 91 ;;
    esac
  }
  validate_snapshot_topology "$topology_profile" ignored
) || die 'exact prepared Kind topology was rejected'
[ "$(grep -c 'rollout status deployment/' "$topology_calls")" = 4 ] ||
  die 'prepared Kind topology did not require all four UI dependencies to be Ready'
grep -Fq -- '--context kind-codewire-e2e-ci -n codewire-e2e' "$topology_calls" ||
  die 'prepared Kind topology did not use its exact context and namespace'
if (
  isolated_docker_client() {
    printf '%s\n' codewire-e2e-ci
  }
  kubectl() {
    case "$*" in
      *'rollout status '*) return 0 ;;
      *'jsonpath={.spec.template.spec.containers[0].image}'*)
        printf '%s\n' codewire-dashboard:e2e
        ;;
      *'CODEWIRE_PUBLIC_ORIGIN'*) printf '%s\n' http://127.0.0.1:8080 ;;
      *) return 91 ;;
    esac
  }
  validate_snapshot_topology "$topology_profile" ignored
) >/dev/null 2>&1; then
  die 'prepared Kind topology accepted the wrong public origin'
fi
if (
  isolated_docker_client() {
    printf '%s\n' another-cluster
  }
  kubectl() { return 0; }
  validate_snapshot_topology "$topology_profile" ignored
) >/dev/null 2>&1; then
  die 'prepared Kind topology accepted a missing exact cluster'
fi
if (
  isolated_docker_client() {
    printf '%s\n' codewire-e2e-ci
  }
  kubectl() {
    case "$*" in
      *'rollout status deployment/codewire-idp '*) return 44 ;;
      *'rollout status '*) return 0 ;;
      *) return 91 ;;
    esac
  }
  validate_snapshot_topology "$topology_profile" ignored
) >/dev/null 2>&1; then
  die 'prepared Kind topology accepted a dependency that was not Ready'
fi
if (
  isolated_docker_client() {
    printf '%s\n' codewire-e2e-ci
  }
  kubectl() {
    case "$*" in
      *'rollout status '*) return 0 ;;
      *'jsonpath={.spec.template.spec.containers[0].image}'*)
        printf '%s\n' codewire-dashboard:local
        ;;
      *) return 91 ;;
    esac
  }
  validate_snapshot_topology "$topology_profile" ignored
) >/dev/null 2>&1; then
  die 'prepared Kind topology accepted the wrong dashboard image reference'
fi
done
printf 'not-a-container-id\n' >"$cidfile"
if read_container_id "$cidfile" >/dev/null 2>&1; then
  die 'malformed Docker container ID was accepted'
fi
printf '%064d' 0 >"$cidfile"
[ "$(read_container_id "$cidfile")" = "$(printf '%064d' 0)" ] ||
  die 'valid Docker container ID without a trailing newline was rejected'
printf '%064d\nunexpected\n' 0 >"$cidfile"
if read_container_id "$cidfile" >/dev/null 2>&1; then
  die 'multi-line Docker container ID was accepted'
fi
printf '%064d\n\n' 0 >"$cidfile"
if read_container_id "$cidfile" >/dev/null 2>&1; then
  die 'Docker container ID with multiple trailing newlines was accepted'
fi
printf '%064d\n' 0 >"$cidfile"
[ "$(read_container_id "$cidfile")" = "$(printf '%064d' 0)" ] ||
  die 'valid newline-terminated Docker container ID was rejected'
printf '%064s' A >"$cidfile"
if read_container_id "$cidfile" >/dev/null 2>&1; then
  die 'uppercase Docker container ID was accepted'
fi
printf '%064d' 0 >"$fixture/renderer-real.cid"
rm -f "$cidfile"
ln -s "$fixture/renderer-real.cid" "$cidfile"
if read_container_id "$cidfile" >/dev/null 2>&1; then
  die 'symlinked Docker container ID file was accepted'
fi

runtime_base="$fixture/runtime-base"
mkdir -m 0700 "$runtime_base"
runtime_directory="$(prepare_private_runtime_directory "$runtime_base")"
[ "$runtime_directory" = "$runtime_base/codewire-playwright-snapshots" ] &&
  [ "$(stat -c '%a' "$runtime_directory")" = 700 ] ||
  die 'private per-user runtime directory was not created with mode 0700'
exec {fixture_lock_fd}<"$runtime_directory"
flock -n "$fixture_lock_fd" || die 'private runtime directory could not be locked'
if (
  exec {contender_lock_fd}<"$runtime_directory"
  flock -n "$contender_lock_fd"
); then
  die 'private runtime directory lock did not serialize concurrent runs'
fi
flock -u "$fixture_lock_fd"
exec {fixture_lock_fd}<&-
chmod 0755 "$runtime_directory"
if prepare_private_runtime_directory "$runtime_base" >/dev/null 2>&1; then
  die 'non-private snapshot runtime directory was accepted'
fi
chmod 0700 "$runtime_directory"
ln -s "$runtime_directory" "$fixture/runtime-link"
if prepare_private_runtime_directory "$fixture/runtime-link" >/dev/null 2>&1; then
  die 'symlinked runtime base was accepted'
fi

snapshot_repo="$fixture/snapshot-repo"
snapshot_relative_dir='apps/dashboard/e2e'
mkdir -p "$snapshot_repo/$snapshot_relative_dir"
git -C "$snapshot_repo" init -q
while IFS= read -r snapshot; do
  mkdir -p "$snapshot_repo/$snapshot_relative_dir/$(dirname "$snapshot")"
  printf '\x89PNG\r\n\x1a\n%s\n' "$snapshot" > \
    "$snapshot_repo/$snapshot_relative_dir/$snapshot"
done < <(retired_snapshots)
while IFS= read -r snapshot; do
  mkdir -p "$snapshot_repo/$snapshot_relative_dir/$(dirname "$snapshot")"
  printf '\x89PNG\r\n\x1a\n%s\n' "$snapshot" > \
    "$snapshot_repo/$snapshot_relative_dir/$snapshot"
done < <(expected_snapshots)
git -C "$snapshot_repo" add "$snapshot_relative_dir"
git -C "$snapshot_repo" -c commit.gpgsign=false -c user.name=Codewire -c user.email=codewire@example.invalid \
  commit -qm 'snapshot validator fixture'
while IFS= read -r snapshot; do
  rm "$snapshot_repo/$snapshot_relative_dir/$snapshot"
done < <(retired_snapshots)
validate_snapshot_worktree "$snapshot_repo" "$snapshot_relative_dir" ||
  die 'the exact retired snapshot deletions were rejected'

retired_type_change='ssr-dashboard.environments.ssr.ts-snapshots/environments-prepared-image-desktop-dashboard-ssr-desktop-linux.png'
current_snapshot='ssr-dashboard.environments.ssr.ts-snapshots/environments-create-desktop-dashboard-ssr-desktop-ubuntu24-cft145.png'
ln -s "$(basename "$current_snapshot")" \
  "$snapshot_repo/$snapshot_relative_dir/$retired_type_change"
if validate_snapshot_worktree "$snapshot_repo" "$snapshot_relative_dir" >/dev/null 2>&1; then
  die 'a retired snapshot type change was accepted as a deletion'
fi
rm "$snapshot_repo/$snapshot_relative_dir/$retired_type_change"

printf 'unapproved change\n' >>"$snapshot_repo/$snapshot_relative_dir/$current_snapshot"
if validate_snapshot_worktree "$snapshot_repo" "$snapshot_relative_dir" >/dev/null 2>&1; then
  die 'a current snapshot modification was accepted beside the retired deletions'
fi
git -C "$snapshot_repo" checkout -q -- "$snapshot_relative_dir/$current_snapshot"
unexpected_snapshot='ssr-dashboard.read.ssr.ts-snapshots/unexpected-dashboard-ssr-desktop-linux.png'
printf '\x89PNG\r\n\x1a\nunexpected\n' > \
  "$snapshot_repo/$snapshot_relative_dir/$unexpected_snapshot"
git -C "$snapshot_repo" add "$snapshot_relative_dir/$unexpected_snapshot"
git -C "$snapshot_repo" -c commit.gpgsign=false -c user.name=Codewire -c user.email=codewire@example.invalid \
  commit -qm 'add unapproved deletion fixture'
rm "$snapshot_repo/$snapshot_relative_dir/$unexpected_snapshot"
if validate_snapshot_worktree "$snapshot_repo" "$snapshot_relative_dir" >/dev/null 2>&1; then
  die 'an unapproved tracked snapshot deletion was accepted'
fi

baseline="$fixture/baseline"
stage="$fixture/stage"
target="$fixture/target"
mkdir -p "$baseline" "$stage" "$target"
while IFS= read -r snapshot; do
  mkdir -p "$baseline/$(dirname "$snapshot")"
  printf '\x89PNG\r\n\x1a\n%s\n' "$snapshot" >"$baseline/$snapshot"
done < <(expected_snapshots)
cp -a "$baseline/." "$stage/"
printf 'changed\n' >>"$stage/$current_snapshot"
validate_snapshot_stage "$baseline" "$stage" ||
  die 'allowlisted snapshot update fixture was rejected'
promote_snapshots "$stage" "$target"
while IFS= read -r snapshot; do
  cmp -s "$stage/$snapshot" "$target/$snapshot" ||
    die "promotion did not copy $snapshot"
  [ "$(stat -c '%a' "$target/$snapshot")" = 644 ] ||
    die "promotion did not normalize $snapshot to mode 0644"
done < <(expected_snapshots)

unapproved_stage_snapshot='ssr-dashboard.read.ssr.ts-snapshots/unapproved-ubuntu24-cft145.png'
printf '\x89PNG\r\n\x1a\nunapproved\n' >"$stage/$unapproved_stage_snapshot"
if validate_snapshot_stage "$baseline" "$stage" >/dev/null 2>&1; then
  die 'an unexpected snapshot mutation was accepted'
fi

for prepared_profile in prepared-kind-management-secrets-mobile prepared-kind-creation; do
prepared_baseline="$fixture/$prepared_profile-baseline"
prepared_stage="$fixture/$prepared_profile-stage"
prepared_target="$fixture/$prepared_profile-target"
mkdir -p "$prepared_target"
while IFS= read -r prepared_snapshot; do
  mkdir -p "$prepared_baseline/$(dirname "$prepared_snapshot")"
  printf '\x89PNG\r\n\x1a\nprepared baseline\n' >"$prepared_baseline/$prepared_snapshot"
done < <(expected_snapshots "$prepared_profile")
cp -a "$prepared_baseline/." "$prepared_stage/"
while IFS= read -r prepared_snapshot; do
  printf 'changed\n' >>"$prepared_stage/$prepared_snapshot"
done < <(expected_snapshots "$prepared_profile")
validate_snapshot_stage "$prepared_baseline" "$prepared_stage" \
  "$prepared_profile" ||
  die "prepared Kind $prepared_profile update was rejected"
promote_snapshots "$prepared_stage" "$prepared_target" \
  "$prepared_profile"
while IFS= read -r prepared_snapshot; do
  cmp -s "$prepared_stage/$prepared_snapshot" "$prepared_target/$prepared_snapshot" ||
    die 'prepared Kind profile did not promote every allowlisted snapshot'
done < <(expected_snapshots "$prepared_profile")
prepared_saved_snapshot="$fixture/$prepared_profile-last.png"
prepared_required_snapshot="$(expected_snapshots "$prepared_profile" | tail -n 1)"
cp "$prepared_stage/$prepared_required_snapshot" "$prepared_saved_snapshot"
rm "$prepared_stage/$prepared_required_snapshot"
if validate_snapshot_stage "$prepared_baseline" "$prepared_stage" \
    "$prepared_profile" >/dev/null 2>&1; then
  die "prepared Kind $prepared_profile accepted a missing required PNG"
fi
printf 'not a PNG\n' >"$prepared_stage/$prepared_required_snapshot"
if validate_snapshot_stage "$prepared_baseline" "$prepared_stage" \
    "$prepared_profile" >/dev/null 2>&1; then
  die "prepared Kind $prepared_profile accepted an invalid required PNG"
fi
cp "$prepared_saved_snapshot" "$prepared_stage/$prepared_required_snapshot"
mkdir -p "$prepared_stage/$(dirname "$unapproved_stage_snapshot")"
printf '\x89PNG\r\n\x1a\nunapproved\n' >"$prepared_stage/$unapproved_stage_snapshot"
if validate_snapshot_stage "$prepared_baseline" "$prepared_stage" \
    "$prepared_profile" >/dev/null 2>&1; then
  die "prepared Kind $prepared_profile accepted a mutation outside its targets"
fi
done
rm -f "$stage/$unapproved_stage_snapshot"
unapproved_stage_link='ssr-dashboard.management-visual.ssr.ts-snapshots/unapproved-link.png'
ln -s "$stage/$current_snapshot" "$stage/$unapproved_stage_link"
if validate_snapshot_stage "$baseline" "$stage" >/dev/null 2>&1; then
  die 'a symlink in snapshot staging was accepted'
fi

clean_log="$fixture/clean.log"
sentinel_log="$fixture/sentinel.log"
printf 'renderer completed\n' >"$clean_log"
printf 'CODEWIRE_KUBECTL_SENTINEL_INVOKED\n' >"$sentinel_log"
assert_kubectl_not_invoked "$clean_log" || die 'clean renderer log was rejected'
if assert_kubectl_not_invoked "$sentinel_log" >/dev/null 2>&1; then
  die 'kubectl sentinel invocation did not block promotion'
fi

"$RUNNER" --help >/dev/null || die 'runner help failed'
if "$RUNNER" --unknown >/dev/null 2>&1; then
  die 'unknown runner argument was accepted'
fi
if "$RUNNER" --prepared-kind-management-secrets-mobile \
    --prepared-kind-management-secrets-mobile >/dev/null 2>&1; then
  die 'duplicate prepared Kind profile flag was accepted'
fi
for other_profile in prepared-kind-creation prepared-kind-management-secrets-mobile; do
  profile_error=''
  if profile_error="$("$RUNNER" --prepared-kind-creation "--$other_profile" 2>&1)"; then
    die "creation profile accepted duplicate or mixed flag: $other_profile"
  fi
  grep -Fq 'only one prepared Kind snapshot profile may be specified' <<<"$profile_error" ||
    die "creation flag collision was not rejected by the profile parser: $other_profile"
done
# All profiles share this failure barrier; a failed renderer cannot promote PNGs.
# shellcheck disable=SC2016 # Match the runner's variables, not this fixture's.
renderer_failure_line="$(grep -nF '[ "$docker_status" -eq 0 ] || fail' "$RUNNER" | cut -d: -f1)"
# shellcheck disable=SC2016 # Match the runner's variables, not this fixture's.
promotion_line="$(grep -nF '  promote_snapshots "$snapshot_stage" "$snapshot_dir" "$snapshot_profile"' "$RUNNER" | cut -d: -f1)"
[ -n "$renderer_failure_line" ] && [ -n "$promotion_line" ] &&
  [ "$renderer_failure_line" -lt "$promotion_line" ] ||
  die 'renderer failure barrier does not precede profile snapshot promotion'
grep -Fq 'scripts/ci/tests/test-kind-e2e-ubuntu-snapshot-runner.sh' "$PRODUCT_VERIFY" ||
  die 'snapshot runner contract test is not wired into edge verification'

printf '[test-kind-e2e-ubuntu-snapshot-runner] renderer isolation and promotion contracts passed\n'
