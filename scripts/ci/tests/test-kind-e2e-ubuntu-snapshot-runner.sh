#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUNNER="$ROOT/scripts/ci/verify/update-playwright-ubuntu24-snapshots.sh"
PRODUCT_VERIFY="$ROOT/scripts/ci/verify/run-product-verification.sh"
ENVIRONMENT_SPEC="$ROOT/apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts"
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
    '--env RUN_AI_ANALYSIS_E2E=0' \
    '--env CODEWIRE_PLAYWRIGHT_ENVIRONMENTS_FIXTURE_RUN_ID="$FIXTURE_RUN_ID"' \
    'rm -f -- "$snapshot_stage/$relative"' \
    '--project=dashboard-ssr-desktop' \
    '--project=dashboard-ssr-mobile' \
    '--output /tmp/codewire-run/test-results' \
    '--update-snapshots=changed --retries=0 --workers=1 --reporter=line'; do
  grep -Fq -- "$required" "$RUNNER" || die "runner is missing contract: $required"
done
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
ln -s apps/dashboard/e2e/example.ts "$source_repo/example-link"
git -C "$source_repo" add apps/dashboard/e2e/example.ts example-link
git -C "$source_repo" ls-files -z >"$tracked_paths"
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

for title in \
    'renders server-owned create options and resources with no browser service caller' \
    'keeps image, repositories, mounts, protected secret boundary, agents, and runtime on one compact form' \
    'keeps environment create and inventory usable on mobile'; do
  grep -Fq "$title" "$RUNNER" || die "focused visual test is not selected: $title"
  grep -Fq "test(\"$title\"" "$ENVIRONMENT_SPEC" ||
    die "focused visual test no longer exists: $title"
done

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

baseline="$fixture/baseline"
stage="$fixture/stage"
target="$fixture/target"
mkdir -p "$baseline" "$stage" "$target"
while IFS= read -r snapshot; do
  printf '\x89PNG\r\n\x1a\n%s\n' "$snapshot" >"$baseline/$snapshot"
done < <(expected_snapshots)
cp -a "$baseline/." "$stage/"
printf 'changed\n' >>"$stage/environments-create-desktop-dashboard-ssr-desktop-ubuntu24-cft145.png"
validate_snapshot_stage "$baseline" "$stage" ||
  die 'allowlisted snapshot update fixture was rejected'
promote_snapshots "$stage" "$target"
while IFS= read -r snapshot; do
  cmp -s "$stage/$snapshot" "$target/$snapshot" ||
    die "promotion did not copy $snapshot"
  [ "$(stat -c '%a' "$target/$snapshot")" = 644 ] ||
    die "promotion did not normalize $snapshot to mode 0644"
done < <(expected_snapshots)

printf '\x89PNG\r\n\x1a\nunapproved\n' >"$stage/unapproved-ubuntu24-cft145.png"
if validate_snapshot_stage "$baseline" "$stage" >/dev/null 2>&1; then
  die 'an unexpected snapshot mutation was accepted'
fi
rm -f "$stage/unapproved-ubuntu24-cft145.png"
ln -s "$stage/environments-create-desktop-dashboard-ssr-desktop-ubuntu24-cft145.png" \
  "$stage/unapproved-link.png"
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
grep -Fq 'scripts/ci/tests/test-kind-e2e-ubuntu-snapshot-runner.sh' "$PRODUCT_VERIFY" ||
  die 'snapshot runner contract test is not wired into edge verification'

printf '[test-kind-e2e-ubuntu-snapshot-runner] renderer isolation and promotion contracts passed\n'
