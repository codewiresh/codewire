#!/usr/bin/env bash
# Verify the exact production dashboard image as a filesystem and running HTTP
# artifact. This intentionally does not rely on a shell inside the image.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
image="${1:-}"

if [ -z "$image" ]; then
  echo "usage: $0 IMAGE" >&2
  exit 2
fi

for tool in curl docker jq sha256sum tar; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "dashboard image verification: missing required tool: $tool" >&2
    exit 1
  fi
done
docker image inspect "$image" >/dev/null

work="$(mktemp -d "${TMPDIR:-/tmp}/codewire-dashboard-image.XXXXXX")"
export_container="codewire-dashboard-export-$$-${RANDOM}"
smoke_container="codewire-dashboard-smoke-$$-${RANDOM}"

cleanup() {
  status=$?
  if [ "$status" -ne 0 ] && docker container inspect "$smoke_container" >/dev/null 2>&1; then
    docker container inspect "$smoke_container" \
      --format 'dashboard smoke state: running={{.State.Running}} exit={{.State.ExitCode}} error={{.State.Error}}' \
      >&2 || true
    docker logs "$smoke_container" >&2 || true
  fi
  docker rm -f "$smoke_container" "$export_container" >/dev/null 2>&1 || true
  rm -rf "$work"
  return "$status"
}
trap cleanup EXIT

config="$(docker image inspect "$image" --format '{{json .Config}}')"
if ! jq -e '
  .User == "65532:65532" and
  .WorkingDir == "/srv/codewire" and
  .Entrypoint == ["/srv/codewire/codewire-dashboard-web"] and
  (.ExposedPorts | has("5173/tcp")) and
  (.Env | index("CODEWIRE_DASHBOARD_LISTEN_ADDR=0.0.0.0:5173") != null) and
  (.Env | index("CODEWIRE_DOCS_ROOT=/srv/codewire/docs") != null)
' <<<"$config" >/dev/null; then
  echo "dashboard image verification: runtime config does not match the accepted non-root contract" >&2
  jq '{User, WorkingDir, Entrypoint, ExposedPorts, Env}' <<<"$config" >&2
  exit 1
fi

docker create --name "$export_container" "$image" >/dev/null
docker export "$export_container" >"$work/rootfs.tar"
tar -tf "$work/rootfs.tar" | sed 's#^\./##' >"$work/paths"

if awk 'BEGIN { bad = 0 } /^\// || /(^|\/)\.\.($|\/)/ { print; bad = 1 } END { exit bad }' \
    "$work/paths" >"$work/unsafe-paths"; then
  :
else
  echo "dashboard image verification: exported image contains unsafe archive paths" >&2
  cat "$work/unsafe-paths" >&2
  exit 1
fi

required_paths=(
  srv/codewire/codewire-dashboard-web
  srv/codewire/docs/index.html
  srv/codewire/docs/search.js
  srv/codewire/docs/search_index.en.json
  usr/share/codewire/Cargo.lock
  usr/share/codewire/dashboard-binary.sha256
  usr/share/codewire/docs.sha256
  usr/share/codewire/runtime-files.sha256
  usr/share/codewire/runtime-inventory.json
  usr/share/codewire/rust-workspace-metadata.json
  usr/share/licenses/codewire/LICENSE
  usr/share/licenses/htmx/LICENSE
  usr/share/licenses/xterm/LICENSE
)
for path in "${required_paths[@]}"; do
  if ! grep -Fxq "$path" "$work/paths"; then
    echo "dashboard image verification: required runtime file is missing: /$path" >&2
    exit 1
  fi
done

forbidden_paths=(
  bin/bash bin/bun bin/node bin/npm bin/sh
  sbin/apk
  usr/bin/apt usr/bin/apt-get usr/bin/bash usr/bin/bun usr/bin/cargo
  usr/bin/dpkg usr/bin/node usr/bin/npm usr/bin/npx usr/bin/rustc usr/bin/sh
  usr/local/bin/bun usr/local/bin/cargo usr/local/bin/node usr/local/bin/npm
  usr/local/bin/rustc usr/local/bin/zola usr/sbin/nginx
)
for path in "${forbidden_paths[@]}"; do
  if grep -Fxq "$path" "$work/paths"; then
    echo "dashboard image verification: forbidden runtime executable is present: /$path" >&2
    exit 1
  fi
done

mkdir "$work/rootfs"
tar --extract --file="$work/rootfs.tar" --directory="$work/rootfs" \
  --no-same-owner --no-same-permissions

(
  cd "$work/rootfs"
  sha256sum --check usr/share/codewire/runtime-files.sha256 >/dev/null
)
(
  cd "$work/rootfs/srv/codewire"
  sha256sum --check ../../usr/share/codewire/dashboard-binary.sha256 >/dev/null
)
(
  cd "$work/rootfs/srv/codewire/docs"
  sha256sum --check ../../../usr/share/codewire/docs.sha256 >/dev/null
)
if ! jq -e '
  .schema_version == 1 and
  .runtime.uid == 65532 and
  .runtime.gid == 65532 and
  (.forbidden | index("shell") != null) and
  (.forbidden | index("node") != null) and
  (.forbidden | index("zola") != null)
' "$work/rootfs/usr/share/codewire/runtime-inventory.json" >/dev/null; then
  echo "dashboard image verification: embedded runtime inventory is invalid" >&2
  exit 1
fi
if ! grep -Fq 'name = "codewire-dashboard-web"' \
    "$work/rootfs/usr/share/codewire/Cargo.lock"; then
  echo "dashboard image verification: embedded Cargo.lock is not the dashboard build lock" >&2
  exit 1
fi
if ! jq -e '
  .version == 1 and
  any(.packages[]; .name == "codewire-dashboard-web") and
  (.resolve == null)
' "$work/rootfs/usr/share/codewire/rust-workspace-metadata.json" >/dev/null; then
  echo "dashboard image verification: embedded no-dependency Cargo metadata is invalid" >&2
  exit 1
fi

if docker run --rm --entrypoint /bin/sh "$image" -c true >/dev/null 2>&1; then
  echo "dashboard image verification: /bin/sh unexpectedly executed" >&2
  exit 1
fi

docker run --detach --name "$smoke_container" \
  --publish 127.0.0.1::5173 \
  --pids-limit 1 \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --env CODEWIRE_DASHBOARD_RUNTIME_MODE=current-thread \
  "$image" >/dev/null
port="$(docker inspect "$smoke_container" \
  --format '{{(index (index .NetworkSettings.Ports "5173/tcp") 0).HostPort}}')"
if [[ ! "$port" =~ ^[0-9]+$ ]]; then
  echo "dashboard image verification: Docker did not assign a loopback smoke port" >&2
  exit 1
fi
base="http://127.0.0.1:${port}"
ready=0
for _ in $(seq 1 80); do
  if curl -fsS "$base/healthz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! docker container inspect "$smoke_container" \
      --format '{{.State.Running}}' 2>/dev/null | grep -Fxq true; then
    docker logs "$smoke_container" >&2 || true
    echo "dashboard image verification: runtime exited before health was ready" >&2
    exit 1
  fi
  sleep 0.25
done
if [ "$ready" != 1 ]; then
  docker logs "$smoke_container" >&2 || true
  echo "dashboard image verification: /healthz did not become ready" >&2
  exit 1
fi

curl_retry=(--silent --show-error --retry 3 --retry-all-errors --retry-delay 1)

curl --fail "${curl_retry[@]}" "$base/" >"$work/home.html"
curl --fail "${curl_retry[@]}" --dump-header "$work/docs.headers" \
  "$base/docs" >"$work/docs.html"
tr -d '\r' <"$work/docs.headers" >"$work/docs.normalized.headers"
grep -Eiq '^content-type: text/html; charset=utf-8$' "$work/docs.normalized.headers"
grep -Eiq '^content-security-policy: ' "$work/docs.normalized.headers"
grep -Fiq '<!doctype html>' "$work/docs.html"
curl --fail "${curl_retry[@]}" "$base/install.sh" >"$work/install.sh"
cmp "$ROOT/apps/cli/install.sh" "$work/install.sh"
curl --fail "${curl_retry[@]}" "$base/.well-known/apple-app-site-association" \
  >"$work/apple.json"
if [ "$(<"$work/apple.json")" != \
    '{"webcredentials":{"apps":["PXQZM3GLP5.sh.codewire.ios"]}}' ]; then
  echo "dashboard image verification: Apple association response drifted" >&2
  exit 1
fi
curl --fail "${curl_retry[@]}" "$base/docs/search_index.en.json" | jq -e \
  'type == "array" and length > 0' >/dev/null

redirect_headers="$work/docs-slash.headers"
status="$(curl "${curl_retry[@]}" --output /dev/null \
  --dump-header "$redirect_headers" --write-out '%{http_code}' "$base/docs/")"
tr -d '\r' <"$redirect_headers" >"$work/docs-slash.normalized.headers"
if [ "$status" != 308 ] || ! grep -Eiq '^location: /docs$' \
    "$work/docs-slash.normalized.headers"; then
  echo "dashboard image verification: /docs/ did not canonically redirect to /docs" >&2
  exit 1
fi

echo "dashboard image verification: OK ($image, uid 65532, locked Rust/Zola artifact, no shell or JS toolchain)"
