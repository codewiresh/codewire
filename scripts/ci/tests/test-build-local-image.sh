#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly HELPER="$ROOT/scripts/ci/images/build-local-image.sh"

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/build-local-image-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"

cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"

case "$1 $2" in
  'buildx create')
    printf 'generated-builder-%s\n' "$FAKE_BUILDER_SUFFIX"
    ;;
  'buildx build')
    exit "${FAKE_BUILD_STATUS:-0}"
    ;;
  'buildx rm')
    exit "${FAKE_RM_STATUS:-0}"
    ;;
  *)
    printf 'unexpected docker command: %s\n' "$*" >&2
    exit 99
    ;;
esac
EOF
chmod +x "$work/bin/docker"

fail() {
  printf '[test-build-local-image] ERROR: %s\n' "$*" >&2
  exit 1
}

run_helper() {
  env CODEWIRE_DOCKER_BIN="$work/bin/docker" \
    FAKE_DOCKER_LOG="$work/docker.log" \
    FAKE_BUILDER_SUFFIX="$1" \
    FAKE_BUILD_STATUS="${2:-0}" \
    FAKE_RM_STATUS="${3:-0}" \
    "$HELPER" example.test/codewire:verify images/example.Dockerfile . \
      --build-arg VERIFY=1
}

: >"$work/docker.log"
run_helper alpha
mapfile -t calls <"$work/docker.log"
[[ "${calls[0]}" == 'buildx create --driver docker-container' ]] ||
  fail "builder creation contract drifted: ${calls[0]}"
[[ "${calls[1]}" == 'buildx build --builder generated-builder-alpha --pull --load --tag example.test/codewire:verify --file images/example.Dockerfile --build-arg VERIFY=1 .' ]] ||
  fail "build contract drifted: ${calls[1]}"
[[ "${calls[2]}" == 'buildx rm --force generated-builder-alpha' ]] ||
  fail "success cleanup contract drifted: ${calls[2]}"

run_helper beta
grep -Fxq 'buildx build --builder generated-builder-beta --pull --load --tag example.test/codewire:verify --file images/example.Dockerfile --build-arg VERIFY=1 .' "$work/docker.log" ||
  fail 'generated builder name was not handed to the second build'
if grep -Eq '(^| )buildx use( |$)|(^| )--use( |$)' "$work/docker.log"; then
  fail 'helper mutated the caller default builder'
fi

: >"$work/docker.log"
set +e
run_helper failed-build 42
status=$?
set -e
[[ "$status" -eq 42 ]] || fail "build failure status was not preserved: $status"
grep -Fxq 'buildx rm --force generated-builder-failed-build' "$work/docker.log" ||
  fail 'builder was not cleaned after build failure'

: >"$work/docker.log"
set +e
run_helper failed-cleanup 0 33 >/dev/null 2>&1
status=$?
set -e
[[ "$status" -eq 33 ]] || fail "cleanup failure was not surfaced: $status"

echo 'local Buildx image helper contract: OK'
