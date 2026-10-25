#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly HELPER="$ROOT/scripts/ci/images/build-local-image.sh"
readonly CW_FIXTURE="$ROOT/scripts/ci/tests/cw_image_fixtures.py"
# Hosted CI writes Python bytecode; prove the capsule stays exact without
# relying on a caller that disables it.
unset PYTHONDONTWRITEBYTECODE

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/build-local-image-test.XXXXXX")"
owned_cw_work=()
# A failing step names itself, and a failure prints the end of every step's
# output: CI shows only this test's own output (main run 22975 showed none).
# The ERR trap records the last failed command, which is the step errexit
# stopped at; a fail() check names itself instead.
set -E
failed_step=''
trap 'failed_step="line $LINENO: $BASH_COMMAND"' ERR
cleanup() {
  local status=$? directory output
  if [[ "$status" -eq 0 ]]; then
    for directory in "${owned_cw_work[@]}"; do rm -rf -- "$directory"; done
    rm -rf "$work"
  else
    printf '[test-build-local-image] failed with status %s at %s\n' "$status" "${failed_step:-an unknown step}" >&2
    for output in "$work"/*.out; do
      [[ -f "$output" ]] || continue
      printf '[test-build-local-image] last lines of %s:\n' "${output##*/}" >&2
      tail -n 40 -- "$output" >&2
    done
    printf '[test-build-local-image] retained failed fixture at %s\n' "$work" >&2
  fi
}
trap cleanup EXIT
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
    cw_context=false
    for argument in "$@"; do
      if [[ "$argument" == cw-source=* ]]; then
        if [[ "${FAKE_PRODUCER_STATUS:-0}" -ne 0 ]]; then
          printf 'synthetic original producer failure; no Docker/CW execution\n' >&2
          exit "$FAKE_PRODUCER_STATUS"
        fi
        exec python3 -B "${FAKE_CW_FIXTURE:?}" export -- "$@"
      fi
    done
    for argument in "$@"; do
      case "$argument" in
        codewire-verified-cw=*)
          cw_context=true
          python3 -B - "$FAKE_CW_FIXTURE" "$FAKE_CW_SOURCE" \
            "${argument#*=}" "$FAKE_CW_CONTEXTS" <<'PY'
from contextlib import closing
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
spec = importlib.util.spec_from_file_location('local_context_fixture', sys.argv[1])
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
source, context = Path(sys.argv[2]), Path(sys.argv[3])
result = context.parents[2] / 'cw-producer-result.json'
expected = fixture.selected_asset(source, result)
with closing(fixture.source.HeldSourceFile(context / 'cw', fixture.release.MAX_EXECUTABLE)) as held:
    assert held.data == expected
    held.revalidate(content=True)
with closing(fixture.source.HeldSourceFile(result, fixture.release.MAX_JSON)) as held:
    summary = fixture.release.parse_canonical(held.data)
    held.revalidate(content=True)
with Path(sys.argv[4]).open('a') as output:
    output.write(json.dumps({'context': str(context), 'work': str(context.parents[2]),
        'source_revision': summary['source']['revision'], 'profile': summary['profile'],
        'payload_sha256': hashlib.sha256(expected).hexdigest(),
        'producer_receipt_sha256': summary['receipt']['sha256']}, sort_keys=True) + '\n')
PY
          ;;
      esac
    done
    if [[ "$cw_context" == true ]]; then printf '#1 synthetic local image solve; no Docker/CW execution\n'; fi
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
  failed_step="the check above"
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

source_fixture="$work/source"
python3 -B "$CW_FIXTURE" source "$source_fixture" >"$work/source.json"
source_sha="$(git -C "$source_fixture" rev-parse HEAD)"

run_cw_helper() {
  local name="$1" recipe="$2" build_status="${3:-0}" cleanup_status="${4:-0}" producer_status="${5:-0}"
  env CODEWIRE_DOCKER_BIN="$work/bin/docker" \
    FAKE_DOCKER_LOG="$work/docker.log" \
    FAKE_BUILDER_SUFFIX="$name" FAKE_BUILD_STATUS="$build_status" \
    FAKE_RM_STATUS="$cleanup_status" FAKE_PRODUCER_STATUS="$producer_status" \
    FAKE_CW_FIXTURE="$CW_FIXTURE" FAKE_CW_SOURCE="$source_fixture" \
    FAKE_CW_CONTEXTS="$work/cw-contexts.jsonl" CODEWIRE_SCCACHE_MODE=local \
    "$HELPER" "example.test/codewire:$name" "$source_fixture/$recipe" "$source_fixture"
}

observed_cw_work() {
  python3 -B - "$work/cw-contexts.jsonl" "$source_sha" <<'PY'
import json
from pathlib import Path
import sys
value = json.loads(Path(sys.argv[1]).read_text().splitlines()[-1])
assert value['source_revision'] == sys.argv[2] and value['profile'] == 'runtime'
assert len(value['payload_sha256']) == len(value['producer_receipt_sha256']) == 64
print(value['work'])
PY
}

for recipe in deployments/docker/daemon.Dockerfile images/workspace/Dockerfile; do
  case "$recipe" in
    deployments/docker/daemon.Dockerfile) family=daemon ;;
    images/workspace/Dockerfile) family=workspace ;;
  esac
  : >"$work/docker.log"
  run_cw_helper "$family-success" "$recipe" >"$work/$family-success.out" 2>&1
  cw_work="$(observed_cw_work)"
  [[ ! -e "$cw_work" ]] || fail "$family successful CW work survived cleanup"
  [[ "$(grep -c '^buildx build ' "$work/docker.log")" -eq 2 ]] ||
    fail "$family did not execute one original producer and one image solve"
  grep -qF -- '--build-context codewire-verified-cw=' "$work/docker.log" ||
    fail "$family image solve lacked its admitted immutable CW context"
  grep -Fxq "buildx rm --force generated-builder-$family-success" "$work/docker.log" ||
    fail "$family successful builder was not removed"

  : >"$work/docker.log"
  set +e
  run_cw_helper "$family-failure" "$recipe" 42 >"$work/$family-failure.out" 2>&1
  status=$?
  set -e
  [[ "$status" -eq 42 ]] || fail "$family consumer failure status was not preserved: $status"
  cw_work="$(observed_cw_work)"
  [[ -d "$cw_work" && -f "$cw_work/cw-producer-result.json" ]] ||
    fail "$family failed CW work was not retained"
  owned_cw_work+=("$cw_work")
  grep -qF "retained failed CW build evidence at $cw_work" "$work/$family-failure.out" ||
    fail "$family failed CW work path was not reported"
  grep -Fxq "buildx rm --force generated-builder-$family-failure" "$work/docker.log" ||
    fail "$family failed builder was not removed"
done

set +e
run_cw_helper cw-cleanup-failure deployments/docker/daemon.Dockerfile 0 33 \
  >"$work/cw-cleanup-failure.out" 2>&1
status=$?
set -e
[[ "$status" -eq 33 ]] || fail "CW success cleanup failure was not surfaced: $status"
cw_work="$(observed_cw_work)"
[[ -d "$cw_work" ]] || fail 'CW evidence was deleted after builder cleanup failure'
owned_cw_work+=("$cw_work")

: >"$work/docker.log"
set +e
run_cw_helper cw-producer-failure deployments/docker/daemon.Dockerfile 0 0 44 \
  >"$work/cw-producer-failure.out" 2>&1
status=$?
set -e
[[ "$status" -eq 44 ]] || fail "CW producer failure status was not preserved: $status"
[[ "$(grep -c '^buildx build ' "$work/docker.log")" -eq 1 ]] ||
  fail 'a failed original producer reached an image solve'
cw_work="$(sed -n 's/^local image build: retained failed CW build evidence at //p' "$work/cw-producer-failure.out")"
[[ "$cw_work" == "$ROOT/.tmp/cw-local-image."* && -d "$cw_work" && ! -e "$cw_work/cw-producer-result.json" ]] ||
  fail 'failed producer work was not retained without an admitted result'
owned_cw_work+=("$cw_work")
grep -Fxq 'buildx rm --force generated-builder-cw-producer-failure' "$work/docker.log" ||
  fail 'failed original producer builder was not removed'

if grep -Eq '(^| )buildx use( |$)|(^| )--use( |$)' "$work/docker.log"; then
  fail 'CW route mutated the caller default builder'
fi

echo 'local CW source/producer/context/cleanup: 6 cases OK'
echo 'local Buildx image helper contract: OK'
