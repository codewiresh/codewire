#!/usr/bin/env bash
# load-fixture-images.sh against a fake Docker daemon: an image the daemon
# holds is used as it is, a kept archive is used only when it loads to the
# pinned ID, a pull by digest is kept for the next job, and only a failed pull
# fails the job.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="$ROOT/scripts/ci/setup/load-fixture-images.sh"
# shellcheck source=scripts/ci/verify/integration-postgres.sh
source "$ROOT/scripts/ci/verify/integration-postgres.sh"

fail() {
  echo "test-load-fixture-images: $*" >&2
  exit 1
}

TMP="$(mktemp -d "${TMPDIR:-/tmp}/test-load-fixture-images.XXXXXX")"
trap 'rm -rf -- "$TMP"' EXIT
mkdir -p "$TMP/bin"
# The fake daemon's store is a folder: one file per image ID, and one per
# pulled reference naming its ID. An archive is a file naming the ID it loads.
cat > "$TMP/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
store="${FAKE_DOCKER_STORE:?}"
printf '%s\n' "$*" >> "$store/calls"
key() { printf '%s' "$1" | tr '/:@' '___'; }
case "$1" in
  tag)
    # docker tag SOURCE TARGET: marks the image as tagged, so a prune of
    # dangling images keeps it.
    [ -z "${FAKE_TAG_FAIL:-}" ] || exit 1
    [ -f "$store/id-$(key "$2")" ] || exit 1
    printf '%s\n' "$3" >> "$store/tags-$(key "$2")"
    exit 0
    ;;
  prune)
    # The VM janitor's docker image prune -f: every untagged image goes.
    for image in "$store"/id-*; do
      [ -e "$image" ] || continue
      [ -f "$store/tags-${image##*/id-}" ] || rm -f -- "$image"
    done
    exit 0
    ;;
esac
case "$1 $2" in
  'image inspect')
    [ "$3" = -f ] || exit 2
    if [ -f "$store/id-$(key "$5")" ]; then printf '%s\n' "$5"; exit 0; fi
    if [ -f "$store/ref-$(key "$5")" ]; then cat "$store/ref-$(key "$5")"; exit 0; fi
    echo "Error: No such image: $5" >&2
    exit 1
    ;;
  'load -q')
    [ "$3" = -i ] || exit 2
    id="$(sed -n 's/^id=//p' "$4")"
    [ -n "$id" ] || { echo 'invalid tar header' >&2; exit 1; }
    : > "$store/id-$(key "$id")"
    ;;
  'pull -q')
    [ -z "${FAKE_PULL_FAIL:-}" ] || { echo 'toomanyrequests' >&2; exit 1; }
    case "$3" in
      *postgres*) id="${FAKE_PULL_ID:-$FAKE_POSTGRES_ID}" ;;
      *nats*) id="${FAKE_PULL_ID:-$FAKE_NATS_ID}" ;;
      *) exit 1 ;;
    esac
    : > "$store/id-$(key "$id")"
    printf '%s\n' "$id" > "$store/ref-$(key "$3")"
    ;;
  'save -o')
    [ -z "${FAKE_SAVE_FAIL:-}" ] || exit 1
    [ -f "$store/id-$(key "$4")" ] || exit 1
    printf 'id=%s\n' "$4" > "$3"
    ;;
  *) echo "unexpected docker $*" >&2; exit 2 ;;
esac
EOF
chmod +x "$TMP/bin/docker"
export PATH="$TMP/bin:$PATH" FAKE_POSTGRES_ID="$INTEGRATION_POSTGRES_PINNED_ID" FAKE_NATS_ID="$INTEGRATION_NATS_PINNED_ID"
pg_id="$INTEGRATION_POSTGRES_PINNED_ID"
nats_id="$INTEGRATION_NATS_PINNED_ID"
pg_archive="$TMP/cache/fixture-images/${pg_id#sha256:}.tar"
nats_archive="$TMP/cache/fixture-images/${nats_id#sha256:}.tar"

# run_case NAME [ENV...] -- IMAGE...: runs the loader against a fresh daemon
# (or the kept one with KEEP_STORE=1), the shared cache and its own GITHUB_ENV.
run_case() {
  local name="$1"
  shift
  local -a env=()
  while [ "$1" != -- ]; do env+=("$1"); shift; done
  shift
  case_dir="$TMP/$name"
  mkdir -p "$case_dir"
  if [ -z "${KEEP_STORE:-}" ]; then
    rm -rf "$TMP/store"
    mkdir -p "$TMP/store"
  fi
  : > "$TMP/store/calls"
  : > "$case_dir/env"
  status=0
  env FAKE_DOCKER_STORE="$TMP/store" GITHUB_ENV="$case_dir/env" CODEWIRE_TOOL_CACHE="$TMP/cache" \
    "${env[@]}" "$SCRIPT" "$@" > "$case_dir/out" 2>&1 </dev/null || status=$?
}

calls() { grep -c "^$1" "$TMP/store/calls" || true; }

# Both pins name an image ID the loader can check.
[[ "$pg_id" =~ ^sha256:[0-9a-f]{64}$ && "$nats_id" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  fail 'a fixture pin has no image ID'
[[ "$INTEGRATION_NATS_PINNED_IMAGE" =~ ^docker\.io/library/nats:[0-9.]+-alpine@sha256:[0-9a-f]{64}$ ]] ||
  fail 'the NATS image is not pinned by digest'

# A daemon that holds neither: each is pulled by its pinned digest, kept by
# its ID, and run by its ID.
run_case first -- postgres nats
[ "$status" -eq 0 ] || { cat "$TMP/first/out" >&2; fail 'the first job failed'; }
grep -qxF "pull -q $INTEGRATION_POSTGRES_PINNED_IMAGE" "$TMP/store/calls" || fail 'PostgreSQL was not pulled by its digest'
grep -qxF "pull -q $INTEGRATION_NATS_PINNED_IMAGE" "$TMP/store/calls" || fail 'NATS was not pulled by its digest'
[ "$(cat "$pg_archive")" = "id=$pg_id" ] || fail 'the PostgreSQL pull was not kept'
[ "$(cat "$nats_archive")" = "id=$nats_id" ] || fail 'the NATS pull was not kept'
grep -qxF "INTEGRATION_POSTGRES_IMAGE=$pg_id" "$TMP/first/env" || fail 'the job does not run PostgreSQL by its ID'
grep -qxF "INTEGRATION_NATS_IMAGE=$nats_id" "$TMP/first/env" || fail 'the job does not run NATS by its ID'
grep -qF 'postgres: pulled by digest and kept' "$TMP/first/out" || fail 'the first job did not report its pull'
[ -z "$(find "$TMP/cache" -name '*.tmp')" ] || fail 'a temporary archive was left behind'

# Each image the job runs by its ID is tagged as verified, so the warm VM's
# prune of dangling images between runs keeps it: the next job on that daemon
# finds it present.
grep -qxF "tag $pg_id localhost/codewire-ci/postgres:verified-${pg_id#sha256:}" "$TMP/store/calls" ||
  fail 'the pulled PostgreSQL was not tagged as verified'
grep -qxF "tag $nats_id localhost/codewire-ci/nats:verified-${nats_id#sha256:}" "$TMP/store/calls" ||
  fail 'the pulled NATS was not tagged as verified'
FAKE_DOCKER_STORE="$TMP/store" docker prune
KEEP_STORE=1 run_case after-prune -- postgres nats
[ "$status" -eq 0 ] || { cat "$TMP/after-prune/out" >&2; fail 'the job after a prune failed'; }
[ "$(calls pull)" -eq 0 ] && [ "$(calls load)" -eq 0 ] || fail 'a prune of dangling images deleted a tagged image'
grep -qF 'postgres: already present' "$TMP/after-prune/out" || fail 'the job after a prune did not find PostgreSQL'
# Untagged, the janitor deletes it, and the next job pulls it again.
run_case untagged FAKE_TAG_FAIL=1 CODEWIRE_TOOL_CACHE= -- postgres
[ "$status" -eq 0 ] || fail 'a failed tag failed the job'
grep -qF 'could not tag the postgres image' "$TMP/untagged/out" || fail 'the failed tag was not reported'
FAKE_DOCKER_STORE="$TMP/store" docker prune
KEEP_STORE=1 run_case untagged-next CODEWIRE_TOOL_CACHE= -- postgres
[ "$(calls pull)" -eq 1 ] || fail 'the fake janitor kept an untagged image'

# The next job on the guest: a fresh daemon loads the kept archives and pulls
# nothing.
run_case kept -- postgres nats
[ "$status" -eq 0 ] || { cat "$TMP/kept/out" >&2; fail 'the kept job failed'; }
[ "$(calls pull)" -eq 0 ] || fail 'a job with kept archives pulled'
[ "$(calls load)" -eq 2 ] || fail 'the kept archives were not loaded'
grep -qF 'postgres: loaded from the kept archive' "$TMP/kept/out" || fail 'the kept job did not report its load'
grep -qxF "tag $pg_id localhost/codewire-ci/postgres:verified-${pg_id#sha256:}" "$TMP/store/calls" ||
  fail 'the loaded PostgreSQL was not tagged as verified'
grep -qxF "INTEGRATION_POSTGRES_IMAGE=$pg_id" "$TMP/kept/env" || fail 'the kept job does not run PostgreSQL by its ID'

# A daemon that already holds the image (a warm daemon, a golden disk) neither
# loads nor pulls it.
KEEP_STORE=1 run_case present -- postgres
[ "$status" -eq 0 ] || fail 'the present job failed'
[ "$(calls pull)" -eq 0 ] && [ "$(calls load)" -eq 0 ] || fail 'an image the daemon held was loaded or pulled'
grep -qF 'postgres: already present' "$TMP/present/out" || fail 'the present job did not report it'

# A kept archive that loads as another image is never run: it is replaced by
# a pull by digest. One that does not load at all is replaced too.
printf 'id=sha256:%064d\n' 7 > "$pg_archive"
run_case changed -- postgres
[ "$status" -eq 0 ] || { cat "$TMP/changed/out" >&2; fail 'the changed-archive job failed'; }
grep -qF 'did not load as' "$TMP/changed/out" || fail 'the changed archive was not reported'
[ "$(calls pull)" -eq 1 ] || fail 'the changed archive was not replaced by a pull'
[ "$(cat "$pg_archive")" = "id=$pg_id" ] || fail 'the changed archive was not replaced'
grep -qxF "INTEGRATION_POSTGRES_IMAGE=$pg_id" "$TMP/changed/env" || fail 'the changed-archive job runs another image'
printf 'garbage\n' > "$pg_archive"
run_case garbage -- postgres
[ "$status" -eq 0 ] && [ "$(calls pull)" -eq 1 ] || fail 'an archive that did not load was not replaced by a pull'

# Keeping is best effort: a save that fails still runs the pulled image.
rm -f "$pg_archive"
run_case unsaved FAKE_SAVE_FAIL=1 -- postgres
[ "$status" -eq 0 ] || fail 'a failed save failed the job'
[ ! -e "$pg_archive" ] && [ -z "$(find "$TMP/cache" -name '*.tmp')" ] || fail 'a failed save left an archive'
grep -qF 'could not keep the postgres archive' "$TMP/unsaved/out" || fail 'the failed save was not reported'
grep -qxF "INTEGRATION_POSTGRES_IMAGE=$pg_id" "$TMP/unsaved/env" || fail 'the unsaved job does not run PostgreSQL'

# A daemon whose store names the pulled image otherwise runs it by the pinned
# reference and keeps nothing.
run_case other-store "FAKE_PULL_ID=$(printf 'sha256:%064d' 9)" -- postgres
[ "$status" -eq 0 ] || fail 'a differently named store failed the job'
grep -qxF "INTEGRATION_POSTGRES_IMAGE=$INTEGRATION_POSTGRES_PINNED_IMAGE" "$TMP/other-store/env" ||
  fail 'a differently named store does not run the pinned reference'
[ ! -e "$pg_archive" ] || fail 'an image without the pinned ID was kept'
[ "$(calls tag)" -eq 0 ] || fail 'an image without the pinned ID was tagged as verified'

# Without a cache (a cloud runner) it pulls and keeps nothing.
rm -rf "$TMP/cache"
run_case no-cache CODEWIRE_TOOL_CACHE= -- postgres
[ "$status" -eq 0 ] && [ "$(calls pull)" -eq 1 ] && [ ! -e "$TMP/cache" ] || fail 'a job without a cache did not just pull'

# Only a failed pull, or an unknown image, fails the job.
run_case pull-fails FAKE_PULL_FAIL=1 -- postgres
[ "$status" -ne 0 ] || fail 'a failed pull passed'
grep -qF "could not pull $INTEGRATION_POSTGRES_PINNED_IMAGE" "$TMP/pull-fails/out" || fail 'the failed pull gave no reason'
[ ! -s "$TMP/pull-fails/env" ] || fail 'a failed pull named an image to run'
run_case unknown -- redis
[ "$status" -ne 0 ] && grep -qF 'unknown fixture image: redis' "$TMP/unknown/out" || fail 'an unknown image was accepted'

echo 'test-load-fixture-images: kept, present, tagged, pruned, changed, unsaved, other-store, no-cache and failure cases passed'
