#!/usr/bin/env bash
# Execute build-cw-linux.sh against a fake docker and a fake client fetcher
# (#3119): the build context is a credential-free clone of exactly the
# selected commit, the bake call names the one target on the trusted builder
# with a local export, and the client keeps the executable only when it is
# exactly the exported file whose SHA-256 record and admission line agree.
# Every mismatch fails. The owner's in-job recovery takes the other path, and
# the bake file and Dockerfile run nothing under emulation.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly CLIENT="$ROOT/scripts/ci/release/build-cw-linux.sh"
readonly HCL="$ROOT/scripts/ci/release/cw-release-linux.hcl"
readonly DOCKERFILE="$ROOT/scripts/ci/release/cw-release-linux.Dockerfile"

fail() {
  printf '[test-build-cw-linux] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/build-cw-linux.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"

# A selected source commit whose checkout carries a job credential in its
# .git/config, as a persisted checkout does.
source="$work/source"
git init -q "$source"
git -C "$source" -c user.name=t -c user.email=t@example.invalid commit -q --allow-empty -m source
git -C "$source" config http.https://git.example.invalid/.extraheader 'AUTHORIZATION: basic synthetic'
sha="$(git -C "$source" rev-parse HEAD)"

cat >"$work/fetcher" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" -eq 1 && -d "$1" ]]
printf synthetic >"$1/ca.crt"; printf synthetic >"$1/client.crt"; printf synthetic >"$1/client.key"
EOF
chmod +x "$work/fetcher"

# The fake docker answers the attach and writes the export the case asks for.
cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_DOCKER_CALLS:?}"
case "$1 $2" in
  "buildx create"|"buildx rm") exit 0 ;;
  "buildx inspect") printf 'Name: %s\nDriver: remote\nStatus: running\nPlatforms: linux/amd64\n' "$3"; exit 0 ;;
  "buildx bake") ;;
  *) echo "unexpected fake docker command: $*" >&2; exit 1 ;;
esac
dest='' target='' allows=()
for arg in "$@"; do
  case "$arg" in
    cw-release-*.output=type=local,dest=*) dest="${arg#*dest=}" ;;
    --allow=*) allows+=("${arg#--allow=}") ;;
  esac
  target="$arg"
done
[[ -n "$dest" ]]
# Buildx refuses a context or output outside its directory without these,
# and the client asks for exactly these.
expected_allows="fs.read=$CW_RELEASE_CONTEXT fs.read=$CW_RELEASE_RUNTIME fs.write=$dest"
[[ "${allows[*]}" == "$expected_allows" ]] || { echo "unexpected entitlements: ${allows[*]}" >&2; exit 1; }
{
  printf 'oidc_request=%s%s\n' "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:+token}" "${ACTIONS_ID_TOKEN_REQUEST_URL:+url}"
  printf 'target=%s\n' "$target"
  printf 'context=%s\n' "$CW_RELEASE_CONTEXT"
  printf 'context_head=%s\n' "$(git -C "$CW_RELEASE_CONTEXT" rev-parse HEAD)"
  printf 'context_config=%s\n' "$(git -C "$CW_RELEASE_CONTEXT" config --list --local | tr '\n' ' ')"
  printf 'has_runtime=%s runtime=%s\n' "$CW_RELEASE_HAS_RUNTIME" "$CW_RELEASE_RUNTIME"
  printf 'version=%s source=%s tag=%s cache=%s jobs=%s cw_jobs=%s\n' "$CW_RELEASE_VERSION" "$CW_RELEASE_SOURCE_SHA" \
    "$CW_RELEASE_TAG_OBJECT_SHA" "$CW_RELEASE_TARGET_CACHE" "${CODEWIRE_CARGO_BUILD_JOBS:-}" "${CW_RELEASE_CARGO_BUILD_JOBS:-}"
  printf 'zig=%s %s zigbuild=%s\n' "$ZIG_VERSION" "$ZIG_X86_64_LINUX_SHA256" "$CARGO_ZIGBUILD_VERSION"
} >"${FAKE_BAKE_RECORD:?}"
# Buildx asks for write access to the nearest existing parent of a missing
# local destination, which the allow above does not cover (cli-release 18343):
# the destination must already be an empty private directory.
[[ -d "$dest" && ! -L "$dest" && -z "$(ls -A "$dest")" ]] ||
  { echo "the local export destination is not an existing empty directory: $dest" >&2; exit 1; }
[[ "$(stat -c %a "$dest")" == 700 ]] || { echo "the local export destination is not private: $dest" >&2; exit 1; }
triple="${target#cw-release-}"
name="cw-${CW_RELEASE_VERSION}-$triple"
printf 'synthetic %s executable\n' "$triple" >"$dest/$name"
chmod 0755 "$dest/$name"
digest="$(sha256sum "$dest/$name" | cut -c1-64)"
admitted_target="$triple" admitted_digest="$digest" admitted_version="$CW_RELEASE_VERSION"
case "${FAKE_EXPORT:-valid}" in
  valid) ;;
  wrong-record) digest="$(printf x | sha256sum | cut -c1-64)" admitted_digest="$digest" ;;
  wrong-admission) admitted_digest="$(printf x | sha256sum | cut -c1-64)" ;;
  wrong-target) admitted_target="x86_64-apple-darwin" ;;
  wrong-version) admitted_version="v9.9.9" ;;
  no-admission) ;;
  extra-file) printf 'extra\n' >"$dest/provenance.json" ;;
  symlink) mv "$dest/$name" "$dest/../real-$name"; ln -s "../real-$name" "$dest/$name" ;;
  failed) echo "fake bake failed" >&2; exit 1 ;;
esac
printf '%s  %s\n' "$digest" "$name" >"$dest/$name.sha256"
if [ "${FAKE_EXPORT:-valid}" != no-admission ]; then
  printf 'cw-release: admitted target=%s version=%s inputs=812 sha256=%s\n' \
    "$admitted_target" "$admitted_version" "$admitted_digest" >"$dest/$name.admitted"
fi
EOF
chmod +x "$work/bin/docker"

run_client() {
  local out="$1"; shift
  env -i PATH="$work/bin:/usr/local/bin:/usr/bin:/bin" HOME="$work" TMPDIR="$work" RUNNER_TEMP="$work" \
    FAKE_DOCKER_CALLS="$work/docker-calls" FAKE_BAKE_RECORD="$work/bake-record" \
    TRUSTED_BUILDKIT_CLIENT_FETCHER="$work/fetcher" GITHUB_OUTPUT="$work/github-output" \
    ACTIONS_ID_TOKEN_REQUEST_TOKEN=synthetic-request ACTIONS_ID_TOKEN_REQUEST_URL=https://oidc.example.invalid \
    CW_RELEASE_SOURCE_SHA="$sha" CODEWIRE_IN_JOB_BUILD=0 "$@" \
    "${client_under_test:-$CLIENT}" "$source" v1.2.3 x86_64-unknown-linux-musl "$out"
}

# The valid export: the client keeps exactly the executable and reports it.
: >"$work/github-output"
run_client "$work/out-valid" >"$work/valid.log" 2>&1 || { cat "$work/valid.log" >&2; fail "a valid export was refused"; }
[ "$(ls -A "$work/out-valid")" = "cw-v1.2.3-x86_64-unknown-linux-musl" ] || fail "the output is not exactly the executable"
expected="$(sha256sum "$work/out-valid/cw-v1.2.3-x86_64-unknown-linux-musl" | cut -c1-64)"
grep -Fxq "cw_sha256=$expected" "$work/github-output" || fail "the job output does not carry the executable's SHA-256"
grep -Fxq "target=cw-release-x86_64-unknown-linux-musl" "$work/bake-record" || fail "bake was not asked for the one target"
grep -Fxq "context_head=$sha" "$work/bake-record" || fail "the build context is not the selected commit"
grep -q 'extraheader\|AUTHORIZATION\|remote\.' "$work/bake-record" && fail "the job credential reached the build context"
grep -q '^has_runtime=0 runtime=.*/no-runtime$' "$work/bake-record" || fail "a run without a runtime passed one"
grep -Fxq 'oidc_request=' "$work/bake-record" || fail "the OIDC request credentials outlived the builder login"
[ -z "$(find "$work" -maxdepth 1 -name 'codewire-cw-release.*')" ] || fail "the client left its private work directory behind"
grep -Fxq "version=v1.2.3 source=$sha tag= cache=warm jobs=14 cw_jobs=8" "$work/bake-record" ||
  fail "the bake variables are not the release's: $(cat "$work/bake-record")"
grep -Fxq 'zig=0.15.2 02aa270f183da276e5b5920b1dac44a63f1a49e55050ebde3aecc9eb82f93239 zigbuild=0.23.0' "$work/bake-record" ||
  fail "the tool pins are not local-runtime-sources.json's"
grep -q -- '--driver remote --platform linux/amd64' "$work/docker-calls" || fail "the trusted builder was not attached"
grep -q -- "buildx bake --builder codewire-cw-release-local-0-[0-9]* --progress plain --allow=fs.read=[^ ]*/source --allow=fs.read=[^ ]*/no-runtime --allow=fs.write=[^ ]*/export --file scripts/ci/release/cw-release-linux.hcl --set cw-release-x86_64-unknown-linux-musl.output=type=local,dest=" \
  "$work/docker-calls" || fail "bake was not called on the attached builder with a local export"
grep -q -- "buildx rm codewire-cw-release-local-0-" "$work/docker-calls" || fail "the client did not forget its builder"

# A packed runtime reaches the build as its own context.
mkdir -p "$work/runtime"
run_client "$work/out-runtime" CW_RELEASE_LOCAL_RUNTIME_DIR="$work/runtime" >"$work/runtime.log" 2>&1 ||
  { cat "$work/runtime.log" >&2; fail "a run with a runtime was refused"; }
grep -Fxq "has_runtime=1 runtime=$work/runtime" "$work/bake-record" || fail "the packed runtime did not reach the build"

# Every mismatch between the export and its records fails, and nothing is kept.
for case in wrong-record wrong-admission wrong-target wrong-version no-admission extra-file symlink failed; do
  if run_client "$work/out-$case" FAKE_EXPORT="$case" >"$work/$case.log" 2>&1; then
    cat "$work/$case.log" >&2
    fail "export case $case was accepted"
  fi
  [ ! -e "$work/out-$case" ] || fail "export case $case left an output"
done
grep -q 'does not match its exported SHA-256 record' "$work/wrong-record.log" || fail "a wrong record was not named"
grep -q 'is not the executable that was admitted' "$work/wrong-admission.log" || fail "a wrong admission was not named"
grep -q 'was admitted for x86_64-apple-darwin' "$work/wrong-target.log" || fail "a wrong target was not named"
grep -q 'was admitted as version v9.9.9' "$work/wrong-version.log" || fail "a wrong version was not named"
grep -q 'is not exactly' "$work/extra-file.log" || fail "an extra exported file was not named"

# The checkout must be the selected commit, and the target one of the two.
if run_client "$work/out-other" CW_RELEASE_SOURCE_SHA="$(printf '%040d' 0)" >"$work/other.log" 2>&1; then
  fail "a checkout that is not the selected commit was built"
fi
if env -i PATH="$work/bin:/usr/bin:/bin" HOME="$work" TMPDIR="$work" CODEWIRE_IN_JOB_BUILD=0 \
    "$CLIENT" "$source" v1.2.3 aarch64-unknown-linux-musl "$work/out-target" >/dev/null 2>&1; then
  fail "a target outside the two Linux release targets was accepted"
fi
# The recovery flag is exactly 0 or 1.
if run_client "$work/out-flag" CODEWIRE_IN_JOB_BUILD=yes >"$work/flag.log" 2>&1; then
  fail "a malformed recovery flag was accepted"
fi

# The owner's recovery builds in the job, never touches the builder, and
# compiles under an explicit environment that holds none of the job's tokens.
# It runs from a copy of the client in a root whose runner-image check, pinned
# fetches, cargo and packaging script are fakes that record what they see.
fake_root="$work/fake-root"
mkdir -p "$fake_root/scripts/ci/release" "$fake_root/scripts/ci/setup"
cp "$CLIENT" "$fake_root/scripts/ci/release/build-cw-linux.sh"
cp "$ROOT/scripts/ci/setup/trusted-buildkit.sh" "$fake_root/scripts/ci/setup/"
cp "$ROOT/scripts/ci/release/local-runtime-sources.json" "$fake_root/scripts/ci/release/"
printf '#!/usr/bin/env bash\nexit 0\n' >"$fake_root/scripts/ci/setup/assert-ci-runner-image.sh"
cat >"$fake_root/scripts/ci/release/fetch-pinned.sh" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  *protoc*) python3 -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1], "w").writestr("bin/protoc", "")' "$3" ;;
  *zig*) d="$(mktemp -d)"; mkdir "$d/zig-x86_64-linux-0.15.2"; tar -cJf "$3" -C "$d" zig-x86_64-linux-0.15.2 ;;
esac
FAKE
cat >"$fake_root/scripts/ci/release/package-cw-release.sh" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
# Under the client's explicit environment only HOME (the test's work directory) says where.
env | LC_ALL=C sort >"$HOME/in-job-env.package"
mkdir -p dist/cw-release
printf 'in-job %s\n' "$CW_RELEASE_TARGETS" >"dist/cw-release/cw-$1-$CW_RELEASE_TARGETS"
FAKE
cat >"$work/bin/cargo" <<'FAKE'
#!/usr/bin/env bash
env | LC_ALL=C sort >"$HOME/in-job-env.cargo"
FAKE
chmod +x "$fake_root"/scripts/ci/release/*.sh "$fake_root"/scripts/ci/setup/*.sh "$work/bin/cargo"
: >"$work/docker-calls"
client_under_test="$fake_root/scripts/ci/release/build-cw-linux.sh"
run_client "$work/out-in-job" CODEWIRE_IN_JOB_BUILD=1 \
  ACTIONS_RUNTIME_TOKEN=synthetic-runtime GITHUB_TOKEN=synthetic-job \
  >"$work/in-job.log" 2>&1 || { cat "$work/in-job.log" >&2; fail "the in-job recovery failed"; }
grep -q 'buildx' "$work/docker-calls" && fail "the in-job recovery attached the builder"
grep -q 'building in the job instead of on the trusted BuildKit builder' "$work/in-job.log" ||
  fail "the in-job recovery did not announce itself"
[ "$(cat "$work/out-in-job/cw-v1.2.3-x86_64-unknown-linux-musl")" = "in-job x86_64-unknown-linux-musl" ] ||
  fail "the in-job recovery did not keep its own build"
for seen in package cargo; do
  if grep -Eq '^(ACTIONS_|GITHUB_TOKEN=|FAKE_DOCKER_CALLS=|TRUSTED_BUILDKIT_)' "$work/in-job-env.$seen"; then
    fail "the in-job $seen step saw a job token or job variable"
  fi
done
{ grep -Fxq "CW_RELEASE_SOURCE_SHA=$sha" "$work/in-job-env.package" &&
  grep -Fxq "CW_RELEASE_BUILD_CMD=cargo zigbuild" "$work/in-job-env.package" &&
  grep -Fxq "CW_RELEASE_TARGETS=x86_64-unknown-linux-musl" "$work/in-job-env.package"; } ||
  fail "the in-job packaging did not get the selected source and target"

# Mutation: without the OIDC drop after the attach, the request credentials
# reach the build, and this test sees them.
sed '/^  drop_oidc$/d' "$CLIENT" >"$fake_root/scripts/ci/release/build-cw-linux.sh"
if grep -q '^  drop_oidc$' "$fake_root/scripts/ci/release/build-cw-linux.sh"; then fail "the OIDC mutation did not apply"; fi
run_client "$work/out-oidc-mutant" \
  >"$work/oidc-mutant.log" 2>&1 || { cat "$work/oidc-mutant.log" >&2; fail "the OIDC mutant did not build"; }
client_under_test=''
grep -Fxq 'oidc_request=tokenurl' "$work/bake-record" || fail "the test cannot see OIDC credentials reach the build"

# Mutation: without creating the export destination first, buildx would ask for
# write access to its parent, and the fake refuses that bake.
# shellcheck disable=SC2016 # the literal line to change
sed 's|^  mkdir -m 0700 "\$work/export" |  mkdir -m 0700 |' "$CLIENT" >"$fake_root/scripts/ci/release/build-cw-linux.sh"
# shellcheck disable=SC2016 # the literal text to look for
if grep -q 'mkdir -m 0700 "\$work/export"' "$fake_root/scripts/ci/release/build-cw-linux.sh"; then
  fail "the export-directory mutation did not apply"
fi
client_under_test="$fake_root/scripts/ci/release/build-cw-linux.sh"
if run_client "$work/out-export-mutant" >"$work/export-mutant.log" 2>&1; then
  fail "a bake to a missing export destination was accepted"
fi
client_under_test=''
grep -q 'the local export destination is not an existing empty directory' "$work/export-mutant.log" ||
  fail "the export-directory mutant failed for another reason"

# Inside the build: every source file is touched before packaging, so a warm
# target directory never keeps another commit's workspace crates; .git is left
# alone; the export is the executable and its two records for this version.
inbuild="$work/inbuild"
mkdir -p "$inbuild/src/crates/a/src" "$inbuild/scripts/ci/release" "$inbuild/target"
git -C "$inbuild/src" init -q
printf 'fn main() {}\n' >"$inbuild/src/crates/a/src/main.rs"
git -C "$inbuild/src" add -A
git -C "$inbuild/src" -c user.name=t -c user.email=t@example.invalid commit -q -m src
: >"$inbuild/compiled-later"
cat >"$inbuild/scripts/ci/release/package-cw-release.sh" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
stale="$(find . -path ./.git -prune -o ! -newer "$FAKE_COMPILED_LATER" -print | head -1)"
[ -z "$stale" ] || { echo "stale source mtime: $stale" >&2; exit 9; }
[ -z "$(find .git -newer "$FAKE_COMPILED_LATER" -print -quit)" ] || { echo ".git was touched" >&2; exit 9; }
[ "$CARGO_TARGET_DIR" = "$FAKE_WARM_TARGET" ] || { echo "not the warm target" >&2; exit 9; }
mkdir -p dist/cw-release
name="cw-$1-$CW_RELEASE_TARGETS"
printf 'built\n' >"dist/cw-release/$name"
printf 'cw-release: admitted target=%s version=%s inputs=3 sha256=%s\n' \
  "$CW_RELEASE_TARGETS" "$1" "$(sha256sum "dist/cw-release/$name" | cut -c1-64)"
FAKE
chmod +x "$inbuild/scripts/ci/release/package-cw-release.sh"
age_source() {
  find "$inbuild/src" -exec touch -h -d '2001-01-01 00:00:00' {} +
  touch -d '2002-01-01 00:00:00' "$inbuild/compiled-later"
}
run_inbuild() {
  local script="$1" out="$2"
  rm -rf "$inbuild/src/dist"
  env -i PATH=/usr/bin:/bin HOME="$work" TMPDIR="$work" \
    CW_RELEASE_SRC="$inbuild/src" CW_RELEASE_SCRIPTS="$inbuild/scripts" CW_RELEASE_OUT="$out" \
    CW_RELEASE_WARM_TARGET="$inbuild/target" FAKE_WARM_TARGET="$inbuild/target" \
    FAKE_COMPILED_LATER="$inbuild/compiled-later" CW_RELEASE_TARGET=aarch64-unknown-linux-gnu \
    CW_RELEASE_VERSION=v1.2.3 CW_RELEASE_HAS_RUNTIME=0 CW_RELEASE_TARGET_CACHE=warm "$script"
}
age_source
run_inbuild "$ROOT/scripts/ci/release/cw-release-linux-build.sh" "$inbuild/out" >"$work/inbuild.log" 2>&1 ||
  { cat "$work/inbuild.log" >&2; fail "the in-build packaging failed"; }
[ "$(cd "$inbuild/out" && find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort | tr '\n' ' ')" = \
  "cw-v1.2.3-aarch64-unknown-linux-gnu cw-v1.2.3-aarch64-unknown-linux-gnu.admitted cw-v1.2.3-aarch64-unknown-linux-gnu.sha256 " ] ||
  fail "the in-build export is not the executable and its two records"
(cd "$inbuild/out" && sha256sum -c --quiet cw-v1.2.3-aarch64-unknown-linux-gnu.sha256) || fail "the in-build SHA-256 record is wrong"
# Mutation: without the touch, the clone's old mtimes reach cargo.
# shellcheck disable=SC2016 # the literal line to remove
grep -v '^find "\$src" -path "\$src/.git" -prune -o -exec touch -h {} +$' \
  "$ROOT/scripts/ci/release/cw-release-linux-build.sh" >"$inbuild/mutant.sh"
chmod +x "$inbuild/mutant.sh"
if cmp -s "$inbuild/mutant.sh" "$ROOT/scripts/ci/release/cw-release-linux-build.sh"; then fail "the mtime mutation did not apply"; fi
age_source
if run_inbuild "$inbuild/mutant.sh" "$inbuild/out-mutant" >"$work/inbuild-mutant.log" 2>&1; then
  fail "a build that keeps the clone's mtimes was accepted"
fi
grep -q 'stale source mtime' "$work/inbuild-mutant.log" || fail "the mtime mutant failed for another reason"

# Static: one platform, no emulation, and the two export targets.
grep -c 'platforms *= \["linux/amd64"\]' "$HCL" | grep -qx 2 || fail "the bake file does not pin linux/amd64 twice"
grep -Eqi 'qemu|binfmt|linux/arm64|--platform' "$HCL" "$DOCKERFILE" && fail "the release build mentions emulation or another platform"
for triple in x86_64-unknown-linux-musl aarch64-unknown-linux-gnu; do
  grep -Fxq "FROM scratch AS cw-$triple" "$DOCKERFILE" || fail "no export target for $triple"
  grep -Fq "id=cw-release-target-$triple,target=/cargo-target,sharing=locked" "$DOCKERFILE" ||
    fail "$triple has no target cache of its own"
done
# The two cw compiles run side by side: every builder cache belongs to one
# target, so no locked mount makes one compile wait for the other. Each runs
# at the cw compile's own Cargo job bound.
ids="$(grep -o -- '--mount=type=cache,id=[^,]*' "$DOCKERFILE" | sed 's/.*id=//')"
[ "$(printf '%s\n' "$ids" | wc -l)" -eq 6 ] || fail "the two build stages do not keep exactly three caches each"
for id in $ids; do
  case "$id" in
    *-x86_64-unknown-linux-musl | *-aarch64-unknown-linux-gnu) ;;
    *) fail "builder cache $id is not one target's own" ;;
  esac
done
[ -z "$(printf '%s\n' "$ids" | sort | uniq -d)" ] || fail "the two cw compiles share a builder cache"
grep -Fq 'CARGO_BUILD_JOBS          = CW_RELEASE_CARGO_BUILD_JOBS' "$HCL" || fail "the cw compile does not take its own Cargo job bound"
grep -q 'type=cache' "$DOCKERFILE" || fail "the release build keeps no builder cache"
if grep -Eq 'cache-(to|from)|sccache' "$HCL" "$DOCKERFILE"; then
  fail "the release build reaches a cache other than the builder's"
fi
# The in-job protoc pin is rust-base.Dockerfile's.
grep -Fq "$(sed -n "s/^readonly PROTOC_SHA256='\(.*\)'$/\1/p" "$CLIENT")" "$ROOT/deployments/docker/rust-base.Dockerfile" ||
  fail "the in-job protoc pin differs from rust-base.Dockerfile's"

echo "build-cw-linux: OK (valid export, runtime, 8 refused exports, wrong source, wrong target, recovery flag, in-job recovery without tokens, OIDC-drop, export-directory and mtime mutants, in-build export, static)"
