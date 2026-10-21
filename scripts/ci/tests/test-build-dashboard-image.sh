#!/usr/bin/env bash
# The dashboard verification image reads the protected cache with the
# protected-read token in a pull request, writes it only from a push to main,
# and otherwise compiles with the local cache; it never passes a credential
# the job's context does not own.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly BUILD="$ROOT/scripts/ci/verify/build-dashboard-image.sh"

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/codewire-build-dashboard-image.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT

mkdir -p "$work/bin"
cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
{
  printf 'arg %s\n' "$@"
  for name in CODEWIRE_SCCACHE_MODE SCCACHE_BUCKET SCCACHE_ENDPOINT CODEWIRE_SCCACHE_PREFIX; do
    [[ ! -v "$name" ]] || printf 'env %s\n' "$name"
  done
} >"$DOCKER_LOG"
EOF
chmod +x "$work/bin/docker"

printf '%s\n' '[default]' 'aws_access_key_id = synthetic' >"$work/r2.aws"
readonly bucket=example-ci-cache-protected
readonly endpoint=https://synthetic.r2.example
readonly prefix=protected/codewire/v1

# build EVENT REF MODE TRUST CREDENTIALS: run the build in one job context.
build() {
  local event="$1" ref="$2" mode="$3" trust="$4" credentials="$5"
  env -i PATH="$work/bin:/usr/bin:/bin" DOCKER_LOG="$work/docker.log" \
    GITHUB_EVENT_NAME="$event" GITHUB_REF="$ref" \
    CODEWIRE_SCCACHE_MODE="$mode" CODEWIRE_R2_CACHE_TRUST="$trust" \
    AWS_SHARED_CREDENTIALS_FILE="$credentials" \
    SCCACHE_BUCKET="$bucket" SCCACHE_ENDPOINT="$endpoint" CODEWIRE_SCCACHE_PREFIX="$prefix" \
    "$BUILD" codewire-dashboard:verification-test >"$work/build.out" 2>&1
}

fail() {
  printf '%s\n' "$1" >&2
  cat "$work/build.out" "$work/docker.log" >&2 2>/dev/null || true
  exit 1
}

has() { grep -qxF -- "arg $1" "$work/docker.log"; }

assert_common() {
  local expected
  for expected in buildx bake dashboard 'dashboard.tags=codewire-dashboard:verification-test'; do
    has "$expected" || fail "the dashboard bake lost $expected"
  done
  ! grep -q '^env ' "$work/docker.log" || fail 'bake inherited a cache variable from the job environment'
}

assert_r2() {
  assert_common
  has 'dashboard.args.CODEWIRE_SCCACHE_MODE=r2' || fail "$1: did not select r2"
  has "dashboard.args.SCCACHE_BUCKET=$bucket" || fail "$1: lost the protected bucket"
  has "dashboard.args.SCCACHE_ENDPOINT=$endpoint" || fail "$1: lost the endpoint"
  has "dashboard.args.CODEWIRE_SCCACHE_PREFIX=$prefix" || fail "$1: lost the prefix"
  has "dashboard.secrets=id=aws_shared_credentials,src=$work/r2.aws" || fail "$1: did not pass the credential"
}

assert_without_credential() {
  local mode="$2"
  assert_common
  has "dashboard.args.CODEWIRE_SCCACHE_MODE=$mode" || fail "$1: did not select $mode"
  ! grep -q -e 'secrets=' -e 'SCCACHE_BUCKET=' "$work/docker.log" ||
    fail "$1: passed a credential or bucket"
}

# A pull request reads the protected cache with its read-only token.
build pull_request refs/pull/7/head r2 protected-read "$work/r2.aws" || fail 'pull request build failed'
assert_r2 'pull request'
grep -qxF 'CODEWIRE_DASHBOARD_IMAGE_CACHE mode=r2 trust=protected-read' "$work/build.out" ||
  fail 'pull request build did not report its read-only trust'
printf '[test-build-dashboard-image] a pull request reads the protected cache read-only\n'

# A push to main reads and writes it with the protected writer.
build push refs/heads/main r2 main "$work/r2.aws" || fail 'main build failed'
assert_r2 'main'
grep -qxF 'CODEWIRE_DASHBOARD_IMAGE_CACHE mode=r2 trust=main' "$work/build.out" ||
  fail 'main build did not report its writer trust'
printf '[test-build-dashboard-image] a push to main writes the protected cache\n'

# A pull request never passes a write credential, even if one is in scope;
# neither does any other non-main context.
for context in 'pull_request refs/pull/7/head' 'push refs/heads/feature' 'workflow_dispatch refs/heads/main'; do
  read -r event ref <<<"$context"
  build "$event" "$ref" r2 main "$work/r2.aws" || fail "$context: build failed"
  assert_without_credential "$context with the writer trust" local
done
# Main does not run on the read-only token as if it were the writer.
build push refs/heads/main r2 protected-read "$work/r2.aws" || fail 'main read-only build failed'
assert_without_credential 'main with the read-only trust' local
printf '[test-build-dashboard-image] the writer credential never leaves a push to main\n'

# Without a usable token the build compiles with the local cache.
build pull_request refs/pull/7/head r2 protected-read '' || fail 'missing credential failed the build'
assert_without_credential 'missing credential' local
build pull_request refs/pull/7/head r2 protected-read "$work/absent.aws" || fail 'absent credential failed the build'
assert_without_credential 'absent credential' local
: >"$work/empty.aws"
build pull_request refs/pull/7/head r2 protected-read "$work/empty.aws" || fail 'empty credential failed the build'
assert_without_credential 'empty credential' local
ln -s "$work/r2.aws" "$work/link.aws"
build pull_request refs/pull/7/head r2 protected-read "$work/link.aws" || fail 'symlinked credential failed the build'
assert_without_credential 'symlinked credential' local
build pull_request refs/pull/7/head local '' '' || fail 'local mode failed the build'
assert_without_credential 'local mode' local
printf '[test-build-dashboard-image] without a usable token the build uses the local cache\n'

# A job with no compiler cache keeps the image's disabled default.
build pull_request refs/pull/7/head '' '' '' || fail 'unset mode failed the build'
assert_without_credential 'unset mode' disabled
build '' '' disabled '' '' || fail 'disabled mode failed the build'
assert_without_credential 'disabled mode' disabled
printf '[test-build-dashboard-image] a disabled cache stays disabled\n'

if build pull_request refs/pull/7/head s3 protected-read "$work/r2.aws"; then
  fail 'an unknown cache mode was accepted'
fi
grep -qF 'invalid CODEWIRE_SCCACHE_MODE: s3' "$work/build.out" || fail 'unknown mode refusal was not attributable'
printf '[test-build-dashboard-image] an unknown cache mode is refused\n'
