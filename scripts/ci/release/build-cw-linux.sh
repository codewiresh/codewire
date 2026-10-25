#!/usr/bin/env bash
# Build one Linux release cw on the trusted BuildKit builder and verify it
# (#3119). The job submits the build, receives the executable and checks it;
# the builder compiles it with the unchanged package-cw-release.sh
# (cw-release-linux.Dockerfile). The owner's recovery,
# CODEWIRE_IN_JOB_BUILD=1 (trusted-buildkit.sh), builds it in the job instead,
# exactly as before.
#
# Usage: build-cw-linux.sh SOURCE_DIR VERSION TARGET OUTPUT_DIR
#
# SOURCE_DIR is the checkout of the selected commit, VERSION the release tag
# (vX.Y.Z), TARGET x86_64-unknown-linux-musl or aarch64-unknown-linux-gnu.
# OUTPUT_DIR gets exactly cw-VERSION-TARGET. CW_RELEASE_SOURCE_SHA,
# CW_RELEASE_TAG_OBJECT_SHA and CW_RELEASE_LOCAL_RUNTIME_DIR mean what they
# mean to package-cw-release.sh. With GITHUB_OUTPUT set, cw_sha256 is written
# to it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=scripts/ci/setup/trusted-buildkit.sh
source "$ROOT/scripts/ci/setup/trusted-buildkit.sh"

# The protoc pin rust-base.Dockerfile installs on the builder.
readonly PROTOC_URL='https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip'
readonly PROTOC_SHA256='6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7'
# Both workflows reuse the per-target Cargo target directory the main builds
# keep on the builder (owner, 2026-10-21, on infra#1617: "Approve, warm cache").
readonly CW_RELEASE_TARGET_CACHE_DEFAULT='warm'
# Cargo jobs for one cw compile on the builder. At 8 jobs with thin LTO the two
# compiles together peaked at 8.47 GiB and averaged 9.4 busy cores of the
# builder's 60 (dry run 18591). The builder shrinks to 12 GiB with two steps at
# once (infra#1534, 2026-10-25: a release that fails is worse than a slow one),
# so each compile takes 8 again: both together then fit with room to spare. The
# in-job recovery does not use this: its Cargo takes the runner's own default.
readonly CW_RELEASE_CARGO_JOBS_DEFAULT=8

die() {
  echo "build-cw-linux: $*" >&2
  exit 1
}

[ "$#" -eq 4 ] || die "usage: build-cw-linux.sh SOURCE_DIR VERSION TARGET OUTPUT_DIR"
source_dir="$1" version="$2" target="$3" output_dir="$4"
case "$target" in
  x86_64-unknown-linux-musl|aarch64-unknown-linux-gnu) ;;
  *) die "TARGET must be x86_64-unknown-linux-musl or aarch64-unknown-linux-gnu, got: $target" ;;
esac
case "$version" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) die "VERSION must look like vX.Y.Z, got: $version" ;;
esac
source_dir="$(cd "$source_dir" && pwd -P)" || die "SOURCE_DIR is not a directory"
[ ! -e "$output_dir" ] || die "OUTPUT_DIR must not exist yet: $output_dir"
source_sha="${CW_RELEASE_SOURCE_SHA:-$(git -C "$source_dir" rev-parse HEAD)}"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || die "the source revision is not a commit id: $source_sha"
[ "$(git -C "$source_dir" rev-parse HEAD)" = "$source_sha" ] ||
  die "the checkout is not the selected source revision $source_sha"
runtime_dir="${CW_RELEASE_LOCAL_RUNTIME_DIR:-}"
if [ -n "$runtime_dir" ]; then
  case "$runtime_dir" in
    /*) [ -d "$runtime_dir" ] || die "CW_RELEASE_LOCAL_RUNTIME_DIR is not a directory" ;;
    *) die "CW_RELEASE_LOCAL_RUNTIME_DIR must be an absolute path" ;;
  esac
fi
name="cw-$version-$target"

# The zig and cargo-zigbuild pins the local runtime's cw builder uses, which
# release delivery has always shared (local-runtime-sources.json).
read -r zig_version zig_sha256 zigbuild_version < <(python3 -c '
import json, sys
pins = json.load(open(sys.argv[1]))["cw_runtime_builder"]
print(pins["zig"]["version"], pins["zig"]["sha256"], pins["cargo_zigbuild"])' \
  "$ROOT/scripts/ci/release/local-runtime-sources.json")

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/codewire-cw-release.XXXXXX")"
builder=''
cleanup() {
  if [ -n "$builder" ]; then
    # Removing a remote builder only forgets it locally; the node is untouched.
    DOCKER_CONFIG="$work/docker-config" timeout 30 docker buildx rm "$builder" >/dev/null 2>&1 || true
  fi
  # The client tuple and the builder's local record, as the other callers do.
  find "$work/trusted-buildkit-tls" "$work/docker-config" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf -- "$work"
}
trap cleanup EXIT

# Forgejo's OIDC claims name the workflow, not the job: while this job could
# request an ID token, it could log in to any role bound to its workflow. The
# remote build needs one login, for the builder's client certificate; drop_oidc
# removes the request credentials as soon as that login is done, and before
# any compile.
drop_oidc() {
  unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL
}

# verify_export DIR: exactly the executable, its SHA-256 line and the admission
# line for this target and version, all three agreeing.
verify_export() {
  local dir="$1" actual digest recorded admitted
  actual="$(cd "$dir" && find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort | tr '\n' ' ')"
  [ "$actual" = "$name $name.admitted $name.sha256 " ] ||
    die "the export is not exactly $name and its two records: $actual"
  for file in "$name" "$name.sha256" "$name.admitted"; do
    [ -f "$dir/$file" ] && [ ! -L "$dir/$file" ] || die "$file is not a regular file"
  done
  [ -x "$dir/$name" ] || die "$name is not executable"
  digest="$(sha256sum "$dir/$name" | cut -c1-64)"
  recorded="$(cat "$dir/$name.sha256")"
  [ "$recorded" = "$digest  $name" ] || die "$name does not match its exported SHA-256 record"
  admitted="$(cat "$dir/$name.admitted")"
  [[ "$admitted" =~ ^cw-release:\ admitted\ target=([^ ]+)\ version=([^ ]+)\ inputs=([1-9][0-9]*)\ sha256=([0-9a-f]{64})$ ]] ||
    die "$name has no admission record: $admitted"
  [ "${BASH_REMATCH[1]}" = "$target" ] || die "$name was admitted for ${BASH_REMATCH[1]}"
  [ "${BASH_REMATCH[2]}" = "$version" ] || die "$name was admitted as version ${BASH_REMATCH[2]}"
  [ "${BASH_REMATCH[4]}" = "$digest" ] || die "$name is not the executable that was admitted"
}

build_remote() {
  local context="$work/source" runtime="$work/no-runtime" has_runtime=0
  # A fresh clone of exactly this commit: the checkout's own .git may carry a
  # job credential, which must never reach the builder or its cache.
  git init -q "$context"
  git -C "$context" -c protocol.file.allow=always fetch -q --depth 1 \
    --upload-pack='git -c uploadpack.allowAnySHA1InWant=true upload-pack' \
    "file://$source_dir" "$source_sha"
  git -C "$context" checkout -q --detach FETCH_HEAD
  [ "$(git -C "$context" rev-parse HEAD)" = "$source_sha" ] || die "the build context is not $source_sha"
  ! git -C "$context" config --local --get-regexp '^(http\..*extraheader|remote\.|credential\.)' >/dev/null ||
    die "the build context's git configuration names a remote or credential"
  if [ -n "$runtime_dir" ]; then
    runtime="$runtime_dir" has_runtime=1
  else
    mkdir -m 0700 "$runtime"
  fi
  # Buildx asks for write access to the nearest existing parent of a missing
  # local export destination, which --allow=fs.write=<destination> does not
  # cover; it refused cli-release 18343 that way, intermittently. An existing
  # destination is exactly the path the allow names.
  mkdir -m 0700 "$work/export" "$work/docker-config" "$work/trusted-buildkit-tls"
  builder="codewire-cw-release-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
  trusted_buildkit_attach "$builder" "$work/docker-config" "$work/trusted-buildkit-tls"
  drop_oidc
  (
    cd "$ROOT"
    DOCKER_CONFIG="$work/docker-config" \
      CW_RELEASE_CONTEXT="$context" \
      CW_RELEASE_DOCKERFILE="$ROOT/scripts/ci/release/cw-release-linux.Dockerfile" \
      CW_RELEASE_SCRIPTS="$ROOT/scripts" \
      CW_RELEASE_RUNTIME="$runtime" \
      CW_RELEASE_HAS_RUNTIME="$has_runtime" \
      CW_RELEASE_VERSION="$version" \
      CW_RELEASE_SOURCE_SHA="$source_sha" \
      CW_RELEASE_TAG_OBJECT_SHA="${CW_RELEASE_TAG_OBJECT_SHA:-}" \
      CW_RELEASE_TARGET_CACHE="${CW_RELEASE_TARGET_CACHE:-$CW_RELEASE_TARGET_CACHE_DEFAULT}" \
      CW_RELEASE_CARGO_BUILD_JOBS="$CW_RELEASE_CARGO_JOBS_DEFAULT" \
      ZIG_VERSION="$zig_version" ZIG_X86_64_LINUX_SHA256="$zig_sha256" \
      CARGO_ZIGBUILD_VERSION="$zigbuild_version" \
      docker buildx bake --builder "$builder" --progress plain \
        --allow="fs.read=$context" --allow="fs.read=$runtime" --allow="fs.write=$work/export" \
        --file scripts/ci/release/cw-release-linux.hcl \
        --set "cw-release-$target.output=type=local,dest=$work/export" \
        "cw-release-$target"
  )
  verify_export "$work/export"
  mkdir -m 0700 "$output_dir"
  cp "$work/export/$name" "$output_dir/$name"
}

# clean_env COMMAND...: run COMMAND with an explicit environment and none of
# the job's tokens (job, Actions runtime or OIDC request credentials). The
# in-job recovery compiles third-party build scripts and the release source's.
clean_env() {
  env -i \
    PATH="$work/protoc/bin:$work/zig-x86_64-linux-$zig_version:$work/tools/bin:$PATH" \
    HOME="$HOME" TMPDIR="${TMPDIR:-/tmp}" LANG=C.UTF-8 \
    ${CARGO_HOME:+CARGO_HOME="$CARGO_HOME"} ${RUSTUP_HOME:+RUSTUP_HOME="$RUSTUP_HOME"} \
    ${CARGO_HTTP_TIMEOUT:+CARGO_HTTP_TIMEOUT="$CARGO_HTTP_TIMEOUT"} \
    ${CARGO_NET_RETRY:+CARGO_NET_RETRY="$CARGO_NET_RETRY"} \
    ${CW_RELEASE_TAG_OBJECT_SHA:+CW_RELEASE_TAG_OBJECT_SHA="$CW_RELEASE_TAG_OBJECT_SHA"} \
    ${runtime_dir:+CW_RELEASE_LOCAL_RUNTIME_DIR="$runtime_dir"} \
    "$@"
}

build_in_job() {
  drop_oidc
  "$ROOT/scripts/ci/setup/assert-ci-runner-image.sh"
  "$ROOT/scripts/ci/release/fetch-pinned.sh" "$PROTOC_URL" "$PROTOC_SHA256" "$work/protoc.zip"
  unzip -q "$work/protoc.zip" -d "$work/protoc"
  "$ROOT/scripts/ci/release/fetch-pinned.sh" \
    "https://ziglang.org/download/$zig_version/zig-x86_64-linux-$zig_version.tar.xz" \
    "$zig_sha256" "$work/zig.tar.xz"
  tar -xJf "$work/zig.tar.xz" -C "$work"
  clean_env cargo install --locked --root "$work/tools" cargo-zigbuild --version "$zigbuild_version"
  (
    cd "$source_dir"
    clean_env CW_RELEASE_SOURCE_SHA="$source_sha" CW_RELEASE_BUILD_CMD='cargo zigbuild' CW_RELEASE_TARGETS="$target" \
      "$ROOT/scripts/ci/release/package-cw-release.sh" "$version"
  )
  mkdir -m 0700 "$output_dir"
  cp "$source_dir/dist/cw-release/$name" "$output_dir/$name"
}

if trusted_buildkit_in_job; then
  build_in_job
else
  build_remote
fi

cw_sha256="$(sha256sum "$output_dir/$name" | cut -c1-64)"
printf 'build-cw-linux: %s sha256=%s\n' "$name" "$cw_sha256"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  printf 'cw_sha256=%s\n' "$cw_sha256" >> "$GITHUB_OUTPUT"
fi
