#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: package-cw-release.sh <vX.Y.Z>

Builds Rust cw release assets into $CW_RELEASE_DIST_DIR. Every build embeds the
explicit version, source revision and source digest in its build record, and
each executable is admitted only if that record, the unchanged source and its
Cargo dep-info agree. With exactly the four release targets it also prepares
the unsigned delivery: one identity per final executable, the OCI image and
native runtime pack from the same Linux x86-64 musl bytes, and the data the
release manifest binds. Signing is a separate step (sign-cw-release.sh);
compilation never receives signing or publication credentials.

Environment:
  CW_RELEASE_TARGETS             Space-separated target triples, built
                                 together in one Cargo invocation so their
                                 builds and final links run side by side;
                                 `none` builds nothing and only prepares the
                                 imported assets.
  CW_RELEASE_PROFILE             Cargo profile to build (default: release).
  CW_RELEASE_BUILD_CMD           Cargo command prefix (default: cargo build).
  CW_RELEASE_DIST_DIR            Output directory (default: dist/cw-release).
  CW_RELEASE_SOURCE_SHA          Selected source commit (default: HEAD).
  CW_RELEASE_TAG_OBJECT_SHA      Selected tag object (default: the source commit,
                                 for unpublished dry runs).
  CW_RELEASE_IMPORT_DIR          cw-<version>-<target> executables built on
                                 another host (the macOS pair, built natively
                                 on the Mac runner) that complete exactly the
                                 four release targets. Preparation admits each
                                 by its build record, as for a local build.
                                 Its local-runtime directory, if any, comes too,
                                 and every cw built here embeds its document.
  CW_RELEASE_LOCAL_RUNTIME_DIR   Absolute path of a local VM runtime directory
                                 (local-runtime.json and blobs/sha256/*) built
                                 from the selected source. Every cw built here
                                 embeds its one document (#2733); the directory
                                 is carried as <dist>/local-runtime and
                                 preparation makes it the delivery's runtime.
EOF
}

die() {
  echo "package-cw-release: $*" >&2
  exit 1
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi

# Compilation runs in a job without signing or publication capability.
for name in CW_RELEASE_GPG_PRIVATE_KEY CW_RELEASE_GPG_PASSPHRASE \
  AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY GH_MIRROR_TOKEN_FILE; do
  [ -z "${!name:-}" ] || die "$name must not reach release compilation"
done

version="${1:-${VERSION:-}}"
[ -n "$version" ] || die "version is required"
case "$version" in
  v[0-9]*.[0-9]*.[0-9]*)
    ;;
  *)
    die "version must look like vX.Y.Z, got: $version"
    ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
release_py="$script_dir/cw_release.py"
release_targets='x86_64-unknown-linux-musl aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin'
host_target="$(rustc -vV | awk '/^host:/ {print $2}')"
targets="${CW_RELEASE_TARGETS:-$host_target}"
[ "$targets" != none ] || targets=""
profile="${CW_RELEASE_PROFILE:-release}"
build_cmd="${CW_RELEASE_BUILD_CMD:-cargo build}"
dist_dir="${CW_RELEASE_DIST_DIR:-dist/cw-release}"
target_dir="${CARGO_TARGET_DIR:-target}"
source_sha="${CW_RELEASE_SOURCE_SHA:-$(git rev-parse HEAD)}"
tag_object_sha="${CW_RELEASE_TAG_OBJECT_SHA:-$source_sha}"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
[ "$(git rev-parse HEAD)" = "$source_sha" ] || die "checkout is not the selected source revision $source_sha"

case "$profile" in
  dev)
    profile_dir="debug"
    profile_flag=()
    ;;
  release)
    profile_dir="release"
    profile_flag=(--release)
    ;;
  *)
    profile_dir="$profile"
    profile_flag=(--profile "$profile")
    ;;
esac

# Bind the source before anything is built. Each build embeds it, and
# admission and preparation recheck it afterwards.
source_digest_before="$(python3 "$release_py" source-digest --source-root .)"

# The local VM runtime every release cw embeds (#2539, #2733): given to the
# job that builds it (the macOS pair's), or imported with that job's assets.
# It is checked before anything is built, and every target built here embeds
# exactly its document.
runtime_dir="${CW_RELEASE_LOCAL_RUNTIME_DIR:-}"
import_dir="${CW_RELEASE_IMPORT_DIR:-}"
if [ -n "$import_dir" ] && [ -e "$import_dir/local-runtime" ]; then
  [ -z "$runtime_dir" ] || die "a local runtime is both imported and given"
  runtime_dir="$(cd "$import_dir/local-runtime" && pwd -P)" || die "the imported local runtime is not a directory"
fi
if [ -n "$runtime_dir" ]; then
  case "$runtime_dir" in
    /*) ;;
    *) die "CW_RELEASE_LOCAL_RUNTIME_DIR must be an absolute path" ;;
  esac
  # The canonical path is what Cargo records in dep-info. Admission accepts
  # exactly this document with exactly the bytes verified here.
  runtime_dir="$(cd "$runtime_dir" && pwd -P)" || die "CW_RELEASE_LOCAL_RUNTIME_DIR is not a directory"
  runtime_check="$(python3 "$release_py" local-runtime --dir "$runtime_dir" --source-sha "$source_sha")" ||
    die "the local runtime is not a local runtime of the selected source"
  printf '%s\n' "$runtime_check"
  runtime_document_sha256="$(printf '%s\n' "$runtime_check" |
    sed -n 's/^cw-release: local runtime document_sha256=\([0-9a-f]\{64\}\) .*$/\1/p')"
  [ "${#runtime_document_sha256}" -eq 64 ] || die "the local runtime check reported no document digest"
fi

rm -rf "$dist_dir"
mkdir -p "$dist_dir"

runtime_env=()
admit_runtime=()
if [ -n "$runtime_dir" ]; then
  runtime_env=("CODEWIRE_LOCAL_RUNTIME=$runtime_dir/local-runtime.json")
  admit_runtime=(--embedded-runtime "$runtime_dir/local-runtime.json=$runtime_document_sha256")
fi
# Every target in one Cargo invocation: their builds and their final
# (single-unit LTO) links run side by side, sharing host build scripts. Each
# target's features resolve as when it is built alone.
if [ -n "$targets" ]; then
  echo "building cw $version for $targets"
  # shellcheck disable=SC2206
  cmd=($build_cmd)
  target_flags=()
  for target in $targets; do
    target_flags+=(--target "$target")
  done
  # macOS bash 3.2 treats an empty array as unbound under set -u.
  env -u CODEWIRE_LOCAL_RUNTIME ${runtime_env[@]+"${runtime_env[@]}"} \
    CODEWIRE_VERSION="$version" \
    CODEWIRE_SOURCE_REVISION="$source_sha" \
    CODEWIRE_SOURCE_TREE_SHA256="$source_digest_before" \
    "${cmd[@]}" \
    --locked \
    "${profile_flag[@]}" \
    -p codewire-cli-bin \
    --bin cw \
    "${target_flags[@]}"
fi

for target in $targets; do
  binary="$target_dir/$target/$profile_dir/cw"
  [ -x "$binary" ] || die "expected built binary at $binary"
  python3 "$release_py" admit \
    --source-root . \
    --executable "$binary" \
    --depinfo "$target_dir/$target/$profile_dir/cw.d" \
    --target "$target" \
    --version "$version" \
    --source-sha "$source_sha" \
    --source-digest-before "$source_digest_before" \
    --target-dir "$target_dir" \
    --cargo-home "$cargo_home" \
    ${admit_runtime[@]+"${admit_runtime[@]}"}
  cp "$binary" "$dist_dir/cw-$version-$target"
done

if [ -n "$runtime_dir" ]; then
  cp -R "$runtime_dir" "$dist_dir/local-runtime"
  python3 "$release_py" local-runtime --dir "$dist_dir/local-runtime" --source-sha "$source_sha" ||
    die "staged local runtime does not verify"
fi

release_set="$(printf '%s\n' $release_targets | sort | tr '\n' ' ')"
imported=""
if [ -n "$import_dir" ]; then
  for target in $release_targets; do
    case " $targets " in *" $target "*) continue ;; esac
    file="$import_dir/cw-$version-$target"
    [ -f "$file" ] && [ ! -L "$file" ] || die "missing imported release asset $file"
    install -m 0755 "$file" "$dist_dir/cw-$version-$target"
    imported="$imported $target"
  done
  # shellcheck disable=SC2086 # word lists of target triples
  [ "$(printf '%s\n' $targets $imported | sort | tr '\n' ' ')" = "$release_set" ] ||
    die "imported assets must complete exactly the four release targets"
fi

(
  cd "$dist_dir"
  sha256sum cw-* | sort -k2 > SHA256SUMS
)

# shellcheck disable=SC2086 # word lists of target triples
sorted_targets="$(printf '%s\n' $targets $imported | sort | tr '\n' ' ')"
if [ "$sorted_targets" = "$release_set" ]; then
  python3 "$release_py" prepare \
    --dist "$dist_dir" \
    --version "$version" \
    --source-root . \
    --source-sha "$source_sha" \
    --tag-object-sha "$tag_object_sha" \
    --source-digest-before "$source_digest_before"
else
  echo "package-cw-release: delivery preparation needs exactly the four release targets; skipped" >&2
fi

echo "release assets:"
# Portable listing: the macOS pair is packaged on a Mac, whose find lacks -printf.
for asset in "$dist_dir"/*; do
  if [ -f "$asset" ]; then
    printf '  %s\n' "${asset##*/}"
  fi
done
