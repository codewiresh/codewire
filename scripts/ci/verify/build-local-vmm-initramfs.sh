#!/usr/bin/env bash
# Build the canonical uncompressed newc archive for the local-VMM guest probe,
# or prove that the exact static-musl build is reproducible. Product-root mode
# additionally seals a caller-pinned static BusyBox into the archive. Archive-
# only mode does not claim the supplied probe was built with the sealed toolchain.
# This focused gate does not attest artifact publication or full supply-chain
# provenance; those remain owned by the supply-chain work item.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly PACKAGE='codewire-vmm-guest-probe'
readonly BINARY='codewire-vmm-guest-probe'
readonly REQUIRED_RUST='1.99.0'
readonly REQUIRED_PROTOC='libprotoc 35.1'
readonly DEFAULT_TARGET='x86_64-unknown-linux-musl'
readonly ARM64_TARGET='aarch64-unknown-linux-musl'
readonly REQUIRED_RUNC_VERSION='1.5.1'
readonly X86_64_RUNC_SHA256='177df879d50c913eb205e898d5c1c05a18f574053c0ce5524c471208eaf06f6f'
# Official runc v1.5.1 release asset runc.arm64:
# https://github.com/opencontainers/runc/releases/download/v1.5.1/runc.arm64
readonly ARM64_RUNC_SHA256='ca70e7dbd6616ca782a59b5d3ac86909123fdaa9fa3f89dcf29051c70eee7ce9'
# bin/busybox.static from Alpine v3.23 busybox-static 1.37.0-r30. The signed
# aarch64 APK has SHA-256 44c9abdfb970f398fa72c8382fe2d8808eea16beaf82daf6ac708b92f1b8659e
# and exact aports commit 1e823a60eb85606954b3a5af5f8e5bbd1ea680cf:
# https://dl-cdn.alpinelinux.org/alpine/v3.23/main/aarch64/busybox-static-1.37.0-r30.apk
readonly ARM64_BUSYBOX_SHA256='198f6f675a49ac734082e054b823d3e2e947180ca2f632852ae1c09e950fd676'
# bin/busybox.static from the same Alpine v3.23 busybox-static 1.37.0-r30 for
# x86_64. The signed APK has SHA-256
# bb30365b954f531938a33de18173342185844828863121d7e821115d2f7f29c9 and the same
# aports commit:
# https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/busybox-static-1.37.0-r30.apk
readonly X86_64_BUSYBOX_SHA256='82bbbabec12a985ae58810cfe975c3399264dc888aa592d8e460732bdd30a8dd'

usage() {
  printf '%s\n' \
    'usage:' \
    '  build-local-vmm-initramfs.sh --probe ABSOLUTE_PATH --output ABSOLUTE_PATH' \
    '  build-local-vmm-initramfs.sh --verify [--target TARGET] [--output ABSOLUTE_PATH]' \
    '  build-local-vmm-initramfs.sh --verify-root --busybox ABSOLUTE_PATH' \
    '    --busybox-sha256 SHA256 --runc ABSOLUTE_PATH' \
    '    --runc-sha256 SHA256 [--target TARGET]' \
    '    [--output ABSOLUTE_PATH]' \
    '' \
    '--probe/--output creates a deterministic archive from caller-supplied bytes.' \
    'It does not prove the probe is static or came from the sealed Rust toolchain.' \
    '--verify accepts only x86_64-unknown-linux-musl (the default) or' \
    'aarch64-unknown-linux-musl. It requires exact Rust 1.99.0, libprotoc' \
    '35.1, the selected installed musl standard library, and readelf. It builds' \
    'each required binary twice and fails closed on any drift. With --output,' \
    'the verified archive' \
    'is published atomically' \
    'after comparison. --verify-root applies the same proof and adds static' \
    'target-architecture BusyBox and official runc 1.5.1 binaries. Exact' \
    'lowercase SHA-256 values must be supplied; runc must match the built-in' \
    'reviewed release digest. BusyBox must also match the built-in reviewed' \
    'Alpine package payload digest for the target.' \
    'cw is supplied separately through the pinned read-only runtime disk.' \
    'Artifact provenance remains a separate gate.' >&2
}

die() {
  printf 'local VMM initramfs: ERROR: %s\n' "$*" >&2
  exit 1
}

absolute_existing_file() {
  local label="$1" path="$2"
  [[ "$path" == /* ]] || die "$label path must be absolute: $path"
  [[ -f "$path" && ! -L "$path" ]] || die "$label must be a regular non-symlink file: $path"
  printf '%s\n' "$path"
}

absolute_output() {
  local path="$1"
  local parent
  [[ "$path" == /* ]] || die "output path must be absolute: $path"
  parent="$(dirname "$path")"
  [[ -d "$parent" && ! -L "$parent" ]] || die "output parent must be a non-symlink directory: $parent"
  printf '%s/%s\n' "$(cd "$parent" && pwd -P)" "$(basename "$path")"
}

build_archive_only() {
  local probe output
  probe="$(absolute_existing_file probe "$1")"
  output="$(absolute_output "$2")"
  (
    cd "$ROOT"
    cargo run --locked --quiet -p "$PACKAGE" --bin "$BINARY" -- \
      newc "$probe" "$output"
  )
  printf 'local VMM initramfs: archive-only OK sha256=%s size=%s path=%s\n' \
    "$(sha256sum "$output" | awk '{print $1}')" \
    "$(stat -c '%s' "$output")" \
    "$output"
  printf 'local VMM initramfs: static-musl provenance NOT VERIFIED (run --verify)\n' >&2
}

require_exact_toolchain() {
  local protoc_release release rust_host sysroot target_libdir
  for tool in cargo rustc protoc readelf sha256sum cmp stat awk sed grep; do
    command -v "$tool" >/dev/null 2>&1 || die "--verify requires $tool"
  done
  [[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] ||
    die "--verify requires an x86_64 Linux build host"

  release="$(rustc -Vv | sed -n 's/^release: //p')"
  [[ "$release" == "$REQUIRED_RUST" ]] ||
    die "--verify requires exact Rust $REQUIRED_RUST (found ${release:-unknown})"
  [[ "$(cargo --version | awk '{print $2}')" == "$REQUIRED_RUST" ]] ||
    die "--verify requires exact Cargo $REQUIRED_RUST"
  protoc_release="$(protoc --version)"
  [[ "$protoc_release" == "$REQUIRED_PROTOC" ]] ||
    die "--verify requires exact $REQUIRED_PROTOC (found ${protoc_release:-unknown})"
  target_libdir="$(rustc --target "$TARGET" --print target-libdir 2>/dev/null)" ||
    die "Rust $REQUIRED_RUST cannot resolve target $TARGET"
  [[ -d "$target_libdir" ]] ||
    die "Rust $REQUIRED_RUST target $TARGET is not installed (missing $target_libdir)"
  compgen -G "$target_libdir/libstd-*.rlib" >/dev/null ||
    die "Rust $REQUIRED_RUST target $TARGET has no static standard library"
  rust_host="$(rustc -Vv | sed -n 's/^host: //p')"
  sysroot="$(rustc --print sysroot)"
  RUST_TOOLS_DIR="$sysroot/lib/rustlib/$rust_host/bin"
  [[ -x "$RUST_TOOLS_DIR/rust-lld" ]] ||
    die "Rust $REQUIRED_RUST toolchain has no rust-lld for host ${rust_host:-unknown}"
}

validate_target() {
  case "$TARGET" in
    "$DEFAULT_TARGET"|"$ARM64_TARGET") ;;
    *) die "unsupported static guest target: $TARGET" ;;
  esac
}

required_busybox_sha256() {
  case "$TARGET" in
    "$DEFAULT_TARGET") printf '%s\n' "$X86_64_BUSYBOX_SHA256" ;;
    "$ARM64_TARGET") printf '%s\n' "$ARM64_BUSYBOX_SHA256" ;;
    *) die "unsupported static guest target: $TARGET" ;;
  esac
}

required_runc_sha256() {
  case "$TARGET" in
    "$DEFAULT_TARGET") printf '%s\n' "$X86_64_RUNC_SHA256" ;;
    "$ARM64_TARGET") printf '%s\n' "$ARM64_RUNC_SHA256" ;;
    *) die "unsupported static guest target: $TARGET" ;;
  esac
}

build_one() {
  local target_dir="$1" build_target="$2"
  local cargo_home remap_flags
  cargo_home="${CARGO_HOME:-${HOME:?HOME is required}/.cargo}"
  [[ -d "$cargo_home" ]] || die "Cargo home does not exist: $cargo_home"
  cargo_home="$(cd "$cargo_home" && pwd -P)"
  remap_flags="--remap-path-prefix=$ROOT=/codewire --remap-path-prefix=$target_dir=/codewire-target --remap-path-prefix=$cargo_home=/cargo-home -C linker=rust-lld -C target-feature=+crt-static"

  (
    cd "$ROOT"
    env \
      -u CARGO_BUILD_RUSTC \
      -u CARGO_BUILD_RUSTC_WRAPPER \
      -u CARGO_BUILD_RUSTFLAGS \
      -u CARGO_BUILD_RUSTDOC \
      -u CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER \
      -u CARGO_ENCODED_RUSTFLAGS \
      -u CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER \
      -u CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS \
      -u CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER \
      -u CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS \
      -u PROTOC \
      -u PROTOC_INCLUDE \
      -u RUSTC \
      -u RUSTC_BOOTSTRAP \
      -u RUSTC_WRAPPER \
      -u RUSTC_WORKSPACE_WRAPPER \
      -u RUSTFLAGS \
      -u RUSTDOC \
      -u RUSTDOCFLAGS \
      CARGO_INCREMENTAL=0 \
      CARGO_TARGET_DIR="$target_dir" \
      LC_ALL=C \
      PATH="$RUST_TOOLS_DIR:$PATH" \
      RUSTFLAGS="$remap_flags" \
      SOURCE_DATE_EPOCH=0 \
      TZ=UTC \
      cargo build --locked --release --target "$build_target" -p "$PACKAGE" --bin "$BINARY"
  )
}

verify_static_elf() {
  local label="$1" binary="$2" expected_target="$3"
  local machine
  case "$expected_target" in
    "$DEFAULT_TARGET") machine='Advanced Micro Devices X86-64' ;;
    "$ARM64_TARGET") machine='AArch64' ;;
    *) die "unsupported static guest target: $expected_target" ;;
  esac
  readelf -hW "$binary" | grep -Fq "$machine" ||
    die "$label is not an ELF for $expected_target"
  if readelf -lW "$binary" | grep -Fq 'INTERP'; then
    die "$label contains a dynamic program interpreter"
  fi
  if readelf -dW "$binary" 2>/dev/null | grep -Fq '(NEEDED)'; then
    die "$label contains a dynamic shared-library dependency"
  fi
}

verify_guest_runtime_abi() {
  python3 - "$1" <<'PY'
import sys
from pathlib import Path

with Path(sys.argv[1]).open('rb') as stream:
    data = stream.read(64 * 1024 * 1024 + 1)
marker = b'\0CWGUESTABI\0seed=9;cw_catalog=1\0'
if len(data) > 64 * 1024 * 1024 or data.count(marker) != 1 or data.count(b'\0CWGUESTABI\0') != 1:
    raise SystemExit('static guest must contain exactly one current seed9/catalog1 capability marker')
PY
}

verify_reproducible() {
  local requested_output="$1" root_busybox="$2" root_busybox_sha256="$3"
  local root_runc="$4" root_runc_sha256="$5"
  local target_a target_b binary_a binary_b packer_a packer_b
  local archive_a archive_b required_runc_sha runc_version
  if [[ -n "$requested_output" ]]; then
    requested_output="$(absolute_output "$requested_output")"
  fi
  validate_target
  require_exact_toolchain
  if [[ -n "$root_busybox" ]]; then
    root_busybox="$(absolute_existing_file BusyBox "$root_busybox")"
    [[ "$root_busybox_sha256" =~ ^[0-9a-f]{64}$ ]] ||
      die "--busybox-sha256 must be exactly 64 lowercase hexadecimal characters"
    [[ "$(sha256sum "$root_busybox" | awk '{print $1}')" == "$root_busybox_sha256" ]] ||
      die "BusyBox digest differs from --busybox-sha256"
    [[ "$root_busybox_sha256" == "$(required_busybox_sha256)" ]] ||
      die "BusyBox digest is not the reviewed Alpine static payload digest for $TARGET"
    verify_static_elf BusyBox "$root_busybox" "$TARGET"
    root_runc="$(absolute_existing_file runc "$root_runc")"
    [[ "$root_runc_sha256" =~ ^[0-9a-f]{64}$ ]] ||
      die "--runc-sha256 must be exactly 64 lowercase hexadecimal characters"
    required_runc_sha="$(required_runc_sha256)"
    [[ "$root_runc_sha256" == "$required_runc_sha" ]] ||
      die "runc digest is not the reviewed static v$REQUIRED_RUNC_VERSION release digest"
    [[ "$(sha256sum "$root_runc" | awk '{print $1}')" == "$root_runc_sha256" ]] ||
      die "runc digest differs from --runc-sha256"
    verify_static_elf runc "$root_runc" "$TARGET"
    if [[ "$TARGET" == "$DEFAULT_TARGET" ]]; then
      runc_version="$(env -i PATH=/usr/bin:/bin "$root_runc" --version | sed -n '1s/^runc version //p')"
      [[ "$runc_version" == "$REQUIRED_RUNC_VERSION" ]] ||
        die "runc did not report exact version $REQUIRED_RUNC_VERSION"
    fi
  fi
  VERIFY_WORK="$(mktemp -d "${TMPDIR:-/tmp}/codewire-local-vmm-initramfs.XXXXXX")"
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  target_a="$VERIFY_WORK/target-a"
  target_b="$VERIFY_WORK/target-b"
  archive_a="$VERIFY_WORK/initramfs-a.cpio"
  archive_b="$VERIFY_WORK/initramfs-b.cpio"

  build_one "$target_a" "$TARGET"
  build_one "$target_b" "$TARGET"
  binary_a="$target_a/$TARGET/release/$BINARY"
  binary_b="$target_b/$TARGET/release/$BINARY"
  [[ -x "$binary_a" && -x "$binary_b" ]] || die "static guest build did not produce both binaries"
  verify_static_elf 'guest probe' "$binary_a" "$TARGET"
  verify_static_elf 'guest probe' "$binary_b" "$TARGET"
  verify_guest_runtime_abi "$binary_a"
  verify_guest_runtime_abi "$binary_b"
  cmp -s "$binary_a" "$binary_b" || die "independent static guest builds are not byte-identical"

  packer_a="$binary_a"
  packer_b="$binary_b"
  if [[ "$TARGET" != "$DEFAULT_TARGET" ]]; then
    # A cross-built guest cannot execute on this sealed x86_64 build host. Build
    # the deterministic newc writer from the same source for the host target in
    # each independent tree, compare those packers, and use each only to package
    # the corresponding already-verified target payload.
    build_one "$target_a" "$DEFAULT_TARGET"
    build_one "$target_b" "$DEFAULT_TARGET"
    packer_a="$target_a/$DEFAULT_TARGET/release/$BINARY"
    packer_b="$target_b/$DEFAULT_TARGET/release/$BINARY"
    [[ -x "$packer_a" && -x "$packer_b" ]] || die "static archive build did not produce both host packers"
    verify_static_elf 'archive packer' "$packer_a" "$DEFAULT_TARGET"
    verify_static_elf 'archive packer' "$packer_b" "$DEFAULT_TARGET"
    cmp -s "$packer_a" "$packer_b" || die "independent static archive packers are not byte-identical"
  fi

  if [[ -n "$root_busybox" ]]; then
    pack_product_root "$packer_a" "$binary_a" "$root_busybox" "$root_runc" "$archive_a"
    pack_product_root "$packer_b" "$binary_b" "$root_busybox" "$root_runc" "$archive_b"
  else
    "$packer_a" newc "$binary_a" "$archive_a"
    "$packer_b" newc "$binary_b" "$archive_b"
  fi
  cmp -s "$archive_a" "$archive_b" || die "independent canonical newc archives are not byte-identical"

  if [[ -n "$requested_output" ]]; then
    # Re-run only the deterministic packer embedded in the already-verified
    # static binary. Its writer uses same-directory create-new, file fsync,
    # rename, and parent-directory fsync; the comparison proves the published
    # bytes are archive A rather than a third unverified build.
    if [[ -n "$root_busybox" ]]; then
      pack_product_root "$packer_a" "$binary_a" "$root_busybox" "$root_runc" "$requested_output"
    else
      "$packer_a" newc "$binary_a" "$requested_output"
    fi
    cmp -s "$archive_a" "$requested_output" ||
      die "atomically published archive differs from verified archive"
  fi

  printf 'local VMM initramfs: static-musl reproducibility OK\n'
  printf 'local VMM initramfs: probe sha256=%s size=%s\n' \
    "$(sha256sum "$binary_a" | awk '{print $1}')" \
    "$(stat -c '%s' "$binary_a")"
  if [[ -n "$root_busybox" ]]; then
    printf 'local VMM initramfs: BusyBox sha256=%s size=%s\n' \
      "$root_busybox_sha256" \
      "$(stat -c '%s' "$root_busybox")"
    printf 'local VMM initramfs: runc version=%s sha256=%s size=%s\n' \
      "$REQUIRED_RUNC_VERSION" \
      "$root_runc_sha256" \
      "$(stat -c '%s' "$root_runc")"
  fi
  printf 'local VMM initramfs: archive sha256=%s size=%s\n' \
    "$(sha256sum "$archive_a" | awk '{print $1}')" \
    "$(stat -c '%s' "$archive_a")"
  if [[ -n "$requested_output" ]]; then
    printf 'local VMM initramfs: verified archive path=%s\n' "$requested_output"
  fi
}

pack_product_root() {
  local packer="$1" probe="$2" root_busybox="$3" root_runc="$4" archive="$5"
  "$packer" newc-root "$probe" "$root_busybox" "$root_runc" "$archive"
}

VERIFY_WORK=''
RUST_TOOLS_DIR=''
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$VERIFY_WORK" && -d "$VERIFY_WORK" ]]; then
    rm -rf -- "$VERIFY_WORK"
  fi
  exit "$status"
}

mode=''
probe=''
busybox=''
busybox_sha256=''
runc=''
runc_sha256=''
output=''
TARGET="$DEFAULT_TARGET"
target_set=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify)
      [[ -z "$mode" ]] || { usage; exit 2; }
      mode='verify'
      shift
      ;;
    --verify-root)
      [[ -z "$mode" ]] || { usage; exit 2; }
      mode='verify-root'
      shift
      ;;
    --probe)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      [[ -z "$mode" || "$mode" == archive ]] || { usage; exit 2; }
      [[ -z "$probe" ]] || { usage; exit 2; }
      mode='archive'
      probe="$2"
      shift 2
      ;;
    --busybox)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      [[ -z "$busybox" ]] || { usage; exit 2; }
      busybox="$2"
      shift 2
      ;;
    --busybox-sha256)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      [[ -z "$busybox_sha256" ]] || { usage; exit 2; }
      busybox_sha256="$2"
      shift 2
      ;;
    --runc)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      [[ -z "$runc" ]] || { usage; exit 2; }
      runc="$2"
      shift 2
      ;;
    --runc-sha256)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      [[ -z "$runc_sha256" ]] || { usage; exit 2; }
      runc_sha256="$2"
      shift 2
      ;;
    --cw-image|--cw-image-index-sha256)
      die 'embedded cw boot assets are unsupported; use cw-runtime-image.py pack and the separate runtime disk'
      ;;
    --output)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      [[ -z "$output" ]] || { usage; exit 2; }
      output="$2"
      shift 2
      ;;
    --target)
      [[ $# -ge 2 && "$target_set" -eq 0 ]] || { usage; exit 2; }
      TARGET="$2"
      target_set=1
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

case "$mode" in
  verify)
    [[ -z "$probe" && -z "$busybox" && -z "$busybox_sha256" && -z "$runc" && -z "$runc_sha256" ]] || { usage; exit 2; }
    verify_reproducible "$output" '' '' '' ''
    ;;
  verify-root)
    [[ -z "$probe" && -n "$busybox" && -n "$busybox_sha256" && -n "$runc" && -n "$runc_sha256" ]] || { usage; exit 2; }
    verify_reproducible "$output" "$busybox" "$busybox_sha256" "$runc" "$runc_sha256"
    ;;
  archive)
    [[ -n "$probe" && -n "$output" && -z "$busybox" && -z "$busybox_sha256" && -z "$runc" && -z "$runc_sha256" && "$target_set" -eq 0 ]] || { usage; exit 2; }
    build_archive_only "$probe" "$output"
    ;;
  *)
    usage
    exit 2
    ;;
esac
