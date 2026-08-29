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
readonly REQUIRED_RUST='1.91.1'
readonly REQUIRED_PROTOC='libprotoc 35.1'
readonly TARGET='x86_64-unknown-linux-musl'

usage() {
  printf '%s\n' \
    'usage:' \
    '  build-local-vmm-initramfs.sh --probe ABSOLUTE_PATH --output ABSOLUTE_PATH' \
    '  build-local-vmm-initramfs.sh --verify [--output ABSOLUTE_PATH]' \
    '  build-local-vmm-initramfs.sh --verify-root --busybox ABSOLUTE_PATH' \
    '    --busybox-sha256 SHA256 [--output ABSOLUTE_PATH]' \
    '' \
    '--probe/--output creates a deterministic archive from caller-supplied bytes.' \
    'It does not prove the probe is static or came from the sealed Rust toolchain.' \
    '--verify requires exact Rust 1.91.1, libprotoc 35.1, the installed x86_64' \
    'musl standard library, and readelf. It builds twice and fails closed on' \
    'any drift. With --output, the verified archive is published atomically' \
    'after comparison. --verify-root applies the same proof and adds a static' \
    'x86_64 BusyBox whose exact lowercase SHA-256 must be supplied.' \
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

build_one() {
  local target_dir="$1"
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
      cargo build --locked --release --target "$TARGET" -p "$PACKAGE" --bin "$BINARY"
  )
}

verify_static_elf() {
  local label="$1" binary="$2"
  readelf -hW "$binary" | grep -Fq 'Advanced Micro Devices X86-64' ||
    die "$label is not an x86_64 ELF"
  if readelf -lW "$binary" | grep -Fq 'INTERP'; then
    die "$label contains a dynamic program interpreter"
  fi
  if readelf -dW "$binary" 2>/dev/null | grep -Fq '(NEEDED)'; then
    die "$label contains a dynamic shared-library dependency"
  fi
}

verify_reproducible() {
  local requested_output="$1" root_busybox="$2" root_busybox_sha256="$3"
  local target_a target_b binary_a binary_b archive_a archive_b
  if [[ -n "$requested_output" ]]; then
    requested_output="$(absolute_output "$requested_output")"
  fi
  require_exact_toolchain
  if [[ -n "$root_busybox" ]]; then
    root_busybox="$(absolute_existing_file BusyBox "$root_busybox")"
    [[ "$root_busybox_sha256" =~ ^[0-9a-f]{64}$ ]] ||
      die "--busybox-sha256 must be exactly 64 lowercase hexadecimal characters"
    [[ "$(sha256sum "$root_busybox" | awk '{print $1}')" == "$root_busybox_sha256" ]] ||
      die "BusyBox digest differs from --busybox-sha256"
    verify_static_elf BusyBox "$root_busybox"
  fi
  VERIFY_WORK="$(mktemp -d "${TMPDIR:-/tmp}/codewire-local-vmm-initramfs.XXXXXX")"
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  target_a="$VERIFY_WORK/target-a"
  target_b="$VERIFY_WORK/target-b"
  archive_a="$VERIFY_WORK/initramfs-a.cpio"
  archive_b="$VERIFY_WORK/initramfs-b.cpio"

  build_one "$target_a"
  build_one "$target_b"
  binary_a="$target_a/$TARGET/release/$BINARY"
  binary_b="$target_b/$TARGET/release/$BINARY"
  [[ -x "$binary_a" && -x "$binary_b" ]] || die "static guest build did not produce both binaries"
  verify_static_elf 'guest probe' "$binary_a"
  verify_static_elf 'guest probe' "$binary_b"
  cmp -s "$binary_a" "$binary_b" || die "independent static guest builds are not byte-identical"

  if [[ -n "$root_busybox" ]]; then
    "$binary_a" newc-root "$binary_a" "$root_busybox" "$archive_a"
    "$binary_b" newc-root "$binary_b" "$root_busybox" "$archive_b"
  else
    "$binary_a" newc "$binary_a" "$archive_a"
    "$binary_b" newc "$binary_b" "$archive_b"
  fi
  cmp -s "$archive_a" "$archive_b" || die "independent canonical newc archives are not byte-identical"

  if [[ -n "$requested_output" ]]; then
    # Re-run only the deterministic packer embedded in the already-verified
    # static binary. Its writer uses same-directory create-new, file fsync,
    # rename, and parent-directory fsync; the comparison proves the published
    # bytes are archive A rather than a third unverified build.
    if [[ -n "$root_busybox" ]]; then
      "$binary_a" newc-root "$binary_a" "$root_busybox" "$requested_output"
    else
      "$binary_a" newc "$binary_a" "$requested_output"
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
  fi
  printf 'local VMM initramfs: archive sha256=%s size=%s\n' \
    "$(sha256sum "$archive_a" | awk '{print $1}')" \
    "$(stat -c '%s' "$archive_a")"
  if [[ -n "$requested_output" ]]; then
    printf 'local VMM initramfs: verified archive path=%s\n' "$requested_output"
  fi
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
output=''
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
    --output)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      [[ -z "$output" ]] || { usage; exit 2; }
      output="$2"
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
    [[ -z "$probe" && -z "$busybox" && -z "$busybox_sha256" ]] || { usage; exit 2; }
    verify_reproducible "$output" '' ''
    ;;
  verify-root)
    [[ -z "$probe" && -n "$busybox" && -n "$busybox_sha256" ]] || { usage; exit 2; }
    verify_reproducible "$output" "$busybox" "$busybox_sha256"
    ;;
  archive)
    [[ -n "$probe" && -n "$output" && -z "$busybox" && -z "$busybox_sha256" ]] || { usage; exit 2; }
    build_archive_only "$probe" "$output"
    ;;
  *)
    usage
    exit 2
    ;;
esac
