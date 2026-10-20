#!/bin/sh
# Install cw from releases.codewire.sh with only stock macOS or Linux tools:
# a POSIX shell, curl and a SHA-256 tool. This first download trusts HTTPS to
# releases.codewire.sh: the executable must match the SHA-256 that the
# release's SHA256SUMS lists for this platform. The verified cw then installs
# itself as a managed installation, so `cw upgrade` verifies every later release
# with its compiled release key and needs neither GnuPG nor Python.
#
# Usage: curl -fsSL https://codewire.sh/install.sh | sh -s -- [--version vX.Y.Z] [--prefix DIR] [--verbose]
#
# Everything runs from main, called on the last line, so a truncated download
# of this script does nothing.

ORIGIN='https://releases.codewire.sh/'
MAX_DOCUMENT=65536
MAX_EXECUTABLE=268435456
MIN_EXECUTABLE=64

stage=''
previous=''
work=''

reject() {
  printf 'cw install: REJECT %s\n' "$1" >&2
  exit 1
}

# Put a cw that was set aside back, unless the managed entry replaced it.
restore_previous() {
  if [ -n "$previous" ]; then
    if [ ! -e "$dir/cw" ] && [ ! -L "$dir/cw" ]; then
      mv -f "$previous" "$dir/cw" || printf 'cw install: the previous cw remains at %s\n' "$previous" >&2
    else
      rm -f "$previous"
    fi
    previous=''
  fi
}

cleanup() {
  restore_previous
  if [ -n "$stage" ]; then rm -f "$stage"; fi
  if [ -n "$work" ]; then rm -rf "$work"; fi
}

interrupted() {
  cleanup
  trap - EXIT
  printf 'cw install: interrupted\n' >&2
  exit 130
}

usage() {
  printf '%s\n' 'Usage: install.sh [--version vX.Y.Z] [--prefix DIR] [--verbose]' \
    '  --version  exact release tag; default: the stable channel' \
    '  --prefix   install to DIR/bin; default: /usr/local/bin or ~/.local/bin' \
    '  --verbose  show the installed target, SHA-256 and size'
}

valid_tag() {
  [ "${#1}" -le 64 ] || return 1
  printf '%s\n' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'
}

target_for() {
  system="$(uname -s)" || reject 'cannot identify the operating system'
  machine="$(uname -m)" || reject 'cannot identify the processor'
  case "$system" in
    Darwin)
      # A shell translated by Rosetta reports x86_64 on Apple silicon.
      if [ "$machine" = x86_64 ] &&
        [ "$(sysctl -n sysctl.proc_translated 2>/dev/null </dev/null)" = 1 ]; then
        machine=arm64
      fi
      case "$machine" in
        arm64 | aarch64) target=aarch64-apple-darwin ;;
        x86_64) target=x86_64-apple-darwin ;;
        *) reject "no cw release for macOS on $machine" ;;
      esac
      ;;
    Linux)
      case "$machine" in
        x86_64 | amd64) target=x86_64-unknown-linux-musl ;;
        aarch64 | arm64) target=aarch64-unknown-linux-gnu ;;
        *) reject "no cw release for Linux on $machine" ;;
      esac
      ;;
    *) reject "no cw release for $system" ;;
  esac
}

select_hasher() {
  if command -v sha256sum >/dev/null 2>&1; then
    hasher=sha256sum
  elif command -v shasum >/dev/null 2>&1; then
    hasher=shasum
  elif command -v openssl >/dev/null 2>&1; then
    hasher=openssl
  else
    reject 'no SHA-256 tool found (sha256sum, shasum or openssl)'
  fi
}

sha256() {
  case "$hasher" in
    sha256sum) line="$(sha256sum "$1" </dev/null)" ;;
    shasum) line="$(shasum -a 256 "$1" </dev/null)" ;;
    openssl) line="$(openssl dgst -sha256 -r "$1" </dev/null)" ;;
  esac || return 1
  digest="${line%% *}"
  printf '%s\n' "$digest" | grep -Eq '^[0-9a-f]{64}$' || return 1
  printf '%s\n' "$digest"
}

# fetch KEY FILE CAP SECONDS: exactly one 200 response, no redirect, proxy or
# content encoding, and at most CAP bytes. Nothing is piped from curl.
fetch() {
  status="$(curl -q --proto '=https' --tlsv1.2 --fail --silent --show-error \
    --proxy '' --noproxy '*' --connect-timeout 10 --max-time "$4" \
    --max-filesize "$3" --header 'Accept-Encoding: identity' \
    --output "$2" --write-out '%{http_code}' "$ORIGIN$1" </dev/null)" ||
    reject "could not download $ORIGIN$1"
  [ "$status" = 200 ] || reject "$ORIGIN$1 answered HTTP $status"
  size="$(wc -c <"$2" | tr -d ' ')" || reject "could not measure $1"
  [ "$size" -gt 0 ] && [ "$size" -le "$3" ] || reject "$1 is empty or exceeds its bound"
}

# A real directory owned by root or this user and writable by no one else.
controlled() {
  [ ! -L "$1" ] && [ -n "$(find "$1" -prune -type d \( -user "$uid" -o -user 0 \) \
    ! -perm -0020 ! -perm -0002 2>/dev/null </dev/null)" ]
}

# Every existing directory from / to DIR must be controlled; missing ones
# are created.
prepare_directory() {
  path=''
  rest="${1#/}/"
  while :; do
    controlled "${path:-/}" || reject "${path:-/} is not a directory controlled by root or the current user"
    [ -n "$rest" ] || break
    part="${rest%%/*}"
    rest="${rest#*/}"
    [ -n "$part" ] || continue
    path="$path/$part"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
      mkdir "$path" || reject "could not create $path"
    fi
  done
}

# An existing cw is either a symbolic link, which cw accepts only as its own
# managed entry, or an ordinary file of this user or root, which is replaced:
# never a directory, hard link or set-id file.
check_destination() {
  [ -e "$1" ] || [ -L "$1" ] || return 0
  [ ! -L "$1" ] || return 0
  [ -n "$(find "$1" -prune -type f -links 1 \( -user "$uid" -o -user 0 \) \
    ! -perm -4000 ! -perm -2000 ! -perm -0020 ! -perm -0002 2>/dev/null </dev/null)" ] ||
    reject "existing $1 is not an owner-controlled regular file"
}

main() {
  umask 022
  version=''
  prefix=''
  verbose=false
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --version)
        [ "$#" -ge 2 ] || reject '--version needs a release tag'
        version="$2"
        shift 2
        ;;
      --version=*) version="${1#--version=}" && shift ;;
      --prefix)
        [ "$#" -ge 2 ] || reject '--prefix needs a directory'
        prefix="$2"
        shift 2
        ;;
      --prefix=*) prefix="${1#--prefix=}" && shift ;;
      --verbose) verbose=true && shift ;;
      -h | --help) usage && exit 0 ;;
      *) reject "unknown argument $1" ;;
    esac
  done

  trap cleanup EXIT
  trap interrupted INT TERM HUP
  command -v curl >/dev/null 2>&1 || reject 'curl is required; install curl and retry'
  uid="$(id -u)" || reject 'cannot identify the current user'
  select_hasher
  target_for
  if [ -n "$version" ]; then
    valid_tag "$version" || reject 'version must be an exact release tag such as v1.2.3'
  fi

  if [ -n "$prefix" ]; then
    case "$prefix" in
      /*) ;;
      *) prefix="$(pwd -P)/$prefix" ;;
    esac
    dir="${prefix%/}/bin"
  elif [ -w /usr/local/bin ] && controlled /usr/local/bin; then
    dir=/usr/local/bin
  else
    [ -n "${HOME:-}" ] || reject 'HOME is not set; pass --prefix'
    dir="$HOME/.local/bin"
  fi
  case "$dir" in
    *'
'*) reject 'install directory contains a newline' ;;
  esac

  work="$(mktemp -d "${TMPDIR:-/tmp}/cw-install.XXXXXX")" || reject 'could not create a private temporary directory'
  if [ -z "$version" ]; then
    fetch 'cw/v1/channels/stable.json' "$work/stable.json" "$MAX_DOCUMENT" 60
    tags="$(tr ',{}' '\n\n\n' <"$work/stable.json" | sed -n 's/^"release_tag":"\([^"]*\)"$/\1/p')"
    [ "$(printf '%s\n' "$tags" | wc -l | tr -d ' ')" = 1 ] && valid_tag "$tags" ||
      reject 'the stable channel does not name one release tag'
    version="$tags"
  fi

  fetch "cw/v1/releases/$version/SHA256SUMS" "$work/SHA256SUMS" "$MAX_DOCUMENT" 60
  asset="cw-$version-$target"
  digests="$(awk -v asset="$asset" '$2 == asset && NF == 2 { print $1 }' "$work/SHA256SUMS")"
  [ "$(printf '%s\n' "$digests" | wc -l | tr -d ' ')" = 1 ] &&
    printf '%s\n' "$digests" | grep -Eq '^[0-9a-f]{64}$' ||
    reject "SHA256SUMS does not list exactly one $asset"

  prepare_directory "$dir"
  check_destination "$dir/cw"
  stage="$(mktemp "$dir/.cw-install.XXXXXX")" || reject "could not stage in $dir"
  fetch "cw/v1/blobs/sha256/$digests" "$stage" "$MAX_EXECUTABLE" 900
  [ "$size" -ge "$MIN_EXECUTABLE" ] || reject 'the executable is too small'
  actual="$(sha256 "$stage")" || reject 'could not hash the downloaded executable'
  [ "$actual" = "$digests" ] || reject "the downloaded executable does not match SHA256SUMS for $asset"
  chmod 0755 "$stage" || reject 'could not make the executable runnable'
  check_destination "$dir/cw"
  # The managed entry is only ever created where no file exists, so an
  # ordinary cw from an earlier install is set aside and restored on failure.
  if [ -f "$dir/cw" ] && [ ! -L "$dir/cw" ]; then
    previous="$(mktemp "$dir/.cw-install.XXXXXX")" || reject "could not stage in $dir"
    mv -f "$dir/cw" "$previous" || reject "could not set $dir/cw aside"
  fi
  if ! "$stage" install --managed --bin-dir "$dir" </dev/null >"$work/managed" 2>&1; then
    restore_previous
    sed -n '1,20p' "$work/managed" >&2
    reject "cw $version could not install itself as a managed installation in $dir"
  fi
  restore_previous
  rm -f "$stage"
  stage=''

  printf '==> Installed cw %s to %s\n' "$version" "$dir/cw"
  if [ "$verbose" = true ]; then
    printf '    target=%s sha256=%s size=%s\n' "$target" "$actual" "$size"
    sed -n '1,20p' "$work/managed" | sed 's/^/    /'
  fi
  case ":${PATH:-}:" in
    *":$dir:"*) ;;
    *) printf 'NOTE: add %s to your PATH\n' "$dir" ;;
  esac
}

main "$@"
