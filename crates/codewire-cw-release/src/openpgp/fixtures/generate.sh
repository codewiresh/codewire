#!/bin/sh
# Regenerates the release-signature verifier's fixtures with GnuPG, signing as
# scripts/ci/release/sign-cw-release.sh does (--armor --detach-sign). Keys are
# created on 2000-01-01 and `past` signatures an hour later, so a one-day
# expiry has passed permanently. Run it only to change the fixture set; it
# needs gpg, never cw or the tests. The short-MPI search can take minutes.
set -eu

out="$(cd "$(dirname "$0")" && pwd -P)"
work="$(mktemp -d "${TMPDIR:-/tmp}/cw-openpgp-fixtures.XXXXXX")"
cleanup() {
  for home in "$work"/*/; do
    [ -d "$home" ] || continue
    gpgconf --homedir "$home" --kill all >/dev/null 2>&1 || true
    gpgconf --homedir "$home" --remove-socketdir >/dev/null 2>&1 || true
  done
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

past=946684800     # 2000-01-01T00:00:00Z
later=$((past + 3600))
future=4102444800  # 2100-01-01T00:00:00Z
printf 'release\n' >"$work/release.data"

g() {
  home="$1"
  shift
  gpg --homedir "$work/$home" --batch --yes --no-options \
    --pinentry-mode loopback --passphrase '' "$@" 2>/dev/null
}

key() {
  name="$1" expiry="$2"
  mkdir -m 0700 "$work/$name"
  g "$name" --faked-system-time "$past" --quick-generate-key \
    "CW Fixture $name <$name@example.invalid>" rsa3072 sign "$expiry"
}

fingerprint() {
  g "$1" --with-colons --list-keys | awk -F: '$1 == "fpr" { print $10 }' | sed -n "${2:-1}p"
}

export_key() {
  g "$1" --armor --export "$(fingerprint "$1")" >"$out/$1.key.asc"
}

sign() {
  home="$1" name="$2"
  shift 2
  g "$home" "$@" --armor --output "$out/$name.sig.asc" --detach-sign "$work/release.data"
}

key good 0
export_key good
fingerprint good >"$out/good.fingerprint"
sign good good-sha512 --digest-algo SHA512
sign good good-sha384 --digest-algo SHA384
sign good good-sha256 --digest-algo SHA256
sign good past --faked-system-time "$later"
sign good future --faked-system-time "$future"
sign good expired-signature --faked-system-time "$later" --default-sig-expire 1d
sign good sha1 --digest-algo SHA1
sign good text-mode --textmode
g good --armor --output "$out/clearsigned.sig.asc" --clearsign "$work/release.data"
g good --output "$out/binary.sig" --detach-sign "$work/release.data"

# An RSA signature whose integer has a zero leading byte is a shorter MPI
# than the modulus. Search the fixed message family for one.
n=0
while :; do
  n=$((n + 1))
  [ "$n" -le 4096 ] || { echo 'no short MPI signature found' >&2; exit 1; }
  printf 'release %s\n' "$n" >"$work/short.data"
  g good --digest-algo SHA512 --armor --output "$work/short.sig.asc" --detach-sign "$work/short.data"
  sed -e '1,/^$/d' -e '/^=/,$d' -e '/^-----END/,$d' "$work/short.sig.asc" | base64 -d >"$work/short.sig"
  # Packet: tag, 2-byte or 1-byte length, v4 header, then the MPI bit count.
  bits="$(od -An -tu1 -N1024 "$work/short.sig" | awk '{ for (f = 1; f <= NF; f++) b[++n] = $f }
    END {
      i = (b[1] == 137) ? 4 : (b[1] == 136) ? 3 : 0
      if (i == 0) exit 1
      u = i + 6 + b[i + 4] * 256 + b[i + 5]
      m = u + 2 + b[u] * 256 + b[u + 1] + 2
      print b[m] * 256 + b[m + 1]
    }')"
  if [ "$bits" -le 3064 ]; then
    cp "$work/short.data" "$out/short-mpi.data"
    cp "$work/short.sig.asc" "$out/short-mpi.sig.asc"
    break
  fi
done

# Each of these keys must fail import: the compiled key may not be limited.
for name in wrong expired revoked subkey; do
  case "$name" in
    expired) key "$name" 1d ;;
    *) key "$name" 0 ;;
  esac
done
revocation="$work/revoked/openpgp-revocs.d/$(fingerprint revoked).rev"
sed -n 's/^:-----BEGIN/-----BEGIN/; /^-----BEGIN/,$p' "$revocation" >"$work/revocation.asc"
g revoked --import "$work/revocation.asc"
g subkey --quick-add-key "$(fingerprint subkey)" rsa3072 sign 0
for name in wrong expired revoked subkey; do
  export_key "$name"
  fingerprint "$name" >"$out/$name.fingerprint"
done
