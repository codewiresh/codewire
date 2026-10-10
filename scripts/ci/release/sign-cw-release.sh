#!/usr/bin/env bash
# Sign one prepared cw release delivery with the release OpenPGP key: the raw
# SHA256SUMS, the canonical release manifest and the stable channel pointer.
# A retained (already published) release keeps its exact signed bytes; only
# its channel pointer is signed. This step never compiles anything.
set -euo pipefail
set +x
umask 077

usage() {
  cat <<'EOF'
usage: sign-cw-release.sh <dist-dir>

Environment:
  CW_RELEASE_GPG_PRIVATE_KEY  ASCII-armored private key (required)
  CW_RELEASE_GPG_KEY_ID       exact 40-character primary fingerprint (required)
  CW_RELEASE_GPG_PASSPHRASE   optional passphrase, passed on file descriptor 0
EOF
}

die() {
  printf 'sign-cw-release: %s\n' "$*" >&2
  exit 1
}

[ "$#" -eq 1 ] || { usage >&2; exit 2; }
dist="$1"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
release_py="$script_dir/cw_release.py"

for name in CW_RELEASE_GPG_PRIVATE_KEY CW_RELEASE_GPG_KEY_ID; do
  [ -n "${!name:-}" ] || die "$name is required"
done
fingerprint="$(printf '%s' "$CW_RELEASE_GPG_KEY_ID" | tr '[:lower:]' '[:upper:]')"
admitted="$(python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import cw_release; print(cw_release.PRODUCTION_FINGERPRINT)' "$script_dir")"
[ "$fingerprint" = "$admitted" ] || die 'signing key is not the admitted release key'

sums="$dist/SHA256SUMS"
sums_sig="$dist/SHA256SUMS.asc"
manifest="$dist/delivery/release.json"
manifest_sig="$dist/delivery/release.json.asc"
pointer="$dist/delivery/channels/stable.pointer.json"
channel="$dist/delivery/channels/stable.json"
[ -f "$sums" ] || die 'SHA256SUMS is missing'
[ ! -e "$pointer" ] && [ ! -e "$channel" ] || die 'a channel pointer is already signed'

work="$(mktemp -d)"
cleanup() {
  local result=$?
  trap - EXIT
  if ! { find "$work" -type f -exec shred -u {} + && rm -rf "$work"; }; then
    printf 'sign-cw-release: private cleanup failed\n' >&2
    result=1
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
mkdir -m 0700 "$work/gnupg"
export GNUPGHOME="$work/gnupg"

printf '%s\n' "$CW_RELEASE_GPG_PRIVATE_KEY" | gpg --batch --import >/dev/null 2>&1 ||
  die 'CW_RELEASE_GPG_PRIVATE_KEY is not a valid OpenPGP private key'

# The trailing ! selects the pinned primary key itself, never a subkey: cw's
# built-in verifier admits only primary-key signatures.
sign() {
  local input="$1" output="$2"
  local -a args=(--batch --yes --pinentry-mode loopback --armor --detach-sign
    --local-user "$fingerprint!" --output "$output")
  if [ -n "${CW_RELEASE_GPG_PASSPHRASE:-}" ]; then
    printf '%s' "$CW_RELEASE_GPG_PASSPHRASE" | gpg "${args[@]}" --passphrase-fd 0 "$input" >/dev/null 2>&1
  else
    gpg "${args[@]}" "$input" </dev/null >/dev/null 2>&1
  fi || die "signing $(basename "$input") failed"
}

if [ -e "$sums_sig" ] || [ -e "$manifest" ] || [ -e "$manifest_sig" ]; then
  # A retained release is already signed and published: never re-sign it.
  [ -f "$sums_sig" ] && [ -f "$manifest" ] && [ -f "$manifest_sig" ] ||
    die 'delivery is partially signed; refusing to re-sign it'
  mode=retained
else
  sign "$sums" "$sums_sig"
  python3 "$release_py" manifest --dist "$dist" >/dev/null
  sign "$manifest" "$manifest_sig"
  mode=fresh
fi
python3 "$release_py" pointer --dist "$dist"
sign "$pointer" "$work/pointer.asc"
python3 "$release_py" channel --dist "$dist" --signature "$work/pointer.asc"
python3 "$release_py" verify --dist "$dist"
printf 'sign-cw-release: signed mode=%s fingerprint=%s\n' "$mode" "$fingerprint"
