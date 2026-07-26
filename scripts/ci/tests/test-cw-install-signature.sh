#!/usr/bin/env bash
# shellcheck disable=SC2016 # The injected curl function expands in the fixture process.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
INSTALLER="$ROOT/apps/cli/install.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

make_key() {
  local home="$1"
  local identity="$2"
  mkdir -m 700 "$home"
  gpg --batch --no-options --homedir "$home" --passphrase '' \
    --quick-generate-key "$identity" ed25519 sign 0 >/dev/null 2>&1
  gpg --batch --no-options --homedir "$home" --with-colons \
    --list-secret-keys "$identity" 2>/dev/null |
    awk -F: '$1 == "fpr" { print $10; exit }'
}

key_a_home="$TMP/key-a-home"
key_b_home="$TMP/key-b-home"
key_a="$(make_key "$key_a_home" 'Installer Fixture A <a@example.invalid>')"
key_b="$(make_key "$key_b_home" 'Installer Fixture B <b@example.invalid>')"

assets="$TMP/assets"
mkdir "$assets"
binary_name='cw-v0.0.0-test-x86_64-unknown-linux-musl'
printf '#!/usr/bin/env sh\necho fixture cw\n' >"$assets/$binary_name"
chmod +x "$assets/$binary_name"
(
  cd "$assets"
  sha256sum "$binary_name" >SHA256SUMS
)
gpg --batch --no-options --homedir "$key_a_home" --armor --export "$key_a" \
  >"$assets/key-a.asc"
gpg --batch --no-options --homedir "$key_b_home" --armor --export "$key_b" \
  >"$assets/key-b.asc"

fixture_installer="$TMP/install.sh"
{
  head -n 1 "$INSTALLER"
  printf '%s\n' 'curl() { bash "$FIXTURE_CURL" "$@"; }'
  tail -n +2 "$INSTALLER" |
    sed "s/^GPG_KEY_ID=.*/GPG_KEY_ID=\"$key_a\"/"
} >"$fixture_installer"

fake_bin="$TMP/bin"
mkdir "$fake_bin"
cat >"$fake_bin/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
output=''
url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o)
      output="$2"
      shift 2
      ;;
    -*)
      shift
      ;;
    *)
      url="$1"
      shift
      ;;
  esac
done
[ -n "$output" ] && [ -n "$url" ]
case "$url" in
  */GPG_PUBLIC_KEY.asc) source="$FIXTURE_PUBLIC_KEY" ;;
  */SHA256SUMS.asc) source="$FIXTURE_ASSETS/SHA256SUMS.asc" ;;
  */SHA256SUMS) source="$FIXTURE_ASSETS/SHA256SUMS" ;;
  */cw-*) source="$FIXTURE_ASSETS/${url##*/}" ;;
  *) exit 22 ;;
esac
cp "$source" "$output"
SH

sign_checksums() {
  local home="$1"
  local key="$2"
  gpg --batch --no-options --homedir "$home" --armor --detach-sign \
    --local-user "$key" --output "$assets/SHA256SUMS.asc" "$assets/SHA256SUMS"
}

run_installer() {
  local public_key="$1"
  local prefix="$2"
  FIXTURE_CURL="$fake_bin/curl" \
    FIXTURE_PUBLIC_KEY="$public_key" \
    FIXTURE_ASSETS="$assets" \
    bash "$fixture_installer" --version v0.0.0-test --prefix "$prefix"
}

# The pinned key alone and its matching signature succeed.
sign_checksums "$key_a_home" "$key_a"
run_installer "$assets/key-a.asc" "$TMP/success-prefix" >/dev/null
[ -f "$TMP/success-prefix/bin/cw" ]

# A keyring with the pinned key first and a second signing key must fail.
cat "$assets/key-a.asc" "$assets/key-b.asc" >"$assets/two-keys.asc"
rm -f "$assets/SHA256SUMS.asc"
sign_checksums "$key_b_home" "$key_b"
if run_installer "$assets/two-keys.asc" "$TMP/two-key-prefix" >/dev/null 2>&1; then
  echo 'installer accepted a signature from a second downloaded primary key' >&2
  exit 1
fi

# A pre-existing ambient key must not participate in release verification.
ambient_home="$TMP/ambient-home"
mkdir -m 700 "$ambient_home"
GNUPGHOME="$ambient_home" gpg --batch --no-options --import \
  "$assets/key-b.asc" >/dev/null 2>&1
if GNUPGHOME="$ambient_home" \
  run_installer "$assets/key-a.asc" "$TMP/ambient-prefix" >/dev/null 2>&1; then
  echo 'installer accepted a signature from the ambient GnuPG keyring' >&2
  exit 1
fi

echo 'cw installer signature tests passed'
