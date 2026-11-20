#!/usr/bin/env bash
# A refresh with the broker's opened Secret Service store lands, staged by the
# authority, while the child's own store refuses every write (#5539). It runs
# the ignored test
# `a_secret_service_childs_refresh_is_staged_by_the_authority` against a
# private gnome-keyring on its own session bus, with its own HOME and runtime
# directory, so the host's keyring and session bus are never reached.
set -euo pipefail

repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
root="$(mktemp -d "${TMPDIR:-/tmp}/cw-child-store.XXXXXX")"
trap 'rm -rf -- "$root"' EXIT
mkdir -m 0700 "$root/home" "$root/runtime" "$root/control"

# The test binary is built first, on the caller's own environment, so the
# private session below only runs it.
test_binary="$(
  cd "$repository" &&
    cargo test -p codewire-cli --lib --no-run --message-format=json 2>/dev/null |
    jq -r 'select(.reason == "compiler-artifact" and .target.name == "codewire_cli"
             and .profile.test == true) | .executable' | tail -n 1
)"
[[ -x "$test_binary" ]] || { echo "test-child-store-secret-service: no test binary" >&2; exit 1; }

env -i PATH=/usr/bin:/bin HOME="$root/home" XDG_RUNTIME_DIR="$root/runtime" \
  ROOT="$root" TEST_BINARY="$test_binary" \
  /usr/bin/dbus-run-session -- /bin/bash -c '
    set -euo pipefail
    printf "%s" codewire-child-store-keyring |
      /usr/bin/gnome-keyring-daemon --foreground --unlock --components=secrets \
        --control-directory="$ROOT/control" >"$ROOT/keyring.log" 2>&1 &
    keyring=$!
    trap "kill $keyring 2>/dev/null || true; wait $keyring 2>/dev/null || true" EXIT
    for _ in $(seq 1 100); do
      if /usr/bin/dbus-send --session --print-reply --dest=org.freedesktop.DBus \
          /org/freedesktop/DBus org.freedesktop.DBus.NameHasOwner \
          string:org.freedesktop.secrets 2>/dev/null | grep -q "boolean true"; then
        break
      fi
      sleep 0.1
    done
    CODEWIRE_PRIVATE_SECRET_SERVICE_BUS="$DBUS_SESSION_BUS_ADDRESS" "$TEST_BINARY" \
      --ignored --exact \
      commands::credential_child_store::tests::a_secret_service_childs_refresh_is_staged_by_the_authority
  '
