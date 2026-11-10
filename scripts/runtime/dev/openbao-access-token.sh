#!/usr/bin/env bash
# A short-lived OpenBao token for the smoke-auth wrappers
# (with-dev-smoke-auth.sh, with-prod-smoke-auth.sh), from the workstation's
# access client instead of a browser OIDC login. Source it; it defines
# functions only.
#
# CODEWIRE_ACCESS_CLIENT names the access client executable, which writes a
# token for `bao human` to descriptor 3. The token lives only in a private
# file, reaches the one fixed KV read through that process's environment,
# never argv or output, and is revoked and shredded afterwards. An inherited
# BAO_TOKEN, VAULT_TOKEN or saved bao session is never used.

# openbao_access_admit: refuse to start without a usable access client and the
# fixed revocation transport.
openbao_access_admit() {
  unset BAO_TOKEN VAULT_TOKEN
  [[ -n "${CODEWIRE_ACCESS_CLIENT:-}" && "$CODEWIRE_ACCESS_CLIENT" == /* &&
     -f "$CODEWIRE_ACCESS_CLIENT" && -x "$CODEWIRE_ACCESS_CLIENT" ]] || {
    printf '%s\n' 'openbao-access: set CODEWIRE_ACCESS_CLIENT to the absolute path of the workstation access client' >&2
    return 1
  }
  local command
  for command in curl shred timeout; do
    command -v "$command" >/dev/null 2>&1 || {
      printf 'openbao-access: missing required command: %s\n' "$command" >&2
      return 1
    }
  done
}

# openbao_access_token_file PATH: exactly one line of opaque token bytes,
# mode 0600, owned by this user, with one link.
openbao_access_token_file() {
  local path="$1" size
  [[ -f "$path" && ! -L "$path" &&
     "$(stat -c '%a:%u:%h' "$path")" == "600:$(id -u):1" ]] || return 1
  size="$(stat -c '%s' "$path")" || return 1
  (( size >= 2 && size <= 2049 )) || return 1
  (( $(wc -l <"$path") == 1 )) || return 1
  LC_ALL=C grep -aE '^[A-Za-z0-9._~-]+$' "$path" | cmp -s - "$path"
}

# openbao_access_acquire DIR: write the token to DIR/bao-token. DIR is a new
# private directory; DIR/bao-home becomes the bao CLI's HOME, so no saved
# session or token helper is read.
openbao_access_acquire() {
  local directory="$1" size
  [[ -d "$directory" && ! -L "$directory" &&
     "$(stat -c '%a:%u' "$directory")" == "700:$(id -u)" ]] || return 1
  [[ ! -e "$directory/bao-token" && ! -L "$directory/bao-token" ]] || return 1
  mkdir -m 0700 "$directory/bao-home" || return 1
  if ! (umask 077; timeout --foreground --signal=TERM --kill-after=5s 60s \
      "$CODEWIRE_ACCESS_CLIENT" bao human \
      3>"$directory/bao-token" >"$directory/access.out" 2>"$directory/access.err"); then
    # Only a closed access session needs the owner; anything else is a fault.
    if grep -Eq 'login-required|explicit login required' "$directory/access.err"; then
      printf '%s\n' 'openbao-access: the access client session is closed; run its login once' >&2
    else
      printf '%s\n' 'openbao-access: the access client did not issue a token; no login attempted' >&2
    fi
    return 1
  fi
  [[ ! -s "$directory/access.out" && ! -s "$directory/access.err" ]] || {
    printf '%s\n' 'openbao-access: the access client wrote unexpected output' >&2
    return 1
  }
  # The client writes the token without a final newline; add exactly one.
  if (( $(wc -l <"$directory/bao-token") == 0 )); then
    size="$(stat -c '%s' "$directory/bao-token")" || return 1
    (( size >= 1 && size <= 2048 )) || return 1
    printf '\n' >>"$directory/bao-token" || return 1
  fi
  openbao_access_token_file "$directory/bao-token" || {
    printf '%s\n' 'openbao-access: the access client issued a malformed token' >&2
    return 1
  }
}

# openbao_access_kv_get DIR ADDR PATH OUTPUT ERROR: the one fixed KV read, as
# JSON, with the acquired token and no ambient proxy, session or helper.
openbao_access_kv_get() {
  local directory="$1" address="$2" path="$3" output="$4" error="$5"
  HTTP_PROXY='' HTTPS_PROXY='' ALL_PROXY='' http_proxy='' https_proxy='' all_proxy='' \
    HOME="$directory/bao-home" BAO_ADDR="$address" \
    BAO_TOKEN="$(<"$directory/bao-token")" \
    bao kv get -format=json "$path" >"$output" 2>"$error"
}

# openbao_access_revoke DIR ADDR: revoke the token and shred it. Succeeds only
# on an HTTP 2xx from revoke-self; the token is always shredded either way.
openbao_access_revoke() {
  local directory="$1" address="$2" code=0
  openbao_access_token_file "$directory/bao-token" || return 1
  (umask 077; sed 's/^/X-Vault-Token: /' "$directory/bao-token" >"$directory/revoke.header") ||
    return 1
  # The token is only in the private header file, never argv or environment.
  HTTP_PROXY='' HTTPS_PROXY='' ALL_PROXY='' http_proxy='' https_proxy='' all_proxy='' \
    HOME="$directory/bao-home" curl --disable --silent --show-error --proto '=https' \
      --noproxy '*' --retry 0 --max-redirs 0 --connect-timeout 10 --max-time 30 \
      --request POST --header "@$directory/revoke.header" \
      --output /dev/null --write-out '%{http_code}' \
      --url "$address/v1/auth/token/revoke-self" \
      >"$directory/revoke.status" 2>"$directory/revoke.err" || code=$?
  shred -u "$directory/bao-token" "$directory/revoke.header" || return 1
  if [[ "$code" != 0 ]] || ! LC_ALL=C grep -Eqx '2[0-9]{2}' "$directory/revoke.status"; then
    printf '%s\n' 'openbao-access: OpenBao did not confirm the token was revoked' >&2
    return 1
  fi
}

# openbao_access_cleanup DIR ADDR: on an early exit, revoke a token still held.
openbao_access_cleanup() {
  local directory="$1" address="$2"
  [[ -s "$directory/bao-token" ]] || return 0
  openbao_access_revoke "$directory" "$address"
}
