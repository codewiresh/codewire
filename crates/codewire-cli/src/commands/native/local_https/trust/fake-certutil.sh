#!/bin/sh
# A stand-in for NSS's certutil in tests (#4316): the subset `trust.rs` uses,
# with each database a directory of `<nickname>.pem` and `<nickname>.flags`
# files. A `fail-add` file in a database makes its next `-A` fail.
set -eu
mode='' database='' nickname='' flags='' input='' armor=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    -H) exit 0 ;;
    -N | -A | -D | -L) mode="$1" ;;
    -d) database="${2#sql:}"; shift ;;
    -n) nickname="$2"; shift ;;
    -t) flags="$2"; shift ;;
    -i) input="$2"; shift ;;
    -a) armor=true ;;
    --empty-password) ;;
    *) echo "fake certutil: unexpected argument $1" >&2; exit 2 ;;
  esac
  shift
done
case "$mode" in
  -N) mkdir -p "$database" && : >"$database/cert9.db" ;;
  -A)
    if [ -e "$database/fail-add" ]; then
      rm "$database/fail-add"
      echo "fake certutil: SEC_ERROR_READ_ONLY" >&2
      exit 1
    fi
    cp "$input" "$database/$nickname.pem"
    printf '%s\n' "$flags" >"$database/$nickname.flags"
    ;;
  -D) rm "$database/$nickname.pem" "$database/$nickname.flags" ;;
  -L)
    if [ -n "$nickname" ]; then
      "$armor" && cat "$database/$nickname.pem"
    else
      printf '\nCertificate Nickname                                         Trust Attributes\n'
      printf '                                                             SSL,S/MIME,JAR/XPI\n\n'
      for pem in "$database"/*.pem; do
        [ -e "$pem" ] || continue
        name="$(basename "$pem" .pem)"
        printf '%-60s %s\n' "$name" "$(cat "$database/$name.flags")"
      done
    fi
    ;;
  *) echo "fake certutil: no mode" >&2; exit 2 ;;
esac
