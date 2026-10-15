#!/usr/bin/env bash
# Download one checksum-pinned build input from an external host (github.com
# release assets, ziglang.org, the Alpine CDN, static.rust-lang.org) with
# bounded attempts (#2691). A connection or TLS handshake that stalls fails
# within the connect bound, and a transfer that stalls fails within the speed
# bound, instead of holding the job until its deadline. Each failed attempt is
# logged and retried after a growing delay, long enough that a later attempt
# resolves the host again. HTTP errors other than 408, 429 and 5xx fail at
# once. The file must match its pinned SHA-256, or the download fails without
# a retry and leaves nothing at OUTPUT.
#
# Runs on Linux and on the macOS runner's stock bash 3.2.
#
# Usage: fetch-pinned.sh URL SHA256 OUTPUT
set -euo pipefail

usage() {
  echo 'usage: fetch-pinned.sh URL SHA256 OUTPUT' >&2
  exit 2
}
[ "$#" -eq 3 ] || usage
url="$1" digest="$2" output="$3"
[[ "$url" =~ ^https://[^[:space:]]+$ ]] || {
  echo "fetch-pinned: only an https URL is fetched: $url" >&2
  exit 2
}
[[ "$digest" =~ ^[0-9a-f]{64}$ ]] || {
  echo 'fetch-pinned: SHA256 must be 64 lowercase hexadecimal digits' >&2
  exit 2
}
[ -n "$output" ] || usage

attempts="${FETCH_PINNED_ATTEMPTS:-5}"
delay="${FETCH_PINNED_RETRY_DELAY_SECONDS:-10}"
[[ "$attempts" =~ ^[1-9][0-9]?$ ]] || {
  echo 'fetch-pinned: FETCH_PINNED_ATTEMPTS must be 1-99' >&2
  exit 2
}
[[ "$delay" =~ ^[0-9]{1,3}$ ]] || {
  echo 'fetch-pinned: FETCH_PINNED_RETRY_DELAY_SECONDS must be 0-999' >&2
  exit 2
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -c1-64
  else
    shasum -a 256 "$1" | cut -c1-64
  fi
}

partial="$output.partial"
rm -f -- "$partial"
trap 'rm -f -- "$partial"' EXIT
attempt=1
while :; do
  status=0
  # The connect bound covers name resolution, the TCP connect and the TLS
  # handshake; the speed bound fails a transfer slower than 1 KiB/s for 30 s.
  http_code="$(curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 20 --speed-limit 1024 --speed-time 30 --max-time 900 \
    --write-out '%{http_code}' --output "$partial" "$url")" || status=$?
  [ "$status" -ne 0 ] || break
  case "$status" in
    # Name resolution, connect, partial file, timeout, TLS connect, empty
    # reply, send and receive failures, HTTP/2 stream errors.
    5|6|7|16|18|28|35|52|55|56|92) reason="curl exit $status" ;;
    22)
      case "$http_code" in
        408|429|5[0-9][0-9]) reason="HTTP $http_code" ;;
        *)
          echo "fetch-pinned: $url answered HTTP $http_code" >&2
          exit "$status"
          ;;
      esac
      ;;
    *)
      echo "fetch-pinned: $url failed with curl exit $status" >&2
      exit "$status"
      ;;
  esac
  if [ "$attempt" -ge "$attempts" ]; then
    printf '[external-download] class=transient-exhausted url=%s reason="%s" attempts=%d\n' \
      "$url" "$reason" "$attempts" >&2
    exit "$status"
  fi
  wait_seconds=$((delay * attempt))
  attempt=$((attempt + 1))
  printf '[external-download] transient failure url=%s reason="%s"; retrying in %ds (attempt %d/%d)\n' \
    "$url" "$reason" "$wait_seconds" "$attempt" "$attempts" >&2
  sleep "$wait_seconds"
done

actual="$(sha256_of "$partial")"
if [ "$actual" != "$digest" ]; then
  printf 'fetch-pinned: %s does not match its pinned SHA-256 (expected %s, got %s)\n' \
    "$url" "$digest" "$actual" >&2
  exit 1
fi
mv -f -- "$partial" "$output"
trap - EXIT
printf '[external-download] fetched url=%s sha256=%s attempt=%d\n' "$url" "$digest" "$attempt" >&2
