#!/usr/bin/env bash

# Retry only failures where curl did not obtain a usable HTTP response. HTTP
# failures (including authentication and authorization) retain their original
# immediate failure behavior.
readonly CURL_TRANSPORT_RETRY_ATTEMPTS=5
readonly CURL_TRANSPORT_RETRY_DELAY_SECONDS=2

curl_with_transport_retry() {
  local attempt status

  for ((attempt = 1; attempt <= CURL_TRANSPORT_RETRY_ATTEMPTS; attempt++)); do
    if curl "$@"; then
      return 0
    else
      status=$?
    fi

    case "$status" in
      5|6|7|28|35|52|55|56) ;;
      *) return "$status" ;;
    esac
    if [[ "$attempt" -ge "$CURL_TRANSPORT_RETRY_ATTEMPTS" ]]; then
      return "$status"
    fi

    printf 'Credential transport failed with curl exit %d; retrying (%d/%d)\n' \
      "$status" "$((attempt + 1))" "$CURL_TRANSPORT_RETRY_ATTEMPTS" >&2
    sleep "$CURL_TRANSPORT_RETRY_DELAY_SECONDS"
  done
}
