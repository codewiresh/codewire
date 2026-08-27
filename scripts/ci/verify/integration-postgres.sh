#!/usr/bin/env bash

# Hermetic PostgreSQL selection for the bounded product integration harness.
# This file is sourced by run-integration-verification.sh and its focused test.
# shellcheck disable=SC2034 # State is consumed by the sourcing script.

integration_postgres_init() {
  INTEGRATION_POSTGRES_CONTAINER="codewire-product-postgres-${GITHUB_RUN_ID:-local-$$}"
  INTEGRATION_POSTGRES_MANAGED=false
  INTEGRATION_POSTGRES_SOURCE=""
}

integration_postgres_configure() {
  if [ "${DATABASE_URL_EXPLICIT:-false}" = true ] \
      || [ "${DATABASE_URL_RUST_EXPLICIT:-false}" = true ]; then
    if [ "${DATABASE_URL_EXPLICIT:-false}" = true ] && [ -z "${DATABASE_URL:-}" ]; then
      echo "::error::DATABASE_URL was explicitly set but empty" >&2
      return 1
    fi
    if [ "${DATABASE_URL_RUST_EXPLICIT:-false}" = true ] \
        && [ -z "${DATABASE_URL_RUST:-}" ]; then
      echo "::error::DATABASE_URL_RUST was explicitly set but empty" >&2
      return 1
    fi
    if [ -z "${DATABASE_URL:-}" ]; then
      DATABASE_URL="$DATABASE_URL_RUST"
    fi
    if [ -z "${DATABASE_URL_RUST:-}" ]; then
      DATABASE_URL_RUST="$DATABASE_URL"
    fi
    INTEGRATION_POSTGRES_SOURCE=explicit
    return
  fi

  if [ "${GITHUB_ACTIONS:-false}" = true ]; then
    DATABASE_URL="postgres://codewire:codewire@127.0.0.1:5432/codewire?sslmode=disable"
    DATABASE_URL_RUST="postgres://codewire:codewire@127.0.0.1:5432/codewire"
    INTEGRATION_POSTGRES_SOURCE=ci
    return
  fi

  if ! command -v docker >/dev/null 2>&1; then
    echo "::error::local integration verification requires Docker or explicit DATABASE_URL and DATABASE_URL_RUST" >&2
    return 1
  fi
  if ! command -v psql >/dev/null 2>&1; then
    echo "::error::local integration verification requires psql" >&2
    return 1
  fi

  local image="${INTEGRATION_POSTGRES_IMAGE:-postgres:17-alpine}"
  local requested_port="${INTEGRATION_POSTGRES_HOST_PORT:-}"
  local publish="127.0.0.1::5432"
  local port=""
  if [ -n "$requested_port" ]; then
    if ! [[ "$requested_port" =~ ^[0-9]+$ ]] \
        || [ "$requested_port" -lt 1024 ] \
        || [ "$requested_port" -gt 65535 ]; then
      echo "::error::INTEGRATION_POSTGRES_HOST_PORT must be an unprivileged TCP port" >&2
      return 1
    fi
    publish="127.0.0.1:${requested_port}:5432"
  fi
  docker run -d --rm --name "$INTEGRATION_POSTGRES_CONTAINER" \
    -e POSTGRES_USER=codewire \
    -e POSTGRES_PASSWORD=codewire \
    -e POSTGRES_DB=codewire \
    -p "$publish" "$image" >/dev/null
  INTEGRATION_POSTGRES_MANAGED=true

  port="$(docker port "$INTEGRATION_POSTGRES_CONTAINER" 5432/tcp | sed 's/.*://')"
  if ! [[ "$port" =~ ^[0-9]+$ ]]; then
    echo "::error::unable to resolve disposable PostgreSQL loopback port" >&2
    return 1
  fi
  if [ -n "$requested_port" ] && [ "$port" != "$requested_port" ]; then
    echo "::error::disposable PostgreSQL did not bind the requested loopback port" >&2
    return 1
  fi

  DATABASE_URL="postgres://codewire:codewire@127.0.0.1:${port}/codewire?sslmode=disable"
  DATABASE_URL_RUST="postgres://codewire:codewire@127.0.0.1:${port}/codewire"

  local _
  for _ in $(seq 1 "${INTEGRATION_POSTGRES_READY_ATTEMPTS:-30}"); do
    if docker exec "$INTEGRATION_POSTGRES_CONTAINER" \
        pg_isready -U codewire -d codewire >/dev/null 2>&1 \
        && psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -tAc 'SELECT 1' \
          >/dev/null 2>&1; then
      INTEGRATION_POSTGRES_SOURCE=managed
      return
    fi
    sleep 1
  done

  echo "::error::disposable PostgreSQL did not become ready" >&2
  return 1
}

integration_postgres_cleanup() {
  if [ "${INTEGRATION_POSTGRES_MANAGED:-false}" = true ]; then
    docker rm -f "$INTEGRATION_POSTGRES_CONTAINER" >/dev/null 2>&1 || true
    INTEGRATION_POSTGRES_MANAGED=false
  fi
}
