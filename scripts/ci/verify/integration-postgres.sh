#!/usr/bin/env bash

# Hermetic PostgreSQL selection for the bounded product integration harness.
# This file is sourced by run-integration-verification.sh and its focused test.
# shellcheck disable=SC2034 # State is consumed by the sourcing script.

# Server settings for every integration PostgreSQL this file starts, and for the
# one ci.yaml's "Start integration Postgres" steps start (test-integration-
# postgres.sh keeps them equal). Each migration test applies the baseline
# migration in one transaction, holding about 900 locks until it commits, and
# the database lanes run those tests side by side. The default lock table (64
# locks per transaction for 100 connections) runs out at a few concurrent
# migrations with "out of shared memory" (#3198); 1024 fits every concurrent
# test the lanes can open within max_connections.
INTEGRATION_POSTGRES_SERVER_ARGS=(-c max_locks_per_transaction=1024)
# The PostgreSQL image every integration server runs, by digest: the same pin
# as the Kind PostgreSQL (KIND_POSTGRES_IMAGE in kind/common.sh) and as
# ci.yaml's "Start integration Postgres" steps (test-integration-postgres.sh
# keeps the three equal). The digest is its linux/amd64 manifest.
# INTEGRATION_POSTGRES_IMAGE overrides it: on CI, the image
# load-fixture-images.sh made present.
INTEGRATION_POSTGRES_PINNED_IMAGE='docker.io/library/postgres:17-alpine@sha256:7456ef82e5f5bc43d997f4781bbd7c0d6389bff397564649a356e206ba473aee'
# The NATS server the runtime plane starts: 2.12.15 on Alpine, the release the
# floating 2.12-alpine tag named when it was pinned (2026-10-26; published
# 2026-08-12). The digest is its multi-platform index, so a workstation of
# either architecture runs it. INTEGRATION_NATS_IMAGE overrides it.
INTEGRATION_NATS_PINNED_IMAGE='docker.io/library/nats:2.12.15-alpine@sha256:b270f5e2428354c0335612694d7dd2fb588148e567a5757fdff325ef9c9332e6'
# Each pinned image's ID in Docker's overlay2 image store, which a metal
# guest's daemon runs on: the digest of its linux/amd64 image config.
# load-fixture-images.sh accepts a kept archive of an image only when it loads
# to that ID; docker load checks every layer against the config, whose digest
# the ID is.
INTEGRATION_POSTGRES_PINNED_ID='sha256:1bea307dfb3ee30541a7acf7de14b58bcd6948da98e5d31a04c627c4d35ec64b'
INTEGRATION_NATS_PINNED_ID='sha256:138f6ccc9fd034c76ac3cee7faed6c5fdb874fd333f477b91f52b4052f6669ce'

# integration_fixture_name KIND prints the container name for one of this
# process's fixtures: codewire-product-KIND-<run>-[<job>-][a<attempt>-]<pid>.
# The concurrent lanes of one merge qualification share a run ID, and on CI
# every job of every main run shares one Docker daemon on main's warm VM
# (infra#1534), where two jobs' processes can have the same PID and a rerun
# attempt of a job can start while the old attempt's task still runs. Each
# fixture removes its own name before it starts, so the name carries the job
# and the attempt. The attempt follows the job, so the VM's per-job usage
# match (codewire-.+-<run>-<job>(-.*)?) still finds it.
integration_fixture_name() {
  local attempt=""
  [[ "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ ]] && attempt="a$GITHUB_RUN_ATTEMPT-"
  printf 'codewire-product-%s-%s-%s%s%s' "$1" "${GITHUB_RUN_ID:-local}" \
    "${GITHUB_JOB:+$GITHUB_JOB-}" "$attempt" "$$"
}

integration_postgres_init() {
  INTEGRATION_POSTGRES_CONTAINER="$(integration_fixture_name postgres)"
  # Every fixture container carries the run, attempt and job that started it,
  # so a cleanup or an operator can select exactly one job's containers
  # (docker ps --filter label=codewire.ci.run=...).
  INTEGRATION_FIXTURE_LABELS=(
    --label "codewire.ci.run=${GITHUB_RUN_ID:-local}"
    --label "codewire.ci.attempt=${GITHUB_RUN_ATTEMPT:-0}"
    --label "codewire.ci.job=${GITHUB_JOB:-local}"
  )
  INTEGRATION_POSTGRES_MANAGED=false
  INTEGRATION_POSTGRES_SOURCE=""
  INTEGRATION_POSTGRES_LANE_CONTAINERS=()
  INTEGRATION_POSTGRES_STARTING=()
  INTEGRATION_POSTGRES_LANE_URL=""
  INTEGRATION_POSTGRES_LANE_URL_RUST=""
}

integration_postgres_require_tools() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "::error::local integration verification requires Docker or explicit DATABASE_URL and DATABASE_URL_RUST" >&2
    return 1
  fi
  if ! command -v psql >/dev/null 2>&1; then
    echo "::error::local integration verification requires psql" >&2
    return 1
  fi
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

  local image="${INTEGRATION_POSTGRES_IMAGE:-$INTEGRATION_POSTGRES_PINNED_IMAGE}"

  # A CI job runs in a container on its own Docker network, which cannot reach
  # a port published on the Docker host's loopback. Without an explicit
  # database, the run starts its own PostgreSQL on that network under its
  # container name, so the concurrent lanes of one job never share one.
  if [ -n "${INTEGRATION_DOCKER_NETWORK:-}" ]; then
    if [[ "$INTEGRATION_DOCKER_NETWORK" =~ [^A-Za-z0-9_.-] ]]; then
      echo "::error::invalid integration Docker network" >&2
      return 1
    fi
    integration_postgres_require_tools || return 1
    docker rm -f "$INTEGRATION_POSTGRES_CONTAINER" >/dev/null 2>&1 || true
    docker run -d --rm --name "$INTEGRATION_POSTGRES_CONTAINER" --pids-limit 2048 \
      --network "$INTEGRATION_DOCKER_NETWORK" \
      --network-alias "$INTEGRATION_POSTGRES_CONTAINER" \
      -e POSTGRES_USER=codewire -e POSTGRES_PASSWORD=codewire -e POSTGRES_DB=codewire "${INTEGRATION_FIXTURE_LABELS[@]}" \
      "$image" "${INTEGRATION_POSTGRES_SERVER_ARGS[@]}" >/dev/null
    INTEGRATION_POSTGRES_MANAGED=true
    DATABASE_URL="postgres://codewire:codewire@${INTEGRATION_POSTGRES_CONTAINER}:5432/codewire?sslmode=disable"
    DATABASE_URL_RUST="postgres://codewire:codewire@${INTEGRATION_POSTGRES_CONTAINER}:5432/codewire"
    integration_postgres_wait_ready "$DATABASE_URL" "job-network" || return 1
    INTEGRATION_POSTGRES_SOURCE=network
    return
  fi

  if [ "${GITHUB_ACTIONS:-false}" = true ]; then
    DATABASE_URL="postgres://codewire:codewire@127.0.0.1:5432/codewire?sslmode=disable"
    DATABASE_URL_RUST="postgres://codewire:codewire@127.0.0.1:5432/codewire"
    INTEGRATION_POSTGRES_SOURCE=ci
    return
  fi

  integration_postgres_require_tools || return 1

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
    "${INTEGRATION_FIXTURE_LABELS[@]}" \
    -p "$publish" "$image" "${INTEGRATION_POSTGRES_SERVER_ARGS[@]}" >/dev/null
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

# A database lane gets its own disposable PostgreSQL beside the selected one:
# on the CI job's network when the database is there, or as another managed
# loopback container locally. Against any other explicit database there is
# nowhere to create one, and lanes share that database one after another.
integration_postgres_lanes_available() {
  [ "${INTEGRATION_POSTGRES_SOURCE:-}" = managed ] \
    || [ "${INTEGRATION_POSTGRES_SOURCE:-}" = network ] \
    || { [ "${INTEGRATION_POSTGRES_SOURCE:-}" = explicit ] && [ -n "${INTEGRATION_DOCKER_NETWORK:-}" ]; }
}

# integration_postgres_start_lane LANE [background] sets
# INTEGRATION_POSTGRES_LANE_URL and INTEGRATION_POSTGRES_LANE_URL_RUST; the
# cleanup removes its container. With background, a lane on the job's network
# starts its container without waiting for Docker, and
# integration_postgres_wait_started waits for every one so started; a managed
# loopback lane needs its port, so it always starts in the foreground.
integration_postgres_start_lane() {
  local lane="$1" name image="${INTEGRATION_POSTGRES_IMAGE:-$INTEGRATION_POSTGRES_PINNED_IMAGE}" host port
  [[ "$lane" =~ ^[a-z][a-z-]{0,31}$ ]] || {
    echo "::error::invalid database lane name: $lane" >&2
    return 1
  }
  name="${INTEGRATION_POSTGRES_CONTAINER}-lane-${lane}"
  docker rm -f "$name" >/dev/null 2>&1 || true
  INTEGRATION_POSTGRES_LANE_CONTAINERS+=("$name")
  if [ "${INTEGRATION_POSTGRES_SOURCE:-}" = managed ]; then
    docker run -d --rm --name "$name" \
      -e POSTGRES_USER=codewire -e POSTGRES_PASSWORD=codewire -e POSTGRES_DB=codewire "${INTEGRATION_FIXTURE_LABELS[@]}" \
      -p 127.0.0.1::5432 "$image" "${INTEGRATION_POSTGRES_SERVER_ARGS[@]}" >/dev/null
    host=127.0.0.1
    port="$(docker port "$name" 5432/tcp | sed 's/.*://')"
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
      echo "::error::unable to resolve the database lane $lane PostgreSQL loopback port" >&2
      return 1
    fi
  else
    host="codewire-integration-postgres-${lane}"
    if [ "${2:-}" = background ]; then
      docker run -d --rm --name "$name" --pids-limit 2048 \
        --network "$INTEGRATION_DOCKER_NETWORK" --network-alias "$host" \
        -e POSTGRES_USER=codewire -e POSTGRES_PASSWORD=codewire -e POSTGRES_DB=codewire "${INTEGRATION_FIXTURE_LABELS[@]}" \
        "$image" "${INTEGRATION_POSTGRES_SERVER_ARGS[@]}" >/dev/null &
      INTEGRATION_POSTGRES_STARTING+=("$!")
    else
      docker run -d --rm --name "$name" --pids-limit 2048 \
        --network "$INTEGRATION_DOCKER_NETWORK" --network-alias "$host" \
        -e POSTGRES_USER=codewire -e POSTGRES_PASSWORD=codewire -e POSTGRES_DB=codewire "${INTEGRATION_FIXTURE_LABELS[@]}" \
        "$image" "${INTEGRATION_POSTGRES_SERVER_ARGS[@]}" >/dev/null
    fi
    port=5432
  fi
  INTEGRATION_POSTGRES_LANE_URL="postgres://codewire:codewire@${host}:${port}/codewire?sslmode=disable"
  INTEGRATION_POSTGRES_LANE_URL_RUST="postgres://codewire:codewire@${host}:${port}/codewire"
}

integration_postgres_wait_started() {
  local pid failed=false
  for pid in "${INTEGRATION_POSTGRES_STARTING[@]}"; do
    wait "$pid" || failed=true
  done
  INTEGRATION_POSTGRES_STARTING=()
  [ "$failed" = false ] || {
    echo "::error::a database lane PostgreSQL did not start" >&2
    return 1
  }
}

# integration_postgres_stop_lane LANE removes a finished lane's PostgreSQL, so
# it holds no memory while the other lanes run. The cleanup removes it again,
# which is harmless.
integration_postgres_stop_lane() {
  docker rm -f "${INTEGRATION_POSTGRES_CONTAINER}-lane-$1" >/dev/null 2>&1 || true
}

integration_postgres_wait_ready() {
  local url="$1" label="$2" _
  for _ in $(seq 1 "${INTEGRATION_POSTGRES_READY_ATTEMPTS:-60}"); do
    if psql "$url" -v ON_ERROR_STOP=1 -tAc 'SELECT 1' >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "::error::${label} PostgreSQL did not become ready" >&2
  return 1
}

integration_postgres_cleanup() {
  local name
  if [ "${INTEGRATION_POSTGRES_MANAGED:-false}" = true ]; then
    docker rm -f "$INTEGRATION_POSTGRES_CONTAINER" >/dev/null 2>&1 || true
    INTEGRATION_POSTGRES_MANAGED=false
  fi
  for name in "${INTEGRATION_POSTGRES_LANE_CONTAINERS[@]}"; do
    docker rm -f "$name" >/dev/null 2>&1 || true
  done
  INTEGRATION_POSTGRES_LANE_CONTAINERS=()
}
