#!/usr/bin/env bash
# Runs inside the storage-measure bench pod's workload container (by default
# the Codewire workspace image). measure-storage.sh mounts this file from a
# ConfigMap and runs it with kubectl exec.
#
#   workload.sh                         run every workload step
#   workload.sh --write-marker V [MIB]  write marker V (and MIB MiB of new data)
#   workload.sh --step NAME             internal: one step, under timeout
#
# Each step prints one "SM_RESULT <json>" line on stdout. Step output goes to
# per-step logs on the measured volume; a failing step's tail goes to stderr.
set -uo pipefail

SM_ROOT="${SM_ROOT:-/workspace/sm}"
SM_STEP_TIMEOUT_SECONDS="${SM_STEP_TIMEOUT_SECONDS:-1800}"
SM_DOCKER_WAIT_SECONDS="${SM_DOCKER_WAIT_SECONDS:-0}"
work="$SM_ROOT/work"
logs="$SM_ROOT/logs"
src="$work/src"
export HOME="$work/home"
export CARGO_HOME="$work/cargo-home"
export CARGO_TARGET_DIR="$work/target"
export TMPDIR="$work/tmp"

now_ms() {
  date +%s%3N
}

# Values are reduced to a JSON-safe alphabet; they are kernel and tool
# identifiers, never free text.
clean() {
  printf '%s' "$1" | tr -cd 'A-Za-z0-9._:/+-' | cut -c1-120
}

emit_result() {
  local step="$1" status="$2" exit_code="$3" ms="$4"
  printf 'SM_RESULT {"step":"%s","status":"%s","exit_code":%d,"ms":%d}\n' \
    "$step" "$status" "$exit_code" "$ms"
}

emit_skip() {
  printf 'SM_RESULT {"step":"%s","status":"skipped","reason":"%s"}\n' "$1" "$2"
}

step_git_clone() {
  git clone --quiet --no-checkout "$SM_GIT_URL" "$src" &&
    git -C "$src" checkout --quiet --detach "$SM_GIT_COMMIT" &&
    [[ "$(git -C "$src" rev-parse HEAD)" == "$SM_GIT_COMMIT" ]]
}

step_cargo_fetch() {
  cargo fetch --locked --manifest-path "$src/Cargo.toml"
}

step_cargo_build() {
  cargo build --locked --offline --manifest-path "$src/Cargo.toml"
}

tree_inputs() {
  local inputs=(src)
  if [[ -d "$CARGO_HOME/registry/src" ]]; then
    inputs+=(cargo-home/registry/src)
  fi
  printf '%s\n' "${inputs[@]}"
}

step_file_tree_pack() {
  local inputs
  mapfile -t inputs < <(tree_inputs)
  tar -C "$work" -cf "$work/tree.tar" "${inputs[@]}" && sync
}

step_file_tree_unpack() {
  mkdir "$work/tree" && tar -C "$work/tree" -xf "$work/tree.tar" && sync
}

step_file_tree_remove() {
  rm -rf "$work/tree" "$work/tree.tar" && sync
}

step_docker_build() {
  printf 'FROM scratch\nCOPY . /src\n' >"$work/Dockerfile" &&
    docker build --quiet --tag storage-measure-build:latest --file "$work/Dockerfile" "$src" &&
    docker image rm storage-measure-build:latest
}

run_step() {
  local name="$1" start end rc
  start="$(now_ms)"
  timeout -k 10 "$SM_STEP_TIMEOUT_SECONDS" bash "${BASH_SOURCE[0]}" --step "$name" \
    >"$logs/$name.log" 2>&1
  rc=$?
  end="$(now_ms)"
  if ((rc == 0)); then
    emit_result "$name" ok 0 "$((end - start))"
  else
    emit_result "$name" failed "$rc" "$((end - start))"
    printf '[storage-measure workload] %s failed (exit %d); log tail:\n' "$name" "$rc" >&2
    tail -n 40 "$logs/$name.log" >&2 || true
  fi
  return "$rc"
}

docker_available() {
  local deadline
  command -v docker >/dev/null 2>&1 || return 1
  ((SM_DOCKER_WAIT_SECONDS > 0)) || return 1
  deadline=$((SECONDS + SM_DOCKER_WAIT_SECONDS))
  while ((SECONDS < deadline)); do
    if docker info >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

emit_info() {
  local fs_type kernel cpus
  fs_type="$(clean "$(findmnt -no FSTYPE --target "$SM_ROOT" 2>/dev/null || stat -f -c %T "$SM_ROOT")")"
  kernel="$(clean "$(uname -r)")"
  cpus="$(nproc)"
  printf 'SM_INFO {"nproc":%d,"kernel":"%s","fs_type":"%s"}\n' "$cpus" "$kernel" "$fs_type"
}

run_all() {
  local failed=0
  : "${SM_GIT_URL:?SM_GIT_URL is required}" "${SM_GIT_COMMIT:?SM_GIT_COMMIT is required}"
  rm -rf "$work" "$logs"
  mkdir -p "$work" "$logs" "$HOME" "$TMPDIR"
  emit_info

  if run_step git_clone; then
    if [[ -f "$src/Cargo.toml" ]]; then
      if run_step cargo_fetch; then
        run_step cargo_build || failed=1
      else
        failed=1
        emit_skip cargo_build cargo-fetch-failed
      fi
    else
      emit_skip cargo_fetch no-cargo-manifest
      emit_skip cargo_build no-cargo-manifest
    fi
    if run_step file_tree_pack; then
      run_step file_tree_unpack || failed=1
    else
      failed=1
      emit_skip file_tree_unpack pack-failed
    fi
    run_step file_tree_remove || failed=1
    if docker_available; then
      run_step docker_build || failed=1
    else
      emit_skip docker_build docker-unavailable
    fi
  else
    failed=1
    for skipped in cargo_fetch cargo_build file_tree_pack file_tree_unpack file_tree_remove docker_build; do
      emit_skip "$skipped" clone-failed
    done
  fi
  return "$failed"
}

write_marker() {
  local value="$1" delta_mib="${2:-0}"
  [[ "$delta_mib" =~ ^[0-9]+$ ]] || return 2
  mkdir -p "$SM_ROOT" || return 1
  if ((delta_mib > 0)); then
    dd if=/dev/urandom of="$SM_ROOT/delta-$(now_ms).bin" bs=1M count="$delta_mib" \
      conv=fsync status=none || return 1
  fi
  printf '%s\n' "$value" >"$SM_ROOT/marker" && sync
}

case "${1:-}" in
  --step)
    [[ $# -eq 2 ]] || exit 2
    case "$2" in
      git_clone|cargo_fetch|cargo_build|file_tree_pack|file_tree_unpack|file_tree_remove|docker_build)
        "step_$2"
        ;;
      *)
        exit 2
        ;;
    esac
    ;;
  --write-marker)
    [[ $# -ge 2 && $# -le 3 ]] || exit 2
    write_marker "$2" "${3:-0}"
    ;;
  '')
    run_all
    ;;
  *)
    exit 2
    ;;
esac
