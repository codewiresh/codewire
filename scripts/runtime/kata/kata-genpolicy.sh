#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"

KATA_GENPOLICY_SOURCE_REPO="${KATA_GENPOLICY_SOURCE_REPO:-https://github.com/noeljackson/kata-containers.git}"
KATA_GENPOLICY_SOURCE_REF="${KATA_GENPOLICY_SOURCE_REF:-b81c0f2db867caddbe98e660e0ccccc9c420b6f8}"
KATA_GENPOLICY_EXPECTED_COMMIT="${KATA_GENPOLICY_EXPECTED_COMMIT:-b81c0f2db867caddbe98e660e0ccccc9c420b6f8}"
KATA_GENPOLICY_WORKDIR="${KATA_GENPOLICY_WORKDIR:-$ROOT/.tmp/kata-genpolicy}"
KATA_GENPOLICY_TRIPLE="${KATA_GENPOLICY_TRIPLE:-x86_64-unknown-linux-gnu}"
KATA_GENPOLICY_BUILD_TYPE="${KATA_GENPOLICY_BUILD_TYPE:-release}"
KATA_GENPOLICY_TIMEOUT_SECONDS="${KATA_GENPOLICY_TIMEOUT_SECONDS:-300}"
KATA_GENPOLICY_INSECURE_REGISTRIES="${KATA_GENPOLICY_INSECURE_REGISTRIES:-}"
KATA_GENPOLICY_SMOKE_IMAGE="${KATA_GENPOLICY_SMOKE_IMAGE:-docker.io/library/busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f}"
KATA_GENPOLICY_SMOKE_PAUSE_IMAGE="${KATA_GENPOLICY_SMOKE_PAUSE_IMAGE:-$KATA_GENPOLICY_SMOKE_IMAGE}"
KATA_GENPOLICY_SMOKE_LOCAL_REGISTRY="${KATA_GENPOLICY_SMOKE_LOCAL_REGISTRY:-0}"
KATA_GENPOLICY_SMOKE_REGISTRY_PORT="${KATA_GENPOLICY_SMOKE_REGISTRY_PORT:-5001}"

SRC_DIR="$KATA_GENPOLICY_WORKDIR/src/kata-containers"
BIN_DIR="$KATA_GENPOLICY_WORKDIR/bin"
OUT_DIR="$KATA_GENPOLICY_WORKDIR/out"
GENPOLICY_BIN="${KATA_GENPOLICY_BIN:-$BIN_DIR/genpolicy}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/kata/kata-genpolicy.sh build
  scripts/runtime/kata/kata-genpolicy.sh smoke
  scripts/runtime/kata/kata-genpolicy.sh generate -y INPUT.yaml [-o OUTPUT.yaml] [--settings-dir DIR] [--allow-unsupported]

Builds and runs Kata Containers genpolicy from the Codewire-pinned Kata source.

Environment:
  KATA_GENPOLICY_SOURCE_REPO       Source repo (default: the Codewire Kata fork)
  KATA_GENPOLICY_SOURCE_REF        Git ref to fetch (default: the Kata 4.3.1 deployment commit)
  KATA_GENPOLICY_EXPECTED_COMMIT   Commit guard; empty disables guard
  KATA_GENPOLICY_WORKDIR           Build/cache dir (default: .tmp/kata-genpolicy)
  KATA_GENPOLICY_TRIPLE            Cargo target triple (default: x86_64-unknown-linux-gnu)
  KATA_GENPOLICY_BUILD_TYPE        release or debug (default: release)
  KATA_GENPOLICY_TIMEOUT_SECONDS   Generation timeout (default: 300)
  KATA_GENPOLICY_INSECURE_REGISTRIES
                                    Space-separated plain-HTTP registries for genpolicy
  KATA_GENPOLICY_BIN               Existing genpolicy binary override
  KATA_GENPOLICY_SMOKE_IMAGE       Smoke workload image
  KATA_GENPOLICY_SMOKE_PAUSE_IMAGE Smoke pause image setting
  KATA_GENPOLICY_SMOKE_LOCAL_REGISTRY=1
                                    Push smoke image to a temporary localhost registry first
  KATA_GENPOLICY_SMOKE_REGISTRY_PORT
                                    Local smoke registry port (default: 5001)

Notes:
  generate copies INPUT.yaml before annotation and writes genpolicy stdout to a
  sibling *.policy-and-base64.txt file. Do not publish outputs from real user
  sandboxes without reviewing them for environment, image, command, or mount data.
USAGE
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

ensure_executable_workdir() {
  mkdir -p "$KATA_GENPOLICY_WORKDIR/.exec-check"

  local probe="$KATA_GENPOLICY_WORKDIR/.exec-check/probe.sh"
  cat >"$probe" <<'SH'
#!/usr/bin/env sh
exit 0
SH
  chmod 0755 "$probe"
  if ! "$probe" >/dev/null 2>&1; then
    rm -f "$probe"
    die "KATA_GENPOLICY_WORKDIR must allow executing build artifacts; $KATA_GENPOLICY_WORKDIR appears to be mounted noexec"
  fi
  rm -f "$probe"
}

ensure_source() {
  require_cmd git
  mkdir -p "$(dirname "$SRC_DIR")"

  if [[ ! -d "$SRC_DIR/.git" ]]; then
    rm -rf "$SRC_DIR"
    git clone --no-checkout "$KATA_GENPOLICY_SOURCE_REPO" "$SRC_DIR"
  fi

  git -C "$SRC_DIR" remote set-url origin "$KATA_GENPOLICY_SOURCE_REPO"
  git -C "$SRC_DIR" fetch --depth 1 origin "$KATA_GENPOLICY_SOURCE_REF"
  git -C "$SRC_DIR" checkout --detach FETCH_HEAD >/dev/null
  git -C "$SRC_DIR" reset --hard FETCH_HEAD >/dev/null

  local commit
  commit="$(git -C "$SRC_DIR" rev-parse HEAD)"
  if [[ -n "$KATA_GENPOLICY_EXPECTED_COMMIT" && "$commit" != "$KATA_GENPOLICY_EXPECTED_COMMIT" ]]; then
    die "Kata source resolved to $commit, expected $KATA_GENPOLICY_EXPECTED_COMMIT"
  fi

  printf '%s\n' "$commit"
}

build_genpolicy() {
  require_cmd make
  require_cmd cargo
  ensure_executable_workdir

  local commit
  commit="$(ensure_source)"

  make -C "$SRC_DIR/src/tools/genpolicy" \
    TRIPLE="$KATA_GENPOLICY_TRIPLE" \
    BUILD_TYPE="$KATA_GENPOLICY_BUILD_TYPE" \
    build

  local profile_dir="debug"
  if [[ "$KATA_GENPOLICY_BUILD_TYPE" == *release* ]]; then
    profile_dir="release"
  fi

  local built_bin="$SRC_DIR/target/$KATA_GENPOLICY_TRIPLE/$profile_dir/genpolicy"
  if [[ ! -x "$built_bin" ]]; then
    built_bin="$(find "$SRC_DIR/target" -type f -name genpolicy -perm -111 | sort | head -n 1)"
  fi
  [[ -n "$built_bin" && -x "$built_bin" ]] || die "genpolicy binary was not produced"

  mkdir -p "$BIN_DIR" "$KATA_GENPOLICY_WORKDIR/policy-inputs/$commit"
  install -m 0755 "$built_bin" "$GENPOLICY_BIN"
  install -m 0644 "$SRC_DIR/src/tools/genpolicy/rules.rego" \
    "$KATA_GENPOLICY_WORKDIR/policy-inputs/$commit/rules.rego"
  install -m 0644 "$SRC_DIR/src/tools/genpolicy/genpolicy-settings.json" \
    "$KATA_GENPOLICY_WORKDIR/policy-inputs/$commit/genpolicy-settings.json"

  printf 'genpolicy built: %s\n' "$GENPOLICY_BIN"
  printf 'kata source commit: %s\n' "$commit"
}

ensure_binary() {
  if [[ ! -x "$GENPOLICY_BIN" ]]; then
    build_genpolicy
  fi
}

source_commit_for_inputs() {
  if [[ -d "$SRC_DIR/.git" ]]; then
    git -C "$SRC_DIR" rev-parse HEAD
  else
    printf '%s\n' "$KATA_GENPOLICY_EXPECTED_COMMIT"
  fi
}

generate_policy() {
  local input="" output="" settings_dir="" allow_unsupported=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -y|--yaml)
        input="${2:-}"
        shift 2
        ;;
      -o|--output)
        output="${2:-}"
        shift 2
        ;;
      --settings-dir)
        settings_dir="${2:-}"
        shift 2
        ;;
      --allow-unsupported|-s)
        allow_unsupported=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown generate argument: $1"
        ;;
    esac
  done

  [[ -n "$input" ]] || die "generate requires -y INPUT.yaml"
  [[ -f "$input" ]] || die "input YAML does not exist: $input"

  require_cmd timeout
  ensure_binary

  local commit inputs_dir
  commit="$(source_commit_for_inputs)"
  inputs_dir="$KATA_GENPOLICY_WORKDIR/policy-inputs/$commit"
  [[ -f "$inputs_dir/rules.rego" ]] || die "missing pinned rules.rego; run build first"
  [[ -f "$inputs_dir/genpolicy-settings.json" ]] || die "missing pinned genpolicy-settings.json; run build first"
  if [[ -n "$settings_dir" ]]; then
    [[ -d "$settings_dir" ]] || die "settings dir does not exist: $settings_dir"
    [[ -f "$settings_dir/genpolicy-settings.json" ]] || die "settings dir missing genpolicy-settings.json: $settings_dir"
  else
    settings_dir="$inputs_dir/genpolicy-settings.json"
  fi

  mkdir -p "$OUT_DIR"
  if [[ -z "$output" ]]; then
    output="$OUT_DIR/$(basename "${input%.yaml}").policy.yaml"
  fi
  mkdir -p "$(dirname "$output")"

  local stdout_file="${output%.yaml}.policy-and-base64.txt"
  umask 077
  cp "$input" "$output"

  local args=(
    "$GENPOLICY_BIN"
    -r
    -b
    -p "$inputs_dir/rules.rego"
    -j "$settings_dir"
    -y "$output"
  )
  if [[ "$allow_unsupported" == 1 ]]; then
    args+=(-s)
  fi
  if [[ -n "$KATA_GENPOLICY_INSECURE_REGISTRIES" ]]; then
    local registry
    for registry in $KATA_GENPOLICY_INSECURE_REGISTRIES; do
      args+=(--insecure-registry "$registry")
    done
  fi

  set +e
  timeout --kill-after=10s "${KATA_GENPOLICY_TIMEOUT_SECONDS}s" "${args[@]}" >"$stdout_file"
  local status=$?
  set -e
  if [[ "$status" -ne 0 ]]; then
    if [[ "$status" == 124 || "$status" == 137 ]]; then
      die "genpolicy timed out after ${KATA_GENPOLICY_TIMEOUT_SECONDS}s; check registry reachability for workload and pause images"
    fi
    die "genpolicy failed with exit status $status"
  fi

  grep -q '^package agent_policy$' "$stdout_file" || \
    die "genpolicy stdout did not contain agent_policy package"
  grep -q 'io.katacontainers.config.hypervisor.cc_init_data' "$output" || \
    die "annotated YAML missing Kata cc_init_data annotation"

  printf 'annotated YAML: %s\n' "$output"
  printf 'policy stdout: %s\n' "$stdout_file"
}

smoke() {
  ensure_binary

  local commit smoke_settings smoke_input cleanup_registry_name=""
  commit="$(source_commit_for_inputs)"
  smoke_settings="$KATA_GENPOLICY_WORKDIR/smoke-settings/$commit"
  mkdir -p "$smoke_settings/genpolicy-settings.d"
  cp "$KATA_GENPOLICY_WORKDIR/policy-inputs/$commit/genpolicy-settings.json" \
    "$smoke_settings/genpolicy-settings.json"

  if [[ "$KATA_GENPOLICY_SMOKE_LOCAL_REGISTRY" == 1 ]]; then
    require_cmd docker
    require_cmd curl
    local registry_name="codewire-genpolicy-registry-$KATA_GENPOLICY_SMOKE_REGISTRY_PORT"
    local registry_ref="localhost:$KATA_GENPOLICY_SMOKE_REGISTRY_PORT/codewire/genpolicy-smoke:latest"
    if ! docker ps --format '{{.Names}}' | grep -Fxq "$registry_name"; then
      docker run -d --rm \
        --name "$registry_name" \
        -p "127.0.0.1:$KATA_GENPOLICY_SMOKE_REGISTRY_PORT:5000" \
        registry:2 >/dev/null
      cleanup_registry_name="$registry_name"
    fi

    local ready=0
    for _ in $(seq 1 30); do
      if curl -fsS "http://127.0.0.1:$KATA_GENPOLICY_SMOKE_REGISTRY_PORT/v2/" >/dev/null 2>&1; then
        ready=1
        break
      fi
      sleep 1
    done
    [[ "$ready" == 1 ]] || die "local genpolicy smoke registry did not become ready on 127.0.0.1:$KATA_GENPOLICY_SMOKE_REGISTRY_PORT"

    docker pull "$KATA_GENPOLICY_SMOKE_IMAGE" >/dev/null
    docker tag "$KATA_GENPOLICY_SMOKE_IMAGE" "$registry_ref"
    docker push "$registry_ref" >/dev/null
    KATA_GENPOLICY_SMOKE_IMAGE="$registry_ref"
    KATA_GENPOLICY_SMOKE_PAUSE_IMAGE="$registry_ref"
    KATA_GENPOLICY_INSECURE_REGISTRIES="${KATA_GENPOLICY_INSECURE_REGISTRIES:+$KATA_GENPOLICY_INSECURE_REGISTRIES }localhost:$KATA_GENPOLICY_SMOKE_REGISTRY_PORT"
  fi

  if [[ -n "$cleanup_registry_name" ]]; then
    # shellcheck disable=SC2064 # Capture the per-smoke registry name while it is still in scope.
    trap "docker rm -f '$cleanup_registry_name' >/dev/null 2>&1 || true" EXIT
  fi

  cat >"$smoke_settings/genpolicy-settings.d/10-codewire-smoke-pause-image.json" <<JSON
[
  {
    "op": "replace",
    "path": "/cluster_config/pause_container_image",
    "value": "$KATA_GENPOLICY_SMOKE_PAUSE_IMAGE"
  }
]
JSON

  smoke_input="$OUT_DIR/commodity-genpolicy-smoke-pod.input.yaml"
  mkdir -p "$OUT_DIR"
  awk -v image="$KATA_GENPOLICY_SMOKE_IMAGE" '
    /^      image: / { print "      image: " image; next }
    { print }
  ' "$ROOT/deployments/k8s/runtime-profiles/policy/commodity-genpolicy-smoke-pod.yaml" >"$smoke_input"

  generate_policy \
    -y "$smoke_input" \
    -o "$OUT_DIR/commodity-genpolicy-smoke-pod.policy.yaml" \
    --settings-dir "$smoke_settings"
}

cmd="${1:-}"
case "$cmd" in
  build)
    shift
    [[ $# -eq 0 ]] || die "build takes no arguments"
    build_genpolicy
    ;;
  generate)
    shift
    generate_policy "$@"
    ;;
  smoke)
    shift
    [[ $# -eq 0 ]] || die "smoke takes no arguments"
    smoke
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
