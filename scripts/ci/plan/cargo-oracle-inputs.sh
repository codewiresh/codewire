# shellcheck shell=bash
# shellcheck disable=SC2154 # rust_artifacts is the caller's (test.sh).
# The planner Cargo oracle's inputs: the lock-pinned registry and Git sources
# of every Rust artifact root. test.sh sources this with `rust_artifacts` set
# to PACKAGE<TAB>MANIFEST lines.

# True only when every root's dependency tree resolves offline. A warm Cargo
# home can hold one root's inputs and miss another's (a lock bump that only one
# root uses), so a single unresolved root means the inputs must be fetched.
cargo_oracle_inputs_available() {
  local artifact package manifest
  for artifact in "${rust_artifacts[@]}"; do
    IFS=$'\t' read -r package manifest <<<"$artifact"
    local -a command=(
      cargo tree --locked --offline --edges "normal,build" --prefix none --format="{p}" -p "$package"
    )
    if [ "$manifest" != Cargo.toml ]; then
      command+=(--manifest-path "$manifest")
    fi
    "${command[@]}" >/dev/null 2>&1 || return 1
  done
}

hydrate_cargo_oracle_inputs() {
  local artifact package manifest
  for artifact in "${rust_artifacts[@]}"; do
    IFS=$'\t' read -r package manifest <<<"$artifact"
    local -a command=(env -u CARGO_NET_OFFLINE cargo fetch --locked --config net.offline=false)
    if [ "$manifest" != Cargo.toml ]; then
      command+=(--manifest-path "$manifest")
    fi
    "${command[@]}"
  done
}
