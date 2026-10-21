#!/usr/bin/env bash
# Sourced. Removes one owned docker-container BuildKit builder and proves it is
# gone. Shared by the workspace verification (workspace-cache.sh) and the Kind
# image build (build-kind-images.sh).
#
# A builder is three Docker objects: the Buildx instance BUILDER, its daemon
# container buildx_buildkit_NODE, and that container's state volume
# buildx_buildkit_NODE_state. `buildx rm` can report failure while, or after,
# Docker removes them: its client gives up on a multi-GB state volume the
# daemon is still deleting under load (#2990). So a failed `buildx rm` is not
# the answer. Each object still present is removed again by its exact name;
# that request waits on the daemon, so a round in which an object disappears
# is progress. The removal fails only after a round that removes nothing, and
# it names every object that persists.

# One Docker request that neither finishes nor fails for this long is hung.
# Removing a state volume of a few GB normally takes well under a minute.
BUILDX_BUILDER_REQUEST_SECONDS="${BUILDX_BUILDER_REQUEST_SECONDS:-300}"

# buildx_builder_request DOCKER ARGS... runs one bounded Docker request.
buildx_builder_request() {
  timeout --signal=TERM --kill-after=5s "${BUILDX_BUILDER_REQUEST_SECONDS}s" "$@" </dev/null
}

# buildx_builder_present DOCKER BUILDER NODE prints each object of the builder
# that Docker does not report as missing, one per line. Only Docker's own
# not-found answer proves an object absent; any other failure counts as present.
buildx_builder_present() {
  local docker_bin="$1" builder="$2" node="$3" output
  output="$(buildx_builder_request "$docker_bin" buildx inspect "$builder" 2>&1)" || true
  [[ "$output" == *"no builder \"$builder\" found"* ]] || printf 'builder %s\n' "$builder"
  output="$(buildx_builder_request "$docker_bin" container inspect --format '{{.Id}}' \
    "buildx_buildkit_$node" 2>&1)" || true
  [[ "$output" == *"No such container: buildx_buildkit_$node"* ]] ||
    printf 'container buildx_buildkit_%s\n' "$node"
  output="$(buildx_builder_request "$docker_bin" volume inspect --format '{{.Name}}' \
    "buildx_buildkit_${node}_state" 2>&1)" || true
  [[ "$output" == *"buildx_buildkit_${node}_state: no such volume"* ]] ||
    printf 'volume buildx_buildkit_%s_state\n' "$node"
}

# buildx_builder_remove DOCKER BUILDER NODE LABEL removes the builder. LABEL
# prefixes its diagnostics. It returns 0 once Docker reports all three objects
# missing, and otherwise the status of the first failed `buildx rm`.
buildx_builder_remove() {
  local docker_bin="$1" builder="$2" node="$3" label="$4"
  local status=0 output='' present='' previous='' kind name started=$SECONDS
  [[ "$builder" =~ ^[[:alnum:]][[:alnum:]_.-]*$ && "$node" =~ ^[[:alnum:]][[:alnum:]_.-]*$ ]] || return 2
  output="$(buildx_builder_request "$docker_bin" buildx rm --force "$builder" 2>&1)" || status=$?
  [[ "$status" != 0 ]] || return 0
  while :; do
    present="$(buildx_builder_present "$docker_bin" "$builder" "$node")"
    if [[ -z "$present" ]]; then
      printf '%s: phase=builder-removal status=%s confirmed-absent=true elapsed_seconds=%s\n' \
        "$label" "$status" "$((SECONDS - started))" >&2
      return 0
    fi
    if [[ -n "$previous" && "$present" == "$previous" ]]; then
      printf '%s: phase=builder-removal status=%s elapsed_seconds=%s persists: %s\n' \
        "$label" "$status" "$((SECONDS - started))" "$(tr '\n' ',' <<<"$present" | sed 's/,$//; s/,/, /g')" >&2
      # Buildx and Docker report object names, never credential material.
      printf '%s\n' "${output:0:600}" | tr -cd '[:print:]\n' |
        sed "s/^/$label: builder-removal output: /" >&2
      return "$status"
    fi
    previous="$present"
    while read -r kind name; do
      case "$kind" in
        builder) buildx_builder_request "$docker_bin" buildx rm --force "$name" >/dev/null 2>&1 || true ;;
        container) buildx_builder_request "$docker_bin" rm --force "$name" >/dev/null 2>&1 || true ;;
        volume) buildx_builder_request "$docker_bin" volume rm "$name" >/dev/null 2>&1 || true ;;
      esac
    done <<<"$present"
  done
}

# buildx_builder_cap BUILDER gives a just-bootstrapped docker-container builder
# its CPU ceiling on the owner's workstation. buildx ignores cgroup-parent under
# systemd's cgroup driver, so the builder container lands in system.slice;
# codewire-cpu caps each buildx_buildkit_* container, but only when it runs. It
# acts only when codewire/root bin/heavy started the build (CODEWIRE_CPU_SLICE)
# and codewire-cpu is installed; CI and tests never set the variable.
buildx_builder_cap() {
  [ -n "${CODEWIRE_CPU_SLICE:-}" ] || return 0
  command -v codewire-cpu >/dev/null 2>&1 || return 0
  codewire-cpu apply >/dev/null 2>&1 ||
    echo "buildx builder $1: codewire-cpu apply failed; it runs without its CPU ceiling" >&2
}
