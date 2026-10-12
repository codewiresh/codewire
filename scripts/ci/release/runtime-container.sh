# shellcheck shell=bash
# Mounts for a pinned builder container of the local VM runtime (#2539).
#
# Sourced by build-runtime-kernel.sh and build-runtime-guest-root.sh. Every
# path is mounted at its own path. Locally each is a bind mount, read-only
# unless it is writable. A CI job runs in a container beside its Docker
# daemon, which resolves bind sources in its own namespace; with a job
# container, each path instead gets the job's volume or bind that holds it,
# and nothing else of the job (never its Docker socket).

# runtime_container_mounts JOB_CONTAINER READ_ONLY_PATH... -- WRITABLE_PATH...
# Sets RUNTIME_MOUNTS to the docker run arguments.
runtime_container_mounts() {
  local job_container="$1" path mode job_mounts best best_length type source destination mount
  local -a read_only=() writable=()
  local -A shared=()
  shift
  mode=read_only
  for path in "$@"; do
    if [ "$path" = -- ]; then
      mode=writable
    elif [ "$mode" = read_only ]; then
      read_only+=("$path")
    else
      writable+=("$path")
    fi
  done
  RUNTIME_MOUNTS=()
  if [ -z "$job_container" ]; then
    for path in ${read_only[@]+"${read_only[@]}"}; do
      RUNTIME_MOUNTS+=(--mount "type=bind,source=$path,target=$path,readonly")
    done
    for path in ${writable[@]+"${writable[@]}"}; do
      RUNTIME_MOUNTS+=(--mount "type=bind,source=$path,target=$path")
    done
    return 0
  fi
  [[ "$job_container" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || {
    echo "runtime container: --job-container is not a container name" >&2
    return 1
  }
  # Each mount's type, its source in the daemon's namespace (a volume name or
  # a path) and its destination in the job container.
  job_mounts="$(docker inspect --format '{{range .Mounts}}{{.Type}}{{"\t"}}{{if eq .Type "volume"}}{{.Name}}{{else}}{{.Source}}{{end}}{{"\t"}}{{.Destination}}{{println}}{{end}}' "$job_container")" || {
    echo "runtime container: cannot inspect container $job_container" >&2
    return 1
  }
  for path in ${read_only[@]+"${read_only[@]}"} ${writable[@]+"${writable[@]}"}; do
    best="" best_length=0
    while IFS=$'\t' read -r type source destination; do
      case "$type" in volume|bind) ;; *) continue ;; esac
      case "$destination" in /?*) ;; *) continue ;; esac
      case "$path/" in "${destination%/}/"*) ;; *) continue ;; esac
      if [ "${#destination}" -gt "$best_length" ]; then
        best="type=$type,source=$source,target=$destination" best_length="${#destination}"
      fi
    done <<<"$job_mounts"
    [ -n "$best" ] || {
      echo "runtime container: $path is not on a mount of $job_container" >&2
      return 1
    }
    shared["$best"]=1
  done
  for mount in "${!shared[@]}"; do
    RUNTIME_MOUNTS+=(--mount "$mount")
  done
}
