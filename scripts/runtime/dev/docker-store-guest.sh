#!/bin/sh
# Guest-only stages shared by normal commodity acceptance and the disk journey.
# Sourced into a managed cw session; never connects to the host Docker socket.

docker_store_fail() { printf 'docker-store: %s\n' "$*" >&2; exit 1; }

docker_store_backend() {
  test "${DOCKER_HOST:-}" = unix:///var/run/docker/docker.sock || docker_store_fail 'unexpected Docker endpoint'
  test "$(docker context show)" = default || docker_store_fail 'unexpected Docker context'
  driver=$(docker info --format '{{.Driver}}')
  case "$ds_mode:$driver" in
    containerd:overlayfs)
      snapshotter=$(docker info --format '{{range .DriverStatus}}{{if eq (index . 0) "driver-type"}}{{index . 1}}{{end}}{{end}}')
      test "$snapshotter" = io.containerd.snapshotter.v1 || docker_store_fail 'overlayfs is not the containerd image store'
      test "$(docker info --format '{{.DockerRootDir}}')" = /var/lib/docker || docker_store_fail 'unexpected Docker data root'
      ;;
    *) docker_store_fail "expected $ds_mode store, observed $driver" ;;
  esac
  printf 'docker-store backend=%s driver=%s\n' "$ds_mode" "$driver"
}

docker_store_limits() {
  # A quota read alone is insufficient: saturate it and observe throttling.
  docker run --rm --network none --cpus .25 --memory 64m --memory-swap 64m --pids-limit 32 "$ds_base" sh -ec '
    test "$(cat /sys/fs/cgroup/cpu.max)" = "25000 100000"
    test "$(cat /sys/fs/cgroup/memory.max)" = 67108864
    test "$(cat /sys/fs/cgroup/pids.max)" = 32
    before=$(awk "\$1 == \"nr_throttled\" {print \$2}" /sys/fs/cgroup/cpu.stat)
    (while :; do :; done) & a=$!
    (while :; do :; done) & b=$!
    sleep 3
    kill "$a" "$b"; wait "$a" 2>/dev/null || :; wait "$b" 2>/dev/null || :
    after=$(awk "\$1 == \"nr_throttled\" {print \$2}" /sys/fs/cgroup/cpu.stat)
    test "$after" -gt "$before"
    printf "cpu-throttling-observed\n"
  '
  # A bounded tmpfs allocation must be killed by the memory controller.
  rc=0
  docker run --name "$ds_oom" --network none --cpus .5 --memory 32m --memory-swap 32m --pids-limit 32 \
    --tmpfs /pressure:rw,size=96m "$ds_base" sh -ec 'exec dd if=/dev/zero of=/pressure/blob bs=1M count=80' >/dev/null 2>&1 || rc=$?
  test "$rc" = 137 || docker_store_fail "memory pressure exited $rc, expected OOM137"
  test "$(docker inspect -f '{{.State.OOMKilled}}' "$ds_oom")" = true || docker_store_fail 'memory limit did not report OOMKilled'
  docker rm "$ds_oom" >/dev/null
  # This creates at most 32 tasks; pids.events must record an actual refusal.
  docker run --rm --network none --cpus .5 --memory 64m --memory-swap 64m --pids-limit 32 "$ds_base" sh -ec '
    test "$(cat /sys/fs/cgroup/pids.max)" = 32
    (for n in $(seq 1 40); do sleep 2 & done; wait) || :
    max=0
    while read -r key value; do test "$key" != max || max=$value; done < /sys/fs/cgroup/pids.events
    test "$max" -gt 0
    printf "pids-denial-observed\n"
  '
  printf 'docker-store resource-enforcement-passed\n'
}

docker_store_managed_root_script() {
  cat <<'CHECK'
root_type=$(stat -f -c %T / 2>/dev/null) || root_type=unavailable
root_magic=$(stat -f -c %t / 2>/dev/null) || root_magic=unavailable
managed_magic=$(stat -f -c %t /managed-store 2>/dev/null) || managed_magic=unavailable
snapshotter_directory=false
if test -d /managed-store/io.containerd.snapshotter.v1.overlayfs; then snapshotter_directory=true; fi
marker_matches=false
if printf 'containerd-overlayfs-v1\n' | cmp -s - /store-version; then marker_matches=true; fi
printf 'docker-store managed-root root-type=%s root-magic=%s managed-magic=%s snapshotter-directory=%s marker-match=%s\n' "$root_type" "$root_magic" "$managed_magic" "$snapshotter_directory" "$marker_matches"
# Linux UAPI linux/magic.h defines OVERLAYFS_SUPER_MAGIC as 0x794c7630.
# Older BusyBox filesystem-name tables may report UNKNOWN for this magic.
test "$root_magic" = 794c7630 || { printf 'docker-store: container root is not overlayfs\n' >&2; exit 1; }
test "$managed_magic" = ef53 || { printf 'docker-store: managed containerd root is not ext4\n' >&2; exit 1; }
test "$snapshotter_directory" = true || { printf 'docker-store: managed containerd overlayfs directory absent\n' >&2; exit 1; }
test "$marker_matches" = true || { printf 'docker-store: Docker format marker mismatch\n' >&2; exit 1; }
CHECK
}

docker_store_seed() {
  mkdir -p "$ds_work"
  docker pull "$ds_base" >/dev/null
  printf 'FROM %s\nRUN mkdir /retained && echo lower > /retained/lower && echo delete-me > /retained/deleted\nENTRYPOINT ["sh"]\n' "$ds_base" > "$ds_work/Dockerfile"
  docker build --network none -q -t "$ds_image" "$ds_work" >/dev/null
  docker image inspect -f '{{.Id}}' "$ds_image" > "$ds_work/image.id"
  docker save -o "$ds_work/image.tar" "$ds_image"
  (cd "$ds_work" && sha256sum image.tar > image.sha256)
  docker image rm "$ds_image" >/dev/null
  docker load -i "$ds_work/image.tar" >/dev/null
  test "$(docker image inspect -f '{{.Id}}' "$ds_image")" = "$(cat "$ds_work/image.id")" || docker_store_fail 'save/load changed image identity'
  printf 'docker-store custody image=%s archive=%s\n' "$(cat "$ds_work/image.id")" "$(cut -d ' ' -f 1 "$ds_work/image.sha256")"
  if test "$ds_mode" = containerd; then
    docker run --rm --network none --cpus .5 --memory 64m --memory-swap 64m --pids-limit 32 \
      --mount type=bind,src=/var/lib/docker/containerd/daemon,dst=/managed-store,readonly \
      --mount type=bind,src=/var/lib/docker/.codewire-containerd-store-v1,dst=/store-version,readonly \
      "$ds_image" -ec "$(docker_store_managed_root_script)"
    printf 'docker-store managed-containerd-root-on-ext4-passed\n'
  fi
  docker volume create "$ds_volume" >/dev/null
  docker run --name "$ds_container" --network none --cpus .5 --memory 64m --memory-swap 64m --pids-limit 32 \
    -v "$ds_volume:/data" "$ds_image" -ec 'echo copy-up > /retained/lower; rm /retained/deleted; echo writable > /retained/upper; echo volume > /data/marker'
  docker_store_verify original
  printf 'docker-store build-run-save-reload-custody-passed\n'
}

docker_store_verify() {
  expected=$1
  docker_store_backend
  (cd "$ds_work" && sha256sum -c image.sha256)
  test "$(docker image inspect -f '{{.Id}}' "$ds_image")" = "$(cat "$ds_work/image.id")" || docker_store_fail 'retained image identity changed'
  test "$(docker inspect -f '{{.Image}}' "$ds_container")" = "$(cat "$ds_work/image.id")" || docker_store_fail 'retained container changed image'
  docker cp "$ds_container:/retained" "$ds_work/check"
  test "$(cat "$ds_work/check/lower")" = copy-up
  test ! -e "$ds_work/check/deleted"
  expected_upper=writable
  test "$expected" != fork || expected_upper=fork
  test "$(cat "$ds_work/check/upper")" = "$expected_upper"
  rm -rf "$ds_work/check"
  docker run --rm --network none --cpus .5 --memory 64m --memory-swap 64m --pids-limit 32 \
    -v "$ds_volume:/data" "$ds_image" -ec "test \"\$(cat /data/marker)\" = $(test "$expected" = fork && echo fork || echo volume); test \"\$(cat /retained/lower)\" = lower; test -f /retained/deleted"
  printf 'docker-store retained-image-layer-volume-passed %s\n' "$expected"
}

docker_store_cleanup() {
  docker rm -f "$ds_container" "$ds_oom" >/dev/null 2>&1 || :
  docker volume rm "$ds_volume" >/dev/null 2>&1 || :
  docker image rm "$ds_image" >/dev/null 2>&1 || :
  rm -rf "$ds_work"
}

docker_store_guest() {
  action=$1; ds_id=$2; ds_mode=$3
  case "$ds_id" in ''|*[!a-z0-9]*) docker_store_fail 'invalid fixture identity' ;; esac
  case "$ds_mode" in containerd) ;; *) docker_store_fail 'invalid expected store' ;; esac
  ds_base='registry.k8s.io/e2e-test-images/busybox@sha256:caec39cad3b12c26600baf6e67ba811ac15d28a9288d0ccdfffb4b318992c3bb'
  ds_work="/workspace/.codewire/docker-journey-$ds_id"
  ds_image="codewire-docker-journey:$ds_id"
  ds_container="cw-docker-layer-$ds_id"; ds_volume="cw-docker-volume-$ds_id"; ds_oom="cw-docker-oom-$ds_id"
  case "$action" in
    core)
      docker_store_backend
      docker_store_seed
      docker_store_limits
      docker_store_cleanup
      ;;
    seed) docker_store_backend; docker_store_seed ;;
    verify) docker_store_verify original ;;
    fork-write)
      docker run --rm --network none --cpus .5 --memory 64m --memory-swap 64m --pids-limit 32 -v "$ds_volume:/data" "$ds_image" -ec 'echo fork > /data/marker'
      printf 'fork\n' > "$ds_work/fork-marker"
      docker cp "$ds_work/fork-marker" "$ds_container:/retained/upper"
      docker_store_verify fork
      ;;
    cleanup) docker_store_cleanup ;;
    *) docker_store_fail 'unknown guest stage' ;;
  esac
}
