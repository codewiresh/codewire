#!/bin/sh
# Runs as the storage-measure bench pod's optional dind container
# (--with-docker). It mirrors the commodity guest-local Docker bootstrap in
# crates/codewire-orchestration/src/sandbox/template/workspace.rs: an ext4
# image on the measured volume, loop-mounted as the Docker data root, with
# the vfs storage driver and the socket shared through an emptyDir.
set -eu

data_image="${SM_DOCKER_DATA_IMAGE:-/workspace/.codewire/docker-data.ext4}"
data_root=/var/lib/docker
data_size="${SM_DOCKER_DATA_SIZE:-8G}"
image_dir="$(dirname "$data_image")"

mkdir -p "$image_dir" "$data_root"
chown 1000:1000 "$image_dir"
chmod 0775 "$image_dir"
if [ ! -s "$data_image" ]; then
  truncate -s "$data_size" "$data_image"
  mkfs.ext4 -q -F "$data_image"
fi
if ! awk -v target="$data_root" '$2 == target && $3 == "ext4" { found = 1 } END { exit found ? 0 : 1 }' /proc/mounts; then
  mount -o loop "$data_image" "$data_root"
fi
exec dockerd --host unix:///var/run/docker/docker.sock --group 1000 \
  --data-root "$data_root" --storage-driver vfs
