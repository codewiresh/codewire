#!/usr/bin/env bash
# A disposable Debian 12 machine on this Linux workstation (#4121): the clean
# box the self-hosted Compose journeys install onto, and a clean Linux host to
# try `cw host` on. QEMU with KVM and user-mode networking only: the guest's
# SSH and HTTPS ports are forwarded to 127.0.0.1, and nothing on the
# workstation's own network changes.
#
#   selfhost-vm.sh create STATE_DIR
#   selfhost-vm.sh ssh STATE_DIR [COMMAND...]
#   selfhost-vm.sh destroy STATE_DIR
#
# create makes STATE_DIR, which must not exist, and boots a copy-on-write
# overlay of the pinned Debian 12 cloud image in it. cloud-init installs
# Docker Engine and the Compose plugin from Docker's repository, after
# checking its signing key, and tcpdump, which lets a journey see every DNS
# query the guest sends. The guest keeps QEMU's clock, so its NTP client is
# masked, and it sends no NTP, LLMNR or mDNS traffic. create returns once
# cloud-init has finished, and prints the forwarded ports. The overlay grows
# to at most 40 GiB, so keep STATE_DIR out of /tmp. The verified base image is
# cached in CODEWIRE_SELFHOST_VM_CACHE (default
# ~/.cache/codewire-selfhost-vm).
#
# ssh runs COMMAND, or a login shell, as the guest's `debian` user, who has
# passwordless sudo and is in the docker group.
#
# destroy stops the QEMU process this STATE_DIR started, and no other, then
# removes STATE_DIR. It refuses a directory that create did not make, and a
# recorded PID that is now another process.
#
# Exit status: 0 done; 1 a step failed; 64 usage or a refused argument.
set -euo pipefail

readonly IMAGE_RELEASE=20261026-2643
readonly IMAGE_NAME="debian-12-genericcloud-amd64-$IMAGE_RELEASE.qcow2"
readonly IMAGE_URL="https://cloud.debian.org/images/cloud/bookworm/$IMAGE_RELEASE/$IMAGE_NAME"
readonly IMAGE_SHA512=0464b5d4ae3aa4f658468d88da83af7857b71548b30d46dcb6282770955a747fb95a983476db90d25afd0653af607224c7ebd05122ab71faa106fd712aaad652
# Docker's Debian repository signing key ("Docker Release (CE deb)").
readonly DOCKER_KEY_FINGERPRINT=9DC858229FC7DD38854AE2D88D81803C0EBFCD88
readonly MARKER=selfhost-vm.state
readonly DISK_SIZE=40G
readonly VCPUS=4
readonly MEMORY_MIB=8192
readonly BOOT_TIMEOUT_SECONDS=180
readonly CLOUD_INIT_TIMEOUT_SECONDS=900
readonly STOP_TIMEOUT_SECONDS=30

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
CACHE_DIR="${CODEWIRE_SELFHOST_VM_CACHE:-$HOME/.cache/codewire-selfhost-vm}"
readonly CACHE_DIR
# The state directory of a VM create has started, so a later failure says how
# to remove it.
STARTED_STATE=''
SSH_ARGS=()

usage() {
  echo "usage: $0 create STATE_DIR | ssh STATE_DIR [COMMAND...] | destroy STATE_DIR" >&2
  exit 64
}

refuse() {
  echo "selfhost-vm: $1" >&2
  exit 64
}

fail() {
  echo "selfhost-vm: $1" >&2
  if [ -n "$STARTED_STATE" ]; then
    echo "selfhost-vm: the VM is still running; remove it with: $0 destroy $STARTED_STATE" >&2
  fi
  exit 1
}

# The setting NAME from STATE_DIR/ports, written by create.
port_setting() {
  local value
  value="$(sed -n "s/^$2=\\([0-9][0-9]*\\)\$/\\1/p" "$1/ports")"
  [ -n "$value" ] || fail "$1/ports has no $2"
  printf '%s\n' "$value"
}

# A TCP port on 127.0.0.1 that nothing listens on now.
free_port() {
  python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

# The verified base image's path, downloading it into the cache when missing.
base_image() {
  local image="$CACHE_DIR/$IMAGE_NAME" partial
  mkdir -p "$CACHE_DIR"
  if [ ! -f "$image" ]; then
    partial="$(mktemp "$CACHE_DIR/.download.XXXXXX")"
    echo "selfhost-vm: downloading $IMAGE_URL" >&2
    curl -fsSL --retry 3 -o "$partial" "$IMAGE_URL" || {
      rm -f -- "$partial"
      fail "the download of $IMAGE_URL failed"
    }
    if ! printf '%s  %s\n' "$IMAGE_SHA512" "$partial" | sha512sum --check --status; then
      rm -f -- "$partial"
      fail "$IMAGE_URL does not match its pinned SHA512"
    fi
    mv -- "$partial" "$image"
  fi
  printf '%s\n' "$image"
}

# cloud-init's user-data for the guest: the debian user with this VM's key,
# Docker from Docker's repository after checking its key, and tcpdump. The
# guest keeps QEMU's clock, so its NTP client is masked, and systemd-resolved
# sends no LLMNR or mDNS: every such request would leave the workstation as
# QEMU's own traffic, and an application firewall would ask about each one.
user_data() {
  cat <<EOF
#cloud-config
hostname: selfhost
bootcmd:
  - [systemctl, mask, --now, systemd-timesyncd.service, chrony.service]
  - [sh, -c, 'mkdir -p /etc/systemd/resolved.conf.d && printf "[Resolve]\nLLMNR=no\nMulticastDNS=no\n" >/etc/systemd/resolved.conf.d/90-no-multicast.conf && systemctl try-restart systemd-resolved.service']
users:
  - name: debian
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: true
    ssh_authorized_keys:
      - $1
ssh_pwauth: false
package_update: true
packages: [ca-certificates, curl, gnupg, tcpdump]
write_files:
  - path: /usr/local/sbin/install-docker
    permissions: "0755"
    content: |
      #!/bin/sh
      set -eu
      curl -fsSL https://download.docker.com/linux/debian/gpg -o /run/docker.asc
      fingerprint="\$(gpg --show-keys --with-colons /run/docker.asc | awk -F: '\$1 == "fpr" { print \$10; exit }')"
      if [ "\$fingerprint" != "$DOCKER_KEY_FINGERPRINT" ]; then
        echo "install-docker: unexpected Docker signing key \$fingerprint" >&2
        exit 1
      fi
      install -m 0755 -d /etc/apt/keyrings
      install -m 0644 /run/docker.asc /etc/apt/keyrings/docker.asc
      echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" \\
        >/etc/apt/sources.list.d/docker.list
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y \\
        docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
      usermod -aG docker debian
runcmd:
  - [/usr/local/sbin/install-docker]
EOF
}

# Set SSH_ARGS to the ssh options that reach the guest of STATE_DIR; the
# destination, debian@127.0.0.1, follows them.
ssh_args() {
  SSH_ARGS=(-i "$1/id_ed25519" -p "$(port_setting "$1" ssh_port)"
    -o IdentitiesOnly=yes -o BatchMode=yes -o LogLevel=ERROR
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$1/known_hosts")
}

create() {
  local state="$1" parent image ssh_port https_port deadline
  [ ! -e "$state" ] || refuse "$state already exists"
  parent="$(cd -- "$(dirname -- "$state")" && pwd -P)" || refuse "the parent of $state does not exist"
  state="$parent/$(basename -- "$state")"
  case "$state" in
  /tmp/*) refuse "$state is under /tmp, a shared memory-backed tmpfs; use a directory under ~/.cache" ;;
  esac
  [ -w /dev/kvm ] || fail "/dev/kvm is not writable by this user"
  for tool in qemu-system-x86_64 qemu-img xorriso ssh ssh-keygen curl python3; do
    command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed"
  done
  image="$(base_image)"

  mkdir -- "$state"
  printf 'selfhost-vm %s\n' "$IMAGE_NAME" >"$state/$MARKER"
  ssh-keygen -q -t ed25519 -N '' -C selfhost-vm -f "$state/id_ed25519"
  user_data "$(cat "$state/id_ed25519.pub")" >"$state/user-data"
  printf 'instance-id: selfhost-%s\nlocal-hostname: selfhost\n' \
    "$(od -An -tx1 -N8 /dev/urandom | tr -d ' \n')" >"$state/meta-data"
  xorriso -as mkisofs -quiet -output "$state/seed.iso" -volid cidata -joliet -rock \
    "$state/user-data" "$state/meta-data"
  qemu-img create -q -f qcow2 -F qcow2 -b "$image" "$state/disk.qcow2" "$DISK_SIZE"

  ssh_port="$(free_port)"
  https_port="$(free_port)"
  printf 'ssh_port=%s\nhttps_port=%s\n' "$ssh_port" "$https_port" >"$state/ports"

  # shellcheck source=scripts/dev/cpu-slice.sh
  . "$SCRIPT_DIRECTORY/cpu-slice.sh"
  cpu_slice_enter selfhost-vm
  qemu-system-x86_64 \
    -name selfhost-vm -machine q35,accel=kvm -cpu host -smp "$VCPUS" -m "$MEMORY_MIB" \
    -drive "if=virtio,format=qcow2,file=$state/disk.qcow2" \
    -drive "if=virtio,format=raw,readonly=on,file=$state/seed.iso" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$ssh_port-:22,hostfwd=tcp:127.0.0.1:$https_port-:443" \
    -device virtio-net-pci,netdev=net0 \
    -display none -serial "file:$state/console.log" \
    -daemonize -pidfile "$state/qemu.pid"
  STARTED_STATE="$state"

  ssh_args "$state"
  deadline=$((SECONDS + BOOT_TIMEOUT_SECONDS))
  until ssh "${SSH_ARGS[@]}" -o ConnectTimeout=5 debian@127.0.0.1 true 2>/dev/null; do
    [ "$SECONDS" -lt "$deadline" ] ||
      fail "no SSH from the guest after ${BOOT_TIMEOUT_SECONDS}s; see $state/console.log"
    sleep 2
  done
  if ! ssh "${SSH_ARGS[@]}" debian@127.0.0.1 \
    timeout "$CLOUD_INIT_TIMEOUT_SECONDS" cloud-init status --wait >/dev/null; then
    ssh "${SSH_ARGS[@]}" debian@127.0.0.1 cloud-init status --long >&2 || true
    fail "cloud-init did not finish cleanly; see $state/console.log, or ssh in and read /var/log/cloud-init-output.log"
  fi
  printf 'selfhost-vm: ready in %s\n' "$state"
  printf '  ssh:   %s ssh %s\n' "$0" "$state"
  printf '  https: 127.0.0.1:%s forwards to the guest port 443\n' "$https_port"
}

ssh_command() {
  local state="$1"
  shift
  [ -f "$state/$MARKER" ] || refuse "$state was not made by selfhost-vm create"
  ssh_args "$state"
  if [ "$#" -eq 0 ]; then
    exec ssh "${SSH_ARGS[@]}" -t debian@127.0.0.1
  fi
  exec ssh "${SSH_ARGS[@]}" debian@127.0.0.1 "$@"
}

# Whether PID is a process that has not exited. A zombie has: it lingers only
# until its parent reaps it, which a container without an init never does.
running() {
  local state
  state="$(sed -n 's/^.*) \(.\).*$/\1/p' "/proc/$1/stat" 2>/dev/null)" || return 1
  [ -n "$state" ] && [ "$state" != Z ]
}

destroy() {
  local state="$1" pid='' deadline
  [ -f "$state/$MARKER" ] || refuse "$state was not made by selfhost-vm create"
  state="$(cd -- "$state" && pwd -P)"
  if [ -f "$state/qemu.pid" ]; then
    pid="$(tr -cd '0-9' <"$state/qemu.pid")"
  fi
  if [ -n "$pid" ] && running "$pid"; then
    # A recorded PID names this VM only while its command line names this
    # directory's disk; after a reboot or exit it may be anything.
    if ! tr '\0' '\n' <"/proc/$pid/cmdline" | grep -Fxq -- "if=virtio,format=qcow2,file=$state/disk.qcow2"; then
      refuse "PID $pid in $state/qemu.pid is not this VM's QEMU; nothing stopped or removed"
    fi
    kill -- "$pid"
    deadline=$((SECONDS + STOP_TIMEOUT_SECONDS))
    while running "$pid"; do
      [ "$SECONDS" -lt "$deadline" ] || fail "QEMU PID $pid did not stop within ${STOP_TIMEOUT_SECONDS}s"
      sleep 1
    done
  fi
  rm -rf -- "$state"
  printf 'selfhost-vm: destroyed %s\n' "$state"
}

[ "$#" -ge 2 ] || usage
command="$1"
state_dir="$2"
shift 2
case "$command" in
create)
  [ "$#" -eq 0 ] || usage
  create "$state_dir"
  ;;
ssh) ssh_command "$state_dir" "$@" ;;
destroy)
  [ "$#" -eq 0 ] || usage
  destroy "$state_dir"
  ;;
*) usage ;;
esac
