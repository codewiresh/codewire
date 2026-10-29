#!/usr/bin/env bash
# run-in-public-netns.sh ADDRESS -- COMMAND...: runs COMMAND in a private
# network namespace (unshare -rn) whose loopback interface is up and also
# holds the public IPv4 ADDRESS, with CODEWIRE_TEST_HOST_ADDRESS=ADDRESS.
# Nothing in the namespace reaches the host network, so ADDRESS may be any
# public address. Tests that need a host interface holding a public address
# run this way (native_egress_broker's #2614 refusal). The address is added
# with iproute2 where it is installed and with the SIOCSIFADDR ioctl on a lo
# alias otherwise (CI's images carry python3, not iproute2). It fails when no
# namespace can be made: such a test must not pass by not running.
set -euo pipefail

die() {
  printf '[run-in-public-netns] ERROR: %s\n' "$*" >&2
  exit 1
}

[ "$#" -ge 3 ] && [ "$2" = -- ] || die 'usage: run-in-public-netns.sh ADDRESS -- COMMAND...'
address="$1"
shift 2
[[ "$address" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "not an IPv4 address: $address"

if [ "${CODEWIRE_PUBLIC_NETNS:-}" != inside ]; then
  command -v unshare >/dev/null 2>&1 || die 'unshare (util-linux) is required'
  exec unshare -rn env CODEWIRE_PUBLIC_NETNS=inside "$0" "$address" -- "$@"
fi

if command -v ip >/dev/null 2>&1; then
  ip link set lo up
  ip addr add "$address/32" dev lo
else
  python3 -I - "$address" <<'PYTHON'
import fcntl
import socket
import struct
import sys

SIOCGIFFLAGS, SIOCSIFFLAGS, SIOCSIFADDR = 0x8913, 0x8914, 0x8916
IFF_UP, IFF_RUNNING = 0x1, 0x40
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    flags = struct.unpack('16sH', fcntl.ioctl(sock, SIOCGIFFLAGS, struct.pack('16sH', b'lo', 0))[:18])[1]
    fcntl.ioctl(sock, SIOCSIFFLAGS, struct.pack('16sH', b'lo', flags | IFF_UP | IFF_RUNNING))
    address = struct.pack('HH4s8s', socket.AF_INET, 0, socket.inet_aton(sys.argv[1]), b'\0' * 8)
    fcntl.ioctl(sock, SIOCSIFADDR, struct.pack('16s16s', b'lo:1', address))
PYTHON
fi
CODEWIRE_TEST_HOST_ADDRESS="$address" exec "$@"
