#!/usr/bin/env bash
# A hosted Sandbox's egress setup against a real kernel (#4000;
# docs/dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md, "Hosted Egress Setup").
#
#   hosted-egress-routing-namespace.sh CW ROUTING_TESTS
#
# CW is a built `cw`; ROUTING_TESTS is codewire-network-session's test
# binary built with --features hosted-routing.
#
# The init makes the TUN's device node, which no user namespace may do, so
# the script re-runs itself through `sudo -n` as root of a new network and
# mount namespace. It mounts a 1 MiB tmpfs over /dev/net in that mount
# namespace only, as the Pod's egress-devnet volume is, and refuses to run
# the init unless that tmpfs is there, so the host's /dev/net/tun is never
# touched. It then gives "eth0" the shape Cilium gives a Pod (a /32, a link
# route to its gateway, a default via it), and:
# - runs `cw __hosted-egress-tun` twice, first over a planted symbolic link
#   and then over a planted node of another device, and checks the node is
#   made afresh each time as 10:200, mode 0600, owned by uid 1000, the link's
#   target untouched, and that the second run changes no routing;
# - shows where four kinds of packet leave;
# - checks `verify()` passes, removes one rule, and checks `verify()` names
#   it.
set -euo pipefail

if [[ "${1:-}" != --inside ]]; then
  [[ $# -eq 2 ]] || { echo "usage: $0 CW ROUTING_TESTS" >&2; exit 2; }
  exec sudo -n unshare --net --mount --propagation private -- "$0" --inside "$1" "$2"
fi
cw="$2"
routing_tests="$3"

mount -t tmpfs -o size=1m,mode=0755 egress-devnet /dev/net
[[ "$(findmnt -n -o FSTYPE,SOURCE --mountpoint /dev/net)" == "tmpfs egress-devnet" ]] ||
  { echo "/dev/net is not this script's tmpfs; refusing to run the init" >&2; exit 1; }

# Documentation addresses: the Pod's own and its gateway as Cilium sets them.
pod_address=10.244.1.23
pod_gateway=169.254.1.1
platform_peer=10.44.0.87
public=198.51.100.7

# Table 1000 does not exist until the first run makes it.
pod_table() { ip route show table 1000 2>/dev/null || echo "(no table 1000)"; }
# `linkdown` is the TUN's carrier, up only while a process holds it open:
# state, not routing, so the before-and-after comparison leaves it out.
tables() { { ip rule; ip route; pod_table; } | sed 's/ linkdown//'; }
show() {
  echo "--- ip rule"; ip rule
  echo "--- ip route"; ip route
  echo "--- ip route show table 1000"; pod_table
  echo "--- cwegress0"
  if ip link show cwegress0 >/dev/null 2>&1; then
    ip -4 -brief addr show cwegress0; ip -brief link show cwegress0
  else
    echo "(no cwegress0)"
  fi
  echo "--- disable_ipv6 all, default: $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6), $(cat /proc/sys/net/ipv6/conf/default/disable_ipv6)"
}
verify() {
  "$routing_tests" --ignored --exact hosted::routing::tests::this_namespace_verifies --quiet 2>&1 \
    | grep -E 'test result|panicked|Readback|called' || true
}

echo "kernel $(uname -r)"
ip link set lo up
ip link add eth0 type veth peer name gateway0
ip addr add "$pod_address/32" dev eth0
ip link set eth0 up
ip link set gateway0 up
ip route add "$pod_gateway" dev eth0 scope link
ip route add default via "$pod_gateway" dev eth0
echo "=== the Pod as Cilium makes it"
show

node() { stat -c '%F %Hr:%Lr %a %u' /dev/net/tun; }

echo
echo "=== first run, over a planted symbolic link"
# The workspace can write /dev/net, so the init must replace, never follow.
echo kept >/dev/net/kept
ln -s /dev/net/kept /dev/net/tun
"$cw" __hosted-egress-tun --owner-uid 1000
show
echo "--- /dev/net/tun: $(node)"
[[ "$(node)" == "character special file 10:200 600 1000" ]] || { echo "the node is wrong" >&2; exit 1; }
[[ "$(cat /dev/net/kept)" == kept && ! -L /dev/net/kept ]] || { echo "the link's target changed" >&2; exit 1; }
echo "--- the link's target: unchanged"

echo
echo "=== second run, over a planted node of another device (1:3, /dev/null's)"
rm /dev/net/tun
mknod -m 0666 /dev/net/tun c 1 3
before="$(tables)"
"$cw" __hosted-egress-tun --owner-uid 1000
after="$(tables)"
echo "--- /dev/net/tun: $(node)"
[[ "$(node)" == "character special file 10:200 600 1000" ]] || { echo "the node is wrong" >&2; exit 1; }
if [[ "$after" == "$before" ]]; then
  echo "nothing changed"
else
  echo "CHANGED:"
  diff <(echo "$before") <(echo "$after") || true
  exit 1
fi

echo
echo "=== where packets leave"
echo "unbound, to a public address:      $(ip route get "$public" | head -1)"
echo "bound to eth0, to a platform peer: $(ip route get "$platform_peer" oif eth0 | head -1)"
echo "UDP from source port 31000:        $(ip route get "$public" ipproto udp sport 31000 | head -1)"
echo "TCP from source port 31000:        $(ip route get "$public" ipproto tcp sport 31000 | head -1)"
echo "from eth0's address (a reply):     $(ip route get "$public" from "$pod_address" | head -1)"

echo
echo "=== verify() as configured"
verify
echo
echo "=== verify() after the Pod-interface rule is removed"
ip rule del priority 1001
verify
