#!/usr/bin/env bash
# A hosted Sandbox's egress routing against a real kernel, without root
# (#4000; designs/hosted-egress.md, "The Sandbox side").
#
#   hosted-egress-routing-namespace.sh CW ROUTING_TESTS
#
# CW is a built `cw`; ROUTING_TESTS is codewire-network-session's test
# binary built with --features hosted-routing. The script re-runs itself as
# root of a new user and network namespace, with uid 1000 mapped from the
# caller's subordinate range as the workspace user, gives "eth0" the shape Cilium
# gives a Pod (a /32, a link route to its gateway, a default via it), then:
# runs `cw __hosted-egress-tun` twice (the second run changes nothing), shows
# where four kinds of packet leave, checks `verify()` passes, removes one
# rule and checks `verify()` names it.
set -euo pipefail

if [[ "${1:-}" != --inside ]]; then
  [[ $# -eq 2 ]] || { echo "usage: $0 CW ROUTING_TESTS" >&2; exit 2; }
  sub_uid="$(awk -F: -v user="$(id -un)" '$1 == user { print $2; exit }' /etc/subuid)"
  sub_gid="$(awk -F: -v user="$(id -un)" '$1 == user { print $2; exit }' /etc/subgid)"
  [[ -n "$sub_uid" && -n "$sub_gid" ]] || { echo "no subordinate uid or gid range for $(id -un)" >&2; exit 2; }
  exec unshare --user --net \
    --map-users="0:$(id -u):1" --map-users="1000:$sub_uid:1" \
    --map-groups="0:$(id -g):1" --map-groups="1000:$sub_gid:1" \
    -- "$0" --inside "$1" "$2"
fi
cw="$2"
routing_tests="$3"

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

echo
echo "=== first run"
"$cw" __hosted-egress-tun --owner-uid 1000
show

echo
echo "=== second run"
before="$(tables)"
"$cw" __hosted-egress-tun --owner-uid 1000
after="$(tables)"
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
