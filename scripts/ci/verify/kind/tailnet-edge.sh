#!/usr/bin/env bash
# Kind's tailnet edge (tests/e2e/kind/tailnet.yaml, #3836): point the
# coordinator's DERP map at Kind's own relay. Sourced by common.sh, for a new
# cluster, and by scripts/dev/kind/deploy-service.sh, which brings a retained
# cluster to the same state.
set -euo pipefail

# The relay's address in the DERP map: the Kind node's InternalIP, port 443,
# where ingress-nginx serves TLS through its host port. The host reaches it on
# the Docker network and workspace Pods through the ingress-nginx egress their
# NetworkPolicy admits; a loopback or Service name would serve only one side.
# Its certificate is the ingress default, so the map marks the node insecure.
KIND_DERP_PORT=443

# Print the single Kind node's IPv4 InternalIP. Arguments go to kubectl first
# (a context); a cluster with other than one node is refused.
kind_derp_node_address() {
  local addresses
  addresses="$(kubectl "$@" get nodes \
    -o 'jsonpath={range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}')" \
    || return $?
  if ! [[ "$addresses" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    echo "::error::Kind's DERP relay needs one node with one IPv4 InternalIP; found: ${addresses:-none}" >&2
    return 1
  fi
  printf '%s\n' "$addresses"
}

# Set the coordinator's DERP map to Kind's relay, replacing the placeholder
# relay in tests/e2e/kind/support.yaml. Arguments: the
# namespace, then kubectl arguments (a context). Changing the environment rolls
# the coordinator; an unchanged one leaves it running.
configure_kind_coordinator_derp() {
  local namespace="$1" address
  shift
  address="$(kind_derp_node_address "$@")" || return $?
  kubectl "$@" -n "$namespace" set env deployment/codewire-coordinator --containers=coordinator \
    "DERP_HOST=${address}" "DERP_PORT=${KIND_DERP_PORT}" DERP_INSECURE=true >/dev/null || return $?
  printf '[kind-tailnet] coordinator advertises DERP relay %s:%s\n' "$address" "$KIND_DERP_PORT" >&2
}
