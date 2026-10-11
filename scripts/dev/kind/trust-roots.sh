#!/usr/bin/env bash
# Republish the retained Kind cluster's synthetic trust roots without a deploy:
#
#   KIND_CLUSTER_NAME=<cluster> make kind-trust-roots
#
# Each root renews at 72 of its 96 hours. The ConfigMaps that services and
# workspace daemons verify against then keep the current root plus the previous
# one until it expires. `make kind-deploy` does the same before each restart.
# Only public certificates are read; nothing is restarted or deployed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=scripts/dev/kind/profile.sh
source "$ROOT/scripts/dev/kind/profile.sh"
kind_profile_load "$ROOT" || exit $?
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-codewire-e2e-ci}"
# shellcheck source=scripts/ci/verify/kind/credentials.sh
source "$ROOT/scripts/ci/verify/kind/credentials.sh"

die() { printf '[kind-trust-roots] error: %s\n' "$*" >&2; exit 1; }

kind get clusters 2>/dev/null | grep -Fxq "$KIND_CLUSTER_NAME" \
  || die "cluster ${KIND_CLUSTER_NAME} does not exist"
if [ "$KIND_PROFILE" = 1 ]; then
  kind_profile_verify_node "$ROOT" || exit $?
else
  # Pin this cluster's own API endpoint; an older kubeconfig entry for the
  # same context can name a port the cluster no longer listens on.
  kubeconfig="$(mktemp "${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}/kind-trust-roots.XXXXXX")"
  trap 'rm -f "$kubeconfig"' EXIT
  kind get kubeconfig --name "$KIND_CLUSTER_NAME" >"$kubeconfig"
  export KUBECONFIG="$kubeconfig"
fi
publish_kind_trust_roots --context "kind-${KIND_CLUSTER_NAME}"
