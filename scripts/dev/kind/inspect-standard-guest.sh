#!/usr/bin/env bash
# Inspect a Kind standard/broker-mode Sandbox's network and binding state
# (#6387, #5602): prints Pod-side vsock guest-daemon logs, Pod-side roots,
# cw-egress admission lines, and (when reachable via `cw exec`) in-VM routes,
# policy rules, /etc/resolv.conf, hosted mounts, and public CA root metadata.
#
# Value-blind: prints only file metadata (mode/owner/size) and public X.509
# certificate fields (subject/issuer/dates/fingerprint), never token contents
# or environment variable values.
#
# usage:
#   CLUSTER=<profile> scripts/dev/kind/inspect-standard-guest.sh <env-id-or-name>
#   KIND_CLUSTER_NAME=<cluster> CW_BIN=/path/to/cw scripts/dev/kind/inspect-standard-guest.sh <env-id-or-name>
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=scripts/dev/kind/profile.sh
source "$ROOT/scripts/dev/kind/profile.sh"
kind_profile_load "$ROOT" || exit $?
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-codewire-e2e-ci}"
NS="${NS:-codewire-e2e}"
SANDBOX_NS="${SANDBOX_NS:-dev-sandboxes}"
TARGET="${1:-}"
[ -n "$TARGET" ] || {
  echo "usage: $0 <environment-id-or-name>" >&2
  exit 2
}

CW_BIN="${CW_BIN:-}"
if [ -z "$CW_BIN" ]; then
  for candidate in "${CARGO_CI_DIR:-}/cw" "$ROOT/target/debug/cw" "$(command -v cw 2>/dev/null || true)"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
      CW_BIN="$candidate"
      break
    fi
  done
fi

kube() { kubectl --context "kind-${KIND_CLUSTER_NAME}" --request-timeout=15s "$@"; }

pod_name="$(kube -n "$SANDBOX_NS" get pods -l "codewire.sh/environment-id=${TARGET}" \
  -o 'jsonpath={.items[0].metadata.name}' 2>/dev/null || true)"
if [ -z "$pod_name" ]; then
  pod_name="$(kube -n "$SANDBOX_NS" get pods -o json 2>/dev/null \
    | jq -r --arg t "$TARGET" '.items[] | select(.metadata.name == $t or .metadata.labels["codewire.sh/environment-name"] == $t) | .metadata.name' \
    | head -n 1)"
fi

echo "=== Kind Standard/Broker Guest Diagnostics (${TARGET}) ==="
if [ -n "$pod_name" ]; then
  pod_uid="$(kube -n "$SANDBOX_NS" get pod "$pod_name" -o 'jsonpath={.metadata.uid}')"
  runtime_class="$(kube -n "$SANDBOX_NS" get pod "$pod_name" -o 'jsonpath={.spec.runtimeClassName}')"
  egress_label="$(kube -n "$SANDBOX_NS" get pod "$pod_name" -o 'jsonpath={.metadata.labels.codewire\.sh/egress}')"
  phase="$(kube -n "$SANDBOX_NS" get pod "$pod_name" -o 'jsonpath={.status.phase}')"
  echo "pod=${SANDBOX_NS}/${pod_name} uid=${pod_uid} phase=${phase} runtimeClass=${runtime_class:-default} egress=${egress_label:-none}"

  echo "--- Pod-side vsock guest-daemon and pod-runtime logs (tail 80) ---"
  kube -n "$SANDBOX_NS" logs "pod/${pod_name}" -c workspace --tail=80 2>&1 || true

  echo "--- cw-egress logs matching Pod UID ${pod_uid} ---"
  kube -n "$NS" logs daemonset/codewire-egress --tail=300 2>&1 | grep -F "$pod_uid" || echo "(no error/event cw-egress lines for ${pod_uid})"

  pg_pod="$(kube -n "$NS" get pods --no-headers 2>/dev/null | awk '/postgres/{print $1; exit}')"
  if [ -n "$pg_pod" ]; then
    echo "--- orchestration egress enforcement row for ${pod_uid} ---"
    kube -n "$NS" exec "$pg_pod" -- psql -U codewire -d codewire -c \
      "SELECT pod_uid, environment_id, node, state, revision, detail, lockdown_refusal, reported_at FROM sandbox_egress_enforcement WHERE pod_uid = '${pod_uid}';" 2>&1 || true
  fi

  echo "--- Pod-side binding/coordinator root mounts (public metadata only) ---"
  kube -n "$SANDBOX_NS" exec "pod/${pod_name}" -c workspace -- sh -c '
    for p in /run/codewire-orchestration-internal-roots /run/codewire-coordinator-extra-roots /var/run/secrets/codewire /codewire/run; do
      [ -e "$p" ] && ls -la "$p" 2>&1 || echo "missing: $p"
    done
    for crt in /run/codewire-orchestration-internal-roots/ca.crt /run/codewire-coordinator-extra-roots/ca.crt; do
      if [ -r "$crt" ]; then
        echo "cert $crt bytes=$(wc -c <"$crt")"
        command -v openssl >/dev/null 2>&1 && openssl x509 -in "$crt" -noout -subject -issuer -dates -fingerprint -sha256 2>&1 || true
      fi
    done
  ' 2>&1 || echo "(Pod-side exec unavailable)"
else
  echo "pod: not found in ${SANDBOX_NS} for ${TARGET}"
fi

if [ -n "$CW_BIN" ] && [ -x "$CW_BIN" ]; then
  echo "--- Guest-side network, hosted mounts, and binding roots via cw exec ---"
  cw_env=()
  if [ -n "${CW_CLI_HOME:-}" ]; then
    cw_env=(
      "HOME=${CW_CLI_HOME}"
      "XDG_CONFIG_HOME=${CW_CLI_HOME}/config"
      "XDG_DATA_HOME=${CW_CLI_HOME}/data"
      "XDG_CACHE_HOME=${CW_CLI_HOME}/cache"
      "CW_CONFIG_DIR=${CW_CLI_HOME}/cw"
    )
  fi
  env "${cw_env[@]}" "$CW_BIN" exec --cloud --in "$TARGET" -- sh -c '
    echo "[ip addr]"
    ip -br addr 2>&1 || true
    echo "[ip route show table all]"
    ip route show table all 2>&1 || true
    echo "[ip rule]"
    ip rule show 2>&1 || true
    echo "[resolv.conf]"
    cat /etc/resolv.conf 2>&1 || true
    echo "[hosted paths (metadata only, value-blind)]"
    for p in /run/codewire/hosted /run/codewire-hosted /run/codewire-orchestration-internal-roots /run/codewire-coordinator-extra-roots /var/run/secrets/codewire /codewire/run /dev/net; do
      if [ -e "$p" ]; then
        echo "-- $p --"
        ls -la "$p" 2>&1 || true
      else
        echo "-- $p: absent --"
      fi
    done
    echo "[binding and coordinator public CA roots]"
    for crt in /run/codewire-orchestration-internal-roots/ca.crt /run/codewire-coordinator-extra-roots/ca.crt /run/codewire/hosted/binding-roots/ca.crt /run/codewire/hosted/coordinator-roots/ca.crt; do
      if [ -r "$crt" ]; then
        echo "cert $crt bytes=$(wc -c <"$crt")"
        command -v openssl >/dev/null 2>&1 && openssl x509 -in "$crt" -noout -subject -issuer -dates -fingerprint -sha256 2>&1 || true
      fi
    done
  ' 2>&1 || echo "(guest cw exec unavailable)"
else
  echo "(cw binary not found; set CW_BIN to inspect inside the VM)"
fi
