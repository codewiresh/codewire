#!/usr/bin/env bash
# Gives a local Kind cluster's billing Dev's Stripe test-mode keys, for a walk
# of the console's card form with Stripe's test cards (#4750), and takes them
# away again.
#
#   scripts/dev/kind/kind-stripe-test-keys.sh apply|remove
#
# apply reads STRIPE_SECRET_KEY and STRIPE_PUBLISHABLE_KEY from Dev's runtime
# document in OpenBao, as sync-local-secrets.sh reads its key, refuses
# anything but test-mode keys, and pipes them into one Secret,
# codewire-kind-stripe. It then points billing at it with explicit env
# entries, which win over the dummy key billing's envFrom carries, and sets
# CODEWIRE_STRIPE_REQUIRE_TEST_KEY so billing itself refuses a live key.
# remove deletes those entries and the Secret, so billing is back on the
# dummy. Neither prints, logs or writes a key; the values pass only through a
# pipe to kubectl, and the apply is server-side so no last-applied copy of
# them is kept. Run remove right after the walk, before any redeploy, which
# would leave the Secret behind, and record each run on its issue. While the
# keys are in, Kind billing's own loops act on Dev's Stripe test account for
# the organizations Kind created, one more reason to remove them promptly. A
# loopback server can still be a tunnel or proxy to elsewhere; this guards
# against a mistyped context, not a deliberately misleading kubeconfig.
set -euo pipefail

case "$-" in
  *x*)
    printf '[kind-stripe] ERROR: shell tracing must be disabled\n' >&2
    exit 1
    ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# The cluster as the Kind dev tooling chooses it (deploy-service.sh): a
# profile's CLUSTER, else KIND_CLUSTER_NAME, else the retained e2e cluster.
# KUBE_CONTEXT is ignored: the Makefile exports its own default for it.
# shellcheck source=scripts/dev/kind/profile.sh
source "$ROOT/scripts/dev/kind/profile.sh"
kind_profile_load "$ROOT" || exit $?
readonly kube_context="kind-${CLUSTER:-${KIND_CLUSTER_NAME:-codewire-e2e-ci}}"
readonly kube_namespace=codewire-e2e
readonly deployment="codewire-billing"
readonly secret_name="codewire-kind-stripe"
readonly openbao_addr="${CODEWIRE_OPENBAO_ADDR:-https://openbao.example.invalid}"
readonly openbao_path="apps/codewire/dev/runtime"
# Built in pieces so no key-shaped literal sits in the source.
readonly secret_pattern="^(sk|rk)_""test_[A-Za-z0-9]{16,247}\$"
readonly publishable_pattern="^pk_""test_[A-Za-z0-9]{16,247}\$"

die() { printf '[kind-stripe] ERROR: %s\n' "$*" >&2; exit 1; }

[[ "$#" -eq 1 && ( "$1" == apply || "$1" == remove ) ]] ||
  die "usage: kind-stripe-test-keys.sh apply|remove"
command -v kubectl >/dev/null 2>&1 || die "kubectl is required"

declare -a openbao_env_unsets=()
for name in "${!BAO_@}"; do
  openbao_env_unsets+=( -u "$name" )
done
kube() {
  env "${openbao_env_unsets[@]}" kubectl --context "$kube_context" --namespace "$kube_namespace" "$@"
}

# Only a local Kind cluster: its context's API server must be on this
# machine's loopback. A context's name is only a kubeconfig label, so the
# server decides; never Dev, Production or any other cluster.
server="$(env "${openbao_env_unsets[@]}" kubectl config view --minify --context "$kube_context" \
  -o 'jsonpath={.clusters[0].cluster.server}' 2>/dev/null)" || server=""
[[ "$server" =~ ^https://(127\.0\.0\.1|localhost|\[::1\]):[0-9]{1,5}$ ]] ||
  die "$kube_context's API server is not on this machine's loopback; nothing was changed"

if [[ "$1" == remove ]]; then
  kube set env "deployment/$deployment" \
    STRIPE_SECRET_KEY- STRIPE_PUBLISHABLE_KEY- CODEWIRE_STRIPE_REQUIRE_TEST_KEY- >/dev/null
  kube delete secret "$secret_name" --ignore-not-found >/dev/null
  kube rollout status "deployment/$deployment" --timeout=180s >/dev/null
  printf '[kind-stripe] Removed the Stripe test keys; billing is back on its dummy key.\n'
  exit 0
fi

command -v bao >/dev/null 2>&1 || die "bao is required"
[[ "${BAO_ADDR:-$openbao_addr}" == "$openbao_addr" ]] || die "BAO_ADDR must be $openbao_addr"

# One field per read; each must be one test-mode line, or nothing is written.
field() {
  BAO_ADDR="$openbao_addr" bao kv get "-field=$1" "$openbao_path" 2>/dev/null
}
keys_env() {
  local secret publishable
  secret="$(field STRIPE_SECRET_KEY)" || return 1
  publishable="$(field STRIPE_PUBLISHABLE_KEY)" || return 1
  [[ "$secret" =~ $secret_pattern && "$publishable" =~ $publishable_pattern ]] || return 2
  printf 'STRIPE_SECRET_KEY=%s\nSTRIPE_PUBLISHABLE_KEY=%s\n' "$secret" "$publishable"
}

# Both keys are read and checked before anything reaches kubectl, so a
# refused key never overwrites the Secret.
status=0
keys="$(keys_env)" || status=$?
case "$status" in
  0) ;;
  2) die "Dev's Stripe keys are not both test-mode keys; nothing was written" ;;
  *) die "Dev's Stripe keys could not be read from OpenBao; nothing was written" ;;
esac
set +e
printf '%s\n' "$keys" |
  kube create secret generic "$secret_name" --from-env-file=/dev/stdin --dry-run=client -o json |
  kube apply --server-side --field-manager=codewire-kind-stripe -f - >/dev/null
results=("${PIPESTATUS[@]}")
set -e
unset keys
[[ "${results[1]}" == 0 && "${results[2]}" == 0 ]] || die "the Secret could not be written"

kube label secret "$secret_name" \
  app.kubernetes.io/managed-by=codewire-local app.kubernetes.io/component=billing \
  --overwrite >/dev/null
kube set env "deployment/$deployment" --from="secret/$secret_name" >/dev/null
kube set env "deployment/$deployment" CODEWIRE_STRIPE_REQUIRE_TEST_KEY=on >/dev/null
kube rollout status "deployment/$deployment" --timeout=180s >/dev/null
printf '[kind-stripe] Billing on %s runs with Dev'"'"'s Stripe test keys. Run remove after the walk.\n' "$kube_context"
