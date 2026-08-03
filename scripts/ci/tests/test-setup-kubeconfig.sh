#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly HELPER="$ROOT/scripts/ci/setup/setup-kubeconfig.sh"

fail() {
  printf '[test-setup-kubeconfig] ERROR: %s\n' "$*" >&2
  exit 1
}

tmp="$(mktemp -d "$ROOT/.test-setup-kubeconfig.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
readonly tmp
token_path="$tmp/projected-token"
kubeconfig="$tmp/kubeconfig"
printf 'synthetic-projected-token-must-not-be-embedded\n' >"$token_path"
readonly token_path kubeconfig

real_kubectl="$(command -v kubectl)"
readonly real_kubectl
cat >"$tmp/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${KUBECTL_TEST_LOG:?}"
printf '\n' >>"${KUBECTL_TEST_LOG:?}"
case "$1" in
  config)
    exec "${REAL_KUBECTL:?}" "$@"
    ;;
  get)
    [[ "$2" == "--raw" && "$3" == "/api" ]] || exit 2
    ;;
  *)
    exit 2
    ;;
esac
EOF
chmod 0755 "$tmp/kubectl"

export KUBECTL_TEST_LOG="$tmp/kubectl.log"
export REAL_KUBECTL="$real_kubectl"
PATH="$tmp:$PATH" \
  CODEWIRE_DEV_TOKEN_PATH="$token_path" \
  CODEWIRE_DEV_K8S_SERVER='https://127.0.0.1:9345/ignored' \
  KUBECONFIG="$kubeconfig" \
  "$HELPER" >/dev/null

grep -Fq "tokenFile: $token_path" "$kubeconfig" ||
  fail "kubeconfig does not reference the projected token file"
grep -Fq 'server: https://127.0.0.1:6443' "$kubeconfig" ||
  fail "kubeconfig changed the normalized Kubernetes endpoint"
! grep -Fq 'synthetic-projected-token-must-not-be-embedded' "$kubeconfig" ||
  fail "kubeconfig embeds the projected token"
grep -Fq "config set users.ci-deployer.user.tokenFile $token_path" \
  "$KUBECTL_TEST_LOG" || fail "helper did not configure tokenFile"
! grep -Fq -- '--token=' "$KUBECTL_TEST_LOG" ||
  fail "helper still snapshots the projected token"
grep -Fqx 'get --raw /api ' "$KUBECTL_TEST_LOG" ||
  fail "helper did not authenticate the generated kubeconfig"

printf '[test-setup-kubeconfig] projected tokenFile kubeconfig accepted\n'
