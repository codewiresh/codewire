#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly PREFLIGHT="$ROOT/scripts/runtime/dev/preflight-openbao-native-secrets.sh"
# mkdir, not install -d: install would reset the mode of an existing shared
# directory that checks running beside this one hold open.
(umask 077; mkdir -p "$ROOT/.tmp")
work="$(mktemp -d "$ROOT/.tmp/test-openbao-native-secret-preflight.XXXXXX")"
trap 'rm -rf "$work"' EXIT

cat >"$work/kubectl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
case " $* " in
  *' get cluster.postgresql.cnpg.io '*) printf 'codewire-db-1' ;;
  *' exec -i pod/codewire-db-1 -c postgres -- psql '*) cat "$FAKE_COUNTS" ;;
  *) exit 91 ;;
esac
MOCK
chmod +x "$work/kubectl"

printf '%s\n' '{"local_secrets":0,"tenant_secrets":0,"tenant_secret_deks":0,"confidential_storage_keys":22,"tenant_secret_control":1,"tenant_secret_kek_canary":1}' >"$work/counts.json"
if FAKE_COUNTS="$work/counts.json" KUBECTL_BIN="$work/kubectl" "$PREFLIGHT" \
    >"$work/unwrapped.out" 2>"$work/unwrapped.err"; then
  printf 'preflight ran outside the Infra access wrapper\n' >&2
  exit 1
fi
grep -Fq 'invoke beneath Infra scripts/kube-access' "$work/unwrapped.err"

success="$(
  FAKE_COUNTS="$work/counts.json" \
    INFRA_KUBECONFIG_DIR="$work" \
    KUBECTL_BIN="$work/kubectl" \
    "$PREFLIGHT"
)"
[[ "$success" == *'PASS counts=local:0,tenant:0,deks:0,confidential:22,control:1,canary:1'* ]]

printf '%s\n' '{"local_secrets":1,"tenant_secrets":0,"tenant_secret_deks":0,"confidential_storage_keys":22,"tenant_secret_control":1,"tenant_secret_kek_canary":0}' >"$work/counts.json"
if FAKE_COUNTS="$work/counts.json" INFRA_KUBECONFIG_DIR="$work" \
    KUBECTL_BIN="$work/kubectl" "$PREFLIGHT" \
    >"$work/rejected.out" 2>"$work/rejected.err"; then
  printf 'non-zero retired store passed preflight\n' >&2
  exit 1
fi
grep -Fq 'REJECT counts=local:1,tenant:0,deks:0,confidential:22,control:1,canary:0' \
  "$work/rejected.out"
if grep -Eqi 'select .*value|secretValue|LUKS_KEY|client_token' "$PREFLIGHT"; then
  printf 'preflight contains a secret-value read surface\n' >&2
  exit 1
fi

printf 'OpenBao native-secret Dev preflight contract: OK\n'
