#!/usr/bin/env bash
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR  # the tests exercise the script default

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/codewire-sync-local-secrets.XXXXXX")"
cleanup() {
  if [[ "${KEEP_SYNC_LOCAL_SECRETS_TEST_TMP:-0}" == 1 ]]; then
    printf 'kept local secret sync fixture: %s\n' "$work" >&2
  else
    rm -rf -- "$work"
  fi
}
trap cleanup EXIT
mkdir -p "$work/bin"

readonly synthetic_value='synthetic-local-anthropic-value'

cat >"$work/bin/bao" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >"$BAO_LOG"
[[ "${BAO_ADDR:-}" == 'https://openbao.example.invalid' ]]
[[ "$*" == 'kv get -field=ANTHROPIC_API_KEY apps/codewire/dev/runtime' ]]
printf '%s\n' "$SYNTHETIC_VALUE"
EOF

cat >"$work/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ -z "${BAO_ADDR+x}" && -z "${BAO_TOKEN+x}" ]]
printf '%q ' "$@" >>"$KUBECTL_LOG"
printf '\n' >>"$KUBECTL_LOG"
case "$*" in
  *'create secret generic codewire-local-anthropic'*)
    [[ "$(cat)" == "ANTHROPIC_API_KEY=$SYNTHETIC_VALUE" ]]
    printf '{"apiVersion":"v1","kind":"Secret"}\n'
    ;;
  *'apply -f -'*)
    grep -Fq '"kind":"Secret"'
    ;;
  *'label secret codewire-local-anthropic'*) ;;
  *) exit 64 ;;
esac
EOF
chmod +x "$work/bin/bao" "$work/bin/kubectl"
: >"$work/kubectl.log"
: >"$work/bao.log"

env -u ANTHROPIC_API_KEY \
  PATH="$work/bin:$PATH" \
  BAO_ADDR='https://openbao.example.invalid' \
  BAO_TOKEN='must-not-reach-kubectl' \
  SYNTHETIC_VALUE="$synthetic_value" \
  BAO_LOG="$work/bao.log" \
  KUBECTL_LOG="$work/kubectl.log" \
  "$ROOT/scripts/dev/kind/sync-local-secrets.sh" \
  >"$work/stdout" 2>"$work/stderr"

if [[ "$(wc -l <"$work/kubectl.log")" != 3 ]]; then
  sed 's/^/[sync-local-secrets] /' "$work/stderr" >&2
  sed 's/^/[bao] /' "$work/bao.log" >&2
  printf 'local secret sync did not execute its exact kubectl sequence\n' >&2
  exit 1
fi
grep -Fq 'Synced the Anthropic credential reference' "$work/stdout"
if rg -F "$synthetic_value" "$work/stdout" "$work/stderr" "$work/kubectl.log"; then
  printf 'local secret value reached observable output\n' >&2
  exit 1
fi

printf 'local OpenBao secret sync contract: OK\n'
