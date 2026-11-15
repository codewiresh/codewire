#!/usr/bin/env bash
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR  # the tests exercise the script default

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="$ROOT/scripts/dev/kind/kind-stripe-test-keys.sh"
mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/codewire-kind-stripe-test-keys.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/bin"

# Synthetic values, built in pieces so no key-shaped literal sits here.
readonly test_secret="sk_""test_SYNTHETICKINDSECRET0123456789"
readonly test_publishable="pk_""test_SYNTHETICKINDPUBLISHABLE01234"
readonly live_secret="sk_""live_SYNTHETICKINDSECRET0123456789"

cat >"$work/bin/bao" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${BAO_ADDR:-}" == 'https://openbao.example.invalid' ]]
printf '%s\n' "$*" >>"$BAO_LOG"
case "$*" in
  'kv get -field=STRIPE_SECRET_KEY apps/codewire/dev/runtime') printf '%s' "$FAKE_SECRET" ;;
  'kv get -field=STRIPE_PUBLISHABLE_KEY apps/codewire/dev/runtime') printf '%s' "$FAKE_PUBLISHABLE" ;;
  *) exit 3 ;;
esac
EOF

cat >"$work/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# No OpenBao variable reaches kubectl.
[[ -z "${BAO_ADDR+x}" && -z "${BAO_TOKEN+x}" ]]
printf '%s\n' "$*" >>"$KUBECTL_LOG"
case "$*" in
  'config view --minify --context '*' -o jsonpath={.clusters[0].cluster.server}')
    printf '%s' "${FAKE_SERVER-https://127.0.0.1:41234}" ;;
  *'create secret generic codewire-kind-stripe --from-env-file=/dev/stdin'*)
    [[ "$(cat)" == "STRIPE_SECRET_KEY=$FAKE_SECRET"$'\n'"STRIPE_PUBLISHABLE_KEY=$FAKE_PUBLISHABLE" ]]
    printf '{"apiVersion":"v1","kind":"Secret"}\n' ;;
  *'apply --server-side --field-manager=codewire-kind-stripe -f -'*) grep -Fq '"kind":"Secret"' ;;
  *'label secret codewire-kind-stripe'*|*'set env deployment/codewire-billing'*|\
  *'rollout status deployment/codewire-billing'*|*'delete secret codewire-kind-stripe --ignore-not-found'*) ;;
  *) exit 64 ;;
esac
EOF
chmod +x "$work/bin/bao" "$work/bin/kubectl"

run() {
  : >"$work/kubectl.log"; : >"$work/bao.log"
  env -u ANTHROPIC_API_KEY PATH="$work/bin:$PATH" \
    BAO_ADDR='https://openbao.example.invalid' BAO_TOKEN='must-not-reach-kubectl' \
    BAO_LOG="$work/bao.log" KUBECTL_LOG="$work/kubectl.log" "$@" \
    >"$work/stdout" 2>"$work/stderr" </dev/null
}
no_value() {
  if grep -rF -e SYNTHETICKIND "$work/stdout" "$work/stderr" "$work/kubectl.log"; then
    printf 'a key value reached observable output\n' >&2; exit 1
  fi
}

# apply: both keys go into the Secret through stdin only, then billing is
# pointed at it, made to refuse a live key, and rolled out.
run env FAKE_SECRET="$test_secret" FAKE_PUBLISHABLE="$test_publishable" "$SCRIPT" apply
expected=(
  'config view --minify --context kind-codewire-e2e-ci -o jsonpath={.clusters[0].cluster.server}'
  'create secret generic codewire-kind-stripe --from-env-file=/dev/stdin --dry-run=client -o json'
  'apply --server-side --field-manager=codewire-kind-stripe -f -'
  'label secret codewire-kind-stripe'
  'set env deployment/codewire-billing --from=secret/codewire-kind-stripe'
  'set env deployment/codewire-billing CODEWIRE_STRIPE_REQUIRE_TEST_KEY=on'
  'rollout status deployment/codewire-billing --timeout=180s'
)
[[ "$(wc -l <"$work/kubectl.log")" == "${#expected[@]}" ]] || { cat "$work/kubectl.log" "$work/stderr" >&2; exit 1; }
# The context check comes first. The Secret's create and apply share a
# pipeline, so they may log in either order. The rest follow in order.
expect_call() {
  local line="$1" want="$2" prefix="--context kind-codewire-e2e-ci --namespace codewire-e2e "
  [[ "$want" == 'config view'* ]] && prefix=""
  [[ "$line" == "$prefix$want"* ]]
}
mapfile -t calls <"$work/kubectl.log"
expect_call "${calls[0]}" "${expected[0]}" || { printf 'first kubectl call was %s\n' "${calls[0]}" >&2; exit 1; }
{ expect_call "${calls[1]}" "${expected[1]}" && expect_call "${calls[2]}" "${expected[2]}"; } ||
  { expect_call "${calls[1]}" "${expected[2]}" && expect_call "${calls[2]}" "${expected[1]}"; } ||
  { printf 'the Secret was not created and applied: %s / %s\n' "${calls[1]}" "${calls[2]}" >&2; exit 1; }
for i in $(seq 3 $(( ${#expected[@]} - 1 ))); do
  expect_call "${calls[$i]}" "${expected[$i]}" ||
    { printf 'kubectl call %d was %s\n' "$((i + 1))" "${calls[$i]}" >&2; exit 1; }
done
grep -Fq "runs with Dev's Stripe test keys" "$work/stdout"
no_value

# A live key, in either field, writes nothing.
for pair in "$live_secret $test_publishable" "$test_secret pk_""live_SYNTHETICKINDPUBLISHABLE01234"; do
  read -r secret publishable <<<"$pair"
  if run env FAKE_SECRET="$secret" FAKE_PUBLISHABLE="$publishable" "$SCRIPT" apply; then
    printf 'apply accepted a live key\n' >&2; exit 1
  fi
  grep -Fq "not both test-mode keys; nothing was written" "$work/stderr"
  if grep -Fq 'apply --server-side' "$work/kubectl.log" || grep -Fq 'set env' "$work/kubectl.log"; then
    printf 'a refused key was written\n' >&2; exit 1
  fi
  no_value
done

# A value with a second line is refused too.
if run env FAKE_SECRET="$test_secret"$'\n'"$test_secret" FAKE_PUBLISHABLE="$test_publishable" "$SCRIPT" apply; then
  printf 'apply accepted a two-line key\n' >&2; exit 1
fi
grep -Fq "nothing was written" "$work/stderr"

# remove: the entries and the Secret go, and billing rolls back to the dummy.
run "$SCRIPT" remove
[[ "$(cat "$work/kubectl.log")" == *'set env deployment/codewire-billing STRIPE_SECRET_KEY- STRIPE_PUBLISHABLE_KEY- CODEWIRE_STRIPE_REQUIRE_TEST_KEY-'* ]]
grep -Fq 'delete secret codewire-kind-stripe --ignore-not-found' "$work/kubectl.log"
grep -Fq 'rollout status deployment/codewire-billing' "$work/kubectl.log"
[[ ! -s "$work/bao.log" ]] || { printf 'remove read OpenBao\n' >&2; exit 1; }

# The Makefile's exported KUBE_CONTEXT doesn't move it off the retained
# cluster; KIND_CLUSTER_NAME does, and every loopback form is accepted.
for server in https://localhost:6443 'https://[::1]:6443'; do
  run env KUBE_CONTEXT=kind-codewire FAKE_SERVER="$server" FAKE_SECRET="$test_secret" FAKE_PUBLISHABLE="$test_publishable" "$SCRIPT" apply ||
    { printf 'apply refused loopback server %s\n' "$server" >&2; cat "$work/stderr" >&2; exit 1; }
  head -1 "$work/kubectl.log" | grep -Fq -- '--context kind-codewire-e2e-ci' ||
    { printf 'KUBE_CONTEXT moved the helper: %s\n' "$(head -1 "$work/kubectl.log")" >&2; exit 1; }
done
run env KIND_CLUSTER_NAME=codewire-other "$SCRIPT" remove
grep -Fq -- '--context kind-codewire-other --namespace codewire-e2e set env' "$work/kubectl.log"

# A context whose server isn't loopback changes nothing, for apply and for
# remove, including a remote URL that only mentions loopback.
for server in https://203.0.113.10:6443 https://kind.example.test:6443 https://127.0.0.1.example.test:6443 \
  'https://dev.example.test/?https://127.0.0.1:6443' 'http://127.0.0.1:6443' 'https://127.0.0.1:6443/extra' ""; do
  for verb in apply remove; do
    if run env FAKE_SERVER="$server" FAKE_SECRET="$test_secret" FAKE_PUBLISHABLE="$test_publishable" "$SCRIPT" "$verb"; then
      printf '%s ran against server %s\n' "$verb" "$server" >&2; exit 1
    fi
    grep -Fq "API server is not on this machine's loopback; nothing was changed" "$work/stderr"
    [[ "$(grep -vc '^config view' "$work/kubectl.log")" == 0 && ! -s "$work/bao.log" ]] ||
      { printf '%s changed something against %s\n' "$verb" "$server" >&2; exit 1; }
  done
done

# Only a local Kind context, a known verb, and no shell tracing.
for args in "$SCRIPT" "$SCRIPT show"; do
  # shellcheck disable=SC2086
  if run env $args; then printf 'accepted: %s\n' "$args" >&2; exit 1; fi
  [[ ! -s "$work/kubectl.log" && ! -s "$work/bao.log" ]]
done
if run bash -x "$SCRIPT" remove; then printf 'ran under shell tracing\n' >&2; exit 1; fi
grep -Fq 'shell tracing must be disabled' "$work/stderr"

printf 'Kind Stripe test-key bridge contract: OK\n'
