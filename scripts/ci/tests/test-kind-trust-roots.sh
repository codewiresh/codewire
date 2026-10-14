#!/usr/bin/env bash
# Retained Kind clusters keep trusting their previous synthetic root until it
# expires: publication is the union of the current root and every unexpired
# root already published, deduplicated and in a stable order. Certificates are
# generated here at run time; none are committed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=scripts/ci/verify/kind/credentials.sh
source "$ROOT/scripts/ci/verify/kind/credentials.sh"

FIXTURE="$(mktemp -d)"
trap 'rm -rf "$FIXTURE"' EXIT
fail() { echo "test-kind-trust-roots: $*" >&2; exit 1; }

# One self-signed certificate per name; an expired one when asked. `req`
# takes explicit validity dates only from OpenSSL 3.4, and the CI job image
# has 3.0, so the expired one is self-signed by `openssl ca`, which has taken
# -startdate/-enddate throughout.
certificate() {
  local name="$1" expired="${2:-}"
  if [ -z "$expired" ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout "$FIXTURE/$name.key" -subj "/CN=$name" -days 2 \
      -out "$FIXTURE/$name.crt" 2>/dev/null
  else
    local ca="$FIXTURE/ca-$name"
    mkdir "$ca"
    : >"$ca/index.txt"
    printf '01\n' >"$ca/serial"
    printf '%s\n' '[ca]' 'default_ca = fixture' '[fixture]' "database = $ca/index.txt" \
      "serial = $ca/serial" "new_certs_dir = $ca" 'default_md = sha256' 'policy = any' \
      '[any]' 'commonName = supplied' >"$ca/ca.cnf"
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout "$FIXTURE/$name.key" -subj "/CN=$name" -out "$ca/request.csr" 2>/dev/null
    openssl ca -batch -config "$ca/ca.cnf" -selfsign -keyfile "$FIXTURE/$name.key" \
      -in "$ca/request.csr" -startdate 20200101000000Z -enddate 20200102000000Z \
      -notext -out "$FIXTURE/$name.crt" 2>/dev/null
  fi
  cat "$FIXTURE/$name.crt"
}
fingerprints() {
  awk -v d="$FIXTURE/fp" '
    /-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s-%04d.pem", d, n) }
    n && f { print > f }
    /-----END CERTIFICATE-----/ { close(f); f = "" }'
  local file
  for file in "$FIXTURE"/fp-*.pem; do
    [ -e "$file" ] || continue
    openssl x509 -in "$file" -noout -subject -nameopt RFC2253 | sed 's/^subject=//'
    rm -f "$file"
  done
}

current="$(certificate current)"
previous="$(certificate previous)"
expired="$(certificate expired yes)"
other="$(certificate other)"

# A fresh cluster publishes only its current root.
[ "$(kind_trust_bundle_union "$current" "" | fingerprints)" = "CN=current" ] ||
  fail 'a first publication is not exactly the current root'

# After renewal: current first, then the still-valid previous root; the expired
# root and the duplicate current root are dropped.
published="$(printf '%s\n%s\n%s\n' "$previous" "$expired" "$current")"
union="$(kind_trust_bundle_union "$current" "$published")"
[ "$(fingerprints <<<"$union" | paste -sd, -)" = "CN=current,CN=previous" ] ||
  fail "union is not current then previous: $(fingerprints <<<"$union" | paste -sd, -)"

# Republishing an unchanged cluster writes the same bytes, so deploys are
# idempotent.
[ "$(kind_trust_bundle_union "$current" "$union")" = "$union" ] ||
  fail 'republishing a current bundle changed it'

# Order is stable: published roots keep their published order.
published="$(printf '%s\n%s\n' "$other" "$previous")"
[ "$(kind_trust_bundle_union "$current" "$published" | fingerprints | paste -sd, -)" \
    = "CN=current,CN=other,CN=previous" ] || fail 'published roots changed order'

# The current root must be exactly one unexpired certificate, and a published
# entry that is not a certificate fails closed rather than being dropped.
if kind_trust_bundle_union "$expired" "" >/dev/null 2>&1; then
  fail 'an expired current root was accepted'
fi
if kind_trust_bundle_union "$(printf '%s\n%s\n' "$current" "$previous")" "" >/dev/null 2>&1; then
  fail 'a current root with two certificates was accepted'
fi
if kind_trust_bundle_union "" "" >/dev/null 2>&1; then
  fail 'an empty current root was accepted'
fi
broken="$(printf '%s\n' '-----BEGIN CERTIFICATE-----' 'bm90IGEgY2VydGlmaWNhdGU=' '-----END CERTIFICATE-----')"
if kind_trust_bundle_union "$current" "$broken" >/dev/null 2>&1; then
  fail 'an invalid published certificate was silently dropped'
fi

# publish_kind_trust_roots: three current roots from their Secrets, stale
# ConfigMaps, and only public tls.crt/ca.crt reads. The stub records every
# apply and refuses any other read.
for name in broker orchestration coordinator old-broker old-orchestration old-coordinator; do
  certificate "$name" >/dev/null
done
export FIXTURE
for name in broker orchestration coordinator old-broker old-orchestration old-coordinator; do
  cp "$FIXTURE/$name.crt" "$FIXTURE/stub-$name.crt"
done
: >"$FIXTURE/applied"
kubectl() {
  [ "$1" = --context ] && [ "$2" = kind-test ] || { echo "unexpected context: $*" >&2; return 97; }
  shift 2
  local args="$*"
  case "$args" in
    *tls.key* | *'{.data}'* | *'-o yaml'*'get secret'* | *'get secret'*'-o yaml'*)
      echo "private or whole-Secret read: $args" >&2; return 96 ;;
    '-n codewire-e2e get secret codewire-kind-credential-broker-root -o jsonpath={.data.tls\.crt}')
      base64 -w0 "$FIXTURE/stub-broker.crt" ;;
    '-n codewire-e2e get secret codewire-kind-orchestration-internal-root -o jsonpath={.data.tls\.crt}')
      base64 -w0 "$FIXTURE/stub-orchestration.crt" ;;
    '-n codewire-e2e get secret codewire-kind-coordinator-root -o jsonpath={.data.tls\.crt}')
      base64 -w0 "$FIXTURE/stub-coordinator.crt" ;;
    '-n codewire-e2e get configmap codewire-credential-broker-roots --ignore-not-found -o jsonpath={.data.ca\.crt}')
      cat "$FIXTURE/stub-old-broker.crt" ;;
    '-n dev-sandboxes get configmap codewire-orchestration-internal-roots --ignore-not-found -o jsonpath={.data.ca\.crt}' | \
    '-n codewire-e2e get configmap codewire-orchestration-internal-roots --ignore-not-found -o jsonpath={.data.ca\.crt}')
      cat "$FIXTURE/stub-old-orchestration.crt" ;;
    '-n dev-sandboxes get configmap codewire-coordinator-extra-roots --ignore-not-found -o jsonpath={.data.ca\.crt}')
      cat "$FIXTURE/stub-old-coordinator.crt" ;;
    '-n '*' create configmap '*' --dry-run=client -o yaml')
      command kubectl "$@" ;;
    '--request-timeout='*' apply -f -')
      cat >>"$FIXTURE/applied"; printf -- '---\n' >>"$FIXTURE/applied" ;;
    *) echo "unexpected kubectl: $args" >&2; return 95 ;;
  esac
}
publish_kind_trust_roots --context kind-test 2>"$FIXTURE/publish.err" ||
  fail "publication failed: $(cat "$FIXTURE/publish.err")"
python3 - "$FIXTURE/applied" <<'PY' >"$FIXTURE/applied.summary" || fail 'applied ConfigMaps are not YAML'
import subprocess, sys, yaml
for doc in yaml.safe_load_all(open(sys.argv[1])):
    if not doc:
        continue
    pem = doc["data"]["ca.crt"]
    names = []
    for block in pem.split("-----END CERTIFICATE-----")[:-1]:
        cert = block[block.index("-----BEGIN"):] + "-----END CERTIFICATE-----\n"
        out = subprocess.run(["openssl", "x509", "-noout", "-subject"], input=cert,
                             capture_output=True, text=True, check=True).stdout
        names.append(out.strip().removeprefix("subject=").removeprefix("CN=").removeprefix("CN = "))
    print(doc["metadata"]["namespace"], doc["metadata"]["name"], ",".join(names))
PY
expected='codewire-e2e codewire-credential-broker-roots broker,old-broker
dev-sandboxes codewire-orchestration-internal-roots orchestration,old-orchestration
codewire-e2e codewire-orchestration-internal-roots orchestration,old-orchestration
dev-sandboxes codewire-coordinator-extra-roots coordinator,old-coordinator'
[ "$(cat "$FIXTURE/applied.summary")" = "$expected" ] ||
  fail "published ConfigMaps differ:
$(cat "$FIXTURE/applied.summary")"

# Identical roots across trust domains still fail closed before any write.
cp "$FIXTURE/stub-broker.crt" "$FIXTURE/stub-coordinator.crt"
: >"$FIXTURE/applied"
if publish_kind_trust_roots --context kind-test 2>/dev/null; then
  fail 'non-distinct trust domains were published'
fi
[ ! -s "$FIXTURE/applied" ] || fail 'a non-distinct publication wrote a ConfigMap'

# Every entry point republishes: the gate's issuer deploy, each kind-deploy
# before it restarts anything, and the explicit make target.
grep -Fxq '  publish_kind_trust_roots || return $?' "$ROOT/scripts/ci/verify/kind/credentials.sh" ||
  fail 'the initial deploy does not publish through the union'
grep -Fxq 'publish_kind_trust_roots --context "kind-${KIND_CLUSTER_NAME}"' \
    "$ROOT/scripts/dev/kind/deploy-service.sh" ||
  fail 'kind-deploy does not republish the trust roots'
awk '/^kind load docker-image/{load=NR} /^publish_kind_trust_roots /{publish=NR}
     /rollout restart/{restart=NR; exit} END{exit !(load && publish > load && restart > publish)}' \
    "$ROOT/scripts/dev/kind/deploy-service.sh" ||
  fail 'kind-deploy does not republish between loading and restarting'
grep -Fxq 'publish_kind_trust_roots --context "kind-${KIND_CLUSTER_NAME}"' \
    "$ROOT/scripts/dev/kind/trust-roots.sh" ||
  fail 'make kind-trust-roots does not publish'
grep -Eq '^kind-trust-roots:' "$ROOT/Makefile" || fail 'make kind-trust-roots is missing'

echo 'test-kind-trust-roots: PASS cases=14'
