#!/usr/bin/env bash
# Synthetic PKI for orchestration's TLS-only internal listener on the local
# `make up` / `make deploy-local` Kind cluster, which has no cert-manager. The
# managed Kind gate (`make kind-up`) issues the same objects with cert-manager.
#
# Creates, once, a local CA and the leaf for
# codewire-orchestration.<namespace>.svc.cluster.local and
# codewire-orchestration-workspace-binding.<namespace>.svc.cluster.local as
# the Secret the orchestration Deployment mounts, and publishes the CA's
# public certificate as codewire-orchestration-internal-roots in the sandbox
# namespace (gateways, workspace daemons, and orchestration's own startup
# check) and the service namespace (Mesh). Existing objects are kept while the
# leaf names both hosts, so running gateways keep verifying; a leaf issued
# before the binding name is replaced with a new CA and roots. The keys exist
# only in a private temporary directory removed on exit and are never printed.
set -euo pipefail

readonly kube_context="${KUBE_CONTEXT:-kind-codewire}"
readonly namespace="${KUBE_NAMESPACE:-default}"
readonly sandbox_namespace="${SANDBOX_NAMESPACE:-dev-sandboxes}"
readonly secret=codewire-orchestration-internal-tls
readonly roots=codewire-orchestration-internal-roots
readonly host="codewire-orchestration.${namespace}.svc.cluster.local"
readonly binding_host="codewire-orchestration-workspace-binding.${namespace}.svc.cluster.local"

log() { printf '[local-internal-tls] %s\n' "$*" >&2; }
kc() { kubectl --context "$kube_context" "$@"; }

for tool in kubectl openssl; do
  command -v "$tool" >/dev/null 2>&1 || { log "ERROR: $tool is required"; exit 1; }
done

# Only the public leaf certificate is read here, to check its names.
leaf_names_both_hosts() {
  local leaf
  leaf="$(kc -n "$namespace" get secret "$secret" -o 'jsonpath={.data.tls\.crt}' 2>/dev/null | base64 -d 2>/dev/null)" || return 1
  [ -n "$leaf" ] || return 1
  openssl x509 -noout -checkhost "$host" <<<"$leaf" 2>/dev/null | grep -q 'does match' \
    && openssl x509 -noout -checkhost "$binding_host" <<<"$leaf" 2>/dev/null | grep -q 'does match'
}

if kc -n "$namespace" get secret "$secret" >/dev/null 2>&1 \
  && kc -n "$sandbox_namespace" get configmap "$roots" >/dev/null 2>&1 \
  && kc -n "$namespace" get configmap "$roots" >/dev/null 2>&1 \
  && leaf_names_both_hosts; then
  log "internal TLS identity and roots already present"
  exit 0
fi

work="$(mktemp -d)"
chmod 0700 "$work"
trap 'rm -rf -- "$work"' EXIT

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$work/ca.key" -out "$work/ca.crt" -days 3650 \
  -subj "/CN=Codewire local orchestration internal CA" \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$work/tls.key" -out "$work/tls.csr" -subj "/CN=${host}" 2>/dev/null
printf 'subjectAltName=DNS:%s,DNS:%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n' \
  "$host" "$binding_host" >"$work/leaf.ext"
openssl x509 -req -in "$work/tls.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
  -CAcreateserial -days 365 -extfile "$work/leaf.ext" -out "$work/tls.crt" 2>/dev/null
openssl verify -CAfile "$work/ca.crt" -verify_hostname "$host" "$work/tls.crt" >/dev/null
openssl verify -CAfile "$work/ca.crt" -verify_hostname "$binding_host" "$work/tls.crt" >/dev/null

kc -n "$namespace" create secret tls "$secret" \
  --cert="$work/tls.crt" --key="$work/tls.key" --dry-run=client -o yaml | kc apply -f - >/dev/null
for target in "$sandbox_namespace" "$namespace"; do
  kc -n "$target" create configmap "$roots" --from-file=ca.crt="$work/ca.crt" \
    --dry-run=client -o yaml | kc apply -f - >/dev/null
done
log "issued a local internal TLS identity for ${host} and ${binding_host}"
