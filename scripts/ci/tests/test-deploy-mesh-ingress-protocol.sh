#!/usr/bin/env bash
# Render each ingress independently: coordinator GRPC must not mask ordinary HTTP.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
fail() { printf 'Mesh ingress protocol: %s\n' "$*" >&2; return 1; }
ordinary_dev() {
  [[ "$(grep -Ec '^    nginx\.ingress\.kubernetes\.io/proxy-http-version: "1\.0"$' <<<"$1")" == 1 ]] ||
    fail 'Dev ordinary ingress must select exactly HTTP/1.0'
}
coordinator() {
  grep -Eq '^    nginx\.ingress\.kubernetes\.io/backend-protocol: "GRPC"$' <<<"$1" ||
    { fail 'coordinator ingress must retain GRPC'; return 1; }
  if grep -q 'nginx.ingress.kubernetes.io/proxy-http-version:' <<<"$1"; then
    fail 'coordinator ingress must not select an HTTP proxy version'
  fi
}
unchanged_ordinary() {
  if grep -q 'nginx.ingress.kubernetes.io/proxy-http-version:' <<<"$1"; then
    fail 'global and Production ordinary ingress must retain their protocol defaults'
  fi
}
render() {
  helm template protocol-test apps/cli/charts/codewire-mesh \
    --set mesh.baseURL=https://mesh.test --set ingress.enabled=true \
    --show-only "templates/$1" "${@:2}"
}
dev_http="$(render ingress.yaml -f deployments/k8s/mesh-dev/values.yaml)" || exit 1
dev_grpc="$(render coordinator-ingress.yaml -f deployments/k8s/mesh-dev/values.yaml)" || exit 1
ordinary_dev "$dev_http"
coordinator "$dev_grpc"
for values in global production; do
  options=()
  if [[ "$values" == production ]]; then options=(-f deployments/k8s/mesh-production/values.yaml); fi
  ordinary_render="$(render ingress.yaml "${options[@]}")" || exit 1
  coordinator_render="$(render coordinator-ingress.yaml "${options[@]}")" || exit 1
  unchanged_ordinary "$ordinary_render"
  coordinator "$coordinator_render"
done
reject() {
  local output
  if output="$("$@" 2>/dev/null)"; then fail 'negative fixture accepted an invalid protocol'; return 1; fi
  [[ -z "$output" ]] || fail 'failed guard emitted a success receipt'
}
reject ordinary_dev "${dev_http//proxy-http-version: \"1.0\"/proxy-http-version: \"1.1\"}"
reject ordinary_dev "$(sed '/nginx.ingress.kubernetes.io\/proxy-http-version:/d' <<<"$dev_http")"
reject coordinator "${dev_grpc//backend-protocol: \"GRPC\"/backend-protocol: \"HTTP\"}"
reject coordinator "$(sed '/  annotations:/a\    nginx.ingress.kubernetes.io/proxy-http-version: "1.0"' <<<"$dev_grpc")"
# Exercise the whole runner, including its receipt, with a failing real render
# boundary. Exported command doubles are confined to each child Bash process.
for render_test_scope in global production; do
  for render_test_template in ingress.yaml coordinator-ingress.yaml; do
    if output="$(
      export render_test_scope render_test_template
      helm() {
        local scope=global
        if [[ "$*" == *deployments/k8s/mesh-dev/values.yaml* ]]; then scope=dev
        elif [[ "$*" == *deployments/k8s/mesh-production/values.yaml* ]]; then scope=production
        fi
        if [[ "$scope" == "$render_test_scope" && "$*" == *"--show-only templates/$render_test_template"* ]]; then
          if [[ "$render_test_template" == coordinator-ingress.yaml ]]; then
            printf '    nginx.ingress.kubernetes.io/backend-protocol: "GRPC"\n'
          fi
          return 1
        fi
        command helm "$@"
      }
      export -f helm
      bash "$ROOT/scripts/ci/tests/test-deploy-mesh-ingress-protocol.sh" 2>/dev/null
    )"; then
      fail 'full runner accepted a failed Helm render'; exit 1
    fi
    [[ -z "$output" ]] || { fail 'failed full runner emitted a success receipt'; exit 1; }
  done
done
printf 'Mesh ingress protocol render tests passed (6 renders, 8 rejection fixtures)\n'
