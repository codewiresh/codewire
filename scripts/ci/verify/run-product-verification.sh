#!/usr/bin/env bash
# Focused automatic product-verification families. Toolchain setup belongs to
# the owning workflow job; this script is also callable for local diagnosis.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
FAMILY="${1:-}"
SELECTION="${VERIFICATION_SELECTION:-|valid:v2|complete|}"
cd "$ROOT"
export CARGO_TARGET_DIR="$(scripts/ci/verify/resolve-cargo-target-dir.sh "$ROOT")"
CARGO_DEBUG_DIR="$CARGO_TARGET_DIR/debug"

selected() {
  [[ "$SELECTION" == *"|$1|"* ]]
}

install_bun_dependencies() {
  PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    bun install --frozen-lockfile --ignore-scripts
}

GO_MODULE_DIRS=(
  libs/api-client-go
  libs/gen-go
  libs/sdk-examples/run-claude/go
  libs/sdk-go
  libs/tailnet
  tests/contract
)
GO_PACKAGE_PATTERNS=(
  ./libs/api-client-go/...
  ./libs/gen-go/...
  ./libs/sdk-examples/run-claude/go/...
  ./libs/sdk-go/...
  ./libs/tailnet/...
  ./tests/contract/...
)

rust_package_args() {
  local prefix="$1" manifest dir token package
  local found=false
  RUST_PACKAGE_ARGS=()

  if [ "$prefix" = rust_pkg_ ] && selected rust_workspace; then
    RUST_PACKAGE_ARGS=(--workspace)
    return
  fi

  for manifest in crates/*/Cargo.toml; do
    dir="${manifest%/Cargo.toml}"
    token="${dir#crates/}"
    token="${token//-/_}"
    # The desktop crate is intentionally detached from the root workspace and
    # is verified by run_detached_desktop instead of Cargo's workspace runner.
    if [ "$prefix" = rust_pkg_ ] && [ "$token" = codewire_desktop ]; then
      continue
    fi
    if selected "${prefix}${token}"; then
      package="$(sed -nE 's/^name = "([^"]+)"/\1/p' "$manifest" | head -n 1)"
      [ -n "$package" ] || {
        echo "::error file=${manifest}::unable to determine Rust package name"
        exit 1
      }
      RUST_PACKAGE_ARGS+=( -p "$package" )
      found=true
    fi
  done

  if [ "$found" = false ]; then
    echo "::error::Rust verification selected without an affected package token"
    exit 1
  fi
}

run_rust_packages() {
  local prefix="$1"
  rust_package_args "$prefix"
  cargo fmt --all --check
  cargo build --locked "${RUST_PACKAGE_ARGS[@]}"
  cargo clippy "${RUST_PACKAGE_ARGS[@]}" --all-targets -- -D warnings
  cargo test "${RUST_PACKAGE_ARGS[@]}" --all-targets
}

run_detached_desktop() {
  local manifest="crates/codewire-desktop/Cargo.toml"
  cargo fmt --manifest-path "$manifest" --check
  cargo check --locked --manifest-path "$manifest"
  cargo test --locked --manifest-path "$manifest"
  scripts/ci/release/package-codewire-desktop.sh --dry-run 0.0.0-ci
}

has_root_rust_selection() {
  local manifest dir token
  if selected rust_workspace; then
    return 0
  fi
  for manifest in crates/*/Cargo.toml; do
    dir="${manifest%/Cargo.toml}"
    token="${dir#crates/}"
    token="${token//-/_}"
    [ "$token" = codewire_desktop ] && continue
    if selected "rust_pkg_${token}"; then
      return 0
    fi
  done
  return 1
}

run_policy() {
  local runtime_shell_files=()
  local runtime_shell_file
  if [ -d scripts/runtime ]; then
    while IFS= read -r -d '' runtime_shell_file; do
      runtime_shell_files+=("$runtime_shell_file")
    done < <(find scripts/runtime -type f -name '*.sh' -print0)
  fi
  if [ "${#runtime_shell_files[@]}" -gt 0 ]; then
    bash -n "${runtime_shell_files[@]}"
  fi
  scripts/ci/tests/test-select-deploy-dev.sh
  scripts/ci/tests/test-resolve-deployed-source.sh
  scripts/ci/tests/test-select-verification.sh
  scripts/ci/tests/test-go-source-ownership.sh
  scripts/ci/tests/test-rust-owned-fixtures.sh
  scripts/ci/tests/test-require-verification-results.sh
  scripts/ci/tests/test-verify-tested-tree-receipt.sh
  scripts/ci/tests/test-resolve-cargo-target-dir.sh
  scripts/ci/tests/test-package-codewire-desktop.sh
  scripts/ci/tests/test-sdk-local-cli-contract.sh
  scripts/ci/tests/test-integration-postgres.sh
  python3 scripts/checks/repo_checks.py license-map
  python3 scripts/checks/repo_checks.py rest-surface-freeze
  python3 scripts/checks/repo_checks.py rust-validation-source
  python3 scripts/checks/repo_checks.py retired-reference-source
  python3 scripts/checks/source/check-native-desktop-ui.py
  python3 scripts/checks/repo_checks.py go-source-classification
}

install_contract_toolchain() {
  go install github.com/bufbuild/buf/cmd/buf@v1.50.0
  go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.5
  go install connectrpc.com/connect/cmd/protoc-gen-connect-go@v1.18.1
  curl -fsSL -o /tmp/protoc.zip \
    https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip
  echo '6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7  /tmp/protoc.zip' \
    | sha256sum -c -
  rm -rf "$HOME/.proto-tools/protoc"
  mkdir -p "$HOME/.proto-tools/protoc"
  unzip -o -q /tmp/protoc.zip -d "$HOME/.proto-tools/protoc"
  local go_bin
  go_bin="$(go env GOPATH)/bin"
  export PATH="$HOME/.proto-tools/protoc/bin:$go_bin:$PATH"
  python3 -m venv .venv-proto
  .venv-proto/bin/python -m pip install --quiet \
    'protobuf==7.35.1' \
    'connectrpc==0.11.1' \
    'protoc-gen-connectrpc==0.11.1'
}

run_contracts_proto() {
  local base_sha="${VERIFICATION_PR_BASE_SHA:-${VERIFICATION_PUSH_BEFORE_SHA:-}}"
  install_contract_toolchain
  if [ -z "$base_sha" ] || [[ "$base_sha" =~ ^0+$ ]]; then
    base_sha="$(git rev-parse HEAD^)"
  fi
  (
    cd proto
    buf lint
    buf breaking --against "../.git#commit=${base_sha},subdir=proto"
  )
  (
    cd proto
    rm -rf \
      ../libs/gen-go/codewire \
      ../libs/gen-python/codewire \
      ../packages/codewire-proto-ts/src/gen/codewire
    buf generate --template buf.gen.codewire.yaml
    buf generate --template buf.gen.google-rpc-ts.yaml
    buf generate --template buf.gen.google-rpc-python.yaml
    buf build --as-file-descriptor-set \
      -o ../crates/codewire-proto/codewire_descriptor.bin
  )
  git diff --exit-code \
    crates/codewire-proto/codewire_descriptor.bin \
    libs/gen-go libs/gen-python packages/codewire-proto-ts/src/gen
  local generated_untracked
  generated_untracked="$(git ls-files --others --exclude-standard -- \
    crates/codewire-proto/codewire_descriptor.bin libs/gen-go libs/gen-python \
    packages/codewire-proto-ts/src/gen)"
  if [ -n "$generated_untracked" ]; then
    printf '%s\n' "$generated_untracked" >&2
    echo 'generated proto code is untracked; run generation and commit it' >&2
    return 1
  fi

  (cd libs/gen-go && GOWORK=off go build ./... && GOWORK=off go vet ./...)
  bun --filter @codewire/proto-ts typecheck
  python3 scripts/checks/repo_checks.py proto-package-boundaries --self-test
  cargo test --locked -p codewire-proto

  PYTHONPATH=libs/gen-python .venv-proto/bin/python - <<'PY'
import py_compile
from pathlib import Path

root = Path("libs/gen-python")
modules = [
    ".".join(path.relative_to(root).with_suffix("").parts)
    for path in sorted(root.rglob("*.py"))
    if path.name.endswith("_pb2.py")
]
for module in modules:
    __import__(module)
stubs = sorted(root.rglob("*_connect.py"))
for stub in stubs:
    py_compile.compile(str(stub), doraise=True)
print(f"generated Python message imports: {len(modules)}; Connect stubs compiled: {len(stubs)}")
PY
}

run_contracts_rest() {
  (cd libs/api-client-go && GOWORK=off go build ./... && GOWORK=off go vet ./...)
  bun run openapi:check-source
  bun run openapi:check-rust-source
  bun run types:generate:ts
  git diff --exit-code \
    packages/codewire-types/generated/api.d.ts \
    libs/api-client-ts/src/schema.gen.ts
}

run_contracts() {
  local run_proto=false run_rest=false
  selected contracts_proto && run_proto=true
  selected contracts_rest && run_rest=true

  if [ "$run_proto" = false ] && [ "$run_rest" = false ]; then
    echo "::error::Contracts selected without contracts_proto or contracts_rest"
    exit 1
  fi

  install_bun_dependencies
  if [ "$run_proto" = true ]; then
    run_contracts_proto
  fi
  if [ "$run_rest" = true ]; then
    run_contracts_rest
  fi
}

run_go_support() {
  if selected go_tailnet; then
    (cd libs/tailnet && GOWORK=off go vet ./... && GOWORK=off go test -short ./...)
    scripts/ci/verify/tailnet-parity.sh
  fi
  if selected go_consumer_interop; then
    cargo test --locked -p codewire-server-core \
      --test go_consumer_interop generated_go_client_consumes_rust_connect \
      -- --exact --ignored --nocapture
  fi
}

run_web() {
  install_bun_dependencies
  bun --filter @codewire/dashboard typecheck
  bun --filter @codewire/dashboard test:unit
  bun --filter @codewire/docs build
}

run_ios_config() {
  python3 - <<'PY'
from pathlib import Path
import plistlib

root = Path("apps/ios")
if "infoPath: Resources/Info.plist" not in (root / "xtool.yml").read_text():
    raise SystemExit("xtool must use the source-owned Info.plist")
with (root / "Resources/Info.plist").open("rb") as stream:
    info = plistlib.load(stream)
schemes = [
    scheme
    for entry in info.get("CFBundleURLTypes", [])
    for scheme in entry.get("CFBundleURLSchemes", [])
]
if schemes != ["sh.codewire.ios"]:
    raise SystemExit("Info.plist must register exactly the iOS OAuth callback scheme")
PY
}

run_ios() {
  run_ios_config
  make ios-test
}

run_sdk_go() {
  (cd libs/sdk-go && GOWORK=off go build ./... && GOWORK=off go vet ./... \
    && GOWORK=off go test ./... -count=1 -timeout 60s)
}

run_sdk_ts() {
  make test-sdk-ts
  scripts/runtime/tests/test-run-sdk-ts-e2e.sh
}

run_sdk_python() {
  local repository_root="$PWD"
  python3 -m venv .venv-sdk
  .venv-sdk/bin/python -m pip install --upgrade pip
  .venv-sdk/bin/python -m pip install --require-hashes \
    -r libs/sdk-python/requirements.lock
  .venv-sdk/bin/python -m pip install --no-deps libs/sdk-python
  local sdk_site_packages forbidden_package
  sdk_site_packages="$(
    .venv-sdk/bin/python -c \
      'import sysconfig; print(sysconfig.get_paths()["purelib"])'
  )"
  [ -d "$sdk_site_packages/codewire/v1" ]
  [ -d "$sdk_site_packages/google/rpc" ]
  for forbidden_package in admin console internal testing; do
    if [ -e "$sdk_site_packages/codewire/$forbidden_package" ]; then
      echo "::error::Python SDK wheel leaked generated codewire/$forbidden_package" >&2
      return 1
    fi
  done
  (cd libs/sdk-python && PYTHONPATH="$repository_root/libs/gen-python${PYTHONPATH:+:$PYTHONPATH}" \
    "$repository_root/.venv-sdk/bin/python" -m unittest test_sdk test_transport -v)
  (cd /tmp && "$repository_root/.venv-sdk/bin/python" -c \
    'from codewire._transport import ConnectTransport; from codewire.errors import CodewireError; from codewire.v1.api_key_connect import ApiKeyServiceClientSync; from google.rpc.error_details_pb2 import BadRequest; assert CodewireError and BadRequest and isinstance(ConnectTransport("https://codewire.example", "").client(ApiKeyServiceClientSync), ApiKeyServiceClientSync)')
  scripts/runtime/tests/test-run-sdk-python-e2e.sh
}

run_apikey_smoke_tooling() {
  scripts/runtime/tests/test-apikey-smoke.sh
}

run_runtime_confidential() {
  scripts/runtime/tests/test-resolve-coco-support-lock.sh
  scripts/runtime/tests/test-confidential-snp-smoke-contract.sh
}

run_rust() {
  if selected rust_pkg_codewire_desktop; then
    run_detached_desktop
  fi
  if has_root_rust_selection; then
    run_rust_packages rust_pkg_
  fi
  if selected rust_pkg_codewire_oidc; then
    cargo check -p codewire-oidc --no-default-features
    cargo test -p codewire-oidc --features axum
    cargo run -p codewire-oidc --example in_memory >/dev/null
  fi
}

run_rust_curated_locks() {
  scripts/ci/tests/test-curated-rust-locks.sh
}

run_derp_contract() {
  local port=$((61000 + (${GITHUB_RUN_ID:-$$} % 4000)))
  local log_dir="${RUNNER_TEMP:-$ROOT/.tmp}/codewire-derp-contract-${GITHUB_RUN_ID:-$$}"
  mkdir -p "$log_dir"
  (
    PORT="$port" TLS_PORT='' STUN_PORT=-1 RUST_LOG=info \
      "$CARGO_DEBUG_DIR/codewire-derp" > "$log_dir/derp.log" 2>&1 &
    local pid=$!
    trap 'kill "$pid" 2>/dev/null || true' EXIT
    local _
    for _ in $(seq 1 45); do
      if curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
        break
      fi
      if ! kill -0 "$pid" 2>/dev/null; then
        cat "$log_dir/derp.log" >&2
        exit 1
      fi
      sleep 1
    done
    if ! curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null; then
      cat "$log_dir/derp.log" >&2
      exit 1
    fi
    (
      cd tests/contract
      DERP_BASE_URL="http://127.0.0.1:${port}/derp" GOWORK=off \
        go test -count=1 -v \
          -run '^TestRawHTTPUpgradeRelaysTailscaleGoClients$' ./derp/... \
          | tee "$log_dir/derp-contract.log"
      DERP_BASE_URL="http://127.0.0.1:${port}/derp" DERP_WEBSOCKET=1 \
        GOWORK=off go test -tags ts_debug_websockets -count=1 -v \
        -run '^TestWebSocketFallbackRelaysTailscaleGoClients$' ./derp/... \
        | tee "$log_dir/derp-websocket-contract.log"
    )
    local logfile
    for logfile in "$log_dir/derp-contract.log" \
        "$log_dir/derp-websocket-contract.log"; do
      if grep -Eq -- '--- SKIP' "$logfile" \
        || ! grep -Eq -- '^[[:space:]]*--- PASS:' "$logfile"; then
        echo "::error::DERP contract reported a skip or no executed test: ${logfile}"
        exit 1
      fi
    done
  )
}

run_transport() {
  run_rust_packages transport_pkg_
  if selected transport_derp_contract; then
    run_derp_contract
  fi
}

install_caddy() {
  local version="${CADDY_VERSION:-2.10.2}"
  mkdir -p "$HOME/.local/bin"
  (
    cd /tmp
    curl -fsSLO "https://github.com/caddyserver/caddy/releases/download/v${version}/caddy_${version}_linux_amd64.tar.gz"
    curl -fsSLO "https://github.com/caddyserver/caddy/releases/download/v${version}/caddy_${version}_checksums.txt"
    grep "caddy_${version}_linux_amd64.tar.gz" \
      "caddy_${version}_checksums.txt" | sha512sum -c -
    tar -xzf "caddy_${version}_linux_amd64.tar.gz" caddy
    install caddy "$HOME/.local/bin/caddy"
  )
  export PATH="$HOME/.local/bin:$PATH"
}

run_edge() {
  install_caddy
  caddy validate --config Caddyfile --adapter caddyfile
  caddy validate --config Caddyfile.docker --adapter caddyfile
  local file pattern
  for file in Caddyfile Caddyfile.docker; do
    grep -qF '*.codewire.localhost {' "$file"
    grep -qF '@billing path_regexp' "$file"
    for pattern in \
        /api/webhooks/stripe /api/v1/admin/billing /api/v1/billing/plans \
        '/api/v1/organizations/[^/]+/billing' \
        '/api/v1/organizations/[^/]+/environments/usage'; do
      grep -qF "$pattern" "$file"
    done
    grep -qF 'handle /api/* {' "$file"
    grep -qE 'reverse_proxy (localhost|127.0.0.1):8084' "$file"
    if grep -qE 'reverse_proxy (localhost|127.0.0.1):8080' "$file"; then
      echo "::error file=${file}::edge routes API traffic to the retired Go server"
      return 1
    fi
  done
  python3 scripts/checks/repo_checks.py connect-edge-routing --self-test
  scripts/ci/tests/test-kind-e2e-cleanup.sh
  scripts/ci/tests/test-kind-e2e-suites.sh
  scripts/ci/tests/test-kind-forwards.sh
}

run_release() {
  scripts/ci/tests/test-base-image-source.sh
  scripts/ci/tests/test-build-push-image.sh
  scripts/ci/tests/test-claude-e2e-workflow.sh
  scripts/ci/tests/test-fetch-infisical-ci-secret.sh
  scripts/ci/tests/test-verify-release-tag-ref.sh
  scripts/ci/tests/test-verify-release-tag-receipt.sh
  scripts/ci/tests/test-mirror-git-tags.sh
  scripts/ci/tests/test-copy-image-to-ghcr.sh
  scripts/ci/tests/test-dispatch-deploy-dev.sh
  scripts/ci/tests/test-dispatch-deploy-prod.sh
  scripts/ci/tests/test-publish-image-to-ghcr.sh
  scripts/ci/tests/test-run-skopeo-container.sh
  scripts/ci/tests/test-support-images-workflow.sh
  scripts/ci/tests/test-workspace-image-verify-workflow.sh
  python3 scripts/ci/tests/test-image-bundle.py
  scripts/ci/tests/test-deploy-prod-workflow.sh
  python3 scripts/checks/repo_checks.py production-source-ownership --self-test
}

install_kustomize() {
  local version="${KUSTOMIZE_VERSION:-v5.4.3}"
  mkdir -p "$HOME/.local/bin"
  (
    cd /tmp
    curl -fsSLO "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/${version}/kustomize_${version}_linux_amd64.tar.gz"
    curl -fsSLO "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/${version}/checksums.txt"
    grep "kustomize_${version}_linux_amd64.tar.gz" checksums.txt | sha256sum -c -
    tar -xzf "kustomize_${version}_linux_amd64.tar.gz" -C "$HOME/.local/bin"
  )
  export PATH="$HOME/.local/bin:$PATH"
}

install_helm() {
  local version="${HELM_VERSION:-v3.16.4}"
  mkdir -p "$HOME/.local/bin"
  (
    cd /tmp
    curl -fsSLO "https://get.helm.sh/helm-${version}-linux-amd64.tar.gz"
    curl -fsSL "https://get.helm.sh/helm-${version}-linux-amd64.tar.gz.sha256sum" \
      -o helm.sha256
    sha256sum -c helm.sha256
    tar -xzf "helm-${version}-linux-amd64.tar.gz"
    install linux-amd64/helm "$HOME/.local/bin/helm"
  )
  export PATH="$HOME/.local/bin:$PATH"
}

run_deploy() {
  scripts/ci/tests/test-install-temporal.sh
  scripts/ci/tests/test-deploy-dev.sh
  install_kustomize
  python3 scripts/checks/repo_checks.py orchestration-host-key-authz --self-test

  local overlay
  for overlay in \
      deployments/k8s/base deployments/k8s/coordinator deployments/k8s/idp \
      deployments/k8s/orchestration \
      deployments/k8s/derp deployments/k8s/flux/mesh-dev \
      deployments/k8s/flux/production deployments/k8s/flux/temporal-dev \
      deployments/k8s/flux/temporal-production \
      deployments/k8s/overlays/local-kind \
      deployments/k8s/overlays/local-kind-static \
      deployments/k8s/overlays/dev deployments/k8s/overlays/production \
      tests/e2e/kind; do
    kustomize build "$overlay" >/dev/null
  done

  install_helm
  scripts/ci/tests/test-deploy-prod-render.sh
  helm template test apps/cli/charts/codewire-mesh \
    --set mesh.baseURL=https://mesh.test \
    | grep -q 'exec codewire-mesh'
  local default_mesh_render retirement_mesh_render retirement_job
  default_mesh_render="$(helm template test apps/cli/charts/codewire-mesh \
    --set mesh.baseURL=https://mesh.test)"
  if grep -Fq 'prelaunch-retire-legacy-auth' <<<"$default_mesh_render"; then
    echo "::error::legacy-auth retirement hook rendered without explicit opt-in"
    return 1
  fi
  retirement_mesh_render="$(helm template codewire-mesh-retirement \
    apps/cli/charts/codewire-mesh \
    --set mesh.baseURL=https://mesh.test \
    --set database.enabled=true \
    --set database.secretName=mesh-database-only \
    --set prelaunchLegacyAuthRetirement.enabled=true \
    --set image.repository=registry.test/codewire/mesh \
    --set image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --set meshAuthorization.url=http://authorization.test \
    --set meshAuthorization.hmacSecretRef.name=must-not-enter-hook)"
  retirement_job="$(awk 'BEGIN { RS="---" } /kind: Job/ && /prelaunch-retire-legacy-auth/ { print }' \
    <<<"$retirement_mesh_render")"
  grep -Fq '"helm.sh/hook": pre-upgrade' <<<"$retirement_job"
  grep -Fq '"helm.sh/hook-delete-policy": before-hook-creation,hook-succeeded' \
    <<<"$retirement_job"
  grep -Fq 'automountServiceAccountToken: false' <<<"$retirement_job"
  grep -Fq 'registry.test/codewire/mesh@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    <<<"$retirement_job"
  grep -Fq 'name: DATABASE_URL' <<<"$retirement_job"
  grep -Fq 'name: mesh-database-only' <<<"$retirement_job"
  grep -Fq 'args: ["prelaunch-retire-legacy-auth"]' <<<"$retirement_job"
  if grep -Fq 'must-not-enter-hook' <<<"$retirement_job"; then
    echo "::error::Mesh authorization credential entered the database-only retirement hook"
    return 1
  fi
  local dev_mesh_render
  dev_mesh_render="$(helm template codewire-mesh-dev apps/cli/charts/codewire-mesh \
    -f deployments/k8s/mesh-dev/values.yaml \
    --set image.repository=registry.test/codewire/mesh --set image.tag=test)"
  grep -q 'mesh.codewire-dev.sh' <<<"$dev_mesh_render"
  grep -Fq -- '--database-url="$DATABASE_URL"' <<<"$dev_mesh_render"
  grep -Fq 'name: DATABASE_URL' <<<"$dev_mesh_render"
  grep -Fq 'name: codewire-mesh-db-app' <<<"$dev_mesh_render"
  grep -Fq 'name: CODEWIRE_MESH_AUTHORIZATION_URL' <<<"$dev_mesh_render"
  grep -Fq 'http://codewire-orchestration.dev.svc.cluster.local:8085' <<<"$dev_mesh_render"
  grep -Fq 'name: CODEWIRE_MESH_AUTHORIZATION_HMAC_SECRET' <<<"$dev_mesh_render"
  grep -Fq 'name: codewire-mesh-coordinator' <<<"$dev_mesh_render"
  grep -Fq 'nginx.ingress.kubernetes.io/backend-protocol: "GRPC"' <<<"$dev_mesh_render"
  grep -Fq 'path: /codewire\.internal\.v1\.MeshCoordinatorService/' <<<"$dev_mesh_render"
  python3 scripts/checks/repo_checks.py production-source-ownership --self-test
}

run_security() {
  if selected security_dev_smoke_auth; then
    scripts/runtime/tests/test-with-dev-smoke-auth.sh
  fi
  if selected security_idp_kek; then
    install_kustomize
    python3 scripts/checks/repo_checks.py idp-signing-kek-isolation
  fi
  if selected security_js; then
    scripts/checks/security/audit-js-supply-chain.sh
  fi
  if selected security_go; then
    local module
    for module in "${GO_MODULE_DIRS[@]}"; do
      (cd "$module" && GOWORK=off go mod verify)
    done
    local go_bin
    go_bin="$(go env GOPATH)/bin"
    export PATH="$go_bin:$PATH"
    go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
    go install honnef.co/go/tools/cmd/staticcheck@2026.1
    go install github.com/securego/gosec/v2/cmd/gosec@latest
    for module in "${GO_MODULE_DIRS[@]}"; do
      (cd "$module" && GOWORK=off govulncheck ./...)
    done
    staticcheck -checks 'all,-SA1019,-ST1000,-ST1003' \
      "${GO_PACKAGE_PATTERNS[@]}"
    gosec -no-fail -quiet "${GO_PACKAGE_PATTERNS[@]}"
  fi
}

case "$FAMILY" in
  policy) run_policy ;;
  contracts) run_contracts ;;
  go-support) run_go_support ;;
  web) run_web ;;
  ios) run_ios ;;
  ios-config) run_ios_config ;;
  sdk-go) run_sdk_go ;;
  sdk-ts) run_sdk_ts ;;
  sdk-python) run_sdk_python ;;
  service-apikey-smoke) run_apikey_smoke_tooling ;;
  runtime-confidential) run_runtime_confidential ;;
  rust) run_rust ;;
  rust-curated-locks) run_rust_curated_locks ;;
  transport) run_transport ;;
  edge) run_edge ;;
  release) run_release ;;
  deploy) run_deploy ;;
  security) run_security ;;
  *)
    echo "usage: run-product-verification.sh policy|contracts|go-support|web|ios|sdk-go|sdk-ts|sdk-python|service-apikey-smoke|runtime-confidential|rust|rust-curated-locks|transport|edge|release|deploy|security" >&2
    exit 2
    ;;
esac
