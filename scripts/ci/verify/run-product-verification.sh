#!/usr/bin/env bash
# Focused automatic product-verification families. Toolchain setup belongs to
# the owning workflow job; this script is also callable for local diagnosis.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
FAMILY="${1:-}"
SELECTION="${VERIFICATION_SELECTION:-|valid:v3|complete|}"
cd "$ROOT"
CARGO_TARGET_DIR="$(scripts/ci/verify/resolve-cargo-target-dir.sh "$ROOT")"
export CARGO_TARGET_DIR
CARGO_DEBUG_DIR="$CARGO_TARGET_DIR/debug"
# Composition state is never accepted from a caller's environment.
RUST_COMPOSE_FORMAT=false
RUST_COMPOSE_FORMAT_DONE=false

selected() {
  [[ "$SELECTION" == *"|$1|"* ]]
}

install_bun_dependencies() {
  PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    bun install --frozen-lockfile --ignore-scripts
}

GO_MODULE_DIRS=(
  libs/gen-go
  libs/sdk-go
  libs/tailnet
  tests/contract
)
GO_PACKAGE_PATTERNS=(
  ./libs/gen-go/...
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
  # The selector gives Rust and transport distinct package/feature graphs.
  # Preserve every generic invocation; only workspace formatting is shared.
  if [[ "$RUST_COMPOSE_FORMAT" != true || "$RUST_COMPOSE_FORMAT_DONE" != true ]]; then
    cargo fmt --all --check || return $?
    RUST_COMPOSE_FORMAT_DONE=true
  fi
  cargo build --locked "${RUST_PACKAGE_ARGS[@]}" || return $?
  cargo clippy "${RUST_PACKAGE_ARGS[@]}" --all-targets -- -D warnings || return $?
  cargo test "${RUST_PACKAGE_ARGS[@]}" --all-targets || return $?
}

run_rust_transport() {
  if ! selected rust && ! selected transport; then
    echo '::error::Rust/transport composition selected without either capability' >&2
    return 1
  fi
  RUST_COMPOSE_FORMAT=true
  RUST_COMPOSE_FORMAT_DONE=false
  if selected rust; then
    run_rust
  fi
  if selected transport; then
    run_transport
  fi
}

run_detached_desktop() {
  local manifest="crates/codewire-desktop/Cargo.toml"
  local desktop_target_dir="${CODEWIRE_DESKTOP_CARGO_TARGET_DIR:-$CARGO_TARGET_DIR}"
  CARGO_TARGET_DIR="$desktop_target_dir" cargo fmt --manifest-path "$manifest" --check
  CARGO_TARGET_DIR="$desktop_target_dir" cargo check --locked --manifest-path "$manifest"
  CARGO_TARGET_DIR="$desktop_target_dir" cargo test --locked --manifest-path "$manifest"
  CARGO_TARGET_DIR="$desktop_target_dir" \
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

run_verification_shell_syntax() {
  local candidate
  for candidate in \
      .githooks/pre-push \
      scripts/dev/preflight.sh \
      scripts/dev/install-hooks.sh \
      scripts/ci/select/select-verification.sh \
      scripts/ci/receipts/verify-release-tag-receipt.sh \
      scripts/ci/tests/test-select-verification.sh \
      scripts/ci/tests/test-verify-release-tag-receipt.sh \
      scripts/ci/tests/test-pre-push-worktree.sh \
      scripts/ci/verify/integration-postgres.sh \
      scripts/ci/verify/run-product-verification.sh \
      scripts/ci/verify/check-darwin-cross.sh \
      scripts/ci/tests/test-darwin-cross-check.sh \
      scripts/ci/verify/check-curated-rust-locks.sh \
      scripts/ci/tests/test-curated-rust-locks.sh \
      scripts/ci/verify/run-integration-verification.sh \
      scripts/ci/tests/test-integration-postgres.sh \
      scripts/ci/verify/rust-stack-rehearsal.sh; do
    if [ -f "$candidate" ]; then
      bash -n "$candidate"
    fi
  done
  if [ -d scripts/runtime ]; then
    while IFS= read -r -d '' candidate; do
      bash -n "$candidate"
    done < <(find scripts/runtime -type f -name '*.sh' -print0)
  fi
}

run_shell_policy() {
  scripts/ci/verify/check-shell-scripts.sh --self-test
  scripts/ci/verify/check-shell-scripts.sh
}

run_policy_core() {
  run_verification_shell_syntax
  scripts/ci/tests/test-setup-kubeconfig.sh
  scripts/ci/tests/test-resolve-deployed-source.sh
  scripts/ci/tests/test-select-verification.sh
  scripts/ci/tests/test-service-ssh-image-verifier.sh
  scripts/ci/tests/test-shellcheck-policy-domain.sh
  scripts/ci/tests/test-go-source-ownership.sh
  scripts/ci/tests/test-rust-owned-fixtures.sh
  scripts/ci/tests/test-require-verification-results.sh
  scripts/ci/tests/test-verify-tested-tree-receipt.sh
  scripts/ci/tests/test-resolve-cargo-target-dir.sh
  scripts/ci/tests/test-cargo-target-runner-failures.sh
  scripts/ci/tests/test-darwin-cross-check.sh
  scripts/ci/tests/test-package-codewire-desktop.sh
  scripts/ci/tests/test-rust-toolchain.sh
  scripts/ci/tests/test-cargo-cache-capacity.sh
  scripts/ci/tests/test-admin-proto-boundary.sh
  scripts/ci/tests/test-ci-tool-downloads.sh
  scripts/ci/tests/test-build-local-image.sh
  scripts/ci/tests/test-dashboard-image-network-probe.sh
  scripts/ci/tests/test-workspace-agent-contract.sh
  scripts/ci/tests/test-workspace-image-verify-workflow.sh
  scripts/ci/tests/test-build-kind-smokes.sh
  python3 -B scripts/ci/tests/test-kind-build-artifacts.py
  scripts/ci/tests/test-openbao-only-secret-authority.sh
  scripts/ci/tests/test-preflight-openbao-native-secrets.sh
  scripts/ci/tests/test-sync-local-secrets.sh
  scripts/ci/tests/test-source-approval-workflow.sh
  scripts/ci/tests/test-fetch-openbao-sccache-r2-credentials.sh
  scripts/ci/tests/test-select-untrusted-rust-cache.sh
  scripts/ci/tests/test-retired-local-sdk-contract.sh
  scripts/ci/tests/test-integration-postgres.sh
  python3 scripts/ci/tests/test-repo-checks-modules.py
  python3 scripts/dev/test-macos-cli.py
  python3 scripts/dev/test-macos-ext4-tool.py
  python3 scripts/dev/test-macos-app-sandbox-canary.py
  python3 crates/codewire-local-vmm/macos-sandbox-canary-experiment/Tests/test_static_contract.py
  python3 scripts/dev/test-macos-vz-inode-probe.py
  python3 scripts/dev/test-macos-vz-console-pair.py
  python3 scripts/dev/test-macos-vz-product-network.py
  python3 scripts/dev/test-macos-vz-production-boot.py
  python3 scripts/dev/test-macos-vz-workload-network.py
  python3 scripts/checks/repo_checks.py license-map
  python3 scripts/checks/repo_checks.py permanent-raw-surface --self-test
  python3 scripts/checks/repo_checks.py rust-validation-source
  python3 scripts/checks/repo_checks.py retired-reference-source
  python3 scripts/checks/source/check-native-desktop-ui.py
  python3 scripts/checks/repo_checks.py go-source-classification
}

run_policy() {
  # A legacy trusted selector does not know when omission is authoritative, so
  # it must retain the historical full ShellCheck behavior. Only a trusted
  # selector that emits policy_shell_omittable may omit the shell domain.
  if selected policy_shell || ! selected policy_shell_omittable; then
    run_shell_policy
  fi
  run_policy_core
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
  )
  python3 scripts/checks/proto_breaking.py --self-test
  BUF="$(command -v buf)" python3 scripts/checks/proto_breaking.py --base-sha "$base_sha"
  (
    cd proto
    rm -rf \
      ../libs/gen-go/codewire \
      ../libs/gen-python/codewire \
      ../packages/codewire-proto-ts/src/gen/codewire
    buf generate --template buf.gen.codewire.yaml
    buf generate --template buf.gen.google-rpc-ts.yaml
    buf generate --template buf.gen.google-rpc-python.yaml
  )
  scripts/ci/proto/build-rust-descriptors.sh
  git diff --exit-code \
    crates/codewire-proto/codewire_descriptor.bin \
    crates/codewire-admin-proto/codewire_admin_descriptor.bin \
    libs/gen-go libs/gen-python packages/codewire-proto-ts/src/gen
  local generated_untracked
  generated_untracked="$(git ls-files --others --exclude-standard -- \
    crates/codewire-proto/codewire_descriptor.bin \
    crates/codewire-admin-proto/codewire_admin_descriptor.bin libs/gen-go libs/gen-python \
    packages/codewire-proto-ts/src/gen)"
  if [ -n "$generated_untracked" ]; then
    printf '%s\n' "$generated_untracked" >&2
    echo 'generated proto code is untracked; run generation and commit it' >&2
    return 1
  fi

  (cd libs/gen-go && GOWORK=off go build ./... && GOWORK=off go vet ./...)
  bun --filter @codewire/proto-ts typecheck
  python3 scripts/checks/repo_checks.py proto-package-boundaries --self-test
  cargo test --locked -p codewire-proto -p codewire-admin-proto

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

run_contracts() {
  if ! selected contracts_proto; then
    echo "::error::Contracts selected without contracts_proto"
    exit 1
  fi

  install_bun_dependencies
  run_contracts_proto
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
  cargo test --locked -p codewire-dashboard-web --lib
  bun run --cwd apps/dashboard typecheck
  bun run --cwd apps/dashboard test:fixtures
  ./apps/dashboard/node_modules/.bin/playwright test \
    --config apps/dashboard/playwright.config.ts --list
  scripts/ci/tests/test-dashboard-browser-gate.sh
  scripts/checks/security/audit-js-supply-chain.sh
  scripts/checks/security/audit-runtime-images.sh --self-test
  scripts/checks/security/audit-runtime-images.sh
  if selected kind; then
    echo 'dashboard image verification deferred to the exact-image Kind transaction'
  elif [ "${CODEWIRE_DASHBOARD_IMAGE_DEFERRED:-false}" = true ]; then
    echo 'dashboard image verification deferred to the selected CI container transaction'
  else
    run_dashboard_image
  fi
}

run_dashboard_image() {
  make verify-dashboard-image \
    DASHBOARD_VERIFY_IMAGE="codewire-dashboard:verification-${GITHUB_RUN_ID:-local}"
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
  local package_work sdist wheel
  package_work="$(mktemp -d "${TMPDIR:-/tmp}/codewire-sdk-python-package.XXXXXX")"
  python3 -m venv .venv-sdk
  .venv-sdk/bin/python -m pip install --upgrade pip
  .venv-sdk/bin/python -m pip install --require-hashes \
    -r libs/sdk-python/requirements-build.lock
  .venv-sdk/bin/python -m build --no-isolation \
    --outdir "$package_work/dist" libs/sdk-python
  sdist="$(find "$package_work/dist" -maxdepth 1 -type f -name '*.tar.gz' -print -quit)"
  wheel="$(find "$package_work/dist" -maxdepth 1 -type f -name '*.whl' -print -quit)"
  [ -n "$sdist" ]
  [ -n "$wheel" ]
  python3 - "$sdist" "$wheel" <<'PY'
import sys
import tarfile
import zipfile

sdist_path, wheel_path = sys.argv[1:]
forbidden = ("codewire/admin/", "codewire/console/", "codewire/internal/", "codewire/testing/")

with tarfile.open(sdist_path, "r:gz") as archive:
    sdist_names = [name.split("/", 1)[-1] for name in archive.getnames()]
if not any(name.startswith("_codewire_generated/codewire/v1/") for name in sdist_names):
    raise SystemExit("Python SDK sdist is missing generated codewire/v1")
if not any(name.startswith("_codewire_generated/google/rpc/") for name in sdist_names):
    raise SystemExit("Python SDK sdist is missing generated google/rpc")
if any(any(part in name for part in forbidden) for name in sdist_names):
    raise SystemExit("Python SDK sdist leaked a forbidden generated package")

with zipfile.ZipFile(wheel_path) as archive:
    wheel_names = archive.namelist()
if not any(name.startswith("codewire/v1/") for name in wheel_names):
    raise SystemExit("Python SDK wheel is missing generated codewire/v1")
if not any(name.startswith("google/rpc/") for name in wheel_names):
    raise SystemExit("Python SDK wheel is missing generated google/rpc")
if any(name.startswith("_codewire_generated/") for name in wheel_names):
    raise SystemExit("Python SDK wheel leaked its sdist-only generated source")
if any(any(part in name for part in forbidden) for name in wheel_names):
    raise SystemExit("Python SDK wheel leaked a forbidden generated package")
PY
  .venv-sdk/bin/python -m pip install --require-hashes \
    -r libs/sdk-python/requirements.lock
  .venv-sdk/bin/python -m pip install --force-reinstall --no-deps "$wheel"
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
  rm -rf -- "$package_work"
}

run_apikey_smoke_tooling() {
  scripts/runtime/tests/test-apikey-smoke.sh
}

run_runtime_confidential() {
  scripts/runtime/tests/test-resolve-coco-support-lock.sh
  scripts/runtime/tests/test-confidential-snp-smoke-contract.sh
}

run_runtime_dev_smoke() {
  install_bun_dependencies
  bun test apps/dashboard/scripts/prepare-dev-smoke-browser-auth.test.ts
  scripts/runtime/tests/test-provision-dev-smoke-user.sh
  scripts/runtime/tests/test-smoke-dev-commodity.sh
  scripts/runtime/tests/test-local-platform-sources-smoke.sh
  scripts/runtime/tests/test-private-checkout-smoke.sh
  scripts/runtime/tests/test-provider-codex-smoke.sh
  python3 -B scripts/runtime/tests/test-provider-codex-workload.py
  scripts/runtime/tests/test-provider-anthropic-smoke.sh
  python3 -B scripts/runtime/tests/test-provider-anthropic-workload.py
  scripts/runtime/tests/test-provider-openai-smoke.sh
  python3 -B scripts/runtime/tests/test-provider-openai-workload.py
  scripts/runtime/tests/test-secrets-credentials-acceptance-runner.sh
  python3 -B scripts/runtime/tests/test-native-mesh-listener.py
}

run_rust() {
  if selected rust_pkg_codewire_desktop; then
    run_detached_desktop
  fi
  if has_root_rust_selection; then
    run_rust_packages rust_pkg_
  fi
  if selected rust_workspace || selected rust_pkg_codewire_cli \
      || selected rust_pkg_codewire_cli_bin || selected rust_pkg_codewire_admin_proto \
      || selected rust_pkg_codewire_proto; then
    scripts/ci/tests/test-admin-proto-boundary.sh --cli-dependencies
  fi
  if selected rust_workspace || selected rust_pkg_codewire_protected_store \
      || selected rust_pkg_codewire_orchestration; then
    scripts/ci/tests/test-openbao-only-secret-authority.sh --production-features
  fi
  if selected rust_workspace || selected rust_pkg_codewire_protected_store; then
    # Platform primitives are optional; default workspace/package tests alone
    # do not promise that their tests or warning-denied targets are exercised.
    cargo clippy --locked -p codewire-protected-store --features platform --all-targets -- -D warnings
    cargo test --locked -p codewire-protected-store --features platform --all-targets
  fi
  if selected rust_workspace || selected rust_pkg_codewire_credential_broker; then
    # Exercise the isolated platform build explicitly; the default local
    # feature cannot qualify platform admission or its production graph.
    scripts/ci/tests/test-openbao-only-secret-authority.sh --production-broker-features
    cargo clippy --locked -p codewire-credential-broker --no-default-features --features platform,codex-enrollment --all-targets -- -D warnings
    cargo test --locked -p codewire-credential-broker --no-default-features --features platform,codex-enrollment --all-targets
  fi
  if selected rust_workspace || selected rust_pkg_codewire_server_core \
      || selected rust_pkg_codewire_orchestration; then
    # The shared projected-Pod verifier is opt-in. Exercise its real feature
    # and focused identity tests without depending on workspace unification.
    cargo clippy --locked -p codewire-server-core --features kubernetes-identity --all-targets -- -D warnings
    cargo test --locked -p codewire-server-core --features kubernetes-identity --lib pod_identity::
  fi
  if selected rust_workspace || selected rust_pkg_codewire_credential_service; then
    scripts/ci/tests/test-openbao-only-secret-authority.sh --production-service-features
    cargo clippy --locked -p codewire-credential-service --features enrollment --all-targets -- -D warnings
    cargo test --locked -p codewire-credential-service --features enrollment --all-targets
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
  if selected transport_pkg_codewire_local_vmm; then
    crates/codewire-local-vmm/macos-vz-runner/Tests/test_ipc_system.sh
    python3 crates/codewire-local-vmm/macos-vz-runner/Tests/test_static_contract.py
    python3 crates/codewire-local-vmm/macos-vz-runner/Tests/test_console_pair_static_contract.py
    cargo test --locked -p codewire-local-vmm --features macos-console-pair-fixture \
      --lib macos_console_pair_fixture
    cargo clippy --locked -p codewire-local-vmm --features macos-console-pair-fixture \
      --lib --bin codewire-macos-console-pair-fixture -- -D warnings
    cargo test --locked -p codewire-local-vmm --features macos-product-network-fixture \
      --lib macos_console_pair_fixture
    cargo clippy --locked -p codewire-local-vmm --features macos-product-network-fixture \
      --lib --bin codewire-macos-product-network-fixture \
      --bin codewire-macos-console-pair-fixture -- -D warnings
    scripts/ci/verify/check-darwin-cross.sh
    # The opt-in developer verifier is not exercised by default package tests.
    # Keep its production-codec preparation and control-loop proof selected.
    cargo test --locked -p codewire-local-vmm --features macos-production-init-fixture \
      --bin codewire-macos-vz-fixture
    cargo clippy --locked -p codewire-local-vmm --features macos-production-init-fixture \
      --bin codewire-macos-vz-fixture -- -D warnings
    cargo test --locked -p codewire-local-vmm --features macos-workload-network-fixture \
      --bin codewire-macos-workload-network-fixture
    cargo clippy --locked -p codewire-local-vmm --features macos-workload-network-fixture \
      --bin codewire-macos-workload-network-fixture -- -D warnings
    # The workload client and isolated service endpoint must retain one exact
    # transcript even though they are built by different feature entrypoints.
    cargo test --locked -p codewire-local-vmm \
      --features macos-product-network-fixture,macos-workload-network-fixture \
      --lib macos_console_pair_fixture::product_network::tests::actual_workload_client_and_service_endpoint_share_exact_transcript \
      -- --exact
  fi
  if selected transport_pkg_codewire_vmm_guest_probe; then
    scripts/ci/verify/build-local-vmm-initramfs.sh --verify
    cargo test --locked -p codewire-vmm-guest-probe --features macos-workload-network-fixture \
      --lib macos_workload_network_fixture::
    cargo clippy --locked -p codewire-vmm-guest-probe --features macos-workload-network-fixture \
      --lib --bin codewire-vmm-guest-probe -- -D warnings
  fi
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
    grep -qF '@billing path /api/webhooks/stripe' "$file"
    grep -qF '/codewire.admin.v1.BillingCatalogService/*' "$file"
    grep -qF '/codewire.console.v1.BillingService/*' "$file"
    for pattern in \
        /api/v1/admin/billing /api/v1/billing/plans \
        '/api/v1/organizations/[^/]+/billing' \
        '/api/v1/organizations/[^/]+/environments/usage'; do
      if grep -qF "$pattern" "$file"; then
        echo "::error file=${file}::retired billing REST matcher remains: ${pattern}"
        return 1
      fi
    done
    grep -qF '/api/webhooks/stripe' "$file"
    grep -qF 'handle /api/* {' "$file"
    grep -qE 'reverse_proxy (localhost|127.0.0.1):8084' "$file"
    if grep -qE 'reverse_proxy (localhost|127.0.0.1):8080' "$file"; then
      echo "::error file=${file}::edge routes API traffic to the retired Go server"
      return 1
    fi
  done
  python3 scripts/checks/repo_checks.py connect-edge-routing --self-test
  scripts/ci/tests/test-kind-e2e-cleanup.sh
  scripts/ci/tests/test-kind-e2e-ubuntu-snapshot-runner.sh
  scripts/ci/tests/test-kind-e2e-suites.sh
  scripts/ci/tests/test-kind-forwards.sh
  python3 -B scripts/ci/tests/test-kind-codex-session.py
  python3 -B scripts/ci/tests/test-kind-credentials.py
}

run_release() {
  scripts/ci/tests/test-base-image-source.sh
  scripts/ci/tests/test-apt-get-with-retry.sh
  scripts/ci/tests/test-build-push-image.sh
  scripts/ci/tests/test-run-rust-build.sh
  scripts/ci/tests/test-fetch-openbao-ghcr-credentials.sh
  scripts/ci/tests/test-fetch-openbao-github-mirror-credentials.sh
  scripts/ci/tests/test-fetch-openbao-nexus-credentials.sh
  scripts/ci/tests/test-forgejo-action-mirrors.sh
  scripts/ci/tests/test-nexus-runtime-pull-contract.sh
  scripts/ci/tests/test-verify-release-tag-ref.sh
  scripts/ci/tests/test-verify-release-tag-receipt.sh
  scripts/ci/tests/test-mirror-git-tags.sh
  scripts/ci/tests/test-mint-github-app-token.sh
  scripts/ci/tests/test-copy-image-to-ghcr.sh
  scripts/ci/tests/test-dispatch-deploy-dev.sh
  scripts/ci/tests/test-dispatch-deploy-prod.sh
  scripts/ci/tests/test-publish-image-to-ghcr.sh
  scripts/ci/tests/test-resolve-published-support-pair.sh
  scripts/ci/tests/test-run-skopeo-container.sh
  scripts/ci/tests/test-support-images-workflow.sh
  scripts/ci/tests/test-workspace-image-verify-workflow.sh
  python3 scripts/ci/tests/test-image-bundle.py
  scripts/ci/tests/test-deploy-prod-workflow.sh
  python3 scripts/checks/repo_checks.py production-source-ownership --self-test
}

download_ci_tool() {
  local url="$1" output="$2"
  curl --fail --silent --show-error --location \
    --retry 5 --retry-all-errors --retry-delay 2 --connect-timeout 20 \
    --output "$output" "$url"
}

install_kustomize() {
  local version="${KUSTOMIZE_VERSION:-v5.4.3}"
  mkdir -p "$HOME/.local/bin"
  (
    cd /tmp
    download_ci_tool \
      "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/${version}/kustomize_${version}_linux_amd64.tar.gz" \
      "kustomize_${version}_linux_amd64.tar.gz"
    download_ci_tool \
      "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/${version}/checksums.txt" \
      checksums.txt
    grep "kustomize_${version}_linux_amd64.tar.gz" checksums.txt | sha256sum -c -
    tar -xzf "kustomize_${version}_linux_amd64.tar.gz" -C "$HOME/.local/bin"
  )
  export PATH="$HOME/.local/bin:$PATH"
}

install_helm() {
  local version="${HELM_VERSION:-v3.16.4}"
  local installed_version
  command -v helm >/dev/null 2>&1 || {
    echo "::error::CI runner image is missing sealed Helm ${version}" >&2
    return 1
  }
  installed_version="$(helm version --template '{{.Version}}')"
  if [ "$installed_version" != "$version" ]; then
    echo "::error::CI runner image Helm version ${installed_version} differs from ${version}" >&2
    return 1
  fi
}

run_deploy() {
  scripts/ci/tests/test-install-temporal.sh
  scripts/ci/plan/test.sh
  scripts/ci/tests/test-deploy-dev.sh
  scripts/ci/tests/test-build-push-runtime-images.sh
  install_kustomize
  python3 scripts/checks/repo_checks.py orchestration-host-key-authz --self-test

  local overlay
  for overlay in \
      deployments/k8s/base deployments/k8s/coordinator deployments/k8s/idp \
      deployments/k8s/orchestration deployments/k8s/credential-service \
      deployments/k8s/derp deployments/k8s/flux/mesh-dev \
      deployments/k8s/flux/production deployments/k8s/flux/temporal-dev \
      deployments/k8s/flux/temporal-production \
      deployments/k8s/overlays/local-kind \
      deployments/k8s/overlays/local-kind-static \
      deployments/k8s/overlays/dev deployments/k8s/overlays/production \
      tests/e2e/kind; do
    kustomize build "$overlay" >/dev/null
  done

  local dashboard_manifest dashboard_source
  for dashboard_source in \
      deployments/k8s/dashboard/deployment.yaml \
      deployments/k8s/overlays/dev/dashboard-deployment.yaml \
      deployments/k8s/overlays/local-kind/dashboard.yaml \
      deployments/k8s/overlays/local-kind-static/dashboard.yaml; do
    dashboard_manifest="$(<"$dashboard_source")"
    grep -Fq 'name: CODEWIRE_IDENTITY_ORIGIN' <<<"$dashboard_manifest"
    grep -Fq 'http://codewire-idp:8091' <<<"$dashboard_manifest"
    grep -Fq 'automountServiceAccountToken: false' <<<"$dashboard_manifest"
    grep -Fq 'allowPrivilegeEscalation: false' <<<"$dashboard_manifest"
    grep -Fq 'drop: ["ALL"]' <<<"$dashboard_manifest"
    grep -Fq 'readOnlyRootFilesystem: true' <<<"$dashboard_manifest"
    grep -Fq 'runAsUser: 65532' <<<"$dashboard_manifest"
    grep -Fq 'runAsGroup: 65532' <<<"$dashboard_manifest"
    grep -Fq 'type: RuntimeDefault' <<<"$dashboard_manifest"
  done

  install_helm
  scripts/ci/tests/test-deploy-prod-render.sh
  local default_mesh_render
  default_mesh_render="$(helm template test apps/cli/charts/codewire-mesh \
    --set mesh.baseURL=https://mesh.test)"
  grep -Fq 'command: ["codewire-mesh"]' <<<"$default_mesh_render"
  grep -Fq -- '- "--base-url=https://mesh.test"' <<<"$default_mesh_render"
  if grep -Fq -- '--database-url' <<<"$default_mesh_render" ||
      grep -Fq 'exec codewire-mesh' <<<"$default_mesh_render" ||
      grep -Fq 'command: ["sh"' <<<"$default_mesh_render"; then
    echo "::error::Mesh deployment rendered a shell or database credential argv path"
    return 1
  fi
  if grep -Fq 'prelaunch-retire-legacy-auth' <<<"$default_mesh_render"; then
    echo "::error::retired Mesh legacy-auth command rendered"
    return 1
  fi
  local dev_mesh_render database_reference_canary_render
  dev_mesh_render="$(helm template codewire-mesh-dev apps/cli/charts/codewire-mesh \
    -f deployments/k8s/mesh-dev/values.yaml \
    --set image.repository=registry.test/codewire/mesh --set image.tag=test)"
  grep -q 'mesh.codewire-dev.sh' <<<"$dev_mesh_render"
  grep -Fq 'command: ["codewire-mesh"]' <<<"$dev_mesh_render"
  if grep -Fq -- '--database-url' <<<"$dev_mesh_render" ||
      grep -Fq 'exec codewire-mesh' <<<"$dev_mesh_render" ||
      grep -Fq 'command: ["sh"' <<<"$dev_mesh_render"; then
    echo "::error::hosted Mesh deployment rendered a shell or database credential argv path"
    return 1
  fi
  grep -Fq 'name: DATABASE_URL' <<<"$dev_mesh_render"
  grep -Fq 'name: codewire-mesh-db-app' <<<"$dev_mesh_render"
  grep -Fq 'name: CODEWIRE_MESH_AUTHORIZATION_URL' <<<"$dev_mesh_render"
  grep -Fq 'http://codewire-orchestration.dev.svc.cluster.local:8085' <<<"$dev_mesh_render"
  grep -Fq 'name: CODEWIRE_MESH_AUTHORIZATION_HMAC_SECRET' <<<"$dev_mesh_render"
  grep -Fq 'name: codewire-mesh-coordinator' <<<"$dev_mesh_render"
  grep -Fq 'nginx.ingress.kubernetes.io/backend-protocol: "GRPC"' <<<"$dev_mesh_render"
  grep -Fq 'path: /codewire\.internal\.v1\.MeshCoordinatorService/' <<<"$dev_mesh_render"
  database_reference_canary_render="$(helm template codewire-mesh-canary \
    apps/cli/charts/codewire-mesh \
    --set mesh.baseURL=https://mesh.test \
    --set database.enabled=true \
    --set database.secretName=synthetic-database-credential-canary \
    --set database.uriKey=synthetic-database-uri-key-canary \
    --set meshAuthorization.url=http://authorization.test \
    --set meshAuthorization.hmacSecretRef.name=synthetic-hmac-secret)"
  grep -Fq 'name: synthetic-database-credential-canary' \
    <<<"$database_reference_canary_render"
  grep -Fq 'key: synthetic-database-uri-key-canary' \
    <<<"$database_reference_canary_render"
  if grep -Fq -- '--database-url' <<<"$database_reference_canary_render" ||
      grep -Fq 'exec codewire-mesh' <<<"$database_reference_canary_render" ||
      grep -Fq 'command: ["sh"' <<<"$database_reference_canary_render"; then
    echo "::error::synthetic database reference entered the Mesh argv path"
    return 1
  fi
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
  policy-core) run_policy_core ;;
  policy-shell) run_shell_policy ;;
  contracts) run_contracts ;;
  go-support) run_go_support ;;
  web) run_web ;;
  dashboard-image) run_dashboard_image ;;
  ios) run_ios ;;
  ios-config) run_ios_config ;;
  sdk-go) run_sdk_go ;;
  sdk-ts) run_sdk_ts ;;
  sdk-python) run_sdk_python ;;
  service-apikey-smoke) run_apikey_smoke_tooling ;;
  runtime-confidential) run_runtime_confidential ;;
  runtime-dev-smoke) run_runtime_dev_smoke ;;
  rust) run_rust ;;
  rust-transport) run_rust_transport ;;
  rust-curated-locks) run_rust_curated_locks ;;
  transport) run_transport ;;
  edge) run_edge ;;
  release) run_release ;;
  deploy) run_deploy ;;
  security) run_security ;;
  *)
    echo "usage: run-product-verification.sh policy|policy-core|policy-shell|contracts|go-support|web|dashboard-image|ios|sdk-go|sdk-ts|sdk-python|service-apikey-smoke|runtime-confidential|runtime-dev-smoke|rust|rust-transport|rust-curated-locks|transport|edge|release|deploy|security" >&2
    exit 2
    ;;
esac
