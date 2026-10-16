.PHONY: help up up-billing down dev dev-down db-init web dashboard-ssr-dev dashboard-watch dashboard-watch-kind kind-up kind-list kind-down kind-deploy kind-trust-roots kind-db-reset kind-db-restore kind-test kind-credentials-real kind-credentials-fake kind-seed-login kind-runtime-images kind-watch kind-status design-system design-check e2e e2e-kind kind-billing-listen kind-forwards-start kind-forwards-stop kind-forwards-status kind-forwards-cleanup kind-clean-runtime test-ui test-ui-dashboard-ssr test-ui-kind test-ui-kind-billing test-billing-smoke-kind seed-test-user seed-e2e-users build build-web clean wasm build-daemon build-dashboard-local build-sandbox-controller build-derp-local build-services-local rollout-local-runtime local-runtime deploy-local deploy-local-static prune-local-legacy-runtime kind-cluster kind-ingress kind-label-local-nodes kind-sandbox-namespace ios ios-test ios-clean proto-tools proto-lint proto-generate proto-drift-check
.PHONY: dogfood cli-build cli-smoke cli-install cli-install-user cli-install-system macos-local-runtime scan-supply-chain verify-dashboard-image sync-local-secrets accept-secrets-credentials

# The older codewire/default-namespace topology has its own fixed endpoints.
# Reject named selection before its build prerequisites or runtime mutations.
ifneq ($(strip $(CLUSTER)),)
ifneq ($(filter up up-billing down deploy-local deploy-local-static local-runtime rollout-local-runtime prune-local-legacy-runtime kind-cluster kind-ingress kind-label-local-nodes kind-sandbox-namespace kind-forwards-start kind-forwards-stop kind-forwards-status kind-forwards-cleanup kind-clean-runtime kind-billing-listen test-ui-kind test-ui-kind-billing test-billing-smoke-kind sync-local-secrets,$(MAKECMDGOALS)),)
$(error CLUSTER selects saved product-gate profiles; use kind-up/kind-down/kind-deploy/kind-watch/kind-test/kind-status for this topology)
endif
endif

# Default target
help:
	@echo "Codewire Development Commands"
	@echo ""
	@echo "Setup & Infrastructure:"
	@echo "  make dev          - Start PostgreSQL for local development"
	@echo "  make dev-down     - Stop all development services"
	@echo ""
	@echo "Database:"
	@echo "  make db-init      - Apply pending SQLx application migrations"
	@echo ""
	@echo "Development:"
	@echo "  make web          - Run the Rust web server on 5173"
	@echo "  make dashboard-ssr-dev - Alias for make web"
	@echo "  make dashboard-watch - Rebuild/restart only the local dashboard on frontend changes"
	@echo "  make dashboard-watch-kind - Watch the dashboard against the existing Kind stack"
	@echo "  make design-system - Preview editable design sources and production fixtures"
	@echo "  make design-check  - Run every design-fixture browser spec (the web gate's fixture check)"
	@echo "  make wasm         - Build WASM package for the dashboard"
	@echo ""
	@echo "Testing:"
	@echo "  make test-ui      - Run Playwright UI tests"
	@echo "  make test-ui-dashboard-ssr - Alias for the canonical Rust browser proof"
	@echo "  make test-ui-kind - Run the complete Rust dashboard suite against interactive Kind"
	@echo "  make test-ui-kind-billing - Run Playwright billing tests against local kind"
	@echo "  make test-billing-smoke-kind - Run Rust billing runtime smoke + Playwright billing against local kind"
	@echo "  make e2e-kind     - Run the isolated Rust-owned Kind product gate"
	@echo "  make kind-up CLUSTER=<name> - Create or validate a saved isolated cluster"
	@echo "  make kind-list   - List saved clusters and endpoints on this Docker daemon"
	@echo "  make kind-down CLUSTER=<name> - Remove only the recorded cluster node"
	@echo "  make accept-secrets-credentials - Run the checked-in #1922 acceptance matrix"
	@echo "  make scan-supply-chain - Run local policy plus the strict external-scanner equivalent"
	@echo "  make verify-dashboard-image - Build and inspect the production Rust/Zola image"
	@echo "  make seed-e2e-users - Seed local E2E login users"
	@echo "  make seed-test-user - Alias for seed-e2e-users"
	@echo ""
	@echo "Build:"
	@echo "  make build        - Build the Rust web binary"
	@echo "  make build-web    - Build the Rust web binary"
	@echo ""
	@echo "CLI:"
	@echo "  make dogfood            - Build, smoke-test, and install this checkout's CLI for your user"
	@echo "  make cli-build          - Build the release CLI"
	@echo "  make cli-smoke          - Build and run CLI help smoke checks"
	@echo "  make cli-install        - Install CLI for the current user"
	@echo "  make cli-install-user   - Install CLI to XDG_BIN_HOME or ~/.local/bin"
	@echo "  make cli-install-system - Install CLI to /usr/local/bin"
	@echo "  make macos-local-runtime KERNEL=/abs/Image INITRAMFS=/abs/cpio E2FSPROGS=/abs/bundle GIT_BUNDLE=/abs/bundle [CW_RUNTIME=/abs/dir] - Install the macOS local VM runtime"
	@echo ""
	@echo "Kind (local k8s):"
	@echo "  make up           - Build images + deploy everything into kind"
	@echo "  make up-billing   - Run 'make up' and then start the Stripe billing listener"
	@echo "  make down         - Delete kind cluster"
	@echo "  make kind-cluster - Create/recreate kind cluster with port mappings"
	@echo "  make kind-label-local-nodes - Apply local sandbox node labels in kind"
	@echo "  make kind-sandbox-namespace - Ensure the local shared sandbox namespace labels"
	@echo "  make deploy-local - Deploy the Rust local-kind runtime"
	@echo "  make deploy-local-static - Deploy the static Rust local-kind runtime"
	@echo "  make kind-forwards-start - Start managed local kind Postgres/Rust service forwards"
	@echo "  make kind-forwards-stop - Stop managed local kind Postgres/Rust service forwards"
	@echo "  make kind-forwards-status - Show helper-owned local kind forwards"
	@echo "  make kind-forwards-cleanup - Stop only helper-owned local kind forwards"
	@echo "  make kind-clean-runtime - Delete orphaned local env workloads from kind"
	@echo "  make sync-local-secrets - Opaquely sync local AI credentials into Kind"
	@echo "  make kind-billing-listen - Start stripe listen, patch kind webhook secret, restart billing"
	@echo ""
	@echo "iOS:"
	@echo "  make ios          - Build and deploy the Swift iOS app to device"
	@echo "  make ios-test     - Run CodewireKit Swift tests on Linux"
	@echo "  make ios-clean    - Remove iOS build artifacts"
	@echo ""
	@echo "SDK (libs/sdk-{go,python,ts}):"
	@echo "  make test-sdk     - Typecheck + unit tests across all 3 SDK languages"
	@echo "  make sdk-e2e      - Run e2e tests against a running server (all 3 languages)"

# Load environment from .env if it exists
-include .env
export

# Default environment variables for local development
export DATABASE_URL ?= postgres://codewire:codewire@localhost:54320/codewire?sslmode=disable
export RUST_LOG ?= codewire_server=debug,tower_http=debug
export DRY_RUN ?= true
export KUBE_CONTEXT ?= $(if $(strip $(CLUSTER)),kind-$(CLUSTER),kind-codewire)
DASHBOARD_PORT ?= 5173
# One-shot Cargo builds share the account's local compiler cache
# (scripts/ci/verify/local-rust-cache.sh).
LOCAL_RUST_CACHE := scripts/ci/verify/local-rust-cache.sh
KUBECTL ?= kubectl --context $(KUBE_CONTEXT)
AGENT_SANDBOX_REPO ?= https://github.com/noeljackson/agent-sandbox.git
AGENT_SANDBOX_SHA ?= $(shell awk '/AGENT_SANDBOX_SHA:/ {print $$2; exit}' .gitea/workflows/ci.yaml)

# Test user credentials for Playwright tests
export TEST_USER_EMAIL ?= test@codewire.sh
export TEST_USER_PASSWORD ?= testpassword123
export TEST_USER_NAME ?= Test User
REGISTRY ?= git.example.com
BUF ?= $(shell command -v buf 2>/dev/null || echo "$(HOME)/go/bin/buf")
GO_BIN ?= $(shell go env GOPATH 2>/dev/null)/bin
SUPPLYCHAIN ?= supplychain
override SUPPLYCHAIN_REQUIRED_REVISION := ea79415
# protoc is pinned because buf.gen.codewire.yaml uses protoc's built-in
# python/pyi generators, whose output is protoc-version-dependent and
# checked in (libs/gen-python). Keep version + checksum in lockstep with
# the Lint job's "Install proto toolchain (pinned)" step in
# .gitea/workflows/ci.yaml.
PROTOC_VERSION := 35.1
PROTOC_SHA256_LINUX_X86_64 := 6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7
PROTOC_DIR := .proto-tools/protoc-$(PROTOC_VERSION)

scan-supply-chain:
	@command -v "$(SUPPLYCHAIN)" >/dev/null 2>&1 || { \
		echo "scan-supply-chain: supplychain is not installed; install a reviewed build and set SUPPLYCHAIN=/path/to/supplychain" >&2; \
		exit 1; \
	}
	@version="$$($(SUPPLYCHAIN) version)"; case "$$version" in \
		*"$(SUPPLYCHAIN_REQUIRED_REVISION)"*) ;; \
		*) echo "scan-supply-chain: expected reviewed Supplychain revision $(SUPPLYCHAIN_REQUIRED_REVISION), got $$version" >&2; exit 1 ;; \
	esac
	scripts/checks/security/audit-js-supply-chain.sh
	scripts/checks/security/audit-runtime-images.sh
	"$(SUPPLYCHAIN)" --source-policy=.supplychain/source-policy.json ci \
		--policy=strict \
		--gitleaks-config=.gitleaks.toml \
		--baseline=.supplychain/bun-baseline.json \
		.

accept-secrets-credentials:
	scripts/runtime/dev/run-secrets-credentials-acceptance.sh

DASHBOARD_VERIFY_IMAGE ?= codewire-dashboard:verification
verify-dashboard-image:
	docker buildx bake --file docker-bake.hcl --pull --load --set 'dashboard.tags=$(DASHBOARD_VERIFY_IMAGE)' dashboard
	scripts/ci/verify/dashboard-image.sh "$(DASHBOARD_VERIFY_IMAGE)"

# Start core development services
dev:
	@echo "Starting PostgreSQL..."
	docker compose up -d postgres
	@echo "Waiting for services to be ready..."
	@until docker compose exec -T postgres pg_isready -U codewire -d codewire 2>/dev/null; do sleep 1; done
	@echo ""
	@echo "Services ready! Run 'make db-init' to apply pending database migrations."

db-init:
	DATABASE_URL="$(DATABASE_URL)" $(LOCAL_RUST_CACHE) cargo run --locked -p codewire-server-core --bin codewire-db-migrate

# Stop all services
dev-down:
	docker compose down

# Run the canonical Rust web server.
web:
	CODEWIRE_PUBLIC_ORIGIN="$${CODEWIRE_PUBLIC_ORIGIN:-http://127.0.0.1:5173}" \
	CODEWIRE_API_ORIGIN="$${CODEWIRE_API_ORIGIN:-http://127.0.0.1:8080}" \
	CODEWIRE_CREDENTIAL_ORIGIN="$${CODEWIRE_CREDENTIAL_ORIGIN:-http://127.0.0.1:8086}" \
	CODEWIRE_IDENTITY_ORIGIN="$${CODEWIRE_IDENTITY_ORIGIN:-http://127.0.0.1:8080}" \
	CODEWIRE_BILLING_ORIGIN="$${CODEWIRE_BILLING_ORIGIN:-http://127.0.0.1:8081}" \
	CODEWIRE_BROWSER_API_ORIGIN="$${CODEWIRE_BROWSER_API_ORIGIN:-http://127.0.0.1:8080}" \
	$(LOCAL_RUST_CACHE) cargo run --locked -p codewire-dashboard-web

dashboard-ssr-dev: web

dashboard-watch:
	CODEWIRE_DASHBOARD_LISTEN_ADDR="$${CODEWIRE_DASHBOARD_LISTEN_ADDR:-127.0.0.1:$(DASHBOARD_PORT)}" \
	CODEWIRE_PUBLIC_ORIGIN="$${CODEWIRE_PUBLIC_ORIGIN:-http://127.0.0.1:$(DASHBOARD_PORT)}" \
	CODEWIRE_API_ORIGIN="$${CODEWIRE_API_ORIGIN:-http://127.0.0.1:8080}" \
	CODEWIRE_CREDENTIAL_ORIGIN="$${CODEWIRE_CREDENTIAL_ORIGIN:-http://127.0.0.1:8086}" \
	CODEWIRE_IDENTITY_ORIGIN="$${CODEWIRE_IDENTITY_ORIGIN:-http://127.0.0.1:8080}" \
	CODEWIRE_BILLING_ORIGIN="$${CODEWIRE_BILLING_ORIGIN:-http://127.0.0.1:8081}" \
	CODEWIRE_BROWSER_API_ORIGIN="$${CODEWIRE_BROWSER_API_ORIGIN:-http://127.0.0.1:8080}" \
	python3 scripts/dev/dashboard-watch.py

dashboard-watch-kind:
	@set -eu; \
	cleanup() { \
		scripts/dev/kind/kind-forwards.sh stop postgres; \
	}; \
	trap cleanup EXIT; \
	trap 'exit 129' HUP; \
	trap 'exit 130' INT; \
	trap 'exit 143' TERM; \
	scripts/dev/kind/kind-forwards.sh start postgres; \
	set -a; eval "$$(scripts/dev/kind/kind-forwards.sh env postgres)"; set +a; \
	CODEWIRE_DASHBOARD_LISTEN_ADDR="$${CODEWIRE_DASHBOARD_LISTEN_ADDR:-127.0.0.1:$(DASHBOARD_PORT)}" \
	CODEWIRE_PUBLIC_ORIGIN="$${CODEWIRE_PUBLIC_ORIGIN:-http://127.0.0.1:$(DASHBOARD_PORT)}" \
	CODEWIRE_API_ORIGIN="$${CODEWIRE_API_ORIGIN:-http://127.0.0.1:8080}" \
	CODEWIRE_CREDENTIAL_ORIGIN="$${CODEWIRE_CREDENTIAL_ORIGIN:-http://127.0.0.1:8086}" \
	CODEWIRE_IDENTITY_ORIGIN="$${CODEWIRE_IDENTITY_ORIGIN:-http://127.0.0.1:8080}" \
	CODEWIRE_BILLING_ORIGIN="$${CODEWIRE_BILLING_ORIGIN:-http://127.0.0.1:8081}" \
	CODEWIRE_BROWSER_API_ORIGIN="$${CODEWIRE_BROWSER_API_ORIGIN:-http://127.0.0.1:8080}" \
	python3 scripts/dev/dashboard-watch.py

# Manual testing on the retained cluster from `KEEP_KIND_CLUSTER=1 make e2e-kind`
# (same KIND_CLUSTER_NAME). KIND_PUBLIC_ORIGIN is the browser origin registered
# as the GitHub App callback origin; the default is the owner workstation's
# Tailnet URL, served by `tailscale serve` from the watcher on 127.0.0.1:5182.
ifeq ($(strip $(CLUSTER)),)
KIND_PUBLIC_ORIGIN ?= http://nj.example.invalid:4174
# The cluster ingress on the same host, for browser terminals and streams.
KIND_BROWSER_API_ORIGIN ?= http://nj.example.invalid:8090
KIND_ORIGIN_ENV = KIND_PUBLIC_ORIGIN="$(KIND_PUBLIC_ORIGIN)" KIND_BROWSER_API_ORIGIN="$(KIND_BROWSER_API_ORIGIN)"
else
export CLUSTER
KIND_ORIGIN_ENV =
endif

# Create and deploy a new retained cluster without running the test suites.
kind-up:
	./scripts/ci/verify/kind-e2e.sh up

kind-list:
	python3 scripts/dev/kind/cluster-profile.py list

kind-down:
	./scripts/ci/verify/kind-e2e.sh down

# Rebuild one service from current source into the retained cluster, e.g.
# `make kind-deploy SERVICE=credential-service`.
kind-deploy:
	@test -n "$(SERVICE)" || { echo "usage: make kind-deploy SERVICE=<idp|orchestration|credential-service|billing|coordinator|mesh|dashboard|daemon>" >&2; exit 2; }
	./scripts/dev/kind/deploy-service.sh "$(SERVICE)"

# Republish the retained cluster's synthetic trust roots (kind-deploy also
# does this), e.g. after the 72-hour root renewal. Restarts nothing.
kind-trust-roots:
	./scripts/dev/kind/trust-roots.sh

# The retained cluster's databases are disposable. A deploy applies new
# migrations after a backup; reset recreates the databases, reruns every
# migration and reloads the gate's fixtures; restore returns to a backup, e.g.
# `make kind-db-restore BACKUP=~/.cache/codewire/kind/<cluster>/database-backups/<time>-upgrade`.
kind-db-reset:
	./scripts/dev/kind/database.sh reset

kind-db-restore:
	@test -n "$(BACKUP)" || { echo "usage: make kind-db-restore BACKUP=<backup directory>" >&2; exit 2; }
	./scripts/dev/kind/database.sh restore "$(BACKUP)"

# Deploy the services the current change feeds, then run only the retained
# Kind suites that cover it (SUITES=... to choose explicitly). Exit 3: only the
# full CI Kind gate covers this change.
kind-test:
	KIND_TEST_SUITES="$(SUITES)" ./scripts/dev/kind/test-selected.sh

kind-credentials-real:
	$(KIND_ORIGIN_ENV) ./scripts/ci/verify/kind-e2e.sh credentials real

kind-credentials-fake:
	./scripts/ci/verify/kind-e2e.sh credentials fake

kind-seed-login:
	./scripts/dev/kind/dev-loop.sh seed-login

kind-runtime-images:
	./scripts/dev/kind/dev-loop.sh runtime-images

kind-watch:
	$(KIND_ORIGIN_ENV) ./scripts/dev/kind/dev-loop.sh watch

kind-status:
	$(KIND_ORIGIN_ENV) ./scripts/dev/kind/dev-loop.sh status

design-system:
	python3 scripts/dev/design-system-server.py

design-check:
	scripts/ci/verify/run-design-fixtures.sh

# Build WASM package
wasm:
	wasm-pack build crates/codewire-wasm --target bundler --out-dir ../../packages/codewire-wasm/pkg

# Run the current Rust-owned product gate in an isolated kind cluster.
e2e-kind:
	./scripts/ci/verify/kind-e2e.sh

e2e: e2e-kind

kind-forwards-start:
	./scripts/dev/kind/kind-forwards.sh start all

kind-forwards-stop:
	./scripts/dev/kind/kind-forwards.sh stop all

kind-forwards-status:
	./scripts/dev/kind/kind-forwards.sh status all

kind-forwards-cleanup:
	./scripts/dev/kind/kind-forwards.sh cleanup all

kind-clean-runtime:
	./scripts/dev/kind/kind-clean-runtime.sh

kind-billing-listen:
	./scripts/dev/kind/kind-billing-listen.sh

test-ui-kind-billing:
	./scripts/dev/kind/test-billing-kind.sh

test-billing-smoke-kind:
	./scripts/dev/kind/test-billing-smoke-kind.sh

# Seed local E2E users for manual UI testing / Playwright
seed-e2e-users:
	./scripts/dev/kind/seed-e2e-users.sh

# Internal service contracts (proto/ at repo root). Local plugins only —
# remote buf plugins don't work in restricted-network CI.
# protoc-gen-es (TypeScript, buf.gen.codewire.yaml and
# buf.gen.google-rpc-ts.yaml) is not installed here: it comes from `bun
# install` (pinned in the root package.json
# devDependencies). The protoc built-in python/pyi generators need
# protobuf-compiler (protoc) on PATH; protoc-gen-connectrpc and its runtime
# compatibility protobuf are pinned into the repo-root .venv-proto venv.
proto-tools:
	go install github.com/bufbuild/buf/cmd/buf@v1.50.0
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.5
	go install connectrpc.com/connect/cmd/protoc-gen-connect-go@v1.18.1
	python3 -m venv .venv-proto
	.venv-proto/bin/python -m pip install --quiet \
		'protobuf==7.35.1' \
		'connectrpc==0.11.1' \
		'protoc-gen-connectrpc==0.11.1'
	@if [ "$$(uname -s)-$$(uname -m)" != "Linux-x86_64" ]; then \
		echo "proto-tools: pinned protoc download only wired for Linux x86_64;" \
			"install protoc $(PROTOC_VERSION) at $(PROTOC_DIR)/bin/protoc manually" && exit 1; \
	fi
	@if [ ! -x $(PROTOC_DIR)/bin/protoc ]; then \
		mkdir -p .proto-tools && \
		curl -fsSL -o .proto-tools/protoc.zip "https://github.com/protocolbuffers/protobuf/releases/download/v$(PROTOC_VERSION)/protoc-$(PROTOC_VERSION)-linux-x86_64.zip" && \
		echo "$(PROTOC_SHA256_LINUX_X86_64)  .proto-tools/protoc.zip" | sha256sum -c - && \
		unzip -o -q .proto-tools/protoc.zip -d $(PROTOC_DIR) && \
		rm .proto-tools/protoc.zip; \
	fi
	@$(PROTOC_DIR)/bin/protoc --version

proto-lint:
	cd proto && $(BUF) lint

proto-generate:
	rm -rf \
		libs/gen-go/codewire \
		libs/gen-python/codewire \
		packages/codewire-proto-ts/src/gen/codewire
	cd proto && PATH="$(abspath $(PROTOC_DIR))/bin:$(GO_BIN):$$PATH" $(BUF) generate --template buf.gen.codewire.yaml
	cd proto && $(BUF) generate --template buf.gen.google-rpc-ts.yaml
	cd proto && PATH="$(abspath $(PROTOC_DIR))/bin:$(GO_BIN):$$PATH" $(BUF) generate --template buf.gen.google-rpc-python.yaml
	PATH="$(abspath $(PROTOC_DIR))/bin:$(GO_BIN):$$PATH" BUF="$(BUF)" scripts/ci/proto/build-rust-descriptors.sh

# Fails if generated code is out of sync with proto/ definitions.
proto-drift-check: proto-generate
	@untracked="$$(git ls-files --others --exclude-standard -- crates/codewire-proto/codewire_descriptor.bin crates/codewire-admin-proto/codewire_admin_descriptor.bin libs/gen-go libs/gen-python packages/codewire-proto-ts/src/gen)"; \
	git diff --exit-code crates/codewire-proto/codewire_descriptor.bin crates/codewire-admin-proto/codewire_admin_descriptor.bin libs/gen-go libs/gen-python packages/codewire-proto-ts/src/gen && [ -z "$$untracked" ] || \
	(echo "ERROR: generated proto code is stale; run 'make proto-generate' and commit"; [ -z "$$untracked" ] || printf '%s\n' "$$untracked"; exit 1)

# Backward-compatible alias
seed-test-user: seed-e2e-users

# Run Playwright UI tests
test-ui: seed-test-user
	./apps/dashboard/node_modules/.bin/playwright test --config apps/dashboard/playwright.config.ts

test-ui-dashboard-ssr: test-ui

test-ui-kind:
	./scripts/dev/kind/test-dashboard-kind.sh

# Run Playwright UI tests with browser visible
test-ui-headed: seed-test-user
	./apps/dashboard/node_modules/.bin/playwright test --config apps/dashboard/playwright.config.ts --headed

# Run Playwright UI tests with interactive UI
test-ui-debug: seed-test-user
	./apps/dashboard/node_modules/.bin/playwright test --config apps/dashboard/playwright.config.ts --ui

# Build the canonical web binary.
build: build-web

build-web:
	$(LOCAL_RUST_CACHE) cargo build --locked -p codewire-dashboard-web

# Build and install the CLI from this source checkout.
cli-build:
	$(MAKE) -C apps/cli build

cli-smoke:
	$(MAKE) -C apps/cli smoke

cli-install: cli-install-user

dogfood: cli-install-user

cli-install-user:
	$(MAKE) -C apps/cli install-user

cli-install-system:
	$(MAKE) -C apps/cli install-system

# Apple Silicon only: build and ad-hoc sign the VZ helper, check the supplied
# arm64 kernel Image and guest root, pack them as a release directory and
# install it with `cw setup --local` (docs/dev/MACOS-CLI.md). REPLACE=1
# replaces a different installed runtime; CW=/abs/cw picks the installing cw.
macos-local-runtime:
	python3 scripts/dev/macos-local-runtime.py --kernel "$(KERNEL)" --initramfs "$(INITRAMFS)" --e2fsprogs "$(E2FSPROGS)" --git "$(GIT_BUNDLE)" $(if $(CW_RUNTIME),--cw-runtime "$(CW_RUNTIME)") $(if $(filter 1,$(REPLACE)),--replace) $(if $(CW),--cw "$(CW)")

# Build the workspace daemon support image for kind/local runtime smoke.
build-daemon:
	@echo "Building daemon image via deployments/docker/daemon.Dockerfile..."
	scripts/ci/images/build-product-images.sh --pull --load --set 'daemon.tags=$(REGISTRY)/codewire/daemon:local' daemon

# Deploy the local Rust runtime into kind.
deploy-local: local-runtime build-dashboard-local
	@$(MAKE) kind-label-local-nodes
	@$(MAKE) kind-sandbox-namespace
	kind load docker-image codewire-dashboard:local --name codewire
	$(KUBECTL) apply -k deployments/k8s/overlays/local-kind/
	@KUBE_CONTEXT="$(KUBE_CONTEXT)" ./scripts/dev/kind/local-internal-tls.sh
	@$(MAKE) sync-local-secrets
	@$(MAKE) prune-local-legacy-runtime
	@$(KUBECTL) -n default rollout status deployment postgres --timeout=60s
	./scripts/dev/kind/install-temporal.sh local-kind
	@$(MAKE) kind-clean-runtime
	$(KUBECTL) -n default rollout restart deployment codewire-dashboard
	@$(MAKE) rollout-local-runtime
	@$(KUBECTL) -n default rollout status deployment codewire-dashboard --timeout=60s

# Deploy the static local Rust runtime into kind.
deploy-local-static: local-runtime build-dashboard-local
	@$(MAKE) kind-label-local-nodes
	@$(MAKE) kind-sandbox-namespace
	kind load docker-image codewire-dashboard:local --name codewire
	$(KUBECTL) apply -k deployments/k8s/overlays/local-kind-static/
	@KUBE_CONTEXT="$(KUBE_CONTEXT)" ./scripts/dev/kind/local-internal-tls.sh
	@$(MAKE) sync-local-secrets
	@$(MAKE) prune-local-legacy-runtime
	@$(KUBECTL) -n default rollout status deployment postgres --timeout=60s
	./scripts/dev/kind/install-temporal.sh local-kind-static
	@$(MAKE) kind-clean-runtime
	$(KUBECTL) -n default rollout restart deployment codewire-dashboard
	@$(MAKE) rollout-local-runtime
	@$(KUBECTL) -n default rollout status deployment codewire-dashboard --timeout=60s

# Build all local images and deploy everything into local kind.
# Shared/prod agent-sandbox is applied from this repo via CI/CD.
up: build-daemon build-dashboard-local build-sandbox-controller build-derp-local build-services-local
	@kind get clusters | grep -q codewire || $(MAKE) kind-cluster
	@$(MAKE) kind-ingress
	@$(MAKE) kind-label-local-nodes
	@$(MAKE) kind-sandbox-namespace
	kind load docker-image $(REGISTRY)/codewire/daemon:local --name codewire
	kind load docker-image codewire-dashboard:local --name codewire
	kind load docker-image agent-sandbox-controller:local --name codewire
	kind load docker-image codewire-derp:local --name codewire
	kind load docker-image codewire-services:local --name codewire
	$(KUBECTL) apply -k deployments/k8s/overlays/local-kind/
	@KUBE_CONTEXT="$(KUBE_CONTEXT)" ./scripts/dev/kind/local-internal-tls.sh
	@$(MAKE) sync-local-secrets
	@$(MAKE) prune-local-legacy-runtime
	$(KUBECTL) apply -k deployments/k8s/agent-sandbox/overlays/local-kind/
	@$(KUBECTL) -n default rollout status deployment postgres --timeout=60s
	./scripts/dev/kind/install-temporal.sh local-kind
	@$(MAKE) kind-clean-runtime
	$(KUBECTL) -n default rollout restart deployment codewire-dashboard
	@$(MAKE) rollout-local-runtime
	@$(KUBECTL) -n default rollout status deployment codewire-dashboard --timeout=60s
	@$(KUBECTL) -n agent-sandbox-system rollout status deployment agent-sandbox-controller --timeout=60s

up-billing: up
	@$(MAKE) kind-billing-listen

# Delete kind cluster
down:
	kind delete cluster --name codewire

# Build the production-equivalent Rust/Zola image for local Kind.
build-dashboard-local:
	docker buildx bake --file docker-bake.hcl --pull --load --set 'dashboard.tags=codewire-dashboard:local' dashboard

# Build the pinned sandbox controller image for local kind only. A sibling
# checkout may be used as an object source, but HEAD is never used implicitly.
build-sandbox-controller:
	@test -n "$(AGENT_SANDBOX_SHA)"
	@tmp=$$(mktemp -d); \
	agent_source=""; \
	cleanup() { \
		if [ -n "$$agent_source" ]; then \
			git -C "$$agent_source" worktree remove -f "$$tmp/agent-sandbox" >/dev/null 2>&1 || true; \
		fi; \
		rm -rf "$$tmp"; \
	}; \
	trap cleanup EXIT; \
	if git -C ../agent-sandbox rev-parse --is-inside-work-tree >/dev/null 2>&1 && \
		git -C ../agent-sandbox cat-file -e "$(AGENT_SANDBOX_SHA)^{commit}" 2>/dev/null; then \
		agent_source=$$(cd ../agent-sandbox && pwd); \
		git -C "$$agent_source" worktree add --detach "$$tmp/agent-sandbox" "$(AGENT_SANDBOX_SHA)" >/dev/null; \
	else \
		git clone "$(AGENT_SANDBOX_REPO)" "$$tmp/agent-sandbox" >/dev/null; \
		git -C "$$tmp/agent-sandbox" checkout "$(AGENT_SANDBOX_SHA)" >/dev/null; \
	fi; \
	docker build -t agent-sandbox-controller:local -f "$$tmp/agent-sandbox/Dockerfile" "$$tmp/agent-sandbox"

# Build DERP image for local kind
build-derp-local:
	docker buildx bake --file docker-bake.hcl --pull --load --set 'derp.tags=codewire-derp:local' derp

build-services-local:
	docker buildx bake --file docker-bake.hcl --pull --load --set 'services-ci.tags=codewire-services:local' services-ci

rollout-local-runtime:
	$(KUBECTL) -n default rollout restart deployment codewire-coordinator codewire-idp codewire-billing codewire-orchestration codewire-derp
	@$(KUBECTL) -n default rollout status deployment codewire-coordinator --timeout=90s
	@$(KUBECTL) -n default rollout status deployment codewire-idp --timeout=90s
	@$(KUBECTL) -n default rollout status deployment codewire-billing --timeout=90s
	@$(KUBECTL) -n default rollout status deployment codewire-orchestration --timeout=90s
	@$(KUBECTL) -n default rollout status deployment codewire-derp --timeout=90s

sync-local-secrets:
	@KUBE_CONTEXT="$(KUBE_CONTEXT)" ./scripts/dev/kind/sync-local-secrets.sh

prune-local-legacy-runtime:
	-$(KUBECTL) -n default delete deployment/codewire-server service/codewire-server deployment/codewire-docs service/docs deployment/nats service/nats serviceaccount/codewire-server secret/codewire-server-token --ignore-not-found
	-$(KUBECTL) delete clusterrole/codewire-server clusterrolebinding/codewire-server clusterrolebinding/codewire-server-auth-delegator --ignore-not-found

# Load and apply the local runtime pieces needed for sandbox-backed environments.
local-runtime: build-daemon build-sandbox-controller build-derp-local build-services-local
	@$(MAKE) kind-label-local-nodes
	@$(MAKE) kind-sandbox-namespace
	kind load docker-image $(REGISTRY)/codewire/daemon:local --name codewire
	kind load docker-image agent-sandbox-controller:local --name codewire
	kind load docker-image codewire-derp:local --name codewire
	kind load docker-image codewire-services:local --name codewire
	$(KUBECTL) apply -k deployments/k8s/agent-sandbox/overlays/local-kind/
	$(KUBECTL) -n agent-sandbox-system rollout restart deployment agent-sandbox-controller
	@$(KUBECTL) -n agent-sandbox-system rollout status deployment agent-sandbox-controller --timeout=60s

# Create/recreate kind cluster with port mappings and source mount
kind-cluster:
	-kind delete cluster --name codewire
	kind create cluster --name codewire --config deployments/kind/cluster-config.yaml
	$(MAKE) kind-ingress
	$(MAKE) kind-label-local-nodes

kind-label-local-nodes:
	@$(KUBECTL) label node codewire-control-plane codewire.sh/node-pool=sandbox --overwrite

kind-sandbox-namespace:
	@$(KUBECTL) create namespace dev-sandboxes --dry-run=client -o yaml | $(KUBECTL) apply -f -
	@$(KUBECTL) label namespace dev-sandboxes \
		app.kubernetes.io/managed-by=codewire \
		codewire.sh/resource-type=sandbox \
		codewire.sh/runtime-scope=shared --overwrite
	@$(KUBECTL) -n dev-sandboxes create serviceaccount codewire-sandbox --dry-run=client -o yaml | $(KUBECTL) apply -f -
	@$(KUBECTL) -n dev-sandboxes patch serviceaccount codewire-sandbox --type=merge -p '{"automountServiceAccountToken":false}'
	@test "$$($(KUBECTL) -n dev-sandboxes get serviceaccount codewire-sandbox -o jsonpath='{.automountServiceAccountToken}')" = false

kind-ingress:
	$(KUBECTL) apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
	$(KUBECTL) -n ingress-nginx rollout status deployment ingress-nginx-controller --timeout=120s

# Clean build artifacts
clean:
	rm -rf dist/
	rm -rf apps/dashboard/dist/

# iOS app
ios:
	$(MAKE) -C apps/ios dev

ios-test:
	$(MAKE) -C apps/ios test

ios-clean:
	$(MAKE) -C apps/ios clean

# --- SDK -------------------------------------------------------------------
# Codewire SDK lives in libs/sdk-{go,python,ts}. Targets here mirror what the
# old separate codewiresh/sdk Makefile exposed.

.PHONY: test-sdk test-sdk-go test-sdk-python test-sdk-ts \
        sdk-e2e sdk-e2e-go sdk-e2e-python sdk-e2e-ts

test-sdk: test-sdk-go test-sdk-python test-sdk-ts

test-sdk-go:
	cd libs/sdk-go && GOWORK=off go build ./... && GOWORK=off go vet ./... && GOWORK=off go test ./... -count=1 -timeout 60s

test-sdk-ts:
	cd libs/sdk-ts && npm ci --silent --install-links --ignore-scripts && npm run typecheck && npm test

test-sdk-python:
	cd libs/sdk-python && \
	  test -d .venv || python3 -m venv .venv && \
	  .venv/bin/pip install --require-hashes -r requirements.lock -q && \
	  .venv/bin/pip install --no-deps . -q && \
	  env -u CODEWIRE_API_KEY -u CODEWIRE_ORG_ID -u CODEWIRE_BASE_URL \
	    PYTHONPATH="$(CURDIR)/libs/gen-python$${PYTHONPATH:+:$$PYTHONPATH}" .venv/bin/python -m unittest test_sdk test_transport test_cw_runtime test_platform_agents -v && \
	  (cd /tmp && $(CURDIR)/libs/sdk-python/.venv/bin/python -c 'from codewire._transport import ConnectTransport; from codewire.errors import CodewireError; from codewire.v1.api_key_connect import ApiKeyServiceClientSync; from google.rpc.error_details_pb2 import BadRequest; assert CodewireError and BadRequest and isinstance(ConnectTransport("https://codewire.example", "").client(ApiKeyServiceClientSync), ApiKeyServiceClientSync)')
	scripts/runtime/tests/test-run-sdk-python-e2e.sh

sdk-e2e: sdk-e2e-go sdk-e2e-python sdk-e2e-ts

sdk-e2e-go:
	cd libs/sdk-go && go test -tags e2e -run TestE2E -v -timeout 10m

sdk-e2e-python: test-sdk-python
	cd libs/sdk-python && \
	  PYTHONPATH="$(CURDIR)/libs/gen-python$${PYTHONPATH:+:$$PYTHONPATH}" \
	  .venv/bin/python -m unittest e2e_test -v

sdk-e2e-ts:
	cd libs/sdk-ts && npm ci --silent --install-links --ignore-scripts && ./node_modules/.bin/tsx src/e2e.ts
