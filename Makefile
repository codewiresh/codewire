.PHONY: help up up-billing down dev dev-down db-init web e2e e2e-kind kind-billing-listen kind-forwards-start kind-forwards-stop kind-forwards-status kind-forwards-cleanup kind-clean-runtime test-ui test-ui-kind-billing test-billing-smoke-kind seed-test-user seed-e2e-users build clean wasm build-gateway build-dashboard-local build-docs-local build-sandbox-controller build-derp-local build-services-local rollout-local-runtime local-runtime deploy-local deploy-local-static prune-local-legacy-runtime kind-cluster kind-ingress kind-label-local-nodes kind-sandbox-namespace ios ios-test ios-clean proto-tools proto-lint proto-generate proto-drift-check api-client-tools api-client-generate api-client-generate-go api-client-generate-ts api-client-generate-py
.PHONY: cli-build cli-smoke cli-install cli-install-user cli-install-system

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
	@echo "  make web          - Run web frontend dev server"
	@echo "  make wasm         - Build WASM package for the dashboard"
	@echo ""
	@echo "Testing:"
	@echo "  make test-ui      - Run Playwright UI tests"
	@echo "  make test-ui-kind-billing - Run Playwright billing tests against local kind"
	@echo "  make test-billing-smoke-kind - Run Rust billing runtime smoke + Playwright billing against local kind"
	@echo "  make e2e-kind     - Run the isolated Rust-owned Kind product gate"
	@echo "  make seed-e2e-users - Seed local E2E login users"
	@echo "  make seed-test-user - Alias for seed-e2e-users"
	@echo ""
	@echo "Build:"
	@echo "  make build        - Build local frontend artifacts"
	@echo "  make build-web    - Build web frontend"
	@echo ""
	@echo "CLI:"
	@echo "  make cli-build          - Build the release CLI"
	@echo "  make cli-smoke          - Build and run CLI help smoke checks"
	@echo "  make cli-install        - Install CLI for the current user"
	@echo "  make cli-install-user   - Install CLI to XDG_BIN_HOME or ~/.local/bin"
	@echo "  make cli-install-system - Install CLI to /usr/local/bin"
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
	@echo "  make sdk-run-claude - Parity smoke: run claude inside a local VM via each SDK"

# Load environment from .env if it exists
-include .env
export

# Default environment variables for local development
export DATABASE_URL ?= postgres://codewire:codewire@localhost:54320/codewire?sslmode=disable
export RUST_LOG ?= codewire_server=debug,tower_http=debug
export DRY_RUN ?= true
export KUBE_CONTEXT ?= kind-codewire
KUBECTL ?= kubectl --context $(KUBE_CONTEXT)
AGENT_SANDBOX_REPO ?= https://github.com/noeljackson/agent-sandbox.git
AGENT_SANDBOX_SHA ?= $(shell awk '/AGENT_SANDBOX_SHA:/ {print $$2; exit}' .gitea/workflows/ci.yaml)

# Test user credentials for Playwright tests
export TEST_USER_EMAIL ?= test@codewire.sh
export TEST_USER_PASSWORD ?= testpassword123
export TEST_USER_NAME ?= Test User
REGISTRY ?= git.example.com
INFISICAL_HOST ?= infisical.example.com
BUF ?= $(shell command -v buf 2>/dev/null || echo "$(HOME)/go/bin/buf")
# protoc is pinned because buf.gen.codewire.yaml uses protoc's built-in
# python/pyi generators, whose output is protoc-version-dependent and
# checked in (libs/gen-python). Keep version + checksum in lockstep with
# the Lint job's "Install proto toolchain (pinned)" step in
# .gitea/workflows/ci.yaml.
PROTOC_VERSION := 35.1
PROTOC_SHA256_LINUX_X86_64 := 6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7
PROTOC_DIR := .proto-tools/protoc-$(PROTOC_VERSION)

# Start core development services
dev:
	@echo "Starting PostgreSQL..."
	docker compose up -d postgres
	@echo "Waiting for services to be ready..."
	@until docker compose exec -T postgres pg_isready -U codewire -d codewire 2>/dev/null; do sleep 1; done
	@echo ""
	@echo "Services ready! Run 'make db-init' to apply pending database migrations."

db-init:
	DATABASE_URL="$(DATABASE_URL)" cargo run --locked -p codewire-server-core --bin codewire-db-migrate

# Stop all services
dev-down:
	docker compose down

# Run web frontend
web:
	cd apps/dashboard && bun run dev

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
	rm -rf libs/gen-go/coordinator
	cd proto && $(BUF) generate
	cd proto && PATH="$(abspath $(PROTOC_DIR))/bin:$$PATH" $(BUF) generate --template buf.gen.codewire.yaml
	cd proto && $(BUF) generate --template buf.gen.google-rpc-ts.yaml
	cd proto && PATH="$(abspath $(PROTOC_DIR))/bin:$$PATH" $(BUF) generate --template buf.gen.google-rpc-python.yaml
	cd proto && $(BUF) build --as-file-descriptor-set -o ../crates/codewire-proto/codewire_descriptor.bin

# Fails if generated code is out of sync with proto/ definitions.
proto-drift-check: proto-generate
	@untracked="$$(git ls-files --others --exclude-standard -- crates/codewire-proto/codewire_descriptor.bin libs/gen-go libs/gen-python packages/codewire-proto-ts/src/gen)"; \
	git diff --exit-code crates/codewire-proto/codewire_descriptor.bin libs/gen-go libs/gen-python packages/codewire-proto-ts/src/gen && [ -z "$$untracked" ] || \
	(echo "ERROR: generated proto code is stale; run 'make proto-generate' and commit"; [ -z "$$untracked" ] || printf '%s\n' "$$untracked"; exit 1)

# Full generated API clients (libs/api-client-*) from the canonical
# openapi.json. Pinned generator versions; regenerate after API changes
# (after `bun run types:generate` refreshes openapi.json).
api-client-tools:
	go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.6.0
	python3 -m pip install --quiet 'openapi-python-client==0.*'

api-client-generate: api-client-generate-go api-client-generate-ts api-client-generate-py

api-client-generate-go:
	cd libs/api-client-go && oapi-codegen -config oapi-codegen.yaml ../../openapi.json

api-client-generate-ts:
	cd libs/api-client-ts && ../../node_modules/.bin/openapi-typescript ../../openapi.json -o src/schema.gen.ts

api-client-generate-py:
	cd libs/api-client-python && openapi-python-client generate --path ../../openapi.json --config config.yaml --output-path . --overwrite --meta pdm

# Backward-compatible alias
seed-test-user: seed-e2e-users

# Run Playwright UI tests
test-ui: seed-test-user
	cd apps/dashboard && bun run test:e2e

# Run Playwright UI tests with browser visible
test-ui-headed: seed-test-user
	cd apps/dashboard && bun run test:e2e:headed

# Run Playwright UI tests with interactive UI
test-ui-debug: seed-test-user
	cd apps/dashboard && bun run test:e2e:ui

# Build all local frontend artifacts.
build: build-web

# Build web frontend
build-web:
	cd apps/dashboard && bun run build

# Build and install the CLI from this source checkout.
cli-build:
	$(MAKE) -C apps/cli build

cli-smoke:
	$(MAKE) -C apps/cli smoke

cli-install: cli-install-user

cli-install-user:
	$(MAKE) -C apps/cli install-user

cli-install-system:
	$(MAKE) -C apps/cli install-system

# Build the Rust gateway image for kind/local runtime smoke.
build-gateway:
	@echo "Building gateway image via deployments/docker/gateway.Dockerfile..."
	docker build -t $(REGISTRY)/codewire/gateway:local -f deployments/docker/gateway.Dockerfile .

# Deploy the local Rust runtime into kind.
deploy-local: local-runtime build-dashboard-local build-docs-local
	@$(MAKE) kind-label-local-nodes
	kind load docker-image codewire-dashboard:local --name codewire
	kind load docker-image codewire-docs:local --name codewire
	$(KUBECTL) apply -k deployments/k8s/overlays/local-kind/
	@$(MAKE) prune-local-legacy-runtime
	@$(KUBECTL) -n default rollout status deployment postgres --timeout=60s
	./scripts/dev/kind/install-temporal.sh local-kind
	@$(MAKE) kind-clean-runtime
	$(KUBECTL) -n default rollout restart deployment codewire-dashboard codewire-docs
	@$(MAKE) rollout-local-runtime
	@$(KUBECTL) -n default rollout status deployment codewire-dashboard --timeout=60s
	@$(KUBECTL) -n default rollout status deployment codewire-docs --timeout=60s

# Deploy the static local Rust runtime into kind.
deploy-local-static: local-runtime build-dashboard-local build-docs-local
	@$(MAKE) kind-label-local-nodes
	kind load docker-image codewire-dashboard:local --name codewire
	kind load docker-image codewire-docs:local --name codewire
	$(KUBECTL) apply -k deployments/k8s/overlays/local-kind-static/
	@$(MAKE) prune-local-legacy-runtime
	@$(KUBECTL) -n default rollout status deployment postgres --timeout=60s
	./scripts/dev/kind/install-temporal.sh local-kind-static
	@$(MAKE) kind-clean-runtime
	$(KUBECTL) -n default rollout restart deployment codewire-dashboard codewire-docs
	@$(MAKE) rollout-local-runtime
	@$(KUBECTL) -n default rollout status deployment codewire-dashboard --timeout=60s
	@$(KUBECTL) -n default rollout status deployment codewire-docs --timeout=60s

# Build all local images and deploy everything into local kind.
# Shared/prod agent-sandbox is applied from this repo via CI/CD.
up: build-gateway build-dashboard-local build-docs-local build-sandbox-controller build-derp-local build-services-local
	@kind get clusters | grep -q codewire || $(MAKE) kind-cluster
	@$(MAKE) kind-ingress
	@$(MAKE) kind-label-local-nodes
	kind load docker-image $(REGISTRY)/codewire/gateway:local --name codewire
	kind load docker-image codewire-dashboard:local --name codewire
	kind load docker-image codewire-docs:local --name codewire
	kind load docker-image agent-sandbox-controller:local --name codewire
	kind load docker-image codewire-derp:local --name codewire
	kind load docker-image codewire-services:local --name codewire
	$(KUBECTL) apply -k deployments/k8s/overlays/local-kind/
	@$(MAKE) prune-local-legacy-runtime
	$(KUBECTL) apply -k deployments/k8s/agent-sandbox/overlays/local-kind/
	helm upgrade --install infisical-operator secrets-operator \
		--kube-context $(KUBE_CONTEXT) \
		--namespace infisical-system --create-namespace --wait \
		--repo https://dl.cloudsmith.io/public/infisical/helm-charts/helm/charts/
	@if [ -n "$$INFISICAL_CLIENT_ID" ] && [ -n "$$INFISICAL_CLIENT_SECRET" ]; then \
		$(KUBECTL) create secret generic infisical-universal-auth \
			--namespace default \
			--from-literal=clientId=$$INFISICAL_CLIENT_ID \
			--from-literal=clientSecret=$$INFISICAL_CLIENT_SECRET \
			--dry-run=client -o yaml | $(KUBECTL) apply -f -; \
	else \
		echo "WARNING: INFISICAL_CLIENT_ID/SECRET not set — skipping auth secret (run via 'bun run up' to inject)"; \
	fi
	@$(KUBECTL) -n default rollout status deployment postgres --timeout=60s
	./scripts/dev/kind/install-temporal.sh local-kind
	@$(MAKE) kind-clean-runtime
	$(KUBECTL) -n default rollout restart deployment codewire-dashboard codewire-docs
	@$(MAKE) rollout-local-runtime
	@$(KUBECTL) -n default rollout status deployment codewire-dashboard --timeout=60s
	@$(KUBECTL) -n default rollout status deployment codewire-docs --timeout=60s
	@$(KUBECTL) -n agent-sandbox-system rollout status deployment agent-sandbox-controller --timeout=60s

up-billing: up
	@$(MAKE) kind-billing-listen

# Delete kind cluster
down:
	kind delete cluster --name codewire

# Build web dev image for kind
build-dashboard-local:
	docker build -t codewire-dashboard:local -f apps/dashboard/Dockerfile.dev .

# Build docs dev image for kind
build-docs-local:
	docker build -t codewire-docs:local -f apps/docs/Dockerfile.dev .

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
	docker build -t codewire-derp:local -f deployments/docker/derp.Dockerfile .

build-services-local:
	docker build -t codewire-services:local -f deployments/docker/services.Dockerfile .

rollout-local-runtime:
	$(KUBECTL) -n default rollout restart deployment codewire-coordinator codewire-idp codewire-billing codewire-orchestration codewire-derp
	@$(KUBECTL) -n default rollout status deployment codewire-coordinator --timeout=90s
	@$(KUBECTL) -n default rollout status deployment codewire-idp --timeout=90s
	@$(KUBECTL) -n default rollout status deployment codewire-billing --timeout=90s
	@$(KUBECTL) -n default rollout status deployment codewire-orchestration --timeout=90s
	@$(KUBECTL) -n default rollout status deployment codewire-derp --timeout=90s

prune-local-legacy-runtime:
	-$(KUBECTL) -n default delete deployment/codewire-server service/codewire-server deployment/nats service/nats serviceaccount/codewire-server secret/codewire-server-token --ignore-not-found
	-$(KUBECTL) delete clusterrole/codewire-server clusterrolebinding/codewire-server clusterrolebinding/codewire-server-auth-delegator --ignore-not-found

# Load and apply the local runtime pieces needed for sandbox-backed environments.
local-runtime: build-gateway build-sandbox-controller build-derp-local build-services-local
	@$(MAKE) kind-label-local-nodes
	@$(MAKE) kind-sandbox-namespace
	kind load docker-image $(REGISTRY)/codewire/gateway:local --name codewire
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
# Codewire SDK lives in libs/sdk-{go,python,ts}; examples live in
# libs/sdk-examples. Targets here mirror what the old separate codewiresh/sdk
# Makefile exposed.

.PHONY: test-sdk test-sdk-go test-sdk-python test-sdk-ts \
        sdk-e2e sdk-e2e-go sdk-e2e-python sdk-e2e-ts \
        sdk-run-claude sdk-run-claude-go sdk-run-claude-python sdk-run-claude-ts

test-sdk: test-sdk-go test-sdk-python test-sdk-ts

test-sdk-go:
	cd libs/sdk-go && GOWORK=off go build ./... && GOWORK=off go vet ./... && GOWORK=off go test ./... -count=1 -timeout 60s

test-sdk-ts:
	cd libs/sdk-ts && npm ci --silent --ignore-scripts && npm run typecheck && npm test

test-sdk-python:
	cd libs/sdk-python && \
	  test -d .venv || python3 -m venv .venv && \
	  .venv/bin/pip install --require-hashes -r requirements.lock -q && \
	  .venv/bin/pip install --no-deps . -q && \
	  env -u CODEWIRE_API_KEY -u CODEWIRE_ORG_ID -u CODEWIRE_BASE_URL \
	    PYTHONPATH="$(CURDIR)/libs/gen-python$${PYTHONPATH:+:$$PYTHONPATH}" .venv/bin/python -m unittest test_sdk test_transport -v && \
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
	cd libs/sdk-ts && npm ci --silent --ignore-scripts && ./node_modules/.bin/tsx src/e2e.ts

# End-to-end parity smoke test against a docker-backed local VM. Requires
# docker, cw on PATH (or $CW_BIN), and a Claude auth env (ANTHROPIC_API_KEY
# preferred for CI; CLAUDE_CODE_OAUTH_TOKEN works locally).
sdk-run-claude: sdk-run-claude-go sdk-run-claude-python sdk-run-claude-ts

sdk-run-claude-go:
	cd libs/sdk-examples/run-claude/go && go run .

sdk-run-claude-python: test-sdk-python
	cd libs/sdk-examples/run-claude/python && \
	  PYTHONPATH="$(CURDIR)/libs/gen-python$${PYTHONPATH:+:$$PYTHONPATH}" \
	  $(CURDIR)/libs/sdk-python/.venv/bin/python run_claude.py

sdk-run-claude-ts:
	cd libs/sdk-ts && npm ci --silent --ignore-scripts && npm run build
	cd libs/sdk-examples/run-claude/typescript && \
	  (test -d node_modules || npm ci --silent --ignore-scripts) && \
	  npm run start --silent
