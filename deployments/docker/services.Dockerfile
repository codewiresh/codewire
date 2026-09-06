# syntax=docker/dockerfile:1.20
# codewire Rust services — one image, many entrypoints.
#
# Builds every Rust server binary once (shared deps compiled a single time)
# and ships them together, the same model as the Go `server` image. Each
# deployment selects its binary via `command`:
#
#   deployments/k8s/idp            → command: ["/codewire-idp"]
#   deployments/k8s/orchestration  → command: ["/codewire-orchestration"]
#   deployments/k8s/billing        → command: ["/codewire-billing"]
#   deployments/k8s/coordinator    → command: ["/codewire-coordinator"]
#   schema bootstrap               → command: ["/codewire-db-migrate"]
#   runtime UDP peer relay         → command: ["/codewire-udp-relay"]
#   isolated credential authority  → command: ["/codewire-credential-service"]
#   diagnostics                    → command: ["/sidecar-smoke"]
#
# Built+pushed as codewire/services by .gitea/workflows/ci.yaml. Build from
# the repo root:
#
#   docker buildx bake --file docker-bake.hcl --pull --load \
#     --set 'services.tags=codewire-services:dev' services
#
# protoc is a build dependency of codewire-orchestration's temporalio-sdk
# family (prost-wkt-types). It comes from one checksum-pinned upstream archive;
# the image never consults an operating-system package repository.

ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
ARG TARGETARCH

# Official Codex 0.149.0 native enrollment executable, the same accepted
# version as the workspace contract. No Node/npm runtime or install script.
# Archive bytes also match the upstream npm SHA-512 integrity values recorded
# in docs/SECRETS.md. Only the selected target's artifact stage is built.
FROM ${DEBIAN_IMAGE} AS codex-amd64
ADD --checksum=sha256:e06f3d106fe8bb058a6bfd30075d89ea17deaee7c8425e0c5d23072df0fdd0e7 \
    https://registry.npmjs.org/@openai/codex/-/codex-0.149.0-linux-x64.tgz /codex.tgz
RUN mkdir /codex && tar -xzf /codex.tgz -C /codex --strip-components=4 \
    package/vendor/x86_64-unknown-linux-musl/bin/codex

FROM ${DEBIAN_IMAGE} AS codex-arm64
ADD --checksum=sha256:2d8e3032f4a058d1597606aba9ed8cc6eff59de678e2f81083ee11b898250e07 \
    https://registry.npmjs.org/@openai/codex/-/codex-0.149.0-linux-arm64.tgz /codex.tgz
RUN mkdir /codex && tar -xzf /codex.tgz -C /codex --strip-components=4 \
    package/vendor/aarch64-unknown-linux-musl/bin/codex

FROM codex-${TARGETARCH} AS codex-enrollment

FROM codewire-rust-base AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# codewire-proto (a codewire-server-core dependency since connect-rpc 03
# WI-2) compiles proto/codewire/** + proto/google/rpc/** at build time via
# protoc — the contract sources must be in the build context.
COPY proto ./proto
# WI-R4 makes orchestration's authenticated environment proxy consume the
# private daemon protocol through codewire-gateway-proto. Its build script
# compiles this separate internal schema at build time.
COPY libs/gateway-proto ./libs/gateway-proto
ARG CODEWIRE_SCCACHE_MODE=disabled
ARG SCCACHE_BUCKET
ARG SCCACHE_ENDPOINT
ARG CODEWIRE_SCCACHE_PREFIX
ARG CODEWIRE_RUST_PROFILE=release
ARG CODEWIRE_ORCHESTRATION_FEATURES=
RUN --mount=type=cache,id=codewire-services-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=codewire-services-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=codewire-sccache-v2,target=/var/cache/sccache,sharing=shared \
    --mount=type=secret,id=aws_shared_credentials \
    find Cargo.toml Cargo.lock crates proto libs/gateway-proto -type f -exec touch {} + && \
    codewire-rust-build cargo build --locked --profile "$CODEWIRE_RUST_PROFILE" \
      --bin codewire-idp \
      --bin sidecar-smoke \
      --bin codewire-billing \
      --bin codewire-coordinator \
      --bin codewire-db-migrate \
      --bin codewire-udp-relay && \
    set -- && \
    if [ -n "$CODEWIRE_ORCHESTRATION_FEATURES" ]; then \
      set -- --features "$CODEWIRE_ORCHESTRATION_FEATURES"; \
    fi && \
    codewire-rust-build cargo build --locked --profile "$CODEWIRE_RUST_PROFILE" \
      -p codewire-orchestration --bin codewire-orchestration "$@" && \
    codewire-rust-build cargo build --locked --profile "$CODEWIRE_RUST_PROFILE" \
      -p codewire-credential-service --features enrollment --bin codewire-credential-service && \
    mkdir -p /out && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-idp" /out/codewire-idp && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-orchestration" /out/codewire-orchestration && \
    cp "target/$CODEWIRE_RUST_PROFILE/sidecar-smoke" /out/sidecar-smoke && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-billing" /out/codewire-billing && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-coordinator" /out/codewire-coordinator && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-db-migrate" /out/codewire-db-migrate && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-udp-relay" /out/codewire-udp-relay && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-credential-service" /out/codewire-credential-service && \
    mkdir -p /out/kind-fixtures && \
    if [ "$CODEWIRE_ORCHESTRATION_FEATURES" = kind-e2e ]; then \
      test "$CODEWIRE_RUST_PROFILE" = ci && \
      codewire-rust-build cargo test --locked --profile ci \
        -p codewire-credential-service --features enrollment --lib --no-run \
        --message-format=json > /tmp/credential-fixture-artifacts.jsonl && \
      credential_fixture="$(sed -n '/"reason":"compiler-artifact"/{/"test":true/{s@.*"executable":"\(/src/target/ci/deps/codewire_credential_service-[0-9a-f][0-9a-f]*\)".*@\1@p;}}' /tmp/credential-fixture-artifacts.jsonl)" && \
      test -n "$credential_fixture" && test -x "$credential_fixture" && \
      "$credential_fixture" --list > /tmp/credential-fixture-tests.txt && \
      grep -qx 'runtime::kind::serve_kind_credential_fixture: test' /tmp/credential-fixture-tests.txt && \
      cp "$credential_fixture" /out/kind-fixtures/credential-service; \
    fi

FROM ${DEBIAN_IMAGE}
COPY --from=builder /out/codewire-idp /codewire-idp
COPY --from=builder /out/codewire-orchestration /codewire-orchestration
COPY --from=builder /out/sidecar-smoke /sidecar-smoke
COPY --from=builder /out/codewire-billing /codewire-billing
COPY --from=builder /out/codewire-coordinator /codewire-coordinator
COPY --from=builder /out/codewire-db-migrate /codewire-db-migrate
COPY --from=builder /out/codewire-udp-relay /codewire-udp-relay
COPY --from=builder /out/codewire-credential-service /codewire-credential-service
# Empty in the release graph: cfg(test) code is built only by services-ci's
# existing kind-e2e feature/profile pair. No production fixture switch exists.
COPY --from=builder /out/kind-fixtures/ /codewire-kind-fixtures/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=codex-enrollment /codex/codex /usr/local/bin/codex
COPY deployments/docker/licenses/codex-LICENSE deployments/docker/licenses/codex-NOTICE /usr/share/licenses/codex/
USER 65532:65532
# No ENTRYPOINT: each deployment sets `command` to pick its binary.
