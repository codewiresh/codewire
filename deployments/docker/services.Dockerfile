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
#   diagnostics                    → command: ["/sidecar-smoke"]
#
# Built+pushed as codewire/services by .gitea/workflows/ci.yaml. Build from
# the repo root:
#
#   docker build -f deployments/docker/services.Dockerfile -t codewire-services:dev .
#
# protobuf-compiler is a build dependency of codewire-orchestration's
# temporalio-sdk family (prost-wkt-types); idp/billing don't need it but the
# single builder installs it once.

ARG RUST_IMAGE=rust:1.91.1-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

FROM ${RUST_IMAGE} AS builder
RUN apt-get update -qq && apt-get install -y -qq protobuf-compiler && rm -rf /var/lib/apt/lists/*
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
ARG CODEWIRE_CARGO_CACHE_PROBE
# The target cache outlives this source snapshot while COPY preserves source
# mtimes. Refresh only workspace inputs so Cargo cannot reuse stale local
# fingerprints; registry/git dependencies and their compiled output stay hot.
RUN --mount=type=cache,id=codewire-services-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=codewire-services-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=codewire-services-release-target,target=/src/target,sharing=locked \
    find Cargo.toml Cargo.lock crates proto libs/gateway-proto -type f -exec touch {} + && \
    if [ -n "$CODEWIRE_CARGO_CACHE_PROBE" ]; then \
      printf 'codewire-services cargo cache probe: %s\n' "$CODEWIRE_CARGO_CACHE_PROBE"; \
      set -- --verbose; \
    else \
      set --; \
    fi; \
    cargo build "$@" --locked --release \
      --bin codewire-idp \
      --bin codewire-orchestration \
      --bin sidecar-smoke \
      --bin codewire-billing \
      --bin codewire-coordinator \
      --bin codewire-db-migrate \
      --bin codewire-udp-relay && \
    mkdir -p /out && \
    cp target/release/codewire-idp /out/codewire-idp && \
    cp target/release/codewire-orchestration /out/codewire-orchestration && \
    cp target/release/sidecar-smoke /out/sidecar-smoke && \
    cp target/release/codewire-billing /out/codewire-billing && \
    cp target/release/codewire-coordinator /out/codewire-coordinator && \
    cp target/release/codewire-db-migrate /out/codewire-db-migrate && \
    cp target/release/codewire-udp-relay /out/codewire-udp-relay

FROM ${DEBIAN_IMAGE}
COPY --from=builder /out/codewire-idp /codewire-idp
COPY --from=builder /out/codewire-orchestration /codewire-orchestration
COPY --from=builder /out/sidecar-smoke /sidecar-smoke
COPY --from=builder /out/codewire-billing /codewire-billing
COPY --from=builder /out/codewire-coordinator /codewire-coordinator
COPY --from=builder /out/codewire-db-migrate /codewire-db-migrate
COPY --from=builder /out/codewire-udp-relay /codewire-udp-relay
USER 65532:65532
# No ENTRYPOINT: each deployment sets `command` to pick its binary.
