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
#   tenant-secret operations       → command: ["/tenant-secret-operator"]
#   runtime UDP peer relay         → command: ["/codewire-udp-relay"]
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

# syntax=docker/dockerfile:1.20
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

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
RUN --mount=type=cache,id=codewire-services-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=codewire-services-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=codewire-sccache-v2,target=/var/cache/sccache,sharing=shared \
    --mount=type=secret,id=aws_shared_credentials \
    find Cargo.toml Cargo.lock crates proto libs/gateway-proto -type f -exec touch {} + && \
    codewire-rust-build cargo build --locked --profile "$CODEWIRE_RUST_PROFILE" \
      --bin codewire-idp \
      --bin codewire-orchestration \
      --bin tenant-secret-operator \
      --bin sidecar-smoke \
      --bin codewire-billing \
      --bin codewire-coordinator \
      --bin codewire-db-migrate \
      --bin codewire-udp-relay && \
    mkdir -p /out && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-idp" /out/codewire-idp && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-orchestration" /out/codewire-orchestration && \
    cp "target/$CODEWIRE_RUST_PROFILE/tenant-secret-operator" /out/tenant-secret-operator && \
    cp "target/$CODEWIRE_RUST_PROFILE/sidecar-smoke" /out/sidecar-smoke && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-billing" /out/codewire-billing && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-coordinator" /out/codewire-coordinator && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-db-migrate" /out/codewire-db-migrate && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-udp-relay" /out/codewire-udp-relay

FROM ${DEBIAN_IMAGE}
COPY --from=builder /out/codewire-idp /codewire-idp
COPY --from=builder /out/codewire-orchestration /codewire-orchestration
COPY --from=builder /out/tenant-secret-operator /tenant-secret-operator
COPY --from=builder /out/sidecar-smoke /sidecar-smoke
COPY --from=builder /out/codewire-billing /codewire-billing
COPY --from=builder /out/codewire-coordinator /codewire-coordinator
COPY --from=builder /out/codewire-db-migrate /codewire-db-migrate
COPY --from=builder /out/codewire-udp-relay /codewire-udp-relay
USER 65532:65532
# No ENTRYPOINT: each deployment sets `command` to pick its binary.
