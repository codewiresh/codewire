# Canonical sandbox gateway image.
#
# The image runs the Rust `codewire-gateway` startup path and ships the Rust
# workspace daemon used inside sandbox pods.

# syntax=docker/dockerfile:1.20
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

FROM codewire-rust-base AS rust-builder
WORKDIR /src
COPY deployments/docker/gateway.Cargo.toml ./Cargo.toml
COPY deployments/docker/gateway.Cargo.lock ./Cargo.lock
COPY crates/codewire-client ./crates/codewire-client
COPY crates/codewire-gateway ./crates/codewire-gateway
COPY crates/codewire-gateway-proto ./crates/codewire-gateway-proto
COPY crates/codewire-proto ./crates/codewire-proto
COPY crates/codewire-tailnet ./crates/codewire-tailnet
COPY proto ./proto
COPY libs/gateway-proto ./libs/gateway-proto
ARG CODEWIRE_SCCACHE_MODE=disabled
ARG SCCACHE_BUCKET
ARG SCCACHE_ENDPOINT
ARG CODEWIRE_SCCACHE_PREFIX
ARG CODEWIRE_RUST_PROFILE=release
RUN --mount=type=cache,id=codewire-gateway-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=codewire-gateway-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=codewire-sccache-v2,target=/var/cache/sccache,sharing=shared \
    --mount=type=secret,id=aws_shared_credentials \
    find Cargo.toml Cargo.lock crates proto libs/gateway-proto -type f -exec touch {} + && \
    codewire-rust-build cargo build --locked --profile "$CODEWIRE_RUST_PROFILE" -p codewire-gateway --bin codewire-gateway \
    && mkdir -p /out \
    && cp "target/$CODEWIRE_RUST_PROFILE/codewire-gateway" /out/codewire-gateway

FROM codewire-rust-base AS cw-builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
COPY libs/gateway-proto ./libs/gateway-proto
ARG CODEWIRE_SCCACHE_MODE=disabled
ARG SCCACHE_BUCKET
ARG SCCACHE_ENDPOINT
ARG CODEWIRE_SCCACHE_PREFIX
ARG CODEWIRE_RUST_PROFILE=release
RUN --mount=type=cache,id=codewire-gateway-cw-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=codewire-gateway-cw-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=codewire-sccache-v2,target=/var/cache/sccache,sharing=shared \
    --mount=type=secret,id=aws_shared_credentials \
    find Cargo.toml Cargo.lock crates proto libs/gateway-proto -type f -exec touch {} + && \
    codewire-rust-build cargo build --locked --profile "$CODEWIRE_RUST_PROFILE" -p codewire-cli-bin --bin cw \
    && mkdir -p /out \
    && cp "target/$CODEWIRE_RUST_PROFILE/cw" /out/cw

FROM ${DEBIAN_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/codewiresh/codewire" \
      org.opencontainers.image.title="codewire-gateway"
COPY --from=rust-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=rust-builder /out/codewire-gateway /usr/local/bin/codewire-gateway
COPY --from=cw-builder /out/cw /usr/local/bin/cw
RUN ln -s cw /usr/local/bin/daemon \
    && ln -s cw /usr/local/bin/codewire-daemon \
    && /usr/local/bin/cw --version
ENTRYPOINT ["/usr/local/bin/codewire-gateway"]
