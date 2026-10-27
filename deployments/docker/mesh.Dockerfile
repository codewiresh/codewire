# Hosted Codewire Mesh image.

# syntax=docker/dockerfile:1.20
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

FROM codewire-rust-base AS builder
# protoc: codewire-mesh -> codewire-server-core -> codewire-proto compiles
# proto/codewire/** + proto/google/rpc/** at build time (connect-rpc 03 WI-2).
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
ARG CODEWIRE_SCCACHE_MODE=disabled
ARG SCCACHE_BUCKET
ARG SCCACHE_ENDPOINT
ARG CODEWIRE_SCCACHE_PREFIX
ARG CODEWIRE_RUST_PROFILE=runtime
# Cargo's job count, set on the trusted BuildKit builder to fit its memory
# (scripts/ci/setup/trusted-buildkit.sh); empty means Cargo's default.
ARG CARGO_BUILD_JOBS
RUN --mount=type=cache,id=codewire-mesh-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=codewire-mesh-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=codewire-sccache-v2,target=/var/cache/sccache,sharing=shared \
    --mount=type=secret,id=aws_shared_credentials \
    find Cargo.toml Cargo.lock crates proto -type f -exec touch {} + && \
    codewire-rust-build cargo build --locked --profile "$CODEWIRE_RUST_PROFILE" -p codewire-mesh --bin codewire-mesh \
    && mkdir -p /out \
    && cp "target/$CODEWIRE_RUST_PROFILE/codewire-mesh" /out/codewire-mesh

FROM ${DEBIAN_IMAGE}
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/codewire-mesh /usr/local/bin/codewire-mesh
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/codewire-mesh"]
