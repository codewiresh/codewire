# Canonical DERP/STUN relay image.
#
# The image runs the Rust `codewire-derp` binary used by the DERP relay and
# STUN-only edge deployments.

# syntax=docker/dockerfile:1.20
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

FROM codewire-rust-base AS rust-builder
WORKDIR /src
COPY deployments/docker/derp.Cargo.toml ./Cargo.toml
COPY deployments/docker/derp.Cargo.lock ./Cargo.lock
COPY crates/codewire-derp ./crates/codewire-derp
COPY crates/codewire-proto ./crates/codewire-proto
COPY crates/codewire-tailnet ./crates/codewire-tailnet
COPY proto ./proto
ARG CODEWIRE_SCCACHE_MODE=disabled
ARG SCCACHE_BUCKET
ARG SCCACHE_ENDPOINT
ARG CODEWIRE_SCCACHE_PREFIX
ARG CODEWIRE_RUST_PROFILE=release
RUN --mount=type=cache,id=codewire-derp-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=codewire-derp-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=codewire-sccache-v2,target=/var/cache/sccache,sharing=shared \
    --mount=type=secret,id=aws_shared_credentials \
    find Cargo.toml Cargo.lock crates proto -type f -exec touch {} + \
    && codewire-rust-build cargo build --locked --profile "$CODEWIRE_RUST_PROFILE" -p codewire-derp --bin codewire-derp \
    && mkdir -p /out \
    && cp "target/$CODEWIRE_RUST_PROFILE/codewire-derp" /out/codewire-derp

FROM ${DEBIAN_IMAGE}
COPY --from=rust-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=rust-builder /out/codewire-derp /usr/local/bin/codewire-derp
EXPOSE 8080 8443 3478/udp
ENTRYPOINT ["/usr/local/bin/codewire-derp"]
