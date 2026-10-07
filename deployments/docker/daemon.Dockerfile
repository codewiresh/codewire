# The workspace support image: it ships only `cw`, the workspace daemon that
# every sandbox Pod runs (from an image volume or an init-container copy).

# syntax=docker/dockerfile:1.20
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

FROM codewire-rust-base AS cw-builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
COPY libs/daemon-proto ./libs/daemon-proto
ARG CODEWIRE_SCCACHE_MODE=disabled
ARG SCCACHE_BUCKET
ARG SCCACHE_ENDPOINT
ARG CODEWIRE_SCCACHE_PREFIX
ARG CODEWIRE_RUST_PROFILE=release
RUN --mount=type=cache,id=codewire-daemon-cw-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=codewire-daemon-cw-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=codewire-sccache-v2,target=/var/cache/sccache,sharing=shared \
    --mount=type=secret,id=aws_shared_credentials \
    find Cargo.toml Cargo.lock crates proto libs/daemon-proto -type f -exec touch {} + && \
    codewire-rust-build cargo build --locked --profile "$CODEWIRE_RUST_PROFILE" -p codewire-cli-bin --bin cw \
    && mkdir -p /out \
    && cp "target/$CODEWIRE_RUST_PROFILE/cw" /out/cw

FROM ${DEBIAN_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/codewiresh/codewire" \
      org.opencontainers.image.title="codewire-daemon"
COPY --from=cw-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=cw-builder /out/cw /usr/local/bin/cw
RUN /usr/local/bin/cw --version
ENTRYPOINT ["/usr/local/bin/cw"]
