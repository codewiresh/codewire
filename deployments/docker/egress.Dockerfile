# The cw-egress image: the one binary, which starts each Sandbox's egress
# broker and network worker from itself by descriptor, and the CA bundle
# (private-docs designs/hosted-egress.md, "The image and its deployment").

ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

FROM codewire-rust-base AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
# Cargo needs every [patch] path the root manifest names (#3980).
COPY third_party/sqlx-sqlite-unused ./third_party/sqlx-sqlite-unused
COPY crates ./crates
COPY proto ./proto
# codewire-daemon-proto, which cw-egress links, compiles these at build.
COPY libs/daemon-proto ./libs/daemon-proto
ARG CODEWIRE_SCCACHE_MODE=disabled
ARG SCCACHE_BUCKET
ARG SCCACHE_ENDPOINT
ARG CODEWIRE_SCCACHE_PREFIX
ARG CODEWIRE_RUST_PROFILE=runtime
# Cargo's job count, set on the trusted BuildKit builder to fit its memory
# (scripts/ci/setup/trusted-buildkit.sh); empty means Cargo's default.
ARG CARGO_BUILD_JOBS
RUN --mount=type=cache,id=codewire-egress-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=codewire-egress-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=codewire-sccache-v2,target=/var/cache/sccache,sharing=shared \
    --mount=type=secret,id=aws_shared_credentials \
    find Cargo.toml Cargo.lock crates proto libs/daemon-proto -type f -exec touch {} + && \
    codewire-rust-build cargo build --locked --profile "$CODEWIRE_RUST_PROFILE" -p codewire-egress-node --bin cw-egress \
    && mkdir -p /out \
    && cp "target/$CODEWIRE_RUST_PROFILE/cw-egress" /out/cw-egress

FROM ${DEBIAN_IMAGE}
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/cw-egress /cw-egress
ENTRYPOINT ["/cw-egress"]
