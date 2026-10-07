# syntax=docker/dockerfile:1.20
# The workspace support image: it ships only `cw`, the workspace daemon that
# every sandbox Pod runs (from an image volume or an init-container copy).
# It keeps its historical `codewire-gateway` name; nothing in it is a gateway.

ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

# The static amd64 asset stage has no certificate store. Take the same public
# trust bundle the existing native builder obtains from the admitted Rust base.
FROM codewire-rust-base AS cw-runtime-trust

# The checked-in host wrapper binds this reserved context after admitting the
# complete static CW record and OCI archive. Without that binding it stays an
# empty local stage; BuildKit cannot turn the name into a registry pull.
FROM scratch AS codewire-verified-cw

FROM scratch AS cw-builder-amd64
COPY --from=codewire-verified-cw --chown=0:0 --chmod=0555 /cw /out/cw
COPY --from=codewire-verified-cw --chown=0:0 --chmod=0444 /provenance.json /out/provenance/provenance.json

# ARM retains its existing native build. It does not claim the verified amd64
# startup asset or the platform updater capability.
FROM codewire-rust-base AS cw-builder-arm64
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
    && mkdir -p /out/provenance \
    && cp "target/$CODEWIRE_RUST_PROFILE/cw" /out/cw

FROM cw-builder-${TARGETARCH} AS cw-builder

FROM ${DEBIAN_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/codewiresh/codewire" \
      org.opencontainers.image.title="codewire-gateway"
COPY --from=cw-runtime-trust /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=cw-builder --chown=0:0 --chmod=0555 /out/cw /usr/local/bin/cw
COPY --from=cw-builder --chown=0:0 /out/provenance/ /usr/local/share/codewire/cw-runtime/
RUN /usr/local/bin/cw --version
ENTRYPOINT ["/usr/local/bin/cw"]
