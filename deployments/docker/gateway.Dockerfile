# Canonical sandbox gateway image.
#
# The image runs the Rust `codewire-gateway` startup path and ships the Rust
# workspace daemon used inside sandbox pods.

ARG RUST_IMAGE=rust:1.91.1-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

FROM ${RUST_IMAGE} AS rust-toolchain
ADD --checksum=sha256:6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7 \
  https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip \
  /tmp/protoc.zip
RUN unzip -q /tmp/protoc.zip -d /opt/protoc \
    && /opt/protoc/bin/protoc --version
ENV PATH="/opt/protoc/bin:${PATH}"

FROM rust-toolchain AS rust-builder
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
RUN --mount=type=cache,id=codewire-root-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=codewire-root-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=codewire-gateway-release-target,target=/src/target,sharing=locked \
    find Cargo.toml Cargo.lock crates proto libs/gateway-proto -type f -exec touch {} + && \
    cargo build --locked --release -p codewire-gateway --bin codewire-gateway \
    && mkdir -p /out \
    && cp target/release/codewire-gateway /out/codewire-gateway

FROM rust-toolchain AS cw-builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
COPY libs/gateway-proto ./libs/gateway-proto
RUN --mount=type=cache,id=codewire-root-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=codewire-root-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=codewire-root-release-target,target=/src/target,sharing=locked \
    find Cargo.toml Cargo.lock crates proto libs/gateway-proto -type f -exec touch {} + && \
    cargo build --locked --release -p codewire-cli-bin --bin cw \
    && mkdir -p /out \
    && cp target/release/cw /out/cw

FROM ${DEBIAN_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/codewiresh/codewire" \
      org.opencontainers.image.title="codewire-gateway"
COPY --from=rust-toolchain /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=rust-builder /out/codewire-gateway /usr/local/bin/codewire-gateway
COPY --from=cw-builder /out/cw /usr/local/bin/cw
RUN ln -s cw /usr/local/bin/daemon \
    && ln -s cw /usr/local/bin/codewire-daemon \
    && /usr/local/bin/cw --version
ENTRYPOINT ["/usr/local/bin/codewire-gateway"]
