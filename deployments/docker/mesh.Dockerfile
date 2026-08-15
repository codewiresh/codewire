# Hosted Codewire Mesh image.

ARG RUST_IMAGE=rust:1.91.1-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

FROM ${RUST_IMAGE} AS protoc
ADD --checksum=sha256:6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7 \
  https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip \
  /tmp/protoc.zip
RUN unzip -q /tmp/protoc.zip -d /opt/protoc \
    && /opt/protoc/bin/protoc --version

FROM ${RUST_IMAGE} AS builder
# protoc: codewire-mesh -> codewire-server-core -> codewire-proto compiles
# proto/codewire/** + proto/google/rpc/** at build time (connect-rpc 03 WI-2).
COPY --from=protoc /opt/protoc /opt/protoc
ENV PATH="/opt/protoc/bin:${PATH}"
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
RUN --mount=type=cache,id=codewire-root-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=codewire-root-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=codewire-root-release-target,target=/src/target,sharing=locked \
    find Cargo.toml Cargo.lock crates proto -type f -exec touch {} + && \
    cargo build --locked --release -p codewire-mesh --bin codewire-mesh \
    && mkdir -p /out \
    && cp target/release/codewire-mesh /out/codewire-mesh

FROM ${DEBIAN_IMAGE}
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/codewire-mesh /usr/local/bin/codewire-mesh
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/codewire-mesh"]
