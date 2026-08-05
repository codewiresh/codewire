# Canonical DERP/STUN relay image.
#
# The image runs the Rust `codewire-derp` binary used by the DERP relay and
# STUN-only edge deployments.

ARG RUST_IMAGE=rust:1.91-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

FROM ${RUST_IMAGE} AS rust-builder
ARG PROTOC_VERSION=35.1
ARG PROTOC_SHA256_LINUX_X86_64=6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7
RUN apt-get update -qq && apt-get install -y -qq curl unzip && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /tmp/protoc.zip "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip" \
    && echo "${PROTOC_SHA256_LINUX_X86_64}  /tmp/protoc.zip" | sha256sum -c - \
    && unzip -q /tmp/protoc.zip -d /opt/protoc \
    && rm /tmp/protoc.zip \
    && /opt/protoc/bin/protoc --version
ENV PATH="/opt/protoc/bin:${PATH}"
WORKDIR /src
COPY deployments/docker/derp.Cargo.toml ./Cargo.toml
COPY deployments/docker/derp.Cargo.lock ./Cargo.lock
COPY crates/codewire-derp ./crates/codewire-derp
COPY crates/codewire-proto ./crates/codewire-proto
COPY crates/codewire-tailnet ./crates/codewire-tailnet
COPY proto ./proto
RUN cargo build --locked --release -p codewire-derp --bin codewire-derp

FROM ${DEBIAN_IMAGE}
RUN apt-get update -qq && apt-get install -y -qq ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=rust-builder /src/target/release/codewire-derp /usr/local/bin/codewire-derp
EXPOSE 8080 8443 3478/udp
ENTRYPOINT ["/usr/local/bin/codewire-derp"]
