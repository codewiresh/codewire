# Canonical sandbox gateway image.
#
# The image runs the Rust `codewire-gateway` startup path and ships the Rust
# workspace daemon used inside sandbox pods.

FROM rust:1.91-bookworm AS rust-toolchain
ARG PROTOC_VERSION=35.1
ARG PROTOC_SHA256_LINUX_X86_64=6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7
RUN apt-get update -qq && apt-get install -y -qq curl unzip && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /tmp/protoc.zip "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip" \
    && echo "${PROTOC_SHA256_LINUX_X86_64}  /tmp/protoc.zip" | sha256sum -c - \
    && unzip -q /tmp/protoc.zip -d /opt/protoc \
    && rm /tmp/protoc.zip \
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
RUN cargo build --locked --release -p codewire-gateway --bin codewire-gateway

FROM rust-toolchain AS cw-builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
COPY libs/gateway-proto ./libs/gateway-proto
RUN cargo build --locked --release -p codewire-cli-bin --bin cw

FROM debian:bookworm-slim
LABEL org.opencontainers.image.source="https://github.com/codewiresh/codewire" \
      org.opencontainers.image.title="codewire-gateway"
RUN apt-get update -qq && apt-get install -y -qq ca-certificates bash && rm -rf /var/lib/apt/lists/*
COPY --from=rust-builder /src/target/release/codewire-gateway /usr/local/bin/codewire-gateway
COPY --from=cw-builder /src/target/release/cw /usr/local/bin/cw
RUN ln -s cw /usr/local/bin/daemon \
    && ln -s cw /usr/local/bin/codewire-daemon \
    && /usr/local/bin/cw --version
ENTRYPOINT ["/usr/local/bin/codewire-gateway"]
