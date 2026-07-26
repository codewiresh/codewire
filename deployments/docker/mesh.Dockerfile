# Hosted Codewire Mesh image.

FROM rust:1.91-bookworm AS builder
# protoc: codewire-mesh -> codewire-server-core -> codewire-proto compiles
# proto/codewire/** + proto/google/rpc/** at build time (connect-rpc 03 WI-2).
RUN apt-get update -qq && apt-get install -y -qq protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
RUN cargo build --locked --release -p codewire-mesh --bin codewire-mesh

FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y -qq ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/codewire-mesh /usr/local/bin/codewire-mesh
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/codewire-mesh"]
