# Hosted Codewire Mesh image.

ARG RUST_IMAGE=rust:1.91-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

FROM ${RUST_IMAGE} AS builder
# protoc: codewire-mesh -> codewire-server-core -> codewire-proto compiles
# proto/codewire/** + proto/google/rpc/** at build time (connect-rpc 03 WI-2).
RUN apt-get update -qq && apt-get install -y -qq protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
RUN cargo build --locked --release -p codewire-mesh --bin codewire-mesh

FROM ${DEBIAN_IMAGE}
RUN apt-get update -qq && apt-get install -y -qq ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/codewire-mesh /usr/local/bin/codewire-mesh
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/codewire-mesh"]
