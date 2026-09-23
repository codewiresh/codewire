# syntax=docker/dockerfile:1
# Local Kind development only (`make kind-deploy`): compile one service binary
# incrementally in the same pinned Rust/Bookworm toolchain as the services
# image and export just that file. Never promotable; nothing here is published.
FROM codewire-rust-base AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
COPY libs/gateway-proto ./libs/gateway-proto
ARG KIND_DEV_CRATE
ARG KIND_DEV_FEATURES=
ARG KIND_DEV_BIN=
# A persistent target directory makes repeated builds incremental; the
# registry caches are shared with the services image build.
RUN --mount=type=cache,id=codewire-services-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=codewire-services-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=codewire-kind-dev-target,target=/src/target,sharing=locked \
    test -n "$KIND_DEV_CRATE" && \
    bin="${KIND_DEV_BIN:-$KIND_DEV_CRATE}" && \
    set -- && \
    if [ -n "$KIND_DEV_FEATURES" ]; then set -- --features "$KIND_DEV_FEATURES"; fi && \
    cargo build --locked --profile ci -p "$KIND_DEV_CRATE" --bin "$bin" "$@" && \
    install -D "target/ci/$bin" "/out/$bin"

FROM scratch
COPY --from=builder /out/ /
