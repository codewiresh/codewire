# syntax=docker/dockerfile:1
# Local Kind development only (`make kind-deploy`): compile one product binary
# incrementally in the same pinned Rust/Bookworm toolchain as the services
# image and export just that file. Never promotable; nothing here is published.
FROM codewire-rust-base AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
COPY libs/gateway-proto ./libs/gateway-proto
# The dashboard embeds its design assets and the CLI installer.
COPY packages/codewire-design ./packages/codewire-design
COPY apps/cli/install.sh ./apps/cli/install.sh
ARG KIND_DEV_CRATE
ARG KIND_DEV_FEATURES=
ARG KIND_DEV_BIN=
# A persistent target directory makes repeated builds incremental; the
# registry caches are shared with the services image build.
#
# Every worktree shares that target directory, and Cargo judges freshness by
# modification time: a worktree whose files are older than the last build from
# another worktree would silently reuse that build's binary. So freshness is
# content-based here. The target keeps a hash of every source file it was built
# from; files whose content differs are touched before building, which makes
# Cargo rebuild exactly the crates they belong to. Without a record every file
# counts as changed. The record is written only after a successful build, so
# it always describes the artifacts beside it.
RUN --mount=type=cache,id=codewire-services-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=codewire-services-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=codewire-kind-dev-target,target=/src/target,sharing=locked \
    test -n "$KIND_DEV_CRATE" && \
    bin="${KIND_DEV_BIN:-$KIND_DEV_CRATE}" && \
    built=target/kind-dev-sources.sha256 && \
    find Cargo.toml Cargo.lock crates proto libs/gateway-proto packages/codewire-design apps/cli/install.sh \
      -type f -print0 | sort -z | xargs -0 sha256sum >/tmp/kind-dev-sources.sha256 && \
    { [ -f "$built" ] || : >"$built"; } && \
    grep -vxFf "$built" /tmp/kind-dev-sources.sha256 | cut -c67- | tr '\n' '\0' | xargs -0r touch -c && \
    set -- && \
    if [ -n "$KIND_DEV_FEATURES" ]; then set -- --features "$KIND_DEV_FEATURES"; fi && \
    cargo build --locked --profile ci -p "$KIND_DEV_CRATE" --bin "$bin" "$@" && \
    install -D "target/ci/$bin" "/out/$bin" && \
    cp /tmp/kind-dev-sources.sha256 "$built"

FROM scratch
COPY --from=builder /out/ /
