# syntax=docker/dockerfile:1
# Local Kind development only (`make kind-deploy`): compile one product binary
# incrementally in the same pinned Rust/Bookworm toolchain as the services
# image and export just that file. Never promotable; nothing here is published.
# With KIND_DEV_FIXTURE_FEATURES it also exports the crate's library test
# binary as kind-fixtures/<bin>, built the way services-ci builds the Kind
# credential fixture, so the gate's synthetic mode runs the current source.
# The retained suites' smoke build (scripts/dev/kind/build-smokes.sh) uses the
# same target: KIND_DEV_BIN may name several binaries, KIND_DEV_EXAMPLES names
# examples (exported as examples/<name>) and KIND_DEV_TEST one integration test
# (exported as tests/<name>), so smokes only link what a deploy compiled.
FROM codewire-rust-base AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
COPY libs/daemon-proto ./libs/daemon-proto
# The dashboard embeds its design assets and the CLI installer.
COPY packages/codewire-design ./packages/codewire-design
COPY apps/cli/install.sh ./apps/cli/install.sh
COPY apps/cli/GPG_PUBLIC_KEY.asc ./apps/cli/GPG_PUBLIC_KEY.asc
# The cw runtime smoke embeds its in-sandbox probe.
COPY scripts/ci/verify/kind/cw_runtime_probe.py ./scripts/ci/verify/kind/cw_runtime_probe.py
ARG KIND_DEV_CRATE
ARG KIND_DEV_FEATURES=
ARG KIND_DEV_BIN=
ARG KIND_DEV_FIXTURE_FEATURES=
ARG KIND_DEV_EXAMPLES=
ARG KIND_DEV_TEST=
ARG KIND_DEV_TREE
# A persistent target directory makes repeated builds incremental; the
# registry caches are shared with the services image build.
#
# Each worktree gets its own target directory inside the shared cache. Cargo
# caches every crate per feature set and judges freshness by modification
# time, so a target shared between worktrees can reuse a crate that another
# worktree built from different source. Within one worktree, freshness is also
# content-based: the target keeps a hash of every source file it was built
# from, and files whose content differs are touched before building, which
# makes Cargo rebuild exactly the crates they belong to. Without a record every
# file counts as changed. The record is written only after a successful build,
# so it always describes the artifacts beside it.
#
# Every compile goes through the repository's disk-only sccache
# (codewire-rust-build local mode), whose content-addressed cache all
# worktrees share: a crate any worktree already compiled from identical inputs
# is a cache hit, so a new worktree's first deploy is no longer a cold build.
RUN --mount=type=cache,id=codewire-services-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=codewire-services-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=codewire-kind-dev-target,target=/src/target,sharing=locked \
    --mount=type=cache,id=codewire-sccache-v2,target=/var/cache/sccache,sharing=shared \
    test -n "$KIND_DEV_CRATE" && \
    test -n "$KIND_DEV_TREE" && \
    export CARGO_TARGET_DIR="/src/target/trees/$KIND_DEV_TREE" && \
    bins="$KIND_DEV_BIN" && \
    if [ -z "$bins$KIND_DEV_EXAMPLES$KIND_DEV_TEST" ]; then bins="$KIND_DEV_CRATE"; fi && \
    built="$CARGO_TARGET_DIR/kind-dev-sources.sha256" && \
    mkdir -p "$CARGO_TARGET_DIR" && \
    find Cargo.toml Cargo.lock crates proto libs/daemon-proto packages/codewire-design apps/cli/install.sh \
      apps/cli/GPG_PUBLIC_KEY.asc scripts/ci/verify/kind/cw_runtime_probe.py \
      -type f -print0 | sort -z | xargs -0 sha256sum >/tmp/kind-dev-sources.sha256 && \
    { [ -f "$built" ] || : >"$built"; } && \
    grep -vxFf "$built" /tmp/kind-dev-sources.sha256 | cut -c67- | tr '\n' '\0' | xargs -0r touch -c && \
    set -- && \
    if [ -n "$KIND_DEV_FEATURES" ]; then set -- --features "$KIND_DEV_FEATURES"; fi && \
    export CODEWIRE_SCCACHE_MODE=local CODEWIRE_RUST_PROFILE=ci && \
    targets= && \
    for bin in $bins; do targets="$targets --bin $bin"; done && \
    for example in $KIND_DEV_EXAMPLES; do targets="$targets --example $example"; done && \
    if [ -n "$targets" ]; then \
      codewire-rust-build cargo build --locked --profile ci -p "$KIND_DEV_CRATE" $targets "$@" && \
      for bin in $bins; do install -D "$CARGO_TARGET_DIR/ci/$bin" "/out/$bin" || exit 1; done && \
      for example in $KIND_DEV_EXAMPLES; do \
        install -D "$CARGO_TARGET_DIR/ci/examples/$example" "/out/examples/$example" || exit 1; \
      done; \
    fi && \
    # Cargo also builds the package's binaries for an integration test; only
    # the test target itself is compiled with the test profile.
    if [ -n "$KIND_DEV_TEST" ]; then \
      codewire-rust-build cargo test --locked --profile ci -p "$KIND_DEV_CRATE" --test "$KIND_DEV_TEST" \
        "$@" --no-run --message-format=json >/tmp/kind-dev-test.jsonl && \
      test_binary="$(sed -n '/"reason":"compiler-artifact"/{/"profile":{[^}]*"test":true/{s@.*"executable":"\([^"]*\)".*@\1@p;}}' /tmp/kind-dev-test.jsonl)" && \
      test -n "$test_binary" && test -x "$test_binary" && \
      install -D "$test_binary" "/out/tests/$KIND_DEV_TEST"; \
    fi && \
    if [ -n "$KIND_DEV_FIXTURE_FEATURES" ]; then \
      codewire-rust-build cargo test --locked --profile ci -p "$KIND_DEV_CRATE" \
        --features "$KIND_DEV_FIXTURE_FEATURES" --lib --no-run \
        --message-format=json >/tmp/kind-dev-fixture.jsonl && \
      fixture="$(sed -n '/"reason":"compiler-artifact"/{/"test":true/{s@.*"executable":"\([^"]*\)".*@\1@p;}}' /tmp/kind-dev-fixture.jsonl)" && \
      test -n "$fixture" && test -x "$fixture" && \
      install -D "$fixture" "/out/kind-fixtures/$bins"; \
    fi && \
    cp /tmp/kind-dev-sources.sha256 "$built"

FROM scratch
COPY --from=builder /out/ /
