# The two Linux cw release compilations on the trusted BuildKit builder
# (#3119). build-cw-linux.sh submits one export target per job through
# cw-release-linux.hcl and verifies what comes back.
#
# The main context is a credential-free clone of exactly the selected source
# commit, .git included: package-cw-release.sh binds the source with git, so
# cw-release-linux.Dockerfile.dockerignore admits everything and overrides the
# source's own .dockerignore. The named context workflow-scripts is the
# workflow ref's scripts/ tree, whose packaging script runs unchanged, as the
# in-job build runs it today. local-runtime is the packed local VM runtime, or
# an empty directory when the run packed none.
#
# Everything runs on linux/amd64: rustc, cargo and zig, which cross-links
# aarch64-unknown-linux-gnu exactly as `cargo zigbuild` does in a job. No
# stage executes an arm64 binary, so nothing here needs emulation.

FROM codewire-rust-base AS cw-release-tools
ARG ZIG_VERSION
ARG ZIG_X86_64_LINUX_SHA256
ARG CARGO_ZIGBUILD_VERSION
ARG TOOLS_CARGO_BUILD_JOBS
# rust-base carries Rust 1.99.1 and protoc 35.1 at their pins. The release
# targets and the components rust-toolchain.toml names are installed here, so
# no build ever reaches rustup's network.
RUN set -eu; \
    test -n "$ZIG_VERSION" && test -n "$ZIG_X86_64_LINUX_SHA256" && test -n "$CARGO_ZIGBUILD_VERSION"; \
    rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-gnu; \
    rustup component add clippy rustfmt; \
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
      --retry 5 --retry-all-errors --connect-timeout 20 \
      --output /tmp/zig.tar.xz "https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz"; \
    echo "${ZIG_X86_64_LINUX_SHA256}  /tmp/zig.tar.xz" | sha256sum -c -; \
    tar -xJf /tmp/zig.tar.xz -C /opt; \
    mv "/opt/zig-x86_64-linux-${ZIG_VERSION}" /opt/zig; \
    rm /tmp/zig.tar.xz; \
    cargo install --locked --root /opt/cargo-zigbuild ${TOOLS_CARGO_BUILD_JOBS:+--jobs "$TOOLS_CARGO_BUILD_JOBS"} \
      cargo-zigbuild --version "$CARGO_ZIGBUILD_VERSION"; \
    rm -rf /usr/local/cargo/registry; \
    test "$(/opt/zig/zig version)" = "$ZIG_VERSION"; \
    test "$(/opt/cargo-zigbuild/bin/cargo-zigbuild --version)" = "cargo-zigbuild $CARGO_ZIGBUILD_VERSION"; \
    test "$(rustup target list --installed | LC_ALL=C sort | tr '\n' ' ')" = \
      'aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu x86_64-unknown-linux-musl '
ENV PATH="/opt/zig:/opt/cargo-zigbuild/bin:${PATH}"

FROM cw-release-tools AS cw-release-source
COPY . /src

FROM cw-release-source AS cw-release-build-x86_64-unknown-linux-musl
ARG CW_RELEASE_VERSION
ARG CW_RELEASE_SOURCE_SHA
ARG CW_RELEASE_TAG_OBJECT_SHA
ARG CW_RELEASE_HAS_RUNTIME
ARG CW_RELEASE_TARGET_CACHE
ARG CARGO_BUILD_JOBS
ARG CARGO_HTTP_TIMEOUT=20
ARG CARGO_NET_RETRY=5
ENV CW_RELEASE_TARGET=x86_64-unknown-linux-musl
RUN --mount=type=bind,from=workflow-scripts,target=/workflow/scripts \
    --mount=type=bind,from=local-runtime,target=/local-runtime \
    --mount=type=cache,id=cw-release-cargo-registry-x86_64-unknown-linux-musl,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cw-release-cargo-git-x86_64-unknown-linux-musl,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=cw-release-target-x86_64-unknown-linux-musl,target=/cargo-target,sharing=locked \
    /workflow/scripts/ci/release/cw-release-linux-build.sh

FROM cw-release-source AS cw-release-build-aarch64-unknown-linux-gnu
ARG CW_RELEASE_VERSION
ARG CW_RELEASE_SOURCE_SHA
ARG CW_RELEASE_TAG_OBJECT_SHA
ARG CW_RELEASE_HAS_RUNTIME
ARG CW_RELEASE_TARGET_CACHE
ARG CARGO_BUILD_JOBS
ARG CARGO_HTTP_TIMEOUT=20
ARG CARGO_NET_RETRY=5
ENV CW_RELEASE_TARGET=aarch64-unknown-linux-gnu
RUN --mount=type=bind,from=workflow-scripts,target=/workflow/scripts \
    --mount=type=bind,from=local-runtime,target=/local-runtime \
    --mount=type=cache,id=cw-release-cargo-registry-aarch64-unknown-linux-gnu,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cw-release-cargo-git-aarch64-unknown-linux-gnu,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=cw-release-target-aarch64-unknown-linux-gnu,target=/cargo-target,sharing=locked \
    /workflow/scripts/ci/release/cw-release-linux-build.sh

# Each target has its own locked Cargo registry, git and target caches, and the
# two stages share no cache, so the two cw compiles run side by side. At 8 Cargo
# jobs with thin LTO they peaked at 8.47 GiB together in dry run 18591; at the
# 16 build-cw-linux.sh now passes, and with one image step beside them, they
# fit the builder's 29 GiB guest (owner, 2026-10-22, infra#1594; #3144).

# The export targets: the executable, its SHA-256 line and the admission line
# package-cw-release.sh printed for it, nothing else.
FROM scratch AS cw-x86_64-unknown-linux-musl
COPY --from=cw-release-build-x86_64-unknown-linux-musl /out/ /

FROM scratch AS cw-aarch64-unknown-linux-gnu
COPY --from=cw-release-build-aarch64-unknown-linux-gnu /out/ /
