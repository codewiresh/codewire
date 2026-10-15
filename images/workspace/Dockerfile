# syntax=docker/dockerfile:1.7
# Codewire developer workspace. The production workflow and local verifier must
# supply the exact base image built from the same source tree.
ARG BASE_IMAGE_REF

# The developer Rust toolchain shipped in the workspace, for the image's own
# platform. The workspace copies only its Cargo and Rustup homes.
FROM rust:1.99.0-slim-bookworm@sha256:2c3a22f0a5533ea2dd5a16627bc841228151faa2d4de2644ac9987e4a2f1f2fa AS cw-toolchain
RUN rustup component add --toolchain 1.99.0 rustfmt clippy

# Checksum-pinned compiler tools, selected for the build platform. None of
# these archives enters the runtime.
FROM scratch AS sccache-amd64
ADD --checksum=sha256:67c4a96dd237c1f518f6b36083f270f9976d516f1e57fce891755ea782e50006 \
  https://github.com/mozilla/sccache/releases/download/v0.17.0/sccache-v0.17.0-x86_64-unknown-linux-musl.tar.gz /sccache.tar.gz
FROM scratch AS sccache-arm64
ADD --checksum=sha256:821a86343191aa1cbab74bd42f9e93c9a63bf85e4742945f40d3ae84193c1c77 \
  https://github.com/mozilla/sccache/releases/download/v0.17.0/sccache-v0.17.0-aarch64-unknown-linux-musl.tar.gz /sccache.tar.gz
FROM scratch AS protoc-amd64
ADD --checksum=sha256:6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7 \
  https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip /protoc.zip
FROM scratch AS protoc-arm64
ADD --checksum=sha256:01bf9d08808c7f96678b63f4bd8efa559bb4f83d5a7a270d5edaf507f9d5d9cf \
  https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-aarch_64.zip /protoc.zip
FROM scratch AS zig-amd64
ADD --checksum=sha256:02aa270f183da276e5b5920b1dac44a63f1a49e55050ebde3aecc9eb82f93239 \
  https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz /zig.tar.xz
FROM scratch AS zig-arm64
ADD --checksum=sha256:958ed7d1e00d0ea76590d27666efbf7a932281b3d7ba0c6b01b0ff26498f667f \
  https://ziglang.org/download/0.15.2/zig-aarch64-linux-0.15.2.tar.xz /zig.tar.xz
FROM sccache-${BUILDARCH} AS build-sccache
FROM protoc-${BUILDARCH} AS build-protoc
FROM zig-${BUILDARCH} AS build-zig

# The arm64 cw is cross-compiled natively on the build platform, never under
# emulation, to the same static musl form as the admitted amd64 asset.
FROM --platform=$BUILDPLATFORM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS cw-cross-compiler
COPY --from=build-protoc /protoc.zip /tmp/protoc.zip
COPY --from=build-sccache /sccache.tar.gz /tmp/sccache.tar.gz
COPY --from=build-zig /zig.tar.xz /tmp/zig.tar.xz
COPY images/workspace/debian.sources /etc/apt/sources.list.d/debian.sources
COPY images/base/apt-transport.conf /etc/apt/apt.conf.d/80-codewire-transport
COPY --chmod=0755 images/base/apt-get-with-retry /usr/local/sbin/apt-get-with-retry
# Every apt-get-with-retry RUN mounts the optional CI snapshot-cache secret and
# removes /var/lib/apt/lists, whose file names would carry the cache host.
RUN --mount=type=secret,id=codewire-apt-mirror,required=false \
    rm -f /etc/apt/sources.list && \
    apt-get-with-retry update && \
    grep -RqsF 'snapshot.debian.org/archive/debian/20251208T000000Z/' /etc/apt/sources.list.d && \
    ! grep -RqsE '(deb|security)\.debian\.org' /etc/apt/sources.list /etc/apt/sources.list.d && \
    apt-get-with-retry install -y --no-install-recommends unzip xz-utils && \
    rm -rf /var/lib/apt/lists/* && \
    unzip -q /tmp/protoc.zip -d /opt/protoc && \
    rm /tmp/protoc.zip && \
    test "$(/opt/protoc/bin/protoc --version)" = 'libprotoc 35.1' && \
    mkdir /tmp/sccache && \
    tar -xzf /tmp/sccache.tar.gz --strip-components=1 -C /tmp/sccache && \
    install -m 0755 /tmp/sccache/sccache /usr/local/bin/sccache && \
    rm -rf /tmp/sccache /tmp/sccache.tar.gz && \
    test "$(sccache --version)" = 'sccache 0.17.0' && \
    mkdir /opt/zig && \
    tar -xJf /tmp/zig.tar.xz --strip-components=1 -C /opt/zig && \
    rm /tmp/zig.tar.xz && \
    test "$(/opt/zig/zig version)" = '0.15.2'
ENV PROTOC=/opt/protoc/bin/protoc
ENV PATH="/opt/zig:${PATH}"
RUN test "$(rustc --version)" = 'rustc 1.99.0 (b940084d7 2026-09-28)' && \
    rustup target add --toolchain 1.99.0 aarch64-unknown-linux-musl && \
    cargo install --locked cargo-zigbuild --version 0.23.0 && \
    test "$(cargo-zigbuild --version)" = 'cargo-zigbuild 0.23.0'
COPY --chmod=0755 scripts/ci/images/run-rust-build.sh /usr/local/bin/codewire-rust-build

# The moving Go developer tools build on the build platform: Go cross-compiles
# for the image's architecture natively, so the arm64 image never compiles
# them under emulation. They still resolve @latest at image-build time (every
# builder bypasses this stage's cache, like workspace-floating-tools), and the
# build information Go embeds in each binary keeps them visible to the SBOM.
FROM --platform=$BUILDPLATFORM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS workspace-floating-go
SHELL ["/bin/bash", "-c"]
ARG BUILDARCH
ARG TARGETARCH
# The same checksum-verified Go archive workspace-foundation installs. Go
# installs a cross-compiled binary below bin/<goos>_<goarch>.
ARG GO_VERSION=1.26.9
RUN set -euo pipefail; \
    case "$BUILDARCH" in \
      amd64) go_sha=42d158b4d8f7b61ac0a830567c940a86098fb7aac52e467a5ebec03ef5cc2f8d ;; \
      arm64) go_sha=4a97373d49fcacdcf3694fea368a500b00ee3e963974f3e7514132717632f052 ;; \
      *) echo "unsupported build architecture: $BUILDARCH" >&2; exit 1 ;; \
    esac; \
    case "$TARGETARCH" in \
      amd64|arm64) ;; \
      *) echo "unsupported workspace image architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -fsSL \
      "https://go.dev/dl/go${GO_VERSION}.linux-${BUILDARCH}.tar.gz" -o /tmp/go.tgz; \
    echo "${go_sha}  /tmp/go.tgz" | sha256sum -c -; \
    tar --no-same-owner -xzf /tmp/go.tgz -C /usr/local; \
    rm -f /tmp/go.tgz; \
    export GOPATH=/tmp/gopath GOCACHE=/tmp/gocache GOOS=linux GOARCH="$TARGETARCH" CGO_ENABLED=0; \
    /usr/local/go/bin/go install golang.org/x/tools/gopls@latest; \
    /usr/local/go/bin/go install github.com/hetznercloud/cli/cmd/hcloud@latest; \
    binaries=/tmp/gopath/bin; \
    [ "$TARGETARCH" = "$BUILDARCH" ] || binaries="$binaries/linux_$TARGETARCH"; \
    install -D -m 0755 "$binaries/gopls" /out/gopls; \
    install -D -m 0755 "$binaries/hcloud" /out/hcloud; \
    rm -rf /tmp/gopath /tmp/gocache

FROM scratch AS codewire-verified-cw

FROM scratch AS cw-builder-amd64
COPY --from=codewire-verified-cw --chown=0:0 --chmod=0555 /cw /out/cw
COPY --from=codewire-verified-cw --chown=0:0 --chmod=0444 /provenance.json /out/provenance/provenance.json

# Only amd64 receives the separately admitted static startup asset and its
# provenance. arm64 cross-compiles the same static musl target from source.
FROM cw-cross-compiler AS cw-builder-arm64
ARG CODEWIRE_RUST_PROFILE=release
ARG CODEWIRE_SCCACHE_MODE=disabled
ARG SCCACHE_BUCKET
ARG SCCACHE_ENDPOINT
ARG CODEWIRE_SCCACHE_PREFIX

# The source tree stays read-only and is never copied into an image layer. Cargo
# owns normal/build dependency closure; only the resulting cw binary crosses
# into the final stage.
RUN --mount=type=bind,target=/src,readonly \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,id=codewire-workspace-sccache-v1,target=/var/cache/sccache,sharing=shared \
    --mount=type=secret,id=aws_shared_credentials \
    SCCACHE_BASEDIRS=/src codewire-rust-build cargo zigbuild --manifest-path /src/Cargo.toml --locked --profile "$CODEWIRE_RUST_PROFILE" \
      --target aarch64-unknown-linux-musl -p codewire-cli-bin --bin cw --target-dir /tmp/cargo-target && \
    mkdir -p /out/provenance && \
    install -D -m 0755 "/tmp/cargo-target/aarch64-unknown-linux-musl/$CODEWIRE_RUST_PROFILE/cw" /out/cw && \
    rm -rf /tmp/cargo-target

FROM cw-builder-${TARGETARCH} AS cw-builder

# Prepare the loopback SSH acceptance target once, at image-build time. Extract
# signed, version-pinned packages without executing maintainer scripts: this
# neither enables a system SSH service nor creates image-wide host keys.
FROM ${BASE_IMAGE_REF} AS stock-ssh-fixture
# OCI image configs do not carry the base SHELL; never inherit it.
SHELL ["/bin/bash", "-c"]
USER root
ARG TARGETARCH
RUN --mount=type=secret,id=codewire-apt-mirror,required=false \
    set -euo pipefail; \
    test "$(dpkg --print-architecture)" = "$TARGETARCH"; \
    grep -RqsF 'snapshot.ubuntu.com/ubuntu/20260803T000000Z/' /etc/apt/sources.list.d; \
    ! grep -RqsE '(archive|security|ports)\.ubuntu\.com' /etc/apt/sources.list /etc/apt/sources.list.d; \
    apt-get-with-retry -o APT::Update::Error-Mode=any update; \
    install -d -m 0755 /packages /out; \
    cd /packages; \
    apt-get-with-retry download openssh-server=1:9.6p1-3ubuntu13.18 libwrap0=7.6.q-33; \
    rm -rf /var/lib/apt/lists/*; \
    packages=(*.deb); test "${#packages[@]}" = 2; \
    for package in "${packages[@]}"; do \
      identity="$(dpkg-deb --show --showformat='${Package} ${Version} ${Architecture}' "$package")"; \
      case "$identity" in \
        "openssh-server 1:9.6p1-3ubuntu13.18 $TARGETARCH"|"libwrap0 7.6.q-33 $TARGETARCH") ;; \
        *) echo 'unexpected SSH fixture package identity' >&2; exit 1 ;; \
      esac; \
      dpkg-deb --extract "$package" /out; \
    done; \
    test -x /out/usr/sbin/sshd; \
    host_keys="$(find /out -name 'ssh_host_*' -print -quit)"; test -z "$host_keys"; \
    chown -R root:root /out; chmod -R go-w /out

FROM ${BASE_IMAGE_REF} AS workspace-foundation
# OCI image configs do not carry the base SHELL; never inherit it.
SHELL ["/bin/bash", "-c"]
USER root
ARG TARGETARCH
ARG NODE_VERSION=22.23.2
ARG GO_VERSION=1.26.9

# Node and Go are direct, checksum-verified upstream archives on both supported
# architectures. Unknown architectures fail closed.
RUN set -euo pipefail; \
    case "$TARGETARCH" in \
      amd64) \
        node_arch=x64; \
        node_sha=b294a556e639d64338823920e5866c21c02741742d2e1529ee1a225c1ec9252a; \
        go_sha=42d158b4d8f7b61ac0a830567c940a86098fb7aac52e467a5ebec03ef5cc2f8d ;; \
      arm64) \
        node_arch=arm64; \
        node_sha=013b59cfd2819703a6f4a14ab891fc46fc2a4e3f5bcd92de3fb4929b43e35b30; \
        go_sha=4a97373d49fcacdcf3694fea368a500b00ee3e963974f3e7514132717632f052 ;; \
      *) echo "unsupported workspace image architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -fsSL \
      "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.gz" \
      -o /tmp/node.tgz; \
    echo "${node_sha}  /tmp/node.tgz" | sha256sum -c -; \
    tar --no-same-owner -xzf /tmp/node.tgz -C /usr/local --strip-components=1; \
    curl --proto '=https' --tlsv1.2 -fsSL \
      "https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz" -o /tmp/go.tgz; \
    echo "${go_sha}  /tmp/go.tgz" | sha256sum -c -; \
    tar --no-same-owner -xzf /tmp/go.tgz -C /usr/local; \
    rm -f /tmp/node.tgz /tmp/go.tgz; \
    node --version; npm --version; /usr/local/go/bin/go version

ENV PATH="/usr/local/go/bin:/home/codewire/go/bin:${PATH}"
ENV GOPATH="/home/codewire/go"

# Codex's Linux sandbox runs commands through the system bubblewrap on PATH;
# without it Codex warns at startup and falls back to its bundled copy.
RUN --mount=type=secret,id=codewire-apt-mirror,required=false \
    apt-get-with-retry update && apt-get-with-retry install -y --no-install-recommends \
      bubblewrap=0.9.0-1ubuntu0.1 \
      file gdb pipx pkg-config protobuf-compiler python3-full python3-venv strace && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /home/codewire/go /home/codewire/.npm-global \
      /opt/codewire/agents/npm /opt/codewire/agents/pipx /opt/codewire/agents/bin && \
    chown -R codewire:codewire /home/codewire/go /home/codewire/.npm-global /opt/codewire/agents

USER codewire
ENV CARGO_HOME="/home/codewire/.cargo"
ENV RUSTUP_HOME="/home/codewire/.rustup"
# User installations persist in the mounted home and take precedence over the
# shipped agents. Image configuration, not a hidden ~/.npmrc, selects their
# npm prefix and the sole admitted lifecycle-script package. The upgrade
# commands of shipped agents that would update in place come next.
ENV NPM_CONFIG_PREFIX="/home/codewire/.npm-global"
ENV NPM_CONFIG_ALLOW_SCRIPTS="@anthropic-ai/claude-code"
ENV PATH="/home/codewire/.npm-global/bin:/home/codewire/.local/bin:/opt/codewire/agents/upgrade:/opt/codewire/agents/npm/bin:/opt/codewire/agents/bin:${CARGO_HOME}/bin:${PATH}"

# Reuse the exact toolchain and explicitly selected components from the
# digest-pinned Rust build stage. This removes a second mutable installer
# transaction and keeps the interactive user's Cargo and Rustup homes writable
# for normal development.
COPY --from=cw-toolchain --chown=codewire:codewire /usr/local/cargo/ /home/codewire/.cargo/
COPY --from=cw-toolchain --chown=codewire:codewire /usr/local/rustup/ /home/codewire/.rustup/
RUN cargo --version && rustc --version && rustfmt --version && cargo clippy --version

# Every actual workspace builder bypasses this named stage. Floating developer
# tools refresh even when the compiler and foundation layers came from R2.
FROM workspace-foundation AS workspace-floating-tools
USER root
# Moving convenience channels intentionally resolve at image-build time. Their
# result remains visible to the SBOM and is identified by the immutable output
# image digest. The package managers are exact pins: npm also installs the
# shipped agents below.
RUN NPM_CONFIG_PREFIX=/usr/local npm install -g --ignore-scripts npm@12.2.0 pnpm@12.9.0 yarn@1.22.22 && \
    npm cache clean --force && \
    curl --proto '=https' --tlsv1.2 -fsSL https://bun.sh/install | bash && \
    install -m 0755 /root/.bun/bin/bun /usr/local/bin/bun && \
    ln -s bun /usr/local/bin/bunx && \
    rm -rf /root/.bun

USER codewire
COPY --from=workspace-floating-go --chown=codewire:codewire /out/ /home/codewire/go/bin/
RUN gopls version && hcloud version && \
    pipx install poetry && \
    pipx install uv && \
    PIPX_HOME=/opt/codewire/agents/pipx PIPX_BIN_DIR=/opt/codewire/agents/bin pipx install aider-chat

FROM workspace-floating-tools AS workspace
# Seed coding agents from the exact versions accepted by the workspace image
# contract, outside the persistent home mount. Interactive users can install
# newer versions into their own prefix without sudo; PATH gives those versions
# precedence. No startup installer or image-home copy is needed.
# npm ci installs the reviewed lockfile, every transitive version included, in
# the layout of a global install. Its allowScripts policy runs only the
# postinstall of Claude's official package, which places its native binary,
# and fails on any other unreviewed lifecycle script. The user's global npm
# configuration does not apply to this project install. Only the agents'
# own commands are linked.
RUN --mount=type=bind,source=images/workspace/agents,target=/tmp/codewire-agents,readonly \
    mkdir -p /opt/codewire/agents/npm/lib /opt/codewire/agents/npm/bin && \
    cp /tmp/codewire-agents/package.json /tmp/codewire-agents/package-lock.json \
      /opt/codewire/agents/npm/lib/ && \
    cd /opt/codewire/agents/npm/lib && \
    env -u NPM_CONFIG_ALLOW_SCRIPTS -u NPM_CONFIG_PREFIX \
      npm ci --strict-allow-scripts --no-audit --no-fund && \
    npm cache clean --force && \
    for agent in claude codex gemini kimi pi; do \
      ln -s "../lib/node_modules/.bin/$agent" "/opt/codewire/agents/npm/bin/$agent"; \
    done

USER root
# The home is a persistent mount, so interactive shell settings live in the image.
RUN printf '\n%s\nset +h\n' \
      '# Find commands on PATH every time, so an agent CLI updated in this shell runs at once.' \
      >>/etc/bash.bashrc
# The shipped agents are image content outside the persistent home. Keep them
# read-only, so no self-updater writes a copy that the next restart discards.
# Codex, Claude and Gemini update into the home's npm prefix themselves; pi,
# Kimi Code and aider reach the home through their upgrade wrappers.
COPY --chmod=0755 images/workspace/agent-upgrade/ /opt/codewire/agents/upgrade/
RUN chown -R -h root:root /opt/codewire/agents && chmod -R go-w /opt/codewire/agents

# Keep the source-built CLI after the moving developer tools. The final image proves
# and exposes the exact binary built from this source tree.
COPY --from=stock-ssh-fixture /out/ /opt/codewire/fixtures/openssh/
COPY --from=cw-builder --chown=0:0 --chmod=0555 /out/cw /usr/local/bin/cw
COPY --from=cw-builder --chown=0:0 /out/provenance/ /usr/local/share/codewire/cw-runtime/
RUN /usr/local/bin/cw --version

USER codewire
