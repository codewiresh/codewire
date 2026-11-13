# Codewire developer workspace. The production workflow and local verifier must
# supply the exact base image built from the same source tree.
ARG BASE_IMAGE_REF

# The developer Rust toolchain shipped in the workspace, for the image's own
# platform. The workspace copies only its Cargo and Rustup homes.
FROM rust:1.99.1-slim-bookworm@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd AS cw-toolchain
RUN rustup component add --toolchain 1.99.1 rustfmt clippy

# Checksum-pinned compiler tools, selected for the build platform. Only protoc
# also enters the workspace, unpacked for the image's own platform.
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

# Infrastructure clients are image-owned binaries, outside the persistent home.
FROM scratch AS kubectl-amd64
ADD --checksum=sha256:cfda68cba5848bc3b6c6135ae2f20ba2c78de20059f68789c090166d6abc3e2c \
  https://dl.k8s.io/release/v1.34.0/bin/linux/amd64/kubectl /kubectl
FROM scratch AS kubectl-arm64
ADD --checksum=sha256:00b182d103a8a73da7a4d11e7526d0543dcf352f06cc63a1fde25ce9243f49a0 \
  https://dl.k8s.io/release/v1.34.0/bin/linux/arm64/kubectl /kubectl
FROM scratch AS atmos-amd64
ADD --checksum=sha256:46be9914a4a6af1c3a680b11231a4b1a5bc512f4bf6f9acaf050c3f4e44ee5c9 \
  https://github.com/cloudposse/atmos/releases/download/v1.233.2/atmos_1.233.2_linux_amd64 /atmos
FROM scratch AS atmos-arm64
ADD --checksum=sha256:765226c8f8be4b586a80842b2f4c3f4cddd3b7932c9172a857a85f1b4fd01db8 \
  https://github.com/cloudposse/atmos/releases/download/v1.233.2/atmos_1.233.2_linux_arm64 /atmos
FROM kubectl-${TARGETARCH} AS workspace-kubectl
FROM atmos-${TARGETARCH} AS workspace-atmos

FROM sccache-${BUILDARCH} AS build-sccache
FROM protoc-${BUILDARCH} AS build-protoc
FROM zig-${BUILDARCH} AS build-zig

# The arm64 cw is cross-compiled natively on the build platform, never under
# emulation, to the same static musl form as the admitted amd64 asset.
FROM --platform=$BUILDPLATFORM rust:1.99.1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS cw-cross-compiler
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
    grep -RqsF 'snapshot.debian.org/archive/debian/20261015T000000Z/' /etc/apt/sources.list.d && \
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
RUN test "$(rustc --version)" = 'rustc 1.99.1 (58cf8f9c3 2026-10-13)' && \
    rustup target add --toolchain 1.99.1 aarch64-unknown-linux-musl && \
    cargo install --locked cargo-zigbuild --version 0.23.0 && \
    test "$(cargo-zigbuild --version)" = 'cargo-zigbuild 0.23.0'
COPY --chmod=0755 scripts/ci/images/run-rust-build.sh /usr/local/bin/codewire-rust-build

# The moving Go developer tools build on the build platform: Go cross-compiles
# for the image's architecture natively, so the arm64 image never compiles
# them under emulation. They still resolve @latest at image-build time (every
# builder bypasses this stage's cache, like workspace-floating-tools), and the
# build information Go embeds in each binary keeps them visible to the SBOM.
FROM --platform=$BUILDPLATFORM rust:1.99.1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS workspace-floating-go
SHELL ["/bin/bash", "-c"]
ARG BUILDARCH
ARG TARGETARCH
# The same checksum-verified Go archive workspace-foundation installs. Go
# installs a cross-compiled binary below bin/<goos>_<goarch>.
ARG GO_VERSION=1.27.4
RUN set -euo pipefail; \
    case "$BUILDARCH" in \
      amd64) go_sha=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840 ;; \
      arm64) go_sha=3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92 ;; \
      *) echo "unsupported build architecture: $BUILDARCH" >&2; exit 1 ;; \
    esac; \
    case "$TARGETARCH" in \
      amd64|arm64) ;; \
      *) echo "unsupported workspace image architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -fsSL --retry 5 --retry-connrefused \
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
ARG CODEWIRE_RUST_PROFILE=runtime
# Cargo's job count, set on the trusted BuildKit builder to fit its memory
# (scripts/ci/setup/trusted-buildkit.sh); empty means Cargo's default.
ARG CARGO_BUILD_JOBS
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
    grep -RqsF 'snapshot.ubuntu.com/ubuntu/20261015T000000Z/' /etc/apt/sources.list.d; \
    ! grep -RqsE '(archive|security|ports)\.ubuntu\.com' /etc/apt/sources.list /etc/apt/sources.list.d; \
    apt-get-with-retry -o APT::Update::Error-Mode=any update; \
    install -d -m 0755 /packages /out; \
    cd /packages; \
    apt-get-with-retry download openssh-server=1:9.6p1-3ubuntu13.20 libwrap0=7.6.q-33; \
    rm -rf /var/lib/apt/lists/*; \
    packages=(*.deb); test "${#packages[@]}" = 2; \
    for package in "${packages[@]}"; do \
      identity="$(dpkg-deb --show --showformat='${Package} ${Version} ${Architecture}' "$package")"; \
      case "$identity" in \
        "openssh-server 1:9.6p1-3ubuntu13.20 $TARGETARCH"|"libwrap0 7.6.q-33 $TARGETARCH") ;; \
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
COPY --from=workspace-kubectl --chmod=0755 /kubectl /usr/local/bin/kubectl
COPY --from=workspace-atmos --chmod=0755 /atmos /usr/local/bin/atmos
RUN kubectl version --client && atmos version
ARG NODE_VERSION=22.23.4
ARG GO_VERSION=1.27.4

# Node and Go are direct, checksum-verified upstream archives on both supported
# architectures. Unknown architectures fail closed.
RUN set -euo pipefail; \
    case "$TARGETARCH" in \
      amd64) \
        node_arch=x64; \
        node_sha=b8492284c76a54baf58d61668dd0e41ee0fc98adabf9503d30f05d08f55b4406; \
        go_sha=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840 ;; \
      arm64) \
        node_arch=arm64; \
        node_sha=f7a1e486dbc8b286847815b477d4fb5e9fb963ed4489c3e1588853d685f589f9; \
        go_sha=3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92 ;; \
      *) echo "unsupported workspace image architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -fsSL --retry 5 --retry-connrefused \
      "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.gz" \
      -o /tmp/node.tgz; \
    echo "${node_sha}  /tmp/node.tgz" | sha256sum -c -; \
    tar --no-same-owner -xzf /tmp/node.tgz -C /usr/local --strip-components=1; \
    curl --proto '=https' --tlsv1.2 -fsSL --retry 5 --retry-connrefused \
      "https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz" -o /tmp/go.tgz; \
    echo "${go_sha}  /tmp/go.tgz" | sha256sum -c -; \
    tar --no-same-owner -xzf /tmp/go.tgz -C /usr/local; \
    rm -f /tmp/node.tgz /tmp/go.tgz; \
    node --version; npm --version; /usr/local/go/bin/go version

ENV PATH="/usr/local/go/bin:/home/codewire/go/bin:${PATH}"
ENV GOPATH="/home/codewire/go"

# Codex's Linux sandbox runs commands through the system bubblewrap on PATH;
# without it Codex warns at startup and falls back to its bundled copy.
# ncurses-term and kitty-terminfo are the terminfo entries of the terminals
# people connect from (alacritty, foot, wezterm, kitty and many more), so
# `clear`, vim and full-screen programs work over `cw shell` as over ssh;
# ncurses-base alone knows little beyond xterm, screen and tmux.
RUN --mount=type=secret,id=codewire-apt-mirror,required=false \
    apt-get-with-retry update && apt-get-with-retry install -y --no-install-recommends \
      bubblewrap=0.9.0-1ubuntu0.3 \
      file gdb kitty-terminfo ncurses-term pipx pkg-config python3-full python3-venv strace && \
    rm -rf /var/lib/apt/lists/*

# The protoc CI pins, for the image's own platform. Ubuntu's protobuf-compiler
# (3.21) cannot compile this repository's protos, which use debug_redact.
RUN --mount=type=bind,from=protoc-amd64,source=/protoc.zip,target=/tmp/protoc-amd64.zip \
    --mount=type=bind,from=protoc-arm64,source=/protoc.zip,target=/tmp/protoc-arm64.zip \
    unzip -q "/tmp/protoc-${TARGETARCH}.zip" -d /opt/protoc && \
    chmod -R a+rX /opt/protoc && \
    test "$(/opt/protoc/bin/protoc --version)" = 'libprotoc 35.1'
ENV PATH="/opt/protoc/bin:${PATH}" PROTOC=/opt/protoc/bin/protoc

RUN mkdir -p /home/codewire/go /home/codewire/.npm-global && \
    chown -R codewire:codewire /home/codewire/go /home/codewire/.npm-global

# Persistent storage covers the home, so keep the pinned Rust payload in the
# image. The binary/dispatcher are image-managed; normal Rustup toolchain and
# component commands can write the fallback store as codewire. User Rustup
# homes and explicitly selected stores remain authoritative.
COPY --from=cw-toolchain --chown=0:0 /usr/local/cargo/bin/ /opt/codewire/rust/cargo/bin/
COPY --from=cw-toolchain --chown=codewire:codewire /usr/local/rustup/ /opt/codewire/rust/rustup/
COPY --chown=0:0 --chmod=0755 images/workspace/rust/rustup /opt/codewire/rust/bin/rustup
RUN for proxy in /opt/codewire/rust/cargo/bin/*; do \
      name="${proxy##*/}"; \
      [ "$name" = rustup ] || ln -s rustup "/opt/codewire/rust/bin/$name"; \
    done && \
    chmod -R go-w /opt/codewire/rust/cargo /opt/codewire/rust/bin

USER codewire
ENV CARGO_HOME="/home/codewire/.cargo"
# User installations persist in the mounted home and take precedence over the
# shipped agents. Image configuration, not a hidden ~/.npmrc, selects their
# npm prefix. npm's install-script policy is left at its default, so project
# and user installs behave like stock npm; only the shipped agents' own install
# below runs under a strict allowlist. The upgrade commands of shipped agents
# that would update in place come next.
ENV NPM_CONFIG_PREFIX="/home/codewire/.npm-global"
ENV PATH="/home/codewire/.npm-global/bin:/home/codewire/.local/bin:/opt/codewire/agents/upgrade:/opt/codewire/agents/npm/bin:/opt/codewire/agents/bin:${CARGO_HOME}/bin:/opt/codewire/rust/bin:${PATH}"

RUN cargo --version && rustc --version && rustfmt --version && cargo clippy --version

# Every actual workspace builder bypasses this named stage. Floating developer
# tools refresh even when the compiler and foundation layers came from R2.
FROM workspace-foundation AS workspace-floating-tools
USER root
# Moving convenience channels intentionally resolve at image-build time. Their
# result remains visible to the SBOM and is identified by the immutable output
# image digest. The package managers are exact pins: npm also installs the
# shipped agents below. Bun is an exact, checksum-verified release: 1.4.4 fixes
# the Brotli decoder out-of-bounds write (CVE-2026-111497).
ARG TARGETARCH
ARG BUN_VERSION=1.4.4
RUN set -euo pipefail; \
    NPM_CONFIG_PREFIX=/usr/local npm install -g --ignore-scripts npm@12.2.0 pnpm@12.9.0 yarn@1.22.22; \
    npm cache clean --force; \
    case "$TARGETARCH" in \
      amd64) bun_arch=x64; bun_sha=bf8ccbfb2b0b80159e0f9a6d15c55317add8077534dbc6130a3edb52fccb395c ;; \
      arm64) bun_arch=aarch64; bun_sha=baa6bb36f51d6e58561e02bbea825038a9df454f673d6d776e8bbf86f8c7850e ;; \
      *) echo "unsupported workspace image architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -fsSL --retry 5 --retry-connrefused \
      "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/bun-linux-${bun_arch}.zip" \
      -o /tmp/bun.zip; \
    echo "${bun_sha}  /tmp/bun.zip" | sha256sum -c -; \
    unzip -q -j /tmp/bun.zip "bun-linux-${bun_arch}/bun" -d /tmp/bun; \
    install -m 0755 /tmp/bun/bun /usr/local/bin/bun; \
    ln -s bun /usr/local/bin/bunx; \
    rm -rf /tmp/bun.zip /tmp/bun; \
    test "$(bun --version)" = "$BUN_VERSION"

USER codewire
COPY --from=workspace-floating-go --chown=codewire:codewire /out/ /home/codewire/go/bin/
RUN gopls version && hcloud version && \
    pipx install poetry && \
    pipx install uv

# The shipped coding agents install in their own stage, as codewire, so npm's
# script allowlist and pipx run unprivileged. The workspace copies the result
# once, owned by root: a recursive chown in the image itself rewrote every
# agent file into a second layer (owner, 2026-11-12, #3013).
FROM workspace-floating-tools AS workspace-agents
USER root
RUN mkdir -p /opt/codewire/agents/npm/lib /opt/codewire/agents/npm/bin \
      /opt/codewire/agents/pipx /opt/codewire/agents/bin && \
    chown -R codewire:codewire /opt/codewire/agents
USER codewire
RUN PIPX_HOME=/opt/codewire/agents/pipx PIPX_BIN_DIR=/opt/codewire/agents/bin pipx install aider-chat
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
    cp /tmp/codewire-agents/package.json /tmp/codewire-agents/package-lock.json \
      /opt/codewire/agents/npm/lib/ && \
    cd /opt/codewire/agents/npm/lib && \
    env -u NPM_CONFIG_PREFIX \
      npm ci --strict-allow-scripts --no-audit --no-fund && \
    npm cache clean --force && \
    for agent in claude codex gemini kimi pi; do \
      ln -s "../lib/node_modules/.bin/$agent" "/opt/codewire/agents/npm/bin/$agent"; \
    done && \
    chmod -R go-w /opt/codewire/agents

FROM workspace-floating-tools AS workspace

# Claude Code fills the terminal, its input box on the bottom rows, as with
# `"tui": "fullscreen"` (#4332); its default draws inline below the output.
# The home is a persistent mount, so this lives in the image. The variable
# outranks Claude's own "tui" setting; `unset CLAUDE_CODE_NO_FLICKER` in a
# shell's rc file restores the inline renderer.
ENV CLAUDE_CODE_NO_FLICKER=1

USER root
# The home is a persistent mount, so interactive shell settings live in the image.
RUN printf '\n%s\nset +h\n' \
      '# Find commands on PATH every time, so an agent CLI updated in this shell runs at once.' \
      >>/etc/bash.bashrc
# The shipped agents are image content outside the persistent home. Keep them
# read-only, so no self-updater writes a copy that the next restart discards.
# Codex and Gemini update into the home's npm prefix themselves; pi, Kimi Code
# and aider reach the home through their upgrade wrappers, and Claude Code's
# wrapper installs its native, self-updating build in the home on first use.
COPY --from=workspace-agents --chown=0:0 /opt/codewire/agents/ /opt/codewire/agents/
COPY --chmod=0755 images/workspace/agent-upgrade/ /opt/codewire/agents/upgrade/
# A hosted Sandbox is Ready before its pod-local Docker daemon listens, so
# `docker` waits, bounded, for that socket and then runs the real CLI
# unchanged (Program #2238). Plugins are found in their usual directories.
RUN install -d -m 0755 /usr/local/libexec/codewire && \
    mv /usr/local/bin/docker /usr/local/libexec/codewire/docker
COPY --chown=0:0 --chmod=0755 images/workspace/docker-cli/docker /usr/local/bin/docker
RUN docker --version

# Keep the source-built CLI after the moving developer tools. The final image proves
# and exposes the exact binary built from this source tree.
COPY --from=stock-ssh-fixture /out/ /opt/codewire/fixtures/openssh/
COPY --from=cw-builder --chown=0:0 --chmod=0555 /out/cw /usr/local/bin/cw
COPY --from=cw-builder --chown=0:0 /out/provenance/ /usr/local/share/codewire/cw-runtime/
RUN /usr/local/bin/cw --version

USER codewire
