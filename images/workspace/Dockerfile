# syntax=docker/dockerfile:1.7
# Codewire developer workspace. The production workflow and local verifier must
# supply the exact base image built from the same source tree.
ARG BASE_IMAGE_REF

FROM rust:1.91.1-slim-bookworm@sha256:8514999d4786ef12efe89239e86b3d0a021b94b9d35108c8efe6c79ca7dc1a65 AS cw-builder
COPY images/workspace/debian.sources /etc/apt/sources.list.d/debian.sources
COPY images/base/apt-transport.conf /etc/apt/apt.conf.d/80-codewire-transport
COPY --chmod=0755 images/base/apt-get-with-retry /usr/local/sbin/apt-get-with-retry
RUN rm -f /etc/apt/sources.list && \
    apt-get-with-retry update && \
    grep -RqsF 'snapshot.debian.org/archive/debian/20251208T000000Z/' /etc/apt/sources.list.d && \
    ! grep -RqsE '(deb|security)\.debian\.org' /etc/apt/sources.list /etc/apt/sources.list.d && \
    apt-get-with-retry install -y --no-install-recommends libprotobuf-dev protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*
RUN rustup component add --toolchain 1.91.1-x86_64-unknown-linux-gnu rustfmt clippy

# The source tree stays read-only and is never copied into an image layer. Cargo
# owns normal/build dependency closure; only the resulting cw binary crosses
# into the final stage.
RUN --mount=type=bind,target=/src,readonly \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --manifest-path /src/Cargo.toml --locked --release \
      -p codewire-cli-bin --bin cw --target-dir /tmp/cargo-target && \
    install -D -m 0755 /tmp/cargo-target/release/cw /out/cw

FROM ${BASE_IMAGE_REF}
USER root
ARG TARGETARCH
ARG NODE_VERSION=22.23.2
ARG GO_VERSION=1.26.6

# Node and Go are direct, checksum-verified upstream archives on both supported
# architectures. Unknown architectures fail closed.
RUN set -euo pipefail; \
    case "$TARGETARCH" in \
      amd64) \
        node_arch=x64; \
        node_sha=b294a556e639d64338823920e5866c21c02741742d2e1529ee1a225c1ec9252a; \
        go_sha=708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89 ;; \
      arm64) \
        node_arch=arm64; \
        node_sha=013b59cfd2819703a6f4a14ab891fc46fc2a4e3f5bcd92de3fb4929b43e35b30; \
        go_sha=d0507e9e9d7fe012aae570108cbd76c15de879e17130ab8cb90d4d7445cb1f2e ;; \
      *) echo "unsupported workspace image architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -fsSL \
      "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.gz" \
      -o /tmp/node.tgz; \
    echo "${node_sha}  /tmp/node.tgz" | sha256sum -c -; \
    tar -xzf /tmp/node.tgz -C /usr/local --strip-components=1; \
    curl --proto '=https' --tlsv1.2 -fsSL \
      "https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz" -o /tmp/go.tgz; \
    echo "${go_sha}  /tmp/go.tgz" | sha256sum -c -; \
    tar -xzf /tmp/go.tgz -C /usr/local; \
    rm -f /tmp/node.tgz /tmp/go.tgz; \
    node --version; npm --version; /usr/local/go/bin/go version

ENV PATH="/usr/local/go/bin:/home/codewire/go/bin:${PATH}"
ENV GOPATH="/home/codewire/go"

# Moving convenience channels intentionally resolve at image-build time. Their
# result remains visible to the SBOM and is identified by the immutable output
# image digest.
RUN npm install -g --ignore-scripts npm@latest pnpm yarn && \
    npm cache clean --force && \
    curl --proto '=https' --tlsv1.2 -fsSL https://bun.sh/install | bash && \
    install -m 0755 /root/.bun/bin/bun /usr/local/bin/bun && \
    ln -s bun /usr/local/bin/bunx && \
    rm -rf /root/.bun

RUN apt-get-with-retry update && apt-get-with-retry install -y --no-install-recommends \
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
# npm prefix and the sole admitted lifecycle-script package.
ENV NPM_CONFIG_PREFIX="/home/codewire/.npm-global"
ENV NPM_CONFIG_ALLOW_SCRIPTS="@anthropic-ai/claude-code"
ENV PATH="/home/codewire/.npm-global/bin:/home/codewire/.local/bin:/opt/codewire/agents/npm/bin:/opt/codewire/agents/bin:${CARGO_HOME}/bin:${PATH}"

RUN go install golang.org/x/tools/gopls@latest && \
    go install github.com/hetznercloud/cli/cmd/hcloud@latest && \
    pipx install poetry && \
    pipx install uv && \
    PIPX_HOME=/opt/codewire/agents/pipx PIPX_BIN_DIR=/opt/codewire/agents/bin pipx install aider-chat

# Seed coding agents from the exact versions accepted by the workspace image
# contract, outside the persistent home mount. Interactive users can install
# newer versions into their own prefix without sudo; PATH gives those versions
# precedence. No startup installer or image-home copy is needed.
# Lifecycle scripts stay disabled except for Claude's official package, whose
# native binary is installed by its required postinstall hook.
RUN npm install --prefix /opt/codewire/agents/npm -g --ignore-scripts \
      @openai/codex@0.149.0 \
      @google/gemini-cli@0.56.0 \
      @moonshot-ai/kimi-code@0.38.0 \
      @earendil-works/pi-coding-agent@0.84.2 && \
    npm install --prefix /opt/codewire/agents/npm -g @anthropic-ai/claude-code@2.1.238

# Reuse the exact toolchain and explicitly selected components from the
# digest-pinned Rust build stage. This removes a second mutable installer
# transaction and keeps the interactive user's Cargo and Rustup homes writable
# for normal development.
COPY --from=cw-builder --chown=codewire:codewire /usr/local/cargo/ /home/codewire/.cargo/
COPY --from=cw-builder --chown=codewire:codewire /usr/local/rustup/ /home/codewire/.rustup/
RUN cargo --version && rustc --version && rustfmt --version && cargo clippy --version

# Keep the source-built CLI after the moving developer tools. A cw-only source
# change then reuses those expensive layers while the final image still proves
# and exposes the exact binary built from this source tree.
USER root
COPY --from=cw-builder /out/cw /usr/local/bin/cw
RUN /usr/local/bin/cw --version

USER codewire
