# syntax=docker/dockerfile:1.7
# Codewire developer workspace. The production workflow and local verifier must
# supply the exact base image built from the same source tree.
ARG BASE_IMAGE_REF

FROM rust:1.91.1-slim-bookworm@sha256:8514999d4786ef12efe89239e86b3d0a021b94b9d35108c8efe6c79ca7dc1a65 AS cw-builder
COPY images/workspace/debian.sources /etc/apt/sources.list.d/debian.sources
RUN rm -f /etc/apt/sources.list && \
    apt-get update && \
    grep -RqsF 'snapshot.debian.org/archive/debian/20251208T000000Z/' /etc/apt/sources.list.d && \
    ! grep -RqsE '(deb|security)\.debian\.org' /etc/apt/sources.list /etc/apt/sources.list.d && \
    apt-get install -y --no-install-recommends libprotobuf-dev protobuf-compiler && \
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
ARG GO_VERSION=1.26.5

# Node and Go are direct, checksum-verified upstream archives on both supported
# architectures. Unknown architectures fail closed.
RUN set -euo pipefail; \
    case "$TARGETARCH" in \
      amd64) \
        node_arch=x64; \
        node_sha=b294a556e639d64338823920e5866c21c02741742d2e1529ee1a225c1ec9252a; \
        go_sha=5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053 ;; \
      arm64) \
        node_arch=arm64; \
        node_sha=013b59cfd2819703a6f4a14ab891fc46fc2a4e3f5bcd92de3fb4929b43e35b30; \
        go_sha=fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49 ;; \
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

RUN apt-get update && apt-get install -y --no-install-recommends \
      file gdb pipx pkg-config protobuf-compiler python3-full python3-venv strace && \
    rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -1sLf https://artifacts-cli.infisical.com/setup.deb.sh | bash && \
    apt-get install -y --no-install-recommends infisical && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /home/codewire/go /home/codewire/.npm-global && \
    chown -R codewire:codewire /home/codewire/go /home/codewire/.npm-global

USER codewire
ENV CARGO_HOME="/home/codewire/.cargo"
ENV RUSTUP_HOME="/home/codewire/.rustup"
ENV PATH="/home/codewire/.npm-global/bin:${CARGO_HOME}/bin:/home/codewire/.local/bin:${PATH}"

RUN go install golang.org/x/tools/gopls@latest && \
    go install github.com/hetznercloud/cli/cmd/hcloud@latest && \
    pipx install poetry && \
    pipx install uv && \
    pipx install aider-chat

# Coding agents are deliberately current rather than version-pinned. They are
# installed into the interactive user prefix, remain scan-visible, and can be
# updated without sudo. Lifecycle scripts stay disabled except for Claude's
# official package, whose native binary is installed by its required
# postinstall hook.
RUN npm config set prefix /home/codewire/.npm-global && \
    npm config set allow-scripts=@anthropic-ai/claude-code --location=user && \
    npm install -g --ignore-scripts \
      @openai/codex \
      @google/gemini-cli \
      @moonshot-ai/kimi-code \
      @earendil-works/pi-coding-agent && \
    npm install -g @anthropic-ai/claude-code

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
RUN /usr/local/bin/cw --version && \
    ln -s cw /usr/local/bin/daemon && \
    ln -s cw /usr/local/bin/codewire-daemon

USER codewire
