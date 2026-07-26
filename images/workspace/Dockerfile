# codewire workspace image — the rootfs that runs inside every sandbox pod.
#
# Build context: the codewire repo root.
#   docker build -t codewire-workspace:local -f images/workspace/Dockerfile .
#
# The Gitea support-image workflow overrides this with the base digest built
# from the same canonical source revision. The public default keeps standalone
# OSS builds immutable while that workflow is being established.
ARG BASE_IMAGE_REF=ghcr.io/codewiresh/base@sha256:04eeaa84ac61ebf06a63f6baa6bc2c275d6b4055ef1d624885e4a639dfd2d1e2

FROM rust:1.91-bookworm AS cw-builder
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends \
      libprotobuf-dev protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
COPY libs/gateway-proto ./libs/gateway-proto
RUN cargo build --locked --release -p codewire-cli-bin --bin cw

FROM ${BASE_IMAGE_REF}
USER root
ARG GO_VERSION=1.26.3

# Go
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xzf -
ENV PATH="/usr/local/go/bin:/home/codewire/go/bin:${PATH}"
ENV GOPATH="/home/codewire/go"

# Node 22 + bun + pnpm + yarn (npm globals as root for system-wide tooling;
# the agent CLIs go under USER codewire below into ~/.npm-global so they can
# self-update at runtime without sudo).
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs && rm -rf /var/lib/apt/lists/*
RUN npm install -g pnpm yarn && \
    curl -fsSL https://bun.sh/install | bash && mv /root/.bun/bin/bun /usr/local/bin/

# Python (with venv/pipx, plus a few debug tools)
RUN apt-get update && apt-get install -y python3-full python3-venv pipx strace gdb file && \
    rm -rf /var/lib/apt/lists/*

# Rust build deps (pkg-config for crates needing system libs; protobuf-compiler
# for crates that build .proto via prost-build).
RUN apt-get update && apt-get install -y pkg-config protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

# hcloud CLI (latest stable GitHub release for linux-amd64)
RUN curl -fsSL https://api.github.com/repos/hetznercloud/cli/releases/latest -o /tmp/hcloud-release.json && \
    hcloud_url=$(jq -r ".assets[] | select(.browser_download_url | test(\"linux-amd64.tar.gz$\")) | .browser_download_url" /tmp/hcloud-release.json | head -n 1) && \
    curl -fsSL "${hcloud_url}" -o /tmp/hcloud.tar.gz && \
    tar -xzf /tmp/hcloud.tar.gz -C /tmp/ hcloud && \
    install -m 0755 /tmp/hcloud /usr/local/bin/hcloud && \
    rm -f /tmp/hcloud-release.json /tmp/hcloud.tar.gz /tmp/hcloud

# Infisical CLI (upstream apt repo)
RUN curl -1sLf 'https://artifacts-cli.infisical.com/setup.deb.sh' | bash && \
    apt-get install -y infisical && rm -rf /var/lib/apt/lists/*

COPY --from=cw-builder /src/target/release/cw /usr/local/bin/cw
RUN /usr/local/bin/cw --version && \
    ln -s cw /usr/local/bin/daemon && \
    ln -s cw /usr/local/bin/codewire-daemon && \
    mkdir -p /home/codewire/go && chown -R codewire:codewire /home/codewire/go

USER codewire
RUN curl -fsSL https://claude.ai/install.sh | bash && \
    go install golang.org/x/tools/gopls@latest && \
    pipx install poetry && pipx install uv

# Agent CLIs (codex, pi-coding-agent) installed as `codewire` user into a
# user-owned npm prefix so they can self-update at runtime without sudo.
# This is the original "permission denied" rabbit hole — installing globally
# as root puts them at /usr/lib/node_modules/@openai/codex with /usr/bin/codex
# as a root-owned symlink, and codex's startup self-update fails EACCES.
RUN mkdir -p /home/codewire/.npm-global && \
    npm config set prefix /home/codewire/.npm-global && \
    npm install -g @openai/codex @mariozechner/pi-coding-agent

# Rust toolchain (stable). Installed as the codewire user so CARGO_HOME and
# RUSTUP_HOME live under $HOME and per-user invariants stay clean.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --no-modify-path

USER root
RUN cp "$(readlink -f /home/codewire/.local/bin/claude)" /usr/local/bin/claude && \
    chmod 0755 /usr/local/bin/claude

USER codewire
ENV PATH="/home/codewire/.npm-global/bin:/home/codewire/.cargo/bin:/home/codewire/.local/bin:${PATH}"
