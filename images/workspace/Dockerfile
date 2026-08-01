# codewire workspace image — the rootfs that runs inside every sandbox pod.
#
# Build context: the codewire repo root.
#   docker build -t codewire-workspace:local -f images/workspace/Dockerfile .
#
# The Gitea support-image workflow overrides this with the base digest built
# from the same canonical source revision. The public default keeps standalone
# OSS builds immutable while that workflow is being established.
ARG BASE_IMAGE_REF=ghcr.io/codewiresh/base@sha256:96f70ee3cedb863d0d5b96f5c1c7b6c3800c1bb4212aa868b73b2f3ed10f8ea8
ARG AIDER_VERSION=0.16.0

# Aider 0.16.0 pins NumPy 1.24, whose wheels support Python through 3.11.
# Keep that runtime isolated and pinned so the canonical Noble base can retain
# its system Python 3.12 for general workspace use.
FROM python:3.11-slim-bookworm@sha256:b18992999dbe963a45a8a4da40ac2b1975be1a776d939d098c647482bcad5cba AS aider-builder
ARG AIDER_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && \
    rm -rf /var/lib/apt/lists/*
RUN python -m venv --copies /opt/aider && \
    /opt/aider/bin/pip install --no-cache-dir "aider-chat==${AIDER_VERSION}"

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
ARG CODEX_VERSION=0.146.0
ARG CLAUDE_CODE_VERSION=2.1.220
ARG GEMINI_CLI_VERSION=0.53.1
ARG KIMI_CODE_VERSION=0.31.1
ARG PI_VERSION=0.73.1

COPY --from=aider-builder --chown=codewire:codewire \
    /usr/local/lib/libpython3.11.so.1.0 /usr/local/lib/libpython3.11.so.1.0
COPY --from=aider-builder /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=aider-builder --chown=codewire:codewire /opt/aider /opt/aider
RUN ldconfig

# Go
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xzf -
ENV PATH="/usr/local/go/bin:/home/codewire/go/bin:${PATH}"
ENV GOPATH="/home/codewire/go"

# Node 22 + bun + pnpm + yarn (npm globals as root for system-wide tooling;
# the agent CLIs go under USER codewire below into ~/.npm-global so they can
# self-update at runtime without sudo).
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs && rm -rf /var/lib/apt/lists/* && \
    node -e 'const [major, minor] = process.versions.node.split(".").map(Number); if (major < 22 || (major === 22 && minor < 19)) { throw new Error(`Node ${process.versions.node} is too old for Kimi Code`); }'
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
ENV PATH="/home/codewire/.npm-global/bin:/opt/aider/bin:/home/codewire/.cargo/bin:/home/codewire/.local/bin:${PATH}"
RUN go install golang.org/x/tools/gopls@latest && \
    pipx install poetry && pipx install uv

# Curated coding-agent CLIs are installed as `codewire` into user-owned
# prefixes. Workspace setup validates this fixed image contract and never
# downloads an agent at runtime. Vendor update mechanisms remain available to
# the normal interactive user without sudo.
RUN mkdir -p /home/codewire/.npm-global && \
    npm config set prefix /home/codewire/.npm-global && \
    npm install -g \
      "@openai/codex@${CODEX_VERSION}" \
      "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
      "@google/gemini-cli@${GEMINI_CLI_VERSION}" \
      "@moonshot-ai/kimi-code@${KIMI_CODE_VERSION}" \
      "@mariozechner/pi-coding-agent@${PI_VERSION}"

# Rust toolchain (stable). Installed as the codewire user so CARGO_HOME and
# RUSTUP_HOME live under $HOME and per-user invariants stay clean.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --no-modify-path
