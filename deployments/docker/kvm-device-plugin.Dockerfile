# The /dev/kvm device plugin's own image (#6202): the one binary and nothing
# else of the services image, whose every service binary a privileged root
# container on each sandbox node never needed. It registers codewire.sh/kvm
# with the kubelet over the kubelet's own socket and holds no credential
# (deployments/k8s/kvm-device-plugin).

ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

FROM codewire-rust-base AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
# Cargo needs every [patch] path the root manifest names (#3980), and every
# workspace member's path dependencies, to resolve the workspace.
COPY third_party/sqlx-sqlite-unused ./third_party/sqlx-sqlite-unused
COPY crates ./crates
COPY proto ./proto
COPY libs/daemon-proto ./libs/daemon-proto
ARG CODEWIRE_SCCACHE_MODE=disabled
ARG SCCACHE_BUCKET
ARG SCCACHE_ENDPOINT
ARG CODEWIRE_SCCACHE_PREFIX
ARG CODEWIRE_RUST_PROFILE=runtime
# Cargo's job count, set on the trusted BuildKit builder to fit its memory
# (scripts/ci/setup/trusted-buildkit.sh); empty means Cargo's default.
ARG CARGO_BUILD_JOBS
RUN --mount=type=cache,id=codewire-kvm-device-plugin-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=codewire-kvm-device-plugin-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=codewire-sccache-v2,target=/var/cache/sccache,sharing=shared \
    --mount=type=secret,id=aws_shared_credentials \
    find Cargo.toml Cargo.lock crates proto libs/daemon-proto -type f -exec touch {} + && \
    codewire-rust-build cargo build --locked --profile "$CODEWIRE_RUST_PROFILE" \
      -p codewire-kvm-device-plugin --bin cw-kvm-device-plugin \
    && mkdir -p /out \
    && cp "target/$CODEWIRE_RUST_PROFILE/cw-kvm-device-plugin" /out/cw-kvm-device-plugin

FROM ${DEBIAN_IMAGE}
COPY --from=builder /out/cw-kvm-device-plugin /cw-kvm-device-plugin
ENTRYPOINT ["/cw-kvm-device-plugin"]
