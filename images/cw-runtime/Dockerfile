# syntax=docker/dockerfile:1.7
# Standalone amd64 CW compiler. ARM product callers retain their native route.
# The fixed empty stage makes an omitted named context fail locally rather
# than interpreting its name as a remotely fetched image.
FROM scratch AS cw-source

FROM rust:1.93.0-bookworm@sha256:d0a4aa3ca2e1088ac0c81690914a0d810f2eee188197034edf366ed010a2b382 AS cw-toolchain
COPY images/workspace/debian.sources /etc/apt/sources.list.d/debian.sources
COPY images/base/apt-transport.conf /etc/apt/apt.conf.d/80-codewire-transport
COPY --chmod=0755 images/base/apt-get-with-retry /usr/local/sbin/apt-get-with-retry
ADD --checksum=sha256:6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7 \
    https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip /tmp/protoc.zip
ADD --checksum=sha256:67c4a96dd237c1f518f6b36083f270f9976d516f1e57fce891755ea782e50006 \
    https://github.com/mozilla/sccache/releases/download/v0.17.0/sccache-v0.17.0-x86_64-unknown-linux-musl.tar.gz /tmp/sccache.tar.gz
ADD --checksum=sha256:02aa270f183da276e5b5920b1dac44a63f1a49e55050ebde3aecc9eb82f93239 \
    https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz /tmp/zig.tar.xz
RUN rm -f /etc/apt/sources.list && \
    apt-get-with-retry update && \
    grep -RqsF 'snapshot.debian.org/archive/debian/20251208T000000Z/' /etc/apt/sources.list.d && \
    ! grep -RqsE '(deb|security)\.debian\.org' /etc/apt/sources.list /etc/apt/sources.list.d && \
    apt-get-with-retry install -y --no-install-recommends python3 unzip xz-utils && \
    rm -rf /var/lib/apt/lists/* && \
    unzip -q /tmp/protoc.zip -d /opt/protoc && \
    tar -xzf /tmp/sccache.tar.gz -C /tmp && \
    install -m 0755 /tmp/sccache-v0.17.0-x86_64-unknown-linux-musl/sccache /usr/local/bin/sccache && \
    mkdir /opt/zig && tar -xJf /tmp/zig.tar.xz --strip-components=1 -C /opt/zig && \
    rm -rf /tmp/protoc.zip /tmp/sccache.tar.gz /tmp/zig.tar.xz /tmp/sccache-v0.17.0-x86_64-unknown-linux-musl && \
    test "$(rustc --version)" = 'rustc 1.93.0 (254b59607 2026-01-19)' && \
    test "$(/opt/protoc/bin/protoc --version)" = 'libprotoc 35.1' && \
    test "$(sccache --version)" = 'sccache 0.17.0' && \
    test "$(/opt/zig/zig version)" = '0.15.2' && \
    rustup target add --toolchain 1.93.0 x86_64-unknown-linux-musl && \
    cargo install --locked cargo-zigbuild --version 0.23.0 && \
    test "$(cargo-zigbuild --version)" = 'cargo-zigbuild 0.23.0'
COPY --chmod=0755 scripts/ci/images/run-rust-build.sh /usr/local/bin/codewire-rust-build
ENV PATH="/opt/zig:/opt/protoc/bin:${PATH}" PROTOC=/opt/protoc/bin/protoc PYTHONDONTWRITEBYTECODE=1

FROM cw-toolchain AS cw-builder
ARG CW_SOURCE_REQUEST_SHA256
ARG CODEWIRE_RUST_PROFILE=release
ARG CODEWIRE_SCCACHE_MODE=disabled
ARG SCCACHE_BUCKET
ARG SCCACHE_ENDPOINT
ARG CODEWIRE_SCCACHE_PREFIX
# Exactly one actual compiler RUN; source admission, compiler completion and
# dep-info/byte export remain inside this vertex. Its history is distinct from
# a later gateway/workspace COPY and must be joined by the owning cache gate.
RUN --mount=type=bind,from=cw-source,source=source,target=/src,readonly \
    --mount=type=bind,from=cw-source,source=git,target=/source-git,readonly \
    --mount=type=bind,from=cw-source,source=request.json,target=/run/cw-source-request.json,readonly \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,id=codewire-workspace-sccache-v1,target=/var/cache/sccache,sharing=shared \
    --mount=type=secret,id=aws_shared_credentials \
    mkdir /out && \
    SCCACHE_BASEDIRS=/src codewire-rust-build python3 /src/scripts/ci/images/finalize-cw-runtime-source.py \
      --request-sha256 "$CW_SOURCE_REQUEST_SHA256"

FROM scratch AS cw-runtime-export
COPY --from=cw-builder /out/assets/ /
