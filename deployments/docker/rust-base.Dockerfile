# syntax=docker/dockerfile:1.20
# Shared product-image build toolchain. This image is a build input only; no
# product runtime inherits from it.
ARG RUST_IMAGE=rust:1.93.0-bookworm@sha256:d0a4aa3ca2e1088ac0c81690914a0d810f2eee188197034edf366ed010a2b382

FROM ${RUST_IMAGE}
ADD --checksum=sha256:6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7 \
  https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip \
  /tmp/protoc.zip
ADD --checksum=sha256:67c4a96dd237c1f518f6b36083f270f9976d516f1e57fce891755ea782e50006 \
  https://github.com/mozilla/sccache/releases/download/v0.17.0/sccache-v0.17.0-x86_64-unknown-linux-musl.tar.gz \
  /tmp/sccache.tar.gz
RUN unzip -q /tmp/protoc.zip -d /opt/protoc \
    && tar -xzf /tmp/sccache.tar.gz -C /tmp \
    && install -m 0755 /tmp/sccache-v0.17.0-x86_64-unknown-linux-musl/sccache /usr/local/bin/sccache \
    && rm -rf /tmp/protoc.zip /tmp/sccache.tar.gz /tmp/sccache-v0.17.0-x86_64-unknown-linux-musl \
    && test "$(rustc --version)" = 'rustc 1.93.0 (254b59607 2026-01-19)' \
    && test "$(/opt/protoc/bin/protoc --version)" = 'libprotoc 35.1' \
    && test "$(sccache --version)" = 'sccache 0.17.0'
COPY scripts/ci/images/run-rust-build.sh /usr/local/bin/codewire-rust-build
ENV PATH="/opt/protoc/bin:${PATH}"
