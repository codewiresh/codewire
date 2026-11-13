# Shared product-image build toolchain. This image is a build input only; no
# product runtime inherits from it.
ARG RUST_IMAGE=rust:1.99.1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c

FROM ${RUST_IMAGE}
ADD --checksum=sha256:6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7 \
  https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip \
  /tmp/protoc.zip
ADD --checksum=sha256:67c4a96dd237c1f518f6b36083f270f9976d516f1e57fce891755ea782e50006 \
  https://github.com/mozilla/sccache/releases/download/v0.17.0/sccache-v0.17.0-x86_64-unknown-linux-musl.tar.gz \
  /tmp/sccache.tar.gz
# cargo-nextest builds the test archive on a builder (infra#1632); the pin is
# scripts/ci/setup/install-cargo-nextest.sh's.
ADD --checksum=sha256:bf92cb81450872d960ffa13857a83084d557ec0cdc141663d263bb23ef756f97 \
  https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-0.9.148/cargo-nextest-0.9.148-x86_64-unknown-linux-musl.tar.gz \
  /tmp/cargo-nextest.tar.gz
RUN unzip -q /tmp/protoc.zip -d /opt/protoc \
    && tar -xzf /tmp/sccache.tar.gz -C /tmp \
    && install -m 0755 /tmp/sccache-v0.17.0-x86_64-unknown-linux-musl/sccache /usr/local/bin/sccache \
    && tar -xzf /tmp/cargo-nextest.tar.gz -C /usr/local/cargo/bin cargo-nextest \
    && rm -rf /tmp/protoc.zip /tmp/sccache.tar.gz /tmp/sccache-v0.17.0-x86_64-unknown-linux-musl /tmp/cargo-nextest.tar.gz \
    && test "$(rustc --version)" = 'rustc 1.99.1 (58cf8f9c3 2026-10-13)' \
    && test "$(/opt/protoc/bin/protoc --version)" = 'libprotoc 35.1' \
    && test "$(sccache --version)" = 'sccache 0.17.0' \
    && cargo nextest --version | head -n 1 | grep -q '^cargo-nextest 0\.9\.148 '
COPY scripts/ci/images/run-rust-build.sh /usr/local/bin/codewire-rust-build
ENV PATH="/opt/protoc/bin:${PATH}"
