ARG RUST_IMAGE=rust:1.91.1-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian12:nonroot@sha256:fccdbb0a547c14e23fcf4ce8ad62ca5d43b4faae8d22cd292f490fef9946c96e
ARG BUILDPLATFORM
ARG TARGETARCH

FROM --platform=${BUILDPLATFORM} ${DEBIAN_IMAGE} AS zola-amd64
ADD --checksum=sha256:0ca09aa40376aaa9ddfb512ff9ad963262ef95edb0d0f2d5ec6961b6f5cf22ef \
  https://github.com/getzola/zola/releases/download/v0.22.1/zola-v0.22.1-x86_64-unknown-linux-gnu.tar.gz \
  /tmp/zola.tar.gz
RUN tar -xzf /tmp/zola.tar.gz -C /tmp zola LICENSE \
  && echo "45de6b2559aba4df42199dc6b0161acb914d37be4ccaa03297cd4a26c8e14042  /tmp/zola" | sha256sum -c - \
  && echo "6fc9e709ccbfe0d77fbffa2427a983282be2eb88e47b1cdb49f21a83b4d1e665  /tmp/LICENSE" | sha256sum -c - \
  && mv /tmp/zola /usr/local/bin/zola \
  && mkdir -p /usr/share/licenses/zola \
  && mv /tmp/LICENSE /usr/share/licenses/zola/LICENSE \
  && test -x /usr/local/bin/zola

FROM --platform=${BUILDPLATFORM} ${DEBIAN_IMAGE} AS zola-arm64
ADD --checksum=sha256:8af437ec6352f33ccd24d7a1cfcb54a3db95d3ce376dc69525b4ef3fb6b8c1d1 \
  https://github.com/getzola/zola/releases/download/v0.22.1/zola-v0.22.1-aarch64-unknown-linux-gnu.tar.gz \
  /tmp/zola.tar.gz
RUN tar -xzf /tmp/zola.tar.gz -C /tmp zola LICENSE \
  && echo "8582915b9949adaad6a2127530295f9b5ebcea15da56f047229e9a59ffdf68c7  /tmp/zola" | sha256sum -c - \
  && echo "6fc9e709ccbfe0d77fbffa2427a983282be2eb88e47b1cdb49f21a83b4d1e665  /tmp/LICENSE" | sha256sum -c - \
  && mv /tmp/zola /usr/local/bin/zola \
  && mkdir -p /usr/share/licenses/zola \
  && mv /tmp/LICENSE /usr/share/licenses/zola/LICENSE \
  && test -x /usr/local/bin/zola

FROM zola-${TARGETARCH} AS zola

FROM ${RUST_IMAGE} AS builder
WORKDIR /workspace
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
COPY libs/gateway-proto ./libs/gateway-proto
COPY packages/codewire-design ./packages/codewire-design
COPY apps/cli/install.sh ./apps/cli/install.sh
RUN cargo build --locked --release -p codewire-dashboard-web \
  && mkdir -p /out \
  && cp target/release/codewire-dashboard-web /out/codewire-dashboard-web \
  && cd /out \
  && sha256sum codewire-dashboard-web > dashboard-binary.sha256
RUN cargo metadata --locked --offline --no-deps --format-version 1 \
      > /out/rust-workspace-metadata.json \
  && cp Cargo.lock /out/Cargo.lock

FROM ${RUST_IMAGE} AS docs-builder
COPY --from=zola /usr/local/bin/zola /usr/local/bin/zola
COPY --from=zola /usr/share/licenses/zola/LICENSE /usr/share/licenses/zola/LICENSE
COPY apps/docs/zola /workspace/apps/docs/zola
COPY apps/dashboard/Dockerfile /workspace/apps/dashboard/Dockerfile
COPY packages/codewire-design/styles.css /workspace/packages/codewire-design/styles.css
WORKDIR /workspace/apps/docs/zola
RUN ./build.sh /out/docs \
  && ./tests/verify.sh /out/docs \
  && cd /out/docs \
  && find . -type f -print0 | sort -z | xargs -0 sha256sum > /out/docs.sha256

FROM ${DEBIAN_IMAGE} AS runtime-assembly
WORKDIR /runtime
COPY --from=builder /out/codewire-dashboard-web ./srv/codewire/codewire-dashboard-web
COPY --from=docs-builder /out/docs ./srv/codewire/docs
COPY --from=builder /out/rust-workspace-metadata.json ./usr/share/codewire/rust-workspace-metadata.json
COPY --from=builder /out/Cargo.lock ./usr/share/codewire/Cargo.lock
COPY --from=builder /out/dashboard-binary.sha256 ./usr/share/codewire/dashboard-binary.sha256
COPY --from=docs-builder /out/docs.sha256 ./usr/share/codewire/docs.sha256
COPY apps/dashboard/runtime-inventory.json ./usr/share/codewire/runtime-inventory.json
COPY LICENSE ./usr/share/licenses/codewire/LICENSE
COPY crates/codewire-dashboard-web/assets/LICENSE-HTMX ./usr/share/licenses/htmx/LICENSE
COPY crates/codewire-dashboard-web/assets/xterm/LICENSE-xterm-6.0.0 ./usr/share/licenses/xterm/LICENSE
COPY crates/codewire-dashboard-web/assets/xterm/LICENSE-addon-fit-0.11.0 ./usr/share/licenses/xterm-addon-fit/LICENSE
COPY crates/codewire-dashboard-web/assets/xterm/LICENSE-addon-web-links-0.12.0 ./usr/share/licenses/xterm-addon-web-links/LICENSE
RUN find . -type f ! -path './usr/share/codewire/runtime-files.sha256' -print0 \
  | sort -z \
  | xargs -0 sha256sum > ./usr/share/codewire/runtime-files.sha256

FROM ${RUNTIME_IMAGE}
COPY --from=runtime-assembly --chown=65532:65532 /runtime/ /
ENV CODEWIRE_DASHBOARD_LISTEN_ADDR=0.0.0.0:5173
ENV CODEWIRE_DOCS_ROOT=/srv/codewire/docs
WORKDIR /srv/codewire
USER 65532:65532
EXPOSE 5173
ENTRYPOINT ["/srv/codewire/codewire-dashboard-web"]
