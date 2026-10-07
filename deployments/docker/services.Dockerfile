# syntax=docker/dockerfile:1.20
# codewire Rust services — one image, many entrypoints.
#
# Builds every Rust server binary once (shared deps compiled a single time)
# and ships them together, the same model as the Go `server` image. Each
# deployment selects its binary via `command`:
#
#   deployments/k8s/idp            → command: ["/codewire-idp"]
#   deployments/k8s/orchestration  → command: ["/codewire-orchestration"]
#   deployments/k8s/billing        → command: ["/codewire-billing"]
#   deployments/k8s/coordinator    → command: ["/codewire-coordinator"]
#   schema bootstrap               → command: ["/codewire-db-migrate"]
#   runtime UDP peer relay         → command: ["/codewire-udp-relay"]
#   isolated credential authority  → command: ["/codewire-credential-service"]
#   diagnostics                    → command: ["/sidecar-smoke"]
#
# Built+pushed as codewire/services by .gitea/workflows/ci.yaml. Build from
# the repo root:
#
#   docker buildx bake --file docker-bake.hcl --pull --load \
#     --set 'services.tags=codewire-services:dev' services
#
# protoc is a build dependency of codewire-orchestration's temporalio-sdk
# family (prost-wkt-types). It comes from one checksum-pinned upstream archive;
# the image never consults an operating-system package repository.

ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
ARG TARGETARCH

# Official Codex 0.149.0 native enrollment executable, the same accepted
# version as the workspace contract. No Node/npm runtime or install script.
# Archive bytes also match the upstream npm SHA-512 integrity values recorded
# in docs/SECRETS.md. Only the selected target's artifact stage is built.
FROM ${DEBIAN_IMAGE} AS codex-amd64
ADD --checksum=sha256:e06f3d106fe8bb058a6bfd30075d89ea17deaee7c8425e0c5d23072df0fdd0e7 \
    https://registry.npmjs.org/@openai/codex/-/codex-0.149.0-linux-x64.tgz /codex.tgz
RUN mkdir /codex && tar -xzf /codex.tgz -C /codex --strip-components=4 \
    package/vendor/x86_64-unknown-linux-musl/bin/codex

FROM ${DEBIAN_IMAGE} AS codex-arm64
ADD --checksum=sha256:2d8e3032f4a058d1597606aba9ed8cc6eff59de678e2f81083ee11b898250e07 \
    https://registry.npmjs.org/@openai/codex/-/codex-0.149.0-linux-arm64.tgz /codex.tgz
RUN mkdir /codex && tar -xzf /codex.tgz -C /codex --strip-components=4 \
    package/vendor/aarch64-unknown-linux-musl/bin/codex

FROM codex-${TARGETARCH} AS codex-enrollment

# Same pinned official GitHub CLI artifacts as images/base/Dockerfile.
# Only the selected architecture is fetched; no package/install scripts run.
FROM ${DEBIAN_IMAGE} AS github-amd64
ADD --checksum=sha256:a2c9b8497e1f85b1ad0dfcb78b5a622e098801b8e461e459e88e1ee12f018112 \
    https://github.com/cli/cli/releases/download/v2.97.0/gh_2.97.0_linux_amd64.tar.gz /gh.tgz
RUN mkdir /gh && tar -xzf /gh.tgz -C /gh --strip-components=1

FROM ${DEBIAN_IMAGE} AS github-arm64
ADD --checksum=sha256:73ea440ecad9c9e284429997ee6f93577bc6f7bc6fba357ef62c53ad8fb641a5 \
    https://github.com/cli/cli/releases/download/v2.97.0/gh_2.97.0_linux_arm64.tar.gz /gh.tgz
RUN mkdir /gh && tar -xzf /gh.tgz -C /gh --strip-components=1

FROM github-${TARGETARCH} AS github-enrollment

# Only the two selected-agent tools and their missing crypto library are
# extracted. These official Bookworm artifacts are independently checksum
# pinned for both architectures; no package scripts or dependency resolver run.
# Immutable Debian snapshots use the dependency origin already admitted by CI.
# Debian tracks CVE-2026-73281 as postponed in this OpenSSH version. Its
# lock/session-bind path is not exposed by our identities/sign-only adapter;
# the private agent is never forwarded and is drained after each Sign.
FROM ${DEBIAN_IMAGE} AS ssh-tools-amd64
ADD --checksum=sha256:42c250b8b9110382488c53c066a960bc564ddac2cb9e449f47b6cdbb5fc1cb60 \
    https://snapshot.debian.org/archive/debian/20260505T204143Z/pool/main/o/openssh/openssh-client_9.2p1-2%2Bdeb12u10_amd64.deb /openssh.deb
ADD --checksum=sha256:89be24b41bff568ee6e7caf5680a3d808e80315ed92e407056ce0fa7a5bda025 \
    https://snapshot.debian.org/archive/debian/20260612T023739Z/pool/main/o/openssl/libssl3_3.0.20-1%7Edeb12u2_amd64.deb /libssl.deb
RUN dpkg-deb --extract /openssh.deb /payload && \
    dpkg-deb --extract /libssl.deb /payload && \
    install -D /payload/usr/bin/ssh-agent /out/usr/bin/ssh-agent && \
    install -D /payload/usr/bin/ssh-add /out/usr/bin/ssh-add && \
    install -Dm644 /payload/usr/lib/x86_64-linux-gnu/libcrypto.so.3 /out/usr/lib/x86_64-linux-gnu/libcrypto.so.3 && \
    install -Dm644 /payload/usr/share/doc/openssh-client/copyright /out/usr/share/doc/openssh-client/copyright && \
    install -Dm644 /payload/usr/share/doc/libssl3/copyright /out/usr/share/doc/libssl3/copyright

FROM ${DEBIAN_IMAGE} AS ssh-tools-arm64
ADD --checksum=sha256:72f7cb7eb432038a62cd89e0552b352a514e880fe3907e73dc50ca2ef6d088d7 \
    https://snapshot.debian.org/archive/debian/20260505T204143Z/pool/main/o/openssh/openssh-client_9.2p1-2%2Bdeb12u10_arm64.deb /openssh.deb
ADD --checksum=sha256:a256e03cc3abd7243ac5c6ee91a9deb56478221ef0d3c2b0748551e13140c0bf \
    https://snapshot.debian.org/archive/debian/20260612T023739Z/pool/main/o/openssl/libssl3_3.0.20-1%7Edeb12u2_arm64.deb /libssl.deb
RUN dpkg-deb --extract /openssh.deb /payload && \
    dpkg-deb --extract /libssl.deb /payload && \
    install -D /payload/usr/bin/ssh-agent /out/usr/bin/ssh-agent && \
    install -D /payload/usr/bin/ssh-add /out/usr/bin/ssh-add && \
    install -Dm644 /payload/usr/lib/aarch64-linux-gnu/libcrypto.so.3 /out/usr/lib/aarch64-linux-gnu/libcrypto.so.3 && \
    install -Dm644 /payload/usr/share/doc/openssh-client/copyright /out/usr/share/doc/openssh-client/copyright && \
    install -Dm644 /payload/usr/share/doc/libssl3/copyright /out/usr/share/doc/libssl3/copyright

FROM ssh-tools-${TARGETARCH} AS selected-ssh-tools

# This same minimal runtime stage can be qualified without recompiling the
# product. The final services image inherits these exact files and helper.
FROM ${DEBIAN_IMAGE} AS ssh-runtime
COPY --from=selected-ssh-tools /out/ /
COPY --chmod=755 crates/codewire-credential-broker/src/ssh_agent/askpass.sh /usr/local/libexec/codewire/ssh-askpass
USER 65532:65532

FROM codewire-rust-base AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# codewire-proto (a codewire-server-core dependency since connect-rpc 03
# WI-2) compiles proto/codewire/** + proto/google/rpc/** at build time via
# protoc — the contract sources must be in the build context.
COPY proto ./proto
# WI-R4 makes orchestration's authenticated environment proxy consume the
# private daemon protocol through codewire-daemon-proto. Its build script
# compiles this separate internal schema at build time.
COPY libs/daemon-proto ./libs/daemon-proto
ARG CODEWIRE_SCCACHE_MODE=disabled
ARG SCCACHE_BUCKET
ARG SCCACHE_ENDPOINT
ARG CODEWIRE_SCCACHE_PREFIX
ARG CODEWIRE_RUST_PROFILE=release
ARG CODEWIRE_ORCHESTRATION_FEATURES=
# One Cargo invocation builds every shipped binary: the three historical
# invocations shared one target tree and lockfile, so their common dependency
# graph (including codewire-server-core, which differed only by the additive
# kubernetes-identity feature) compiled up to three times. Feature flags here
# enable only optional dependencies, so Cargo's additive unification keeps
# each binary's behavior identical while every dependency compiles once.
RUN --mount=type=cache,id=codewire-services-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=codewire-services-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=codewire-sccache-v2,target=/var/cache/sccache,sharing=shared \
    --mount=type=secret,id=aws_shared_credentials \
    find Cargo.toml Cargo.lock crates proto libs/daemon-proto -type f -exec touch {} + && \
    feature_args='codewire-credential-service/enrollment' && \
    case "$CODEWIRE_ORCHESTRATION_FEATURES" in \
      '') ;; \
      kind-e2e) \
        feature_args="$feature_args codewire-orchestration/kind-e2e codewire-credential-service/kind-e2e" ;; \
      *) \
        feature_args="$feature_args codewire-orchestration/$CODEWIRE_ORCHESTRATION_FEATURES" ;; \
    esac && \
    codewire-rust-build cargo build --locked --profile "$CODEWIRE_RUST_PROFILE" \
      -p codewire-idp --bin codewire-idp \
      -p codewire-orchestration --bin codewire-orchestration --bin sidecar-smoke \
      -p codewire-billing --bin codewire-billing --bin billing-runtime-smoke \
      -p codewire-coordinator --bin codewire-coordinator \
      -p codewire-server-core --bin codewire-db-migrate \
      -p codewire-udp-relay --bin codewire-udp-relay \
      -p codewire-credential-service --bin codewire-credential-service \
      --features "$feature_args" && \
    mkdir -p /out && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-idp" /out/codewire-idp && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-orchestration" /out/codewire-orchestration && \
    cp "target/$CODEWIRE_RUST_PROFILE/sidecar-smoke" /out/sidecar-smoke && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-billing" /out/codewire-billing && \
    cp "target/$CODEWIRE_RUST_PROFILE/billing-runtime-smoke" /out/codewire-billing-runtime-smoke && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-coordinator" /out/codewire-coordinator && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-db-migrate" /out/codewire-db-migrate && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-udp-relay" /out/codewire-udp-relay && \
    cp "target/$CODEWIRE_RUST_PROFILE/codewire-credential-service" /out/codewire-credential-service && \
    mkdir -p /out/kind-fixtures /out/kind-git-runtime && \
    if [ "$CODEWIRE_ORCHESTRATION_FEATURES" = kind-e2e ]; then \
      test "$CODEWIRE_RUST_PROFILE" = ci && \
      codewire-rust-build cargo test --locked --profile ci \
        -p codewire-credential-service --features enrollment --lib --no-run \
        --message-format=json > /tmp/credential-fixture-artifacts.jsonl && \
      credential_fixture="$(sed -n '/"reason":"compiler-artifact"/{/"test":true/{s@.*"executable":"\(/src/target/ci/deps/codewire_credential_service-[0-9a-f][0-9a-f]*\)".*@\1@p;}}' /tmp/credential-fixture-artifacts.jsonl)" && \
      test -n "$credential_fixture" && test -x "$credential_fixture" && \
      "$credential_fixture" --list > /tmp/credential-fixture-tests.txt && \
      grep -qx 'runtime::kind::serve_kind_credential_fixture: test' /tmp/credential-fixture-tests.txt && \
      cp "$credential_fixture" /out/kind-fixtures/credential-service && \
      test "$(git --version)" = 'git version 2.39.5' && \
      install -D /usr/bin/git /out/kind-git-runtime/usr/bin/git && \
      install -D /usr/lib/git-core/git-http-backend /out/kind-git-runtime/usr/lib/git-core/git-http-backend && \
      ln -s ../../bin/git /out/kind-git-runtime/usr/lib/git-core/git && \
      ln -s git /out/kind-git-runtime/usr/lib/git-core/git-upload-pack && \
      ln -s git /out/kind-git-runtime/usr/lib/git-core/git-pack-objects && \
      install -Dm644 /usr/share/doc/git/copyright /out/kind-git-runtime/usr/share/doc/git/copyright; \
    fi

FROM ssh-runtime
COPY --from=builder /out/codewire-idp /codewire-idp
COPY --from=builder /out/codewire-orchestration /codewire-orchestration
COPY --from=builder /out/sidecar-smoke /sidecar-smoke
COPY --from=builder /out/codewire-billing /codewire-billing
COPY --from=builder /out/codewire-billing-runtime-smoke /codewire-billing-runtime-smoke
COPY --from=builder /out/codewire-coordinator /codewire-coordinator
COPY --from=builder /out/codewire-db-migrate /codewire-db-migrate
COPY --from=builder /out/codewire-udp-relay /codewire-udp-relay
COPY --from=builder /out/codewire-credential-service /codewire-credential-service
# Empty in the release graph: cfg(test) code is built only by services-ci's
# existing kind-e2e feature/profile pair. No production fixture switch exists.
COPY --from=builder /out/kind-fixtures/ /codewire-kind-fixtures/
# Stock Git from the already digest-pinned Rust/Bookworm toolchain, only for
# the synthetic smart-HTTP provider. No client HTTP/SSH helpers, package resolver
# or new download. The pinned Debian runtime already supplies libpcre2/libz and
# libc/loader; do not overwrite them with the builder's older libc. Like the
# libtest payload above, this directory is empty outside kind-e2e + profile ci.
COPY --from=builder /out/kind-git-runtime/ /
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=codex-enrollment /codex/codex /usr/local/bin/codex
COPY --from=github-enrollment /gh/bin/gh /usr/local/bin/gh
COPY --from=github-enrollment /gh/LICENSE /usr/share/licenses/gh/LICENSE
COPY deployments/docker/licenses/codex-LICENSE deployments/docker/licenses/codex-NOTICE /usr/share/licenses/codex/
USER 65532:65532
# Exercise the minimal Git closure in the actual non-root runtime, including
# CGI advertisement/pack transfer and child cleanup. Release proves absence.
RUN if [ -x /codewire-kind-fixtures/credential-service ]; then \
      /codewire-kind-fixtures/credential-service --list > /tmp/kind-git-tests.txt && \
      grep -qx 'runtime::kind::git::tests::stock_git_smart_http_round_trip: test' /tmp/kind-git-tests.txt && \
      /codewire-kind-fixtures/credential-service --exact \
        runtime::kind::git::tests::stock_git_smart_http_round_trip --test-threads=1 && \
      rm /tmp/kind-git-tests.txt; \
    else \
      test ! -e /usr/bin/git && test ! -e /usr/lib/git-core/git-http-backend && \
      test ! -e /usr/lib/git-core/git-upload-pack && test ! -e /usr/lib/git-core/git-pack-objects; \
    fi
# No ENTRYPOINT: each deployment sets `command` to pick its binary.
