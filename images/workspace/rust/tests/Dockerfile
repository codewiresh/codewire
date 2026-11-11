# Focused native acceptance fixture, not the workspace image. Supply the exact
# cw-toolchain FROM reference from images/workspace/Dockerfile; never a tag.
ARG RUST_TOOLCHAIN_IMAGE
FROM ${RUST_TOOLCHAIN_IMAGE}
RUN rustup component add --toolchain 1.99.1 rustfmt clippy && \
    groupadd --gid 1000 codewire && \
    useradd --uid 1000 --gid 1000 --create-home codewire && \
    mkdir -p /opt/codewire/rust/cargo /opt/codewire/rust/bin && \
    mv /usr/local/cargo/bin /opt/codewire/rust/cargo/bin && \
    mv /usr/local/rustup /opt/codewire/rust/rustup && \
    chown -R codewire:codewire /opt/codewire/rust/rustup
COPY --chown=0:0 --chmod=0755 images/workspace/rust/rustup /opt/codewire/rust/bin/rustup
RUN for proxy in /opt/codewire/rust/cargo/bin/*; do \
      name="${proxy##*/}"; \
      [ "$name" = rustup ] || ln -s rustup "/opt/codewire/rust/bin/$name"; \
    done && \
    chmod -R go-w /opt/codewire/rust/cargo /opt/codewire/rust/bin
COPY --chown=0:0 --chmod=0755 images/workspace/rust/tests/verify.sh /usr/local/bin/verify-rust
ENV HOME=/home/codewire CARGO_HOME=/home/codewire/.cargo
# The official Rust parent sets RUSTUP_HOME; env -u below removes that inherited
# variable, matching the workspace's Ubuntu parent, which does not set it.
ENV PATH="/home/codewire/.cargo/bin:/opt/codewire/rust/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
USER 1000:1000
WORKDIR /tmp
ENTRYPOINT ["env", "-u", "RUSTUP_HOME", "verify-rust"]
