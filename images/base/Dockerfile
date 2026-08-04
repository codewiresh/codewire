# syntax=docker/dockerfile:1.7
FROM ubuntu:noble@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive
ENV SHELL=/bin/bash

# Noble is installed only from this signed, dated Ubuntu snapshot. The pinned
# parent has no CA bundle, so the first transaction disables TLS peer checking
# only while apt still verifies the signed InRelease and package hashes. Every
# later transaction uses normal TLS verification.
COPY ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources
RUN rm -f /etc/apt/sources.list && \
    apt-get -o Acquire::https::Verify-Peer=false update && \
    apt-get -o Acquire::https::Verify-Peer=false install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get update && \
    grep -RqsF 'snapshot.ubuntu.com/ubuntu/20260803T000000Z/' /etc/apt/sources.list.d && \
    ! grep -RqsE '(archive|security|ports)\.ubuntu\.com' /etc/apt/sources.list /etc/apt/sources.list.d && \
    apt-get install -y --no-install-recommends \
      bash build-essential ca-certificates curl file git htop iproute2 iptables jq locales man \
      openssh-server postgresql-client python3 python3-pip sudo tmux unzip vim wget rsync && \
    rm -rf /var/lib/apt/lists/*

# Foundational release tools are direct, checksum-verified upstream artifacts.
# Every supported architecture has an explicit reviewed digest; unknown
# architectures fail closed instead of silently receiving a different binary.
ARG TARGETARCH
ARG DOCKER_VERSION=29.7.1
ARG BUILDX_VERSION=0.36.0
ARG COMPOSE_VERSION=5.4.0
ARG GH_VERSION=2.97.0
RUN set -euo pipefail; \
    case "$TARGETARCH" in \
      amd64) \
        docker_arch=x86_64; compose_arch=x86_64; gh_arch=amd64; \
        docker_sha=0fcea2a8b4d1b54ccc9010e3451b78504a369d414f37eb3bb79300e1b5c22ce6; \
        buildx_sha=07823fdfcd82a41be90155a8b16876c1a780a6462de805a9f3f63b3119ccfb99; \
        compose_sha=837fd1d35bf6a494f41b5b5988269a7be79de337cf1a1a6ff0e45ab51bb4e9be; \
        gh_sha=a2c9b8497e1f85b1ad0dfcb78b5a622e098801b8e461e459e88e1ee12f018112 ;; \
      arm64) \
        docker_arch=aarch64; compose_arch=aarch64; gh_arch=arm64; \
        docker_sha=4eb4d1b21131897ed3990aac31039161bf4bdd07fcfb733e996010319ff4e069; \
        buildx_sha=70382de03915c07c488ae4ddc4f7e169ee978f953e754ecfce110ba017e0132b; \
        compose_sha=fc5d1371f1ec7987e703da94ede49af3fbfb240b83f22991a98511de7bc4b93b; \
        gh_sha=73ea440ecad9c9e284429997ee6f93577bc6f7bc6fba357ef62c53ad8fb641a5 ;; \
      *) echo "unsupported base image architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -fsSL \
      "https://download.docker.com/linux/static/stable/${docker_arch}/docker-${DOCKER_VERSION}.tgz" \
      -o /tmp/docker.tgz; \
    echo "${docker_sha}  /tmp/docker.tgz" | sha256sum -c -; \
    tar -xzf /tmp/docker.tgz -C /tmp; \
    install -m 0755 /tmp/docker/* /usr/local/bin/; \
    install -d -m 0755 /usr/local/lib/docker/cli-plugins; \
    curl --proto '=https' --tlsv1.2 -fsSL \
      "https://github.com/docker/buildx/releases/download/v${BUILDX_VERSION}/buildx-v${BUILDX_VERSION}.linux-${TARGETARCH}" \
      -o /usr/local/lib/docker/cli-plugins/docker-buildx; \
    echo "${buildx_sha}  /usr/local/lib/docker/cli-plugins/docker-buildx" | sha256sum -c -; \
    curl --proto '=https' --tlsv1.2 -fsSL \
      "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-${compose_arch}" \
      -o /usr/local/lib/docker/cli-plugins/docker-compose; \
    echo "${compose_sha}  /usr/local/lib/docker/cli-plugins/docker-compose" | sha256sum -c -; \
    chmod 0755 /usr/local/lib/docker/cli-plugins/docker-buildx /usr/local/lib/docker/cli-plugins/docker-compose; \
    ln -s /usr/local/lib/docker/cli-plugins/docker-compose /usr/local/bin/docker-compose; \
    curl --proto '=https' --tlsv1.2 -fsSL \
      "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${gh_arch}.tar.gz" \
      -o /tmp/gh.tgz; \
    echo "${gh_sha}  /tmp/gh.tgz" | sha256sum -c -; \
    tar -xzf /tmp/gh.tgz -C /tmp; \
    install -m 0755 "/tmp/gh_${GH_VERSION}_linux_${gh_arch}/bin/gh" /usr/local/bin/gh; \
    rm -rf /tmp/docker /tmp/docker.tgz /tmp/gh.tgz "/tmp/gh_${GH_VERSION}_linux_${gh_arch}"; \
    docker --version; dockerd --version; docker buildx version; docker compose version; gh --version

RUN locale-gen en_US.UTF-8
ENV LANG=en_US.UTF-8

RUN userdel -r ubuntu 2>/dev/null || true && \
    groupadd -f docker && \
    useradd codewire --create-home --shell=/bin/bash --uid=1000 --user-group && \
    echo "codewire ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/nopasswd && \
    usermod -aG docker codewire

# sshd runs as codewire on port 2222. Host keys and authorized_keys live in
# /etc/codewire/ssh so ~/.ssh can be mounted read-only for git credentials.
RUN mkdir -p /run/sshd /etc/codewire/ssh && \
    chown codewire:codewire /etc/codewire/ssh && \
    chmod 700 /etc/codewire/ssh && \
    echo -e "Port 2222\nPasswordAuthentication no\nPermitRootLogin no\nPubkeyAuthentication yes\nHostKey /etc/codewire/ssh/ssh_host_ed25519_key\nAuthorizedKeysFile /etc/codewire/ssh/authorized_keys .ssh/authorized_keys" \
    > /etc/ssh/sshd_config.d/codewire.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

EXPOSE 2222

USER codewire
WORKDIR /home/codewire

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]
