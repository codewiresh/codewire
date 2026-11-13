FROM ubuntu:noble@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive
ENV SHELL=/bin/bash

# Noble is installed only from this signed, dated Ubuntu snapshot. The pinned
# parent has no CA bundle, so the first transaction disables TLS peer checking
# only while apt still verifies the signed InRelease and package hashes. Every
# later transaction uses normal TLS verification. CI may supply an internal
# HTTP cache of the same snapshot as an optional secret; apt-get-with-retry
# reads it without changing these sources, and the lists named after that cache
# are removed before this layer ends.
COPY ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources
COPY apt-transport.conf /etc/apt/apt.conf.d/80-codewire-transport
COPY --chmod=0755 apt-get-with-retry /usr/local/sbin/apt-get-with-retry
RUN --mount=type=secret,id=codewire-apt-mirror,required=false \
    rm -f /etc/apt/sources.list && \
    apt-get-with-retry -o Acquire::https::Verify-Peer=false update && \
    apt-get-with-retry -o Acquire::https::Verify-Peer=false install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get-with-retry update && \
    grep -RqsF 'snapshot.ubuntu.com/ubuntu/20261015T000000Z/' /etc/apt/sources.list.d && \
    ! grep -RqsE '(archive|security|ports)\.ubuntu\.com' /etc/apt/sources.list /etc/apt/sources.list.d && \
    apt-get-with-retry install -y --no-install-recommends \
      bash build-essential ca-certificates curl file git htop iproute2 iptables jq locales man \
      openssh-client postgresql-client python3 python3-pip sudo tmux unzip vim wget rsync && \
    rm -rf /var/lib/apt/lists/*

# Foundational release tools are direct, checksum-verified upstream artifacts.
# Every supported architecture has an explicit reviewed digest; unknown
# architectures fail closed instead of silently receiving a different binary.
ARG TARGETARCH
ARG DOCKER_VERSION=29.9.2
ARG BUILDX_VERSION=0.36.0
ARG COMPOSE_VERSION=5.4.0
ARG GH_VERSION=2.97.0
RUN set -euo pipefail; \
    case "$TARGETARCH" in \
      amd64) \
        docker_arch=x86_64; compose_arch=x86_64; gh_arch=amd64; \
        docker_sha=9ac225999fd5e863f7694c728ef23d480616b1e5639328fa309befd4243d69eb; \
        buildx_sha=07823fdfcd82a41be90155a8b16876c1a780a6462de805a9f3f63b3119ccfb99; \
        compose_sha=837fd1d35bf6a494f41b5b5988269a7be79de337cf1a1a6ff0e45ab51bb4e9be; \
        gh_sha=a2c9b8497e1f85b1ad0dfcb78b5a622e098801b8e461e459e88e1ee12f018112 ;; \
      arm64) \
        docker_arch=aarch64; compose_arch=aarch64; gh_arch=arm64; \
        docker_sha=873b3e0207857c3b2f28392fb922f3ea6efe37620c16d4d4aaf2fef409c90b73; \
        buildx_sha=70382de03915c07c488ae4ddc4f7e169ee978f953e754ecfce110ba017e0132b; \
        compose_sha=fc5d1371f1ec7987e703da94ede49af3fbfb240b83f22991a98511de7bc4b93b; \
        gh_sha=73ea440ecad9c9e284429997ee6f93577bc6f7bc6fba357ef62c53ad8fb641a5 ;; \
      *) echo "unsupported base image architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -fsSL --retry 5 --retry-connrefused \
      "https://download.docker.com/linux/static/stable/${docker_arch}/docker-${DOCKER_VERSION}.tgz" \
      -o /tmp/docker.tgz; \
    echo "${docker_sha}  /tmp/docker.tgz" | sha256sum -c -; \
    tar -xzf /tmp/docker.tgz -C /tmp; \
    install -m 0755 /tmp/docker/* /usr/local/bin/; \
    install -d -m 0755 /usr/local/lib/docker/cli-plugins; \
    curl --proto '=https' --tlsv1.2 -fsSL --retry 5 --retry-connrefused \
      "https://github.com/docker/buildx/releases/download/v${BUILDX_VERSION}/buildx-v${BUILDX_VERSION}.linux-${TARGETARCH}" \
      -o /usr/local/lib/docker/cli-plugins/docker-buildx; \
    echo "${buildx_sha}  /usr/local/lib/docker/cli-plugins/docker-buildx" | sha256sum -c -; \
    curl --proto '=https' --tlsv1.2 -fsSL --retry 5 --retry-connrefused \
      "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-${compose_arch}" \
      -o /usr/local/lib/docker/cli-plugins/docker-compose; \
    echo "${compose_sha}  /usr/local/lib/docker/cli-plugins/docker-compose" | sha256sum -c -; \
    chmod 0755 /usr/local/lib/docker/cli-plugins/docker-buildx /usr/local/lib/docker/cli-plugins/docker-compose; \
    ln -s /usr/local/lib/docker/cli-plugins/docker-compose /usr/local/bin/docker-compose; \
    curl --proto '=https' --tlsv1.2 -fsSL --retry 5 --retry-connrefused \
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
    groupadd --gid 1000 codewire && \
    groupadd -f docker && \
    useradd codewire --create-home --shell=/bin/bash --uid=1000 --gid=1000 && \
    echo "codewire ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/nopasswd && \
    usermod -aG docker codewire

COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

USER codewire
WORKDIR /home/codewire

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]
