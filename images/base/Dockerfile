FROM ubuntu:noble

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive
ENV SHELL=/bin/bash

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash build-essential ca-certificates curl git htop jq locales man \
    openssh-server postgresql-client python3 python3-pip software-properties-common \
    sudo unzip vim wget rsync tmux && rm -rf /var/lib/apt/lists/*

# Latest git.
RUN add-apt-repository ppa:git-core/ppa && apt-get update && \
    apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Docker CE.
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc && \
    chmod a+r /etc/apt/keyrings/docker.asc && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list && \
    apt-get update && apt-get install -y \
    containerd.io docker-ce docker-ce-cli \
    docker-buildx-plugin docker-compose-plugin && \
    rm -rf /var/lib/apt/lists/* && \
    ln -sf /usr/libexec/docker/cli-plugins/docker-compose /usr/bin/docker-compose

# GitHub CLI.
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    > /etc/apt/sources.list.d/github-cli.list && \
    apt-get update && apt-get install -y gh && rm -rf /var/lib/apt/lists/*

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
