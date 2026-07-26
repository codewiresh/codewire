#!/usr/bin/env bash
set -euo pipefail

# The platform path writes keys outside $HOME because ~/.ssh can be mounted
# read-only for git credentials.
if [ -n "${CODEWIRE_SSH_AUTHORIZED_KEYS:-}" ]; then
  printf '%s\n' "$CODEWIRE_SSH_AUTHORIZED_KEYS" \
    > /etc/codewire/ssh/authorized_keys
  chmod 600 /etc/codewire/ssh/authorized_keys
fi

if [ ! -f /etc/codewire/ssh/ssh_host_ed25519_key ]; then
  ssh-keygen -t ed25519 -f /etc/codewire/ssh/ssh_host_ed25519_key -N '' -q
fi

/usr/sbin/sshd -f /etc/ssh/sshd_config -e 2>/dev/null &

exec "$@"
