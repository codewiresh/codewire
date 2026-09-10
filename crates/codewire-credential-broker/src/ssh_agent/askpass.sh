#!/bin/sh
# Fixed broker-installed helper. The value exists only in the FIFO and the
# ssh-add-owned askpass stdout pipe; neither the prompt nor value is logged.
set -eu
exec /bin/cat -- "${CODEWIRE_SSH_ASKPASS_FIFO:?}"
