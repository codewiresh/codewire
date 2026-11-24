#!/usr/bin/env bash
# The /dev/kvm device plugin image's tags in Harbor (#6202), exactly as
# egress-image-tag.sh keeps cw-egress's: Dev delivery builds and signs the
# image but never delivers it, and keys it by the planner's
# kvm_device_plugin_image fingerprint. The same commands and the same rules
# apply.
set -euo pipefail
CODEWIRE_SIGNED_IMAGE_REPOSITORY=codewire/kvm-device-plugin \
  exec "$(dirname "${BASH_SOURCE[0]}")/egress-image-tag.sh" "$@"
