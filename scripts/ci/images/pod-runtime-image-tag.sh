#!/usr/bin/env bash
# The standard pod-runtime image's tags in Harbor (#5602), exactly as
# egress-image-tag.sh keeps cw-egress's: Dev delivery builds and signs the
# image but never delivers it, and keys it by the planner's pod_runtime_image
# fingerprint. The same commands and the same rules apply.
set -euo pipefail
CODEWIRE_SIGNED_IMAGE_REPOSITORY=codewire/pod-runtime \
  exec "$(dirname "${BASH_SOURCE[0]}")/egress-image-tag.sh" "$@"
