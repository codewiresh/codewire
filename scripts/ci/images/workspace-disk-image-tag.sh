#!/usr/bin/env bash
# The standard workspace disk's tags in Harbor (#5602), exactly as
# egress-image-tag.sh keeps cw-egress's: Dev delivery builds and signs the
# disk but never delivers it, and keys it by the planner's
# workspace_disk_image fingerprint. The same commands and the same rules
# apply.
set -euo pipefail
CODEWIRE_SIGNED_IMAGE_REPOSITORY=codewire/workspace-disk \
  exec "$(dirname "${BASH_SOURCE[0]}")/egress-image-tag.sh" "$@"
