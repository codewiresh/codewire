#!/usr/bin/env bash

# Protected delivery jobs have a 110-minute outer bound. Reserve one hour for
# the repository-owned Nexus maintenance window while leaving the rest of the
# job for the exact build, immutable copy, and Deploy dispatch.
# shellcheck disable=SC2034 # These constants are consumed by sourcing builders.
readonly NEXUS_BACKUP_RETRY_ATTEMPTS=61
readonly NEXUS_BACKUP_RETRY_DELAY_SECONDS=60
