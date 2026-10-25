# shellcheck shell=bash
# shellcheck disable=SC2034 # Readers source this file for the one setting.
#
# What a push to main runs: the one switch that select-verification.sh (CI's
# Kind) and cw-release-dry-run.yaml (the release dry run) both read.
#
# Temporary, by the owner's decision of 2026-10-20: Kind and the release dry
# run take too long to run on every push to main. While this is false, a push
# to main runs neither. Both still run on a dispatched release candidate, on a
# pull request labelled ci-full, and on each workflow's four-hourly schedule
# when its inputs changed. The release tag receipt needs the dry run of the
# exact candidate commit, and its Kind run while RELEASE_REQUIRES_KIND in
# scripts/ci/receipts/verify-release-tag-receipt.sh says so.
#
# Set it back to true, which restores both on every push to main exactly as
# before and leaves the schedules with nothing to run, once all three hold:
#   - #2949 is fixed;
#   - #2970 to #2975 have landed;
#   - the metal CI capacity (infra#1534) is live.
MAIN_PUSH_RUNS_KIND_AND_DRY_RUN=false
