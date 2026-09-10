#!/usr/bin/env bash
# Reviewed warning groups that are temporarily owned by other active work.

# shellcheck disable=SC2034 # Consumed by check-shell-scripts.sh after sourcing.
readonly SHELLCHECK_BASELINE_TSV=$'# path\tcode\tcount\treason\n'\
$'scripts/ci/select/select-verification.sh\tSC2221\t2\tactive-resize-selector-owner\n'\
$'scripts/ci/select/select-verification.sh\tSC2222\t2\tactive-resize-selector-owner\n'\
$'scripts/runtime/tests/test-smoke-dev-commodity.sh\tSC1090\t9\tintentional-dynamic-source-fixtures\n'\
$'scripts/runtime/tests/test-smoke-dev-commodity.sh\tSC2034\t12\tstate-consumed-by-sourced-fixtures'
