#!/usr/bin/env bash
# The Orca and herdr plugins' own tests (integrations/), which run their
# scripts against stub cw, ssh and herdr. Selected with the CI-script tests
# when integrations/ changes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
"$ROOT/integrations/orca/tests/test-recipes.sh"
"$ROOT/integrations/herdr/tests/test-plugin.sh"
