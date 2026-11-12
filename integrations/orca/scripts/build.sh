#!/usr/bin/env bash
# Builds recipes/<placement>.json, the files Orca reads, from src/: each step is
# `placement=...`, src/common.sh and the step's script, as one shell string.
# Usage: scripts/build.sh [--check]   (--check fails when a recipe is stale)
set -euo pipefail
cd "$(dirname "$0")/.."

check="${1:-}"
case "$check" in "" | --check) ;; *) echo "usage: $0 [--check]" >&2; exit 2 ;; esac
stale=0

# Each source starts with a ShellCheck directive for the file alone, dropped
# here; tests/test-recipes.sh checks each step whole.
step() { # placement script
  printf 'placement=%s\n' "$1"
  awk 'FNR > 1 || !/^# shellcheck /' src/common.sh src/"$2"
}

recipe() { # placement name description
  jq -n --arg id "codewire-$1" --arg name "$2" --arg description "$3" \
    --arg create "$(step "$1" "create-$1.sh")" \
    --arg suspend "$(step "$1" suspend.sh)" \
    --arg resume "$(step "$1" resume.sh)" \
    --arg destroy "$(step "$1" destroy.sh)" \
    '{schemaVersion: 1, $id, $name, $description, $create, $suspend, $resume, $destroy}'
}

emit() { # placement name description
  local out="recipes/$1.json"
  if [ "$check" = --check ]; then
    if ! diff -q <(recipe "$@") "$out" >/dev/null 2>&1; then
      echo "stale: integrations/orca/$out (run integrations/orca/scripts/build.sh)" >&2
      stale=1
    fi
  else
    recipe "$@" >"$out"
    echo "wrote $out"
  fi
}

emit local "Codewire local VM" \
  "A Codewire VM on this computer, cloned from the project's committed state, with no host mounts."
emit cloud "Codewire cloud sandbox" \
  "A Codewire cloud sandbox in your current organization, cloned from the project's origin."

exit "$stale"
