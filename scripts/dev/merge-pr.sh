#!/usr/bin/env bash
# Supply public-safe merge metadata explicitly; CLI defaults may contain URLs.
set -euo pipefail

if [[ $# == 1 && ( "$1" == --help || "$1" == -h ) ]]; then
  printf 'usage: scripts/dev/merge-pr.sh PR_NUMBER "COMMIT TITLE"\n'
  exit 0
fi
if [[ $# != 2 || ! "$1" =~ ^[1-9][0-9]*$ || -z "$2" || "$2" == *$'\n'* || "$2" == *$'\r'* || "$2" == *'Reviewed-on:'* ]]; then
  printf 'usage: scripts/dev/merge-pr.sh PR_NUMBER "COMMIT TITLE"\n' >&2
  exit 2
fi
pr="$1" title="$2"
[[ "$title" == *" (#$pr)" ]] || title="$title (#$pr)"
exec fj pr -R origin merge "$pr" -M squash -t "$title" -m "Reviewed-on: #$pr"
