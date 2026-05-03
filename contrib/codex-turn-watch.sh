#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $(basename "$0") <session>" >&2
  exit 1
fi

session="$1"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

default_descriptor="$HOME/.codewire/protocols/codex.json"
descriptor="${CW_CODEX_PROTOCOL:-$default_descriptor}"
if [[ ! -f "$descriptor" ]]; then
  descriptor="$script_dir/protocols/codex.json"
fi

cw watch "$session" --output json | python3 "$script_dir/protocol-watch.py" "$descriptor"
