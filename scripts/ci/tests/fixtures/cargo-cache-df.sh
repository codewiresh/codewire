#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  -Pk)
    printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
    printf 'fixture 8388608 0 __AVAILABLE_KIB__ 0%% /fixture\n'
    ;;
  -Pi)
    printf 'Filesystem Inodes IUsed IFree IUse%% Mounted on\n'
    printf 'fixture 40000 0 __AVAILABLE_INODES__ 0%% /fixture\n'
    ;;
  *)
    printf 'unexpected df arguments\n' >&2
    exit 2
    ;;
esac
