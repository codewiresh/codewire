#!/usr/bin/env bash
# Shared host temp-capacity preflight for the integrated Kind gate. Source this file.

prepare_kind_temp_runtime() {
  local required_kib=1048576
  local candidate resolved available_kib reason
  local -a candidates

  if [ "${TMPDIR+x}" = x ]; then
    candidates=("$TMPDIR")
  else
    candidates=(/tmp)
    [ -z "${XDG_RUNTIME_DIR:-}" ] || candidates+=("$XDG_RUNTIME_DIR")
    candidates+=(/dev/shm)
  fi

  for candidate in "${candidates[@]}"; do
    reason=""
    if [ ! -d "$candidate" ] || [ ! -w "$candidate" ]; then
      reason="not a writable directory"
    else
      resolved="$(realpath -e "$candidate" 2>/dev/null || true)"
      if [ -z "$resolved" ]; then
        reason="cannot resolve path"
      elif [ "${#resolved}" -gt 48 ]; then
        reason="resolved path is too long for Chromium IPC (${#resolved} > 48)"
      else
        available_kib="$(df -Pk "$resolved" 2>/dev/null | awk 'END { print $4 }' || true)"
        if ! [[ "$available_kib" =~ ^[0-9]+$ ]]; then
          reason="available capacity is unreadable"
        elif [ "$available_kib" -lt "$required_kib" ]; then
          reason="${available_kib} KiB available; ${required_kib} KiB required"
        else
          export TMPDIR="$resolved"
          printf '[kind-host] temp root accepted: path=%s available_kib=%s\n' \
            "$resolved" "$available_kib"
          return 0
        fi
      fi
    fi

    printf '[kind-host] temp root rejected: path=%s reason=%s\n' "$candidate" "$reason" >&2
    if [ "${TMPDIR+x}" = x ]; then
      break
    fi
  done

  echo "::error::no Kind temp root has ${required_kib} KiB available with a Chromium-safe path; set TMPDIR to a suitable short writable directory"
  return 1
}
