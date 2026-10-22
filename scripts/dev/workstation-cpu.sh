#!/usr/bin/env bash
# CPU limits that keep a Linux workstation usable while agents run the
# Codewire dev loop: preflight runs, image builds and Kind on the same cores as
# the owner's desktop. Needs systemd with cgroup v2 and passwordless sudo.
#
#   workstation-cpu.sh status      load, each limit and the CPU each group uses
#   workstation-cpu.sh apply       set the standing limits below
#   workstation-cpu.sh run PID...  move processes, and every child they start
#                                  later, into cwvmtest.slice, then apply
#   workstation-cpu.sh reset       remove every limit this script set
#
# A weight shares CPU only when cores are contended; a ceiling caps a group
# even when cores are idle. The limits are runtime state: a reboot clears them,
# and the next `apply` or `run` sets them again. Change a value here, not with
# a one-off `systemctl set-property`, so every `run` keeps it.
set -euo pipefail

readonly SLICE=cwvmtest.slice
# Preflight runs and local-VM runs started with `run`. The ceiling is the one
# limit on how much CPU they take together (12 of 16 cores); any number of jobs
# may share it, and the desktop weight still wins when the cores are contended.
readonly SLICE_WEIGHT=200 SLICE_CEILING=1200%
# Their memory together: above this the kernel reclaims inside the slice, so
# compiles peaking at link time slow down instead of swapping the whole box.
readonly SLICE_MEMORY_HIGH=88G
# Docker image builders (buildx_buildkit_* containers, one scope each).
readonly BUILDER_CEILING=400%
# Remote login sessions, such as the tmux server background agents run in.
readonly REMOTE_CEILING=300%
# The compositor's session, desktop apps (app.slice) and audio (session.slice)
# outweigh terminals, agents and builds whenever the cores are contended.
# Terminals are left at the default: many of them run agents.
readonly DESKTOP_WEIGHT=1000
# Everything users run, against system.slice (Docker, Kind, services) at 100.
readonly USER_WEIGHT=400
readonly DESKTOP_USER_UNITS="app.slice session.slice"

usage() {
  echo "usage: workstation-cpu.sh status | apply | run PID... | reset" >&2
  exit 2
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    exec sudo -n "$0" "$@"
  fi
  [ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_USER:-}" ] ||
    { echo "workstation-cpu: run it as the workstation user, not as root" >&2; exit 1; }
}

user_systemctl() {
  systemctl --user -M "$SUDO_USER@" "$@"
}

# sessions prints "<scope> <desktop|remote|other>" for each of UID's sessions.
sessions() {
  local id user remote type scope key value
  for id in $(loginctl list-sessions --no-legend | awk '{print $1}'); do
    user="" remote="" type="" scope=""
    while IFS='=' read -r key value; do
      case "$key" in
        User) user="$value" ;;
        Remote) remote="$value" ;;
        Type) type="$value" ;;
        Scope) scope="$value" ;;
      esac
    done < <(loginctl show-session "$id" -p User -p Remote -p Type -p Scope 2>/dev/null)
    [ "$user" = "$1" ] && [ -n "$scope" ] || continue
    case "$type:$remote" in
      wayland:* | x11:*) echo "$scope desktop" ;;
      *:yes) echo "$scope remote" ;;
      *) echo "$scope other" ;;
    esac
  done
}

# builders prints "<scope> <container name>" for each running image builder.
builders() {
  command -v docker >/dev/null || return 0
  docker ps --no-trunc --filter name=buildx_buildkit_ --format '{{.ID}} {{.Names}}' 2>/dev/null |
    while read -r id name; do
      [ -d "/sys/fs/cgroup/system.slice/docker-$id.scope" ] && echo "docker-$id.scope $name"
    done
}

apply() {
  local uid=$1 unit kind
  systemctl set-property --runtime "$SLICE" CPUWeight="$SLICE_WEIGHT" CPUQuota="$SLICE_CEILING" \
    MemoryHigh="$SLICE_MEMORY_HIGH"
  systemctl set-property --runtime user.slice CPUWeight="$USER_WEIGHT"
  systemctl set-property --runtime "user@$uid.service" CPUWeight="$DESKTOP_WEIGHT"
  for unit in $DESKTOP_USER_UNITS; do
    user_systemctl set-property --runtime "$unit" CPUWeight="$DESKTOP_WEIGHT"
  done
  while read -r unit kind; do
    case "$kind" in
      desktop) systemctl set-property --runtime "$unit" CPUWeight="$DESKTOP_WEIGHT" ;;
      remote) systemctl set-property --runtime "$unit" CPUQuota="$REMOTE_CEILING" ;;
    esac
  done < <(sessions "$uid")
  while read -r unit _; do
    systemctl set-property --runtime "$unit" CPUQuota="$BUILDER_CEILING"
  done < <(builders)
}

# clear_cpu DIR SYSTEMCTL... clears the CPUWeight, CPUQuota and MemoryHigh that
# `set-property --runtime` stored in the drop-in directory DIR. Transient units
# (sessions, containers) keep their other drop-ins and drop these with the unit.
clear_cpu() {
  local dir=$1 unit props=() file
  shift
  unit="$(basename "$dir" .d)"
  [ -f "$dir/50-CPUWeight.conf" ] && props+=(CPUWeight=)
  [ -f "$dir/50-CPUQuota.conf" ] && props+=(CPUQuota=)
  [ -f "$dir/50-MemoryHigh.conf" ] && props+=(MemoryHigh=)
  [ "${#props[@]}" -gt 0 ] || return 0
  if [ "$("$@" show -p LoadState --value "$unit")" = loaded ]; then
    "$@" set-property --runtime "$unit" "${props[@]}"
  fi
  case "$dir" in
    */transient/*) ;;
    *)
      for file in 50-CPUWeight.conf 50-CPUQuota.conf 50-MemoryHigh.conf; do rm -f "$dir/$file"; done
      rmdir "$dir" 2>/dev/null || true
      ;;
  esac
}

reset() {
  local uid=$1 dir
  for dir in /run/systemd/system.control/*.d /run/systemd/transient/*.d; do
    [ -d "$dir" ] || continue
    case "$(basename "$dir" .d)" in
      "$SLICE" | codewire-vmtest.slice | user.slice | user-*.slice | user@*.service | session-*.scope | docker-*.scope)
        clear_cpu "$dir" systemctl ;;
    esac
  done
  for dir in "/run/user/$uid/systemd/user.control/"*.d; do
    [ -d "$dir" ] || continue
    case " $DESKTOP_USER_UNITS " in
      *" $(basename "$dir" .d) "*) clear_cpu "$dir" user_systemctl ;;
    esac
  done
}

run() {
  local uid=$1 pid owner
  shift
  [ "$#" -ge 1 ] || usage
  for pid in "$@"; do
    [[ "$pid" =~ ^[0-9]+$ ]] && [ -d "/proc/$pid" ] || { echo "workstation-cpu: no such process $pid" >&2; exit 1; }
    owner="$(stat -c %u "/proc/$pid")"
    [ "$owner" = "$uid" ] || { echo "workstation-cpu: refusing process $pid owned by uid $owner" >&2; exit 1; }
    busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
      StartTransientUnit 'ssa(sv)a(sa(sv))' "codewire-vmtest-$pid-$(date +%s).scope" fail 2 \
      PIDs au 1 "$pid" Slice s "$SLICE" 0 >/dev/null
  done
  apply "$uid"
  echo "moved $* into $SLICE (weight $SLICE_WEIGHT, ceiling $SLICE_CEILING, memory high $SLICE_MEMORY_HIGH)"
}

# ceiling prints a cgroup's cpu.max as a share of one core, or "none".
ceiling() {
  local quota period
  read -r quota period <"$1/cpu.max" 2>/dev/null || { echo -; return; }
  if [ "$quota" = max ]; then echo none; else echo "$((quota * 100 / period))%"; fi
}

usage_usec() {
  awk '$1 == "usage_usec" {print $2}' "$1/cpu.stat" 2>/dev/null || echo 0
}

status() {
  local uid=$1 cg=/sys/fs/cgroup i unit label start end
  local user="$cg/user.slice/user-$uid.slice"
  local -a paths=() names=() labels=() before=()
  add() { paths+=("$1"); names+=("$2"); labels+=("$3"); }
  add "$cg/$SLICE" "$SLICE" "preflight and local-VM runs"
  add "$cg/system.slice" system.slice "Docker, Kind and system services"
  add "$cg/user.slice" user.slice "everything users run"
  add "$user/user@$uid.service" "user@$uid.service" "user services and terminals"
  add "$user/user@$uid.service/app.slice" app.slice "desktop apps"
  add "$user/user@$uid.service/session.slice" session.slice "audio and portals"
  while read -r unit label; do add "$user/$unit" "$unit" "$label session"; done < <(sessions "$uid")
  while read -r unit label; do add "$cg/system.slice/$unit" "docker-${unit:7:12}.scope" "builder $label"; done < <(builders)
  start=$(date +%s%N)
  for i in "${!paths[@]}"; do before[i]=$(usage_usec "${paths[$i]}"); done
  sleep 2
  for i in "${!paths[@]}"; do before[i]=$(($(usage_usec "${paths[$i]}") - before[i])); done
  end=$(date +%s%N)
  read -r load1 load5 load15 _ </proc/loadavg
  printf 'load %s %s %s on %s cores; NOW is CPU over the last 2 s (100%% = one core)\n\n' \
    "$load1" "$load5" "$load15" "$(getconf _NPROCESSORS_ONLN)"
  printf '%-27s %-7s %-8s %-6s %s\n' UNIT WEIGHT CEILING NOW WHAT
  for i in "${!paths[@]}"; do
    if [ ! -d "${paths[$i]}" ]; then
      printf '%-27s %-7s %-8s %-6s %s\n' "${names[$i]}" - - - "${labels[$i]} (none running)"
      continue
    fi
    printf '%-27s %-7s %-8s %-6s %s\n' "${names[$i]}" "$(cat "${paths[$i]}/cpu.weight")" \
      "$(ceiling "${paths[$i]}")" "$((before[i] * 100000 / (end - start)))%" "${labels[$i]}"
  done
}

case "${1:-}" in
  status) status "${SUDO_UID:-$(id -u)}" ;;
  apply) need_root "$@"; apply "$SUDO_UID" ;;
  run) need_root "$@"; shift; run "$SUDO_UID" "$@" ;;
  reset) need_root "$@"; reset "$SUDO_UID" ;;
  *) usage ;;
esac
