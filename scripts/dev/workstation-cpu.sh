#!/usr/bin/env bash
# CPU limits that keep a Linux workstation usable while agents run the
# Codewire dev loop: preflight runs, image builds and Kind on the same cores as
# the owner's desktop. Needs systemd with cgroup v2 and passwordless sudo.
#
#   workstation-cpu.sh status      load, each limit and the CPU each group uses
#   workstation-cpu.sh apply       set the standing limits below
#   workstation-cpu.sh run PID...  move processes, and every child they start
#                                  later, into cwvmtest.slice, then apply
#   workstation-cpu.sh build [--first] -- COMMAND...
#                                  wait in line for a build slot, then run
#                                  COMMAND in cwvmtest.slice; for compiles and
#                                  test runs. --first takes its place as if it
#                                  had arrived 30 minutes ago: for a check a
#                                  merge or a fix waits on
#   workstation-cpu.sh reset       remove every limit this script set
#
# `build` and `run` refuse to start, with status 75, while the filesystem that
# holds the job's target directory has less than DISK_FLOOR_GB free.
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
# Heavy jobs (compiles, test runs, verification families) that run at once.
# The slice's ceiling caps their cores, not their number: on 2026-11-15 about
# 20 shared it, the load average passed 280 and a push check took 29 to 43
# minutes. With a slot each, a job runs near full speed and the rest queue.
# `build` holds one for its command; `run` takes none, so local VMs and dev
# servers that live for hours never hold up a compile.
readonly BUILD_SLOTS=3
# How far ahead of its arrival a --first build takes its place in the line.
readonly FIRST_AHEAD_SECONDS="${CODEWIRE_CPU_FIRST_AHEAD_SECONDS:-1800}"
# One lock and one holder line per slot, and the log of every job's wait and
# run time; tests point it at a fixture.
BUILD_SLOT_DIR="${CODEWIRE_CPU_SLOT_DIR:-$HOME/.cache/codewire-build-slots}"
# The least free space, in GB, a build or a local VM may start with. On
# 2026-11-15 the workstation's disk filled at about 19:16Z: the 1Password app
# stopped, and with it every SSH push, fetch and kube-access, while builds kept
# starting onto the full disk. Measured on the filesystem that holds the
# build's target directory.
readonly DISK_FLOOR_GB="${CODEWIRE_CPU_DISK_FLOOR_GB:-60}"
# The exit status of a refusal for want of space: try again once it is freed.
readonly DISK_REFUSED=75

usage() {
  # cpu-slice.sh finds `build` by the words "build -- COMMAND"; keep them.
  echo "usage: workstation-cpu.sh status | apply | run PID... | build -- COMMAND... | build --first -- COMMAND... | reset" >&2
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

# disk_check exits with DISK_REFUSED, saying how much is free, when the
# filesystem that holds this job's target directory has less than
# DISK_FLOOR_GB free. A target directory that doesn't exist yet is measured at
# its nearest existing parent. Unreadable free space refuses too: a build
# started blind is what filled the disk.
disk_check() {
  local path="${CODEWIRE_CPU_DISK_PATH:-${CARGO_TARGET_DIR:-$PWD}}" floor free mount
  # A word would count as 0 and switch the floor off.
  case "$DISK_FLOOR_GB" in
    '' | *[!0-9]* | ????????*) floor=bad ;;
    *) floor=$((10#$DISK_FLOOR_GB)) ;;
  esac
  if [ "$floor" = bad ]; then
    echo "codewire-cpu: CODEWIRE_CPU_DISK_FLOOR_GB must be a whole number of GB, at most 7 digits: $DISK_FLOOR_GB" >&2
    exit 2
  fi
  case "$path" in /*) ;; *) path="$PWD/$path" ;; esac
  while [ ! -e "$path" ] && [ "$path" != / ]; do path="$(dirname "$path")"; done
  read -r free mount < <(df -B1G --output=avail,target "$path" 2>/dev/null | tail -n 1) || true
  if ! [[ "${free:-}" =~ ^[0-9]+$ ]]; then
    echo "codewire-cpu: could not read the free space for $path; refusing to start" >&2
    exit "$DISK_REFUSED"
  fi
  [ "$free" -lt "$floor" ] || return 0
  echo "codewire-cpu: only $free GB free on $mount (for $path), below the floor of $floor GB; free space first, for example cargo clean in idle worktrees' target directories, then retry" >&2
  exit "$DISK_REFUSED"
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
  [ "${1:-}" != --in-build ] || shift
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

# A waiter in `build` runs the helpers below with signal traps set, so they
# use no command or process substitution: bash 5.2 parses a substitution's
# text when it runs it, and a trap that runs during that parse fails with
# "unexpected EOF while looking for matching `)'" and exits 2. On 2026-11-16 a
# waiter told to stop with TERM or HUP exited 2 that way in 2 of 120 tries
# under Ubuntu 24.04's bash 5.2.21, and pull request runs went red on it.

# slot_holders_line sets holders_line to each slot's holder, or "free".
slot_holders_line() {
  local slot holder
  holders_line=
  for ((slot = 1; slot <= BUILD_SLOTS; slot++)); do
    { IFS= read -r holder <"$BUILD_SLOT_DIR/$slot.holder"; } 2>/dev/null || holder=
    if [ ! -e "$BUILD_SLOT_DIR/$slot.lock" ] || flock -n "$BUILD_SLOT_DIR/$slot.lock" true 2>/dev/null; then
      holder=free
    fi
    holders_line+="${holders_line:+; }$slot: ${holder:-held}"
  done
}

# slot_holders prints each slot's holder, or "free", on one line.
slot_holders() {
  slot_holders_line
  echo "$holders_line"
}

# process_start PID sets proc_state and proc_start to the process's state and
# its start time (fields 3 and 22 of /proc/PID/stat, read past the command
# name, which may hold spaces and brackets), or to nothing when there is no
# such process.
process_start() {
  local stat
  proc_state='' proc_start=''
  { IFS= read -r stat <"/proc/$1/stat"; } 2>/dev/null || return 0
  # shellcheck disable=SC2086 # split the fields after the command name
  set -- ${stat##*) }
  proc_state="$1" proc_start="${20}"
}

# queue_head sets head to the ticket of the waiter whose turn it is: the oldest
# ticket whose waiter can take a slot. A ticket is named for its arrival time
# and its waiter's process and holds that process's start time, so the names
# sort in arrival order and a reused process ID does not pass for the waiter.
# Only the head may take a slot, so a head that can never take its turn would
# stop every build on the workstation:
# - a ticket whose waiter has gone (killed, or its ID reused) is removed here;
# - a stopped waiter (Ctrl-Z) keeps its ticket and is passed over until it
#   continues.
queue_head() {
  # Not `ticket`: the waiter's EXIT trap removes "$ticket", and a signal handled
  # while this runs would see this function's variable in its place, unset
  # (exit 1 under set -u, the waiter's own ticket left behind) or naming
  # another waiter's ticket, which it would remove (2026-11-16).
  local queued recorded
  head=
  for queued in "$BUILD_SLOT_DIR"/queue/*; do
    [ -e "$queued" ] || continue
    process_start "${queued##*-}"
    { IFS= read -r recorded <"$queued"; } 2>/dev/null || recorded=
    if [ -z "$proc_start" ] || [ "$proc_start" != "$recorded" ]; then
      rm -f "$queued"
      continue
    fi
    [ "$proc_state" != T ] || continue
    head="$queued"
    return
  done
}

# build [--first] COMMAND...: hold one build slot for COMMAND and run it in
# the slice. Waiters are served in arrival order: on 2026-11-15, with 36 jobs
# waiting for 3 slots and each one racing for a freed slot, one job waited 40
# minutes while later arrivals ran. --first takes its place as if it had
# arrived FIRST_AHEAD_SECONDS ago: it passes whoever has waited less than that
# and nobody who has waited longer. Ahead of everyone, it starved the plain
# line: later the same day the head of the line had waited 85 minutes while
# --first builds were most of what was served.
# It waits as long as it takes and says every minute whom it waits for; the
# caller's own timeout bounds it. The slot is this process's lock, so it is
# free again however this process ends, and COMMAND does not inherit it: a
# daemon COMMAND leaves behind (a compiler cache server) can't keep the slot.
# A command started from inside a slot runs in that slot.
build() {
  local first=false
  if [ "${1:-}" = --first ]; then first=true; shift; fi
  [ "${1:-}" != -- ] || shift
  [ "$#" -ge 1 ] || usage
  [ -z "${CODEWIRE_CPU_SLOT:-}" ] || exec "$@"
  local slot fd ticket first_ahead started=$SECONDS waited=0 report=0 ran child status=0 signalled=
  local head proc_state proc_start holders_line waiting queued ended here
  mkdir -p "$BUILD_SLOT_DIR/queue"
  # 19 digits of arrival time, so tickets sort by it.
  ticket="$(date +%s%N)"
  if $first; then
    # A word would count as 0 and a huge number would wrap to a name that
    # sorts ahead of everyone, so the bound is a plain number of seconds, at
    # most a day.
    case "$FIRST_AHEAD_SECONDS" in
      '' | *[!0-9]* | ??????*) first_ahead=bad ;;
      *) first_ahead=$((10#$FIRST_AHEAD_SECONDS)) ;;
    esac
    if [ "$first_ahead" = bad ] || [ "$first_ahead" -gt 86400 ]; then
      echo "codewire-cpu: CODEWIRE_CPU_FIRST_AHEAD_SECONDS must be a number of seconds, at most 86400: $FIRST_AHEAD_SECONDS" >&2
      exit 2
    fi
    ticket=$((ticket - first_ahead * 1000000000))
  fi
  # Once on joining, so a job on a full disk doesn't wait for nothing, and
  # again when served, which may be 40 minutes later. --first is no exception.
  disk_check
  ticket="$(printf '%019d' "$ticket")"
  ticket="$BUILD_SLOT_DIR/queue/$ticket-$$"
  # A waiter that is told to stop takes its ticket with it, and exits with the
  # signal's own status; one that is killed outright leaves its ticket for
  # queue_head to remove.
  # The paths are written into the trap now, so no variable a helper declares
  # later can change what it removes.
  # shellcheck disable=SC2064 # expanded now, on purpose
  trap "rm -f -- $(printf '%q' "$ticket") $(printf '%q' "${ticket%/*}/.${ticket##*/}")" EXIT
  trap 'exit 143' TERM
  trap 'exit 130' INT
  trap 'exit 129' HUP
  while :; do
    # The queue, or this ticket, may have been cleared away while waiting. The
    # ticket appears whole: queue_head removes one whose start time it cannot
    # read, and an empty file would be one. Its draft's name starts with a
    # dot, so queue_head's glob never sees it.
    if [ ! -e "$ticket" ]; then
      mkdir -p "$BUILD_SLOT_DIR/queue"
      process_start "$$"
      echo "$proc_start" >"${ticket%/*}/.${ticket##*/}"
      mv "${ticket%/*}/.${ticket##*/}" "$ticket"
    fi
    queue_head
    if [ "$head" = "$ticket" ]; then
      for ((slot = 1; slot <= BUILD_SLOTS; slot++)); do
        exec {fd}>>"$BUILD_SLOT_DIR/$slot.lock"
        ! flock -n "$fd" || break 2
        exec {fd}>&-
      done
    fi
    waited=$((SECONDS - started))
    if [ "$waited" -ge "$report" ]; then
      waiting=0
      for queued in "$BUILD_SLOT_DIR"/queue/[0-9]*; do
        [ ! -f "$queued" ] || waiting=$((waiting + 1))
      done
      slot_holders_line
      echo "codewire-cpu: waited ${waited}s for one of $BUILD_SLOTS build slots, $waiting in line ($holders_line)" >&2
      report=$((waited + 60))
    fi
    sleep 2
  done
  rm -f "$ticket"
  trap - EXIT TERM INT HUP
  # Refusing here frees the slot: it is this process's lock.
  disk_check
  waited=$((SECONDS - started))
  here="$(pwd -P)"
  printf 'pid %s since %s in %s: %s\n' "$$" "$(date -u +%H:%M:%SZ)" "$here" "$*" \
    >"$BUILD_SLOT_DIR/$slot.holder"
  # Tests keep the fixture out of systemd.
  if [ -z "${CODEWIRE_CPU_SLOT_ONLY:-}" ] && ! grep -q "/$SLICE/" /proc/self/cgroup 2>/dev/null; then
    "$0" run --in-build "$$" >/dev/null || echo "codewire-cpu: could not join $SLICE; running outside it" >&2
  fi
  export CODEWIRE_CPU_SLOT="$slot"
  ran=$SECONDS
  # Without job control bash starts a background command with SIGINT and
  # SIGQUIT ignored, and its children inherit that: a Ctrl-C would stop cargo
  # and leave rustc and the test binaries running after the slot is free.
  env --default-signal=INT,QUIT "$@" <&0 {fd}>&- &
  child=$!
  trap 'signalled=1; kill -TERM "$child" 2>/dev/null' TERM INT HUP
  # Wait first and look afterwards. Bash reaps a command that has ended
  # before this line, and then no process answers `kill -0`, though its status
  # has not been read: looking first reported 0 for a command that failed at
  # once. Only a wait that a forwarded signal cut short comes round again: the
  # interrupted wait did not read the command's status, so the next one
  # returns it, also when the command has ended in between. Nothing here asks
  # whether a process with its PID exists; after a real end that may be a
  # stranger.
  while :; do
    signalled=
    if wait "$child"; then status=0; else status=$?; fi
    [ -n "$signalled" ] || break
  done
  # The forwarding trap is still set here, so no substitution (see above).
  TZ=UTC0 printf -v ended '%(%Y-%m-%dT%H:%M:%SZ)T' -1
  { printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$ended" "$slot" "$waited" \
    "$((SECONDS - ran))" "$status" "$here" "$*" >>"$BUILD_SLOT_DIR/times.tsv"; } 2>/dev/null || true
  exit "$status"
}

# outside_slots UID prints each cargo or verification-family job of UID's that
# runs without a build slot: started with `run`, or with nothing at all.
outside_slots() {
  local pid parent
  for pid in $(pgrep -u "$1" -x 'cargo(-[a-z0-9]+)?' 2>/dev/null; pgrep -u "$1" -f '^bash [^ ]*scripts/ci/local/run-family\.sh ' 2>/dev/null); do
    parent="$(ps -o comm= -p "$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')" 2>/dev/null || true)"
    case "$parent" in cargo | cargo-*) continue ;; esac
    ! tr '\0' '\n' <"/proc/$pid/environ" 2>/dev/null | grep -q '^CODEWIRE_CPU_SLOT=' || continue
    printf '  pid %-8s %s: %s\n' "$pid" "$(readlink "/proc/$pid/cwd" 2>/dev/null || echo '?')" \
      "$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | cut -c1-100)"
  done
}

# ceiling prints a cgroup's cpu.max as a share of one core, or "none".
# Every running buildx daemon and Kind node container, one per line:
# ID<TAB>buildx|kind<TAB>KEY<TAB>NAME<TAB>UP, where KEY is what its owner
# record is named by: the Kind cluster, or the buildx daemon's name.
builder_containers() {
  command -v docker >/dev/null || return 0
  docker ps --no-trunc \
    --format '{{.ID}}	{{.Names}}	{{.RunningFor}}	{{.Label "io.x-k8s.kind.cluster"}}' 2>/dev/null |
    while IFS=$'\t' read -r id name up cluster; do
      if [ -n "$cluster" ]; then
        printf '%s\tkind\t%s\t%s\t%s\n' "$id" "$cluster" "$name" "${up% ago}"
      elif [[ "$name" == buildx_buildkit_* ]]; then
        printf '%s\tbuildx\t%s\t%s\t%s\n' "$id" "${name#buildx_buildkit_}" "$name" "${up% ago}"
      fi
    done
}

# The owner record (scripts/dev/builder-owner.sh) for KIND KEY in DIR: a Kind
# cluster's by its name; a buildx daemon's by the longest builder name its
# node name starts with (buildx names the node BUILDER0, or BUILDER-node).
builder_owner() {
  local dir="$1" kind="$2" key="$3" file best='' base
  [ -d "$dir" ] || return 0
  if [ "$kind" = kind ]; then
    best="$dir/$key"
  else
    for file in "$dir"/*; do
      base="${file##*/}"
      [ -f "$file" ] && [[ "$key" == "$base"* ]] && [ "${#base}" -gt "${#best}" ] && best="$base"
    done
    [ -n "$best" ] && best="$dir/$best"
  fi
  [ -n "$best" ] && [ -f "$best" ] || return 0
  awk -F= '$1 == "owner" && $2 != "" {o=$2} $1 == "task" {t=$2}
    END {if (o != "") printf "%s (%s)", o, t; else if (t != "") printf "task %s", t}' "$best"
}

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
  local -a b_rows=() b_used=()
  local row
  while IFS= read -r row; do b_rows+=("$row"); done < <(builder_containers)
  start=$(date +%s%N)
  for i in "${!paths[@]}"; do before[i]=$(usage_usec "${paths[$i]}"); done
  for i in "${!b_rows[@]}"; do b_used[i]=$(usage_usec "$cg/system.slice/docker-${b_rows[$i]%%$'\t'*}.scope"); done
  sleep 2
  for i in "${!paths[@]}"; do before[i]=$(($(usage_usec "${paths[$i]}") - before[i])); done
  for i in "${!b_rows[@]}"; do
    b_used[i]=$(($(usage_usec "$cg/system.slice/docker-${b_rows[$i]%%$'\t'*}.scope") - b_used[i]))
  done
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
  printf '\nbuild slots (%s): %s\n' "$BUILD_SLOTS" "$(slot_holders)"
  printf 'waiting in line: %s\n' "$(find "$BUILD_SLOT_DIR/queue" -type f -name '[0-9]*' 2>/dev/null | wc -l)"
  label="$(outside_slots "$uid")"
  if [ -n "$label" ]; then
    printf 'heavy jobs outside a build slot (start them with `build --`):\n%s\n' "$label"
  else
    printf 'no cargo or verification-family job runs outside a build slot\n'
  fi
  builder_status "$uid" "$((end - start))"
}

# The buildx daemons and Kind nodes, each with its CPU over the sample above,
# its memory and its recorded owner. A buildx daemon is idle under 1% of a
# core; a Kind node never is by CPU (its control plane runs Kubernetes, about
# 4-25% of a core at rest), so its age stands beside it instead. Each session
# removes only its own: `kind delete cluster --name CLUSTER`, or
# `docker buildx rm BUILDER`; nobody removes another's.
builder_status() {
  local uid="$1" span="$2" dir i id kind key name up now mem owner state idle=0
  dir="$(getent passwd "$uid" | cut -d: -f6)/.cache/codewire-builders"
  if [ "${#b_rows[@]}" -eq 0 ]; then
    printf '\nno buildx or Kind node container is running\n'
    return 0
  fi
  printf '\nbuilder containers (NOW over the same 2 s; remove only your own):\n'
  printf '%-6s %-5s %-12s %-5s %-7s %-28s %s\n' KIND STATE UP NOW MEMORY OWNER NAME
  for i in "${!b_rows[@]}"; do
    IFS=$'\t' read -r id kind key name up <<<"${b_rows[$i]}"
    now=$((b_used[i] * 100000 / span))
    mem="$(awk '{printf "%.0fM", $1 / 1048576}' "/sys/fs/cgroup/system.slice/docker-$id.scope/memory.current" 2>/dev/null)"
    owner="$(builder_owner "$dir" "$kind" "$key")"
    if [ "$kind" = kind ]; then
      state=up
    elif [ "$now" -lt 1 ]; then
      state=idle idle=$((idle + 1))
    else
      state=busy
    fi
    printf '%-6s %-5s %-12s %-5s %-7s %-28s %s\n' "$kind" "$state" "$up" "$now%" "${mem:--}" \
      "${owner:-not recorded}" "$name"
  done
  printf '%s idle buildx daemon(s). Remove only your own: docker buildx rm BUILDER, or kind delete cluster --name CLUSTER.\n' \
    "$idle"
}

case "${1:-}" in
  status) status "${SUDO_UID:-$(id -u)}" ;;
  apply) need_root "$@"; apply "$SUDO_UID" ;;
  # Checked once, before sudo, as the user with the user's environment: the
  # sudo re-run strips CODEWIRE_CPU_DISK_FLOOR_GB and CARGO_TARGET_DIR, so it
  # must not check again. build has just checked for its own.
  run) [ "${2:-}" = --in-build ] || [ "$(id -u)" -eq 0 ] || disk_check; need_root "$@"; shift; run "$SUDO_UID" "$@" ;;
  build) shift; build "$@" ;;
  reset) need_root "$@"; reset "$SUDO_UID" ;;
  *) usage ;;
esac
