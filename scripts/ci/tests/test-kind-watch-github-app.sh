#!/usr/bin/env bash
# Hermetic contract for the GitHub App settings a `make kind-watch` dashboard
# reads once, at start: `dev-loop.sh watch` refuses a real credential-service
# without the App's public values, and every credential-mode switch asks to
# restart a dashboard that was already running. Fake kind, kubectl, ss, curl,
# docker and python3 stand in for the cluster and the watcher.
set -euo pipefail
unset CLUSTER KIND_PROFILE

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
FIXTURE="$(mktemp -d "$ROOT/.tmp/kind-watch-github-app.XXXXXX")"
DASHBOARD_PID=''
cleanup() {
  if [ -n "$DASHBOARD_PID" ]; then
    kill "$DASHBOARD_PID" 2>/dev/null || true
    wait "$DASHBOARD_PID" 2>/dev/null || true
  fi
  rm -rf -- "$FIXTURE"
}
trap cleanup EXIT
BIN="$FIXTURE/bin"
TREE="$FIXTURE/tree"
CALLS="$FIXTURE/calls"
SCRIPT="$TREE/scripts/dev/kind/dev-loop.sh"
# Never the workstation's own watcher port: the fakes answer for this one only.
readonly WATCH_ADDR=127.0.0.1:65182
readonly ORIGIN=http://review.example.test:4174
readonly MISSING_MESSAGE='credential-service is real but the GitHub App public values are missing from codewire-github-app-authorization; rerun make kind-credentials-real'
readonly RESTART_HINT='A make kind-watch dashboard is running from before this switch; restart it (stop it, then make kind-watch) so it reads the GitHub App settings.'

fail() {
  printf '[test-kind-watch-github-app] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$BIN" "$(dirname "$SCRIPT")" "$TREE/scripts/dev" \
  "$TREE/crates/codewire-server-core/src" \
  "$TREE/crates/codewire-orchestration/src/sandbox/template"
cp "$ROOT/scripts/dev/kind/dev-loop.sh" "$SCRIPT"
cp "$ROOT/scripts/dev/kind/profile.sh" "$TREE/scripts/dev/kind/profile.sh"
: >"$TREE/scripts/dev/dashboard-watch.py"
printf 'pub const DEFAULT_WORKSPACE_IMAGE: &str = "registry.example.invalid/codewire/workspace@sha256:%064d";\n' 0 \
  >"$TREE/crates/codewire-server-core/src/runtime_images.rs"
printf 'pub const DEFAULT_DIND_IMAGE: &str = "docker.io/library/docker:29.7.1-dind@sha256:%064d";\n' 1 \
  >"$TREE/crates/codewire-orchestration/src/sandbox/template/mod.rs"

cat >"$BIN/kind" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  'get clusters') printf 'codewire-e2e-ci\n' ;;
  'get nodes --name codewire-e2e-ci') ;;
  *) exit 64 ;;
esac
EOF

# The credential-service command and origin, the review origin and the
# GitHub App Secret's public fields. An unset FAKE_CLIENT_ID or FAKE_SLUG is a
# field the Secret lacks; FAKE_SECRET=absent is no Secret at all.
cat >"$BIN/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'kubectl %s\n' "$*" >>"$FAKE_CALLS"
field() {
  [ "${FAKE_SECRET:-present}" = present ] || exit 1
  [ "${1+x}" = x ] || exit 0
  printf '%s' "$1" | base64
}
case "$*" in
  *' get deployment codewire-credential-service') ;;
  *' get deployment codewire-credential-service -o jsonpath={.spec.template.spec.containers[?(@.name=="credential-service")].command[0]}')
    case "$FAKE_MODE" in
      real) printf /codewire-credential-service ;;
      fake) printf /codewire-kind-fixtures/credential-service ;;
    esac
    ;;
  *'CREDENTIAL_PUBLIC_ORIGIN'*) printf '%s' "$FAKE_CREDENTIAL_ORIGIN" ;;
  *' get configmap codewire-config -o jsonpath={.data.FRONTEND_URL}') printf '%s' "$KIND_PUBLIC_ORIGIN" ;;
  *' get secret codewire-github-app-authorization -o jsonpath={.data.client-id}') field ${FAKE_CLIENT_ID+"$FAKE_CLIENT_ID"} ;;
  *' get secret codewire-github-app-authorization -o jsonpath={.data.slug}') field ${FAKE_SLUG+"$FAKE_SLUG"} ;;
  *) exit 64 ;;
esac
EOF

# FAKE_SS_PID listens on the watcher's port; FAKE_SS_FAIL models a host where
# ss is missing or refuses, as a CI runner may. The restart hint reads the
# listener's process (-p); the watcher only asks whether the port is listening.
cat >"$BIN/ss" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "${FAKE_SS_FAIL:-0}" != 1 ] || exit 1
case "$*" in
  "-Hltnp sport = :${KIND_WATCH_ADDR##*:}") users=' users:(("listener",pid='"${FAKE_SS_PID:-}"',fd=9))' ;;
  "-Hltn sport = :${KIND_WATCH_ADDR##*:}") users='' ;;
  *) exit 64 ;;
esac
[ -z "${FAKE_SS_PID:-}" ] \
  || printf 'LISTEN 0 128 %s 0.0.0.0:*%s\n' "$KIND_WATCH_ADDR" "$users"
EOF

cat >"$BIN/curl" <<'EOF'
#!/usr/bin/env bash
printf 200
EOF

cat >"$BIN/docker" <<'EOF'
#!/usr/bin/env bash
printf 'docker %s\n' "$*" >>"$FAKE_CALLS"
exit 64
EOF

# The watcher the script execs. The App values are synthetic test strings.
cat >"$BIN/python3" <<'EOF'
#!/usr/bin/env bash
printf 'watcher %s client-id=%s slug=%s listen=%s\n' "$*" "${GITHUB_APP_CLIENT_ID-unset}" \
  "${GITHUB_APP_SLUG-unset}" "${CODEWIRE_DASHBOARD_LISTEN_ADDR-unset}" >>"$FAKE_CALLS"
EOF
chmod +x "$BIN"/*

# Credential-mode switches run in their own process, as kind-e2e.sh runs them,
# so errexit applies however this test calls them: credential-mode.sh is
# sourced with every cluster step stubbed.
cat >"$FIXTURE/switch.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
NS=codewire-e2e
KIND_INGRESS_URL=http://127.0.0.1:8090
log() { printf '[kind-e2e] %s\n' "$*"; }
source "$CREDENTIAL_MODE"
require_kind_services_ci_image() { :; }
load_kind_github_app() { [ "${FAKE_LOAD_FAIL:-0}" != 1 ]; }
patch_kind_credential_container() { :; }
set_kind_frontend_url() { :; }
render_kind_credential_fixture_patch() { printf '/dev/null\n'; }
kubectl() {
  case "$*" in
    *'get secret codewire-kind-postgres-root'*) printf 'c3ludGhldGljLXJvb3QK' ;;
  esac
}
kubectl_apply() { :; }
"switch_kind_credentials_$1"
EOF

# run_watch|run_switch [NAME=value...]: extra environment for the fakes.
run_watch() {
  : >"$CALLS"
  env PATH="$BIN:$PATH" KIND_CLUSTER_NAME=codewire-e2e-ci KIND_WATCH_ADDR="$WATCH_ADDR" \
    KIND_PUBLIC_ORIGIN="$ORIGIN" KIND_WATCH_SOURCE_ROOT="$TREE" FAKE_CALLS="$CALLS" \
    FAKE_CREDENTIAL_ORIGIN="$ORIGIN" "$@" "$SCRIPT" watch
}

run_switch() {
  local mode="$1"
  shift
  env PATH="$BIN:$PATH" KIND_WATCH_ADDR="$WATCH_ADDR" KIND_PUBLIC_ORIGIN="$ORIGIN" ROOT="$ROOT" \
    CREDENTIAL_MODE="$ROOT/scripts/ci/verify/kind/credential-mode.sh" "$@" \
    bash "$FIXTURE/switch.sh" "$mode"
}

watcher_calls() {
  grep -c '^watcher ' "$CALLS" || true
}

# A real credential-service without either public value never starts the
# dashboard, and stops before the watch changes the cluster or a node.
refused_case() {
  local label="$1"
  shift
  if run_watch FAKE_MODE=real "$@" >"$FIXTURE/${label}.out" 2>&1; then
    fail "${label}: the watch started without the GitHub App's public values"
  fi
  grep -Fq -- "$MISSING_MESSAGE" "$FIXTURE/${label}.out" \
    || fail "${label}: unexpected failure ($(cat "$FIXTURE/${label}.out"))"
  [ "$(watcher_calls)" = 0 ] || fail "${label}: the watcher ran"
  ! grep -Eq ' (patch|rollout) |^docker ' "$CALLS" || fail "${label}: the cluster was changed"
}
refused_case slug_missing FAKE_CLIENT_ID=Iv1.synthetic
refused_case client_id_missing FAKE_SLUG=codewire-synthetic
refused_case both_empty FAKE_CLIENT_ID= FAKE_SLUG=
refused_case secret_absent FAKE_SECRET=absent FAKE_CLIENT_ID=Iv1.synthetic FAKE_SLUG=codewire-synthetic

# With both values the real watch passes the guard and hands them to the
# dashboard.
run_watch FAKE_MODE=real FAKE_CLIENT_ID=Iv1.synthetic FAKE_SLUG=codewire-synthetic \
  >"$FIXTURE/real.out" 2>&1 || fail "real watch failed: $(cat "$FIXTURE/real.out")"
grep -Fxq "watcher ${TREE}/scripts/dev/dashboard-watch.py client-id=Iv1.synthetic slug=codewire-synthetic listen=${WATCH_ADDR}" \
  "$CALLS" || fail "the real watch did not start the dashboard with the App values"
! grep -q 'WARNING' "$FIXTURE/real.out" || fail "the real watch warned about the fixture"

# The real-mode origin check still comes first.
if run_watch FAKE_MODE=real FAKE_CLIENT_ID=Iv1.synthetic FAKE_SLUG=codewire-synthetic \
  FAKE_CREDENTIAL_ORIGIN=http://other.example.test >"$FIXTURE/origin.out" 2>&1; then
  fail "a real watch with another credential origin started"
fi
grep -Fq 'differs from KIND_PUBLIC_ORIGIN' "$FIXTURE/origin.out" || fail "origin mismatch not reported"
[ "$(watcher_calls)" = 0 ] || fail "a real watch with another credential origin ran the watcher"

# The synthetic fixture needs no App: the watch warns, says to restart it
# after switching, and starts.
run_watch FAKE_MODE=fake FAKE_SECRET=absent >"$FIXTURE/fake.out" 2>&1 \
  || fail "fake watch failed: $(cat "$FIXTURE/fake.out")"
grep -Fq 'Run make kind-credentials-real (needs an OpenBao login), then restart make kind-watch' \
  "$FIXTURE/fake.out" || fail "the fake watch did not explain the restart: $(cat "$FIXTURE/fake.out")"
[ "$(watcher_calls)" = 1 ] || fail "the fake watch did not start the dashboard"

# The stand-in dashboard: the kernel names a script process after its file,
# truncated as it truncates codewire-dashboard-web. It waits on a FIFO it
# holds open itself, so stopping it leaves no child behind.
{
  printf '#!%s\n' "$BASH"
  cat <<'EOF'
exec 3<>"$1"
read -r -t 120 -u 3 _ || true
EOF
} >"$BIN/codewire-dashboard-web"
chmod +x "$BIN/codewire-dashboard-web"
mkfifo "$FIXTURE/dashboard.fifo"
"$BIN/codewire-dashboard-web" "$FIXTURE/dashboard.fifo" &
DASHBOARD_PID=$!
for _ in $(seq 1 50); do
  [ "$(cat "/proc/${DASHBOARD_PID}/comm" 2>/dev/null)" != codewire-dashbo ] || break
  sleep 0.1
done
[ "$(cat "/proc/${DASHBOARD_PID}/comm")" = codewire-dashbo ] \
  || fail "the stand-in dashboard is not named codewire-dashbo"

# A successful switch asks to restart a dashboard on the watcher's port. With
# no listener, a listener that is not the dashboard, or no usable ss (as on a
# CI runner) it says nothing and still succeeds.
for mode in real fake; do
  run_switch "$mode" FAKE_SS_PID="$DASHBOARD_PID" >"$FIXTURE/${mode}-running.out" 2>&1 \
    || fail "${mode} switch with a running dashboard failed: $(cat "$FIXTURE/${mode}-running.out")"
  [ "$(grep -Fxc "[kind-e2e] ${RESTART_HINT}" "$FIXTURE/${mode}-running.out")" = 1 ] \
    || fail "${mode} switch did not ask to restart the running dashboard"
  for listener in none other ss_fails; do
    case "$listener" in
      none) extra=() ;;
      other) extra=("FAKE_SS_PID=$$") ;;
      ss_fails) extra=("FAKE_SS_PID=${DASHBOARD_PID}" FAKE_SS_FAIL=1) ;;
    esac
    run_switch "$mode" "${extra[@]}" >"$FIXTURE/${mode}-${listener}.out" 2>&1 \
      || fail "${mode} switch (${listener}) failed: $(cat "$FIXTURE/${mode}-${listener}.out")"
    ! grep -Fq 'make kind-watch' "$FIXTURE/${mode}-${listener}.out" \
      || fail "${mode} switch (${listener}) printed the restart hint"
  done
done

# A failed switch stops before the hint.
if run_switch real FAKE_SS_PID="$DASHBOARD_PID" FAKE_LOAD_FAIL=1 >"$FIXTURE/failed.out" 2>&1; then
  fail "a switch whose GitHub App copy failed succeeded"
fi
! grep -Fq 'make kind-watch' "$FIXTURE/failed.out" || fail "a failed switch printed the restart hint"

printf '[test-kind-watch-github-app] start-time App guard and credential-switch restart hint passed\n'
