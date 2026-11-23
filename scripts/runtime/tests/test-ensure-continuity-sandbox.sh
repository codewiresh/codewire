#!/usr/bin/env bash
# scripts/runtime/dev/ensure-continuity-sandbox.sh against a fake cw (#6095):
# it creates the plain continuity Sandbox only when it is missing, starts a
# stopped one, changes nothing that exists, and refuses a same-named Sandbox
# in another shape. It never touches credentials or profiles, which the
# organization-scoped smoke key cannot reach.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ENSURE="$ROOT/scripts/runtime/dev/ensure-continuity-sandbox.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/ensure-continuity-tests.XXXXXX")"
trap 'rm -rf -- "$TEST_TMP"' EXIT

readonly API_KEY="cw_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
readonly NAME=continuity-walk

fail() { printf 'ensure-continuity-sandbox tests: %s\n' "$*" >&2; exit 1; }

# The fake cw keeps the organization's Sandboxes in one JSON file and logs
# each call. Like the organization-scoped smoke key, it refuses anything
# account-global.
mkdir "$TEST_TMP/bin"
cat >"$TEST_TMP/bin/cw" <<'FAKE_CW'
#!/usr/bin/env python3
import json, os, sys
state = os.environ["FAKE_STATE"]
args = sys.argv[1:]
with open(os.path.join(state, "calls"), "a") as log:
    log.write(" ".join(args) + "\n")
if os.environ.get("CODEWIRE_API_KEY", "")[:3] != "cw_" or os.environ.get("CODEWIRE_DEV_SMOKE_API_KEY"):
    sys.exit(90)
if args[0] == "credentials" or any(arg.startswith("--profile") for arg in args):
    print("organization-scoped API key cannot perform account-global operations", file=sys.stderr)
    sys.exit(1)
def load():
    with open(os.path.join(state, "sandboxes.json")) as f:
        return json.load(f)
def save(value):
    with open(os.path.join(state, "sandboxes.json"), "w") as f:
        json.dump(value, f)
fail_step = os.environ.get("FAKE_FAIL", "")
if fail_step and fail_step in " ".join(args):
    sys.exit(1)
if args[:2] == ["--cloud", "ls"]:
    # The real list entry: no idle stop or TTL, which only info shows.
    listed = load()
    if isinstance(listed, list):
        listed = [{key: sandbox[key] for key in ("id", "name", "state", "type")}
                  for sandbox in listed]
    print(json.dumps(listed))
elif args[:2] == ["--cloud", "info"]:
    found = [sandbox for sandbox in load() if sandbox["name"] == args[2]]
    if len(found) != 1:
        sys.exit(1)
    print(json.dumps(found[0]))
elif args[:2] == ["--cloud", "create"]:
    sandboxes = load()
    environment = {"id": "00000000-0000-4000-8000-000000000003", "type": "sandbox",
                   "name": args[args.index("--name") + 1], "state": "pending",
                   "idle_stop_seconds": 0, "ttl_seconds": None}
    sandboxes.append(environment)
    save(sandboxes)
    print(json.dumps(environment))
elif args[:2] == ["--cloud", "start"]:
    sandboxes = load()
    for sandbox in sandboxes:
        if sandbox["name"] == args[2]:
            sandbox["state"] = "starting"
    save(sandboxes)
else:
    sys.exit(91)
FAKE_CW
chmod +x "$TEST_TMP/bin/cw"

reset() { # SANDBOXES: a fresh organization
  rm -rf "$TEST_TMP/state"
  mkdir "$TEST_TMP/state"
  printf '%s' "$1" >"$TEST_TMP/state/sandboxes.json"
  : >"$TEST_TMP/state/calls"
}

ensure() { # [ENV=VALUE...]: one run; output in $TEST_TMP/out
  env -i PATH="/usr/bin:/bin" TMPDIR="$TEST_TMP" FAKE_STATE="$TEST_TMP/state" \
    CW_BIN="$TEST_TMP/bin/cw" CODEWIRE_SERVER_URL=https://codewire-dev.sh \
    CODEWIRE_DEV_SMOKE_API_KEY="$API_KEY" "$@" \
    "$ENSURE" "$NAME" >"$TEST_TMP/out" 2>&1
}

expect_line() { # LINE: the run printed exactly this one line
  [[ "$(cat "$TEST_TMP/out")" == "$1" ]] || fail "expected '$1', got: $(cat "$TEST_TMP/out")"
}

mutations() { grep -cE '^--cloud (create|start)' "$TEST_TMP/state/calls" || true; }

# An organization without it gets one plain Sandbox.
reset '[]'
ensure || fail "a fresh organization failed: $(cat "$TEST_TMP/out")"
expect_line '[pod-continuity] ensure created'
create="$(grep '^--cloud create ' "$TEST_TMP/state/calls")" || fail 'no Sandbox was created'
for flag in "--name $NAME" "--idle-stop off" --no-file --no-profile --no-network --no-wait; do
  [[ " $create " == *" $flag "* ]] || fail "the create lacks $flag: $create"
done
[[ " $create " != *' --ttl '* && " $create " != *' --profile '* ]] ||
  fail "the create set a TTL or a profile: $create"
! grep -q '^credentials ' "$TEST_TMP/state/calls" || fail 'the run touched credentials or profiles'
! grep -qF "$API_KEY" "$TEST_TMP/out" "$TEST_TMP/state/calls" || fail 'the API key reached argv or output'

# Run again: it is present and nothing changes.
ensure || fail "a second run failed: $(cat "$TEST_TMP/out")"
expect_line '[pod-continuity] ensure present'
[[ "$(mutations)" == 1 ]] || fail "a second run changed something: $(cat "$TEST_TMP/state/calls")"

# A stopped Sandbox is started, and nothing else changes.
sed -i 's/"state": "pending"/"state": "stopped"/' "$TEST_TMP/state/sandboxes.json"
ensure || fail "a stopped Sandbox failed: $(cat "$TEST_TMP/out")"
expect_line '[pod-continuity] ensure started'
grep -qxF -- "--cloud start $NAME --output json" "$TEST_TMP/state/calls" || fail 'the Sandbox was not started by name'
[[ "$(mutations)" == 2 ]] || fail "a start changed something else: $(cat "$TEST_TMP/state/calls")"

# A same-named Sandbox in another shape is refused, and nothing is made.
refused() { # REASON SANDBOXES
  local reason="$1"
  reset "$2"
  if ensure; then fail "a run with reason $reason succeeded"; fi
  expect_line "[pod-continuity] ensure refused reason=$reason"
  [[ "$(mutations)" == 0 ]] || fail "a refused run ($reason) changed something: $(cat "$TEST_TMP/state/calls")"
}
sandbox='{"id":"00000000-0000-4000-8000-000000000003","type":"sandbox","name":"continuity-walk","state":"running","idle_stop_seconds":0,"ttl_seconds":null}'
refused sandbox "[${sandbox/\"idle_stop_seconds\":0/\"idle_stop_seconds\":21600}]"
refused sandbox "[${sandbox/\"ttl_seconds\":null/\"ttl_seconds\":7200}]"
refused sandbox "[${sandbox/\"type\":\"sandbox\"/\"type\":\"host\"}]"
refused sandbox-state "[${sandbox/running/error}]"
refused sandbox-list "[$sandbox,$sandbox]"
refused sandbox-list '{}'

# A failed cw call names its step, and nothing after it runs.
reset '[]'
if ensure FAKE_FAIL='--cloud create'; then fail 'a failed create succeeded'; fi
expect_line '[pod-continuity] ensure failed step=create-sandbox'
reset '[]'
if ensure FAKE_FAIL='--cloud ls'; then fail 'a failed list succeeded'; fi
expect_line '[pod-continuity] ensure failed step=list-sandboxes'
[[ "$(mutations)" == 0 ]] || fail 'a failed list went on to create'

# Only Dev, only the smoke key's shape, and only a plain name.
reset '[]'
if ensure CODEWIRE_SERVER_URL=https://codewire.sh; then fail 'another server was accepted'; fi
expect_line '[pod-continuity] ensure refused reason=server'
if ensure CODEWIRE_DEV_SMOKE_API_KEY=not-a-key; then fail 'a malformed key was accepted'; fi
expect_line '[pod-continuity] ensure refused reason=api-key'
[[ ! -s "$TEST_TMP/state/calls" ]] || fail 'a refused input reached cw'

printf 'ensure-continuity-sandbox tests: create, rerun, start, refusals, failures and inputs checked\n'
