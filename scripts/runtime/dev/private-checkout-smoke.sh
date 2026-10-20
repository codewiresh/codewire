#!/usr/bin/env bash
# Sourced by the isolated Linux/platform entrypoint. Only the selected SSH
# PUBLIC key reaches the host fixture; private signing stays on the platform.
# shellcheck disable=SC2034 # Shared state is owned by the parent entrypoint.
LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN="${LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN:-}"
CHECKOUT_FIXTURE_PID=''
CHECKOUT_FIXTURE_DIR=''

validate_private_checkout_options() {
  if [[ "$LP_INITIAL_PRIVATE_CHECKOUT" == 0 ]]; then
    [[ -z "$LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN" ]] || die 'checkout fixture requires --initial-private-checkout'
    return
  fi
  [[ -z "$LOCAL_PLATFORM_NETWORK_ID" && "$LOCAL_PLATFORM_DISPOSABLE_NETWORK" == 0 &&
     -z "$LOCAL_PLATFORM_MESH_PROBE_BIN" ]] || die 'initial checkout uses the host loopback fixture, not a Mesh network'
  [[ "$LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN" == /* &&
     "$(realpath -e -- "$LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN")" == "$LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN" &&
     -f "$LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN" && -x "$LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN" &&
     ! -L "$LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN" ]] || die 'initial checkout requires a canonical prebuilt fixture executable'
}

private_checkout_json() {
  local name="$1" file="$CHECKOUT_FIXTURE_DIR/$1.json"
  [[ "$name" == ready || "$name" == counter || "$name" == finish ]] || return 1
  [[ -f "$file" && ! -L "$file" && "$(stat -c '%u:%a' "$file")" == "$(id -u):600" &&
     "$(stat -c %s "$file")" -le 16384 ]] || return 1
  jq -e 'type == "object" and .version == 1' "$file" >/dev/null
}

private_checkout_alive() {
  [[ -n "$CHECKOUT_FIXTURE_PID" ]] && jobs -pr | grep -qx "$CHECKOUT_FIXTURE_PID"
}

private_checkout_ready() {
  private_checkout_alive && private_checkout_json ready && private_checkout_json counter
}

private_checkout_start() {
  CHECKOUT_FIXTURE_DIR="$LP_RUNTIME/checkout-fixture"
  jq -er '.[0].sshPublicKey.openssh' "$TMPDIR_SMOKE/provider-ssh-credential.json" \
    >"$LP_RUNTIME/checkout-selected.pub"
  env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
    "$LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN" --public-key-file "$LP_RUNTIME/checkout-selected.pub" \
      --output-dir "$CHECKOUT_FIXTURE_DIR" --timeout-seconds 1800 \
      >"$TMPDIR_SMOKE/checkout-fixture.out" 2>"$TMPDIR_SMOKE/checkout-fixture.err" &
  CHECKOUT_FIXTURE_PID=$!
  wait_until 'initial-checkout fixture readiness' "$(( $(seconds_now) + 20 ))" private_checkout_ready
  private_checkout_validate_metadata || die 'initial-checkout fixture metadata drifted'
}

private_checkout_validate_metadata() {
  # Treat fixture metadata as input, not shell code. Only a fixed public URL,
  # content and matching host pin can enter the product document.
  jq -e '
    (.url | capture(":(?<port>[0-9]+)/repository[.]git$").port | tonumber) as $port |
    (keys == ["content","content_path","known_hosts","revision","url","version"]) and
    .content_path == "proof.txt" and .content == "initial-private-checkout-synthetic-v1" and
    (.revision | type == "string" and test("^[0-9a-f]{40}$")) and
    (.url | type == "string" and test("^ssh://synthetic@127[.]0[.]0[.]1:[0-9]+/repository[.]git$")) and
    $port > 0 and $port <= 65535 and
    (.known_hosts | type == "array" and length == 1) and
    (.known_hosts[0] | startswith("[127.0.0.1]:" + ($port|tostring) + " ssh-ed25519 ")) and
    (.known_hosts[0] | test("^\\[127[.]0[.]0[.]1\\]:[0-9]+ ssh-ed25519 [A-Za-z0-9+/]+={0,2}$"))
  ' "$CHECKOUT_FIXTURE_DIR/ready.json" >/dev/null
}

private_checkout_stop() {
  [[ -n "$CHECKOUT_FIXTURE_PID" ]] || return 0
  local rc=0 attempt
  if private_checkout_alive; then
    kill -TERM "$CHECKOUT_FIXTURE_PID" || rc=1
    for ((attempt=0; attempt<450; attempt++)); do
      private_checkout_alive || break
      sleep 0.1
    done
    if private_checkout_alive; then
      kill -KILL "$CHECKOUT_FIXTURE_PID" || true
      rc=1
    fi
  else
    # An early exit is a fixture failure, even if it left a success-shaped
    # receipt. Only this owner may end the target after the product proof.
    rc=1
  fi
  wait "$CHECKOUT_FIXTURE_PID" || rc=1
  CHECKOUT_FIXTURE_PID=''
  private_checkout_json finish &&
    jq -e '.drained == true and
      (keys == ["authenticated","denied","drained","unsupported_commands","version"])' \
      "$CHECKOUT_FIXTURE_DIR/finish.json" >/dev/null || rc=1
  return "$rc"
}

private_checkout_count() {
  private_checkout_alive && private_checkout_json counter || return 1
  jq -er 'select(keys == ["authenticated","denied","unsupported_commands","version"]) |
    select([.authenticated,.denied,.unsupported_commands] | all(.[]; type == "number" and . >= 0 and . == floor)) |
    .authenticated' \
    "$CHECKOUT_FIXTURE_DIR/counter.json"
}

private_checkout_create() {
  local document="$1" phase="$2" duration="$3"
  local filename="${document##*/}"
  [[ "$LP_WORKSPACE" == /* && "$document" == "$LP_WORKSPACE/$filename" &&
     -f "$document" && ! -L "$document" &&
     "$(realpath -e -- "$document")" == "$document" ]] ||
    die 'initial-checkout document must be a regular file directly inside the owned workspace'
  # Native --file resolves beneath the default --path (the current directory).
  # Keep attempted-create state in the owner, even if the CLI reply is lost.
  LP_CREATE_ATTEMPTED=1
  (
    cd -- "$LP_WORKSPACE" || exit 1
    cw_with_timeout "$duration" create --local --name "$SMOKE_NAME" --cpu 2 --memory 16GB \
      --no-docker --no-network --file "$filename" --yes --output json
  ) \
    >"$TMPDIR_SMOKE/checkout-$phase.json" 2>"$TMPDIR_SMOKE/checkout-$phase.err"
}

private_checkout_reject() {
  local document="$1" phase="$2" reason="$3"
  if private_checkout_create "$document" "$phase" 90; then
    die 'invalid initial-checkout configuration was accepted'
  fi
  grep -Fq -- "$reason" "$TMPDIR_SMOKE/checkout-$phase.err" ||
    die 'initial checkout failed outside the expected validation boundary'
  [[ "$(private_checkout_count)" == 0 ]] || die 'invalid initial checkout authenticated to the fixture'
  cw_with_timeout 30 ls --local --output json >"$TMPDIR_SMOKE/checkout-rejected-inventory.json" ||
    die 'cannot inspect the rejected initial checkout'
  jq -e --arg name "$SMOKE_NAME" 'type == "array" and all(.[]; .name != $name or .state != "running")' \
    "$TMPDIR_SMOKE/checkout-rejected-inventory.json" >/dev/null || die 'rejected checkout started a VM'
  local_platform_cleanup_environment || die 'rejected initial checkout cleanup failed'
  LP_CREATE_ATTEMPTED=0
  ENV_ID=''
}

private_checkout_journey() {
  SMOKE_NAME="local-checkout-$(tr -d '-' </proc/sys/kernel/random/uuid)"
  cw_with_timeout 30 ls --local --output json >"$TMPDIR_SMOKE/checkout-before.json"
  jq -e --arg name "$SMOKE_NAME" 'type == "array" and all(.[]; .name != $name)' \
    "$TMPDIR_SMOKE/checkout-before.json" >/dev/null || die 'initial-checkout environment name collision'
  prepare_provider_ssh_identity
  private_checkout_start
  local revision install
  revision="$(jq -er .revision "$CHECKOUT_FIXTURE_DIR/ready.json")"
  install="set -eu; cd /workspace/private-checkout; test \"\$(git rev-parse HEAD)\" = '$revision'; test \"\$(cat proof.txt)\" = initial-private-checkout-synthetic-v1; test ! -e .install-proved; printf '%s\\n' initial-private-checkout-before-install > .install-proved"
  jq -n --slurpfile fixture "$CHECKOUT_FIXTURE_DIR/ready.json" --arg image "$LOCAL_PLATFORM_IMAGE" \
    --arg profile "platform:id:$PROVIDER_SSH_PROFILE_ID" --arg install "$install" '
    {version:1,image:$image,working_directory:"/workspace/private-checkout",credentials:{profile:$profile},
     repositories:[{source:$fixture[0].url,revision:$fixture[0].revision,
       known_hosts:$fixture[0].known_hosts,destination:"/workspace/private-checkout"}],
     install_command:$install}
  ' >"$LP_WORKSPACE/codewire.yaml"
  jq 'del(.credentials)' "$LP_WORKSPACE/codewire.yaml" >"$LP_WORKSPACE/unselected.json"
  private_checkout_reject "$LP_WORKSPACE/unselected.json" unselected \
    'SSH repository checkout requires a selected credential profile'
  jq '.repositories[0].known_hosts=[]' "$LP_WORKSPACE/codewire.yaml" >"$LP_WORKSPACE/untrusted.json"
  private_checkout_reject "$LP_WORKSPACE/untrusted.json" untrusted \
    'must pin at least one SSH host key'
  private_checkout_create "$LP_WORKSPACE/codewire.yaml" created 1500 || die 'initial private checkout failed during normal local create'
  ENV_ID="$(jq -er '.id | select(. != "00000000-0000-0000-0000-000000000000" and
    test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))' "$TMPDIR_SMOKE/checkout-created.json")"
  [[ "$(private_checkout_count)" -gt 0 ]] || die 'initial private checkout did not authenticate with the selected platform key'
  cw_with_timeout 30 use --local "$ENV_ID" >"$TMPDIR_SMOKE/checkout-use.out"
  local_platform_binding '' 0 || die 'initial-checkout credential/profile placement binding drifted'
  cw_with_timeout 60 run --no-tty -- /bin/sh -c \
    "set -eu; cd /workspace/private-checkout; test \"\$(git rev-parse HEAD)\" = '$revision'; test \"\$(cat proof.txt)\" = initial-private-checkout-synthetic-v1; test \"\$(cat .install-proved)\" = initial-private-checkout-before-install; printf '%s\\n' initial-private-checkout-proved" \
    >"$TMPDIR_SMOKE/checkout-proof.out" 2>"$TMPDIR_SMOKE/checkout-proof.err" ||
    die 'initial checkout was not available before install and managed execution'
  grep -qx initial-private-checkout-proved "$TMPDIR_SMOKE/checkout-proof.out" || die 'initial checkout receipt is missing'
}
