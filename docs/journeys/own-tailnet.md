# Your own tailnet from a cloud sandbox

A user joins their own Tailscale-compatible tailnet from a cloud sandbox and
reaches a private service on it (#5741). The tailnet can be on tailscale.com
or on a self-hosted Headscale. Target, not shipped (#5741): the workspace
image ships `tailscale` and `tailscaled`, and doesn't start them. The user
starts them in userspace mode, so they add no network device, no route and no resolver to the sandbox. The
contract is "A user's own tailnet" in `SPEC.md` "What a workload inside a
sandbox can and cannot do". The auth key is an application secret, as
`docs/dev/SECRETS-AND-CREDENTIALS.md` "Application secrets" says. This
journey was written before the code. The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-23. Written first; every step is not yet observed. #6085 adds
the binaries to the image.

| ID | Dev | Production |
| --- | --- | --- |
| `own-tailnet-binaries` | not yet observed | not yet observed |
| `own-tailnet-join` | not yet observed | not yet observed |
| `own-tailnet-reach` | not yet observed | not yet observed |
| `own-tailnet-relay` | not yet observed | not yet observed |
| `own-tailnet-bad-key` | not yet observed | not yet observed |
| `own-tailnet-leave` | not yet observed | not yet observed |
| `own-tailnet-sandbox-unchanged` | not yet observed | not yet observed |

## Before the walk

- **A walk tailnet and tag.** The sandbox's tag is the trust boundary: its
  ACL admits it only to the target on 443, and to nothing else on the tailnet.
  Either a tailnet of its own, or the maintainers' own tailnet with their
  sandbox tag, whose one rule reaches only the tailnet's front door on 443,
  where every service has its own sign-in. The maintainers hold its control
  URL and how keys are minted.
- **A target.** One HTTPS service the tag reaches, by its tailnet name, with
  an answer that needs no sign-in and is the same every time (on the
  maintainers' front door, the registry's `/v2/` refusal). A target started
  for the walk is removed by name afterwards.
- **An auth key.** One-use, ephemeral, tagged with the sandbox tag, and
  expiring in 10 minutes. Mint it just before the create and store it as an
  application secret:
  `cw secrets --cloud --project=tailnet-walk set TS_AUTHKEY < KEYFILE`, then
  remove the file. Never paste it into a terminal inside the sandbox.
- **The surface.** Walk on Dev as the Dev smoke identity
  (`scripts/runtime/dev/with-dev-smoke-auth.sh -- COMMAND`). Record whether
  hosted egress was on, because `own-tailnet-relay` differs between the two.
- **What to record.** `cw version`, the source the surface was running,
  `tailscale version` in the sandbox, and the tailnet's control software and
  version.

## `own-tailnet-binaries`: the image ships them, not running

- **Driving it:**
  1. `cw --cloud create --name tailnet-walk --secrets tailnet-walk`.
  2. `cw exec --in tailnet-walk -- tailscale version`.
  3. `cw exec --in tailnet-walk -- pgrep -x tailscaled`.
- **Proof:**
  - The version is the one the image pins.
  - No `tailscaled` is running.
  - `ip link` shows no `tailscale0`.

## `own-tailnet-join`: userspace mode, with the key from a file

- **Driving it** (in `cw shell tailnet-walk`):

  ```sh
  umask 077
  findmnt -n -o FSTYPE --target "$XDG_RUNTIME_DIR"   # expect tmpfs
  tailscaled --tun=userspace-networking --state=mem: \
    --socket="$XDG_RUNTIME_DIR/tailscaled.sock" \
    --outbound-http-proxy-listen=127.0.0.1:1056 \
    --socks5-server=127.0.0.1:1055 >"$XDG_RUNTIME_DIR/tailscaled.log" 2>&1 &
  key="$XDG_RUNTIME_DIR/ts.key"
  trap 'rm -f "$key"' EXIT
  printf '%s' "$TS_AUTHKEY" >"$key"
  tailscale --socket="$XDG_RUNTIME_DIR/tailscaled.sock" up \
    --login-server=CONTROL_URL --auth-key="file:$key" \
    --advertise-tags=SANDBOX_TAG --shields-up --accept-routes \
    --hostname=tailnet-walk
  rm -f "$key"
  tailscale --socket="$XDG_RUNTIME_DIR/tailscaled.sock" status
  tailscale --socket="$XDG_RUNTIME_DIR/tailscaled.sock" debug prefs
  ```

- **Proof:**
  - `$XDG_RUNTIME_DIR` is a tmpfs, and the key file is gone after `up`,
    whether `up` succeeded or not.
  - `status` lists this node with the sandbox tag, and the target or the
    subnet router that carries it.
  - The control server lists the node as ephemeral.
  - `tailscaled` runs as the workspace user, not root.
  - The prefs show shields up, no Tailscale SSH, no exit node advertised, no
    routes advertised, and no serve or funnel configuration
    (`tailscale serve status` is empty).
  - The proxy ports listen on 127.0.0.1 only, and no preview publishes them.
  - `ip route` and `/etc/resolv.conf` are byte-for-byte what they were before.
- **Gotchas:**
  - `--state=mem:` keeps the node key in memory only, so a restart of the
    sandbox needs a new key. That is intended. Without it, `tailscaled` keeps
    the node key under `~/.local/share/tailscale`, in the persistent home,
    where snapshots and copies of the home carry it.
  - Under a restrictive policy, the control server and the tailnet's DERP
    hosts must be allowed on 443, and the control server on 80 too, because the
    client may use it.
  - `--accept-routes` lets the userspace stack reach a target behind a subnet
    router, such as a front door. The routes stay inside `tailscaled`; the
    sandbox's route table doesn't change.
  - Check every flag here against `--help` of the version the image pins, and
    correct this file if one differs.

## `own-tailnet-reach`: a tailnet service through the local proxy

- **Driving it:**
  1. `curl -sS --proxy http://127.0.0.1:1056 https://TARGET_NAME/TARGET_PATH`,
     where `TARGET_NAME` is the target's tailnet name and `TARGET_PATH` the
     path of its fixed answer.
  2. The same with `--socks5-hostname 127.0.0.1:1055`.
  3. `curl -sS -m 5 https://TARGET_NAME/TARGET_PATH` with no proxy.
- **Proof:**
  - Steps 1 and 2 return the target's fixed answer. The proxy resolves the
    MagicDNS name, so the sandbox's own resolver never sees it.
  - Step 3 fails: nothing outside the proxy uses the tailnet, so the name
    doesn't resolve, or resolves to an address the sandbox can't reach.

## `own-tailnet-relay`: no direct UDP, still connected

- **Driving it:**
  - `tailscale netcheck`.
  - `tailscale ping TARGET_NAME`.
- **Proof:**
  - Under hosted egress, the default (`SPEC.md`: TCP and DNS only) refuses
    STUN and every direct UDP path. `netcheck` shows no UDP, `ping` answers
    "via DERP", and `own-tailnet-reach` still passes.
  - With hosted egress off, it may answer directly. Record which.

## `own-tailnet-bad-key`: a used, expired or wrong key

- **Driving it:** `tailscale up` again with the key the first join used, then
  with a key minted 11 minutes earlier, then with no key at all.
- **Proof:**
  - Each attempt fails with the control server's own refusal, and no node is
    left registered.
  - With no key, `tailscale up` prints a sign-in URL and waits. Ctrl-C leaves
    nothing registered.

## `own-tailnet-leave`: stop and remove

- **Driving it:**
  1. `tailscale --socket="$XDG_RUNTIME_DIR/tailscaled.sock" logout`.
  2. Kill `tailscaled` by its PID.
  3. `cw --cloud rm tailnet-walk --yes`.
  4. Delete `TS_AUTHKEY`, and any target started for the walk with its node.
- **Proof:**
  - The control server no longer lists the sandbox's node, at once after
    `logout`, or after its ephemeral timeout if the sandbox was removed first.
  - The control server lists no node with the sandbox tag from this walk at
    all, so a leaked key made no second node.
  - The secret project is empty.

## `own-tailnet-sandbox-unchanged`: Codewire's own networking is untouched

- **Driving it**, while joined:
  - `cw exec --in tailnet-walk -- true`
  - `cw shell tailnet-walk`
  - `cw run --in tailnet-walk --name s -- sleep 60` and `cw attach`
  - a preview of a loopback server
  - `cw network connect` to a Mesh member, if the sandbox has one
- **Proof:**
  - Each behaves as it does with no tailnet joined.
  - Under hosted egress, the refusal log shows refusals only for UDP and for
    protected addresses. `tailscaled`'s sends to peers' private endpoints
    appear there, refused. Nothing the environment's policy allows is refused,
    and nothing reaches a protected address.
