# Your own tailnet from a cloud sandbox

A user joins their own Tailscale-compatible tailnet from a cloud sandbox and
reaches a private service on it (#5741). The tailnet can be on tailscale.com
or on a self-hosted Headscale. The workspace image ships `tailscale` and
`tailscaled` (#6085) and doesn't start them. The user starts them in userspace
mode, so they add no network device, no route and no resolver to the sandbox.
The contract is "A user's own tailnet" in `SPEC.md` "What a workload inside a
sandbox can and cannot do". The auth key is an application secret, as
`docs/dev/SECRETS-AND-CREDENTIALS.md` "Application secrets" says. This
journey was written before the code. The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-23. Walked on Dev on 2026-11-23 against a Headscale tailnet,
with hosted egress on (#5741 comment 135387). The walk corrected the join: a
cloud sandbox has no `$XDG_RUNTIME_DIR`, `tailscaled` needs its own session,
and a tagged key carries its tag. A second walk the same day (#6167 comment
135831) reached the target by its tailnet name, once the control server
published its DNS records without a type, and walked an expired key and
Codewire's own networking while joined. Not yet observed: `cw network
connect` while joined, the refusal log, tailscale.com, and Production.

| ID | Dev | Production |
| --- | --- | --- |
| `own-tailnet-binaries` | observed 2026-11-23 | not yet observed |
| `own-tailnet-join` | observed 2026-11-23 | not yet observed |
| `own-tailnet-reach` | observed 2026-11-23 | not yet observed |
| `own-tailnet-relay` | observed 2026-11-23, under hosted egress | not yet observed |
| `own-tailnet-bad-key` | observed 2026-11-23 | not yet observed |
| `own-tailnet-leave` | observed 2026-11-23 | not yet observed |
| `own-tailnet-sandbox-unchanged` | observed 2026-11-23, but `cw network connect` and the refusal log | not yet observed |

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
- **Gotchas:**
  - Outside a terminal, `create` asks for `--yes` ("Source selection requires
    --yes for noninteractive or JSON commands") and creates nothing.
- **Observed:** 2026-11-23 on Dev, services from source 5221bbc23e, `cw`
  v0.4.26, as the Dev smoke identity (#5741 comment 135387). `tailscale
  version` and `tailscaled --version` gave 1.104.7 (go1.27.4), `pgrep`
  exited 1, and the links were `lo`, `eth0`, `cwegress0` and `docker0`.

## `own-tailnet-join`: userspace mode, with the key from a file

- **Driving it:**
  1. A private directory on tmpfs, in `cw shell tailnet-walk`:
     `mkdir -m 700 /dev/shm/tailnet-walk`, then
     `findmnt -n -o FSTYPE --target /dev/shm/tailnet-walk` (expect `tmpfs`).
  2. `tailscaled` in its own session:

     ```sh
     cw run --in tailnet-walk --name tailscaled --detach -- \
       tailscaled --tun=userspace-networking --state=mem: \
       --socket=/dev/shm/tailnet-walk/tailscaled.sock \
       --outbound-http-proxy-listen=127.0.0.1:1056 \
       --socks5-server=127.0.0.1:1055
     ```

  3. The join, in `cw shell tailnet-walk`:

     ```sh
     umask 077
     R=/dev/shm/tailnet-walk
     key="$R/ts.key"
     trap 'rm -f "$key"' EXIT
     printf '%s' "$TS_AUTHKEY" >"$key"
     tailscale --socket="$R/tailscaled.sock" up \
       --login-server=CONTROL_URL --auth-key="file:$key" \
       --shields-up --accept-routes --hostname=tailnet-walk
     rm -f "$key"
     tailscale --socket="$R/tailscaled.sock" status
     tailscale --socket="$R/tailscaled.sock" debug prefs
     ```

- **Proof:**
  - The directory is a tmpfs, and the key file is gone after `up`, whether
    `up` succeeded or not.
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
  - A cloud sandbox has no `$XDG_RUNTIME_DIR`. A path built on it falls back
    to `/`, where the key file and the socket can't be written. `/dev/shm` is
    the sandbox's tmpfs; `/tmp` is on disk.
  - A process started with `&` ends with its session (`cw run --help`), so
    `tailscaled` runs in a session of its own.
  - A tagged key applies its own tag. Don't pass `--advertise-tags`: Headscale
    refuses a tag the key's user doesn't own ("requested tags [...] are invalid
    or not permitted").
  - After a failed `up`, the next `up` needs `--reset`, or it refuses until
    every earlier flag is repeated.
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
    correct this file if one differs. Checked against 1.104.7.
- **Observed:** 2026-11-23 on Dev, services from source 5221bbc23e, `cw`
  v0.4.26, as the Dev smoke identity, against Headscale, with the commands
  above (#5741 comment 135387). Earlier attempts in the same walk failed on
  the `$XDG_RUNTIME_DIR`, tag and `--reset` gotchas, each with nothing
  written. `up` exited 0. `status` listed the node
  with the sandbox tag and the subnet router online. Headscale listed it with
  the tag, from an ephemeral key now used. The prefs showed `ShieldsUp: true`,
  `RunSSH: false`, `RouteAll: true` and nothing advertised; there was no serve
  config. `tailscaled` ran as `codewire`, 1055 and 1056 listened on 127.0.0.1
  only, and the hashes of `ip route` and `/etc/resolv.conf` matched those
  from before the join. The key file was gone after every `up`.

## `own-tailnet-reach`: a tailnet service through the local proxy

- **Driving it:**
  1. `curl -sS --proxy http://127.0.0.1:1056 https://TARGET_NAME/TARGET_PATH`,
     where `TARGET_NAME` is the target's tailnet name and `TARGET_PATH` the
     path of its fixed answer.
  2. The same with `--socks5-hostname 127.0.0.1:1055`.
  3. `curl -sS -m 5 https://TARGET_NAME/TARGET_PATH` with no proxy.
- **Proof:**
  - Steps 1 and 2 return the target's fixed answer. The proxy resolves the
    tailnet name, so the sandbox's own resolver never sees it.
  - Step 3 fails: nothing outside the proxy uses the tailnet, so the name
    doesn't resolve, or resolves to an address the sandbox can't reach.
- **Gotchas:**
  - `tailscaled`'s proxies (checked against 1.104.7) skip a DNS record the
    control server sends with a type, and the SOCKS5 lookup then falls
    through to the sandbox's resolver (#6167). `tailscale dns query
    TARGET_NAME A` answers either way, so it doesn't show the difference. A
    Headscale `dns.extra_records` entry needs only `name` and `value`; leave
    out `type`. Until the control server changes,
    `curl --proxy http://127.0.0.1:1056 --connect-to TARGET_NAME:443:ADDRESS:443 https://TARGET_NAME/TARGET_PATH`
    reaches the target with the name kept for TLS.
- **Observed:** 2026-11-23 on Dev, twice.
  - First walk (#5741 comment 135387): the control server's records had a
    type. By name, step 1 failed with "CONNECT tunnel failed, response 500"
    and step 2 with "Can't complete SOCKS5 connection".
  - Also in the first walk: by address, with the name kept for TLS, the HTTP
    proxy (`--connect-to`) and SOCKS5 (`--resolve`) both returned the
    registry's fixed `401` refusal.
  - Second walk (#6167 comment 135831), with records without a type: steps 1
    and 2 both returned the registry's fixed `401` refusal by name.
  - In both walks, step 3 failed with "Could not resolve host".

## `own-tailnet-relay`: no direct UDP, still connected

- **Driving it:**
  - `tailscale netcheck`.
  - `tailscale ping TARGET_NAME`.
- **Proof:**
  - Under hosted egress, the default (`SPEC.md`: TCP and DNS only) refuses
    STUN and every direct UDP path. `netcheck` shows no UDP, `ping` answers
    "via DERP", and `own-tailnet-reach` still passes.
  - With hosted egress off, it may answer directly. Record which.
- **Observed:** 2026-11-23 on Dev with hosted egress on, as above (#5741
  comment 135387). `netcheck` reported `UDP: false` and the control server's
  embedded DERP. `ping` to the subnet router answered "via DERP" three times
  in about 55 ms, then "direct connection not established". The reach by
  address above ran over that relay.

## `own-tailnet-bad-key`: a used, expired or wrong key

- **Driving it:** `tailscale up` again with the key the first join used, then
  with a key minted 11 minutes earlier, then with no key at all.
- **Proof:**
  - Each attempt fails with the control server's own refusal, and no node is
    left registered.
  - With no key, `tailscale up` prints a sign-in URL and waits. Ctrl-C leaves
    nothing registered.
- **Gotchas:**
  - Run these on a second userspace `tailscaled` with its own socket, so the
    joined node is untouched.
- **Observed:** 2026-11-23 on Dev, as above, on a second `tailscaled`.
  - First walk (#5741 comment 135387): the used key was refused with
    "backend error: authkey already used".
  - Also in the first walk: with no key, `up --reset` printed a sign-in URL
    and waited until the timeout.
  - Second walk (#6167 comment 135831): a key minted 11 minutes earlier and
    never used was refused with "backend error: authkey expired".
  - Afterwards Headscale listed no node from any of these attempts.

## `own-tailnet-leave`: stop and remove

- **Driving it:**
  1. `tailscale --socket=/dev/shm/tailnet-walk/tailscaled.sock logout`.
  2. Kill `tailscaled` by its PID.
  3. `cw --cloud rm tailnet-walk --yes`.
  4. Delete `TS_AUTHKEY`, and any target started for the walk with its node.
- **Proof:**
  - The control server no longer lists the sandbox's node, at once after
    `logout`, or after its ephemeral timeout if the sandbox was removed first.
  - The control server lists no node with the sandbox tag from this walk at
    all, so a leaked key made no second node.
  - The secret project is empty.
- **Observed:** 2026-11-23 on Dev, as above (#5741 comment 135387). `logout`
  exited 0, and 3 seconds later Headscale listed no node with the sandbox
  tag, the same node count as before the walk. Both `tailscaled` processes
  were killed by PID, the sandbox was removed, `TS_AUTHKEY` was deleted
  ("No secrets in project"), and then the project.

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
- **Gotchas:**
  - A session started with `cw run --detach` and no `-t` has no terminal.
    `cw attach` shows its output but reads no keys, so Ctrl-B, then d, doesn't
    detach. This is the same with no tailnet joined.
- **Observed:** 2026-11-23 on Dev, as above, for four of the five (#5741
  comment 135387, #6167 comment 135831):
  - `cw exec --in tailnet-walk -- true` exited 0.
  - `cw shell` ran a command and exited with the shell's own status.
  - `cw attach` to a `cw run --detach` session showed its live output.
  - A preview of a server bound to 127.0.0.1 served its page on the first
    request, and answered 404 after `cw ports --unpublish`.
- **Not yet observed:**
  - `cw network connect`: Dev's Mesh refused the smoke identity
    ("forbidden"), so the sandbox had no Mesh member.
  - The refusal log: the hosted refusal log isn't built yet.
