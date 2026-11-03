# DERP Relay + STUN Direct Peering

## How SSH connects

```
CLI --> WireGuard tunnel --> workspace daemon SSH server
         |
         +-- Transport: direct UDP (preferred fast path, needs STUN/disco)
         +-- Transport: UDP relay (shared UDP relay, before DERP)
         +-- Transport: DERP relay (TCP fallback)

CLI --> platform WebSocket SSH proxy (final non-WireGuard fallback)
```

The CLI establishes a WireGuard tunnel to the workspace daemon. The local CLI/VS Code
SSH transport ladder is direct UDP, then UDP relay, then DERP, then the
platform WebSocket SSH proxy. WebSocket is the final fallback for browser
access, locked-down networks, and compatibility. DERP may still bootstrap
discovery while magicsock selects a better packet path, but it is not the
preferred local CLI/VS Code SSH path.

1. **Direct UDP** (preferred fast path): each peer advertises candidate
   endpoints. A hosted daemon advertises the direct-UDP endpoint the platform
   publishes for it; a client, or a daemon with no published endpoint, learns
   its own from public STUN. magicsock/disco then upgrades WireGuard packet flow
   from DERP to peer-to-peer UDP when the network allows it. The DERP
   connection stays up as fallback. In-cluster STUN only reveals private pod
   addresses and is relay-only evidence. An advertised endpoint must also be
   routable from the other peer.
2. **UDP relay** (bounded UDP fallback): If true peer-to-peer UDP cannot
   be validated, the tailnet may allocate a shared UDP relay endpoint for the
   two disco keys. This is not `direct_udp`; new Rust diagnostics should report
   it as `udp_relay`, while legacy Go diagnostics may still emit `peer_relay`,
   so smoke and operations can distinguish relayed UDP from a real direct path.
3. **DERP relay** (TCP bootstrap/fallback): The CLI connects to the public DERP
   host (`derp.codewire.sh` or `derp.codewire-dev.sh`). Workspace daemons use
   the DERP node of the DERP map the coordinator sends them, through the same
   public edge, so both peers land on the same DERP relay/mesh.

DERP relay and WebSocket fallback stay mandatory because provider firewalls,
NAT shape, and client networks can still block UDP.

## Runtime transport zones

A hosted runtime cluster may place workspace Pods on runtime workers in more
than one network. Inside the cluster, the cluster network carries pod traffic
between nodes, so a `codewire-udp-relay` pod can forward to a workspace Pod on
any healthy runtime worker. That does not make the public internet path
network-agnostic: the public relay endpoint must be an IP that routes to the
relay's transport zone. The shared UDP relay advertises a dedicated VIP, for
example `203.0.113.35:41641`, rather than a node's own address.

A transport zone may also have a stable DNS name, such as
`example-zone.mesh.example.invalid`, that maps to the zone's relay VIP. Codewire
still chooses which relay to return after scheduling the sandbox, and the CLI
uses the coordinator- or binding-provided candidate; it never constructs a zone
relay host name itself. The Rust relay descriptor is socket-address shaped, so
a zone advertises the VIP's socket address even when DNS also names it.

The runtime transport-zone catalog is the handoff between the site's
infrastructure and Codewire. The site owns the node labels
(`node.codewire.sh/runtime-region`, `node.codewire.sh/transport-zone`), the
VIP, DNS and firewall resources, and the catalog payload. Codewire ingests that
payload into Postgres, then the workspace
binding reads the bound workspace Pod's node labels and returns the selected
zone's direct-UDP and peer-relay endpoints to the daemon. The daemon allocates
relay slots through `AllocatePeerRelay`; the allocator and its token stay in
orchestration. The relay's NetworkPolicy keeps relay data on UDP 41641 and its
read-only endpoints on TCP 8096 (`/healthz`, `/readyz`, `/metrics`) open to every
source, because Prometheus runs on host networking and matches no Pod selector.
It admits only orchestration to the allocator on TCP 8095. Traffic from the
relay's own node isn't blocked, so a host-network process there can still
allocate until the allocator has a token.

Terminology:

- `runtime_region`: product/scheduling region, for example `dev-eu`.
- `transport_zone`: provider/routing domain, for example `example-zone`.
- `relay_endpoint`: public UDP endpoint advertised for relayed UDP, for example
  `203.0.113.35:41641`.
- `relay_dns`: stable operator DNS name for that endpoint, for example
  `example-zone.mesh.example.invalid`.

Catalog payload shape (the names and addresses are documentation placeholders;
your site's values are deployment inputs):

```json
{
  "version": 1,
  "zones": [
    {
      "name": "example-zone",
      "runtime_region": "dev-eu",
      "peer_relay": {
        "public_endpoints": ["203.0.113.35:41641"],
        "dns": "example-zone.mesh.example.invalid",
        "allocator_url": "http://codewire-udp-relay.dev.svc.cluster.local:8095/internal/udp-relay/allocations",
        "bind_addrs": ["codewire-udp-relay.dev.svc.cluster.local:41641"]
      },
      "direct_udp": {
        "vip": "203.0.113.36",
        "port_start": 32000,
        "port_end": 60999
      },
      "stun": { "endpoints": ["stun.example.invalid:3478"] },
      "derp": { "endpoints": ["derp.example.invalid"] }
    }
  ]
}
```

## DERPMap architecture

The CLI-facing DERPMap has one region with two nodes:

```
Region 1 ("cw"):
  Node 1a: derp.codewire.sh:443   STUNPort=-1  (relay only)
  Node 1s: stun.codewire.sh:3478  STUNOnly=true (STUN only)
```

Workspace daemons use the same DERPMap: the coordinator sends it when the
daemon's node session opens, and the daemon takes its relay and STUN nodes from
it, falling back to DERP on the coordinator's origin.

**Why two nodes?** Tailscale's magicsock selects `preferred_derp` based on STUN latency. If STUN runs on the same node as DERP, STUN latency competes with DERP latency and can steal `preferred_derp` to a non-relay region. Separating them (STUNPort=-1 on relay, STUNOnly on STUN) keeps `preferred_derp=1` stable.

## DERP client admission

The public DERP relay serves only node keys that a coordinator has registered
for a live, authorized session: the platform coordinator's sandbox daemons and
CLI clients, and Mesh's members. Payloads are WireGuard-encrypted end to end
either way; admission stops strangers using the relay as free bandwidth.

- Every client connects to DERP before it sends its node to its coordinator,
  and its handshake returns once it has written `ClientInfo`. The relay
  therefore holds an unknown key before `ServerInfo`, unroutable, and asks
  the verifiers again with backoff until the 10 s handshake deadline. A key
  registered within that window is served; otherwise the connection closes
  and the client's reconnect backoff retries.
- The relay calls `codewire.internal.v1.DerpAdmissionService/CheckNodeKey`
  on each URL in `DERP_VERIFY_CLIENT_URLS`, as a Connect unary JSON POST with
  the 32-byte key. Any `registered: true` admits the key, which is then
  cached for 30 s; unknown keys are never cached, and at most 64 lookups per
  relay run at once.
- The coordinator records each session's node key in the NATS KV bucket
  `coordinator-node-keys` while the session lives, so either replica answers.
  Mesh answers from its own registry. Both serve the service on a separate
  listener (`8097`) that no edge routes to (the `derp-admission` closed
  listener in `scripts/checks/contracts/connect-edge-ownership.json`); the
  site's network policy admits only DERP to it.
- When no verifier answers, new keys are refused and live sessions keep
  relaying: admission happens once per connection. Mesh peers, which prove
  `DERP_MESH_KEY`, are never looked up.
- Without `DERP_VERIFY_CLIENT_URLS` the relay serves every client, as a local
  or self-hosted relay does.

`cargo run -p codewire-derp --example derp_probe -- derp.example.com:443`
connects with a fresh, unregistered key and reports `admitted` or `refused`.

## Network Paths

**DERP path:** `derp.codewire-dev.sh:443` or `derp.codewire.sh:443`
-> public ingress -> DERP service `:8080`.

The public STUN edge is a host-network path. The site's cluster network
policy must let sandbox namespaces reach the edge's node on UDP `3478`:
Kubernetes `NetworkPolicy` pod selectors do not reliably describe host-network
node traffic, and a CNI such as Cilium classifies it as node traffic, not
ordinary internet egress.

**STUN path:** CLI or workspace daemon UDP socket ->
`stun.codewire-dev.sh:3478` or `stun.codewire.sh:3478` -> public STUN edge.

STUN is intentionally public edge infrastructure, not a cluster-internal
service. A private network between the cluster's nodes does not prove the
public UDP path that external clients will use, so STUN is queried over the
same public UDP internet path used for direct WireGuard candidates.

**Direct UDP path:** CLI UDP socket <-> network/NAT/provider path <-> the
environment's `cw-tailnet-udp-<env>` LoadBalancer <-> the daemon's UDP socket
inside the workspace Pod. The daemon advertises that LoadBalancer endpoint
from its access grant; the client learns its own endpoint from STUN; disco
validates peer reachability; WireGuard traffic moves directly only after the
tailnet confirms that path. Every workspace daemon gets the same DERP/STUN
capability, and transport selection belongs to the tailnet implementation.

The sandbox-side UDP socket binds at `0.0.0.0:31000` in the workspace Pod,
only once the daemon is bound. That is a pod-local destination port. In Kubernetes/Cilium, a STUN-observed node-side source port
does not guarantee arbitrary external peer packets will be DNATed back into the
pod. Codewire therefore creates no per-sandbox UDP NodePort Service; the
environment's `cw-tailnet-udp-<env>` LoadBalancer and the shared UDP relay
carry the external paths.

STUN is still required, for clients. The CLI uses public STUN to discover its
own endpoint, and so does any client running inside a Sandbox, such as a nested
`cw` or a Mesh member that dials another environment. A daemon runs STUN only
when the platform publishes no direct endpoint for it: behind a published
endpoint, a STUN answer could name only the node's outbound NAT mapping, which
admits replies from that STUN server and nothing else, so the daemon advertises
the published endpoint alone. Disco proves the advertised tuple before
WireGuard data moves directly. Direct UDP proof is the combination of an
advertised routable endpoint and a path probe reporting `transport=direct_udp`.

A hosted environment proves its fast path through the shared UDP relay:
`cw doctor tailnet` reports `transport=udp_relay` through the zone's peer
relay endpoint, the sandbox namespace has no `codewire.sh/type=direct-udp`
Service, the workspace binding's access grant carries that peer relay
endpoint, and the workspace Pod carries neither
`CODEWIRE_UDP_RELAY_ALLOCATOR_URL` nor `CODEWIRE_UDP_RELAY_BIND_ADDRS`, because
relay slots come from `AllocatePeerRelay`. A forced-DERP run separately proves
`transport=derp`; older Go diagnostics may still emit the accepted
`peer_relay` and `derp_relay` aliases. Rust diagnostics report relayed UDP as
`udp_relay`, never `direct_udp`, unless the selected path is actually
peer-to-peer.

The daemon's SSH server offers russh's default key exchanges, with
`mlkem768x25519-sha256` first, so OpenSSH 10 negotiates a post-quantum key
exchange without its per-connection warning. Its larger KEXINIT packets need a
path MTU that carries full-size tunnel packets: the tailnet's tunnel MTU is
1130 bytes, which leaves room for WireGuard, relay, UDP, IP and pod network
overhead.

## STUN edge

**Clients, and daemons with no published endpoint:** public STUN host -> DNS
-> public edge node -> host-network `codewire-stun` pod `:3478/udp`.

Your site runs the STUN edge as a `codewire-stun` deployment of the
`codewire-derp` binary in STUN-only mode (`PORT=-1`, `TLS_PORT=-1`,
`STUN_PORT=3478`), with `hostNetwork: true`, on a node whose public IP backs
your site's STUN host name. The site's firewall must admit public UDP `3478` to that node, and
sandbox pods also need the host-network egress policy above. Sandboxes and the
DERPMap advertise the standard public STUN port `3478/udp`, not a Kubernetes
NodePort.

A Sandbox on another node must reach the edge node's public address over the
public path, with its usual outbound NAT. If the site's node mesh (for example
a WireGuard underlay between nodes) routes that public address, the request
enters the mesh with the Pod's own source address, which the mesh peer can drop
without a trace: the Sandbox gets no STUN answer although policy forwarded the
request. Keep every node's public address out of the mesh's routed networks.

## DERPMap delivery

1. CLI creates a **bootstrap DERPMap** (relay-only, no STUN) from the server URL
2. CLI connects to the coordinator WebSocket
3. Server sends the **full DERPMap** (with STUN node) via the coordinator
4. CLI calls `conn.SetDERPMap()` which stores it and triggers `ReSTUN("derpmap-update")`
5. magicsock runs netcheck and sends STUN probes to the configured STUN node
6. STUN responses produce candidate endpoints, which may still be private
   inside a Kubernetes/Kata/Cilium topology
7. Direct UDP is established only if both peers can send WireGuard packets to a
   mutually routable endpoint; otherwise the tailnet uses the UDP relay if it
   has an active allocation, then DERP relay

Workspace daemons do not block coordinator registration on DERP readiness.
The daemon opens its tailnet listener, connects to the coordinator, publishes
its node, and warms the home DERP connection in the background. This avoids a
startup deadlock where the daemon waits for DERP before publishing while the
CLI waits for the daemon peer before sending traffic. The CLI still waits for
its own DERP home before dialing, and the smoke test records the eventual path
probe as direct UDP, UDP relay, or DERP fallback evidence.

## SSH connection start

`cw shell --stdio` dials SSH as soon as the coordinator delivers the
environment peer. It waits neither for STUN nor for a better path: the client
binds its UDP socket and publishes its node at once, publishes its mapped
endpoint when STUN answers, and WireGuard rides DERP until disco proves direct
UDP or the UDP relay. The transport then moves WireGuard to that path under
the open stream; SSH does not reconnect. Only an explicit
`CW_TAILNET_EXPECTED_TRANSPORT=direct_udp|udp_relay|derp` waits, up to
`CW_TAILNET_DIRECT_WAIT` (default 2s), and fails when that path is not ready.
`cw doctor tailnet --direct-wait` keeps its own wait for the proofs.

The coordinator delivers each peer's node to the other at about the same
time, so the client's first WireGuard handshake initiation often reaches the
daemon a few milliseconds before the daemon knows the client's key, and the
daemon drops it. WireGuard alone would retry only after its 5 s
`REKEY_TIMEOUT`. The tailnet `Conn` therefore resends the identical
initiation 50 ms later and then with doubling delays until the first session
exists: a peer that dropped the original accepts the copy, and one that
already answered rejects it as a replay, so a slow response stays valid.

## Key config

| Env var | Where | Value | Purpose |
|---------|-------|-------|---------|
| `STUN_HOST` | server configmap | `stun.codewire.sh` | Advertised to CLI in DERPMap |
| `STUN_PORT` | server configmap | `3478` | Public STUN edge port, advertised in DERPMap |
| `STUN_SERVERS` | server configmap | optional comma-separated `host[:port]` list | Extra STUN candidates in the DERPMap |
| `CODEWIRE_UDP_RELAY_ADVERTISE_ADDRS` | server configmap | dev: the peer relay VIP, such as `203.0.113.35:41641` | Public shared UDP peer-relay endpoint advertised in allocated relay descriptors |
| `CODEWIRE_UDP_RELAY_ALLOCATOR_URL` | server configmap | cluster-local relay allocator URL | Internal HTTP allocation endpoint orchestration calls for `AllocatePeerRelay` |
| `DERP_HOST` | server configmap | `derp.codewire.sh` | DERP relay hostname |
| `DERP_MESH_KEY` | secret | 64-char hex | Shared key for multi-replica DERP mesh |
| `DERP_VERIFY_CLIENT_URLS` | DERP deployment | comma-separated `http://host:port` | Coordinator and Mesh node-key lookups; unset serves every client |
| `COORDINATOR_DERP_VERIFY_ADDR` | coordinator deployment | `0.0.0.0:8097` | Coordinator's node-key lookup listener |
| `CODEWIRE_MESH_DERP_VERIFY_ADDR` | Mesh chart (`mesh.derpVerifyPort`) | `0.0.0.0:8097` | Mesh's node-key lookup listener |

## CLI debug flags

```bash
cw doctor tailnet <env> --direct-wait 20s --expect direct_udp --output json
                                             # noninteractive coordinator/DERP/STUN/direct UDP proof
cw doctor tailnet <env> --expect udp_relay  # prove shared UDP relay path
cw doctor tailnet <env> --expect any        # prove usable tailnet with DERP fallback allowed
cw doctor tailnet <env> --skip-forced-derp  # skip the forced relay-only probe
CW_DEBUG_TAILNET=1 cw shell --stdio <env>    # phase timeline and tailnet debug events
CW_DERP_ONLY=1 cw shell --stdio <env>        # strip STUN nodes
CW_DERP_ONLY=1 TS_DEBUG_NEVER_DIRECT_UDP=1 cw shell --stdio <env>
                                             # force relay-only evidence
```

`cw doctor tailnet` uses the same coordinator and tailnet bootstrap as
`cw shell --stdio`, but stops before SSH. It reports the received DERPMap, the
workspace peer's advertised endpoints, the direct path probe, and a forced
DERP-only fallback probe. Use `--expect direct_udp` for explicit direct-UDP
proof. Use `--expect udp_relay` for the shared UDP relay path. Use the default
`--expect any` when a runner may be on a UDP-blocked network and DERP fallback
is acceptable. In forced-DERP mode, the CLI strips peer direct endpoints before
updating the tailnet so the diagnostic cannot accidentally report `direct_udp`
from coordinator-provided endpoint candidates.

With `CW_DEBUG_TAILNET=1`, `cw shell --stdio` writes to stderr a
`phase=<name> elapsed_ms=<n>` line for each setup step (`derp_map`,
`stun_resolve`, `derp_connect`, `direct_udp_bind`, `coordinator`, `peer`,
`session`, `path`), the path probe line collected during setup, and
the tailnet's debug events stamped with the time since start. `RUST_LOG`
replaces the default `codewire_tailnet=debug,codewire_client=debug` filter;
`codewire_tailnet=trace` also shows which path carried each WireGuard
datagram. It does not run a second active path probe after the SSH stream is
open.
`transport=direct_udp` proves the WireGuard packet path bypassed DERP at probe
time; `transport=udp_relay` proves the shared UDP relay path; and
`transport=derp` means DERP was the selected fallback. The older
`peer_relay`/`derp_relay` labels remain accepted as fixture aliases.

For deterministic DERP relay testing, set both `CW_DERP_ONLY=1` and
Tailscale's `TS_DEBUG_NEVER_DIRECT_UDP=1`.

## Code paths

- **DERPMap construction (coordinator):** `crates/codewire-coordinator/src/lib.rs:build_derp_map()`
- **STUN node injection (coordinator):** same function, adds a `STUNOnly`
  node when `STUN_HOST` is set
- **Daemon DERP/STUN/relay:** `crates/codewire-workspace-access/src/daemon_tailnet.rs`
  takes DERP and STUN from the coordinator's DERP map and direct-UDP and relay
  endpoints from the binding's access grant.
- **Sandbox rendering/NetworkPolicy:** `crates/codewire-orchestration/src/sandbox/template/`
  renders the workspace's STUN and relay egress, the world-only ingress on
  `31000/udp`, and the `cw-tailnet-udp-<env>` LoadBalancer.
- **UDP peer-relay allocation:** `crates/codewire-udp-relay` serves the shared
  relay socket and allocator; orchestration calls the allocator for the
  daemon's `AllocatePeerRelay`.
- **CLI bootstrap:** `crates/codewire-cli/src/tailnet_ssh.rs` and the
  `cw doctor tailnet` implementation in `crates/codewire-cli/src/lib.rs`
- **Rust tailnet candidate:** `crates/codewire-tailnet/src/disco.rs`,
  `crates/codewire-tailnet/src/endpoint_tracker.rs`,
  `crates/codewire-tailnet/src/stun.rs`,
  `crates/codewire-tailnet/src/direct_udp/`, and
  `crates/codewire-workspace-access/src/daemon_tailnet.rs`. This path sends Tailscale-shaped
  STUN Binding Requests (`tailnode` software attribute plus fingerprint) to
  interoperate with the Codewire DERP/STUN server, parses RFC5389 mapped
  endpoint responses from the same UDP socket, caches endpoints through short STUN
  flaps, republishes coordinator nodes when local endpoints change, supports
  Tailscale-compatible disco Ping/Pong/CallMeMaybe, and keeps DERP fallback.
  Hosted environments use the shared UDP peer relay and do not create
  per-sandbox NodePort Services.

Useful targeted gates:

```bash
cargo test -p codewire-tailnet stun
cargo test -p codewire-tailnet direct_udp
cargo test -p codewire-tailnet conn_tunnel_uses_stun_discovered_direct_udp_path_without_static_endpoints
cargo test -p codewire-tailnet live_tailscale_stun_server_discovers_mapped_addr -- --ignored --nocapture
cargo test -p codewire-cli tailnet
cargo test -p codewire-cli doctor_tailnet
```

The `conn_tunnel_uses_stun_discovered_direct_udp_path_without_static_endpoints`
gate is the hermetic Rust proof of direct UDP: both tailnet peers bind UDP,
derive their advertised endpoints from fake STUN servers, exchange disco
Ping/Pong, verify endpoint ownership, and carry TCP bytes over WireGuard
direct UDP without any static advertised endpoint or Kubernetes NodePort.
