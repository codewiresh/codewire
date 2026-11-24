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

The WebSocket proxy pings its client every 30 s, and the workspace SSH server
sends a keepalive every 15 s, so a quiet shell is never silent on the wire and
no proxy's idle timeout closes it. When a rollout replaces the orchestration
replica holding a connection, the replica keeps it until its drain deadline,
270 s after SIGTERM, then closes it with WebSocket code 1012, "server
restarting; connect again". The SSH connection lives in that replica and
cannot move, so the session ends there, and `cw shell --stdio` prints
`the connection ended: server restarting; connect again` before OpenSSH's own
disconnect. A revoked credential closes with 1008, "access revoked", printed
the same way (#6100, #3586).

An SSH connection over `cw shell --stdio` does not survive a network cut of
about a minute, on any path. The workspace SSH server drops a client after
three unanswered keepalives, 45 to 60 s, and stops the processes its sessions
started, except those in a session of their own (`setsid`). The ProxyCommand
pipe never reconnects. #6101 records that decision; a durable transport would
be #6147. While the connection is up, the server's keepalives reach `cw` at
least every 15 s. So when the connection ends after 45 s or more with nothing
from the server, measured on the wall clock so that a laptop's sleep counts,
`cw shell --stdio` says so after OpenSSH's own line:
`Lost the connection to ENV: SSH sessions end after about a minute offline,
and their processes stop`, then `for work that must keep running, use
cw shell --durable ENV or cw run --detach`. A connection that ends any other
way, such as a shell's `exit`, prints nothing more.

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
relay slots through `AllocatePeerRelay`; the allocator and its client
certificate stay in orchestration. The relay's NetworkPolicy keeps relay data
on UDP 41641 and its read-only endpoints on TCP 8096 (`/healthz`, `/readyz`,
`/metrics`) open to every source, because Prometheus runs on host networking
and matches no Pod selector. It admits only orchestration to the allocator. Traffic from the relay's own
node isn't blocked by that policy, so the allocator also authenticates its
caller with mutual TLS (#4011):

- On TCP 8097, its only allocator port, the relay serves the allocator over
  TLS and allocates only for a client certificate that carries
  orchestration's name. A caller with no certificate, or another one, gets
  `401`. There is no plain allocator.
- The relay's server leaf and orchestration's client leaf come from one
  namespace-local authority, `codewire-udp-relay-allocator`, that signs
  nothing else. The site provisions it and publishes its public certificate
  as the `codewire-udp-relay-allocator-roots` ConfigMap. Both sides read
  their leaf and those roots again for every connection, so a rotation needs
  no restart.
- Orchestration verifies the relay by its short Service name, so a zone's
  allocator URL is
  `https://codewire-udp-relay:8097/internal/udp-relay/allocations`.
  Orchestration refuses to start with a catalog whose `allocator_url` is not
  `https`, and never calls a plain URL.
- `codewire_udp_relay_allocator_calls_total{caller=...}` on `/metrics` counts
  calls by `orchestration`, `no_certificate` and `another_certificate`.
- Allocator TLS files that are missing or unreadable close only the
  allocator: the relay still carries relay data and serves `/healthz`,
  `/readyz` and `/metrics`, and the allocator opens once the files can serve
  a handshake. The relay ignores, and logs, the removed plain listener's
  `CODEWIRE_UDP_RELAY_ALLOCATOR_ADDR` and `CODEWIRE_UDP_RELAY_ALLOCATOR_TOKEN`.

Orchestration limits what a daemon may ask the relay for (#5962). The relay
forwards only between clients that have each proved their disco private key in
the bind handshake, so a pair that names another node's key can't misdirect
traffic. It could still take slots, so:

- **A per-environment cap.** Each environment may hold at most 32 distinct
  pairs, each counted for the 300 s steady-state lifetime the relay returns.
  Asking again for a pair already counted is free, and a pair past the cap is
  `resource_exhausted`.
  - The count is kept per orchestration replica, so the effective bound is
    replicas × 32. That's well under the relay's VNI pool.
- **Keys checked against the coordinator.** Before it counts a pair or
  calls the allocator, orchestration asks the coordinator's `CheckDiscoKey`
  about both keys, as the calling environment:
  - `disco_keys[0]` must be `BOUND_HERE`, the calling environment's own
    daemon;
  - `disco_keys[1]` must be bound (`BOUND_ELSEWHERE` or `BOUND_HERE`);
  - any other answer is `permission_denied`, and an unreachable coordinator is
    `unavailable`.

  Orchestration reaches the lookup at `CODEWIRE_PEER_RELAY_ADMISSION_URL`, the
  coordinator's 8097 origin; without it, no relay is allocated. Each lookup is
  bounded at 2 s. The site's policy admits orchestration to that port,
  matched by namespace and service account. DERP runs as its own service
  account, `codewire-derp`, with no API token, so it can be matched the same
  way.
- **A refused allocation costs only the relay path.** The daemon keeps the
  peer on direct UDP or DERP.

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
        "allocator_url": "https://codewire-udp-relay:8097/internal/udp-relay/allocations",
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
it, falling back to DERP on the coordinator's origin. A broker-mode daemon
(hosted egress, #4000) has no fallback: it dials only the deployment's relay,
and a missing map is refused (`broker_no_derp_map`), because the coordinator's
address there is the platform gateway, which serves only the coordinators'
streams.

**Why two nodes?** Tailscale's magicsock selects `preferred_derp` based on STUN latency. If STUN runs on the same node as DERP, STUN latency competes with DERP latency and can steal `preferred_derp` to a non-relay region. Separating them (STUNPort=-1 on relay, STUNOnly on STUN) keeps `preferred_derp=1` stable.

**The relay runs unprivileged.** The `codewire-derp` image runs as user and
group 65532, and the chart's `codewire-derp` Deployment adds `runAsNonRoot`, a
read-only root filesystem, no privilege escalation, every capability dropped
and the runtime's default seccomp profile. Its ports (8080, 8443, 3478/udp) are
above 1024 and it writes no files, so it needs none of them. A TLS Secret
mounted into the pod must be group-readable (mode 0440): the pod's `fsGroup`
65532 gives the root-owned files the relay's group.

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

## The relay's TLS listener

The relay's own TLS listener (`TLS_PORT`, 8443 in the manifests) is separate
from the public edge, which terminates TLS for the advertised `DERP_HOST` and
forwards to the relay's plain HTTP port. On Dev and Production nothing in the
platform dials 8443 today; local and test clients reach it with
`DERP_INSECURE` and skip the certificate check.

- **The self-signed certificate.** At start the relay makes a self-signed
  certificate for the names in `TLS_HOSTS`, its in-cluster names, and serves it
  to every client, as before. Without the three settings below, that is all it
  does.
- **The public certificate** (#4000). A broker-mode Sandbox dials the relay
  inside the cluster but verifies it as `DERP_HOST`, against the public roots,
  and refuses a relay it can't verify. So a deployment with a public name gives
  the relay a publicly trusted certificate for that name: `TLS_PUBLIC_HOSTNAME`,
  and PEM files `TLS_PUBLIC_CERT_FILE` (the chain, end-entity first) and
  `TLS_PUBLIC_KEY_FILE`, all three or none. A client that asks for that name
  gets that certificate. A client asking for any other name, or for none, gets
  the self-signed one, so every caller of today is unchanged.
- **Renewal.** The relay reads the files again every 60 s and serves a changed
  certificate from then on, without a restart, which would drop every relayed
  connection. Its key must match the chain's end-entity certificate.
- **Failures.** Files that are missing or don't parse never stop the relay. It
  keeps the last good public certificate, or until there is one the
  self-signed one, and logs a warning. A broker-mode client asking for the
  public name then fails its own verification. Setting only one or two of the
  three stops the relay at start.

## Coordinator sessions and node keys

A peer's coordinator session names its node by the session, so a peer whose
stream breaks and reconnects announces the same node key again under a new
session (#5120). A stream can break without either end seeing it: the CLI's
stream crosses the CDN edge, which answers its HTTP/2 PINGs, and a stalled
edge connection leaves the coordinator holding the old stream for minutes. The
coordinator therefore owns each node key and ends sessions that have gone
quiet; it does not wait for a send to fail.

- **Binding.** The NATS KV bucket `coordinator-node-bindings` (with no NATS,
  the coordinator's local registry) maps each node key to
  `{principal, environment, session}`. The principal is the signed-in user for
  a CLI client, and the environment itself for its daemon. The first session to
  announce a key binds it. The bucket's TTL is seven days, and NATS counts it
  from an entry's last write, so a live session rewrites its binding every
  hour, a compare-and-set that keeps a long-lived daemon's key bound however
  long it runs. When the session ends, the binding keeps
  `{principal, environment}` and drops `session`; it then ages out seven days
  after that last write. Keys are fresh for each tailnet, so a week outlasts
  any reconnect. A binding is cleared only when it expires. The coordinator
  hears of no sign-out and no removal of a node, and none is needed: the key is
  random to its tailnet, and a principal that signed out, or an environment
  that was deleted, can open no session meanwhile. `coordinator-node-keys`, the live-session record DERP admission
  reads, is unchanged.
- **One writer at a time.** Binding, refreshing, retiring and taking over
  are compare-and-set on the binding's KV revision: create when absent,
  update with the revision just read otherwise. Of two sessions racing for one
  key, exactly one wins. The loser is refused; it does not retry and
  overwrite. A session changes its binding only while the binding names it:
  when it ends, it drops `session` only if the binding it reads still names
  this session, so a late end after a takeover leaves the successor's binding
  alone. A refresh that finds another session named ends this one, as a
  takeover would.
- **Refused.** An announcement of a bound key from another principal, or
  from the same principal in another environment, is refused, while the key's
  session is live and for the binding's seven days after. The announcing
  session gets the refusal, and its node reaches no peer.
- **Retired.** An announcement of a bound key from the same principal and
  environment, under a new session, takes the binding over. The older session
  is retired: its peers get a `PeerRemove` for it, and the replica that holds
  it, this one or the other, ends it on the environment's existing NATS
  subject. A reconnect therefore leaves one session and one peer, whichever
  replica each stream reached.
- **Quiet sessions end.** A session that has sent a `CoordinatePing` ends
  when 45 s pass with nothing received from it (the coordinator's
  `SESSION_SILENCE_LIMIT`). That is three of the peer's 15 s pings,
  mirroring the peer's own `COORDINATOR_SILENCE_LIMIT`.
  Its binding stays as above, and its peers get a `PeerRemove`. A session
  that has never pinged, from a CLI older than v0.4.1, keeps the earlier
  behaviour: it ends when a send to it fails, or when its proof lapses.
- **Proof of possession** of the node key is not required. Binding to the
  principal and environment is the boundary (#5131).
- **Disco keys are bound the same way (#5962).**
  - **The bucket:** each node's disco key is bound to the same
    `{principal, environment, session}` in its own bucket,
    `coordinator-disco-bindings` (or the local registry without NATS), with
    the node key's TTL, refresh and compare-and-set.
  - **Refusal:** an announcement whose disco key another principal or
    environment holds is refused as a held node key is. Its session ends, and
    its node reaches no peer.
  - **Rotation:** a node gets a fresh disco key whenever its tailscale
    restarts. A session that announces a new disco key binds it and releases
    its previous one at once, as a session's end releases its key.
  - **The all-zero key** means a node has no disco key, and is never bound.
- **Peer relay admission (#5962).**
  - **The lookup:** the coordinator serves
    `codewire.internal.v1.PeerRelayAdmissionService/CheckDiscoKey` on the
    same closed listener as DERP admission (8097). It takes a disco key and
    the asking environment, and answers one of three things:
    - `BOUND_HERE`: the key is held by that environment's own daemon, with a
      live session;
    - `BOUND_ELSEWHERE`: it's held by any other live session, the
      environment's clients included;
    - `UNBOUND`: no binding, or one whose session has ended.
  - **It never names a holder,** so no caller can use it to enumerate keys.
  - **An unreadable bucket** is `unavailable`, never an answer.

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
| `CODEWIRE_UDP_RELAY_ALLOCATOR_URL` | server configmap | empty | Predates the transport-zone catalog: without one, a value only opens the workspace's relay data egress, and nothing calls it. `AllocatePeerRelay` uses the zone's `https` `peer_relay.allocator_url` |
| `DERP_HOST` | server configmap | `derp.codewire.sh` | DERP relay hostname the coordinator advertises. Required, with no default: unset or empty, the coordinator refuses to start |
| `DERP_PORT` | server configmap | unset (443) | The relay's HTTPS port in the DERPMap |
| `DERP_INSECURE` | Kind only | `true` | Tells clients to skip the relay's certificate check; never set on a real deployment |
| `DERP_MESH_KEY` | secret | 64-char hex | Shared key for multi-replica DERP mesh |
| `DERP_VERIFY_CLIENT_URLS` | DERP deployment | comma-separated `http://host:port` | Coordinator and Mesh node-key lookups; unset serves every client |
| `TLS_HOSTS` | DERP deployment | comma-separated in-cluster names | Names of the TLS listener's self-signed certificate |
| `TLS_PUBLIC_HOSTNAME` | DERP deployment | the `DERP_HOST` value | With the two files below: the name the listener serves its public certificate for ("The relay's TLS listener") |
| `TLS_PUBLIC_CERT_FILE`, `TLS_PUBLIC_KEY_FILE` | DERP deployment | PEM paths, such as a mounted cert-manager Secret's `tls.crt` and `tls.key` | The public certificate and its key, read again every 60 s |
| `RUST_LOG` | DERP and STUN edge deployments | unset (`info`) | The relay's log filter. It logs JSON lines on stdout; the alert on a public certificate that won't load matches its warning |
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
