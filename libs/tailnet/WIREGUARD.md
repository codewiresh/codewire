# WireGuard Transport Paths

## Architecture

Each `Conn` wraps a Tailscale userspace WireGuard engine + gvisor netstack.
The stack: gvisor TCP/IP → tstun.Wrapper → WireGuard device → magicsock → network.

## Transport paths

1. **DERP relay** (default) — WireGuard packets are relayed through a DERP
   server over TLS+HTTP upgrade. Both peers maintain a persistent connection
   to their home DERP region. Packets arrive within ~50ms for same-region peers.

2. **Direct UDP** — magicsock uses STUN + disco probes to discover direct paths.
   Once a direct path is found, traffic upgrades from DERP to UDP transparently.
   The DERP connection is kept alive as a fallback.

3. **WebSocket DERP** — when standard DERP (HTTP upgrade) is blocked by
   proxies, the derphttp client falls back to WebSocket transport
   (`TS_DEBUG_DERP_WS_CLIENT=1` or `ts_debug_websockets` build tag).

`Conn.ProbePeerPath` wraps magicsock's disco ping result into the Codewire
path names used by Guard smoke evidence: `direct_udp`, `derp_relay`,
`peer_relay`, or `unknown`.

## Key lifecycle

```
NewConn
  └─ applyNetworkMap(nil)
       ├─ engine.SetNetworkMap(nm)          — stores netmap in engine
       ├─ magicConn.SetNetworkMap(self, peers) — populates magicsock peer map
       ├─ netStack.UpdateNetstackIPs(nm)    — registers local addrs on gvisor NIC
       └─ engine.Reconfig(cfg, ...)         — configures WireGuard device
            └─ userspaceEngine.Reconfig
                 ├─ magicConn.SetPrivateKey(cfg.PrivateKey)  ← from nmToCfg
                 ├─ magicConn.UpdatePeers(peerSet)
                 └─ maybeReconfigWireguardLocked(cfg)
                      └─ wgdev.Reconfig → magicConn.ParseEndpoint(peer)
```

`nmToCfg()` must include `PrivateKey` and `Addresses`. Without `PrivateKey`,
every `Reconfig` zeroes the magicsock key, disabling DERP connections.

## Required init sequence

1. `netstack.Create(...)` — creates gvisor stack
2. `sys.Tun.Get().Start()` — unblocks TUN wrapper reads (required!)
3. `sys.Tun.Get().SetFilter(filter.NewAllowAllForTest(logf))` — nil filter drops all packets
4. `ns.Start(lb)` — starts netstack packet processing
5. `applyNetworkMap(nil)` — initial engine + magicsock config

Both `Tun.Start()` and `SetFilter()` are easy to miss since they're normally
handled by `LocalBackend.Start()` which we don't call.
