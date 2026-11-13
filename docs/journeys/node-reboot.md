# A Production node reboot

Production keeps serving through the loss of any one worker node: Mesh, NATS
and the coordinator stay up, the tailnet's STUN and peer relay stay up, and
sandboxes on other nodes keep their sessions (#3542, #4461). This file is how
that is proved and what has been seen. It is step 9 of the
[launch walk](launch.md). The format is in [README.md](README.md).

A **drain** (cordon, then evict every Pod under its disruption budget) is the
planned case and comes first. An undrained **reboot** loses the node's Pods
at once and is the harder case. Each is observed separately.

## Where it stands

Updated 2026-11-13.

| ID | What survives | Drain, Production | Reboot, Production |
| --- | --- | --- | --- |
| `reboot-nats` | JetStream quorum and the coordinator's KV buckets | observed 2026-11-13, two workers | not yet observed |
| `reboot-coordinator` | the tailnet coordinator | observed 2026-11-13, two workers | not yet observed |
| `reboot-sessions` | sandboxes and sessions on other nodes | observed 2026-11-13, two workers | not yet observed |
| `reboot-spread` | every multi-replica service still on two or more nodes afterwards | failure observed 2026-11-13; fixed by hand, rule pending | not yet observed |
| `reboot-stun-relay` | STUN and the UDP peer relay | not yet observed (#4461) | not yet observed |
| `reboot-mesh` | the Mesh API and its members' sessions | not yet observed (#3542 step 5) | not yet observed |

## Before any of these

- A drain or reboot of a Production node needs the owner's yes for that
  action, or a recorded approval that names it. The owner approved the drain
  of each worker for acceptance on #3542 (2026-11-12).
- The operator steps (cordon, drain, uncordon, the post-drain spread check
  and rebalance) are in infra's Production worker drain runbook (infra#2525).
  Never relax a disruption budget, and never drain a second worker before the
  first is back and NATS reads three of three.
- Rehearsal on Dev proves nothing here: Dev runs one NATS server and one Mesh
  replica on purpose (#3542).
- The checks below run as the Production smoke identity:
  `scripts/runtime/prod/with-prod-smoke-auth.sh -- COMMAND`. It may create,
  inspect and remove only its own environments.

## `reboot-nats`: JetStream keeps quorum

- **Entry points:** none for a user. The coordinator is NATS's only client;
  `cw shell`, `cw run` and DERP admission depend on it.
- **States to exercise:** each worker drained in turn, so each NATS server is
  the one away once; the stream leader on the drained node; the node back and
  its server caught up.
- **Driving it:** read each server's JetStream state through the API
  server's pod proxy, before, while drained, and after:

  ```sh
  kubectl get --raw "/api/v1/namespaces/prod/pods/nats-0:8222/proxy/jsz?accounts=true&streams=true&config=true"
  ```

  (and `nats-1`, `nats-2`). A server reports only the streams it holds.
- **Proof:** in every sample both streams, `KV_coordinator-nodes` and
  `KV_coordinator-node-keys`, have a leader, `config.num_replicas` is 3, and
  the leader reports its followers `current`, except the one whose server is
  away. After the uncordon all three are current again.
- **Gotchas:**
  - Each NATS server sits on its own node (infra#2523). A drain leaves that
    node's server Pending until the node returns, so NATS runs two of three
    meanwhile. That is expected.
  - A stream at one replica goes offline with its server. Both streams were
    moved to three replicas in place first (#4374, deploy#243).
- **Observed:**
  - Production, 2026-11-13, v0.4.17: drains of the small nbg1 worker and of
    the other nbg1 worker. Every sample had a leader for both streams at R3;
    the leader handed over at the cordon, before the eviction; three of three
    again 30 s and 70 s after uncordon. Evidence: #3542, "Acceptance drains".
  - A reboot: not yet observed.

## `reboot-coordinator`: the coordinator keeps serving

- **Entry points:** every tailnet attach (`cw shell`, `cw run`, `cw attach`)
  and DERP admission.
- **States to exercise:** a drain of the node holding one of its two
  replicas.
- **Driving it:** `kubectl -n prod get pods -l
  app.kubernetes.io/component=coordinator -o wide` before, while drained and
  after; the smoke session below runs while drained.
- **Proof:** one replica keeps running throughout, restart count 0, and no
  NATS KV setup failure in its log.
- **Gotchas:** its two replicas never share a node (required anti-affinity,
  deploy#243), so while a node is drained the evicted replica can stay
  Pending. Its disruption budget allows that one.
- **Observed:** Production, 2026-11-13, v0.4.17: both drains, 0 restarts; one
  replica Pending during the second (#3542).

## `reboot-sessions`: sandboxes elsewhere keep working

- **Entry points:** `cw create`, `cw --cloud run`, `cw network nodes`.
- **States to exercise:** a new environment with a Mesh network created while
  a node is drained; a session opened in it.
- **Driving it:** before, while drained and after, as the smoke identity:

  ```sh
  cw network create --cloud --org ORG --no-use NET
  cw --cloud create --no-file --name ENV --image workspace --ttl 1h --network NET --yes
  cw --cloud run --in ENV -- sh -c 'echo ok'
  cw network nodes --cloud --org ORG --network NET
  cw --cloud rm ENV --yes
  cw network delete --cloud --org ORG --yes NET
  ```

- **Proof:** `cw --cloud run` prints `ok` and its path line ("via direct
  UDP", "via DERP"), and the environment's node is `reported online`.
- **Gotchas:** a workstation firewall that blocks `cw`'s direct UDP makes
  every session take DERP, before and after alike; compare against a
  baseline taken first.
- **Observed:** Production, 2026-11-13, v0.4.17: before, during and after
  both drains. Create in 3–8 s, session in 2–5 s, node online every time; via
  direct UDP during the second drain (#3542).

## `reboot-spread`: nothing ends up on one node

- **Entry points:** none for a user; it decides whether the *next* node's
  loss takes a service down.
- **States to exercise:** after each drain's uncordon.
- **Driving it:** the post-drain spread check in infra's drain runbook
  (infra#2525) lists every multi-replica Deployment whose replicas share one
  node.
- **Proof:** the list is empty.
- **Gotchas:** Pods evicted in a drain stay where they land. A Deployment
  without a required per-node rule can end with every replica on the one
  node that stayed schedulable, and an uncordon doesn't move it back.
- **Observed:**
  - Production, 2026-11-13: **failure.** After the two drains, 15
    Deployments (among them the dashboard, the IdP, DERP, Temporal and
    Kyverno's admission controllers) had every replica on one node. They
    were restarted one at a time and the list is now empty (#3542,
    "Rebalance after the drains").
  - The per-node rules that stop it recurring: deploy#246 (codewire services
    and Temporal) and infra#2525 (Kyverno, k8up, the storage operator). Not
    yet observed through a drain.

## `reboot-stun-relay`: STUN and the peer relay stay up

- **Entry points:** every tailnet connection: a client learns its public
  endpoint over STUN, and peers that can't reach each other directly use the
  UDP relay.
- **States to exercise:** the node that runs STUN and the relay drained; a
  pair of peers that needs the relay.
- **Driving it:** no command yet that forces a relayed path (#4461).
- **Proof:** STUN answers and a relayed pair moves to another relay within
  one discovery cycle (design for #3542, section 13, probes 7 and 8).
- **Gotchas:** STUN and the relay each run as one replica on one node today
  (#4461), so a drain of that node takes both down.
- **Observed:** not yet observed. During the second drain on 2026-11-13 both
  were down and a session still connected over direct UDP, which a sandbox's
  fixed direct address allows without either. A pair that needs the relay
  wasn't tested.

## `reboot-mesh`: Mesh keeps serving

- **Entry points:** `cw network` commands; every Mesh member's session.
- **States to exercise:** the node running Mesh drained; members on other
  nodes reaching each other meanwhile.
- **Driving it:** no command yet: Mesh runs one replica, pinned to one node
  by its volume, so draining that node takes Mesh down. Two replicas sharing
  their state are #3542's step 5.
- **Proof:** `cw network list` answers and two members on other nodes keep
  reaching each other throughout.
- **Gotchas:** the node that holds Mesh has not been drained for this reason.
- **Observed:** not yet observed.
