# Mesh Networks

This walk proves that Sandboxes and local VMs on one Mesh Network reach each
other's published ports and nothing else does, and that the dashboard shows
the same Mesh Networks, nodes and join state as `cw`. `SPEC.md` "Networking
and egress" defines Mesh. The user docs are
`apps/docs/zola/content/networking/mesh.md` and
`apps/docs/zola/content/use-cases/agentic-collaboration.md`. The format is in
[README.md](README.md).

The dashboard steps are written first, as the owner's rule of 2026-11-15
(#3013) requires: a review refuses dashboard code this file does not
describe. Every step reads "not yet observed".

## Where the walk stands

Updated 2026-11-16. A Sandbox is recorded on Dev and on Production separately.

| ID | Issue | Kind | Dev | Production |
| --- | --- | --- | --- | --- |
| `mesh-cli` | #3350 | not yet observed | not yet observed | not yet observed |
| `mesh-sandbox-network` | #5115 | not yet observed | not yet observed | not yet observed |
| `mesh-networks-page` | #5118 | not yet observed | not yet observed | not yet observed |
| `mesh-network-on-create` | #5119 | not yet observed | not yet observed | not yet observed |

#3350's comments record a walk of `mesh-cli` on Dev (Standard and
Confidential, 2026-11-12) and on Production (Standard, 2026-11-13). It was
written before this file existed, so it is not carried here as an
observation; walk it again and record it in this file.

## Before the walk

- Record `cw version`, and for a dashboard step the dashboard's source commit.
- Use a throwaway organization, or names that mark the walk (`mesh-walk`,
  `mesh-walk-a`, `mesh-walk-b`, `mesh-walk-c`), and remove them at the end.
  A Mesh Network's name is retired for good when it is deleted, so use a
  fresh name for each walk.
- A walk on Production leaves its Mesh Network's name retired for good, so it
  is not wholly self-cleaning. Record the owner's yes on #3350 before the
  first Production walk.
- On Production, use the dedicated smoke identity
  (`scripts/runtime/prod/with-prod-smoke-auth.sh`) and only its own
  environments.

## `mesh-cli`: Sandboxes on one Mesh Network reach each other

Issue: #3350.

- **Entry points:** `cw --cloud network create | list | nodes | revoke |
  delete`; `cw --cloud create --network cloud:NAME`; `cw ports ENV --publish
  PORT`; `cw network connect NODE PORT` inside a Sandbox; `cw info ENV`.
- **States to exercise:**
  - two Sandboxes on the Mesh Network, and a third on none;
  - a port that is published, and one that is not;
  - a Sandbox stopped and started again;
  - a node revoked by a Mesh Network owner;
  - a Sandbox deleted;
  - deleting the Mesh Network while nodes remain, then after.
- **Driving it:**

  ```sh
  cw --cloud network create mesh-walk --org ORG_ID --no-use
  cw --cloud create --name mesh-walk-a --network cloud:mesh-walk -y
  cw --cloud create --name mesh-walk-b --network cloud:mesh-walk -y
  cw --cloud create --name mesh-walk-c -y
  cw info mesh-walk-a
  cw --cloud network nodes --org ORG_ID --network mesh-walk
  cw run --in mesh-walk-a --name server --detach -- python3 -m http.server 8000
  cw ports mesh-walk-a --publish 8000
  cw run --in mesh-walk-b --name probe-before --no-tty -- sh -c 'printf "GET / HTTP/1.0\r\n\r\n" | cw network connect mesh-walk-a 8000 | head -1'
  cw run --in mesh-walk-c --name probe-before --no-tty -- sh -c 'printf "GET / HTTP/1.0\r\n\r\n" | cw network connect mesh-walk-a 8000 | head -1'
  cw stop mesh-walk-a
  cw start mesh-walk-a
  cw --cloud restart mesh-walk-a --session server
  cw run --in mesh-walk-b --name probe-after --no-tty -- sh -c 'printf "GET / HTTP/1.0\r\n\r\n" | cw network connect mesh-walk-a 8000 | head -1'
  cw --cloud network delete mesh-walk --org ORG_ID --yes
  ```

  Then revoke `mesh-walk-b`'s node as the Mesh Network's owner, delete the
  three Sandboxes, and delete the Mesh Network.
- **Proof:**
  - `cw info` reads `Network: cloud:mesh-walk (attached)` for `mesh-walk-a`
    and `mesh-walk-b`, and `Network: not attached` for `mesh-walk-c`;
  - `nodes` lists both Sandboxes, each `reported online`;
  - the probe from `mesh-walk-b` prints `HTTP/1.0 200 OK`; the probe from
    `mesh-walk-c` fails with "this environment has not joined its Mesh
    network; `cw info` shows why";
  - after the stop, `mesh-walk-a` reads `reported offline` within 45 s, and
    after the start it is online again under the same node name;
  - after the start, the probe from the unchanged `mesh-walk-b` prints
    `HTTP/1.0 200 OK` again, without `mesh-walk-b` restarting: its
    subscription to `mesh-walk-a` outlived `mesh-walk-a`'s session, so Mesh
    sent it the new node (#5642);
  - after the revoke, `cw info mesh-walk-b` reads `(revoked by a network
    owner)` and its probe fails;
  - deleting the Mesh Network is refused while it has nodes, and succeeds
    after the Sandboxes are deleted;
  - no Sandbox holds a platform API key, a user sign-in, an invite code or
    a long-lived Mesh credential (#3350's acceptance).
- **Gotchas:**
  - Only published ports are served. `cw network connect` to a port that is
    not published prints nothing and exits 0 (#4258); publish first.
  - `cw run --name` never reuses a session's name, even a stopped one's. After
    the start, restart the stopped `server` session instead; its published
    port is kept across the stop.
  - Online means a live session with Mesh, not that two nodes reach each
    other. Only the probe proves reach.
  - Production Mesh runs one replica (#3542); a drain of its node takes Mesh
    down until the replacement starts.
- **Observed:** not yet observed.

## `mesh-sandbox-network`: a Sandbox's page names its Mesh Network

Issue: #5115.

- **Entry points:** the details menu on a Sandbox's page; its Ports dialog.
- **States to exercise:** a Sandbox on no Mesh Network; one joining; one
  joined; one not joined for each failure (`mesh_unreachable`,
  `network_not_found`, `not_a_member`, `node_name_taken`, any other refusal);
  one revoked; a change of state while the page is open.
- **Driving it:** with the Sandboxes of `mesh-cli`, open each one's page and
  its details menu, and its Ports dialog. Revoke a node while its page is
  open. The failure states that can't be caused on demand are driven through
  the dashboard's fixture specs with the same server responses.
- **Proof:**
  - the line reads the Mesh Network's name and the same words `cw info`
    prints for that state: "attached", "joining", "revoked by a network
    owner", or "not joined:" with "Mesh is unreachable; it retries", "the
    network does not exist", "its creator is not a member of the network",
    "another node in the network has its name" or "Mesh refused it";
  - a Sandbox on no Mesh Network says so, with a link to Mesh Networks;
  - the Ports dialog names the Mesh Network whose members reach each
    published port, and says an unpublished port is reached by no one;
  - a revoke changes the open page without a reload, from a live event, and
    the page makes no request without one.
- **Gotchas:** a Sandbox stays on the Mesh Network it was created on; the
  page offers no way to move it.
- **Observed:** not yet observed.

## `mesh-networks-page`: an organization's Mesh Networks in the dashboard

Issue: #5118.

- **Entry points:** Mesh Networks in the organization's navigation, and a
  Mesh Network's own page.
- **States to exercise:**
  - an organization with no Mesh Networks;
  - a Mesh Network with no nodes, and one with a Sandbox, a local VM and a
    trusted host;
  - a node going offline and online while the page is open;
  - an invite code made, then used by a machine;
  - a revoke by the Mesh Network's owner, and one by a member of their own
    local VM, and the Revoke a member may not use;
  - deleting a Mesh Network with nodes, and without;
  - creating one with a retired name;
  - Mesh not answering.
- **Driving it:** on the retained Kind cluster, then Dev, signed in as an
  organization owner and then as a member:
  1. Open Mesh Networks with none. Create `mesh-walk`.
  2. Create a Sandbox with `--network cloud:mesh-walk` and a local VM with
     `cw --local create --network cloud:mesh-walk`, and open the Mesh
     Network's page.
  3. Stop the Sandbox and wait; start it again.
  4. Make an invite code, and join a machine with `cw network join CODE`.
  5. As the member, revoke the local VM they created, then try to revoke the
     owner's machine. As the owner, revoke the joined machine.
  6. Delete `mesh-walk` with its Sandbox still on it; delete the Sandbox and
     the local VM, then delete it.
  7. Create a Mesh Network named `mesh-walk` again.
  8. Stop Mesh (Kind only), and open the page.
- **Proof:**
  - the list and each node's status, last heard and owner match `cw --cloud
    network list` and `cw --cloud network nodes` at the same moment;
  - the title "Mesh Networks" and Create Mesh Network share one line, with
    the description below, at 1440 and 390;
  - in step 3 the node reads Offline within 45 s and Online again, without
    a reload;
  - the invite code is shown once, with its expiry, and the joined machine
    appears in the list;
  - as the member, Revoke on the owner's machine and on a Sandbox's node is
    disabled and says who can revoke it, and a Sandbox's node says it leaves
    when its Sandbox is deleted; as the owner, every node offers Revoke,
    a Sandbox's node included (`crates/codewire-mesh/src/product.rs`);
  - step 6 is refused, and the page names the nodes still on the Mesh
    Network from its own node list, because Mesh's refusal names none; then
    it succeeds. Step 7 is refused because the name was retired;
  - with Mesh stopped the page says Mesh isn't answering and keeps what it
    last showed; nothing claims two nodes reach each other.
- **Gotchas:** the node kind (Sandbox, local VM, host) is not recorded by
  Mesh yet (#5118); until it is, the page shows only what it can prove.
- **Observed:** not yet observed.

## `mesh-network-on-create`: choose a Mesh Network when creating a Sandbox

Issue: #5119.

- **Entry points:** the Mesh Network field of the Sandbox create form.
- **States to exercise:** an organization with no Mesh Networks; one with
  two; a Mesh Network the creator is not a member of; the choice of None.
- **Driving it:** create a Sandbox from the dashboard on `mesh-walk`, and one
  with None, then read each with `cw info`.
- **Proof:** the Sandbox created on `mesh-walk` reads `(attached)` in
  `cw info` and appears on the Mesh Network's page; the one created with
  None names no network; with no Mesh Networks the field says so and links
  to Mesh Networks.
- **Gotchas:** the field says a Sandbox stays on the Mesh Network it was
  created on.
- **Observed:** not yet observed.
