# Previews and ports

This walk proves that a server running in an environment can be reached from
the user's browser: through `cw ports` on a local VM, through a preview URL in
cloud, and (once #4316 lands) through an HTTPS hostname of its own on a local
VM; and, over SSH, a Unix socket in the environment (#5608). `SPEC.md` "Ports
and previews" and "Port forwarding over SSH" define them. The launch walk's
step 3 ([launch.md](launch.md), `launch-preview`) covers the cloud preview on
Production as part of the launch. This file holds the full set of states for
both placements. The format is in [README.md](README.md).

## Where the walk stands

Updated 2026-11-21.

| ID | Issue | Linux local VM | macOS local VM | Dev | Production |
| --- | --- | --- | --- | --- | --- |
| `ports-local-publish` | #4347 | observed on the branch, 2026-11-13 (#4415) | not yet observed | n/a | n/a |
| `preview-cloud-loopback` | #4357 | n/a | n/a | not yet observed | not yet observed |
| `ssh-socket-forward` | #5608 | observed 2026-11-20 (#5625) | not yet observed | observed 2026-11-21 (#5621) | not yet observed |
| `local-https-hostnames` | #4316 | no command yet | no command yet | n/a | n/a |
| `preview-host-variable` | #4316 | no command yet | no command yet | no command yet | no command yet |

## Before the walk

- Record `cw version` with every observation. A local VM runs the runtime of
  the `cw` that started it, so `cw setup --local` first, and stop and start an
  existing VM after an upgrade: a VM that an older runtime started keeps that
  runtime's port path until it restarts.
- Run the guest servers detached, so the shell that started them can end.
- Two guest servers make every case visible: one on `127.0.0.1` only, which
  is what most dev servers, `ng serve`, Vite and Compose's
  `127.0.0.1:P:P` publications do, and one on `0.0.0.0`. A walk with only the
  second passes when the loopback case is broken.

## `ports-local-publish`: `cw ports` on a local VM

Issue: #4347. Code: `crates/codewire-local-vmm/src/runner/host_port_forward.rs`,
`crates/codewire-local-vmm/src/guest_loopback.rs`.

- **Entry points:** `cw ports ENV --publish PORT [--host-port HOST_PORT]`,
  `cw ports ENV --unpublish PORT`, and `cw ports ENV` to list. Ports declared
  under `ports:` in `codewire.yaml` are published the same way.
- **States to exercise:**
  - a server on `127.0.0.1` only, and one on `0.0.0.0`;
  - a container in the guest published to the guest's loopback
    (`docker run -p 127.0.0.1:9003:80`);
  - a port with nothing listening;
  - port 2222, the workspace SSH server, which belongs to the platform;
  - unpublish, then publish again;
  - `cw` replaced under a running VM, as `cw upgrade` replaces it.
- **Driving it:**

  ```sh
  cw --local create --name ports-walk -y
  cw --local run --in ports-walk --detach --no-tty -- \
    python3 -m http.server --bind 127.0.0.1 9000
  cw --local run --in ports-walk --detach --no-tty -- \
    python3 -m http.server --bind 0.0.0.0 9001
  cw --local ports ports-walk --publish 9000 --host-port 29000
  cw --local ports ports-walk --publish 9001 --host-port 29001
  curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:29000/
  curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:29001/
  ss -ltn '( sport = :29000 or sport = :29001 )'
  cw --local ports ports-walk --publish 9002 --host-port 29002
  cw --local ports ports-walk --publish 2222 --host-port 29222
  cw --local ports ports-walk --unpublish 9000 --host-port 29000
  ```

- **Proof:**
  - both `curl`s print `200`;
  - `ss` shows the listeners on `127.0.0.1` only, and the host's network
    address refuses the port;
  - the publish of 9002 says "Nothing in ports-walk listens on
    127.0.0.1:9002 yet; connections are refused until a server listens
    there.";
  - the publish of 2222 says the port belongs to the platform;
  - after the unpublish, `curl` to 29000 is refused, and after publishing
    again it prints `200`.

  Before #4347, the loopback-only server's `curl` got an empty reply. That
  is the failure this sub-feature exists to catch.
- **Gotchas:**
  - A failed forward closes the host connection. Its reason is in the
    runner's diagnostic log as `host_port_forward_failed` with one of
    `nothing_listens`, `refused`, `daemon_unreachable` or `limit`, not in
    `cw`'s output.
  - A host port that another program holds can't be published. Pick a free
    one with `--host-port`.
- **Observed:**
  - Linux x86_64 KVM local VM, `cw` and runtime built from #4415's head
    `99f12fde7` (merged as `f6b69fcec`), 2026-11-13: every proof above held,
    including the Compose-style publication and both ports answering after
    `cw` was replaced (#4415). This was seen on the branch, not on a
    release.
  - macOS: not yet observed.

## `preview-cloud-loopback`: a cloud preview of a server on loopback

Issue: #4357. Code: `crates/codewire-orchestration/src/api/preview.rs`.

- **Entry points:** `cw ports ENV --publish PORT --label LABEL --access
  ACCESS`; the **Ports** dialog on the dashboard's Sandbox page; `ports:` in
  `codewire.yaml`.
- **States to exercise:** a server on `127.0.0.1` only, a server on
  `0.0.0.0`, a port with nothing listening, and a `creator` preview opened
  signed out, from a browser (#4700) and from `curl`.
- **Driving it:**

  ```sh
  cw run --in preview-walk --detach --no-tty -- \
    python3 -m http.server 3000 --bind 127.0.0.1
  cw run --in preview-walk --detach --no-tty -- \
    python3 -m http.server 3001 --bind 0.0.0.0
  cw ports preview-walk --publish 3000 --label loop --access creator
  cw ports preview-walk --publish 3001 --label all --access creator
  cw ports preview-walk
  ```

  Open each printed URL in a browser signed in as the creator. Then open
  one in a signed-out browser, sign in as the creator, and run
  `curl -i URL` with no credential.
- **Proof:**
  - Both URLs show the directory listing the server serves. A 502
    "preview backend unreachable" for the loopback server is the failure.
  - The signed-out browser reaches "Sign in to view preview", and after
    signing in it is back on the preview.
  - `curl` gets `401` with `WWW-Authenticate: Bearer realm="Codewire
    preview"` and a body saying to open the preview in a browser or send a
    Codewire API key. A bare `{"error":"unauthorized"}` is the failure.
- **Gotchas:** the public docs' preview example binds `0.0.0.0`
  (`use-cases/preview-environments.md`), which passes and hides the loopback
  case.
- **Observed:**
  - Not yet observed for the loopback server. #4357 reports, from reading
    the code, that it answers 502 because the proxy dials the Pod's address.
  - Signed out, on Dev source 14fb7f56a, 2026-11-14 (#4700): a headless
    Chromium went from the preview to the authorize step to
    "Sign in to view preview", and `curl` got a bare `401` with
    `{"error":"unauthorized"}`. Signing in and returning is not yet
    observed.

## `ssh-socket-forward`: a Unix socket in the environment, forwarded over SSH

Issue: #5608. Spec: `SPEC.md` "Port forwarding over SSH". Code:
`crates/codewire-workspace-access/src/ssh/forward.rs` and the guest daemon's
`ForwardUnix`.

- **Entry points:** `ssh -L LOCAL.sock:REMOTE.sock` and `ssh -W REMOTE.sock`
  to `cw-cloud-NAME` or `cw-local-NAME`, through the block `cw setup ssh`
  writes; tools that run them, such as Rex's `ssh://` hosts.
- **States to exercise:**
  - a socket the workload user serves, under the home directory, with the
    server reading its caller's peer credentials;
  - the environment's Docker socket;
  - a platform socket (the daemon's `mesh.sock`; the credential bridge's
    sockets where credentials are attached) by its path, through a symlink
    and through a hard link in the home directory;
  - a target under `/codewire` or `/run/codewire` that is not registered;
  - a target that is not a socket, a relative path, an abstract name
    (`@name`), a path over 107 bytes, and `ssh -R` with a socket;
  - on a local VM: a socket on a mount only the container sees (its `/tmp`),
    the environment's Docker socket through `/var/run/docker.sock`, which
    links to `/run/codewire-docker/docker.sock`, the two sockets under
    `/run/codewire-host`, a socket only root may open, and a VM whose
    runtime predates `ForwardUnix`;
  - 256 forwards open at once, TCP and Unix together, then one more (a test
    in `forward/tests.rs`, since a walk can't hold that many);
  - Rex: `rex server install ssh://cw-cloud-NAME`, then
    `rex -S NAME server status`.
- **Driving it:** with `walk` a running environment of each placement and
  `HOST` its alias (`cw-cloud-walk` or `cw-local-walk`). The paths below are
  a hosted Sandbox's, where the platform's socket is
  `/codewire/run/daemon/mesh.sock` and Docker's is `/run/docker/docker.sock`.
  On a local VM, first list the sockets the workload user sees, with
  `cw exec --in walk find /run /var/run /tmp /home /codewire -type s`, and
  use its platform sockets (under `/run/codewire`) and its Docker socket
  instead:

  ```sh
  # A server that answers each caller with its peer credentials.
  cw run --in walk --name peer --detach --no-tty -- python3 -c '
  import os, socket, struct
  p = os.path.expanduser("~/peer.sock")
  s = socket.socket(socket.AF_UNIX); s.bind(p); s.listen()
  while True:
      c, _ = s.accept()
      pid, uid, gid = struct.unpack("3i", c.getsockopt(
          socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
      c.sendall(b"uid=%d gid=%d\n" % (uid, gid)); c.close()'
  ssh -N -o ExitOnForwardFailure=yes \
    -L "$PWD/peer.sock:/home/codewire/peer.sock" HOST &
  socat - "UNIX-CONNECT:$PWD/peer.sock"
  ssh -W /home/codewire/peer.sock HOST </dev/null

  ssh -N -L "$PWD/docker.sock:/run/docker/docker.sock" HOST &
  docker -H "unix://$PWD/docker.sock" ps

  cw exec --in walk sh -c 'ln -s /codewire/run/daemon/mesh.sock ~/m-sym; ln /codewire/run/daemon/mesh.sock ~/m-hard'
  for t in /codewire/run/daemon/mesh.sock /home/codewire/m-sym \
           /home/codewire/m-hard /home/codewire/.bashrc ./peer.sock \
           "/home/codewire/$(printf 'x%.0s' $(seq 110))" /codewire/bin/cw; do
    ssh -W "$t" HOST </dev/null
  done
  ssh -N -o ExitOnForwardFailure=yes -R "/home/codewire/r.sock:$PWD/peer.sock" HOST

  # A local VM only: a socket on the container's own /tmp, which a walk
  # under the workload's root would not see.
  cw run --in walk --name tmp-peer --detach --no-tty -- python3 -c '
  import socket
  s = socket.socket(socket.AF_UNIX); s.bind("/tmp/peer.sock"); s.listen()
  while True:
      c, _ = s.accept(); c.sendall(b"from /tmp\n"); c.close()'
  ssh -W /tmp/peer.sock HOST </dev/null

  # A local VM only: a socket only root may open.
  cw exec --in walk sudo python3 -c 'import os, socket, time
  s = socket.socket(socket.AF_UNIX); s.bind("/run/root-only.sock")
  os.chmod("/run/root-only.sock", 0o600); s.listen(); time.sleep(600)' &
  ssh -W /run/root-only.sock HOST </dev/null
  ```

- **Proof:**
  - `socat` and `ssh -W` print `uid=1000 gid=1000`: the server saw the
    workload user, on both placements. On a local VM, `uid=0` is the
    failure.
  - `docker ps` lists the environment's containers.
  - Each platform target, by path, symlink or hard link, is refused with
    "administratively prohibited" and a reason naming the socket, such as
    "… is the daemon's mesh socket, which belongs to the platform". A
    connection that opens is the failure.
  - `.bashrc` (not a socket), `./peer.sock` (relative), the long path and
    `/codewire/bin/cw` (the platform's directory) are refused, each with its
    reason; `ssh -R` exits with "remote port forwarding failed". On a local
    VM `ssh -W /tmp/peer.sock` prints `from /tmp`, `docker version` through
    a forward of `/var/run/docker.sock` names the environment's Docker, both
    `/run/codewire-host` sockets are refused, the root-only socket
    is refused for permission, and an old runtime refuses with a reason
    naming the runtime.
  - The environment's log has one line per forward, opened or refused, with
    the target path escaped and the reason.
  - `rex -S NAME server status` connects, with the Rex server on its own
    socket and no TCP listener.
- **Gotchas:**
  - OpenSSH sends a socket target only if it contains a `/`, so `ssh` can
    send `./peer.sock` but not an abstract name; the abstract case is a test
    in `forward/tests.rs`, below OpenSSH.
  - A hard link to a socket needs the link in the same filesystem as the
    socket. Where it can't be made, record that and keep the symlink case.
  - `StreamLocalBindUnlink=yes` lets a rerun reuse `LOCAL.sock`; without it
    a leftover local socket makes `ssh` fail before any channel opens.
- **Observed:**
  - Linux local VM, 2026-11-20 (codewire-79), `cw` and runtime built from
    #5625 at 9db31c470f: a server in the home directory and one on the
    container's own `/tmp` tmpfs each saw uid=1000 gid=1000 groups=1001
    through `ssh -W` and `ssh -L`, the same as a workload process; a
    root-only socket was refused for permission; the credential bridge's
    socket was refused by identity, directly and through a symlink (a hard
    link can't be made across the mount); `poweroff.sock` was refused by
    the backstop; `.bashrc` and `./peer.sock` were refused. The Docker
    socket was refused by the `/run/codewire-*` backstop, the finding the
    exemption fixes. Evidence: the walk comment on #5608.
  - Linux local VM, 2026-11-20 (codewire-79), at c9f699bf4d with the
    exemption: `docker version` through `ssh -L` of `/var/run/docker.sock`
    answered from the environment's Docker (server 29.9.2, kernel
    6.18.48-codewire3), and both `/run/codewire-host` sockets were still
    refused. Evidence: the walk comment on #5608.
  - Dev at source 6ef416acfb, 2026-11-21, the Dev smoke identity
    with `cw` v0.4.24: a server in the home directory saw uid=1000 gid=1000
    groups=1000 1001 (the hosted daemon, uid 1000, connects itself); the
    daemon's Mesh socket was refused by identity, directly and through a
    symlink; `/codewire/bin/cw` was refused as not a socket; `docker info`
    through `ssh -L` of `/run/docker/docker.sock` named the Sandbox's own
    Docker. The credential bridge's sockets need credentials attached, which
    the organization-scoped smoke key can't do: not yet observed on Dev.
    Evidence: the walk comment on #5608.
  - Production: not yet observed.

## `local-https-hostnames`: an HTTPS hostname per labelled port on a local VM

Issue: #4316. No command yet: the router, `cw local-https setup`, `trust` and
`untrust` are not built. The plan is on #4316.

- **Entry points (planned):** a `ports:` entry with a `label` in
  `codewire.yaml`; `cw ports ENV` and `cw ports ENV --output json`, which
  show each URL; `cw create`, which prints them.
- **States to exercise (planned):**
  - two local VMs serving their own `https://<label>-<env>.cw.localhost` at
    the same time, each signed in to an app in its own browser session;
  - a server bound only to the guest's `127.0.0.1`;
  - a WebSocket through the hostname;
  - the app sees its host with no port, and `X-Forwarded-Proto: https`;
  - Linux without `sudo cw local-https setup`: `cw` says why port 443 needs
    it and what the setup changes;
  - another program holding port 443: `cw` names it and asks;
  - a stopped VM: its hostnames refuse connections;
  - no labelled ports: nothing changes.
- **Observed:** not yet observed.

## `preview-host-variable`: an environment knows its own preview host

Issue: #4316. No command yet.

- **Entry points (planned):** `CODEWIRE_PREVIEW_HOST_<port>` and, for a
  labelled port, `CODEWIRE_PREVIEW_HOST_<LABEL>` in every workload process,
  set at each start, locally and in cloud.
- **States to exercise (planned):** a local VM, a cloud Sandbox, and a
  snapshot copy under a new name, which gets its own host.
- **Observed:** not yet observed.
