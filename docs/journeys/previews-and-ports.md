# Previews and ports

This walk proves that a server running in an environment can be reached from
the user's browser: through `cw ports` on a local VM, through a preview URL in
cloud, and (once #4316 lands) through an HTTPS hostname of its own on a local
VM. `SPEC.md` "Ports and previews" defines the feature. The launch walk's
step 3 ([launch.md](launch.md), `launch-preview`) covers the cloud preview on
Production as part of the launch. This file holds the full set of states for
both placements. The format is in [README.md](README.md).

## Where the walk stands

Updated 2026-11-13.

| ID | Issue | Linux local VM | macOS local VM | Dev | Production |
| --- | --- | --- | --- | --- | --- |
| `ports-local-publish` | #4347 | observed on the branch, 2026-11-13 (#4415) | not yet observed | n/a | n/a |
| `preview-cloud-loopback` | #4357 | n/a | n/a | not yet observed | not yet observed |
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
  `0.0.0.0`, and a port with nothing listening.
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

  Open each printed URL in a browser signed in as the creator.
- **Proof:** both URLs show the directory listing the server serves. A 502
  "preview backend unreachable" for the loopback server is the failure.
- **Gotchas:** the public docs' preview example binds `0.0.0.0`
  (`use-cases/preview-environments.md`), which passes and hides the loopback
  case.
- **Observed:** not yet observed. #4357 reports, from reading the code, that
  the loopback server answers 502 because the proxy dials the Pod's address.

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
