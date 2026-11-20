# A Rex server in an environment

This journey proves that a user can run a Rex server inside a cloud
environment or a local VM and use it from the Rex on their own computer, as
the Rex guide describes in "Run a Rex server in an environment"
(`apps/docs/zola/content/integrations/rex.md`). It is a walk across features
that already exist: the hosts `cw setup ssh` defines, named sessions and SSH
port forwarding. The format is in [README.md](README.md).

## Where the journey stands

Updated 2026-11-20.

| ID | Dev (cloud environment) | Local VM (Linux) | Production |
| --- | --- | --- | --- |
| `rex-server-install` | observed 2026-11-20 | observed 2026-11-20 | not yet observed |
| `rex-server-session` | observed 2026-11-20 | observed 2026-11-20 | not yet observed |
| `rex-server-connect` | observed 2026-11-20, with the `rex` command line; not with the Rex app | observed 2026-11-20, the same | not yet observed |
| `rex-server-recover` | observed 2026-11-20 | observed 2026-11-20 | not yet observed |

Both walks used a `cw` built from main 036f7dfc23. On Dev the commands ran as
the synthetic Dev identity; Dev's latest promoted source during the last run
was b35c34a541. The local VM ran a runtime built from the same commit as its
`cw`. Rex was 0.0.1794283804-gc3af96 on the computer and the snapshot
a086db17db in the environment. The record is the pull request that added
this file.

## Before the walk

- The computer needs Rex, `cw`, and an `ssh` new enough for `%n` (see
  `cw setup ssh --help`).
- On Dev, `scripts/runtime/dev/with-dev-smoke-auth.sh -- COMMAND` runs one
  command as the synthetic Dev identity. Never use a person's sign-in.
- Keep the walk away from a person's own SSH config and Rex hosts: run the
  computer's side in a disposable home. `rex server install` and
  `rex hosts edit` change the Rex hosts of whoever runs them.
- The examples call the environment `my-rex`. For a local VM, read
  `cw-local-my-rex` for `cw-cloud-my-rex`.

## `rex-server-install`: Rex's own install over the SSH host

**Entry points:** `rex server install ssh://cw-cloud-NAME` or
`ssh://cw-local-NAME`, after `cw setup ssh`.

**States to exercise:** an environment without Rex; the two warnings Rex
ends with; a server Rex's connection attempt left running.

**Driving it:**

1. `cw create --cloud --name my-rex` (or `--local`), then `cw setup ssh`.
2. `rex server install ssh://cw-cloud-my-rex --label my-rex --yes`. Its
   output shows `+ ssh cw-cloud-my-rex …` lines, then
   `Installed Rex in ~/.local/bin on cw-cloud-my-rex.`, a warning that the
   host has no systemd, a warning that it could not reach the server through
   ssh, and `Added my-rex to your hosts.`
3. `cw exec --in my-rex -- rex server stop`. It prints `Rex server stopped.`
   when the attempt left a server (seen in the local VM, and in some runs on
   Dev), and `Error: rex server is not running` with status 1 when it did not
   (most runs on Dev).

**Proof:** `cw exec --in my-rex -- sh -c 'command -v rex'` prints
`/home/codewire/.local/bin/rex`, and `rex hosts` lists `my-rex` at
`ssh://cw-cloud-my-rex`.

**Gotchas:** `rex -S my-rex` cannot connect at this point. Rex forwards a
Unix socket (`ssh -L LOCAL.sock:REMOTE.sock`) and the environment's SSH
server answers `open failed: administratively prohibited` (#5608);
`rex -vv` shows both lines. The install downloads Rex inside the environment (its
`+ fetch` lines); a network policy that refuses those hosts was not
exercised.

## `rex-server-session`: the server as a named session

**Entry points:** `cw run --in ENV --name rex --detach -- rex server run …`.

**States to exercise:** a first start; a port that is taken; a leftover Rex
server holding Rex's socket; a session name used before; stopping the
session.

**Driving it:**

1. `cw run --in my-rex --name rex --detach -- rex server run --extra-listen http://127.0.0.1:7350 --allow-anonymous`.
   It prints `✓ Started session my-rex/rex`.
2. `cw logs my-rex --session rex` ends with a warning that the TCP listener
   admits every caller anonymously, and `Rex server ready`.

**Proof:** `cw ls my-rex` shows `rex` as `Running`, and
`cw exec --in my-rex -- rex ls` answers from inside the environment. After
`cw stop my-rex --session rex` nothing listens on port 7350 and no Rex
server runs; `cw restart my-rex --session rex` brings the listener back
(observed on Dev).

**Gotchas:** without `--allow-anonymous` the session exits at once and its
log says Rex cannot identify the callers of a TCP endpoint. A taken port
(7777 in a cloud environment) exits with `address already in use`. A
leftover server exits it with `server endpoint is already in use`; stop that
server, then `cw restart my-rex --session rex`, because `--name` never
reuses a name. The guide warns that VS Code forwards the listener's port to
the computer unless told not to; that was not exercised with an editor. Its
warning about a browser inside the environment rests on a probe of the same
Rex snapshot: the listener answered a WebSocket request whose `Origin` was
another site with 403, and one whose `Host` and `Origin` were both a made-up
name on port 7350 with 101.

## `rex-server-connect`: the computer's Rex reaches the server

**Entry points:** an `ssh -L` forward over the `cw-cloud-NAME` or
`cw-local-NAME` host, and a Rex host whose endpoint is the forward's local
end.

**States to exercise:** the forward up; the forward down.

**Driving it:**

1. `ssh -f -N -o ExitOnForwardFailure=yes -o StreamLocalBindUnlink=yes -L ~/.ssh/my-rex.sock:127.0.0.1:7350 cw-cloud-my-rex`.
2. `rex hosts edit my-rex --endpoint "unix://$HOME/.ssh/my-rex.sock"`.
3. `rex -S my-rex server status` lists the listener
   `http://127.0.0.1:7350 (tcp, anonymous)`.
4. `rex -S my-rex new work`, then `rex -S my-rex ls` lists `work`.

**Proof:** `rex -S my-rex send -s work 'hostname'` with a newline, then
`rex -S my-rex capture -s work`, shows the environment's host name, not the
computer's. The socket in `~/.ssh` has mode 0600.

**Gotchas:** with the forward down, every `-S my-rex` command answers
`host "my-rex" could not be reached`. The `rex` command line has no terminal
attach; the Rex app's view of the host is a separate observation.

## `rex-server-recover`: after a lost forward and after a stop

**Entry points:** the same `ssh` command; `cw stop`, `cw start` and
`cw restart ENV --session rex`.

**States to exercise:** the forward ended while the environment ran; the
environment stopped and started.

**Driving it:**

1. End the `ssh` process, run the same `ssh` command again, then
   `rex -S my-rex ls`.
2. `cw stop my-rex`, `cw start my-rex`,
   `cw restart my-rex --session rex`, the same `ssh` command again, then
   `rex -S my-rex ls`.

**Proof:** after step 1, `work` is listed and its screen still shows the
earlier output. After step 2, `work` is listed again with a new shell.

**Gotchas:** after a stop, `cw ls my-rex` shows the session as `Stopped` in
a cloud environment and `Interrupted` in a local VM until it is restarted.
The old `ssh` may still be running after a stop and start; the same command
replaces its socket.
