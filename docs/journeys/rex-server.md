# A Rex server in an environment

This journey proves that a user can run a Rex server inside a cloud
environment or a local VM and use it from the Rex on their own computer, as
the Rex guide describes in "Run a Rex server in an environment"
(`apps/docs/zola/content/integrations/rex.md`). It is a walk across features
that already exist: the hosts `cw setup ssh` defines and Unix-socket
forwarding over SSH (#5608). The format is in [README.md](README.md).

## Where the journey stands

Updated 2026-11-21.

| ID | Dev (cloud environment) | Local VM (Linux) | Production |
| --- | --- | --- | --- |
| `rex-server-install` | observed 2026-11-21 | observed 2026-11-21 | not yet observed |
| `rex-server-connect` | observed 2026-11-21, with the `rex` command line; not with the Rex app | observed 2026-11-21, the same | not yet observed |
| `rex-server-recover` | observed 2026-11-21 | observed 2026-11-21 | not yet observed |

On Dev the commands ran as the synthetic Dev identity with `cw` v0.4.24,
while Dev's promoted source was e62d4d033e, then 6493623002 from 14:23Z;
both include #5621. The local VM ran `cw` and a runtime both built from
#5752's 9c657256e8, which includes #5625. Rex was the computer's installed
build and the snapshot a086db17db in the environment. The record is #5608.

A local VM on a runtime with #5625 but not #5752 connects at the SSH level
and then hangs: Rex's install says it could not reach the server, and
`rex -S` times out. Its forward helper held back what the server sent after
the last newline, and Rex's first message has none (observed at main
a7b8429ab5 on 2026-11-21).

Before #5608, Rex's `ssh://` host could not connect: the environment's SSH
server refused the socket forward with `open failed: administratively
prohibited`, and the guide gave the server an anonymous TCP listener instead
(observed on Dev and in a local VM on 2026-11-20).

## Before the walk

- The computer needs Rex, `cw`, and an `ssh` new enough for `%n` (see
  `cw setup ssh --help`).
- On Dev, `scripts/runtime/dev/with-dev-smoke-auth.sh -- COMMAND` runs one
  command as the synthetic Dev identity. Never use a person's sign-in.
- Keep the walk away from a person's own SSH config and Rex hosts: run the
  computer's side in a disposable home. `rex server install` and
  `rex hosts edit` change the Rex hosts of whoever runs them.
- A local VM needs a runtime with Unix-socket forwarding (#5625, #5752); a `cw`
  built from source needs a runtime built from the same commit
  (`docs/dev/LINUX-LOCAL-VMS.md`).
- The examples call the environment `my-rex`. For a local VM, read
  `cw-local-my-rex` for `cw-cloud-my-rex`.

## `rex-server-install`: Rex's own install over the SSH host

**Entry points:** `rex server install ssh://cw-cloud-NAME` or
`ssh://cw-local-NAME`, after `cw setup ssh`.

**States to exercise:** an environment without Rex; the systemd warning Rex
ends with.

**Driving it:**

1. `cw create --cloud --name my-rex` (or `--local`), then `cw setup ssh`.
2. `rex server install ssh://cw-cloud-my-rex --label my-rex --yes`. Its
   output shows `+ ssh cw-cloud-my-rex …` lines, then
   `Installed Rex in ~/.local/bin on cw-cloud-my-rex.`,
   `The server on cw-cloud-my-rex answered through ssh.`, a warning that the
   host has no systemd, and `Added my-rex to your hosts.`

**Proof:** `cw exec --in my-rex -- ps -eo pid,sid,args` shows
`/home/codewire/.local/bin/rex server run --listen unix:///home/codewire/.local/state/rex/run/server.sock …`
in its own session, and `rex hosts` lists `my-rex` at
`ssh://cw-cloud-my-rex`.

**Gotchas:** the install downloads Rex inside the environment (its
`+ fetch` lines); a network policy that refuses those hosts was not
exercised.

## `rex-server-connect`: the computer's Rex reaches the server

**Entry points:** a Rex host whose endpoint is `ssh://cw-cloud-NAME` or
`ssh://cw-local-NAME`.

**States to exercise:** a first connection; a `rex` command inside the
environment.

**Driving it:**

1. `rex -S my-rex server status` shows `you: uid 1000 over unix` and one
   socket listener,
   `unix:///home/codewire/.local/state/rex/run/server.sock (unix, peer_credentials, primary)`,
   beside the login server's socket. No TCP listener.
2. `rex -S my-rex new work`, then `rex -S my-rex ls` lists `work`.
3. `cw exec --in my-rex -- sh -c '~/.local/bin/rex ls'` lists `work` too.

**Proof:** `rex -S my-rex send -s work 'hostname'` with a newline, then
`rex -S my-rex capture -s work`, shows the environment's host name, not the
computer's. No `ssh` process stays running on the computer between
commands.

**Gotchas:** the `rex` command line has no terminal attach; the Rex app's
view of the host is a separate observation.

## `rex-server-recover`: after a stop

**Entry points:** `cw stop`, `cw start`, then any `rex -S NAME` command.

**States to exercise:** the environment stopped; the environment started
again.

**Driving it:**

1. `cw stop my-rex`, then `rex -S my-rex ls`.
2. `cw start my-rex`, then `rex -S my-rex ls`.

**Proof:** after step 1 the command answers
`host "my-rex" could not be reached` and exits 4. After step 2 it lists
`work`, `rex -S my-rex server status` shows a server started after the
environment's start, and `work` has a new shell.
