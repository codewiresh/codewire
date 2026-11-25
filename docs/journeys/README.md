# Journeys

A journey file says how to prove that one user-facing feature works: what to
run, what must be seen, and when it was last seen. `AGENTS.md` ("Done means
observed working") requires every user-visible change to walk its acceptance
journey. The journeys are written down here so that the next person or agent
runs the same commands and holds the result to the same standard.

| File | Journey |
| --- | --- |
| [tool-compatibility.md](tool-compatibility.md) | Homepage compatibility cards and the Rex/Orca plugin setup guides: branding, links, agent rotation, themes and mobile layout |
| [agent-quickstart.md](agent-quickstart.md) | Copy a setup prompt or follow the human walkthrough with the public TanStack Router and Vite example |
| [public-controls.md](public-controls.md) | Public-site pill buttons and rounded segmented controls on the homepage and pricing page |
| [homepage-safety.md](homepage-safety.md) | The homepage Safety section: the credential proxy and network egress control panels, their animation, reduced motion, no JavaScript, themes and widths |
| [rex-server.md](rex-server.md) | A Rex server inside a cloud environment or a local VM: Rex's own install over the `cw setup ssh` host, the computer's Rex reaching the server over a Unix-socket forward, and what happens after a stop |
| [launch.md](launch.md) | The public-launch walk (#4370), step by step: what the launch asks of each step, which journey below holds it, and where the walk stands |
| [nix-install.md](nix-install.md) | Installing `cw` with Nix (#5399): `nix run` and `nix profile install` from the public flake, the released bytes, `cw upgrade` deferring to Nix, and a release moving the flake. Written first; only the local half of a wrong hash's refusal is observed |
| [homebrew-install.md](homebrew-install.md) | Installing `cw` with Homebrew (#5407): `brew trust` and `brew install` from the tap, the released bytes, Homebrew's own checks, `cw upgrade` deferring to Homebrew, and a release moving the tap. Linux x86_64 observed; macOS not yet observed |
| [local-vm-mac.md](local-vm-mac.md) | Local VMs on a Mac (#4370 step 11): install, create, shell, run, stop and start on macOS 27 and 26 |
| [local-vm-upgrade.md](local-vm-upgrade.md) | Local VMs across an upgrade that changes the guest runtime ABI (#4980): a start moves a stopped environment onto the installed runtime, and old VM checkpoints say why they can't be restored and can be removed |
| [local-vm-credentials-smoke.md](local-vm-credentials-smoke.md) | The automated local VM credentials and proxy smoke (#5220): a profile added after create, each credential type through the proxy and revoked, attach across a restart, an upgrade with the previous release's authority or VM in place, and the proxy down |
| [local-vm-limits.md](local-vm-limits.md) | Limits inside a local VM (#5384, #5464): a workload that forks without end is refused by the guest, and the VM stays up; `sudo` works with Docker on and refuses with `--no-docker` |
| [local-vm-docker.md](local-vm-docker.md) | Docker in a local VM (#5418): `docker exec` runs in the container it names, also after the VM is stopped and started |
| [local-vm-git.md](local-vm-git.md) | Git in a local VM's mounted folder (#5478): a mounted checkout, its nested repositories and submodules work with nothing set by hand, and a user's own `safe.directory` lines stay |
| [local-vm-linux.md](local-vm-linux.md) | Local VMs on Linux: the steps that differ from the Mac's, starting with the shared image disk (#4646, trial branch) |
| [invitations.md](invitations.md) | Invite a teammate by email, who accepts, is listed and can be removed, within the invitation limits |
| [email.md](email.md) | Every email Codewire sends (#4553): one plain layout and a text part, from `Codewire <hello@codewire.sh>`, and which have been seen arriving |
| [self-hosted.md](self-hosted.md) | The self-hosted walk (#4121): install, the first admin, invite links and sign-up without an invite |
| [interruptions.md](interruptions.md) | Every way a running cloud Sandbox is restarted, stopped, cut off or disconnected (#6084): what the user sees for each, the journey that proves it, and the issue for each gap |
| [node-reboot.md](node-reboot.md) | Production keeps serving through one node's drain or reboot, and a sandbox on that node says why it restarted (#3542, #4461, #3772) |
| [billing-and-credits.md](billing-and-credits.md) | Compute credit (#3381): add a card, top up, add credit, the receipt, costs in credits and the empty-balance refusal |
| [previews-and-ports.md](previews-and-ports.md) | Reaching a server in an environment: `cw ports` on a local VM (#4347), cloud previews of loopback servers (#4357), local HTTPS hostnames (#4316), and Unix sockets forwarded over SSH (#5608) |
| [cloud-sandbox.md](cloud-sandbox.md) | A cloud sandbox: create it, see why a create failed, run commands and shells, stop a session and every process it started, stop and start it and restart its sessions by name, the list of steps its page shows while it starts, copy files with `cw cp`, and keep working across an orchestration rollout |
| [sdk-files.md](sdk-files.md) | File calls from the SDKs (#5804): `stat` and `exists` on a file, a folder, a symlink and a missing path, and many files written in one call. Written first; every step is not yet observed |
| [environment-labels.md](environment-labels.md) | Environment labels (#5804): set at create, changed, and used to find environments, in the cloud, on a local VM and from the four SDKs, within their limits. Written first; every step is not yet observed |
| [systemd-workspace.md](systemd-workspace.md) | A cloud sandbox that boots systemd (#5638): systemd as PID 1 for every session, with the daemon as a unit, sessions and Docker as in a default sandbox, a user's own units across a restart, a clean stop, and `rex server install`. Written first; not yet observed |
| [standard-runtime.md](standard-runtime.md) | A cloud sandbox on the `standard` runtime profile (#5602): the VM Codewire's own runtime starts inside the Pod, commands and Docker in it, its network through the node's egress service, stop and start, the admission rule, and the other profiles left alone. Written first; every step is not yet observed |
| [idle-stop.md](idle-stop.md) | Idle stop (#3384): a cloud Sandbox nobody uses stops itself after its timeout, keeps its files and says why; CPU, input, agent turns and preview requests keep it up. Observed on Dev 2026-11-21, but the agent, a gone daemon, the dashboard, the browser terminal and a signed-in preview |
| [fast-start.md](fast-start.md) | Fast sandbox starts (#2238): a create from the warm pool usable in seconds, under 5% of Production creates cold, and no image pull on the first start after a release |
| [editor.md](editor.md) | A cloud sandbox in a desktop editor over Remote-SSH (#4641): `cw vscode`, `cw setup ssh`, editing, a reconnect after sleep, and what a failed connection says |
| [signup-and-verification.md](signup-and-verification.md) | Getting an account and proving its address: email sign-up, verification, GitHub and Google, and the abuse gates (#4481, #4062, #3297, #2053) |
| [hosts.md](hosts.md) | Hosts (#3609): enroll a computer, keep its agent connected through proxies, logouts and reboots, the Hosts page, and environments created on a host |
| [snapshots-and-forks.md](snapshots-and-forks.md) | Disk snapshots and forks: capture, list, inspect and remove a snapshot, and create sandboxes from it, in the cloud and on a local VM (#3046, #4370); VM checkpoints of a local VM, restored in place or forked, on Linux and a Mac (#4654) |
| [claude-in-a-sandbox.md](claude-in-a-sandbox.md) | Claude Code starts in a Sandbox with no screen (#5813): typed or detached, in bypass permissions mode, a managed agent in bypass mode, the user's own settings kept, and an administrator's off switch. Observed on Dev 2026-11-22, but the off switch and a local VM |
| [credentials.md](credentials.md) | Connecting provider credentials with `cw credentials`, the same with `--local` and `--cloud` (#4717): first the Claude sign-in (#4714) |
| [updates.md](updates.md) | The public Updates page: a Liminal CMS site's posts, newest first, the sidebar link, the CMS down and the page switched off. The empty state observed on Dev and Production, the sidebar link on Dev; a published post not yet observed |
| [analytics.md](analytics.md) | Web analytics (infra#2677): cookie-free page counts on the public pages with Codewire's own copy of Umami's tracker; the homepage for every visitor, the other public pages only signed out, and no other page. Written first; not yet observed |
| [feedback.md](feedback.md) | Feedback (#4061): `cw feedback` signed in and anonymous, the stored row, the hourly limits and the admin page |
| [sandbox-identity.md](sandbox-identity.md) | Sandbox identity (#4661): each organization's OIDC issuer, its keys and their rotation, the groups and audiences an admin sets, the tokens a Sandbox mints for Kubernetes, OpenBao and cloud verifiers, and the token files. Discovery and custody observed on Dev; audiences, stop and resume, limits and audit records partly; the token files not yet built |
| [network-and-egress.md](network-and-egress.md) | Network policies, refusals and agents through the front door (#3997): choosing what an environment may reach, the refusal log, and Claude Code and Codex with stock settings and no token inside. Written first; every step is not yet observed |
| [audit-log.md](audit-log.md) | A hosted Sandbox's audit log (#6189): access, lifecycle, policy, refusals and credential use, who may read it, `cw audit` and the dashboard page. Written first; every step is not yet observed |
| [own-tailnet.md](own-tailnet.md) | Your own tailnet from a cloud sandbox (#5741): the image's `tailscale` in userspace mode, joining with a one-use key, reaching a tailnet service through the local proxy, relays without UDP, refused keys, leaving, and Codewire's own networking untouched. Observed on Dev 2026-11-23, but `cw network connect` while joined and the refusal log |
| [ios-app.md](ios-app.md) | The iOS app (#3825): create an environment from the app, follow its setup steps and open its shell. Written first; not yet observed |
| [cli-completion.md](cli-completion.md) | Tab completion of names in `cw` (#5108): environments, sessions, credentials, profiles, policies, mesh networks, presets, snapshots, checkpoints and organizations in zsh, bash and fish, bounded and never prompting. Written first; every step is not yet observed |
| [mesh.md](mesh.md) | Mesh Networks (#3350, #5115, #5118, #5119): Sandboxes on one Mesh Network reach each other's published ports and nothing else does, and the dashboard shows the same Mesh Networks, nodes and join state as `cw`. Written first; every step is not yet observed |
| [account-access.md](account-access.md) | What an account can still reach after a sign-out, a disable or a revoked credential (#3586): first, a terminal ticket from a session that has ended |
| [host-bound-secrets.md](host-bound-secrets.md) | Host-bound application secrets (#4003): a secret bound to hosts reaches the environment as a placeholder and is swapped only on those hosts, the re-entry rule, host changes, hints, presets and the dashboard. Written first; every step is not yet observed |
| [api-keys.md](api-keys.md) | API keys (#5688): permissions and an expiry chosen at creation, made only from a sign-in, keys from before, what ends a key, and its audit. Written first; every step is not yet observed |
| [sdk-sign-in.md](sdk-sign-in.md) | Signing in from the environment (#5687, #5688): an SDK, a script or `cw` with an API key or a user token from `cw auth token`, from code, the environment or `.env`; what ends a user token; binding a profile with one. Written first; every step is not yet observed |
| [native-sign-in.md](native-sign-in.md) | Staying signed in (#6145): `cw`, the desktop app and the iOS app across a 1-hour access token's expiry, refreshing ahead and once on a refused token, with no sign-in screen until the sign-in ends. Written first; every step is not yet observed |
| [admin-overview.md](admin-overview.md) | Admin → Overview (#5304): the Sandboxes card shows the ones active now, and nothing else. Admin → Organizations (#6086): each organization's Sandboxes created, running, stopped, failed and deleted, with totals. Written first; not yet observed |
| [deletion.md](deletion.md) | Deleting an account or an organization (#4823): the account-deletion page and `cw org delete` say it is permanent, before it happens |
| [dashboard-keyboard.md](dashboard-keyboard.md) | Keyboard focus in the dashboard (#4531, #4533): the Create Sandbox drawer is modal and returns focus to its opener, and a control waiting on its request keeps focus. Written first; every step is not yet observed |
| [desktop.md](desktop.md) | An environment's desktop (#3223): `cw desktop`, the dashboard's Desktop panel, an agent drawing on `DISPLAY=:1`, its Codewire look and Chromium, who may open it, and what ends it. `cw desktop` observed from Linux on Dev, Production and a Linux local VM, and from macOS on Dev; the Desktop panel partly on Kind and Dev, not yet in Production |
| [edge-caching.md](edge-caching.md) | Caching at the edge (#5054, #5123, #5072): no cache in front of Codewire keeps one caller's response for another; the homepage is the one reviewed exception. Observed on Dev 2026-11-21 |

## What a journey file holds

A file opens with one paragraph naming the feature and its `SPEC.md` section,
or, for a walk across features, the issue that defines it. Then each
sub-feature has a short stable ID and these fields, in this order:

- **Entry points:** every way a user reaches it (dashboard, `cw`, SDK).
- **States to exercise:** the empty, failure and recovery states, not only
  the one that works.
- **Driving it:** the preconditions, then each action as the exact command
  and the result a user can see.
- **Proof:** the value that tells success from failure. "It answered" is not
  proof; a checksum, an ID that changed or a balance that moved is.
- **Gotchas:** what wastes a run or makes its result meaningless.
- **Observed:** one line per observation, as below.

## What "observed" means

A sub-feature is observed when someone ran its commands on a named surface
and saw the result. The record gives:

- the surface (a local VM, Kind, Dev, Production);
- the source commit or release that surface was running;
- the date, and where the evidence is (an issue comment or a pull request).

Everything else reads **not yet observed**. A passing test, a merged pull
request and a design are not observations. Dev and Production are recorded
separately, and an observation on Dev counts only on the source Dev had
rolled out.

## Rules

- A command, script or spec named here exists in this repository. Where
  nothing can drive a step yet, the file says "no command yet" and names the
  issue. A gap is written down, never worked around. Policy holds the paths
  to this: `python3 scripts/checks/repo_checks.py journey-paths` fails on a
  repository path, in inline code or a code block, that is not in the tree,
  and on a link to a file that does not exist. It does not check that a `cw`
  command exists.
- A journey is never weakened to pass. A proof through one entry point does
  not count for the others.
- A proof on a stand-in (Kind for Dev, Dev for Production) lists what the
  stand-in did that the real target will not.
- This is public text: no private hosts, no credentials, no names of people's
  machines.

## Not built yet

These belong to #4356 and do not exist. Do not rely on them:

- `covers:` lines that name the source paths a journey proves. Journey
  files carry none yet. Only the dashboard specs have them today
  (`docs/TESTING.md`).
- `scripts/dev/preflight.sh --explain` printing the journeys a change
  selects.

## Adding or changing a journey

1. Check that every command and path exists before writing it down.
2. Run it. Record what was seen under **Observed**, or write "not yet
   observed".
3. When behaviour changes, change the journey in the same pull request, and
   remove an observation that no longer describes the product.
