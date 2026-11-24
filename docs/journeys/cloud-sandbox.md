# A cloud sandbox

This journey proves what a user does with a cloud sandbox, as `SPEC.md`
describes it in "4. Hosted sandboxes" and "7. Access paths": creating one,
what a create that fails leaves behind, the dashboard links that open the
credential dialog a sandbox needs, running commands and shells in it,
stopping and starting it, what its page shows while it starts, copying files
with `cw cp` ("File transfer" in section 7), what `cw` inside a sandbox
knows (section 8), and what a user sees while a release replaces the orchestration
service ("Rollouts drain" in section 10). Large `cw run` output is not written
yet; its owner adds it. The format is in [README.md](README.md).

## Where the journey stands

Updated 2026-11-24.

| ID | Owner | Dev | Production |
| --- | --- | --- | --- |
| `sandbox-create` | cw-cleanup | observed 2026-11-14; a taken name refused (#4717) not yet observed | not yet observed |
| `sandbox-create-fails` | cw-cleanup | observed 2026-11-17 (#4483) | not yet observed; v0.4.21 lacks #4483's reasons |
| `sandbox-credential-links` | cw-accounts | partly observed 2026-11-24 (Create's GitHub link, on every delivery) | not yet observed |
| `sandbox-failure-trace-id` | cw-tracing | observed 2026-11-23 (#5633) | not yet observed |
| `sandbox-run-exec` | cw-cleanup | observed 2026-11-14 | not yet observed |
| `sandbox-run-env` | cw-cli | not yet observed (#5222) | not yet observed |
| `sandbox-shell` | cw-cleanup | observed 2026-11-14 | not yet observed |
| `sandbox-msg-session` | cw-cli | observed 2026-11-21 (#5085), a build of ab7223798f; an unnamed session not walked | not yet observed |
| `sandbox-cw-knows-its-server` | cw-identity | observed 2026-11-23 (#5202); a real agent's `cw` not walked; a home another tool wrote first, and a refusal's words, not yet observed (#6315) | not yet observed |
| `sandbox-attach-stays` | cw-mesh | observed 2026-11-18 (#5120); 4.5 h attach 2026-11-21 | observed in part 2026-11-21 (#5120): the attach only, no cut or `cw shell` |
| `sandbox-stop-start` | cw-cleanup | observed 2026-11-14; named sessions and `cw run --name` 2026-11-20 (#5494, #5497) | not yet observed |
| `sandbox-update-startup` | cw-cli | observed 2026-11-23 (#5949); other members, admins, the audit row and the creator leaving not yet observed | not yet observed |
| `sandbox-session-stop` | cw-cleanup | observed 2026-11-20 (#5490) | not yet observed |
| `sandbox-start-list` | cw-fast-start | not yet observed | not yet observed |
| `sandbox-list-live` | cw-placement | not yet observed | not yet observed |
| `sandbox-row-menu` | cw-web | partly observed 2026-11-24 (open, held, dialog items and Escape at 1440, on every delivery) | not yet observed |
| `sandbox-setup-retry` | cw-hosted-runtime | observed 2026-11-23 (the dashboard on every delivery; the CLI on 2026-11-21, all but the 2-minute note) | not yet observed |
| `sandbox-unplanned-restart` | cw-hosted-runtime | not yet observed | not yet observed |
| `sandbox-attach-repaint` | cw-direct-udp | partly observed 2026-11-18 (#5120) | not yet observed |
| `sandbox-cp-upload` | cw-workspace-mount | observed 2026-11-14 (#4460) | not yet observed |
| `sandbox-cp-resume` | cw-workspace-mount | observed 2026-11-13 (#4373) | not yet observed; v0.4.17 lacks it |
| `sandbox-cp-download` | cw-workspace-mount | observed 2026-11-13 (#4394) | not yet observed |
| `sandbox-rollout` | cw-rollout | observed 2026-11-13 (#4426) | not yet observed |
| `sandbox-amp` | cw-integrations | not yet observed | not yet observed |
| `sandbox-amp-orb` | cw-integrations | not yet observed | not yet observed |

## Before the walk

- The `sandbox-cp` steps use one running cloud sandbox, called `cp-walk` in
  the examples. The create, command and stop steps make their own, called
  `walk`, and remove it at the end.
- On Dev, `scripts/runtime/dev/with-dev-smoke-auth.sh -- COMMAND` runs one
  command as the synthetic Dev identity. On Production, the smoke identity
  (`scripts/runtime/prod/with-prod-smoke-auth.sh`) may create, inspect and
  remove only its own sandboxes.
- The Dev smoke identity keeps one bound (Pod-scope) continuity Sandbox
  running, named in deploy's `settings/dev.env`; Dev acceptance reads its Pod
  before and after each delivery and fails the delivery that replaced it
  (#6095). Never remove it in a walk.
- Record `cw version` and the source the surface was running with every
  observation. On Dev, check that the orchestration image matches the
  services digest in the deploy repository's Dev `release.json` and that its
  rollout has finished. A promotion that has not rolled out is not the source
  you tested.

## `sandbox-create`: create a sandbox and remove it

- **Entry points:** `cw --cloud create`; the dashboard's new-environment
  form; the SDKs. Only `cw` is walked here.
- **States to exercise:**
  - a create that waits and ends usable;
  - a create with `--no-wait`, which returns at once and is followed with
    `cw ls`;
  - a create the platform ends (see `sandbox-create-fails`);
  - a second create under the name of a live environment in the
    organization (#4717).
- **Driving it:**

  ```sh
  cw --cloud create --name walk --no-file --ttl 30m --no-network
  cw --cloud ls
  cw --cloud info walk
  cw --cloud create --name walk --no-file --ttl 30m --no-network
  cw --cloud rm walk --yes
  cw --cloud ls
  ```

- **Proof:**
  - `cw create` exits 0 and prints "Environment walk created";
  - `cw ls` shows `walk` as `running`, and `cw info` gives it an ID, `State:
    running` and a `StartedAt` time;
  - the second `cw create --name walk` exits 1 with ``cloud environment
    "walk" already exists (remove it with `cw --cloud rm walk` or choose
    another --name)``, the sentence a local VM gives, and `cw ls` still
    shows one `walk` (not yet observed);
  - after `cw rm`, `cw ls` no longer shows it.
- **Gotchas:**
  - `--no-file` keeps a `codewire.yaml` in the current directory out of the
    walk. Without it the create takes that file's image, repositories and
    setup, and its time is not comparable.
  - A create from the warm pool takes a few seconds. One that misses the pool
    waits for a new sandbox and can take a minute or more; both are correct.
  - `--ttl` removes a walk's sandbox if the walk is abandoned. Set it.
  - `cw rm` answers "Removal started" while the platform removes the sandbox
    in the background; the row leaves `cw ls` at once.
- **Observed:**
  - Dev, 2026-11-14 (cw-cleanup): Dev's latest promotion was source
    f9a5fa8d2; whether its rollout had finished was not checked. `cw`
    v0.4.17, as the Dev smoke identity: the create ended in 2 s, `cw ls`
    showed `running`, `cw info` showed `State: running`, and after `cw rm`
    the name was gone from `cw ls`. Evidence: the pull
    request that added this section.

## `sandbox-create-fails`: a create the platform ends says why

Issues: #4431 (the create never ended), #4482 (the failed create vanished),
#4483 (the reason is a sentence, with no runtime text).

- **Entry points:** `cw create`, then `cw ls`, `cw info` and `cw rm`. The
  dashboard does not show a failed create yet (#4484).
- **States to exercise:**
  - an image that cannot be pulled;
  - a container whose command cannot start;
  - both with a create that waits, and with `--no-wait`;
  - the failed row one day later.
- **Driving it:**

  ```sh
  cw --cloud create --name walk --no-file --ttl 30m --no-network \
    --image registry.invalid/none/none:0 --no-wait
  sleep 120
  cw --cloud ls
  cw --cloud ls --output json
  cw --cloud info walk
  cw --cloud rm walk --yes
  cw --cloud start walk
  ```

  Without `--no-wait`, the same create stays in the foreground until the
  platform ends it.
- **Proof:**
  - the waiting create exits 1 within about two minutes. Its failed step is
    "Starting the sandbox", and the reason is one short sentence with the
    cause, HTTP status and exit code where known and what to do next, here
    that the image could not be pulled. It has no runtime text in it;
  - `cw ls` shows the row as `failed`, with how long ago, and a line under
    the table that begins "walk was not created:" and gives the reason;
  - the JSON entry has `"state": "failed"` and a `failed` object with `code`
    `container_start_failed`, the reason and the time;
  - `cw info walk` shows `State: failed` and the reason, and no
    `Recoverable` line;
  - `cw rm walk` exits 0 and says the environment was already removed;
  - `cw start walk` answers "not found": a failed create is no target for
    any command but `info` and `rm`;
  - no Pod and no claim is left for the environment's ID. On Dev that is
    read from the cluster; a user cannot see it.
- **Gotchas:**
  - A pull failure ends the create after about a minute, a start error after
    about 20 seconds. Looking sooner shows `creating`, which is correct.
  - The failed row is listed for 24 hours and then shows only under
    `cw ls --all`, as `destroyed`. A walk of that part needs a row made the
    day before.
  - A `cw` older than the change (v0.4.17 and older) never asks for failed
    creates, so its `cw ls` does not show the row. That is the old client,
    not a failure of the server.
  - A server older than #4483 puts the runtime's own text in the reason. An
    older `cw` names the wait that was open, such as "Waiting for SSH
    access", as the failed step.
  - The runtime's own text is only in the server's log, which a user cannot
    read. An operator finds it there by the environment's ID.
- **Observed:**
  - Dev, 2026-11-17 (cw-cleanup): Dev ran source 4fd096025, which includes
    #4828. `cw` built from main at 29eca2c2a plus #5152's projection change,
    which does not touch this path, as the Dev smoke identity. A waiting
    create with the image above exited 1 after 75 s; its failed step
    was "Starting the sandbox", with the reason "The image `IMAGE` could not
    be pulled: its registry could not be reached. Check the registry's
    address." The same create with `--no-wait` was listed as `failed` 77 s
    after the create. A container whose command could not start was `failed`
    38 s after its create, with "The container `workspace` could not start
    (StartError, exit code 128). Try again." No reason held runtime text.
    `cw ls` offered no "Sessions:" hint, `cw info` had no `Recoverable` line,
    no Pod or claim was left for any of the three, and `cw rm` and `cw start`
    answered as under Proof. Evidence: #4483, the comment of 2026-11-17.
  - Dev, 2026-11-14 (cw-cleanup): Dev ran source b98e0702d, which includes
    #4497; the server answered the new list request, which only that source
    does. `cw` built from #4497's head 3e61900ac, as the Dev smoke identity.
    A `--no-wait` create with the image above was listed as `failed` 73 s
    after the create, with `ErrImagePull` in its reason; no Pod or claim was
    left; `cw info`, `cw rm` and `cw start` answered as under Proof. Three
    failed creates from the day before left `cw ls` once they were 24 hours
    old and read `destroyed` under `cw ls --all`. Evidence: #4482, the two
    closing comments.
  - Dev, 2026-11-13 (cw-cleanup): Dev ran source 3abfebe8b, which includes
    #4441. A waiting create with an image tag that does not exist exited 1
    after 27 s with the reason; a container whose command could not start
    ended about 20 s after its create; a healthy create still succeeded.
    Evidence: #4431, closing comment.

## `sandbox-credential-links`: a credential link opens the dialog it names

Issue: #4905 (the link opened the credentials list).

- **Entry points:** the dashboard only. Create Sandbox's "From GitHub"
  heading link; the "Needs attention" notices in a Sandbox row's "Secrets and
  credentials" menu and on the Sandbox page.
- **States to exercise:**
  - no GitHub connection: the link reads "Connect GitHub";
  - an inactive connection (Reconnect needed or revoked): "Reconnect GitHub";
  - a connected account: "Manage GitHub connection";
  - a Sandbox bound to a profile whose credential needs action, such as
    "Codex needs Reconnect" or "OpenAI API key needs replacing".
- **Driving it:**
  1. Signed in with no GitHub connection, open Create Sandbox, fill in a
     field, and choose "Connect GitHub", then "Save draft and leave".
  2. Connect GitHub from the open dialog, then choose "Return to Create
     Sandbox".
  3. With the GitHub connection marked Reconnect needed, open Create
     Sandbox and choose "Reconnect GitHub".
  4. With it connected, choose "Manage GitHub connection".
  5. With a bound profile's Codex credential refresh failed, open the
     Sandbox's row menu, then "Secrets and credentials", and choose "Codex
     needs Reconnect"; then do the same from the Sandbox page's "Needs
     attention" notice.

  On Kind, `apps/dashboard/e2e/ssr-dashboard.credentials.ssr.ts` ("managed
  provider credential browser journey") drives steps 1 and 2 with the
  synthetic GitHub App.
- **Proof:**
  - step 1 lands on `/settings/credentials/?creation_draft=<draft>&dialog=connect-github#connect-github`
    with the Connect GitHub dialog open and nothing else to click first;
  - step 2 returns to Create Sandbox with the draft's values in place;
  - step 3 opens "Reconnect <account>", that connection's own dialog;
  - step 4 opens the credentials list, with no dialog open;
  - step 5 opens that credential's own dialog: Reconnect for Codex and
    GitHub, Rotate API key for an OpenAI or Anthropic key, Replace token for
    a Claude subscription token. A Claude sign-in (reconnected from `cw`) and
    an SSH key (replaced by adding another) open the list.
- **Gotchas:**
  - The page opens only a dialog it allows for the signed-in account's
    current credentials. A stale link, such as one for a credential deleted
    since, lands on the list; that is correct.
  - Create shows no setup link until its choices load, because the
    connection is not known before then.
- **Observed:**
  - Dev, 2026-11-24, partly: promote-dev runs 75308 and 76288 (sources
    730bb69218 and 5be4124bae). Every delivery's walkthrough
    (`apps/dashboard/scripts/dev-ux-walkthrough.ts`, stage
    `sandbox-credential-links`) holds, at 1440, that Create's GitHub link
    targets the dialog for the walk account's state, that the dialog is open
    on landing, and that "Return to Create Sandbox" brings the draft back:
    steps 1 and 2, and whichever of steps 3 and 4 fits that account. Step 5,
    the "Needs attention" links, is not yet observed.
  - Production: not yet observed.

## `sandbox-failure-trace-id`: a failed command prints the id of its trace

Issue: #5633. The rule is in `docs/CONFIGURATION.md`, "Tracing".

- **Entry points:** any `cw` command whose request the platform answers with
  an error. Here, `cw --cloud credentials get` and `cw --cloud policy check`
  with a name that doesn't exist: both send the name to the server, which
  refuses it.
- **States to exercise:**
  - an error the server answered, with text output and with `--output json`;
  - a server error that `cw` puts in its own words (`policy check` on a
    deployment without organization network policies);
  - a "not found" that `cw` concludes itself from a list the server answered
    (`cw --cloud info` with a missing name);
  - a failure with no server answer: a server URL whose host doesn't resolve;
  - a command that succeeds.
- **Driving it:**

  ```sh
  cw --cloud credentials get walk-missing-YYYYMMDD
  cw --cloud credentials get walk-missing-YYYYMMDD --output json
  cw --cloud policy check walk-missing-YYYYMMDD example.com
  cw --cloud info walk-missing-YYYYMMDD
  cw --server https://unresolvable.invalid --cloud ls
  cw --cloud ls
  ```

- **Proof:**
  - each failed command exits 1. After its `✗` line and any `→` line comes one
    line `trace ` followed by 32 lowercase hex digits;
  - an operator's ranged read of the trace store for that id, over the minute
    of the command, returns a trace whose root is that request
    (`POST /codewire.v1.…`) on the service that answered it;
  - `cw --cloud info` with a missing name, the unresolvable server and the
    successful `cw ls` print no `trace` line.
- **Gotchas:**
  - Dev keeps every trace. A deployment whose sampler drops a request sends no
    header, so `cw` prints no line, and that is not a failure.
  - Only an operator can read the trace store, one ranged request at a time.
- **Observed:**
  - Dev, 2026-11-22 (#5633), as the Dev smoke identity, with a `cw` built from
    main: `cw --cloud credentials get walk-missing-20261122` exited 1 with
    the server's refusal, then `trace d7140724d2e705d80c910abe56c926b9`. The
    trace store holds that trace, rooted at `POST
    /codewire.v1.CredentialService/GetCredential` on `codewire-orchestration`.
    The unresolvable server and a successful `cw --cloud ls` printed no line,
    and neither did `cw --cloud info` with a missing name, as above.
  - Dev, 2026-11-23 (#5633), as the Dev smoke identity, with a `cw` built from
    main `b93e21eba5` (which contains #6116):
    - `cw --cloud policy check walk-missing-20261123 example.com` exited 1 with
      `✗ Couldn't read the network policy: network policy not found`, in `cw`'s
      words, then `trace f8578dd3b6782de44a80f8b2a66c686e`. The trace store
      holds it, rooted at `POST /codewire.v1.NetworkPolicyService/GetNetworkPolicy`
      on `codewire-orchestration`. Dev now has organization network policies on,
      so the refusal is "not found" rather than "not enabled"; both take the
      same path.
    - With `--output json`, `policy check` and `credentials get` each exited 1
      with the error and a `trace` line.
    - A successful `cw --cloud ls` printed no line.

## `sandbox-run-exec`: run a command in a sandbox

- **Entry points:** `cw exec --in SANDBOX COMMAND` (no session; the command's
  exit status is `cw`'s) and `cw run --in SANDBOX COMMAND` (a session that
  `cw ls SANDBOX` lists and `cw logs` replays). `ssh` through `cw setup ssh`
  takes a different path and does not count here.
- **States to exercise:**
  - a command that succeeds, with its output;
  - a command that exits non-zero;
  - a program that doesn't exist, in a sandbox and in a local VM (#4717);
  - input on stdin;
  - `cw exec` in the background of its terminal, as under `timeout` without
    `--foreground` (#4883);
  - a command in a stopped sandbox, which is refused;
  - output larger than a terminal's worth (`sandbox-run-large-output`, not
    written yet).
- **Driving it:**

  ```sh
  cw exec --in walk sh -c 'echo marker-1 > /workspace/marker && cat /workspace/marker'
  cw exec --in walk sh -c 'exit 7'; echo $?
  cw exec --in walk -- definitely-not-a-command; echo $?
  cw --local exec --in local-walk -- definitely-not-a-command; echo $?
  printf 'from stdin\n' | cw exec --in walk cat
  timeout 60 cw exec --in walk cat; echo $?   # from an interactive shell
  cw run --in walk --name job sh -c 'echo run-output-1; echo run-output-2'
  cw ls walk
  cw logs walk --session job
  ```

- **Proof:**
  - the first command prints `marker-1`;
  - the second makes `cw` exit 7;
  - a missing program makes `cw` exit 127 in both placements, with the
    shell's "not found" (`definitely-not-a-command: command not found` from
    a local VM), never "guest probe failed" (not yet observed);
  - the third prints `from stdin`;
  - the fourth exits 0 at once, the command having had no input, where `cw`
    used to be stopped (SIGTTIN) and `timeout` to exit 1;
  - `cw run` prints both lines, `cw ls walk` lists session `job` as `Exited`,
    and `cw logs` prints the same two lines again.
- **Gotchas:**
  - `cw`'s own options go before the command. After `--`, every word is the
    command's.
- **Observed:**
  - The terminal's background (#4883): not yet observed on Dev or
    Production. On a macOS local VM, 2026-11-15 (cw-mac), with the fix on the
    installed build, `/usr/bin/timeout 60 cw exec … /bin/echo` exited 0 with
    its output, where the same build without it exited 1 with none. Evidence:
    #4977.
  - Dev, 2026-11-15 (cw-cli), the stopped sandbox: with `cw` built from
    #4689's branch at eff227270, `cw exec`, `cw run`, `cw shell`, `cw logs`,
    `cw cp` and `cw vscode` each said "Cloud environment NAME is stopped",
    then `→ cw --cloud start NAME` on its own line, and exited 1. After
    `cw --cloud start`, `cw exec` ran. Evidence: #4820.
  - Dev, 2026-11-14 (cw-cleanup): surface and client as for
    `sandbox-create`. All four results under Proof were seen: the marker,
    exit status 7, the stdin line, and the two `cw run` lines again from
    `cw logs`. Evidence: the pull
    request that added this section.

## `sandbox-run-env`: pass a variable by name

#5222. A program that holds a secret, such as a per-thread
token, hands it to one command in a sandbox without putting it in `cw`'s
arguments.

- **Entry points:** `cw exec` and `cw run` with `--env KEY` or
  `--env KEY=VALUE`; `cw create --env` and `cw init --env`.
- **States to exercise:**
  - `--env KEY=VALUE`, as today;
  - `--env KEY` with `KEY` set in the caller's environment, through `cw exec`
    and through `cw run`, in a sandbox and in a local VM;
  - `--env KEY` with `KEY` unset, and with `KEY` set to an empty string;
  - `cw create --env KEY`, in a sandbox and a local VM, and `cw init --env
    KEY`: refused;
  - `cw run --agent claude --env KEY` in a local VM: the agent's process has
    the value;
  - the host's process table while `cw` runs.
- **Driving it:**

  ```sh
  export WALK_TOKEN=walk-value-5222
  cw exec --in walk --env WALK_TOKEN -- sh -c 'printf "%s\n" "$WALK_TOKEN"'
  cw run --in walk --name env-job --env WALK_TOKEN -- sh -c 'printf "%s\n" "$WALK_TOKEN"; sleep 20' &
  ps -axo args= | grep -F 'cw run --in walk'   # while it runs
  wait
  env -u WALK_TOKEN cw exec --in walk --env WALK_TOKEN -- true; echo $?
  WALK_TOKEN= cw exec --in walk --env WALK_TOKEN -- sh -c 'printf "[%s]\n" "$WALK_TOKEN"'
  cw --cloud create --name walk-env --env WALK_TOKEN --yes; echo $?
  ```

- **Proof:**
  - each command prints `walk-value-5222`, from `cw exec` and from the
    session's output in `cw logs walk --session env-job`;
  - the process table shows `--env WALK_TOKEN` and never the value;
  - unset: refused before anything starts, naming `WALK_TOKEN` and saying it
    isn't set, exit 1, with no session made;
  - set to an empty string: sent as empty, `[]`;
  - `cw create --env WALK_TOKEN`: refused, saying `cw create --env` needs
    `KEY=VALUE` and naming `cw secrets` for a secret; nothing created; the
    same for `cw init --env WALK_TOKEN`;
  - the local VM's agent session starts with `--env WALK_TOKEN`, its
    process environment holds the value (`cw exec` reading
    `/proc/PID/environ` of the agent's process), and the host's process
    table shows only the name;
  - no output or error of `cw` contains the value.
- **Observed:** not yet.

## `sandbox-msg-session`: send text to a session and list its sessions

#5085, from the owner's session of 2026-11-16, which is quoted there.

- **Entry points:** `cw msg`, `cw ls SANDBOX`.
- **States to exercise:**
  - unquoted text after `--session`;
  - a sandbox with one running session, and `cw msg SANDBOX TEXT` with no
    `--session`;
  - several running sessions, at a terminal and piped;
  - bare `cw msg`;
  - `cw ls SANDBOX` with an unnamed dashboard shell and an agent started with
    a long prompt, at a narrow terminal, at a wide one and piped.
- **Driving it:**

  ```sh
  cw run --in walk --name lead --detach -- sh -c 'cat'
  cw msg walk --session lead just continue
  cw msg walk hello there
  cw msg
  cw msg walk
  cw run --in walk --detach -- sh -c 'sleep 600 # a long command that a narrow terminal cuts'
  cw ls walk
  cw ls walk | cat
  ```

- **Proof:**
  - `cw msg walk --session lead just continue` prints `Sent to terminal
    walk/lead.`, and `cw logs walk --session lead` shows `just continue`;
  - `cw msg walk hello there` sends to `lead`, the one running session;
  - with a second running session, a terminal shows the session picker,
    with `cw ls walk`'s columns and no full session ID, and a pipe refuses
    with both names and the `--session` command;
  - bare `cw msg` says how to send and gives a `→` command; `cw msg walk`,
    or a bare `cw msg` with `walk` selected, also lists walk's running
    sessions; neither prints clap's "required arguments" error;
  - `cw ls walk` starts each row with the session's name, or its ID when it
    has none, never `-`; a dashboard shell reads `bash`; COMMAND is cut with
    `…` to the terminal and is whole when piped.
- **Observed:** Dev, 2026-11-21, `cw` built from ab7223798f, as the Dev
  smoke identity (an API key in a throwaway `HOME`), in sandboxes
  `cwcli-msg-walk` and `cwcli-msg-walk2`, each removed afterwards:
  - `cw msg cwcli-msg-walk --session lead just continue` printed `Sent to
    terminal cwcli-msg-walk/lead.`; `cw msg cwcli-msg-walk hello there`
    went to `lead`, the one running session; `cw logs` showed both lines;
  - with a second session, a pipe refused with `✗ There are 2 running
    sessions in cwcli-msg-walk2 (lead, sh); name one with --session` and `→
    cw msg cwcli-msg-walk2 --session lead hi`; at a terminal the picker
    showed `SESSION STATE COMMAND` with no session ID, and Esc answered `✗
    Canceled; no session chosen`;
  - bare `cw msg` answered `✗ Say what to send: …` and `→ cw msg ENV
    continue`; `cw msg cwcli-msg-walk2` added `cwcli-msg-walk2's running
    sessions: lead, sh`;
  - `cw ls cwcli-msg-walk2` at 60 columns cut the long command with `…`; at
    200 columns and piped it was whole.
  - Not walked: a session with no name. `cw run` without `--name` names the
    session after its program (`sh`), and a dashboard shell needs the
    browser; the short ID is covered by the command's tests.

## `sandbox-shell`: open a shell in a sandbox

- **Entry points:** `cw shell SANDBOX`; the dashboard's terminal; `ssh`
  through `cw setup ssh`. Only `cw shell` is walked here.
- **States to exercise:**
  - a shell that runs a command and is left with `exit`;
  - the shell's exit status reaching `cw`;
  - `--durable`, a shell that keeps running after its terminal detaches (not
    walked yet).
- **Driving it:** `cw shell` needs a terminal. By hand:

  ```sh
  cw shell walk
  echo shell-says-$((6*7))
  exit 3
  echo $?
  ```

  Without a person, give it a terminal with `script`:

  ```sh
  printf 'echo shell-says-$((6*7)); exit 3\n' | script -qec 'cw shell walk' /dev/null
  echo $?
  ```

- **Proof:** the shell prints `shell-says-42`, which only a shell in the
  sandbox computes from that input, and `cw` exits 3.
- **Gotchas:**
  - Run without a terminal, `cw shell` is not this journey. Use `cw exec` for
    a command with no terminal.
  - Every key goes to the shell, Ctrl-B included, unless it was opened with
    `--durable`.
- **Observed:**
  - Dev, 2026-11-14 (cw-cleanup): surface and client as for
    `sandbox-create`, driven with `script`. The shell printed
    `shell-says-42` and `cw` exited 3. The dashboard terminal and `ssh` were
    not walked. Evidence: the pull
    request that added this section.

## `sandbox-cw-knows-its-server`: `cw` inside a sandbox knows its server

`SPEC.md` section 8, "What a workload inside a sandbox can and cannot do"
(#5100). A sandbox holds no Codewire sign-in. `cw` inside it knows which
server it belongs to and says what it can do, instead of asking for a URL.

- **Entry points:** `cw` in a shell inside a cloud sandbox. A local VM gets
  the same later (#5103, not yet built).
- **States to exercise:**
  - a command that needs a sign-in, run with no sign-in;
  - `cw network connect`, which works without one;
  - `cw login` offering the sandbox's server;
  - a saved server or `CODEWIRE_SERVER_URL` taking precedence over the
    sandbox's;
  - a home where another tool made `~/.local` first, so it inherited the
    home volume's setgid bit (#6315);
  - a refusal: a version store directory writable by its group.
- **Driving it:** in `walk`:

  ```sh
  cw --cloud exec --in walk -- sh -c 'echo "$CODEWIRE_SANDBOX_SERVER_URL"; cw whoami; echo "exit $?"'
  cw --cloud exec --in walk -- sh -c 'timeout 8 cw login </dev/null'
  cw --cloud exec --in walk -- sh -c 'CODEWIRE_SERVER_URL=https://other.invalid cw whoami'
  cw --cloud exec --in walk -- sh -lc 'command -v cw; cw ls; echo "exit $?"'
  cw --cloud exec --in walk -- bash -c 'cw login </dev/null >/dev/null 2>&1 & p=$!; sleep 2; readlink /proc/$p/exe; kill $p'
  cw --cloud exec --in walk -- bash -c 'mkdir -p ~/.local/share; stat -c "%n %a" ~/.local ~/.local/share; cw --version; echo "exit $?"'
  cw --cloud exec --in walk -- bash -c 'chmod g+w ~/.local/share; cw --version; echo "exit $?"; chmod g-w ~/.local/share'
  ```

  Then run an agent in `walk` and ask it to run `cw whoami` and `cw ls`, with
  a bare `cw` as it would type it.

- **Proof:**
  - The first line is the server you created `walk` on (`https://codewire-dev.sh`
    on Dev).
  - `cw whoami` exits nonzero and says this is a Codewire sandbox on that
    server with no sign-in. It names `cw network connect` as what works here,
    and says that `cw login` here would store a key that anything in the
    sandbox could use. Nowhere does it say "no server configured" or ask for
    a URL.
  - `cw login` names that server as this sandbox's before it waits. Stop it
    there; don't sign in.
  - With `CODEWIRE_SERVER_URL` set, that server wins: `cw` gives the plain
    not-signed-in message, not the sandbox's.
  - `command -v cw` is `/usr/local/bin/cw`, yet the running `cw`'s
    executable is `/codewire/bin/cw`: the release's, not the image's
    (#5202). `cw --version` can't show this, because both builds can print
    the same version.
  - `cw ls` says it isn't signed in, as `cw whoami` does. It never mentions a
    local VM store or a development build, on Dev too.
  - The agent's bare `cw` gives the same answers.
  - Not yet observed (#6315): `~/.local` and `~/.local/share` are 2755, and
    `cw --version` still runs and exits 0.
  - Not yet observed (#6315): with `~/.local/share` writable by its group,
    `cw` exits 1, says "Your cw version store under ~/.local is not
    private", and gives a `→` line with the `ls -ld` to check. It never
    prints only "platform CW default selection refused".
- **Gotchas:**
  - A workload started by a custom image's own entrypoint does not see the
    variable; only daemon sessions (`cw exec`, `cw shell`, SSH) do.
  - On Kind there is no `https` server origin, so the variable is absent and
    `cw` says it isn't signed in, with `→ cw login`, as on any machine
    without a sign-in.
  - A workspace image older than #5202's launcher runs its own `cw` from
    PATH, which can be older than the release. The `readlink` proof shows
    which one ran.
- **Observed:**
  - Dev, 2026-11-17 (cw-identity), source 4b9752e7, promote-dev 57727, host
    `cw` 0.4.21, as the Dev smoke identity. The session carries
    `CODEWIRE_SANDBOX_SERVER_URL=https://codewire-dev.sh`. With
    `/codewire/bin/cw`: `cw whoami` names the sandbox on that server, says it
    holds no sign-in, names `cw network connect` and the cost of `cw login`,
    and exits 1; `cw org list` says the same and exits 0; `cw login` prints
    "Connecting to codewire-dev.sh (this sandbox's server)…" and the warning
    before it waits; `CODEWIRE_SERVER_URL` wins; an `http` value is ignored.
    Not observed with the `cw` on PATH: it is the image's 2026-11-13 build
    and still says "no server configured" (#5202). Evidence: #5100.
  - Dev, 2026-11-23 (cw-sandbox-images), source 5221bbc23e, promote-dev
    74351, host `cw` 0.4.26, as the Dev smoke identity, in two fresh
    sandboxes. The bare `cw` on PATH (`/usr/local/bin/cw`) ran as
    `/codewire/bin/cw`; with another `HOME` it ran itself, as the launcher
    intends. `cw whoami` and `cw login` named the sandbox's server,
    `CODEWIRE_SERVER_URL` won, and `cw ls` gave the not-signed-in sentence
    with no local VM store, from a login and a non-login shell. A real
    agent's `cw` was not walked. Evidence: #5202.

## `sandbox-attach-stays`: an attached session stays connected

- **Entry points:** `cw attach SANDBOX --session NAME` with a full-screen
  program in the session, and `cw shell SANDBOX`, both over the tailnet.
- **States to exercise:**
  - an attachment left open for 30 minutes with a key every 10 seconds and
    mouse reports every minute;
  - a real cut, such as a Wi-Fi change, which may reconnect once. Before
    #5120 the client's coordinator session also reconnected every few
    minutes on its own; in the 2026-11-18 walk it did not in 30 minutes, so
    the cut is what makes a reconnect;
  - after a reconnect, the coordinator ending the client's older session
    within about 45 seconds (or at once, when the new session takes the key
    over), so the daemon is told to remove it.
- **Driving it:** without a person, give `cw attach` a terminal and a trickle
  of input, with `CW_DEBUG_TAILNET=1` so the attachment logs its path:

  ```sh
  cw run --in walk --name soak --detach --tty -- sh -c \
    'printf "\033[?1049h\033[?1003h"; cat >/dev/null & while :; do date; sleep 5; done'
  CW_DEBUG_TAILNET=1 script -qec 'cw attach walk --session soak' /dev/null
  ```

  Keep the coordinator's and the daemon's logs for the same window
  (`kubectl logs` on the coordinator and on the sandbox's Pod, read-only).
  For the cut, leave the attachment up for at least 40 s first, so its
  session has pinged, then cut for about 60 s and stay attached 2 minutes
  after the network returns.
- **Proof:**
  - no `[cw] connection lost` line in 30 minutes without a real cut;
  - the daemon logs no `rust tailnet refused peer addresses` line for the
    client;
  - after the cut, the coordinator log shows the older session ended
    (`ended=Some(Silent)`, or at once when the new session takes the key
    over) within about 45 seconds of its last ping, with `coordinator
    peer_remove sent` to the sandbox's daemon, and one client session left
    after the reconnect.
- **Gotchas:**
  - A cut in the first 15 s of an attachment proves nothing about the
    45 s limit: a session that has not pinged yet keeps the older
    behaviour and is not ended for silence.
  - The daemon does not log the `PeerRemove` it receives at its default
    level; the coordinator's `peer_remove sent` line is the record.
  - Before the fix, a drop came about 60 seconds after each coordinator
    reconnect, when SSH keepalive gave up.
  - Dev runs one coordinator replica and rolls it out on every delivery,
    so an attached client's coordinator session reconnects about 70 s after
    each new coordinator ReplicaSet, with the error `failed to read response
    body`. That is the rollout, not a fault; the attachment stays up.
- **Observed:**
  - Dev, 2026-11-18 (cw-direct-udp): source a44ac15fc, rollout finished,
    `cw` built from main b26ed65a9, as the Dev smoke identity; evidence on
    #5120. `cw attach` (keys and mouse reports) and `cw shell` side by side
    for 30 minutes: no connection-lost line, no refused peer addresses, and
    neither client's coordinator session reconnected on its own. A 60 s cut
    of the attach: one connection-lost line and one path line; the older
    session ended `Silent` about 45 s after its last ping, with
    `peer_remove` sent at once, and one session remained.
  - Production and Dev, 2026-11-21 (cw-mesh): released `cw v0.4.26` on the
    workstation, both surfaces on v0.4.26, as each smoke identity; evidence
    on #5120. One `cw attach` per surface for 4.5 hours, with a key every
    10 s and 40 mouse reports a minute: one attachment each, no
    connection-lost line, no refused peer addresses and no keepalive end.
    The client's coordinator session reconnected once on Production, with
    no rollout and no cause found, and nine times on Dev, each a Dev
    coordinator rollout; each took about a second, and the attachment
    stayed up. Not walked on Production: the cut and
    `cw shell`.

## `sandbox-stop-start`: stop a sandbox and start it again

- **Entry points:** `cw stop SANDBOX` and `cw start SANDBOX`; the dashboard's
  stop and start buttons. Only `cw` is walked here.
- **States to exercise:**
  - stop a running sandbox;
  - a command against it while stopped;
  - start it again, and find the files under `/workspace` unchanged;
  - a sandbox in `error`: `cw --cloud start` recovers it, retrying its create
    and replacing a failed Pod, as one `cw --local start` recovers a local VM
    in `error` (#4953); not walked yet;
  - a start the cluster has no room for, which ends with a "no capacity"
    message (not walked yet);
  - a named session running at the stop, in a Sandbox with and without a
    secret project, restarted by its name after the start (#5471);
  - `cw run --name` with that name after the start, at a terminal and in a
    script (#5471);
  - a stop of the stopped sandbox, and a start of the running one, in both
    placements (#4717).
- **Driving it:**

  ```sh
  cw exec --in walk sh -c 'echo marker-1 > /workspace/marker'
  cw --cloud run --in walk --name play --detach -- sleep 86400
  cw --cloud stop walk
  cw --cloud stop walk; echo $?
  cw --cloud ls
  cw --cloud ls walk; cw exec --in walk true; cw logs walk; cw msg walk hi
  cw --cloud start walk
  cw --cloud start walk; echo $?
  cw --cloud ls
  cw --cloud ls walk
  cw exec --in walk cat /workspace/marker
  cw --cloud restart walk --session play
  cw --cloud run --in walk --name play --detach -- sleep 86400 </dev/null
  ```

- **Proof:**
  - after the stop, `cw ls` shows `walk` as `stopped`;
  - while it is stopped, `cw ls walk`, `cw exec`, `cw logs` and `cw msg` each
    say `Cloud environment walk is stopped` with `→ cw --cloud start walk`,
    and exit 1; a stopped local VM says `Local environment walk is stopped`
    with `→ cw --local start walk` (#4717; not yet observed);
  - the second stop prints `Environment walk is already stopped.` and the
    second start `Environment walk is already running.`, each exiting 0, as
    `cw --local stop` and `cw --local start` of a local VM do (not yet
    observed);
  - after the start, `cw ls` shows it as `running`;
  - the marker command prints the marker written before the stop. A file that
    survives is the proof; "running" alone is not;
  - `cw ls walk` shows `play` as `Stopped`, "stopped with the environment",
    with and without a secret project, and never "cleanup is unknown";
  - `cw restart walk --session play` brings `play` back as `Running` under
    the same name;
  - the last `cw run --name play`, with no terminal, refuses because `play` is
    running and names it; once `play` has ended, it prints the exact
    `cw restart` command and exits non-zero. At a terminal it asks "restart
    it?" instead. No message says "fenced".
- **Gotchas:**
  - Only files under `/workspace` and `/home/codewire` survive a stop.
    Processes do not; a session's record and name do, and it can be
    restarted.
  - `cw start` returns once the sandbox is usable, so the next command needs
    no wait.
- **Observed:**
  - Dev, 2026-11-14 (cw-cleanup): surface and client as for
    `sandbox-create`. The stop took 3 s and `cw ls` showed `stopped`; the
    start took 8 s and `cw ls` showed `running`; the marker written before
    the stop was read back unchanged. Evidence: the pull
    request that added this section.
  - Named sessions, before the fix, Dev, 2026-11-19 (codewire-79), the Dev
    smoke identity with `cw` v0.4.24 (#5471). Without a secret project,
    `play` came back `Interrupted`, "the environment daemon restarted", and
    `cw restart` worked. With a secret project, it came back with cleanup
    unknown, and `cw restart` answered "Session cleanup is unknown; restart is
    fenced". The kernel boot ID inside the Sandbox changed across the stop and
    start.
  - Named sessions with the fix, Dev, 2026-11-20 (codewire-79), the Dev smoke
    identity with `cw` v0.4.24, Dev at source cd34a5cf97 with its daemon image
    rolled out (#5494). With and without a secret project, the stop took 5 to
    7 s and the start 7 to 9 s, including sign-in; the marker came back, the
    boot ID changed, and `play` showed `Stopped`, "stopped with the
    environment", with cleanup known. `cw restart walk --session play` brought
    it back `Running` under the same session ID. `cw run --name play` while it
    ran refused and named the attach command. Evidence: the walk comment on
    #5471.
  - `cw run --name` on an ended session, Dev, 2026-11-20 (codewire-79), the
    Dev smoke identity with `cw` built from main at 7c141784b6 (#5497), Dev at
    source a2d07a4737. After a stop and start left `play` `Stopped`: with no
    terminal, `cw run --name play` exited 1 with "A session named play already
    exists in w20f (stopped); `--name` never reuses one: restart it with `cw
    --cloud restart w20f --session play`, or choose another --name". At a
    terminal it asked "Restart it? [Y/n]", and `y` brought `play` back
    `Running` under the same session ID, exit 0. With `play` running it
    refused and named the attach command. No message said "fenced". Evidence:
    the walk comment on #5471.

## `sandbox-update-startup`: an existing Sandbox gains a startup script

Issue: #5949. A Sandbox keeps the `codewire.yaml` settings it was created
with; recreating it to add a startup script gives it a new ID, and with it new
preview host names, which breaks whatever is bound to them (passkeys, OAuth
redirect URIs, cookies).

- **Entry points:** `cw update SANDBOX --file codewire.yaml`; `cw export
  SANDBOX` to see the saved settings.
- **States to exercise:**
  - a Sandbox created without a `startup_script` gets one: the update shows
    `startup_script` added and says it runs at the next start; `cw export`
    shows it; after `cw stop` and `cw start` it has run; the preview host name
    is unchanged;
  - a changed script, and a removed one, the same way;
  - the update on a running Sandbox: it keeps running, and the script runs at
    its next start;
  - a file that also changes `install_command` (or the image, or
    repositories): refused by that name, saying only a new Sandbox takes it,
    and `cw export` shows nothing changed;
  - a file that changes `secrets`: refused, pointing to `--secrets`;
  - a file identical to the saved settings: says nothing changed;
  - another member of the organization, and an organization admin: refused,
    only the creator may;
  - the audit row: actor, Sandbox, the script's SHA-256 and length, no text;
  - the creator leaves the organization: the saved script is cleared, and the
    next start runs none;
  - `cw --local update --file`: refused, a local VM's setup is per VM.
- **Driving it:**

  ```sh
  cw --cloud create walk-start --file codewire.yaml --yes   # no startup_script
  cw ports walk-start                                         # note the preview host
  printf 'startup_script: echo started > /workspace/started\n' >> codewire.yaml
  cw update walk-start --file codewire.yaml
  cw export walk-start
  cw --cloud stop walk-start && cw --cloud start walk-start
  cw exec --in walk-start cat /workspace/started
  cw ports walk-start                                         # same preview host
  ```

- **Proof:** `cw export` shows the script before the restart; after it,
  `/workspace/started` exists; the preview host name is the one noted before;
  `install_command` didn't run again (the Sandbox's setup stays complete, and a
  marker its install wrote isn't rewritten); each refusal leaves `cw export`
  unchanged.
- **Observed:**
  - Dev, 2026-11-23 (cw-cli): Dev ran source 1cf36b4f61, its services digest
    rolled out. `cw` built from that commit, as the Dev smoke identity, on a
    Sandbox created with an `install_command` and port 3000 and no
    `startup_script`. Stopped, `cw update --file` printed the script and "It
    runs at the next start, not now.", then "✓ Startup script added"; without
    `--yes` and a terminal it saved nothing. `cw export` showed the script.
    Each of two starts showed "Running startup script" and appended one line,
    as UID 1000, to its marker; the install's marker kept its one line. The
    ID and the preview host from `cw ports` were the same as at create. On the
    running Sandbox a changed script was saved while it kept running and ran
    only at the next start; a removed one ran at no later start; an identical
    file said "Nothing to change"; `install_command` was refused by name with
    `cw --cloud create --file` as the next step, and `secrets` pointing to
    `--secrets`, each leaving `cw export` unchanged. `cw --local update` with
    no local VM said the local environment wasn't found, before its own
    refusal. Not walked: another member, an admin, the audit row and the
    creator leaving.

## `sandbox-session-stop`: stopping a session ends every process it started

Issue: #5472.

- **Entry points:** `cw stop SANDBOX --session NAME`.
- **States to exercise:**
  - a session whose command runs directly (`sleep`);
  - a session whose command leaves a child running (`sh -c 'sleep 86400; true'`),
    as `pnpm dev` leaves `node`;
  - a session that ignores TERM (`sh -c 'trap "" TERM; sleep 86400'`);
  - an interactive shell with a background job:
    `cw --cloud run --in walk --name sh -t -- bash`, then `sleep 86400 &` in
    it, then the stop from another terminal (`cw shell` takes no `--name`);
  - a command that starts a child and exits:
    `cw run --in walk --name bg --detach -- sh -c 'sleep 86400 & echo started'`,
    and the same with `nohup sleep 86400 &`;
  - a child started with `setsid`, which is not the session's:
    `sh -c 'setsid sleep 86400 >/dev/null 2>&1 < /dev/null & exit 0'`;
  - a `setsid` child that keeps the session's output, then a stop and a
    restart (#5635):
    `cw run --in walk --name web --detach -- bash -c 'setsid sleep 7777 & sleep 100000'`,
    `cw stop walk --session web`, `cw restart walk --session web`;
  - another session in the same Sandbox, still `Running` after each stop.
- **Driving it:**

  ```sh
  cw --cloud run --in walk --name forks --detach -- sh -c 'sleep 86400; true'
  cw --cloud stop walk --session forks
  cw --cloud ls walk
  cw exec --in walk ps -eo pid,ppid,pgid,args
  ```

- **Proof:**
  - each stop returns within 5 s, and `cw ls walk` shows the session
    `Stopped`, never `Stopping`;
  - `bg` ends `Exited` with status 0 as soon as `sh` exits, with and without
    `nohup`, and its last output line is "[cw] Ended 1 process left running
    after the command exited (pid N `sleep`) …"; the `setsid` child is still
    running afterwards, and its session's end names nothing;
  - `ps` shows no `sleep 86400` left from the stopped session, the background
    job's included, and the other session's process and the daemon are
    untouched;
  - no answer says "refresh sessions";
  - the stop of `web` answers within 5 s and `cw ls walk` shows it
    `Stopped`, its status naming the holder ("Its output is still open in 1
    process that left the session (pid N `sleep`), which keeps running; …"),
    never `Interrupted` or "outcome is unknown"; `sleep 7777` is still
    running, and `cw restart` starts `web` again (#5635).
- **Gotchas:**
  - A process the session moved out of its group on purpose (`setsid`, a
    daemonizing server, a `docker run -d` container) is not the session's,
    and keeps running after the stop.
- **Observed:**
  - Before the fix, Dev, 2026-11-19 (codewire-79), the Dev smoke identity with
    `cw` v0.4.24 (#5472): the direct `sleep` stopped in 2 s. The forking and
    TERM-ignoring sessions answered "Environment session outcome is unknown;
    refresh sessions before trying again" after 7 s and stayed `Stopping`
    for over 3 minutes. Their `sleep` was re-parented to PID 1 and still
    running. `sh -c 'sleep 86400 & echo started'` stayed `Running` after
    `sh` exited, its `sleep` re-parented to PID 1.
  - With the fix, Dev, 2026-11-20 (codewire-79), the Dev smoke identity with
    `cw` v0.4.24, Dev at source cd34a5cf97 with its daemon image rolled out
    (#5490, which landed in #5494's commit). Each session ran in a Unix
    session of its own, never in the Sandbox's session 1. The direct,
    forking and TERM-ignoring sessions, and an interactive `bash` with
    `sleep 86400 &` in its own process group, each stopped in about 3.5 s
    including sign-in, and showed `Stopped`. No `sleep` of theirs was left,
    the background job's included; `keep` and the daemon were untouched, and
    no answer said "refresh sessions". `bg` and its `nohup` variant ended
    `Exited` with status 0, their last line "[cw] Ended 1 process left running
    after the command exited (pid N `sleep`) …"; the `setsid` child was still
    running, and its session's end named nothing. Evidence: the walk
    comment on #5472.
  - A `setsid` child keeping the output, before the fix, Dev at source
    b1a024b6db, 2026-11-20 (codewire-79), the Dev smoke identity with `cw`
    v0.4.24 (#5635): the stop of `web` answered "The session's outcome is
    unknown" after 7 s, `web` ended `Interrupted` with cleanup unknown, and
    `cw restart` refused it; only `sleep 7777` was left, in its own session.
    Evidence: the comment on #5635.
  - With the fix, Dev at source 6ef416acfb, 2026-11-21, the Dev
    smoke identity with `cw` v0.4.24 (#5649): the stop of `web` answered
    `Stopped` in 5 s including sign-in, with cleanup known and the status
    "session stopped. Its output is still open in 1 process that left the
    session (pid 11165 `sleep`), which keeps running; …"; only `sleep 7777`,
    in its own session, was left, and `cw restart` brought `web` back
    `Running` under the same session ID. Evidence: the walk comment on #5635.

## `sandbox-start-list`: a starting sandbox's page shows one list of steps

Issue: #3772.

- **Entry points:** the dashboard's Create Sandbox form, and Start on a
  stopped Sandbox's page.
- **States to exercise:**
  - a plain create, with no repository and no setup commands;
  - a stopped Sandbox started again;
  - a create with install and startup commands, whose steps follow the first
    row (walked on Kind only);
  - a setup that fails, which is `sandbox-setup-retry`.
- **Driving it:** signed in to the dashboard, create a Sandbox from the form
  and stay on the page it lands on. Once its terminal has opened, press Stop,
  confirm, wait for "stopped", and press Start. On Dev every delivery walks
  this as the Dev smoke browser identity, in
  `apps/dashboard/scripts/dev-ux-walkthrough.ts`: `create-start-list` and
  `create-start-list-rows` after Create, and
  `lifecycle-live-state-start-list` after Start. In the delivery's acceptance
  output a check that holds prints `stage NAME duration_ms=N`, and one that
  fails prints `stage NAME not-held expectation=LABEL class=CLASS`. A failed
  check does not fail the acceptance yet: the checks could not be run
  against Dev before they merged. They become failing once three deliveries
  in a row show all three stages and no `not-held` line.
- **Proof:**
  - **After Create:** the page shows "Starting your Sandbox" over a list whose
    first row is "Starting the Sandbox". Every row is that one or a named
    setup step, and none appears twice. No "Sandbox creation started." alert
    sits above it.
  - **After Start:** the list holds exactly one row, "Starting the Sandbox".
    None of the earlier run's or the stop's rows return, and no "Sandbox start
    requested." alert sits above it.
  - **Both:** the list gives way to a terminal when the Sandbox runs.
- **Gotchas:**
  - A create served from the warm pool can be running before the page first
    paints, and then no list is ever seen. Dev's walk creates a shape that has
    no pool (1 vCPU, 2 GiB, 10 GiB), so its list is always there to check. If
    that shape gains a pool, the create half of this step stops proving
    anything and has to change.
  - Nothing signs a browser in as the Production smoke identity, so
    Production has no walk yet.
- **Observed:**
  - Kind, 2026-11-14: the retained review cluster with a synthetic account,
    on the branch that merged as #4774 (`a6fefaf01`). A plain create, a create
    with setup, and stop then start each showed every step once, with no
    alert, and ended in a terminal. Evidence: #3772's comments of that date.
  - Dev: not yet.
  - Production: not yet.

## `sandbox-list-live`: the Sandboxes page changes as its Sandboxes do

Issue: #4762.

- **Entry points:** the dashboard's Sandboxes page (`/<org>/sandboxes`) and
  its sidebar rail, with a Sandbox's state changed from `cw` or another tab.
  Design: private-docs `designs/live-updates.md` §3a (#4762).
- **States to exercise:**
  - a Sandbox stopped, then started, from `cw`: only its row changes;
  - a Sandbox created, and one removed, from `cw`: the list gains or loses
    the row;
  - a row's menu open while its Sandbox changes: the menu stays open, and the
    row changes once it is closed;
  - a row's Resize, Delete or Secrets and credentials dialog open while its
    Sandbox changes: the same;
  - a Sandbox removed while its row's menu is open: the row stays, with its
    old actions, until the menu closes. An action chosen then is refused by
    the server, never applied;
  - the tab hidden while Sandboxes change, then shown: the list catches up
    once;
  - a filter or search that the changed Sandbox no longer matches: the row
    leaves the list.
- **Driving it:** open the Sandboxes page with the browser's network panel
  showing fragment requests. In a terminal:

  ```sh
  cw --cloud stop walk
  cw --cloud start walk
  cw --cloud create --name walk-2 --no-file --ttl 30m --no-network --no-wait
  cw --cloud rm walk-2 --yes
  ```

  Then repeat the stop with `walk`'s row menu open, and with its Resize
  dialog open.
- **Proof:**
  - each change shows on the page within 2 s;
  - between changes the page makes no request for the list, and a change
    requests only that row's fragment, except a create, a removal or a
    filter change, which requests the list once;
  - an open menu or dialog is never closed or replaced by an update;
  - the rail shows the same states as the list.
- **Gotchas:** with the stream unavailable or busy, the page degrades to a
  fallback: it refreshes when the tab is focused or shown, and once a minute
  while visible. A walk that sees list requests once a minute has lost the
  stream; that is not the journey working.
- **Observed:** not yet observed.

## `sandbox-row-menu`: a Sandboxes row's menu reaches every action

Issue: #5383. Code: `crates/codewire-dashboard-web/templates/environment-list.html`,
`packages/codewire-design/environments.js`,
`packages/codewire-design/routes/environments.css`.

- **Entry points:** the ⋯ button at the end of each row on the Sandboxes
  page (`/<org>/`), by pointer and by keyboard.
- **States to exercise:**
  - a running and a stopped Sandbox, two or more rows, so a menu opens over
    later rows;
  - the menu left open for longer than the list's refresh (5 s while the
    list still polls, #4762);
  - Secrets and credentials, Resize and Delete, each opened, cancelled and
    then carried out;
  - desktop 1440 and phone 390.
- **Driving it:** on Kind or Dev, open the first row's menu and wait 10 s
  without touching anything. Move the pointer slowly down to Delete and click
  it. Cancel, open the menu again and press Delete permanently. Repeat with
  the keyboard: Tab to the ⋯ button, Enter, Tab to Delete, Enter.
- **Proof:**
  - the menu stays open for as long as the user leaves it open; the list
    catches up on its first refresh after the menu or a dialog closes;
  - no later row's ⋯ button shows through the open panel;
  - no item in the menu carries a caret: Secrets and credentials, Resize and
    Delete each open a dialog named for the Sandbox, and Escape or Cancel
    returns focus to the item;
  - Delete permanently deletes the Sandbox, and its row leaves the list;
  - fixture specs, at 1440 and 390, in
    `apps/dashboard/e2e/ssr-dashboard.sandbox-inventory.ssr.ts`: "a row menu
    stays open through the list's refresh until it is closed", "a list
    refresh already on its way when a row menu opens leaves the menu open,
    and runs once it closes" and "an open row menu sits above the other
    rows' menu buttons".
- **Gotchas:**
  - a check that clicks Delete within a second of opening the menu passes
    on the broken code; wait past a refresh first.
  - the live stream's first resync refreshes the list within a second of
    every page load, so a menu opened at once meets a refresh already on its
    way. Its answer is dropped while the menu is open (#6235); before that,
    Dev's walkthrough saw the menu close at once (run 75308).
- **Observed:**
  - Dev, 2026-11-24, partly: promote-dev run 76288 (source 5be4124bae).
    Every delivery's walkthrough (stage `sandbox-row-menu`) holds, at 1440,
    on its own new Sandbox's row: the menu opens, is still open 6 s later,
    Secrets and credentials, Resize and Delete each open a dialog with no
    caret, and Escape closes the menu. Delete carried out, the keyboard
    path, later rows' buttons and 390 are not yet observed on Dev.
  - Production: not yet observed.

## `sandbox-setup-retry`: a failed setup, fixed in a shell and retried

Issues: #4767, and #5050 for the clone's reason.

- **Entry points:**
  - the dashboard's Sandbox page: the failure banner, its terminal and **Retry setup**;
  - `cw shell`, `cw run` and `cw retry SANDBOX`, which cw-cli owns.
- **States to exercise:**
  - a create whose install command fails;
  - a fix made in its terminal, then Retry setup;
  - a setup that failed before or at the clone, whose Retry asks first;
  - a clone of a private repository on a host other than GitHub, which needs a credential Codewire doesn't have (#5050).
- **Driving it:** create a Sandbox with an install command that fails until a file exists, for example `test -f /workspace/ok`. Open its terminal, run `touch /workspace/ok`, and press Retry setup. From the CLI: `cw create` with the same install command, `cw shell SANDBOX` and `touch /workspace/ok` there, then `cw retry SANDBOX`.

  On Dev every delivery walks this as the Dev smoke browser identity, in `apps/dashboard/scripts/dev-ux-walkthrough.ts` (#5065). Once the walk's own Sandbox has a terminal, it creates two more in a tab of its own:
  - one whose install is `test -f /tmp/dev-ux-setup-fixed`;
  - one that clones `https://codewire-dev.sh/_dev-ux/no-repository.git`, an address where Dev has no repository.

  Their setup fails while the walk goes on. After the walk's own Sandbox is deleted, the stages run in order: `setup-retry-banner`, then `setup-retry-resume`, which fixes it in the terminal and retries, then `setup-retry-resume-list`, then `setup-retry-reclone`, which retries the clone and cancels "Retry cloning?". Last, `setup-retry-delete` deletes both. Each check runs only if the one it depends on held. A check that holds prints `stage NAME duration_ms=N`, and one that fails prints `stage NAME not-held expectation=LABEL class=CLASS`. A failed check fails the acceptance, naming the first that failed, once both Sandboxes are deleted (#4767).
- **Proof:**
  - **After the failure:** the page shows the banner "Setup failed at Running install command: …" over an open terminal.
  - **After Retry:** the list, headed "Retrying setup", shows the steps before install as done without running them, and install runs again. The Sandbox then becomes ready, and the banner is gone.
  - **The clone case:** a Retry that would clone again opens "Retry cloning?" before it runs. On Dev the banner names the host, `codewire-dev.sh`, in the sentence #5053 adds; Cancel leaves the Sandbox failed.
  - **A clone that needs a credential:** the banner reads "Setup failed at Cloning repositories: git clone <url>: <host> needs a credential that Codewire doesn't have; clone it in the terminal with your own". It names the host from the project's URL and nothing the remote wrote. The terminal opens, so the repository can be cloned there with your own token.
  - **`cw create` with the failure:** it ends with `✗ Setup failed at Running install command: …`, which says SANDBOX is still running and to fix it there and run `cw retry SANDBOX`, then `→ cw shell SANDBOX`, and exits 1.
  - **`cw` after the failure:** `cw run --in SANDBOX -- CMD` and `cw shell SANDBOX` print `! Setup failed at Running install command: …` and `→ cw retry SANDBOX`, then run.
  - **`cw retry SANDBOX`:** it follows the retry's steps from install and ends with `✓ Setup complete for SANDBOX`. A retry that would clone again names the directories and asks `Retry? [y/N]`; without a terminal it refuses with `→ cw retry SANDBOX --yes`.
  - **`cw` while setup runs:** they refuse with "The setup of SANDBOX is running; wait for it, or follow it with `cw logs SANDBOX --setup --follow`".
  - **Ctrl-C during `cw retry`:** it ends with "Interrupted. The setup retry of SANDBOX continues in the background; check it with `cw --cloud logs SANDBOX --setup --follow`.", and the retry carries on.
- **Gotchas:**
  - A Retry runs the failed step's own command again: install and startup scripts should be safe to rerun.
  - New terminals wait while the Retry's setup runs, as they do during the first setup.
- **Observed:**
  - Dev, 2026-11-16, in part: source 54ed105a2, the CLI only, as the Dev smoke identity with the released `cw` v0.4.21. Evidence: #4767's comment of that date.
    - `cw create --cloud --install 'test -f /tmp/setup-walk-fixed'` stopped at "Running install command: workspace exec exited 1" and exited 1.
    - `cw info` showed the Sandbox running, with `setup_error` "install: workspace exec exited 1".
    - `cw exec` ran in it at once.
    - After `cw stop` and `cw start`, `cw exec` ran again and the error stayed recorded.
  - Dev, 2026-11-16 (cw-cli), `cw` built from #5028 at 49a8bb95b, smoke identity: after an install command failed, `cw run --in SANDBOX --no-tty -- echo ran` printed `! Setup failed at Running install command: workspace exec exited 1`, started the session and printed `ran` (exit 0). `cw shell SANDBOX` printed the same line and opened the shell, which ran a piped command. Evidence: #5028.
  - Kind, 2026-11-16: a local cluster built from #5053's branch at 0c7e484d8 (with #4846), the dashboard as the synthetic owner. Evidence: #4767's Kind comment of that date.
    - An install command failed: the danger banner read "Setup failed at Running install command: workspace exec exited 1", with a terminal open. After the cause was fixed in that terminal, Retry setup ran install again, and only install, then setup completed and the banner cleared.
    - A clone of a private repository on a forge other than GitHub, with no credential, failed with #5053's sentence naming the host. Retry setup asked "Retry cloning?"; Cancel left the failure; "Delete and retry" showed "Retrying setup" and failed again the same way.
  - Dev, 2026-11-17, 08:50–08:51Z: Dev ran source cd986b75d (promoted 08:34:29Z; the next promotion came at 08:52:06Z), with #5167 at 94ce6da8a (a built `cw`), the smoke identity and an install command `test -f /workspace/ok`. Evidence: #5167's body.
    - `cw create --cloud` ended with `✗ Setup failed at Running install command: workspace exec exited 1; NAME is still running, so fix it there and run `cw retry NAME` …` and `→ cw shell NAME`, exit 1.
    - `cw retry` before the fix followed install again to the same failure, exit 1.
    - `cw run --in NAME -- touch /workspace/ok` printed `! Setup failed at …` and `→ cw retry NAME`, then ran, exit 0.
    - `cw retry` after it ran install only and ended with `✓ Setup complete for NAME` in about 1 s, exit 0. Once more, the service refused: `This Sandbox's setup completed`.
  - Dev, 2026-11-21, 20:41–20:45Z: Dev ran source 8880d56e76 (promoted 20:15Z, acceptance passed 20:23Z), with `cw` built from that commit, the smoke identity and an install command `sleep 20; test -f /workspace/ok`. Evidence: #4767's comment of that date.
    - `cw create --cloud` ended with `✗ Setup failed at Running install command: …` and `→ cw shell NAME`, exit 1.
    - Ctrl-C during `cw retry` (a SIGINT at 8 s, at a terminal) ended with "Interrupted. The setup retry of NAME continues in the background; check it with `cw --cloud info NAME`.", and the retry carried on. `cw info` shows nothing about setup, so this change points to the setup log instead.
    - `cw run --in NAME -- true` during it refused with "✗ Hrt-retry-a-2041's setup is running; …", exit 1. The error line capitalised the Sandbox's name, so the sentence no longer starts with it.
    - Once the retry had failed, `cw run --in NAME -- touch /workspace/ok` printed `! Setup failed at …` and `→ cw retry NAME`, then ran, exit 0. `cw retry` then ran install only and ended with `✓ Setup complete for NAME`, exit 0; once more, the service refused with `This Sandbox's setup completed`.
    - A create cloning `https://git.example.invalid/none/none.git` failed at "Cloning repositories: … git.example.invalid couldn't be reached from the Sandbox", exit 1. `cw retry` without a terminal refused with "Retrying setup clones the repositories again, which deletes /workspace/none and any edits made there" and `→ cw retry NAME --yes`. At a terminal it asked `… Retry? [y/N]:`, and `n` ended with `✗ Cancelled; setup was not retried`. `cw retry NAME --yes` cloned again and failed the same way, exit 1.
    - Both Sandboxes were removed by name, and `cw ls --cloud` then listed neither.
  - Dev, 2026-11-23, the dashboard, in every delivery's walk as the Dev smoke browser identity: promote-dev 73120, 73147 and 73181 (source 18ca1cb222, with #6003 and #6034) held all six checks. The banner read "Setup failed at Running install command: …"; after the fix in its terminal, Retry setup showed "Retrying setup" with the earlier steps done instantly and install completed; the clone case asked "Retry cloning?" and Cancel kept the failure; both Sandboxes were deleted. In one of those walks, the one whose retried Sandbox completed at 07:58:38Z, the TTL checkpoint written with `complete` sorted after it: the order that left the list on the failed run before #6034. Evidence: #4767's comments of that date.
  - Not yet observed: `cw retry`'s 2-minute note, "The retry hasn't started yet; it runs after the Sandbox's current operation".
  - Production: not yet; v0.4.21 lacks Retry setup.

## `sandbox-unplanned-restart`: a restart nobody asked for is shown, and the owners are emailed

Issues: #5997, from a customer whose app stayed down after a restart they
never saw (#5950). Builds on #3772's restart notice
([`reboot-restart-notice`](node-reboot.md)).

- **Entry points:** `cw ls` and `cw info SANDBOX`, their `--output json`, the
  SDKs' environment fields, and the email to the organization's owners.
- **States to exercise:**
  - each cause: `pod_failed`, `runtime_replaced`, `node_lost` and
    `configuration_changed`;
  - a requested start, stop, restart, resize, update or daemon repair, which
    records nothing and sends nothing;
  - the next start or stop, an idle stop included, which clears what `cw`
    shows;
  - three Sandboxes in one organization restarting within 10 minutes, which
    send one email.
- **Driving it:** on Dev, as the smoke identity, with a long-running session
  open in the Sandbox, delete its Pod (`runtime_replaced`), or kill its VM with
  `scripts/runtime/dev/prove-dev-vm-death-recovery.sh` (`pod_failed`). Once
  it's running again:

  ```sh
  cw ls
  cw info SANDBOX
  cw info SANDBOX --output json
  ```

  and read the email that reaches the smoke organization's owner.
- **Proof** (the wording waits for the owner's land-it; #5997):
  - `cw ls` shows the Sandbox `running` with a note under the table that it
    restarted on its own, how long ago, why, and that running processes were
    lost, then `→ cw info SANDBOX`.
  - `cw info` shows a `Restarted:` line with the local time, how long ago,
    the cause in words, and that files are safe and running processes were
    lost.
  - The JSON has `restarted_at` (RFC 3339) and `restart_cause`, and so do the
    SDKs.
  - Every owner gets one email naming the Sandbox, the organization, the time
    in UTC, the cause, what was lost and kept, and a link to the Sandbox.
  - A requested restart shows none of this and sends nothing.
- **Gotchas:**
  - The email goes to owners only, not to the member who created the
    Sandbox, unless they are an owner.
  - A deleted Pod stands in for a node drain on Dev; a lost node is walked on
    Kind or in a planned drill, never by taking a Production node away.
- **Observed:** not yet observed.

## `sandbox-attach-repaint`: a full-screen program is left clean after a reconnect

Issue: #5090 (text left in an attached agent's screen after a drop).

- **Entry points:** `cw attach SANDBOX --session NAME` and `cw shell
  --durable`, which reattach after a drop. Plain `cw shell` prints the same
  path line once, but does not redraw a full-screen program.
- **States to exercise:**
  - a first attachment, which neither flickers nor redraws;
  - a reattach after a drop while a full-screen program with mouse reporting
    holds the screen;
  - the mouse moved and keys typed during the drop;
  - a reattach that takes a different path, which prints its path line again.
- **Driving it:** a terminal, a running sandbox `walk`, and a way to cut the
  network of `cw` for about 20 s (Wi-Fi off and on, or `nmcli networking
  off` and `on`; on a shared machine, `IPAddressDeny=any` on the systemd
  scope `cw` runs in cuts only that). Record the terminal with `script`:

  ```sh
  cw --cloud run --in walk --name tui --tty --detach -- vim -c 'set mouse=a'
  script -qc 'cw --cloud attach walk --session tui' attach.log
  ```

  With vim showing, cut the network. Wait for `[cw] connection lost`, move
  the mouse over the window, type `ihello` and Escape, then restore the
  network. Once vim answers again, look at the screen, then type `:q!` and
  Enter. Afterwards:

  ```sh
  grep -a '\[cw\]' attach.log
  grep -ac '  via ' attach.log
  ```

- **Proof:**
  - after the reconnect the screen shows only vim's own frame, with `hello`
    in the buffer: no `[cw]` line and no `via` line is left in it;
  - `grep -a '\[cw\]'` shows the connection-lost line and no "key(s) typed
    during the drop were lost" line, since seven keys are well under
    the bounds, however far the mouse moved; a resent count, if any, is at
    most the keys typed;
  - `grep -ac '  via '` prints 1 when the path did not change.
- **Gotchas:**
  - The redraw needs the program to hold the alternate screen. A program
    drawn on the normal screen, such as a shell prompt, is not redrawn.
  - Keys and mouse reports sent before the client noticed the drop went
    into the dead connection; they are resent on reattach, and only the
    keys are counted as resent. If more of them than the client keeps were
    lost, the lost count is in bytes and can include those reports.
  - Without `set mouse=a`, vim asks for no mouse reports and the mouse half
    of the walk proves nothing.
  - Start the detached vim from a shell that has `TERM` set. Started
    without one, the session's `TERM` is empty and that vim ignores resizes,
    so no repaint can clean its screen (#5306).
  - Keys typed during the drop are echoed by the local terminal until the
    reattach (#5305); on the alternate screen the repaint wipes them.
- **Observed:**
  - Dev, 2026-11-18 (cw-direct-udp): surface and client as for
    `sandbox-attach-stays`; evidence on #5120. Both `cw attach --session`
    and `cw shell --durable`, at 120x40 with vim and `set mouse=a`: after
    the reattach the screen was vim's frame with `hello` in the buffer and
    no `[cw]` or `via` line in it; `[cw]` lines were only the connection-lost
    line and, after `:q!`, "session exited"; no lost or resent line, and one
    `  via ` line. A reattach over a different path was not exercised.

## `sandbox-cp-upload`: copy a file into a sandbox

Issue: #3968 (`cw cp` sent a whole file as one message).

- **Entry points:** `cw cp LOCAL SANDBOX:PATH`. `scp`, `sftp` and `rsync`
  through `cw setup ssh` take a different path and do not count here.
- **States to exercise:**
  - a file under 4 MiB;
  - one between 4 MiB and 64 MiB, which goes in one request;
  - one over 100 MB, which goes in 64 MiB parts;
  - a destination outside `/workspace` and `/home/codewire`, which is
    refused;
  - an upload stopped with Ctrl-C (see `sandbox-cp-resume`).
- **Driving it:**

  ```sh
  head -c 1073741824 /dev/urandom > big.bin
  sha256sum big.bin
  cw cp big.bin cp-walk:/workspace/big.bin
  cw exec --in cp-walk sha256sum /workspace/big.bin
  cw exec --in cp-walk stat -c '%s %a' /workspace/big.bin
  cw exec --in cp-walk ls -a /workspace
  ```

- **Proof:**
  - the two checksums are equal;
  - the size in the sandbox is the source's, with mode 644;
  - no `.codewire-upload-*` staging file is left in `/workspace`.
- **Gotchas:**
  - Cloud requests pass an edge that refuses a request body over about
    100 MB with HTTP 413. A file over 64 MiB therefore goes up in parts.
  - A server without parts (v0.4.17 and older) gets the file in one request,
    so a file over about 100 MB fails there with an error saying the server
    takes no resumable uploads.
  - Uploads run at about 4.7 MB/s on Dev at low workstation load, so 1 GiB
    takes about four minutes. Since #4460 the bridge writes to the sandbox a
    mebibyte at a time. What bounds uploads now is not yet known (#4638). A
    slow upload is not a failure.
  - A Dev rollout during a transfer can end it at the old Pod's drain
    deadline (`sandbox-rollout`). Check that none is running before timing
    anything.
- **Observed:**
  - Dev, 2026-11-14 (cw-rollout): Dev ran source 94e2e4b650, which includes
    #4460, with its rollout finished. An optimized `cw` built from #4547's
    branch at fb4cf048b (client side as on `main`; SHA-256 `1a8764f8…`), as
    the Dev smoke identity, uploaded 1 GiB in 235.1 s and 221.3 s at a
    workstation load of 34 and 8, with SHA-256 equal, 1,073,741,824 bytes,
    mode 644 and no staging file. On source a9dd8b270, before #4460 and at a
    load of about 100, it took 382.4 s and 379.0 s, so the gain is not
    isolated from load. Evidence: #4460, closing comment.
  - Dev, 2026-11-13: Dev ran source 3a3a53521, with its rollout finished;
    `cw` was built at 3a3a53521. A 1 GiB upload, interrupted and then
    resumed, ended with an equal SHA-256, 1,073,741,824 bytes, mode 644 and
    no staging file. Evidence: #4373, closing comment.
  - Dev, 2026-11-12: a 90 MiB upload in one request in 32 s, SHA-256 equal,
    with `cw` built from #4393's branch. Dev's source was not recorded.
    Evidence: #4393.
  - Production: not yet observed. v0.4.17 streams uploads (#4393) but has no
    upload parts, so a file over about 100 MB is expected to fail there
    until a release includes #4416.

## `sandbox-cp-resume`: an interrupted upload resumes when rerun

Issue: #4373 (resumable uploads).

- **Entry points:** `cw cp`, run again with the same source and destination.
- **States to exercise:**
  - an upload interrupted part-way, then rerun;
  - a rerun after the source file changed, which starts a new upload;
  - an upload never rerun, whose staging file is removed after 24 hours.
- **Driving it:**

  ```sh
  head -c 1073741824 /dev/urandom > big.bin
  sha256sum big.bin
  timeout -s INT 40 cw cp big.bin cp-walk:/workspace/big.bin
  cw exec --in cp-walk ls -la /workspace
  cw cp big.bin cp-walk:/workspace/big.bin
  cw exec --in cp-walk sha256sum /workspace/big.bin
  cw exec --in cp-walk ls -a /workspace
  ```

- **Proof:**
  - after the interruption, `/workspace/big.bin` does not exist, and a
    `.codewire-upload-part-*` file holds some of the bytes;
  - the rerun prints `Resuming the upload at N of 1073741824 bytes`, with N
    above 0;
  - the final checksum equals the source's, and no staging file is left.
- **Gotchas:**
  - N can be more than the staging file's size seen after the interruption.
    Writes already in flight finish after `cw` stops.
  - The upload is matched by the local file's path, size and modification
    time, and by the destination. Touching or rewriting the source starts
    over, by design.
  - A file of 64 MiB or less goes in one request and does not resume. Use a
    file well over 64 MiB.
- **Observed:**
  - Dev, 2026-11-13: Dev ran source 3a3a53521, with its rollout finished;
    `cw` was built at 3a3a53521, as the Dev smoke identity. An interruption
    after 40 s left no `big.bin` and a staging file holding 101,253,120
    bytes. The rerun printed `Resuming the upload at 104857600 of
    1073741824 bytes` and sent the remaining 968,884,224 bytes in 394 s.
    SHA-256 `be3198bba56fe73f4d1be0f329840de99e0d5fc9b7a5c7f38751122b7b8acbad`
    on both sides. Evidence: #4373, closing comment.
  - The changed-source and 24-hour expiry states: not yet observed. Only
    the unit tests in #4416 cover them.
  - Production: not yet observed. v0.4.17 does not include #4416.

## `sandbox-cp-download`: copy a file out of a sandbox

Issue: #3968; download speed is #4394.

- **Entry points:** `cw cp SANDBOX:PATH LOCAL`.
- **States to exercise:**
  - a file over 4 MiB;
  - a download onto an existing local file;
  - a download stopped with Ctrl-C, which leaves an existing destination as
    it was and no partial file.
- **Driving it:**

  ```sh
  cw exec --in cp-walk sha256sum /workspace/big.bin
  echo keep > back.bin
  timeout -s INT 20 cw cp cp-walk:/workspace/big.bin ./back.bin
  cat back.bin
  ls -a
  time cw cp cp-walk:/workspace/big.bin ./back.bin
  sha256sum back.bin
  ```

- **Proof:**
  - after the interruption, `back.bin` still reads `keep`, and no
    `.back.bin.cw-partial-*` file is left;
  - after the full download, the checksum equals the sandbox's;
  - the time is recorded.
- **Gotchas:**
  - A download is written to a temporary file beside its destination and
    renamed into place only when complete. The local folder needs room for
    the whole file next to the existing destination.
  - Speed on Dev is set by the round trip from orchestration to the
    sandbox's site, once per 1 MiB read. Production's orchestration and
    sandboxes are split across sites in the same way, and its speed has not
    been measured.
- **Observed:**
  - Dev, 2026-11-13 (cw-rollout): Dev ran source 3abfebe8b, which includes
    #4423 and #4434. An optimized `cw` built from `main`, as the Dev smoke
    identity, downloaded 1 GiB in 106.3 s and 113.6 s (about 9.7 MB/s),
    with SHA-256 equal. Before those changes it took 370 s, on source
    3a6203ff. Evidence: #4394, closing comment.
  - Dev, 2026-11-12: Ctrl-C during a download left the destination
    unchanged and no partial file, with `cw` built from #4393's branch.
    Dev's source was not recorded. Evidence: #4393.
  - Production: not yet observed.

## `sandbox-rollout`: transfers and API calls across an orchestration rollout

Issue: #4426 (a rollout cut open transfers); the drain shipped in #4445 and
#4472.

A release replaces the orchestration Pod. The old Pod drains instead of
cutting what it serves. For 10 s it keeps serving while the gateway drops it.
Then it hands over leadership and Temporal work, and lets open transfers
finish. Streams whose clients re-attach end at once. Anything still open at
the drain deadline, 270 s after SIGTERM and inside the 300 s grace, ends with
an error the client can retry.

- **Entry points:**
  - `cw cp`, in either direction;
  - a host attached with `cw host` (`AttachHost`);
  - a session attached with `cw shell` or `cw run` (`AttachSession`);
  - the dashboard's terminal;
  - any API call during the rollout.
- **States to exercise:**
  - a download that finishes on the old Pod during its drain (the usual
    case);
  - a download still open at the drain deadline, which ends with "download
    it again", never `failed to read response body`;
  - an upload in parts across the rollout, and one with a part still open at
    the deadline, which resumes on the new Pod (#4460);
  - a host or session attached when the old Pod drains, which re-attaches to
    the new one;
  - a dashboard terminal open on the old Pod at the drain deadline, both the
    durable terminal and the one-off terminal (#4459);
  - API calls throughout, none refused.
- **Driving it:**
  1. Dev runs a source with #4445, so its orchestration Pods carry a 10 s
     `preStop`. Run every `cw` command as the Dev smoke identity (see "Before
     the walk").
  2. Make a file in the sandbox and note its checksum:

     ```sh
     cw exec --in cp-walk sh -c 'head -c 1073741824 /dev/urandom > /workspace/gen.bin && sha256sum /workspace/gen.bin'
     ```

  3. Wait for a Dev delivery that replaces orchestration, watching the
     `codewire-orchestration` Pods in Dev's `dev` namespace. This walk never
     starts a delivery; deliveries follow `main`.
  4. When a new orchestration Pod appears, until the old Pod is gone, run
     downloads back to back and an API call once a second:

     ```sh
     cw cp cp-walk:/workspace/gen.bin ./gen.bin && sha256sum gen.bin
     while sleep 1; do cw org list > /dev/null || date -u; done
     ```

- **Proof:**
  - each download's checksum equals the one the sandbox printed, and a
    download still open at the deadline ends with Codewire's "download it
    again" error;
  - no `cw org list` call fails at the gateway;
  - a dashboard terminal open at the deadline closes with WebSocket code 1012,
    "server restarting", never a reset, and the browser connects again to the
    new Pod. The one-off terminal's shell ends first and its runtime
    admission lease is released, not left `resolution_required`;
  - the old Pod logs `draining: releasing leadership, Temporal tasks and
    re-attachable streams`, then `leader: draining, released leadership` and
    `temporal worker stopped`;
  - the new Pod logs `leader: acquired leadership` within about 1 s of that
    release, because it waits on the release instead of retrying every 5 s
    (#6099), and its `credential relay admitted its first epoch` follows
    within about 2 s;
  - the old Pod is gone within its 300 s grace.
- **Gotchas:**
  - A Pod's own spec decides how it stops. The rollout that first delivers
    the drain still kills Pods that have no `preStop`, so walk the rollout
    after it.
  - A delivery that changes no orchestration image replaces no Pod.
  - The workstation's own network can fail a call. Count a failure only if
    the gateway saw it (#4383).
  - A 1 GiB download takes about 110 s on Dev, so start downloads back to
    back to keep one open when the old Pod gets SIGTERM.
- **Observed:**
  - Dev, 2026-11-13, source `934d5809`, before #4445: failure observed. A
    256 MiB download was cut at 58.9 s by the rollout's kill. Evidence:
    #4426.
  - Dev, 2026-11-13, source `1e0f58773`, before #4445: failure observed. A
    1 GiB download was cut at 172 s by the 13:01Z rollout. Evidence: #4394.
  - Dev, 2026-11-13, source `6fe84fa45` (with #4445) draining to
    `b7272211f`: a 1 GiB download started on the old Pod 23 s before its
    `preStop` completed with SHA-256 equal after 108.4 s. The old Pod exited
    96 s after its deletion. The new Pod took leadership 4.75 s after the old
    one's SIGTERM. The gateway saw no failed call. Evidence: #4426.
  - Dev, 2026-11-13, source `b7272211f` (with #4445 and #4472) draining: a
    1 GiB download on the draining Pod completed with SHA-256 equal. A 5 GiB
    download still open at the deadline ended with "download it again", and
    the gateway logged 200 with no reset. A 1 GiB upload across the rollout
    completed in parts with SHA-256 equal in the sandbox. 772 API calls at
    1 Hz, none failed. Leadership moved 4.2 s after its release. Evidence:
    #4426.
  - An upload part open at the drain deadline resuming: not yet observed.
    On Dev a 64 MiB part finishes in about 14 s, so the part on the old Pod
    ends long before the 270 s deadline and later parts go to the new Pod.
    Only an upload slower than about 0.24 MB/s would leave a part open at
    the deadline. The bridge's and the CLI's tests cover it (#4460).
  - `AttachSession` re-attaching through orchestration, and the dashboard's
    terminals: not yet observed. The one-off terminal closing with 1012 at
    the deadline is covered by its relay test (#4459). A `cw run` across the rollout used direct
    UDP, not orchestration.
  - `AttachHost` at SIGTERM: not yet observed. It needs a host agent on Dev
    (#4426).
  - The handover gap, before #6099: over 7 Production releases and 9 Dev
    deliveries on 2026-11-20 to 2026-11-23, leadership moved 0.5–4.6 s
    after its release, and the relay admitted its first epoch 2.0–6.5 s
    after SIGTERM. Evidence: #6099.
  - The handover gap with the release notice (#6099): Dev, 2026-11-23, three
    deliveries after #6115 (15:29Z, 15:39Z, 15:54Z). Leadership moved
    13–20 ms after its release, and the relay admitted its first epoch
    0.4–1.6 s after SIGTERM. Evidence: #6099.
  - Production: not yet observed.

## `sandbox-amp`: Amp from the image, and its update into the home

Issue: #5049.

- **Entry points:** `cw run --in SANDBOX -- amp …`, and `amp` in a sandbox's
  terminal.
- **States to exercise:**
  - a fresh sandbox, where `amp` is the image's;
  - `amp update`, after which the home's copy is the one that runs;
  - a sandbox stopped and started after the update, where the home's copy
    remains;
  - `amp update --porcelain`, which the image's wrapper refuses.
- **Driving it:**

  ```sh
  cw create --name amp-walk -y
  cw run --in amp-walk --no-tty -- sh -lc 'command -v amp; amp --version'
  cw run --in amp-walk --no-tty -- amp update
  cw run --in amp-walk --no-tty -- sh -lc 'command -v amp; amp --version'
  cw stop amp-walk && cw start amp-walk
  cw run --in amp-walk --no-tty -- sh -lc 'command -v amp; amp --version'
  cw run --in amp-walk --no-tty -- amp update --porcelain
  ```

  Then open the sandbox's terminal and start `amp`. It asks to sign in with
  its own flow, since Codewire brokers no Amp key. Remove the sandbox
  afterwards with `cw rm --yes amp-walk`.
- **Proof:**
  - **Fresh:** `command -v amp` is `/opt/codewire/agents/upgrade/amp`, and
    the version is the one pinned in `images/workspace/agents/package.json`.
  - **After `amp update`:** `command -v amp` is
    `/home/codewire/.npm-global/bin/amp`, `amp --version` runs and prints the
    newer or the same version, and it is still there after the stop and start.
  - **The refused option:** `--porcelain` exits 2 and names the one option
    the wrapper takes.
- **Gotchas:** a home install without the wrapper (`npm install --global
  @sourcegraph/amp`) skips `@ampcode/cli`'s postinstall and leaves a stub
  that prints "Amp native binary not installed".
- **Observed:** not yet observed.

## `sandbox-amp-orb`: a preset that meets Amp's orb image contract

Issue: #5045. The recipe is "A preset for Amp's self-hosted orbs" in
`apps/docs/zola/content/environments/presets.md`.

- **Entry points:** `cw preset create amp-orb` with that startup script, then
  `cw create --preset amp-orb`, `cw stop` and `cw start`, as Amp's dispatch
  program drives them.
- **States to exercise:**
  - a fresh sandbox from the preset;
  - the same sandbox after `cw stop` and `cw start`, with a file in
    `user`'s home from before;
  - the startup script run a second time by hand, which changes nothing.
- **Driving it:** create the preset as the recipe says, then:

  ```sh
  cw create --name orb-walk --preset amp-orb -y
  cat > orb-check.sh <<'CHECK'
  set -eu
  getent passwd user | cut -d: -f1,3,4,6,7
  readlink -f /home/user
  sudo -u user sudo -n true && echo sudo-ok
  stat -c '%U:%G %a' /etc/sudoers.d/90-amp-orb
  sudo -u user /usr/local/bin/amp --version
  git --version
  ldd --version | head -n 1
  CHECK
  cw cp orb-check.sh orb-walk:/workspace/orb-check.sh
  cw run --in orb-walk --no-tty -- sh /workspace/orb-check.sh
  cw run --in orb-walk --no-tty -- sudo -u user sh -c 'echo kept > /home/user/kept'
  cw stop orb-walk && cw start orb-walk
  cw run --in orb-walk --no-tty -- sh /workspace/orb-check.sh
  cw run --in orb-walk --no-tty -- sudo -u user cat /home/user/kept
  ```

  Then run the preset's startup script once more inside the sandbox, run
  the check again, and remove the sandbox with `cw rm --yes orb-walk`.
- **Proof**, on each check, item by item against Amp's contract:
  - `user:1100:1100:/home/user:/bin/bash`, and `/home/user` resolves to
    `/workspace/.amp-orb/home`;
  - `sudo-ok`, and the sudoers file reads `root:root 440`;
  - `amp --version` prints the version pinned in
    `images/workspace/agents/package.json`;
  - git 2.34 or later;
  - glibc;
  - after the stop and start, `kept` is still there, owned by `user`;
  - the startup script's second run exits 0, and the check reads the same.
- **Gotchas:** a preset made with `--install` instead of `--startup` meets
  the contract until the first stop. The account is on the image's
  filesystem, which a start replaces.
- **Observed:** not yet observed.

