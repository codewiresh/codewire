# A cloud sandbox

This journey proves what a user does with a cloud sandbox, as `SPEC.md`
describes it in "4. Hosted sandboxes" and "7. Access paths": creating one,
what a create that fails leaves behind, running commands and shells in it,
stopping and starting it, copying files with `cw cp` ("File transfer" in
section 7), and what a user sees while a release replaces the orchestration
service ("Rollouts drain" in section 10). Large `cw run` output is not written
yet; its owner adds it. The format is in [README.md](README.md).

## Where the journey stands

Updated 2026-11-14.

| ID | Owner | Dev | Production |
| --- | --- | --- | --- |
| `sandbox-create` | cw-cleanup | observed 2026-11-14 | not yet observed |
| `sandbox-create-fails` | cw-cleanup | observed 2026-11-14 (#4482) | not yet observed; v0.4.17 lacks it |
| `sandbox-run-exec` | cw-cleanup | observed 2026-11-14 | not yet observed |
| `sandbox-shell` | cw-cleanup | observed 2026-11-14 | not yet observed |
| `sandbox-stop-start` | cw-cleanup | observed 2026-11-14 | not yet observed |
| `sandbox-cp-upload` | cw-workspace-mount | observed 2026-11-14 (#4460) | not yet observed |
| `sandbox-cp-resume` | cw-workspace-mount | observed 2026-11-13 (#4373) | not yet observed; v0.4.17 lacks it |
| `sandbox-cp-download` | cw-workspace-mount | observed 2026-11-13 (#4394) | not yet observed |
| `sandbox-rollout` | cw-rollout | observed 2026-11-13 (#4426) | not yet observed |

## Before the walk

- The `sandbox-cp` steps use one running cloud sandbox, called `cp-walk` in
  the examples. The create, command and stop steps make their own, called
  `walk`, and remove it at the end.
- On Dev, `scripts/runtime/dev/with-dev-smoke-auth.sh -- COMMAND` runs one
  command as the synthetic Dev identity. On Production, the smoke identity
  (`scripts/runtime/prod/with-prod-smoke-auth.sh`) may create, inspect and
  remove only its own sandboxes.
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
  - a create the platform ends (see `sandbox-create-fails`).
- **Driving it:**

  ```sh
  cw --cloud create --name walk --no-file --ttl 30m --no-network
  cw --cloud ls
  cw --cloud info walk
  cw --cloud rm walk --yes
  cw --cloud ls
  ```

- **Proof:**
  - `cw create` exits 0 and prints "Environment walk created";
  - `cw ls` shows `walk` as `running`, and `cw info` gives it an ID, `State:
    running` and a `StartedAt` time;
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

Issues: #4431 (the create never ended), #4482 (the failed create vanished).

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
  - the waiting create exits 1 within about two minutes and prints the
    reason, here that the image could not be pulled;
  - `cw ls` shows the row as `failed`, with how long ago, and a line under
    the table that begins "walk was not created:" and gives the reason;
  - the JSON entry has `"state": "failed"` and a `failed` object with `code`
    `container_start_failed`, the reason and the time;
  - `cw info walk` shows `State: failed` and the whole reason;
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
  - The reason is the container runtime's own text and can be long (#4483).
- **Observed:**
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

## `sandbox-run-exec`: run a command in a sandbox

- **Entry points:** `cw exec --in SANDBOX COMMAND` (no session; the command's
  exit status is `cw`'s) and `cw run --in SANDBOX COMMAND` (a session that
  `cw ls SANDBOX` lists and `cw logs` replays). `ssh` through `cw setup ssh`
  takes a different path and does not count here.
- **States to exercise:**
  - a command that succeeds, with its output;
  - a command that exits non-zero;
  - input on stdin;
  - a command in a stopped sandbox, which is refused;
  - output larger than a terminal's worth (`sandbox-run-large-output`, not
    written yet).
- **Driving it:**

  ```sh
  cw exec --in walk -- sh -c 'echo marker-1 > /workspace/marker && cat /workspace/marker'
  cw exec --in walk -- sh -c 'exit 7'; echo $?
  printf 'from stdin\n' | cw exec --in walk -- cat
  cw run --in walk --name job -- sh -c 'echo run-output-1; echo run-output-2'
  cw ls walk
  cw logs walk --session job
  ```

- **Proof:**
  - the first command prints `marker-1`;
  - the second makes `cw` exit 7;
  - the third prints `from stdin`;
  - `cw run` prints both lines, `cw ls walk` lists session `job` as `Exited`,
    and `cw logs` prints the same two lines again.
- **Gotchas:**
  - `cw`'s own options go before the command. After `--`, every word is the
    command's.
  - `cw exec` in a stopped sandbox fails with a message about a missing SSH
    host key for the sandbox's Pod. The refusal is right; the message does
    not say that the sandbox is stopped (#4689). Seen with `cw` v0.4.17 and
    with one built from `main` at 14fb7f56a.
- **Observed:**
  - Dev, 2026-11-14 (cw-cleanup): surface and client as for
    `sandbox-create`. All four results under Proof were seen: the marker,
    exit status 7, the stdin line, and the two `cw run` lines again from
    `cw logs`. Evidence: the pull
    request that added this section.

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

## `sandbox-stop-start`: stop a sandbox and start it again

- **Entry points:** `cw stop SANDBOX` and `cw start SANDBOX`; the dashboard's
  stop and start buttons. Only `cw` is walked here.
- **States to exercise:**
  - stop a running sandbox;
  - a command against it while stopped;
  - start it again, and find the files under `/workspace` unchanged;
  - a start the cluster has no room for, which ends with a "no capacity"
    message (not walked yet).
- **Driving it:**

  ```sh
  cw exec --in walk -- sh -c 'echo marker-1 > /workspace/marker'
  cw --cloud stop walk
  cw --cloud ls
  cw --cloud start walk
  cw --cloud ls
  cw exec --in walk -- cat /workspace/marker
  ```

- **Proof:**
  - after the stop, `cw ls` shows `walk` as `stopped`;
  - after the start, `cw ls` shows it as `running`;
  - the last command prints the marker written before the stop. A file that
    survives is the proof; "running" alone is not.
- **Gotchas:**
  - Only files under `/workspace` and `/home/codewire` survive a stop.
    Processes and sessions do not.
  - `cw start` returns once the sandbox is usable, so the next command needs
    no wait.
- **Observed:**
  - Dev, 2026-11-14 (cw-cleanup): surface and client as for
    `sandbox-create`. The stop took 3 s and `cw ls` showed `stopped`; the
    start took 8 s and `cw ls` showed `running`; the marker written before
    the stop was read back unchanged. Evidence: the pull
    request that added this section.

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
  - the old Pod logs `draining: releasing leadership, Temporal tasks and
    re-attachable streams`, then `leader: draining, released leadership` and
    `temporal worker stopped`;
  - the new Pod logs `leader: acquired leadership` within about 5 s of that
    release;
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
    terminal: not yet observed. A `cw run` across the rollout used direct
    UDP, not orchestration.
  - `AttachHost` at SIGTERM: not yet observed. It needs a host agent on Dev
    (#4426).
  - Production: not yet observed.
