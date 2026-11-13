# A cloud sandbox

This journey proves what a user does with a cloud sandbox, as `SPEC.md`
describes it in "4. Hosted sandboxes" and "7. Access paths". It is written so
far for copying files with `cw cp` ("File transfer" in section 7), and for what
a user sees while a release replaces the orchestration service ("Rollouts
drain" in section 10). Other parts of the sandbox journey are added as their
owners write them. The format is in [README.md](README.md).

## Where the journey stands

Updated 2026-11-13.

| ID | Owner | Dev | Production |
| --- | --- | --- | --- |
| `sandbox-cp-upload` | cw-workspace-mount | observed 2026-11-13 (#4373) | not yet observed |
| `sandbox-cp-resume` | cw-workspace-mount | observed 2026-11-13 (#4373) | not yet observed; v0.4.17 lacks it |
| `sandbox-cp-download` | cw-workspace-mount | observed 2026-11-13 (#4394) | not yet observed |
| `sandbox-rollout` | cw-rollout | observed 2026-11-13 (#4426) | not yet observed |

## Before the walk

- Use one running cloud sandbox for every step. The examples call it
  `cp-walk`.
- On Dev, `scripts/runtime/dev/with-dev-smoke-auth.sh -- COMMAND` runs one
  command as the synthetic Dev identity. On Production, the smoke identity
  (`scripts/runtime/prod/with-prod-smoke-auth.sh`) may create, inspect and
  remove only its own sandboxes.
- Record `cw version` and the source the surface was running with every
  observation. On Dev, check that the orchestration image matches the
  services digest in the deploy repository's Dev `release.json` and that its
  rollout has finished. A promotion that has not rolled out is not the source
  you tested.

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
  - Uploads run at about 2.5 MB/s on Dev, so 1 GiB takes about seven
    minutes. Each 64 KiB write crosses from orchestration to the sandbox's
    site and back. #4460 batches the writes. A slow upload is not a failure.
  - A Dev rollout during a transfer can end it at the old Pod's drain
    deadline (`sandbox-rollout`). Check that none is running before timing
    anything.
- **Observed:**
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
  - An upload part open at the deadline resuming (#4460), `AttachSession`
    re-attaching through orchestration, and the dashboard's terminal: not yet
    observed. A `cw run` across the rollout used direct UDP, not
    orchestration.
  - `AttachHost` at SIGTERM: not yet observed. It needs a host agent on Dev
    (#4426).
  - Production: not yet observed.
