# File calls from the SDKs

What a program sees when it works with files in an environment through the
Go, Python, TypeScript and Rust SDKs (SPEC.md, "File transfer", #5804). The
SDKs reach only cloud environments; a local VM's answers are held by the
supervisor's tests until they reach local VMs too. The format is in
[README.md](README.md).

## Where it stands

Updated 2026-11-22. Written before the code; nothing here has been built or
walked.

| ID | Dev | Production |
| --- | --- | --- |
| `files-stat` | not yet observed | not yet observed |
| `files-write-many` | not yet observed | not yet observed |

## Before the walk

- On Dev, `scripts/runtime/dev/with-dev-smoke-auth.sh -- COMMAND` runs one
  command as the synthetic Dev identity. Never use a person's sign-in.
- Run `cw` in a disposable home (`HOME` and `CW_CONFIG_DIR` under the walk's
  scratch directory).
- The examples use a cloud sandbox `files-a` holding `/workspace/f.txt`
  (5 bytes), the folder `/workspace/d` and the symlink `/workspace/link` to
  `f.txt`, made with `cw exec`. Remove it by exact name afterwards.

## `files-stat`: stat and exists

- **Entry points:** `files.stat` and `files.exists` in each SDK, over
  `StatFile`.
- **Driving it:** in each SDK, against `files-a`:
  1. `stat` and `exists` on `/workspace/f.txt`, `/workspace/d`,
     `/workspace/link` and `/workspace/missing`;
  2. `stat` on `/etc/passwd`;
  3. with an API key made with `--no-permissions`, step 1 again.
- **What must be seen:**
  - `f.txt` has size 5 and is not a folder; `d` is a folder; `link` is a
    symlink (mode `0o120000`), not the file it points to. Each matches its
    `ListFiles` row and `exists` is true for all three.
  - `missing` raises the SDK's not-found error from `stat`, and `exists` is
    false.
  - `/etc/passwd` is refused with the same error `ListFiles` gives for it.
  - Step 3 gives the same answers as step 1.

## `files-write-many`: many files in one call

- **Entry points:** `files.write_many` in each SDK (`writeMany`,
  `WriteMany`), over `WriteFiles`.
- **Driving it:** in each SDK, against `files-a`:
  1. write `/workspace/proj/a.txt`, `/workspace/proj/src/b.txt` (a folder
     that doesn't exist yet) and `/workspace/f.txt` (replacing it) in one
     call, then `stat` each and read each back with `cw exec cat`;
  2. one call holding 1,001 files; one holding 17 MiB; one naming
     `/workspace/x.txt` twice; one naming `/etc/x` beside a good path;
  3. with an API key made with `--no-permissions`, step 1 again with new
     paths.
- **What must be seen:**
  - step 1 returns the three paths with their sizes in order; each file
    holds exactly what was sent, with mode `0644`, and `/workspace/proj/src`
    now exists;
  - each call in step 2 is refused with `invalid_argument` naming the rule,
    and none of its files, the good path's included, exists afterwards;
  - step 3 writes as step 1 does.
