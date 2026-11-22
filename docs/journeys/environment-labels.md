# Environment labels

Labels on an environment: set them when it is made, change them, and find
environments by them, in the cloud, on a local VM and from the four SDKs
(SPEC.md, "Environments", #5804). The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-22. Written before the code; nothing here has been built or
walked.

| ID | Dev | Production |
| --- | --- | --- |
| `labels-create` | not yet observed | not yet observed |
| `labels-find` | not yet observed | not yet observed |
| `labels-change` | not yet observed | not yet observed |
| `labels-limits` | not yet observed | not yet observed |
| `labels-local` | not yet observed (a local VM on the host) | not applicable |
| `labels-sdk` | not yet observed | not yet observed |

## Before the walk

- On Dev, `scripts/runtime/dev/with-dev-smoke-auth.sh -- COMMAND` runs one
  command as the synthetic Dev identity. Never use a person's sign-in.
- Run `cw` in a disposable home (`HOME` and `CW_CONFIG_DIR` under the walk's
  scratch directory), so no step reads a maintainer's own sign-in.
- The examples make `lab-a` and `lab-b` in the cloud and `lab-l` on a local
  VM. Remove each by exact name afterwards.
- `labels-change` needs an API key of the walking organization made with
  `--no-permissions`, removed by exact name afterwards.

## `labels-create`: labels set at create are shown

- **Entry points:** `cw create --label`, `cw info`, `cw ls --output json`.
- **Driving it:**
  1. `cw create --cloud --name lab-a --label team=search --label job=nightly --yes`.
  2. `cw create --cloud --name lab-b --label team=search --yes`.
  3. `cw info lab-a` and `cw ls --output json`.
- **What must be seen:** `cw info lab-a` shows both labels; the JSON row of
  `lab-a` holds `{"team":"search","job":"nightly"}` and the row of `lab-b`
  holds `{"team":"search"}`. An environment made without `--label` has an
  empty set.

## `labels-find`: a list filtered by labels

- **Entry points:** `cw ls --label`, `ListEnvironments` with `labels`.
- **Driving it:**
  1. `cw ls --label team=search`.
  2. `cw ls --label team=search --label job=nightly`.
  3. `cw ls --label team=nobody`.
- **What must be seen:** the first lists `lab-a` and `lab-b`, the second only
  `lab-a`, and the third lists nothing and says that no environment has
  those labels, exiting 0.

## `labels-change`: labels changed and removed

- **Entry points:** `cw label`, `UpdateEnvironmentLabels`.
- **Driving it:**
  1. `cw label lab-b team=billing owner=ci`.
  2. `cw label lab-b --remove owner`.
  3. With the no-permissions API key in `CODEWIRE_API_KEY`:
     `cw label lab-b team=other`.
  4. `cw info lab-b`.
  5. Two changes at once: `cw label lab-b a=1 & cw label lab-b b=2; wait`,
     then `cw info lab-b`.
  6. From an SDK, a replace with `{team: "search"}`, then `cw info lab-b`.
- **What must be seen:** after step 1 `lab-b` has `team=billing` and
  `owner=ci`; after step 2 only `team=billing`. Step 3 is refused with
  `permission_denied` naming `write:environments`, and step 4 still shows
  `team=billing`. After step 5 `lab-b` has both `a=1` and `b=2`; after step 6
  it has only `team=search`.

## `labels-limits`: a request over a limit is refused whole

- **Driving it:** each of these, with `cw create --cloud --name lab-x` and
  with `cw label lab-a`:
  - 65 labels;
  - a key of 64 characters, a key starting with `-`, and a key holding a
    space;
  - a value of 257 characters, and a value holding a newline;
  - `cw label lab-a team=x --remove team`, one key both set and removed.
- **What must be seen:** each is refused with `invalid_argument` naming the
  label and the limit. No `lab-x` is made, and `lab-a`'s labels are unchanged.
  A key of 63 characters and a value of 256 are accepted.

## `labels-local`: the same on a local VM

- **Entry points:** `cw create --local --label`, `cw --local ls --label`,
  `cw label` on a local VM.
- **Driving it:**
  1. `cw create --local --name lab-l --label team=search --yes`.
  2. `cw --local ls --label team=search`, then `cw ls --label team=search`.
  3. `cw label lab-l team=billing`, then `cw info lab-l`.
  4. `cw stop lab-l`, `cw start lab-l`, `cw info lab-l`.
  5. The `labels-limits` refusals against `lab-l`.
- **What must be seen:** step 2 lists `lab-l` alone, then `lab-l` beside
  `lab-a` and `lab-b`. Step 3 shows `team=billing`, and it survives step 4.
  The refusals in step 5 read as in the cloud. The organization's
  `ListEnvironments` never returns `lab-l` or its labels.

## `labels-sdk`: labels from each SDK

- **Entry points:** the Go, Python, TypeScript and Rust SDKs.
- **Driving it:** in each SDK, create an environment with two labels, list
  with one of them as a filter, replace its labels, list again, and delete
  it.
- **What must be seen:** each list returns exactly the environments whose
  labels match, with their labels; each SDK's refusal of 65 labels carries
  the server's message.
