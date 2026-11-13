# Journeys

A journey file says how to prove that one user-facing feature works: what to
run, what must be seen, and when it was last seen. `AGENTS.md` ("Done means
observed working") requires every user-visible change to walk its acceptance
journey. The journeys are written down here so that the next person or agent
runs the same commands and holds the result to the same standard.

| File | Journey |
| --- | --- |
| [launch.md](launch.md) | The public-launch walk (#4370): a new account goes from sign-up to a snapshot and a fork |

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
  issue. A gap is written down, never worked around.
- A journey is never weakened to pass. A proof through one entry point does
  not count for the others.
- A proof on a stand-in (Kind for Dev, Dev for Production) lists what the
  stand-in did that the real target will not.
- This is public text: no private hosts, no credentials, no names of people's
  machines.

## Not built yet

These belong to #4356 and do not exist. Do not rely on them:

- `covers:` lines that name the source paths a journey proves, and a policy
  check that fails when a journey names a missing path. Until that check
  exists, journey files carry no `covers:` lines. Only the dashboard specs
  have them today (`docs/TESTING.md`).
- `scripts/dev/preflight.sh --explain` printing the journeys a change
  selects.

## Adding or changing a journey

1. Check that every command and path exists before writing it down.
2. Run it. Record what was seen under **Observed**, or write "not yet
   observed".
3. When behaviour changes, change the journey in the same pull request, and
   remove an observation that no longer describes the product.
