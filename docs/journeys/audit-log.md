# Sandbox audit log

A hosted Sandbox's audit log (#6189): what happened to it and through it,
who did it, and who may read it. `SPEC.md` "Sandbox audit log" defines it;
the hosted refusal log (#6144) is its `refused` kind. This journey was
written before the code. `cw audit` does not exist yet, and the commands
below are the ones SPEC proposes. Its exact text is in
[`docs/design/previews/cw-audit.txt`](../design/previews/cw-audit.txt). The
format is in [README.md](README.md).

## Where it stands

Written first; every step is not yet observed.

| ID | Dev | Production |
| --- | --- | --- |
| `audit-log` | not yet observed | not yet observed |

## `audit-log`: a Sandbox's members see what happened to it

- **Entry points:** `cw audit ENV`, with `--kind`, `--since`, `--until`,
  `--limit`, `--cursor` and `--output json`; the Sandbox's Audit log page
  in the dashboard; the API read behind both; `cw --cloud policy log ENV`
  and the `Refused:` line of `cw info ENV`, which read its `refused`
  events.
- **States to exercise:**
  - each kind: `access`, `lifecycle`, `policy`, `refused` and
    `credentials`;
  - a refusal repeated many times, and one the next revision allows;
  - a name that fails the host check;
  - an admin opening a member's Sandbox, read by that member, by another
    admin and by an owner;
  - a member of another organization, and a request from inside the
    Sandbox;
  - nothing in the last 7 days, and a filter that matches nothing;
  - the Sandbox deleted, then read by an owner and by its member;
  - a local VM, and a platform without the read.
- **Driving it:** no command yet (#6189). On Dev, with hosted egress on and
  `cw-egress` running, so that `hosted-enforcement` in
  [network-and-egress.md](network-and-egress.md) reads `ENFORCED` for a new
  Sandbox, and the policy store switched on. Use `cw` built from the source
  under test.

  Preconditions:
  - three walk accounts in one organization: M, a member; D, an admin; and
    O, an owner; and X, a member of another organization;
  - a scratch `HOME` for each account, so no step uses a maintainer's own
    sign-in or keyring;
  - a cloud credential profile of M's, `walk-audit`, holding M's GitHub
    connection to a test account ([credentials.md](credentials.md) makes
    one).

  As M, make the Sandbox and its policy, open a terminal, change the
  policy, get refusals, attach and use a credential, then stop and start:

  ```sh
  cw --cloud policy create walk-audit --allow docs.rs:443
  cw --cloud policy allow walk-audit github.com:443
  cw --cloud create --name walk-audit
  cw audit walk-audit --kind refused
  cw shell walk-audit
  cw update walk-audit --policy walk-audit
  cw exec --in walk-audit -- sh -c 'for i in 1 2 3 4 5; do curl -sS -m 5 https://crates.io/ ; done ; true'
  cw exec --in walk-audit -- sh -c 'timeout 10 nslookup example.com 8.8.8.8 ; true'
  cw --cloud policy allow walk-audit crates.io:443
  cw exec --in walk-audit -- sh -c 'curl -sS -m 5 https://crates.io/ ; curl -sS -m 5 https://pypi.org/ ; true'
  cw update walk-audit --profile walk-audit
  cw exec --in walk-audit -- git ls-remote https://github.com/codewiresh/codewire HEAD
  cw stop walk-audit
  cw start walk-audit
  cw audit walk-audit
  cw audit walk-audit --kind refused
  cw audit walk-audit --output json
  cw --cloud policy log walk-audit
  cw --cloud policy log walk-audit --output json
  cw info walk-audit
  ```

  Type `exit` in the shell after a minute. Then:

  1. As D, the admin: `cw shell walk-audit`, then `exit`.
  2. As M, D and O in turn: `cw audit walk-audit --kind access`.
  3. As M, open the Sandbox's Audit log page in the dashboard. With it
     open, run the `pypi.org` request again from another terminal. Choose
     each kind chip, the "Last hour" range, and "Show older events".
  4. As X: `cw audit walk-audit`.
  5. Inside the Sandbox: `cw exec --in walk-audit -- cw audit walk-audit`.
  6. On a local VM of M's, `walk-log`: `cw audit walk-log`.
  7. Note the Sandbox's ID from `cw info walk-audit --output json`.
     Remove it with `cw --cloud rm walk-audit --yes`. As O, run `cw audit`
     with that ID; as M, the same.
  8. Remove the policy and the profile by exact name:
     `cw --cloud policy delete walk-audit`, and the profile as
     [credentials.md](credentials.md) says.
- **Proof:**
  - right after the create, `cw audit walk-audit --kind refused` reads `No
    refused events for walk-audit in the last 7 days.` with `→ cw audit
    walk-audit`, exit 0;
  - `cw audit walk-audit` lists, newest first, by when each began:
    `Created by M`; `Terminal opened by M from IP`, with its open and close
    times; one `Exec by M from IP` line for the hour, counting the
    sessions; `Policy changed from hosted-default to walk-audit by M`; one
    `Refused crates.io:443 (tcp)` line with a count of at least 5 and its
    first and last time, reading `Allowed since rev 3`; `walk-audit edited
    by M: rev 2 → rev 3 · allows crates.io:443`; `Enforcing walk-audit rev
    3 · by the platform`; `Refused pypi.org:443 (tcp)` under rev 3;
    `Refused 8.8.8.8:53 (udp) · UDP not carried`; the credential attached;
    `GitHub used for github.com` with a count for the hour; `Stopped by M`
    and `Started by M`;
  - the IP in each access line is the public address of the machine that
    ran the command, never an address inside Codewire;
  - the last line is `→ cw --cloud policy allow walk-audit pypi.org:443`,
    and no line offers a step for crates.io;
  - `--kind refused` shows only refused lines and the same `→` step;
  - JSON holds `environment`, `policy` (walk-audit, revision 3), `events`
    and `next_cursor`, and nothing else on stdout. Each event has `id`,
    `kind`, `action`, `time`, `last`, `count` and `actor`, and the fields
    of its kind. The crates.io event has `allowed_since_revision` 3. No
    value holds a command line, a path, a header, a body or a credential;
  - `cw --cloud policy log walk-audit` prints the table `cw --local policy
    log` prints, with one row each for crates.io (rev 2, count at least 5),
    pypi.org (rev 3) and 8.8.8.8 (udp), the last line `Showing the last 7
    days.` and the same `→` step as `cw audit`. Its JSON holds only
    `refusals` and `dropped`, each row with a local row's fields. `cw info
    walk-audit` has a `Refused:` line counting the same requests in the last
    7 days and naming `cw --cloud policy log walk-audit`;
  - D's terminal line reads `Terminal opened by D (admin) from IP`, the
    same for M, D and O, IP included;
  - the page lists the same events in the same words. The new `pypi.org`
    refusal appears without a reload. The chips and range filter it.
    "Show older events" adds nothing, since the Sandbox is new;
  - X is refused as not found and sees no event;
  - inside the Sandbox, `cw audit` is refused and prints no event;
  - `cw audit walk-log` says local VMs have no audit log, with `→ cw
    --local policy log walk-log`, exit 1;
  - after the delete, O reads every event by ID, with `Deleted by M` first;
    M is refused;
  - against a platform without the read, `cw audit` says the platform has
    no audit log yet, never an RPC error.
- **Gotchas:**
  - refusals reach the log within about 5 seconds: the broker reports once
    a second and `cw-egress` sends every 5. Read again before calling an
    event missing;
  - the guest's resolver retries a refused lookup, so one `curl` can count
    more than once;
  - a Sandbox whose status isn't `ENFORCED` has no hosted broker, so it
    records no refusals; that is `hosted-enforcement`'s finding, not this
    walk's;
  - a platform restart and an idle stop are not driven here. They come
    from `sandbox-unplanned-restart` in [cloud-sandbox.md](cloud-sandbox.md)
    and from [idle-stop.md](idle-stop.md); read `cw audit` after those
    walks;
  - a withheld name can't be made from inside the Sandbox: the guest's
    network stack refuses a name with an escape byte before the broker
    sees it, as in `refusal-log`. The host check that writes `(a name cw
    won't show)` is held by #6144's tests;
  - a new Sandbox always has its create event, so the "nothing in the last
    7 days" text is held by tests and the preview, not this walk;
  - the bounds on the read (the 5-second statement timeout and 30 grouped
    reads a minute), the live event reaching only watchers who may read the
    log, and refusing an environment-scoped session from inside the Sandbox
    are held by tests; the walk sees only the plain refusal from inside;
  - the 90-day retention, the monthly partitions, the hour's fold and the
    1,000-subject bound are held by tests; this walk sees only that counts
    grow and lines don't multiply;
  - the policy revisions in the proof assume the policy was new at step 1;
    `policy allow` for GitHub makes revision 2.
- **Observed:** not yet observed.
