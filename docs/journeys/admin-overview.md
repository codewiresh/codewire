# Admin Overview

This walk proves what a platform administrator reads on Admin → Overview
(#5304), where the Sandboxes figure is the ones active now, never a lifetime
count, and on Admin → Organizations (#6086), where each organization's
Sandboxes are counted.
The format is in [README.md](README.md).

## `admin-overview-sandboxes`: the card shows the Sandboxes active now

Issue: #5304. Code: `crates/codewire-dashboard-web/templates/admin-overview.html`,
`get_admin_stats_core` in `crates/codewire-orchestration/src/api/admin.rs`.

- **Entry points:** Admin → Overview (`/admin/`), signed in as a platform
  administrator.
- **States to exercise:**
  - an install with running, starting, stopped and deleted Sandboxes;
  - one where every Sandbox has been deleted;
  - one with none ever created.
- **Driving it:** on Kind or Dev, sign in as an administrator, note
  `cw list` across the organizations (or the database's own count), and open
  `/admin/`.
- **Proof:**
  - The card reads "Active Sandboxes" and one number: every Sandbox that is
    not stopped, deleted, being deleted, archived or in error. There is no
    other line on the card.
  - With every Sandbox deleted, the number is 0.
- **Gotchas:** a deleted Sandbox keeps its row, so any count of the
  `environments` table without a state filter is the lifetime count.
- **Observed:** not yet observed.

## `admin-organizations-sandboxes`: each organization's Sandboxes are counted

Issue: #6086. Code: `crates/codewire-dashboard-web/templates/admin-organizations.html`,
`list_organization_sandbox_counts_core` in
`crates/codewire-orchestration/src/api/admin.rs`; the counts are defined on
`SandboxCounts` in `proto/codewire/admin/v1/admin.proto`.

- **Entry points:** Admin → Organizations (`/admin/organizations/`), signed in
  as a platform administrator.
- **States to exercise:**
  - an organization with running, starting, failed, stopped, archived and
    deleted Sandboxes;
  - an organization that has never created one;
  - the counts failing to load;
  - a phone-width window.
- **Driving it:** on Kind or Dev, sign in as an administrator. Read each
  organization's rows in `environments` by state, then open
  `/admin/organizations/`.
- **Proof:**
  - Five totals above "All organizations" count every organization's
    Sandboxes: created, running, stopped, failed and deleted.
  - Each organization's row has those five columns and when it last created a
    Sandbox. The states behind each count are on `SandboxCounts` in the
    proto:
    - Created is every Sandbox it ever created.
    - Running is running or on its way there, starting included.
    - Stopped is stopping, stopped, archiving or archived.
    - Failed is in error, failed to build or in an unknown state.
    - Deleted is being deleted or deleted.
  - Running, Stopped, Failed and Deleted add up to Created.
  - An organization that never created a Sandbox shows 0 in each column and
    "Never" for the last one.
  - When the counts can't be read, the page still renders: the totals and each
    column say "Unavailable".
  - A non-administrator is refused, as for the rest of Admin.
  - At 390 px the table scrolls inside its card and the page doesn't scroll
    sideways.
- **Gotchas:** the counts come from one query for every organization, not one
  per row; a deleted Sandbox keeps its row, so Created never goes down.
- **Observed:** not yet observed.
