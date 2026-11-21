# Admin Overview

This walk proves what a platform administrator reads on Admin → Overview
(#5304): the Sandboxes figure is the ones active now, never a lifetime count.
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
