# Git in a local VM's mounted folder

Git inside a local VM, in a folder mounted from the host
([LINUX-LOCAL-VMS.md](../dev/LINUX-LOCAL-VMS.md), "Direct mounts"). A share's
files can belong to someone other than the workload user. On a Mac they
appear as root's; on Linux they're the host user's uid. So Git refused
mounted repositories with "dubious ownership" until the user set
`safe.directory` by hand (#5478). The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-20.

| ID | Linux host | Mac |
| --- | --- | --- |
| `local-vm-git-mounted` | observed working with #5659 (be7b44ead), 2026-11-20; failure observed on v0.4.24 for a nested repository of another uid | not yet observed |

## `local-vm-git-mounted`: Git works in a mounted checkout with nothing set by hand

- **Entry points:** `git` from `cw exec` or a shell in a VM created with
  `--path-mode mount` (the default), or with a `mounts:` entry in
  `codewire.yaml`.
- **States to exercise:**
  - the mounted checkout itself;
  - a second repository nested inside it, and a submodule's working tree;
  - a user's own `safe.directory` line in `~/.gitconfig`, which must survive
    a boot;
  - the VM after a stop and start;
  - a VM with no mounted folder (`--path-mode clone` or `copy`), whose Git
    config is left alone.
- **Driving it:**
  1. On the host, in an empty folder, make a checkout with a second
     repository and a submodule inside it:
     `git init -q top && git -C top commit -q --allow-empty -m one &&
     git init -q top/nested && git -C top/nested commit -q --allow-empty -m one`.
     Then add a submodule with
     `git -C top -c protocol.file.allow=always submodule add -q ./nested sub`.
  2. In `top`: `cw create --local --name git-walk --path-mode mount
     --no-profile --yes`.
  3. `cw exec --in git-walk -- sh -c 'for d in /workspace/top
     /workspace/top/nested /workspace/top/sub; do git -C "$d" status
     --short --branch >/dev/null && echo "$d ok" || echo "$d refused"; done'`.
  4. `cw exec --in git-walk -- sh -c 'cat ~/.codewire/gitconfig; git config
     --global --get-all include.path; git config --global --get-all
     safe.directory; sudo -n env -i HOME=/root PATH=/usr/bin:/bin git -C
     /workspace/top/nested status >/dev/null 2>&1 && echo "root trusts it" ||
     echo "root refuses"'`.
  5. `cw exec --in git-walk -- git config --global --add safe.directory
     /mine`, then `cw --local stop git-walk`, `cw --local start git-walk`,
     and steps 3 and 4 again.
  6. A VM with no mount: `cw create --local --name git-clone --path-mode
     clone --no-profile --yes`, then `cw exec --in git-clone -- sh -c 'test
     -e ~/.codewire/gitconfig && echo present || echo absent; git config
     --global --get-all include.path'`.
- **Proof:**
  - step 3 prints `ok` for all three paths, before and after the stop and
    start;
  - step 4 shows the product's file holding `directory = *` and one
    `include.path` naming it. `safe.directory` has no line in the global file
    itself, and root's Git refuses the repository;
  - after step 5, `/mine` is still there, unchanged, and the `include.path`
    line still appears once;
  - step 6 prints `absent` and no `include.path`.
- **Gotchas:**
  - On a Linux host whose user is uid 1000, the share's files already belong
    to the workload user, so step 3 passes even without the fix. Walk the
    fix on Linux with a host user of another uid.
  - `sudo -n` exists only in a VM with Docker on (the default). With
    `--no-docker`, skip root's check.
  - Check root in a clean environment, as step 4 does. Under a plain `sudo`,
    Git's own rule trusts a repository owned by the user who ran sudo
    (`SUDO_UID`), with or without this fix. The product's line is in the
    workload user's config, which root never reads.
  - The product's file is rewritten at every boot; edit your own
    `~/.gitconfig`, never `~/.codewire/gitconfig`.
- **Observed:**
  - Linux, 2026-11-20, a host user with uid 1000, in the credentials smoke's
    isolation, with `top`'s nested repository chowned to uid 1234 on the host
    (#5478):
    - released v0.4.24, before the fix:
      - step 3: `/workspace/top ok`, `/workspace/top/nested refused`,
        `/workspace/top/sub ok`. The share's own files are the workload's
        uid on this host, but the nested repository isn't;
      - no product file and no `include.path`;
      - `sudo` couldn't run at all ("no new privileges"; the sudo fix came
        after v0.4.24);
    - #5659 at be7b44ead, the fix:
      - step 3: all three `ok`, before and after a stop and start;
      - step 4: `~/.codewire/gitconfig` held the owner line, `[safe]` and
        `directory = *`; one `include.path` named
        `/home/codewire/.codewire/gitconfig`; no `safe.directory` in the
        global file itself;
      - root in a clean environment (`HOME=/root`, no `SUDO_UID`) refused
        both `top` and `nested`. Under a plain `sudo` (`SUDO_UID=1000`), root
        trusted `top`, owned by uid 1000, by Git's own `SUDO_UID` rule, and
        still refused `nested`. So the product's `*` doesn't reach root;
      - step 5: `/mine` was unchanged after the stop and start, and
        `include.path` still appeared once;
      - step 6, a `--path-mode clone` VM: `absent`, and no `include.path`.
  - Not yet observed: the Mac (shares owned by root), on the owner's walk
    list.
