# Installing cw with Nix

People who manage their tools with Nix install `cw` from the repository's
flake: `nix run` and `nix profile install`, and every release moves it
(#5399; owner, 2026-11-18). The design is
[CLI-NIX-INSTALL.md](../dev/CLI-NIX-INSTALL.md); what users are told is the
docs' install page ("Install with Nix"). The format is in
[README.md](README.md).

## Where the journey stands

Updated 2026-11-22. x86_64-linux is observed on NixOS, with v0.4.24
(2026-11-19) and with v0.4.27 (2026-11-22), each in a scratch NixOS 26.05 VM
with no prior `cw`. aarch64-darwin and aarch64-linux aren't walked yet, and
nor is x86_64-darwin. The public Nix check hasn't run yet: every run of the
mirror's `Nix flake` workflow so far ended in `startup_failure` before its
jobs started.

| ID | x86_64-linux (NixOS) | aarch64-linux | aarch64-darwin | x86_64-darwin |
| --- | --- | --- | --- | --- |
| `nix-run` | observed 2026-11-22 | not yet observed | not yet observed | not yet observed |
| `nix-profile` | observed 2026-11-22 | not yet observed | not yet observed | not yet observed |
| `nix-bytes` | observed 2026-11-22 | not yet observed | not yet observed | not yet observed |
| `nix-local-vm` | not applicable | not applicable | not yet observed | not applicable |
| `nix-upgrade-refusal` | observed 2026-11-22 | not yet observed | not yet observed | not yet observed |
| `nix-release-moves` | observed 2026-11-22, but its Nix check hasn't run | not applicable | not applicable | not applicable |
| `nix-check-refuses` | local half observed 2026-11-19 | not applicable | public CI not yet observed | not applicable |

#5399's done-when covers x86_64-linux on NixOS. The Mac and arm64 Linux walks
come after launch.

## Before the walk

- A clean machine: Nix with flakes on (`experimental-features = nix-command
  flakes`), no `cw` on `PATH`, no `~/.local/share/codewire` and no
  `~/.nix-profile/bin/cw`. A fresh NixOS VM, and a Mac user account that has
  never run `cw`, are clean.
- Record `nix --version` and the current stable release:
  `curl -fsSL https://releases.codewire.sh/cw/v1/channels/stable.json | jq -r .pointer.release_tag`.
- Nix caches a `github:` flake for an hour. After a release, add `--refresh`
  to see the newest one.

## `nix-run`: run cw without installing it

- **Do:** `nix run github:codewiresh/codewire -- version`.
- **See:** the stable version recorded above, and nothing installed:
  `command -v cw` finds nothing afterwards.
- **Observed 2026-11-22, x86_64-linux (NixOS 26.05, Nix 2.34.9):** with
  `--refresh`, `cw v0.4.27`, the stable release; no `cw` on `PATH`
  afterwards. The same on 2026-11-19 with `cw v0.4.24`.

## `nix-profile`: install it

- **Do:** `nix profile install github:codewiresh/codewire`, then a new shell,
  `command -v cw` and `cw version`.
- **See:** `cw` resolves to `~/.nix-profile/bin/cw` (or the profile's
  equivalent) and prints the stable version. `nix profile list` shows one
  element for it; record its name, which the refusal in
  `nix-upgrade-refusal` must name.
- **Observed 2026-11-22, x86_64-linux:** rc 0, element `codewire`;
  `~/.nix-profile/bin/cw` resolves to `/nix/store/…-cw-0.4.27/bin/cw`, and
  `cw version` prints `cw v0.4.27`.

## `nix-bytes`: the installed cw is the released cw

- **Do:** `sha256sum "$(readlink -f "$(command -v cw)")"` (`shasum -a 256` on a
  Mac), and compare with `nix/release.json` at the flake's revision.
- **See:**
  - **macOS and x86_64-linux:** the same SHA-256 as the release. On a Mac,
    `codesign --verify --strict --verbose=2` on that file says it is valid
    on disk and satisfies its Designated Requirement.
  - **aarch64-linux:** a different SHA-256, because only the interpreter is
    patched; `readelf -l` names an interpreter under `/nix/store/`, and
    `cw version` runs.
- **Observed 2026-11-22, x86_64-linux:**
  `ce2c5d9a18813a5a0610fff428e754a940ca68f4b4d90090cbd1b3eec7dcd7f7`, the
  release's `x86_64-unknown-linux-musl` executable.

## `nix-local-vm`: a local VM from a Nix cw on a Mac

- **Do:** with the Nix `cw` first on `PATH`, `cw setup --local`, then
  `cw create --local nix-walk`, `cw exec nix-walk -- uname -a`, `cw stop nix-walk`,
  `cw start nix-walk`, and `cw rm nix-walk`.
- **See:** each step succeeds as in [local-vm-mac.md](local-vm-mac.md). The
  runtime it unpacked is under the user's Codewire data directory, and nothing
  was written under `/nix/store`. `cw setup ssh` writes a config that names the
  profile link, not a `/nix/store` path, so it still works after the profile
  moves.
- **Then:** `nix profile upgrade` to a newer release (or roll the profile back
  and forward), `nix-collect-garbage`, and `cw start nix-walk` again. It
  starts, because nothing kept the old store path.

## `nix-upgrade-refusal`: cw upgrade defers to Nix

- **Do:** with the Nix `cw`, run `cw upgrade --cli`, `cw upgrade`, and
  `cw upgrade rollback`. Then create a managed store as an earlier
  `install.sh` would (`curl -fsSL https://get.codewire.sh | sh`), put the
  Nix `cw` first on `PATH` again, and repeat.
- **See:** each one refuses with the message in CLI-NIX-INSTALL.md
  ("Updating"), naming the element name recorded in `nix-profile`, and exits
  non-zero. Nothing changes: `~/.local/bin/cw` and
  `~/.local/share/codewire/cli/selection.json` are byte-for-byte as before,
  or still absent. `cw upgrade --vms` still runs. The daily update notice
  names the Nix command.
- **Observed 2026-11-22, x86_64-linux (v0.4.27):** all three refuse with
  exit 1, naming `nix profile upgrade codewire`, both before and after
  `install.sh` created a managed store. Without the store,
  `~/.local/bin/cw` and `selection.json` stay absent. With it, both are
  byte-identical before and after. `cw upgrade --vms` answers
  "No local VMs run on a previous cw." and exits 0. The daily update notice
  wasn't waited for.

## `nix-release-moves`: a release moves the flake

- **Do:** after the next release's `cli-release` succeeds, find the
  `automation/nix-release-pin` pull request.
- **See:** it changes only `nix/release.json` and the signed
  `nix/SHA256SUMS` and `nix/SHA256SUMS.asc` that prove it. Its body lists the
  four systems with the signed `SHA256SUMS` hash, the hash written and
  `exact match`. Its Nix check is green. After it lands,
  `nix run --refresh github:codewiresh/codewire -- version` prints the new
  release, and nobody edited the file by hand.
- **Observed 2026-11-22 (v0.4.27):** cli-release opened #5839 from
  `automation/nix-release-pin`, with those three files and four `exact match`
  rows. It landed through the merge queue, and the NixOS walk above printed
  `cw v0.4.27` from the mirror. The Nix check didn't run: the mirror's
  `Nix flake` workflow ended in `startup_failure`, as every run of it has so
  far.

## `nix-check-refuses`: a wrong hash fails the check

The public check runs only on main, so a wrong hash is proved with its two
commands on a copy of the flake, never on main.

- **Do:** in a scratch copy of the checkout (`git archive HEAD | tar -x -C
  COPY`), change the `x86_64-linux` `sha256` in `nix/release.json` by one
  digit. Run
  `python3 -I -B scripts/ci/release/nix_release_pin.py check --pin COPY/nix/release.json`
  from the checkout, and `nix build path:COPY#cw` on x86_64 Linux.
- **See:** the first fails and names `x86_64-linux` with the pinned and the
  signed value. The second fails because the download is addressed by the
  digest: no blob has the tampered one, so the fetch answers 404 and the build
  stops with "cannot download".
- **And before merge:** run the Supply-chain scan's proof the way the step
  does, with this checkout as the base and the copy as the candidate:
  `python3 -I -B scripts/ci/release/nix_release_pin.py verify --base . --candidate COPY`.
  It fails, naming `x86_64-linux` and saying the hash is not the signed one.
- **And:** the latest `Nix flake` run on the public mirror's Actions page,
  for the current pin, is green on Linux and macOS.
