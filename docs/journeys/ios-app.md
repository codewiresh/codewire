# The iOS app

This journey proves the iOS app's features on a real iPhone, under `SPEC.md`
"3. Components", "Native apps", and Program #3825. The app's Rust core is
`crates/codewire-client-ffi`: it reuses `cw`'s own client paths, so each step
here has a `cw` counterpart whose journey is in
[cloud-sandbox.md](cloud-sandbox.md). The format is in
[README.md](README.md).

## Where the journey stands

Updated 2026-11-16.

| ID | Owner | Dev | Production |
| --- | --- | --- | --- |
| `ios-create` | cw-ios | not yet observed | not yet observed |

A debug build signs in to Dev by default and offers Production; a release
build signs in to Production only.

## Before the walk

- An iPhone with the app installed from the change under test, signed in to
  the owner's own organization on the surface being walked. Builds and
  installs follow `apps/ios/BUILD.md`.
- Record the app's source commit and the source the surface runs.
- Remove every environment the walk creates, by its exact name, from the app
  or with `cw --cloud rm NAME --yes`.

## `ios-create`: create an environment from the app

- **Entry points:** the environment list's **+** button; **New Environment**
  in the empty list. The same create as `cw --cloud create --preset-id ID`
  (`cloud-sandbox.md` `sandbox-create`).
- **States to exercise:**
  - the form: presets loading, the organization's presets listed, and a
    failed preset listing, which still lets a create go without a preset;
  - a create the server refuses (for example an organization out of
    credit), shown in the sheet with the server's reason;
  - setup steps arriving one by one, then **Waiting for the workspace
    daemon**, then **Open Shell**;
  - a setup that fails: at a `failed` row, the failed step and its message;
    without one, the reason the environment gave (`cw create`'s setup guard);
  - the stream lost mid-setup (airplane mode on and off): a reconnect line,
    then the steps carry on from the last one shown, none repeated;
  - closing the sheet during setup: the environment carries on and reaches
    `running` in the list.
- **Driving it:** in the organization, tap **+**, enter a name, choose a
  preset, tap **Create**. Watch the steps; at **Open Shell**, open it and run
  `echo $HOSTNAME`. Close the shell, delete the environment from its detail
  page.
- **Proof:** the environment's ID in the sheet matches the one `cw --cloud ls`
  lists; its setup steps match `cw logs NAME --setup` row for row; the shell
  answers `echo $HOSTNAME` with the environment's host name.
- **Gotchas:** a create counts against the organization's credit; remove each
  environment. The app follows the first run of setup only; a restart later
  is the list's to show.
- **Observed:** not yet observed.
