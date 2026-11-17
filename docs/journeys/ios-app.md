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
  in the empty list. The sheet is the dashboard's Create Sandbox form for a
  phone: the same fields, rules, refusal words and request, built by the same
  code (`codewire_project::create_input`, then
  `codewire_project_proto::create_request`). The `cw` counterpart is
  `cw --cloud create` (`cloud-sandbox.md` `sandbox-create`).
- **The form (not yet observed):**
  - **Name**, which Codewire picks when left empty.
  - **Workspace image.** The organization's presets are suggestions under it,
    filtered as you type; there is no separate preset list. Choosing one
    fills its image, resources, Delete after, commands and previews into the
    fields still empty, and an edit always wins.
  - **Resources and lifetime:** CPU, Memory and Disk, and Delete after, in
    the dashboard's units and limits.
  - **Repositories:** the connected GitHub account's repositories to search,
    or a URL, branch and mount path under `/workspace`.
  - **Ports:** an internal port, a preview label and who can open the
    preview.
  - **Isolation:** Confidential only where the organization offers it.
  - **Runtime commands:** Install command and Startup script.
  - **Sources:** a secret project and a provider access profile; personal
    secrets and personal access are each confirmed on their own.
  - Resources, Repositories, Ports, Isolation, Runtime commands and Sources
    start collapsed. There is no agent picker (#4341).
- **States to exercise:**
  - the form: options loading; the organization's presets as image
    suggestions; options that fail to load, which still lets a create go with
    an image or a repository;
  - a field the rules refuse, such as a CPU out of range or a duplicate
    preview label, shown at that field in the dashboard's words before any
    request (not yet observed);
  - a create the server refuses (for example an organization out of
    credit), shown in the sheet with the server's reason;
  - a create with a preset and nothing else filled in, which the server
    accepts (not yet observed; the 2026-11-16 walk was refused with
    "project_spec is required", because the request had no project);
  - setup steps arriving one by one, then **Waiting for the workspace
    daemon**, then **Open Shell**;
  - a setup that fails: at a `failed` row, the failed step and its message;
    without one, the reason the environment gave (`cw create`'s setup guard);
  - the stream lost mid-setup (airplane mode on and off): a reconnect line,
    then the steps carry on from the last one shown, none repeated;
  - closing the sheet during setup: the environment carries on and reaches
    `running` in the list.
- **Driving it:** in the organization, tap **+**, enter a name, start typing
  in Workspace image and choose a preset, set one resource and one
  repository, tap **Create**. Watch the steps; at **Open Shell**, open it and run
  `echo $HOSTNAME`. Close the shell, delete the environment from its detail
  page.
- **Proof:** the environment's ID in the sheet matches the one `cw --cloud ls`
  lists; `cw info NAME` shows the image, resources and repository the form
  asked for; its setup steps match `cw logs NAME --setup` row for row; the shell
  answers `echo $HOSTNAME` with the environment's host name.
- **Gotchas:** a create counts against the organization's credit; remove each
  environment. The app follows the first run of setup only; a restart later
  is the list's to show.
- **Observed:**
  - 2026-11-16 (the owner, on their iPhone, a debug build of the #4998
    core): **refused.** Create with a preset and nothing else filled
    in failed with "project_spec is required": the request carried no
    project. The preset list was also too long to use. Both led to the form
    above.
