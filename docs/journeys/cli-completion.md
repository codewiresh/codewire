# CLI tab completion

`cw` completes the names a command takes, not only its commands and flags:
environments, sessions, credential profiles, credentials, network policies,
mesh networks, presets, snapshots, VM checkpoints and organizations, in zsh,
bash and fish (#5108; owner, 2026-11-16: "tab complete the cli"). Before this,
`cw completion` printed a static script, so `cw attach <TAB>` offered nothing.
The presentation rules are in the `codewire-cli-design` skill ("Completion");
what users are told is in the docs' install page and CLI reference ("cw
completion"). The format is in [README.md](README.md).

## Where the journey stands

Updated 2026-11-16. Written first; nothing here is observed.

| ID | Local | Dev | Production |
| --- | --- | --- | --- |
| `complete-environments` | not yet observed | not yet observed | not applicable |
| `complete-sessions` | not yet observed | not yet observed | not applicable |
| `complete-account-names` | not yet observed | not yet observed | not applicable |
| `complete-snapshots` | not yet observed | not yet observed | not applicable |
| `complete-bounds` | not yet observed | not yet observed | not applicable |
| `complete-install` | not yet observed | not applicable | not applicable |

Production is not walked: completion reads only the signed-in user's own
names, and a walk on Dev proves the same code. Record it on Production when a
release carries it and someone has the released `cw` in a shell.

## Before the walk

- Use a `cw` built from the source under test, and record `cw version`.
- Give the walk a throwaway `HOME`, so it never touches the walker's own
  sign-in, cache or completion files, and run the shell as that user:
  `HOME=$(mktemp -d) zsh -i` (bash and fish alike), after
  `cw completion --install`.
- Cloud names need a sign-in: on Dev,
  `scripts/runtime/dev/with-dev-smoke-auth.sh -- COMMAND` runs one command as
  the synthetic Dev identity, and `cw login` signs a shell in for the walk.
- Create one local environment and one cloud environment with different
  names, a session in each, and one of each other name below, so that every
  completion has something to offer and something to leave out.
- Look at what the shell offers with the shell's own key (`TAB`), and with
  `CW_COMPLETE=SHELL cw -- cw WORDS…` for the engine alone, which is what a test
  asserts.

## What completes

The command tree is the source of the list: every argument that takes one of
these names is wired to its source, and a test walks the tree so that a new
argument that takes a name and has no completer fails.

| Name | Where | Source |
| --- | --- | --- |
| Environment | `ENV` and `--in`, on every command | Local state for a local environment; the cloud list for a cloud one. `--local` and `--cloud`, and `cw --cloud …`, narrow it. With neither, both are offered, a local one first |
| Session | `--session`, on `attach`, `msg`, `logs`, `steer` and `interrupt` | The sessions of the environment already typed on the line, or of the current one. No environment, nothing |
| Credential, credential profile | `cw credentials …`, `--profile` | Local credential names from local state, cloud ones from the cloud list, by the same placement rule |
| Network policy | `cw policy …`, `--policy` | The policies the placement has |
| Mesh network, node | `cw network …` | The signed-in organization's networks, and a network's nodes once it is on the line |
| Preset | `--preset` | The presets `cw create` accepts |
| Snapshot, VM checkpoint | `cw snapshot …`, `cw checkpoint …`, `--snapshot`, `--checkpoint` | Local state for a local one, the cloud list otherwise |
| Organization | `--org`, `cw org …` | The organizations the signed-in user belongs to, in the form the argument accepts (a slug or an ID) |

A completion offers names only. Where a name and an ID both identify a thing,
the name is offered; a session with no name offers its short ID, which
`--session` accepts, and a credential name that two providers share is offered
as `PROVIDER/NAME` once #4928 lands. Free text completes nothing: the words of
a message (`cw msg`) and the command `cw exec` runs. No secret value, token, key or hash is ever read for
completion, let alone offered.

## `complete-environments`: `cw attach <TAB>`

- **Entry points:** `TAB` after any command that takes `ENV` or `--in`, in
  zsh, bash and fish.
- **States to exercise:**
  - a local and a cloud environment (both offered, labelled by placement
    where the shell shows descriptions: zsh and fish);
  - `--local` and `--cloud` before the cursor (only that placement's);
  - a prefix (`cw attach fa<TAB>` offers only names that start with it);
  - signed out (local names only, and no message in the line);
  - no environments (nothing is offered, and the line is left alone).
- **Driving it:** in each shell, `cw attach <TAB>`, `cw --cloud attach <TAB>`,
  `cw exec --in <TAB>`, `cw rm <TAB>` and `cw attach fa<TAB>`.
- **Proof:** the offered names equal `cw ls -o json` names for the same
  placement, as sets, in all three shells; the engine call returns the same
  set in a test with fixed local state and a stub cloud list.
- **Gotchas:** a shell that caches completions (zsh `_cache`, fish's
  `__fish_complete`) can show a stale list; use a new shell.

## `complete-sessions`: `cw msg ENV --session <TAB>`

- **Entry points:** `--session` on `attach`, `msg`, `logs`, `steer` and
  `interrupt`.
- **States to exercise:** a session with no name (its short ID is offered, and
  the description in zsh and fish is the program name only, the first word of
  its command with no arguments, its state and when it started; no further
  part of the command line is shown or cached), a local environment whose
  daemon runs, one whose
  daemon is stopped (nothing is offered, and completion never starts it), a
  cloud environment that is running and one that is stopped, and no
  environment on the line.
- **Driving it:** `cw msg local-app --session <TAB>`, `cw logs --in cloud-app
  --session <TAB>`, and `cw attach --session <TAB>`.
- **Proof:** the offered names are the environment's sessions as
  `cw sessions -o json` lists them, and the stopped environment's daemon is
  still stopped afterwards.

## `complete-account-names`: credentials, profiles, policies, networks, presets, organizations

- **Entry points:** `cw credentials <TAB>`, `cw create --profile <TAB>`,
  `cw policy allow <TAB>`, `cw network <TAB>`, `cw create --preset <TAB>`,
  `cw --org <TAB>`.
- **States to exercise:** each name with none to offer, with one, and with
  several; a cloud name while signed out (nothing offered, no prompt).
- **Proof:** each offered set equals the matching list command's names
  (`cw credentials ls`, `cw policy ls`, `cw network ls`, `cw org list`).
- **Gotchas:** an organization's list is the signed-in user's, so walk it as
  a user with two organizations.

## `complete-snapshots`: `cw create --snapshot <TAB>`

- **Entry points:** `--snapshot` and `--checkpoint`, and `cw snapshot …` and
  `cw checkpoint …`.
- **States to exercise:** a local snapshot, a cloud snapshot, and a VM
  checkpoint on a local VM.
- **Proof:** the offered names equal the list commands' names for the same
  placement.

## `complete-bounds`: completion never hangs, prompts or prints

- **Entry points:** every completion above.
- **States to exercise:** the server unreachable, the server answering slowly,
  signed out, an expired sign-in (completion neither refreshes nor rewrites
  it), a corrupt or unreadable cache file, a terminal with no `HOME`, a switch
  to another account, organization or server (the previous one's cloud names
  are not offered, not even from a fresh cache), and `cw logout` (the cache is
  gone), and a local daemon that is wedged: its socket accepts and never
  answers.
- **Driving it:** point `CODEWIRE_API_URL` at a port that accepts and never
  answers, then at a closed port, then sign out, and `TAB` after `cw attach`
  each time. Time the engine call with `time CW_COMPLETE=zsh cw -- cw attach ''`.
- **Proof:**
  - each of these returns in under 1 s, and a hung server costs exactly the
    request bound (see the skill), never more;
  - a wedged local daemon costs its 400 ms bound and nothing offers its
    names;
  - nothing is written to the line or the terminal: no prompt, no error text,
    no sign-in, no browser;
  - with the server down and a cache within its stale limit, the cached names
    are offered; past it, none are;
  - after `cw logout`, and after a switch of account, organization or server,
    no cloud name from before is offered;
  - the cache file holds names only, in the user's own state directory, mode
    0600, and a test reads it and finds no value, token or ID.

## `complete-install`: install, doctor and upgrade

- **Entry points:** `cw completion --install`, `cw completion SHELL`,
  `cw doctor`, and an upgrade.
- **States to exercise:** a fresh install in each shell; a shell that already
  has the static script an older `cw` wrote (it completes commands and flags
  only, and `cw doctor` says to reinstall); a script written by an earlier
  version after `cw` is upgraded (upstream's glue and the binary may no
  longer agree, so `cw doctor` names both versions and the command).
- **Proof:** `cw doctor` reports completion installed with names, or says
  `cw completion --install` is needed and why; an old static script is named
  as such; the installed file's first line names the `cw` version that wrote
  it; the install docs list what completes and match this table.
