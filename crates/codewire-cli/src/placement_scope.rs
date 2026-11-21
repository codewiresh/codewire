//! Placement scope: which commands read `--local` / `--cloud`.

use super::*;

/// `--local` / `--cloud` reach every command through the one global pair.
/// A command that does not read a placement refuses it before any effect,
/// so an explicit placement is never ignored or reinterpreted.
pub(crate) fn validate_placement_scope(
    command: &Command,
    name: &str,
    placement: Option<EnvironmentPlacement>,
    member: bool,
) -> anyhow::Result<()> {
    let Some(placement) = placement else {
        return Ok(());
    };
    let flag = match placement {
        EnvironmentPlacement::Local => "--local",
        EnvironmentPlacement::Platform => "--cloud",
    };
    anyhow::ensure!(
        !member,
        "{flag} cannot be combined with --member, which names its pinned host target"
    );
    if let Command::Setup(SetupArgs {
        command: Some(setup),
        ..
    }) = command
    {
        let name = match setup {
            SetupCommand::Ssh(_) => "ssh",
            SetupCommand::Rex(_) => "rex",
        };
        anyhow::bail!("{flag} does not apply to `cw setup {name}`");
    }
    let reads = matches!(
        command,
        Command::Setup(_)
            // Which one the feedback says the sender works in.
            | Command::Feedback(_)
            | Command::Use(_)
            | Command::Credentials(_)
            | Command::Policy(_)
            | Command::Snapshot(_)
            | Command::Checkpoint(_)
            | Command::Secrets(_)
            | Command::Env(_)
            | Command::Run(_)
            | Command::Exec(_)
            | Command::Attach(_)
            | Command::Send(_)
            | Command::Wait(_)
            | Command::Shell(_)
            | Command::Vscode(_)
            | Command::Ls(_)
            | Command::Logs(_)
            | Command::Stop(_)
            | Command::Restart(_)
            | Command::Info(_)
            | Command::Export(_)
            | Command::Create(_)
            | Command::Start(_)
            | Command::Retry(_)
            | Command::Rm(_)
            | Command::Update(_)
            | Command::Cp(_)
            | Command::Ports(_)
            | Command::Runtime(_)
            | Command::Agent(_)
            | Command::Daemon(_)
            | Command::Resize(_)
            | Command::Report(_)
            | Command::Extend(_)
            | Command::Access(_)
            | Command::Share(_)
            | Command::Protect(_)
            | Command::Unprotect(_)
            | Command::CancelDelete(_)
            | Command::Prune(_)
            | Command::Nuke(_)
            | Command::RefreshSkills(_)
            // `cw --cloud ssh known-hosts`, as the `cw-cloud-*` block runs it.
            | Command::Ssh { .. }
            // --cloud: the platform's hosted Mesh; --local: the local Mesh service.
            | Command::Network { .. }
    );
    // The managed session controls and the environment a message or inbox
    // addresses exist only on Unix.
    #[cfg(unix)]
    let reads = reads
        || matches!(
            command,
            Command::Interrupt(_) | Command::Steer(_) | Command::Msg(_) | Command::Inbox(_)
        );
    anyhow::ensure!(reads, "{flag} does not apply to `cw {name}`");
    Ok(())
}
