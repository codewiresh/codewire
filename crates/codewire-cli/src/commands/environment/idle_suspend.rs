//! `cw update --idle-suspend`'s confirmation and `cw info`'s IdleSuspend
//! line (#5529).

use super::*;

pub(super) fn print_status(
    environment_ref: &str,
    response: &StatusResponse,
    idle_suspend_seconds: i32,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(response)?),
        OutputFormat::Text => print!(
            "{}",
            format_env_idle_suspend_text(environment_ref, idle_suspend_seconds)
        ),
    }
    Ok(())
}

/// The confirmation of `cw update ENV --idle-suspend`.
pub(crate) fn format_env_idle_suspend_text(
    environment_ref: &str,
    idle_suspend_seconds: i32,
) -> String {
    if idle_suspend_seconds == 0 {
        format!(
            "Environment {environment_ref}: idle suspend off; it never pauses for being idle.\n"
        )
    } else {
        format!(
            "Environment {environment_ref}: pauses after {} with no activity; any use wakes it.\n",
            codewire_project::format_idle_suspend(idle_suspend_seconds)
        )
    }
}

/// `cw info`'s IdleSuspend line, for a cloud sandbox.
pub(super) fn info_line(environment: &Environment) -> String {
    format!(
        "{:<14} {}\n",
        "IdleSuspend:",
        codewire_project::format_idle_suspend(environment.idle_suspend_seconds)
    )
}

/// Whether it runs and isn't suspended: reading its daemon then wakes
/// nothing.
pub(super) fn awake(environment: &Environment) -> bool {
    environment.state == "running" && environment.suspended_at.is_none()
}
