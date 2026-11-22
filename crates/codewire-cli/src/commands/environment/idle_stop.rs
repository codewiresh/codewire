//! `cw update --idle-stop`'s confirmation. Moved out of `environment.rs`
//! unchanged (#3384).

use super::*;

pub(crate) fn print_env_idle_stop_status(
    environment_ref: &str,
    response: &StatusResponse,
    idle_stop_seconds: i32,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(response)?),
        OutputFormat::Text => print!(
            "{}",
            format_env_idle_stop_text(environment_ref, idle_stop_seconds)
        ),
    }
    Ok(())
}

/// The confirmation of `cw update ENV --idle-stop`.
pub(crate) fn format_env_idle_stop_text(environment_ref: &str, idle_stop_seconds: i32) -> String {
    if idle_stop_seconds == 0 {
        format!("Environment {environment_ref}: idle stop off; it runs until stopped.\n")
    } else {
        format!(
            "Environment {environment_ref}: stops, keeping its disk, after {} with no activity.\n",
            codewire_project::format_idle_stop(idle_stop_seconds)
        )
    }
}

/// What a cloud Sandbox with an idle timeout says when its server says it
/// doesn't enforce one: the timeout is kept, but it never stops for being
/// idle. A server that says nothing, being older, gets no note (#3384).
pub(crate) fn unenforced_note(environment: &Environment) -> Option<&'static str> {
    (environment.environment_type == "sandbox"
        && environment.idle_stop_seconds > 0
        && environment.idle_stop_enforced == Some(false))
    .then_some("This server doesn't stop idle Sandboxes: the timeout is kept, but not enforced.")
}

/// After `cw update --idle-stop`: the note, read from the environment as it
/// now is; a read that fails only leaves it out.
pub(super) async fn note_after_update(
    client: &EnvironmentClient,
    org_id: &str,
    environment_id: &str,
    output: OutputFormat,
) {
    if let (OutputFormat::Text, Ok(current)) =
        (output, client.get_environment(org_id, environment_id).await)
        && let Some(note) = unenforced_note(&current)
    {
        println!("{note}");
    }
}

/// After a cloud create: the note, for text output.
pub(super) fn note_after_create(environment: &Environment, output: OutputFormat) {
    if let (OutputFormat::Text, Some(note)) = (output, unenforced_note(environment)) {
        println!("{note}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only a cloud Sandbox with a timeout its server doesn't enforce gets
    /// the note (#3384).
    #[test]
    fn the_note_is_only_for_a_timeout_the_server_does_not_enforce() {
        let sandbox = |seconds, enforced: Option<bool>| Environment {
            environment_type: "sandbox".into(),
            idle_stop_seconds: seconds,
            idle_stop_enforced: enforced,
            ..Default::default()
        };
        assert_eq!(
            unenforced_note(&sandbox(1800, Some(false))),
            Some("This server doesn't stop idle Sandboxes: the timeout is kept, but not enforced.")
        );
        assert_eq!(unenforced_note(&sandbox(1800, Some(true))), None);
        // An older server says nothing: no note.
        assert_eq!(unenforced_note(&sandbox(1800, None)), None);
        assert_eq!(unenforced_note(&sandbox(0, Some(false))), None);
        let vm = Environment {
            environment_type: "vm".into(),
            ..sandbox(1800, Some(false))
        };
        assert_eq!(unenforced_note(&vm), None);
    }
}
