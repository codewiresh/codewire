//! `cw info`'s text for a local VM: its resources, saved configuration,
//! network, what is wrong with it and the conversations that need attention.

use super::{NativeEnvironmentView, sources};
use crate::output::Style;

pub(super) fn format_native_environment(
    view: &NativeEnvironmentView,
    configuration: Option<&codewire_project::ProjectSpec>,
    attention: &[String],
    style: Style,
) -> String {
    let access = match (&view.access_profile, view.access_profile_revision) {
        (profile, Some(revision)) if !profile.is_empty() => {
            format!("{profile} (revision {revision})")
        }
        _ => "none".to_owned(),
    };
    let mut output = format!(
        "Environment: {}\nBackend:     {}\nState:       {}\nCPU:         {}\nMemory:      {}\nDisk:        {}\nWorkspace:   {} input(s), plan {}\nWorking dir: {}\nAccess:      {}\n",
        view.name,
        view.backend,
        view.state,
        view.cpu,
        view.memory,
        view.disk,
        view.workspace_inputs,
        view.workspace_plan,
        view.working_directory,
        access,
    );
    if let Some(configuration) = configuration {
        output.push_str(&format_native_configuration(configuration));
    }
    output.push_str(&format!(
        "Docker:      {}\n",
        view.docker_disk.as_deref().unwrap_or("disabled")
    ));
    if let Some(generation) = view.skill_snapshot_generation {
        output.push_str(&format!(
            "Skills:      {} snapshot(s), generation {}, plan {}\n",
            view.skill_count, generation, view.skill_snapshot
        ));
    }
    for port in &view.ports {
        output.push_str(&format!(
            "Port:        {} -> {}\n",
            port.listen, port.guest_port
        ));
    }
    if let Some(network) = &view.network {
        output.push_str(&format!("Network:     {network}\n"));
    }
    if let Some(network_policy) = &view.network_policy {
        output.push_str(&format!("Network policy: {network_policy}\n"));
        if view.policy_leaves_providers_to_credentials {
            output.push_str(
                "                selected model credentials still reach their providers\n",
            );
        }
    }
    output.push_str(&view.error.line());
    output.push_str(&view.error.refusals_line());
    for row in attention {
        output.push_str(&format!("Attention:   {row}\n"));
    }
    output.push_str(&format!("Generation:  {}\n", view.generation));
    output.push_str(&sources::format_source_view(
        view.source_selection.as_ref(),
        &view.error.credentials_note(style),
    ));
    output
}

/// The saved configuration a person set in codewire.yaml or on create: the
/// install command, environment variable names (never their values) and
/// agents.
fn format_native_configuration(spec: &codewire_project::ProjectSpec) -> String {
    use crate::commands::progress::terminal_text;
    let install = Some(terminal_text(&spec.install_command))
        .filter(|command| !command.is_empty())
        .unwrap_or_else(|| "none".to_owned());
    let names = spec
        .environment
        .keys()
        .map(|name| terminal_text(name))
        .collect::<Vec<_>>();
    let variables = if names.is_empty() {
        "none".to_owned()
    } else {
        names.join(", ")
    };
    let mut agents = spec
        .agents
        .tools
        .iter()
        .map(|tool| terminal_text(tool))
        .collect::<Vec<_>>()
        .join(", ");
    if agents.is_empty() {
        agents = "none".to_owned();
    }
    if spec.agents.install == Some(false) {
        agents.push_str(" (agent install off)");
    }
    format!("Install:     {install}\nEnv vars:    {variables}\nAgents:      {agents}\n")
}
