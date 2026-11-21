//! The line a create, start or update prints for each credential in the
//! environment's profile that its agents can't use, for a local VM and a
//! hosted Sandbox alike (#5545, #5594).

use super::CredentialView;
use crate::commands::platform_commands::shell_word;
use crate::commands::progress::terminal_text;

/// `Claude (sign-in) 'walk' in profile work is revoked; agents in this VM
/// can't use it. Reconnect with ...`, or nothing for a credential its agents
/// can use. A sign-in is reconnected under its own name, and anything else is
/// replaced in the profile.
pub(in crate::commands) fn withheld_line(
    credential: &CredentialView,
    profile: &str,
    slot: &str,
    now_unix: u64,
) -> Option<String> {
    let state = match credential.status_at(now_unix) {
        "revoked" => "is revoked",
        "expired" => "has expired",
        "refresh_failed" => "needs reconnecting",
        _ => return None,
    };
    let (placement, agents) = match credential.placement {
        "cloud" => ("--cloud", "agents in this Sandbox"),
        _ => ("--local", "agents in this VM"),
    };
    let name = terminal_text(&shell_word(&credential.name));
    let profile = terminal_text(&shell_word(profile));
    let connect = |provider: &str| {
        format!("Reconnect with `cw credentials {placement} connect {provider} --name {name}`.")
    };
    let fix = match (credential.provider.as_str(), credential.authentication_kind) {
        ("anthropic", "claude_sign_in") => connect("claude"),
        ("openai", "oauth") => connect("codex"),
        ("github", _) => connect("github"),
        _ => format!(
            "Replace it with `cw credentials {placement} --profile {profile} set {slot} NAME`."
        ),
    };
    let kind = credential.kind_label();
    let display = terminal_text(&credential.name);
    Some(format!(
        "{kind} '{display}' in profile {profile} {state}; {agents} can't use it. {fix}"
    ))
}
