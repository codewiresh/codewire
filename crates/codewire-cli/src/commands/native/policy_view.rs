//! A local VM's network policy selection in words: its `Network policy:`
//! line, and what `cw update ENV --policy` prints. Moved out of
//! `native.rs` (#3997).

use super::*;

/// Whether `policy` doesn't allow the model providers by rule: every policy
/// but the built-ins `open` and `web`, which allow every public destination on 443.
/// By reference, so a stored policy named `web` (from before #3997) is not
/// taken for the built-in.
fn leaves_providers_to_credentials(policy: Option<&v1::EnvironmentNetworkPolicy>) -> bool {
    policy.is_some_and(|policy| !matches!(policy.reference.as_str(), "open" | "web"))
}

/// What `cw info` says under a local VM's `Network policy:` line; never in
/// JSON.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum PolicyNote {
    #[default]
    None,
    /// The policy doesn't allow the model providers by rule, so a selected
    /// model credential is the one thing still reaching out (#5215). Whether
    /// the profile holds one isn't known here, so it shows for every policy
    /// but `open` and `web`.
    ProvidersStillReached,
    /// `open`, which allows every public TCP port since #3997.
    OpenWidened(&'static str),
}

impl PolicyNote {
    pub(super) fn of(policy: Option<&v1::EnvironmentNetworkPolicy>) -> Self {
        if let Some(widened) = policy.and_then(|policy| {
            crate::commands::environment::open_widening_notice(&policy.reference)
        }) {
            return Self::OpenWidened(widened);
        }
        if leaves_providers_to_credentials(policy) {
            return Self::ProvidersStillReached;
        }
        Self::None
    }

    /// The line under `Network policy:`, indented to its value, if any.
    pub(super) fn line(self) -> Option<String> {
        let note = match self {
            Self::None => return None,
            Self::ProvidersStillReached => "selected model credentials still reach their providers",
            Self::OpenWidened(widened) => widened,
        };
        Some(format!("{:16}{note}\n", ""))
    }
}

/// `work · rev 3`, then what a running VM enforces when it could not take
/// the selection (#2537): `work · rev 4 · enforces rev 3 until restarted`.
pub(crate) fn network_policy_text(policy: &v1::EnvironmentNetworkPolicy) -> String {
    let selected = if policy.revision > 0 {
        format!("{} · rev {}", policy.name, policy.revision)
    } else {
        policy.name.clone()
    };
    if !policy.restart_required {
        return selected;
    }
    let enforced = if policy.enforced_revision > 0 {
        format!("rev {}", policy.enforced_revision)
    } else {
        "an earlier selection".to_owned()
    };
    format!("{selected} · enforces {enforced} until restarted")
}

/// What `cw update ENV --policy` changed.
pub(crate) fn print_network_policy_update(
    environment: &v1::Environment,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let policy = environment
        .network_policy
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("the supervisor did not report the network policy"))?;
    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "environment": environment.name,
                "network_policy": {
                    "reference": policy.reference,
                    "name": policy.name,
                    "revision": policy.revision,
                    "digest": policy.digest,
                    "enforced_revision": policy.enforced_revision,
                    "enforced_digest": policy.enforced_digest,
                    "restart_required": policy.restart_required,
                },
            }))?
        ),
        OutputFormat::Text => {
            println!(
                "Network policy for {}: {}",
                environment.name,
                network_policy_text(policy)
            );
            if policy.restart_required {
                println!(
                    "Its running VM could not take it, so it applies at the next start: `cw restart {}`",
                    environment.name
                );
            }
            if let PolicyNote::OpenWidened(widened) = PolicyNote::of(Some(policy)) {
                let style =
                    crate::output::Capabilities::from_process(crate::output::OutputMode::Text)
                        .stderr_style();
                eprintln!(
                    "{} {widened}",
                    style.status(crate::output::Status::Attention)
                );
            }
        }
    }
    Ok(())
}
