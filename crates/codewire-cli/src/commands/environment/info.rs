//! `cw info`'s text and the labels it and the lists share.

use super::*;

mod restart;
pub(crate) use restart::UnplannedRestart;

/// `cw info`'s Type line, and the Host line of an environment on a host.
fn type_lines(environment: &Environment) -> String {
    let mut lines = format!("{:<14} {}\n", "Type:", env_type_label(environment));
    if let Some(host) = &environment.host {
        lines.push_str(&format!(
            "{:<14} {} ({})\n",
            "Host:",
            super::progress::terminal_text(&host.name),
            host.id
        ));
    }
    lines
}

pub(crate) fn format_env_info_text(environment: &Environment) -> String {
    format_env_info_text_at(environment, chrono::Utc::now(), &chrono::Local)
}

/// [`format_env_info_text`] with the time an unplanned restart's age is
/// measured from, and the zone its time is shown in.
pub(crate) fn format_env_info_text_at<Tz: chrono::TimeZone>(
    environment: &Environment,
    now: chrono::DateTime<chrono::Utc>,
    zone: &Tz,
) -> String
where
    Tz::Offset: std::fmt::Display,
{
    let mut output = String::new();
    output.push_str(&format!("{:<14} {}\n", "ID:", environment.id));
    output.push_str(&format!(
        "{:<14} {}\n",
        "Name:",
        environment
            .name
            .as_deref()
            .and_then(trimmed_str)
            .unwrap_or("--")
    ));
    output.push_str(&type_lines(environment));
    output.push_str(&format!(
        "{:<14} {}\n",
        "State:",
        env_state_label(environment)
    ));
    output.push_str(&format!(
        "{:<14} {}\n",
        "DesiredState:",
        trimmed_str(&environment.desired_state).unwrap_or("--")
    ));
    output.push_str(&format!(
        "{:<14} {}\n",
        "PresetID:",
        trimmed_str(&environment.preset_id).unwrap_or("--")
    ));
    if let Some(network) = environment.network.as_deref().and_then(trimmed_str) {
        output.push_str(&format!("{:<14} {}\n", "Network:", network));
    }
    if let Some(policy) = &environment.network_policy {
        output.push_str(&format!("{:<14} {}\n", "NetworkPolicy:", policy.summary()));
        // An explicit `open` allows every TCP port since #3997.
        if let Some(widened) = super::policy_notice::open_widening_notice(&policy.reference) {
            output.push_str(&format!("{:<14} {widened}\n", "Notice:"));
        }
    }
    if let Some(egress) = egress_label(environment) {
        output.push_str(&format!("{:<14} {egress}\n", "Egress:"));
    }
    // Not enforced, or nothing confirms it: say so in a sentence (#3997).
    if let Some(notice) = environment
        .network_policy
        .as_ref()
        .filter(|policy| matches!(policy.enforcement.as_str(), "not_enforced" | "unconfirmed"))
        .and_then(super::policy_notice::enforcement_notice)
    {
        output.push_str(&format!("{:<14} {notice}\n", "Notice:"));
    }
    output.push_str(&format!("CPU:           {}m\n", environment.cpu_millicores));
    output.push_str(&format!(
        "Isolation:     {}\n",
        trimmed_str(&environment.isolation_tier).unwrap_or("standard")
    ));
    output.push_str(&format!("Memory:        {}MB\n", environment.memory_mb));
    output.push_str(&format!("Disk:          {}GB\n", environment.disk_gb));
    output.push_str(&format!(
        "CreatedBy:     {}\n",
        trimmed_str(&environment.created_by).unwrap_or("--")
    ));
    output.push_str(&format!(
        "CreatedAt:     {}\n",
        trimmed_str(&environment.created_at).unwrap_or("--")
    ));
    if let Some(started_at) = environment.started_at.as_deref().and_then(trimmed_str) {
        output.push_str(&format!("StartedAt:     {started_at}\n"));
    }
    if let Some(restarted) = restart::info_value(environment, now, zone) {
        output.push_str(&format!("Restarted:     {restarted}\n"));
    }
    if let Some(stopped_at) = environment.stopped_at.as_deref().and_then(trimmed_str) {
        output.push_str(&format!("StoppedAt:     {stopped_at}\n"));
    }
    if let Some(stop_reason) = environment.stop_reason.as_deref() {
        output.push_str(&format!("StopReason:    {stop_reason}\n"));
    }
    if environment.stop_reason.as_deref() == Some("idle") {
        let name = environment
            .name
            .as_deref()
            .and_then(trimmed_str)
            .unwrap_or(&environment.id);
        output.push_str(&format!(
            "Notice:        {}\n",
            codewire_project::idle_stop_notice(name, environment.idle_stop_seconds)
        ));
    }
    // Only a cloud sandbox stops itself for being idle (#3384).
    if environment.environment_type == "sandbox" {
        let unenforced = super::idle_stop::unenforced_note(environment).is_some();
        output.push_str(&format!(
            "IdleStop:      {}{}\n",
            codewire_project::format_idle_stop(environment.idle_stop_seconds),
            if unenforced {
                " (not enforced on this server)"
            } else {
                ""
            }
        ));
        output.push_str(&super::idle_suspend::info_line(environment));
    }
    if let Some(shutdown_at) = environment.shutdown_at.as_deref().and_then(trimmed_str) {
        output.push_str(&format!("ShutdownAt:    {shutdown_at}\n"));
    }
    if let Some(ttl_seconds) = environment.ttl_seconds {
        output.push_str(&format!("TTL:           {ttl_seconds}s\n"));
    }
    if let Some(error_reason) = environment.error_reason.as_deref().and_then(trimmed_str) {
        // A runtime being replaced, or running again after a failure, is a
        // notice, not a current fault.
        let label = if matches!(
            environment.error_code.as_deref(),
            Some("sandbox_replacing" | "sandbox_restarted")
        ) {
            "Notice:        "
        } else {
            "ErrorReason:   "
        };
        output.push_str(&format!("{label}{error_reason}\n"));
    }
    output.push_str(&lifecycle::recoverable_line(environment));
    output.push_str(&format!(
        "TotalRunning:  {}s\n",
        environment.total_running_seconds
    ));
    if environment.protected {
        output.push_str(&format!("{:<14} yes\n", "Protected:"));
    }
    if let Some(deleting_at) = environment
        .deletion_grace_until
        .as_deref()
        .and_then(trimmed_str)
    {
        output.push_str(&format!("{:<14} {}\n", "DeletingAt:", deleting_at));
    }
    output
}

pub(crate) fn env_type_label(environment: &Environment) -> &str {
    trimmed_str(&environment.environment_type).unwrap_or("--")
}

pub(crate) fn env_state_label(environment: &Environment) -> &str {
    if environment
        .deletion_grace_until
        .as_deref()
        .and_then(trimmed_str)
        .is_some()
        && !matches!(environment.state.as_str(), "destroyed" | "destroying")
    {
        return "deleting";
    }
    if environment.failed_create() {
        return "failed";
    }
    if environment.suspended() {
        return "suspended";
    }
    trimmed_str(&environment.state).unwrap_or("--")
}

/// The hosted egress status in words; the codes are under `--output json`.
pub(crate) fn egress_label(environment: &Environment) -> Option<String> {
    let label = match environment.egress_enforcement.as_deref()? {
        "not_enforced" => "not enforced".to_owned(),
        "unconfirmed" => "unconfirmed".to_owned(),
        "enforced" => "enforced".to_owned(),
        "enforcing" => "applying the selected policy".to_owned(),
        "failed_closed" => match environment.egress_failure.as_deref() {
            Some("self_check_failed") => "blocked: its egress self-check failed".to_owned(),
            Some("policy_digest_mismatch") => {
                "blocked: its policy could not be confirmed".to_owned()
            }
            Some("lockdown_not_applied") => {
                "blocked: the platform's egress lockdown is not in place".to_owned()
            }
            Some(code) => format!("blocked ({code})"),
            None => "blocked".to_owned(),
        },
        other => other.to_owned(),
    };
    Some(label)
}

pub(crate) fn env_created_label(environment: &Environment) -> &str {
    trimmed_str(&environment.created_at).unwrap_or("--")
}
