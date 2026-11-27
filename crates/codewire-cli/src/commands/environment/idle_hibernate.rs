//! `cw update --idle-hibernate` confirmation, `cw info` IdleHibernate and
//! hibernate/fallback notices (#6647, `docs/dev/SANDBOX-SLEEP.md`).

use super::*;

pub(super) fn print_status(
    environment_ref: &str,
    response: &StatusResponse,
    idle_hibernate_seconds: i32,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(response)?),
        OutputFormat::Text => print!(
            "{}",
            format_env_idle_hibernate_text(environment_ref, idle_hibernate_seconds)
        ),
    }
    Ok(())
}

/// The confirmation of `cw update ENV --idle-hibernate`.
pub(crate) fn format_env_idle_hibernate_text(
    environment_ref: &str,
    idle_hibernate_seconds: i32,
) -> String {
    if idle_hibernate_seconds == 0 {
        format!(
            "Environment {environment_ref}: idle hibernate off; it never hibernates for being idle.\n"
        )
    } else {
        format!(
            "Environment {environment_ref}: hibernates after {} with no activity; start or access restores it.\n",
            codewire_project::format_idle_hibernate(idle_hibernate_seconds)
        )
    }
}

/// `cw info`'s IdleHibernate line, for a cloud sandbox.
pub(super) fn info_line(environment: &Environment) -> String {
    format!(
        "{:<14} {}\n",
        "IdleHibernate:",
        codewire_project::format_idle_hibernate(environment.idle_hibernate_seconds)
    )
}

/// Human-readable notice for a hibernated Sandbox, naming why it hibernated
/// and how to wake it.
pub(crate) fn hibernated_notice(environment: &Environment) -> Option<String> {
    if !environment.hibernated() {
        return None;
    }
    let name = environment
        .name
        .as_deref()
        .and_then(trimmed_str)
        .unwrap_or(&environment.id);
    let reason = match environment.hibernate_reason.as_deref() {
        Some("idle") if environment.idle_hibernate_seconds > 0 => format!(
            "Hibernated after {} idle.",
            codewire_project::idle_stop_words(environment.idle_hibernate_seconds)
        ),
        Some("idle") => "Hibernated after being idle.".to_owned(),
        _ => "Hibernated to its encrypted volume.".to_owned(),
    };
    Some(format!(
        "{reason} Processes and files are saved; run `cw start {name}` or connect to restore it."
    ))
}

/// Human-readable notice when a start could not restore from hibernate and
/// cold-booted cleanly from disks (processes lost, files kept).
pub(crate) fn fallback_notice(reason: &str) -> String {
    let trimmed = reason.trim();
    let detail = match trimmed {
        "runtime-image-expired" => {
            "its runtime image is past the 30-day restore window (runtime-image-expired)".to_owned()
        }
        "image-disk-mismatch" => {
            "its workspace image disk was rebuilt (image-disk-mismatch)".to_owned()
        }
        "vmm-digest-mismatch" => "its VMM binary changed (vmm-digest-mismatch)".to_owned(),
        "runtime-image-digest-mismatch" => {
            "its runtime image digest changed (runtime-image-digest-mismatch)".to_owned()
        }
        "vm-config-mismatch" => {
            "its VM configuration changed since hibernate (vm-config-mismatch)".to_owned()
        }
        "generation-mismatch" | "generation-consumed" => {
            format!("its restore generation was already consumed ({trimmed})")
        }
        "damaged-memory-file" => {
            "its hibernate memory image was missing or damaged (damaged-memory-file)".to_owned()
        }
        "rebind-failed" => {
            "the restored daemon could not complete its new Pod bind (rebind-failed)".to_owned()
        }
        other => format!("restore failed ({other})"),
    };
    format!(
        "Could not restore from hibernate because {detail}; booted cleanly from disks — running processes were lost while files were kept."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_and_update_formatting_cover_hibernate_and_fallback() {
        assert!(format_env_idle_hibernate_text("dev", 0).contains("idle hibernate off"));
        assert!(format_env_idle_hibernate_text("dev", 21600).contains("hibernates after 6h"));
        let mut env = Environment {
            id: "env-1".into(),
            name: Some("dev".into()),
            environment_type: "sandbox".into(),
            state: "stopped".into(),
            idle_hibernate_seconds: 21600,
            hibernated_at: Some("2026-11-27T12:00:00Z".into()),
            hibernate_reason: Some("idle".into()),
            ..Environment::default()
        };
        assert_eq!(info_line(&env), "IdleHibernate: 6h\n");
        let notice = hibernated_notice(&env).expect("hibernated notice");
        assert!(notice.contains("6 hours idle"));
        assert!(notice.contains("cw start dev"));
        let info = super::super::info::format_env_info_text(&env);
        assert!(info.contains("State:         hibernated\n"));
        assert!(info.contains("IdleHibernate: 6h\n"));
        assert!(info.contains("HibernatedAt:  2026-11-27T12:00:00Z\n"));
        assert!(info.contains("HibernateReason: idle\n"));

        env.state = "running".into();
        env.hibernated_at = None;
        env.hibernate_reason = None;
        env.hibernate_fallback_reason = Some("image-disk-mismatch".into());
        let fallback_info = super::super::info::format_env_info_text(&env);
        assert!(fallback_info.contains("image-disk-mismatch"));
        assert!(fallback_info.contains("running processes were lost while files were kept"));
        assert!(fallback_notice("runtime-image-expired").contains("30-day restore window"));
        assert!(fallback_notice("damaged-memory-file").contains("missing or damaged"));
        assert!(fallback_notice("vmm-digest-mismatch").contains("VMM binary changed"));
        assert!(fallback_notice("runtime-image-digest-mismatch").contains("runtime image digest"));
        assert!(fallback_notice("vm-config-mismatch").contains("VM configuration changed"));
    }
}
