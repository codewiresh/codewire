//! A suspended Sandbox's daemon status, answered from its mark (#5529,
//! `docs/dev/IDLE-STOP.md`, "Calls that must not wake a suspended
//! Sandbox"): asking the daemon would wake the VM, and `cw ls` asks this of
//! every Sandbox it lists.

use super::{EnvironmentDaemonStatus, v1};

/// What a suspended Sandbox's daemon status says.
pub(crate) const SUSPENDED_MESSAGE: &str = "suspended; any use wakes it";

/// The status of `environment_id`'s daemon when its Sandbox is suspended,
/// or `None` when it isn't and the daemon should be asked.
pub(super) async fn status(
    pool: &sqlx::PgPool,
    environment_id: &str,
    pod_name: &str,
) -> Result<Option<EnvironmentDaemonStatus>, sqlx::Error> {
    let suspended: Option<bool> =
        sqlx::query_scalar("SELECT suspended_at IS NOT NULL FROM environments WHERE id = $1")
            .bind(environment_id)
            .fetch_optional(pool)
            .await?;
    Ok(suspended.unwrap_or(false).then(|| marked(pod_name)))
}

fn marked(pod_name: &str) -> EnvironmentDaemonStatus {
    EnvironmentDaemonStatus {
        state: v1::DaemonState::Ready,
        protocol_version: 0,
        minimum_protocol_version: 0,
        daemon_version: String::new(),
        capabilities: Vec::new(),
        message: SUSPENDED_MESSAGE.to_owned(),
        diagnostics: Vec::new(),
        pod_name: pod_name.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_suspended_daemon_is_ready_and_says_so_without_any_daemon_fields() {
        let status = marked("workspace-a");
        assert_eq!(status.state, v1::DaemonState::Ready);
        assert_eq!(status.message, "suspended; any use wakes it");
        assert_eq!(status.pod_name, "workspace-a");
        assert!(status.capabilities.is_empty() && status.daemon_version.is_empty());
    }
}
