//! Environment lifecycle job handlers (#36 Stage D3).
//!
//! These are the activity bodies the Temporal worker dispatches
//! (`temporal.rs`). They were originally the JetStream consumer
//! handlers; the NATS consumer plane was retired in D3 (the owner
//! decision of 2026-06-12) — Temporal is now the only trigger path and
//! per-environment serialization comes from one workflow per
//! environment id, so the old `dispatcher.go`-style consume loop and
//! the `TENANT_LOCKS` distributed lock are gone.
//!
//! The handlers stay idempotent and journal-checkpointed: a Temporal
//! retry replays the same resumable logic the JetStream redelivery
//! exercised before the cutover.

pub mod activity_authority;
pub mod agents;
pub mod billing_sessions;
pub mod cloudflare;
pub mod create;
pub mod env_data;
pub mod env_log;
#[cfg(feature = "kind-e2e")]
pub mod fencing_evidence;
pub mod gatewayauth;
pub mod image_cache;
pub mod lifecycle;
pub mod loops;
pub mod organization_deletion;
pub mod port_dns;
pub mod postgres_secrets;
pub mod resize;
pub mod scripts;
pub mod secrets;
pub mod setup;
pub mod setup_lease;
mod start_timing;
pub mod tenant_secret_teardown;
pub(crate) mod workspace_binding;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// Internal shared command shape the handlers
/// consume (built by the Temporal activities from `EnvironmentCommand`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JobPayload {
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub resource_id: String,
    #[serde(default)]
    pub environment_id: String,
    #[serde(default)]
    pub resource_type: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub admin_email: String,
    #[serde(default)]
    pub force: bool,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub port_id: String,
}

/// Shared context for job handlers (the Rust analog of WorkerContext).
pub struct WorkerContext {
    pub pool: PgPool,
    pub cloudflare: Option<cloudflare::CloudflareClient>,
    pub preview_base_domain: String,
    /// Ambient kube client; None mirrors a nil sandbox backend in Go
    /// (health checks pass, workspace execs fail).
    pub kube: Option<kube::Client>,
    /// Tenant secret store shared by the API and every worker activity.
    pub secrets: std::sync::Arc<secrets::SecretStore>,
    /// Sandbox/create config slice (env-derived, Go config.Config names).
    pub sandbox_cfg: create::SandboxWorkerCfg,
    /// Platform-only recovery/KBS lifecycle. Never falls back to tenant
    /// secrets or PostgreSQL key storage.
    pub confidential_storage:
        Option<std::sync::Arc<crate::confidential_storage::ConfidentialStorageManager>>,
    /// Lifecycle trigger: the reconciler SignalWithStarts the
    /// environment workflow (D3 — Temporal is the only trigger path).
    pub temporal_trigger: std::sync::Arc<crate::temporal::TemporalTrigger>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_payload_round_trips() {
        let json = r#"{"tenant_id":"t1","environment_id":"env1","action":"port.dns.create","port_id":"p1","nonce":"n1","force":true}"#;
        let p: JobPayload = serde_json::from_str(json).unwrap();
        assert_eq!(p.tenant_id, "t1");
        assert_eq!(p.environment_id, "env1");
        assert_eq!(p.action, "port.dns.create");
        assert_eq!(p.port_id, "p1");
        assert!(p.force);
        // Absent optional fields default cleanly.
        let p: JobPayload = serde_json::from_str(r#"{"tenant_id":"t","action":"a"}"#).unwrap();
        assert_eq!(p.environment_id, "");
    }
}
