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
pub mod confidential_slots;
pub mod create;
pub mod credential_relay;
pub mod credit_stop;
pub mod env_data;
pub mod env_log;
pub mod environment_auth;
#[cfg(feature = "kind-e2e")]
pub mod fencing_evidence;
pub mod image_cache;
pub mod lifecycle;
pub mod loops;
pub mod organization_deletion;
pub mod port_dns;
pub mod postgres_secrets;
pub mod resize;
#[cfg(test)]
mod sandbox_stopped_database_tests;
pub mod scripts;
pub mod secret_readiness;
pub mod secrets;
pub mod setup;
pub mod setup_lease;
pub mod snapshots;
mod start_timing;
pub mod tenant_secret_teardown;
pub mod unverified_purge;
pub mod warm_pool;
pub mod workspace_binding;

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
    /// The environment runtime; present exactly when `kube` is (#3628).
    pub runtime: Option<std::sync::Arc<dyn crate::runtime::RuntimeDriver>>,
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
    /// Whether this deployment stops sandboxes that ran out of credit.
    pub credit_enforcement: codewire_server_core::credit_enforcement::CreditEnforcement,
    /// What the purge of unverified email sign-ups does (#4541).
    pub unverified_signup_purge: unverified_purge::UnverifiedSignupPurge,
}

impl WorkerContext {
    /// The environment runtime, or the error a worker reports without one.
    fn require_runtime(&self) -> anyhow::Result<&dyn crate::runtime::RuntimeDriver> {
        self.runtime
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("sandbox backend is not configured"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The size of the future `f` returns, read from its type alone.
    fn future_size<F, Fut>(_: &F) -> usize
    where
        Fut: std::future::Future,
        F: FnOnce() -> Fut,
    {
        std::mem::size_of::<Fut>()
    }

    /// Activity futures live inline in the Temporal activity's own future and
    /// are moved before they are pinned. One that grows by an inline state
    /// machine overflows the worker thread's stack in an unoptimised build, so
    /// a large rarely-taken branch is boxed instead. Each bound leaves room
    /// for ordinary growth; reaching one means boxing, not raising it.
    #[test]
    fn activity_futures_stay_small_enough_to_move_on_the_worker_stack() {
        const BOUND: usize = 128 * 1024;
        fn never<T>() -> T {
            unreachable!("only the type is measured")
        }
        let sizes = [
            (
                "setup",
                future_size(&|| {
                    setup::handle_environment_setup(never(), never(), never(), never(), never())
                }),
            ),
            (
                "post-start configuration",
                future_size(&|| {
                    setup::handle_post_start_configuration(
                        never(),
                        never(),
                        never(),
                        never(),
                        never(),
                    )
                }),
            ),
            (
                "start",
                future_size(&|| {
                    lifecycle::handle_environment_start(never(), never(), never(), never(), never())
                }),
            ),
            (
                "create",
                future_size(&|| {
                    create::handle_environment_create_without_setup_publish(
                        never(),
                        never(),
                        never(),
                    )
                }),
            ),
            (
                "stop",
                future_size(&|| lifecycle::handle_environment_stop(never(), never(), never())),
            ),
            (
                "destroy",
                future_size(&|| lifecycle::handle_environment_destroy(never(), never(), never())),
            ),
            (
                "resize",
                future_size(&|| resize::run_environment_resize(never(), never(), never(), never())),
            ),
        ];
        for (activity, size) in sizes {
            eprintln!("{activity} activity future: {size} bytes");
            assert!(
                size <= BOUND,
                "{activity} activity future is {size} bytes, over {BOUND}"
            );
        }
    }

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
