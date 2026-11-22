//! An [`ApiState`] for tests: every dependency is local or offline, and the
//! database is the pool the test passes.

use std::sync::Arc;
use std::time::Duration;

use codewire_protected_store::secret_envelope::TestKekProvider;
use codewire_server_core::auth::AuthState;
use sqlx::PgPool;

use super::ApiState;

pub(crate) async fn offline(pool: PgPool) -> ApiState {
    let session_secret = "synthetic-no-store-session-secret".to_string();
    ApiState {
        credit_enforcement: Default::default(),
        idle_stop: Default::default(),
        pool: pool.clone(),
        preview_base_domain: "preview.test".to_string(),
        frontend_url: "https://dashboard.example.test".to_string(),
        http_client: reqwest::Client::new(),
        preview_upstream: super::preview::PreviewUpstream::new(
            pool.clone(),
            None,
            session_secret.clone(),
            Default::default(),
        ),
        temporal_trigger: Arc::new(crate::temporal::tests::offline_trigger().await),
        secrets: Arc::new(crate::worker::secrets::SecretStore::new_for_test(
            pool.clone(),
            Arc::new(TestKekProvider),
        )),
        auth: AuthState { pool: pool.clone() },
        kube: None,
        runtime: None,
        environment_daemon_endpoints: Default::default(),
        session_secret,
        terminal_ticket_replays: Arc::default(),
        org_slugs: Arc::new(super::preview::OrgSlugCache::new(Duration::from_secs(5))),
        sandbox_cfg: Default::default(),
        confidential_storage_flags: crate::confidential_storage::FeatureFlags { enabled: false },
        network_policy_flags: Default::default(),
        environment_logs: super::log_notifications::EnvironmentLogNotifications::new(1),
        live: super::live::LiveNotifications::new(super::live::MAX_WATCHES_PER_ACCOUNT),
        drain: Default::default(),
        cw_runtime_staging: super::cw_runtime::staging::Staging::removed(),
        revocation: codewire_server_core::revocation::Fence::new(),
    }
}
