//! Disposable-database fixture for the runtime-lease owner tests of the SSH
//! proxy and daemon repair. Each test seeds its own organization and
//! environment, so the suites can share one migrated schema.

use std::future::Future;
use std::time::Duration;

use codewire_server_core::AppError;
use codewire_server_core::org_deletion::{
    OrganizationMutationLease, unresolved_organization_mutation_leases,
};
use sqlx::PgPool;
use tokio::sync::oneshot;
use uuid::Uuid;

const PROJECT_SPEC: &str = r#"{"schema_version":1,"working_directory":"/workspace"}"#;

/// One organization with a running Sandbox environment, its preset and its
/// backend row. The identifier doubles as organization, user, preset and
/// environment ID; it is also a canonical organization route slug.
pub(crate) struct LeaseFixture {
    pub(crate) pool: PgPool,
    pub(crate) id: String,
}

impl LeaseFixture {
    pub(crate) async fn seed(namespace: &str) -> Self {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("runtime lease owner tests require the disposable test database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("connect disposable database");
        let id = format!("lease-{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO users (id, email, name, email_verified) \
             VALUES ($1, $2, 'Runtime lease owner test', true)",
        )
        .bind(&id)
        .bind(format!("{id}@example.test"))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) \
             VALUES ($1, 'Runtime lease owner test', $1, $1)",
        )
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $1, $1, 'owner')",
        )
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO environment_presets (id, org_id, name, slug, project_spec) \
             VALUES ($1, $1, 'Runtime lease owner test', $1, $2::jsonb)",
        )
        .bind(&id)
        .bind(PROJECT_SPEC)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO environments \
                 (id, org_id, created_by, type, state, desired_state, preset_id, project_spec, \
                  environment_operation_generation) \
             VALUES ($1, $1, $1, 'sandbox', 'running', 'started', $1, $2::jsonb, 1)",
        )
        .bind(&id)
        .bind(PROJECT_SPEC)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO sandbox_environment_backend (environment_id, namespace, setup_complete) \
             VALUES ($1, $2, true)",
        )
        .bind(&id)
        .bind(namespace)
        .execute(&pool)
        .await
        .unwrap();
        Self { pool, id }
    }

    pub(crate) async fn cleanup(self) {
        for (table, column) in [
            ("organization_mutation_leases", "organization_id"),
            ("sandbox_environment_backend", "environment_id"),
            ("environments", "id"),
            ("environment_presets", "id"),
            ("org_members", "id"),
            ("organizations", "id"),
            ("users", "id"),
        ] {
            sqlx::query(&format!("DELETE FROM {table} WHERE {column} = $1"))
                .bind(&self.id)
                .execute(&self.pool)
                .await
                .unwrap();
        }
        self.pool.close().await;
    }

    /// No runtime lease of this organization blocks external cleanup.
    pub(crate) async fn assert_no_unresolved_leases(&self) {
        let unresolved = unresolved_organization_mutation_leases(&self.pool, &self.id)
            .await
            .unwrap();
        assert!(unresolved.is_empty(), "{unresolved:?}");
    }

    /// The single unresolved runtime lease of this organization, in `state`.
    pub(crate) async fn only_unresolved_lease(&self, state: &str) -> String {
        let unresolved = unresolved_organization_mutation_leases(&self.pool, &self.id)
            .await
            .unwrap();
        assert_eq!(unresolved.len(), 1, "{unresolved:?}");
        assert_eq!(unresolved[0].state, state);
        assert_eq!(unresolved[0].mutation_class, "environment_runtime_dispatch");
        unresolved[0].id.clone()
    }

    /// Holds this organization's row lock, which runtime lease admission
    /// takes first, so a test can act while an admission waits on it (#4523).
    /// The lock goes when the returned hold is dropped.
    pub(crate) async fn hold_admission(&self) -> HeldAdmission {
        let mut tx = self.pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM organizations WHERE id = $1 FOR UPDATE")
            .bind(&self.id)
            .execute(&mut *tx)
            .await
            .unwrap();
        let backend: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        HeldAdmission { _tx: tx, backend }
    }

    /// Waits until a lease admission is blocked on `held`'s own connection, so
    /// another session's lock wait in the same database never counts.
    pub(crate) async fn admission_waiting(&self, held: &HeldAdmission) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity \
                 WHERE $1 = ANY(pg_blocking_pids(pid)) \
                 AND query LIKE 'SELECT deletion_state FROM organizations%'",
            )
            .bind(held.backend)
            .fetch_one(&self.pool)
            .await
            .unwrap();
            if waiting > 0 {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no lease admission reached the organization lock"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Wait for the admitted operation, not its dropped caller, to settle the
    /// lease. A lease that stays active here is the stranded-barrier defect.
    pub(crate) async fn settled_lease(&self, lease_id: &str) -> OrganizationMutationLease {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let lease = sqlx::query_as::<_, OrganizationMutationLease>(
                "SELECT * FROM organization_mutation_leases WHERE id = $1",
            )
            .bind(lease_id)
            .fetch_one(&self.pool)
            .await
            .unwrap();
            if lease.state != "active" {
                return lease;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "runtime lease {lease_id} stayed active after its operation finished"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// Poll a fenced request until its operation has started after admission,
/// then drop it the way a disconnected client drops its handler future.
pub(crate) async fn drop_caller_after_operation_starts<T>(
    caller: impl Future<Output = Result<T, AppError>>,
    started: oneshot::Receiver<()>,
) {
    let mut caller = Box::pin(caller);
    tokio::select! {
        _ = &mut caller => panic!("fenced request finished before its caller was dropped"),
        started = tokio::time::timeout(Duration::from_secs(30), started) => {
            started
                .expect("fenced operation starts within the 30 s hang guard")
                .expect("fenced operation starts after lease admission");
        }
    }
    drop(caller);
}

/// The organization row lock [`LeaseFixture::hold_admission`] holds,
/// and the backend holding it.
pub(crate) struct HeldAdmission {
    _tx: sqlx::Transaction<'static, sqlx::Postgres>,
    backend: i32,
}
