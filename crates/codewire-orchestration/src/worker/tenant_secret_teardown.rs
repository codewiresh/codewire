//! Dark tenant-secret phase for durable organization deletion.
//!
//! The phase waits for pre-fence provider mutations to reach their bounded
//! recovery boundary, re-enumerates both database-discovered and
//! provider-discovered project paths, removes them idempotently, and resolves
//! ambiguity only after the complete namespace is absent. Discovery rows stay
//! in Postgres for the WI-5 atomic finalizer.

use std::collections::BTreeSet;

use codewire_server_core::AppError;
use codewire_server_core::org_deletion::{
    mark_organization_mutation_resolution_required, resolve_organization_mutation_lease,
};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};

use super::secrets::SecretStore;

const TENANT_SECRET_LEASE_DEADLINE_CODE: &str = "tenant_secret_provider_deadline_elapsed";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationTenantSecretTeardownInput {
    pub operation_id: String,
    pub organization_id: String,
    pub generation: i64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationTenantSecretTeardownResult {
    pub state: String,
    pub project_path_count: u32,
}

#[derive(Debug, FromRow)]
struct TenantSecretLease {
    id: String,
    state: String,
    deadline_elapsed: bool,
}

/// Execute or resume one generation's tenant-secret phase.
pub async fn teardown_organization_tenant_secrets(
    pool: &PgPool,
    store: &SecretStore,
    input: &OrganizationTenantSecretTeardownInput,
) -> Result<OrganizationTenantSecretTeardownResult, AppError> {
    require_current_generation(pool, input).await?;
    let leases = prepare_tenant_secret_leases(pool, input).await?;

    let project_parent = format!("/projects/{}", input.organization_id);
    let mut project_ids: BTreeSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT id FROM secret_projects WHERE org_id = $1 ORDER BY id",
    )
    .bind(&input.organization_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)?
    .into_iter()
    .collect();
    project_ids.extend(list_folders(store, &project_parent).await?);
    if project_ids.iter().any(|project_id| {
        project_id.is_empty() || project_id == "." || project_id == ".." || project_id.contains('/')
    }) {
        return Err(AppError::InternalMsg(
            "tenant secret provider returned an invalid project folder".into(),
        ));
    }

    delete_path(store, &format!("/org-secrets/{}", input.organization_id)).await?;
    for project_id in &project_ids {
        delete_path(store, &format!("{project_parent}/{project_id}")).await?;
    }

    let remaining_projects = list_folders(store, &project_parent).await?;
    if !remaining_projects.is_empty() {
        return Err(AppError::ServiceUnavailable(
            "tenant secret project re-enumeration is not empty".into(),
        ));
    }
    delete_path(store, &project_parent).await?;

    let database_project_ids: BTreeSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT id FROM secret_projects WHERE org_id = $1 ORDER BY id",
    )
    .bind(&input.organization_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)?
    .into_iter()
    .collect();
    if !database_project_ids.is_subset(&project_ids) {
        return Err(AppError::Conflict(
            "tenant secret discovery rows changed during re-enumeration".into(),
        ));
    }

    for lease in leases {
        resolve_organization_mutation_lease(pool, &lease.id).await?;
    }
    Ok(OrganizationTenantSecretTeardownResult {
        state: "completed".into(),
        project_path_count: project_ids.len().try_into().unwrap_or(u32::MAX),
    })
}

async fn require_current_generation(
    pool: &PgPool,
    input: &OrganizationTenantSecretTeardownInput,
) -> Result<(), AppError> {
    let current: Option<(String, i64, String, String)> = sqlx::query_as(
        r#"SELECT org.deletion_operation_id, org.deletion_generation,
                  org.deletion_state, operation.state
           FROM organizations org
           JOIN organization_deletion_operations operation
             ON operation.id = org.deletion_operation_id
           WHERE org.id = $1 AND operation.id = $2"#,
    )
    .bind(&input.organization_id)
    .bind(&input.operation_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)?;
    let Some((operation_id, generation, deletion_state, operation_state)) = current else {
        return Err(AppError::NotFound(
            "organization deletion generation not found".into(),
        ));
    };
    if operation_id != input.operation_id
        || generation != input.generation
        || deletion_state != "deleting"
        || operation_state != "started"
    {
        return Err(AppError::Conflict(
            "organization deletion generation is no longer current".into(),
        ));
    }
    Ok(())
}

async fn prepare_tenant_secret_leases(
    pool: &PgPool,
    input: &OrganizationTenantSecretTeardownInput,
) -> Result<Vec<TenantSecretLease>, AppError> {
    let leases = sqlx::query_as::<_, TenantSecretLease>(
        r#"SELECT id, state, deadline_at <= NOW() AS deadline_elapsed
           FROM organization_mutation_leases
           WHERE organization_id = $1
             AND mutation_class = 'tenant_secret_provider'
             AND state IN ('active', 'resolution_required')
           ORDER BY admitted_at, id"#,
    )
    .bind(&input.organization_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)?;

    if leases
        .iter()
        .any(|lease| lease.state == "active" && !lease.deadline_elapsed)
    {
        return Err(AppError::Conflict(
            "tenant secret mutation deadline has not elapsed".into(),
        ));
    }
    for lease in &leases {
        if lease.state == "active" {
            mark_organization_mutation_resolution_required(
                pool,
                &lease.id,
                TENANT_SECRET_LEASE_DEADLINE_CODE,
            )
            .await?;
        }
    }
    Ok(leases)
}

async fn list_folders(store: &SecretStore, parent_path: &str) -> Result<Vec<String>, AppError> {
    store
        .list_folders_at_path(parent_path)
        .await
        .map_err(|error| {
            tracing::warn!(
                parent_path,
                error = %error,
                "tenant secret folder re-enumeration failed"
            );
            AppError::ServiceUnavailable("tenant secret provider re-enumeration failed".into())
        })
}

async fn delete_path(store: &SecretStore, path: &str) -> Result<(), AppError> {
    store.delete_path(path).await.map_err(|error| {
        tracing::warn!(path, error = %error, "tenant secret path deletion failed");
        AppError::ServiceUnavailable("tenant secret provider deletion failed".into())
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    use axum::Router;
    use axum::extract::{Json, Path, Query, State};
    use axum::http::StatusCode;
    use axum::routing::{delete, get};
    use codewire_server_core::auth::AuthUser;
    use codewire_server_core::org_deletion::{
        OrganizationMutationClass, OrganizationTenantSecretMutationError,
        acquire_organization_mutation_lease, begin_organization_deletion,
        mark_organization_deletion_started, mark_organization_mutation_resolution_required,
        run_organization_tenant_secret_mutation,
    };
    use serde::Deserialize;
    use sqlx::postgres::PgPoolOptions;
    use tokio::sync::{Mutex, oneshot};
    use uuid::Uuid;

    use crate::api::secret_projects::delete_secret_project_storage;
    use crate::worker::secrets::{InfisicalClient, LocalSecretStore};

    use super::*;

    struct Fixture {
        owner: AuthUser,
        org_id: String,
        project_id: String,
    }

    async fn pool() -> Option<PgPool> {
        let url = match std::env::var("DATABASE_URL") {
            Ok(url) if !url.is_empty() => url,
            _ => {
                eprintln!("DATABASE_URL unset — skipping tenant secret teardown DB flow");
                return None;
            }
        };
        Some(
            PgPoolOptions::new()
                .max_connections(10)
                .connect(&url)
                .await
                .expect("connect tenant secret teardown test database"),
        )
    }

    async fn seed(pool: &PgPool) -> Fixture {
        let suffix = Uuid::new_v4().simple().to_string();
        let user_id = format!("u_secret_teardown_{suffix}");
        let org_id = format!("org_secret_teardown_{suffix}");
        let project_id = format!("project_secret_teardown_{suffix}");
        sqlx::query(
            r#"INSERT INTO users (id, email, name, email_verified, is_admin)
               VALUES ($1, $2, 'Tenant secret teardown test', true, false)"#,
        )
        .bind(&user_id)
        .bind(format!("{suffix}@example.test"))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO organizations (id, name, slug, created_by)
               VALUES ($1, 'Tenant secret teardown test', $2, $3)"#,
        )
        .bind(&org_id)
        .bind(format!("secret-teardown-{suffix}"))
        .bind(&user_id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO org_members (id, org_id, user_id, role)
               VALUES ($1, $2, $3, 'owner')"#,
        )
        .bind(format!("member_secret_teardown_{suffix}"))
        .bind(&org_id)
        .bind(&user_id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO secret_projects (id, org_id, name)
               VALUES ($1, $2, 'tenant-secret-test')"#,
        )
        .bind(&project_id)
        .bind(&org_id)
        .execute(pool)
        .await
        .unwrap();
        Fixture {
            owner: AuthUser {
                user_id,
                org_id: None,
                is_admin: false,
                via_api_key: false,
            },
            org_id,
            project_id,
        }
    }

    async fn cleanup(pool: &PgPool, fixture: &Fixture) {
        let project_path = format!("/projects/{}/{}", fixture.org_id, fixture.project_id);
        let _ = sqlx::query(
            r#"DELETE FROM local_secrets
               WHERE path = $1 OR left(path, char_length($2) + 1) = $2 || '/'"#,
        )
        .bind(&project_path)
        .bind(format!("/projects/{}", fixture.org_id))
        .execute(pool)
        .await;
        let _ = sqlx::query("DELETE FROM local_secrets WHERE path = $1")
            .bind(format!("/org-secrets/{}", fixture.org_id))
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM secret_projects WHERE org_id = $1")
            .bind(&fixture.org_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM org_members WHERE org_id = $1")
            .bind(&fixture.org_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(&fixture.org_id)
            .execute(pool)
            .await;
        let _ =
            sqlx::query("DELETE FROM organization_deletion_operations WHERE organization_id = $1")
                .bind(&fixture.org_id)
                .execute(pool)
                .await;
        let _ = sqlx::query("DELETE FROM organization_mutation_leases WHERE organization_id = $1")
            .bind(&fixture.org_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM audit_logs WHERE metadata->>'organization_id' = $1")
            .bind(&fixture.org_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&fixture.owner.user_id)
            .execute(pool)
            .await;
    }

    async fn start_deletion(
        pool: &PgPool,
        fixture: &Fixture,
    ) -> OrganizationTenantSecretTeardownInput {
        let operation = begin_organization_deletion(pool, &fixture.owner, &fixture.org_id)
            .await
            .unwrap();
        mark_organization_deletion_started(pool, &operation.id, operation.generation)
            .await
            .unwrap();
        OrganizationTenantSecretTeardownInput {
            operation_id: operation.id,
            organization_id: fixture.org_id.clone(),
            generation: operation.generation,
        }
    }

    #[derive(Default)]
    struct FakeInfisicalState {
        secrets: BTreeMap<String, BTreeMap<String, String>>,
        folders: BTreeMap<String, BTreeSet<String>>,
        fail_delete_key: Option<String>,
        ghost_after_delete: Option<(String, String, usize)>,
        delete_observed: BTreeSet<String>,
    }

    #[derive(Clone, Default)]
    struct FakeInfisical {
        state: Arc<Mutex<FakeInfisicalState>>,
    }

    impl FakeInfisical {
        async fn insert(&self, path: &str, key: &str, value: &str) {
            let (parent, name) = path.trim_end_matches('/').rsplit_once('/').unwrap();
            let parent = if parent.is_empty() { "/" } else { parent };
            let mut state = self.state.lock().await;
            state
                .secrets
                .entry(path.into())
                .or_default()
                .insert(key.into(), value.into());
            state
                .folders
                .entry(parent.into())
                .or_default()
                .insert(name.into());
        }

        async fn serve(&self) -> (String, tokio::task::JoinHandle<()>) {
            let app = Router::new()
                .route("/api/v3/secrets/raw", get(fake_list_secrets))
                .route("/api/v3/secrets/raw/{key}", delete(fake_delete_secret))
                .route("/api/v2/folders", get(fake_list_folders))
                .route("/api/v2/folders/{name}", delete(fake_delete_folder))
                .with_state(self.state.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            (format!("http://{address}"), task)
        }
    }

    #[derive(Deserialize)]
    struct SecretListQuery {
        #[serde(rename = "secretPath")]
        secret_path: String,
    }

    async fn fake_list_secrets(
        State(state): State<Arc<Mutex<FakeInfisicalState>>>,
        Query(query): Query<SecretListQuery>,
    ) -> Json<serde_json::Value> {
        let mut state = state.lock().await;
        let mut entries = state
            .secrets
            .get(&query.secret_path)
            .cloned()
            .unwrap_or_default();
        let should_ghost = state
            .ghost_after_delete
            .as_ref()
            .is_some_and(|(path, _, remaining)| {
                path == &query.secret_path
                    && *remaining > 0
                    && state.delete_observed.contains(&query.secret_path)
            });
        if should_ghost && let Some((_, value, remaining)) = state.ghost_after_delete.as_mut() {
            entries.insert("GHOST".into(), value.clone());
            *remaining -= 1;
        }
        Json(serde_json::json!({
            "secrets": entries.into_iter().map(|(key, value)| {
                serde_json::json!({"secretKey": key, "secretValue": value})
            }).collect::<Vec<_>>()
        }))
    }

    #[derive(Deserialize)]
    struct SecretDeleteBody {
        #[serde(rename = "secretPath")]
        secret_path: String,
    }

    async fn fake_delete_secret(
        State(state): State<Arc<Mutex<FakeInfisicalState>>>,
        Path(key): Path<String>,
        Json(body): Json<SecretDeleteBody>,
    ) -> StatusCode {
        let mut state = state.lock().await;
        if state.fail_delete_key.as_deref() == Some(&key) {
            return StatusCode::SERVICE_UNAVAILABLE;
        }
        if let Some(secrets) = state.secrets.get_mut(&body.secret_path) {
            secrets.remove(&key);
        }
        state.delete_observed.insert(body.secret_path);
        StatusCode::OK
    }

    #[derive(Deserialize)]
    struct FolderListQuery {
        path: String,
    }

    async fn fake_list_folders(
        State(state): State<Arc<Mutex<FakeInfisicalState>>>,
        Query(query): Query<FolderListQuery>,
    ) -> Json<serde_json::Value> {
        let state = state.lock().await;
        let folders = state.folders.get(&query.path).cloned().unwrap_or_default();
        Json(serde_json::json!({
            "folders": folders.into_iter().map(|name| serde_json::json!({"name": name})).collect::<Vec<_>>()
        }))
    }

    #[derive(Deserialize)]
    struct FolderDeleteBody {
        path: String,
    }

    async fn fake_delete_folder(
        State(state): State<Arc<Mutex<FakeInfisicalState>>>,
        Path(name): Path<String>,
        Json(body): Json<FolderDeleteBody>,
    ) -> StatusCode {
        let mut state = state.lock().await;
        let full_path = if body.path == "/" {
            format!("/{name}")
        } else {
            format!("{}/{name}", body.path.trim_end_matches('/'))
        };
        if state
            .secrets
            .get(&full_path)
            .is_some_and(|secrets| !secrets.is_empty())
        {
            return StatusCode::CONFLICT;
        }
        state.secrets.remove(&full_path);
        let Some(children) = state.folders.get_mut(&body.path) else {
            return StatusCode::NOT_FOUND;
        };
        if !children.remove(&name) {
            return StatusCode::NOT_FOUND;
        }
        StatusCode::OK
    }

    #[tokio::test]
    async fn db_partial_infisical_delete_retains_project_discovery_row() {
        let Some(pool) = pool().await else { return };
        let fixture = seed(&pool).await;
        let path = format!("/projects/{}/{}", fixture.org_id, fixture.project_id);
        let fake = FakeInfisical::default();
        fake.insert(&path, "A_FIRST", "first-value").await;
        fake.insert(&path, "Z_FAIL", "second-value").await;
        fake.state.lock().await.fail_delete_key = Some("Z_FAIL".into());
        let (host, server) = fake.serve().await;
        let store = SecretStore::Infisical(InfisicalClient::for_test(host, "project".into()));

        let result = run_organization_tenant_secret_mutation(&pool, &fixture.org_id, async {
            delete_secret_project_storage(&pool, &store, &fixture.org_id, &fixture.project_id).await
        })
        .await;
        assert!(result.is_err());
        let retained: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM secret_projects WHERE id = $1)")
                .bind(&fixture.project_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(retained);
        let remaining = store.get_secrets_raw_at_path(&path).await.unwrap();
        assert_eq!(
            remaining.len(),
            1,
            "one successful delete must not erase discovery"
        );

        server.abort();
        cleanup(&pool, &fixture).await;
    }

    #[tokio::test]
    async fn db_partial_local_delete_retains_project_discovery_row() {
        let Some(pool) = pool().await else { return };
        let fixture = seed(&pool).await;
        let path = format!("/projects/{}/{}", fixture.org_id, fixture.project_id);
        let store = SecretStore::Local(LocalSecretStore { pool: pool.clone() });
        store
            .set_secret_at_path(&path, "A_FIRST", "first-value")
            .await
            .unwrap();
        store
            .set_secret_at_path(&path, "Z_FAIL", "second-value")
            .await
            .unwrap();

        let suffix = Uuid::new_v4().simple().to_string();
        let function = format!("reject_local_secret_delete_{suffix}");
        let trigger = format!("reject_local_secret_delete_trigger_{suffix}");
        let trigger_sql = format!(
            r#"CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$
               BEGIN
                 IF OLD.path = '{path}' AND OLD.key = 'Z_FAIL' THEN
                   RAISE EXCEPTION 'injected local secret deletion failure';
                 END IF;
                 RETURN OLD;
               END $$;
               CREATE TRIGGER {trigger} BEFORE DELETE ON local_secrets
               FOR EACH ROW EXECUTE FUNCTION {function}();"#
        );
        sqlx::raw_sql(&trigger_sql).execute(&pool).await.unwrap();

        let result = run_organization_tenant_secret_mutation(&pool, &fixture.org_id, async {
            delete_secret_project_storage(&pool, &store, &fixture.org_id, &fixture.project_id).await
        })
        .await;
        assert!(result.is_err());
        let retained: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM secret_projects WHERE id = $1)")
                .bind(&fixture.project_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(retained);
        let remaining = store.get_secrets_raw_at_path(&path).await.unwrap();
        assert_eq!(
            remaining.len(),
            1,
            "one successful delete must not erase discovery"
        );

        let drop_sql =
            format!("DROP TRIGGER {trigger} ON local_secrets; DROP FUNCTION {function}();");
        sqlx::raw_sql(&drop_sql).execute(&pool).await.unwrap();
        cleanup(&pool, &fixture).await;
    }

    #[tokio::test]
    async fn db_stalled_pre_fence_write_is_removed_by_post_drain_enumeration() {
        let Some(pool) = pool().await else { return };
        let fixture = seed(&pool).await;
        let path = format!("/projects/{}/{}", fixture.org_id, fixture.project_id);
        let store = Arc::new(SecretStore::Local(LocalSecretStore { pool: pool.clone() }));
        let (admitted_tx, admitted_rx) = oneshot::channel();
        let (continue_tx, continue_rx) = oneshot::channel();
        let task_pool = pool.clone();
        let task_org = fixture.org_id.clone();
        let task_path = path.clone();
        let task_store = store.clone();
        let mutation = tokio::spawn(async move {
            run_organization_tenant_secret_mutation(&task_pool, &task_org, async {
                let _ = admitted_tx.send(());
                let _ = continue_rx.await;
                task_store
                    .set_secret_at_path(&task_path, "AFTER_FENCE", "never-log-this-value")
                    .await
                    .map_err(|error| {
                        OrganizationTenantSecretMutationError::ambiguous(AppError::Internal(error))
                    })?;
                Ok(())
            })
            .await
        });
        admitted_rx.await.unwrap();
        let input = start_deletion(&pool, &fixture).await;
        continue_tx.send(()).unwrap();
        mutation.await.unwrap().unwrap();

        let result = teardown_organization_tenant_secrets(&pool, &store, &input)
            .await
            .unwrap();
        assert_eq!(result.state, "completed");
        assert!(
            store
                .get_secrets_raw_at_path(&path)
                .await
                .unwrap()
                .is_empty()
        );
        let retained: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM secret_projects WHERE id = $1)")
                .bind(&fixture.project_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            retained,
            "the WI-5 finalizer still owns discovery-row deletion"
        );

        cleanup(&pool, &fixture).await;
    }

    #[tokio::test]
    async fn db_post_drain_reenumeration_retries_value_blind_before_resolving_lease() {
        let Some(pool) = pool().await else { return };
        let fixture = seed(&pool).await;
        let path = format!("/projects/{}/{}", fixture.org_id, fixture.project_id);
        let canary = "tenant-secret-value-must-not-escape";
        let fake = FakeInfisical::default();
        fake.insert(&path, "ONLY", canary).await;
        fake.state.lock().await.ghost_after_delete = Some((path.clone(), canary.into(), 1));
        let (host, server) = fake.serve().await;
        let store = SecretStore::Infisical(InfisicalClient::for_test(host, "project".into()));

        let lease = acquire_organization_mutation_lease(
            &pool,
            &fixture.org_id,
            OrganizationMutationClass::TenantSecretProvider,
        )
        .await
        .unwrap();
        mark_organization_mutation_resolution_required(
            &pool,
            &lease.id,
            "tenant_secret_provider_ambiguous",
        )
        .await
        .unwrap();
        let input = start_deletion(&pool, &fixture).await;

        let first = teardown_organization_tenant_secrets(&pool, &store, &input)
            .await
            .unwrap_err();
        assert!(!first.to_string().contains(canary));
        let first_state: String =
            sqlx::query_scalar("SELECT state FROM organization_mutation_leases WHERE id = $1")
                .bind(&lease.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(first_state, "resolution_required");

        let second = teardown_organization_tenant_secrets(&pool, &store, &input)
            .await
            .unwrap();
        assert_eq!(second.state, "completed");
        let second_state: String =
            sqlx::query_scalar("SELECT state FROM organization_mutation_leases WHERE id = $1")
                .bind(&lease.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(second_state, "resolved");
        let retained: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM secret_projects WHERE id = $1)")
                .bind(&fixture.project_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(retained);

        server.abort();
        cleanup(&pool, &fixture).await;
    }
}
