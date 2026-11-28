//! Disposable-PostgreSQL proof of what a Pod's first bind records of its
//! host-bound secrets (#4003): each bound secret its selection projects, from
//! the sources its binding's digest captured, stored once with the
//! interception decision and frozen for the Pod's life. Every value is
//! synthetic.

use std::sync::Arc;

use anyhow::{Result, ensure};
use codewire_access::{StoredBinding, StoredPresentation};
use codewire_protected_store::secret_envelope::TestKekProvider;

use super::*;
use crate::test_database_support::TestDatabase;
use crate::worker::postgres_secrets::{BindingWrite, PostgresSecretStore};
use crate::workspace_binding::store::{BindingStore, PgBindingStore};

const CREATOR: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";
const ORGANIZATION: &str = "0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b";
const PROJECT: &str = "7d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";
const ENV: &str = "550e8400-e29b-41d4-a716-446655440000";
const POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
const CANARY: &str = "synthetic-first-bind-canary";

fn org_path() -> String {
    format!("/org-secrets/{ORGANIZATION}")
}

fn project_path() -> String {
    format!("/projects/{ORGANIZATION}/{PROJECT}")
}

fn user_path() -> String {
    format!("/users/{CREATOR}")
}

fn bind(hosts: &[&str]) -> BindingWrite {
    BindingWrite::Bind(StoredBinding {
        hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
        presentation: StoredPresentation::Header {
            headers: vec!["Authorization".into()],
            scheme: Some("Bearer".into()),
        },
        prefix: None,
        preset: None,
    })
}

/// An environment selecting its organization's, its project's and its
/// creator's secrets, which sets `OVERRIDDEN` itself, with a binding whose
/// digest is that selection's.
async fn seed(db: &TestDatabase) -> Result<String> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    sqlx::query("INSERT INTO secret_projects (id, org_id, name) VALUES ($1, $2, 'first-bind')")
        .bind(PROJECT)
        .bind(ORGANIZATION)
        .execute(&db.pool)
        .await?;
    let spec = serde_json::json!({
        "schema_version": 1,
        "working_directory": "/workspace",
        "secrets": {"organization": true, "project": format!("platform:id:{PROJECT}"), "user": "platform"},
        "environment": {"OVERRIDDEN": "set-by-the-environment"},
    });
    sqlx::query(
        "INSERT INTO environment_presets (id, org_id, name, slug, project_spec) \
         VALUES ('first-bind-preset', $1, 'First bind', 'first-bind', $2)",
    )
    .bind(ORGANIZATION)
    .bind(&spec)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments \
         (id, org_id, created_by, preset_id, type, state, desired_state, project_spec, \
          environment_operation_generation) \
         VALUES ($1, $2, $3, 'first-bind-preset', 'sandbox', 'running', 'started', $4, 3)",
    )
    .bind(ENV)
    .bind(ORGANIZATION)
    .bind(CREATOR)
    .bind(&spec)
    .execute(&db.pool)
    .await?;
    let environment = crate::worker::env_data::load_environment(&db.pool, ENV).await?;
    let selection = environment
        .projection_selection
        .map_err(|_| anyhow::anyhow!("the seeded selection is valid"))?
        .ok_or_else(|| anyhow::anyhow!("the seeded environment selects secrets"))?;
    let digest: String = selection
        .sha256()?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    sqlx::query(
        "INSERT INTO sandbox_workspace_bindings \
         (pod_uid, environment_id, namespace, pod_name, claim_uid, sandbox_uid, \
          operation_generation, projection_selection_sha256, managed_credential_clients, \
          credential_scope) \
         VALUES ($1, $2, 'sandboxes', 'sandbox-first-bind', \
         'c0ffee00-e29b-41d4-a716-446655440000', '5a4db0c5-e29b-41d4-a716-446655440000', \
         3, $3, '', 'pod')",
    )
    .bind(POD)
    .bind(ENV)
    .bind(&digest)
    .execute(&db.pool)
    .await?;
    Ok(digest)
}

/// Writes the secrets: a bound one in each of the organization and the
/// project, a plain one, a bound key the creator's plain key overrides, and
/// a bound key the environment sets itself.
async fn secrets(db: &TestDatabase) -> Result<()> {
    let store = PostgresSecretStore::new(db.pool.clone(), Arc::new(TestKekProvider));
    let reserved = ReservedHosts::default();
    for (path, key, binding) in [
        (org_path(), "FANCY_TOKEN", bind(&["api.fancy.example"])),
        (
            project_path(),
            "OTHER_TOKEN",
            bind(&["uploads.other.example", "api.other.example"]),
        ),
        (user_path(), "PLAIN_TOKEN", BindingWrite::Keep),
        (org_path(), "SHADOWED", bind(&["api.shadowed.example"])),
        (user_path(), "SHADOWED", BindingWrite::Keep),
        (org_path(), "OVERRIDDEN", bind(&["api.overridden.example"])),
    ] {
        store
            .write_secret_at_path(&path, key, Some(CANARY), binding, &reserved)
            .await?;
    }
    Ok(())
}

/// The binding's identity as the store wrote it.
#[derive(sqlx::FromRow)]
struct Identity {
    binding_id: Option<Uuid>,
    binding_generation: i64,
}

async fn recorded_as(
    db: &TestDatabase,
    path: String,
    key: &str,
    hosts: &[&str],
) -> Result<FirstBindSecret> {
    let identity: Identity = sqlx::query_as(
        "SELECT binding_id, binding_generation FROM tenant_secrets WHERE path = $1 AND key = $2",
    )
    .bind(&path)
    .bind(key)
    .fetch_one(&db.pool)
    .await?;
    Ok(FirstBindSecret {
        path,
        key: key.into(),
        binding_id: identity
            .binding_id
            .ok_or_else(|| anyhow::anyhow!("{key} is bound"))?
            .to_string(),
        binding_generation: u64::try_from(identity.binding_generation)?,
        prefix: None,
        hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
    })
}

async fn stored(db: &TestDatabase) -> Result<Option<serde_json::Value>> {
    Ok(sqlx::query_scalar(
        "SELECT bound_secrets FROM sandbox_workspace_bindings WHERE pod_uid = $1",
    )
    .bind(POD)
    .fetch_one(&db.pool)
    .await?)
}

/// The first bind reads, of each key its selected sources hold, the secret
/// the projection takes, and records it only when that one is bound: by its
/// path and key, its binding's identity and its canonical hosts. Only a
/// binding with no digest records none; one whose digest doesn't read, or
/// that its environment's selection no longer reproduces, is unavailable.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_first_bind_reads_each_selected_bound_secret() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let digest = seed(&db).await?;
        secrets(&db).await?;
        let read = selected(&db.pool, ENV, Some(&digest))
            .await
            .map_err(|_| anyhow::anyhow!("the selection reads"))?;
        let expected = vec![
            recorded_as(&db, org_path(), "FANCY_TOKEN", &["api.fancy.example"]).await?,
            recorded_as(
                &db,
                project_path(),
                "OTHER_TOKEN",
                &["api.other.example", "uploads.other.example"],
            )
            .await?,
        ];
        ensure!(read == expected, "recorded {read:?}");
        ensure!(!format!("{read:?}").contains(CANARY), "no value is read");
        ensure!(
            selected(&db.pool, ENV, None)
                .await
                .is_ok_and(|none| none.is_empty())
        );
        // A digest the selection doesn't reproduce, or one that doesn't
        // read, is unavailable: its sources can't be read, so it records
        // nothing rather than none.
        for digest in ["ab".repeat(32), "not-a-digest".to_owned()] {
            ensure!(
                selected(&db.pool, ENV, Some(&digest)).await.is_err(),
                "{digest} was read as a selection"
            );
        }
        // A selection that changed since the binding captured it.
        sqlx::query(
            "UPDATE environments SET project_spec = project_spec - 'secrets' || \
             '{\"secrets\":{\"organization\":true}}'::jsonb WHERE id = $1",
        )
        .bind(ENV)
        .execute(&db.pool)
        .await?;
        ensure!(
            selected(&db.pool, ENV, Some(&digest)).await.is_err(),
            "a selection that no longer reproduces the binding's digest was read"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// The bound secrets are stored with the interception decision in one write,
/// and neither changes after: a later bind's are ignored, and the binding's
/// trigger refuses a direct change, as it refuses one to a binding whose
/// decision was stored without them.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_bound_secrets_are_recorded_once_with_the_decision() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let digest = seed(&db).await?;
        secrets(&db).await?;
        let first = selected(&db.pool, ENV, Some(&digest))
            .await
            .map_err(|_| anyhow::anyhow!("the selection reads"))?;
        ensure!(first.len() == 2);
        ensure!(
            stored(&db).await?.is_none(),
            "nothing before the first bind"
        );
        let store = PgBindingStore::from_pool(db.pool.clone());
        ensure!(
            store
                .record_interception(POD, true, &first)
                .await
                .map_err(|_| anyhow::anyhow!("record"))?
        );
        let recorded: Vec<FirstBindSecret> = serde_json::from_value(
            stored(&db)
                .await?
                .ok_or_else(|| anyhow::anyhow!("recorded"))?,
        )?;
        ensure!(recorded == first, "recorded as read: {recorded:?}");
        ensure!(
            store
                .record_interception(POD, false, &[])
                .await
                .map_err(|_| anyhow::anyhow!("record"))?,
            "a later bind reads the stored decision"
        );
        ensure!(
            stored(&db)
                .await?
                .map(serde_json::from_value::<Vec<FirstBindSecret>>)
                .transpose()?
                == Some(first.clone()),
            "and leaves the bound secrets as they were"
        );
        let refused = |result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>| {
            result
                .err()
                .and_then(|error| {
                    error
                        .as_database_error()
                        .and_then(|e| e.code())
                        .map(|c| c.into_owned())
                })
                .as_deref()
                == Some("23514")
        };
        for value in ["'[]'", "'null'", "NULL"] {
            ensure!(
                refused(
                    sqlx::query(&format!(
                        "UPDATE sandbox_workspace_bindings SET bound_secrets = {value}::jsonb \
                         WHERE pod_uid = $1"
                    ))
                    .bind(POD)
                    .execute(&db.pool)
                    .await
                ),
                "the trigger refuses setting {value}"
            );
        }
        // A decision the credential relay stored alone, for a Pod an older
        // orchestration bound, never gains bound secrets later.
        sqlx::query(
            "INSERT INTO sandbox_workspace_bindings \
             (pod_uid, environment_id, namespace, pod_name, claim_uid, sandbox_uid, \
              operation_generation, managed_credential_clients, credential_scope, \
              released_at, interception) \
             VALUES ('a1560db3-8899-40c9-b521-500f223b04fb', $1, 'sandboxes', 'older', \
             'c0ffee00-e29b-41d4-a716-446655440000', '5a4db0c5-e29b-41d4-a716-446655440000', \
             2, '', 'pod', now(), false)",
        )
        .bind(ENV)
        .execute(&db.pool)
        .await?;
        ensure!(refused(
            sqlx::query(
                "UPDATE sandbox_workspace_bindings SET bound_secrets = '[]'::jsonb \
                 WHERE pod_uid = 'a1560db3-8899-40c9-b521-500f223b04fb'",
            )
            .execute(&db.pool)
            .await
        ));
        Ok(())
    }
    .await;
    db.finish(result).await
}
