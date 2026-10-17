//! Claim-time workspace binding: disposable database proof for the binding
//! table, the backend pointer and the insert-only, cascade-only triggers.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

const ENV_A: &str = "binding-env-a";
const ENV_B: &str = "binding-env-b";
const POD_A: &str = "0b5a3e7c-5d1e-4c55-9f0e-3b1d7a6c2e01";
const POD_A2: &str = "0b5a3e7c-5d1e-4c55-9f0e-3b1d7a6c2e02";
const POD_B: &str = "0b5a3e7c-5d1e-4c55-9f0e-3b1d7a6c2e03";
const CLAIM_UID: &str = "6f2d8c1a-0e4b-4f7a-9c3d-5b8e2a1f0c41";
const SANDBOX_UID: &str = "6f2d8c1a-0e4b-4f7a-9c3d-5b8e2a1f0c42";
const PVC_UID: &str = "6f2d8c1a-0e4b-4f7a-9c3d-5b8e2a1f0c43";

/// Two running sandboxes with backend rows written by version-33 code: no
/// pointer columns exist yet, and every other backend column is populated.
async fn seed(pool: &PgPool) -> anyhow::Result<()> {
    seed_platform_credential_owners(pool).await?;
    seed_platform_credential(
        pool,
        "binding-retained",
        Some("credential-user-a"),
        None,
        "Retained",
    )
    .await?;
    seed_platform_credential_material(pool, "binding-retained", 1).await?;
    seed_test_tenant_secret_dek(pool, "binding-dek", "user", "credential-user-a").await?;
    sqlx::raw_sql(
        "INSERT INTO tenant_secrets(path,key,dek_id,scope,scope_id,ciphertext,nonce,format,storage_contract_version) \
         VALUES('/users/credential-user-a','BINDING_RETAINED','binding-dek','user','credential-user-a',\
         decode(repeat('01',32),'hex'),decode(repeat('02',12),'hex'),1,1); \
         INSERT INTO environment_presets(id,org_id,name,slug,project_spec) VALUES('binding-preset','credential-org-a',\
         'Binding','binding','{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
         INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,environment_operation_generation,project_spec) \
         VALUES('binding-env-a','credential-org-a','credential-user-a','sandbox','binding-preset','running','started',3,\
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb), \
         ('binding-env-b','credential-org-a','credential-user-a','sandbox','binding-preset','running','started',1,\
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
         INSERT INTO sandbox_environment_backend(environment_id,namespace,sandbox_claim_name,pod_name,pod_ip,\
         sandbox_claim_uid,setup_phase,setup_complete) VALUES \
         ('binding-env-a','codewire-sandboxes','sandbox-binding-env-a','sandbox-binding-env-a','10.0.0.10',\
         '6f2d8c1a-0e4b-4f7a-9c3d-5b8e2a1f0c41',4,true), \
         ('binding-env-b','codewire-sandboxes','sandbox-binding-env-b','sandbox-binding-env-b','10.0.0.11',\
         '6f2d8c1a-0e4b-4f7a-9c3d-5b8e2a1f0c51',1,false);",
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// The binding JSON a recorder writes for environment A's Pod. Cases override
/// single fields through `jsonb_populate_record`, so every rejection below is
/// an INSERT that differs from a valid row in exactly one column.
fn binding(pod_uid: &str, environment_id: &str) -> serde_json::Value {
    serde_json::json!({
        "pod_uid": pod_uid,
        "environment_id": environment_id,
        "namespace": "codewire-sandboxes",
        "pod_name": format!("sandbox-{environment_id}"),
        "claim_uid": CLAIM_UID,
        "sandbox_uid": SANDBOX_UID,
        "workspace_pvc_uid": PVC_UID,
        "operation_generation": 3,
        "projection_selection_sha256": "a".repeat(64),
        "managed_credential_clients": "codex",
        "credential_scope": "environment",
        "bound_at": "2026-10-01T12:00:00Z",
        "released_at": null,
    })
}

async fn insert_binding<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    row: &serde_json::Value,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(
        "INSERT INTO sandbox_workspace_bindings \
         SELECT (jsonb_populate_record(NULL::sandbox_workspace_bindings, $1)).*",
    )
    .bind(row)
    .execute(executor)
    .await
}

/// Record environment A's live binding and point its backend row at it, as
/// the recorder's fenced transaction does.
async fn seed_binding(pool: &PgPool) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    insert_binding(&mut *tx, &binding(POD_A, ENV_A)).await?;
    sqlx::query(
        "UPDATE sandbox_environment_backend SET pod_uid=$1, bound_at=$2::timestamptz, workspace_pvc_uid=$3 \
         WHERE environment_id=$4",
    )
    .bind(POD_A)
    .bind("2026-10-01T12:00:00Z")
    .bind(PVC_UID)
    .bind(ENV_A)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn pointers_absent(pool: &PgPool) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT bool_and(pod_uid IS NULL AND bound_at IS NULL AND workspace_pvc_uid IS NULL) \
         FROM public.sandbox_environment_backend",
    )
    .fetch_one(pool)
    .await?)
}

fn sqlstate(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()
        .and_then(|e| e.code())
        .map(|code| code.into_owned())
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn workspace_binding_fresh_schema_constrains_rows_pointer_trigger_and_indexes()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        seed(&pool).await?;
        // Existing backend rows stay valid with NULL pointers, and ordinary
        // writers that never name the new columns keep working.
        anyhow::ensure!(pointers_absent(&pool).await?);
        sqlx::query("UPDATE sandbox_environment_backend SET setup_phase=setup_phase+1")
            .execute(&pool)
            .await?;
        seed_binding(&pool).await?;
        let measured = fingerprint(&pool).await?;
        anyhow::ensure!(
            measured == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT,
            "workspace binding measured fingerprint: {measured}"
        );

        // Each rejected binding differs from a valid row in one column. The
        // INSERT path is used because the insert-only trigger would otherwise
        // answer every UPDATE before a CHECK constraint is evaluated.
        let uppercase = POD_B.to_ascii_uppercase();
        for (column, value, code) in [
            ("pod_uid", serde_json::json!("not-a-kubernetes-uid"), "23514"),
            ("pod_uid", serde_json::json!(uppercase), "23514"),
            ("pod_uid", serde_json::Value::Null, "23502"),
            ("environment_id", serde_json::json!("missing-environment"), "23503"),
            ("environment_id", serde_json::Value::Null, "23502"),
            ("namespace", serde_json::json!(" "), "23514"),
            ("pod_name", serde_json::json!(""), "23514"),
            ("claim_uid", serde_json::json!("claim-name"), "23514"),
            ("claim_uid", serde_json::Value::Null, "23502"),
            ("sandbox_uid", serde_json::json!(CLAIM_UID.to_ascii_uppercase()), "23514"),
            ("sandbox_uid", serde_json::Value::Null, "23502"),
            ("workspace_pvc_uid", serde_json::json!("workspace-sandbox"), "23514"),
            ("operation_generation", serde_json::json!(0), "23514"),
            ("operation_generation", serde_json::Value::Null, "23502"),
            ("projection_selection_sha256", serde_json::json!("A".repeat(64)), "23514"),
            ("projection_selection_sha256", serde_json::json!("a".repeat(63)), "23514"),
            ("managed_credential_clients", serde_json::Value::Null, "23502"),
            ("credential_scope", serde_json::json!("namespace"), "23514"),
            ("credential_scope", serde_json::Value::Null, "23502"),
            ("bound_at", serde_json::Value::Null, "23502"),
            ("released_at", serde_json::json!("2026-10-01T11:59:59Z"), "23514"),
        ] {
            let mut row = binding(POD_B, ENV_B);
            row[column] = value.clone();
            let mut tx = pool.begin().await?;
            let error = insert_binding(&mut *tx, &row)
                .await
                .expect_err("invalid workspace binding accepted");
            anyhow::ensure!(
                sqlstate(&error).as_deref() == Some(code),
                "{column}={value}: {error}"
            );
            tx.rollback().await?;
        }
        // A volume-less workspace records no PVC, and a binding may omit the
        // projection digest.
        let mut row = binding(POD_B, ENV_B);
        row["workspace_pvc_uid"] = serde_json::Value::Null;
        row["projection_selection_sha256"] = serde_json::Value::Null;
        let mut tx = pool.begin().await?;
        insert_binding(&mut *tx, &row).await?;
        tx.rollback().await?;

        // One Pod serves one environment: the same Pod UID cannot be recorded
        // for a second environment, live or released.
        let mut released = binding(POD_A, ENV_B);
        released["released_at"] = serde_json::json!("2026-10-01T12:00:01Z");
        for row in [binding(POD_A, ENV_B), released] {
            let error = insert_binding(&pool, &row)
                .await
                .expect_err("second environment bound to one Pod");
            anyhow::ensure!(sqlstate(&error).as_deref() == Some("23505"), "{error}");
        }
        // One live binding per environment; released history may accumulate.
        let error = insert_binding(&pool, &binding(POD_A2, ENV_A))
            .await
            .expect_err("second live binding for one environment");
        anyhow::ensure!(sqlstate(&error).as_deref() == Some("23505"), "{error}");
        let mut history = binding(POD_A2, ENV_A);
        history["released_at"] = serde_json::json!("2026-10-01T12:00:05Z");
        insert_binding(&pool, &history).await?;

        // The backend pointer names only a binding of the same environment,
        // and pointer and bind time are set together.
        for (assignment, code) in [
            (format!("pod_uid='{POD_A}', bound_at=now()"), "23503"),
            (format!("pod_uid='{POD_B}', bound_at=now()"), "23503"),
            (format!("pod_uid='{POD_A}'"), "23514"),
            ("bound_at=now()".to_owned(), "23514"),
            ("workspace_pvc_uid='workspace-sandbox'".to_owned(), "23514"),
            (format!("workspace_pvc_uid='{}'", PVC_UID.to_ascii_uppercase()), "23514"),
        ] {
            let mut tx = pool.begin().await?;
            let error = sqlx::query(&format!(
                "UPDATE sandbox_environment_backend SET {assignment} WHERE environment_id='{ENV_B}'"
            ))
            .execute(&mut *tx)
            .await
            .expect_err("invalid backend binding pointer accepted");
            anyhow::ensure!(
                sqlstate(&error).as_deref() == Some(code),
                "{assignment}: {error}"
            );
            tx.rollback().await?;
        }
        for assignment in ["bound_at=NULL", "pod_uid=NULL"] {
            let mut tx = pool.begin().await?;
            let error = sqlx::query(&format!(
                "UPDATE sandbox_environment_backend SET {assignment} WHERE environment_id='{ENV_A}'"
            ))
            .execute(&mut *tx)
            .await
            .expect_err("incoherent backend binding pointer accepted");
            anyhow::ensure!(sqlstate(&error).as_deref() == Some("23514"), "{assignment}: {error}");
            tx.rollback().await?;
        }

        // Rows are insert-only except a single release.
        for assignment in [
            format!("environment_id='{ENV_B}'"),
            format!("pod_uid='{POD_B}'"),
            "namespace='other-namespace'".to_owned(),
            "pod_name='other-pod'".to_owned(),
            format!("claim_uid='{SANDBOX_UID}'"),
            format!("sandbox_uid='{CLAIM_UID}'"),
            "workspace_pvc_uid=NULL".to_owned(),
            "operation_generation=operation_generation+1".to_owned(),
            "projection_selection_sha256=NULL".to_owned(),
            "managed_credential_clients=''".to_owned(),
            "credential_scope='pod'".to_owned(),
            "bound_at=bound_at+interval '1 second'".to_owned(),
        ] {
            let mut tx = pool.begin().await?;
            let error = sqlx::query(&format!(
                "UPDATE sandbox_workspace_bindings SET {assignment} WHERE pod_uid='{POD_A}'"
            ))
            .execute(&mut *tx)
            .await
            .expect_err("workspace binding changed in place");
            anyhow::ensure!(
                sqlstate(&error).as_deref() == Some("23514")
                    && error.to_string().contains("immutable except its release"),
                "{assignment}: {error}"
            );
            tx.rollback().await?;
        }
        // A no-op write and the release itself are allowed; the release is
        // then final.
        sqlx::query("UPDATE sandbox_workspace_bindings SET released_at=NULL WHERE pod_uid=$1")
            .bind(POD_A)
            .execute(&pool)
            .await?;
        sqlx::query(
            "UPDATE sandbox_workspace_bindings SET released_at=bound_at+interval '1 minute' WHERE pod_uid=$1",
        )
        .bind(POD_A)
        .execute(&pool)
        .await?;
        sqlx::query("UPDATE sandbox_workspace_bindings SET released_at=released_at WHERE pod_uid=$1")
            .bind(POD_A)
            .execute(&pool)
            .await?;
        for assignment in ["released_at=NULL", "released_at=released_at+interval '1 second'"] {
            let mut tx = pool.begin().await?;
            let error = sqlx::query(&format!(
                "UPDATE sandbox_workspace_bindings SET {assignment} WHERE pod_uid='{POD_A}'"
            ))
            .execute(&mut *tx)
            .await
            .expect_err("released workspace binding changed");
            anyhow::ensure!(
                sqlstate(&error).as_deref() == Some("23514")
                    && error.to_string().contains("release is final"),
                "{assignment}: {error}"
            );
            tx.rollback().await?;
        }

        // Rows leave only with their environment: a direct DELETE of a live,
        // pointed-at or released binding is refused before any foreign key.
        for pod in [POD_A, POD_A2] {
            let mut tx = pool.begin().await?;
            let error = sqlx::query("DELETE FROM sandbox_workspace_bindings WHERE pod_uid=$1")
                .bind(pod)
                .execute(&mut *tx)
                .await
                .expect_err("workspace binding deleted directly");
            anyhow::ensure!(
                sqlstate(&error).as_deref() == Some("23514")
                    && error.to_string().contains("removed only with its environment"),
                "{pod}: {error}"
            );
            tx.rollback().await?;
        }

        let triggers: Vec<String> = sqlx::query_scalar(
            "SELECT pg_get_triggerdef(oid) FROM pg_trigger \
             WHERE tgrelid='public.sandbox_workspace_bindings'::regclass AND NOT tgisinternal \
             ORDER BY tgname",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            matches!(triggers.as_slice(), [delete, update]
                if delete.contains("codewire_workspace_binding_cascade_only BEFORE DELETE")
                    && update.contains("codewire_workspace_binding_immutable BEFORE UPDATE")
                    && triggers.iter().all(|trigger| trigger.contains("FOR EACH ROW")
                        && trigger.contains("EXECUTE FUNCTION codewire_workspace_binding_immutable()"))),
            "{triggers:?}"
        );
        // A plain invoker trigger function: not SECURITY DEFINER, a fixed
        // search path, owned by the migration role and executable by no one
        // else.
        anyhow::ensure!(
            sqlx::query_scalar::<_, bool>(
                "SELECT NOT p.prosecdef AND p.prorettype='trigger'::regtype AND l.lanname='plpgsql' \
                 AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[] \
                 AND p.proowner=(SELECT c.relowner FROM pg_catalog.pg_class c \
                                 WHERE c.oid='public._sqlx_migrations'::regclass) \
                 AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(\
                     COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a \
                     WHERE a.grantee<>p.proowner) \
                 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang \
                 WHERE p.oid='public.codewire_workspace_binding_immutable'::regproc",
            )
            .fetch_one(&pool)
            .await?,
            "the trigger function's authority changed"
        );
        let indexes: Vec<String> = sqlx::query_scalar(
            "SELECT indexname FROM pg_indexes WHERE schemaname='public' \
             AND tablename='sandbox_workspace_bindings' ORDER BY indexname",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            indexes
                == [
                    "sandbox_workspace_bindings_environment_id_pod_uid_key",
                    "sandbox_workspace_bindings_live_environment",
                    "sandbox_workspace_bindings_pkey",
                ],
            "{indexes:?}"
        );
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn workspace_binding_pointer_moves_within_one_environment_and_cascades_with_it()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        seed(&pool).await?;
        seed_binding(&pool).await?;
        // A pointed-to binding cannot be removed out from under its backend:
        // the cascade-only guard refuses the direct DELETE first.
        let error = sqlx::query("DELETE FROM sandbox_workspace_bindings WHERE pod_uid=$1")
            .bind(POD_A)
            .execute(&pool)
            .await
            .expect_err("live pointer target deleted");
        anyhow::ensure!(sqlstate(&error).as_deref() == Some("23514"), "{error}");

        // A restart: release the old Pod, record the new one, then move the
        // pointer, in one transaction as the recorder does.
        let mut tx = pool.begin().await?;
        sqlx::query(
            "UPDATE sandbox_workspace_bindings SET released_at=bound_at+interval '1 minute' \
             WHERE environment_id=$1 AND released_at IS NULL",
        )
        .bind(ENV_A)
        .execute(&mut *tx)
        .await?;
        let mut replacement = binding(POD_A2, ENV_A);
        replacement["bound_at"] = serde_json::json!("2026-10-01T12:05:00Z");
        insert_binding(&mut *tx, &replacement).await?;
        sqlx::query(
            "UPDATE sandbox_environment_backend SET pod_uid=$1, bound_at=$2::timestamptz WHERE environment_id=$3",
        )
        .bind(POD_A2)
        .bind("2026-10-01T12:05:00Z")
        .bind(ENV_A)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        anyhow::ensure!(
            sqlx::query_as::<_, (i64, i64)>(
                "SELECT count(*), count(*) FILTER (WHERE released_at IS NULL) \
                 FROM sandbox_workspace_bindings WHERE environment_id=$1",
            )
            .bind(ENV_A)
            .fetch_one(&pool)
            .await?
                == (2, 1)
        );
        // Environment B is bound to its own Pod independently.
        let mut tx = pool.begin().await?;
        insert_binding(&mut *tx, &binding(POD_B, ENV_B)).await?;
        sqlx::query(
            "UPDATE sandbox_environment_backend SET pod_uid=$1, bound_at=now() WHERE environment_id=$2",
        )
        .bind(POD_B)
        .bind(ENV_B)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        // Deleting environment A removes its backend row and every binding it
        // had, live or released, and leaves B intact.
        sqlx::query("DELETE FROM environments WHERE id=$1")
            .bind(ENV_A)
            .execute(&pool)
            .await?;
        anyhow::ensure!(
            sqlx::query_as::<_, (i64, i64)>(
                "SELECT (SELECT count(*) FROM sandbox_workspace_bindings WHERE environment_id=$1), \
                 (SELECT count(*) FROM sandbox_environment_backend WHERE environment_id=$1)",
            )
            .bind(ENV_A)
            .fetch_one(&pool)
            .await?
                == (0, 0)
        );
        anyhow::ensure!(
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT b.pod_uid FROM sandbox_environment_backend b \
                 JOIN sandbox_workspace_bindings w ON w.pod_uid=b.pod_uid AND w.environment_id=b.environment_id \
                 WHERE b.environment_id=$1",
            )
            .bind(ENV_B)
            .fetch_one(&pool)
            .await?
            .as_deref()
                == Some(POD_B)
        );
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
