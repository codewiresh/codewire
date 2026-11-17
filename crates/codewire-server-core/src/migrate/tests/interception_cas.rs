//! Hosted interception CAs (0032, #5030): one sealed CA per Pod
//! UID, its environment only from the Pod's binding, attached by the bind,
//! deleted by the release, and four functions that run as the migration owner
//! with a pinned search_path and no dynamic SQL; the rollback restores the
//! earlier shape. The store's behaviour as the broker role is in
//! codewire-platform-credentials' storage suite.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

fn through(version: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .iter()
                .filter(|migration| migration.version <= version)
                .cloned()
                .collect(),
        ),
        ..sqlx::migrate::Migrator::DEFAULT
    }
}

/// The SQLSTATE of a refused statement, or `None` when it succeeded.
async fn refused(pool: &PgPool, sql: &str) -> Option<String> {
    match sqlx::query(sql).execute(pool).await {
        Ok(_) => None,
        Err(sqlx::Error::Database(error)) => Some(error.code().unwrap_or_default().into_owned()),
        Err(error) => Some(error.to_string()),
    }
}

const POD: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

/// One sealed CA row for `pod` with `ciphertext_bytes` of ciphertext.
fn ca(pod: &str, ciphertext_bytes: usize) -> String {
    format!(
        "INSERT INTO platform_interception_cas (pod_uid, pod_namespace, pod_name, \
         certificate_der, not_before, not_after, kek_provider, key_name, key_version, \
         wrapped_dek, wrapped_format, ciphertext, nonce, format) VALUES ('{pod}', 'sandboxes', \
         'workspace', '\\x30', now(), now() + interval '1 day', 'openbao-transit', \
         'codewire-credentials', 1, '\\x01', 1, decode(repeat('00', {ciphertext_bytes}), 'hex'), \
         decode(repeat('00', 12), 'hex'), 1)"
    )
}

fn binding(pod: &str, environment: &str) -> String {
    format!(
        "INSERT INTO sandbox_workspace_bindings(pod_uid, environment_id, namespace, pod_name, \
         claim_uid, sandbox_uid, operation_generation, managed_credential_clients, \
         credential_scope) VALUES ('{pod}', '{environment}', 'sandboxes', 'pod', \
         '{}', '{}', 7, '', 'environment')",
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4()
    )
}

/// The four functions: (name, whether it runs as its owner).
const FUNCTIONS: [(&str, bool); 6] = [
    ("codewire_interception_ca_lock", false),
    ("codewire_interception_ca_insert", true),
    ("codewire_interception_ca_immutable", false),
    ("codewire_interception_ca_attach", true),
    ("codewire_interception_ca_release", true),
    ("forget_interception_ca", true),
];

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn interception_cas_upgrade_holds_one_sealed_ca_per_pod_and_rolls_back() -> anyhow::Result<()>
{
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(31).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        sqlx::raw_sql(
            "INSERT INTO users (id, email) VALUES ('ca-admin', 'admin@example.test'); \
             INSERT INTO organizations (id, name, slug, created_by) VALUES \
               ('ca-org', 'CAs', 'ca-org', 'ca-admin'); \
             INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) VALUES \
               ('ca-preset', 'ca-org', 'Preset', 'ready', '{}'::jsonb); \
             INSERT INTO environments (id, org_id, created_by, type, preset_id, project_spec) VALUES \
               ('ca-env', 'ca-org', 'ca-admin', 'sandbox', 'ca-preset', '{}'::jsonb), \
               ('ca-other', 'ca-org', 'ca-admin', 'sandbox', 'ca-preset', '{}'::jsonb);",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;
        through(32).run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        // One row per Pod UID, a sealed key's length, an unbound Pod's row
        // with no environment.
        anyhow::ensure!(refused(&pool, &ca(POD, 154)).await.is_none());
        anyhow::ensure!(refused(&pool, &ca(POD, 154)).await.as_deref() == Some("23505"));
        anyhow::ensure!(refused(&pool, &ca("not-a-uid", 154)).await.as_deref() == Some("23514"));
        // The Pod's namespace and name are Kubernetes names.
        for bad in [
            ca(POD, 154).replace("'sandboxes'", "'Sandboxes'"),
            ca(POD, 154).replace("'workspace'", "'work_space'"),
            ca(POD, 154).replace("'workspace'", "''"),
        ] {
            let bad = bad.replace(POD, "3f2504e0-4f89-41d3-9a0c-0305e82c3301");
            anyhow::ensure!(refused(&pool, &bad).await.as_deref() == Some("23514"), "{bad}");
        }
        let other = "0f8fad5b-d9cb-469f-a165-70867728950e";
        anyhow::ensure!(refused(&pool, &ca(other, 16)).await.as_deref() == Some("23514"));
        let environment: Option<String> =
            sqlx::query_scalar("SELECT environment_id FROM platform_interception_cas")
                .fetch_one(&pool)
                .await?;
        anyhow::ensure!(environment.is_none());

        // The bind attaches it; the release deletes it.
        sqlx::query(&binding(POD, "ca-env")).execute(&pool).await?;
        let environment: Option<String> =
            sqlx::query_scalar("SELECT environment_id FROM platform_interception_cas")
                .fetch_one(&pool)
                .await?;
        anyhow::ensure!(environment.as_deref() == Some("ca-env"));
        sqlx::query(
            "UPDATE sandbox_workspace_bindings SET released_at = GREATEST(now(), bound_at) \
             WHERE pod_uid = $1",
        )
        .bind(POD)
        .execute(&pool)
        .await?;
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM platform_interception_cas")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(rows == 0);
        anyhow::ensure!(refused(&pool, &ca(POD, 154)).await.as_deref() == Some("23514"));

        // Destroying the environment deletes an attached row with it.
        sqlx::query(&ca(other, 154)).execute(&pool).await?;
        sqlx::query(&binding(other, "ca-other")).execute(&pool).await?;
        sqlx::query("DELETE FROM environments WHERE id = 'ca-other'")
            .execute(&pool)
            .await?;
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM platform_interception_cas")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(rows == 0);

        // PUBLIC holds nothing on the table or any function.
        let public: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.role_table_grants \
             WHERE table_name = 'platform_interception_cas' AND grantee = 'PUBLIC')",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(!public, "PUBLIC holds a privilege on interception CAs");
        for (name, definer) in FUNCTIONS {
            let (security_definer, config, source, public_execute): (
                bool,
                Option<Vec<String>>,
                String,
                bool,
            ) = sqlx::query_as(
                "SELECT p.prosecdef, p.proconfig, p.prosrc, \
                 has_function_privilege('public', p.oid, 'EXECUTE') \
                 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
                 WHERE n.nspname = 'public' AND p.proname = $1",
            )
            .bind(name)
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(security_definer == definer, "{name} runs as the wrong role");
            anyhow::ensure!(
                config.as_deref() == Some(&["search_path=pg_catalog, pg_temp".to_owned()][..]),
                "{name}'s search_path is not pinned: {config:?}"
            );
            anyhow::ensure!(!public_execute, "PUBLIC may execute {name}");
            // No dynamic SQL, and every relation named is this table, the
            // bindings or the lock.
            let lowered = source.to_lowercase();
            anyhow::ensure!(!lowered.contains("execute "), "{name} runs dynamic SQL");
            for word in lowered.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.')) {
                if let Some(relation) = word.strip_prefix("public.") {
                    anyhow::ensure!(
                        [
                            "platform_interception_cas",
                            "sandbox_workspace_bindings",
                            "codewire_interception_ca_lock"
                        ]
                        .contains(&relation),
                        "{name} names {relation}"
                    );
                }
            }
        }

        sqlx::raw_sql(
            "DROP TRIGGER codewire_interception_ca_attach ON sandbox_workspace_bindings; \
             DROP TRIGGER codewire_interception_ca_release ON sandbox_workspace_bindings; \
             DROP TABLE platform_interception_cas; \
             DROP FUNCTION forget_interception_ca(text); \
             DROP FUNCTION codewire_interception_ca_release(); \
             DROP FUNCTION codewire_interception_ca_attach(); \
             DROP FUNCTION codewire_interception_ca_immutable(); \
             DROP FUNCTION codewire_interception_ca_insert(); \
             DROP FUNCTION codewire_interception_ca_lock(text);",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
