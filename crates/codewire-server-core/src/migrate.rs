//! Standard SQLx migration entrypoint shared by the Rust services.

use anyhow::Context;
use sqlx::migrate::Migrator;
use sqlx::{Connection, PgConnection};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Return the single embedded application-schema migration history.
///
/// Services that must validate the accepted SQLx ledger use this accessor
/// instead of embedding a second migration path.
pub fn application_migrator() -> &'static Migrator {
    &MIGRATOR
}

/// Apply the immutable application migration history.
///
/// SQLx owns the migration table, advisory lock, ordering, checksums, dirty
/// state, and transaction boundaries. Keep this function as a thin entrypoint;
/// schema inference and migration-ledger repair do not belong in services.
pub async fn ensure_schema(database_url: &str) -> anyhow::Result<()> {
    let mut connection = PgConnection::connect(database_url)
        .await
        .context("connect for SQLx database migrations")?;
    application_migrator()
        .run(&mut connection)
        .await
        .context("run SQLx database migrations")?;
    connection
        .close()
        .await
        .context("close SQLx migration connection")?;
    Ok(())
}

/// Apply migrations and expose a clear startup boundary in service logs.
pub async fn ensure_schema_logged(database_url: &str) -> anyhow::Result<()> {
    tracing::info!("ensuring database schema");
    ensure_schema(database_url).await?;
    tracing::info!("database schema ready");
    Ok(())
}

#[cfg(test)]
mod tests {
    mod account_deletion;
    mod account_deletion_initiator;
    mod billing_rate_cards;
    mod confidential_activation_slots;
    mod default_access_profile;
    mod environment_error_code;
    mod environment_mesh;
    mod environment_quota_defaults;
    mod environment_source_snapshot;
    mod feedback;
    mod host_operations;
    mod hosted_snapshots;
    mod hosts;
    mod invite_only_sign_up;
    mod network_policies;
    mod oauth_sign_in;
    mod oidc_consumed_refresh_tokens;
    mod org_invitation_emails;
    mod organization_confidential_environments;
    mod organization_dedicated_cpu;
    mod owner_sources;
    mod preview_browser;
    mod rate_limit_settings;
    mod resend_verification_purpose;
    mod reserve_legal_page_slugs;
    mod runtime_dispatch_scope;
    mod session_mutation;
    mod signup_credit_setting;
    mod ssh;
    mod ssh_host_keys;
    mod two_factor_replacements;
    mod user_cli_sign_in;
    mod workspace_binding;
    use std::time::Duration;

    use sha2::{Digest, Sha384};
    use sqlx::{PgPool, postgres::PgPoolOptions};

    use super::*;

    // Measured on disposable PostgreSQL from the full history: the baseline
    // (which equals the 41-migration history it replaced) and 0002 to 0026.
    const ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT: &str =
        "7255e2a6736bb2553b838eb2b307f49222c485d95372da2d995ef42c2b2ff959";
    // SHA-384 of 0001_baseline.sql. A change to the baseline is a change to
    // every database that already applied it; later schema changes are new
    // migrations.
    const APPLIED_BASELINE_CHECKSUM: &str = "b7977e9e949c128762a0a357a1ed3d7ba910f5003bdc23a249a3ec24a3610aef6c1030101b5a2441dfdf9dbeb3b3ff4f";
    // SHA-384 of 0002_environment_mesh_attachment.sql (#3350).
    const APPLIED_ENVIRONMENT_MESH_CHECKSUM: &str = "1580d3734456d7e5ef52527fb29e286529be4df083d5e5884db1ec59570609026ed0d70c0cdba61da5fe1baeaa70cfaa";
    // SHA-384 of 0003_default_access_profile.sql (#3550).
    const APPLIED_DEFAULT_ACCESS_PROFILE_CHECKSUM: &str = "729b64927ce42848db8f5a96d8a15845d50232f8dfccc409618974cad9f1c87e964b2416e5da27cf126273f10000c0cd";
    // SHA-384 of 0004_environment_quota_defaults.sql (#3583).
    const APPLIED_ENVIRONMENT_QUOTA_DEFAULTS_CHECKSUM: &str = "4c28b1cb4809bd52472e999eaf8693d840036cb096ad94bef2782ef599c1010ed5fc247d04ef62ef65da8a61d7e53189";
    // SHA-384 of 0005_organization_confidential_environments.sql (#2497).
    const APPLIED_ORGANIZATION_CONFIDENTIAL_CHECKSUM: &str = "acb8d45a0ff44e775eeb1e34f87f6f2e01011e78790ac341e3a7e44b45d303046f8481706f2078eeef6b96bbff7d2047";
    // SHA-384 of 0006_billing_rate_cards.sql (#3381).
    const APPLIED_BILLING_RATE_CARDS_CHECKSUM: &str = "c8ff676f48fe8ce0b9b9a60070996cfeb9e43bdb065532fe54564bbb2b738a52629af8ab4602079737181ba7c0be9a49";
    // SHA-384 of 0007_account_deletion.sql (#3679).
    const APPLIED_ACCOUNT_DELETION_CHECKSUM: &str = "2b75e286fd87195ac1637b18f50b8d5dc602ee3eafcf09b7c2e4497cc3147ac5221ec9265aad6f46ced75501df0e0ce5";

    // SHA-384 of 0008_organization_dedicated_cpu.sql (#3635).
    const APPLIED_ORGANIZATION_DEDICATED_CPU_CHECKSUM: &str = "60d10bbbe5d559f31ee792693b94e71c78677cdcc4ef39768281655486ffedfcfad95a30145208e1f2c9ad6627263fe8";

    // SHA-384 of 0009_hosted_snapshots.sql (#3046).
    const APPLIED_HOSTED_SNAPSHOTS_CHECKSUM: &str = "ca4e72846fc159e91a1fafb505a6253ba211790b8acc665fbe04e675dd727dadfd98cd06e560a216cae8deab9d8ed5bf";

    // SHA-384 of 0010_environment_source_snapshot.sql (#3046).
    const APPLIED_ENVIRONMENT_SOURCE_SNAPSHOT_CHECKSUM: &str = "757bd0253e49b76952d2b54ed3a7f9af32adcb454661aed33042a24c2e05e039a5d5be2c18f3eff954100154142766c3";

    // SHA-384 of 0011_environment_error_code.sql (#3635).
    const APPLIED_ENVIRONMENT_ERROR_CODE_CHECKSUM: &str = "b6cf1988b8d51f6d4b37d485e4bb51328e17d3acf0602504c2ba5e716afe4e50f205c6d33422c723ddfa02dcefcae13d";

    // SHA-384 of 0012_signup_credit_setting.sql (#3381).
    const APPLIED_SIGNUP_CREDIT_SETTING_CHECKSUM: &str = "8cf73e83d985a84859354a789134c853940e969d262b5e648c251daa8b520ef84a8d53e8bba238574ee20ea165119741";

    // SHA-384 of 0013_feedback.sql (#4061).
    const APPLIED_FEEDBACK_CHECKSUM: &str = "84b91df55fdd5bc3579b1f5c4317568bcdc199d2081b3f329937b848e33988465586f13fe7ec46e5286863d91da47108";

    // SHA-384 of 0014_user_cli_sign_in.sql (Get started checklist, owner
    // 2026-11-10).
    const APPLIED_USER_CLI_SIGN_IN_CHECKSUM: &str = "e14f098ce3c4cd9d032047c1ee29285a856536c97d5528aa805ebb77ea6ba9ac77965121d564b6c0e042e4fdeb299c4a";

    // SHA-384 of 0015_hosts.sql (#3609).
    const APPLIED_HOSTS_CHECKSUM: &str = "2f3a94dd113b5f2ae08d352f10093f0a352c100b0414da65d0326e0d433db4eb27a4e75c6c06d9033b8e4c8869a20b11";

    // SHA-384 of 0016_oauth_sign_in.sql (#4062).
    const APPLIED_OAUTH_SIGN_IN_CHECKSUM: &str = "869731a7fb4588c584032c5a239596e0182867bcea7d5af3fe3c361b50627390b06fe6ddb6b9ed3fc2fd43252fc70457";

    // SHA-384 of 0017_reserve_legal_page_slugs.sql (the public /privacy and
    // /terms pages).
    const APPLIED_RESERVE_LEGAL_PAGE_SLUGS_CHECKSUM: &str = "cf4af5d327730d2435d300c0b7bea3c7d3b9c389d5b6552ecf266b01ef953795a8263b1aa08bca5fef9fd12e68f11bea";

    // SHA-384 of 0018_confidential_activation_slots.sql (#4281).
    const APPLIED_CONFIDENTIAL_ACTIVATION_SLOTS_CHECKSUM: &str = "ead3d33957e48430244fca9215827bc76899f840480b8df795cb1d3afbe6087021d977fe06204db25a5dd805a4d5a59e";

    // SHA-384 of 0019_resend_verification_purpose.sql (#4322).
    const APPLIED_RESEND_VERIFICATION_PURPOSE_CHECKSUM: &str = "8bcd5d0e0f1739393232fb0dc2fa737f31c71edc753feb69aea40368e246cf7e29b2e2c3161fd3a4033fdff16f4e4711";

    // SHA-384 of 0020_oidc_consumed_refresh_tokens.sql.
    const APPLIED_OIDC_CONSUMED_REFRESH_TOKENS_CHECKSUM: &str = "40ba4f98317550bcd65b8f1cc1bfc710457652f1eaab2e388de08d49d26091f4e138848b2a75e5907e98dff70975bafa";

    // SHA-384 of 0021_org_invitation_emails.sql (#3847).
    const APPLIED_ORG_INVITATION_EMAILS_CHECKSUM: &str = "049767700a5a4f914d6031c532423842a720d2b1b90cf20a95250db3810d954eb0fe25dcda61878c626af7f493cd3485";
    // SHA-384 of 0022_rate_limit_settings.sql (#3297).
    const APPLIED_RATE_LIMIT_SETTINGS_CHECKSUM: &str = "577f30add81a0745385c6c74cef04e52ce2dd9057018cf5ceb9ba5841e4ea93f159c971cb80dd081225f7d4be24d18bb";
    // SHA-384 of 0023_invite_only_sign_up.sql (#4121).
    const APPLIED_INVITE_ONLY_SIGN_UP_CHECKSUM: &str = "0d29a3cd63e528e7948271c704451f4d80d7eed6b4d48127407cef12d41945163367cea5b5cb7513842c45d039558e5e";
    // SHA-384 of 0024_account_deletion_initiator.sql (#4541).
    const APPLIED_ACCOUNT_DELETION_INITIATOR_CHECKSUM: &str = "346922afaa78226b36b08669ec9f693fdfc3722bf0b2b377b048c0e986761526ac9eae29bc57216dfbdb9fdf7c340298";
    // SHA-384 of 0025_platform_network_policies.sql (#4000).
    const APPLIED_NETWORK_POLICIES_CHECKSUM: &str = "67288f134a1f317b753e94fb84201daf0f23159db9a2847df8a5a4053533df08e0a7dbaefe1da77ca0c2d6cffb1009ce";

    // SHA-384 of 0026_host_operations.sql (#3609).
    const APPLIED_HOST_OPERATIONS_CHECKSUM: &str = "232e295da610657e51ec588699ca5ab53b75d28b7a1536e25737bf11d4edb8eba80046e9f63299c6edf74fe424ff997b";

    async fn startup(database_url: String) -> anyhow::Result<()> {
        ensure_schema(&database_url).await
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn account_access_disable_and_predecessor_issuance_serialize_in_both_orders()
    -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            ensure_schema(&test_db.url).await?;
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&test_db.url)
                .await?;

            for (label, disable_first) in [("issuer-first", false), ("disable-first", true)] {
                let user_id = format!("account-access-concurrent-{label}");
                let session_id = format!("account-access-concurrent-session-{label}");
                let token_hash = if disable_first {
                    "a".repeat(64)
                } else {
                    "b".repeat(64)
                };
                sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
                    .bind(&user_id)
                    .bind(format!("{user_id}@example.test"))
                    .execute(&pool)
                    .await?;

                if disable_first {
                    let mut disable = pool.begin().await?;
                    let disable_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                        .fetch_one(&mut *disable)
                        .await?;
                    sqlx::query("UPDATE users SET enabled = false WHERE id = $1")
                        .bind(&user_id)
                        .execute(&mut *disable)
                        .await?;

                    let issuer_pool = pool.clone();
                    let issuer_user = user_id.clone();
                    let issuer_session = session_id.clone();
                    let issuer_hash = token_hash.clone();
                    let (pid_tx, pid_rx) = tokio::sync::oneshot::channel();
                    let issuer = tokio::spawn(async move {
                        let mut tx = issuer_pool.begin().await?;
                        let issuer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                            .fetch_one(&mut *tx)
                            .await?;
                        let _ = pid_tx.send(issuer_pid);
                        let insert = sqlx::query(
                            "INSERT INTO sessions (id, user_id, token_hash, expires_at) \
                             VALUES ($1, $2, $3, NOW() + interval '1 hour')",
                        )
                        .bind(issuer_session)
                        .bind(issuer_user)
                        .bind(issuer_hash)
                        .execute(&mut *tx)
                        .await;
                        let error_code = insert
                            .as_ref()
                            .err()
                            .and_then(|error| error.as_database_error())
                            .and_then(|error| error.code())
                            .map(|code| code.into_owned());
                        tx.rollback().await?;
                        anyhow::Ok(error_code)
                    });
                    wait_for_lock_blocker(&pool, pid_rx.await?, disable_pid).await?;
                    disable.commit().await?;
                    anyhow::ensure!(
                        issuer.await??.as_deref() == Some("28000"),
                        "predecessor issuer succeeded after disable in {label}"
                    );
                } else {
                    let mut issuer = pool.begin().await?;
                    let issuer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                        .fetch_one(&mut *issuer)
                        .await?;
                    sqlx::query(
                        "INSERT INTO sessions (id, user_id, token_hash, expires_at) \
                         VALUES ($1, $2, $3, NOW() + interval '1 hour')",
                    )
                    .bind(&session_id)
                    .bind(&user_id)
                    .bind(&token_hash)
                    .execute(&mut *issuer)
                    .await?;

                    let disable_pool = pool.clone();
                    let disable_user = user_id.clone();
                    let (pid_tx, pid_rx) = tokio::sync::oneshot::channel();
                    let disable = tokio::spawn(async move {
                        let mut tx = disable_pool.begin().await?;
                        let disable_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                            .fetch_one(&mut *tx)
                            .await?;
                        let _ = pid_tx.send(disable_pid);
                        sqlx::query("UPDATE users SET enabled = false WHERE id = $1")
                            .bind(disable_user)
                            .execute(&mut *tx)
                            .await?;
                        tx.commit().await?;
                        anyhow::Ok(())
                    });
                    wait_for_lock_blocker(&pool, pid_rx.await?, issuer_pid).await?;
                    issuer.commit().await?;
                    disable.await??;
                }

                let sessions: i64 =
                    sqlx::query_scalar("SELECT count(*) FROM sessions WHERE user_id = $1")
                        .bind(&user_id)
                        .fetch_one(&pool)
                        .await?;
                anyhow::ensure!(
                    sessions == 0,
                    "disable/issuer order retained a session in {label}"
                );
            }
            pool.close().await;
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn account_access_disable_serializes_existing_capability_updates_in_both_orders()
    -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            ensure_schema(&test_db.url).await?;
            let pool = PgPoolOptions::new()
                .max_connections(6)
                .connect(&test_db.url)
                .await?;

            for (capability_index, (capability, update_sql)) in [
                (
                    "session",
                    "UPDATE sessions SET updated_at = NOW() WHERE id = $1",
                ),
                (
                    "api-key-touch",
                    "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1",
                ),
            ]
            .into_iter()
            .enumerate()
            {
                for (order_index, (order, update_first)) in
                    [("update-first", true), ("disable-first", false)]
                        .into_iter()
                        .enumerate()
                {
                    let suffix = format!("{capability_index}-{order_index}");
                    let user_id = format!("account-access-existing-update-user-{suffix}");
                    let organization_id = format!("account-access-update-org-{suffix}");
                    let session_id = format!("account-access-existing-update-session-{suffix}");
                    let api_key_id = format!("account-access-existing-update-api-key-{suffix}");
                    let update_id = if capability == "session" {
                        session_id.clone()
                    } else {
                        api_key_id.clone()
                    };
                    let token_hash = format!("{:064x}", suffix.len());
                    let key_hash = format!("{:064x}", suffix.len() + 1);
                    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
                        .bind(&user_id)
                        .bind(format!("{user_id}@example.test"))
                        .execute(&pool)
                        .await?;
                    sqlx::query(
                        "INSERT INTO organizations (id, name, slug, created_by) \
                         VALUES ($1, $2, $3, $4)",
                    )
                    .bind(&organization_id)
                    .bind(format!("Account Access Existing Update {suffix}"))
                    .bind(&organization_id)
                    .bind(&user_id)
                    .execute(&pool)
                    .await?;
                    sqlx::query(
                        "INSERT INTO sessions (id, user_id, token_hash, expires_at) \
                         VALUES ($1, $2, $3, NOW() + interval '1 hour')",
                    )
                    .bind(&session_id)
                    .bind(&user_id)
                    .bind(&token_hash)
                    .execute(&pool)
                    .await?;
                    sqlx::query(
                        "INSERT INTO api_keys (id, user_id, org_id, name, key_hash, key_prefix, scopes) \
                         VALUES ($1, $2, $3, 'Existing update key', $4, $5, ARRAY[]::text[])",
                    )
                    .bind(&api_key_id)
                    .bind(&user_id)
                    .bind(&organization_id)
                    .bind(&key_hash)
                    .bind(format!("update-{suffix}"))
                    .execute(&pool)
                    .await?;

                    if update_first {
                        let mut update = pool.begin().await?;
                        let update_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                            .fetch_one(&mut *update)
                            .await?;
                        sqlx::query(update_sql)
                            .bind(&update_id)
                            .execute(&mut *update)
                            .await?;

                        let disable_pool = pool.clone();
                        let disable_user = user_id.clone();
                        let (pid_tx, pid_rx) = tokio::sync::oneshot::channel();
                        let disable = tokio::spawn(async move {
                            let mut tx = disable_pool.begin().await?;
                            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                                .fetch_one(&mut *tx)
                                .await?;
                            let _ = pid_tx.send(pid);
                            sqlx::query("UPDATE users SET enabled = false WHERE id = $1")
                                .bind(disable_user)
                                .execute(&mut *tx)
                                .await?;
                            tx.commit().await?;
                            anyhow::Ok(())
                        });
                        wait_for_lock_blocker(&pool, pid_rx.await?, update_pid).await?;
                        update.commit().await?;
                        disable.await??;
                    } else {
                        let mut disable = pool.begin().await?;
                        let disable_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                            .fetch_one(&mut *disable)
                            .await?;
                        sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
                            .bind(&user_id)
                            .fetch_one(&mut *disable)
                            .await?;
                        if update_waits_on(&pool, update_sql, &update_id, disable_pid).await? {
                            disable.rollback().await?;
                            anyhow::bail!(
                                "ordinary {capability} update waited on the account lock in {order}"
                            );
                        }
                        sqlx::query("UPDATE users SET enabled = false WHERE id = $1")
                            .bind(&user_id)
                            .execute(&mut *disable)
                            .await?;
                        disable.commit().await?;
                    }

                    let sessions: i64 = sqlx::query_scalar(
                        "SELECT count(*) FROM sessions WHERE user_id = $1",
                    )
                    .bind(&user_id)
                    .fetch_one(&pool)
                    .await?;
                    let api_key_disabled: bool = sqlx::query_scalar(
                        "SELECT disabled_at IS NOT NULL FROM api_keys WHERE id = $1",
                    )
                    .bind(&api_key_id)
                    .fetch_one(&pool)
                    .await?;
                    anyhow::ensure!(
                        sessions == 0 && api_key_disabled,
                        "disablement did not revoke existing {capability} update state in {order}"
                    );
                }
            }

            // Control: a statement that does take the account lock is reported
            // as waiting on it, so the check above cannot pass vacuously.
            let user_id = "account-access-existing-update-user-control";
            sqlx::query("INSERT INTO users (id, email) VALUES ($1, $1 || '@example.test')")
                .bind(user_id)
                .execute(&pool)
                .await?;
            let mut disable = pool.begin().await?;
            let disable_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *disable)
                .await?;
            sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
                .bind(user_id)
                .fetch_one(&mut *disable)
                .await?;
            let waited = update_waits_on(
                &pool,
                "SELECT id FROM users WHERE id = $1 FOR KEY SHARE",
                user_id,
                disable_pid,
            )
            .await;
            disable.rollback().await?;
            anyhow::ensure!(waited?, "an account-lock wait was not reported");
            pool.close().await;
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn account_access_transition_guards_avoid_predecessor_deadlocks_in_both_orders()
    -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            ensure_schema(&test_db.url).await?;
            let pool = PgPoolOptions::new()
                .max_connections(8)
                .connect(&test_db.url)
                .await?;
            let client_id = "account-access-transition-client";
            sqlx::query(
                "INSERT INTO oidc_clients (id, name, application_type, auth_method, redirect_uris) \
                 VALUES ($1, 'Account transition guard', 'native', 'none', \
                         ARRAY['https://account-access.example.test/callback'])",
            )
            .bind(client_id)
            .execute(&pool)
            .await?;

            for (label, transition_first) in [
                ("authorization-request-transition-first", true),
                ("authorization-request-disable-first", false),
            ] {
                let user_id = format!("account-access-transition-user-{label}");
                let request_id = format!("account-access-transition-request-{label}");
                sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
                    .bind(&user_id)
                    .bind(format!("{user_id}@example.test"))
                    .execute(&pool)
                    .await?;
                sqlx::query(
                    "INSERT INTO oidc_auth_requests (id, client_id, scopes, redirect_uri, expires_at) \
                     VALUES ($1, $2, ARRAY['openid'], \
                             'https://account-access.example.test/callback', \
                             NOW() + interval '10 minutes')",
                )
                .bind(&request_id)
                .bind(client_id)
                .execute(&pool)
                .await?;

                if transition_first {
                    let mut transition = pool.begin().await?;
                    let transition_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                        .fetch_one(&mut *transition)
                        .await?;
                    sqlx::query(
                        "UPDATE oidc_auth_requests \
                         SET user_id = $1, auth_time = NOW(), done = true WHERE id = $2",
                    )
                    .bind(&user_id)
                    .bind(&request_id)
                    .execute(&mut *transition)
                    .await?;

                    let disable_pool = pool.clone();
                    let disable_user = user_id.clone();
                    let (pid_tx, pid_rx) = tokio::sync::oneshot::channel();
                    let disable = tokio::spawn(async move {
                        let mut tx = disable_pool.begin().await?;
                        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                            .fetch_one(&mut *tx)
                            .await?;
                        let _ = pid_tx.send(pid);
                        sqlx::query("UPDATE users SET enabled = false WHERE id = $1")
                            .bind(disable_user)
                            .execute(&mut *tx)
                            .await?;
                        tx.commit().await?;
                        anyhow::Ok(())
                    });
                    wait_for_lock_blocker(&pool, pid_rx.await?, transition_pid).await?;
                    transition.commit().await?;
                    disable.await??;
                    let retained: i64 = sqlx::query_scalar(
                        "SELECT count(*) FROM oidc_auth_requests WHERE user_id = $1",
                    )
                    .bind(&user_id)
                    .fetch_one(&pool)
                    .await?;
                    anyhow::ensure!(
                        retained == 0,
                        "disablement retained predecessor authorization-request state in {label}"
                    );
                } else {
                    let mut disable = pool.begin().await?;
                    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
                        .bind(&user_id)
                        .fetch_one(&mut *disable)
                        .await?;
                    let transition_pool = pool.clone();
                    let transition_user = user_id.clone();
                    let transition_request = request_id.clone();
                    let transition = tokio::spawn(async move {
                        let mut tx = transition_pool.begin().await?;
                        let result = sqlx::query(
                            "UPDATE oidc_auth_requests \
                             SET user_id = $1, auth_time = NOW(), done = true WHERE id = $2",
                        )
                        .bind(transition_user)
                        .bind(transition_request)
                        .execute(&mut *tx)
                        .await;
                        let code = result
                            .as_ref()
                            .err()
                            .and_then(|error| error.as_database_error())
                            .and_then(|error| error.code())
                            .map(|code| code.into_owned());
                        tx.rollback().await?;
                        anyhow::Ok(code)
                    });
                    let code = tokio::time::timeout(Duration::from_millis(500), transition)
                        .await
                        .context("predecessor authorization-request transition waited on disablement")???;
                    anyhow::ensure!(
                        code.as_deref() == Some("55P03"),
                        "predecessor authorization-request transition returned {code:?} instead of 55P03"
                    );
                    sqlx::query("UPDATE users SET enabled = false WHERE id = $1")
                        .bind(&user_id)
                        .execute(&mut *disable)
                        .await?;
                    disable.commit().await?;
                    let state: (Option<String>, bool) = sqlx::query_as(
                        "SELECT user_id, done FROM oidc_auth_requests WHERE id = $1",
                    )
                    .bind(&request_id)
                    .fetch_one(&pool)
                    .await?;
                    anyhow::ensure!(
                        state == (None, false),
                        "disablement-first authorization-request transition changed state: {state:?}"
                    );
                }

                sqlx::query("DELETE FROM oidc_auth_requests WHERE id = $1")
                    .bind(&request_id)
                    .execute(&pool)
                    .await?;
                sqlx::query("DELETE FROM users WHERE id = $1")
                    .bind(&user_id)
                    .execute(&pool)
                    .await?;
            }

            for (label, transition_first) in [
                ("api-key-transition-first", true),
                ("api-key-disable-first", false),
            ] {
                let user_id = format!("account-access-api-key-transition-user-{label}");
                let organization_id = format!("account-access-api-key-transition-org-{label}");
                let organization_slug = format!("account-access-key-{label}");
                let key_id = format!("account-access-api-key-transition-key-{label}");
                let key_hash = if transition_first {
                    "f".repeat(64)
                } else {
                    "e".repeat(64)
                };
                sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
                    .bind(&user_id)
                    .bind(format!("{user_id}@example.test"))
                    .execute(&pool)
                    .await?;
                sqlx::query(
                    "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $2, $3, $4)",
                )
                .bind(&organization_id)
                .bind(format!("Account access API key transition {label}"))
                .bind(&organization_slug)
                .bind(&user_id)
                .execute(&pool)
                .await?;
                sqlx::query(
                    "INSERT INTO api_keys \
                     (id, user_id, org_id, name, key_hash, key_prefix, scopes, disabled_at) \
                     VALUES ($1, $2, $3, 'Transition key', $4, $5, ARRAY[]::text[], NOW())",
                )
                .bind(&key_id)
                .bind(&user_id)
                .bind(&organization_id)
                .bind(&key_hash)
                .bind(format!("transition-{label}"))
                .execute(&pool)
                .await?;

                if transition_first {
                    let mut transition = pool.begin().await?;
                    let transition_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                        .fetch_one(&mut *transition)
                        .await?;
                    sqlx::query("UPDATE api_keys SET disabled_at = NULL WHERE id = $1")
                        .bind(&key_id)
                        .execute(&mut *transition)
                        .await?;

                    let disable_pool = pool.clone();
                    let disable_user = user_id.clone();
                    let (pid_tx, pid_rx) = tokio::sync::oneshot::channel();
                    let disable = tokio::spawn(async move {
                        let mut tx = disable_pool.begin().await?;
                        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                            .fetch_one(&mut *tx)
                            .await?;
                        let _ = pid_tx.send(pid);
                        sqlx::query("UPDATE users SET enabled = false WHERE id = $1")
                            .bind(disable_user)
                            .execute(&mut *tx)
                            .await?;
                        tx.commit().await?;
                        anyhow::Ok(())
                    });
                    wait_for_lock_blocker(&pool, pid_rx.await?, transition_pid).await?;
                    transition.commit().await?;
                    disable.await??;
                } else {
                    let mut disable = pool.begin().await?;
                    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
                        .bind(&user_id)
                        .fetch_one(&mut *disable)
                        .await?;
                    let transition_pool = pool.clone();
                    let transition_key = key_id.clone();
                    let transition = tokio::spawn(async move {
                        let mut tx = transition_pool.begin().await?;
                        let result = sqlx::query("UPDATE api_keys SET disabled_at = NULL WHERE id = $1")
                            .bind(transition_key)
                            .execute(&mut *tx)
                            .await;
                        let code = result
                            .as_ref()
                            .err()
                            .and_then(|error| error.as_database_error())
                            .and_then(|error| error.code())
                            .map(|code| code.into_owned());
                        tx.rollback().await?;
                        anyhow::Ok(code)
                    });
                    let code = tokio::time::timeout(Duration::from_millis(500), transition)
                        .await
                        .context("predecessor API-key reactivation waited on disablement")???;
                    anyhow::ensure!(
                        code.as_deref() == Some("55P03"),
                        "predecessor API-key reactivation returned {code:?} instead of 55P03"
                    );
                    sqlx::query("UPDATE users SET enabled = false WHERE id = $1")
                        .bind(&user_id)
                        .execute(&mut *disable)
                        .await?;
                    disable.commit().await?;
                }

                let retired: (bool, bool) = sqlx::query_as(
                    "SELECT disabled_at IS NOT NULL, \
                            expires_at IS NOT NULL AND expires_at <= clock_timestamp() \
                     FROM api_keys WHERE id = $1",
                )
                .bind(&key_id)
                .fetch_one(&pool)
                .await?;
                anyhow::ensure!(
                    retired == (true, true),
                    "disablement did not permanently retire predecessor API key in {label}"
                );
                sqlx::query("DELETE FROM api_keys WHERE id = $1")
                    .bind(&key_id)
                    .execute(&pool)
                    .await?;
                sqlx::query("DELETE FROM organizations WHERE id = $1")
                    .bind(&organization_id)
                    .execute(&pool)
                    .await?;
                sqlx::query("DELETE FROM users WHERE id = $1")
                    .bind(&user_id)
                    .execute(&pool)
                    .await?;
            }

            sqlx::query("DELETE FROM oidc_clients WHERE id = $1")
                .bind(client_id)
                .execute(&pool)
                .await?;
            pool.close().await;
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn platform_credentials_schema_fences_owners_names_envelopes_and_generations()
    -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            ensure_schema(&test_db.url).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            assert_platform_credential_schema(&pool).await?;
            seed_platform_credential_owners(&pool).await?;
            for (id, user_id, organization_id) in [
                ("user-a", Some("credential-user-a"), None),
                ("user-b", Some("credential-user-b"), None),
                ("org-a", None, Some("credential-org-a")),
                ("org-b", None, Some("credential-org-b")),
            ] {
                // Identical names are valid in different user/org scopes.
                seed_platform_credential(&pool, id, user_id, organization_id, "Work").await?;
                seed_platform_credential_material(&pool, id, 1).await?;
            }
            seed_platform_credential(&pool, "user-extra", Some("credential-user-a"), None, "Other").await?;
            seed_platform_credential(&pool, "org-extra", None, Some("credential-org-a"), "Other").await?;
            for query in [
                "UPDATE platform_credentials SET display_name = 'wOrK' WHERE id = 'user-extra'",
                "UPDATE platform_credentials SET display_name = 'wOrK' WHERE id = 'org-extra'",
            ] {
                assert_platform_credential_rejected(&pool, query, "23505").await?;
            }
            for assignment in [
                "user_id = NULL",
                "organization_id = 'credential-org-a'",
                "authentication_kind = 'unsupported'",
                "status = 'unsupported'",
                "display_name = ''",
                "display_name = repeat('x', 257)",
                "display_name = repeat('é', 129)",
                "account_hint = ''",
                "account_hint = repeat('x', 257)",
                "account_hint = repeat('é', 129)",
                "expires_at_unix = -1",
                "revocation_generation = 0",
                "revocation_generation = -1",
                "material_generation = 0",
                "material_generation = -1",
            ] {
                assert_platform_credential_rejected(
                    &pool,
                    &format!("UPDATE platform_credentials SET {assignment} WHERE id = 'user-a'"),
                    "23514",
                ).await?;
            }
            for assignment in ["user_id = 'absent-user'", "material_generation = 2"] {
                assert_platform_credential_rejected(
                    &pool,
                    &format!("UPDATE platform_credentials SET {assignment} WHERE id = 'user-a'"),
                    "23503",
                ).await?;
            }
            for column in [
                "id", "provider", "authentication_kind", "display_name", "status",
                "revocation_generation", "material_generation", "created_at", "updated_at",
            ] {
                assert_platform_credential_rejected(
                    &pool,
                    &format!("UPDATE platform_credentials SET {column} = NULL WHERE id = 'user-a'"),
                    "23502",
                ).await?;
            }
            assert_platform_credential_rejected(
                &pool,
                "UPDATE platform_credentials SET organization_id = 'absent-org' WHERE id = 'org-a'",
                "23503",
            ).await?;
            for kind in ["oauth", "api_key", "access_token", "github_app"] {
                sqlx::query("UPDATE platform_credentials SET authentication_kind = $1 WHERE id = 'user-a'")
                    .bind(kind).execute(&pool).await?;
            }
            for status in ["active", "expired", "refresh_failed", "revoked"] {
                sqlx::query("UPDATE platform_credentials SET status = $1 WHERE id = 'user-a'")
                    .bind(status).execute(&pool).await?;
            }
            sqlx::query("UPDATE platform_credentials SET expires_at_unix = 0 WHERE id = 'user-a'")
                .execute(&pool).await?;
            sqlx::query("UPDATE platform_credentials SET expires_at_unix = NULL WHERE id = 'user-a'")
                .execute(&pool).await?;
            sqlx::query(
                "UPDATE platform_credentials SET display_name = repeat('é', 128), \
                 account_hint = repeat('é', 128) WHERE id = 'user-a'",
            ).execute(&pool).await?;

            for assignment in [
                "material_generation = 0",
                "kek_provider = 'unsupported'",
                "key_version = 0",
                "key_version = -1",
                "key_version = 4294967296",
                "wrapped_dek = decode('', 'hex')",
                "wrapped_dek = decode(repeat('00', 65537), 'hex')",
                "wrapped_format = 0",
                "wrapped_format = 2",
                "ciphertext = decode(repeat('00', 15), 'hex')",
                "ciphertext = decode(repeat('00', 1048593), 'hex')",
                "nonce = decode(repeat('00', 11), 'hex')",
                "nonce = decode(repeat('00', 13), 'hex')",
                "format = 0",
                "format = 2",
            ] {
                assert_platform_credential_rejected(
                    &pool,
                    &format!("UPDATE platform_credential_material SET {assignment} WHERE credential_id = 'user-a'"),
                    "23514",
                ).await?;
            }
            for assignment in ["material_generation = 2", "credential_id = 'absent-credential'"] {
                assert_platform_credential_rejected(
                    &pool,
                    &format!("UPDATE platform_credential_material SET {assignment} WHERE credential_id = 'user-a'"),
                    "23503",
                ).await?;
            }
            for column in [
                "credential_id", "material_generation", "kek_provider", "key_name", "key_version",
                "wrapped_dek", "wrapped_format", "ciphertext", "nonce", "format",
            ] {
                assert_platform_credential_rejected(
                    &pool,
                    &format!("UPDATE platform_credential_material SET {column} = NULL WHERE credential_id = 'user-a'"),
                    "23502",
                ).await?;
            }
            assert_platform_credential_rejected(
                &pool,
                "INSERT INTO platform_credential_material SELECT * \
                 FROM platform_credential_material WHERE credential_id = 'user-a'",
                "23505",
            ).await?;
            sqlx::query(
                "UPDATE platform_credential_material SET key_version = 4294967295, \
                 wrapped_dek = decode(repeat('00', 65536), 'hex'), \
                 ciphertext = decode(repeat('00', 1048592), 'hex') WHERE credential_id = 'user-a'",
            ).execute(&pool).await?;

            // A failed or cancelled replacement must retain the old complete
            // pair; the successful sequence needs no deferred FK or trigger.
            let mut replacement = pool.begin().await?;
            sqlx::query("DELETE FROM platform_credential_material WHERE credential_id = 'user-b'")
                .execute(&mut *replacement).await?;
            sqlx::query("UPDATE platform_credentials SET material_generation = 2 WHERE id = 'user-b'")
                .execute(&mut *replacement).await?;
            replacement.rollback().await?;
            let generations: (i64, i64) = sqlx::query_as(
                "SELECT c.material_generation, m.material_generation FROM platform_credentials c \
                 JOIN platform_credential_material m ON m.credential_id = c.id WHERE c.id = 'user-b'",
            ).fetch_one(&pool).await?;
            anyhow::ensure!(generations == (1, 1), "rolled-back replacement changed stored generations");
            let mut replacement = pool.begin().await?;
            sqlx::query("DELETE FROM platform_credential_material WHERE credential_id = 'user-b'")
                .execute(&mut *replacement).await?;
            sqlx::query("UPDATE platform_credentials SET material_generation = 2 WHERE id = 'user-b'")
                .execute(&mut *replacement).await?;
            sqlx::query(
                "INSERT INTO platform_credential_material \
                 (credential_id, material_generation, kek_provider, key_name, key_version, \
                  wrapped_dek, wrapped_format, ciphertext, nonce, format) \
                 VALUES ('user-b', 2, 'openbao-transit', 'credential-key', 1, \
                         decode('01', 'hex'), 1, decode(repeat('00', 16), 'hex'), \
                         decode(repeat('00', 12), 'hex'), 1)",
            ).execute(&mut *replacement).await?;
            replacement.commit().await?;
            let generations: (i64, i64) = sqlx::query_as(
                "SELECT c.material_generation, m.material_generation FROM platform_credentials c \
                 JOIN platform_credential_material m ON m.credential_id = c.id WHERE c.id = 'user-b'",
            ).fetch_one(&pool).await?;
            anyhow::ensure!(generations == (2, 2));

            // Explicit credential deletion and both owner cascades remove
            // ciphertext without touching another owner's records.
            sqlx::query("DELETE FROM platform_credentials WHERE id = 'user-a'").execute(&pool).await?;
            sqlx::query("DELETE FROM organizations WHERE id = 'credential-org-a'").execute(&pool).await?;
            sqlx::query("DELETE FROM users WHERE id = 'credential-user-b'").execute(&pool).await?;
            let remaining: Vec<String> = sqlx::query_scalar("SELECT id FROM platform_credentials ORDER BY id")
                .fetch_all(&pool).await?;
            let remaining_material: Vec<String> = sqlx::query_scalar(
                "SELECT credential_id FROM platform_credential_material ORDER BY credential_id",
            ).fetch_all(&pool).await?;
            anyhow::ensure!(remaining == ["org-b", "user-extra"]);
            anyhow::ensure!(remaining_material == ["org-b"]);
            pool.close().await;
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn tenant_secret_writer_fence_rejects_omitted_version_before_on_conflict()
    -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            ensure_schema(&test_db.url).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            seed_test_tenant_secret_dek(&pool, "current-user-dek", "user", "current-user").await?;

            sqlx::query(
                "INSERT INTO tenant_secrets \
                 (path, key, dek_id, scope, scope_id, ciphertext, nonce, format, \
                  storage_contract_version) \
                 VALUES ('/users/current-user', 'SSH_PRIVATE_KEY', 'current-user-dek', \
                         'user', 'current-user', decode(repeat('11', 16), 'hex'), \
                         decode(repeat('22', 12), 'hex'), 1, 1)",
            )
            .execute(&pool)
            .await?;

            let old_upsert = sqlx::query(
                "INSERT INTO tenant_secrets \
                 (path, key, dek_id, scope, scope_id, ciphertext, nonce, format) \
                 VALUES ('/users/current-user', 'SSH_PRIVATE_KEY', 'current-user-dek', \
                         'user', 'current-user', decode(repeat('33', 16), 'hex'), \
                         decode(repeat('44', 12), 'hex'), 1) \
                 ON CONFLICT (path, key) DO UPDATE SET \
                   dek_id = EXCLUDED.dek_id, scope = EXCLUDED.scope, \
                   scope_id = EXCLUDED.scope_id, ciphertext = EXCLUDED.ciphertext, \
                   nonce = EXCLUDED.nonce, format = EXCLUDED.format, updated_at = now()",
            )
            .execute(&pool)
            .await
            .expect_err("an omitted-version ON CONFLICT candidate must fail its check first");
            assert_storage_contract_violation(&old_upsert)?;

            let unchanged: (Vec<u8>, i16) = sqlx::query_as(
                "SELECT ciphertext, storage_contract_version FROM tenant_secrets \
                 WHERE path = '/users/current-user' AND key = 'SSH_PRIVATE_KEY'",
            )
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(
                unchanged == (vec![0x11; 16], 1),
                "rejected omitted-version upsert changed stored ciphertext or version"
            );

            sqlx::query(
                "INSERT INTO tenant_secrets \
                 (path, key, dek_id, scope, scope_id, ciphertext, nonce, format, \
                  storage_contract_version) \
                 VALUES ('/users/current-user', 'SSH_PRIVATE_KEY', 'current-user-dek', \
                         'user', 'current-user', decode(repeat('55', 16), 'hex'), \
                         decode(repeat('66', 12), 'hex'), 1, 1) \
                 ON CONFLICT (path, key) DO UPDATE SET \
                   dek_id = EXCLUDED.dek_id, scope = EXCLUDED.scope, \
                   scope_id = EXCLUDED.scope_id, ciphertext = EXCLUDED.ciphertext, \
                   nonce = EXCLUDED.nonce, format = EXCLUDED.format, updated_at = now()",
            )
            .execute(&pool)
            .await?;
            let current: (Vec<u8>, i16) = sqlx::query_as(
                "SELECT ciphertext, storage_contract_version FROM tenant_secrets \
                 WHERE path = '/users/current-user' AND key = 'SSH_PRIVATE_KEY'",
            )
            .fetch_one(&pool)
            .await?;
            let current_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM tenant_secrets \
                 WHERE path = '/users/current-user' AND key = 'SSH_PRIVATE_KEY'",
            )
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(
                current_count == 1 && current == (vec![0x55; 16], 1),
                "explicit current insert/upsert did not preserve the writer contract: {current:?}"
            );
            pool.close().await;
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    async fn assert_platform_credential_schema(pool: &PgPool) -> anyhow::Result<()> {
        for (table, expected) in [
            (
                "platform_credentials",
                &[
                    "id",
                    "user_id",
                    "organization_id",
                    "provider",
                    "authentication_kind",
                    "display_name",
                    "account_hint",
                    "status",
                    "expires_at_unix",
                    "revocation_generation",
                    "material_generation",
                    "created_at",
                    "updated_at",
                    "ssh_public_key",
                    "ssh_fingerprint",
                ][..],
            ),
            (
                "platform_credential_material",
                &[
                    "credential_id",
                    "material_generation",
                    "kek_provider",
                    "key_name",
                    "key_version",
                    "wrapped_dek",
                    "wrapped_format",
                    "ciphertext",
                    "nonce",
                    "format",
                ][..],
            ),
        ] {
            let columns: Vec<String> = sqlx::query_scalar(
                "SELECT column_name FROM information_schema.columns \
                 WHERE table_schema = 'public' AND table_name = $1 ORDER BY ordinal_position",
            )
            .bind(table)
            .fetch_all(pool)
            .await?;
            anyhow::ensure!(
                columns == expected,
                "{table} columns changed; metadata must contain neither envelope nor protected reference"
            );
        }
        let material_fk: (String, bool, bool) = sqlx::query_as(
            "SELECT pg_get_constraintdef(oid), condeferrable, condeferred \
             FROM pg_catalog.pg_constraint \
             WHERE conrelid = 'public.platform_credential_material'::regclass \
               AND conname = 'platform_credential_material_generation_fkey'",
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            material_fk == (
                "FOREIGN KEY (credential_id, material_generation) REFERENCES platform_credentials(id, material_generation) ON DELETE CASCADE".to_owned(),
                false,
                false,
            ),
            "protected material lost its immediate metadata-generation foreign key"
        );
        Ok(())
    }

    async fn seed_platform_credential_owners(pool: &PgPool) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO users (id, email) VALUES \
             ('credential-user-a', 'credential-a@example.test'), \
             ('credential-user-b', 'credential-b@example.test')",
        )
        .execute(pool)
        .await?;
        // Both organizations belong to user A so deletion of user B isolates
        // the user cascade from the independent organization-cascade proof.
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) VALUES \
             ('credential-org-a', 'Credential A', 'credential-a', 'credential-user-a'), \
             ('credential-org-b', 'Credential B', 'credential-b', 'credential-user-a')",
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn seed_platform_credential(
        pool: &PgPool,
        id: &str,
        user_id: Option<&str>,
        organization_id: Option<&str>,
        display_name: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO platform_credentials \
             (id, user_id, organization_id, provider, authentication_kind, display_name, \
              status, revocation_generation, material_generation) \
             VALUES ($1, $2, $3, 'openai', 'oauth', $4, 'active', 1, 1)",
        )
        .bind(id)
        .bind(user_id)
        .bind(organization_id)
        .bind(display_name)
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn seed_platform_credential_material(
        pool: &PgPool,
        id: &str,
        generation: i64,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO platform_credential_material \
             (credential_id, material_generation, kek_provider, key_name, key_version, \
              wrapped_dek, wrapped_format, ciphertext, nonce, format) \
             VALUES ($1, $2, 'openbao-transit', 'credential-key', 1, decode('01', 'hex'), \
                     1, decode(repeat('00', 16), 'hex'), decode(repeat('00', 12), 'hex'), 1)",
        )
        .bind(id)
        .bind(generation)
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn assert_platform_credential_rejected(
        pool: &PgPool,
        query: &str,
        expected_code: &str,
    ) -> anyhow::Result<()> {
        let error = sqlx::query(query)
            .execute(pool)
            .await
            .expect_err("invalid synthetic credential storage must be rejected");
        let code = error.as_database_error().and_then(|error| error.code());
        anyhow::ensure!(
            code.as_deref() == Some(expected_code),
            "credential constraint returned SQLSTATE {code:?}, expected {expected_code}"
        );
        Ok(())
    }

    async fn seed_test_tenant_secret_dek(
        pool: &PgPool,
        dek_id: &str,
        scope: &str,
        scope_id: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO tenant_secret_deks \
             (dek_id, scope, scope_id, provider, key_name, key_version, wrapped_dek) \
             VALUES ($1, $2, $3, 'openbao-transit', 'tenant-dek', 1, \
                     'vault:v1:generated')",
        )
        .bind(dek_id)
        .bind(scope)
        .bind(scope_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    fn assert_storage_contract_violation(error: &sqlx::Error) -> anyhow::Result<()> {
        let constraint = error
            .as_database_error()
            .and_then(|database_error| database_error.constraint());
        anyhow::ensure!(
            constraint == Some("tenant_secrets_storage_contract_version_check"),
            "old tenant-secret writer failed for the wrong reason: {error}"
        );
        Ok(())
    }

    #[test]
    fn the_embedded_history_is_the_pinned_baseline_and_its_successors() -> anyhow::Result<()> {
        let migrations: Vec<_> = MIGRATOR.iter().collect();
        let pinned = [
            (1, APPLIED_BASELINE_CHECKSUM),
            (2, APPLIED_ENVIRONMENT_MESH_CHECKSUM),
            (3, APPLIED_DEFAULT_ACCESS_PROFILE_CHECKSUM),
            (4, APPLIED_ENVIRONMENT_QUOTA_DEFAULTS_CHECKSUM),
            (5, APPLIED_ORGANIZATION_CONFIDENTIAL_CHECKSUM),
            (6, APPLIED_BILLING_RATE_CARDS_CHECKSUM),
            (7, APPLIED_ACCOUNT_DELETION_CHECKSUM),
            (8, APPLIED_ORGANIZATION_DEDICATED_CPU_CHECKSUM),
            (9, APPLIED_HOSTED_SNAPSHOTS_CHECKSUM),
            (10, APPLIED_ENVIRONMENT_SOURCE_SNAPSHOT_CHECKSUM),
            (11, APPLIED_ENVIRONMENT_ERROR_CODE_CHECKSUM),
            (12, APPLIED_SIGNUP_CREDIT_SETTING_CHECKSUM),
            (13, APPLIED_FEEDBACK_CHECKSUM),
            (14, APPLIED_USER_CLI_SIGN_IN_CHECKSUM),
            (15, APPLIED_HOSTS_CHECKSUM),
            (16, APPLIED_OAUTH_SIGN_IN_CHECKSUM),
            (17, APPLIED_RESERVE_LEGAL_PAGE_SLUGS_CHECKSUM),
            (18, APPLIED_CONFIDENTIAL_ACTIVATION_SLOTS_CHECKSUM),
            (19, APPLIED_RESEND_VERIFICATION_PURPOSE_CHECKSUM),
            (20, APPLIED_OIDC_CONSUMED_REFRESH_TOKENS_CHECKSUM),
            (21, APPLIED_ORG_INVITATION_EMAILS_CHECKSUM),
            (22, APPLIED_RATE_LIMIT_SETTINGS_CHECKSUM),
            (23, APPLIED_INVITE_ONLY_SIGN_UP_CHECKSUM),
            (24, APPLIED_ACCOUNT_DELETION_INITIATOR_CHECKSUM),
            (25, APPLIED_NETWORK_POLICIES_CHECKSUM),
            (26, APPLIED_HOST_OPERATIONS_CHECKSUM),
        ];
        anyhow::ensure!(
            migrations.len() == pinned.len(),
            "every accepted migration is pinned"
        );
        for (migration, (version, checksum)) in migrations.iter().zip(pinned) {
            anyhow::ensure!(migration.version == version);
            anyhow::ensure!(
                format!("{:x}", Sha384::digest(migration.sql.as_bytes())) == checksum,
                "migration {version} changed after it was accepted"
            );
        }
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn the_baseline_builds_the_accepted_schema_and_a_second_run_is_a_noop()
    -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            ensure_schema(&test_db.url).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            let first = applied_migrations(&pool).await?;
            anyhow::ensure!(
                first.len() == 26
                    && first.iter().map(|migration| migration.0).eq([
                        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                        22, 23, 24, 25, 26
                    ])
                    && first.iter().all(|migration| migration.2)
            );
            let fingerprint: String = sqlx::query_scalar(include_str!(
                "../tests/data/application_schema_fingerprint.sql"
            ))
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(
                fingerprint == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT,
                "application schema fingerprint changed: {fingerprint}"
            );
            let plans: i64 = sqlx::query_scalar("SELECT count(*) FROM billing_catalog_plans")
                .fetch_one(&pool)
                .await?;
            anyhow::ensure!(plans > 0, "the baseline must seed the billing catalog");
            pool.close().await;

            ensure_schema(&test_db.url).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            anyhow::ensure!(applied_migrations(&pool).await? == first);
            pool.close().await;
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn standard_migrator_serializes_concurrent_startups() -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            let (first, second, third, fourth) = tokio::join!(
                startup(test_db.url.clone()),
                startup(test_db.url.clone()),
                startup(test_db.url.clone()),
                startup(test_db.url.clone()),
            );
            first?;
            second?;
            third?;
            fourth?;

            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            let applied = applied_migrations(&pool).await?;
            anyhow::ensure!(
                applied.len()
                    == MIGRATOR
                        .iter()
                        .filter(|m| !m.migration_type.is_down_migration())
                        .count()
            );
            pool.close().await;
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn standard_migrator_rejects_checksum_drift() -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            ensure_schema(&test_db.url).await?;
            let version = MIGRATOR
                .iter()
                .next()
                .context("embedded migration history is empty")?
                .version;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            sqlx::query(
                "UPDATE _sqlx_migrations SET checksum = decode('00', 'hex') WHERE version = $1",
            )
            .bind(version)
            .execute(&pool)
            .await?;
            pool.close().await;

            let error = ensure_schema(&test_db.url)
                .await
                .expect_err("modified migration checksum must fail closed");
            anyhow::ensure!(
                format!("{error:#}").contains("previously applied but has been modified")
            );
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn standard_migrator_rejects_dirty_ledger() -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            ensure_schema(&test_db.url).await?;
            let future = embedded_max_version()? + 1;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            sqlx::query(
                r#"
                INSERT INTO _sqlx_migrations
                    (version, description, success, checksum, execution_time)
                VALUES ($1, 'dirty migration', false, decode('00', 'hex'), 0)
                "#,
            )
            .bind(future)
            .execute(&pool)
            .await?;
            pool.close().await;

            let error = ensure_schema(&test_db.url)
                .await
                .expect_err("dirty migration ledger must fail closed");
            anyhow::ensure!(format!("{error:#}").contains("partially applied"));
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    async fn applied_migrations(
        pool: &PgPool,
    ) -> anyhow::Result<Vec<(i64, String, bool, Vec<u8>)>> {
        Ok(sqlx::query_as(
            r#"
            SELECT version, description, success, checksum
            FROM _sqlx_migrations
            ORDER BY version
            "#,
        )
        .fetch_all(pool)
        .await?)
    }

    fn embedded_max_version() -> anyhow::Result<i64> {
        MIGRATOR
            .iter()
            .map(|migration| migration.version)
            .max()
            .context("embedded migration history is empty")
    }

    struct TestDatabase {
        admin_url: String,
        name: String,
        url: String,
    }

    impl TestDatabase {
        async fn create(admin_url: &str) -> anyhow::Result<Self> {
            static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos();
            let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let name = format!("cw_sqlx_migration_{}_{sequence}_{now}", std::process::id());
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .connect(admin_url)
                .await?;
            sqlx::query(&format!("CREATE DATABASE {}", quote_ident(&name)))
                .execute(&admin)
                .await?;
            admin.close().await;

            let mut url = url::Url::parse(admin_url)?;
            url.set_path(&name);
            Ok(Self {
                admin_url: admin_url.to_string(),
                name,
                url: url.to_string(),
            })
        }

        async fn drop(self) -> anyhow::Result<()> {
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .connect(&self.admin_url)
                .await?;
            sqlx::query(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                quote_ident(&self.name)
            ))
            .execute(&admin)
            .await?;
            admin.close().await;
            Ok(())
        }
    }

    fn quote_ident(identifier: &str) -> String {
        format!(r#""{}""#, identifier.replace('"', r#""""#))
    }

    /// Bounds only a hang: every lock wait in these tests ends on its event.
    const LOCK_WAIT_HANG_GUARD: Duration = Duration::from_secs(60);

    /// Runs `sql` with `id` in its own transaction and commits it, unless
    /// Postgres reports it waiting on `holder`'s locks; then it returns true,
    /// leaving the statement waiting until `holder` ends. A slow connection,
    /// statement or commit is not a wait on `holder` (#3289).
    async fn update_waits_on(
        pool: &PgPool,
        sql: &'static str,
        id: &str,
        holder: i32,
    ) -> anyhow::Result<bool> {
        let (pid_tx, pid_rx) = tokio::sync::oneshot::channel();
        let update_pool = pool.clone();
        let id = id.to_owned();
        let mut update = tokio::spawn(async move {
            let mut tx = update_pool.begin().await?;
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *tx)
                .await?;
            let _ = pid_tx.send(pid);
            sqlx::query(sql).bind(id).execute(&mut *tx).await?;
            tx.commit().await?;
            anyhow::Ok(())
        });
        tokio::time::timeout(LOCK_WAIT_HANG_GUARD, async {
            let waiter = tokio::select! {
                biased;
                finished = &mut update => {
                    finished??;
                    return anyhow::Ok(false);
                }
                pid = pid_rx => pid?,
            };
            loop {
                tokio::select! {
                    biased;
                    finished = &mut update => {
                        finished??;
                        return Ok(false);
                    }
                    _ = tokio::time::sleep(Duration::from_millis(5)) => {}
                }
                let blocked: bool = sqlx::query_scalar(
                    "SELECT $2::integer = ANY(pg_catalog.pg_blocking_pids($1::integer))",
                )
                .bind(waiter)
                .bind(holder)
                .fetch_one(pool)
                .await?;
                if blocked {
                    return Ok(true);
                }
            }
        })
        .await
        .context("an ordinary update neither finished nor waited on the account lock")?
    }

    async fn wait_for_lock_blocker(pool: &PgPool, waiter: i32, blocker: i32) -> anyhow::Result<()> {
        tokio::time::timeout(LOCK_WAIT_HANG_GUARD, async {
            loop {
                let blocked: bool = sqlx::query_scalar(
                    "SELECT $2::integer = ANY(pg_catalog.pg_blocking_pids($1::integer))",
                )
                .bind(waiter)
                .bind(blocker)
                .fetch_one(pool)
                .await?;
                if blocked {
                    return anyhow::Ok(());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .context("expected account-access transaction lock barrier")?
    }
}
