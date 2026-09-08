//! Function-only staged 25 -> 26 proof. No platform environment is synthesized.

use super::*;

const VERSION: i64 = 26;
const SIGNATURE: &str = "public.codewire_platform_lock_owner_source_authority(text,text,text)";
const CALL: &str =
    "SELECT public.codewire_platform_lock_owner_source_authority($1::text,$2::text,$3::text)";
const SQL: &str = include_str!("../../../migrations/0026_owner_source_authority.sql");
// Independently frozen after the accepted SSH component PostgreSQL proof.
// This is a staged branch boundary, not deployed or merged version25 history.
const ACCEPTED_STAGED25: &str = "a1fa99436ba0690f41f8e90f2152dcec9253c263e73086104b7de23efd12d0a09a7b6d9d93d87c299658f817bb311edf";
const WAIT: Duration = Duration::from_secs(5);

pub(super) fn assert_accepted_staged25() -> anyhow::Result<()> {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == 25)
        .context("accepted staged migration25 missing")?;
    anyhow::ensure!(
        format!("{:x}", Sha384::digest(migration.sql.as_bytes())) == ACCEPTED_STAGED25,
        "migration25 differs from the accepted staged SSH component"
    );
    Ok(())
}

#[test]
fn owner_source_upgrade_retains_independently_accepted_history() -> anyhow::Result<()> {
    assert_applied_broker_lock_history()?;
    let consent = MIGRATOR
        .iter()
        .find(|m| m.version == 22)
        .context("migration22 missing")?;
    anyhow::ensure!(
        format!("{:x}", Sha384::digest(consent.sql.as_bytes())) == FROZEN_BINDING_CONSENT_CHECKSUM
    );
    projection::assert_accepted_prior23()?;
    ssh::assert_accepted_staged24()?;
    assert_accepted_staged25()
}

async fn definition(pool: &PgPool) -> anyhow::Result<String> {
    let rows: Vec<(String, String, bool, String, String)> = sqlx::query_as(
        "SELECT pg_catalog.oidvectortypes(p.proargtypes),pg_catalog.pg_get_function_result(p.oid), \
         p.prosecdef AND NOT p.proleakproof AND NOT p.proisstrict AND p.prokind='f' \
         AND p.provolatile='v' AND p.proparallel='u' AND l.lanname='plpgsql' \
         AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[] \
         AND p.proowner=(SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid='public._sqlx_migrations'::regclass) \
         AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner), \
         p.prosrc,pg_catalog.pg_get_functiondef(p.oid) \
         FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace \
         JOIN pg_catalog.pg_language l ON l.oid=p.prolang \
         WHERE n.nspname='public' AND p.proname='codewire_platform_lock_owner_source_authority'",
    ).fetch_all(pool).await?;
    anyhow::ensure!(rows.len() == 1, "owner-source helper inventory changed");
    let (args, result, private, body, definition) = &rows[0];
    anyhow::ensure!(args == "text, text, text" && result == "boolean");
    anyhow::ensure!(
        *private,
        "owner-source helper owner/search-path/ACL changed"
    );
    let expected = SQL
        .split_once("\nAS $$\n")
        .context("missing function body")?
        .1
        .split_once("\n$$;")
        .context("missing function terminator")?
        .0;
    anyhow::ensure!(
        body.trim() == expected,
        "installed owner-source helper body differs"
    );
    Ok(definition.clone())
}

async fn old_functions(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    // Compare every pre-26 helper byte-for-byte. Migration27's two new
    // session helpers have their own inventory/authority proof; neither was
    // present in the staged25 baseline and neither replaces a prior helper.
    Ok(sqlx::query_scalar(
        "SELECT pg_catalog.pg_get_functiondef(p.oid) FROM pg_catalog.pg_proc p \
         JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace \
         WHERE n.nspname='public' AND starts_with(p.proname,'codewire_') \
         AND p.proname NOT IN ('codewire_platform_lock_owner_source_authority', \
         'codewire_authenticate_credential_session','codewire_lock_credential_session_authority') \
         ORDER BY p.proname,p.oid",
    )
    .fetch_all(pool)
    .await?)
}

async fn seed(pool: &PgPool) -> anyhow::Result<()> {
    seed_platform_credential_owners(pool).await?;
    sqlx::raw_sql(
        "INSERT INTO public.org_members(id,org_id,user_id,role) VALUES \
         ('source-member-a','credential-org-a','credential-user-a','member'), \
         ('source-member-b','credential-org-b','credential-user-a','member'); \
         INSERT INTO public.secret_projects(id,org_id,name) VALUES \
         ('source-project-a','credential-org-a','Project A'), \
         ('source-project-b','credential-org-b','Project B');",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn allowed(
    pool: &PgPool,
    user: Option<&str>,
    organization: Option<&str>,
    project: Option<&str>,
) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar(CALL)
        .bind(user)
        .bind(organization)
        .bind(project)
        .fetch_one(pool)
        .await?)
}

async fn rows(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    let mut rows = Vec::new();
    for table in [
        "users",
        "organizations",
        "org_members",
        "secret_projects",
        "platform_credentials",
        "platform_credential_material",
    ] {
        // Fixed fixture tables only; no caller-controlled SQL identifier.
        let value: String = sqlx::query_scalar(&format!(
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM public.{table} t"
        )).fetch_one(pool).await?;
        rows.push(value);
    }
    Ok(rows)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn owner_source_staged_upgrade_preserves25_rows_authority_and_noop() -> anyhow::Result<()> {
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let before = applied_migrations(&pool).await?;
        anyhow::ensure!(before.len() == 25 && before[24].0 == 25);
        let prior_checksum: String = sqlx::query_scalar("SELECT encode(checksum,'hex') FROM public._sqlx_migrations WHERE version=25 AND success").fetch_one(&pool).await?;
        anyhow::ensure!(prior_checksum == ACCEPTED_STAGED25);
        seed(&pool).await?;
        seed_platform_credential(&pool, "source-retained", Some("credential-user-a"), None, "Retained").await?;
        seed_platform_credential_material(&pool, "source-retained", 1).await?;
        let retained = rows(&pool).await?;
        let old = old_functions(&pool).await?;
        pool.close().await;
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let after = applied_migrations(&pool).await?;
        anyhow::ensure!(after.len() == MIGRATOR.iter().count() && after[..25] == before && after[25].0 == VERSION);
        anyhow::ensure!(rows(&pool).await? == retained);
        anyhow::ensure!(old_functions(&pool).await? == old);
        let installed = definition(&pool).await?;
        let fingerprint: String = sqlx::query_scalar(include_str!("../../../tests/data/application_schema_fingerprint.sql")).fetch_one(&pool).await?;
        anyhow::ensure!(fingerprint == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT, "function-only migration changed tables: {fingerprint}");
        pool.close().await;
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == after);
        anyhow::ensure!(rows(&pool).await? == retained);
        anyhow::ensure!(definition(&pool).await? == installed && old_functions(&pool).await? == old);
        pool.close().await;
        Ok(())
    }.await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn owner_source_fresh_helper_locks_only_exact_active_member_scope_without_environment()
-> anyhow::Result<()> {
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        definition(&pool).await?;
        seed(&pool).await?;
        for (user, org, project, expected) in [
            (Some("credential-user-a"), Some("credential-org-a"), None, true),
            (Some("credential-user-a"), Some("credential-org-a"), Some("source-project-a"), true),
            (Some("credential-user-a"), Some("credential-org-b"), Some("source-project-b"), true),
            (Some("credential-user-a"), Some("credential-org-a"), Some("source-project-b"), false),
            (Some("credential-user-a"), Some("credential-org-a"), Some("missing"), false),
            (Some("credential-user-a"), Some("credential-org-a"), Some(""), false),
            (Some("credential-user-b"), Some("credential-org-a"), None, false),
            (Some("missing"), Some("credential-org-a"), None, false),
            (Some("credential-user-a"), Some("missing"), None, false),
            (Some(""), Some("credential-org-a"), None, false),
            (Some("credential-user-a"), Some(""), None, false),
            (None, Some("credential-org-a"), None, false),
            (Some("credential-user-a"), None, None, false),
        ] {
            anyhow::ensure!(allowed(&pool, user, org, project).await? == expected);
        }
        sqlx::query("UPDATE public.org_members SET role='' WHERE id='source-member-a'").execute(&pool).await?;
        anyhow::ensure!(!allowed(&pool, Some("credential-user-a"), Some("credential-org-a"), None).await?);
        sqlx::query("UPDATE public.organizations SET deletion_state='deleting',deletion_generation=1, \
            deletion_requested_by='credential-user-a',deletion_requested_at=clock_timestamp(), \
            deletion_operation_id='source-delete',deletion_workflow_id='source-delete',deletion_phase='write_fenced' \
            WHERE id='credential-org-b'").execute(&pool).await?;
        anyhow::ensure!(!allowed(&pool, Some("credential-user-a"), Some("credential-org-b"), Some("source-project-b")).await?);
        anyhow::ensure!(sqlx::query_scalar::<_, bool>("SELECT NOT EXISTS(SELECT 1 FROM public.environments)").fetch_one(&pool).await?);
        pool.close().await;
        Ok(())
    }.await;
    result.and(db.drop().await)
}

async fn denied(pool: &PgPool, sql: &str) -> anyhow::Result<()> {
    let error = sqlx::query(sql)
        .execute(pool)
        .await
        .err()
        .context("restricted login acquired forbidden authority")?;
    anyhow::ensure!(
        error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref()
            == Some("42501"),
        "denial was not insufficient_privilege"
    );
    Ok(())
}

async fn restricted_checks(admin: &PgPool, reader: &PgPool, role: &str) -> anyhow::Result<()> {
    denied(reader, "SELECT public.codewire_platform_lock_owner_source_authority('credential-user-a','credential-org-a',NULL)").await?;
    sqlx::query(&format!(
        "GRANT EXECUTE ON FUNCTION {SIGNATURE} TO {}",
        quote_ident(role)
    ))
    .execute(admin)
    .await?;
    anyhow::ensure!(
        allowed(
            reader,
            Some("credential-user-a"),
            Some("credential-org-a"),
            Some("source-project-a")
        )
        .await?
    );
    anyhow::ensure!(
        !allowed(
            reader,
            Some("credential-user-b"),
            Some("credential-org-a"),
            None
        )
        .await?
    );
    let owner: String = sqlx::query_scalar("SELECT pg_catalog.pg_get_userbyid(proowner) FROM pg_catalog.pg_proc WHERE oid=$1::regprocedure").bind(SIGNATURE).fetch_one(admin).await?;
    for sql in [
        "SELECT * FROM public.users",
        "SELECT * FROM public.organizations",
        "SELECT * FROM public.org_members",
        "SELECT * FROM public.secret_projects",
        "SELECT * FROM public.environments",
        "SELECT * FROM public.tenant_secrets",
        "SELECT * FROM public.platform_credential_material",
        "UPDATE public.org_members SET role='owner'",
        "DELETE FROM public.secret_projects",
        "CREATE TABLE public.forbidden(id integer)",
        "SELECT public.codewire_platform_lock_owner('user','credential-user-a')",
        "ALTER FUNCTION public.codewire_platform_lock_owner_source_authority(text,text,text) SECURITY INVOKER",
        "CREATE OR REPLACE FUNCTION public.codewire_platform_lock_owner_source_authority(text,text,text) RETURNS boolean LANGUAGE sql AS 'SELECT true'",
    ] {
        denied(reader, sql).await?;
    }
    denied(reader, &format!("SET ROLE {}", quote_ident(&owner))).await?;
    sqlx::query("RESET ROLE").execute(reader).await?;
    let session: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(reader)
        .await?;
    anyhow::ensure!(
        session == role,
        "fixture did not authenticate as the restricted login"
    );

    let mut connection = reader.acquire().await?;
    sqlx::raw_sql(
        "CREATE TEMP TABLE users(id text); CREATE TEMP TABLE organizations(id text,deletion_state text); \
         CREATE TEMP TABLE org_members(id text,org_id text,user_id text,role text); \
         CREATE TEMP TABLE secret_projects(id text,org_id text); \
         INSERT INTO pg_temp.users VALUES('forged-user'); \
         INSERT INTO pg_temp.organizations VALUES('forged-org','active'); \
         INSERT INTO pg_temp.org_members VALUES('forged-member','forged-org','forged-user','owner'); \
         INSERT INTO pg_temp.secret_projects VALUES('forged-project','forged-org'),('source-project-b','credential-org-a'); \
         SET search_path=pg_temp,public,pg_catalog;",
    ).execute(&mut *connection).await?;
    for (user, org, project, expected) in [
        (
            "credential-user-a",
            "credential-org-a",
            "source-project-a",
            true,
        ),
        (
            "credential-user-a",
            "credential-org-a",
            "source-project-b",
            false,
        ),
        ("forged-user", "forged-org", "forged-project", false),
    ] {
        let found: bool = sqlx::query_scalar(CALL)
            .bind(user)
            .bind(org)
            .bind(project)
            .fetch_one(&mut *connection)
            .await?;
        anyhow::ensure!(found == expected);
    }
    let path: String = sqlx::query_scalar("SHOW search_path")
        .fetch_one(&mut *connection)
        .await?;
    anyhow::ensure!(
        path == "pg_temp, public, pg_catalog",
        "helper changed caller search_path"
    );
    sqlx::query("RESET search_path")
        .execute(&mut *connection)
        .await?;
    drop(connection);
    Ok(())
}

async fn wait_blocked(pool: &PgPool, waiter: i32, holder: i32) -> anyhow::Result<()> {
    tokio::time::timeout(WAIT, async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT $2::integer=ANY(pg_catalog.pg_blocking_pids($1::integer))",
            )
            .bind(waiter)
            .bind(holder)
            .fetch_one(pool)
            .await?;
            if blocked {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("exact synthetic writer did not wait for owner-source lock")?
}

async fn writer_waits(admin: &PgPool, reader: &PgPool, mutation: &str) -> anyhow::Result<()> {
    let mut hold = reader.begin().await?;
    let holder: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *hold)
        .await?;
    let found: bool = sqlx::query_scalar(CALL)
        .bind("credential-user-a")
        .bind("credential-org-a")
        .bind("source-project-a")
        .fetch_one(&mut *hold)
        .await?;
    anyhow::ensure!(found);
    let mut writer = admin.acquire().await?;
    sqlx::query("SET statement_timeout='8s'")
        .execute(&mut *writer)
        .await?;
    let waiter: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await?;
    // Join both owned operations; no spawned SQL writer can outlive this proof.
    let (write, release) = tokio::join!(sqlx::query(mutation).execute(&mut *writer), async {
        let blocked = wait_blocked(admin, waiter, holder).await;
        hold.commit().await?;
        blocked
    });
    release?;
    anyhow::ensure!(write?.rows_affected() == 1);
    Ok(())
}

async fn concurrent_checks(admin: &PgPool, reader: &PgPool) -> anyhow::Result<()> {
    writer_waits(
        admin,
        reader,
        "UPDATE public.users SET email='source-lock@example.test' WHERE id='credential-user-a'",
    )
    .await?;
    writer_waits(
        admin,
        reader,
        "UPDATE public.organizations SET name='Source lock' WHERE id='credential-org-a'",
    )
    .await?;
    writer_waits(
        admin,
        reader,
        "UPDATE public.org_members SET role='' WHERE id='source-member-a'",
    )
    .await?;
    anyhow::ensure!(
        !allowed(
            reader,
            Some("credential-user-a"),
            Some("credential-org-a"),
            Some("source-project-a")
        )
        .await?
    );
    sqlx::query("UPDATE public.org_members SET role='member' WHERE id='source-member-a'")
        .execute(admin)
        .await?;
    writer_waits(
        admin,
        reader,
        "DELETE FROM public.secret_projects WHERE id='source-project-a'",
    )
    .await?;
    anyhow::ensure!(
        !allowed(
            reader,
            Some("credential-user-a"),
            Some("credential-org-a"),
            Some("source-project-a")
        )
        .await?
    );
    anyhow::ensure!(
        allowed(
            reader,
            Some("credential-user-a"),
            Some("credential-org-a"),
            None
        )
        .await?
    );

    // Revocation that wins first is observed after the waiting SHARE lock, not
    // authorized using a transaction-start view of the old membership row.
    let mut revoke = admin.begin().await?;
    let holder: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *revoke)
        .await?;
    sqlx::query("DELETE FROM public.org_members WHERE id='source-member-a'")
        .execute(&mut *revoke)
        .await?;
    let mut connection = reader.acquire().await?;
    sqlx::query("SET statement_timeout='8s'")
        .execute(&mut *connection)
        .await?;
    let waiter: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *connection)
        .await?;
    let (admitted, release) = tokio::join!(
        sqlx::query_scalar::<_, bool>(CALL)
            .bind("credential-user-a")
            .bind("credential-org-a")
            .bind(None::<&str>)
            .fetch_one(&mut *connection),
        async {
            let blocked = wait_blocked(admin, waiter, holder).await;
            revoke.commit().await?;
            blocked
        }
    );
    release?;
    anyhow::ensure!(
        !admitted?,
        "waiting admission ignored committed membership deletion"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL with synthetic role creation"]
async fn owner_source_restricted_login_search_path_and_concurrent_revocation_fences()
-> anyhow::Result<()> {
    let admin_url = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin_url).await?;
    let role = format!("cw_owner_source_{}", uuid::Uuid::new_v4().simple());
    let mut created_role = false;
    let result = async {
        ensure_schema(&db.url).await?;
        let admin = PgPoolOptions::new().max_connections(3).connect(&db.url).await?;
        // Fixed public synthetic credential, used only with this disposable role.
        const PASSWORD: &str = "synthetic-owner-source-test-only";
        sqlx::query(&format!("CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{PASSWORD}'", quote_ident(&role)))
            .execute(&admin).await?;
        created_role = true;
        let result = async {
            seed(&admin).await?;
            for grant in [
                format!("GRANT CONNECT,TEMPORARY ON DATABASE {} TO {}", quote_ident(&db.name), quote_ident(&role)),
                format!("GRANT USAGE ON SCHEMA public TO {}", quote_ident(&role)),
            ] { sqlx::query(&grant).execute(&admin).await?; }
            let mut url = url::Url::parse(&db.url)?;
            url.set_username(&role).map_err(|_| anyhow::anyhow!("synthetic role username"))?;
            url.set_password(Some(PASSWORD)).map_err(|_| anyhow::anyhow!("synthetic role password"))?;
            let reader = PgPoolOptions::new().max_connections(2).connect(url.as_str()).await?;
            let result = async {
                restricted_checks(&admin, &reader, &role).await?;
                concurrent_checks(&admin, &reader).await
            }.await;
            reader.close().await;
            result
        }.await;
        admin.close().await;
        result
    }.await;
    let dropped = db.drop().await;
    let role_cleanup = async {
        if created_role {
            let mut admin = PgConnection::connect(&admin_url).await?;
            sqlx::query(&format!("DROP ROLE {}", quote_ident(&role)))
                .execute(&mut admin)
                .await?;
            admin.close().await?;
        }
        Ok(())
    }
    .await;
    result.and(dropped).and(role_cleanup)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL with event-trigger creation"]
async fn owner_source_failed_forward_migration_rolls_back_function_and_ledger() -> anyhow::Result<()>
{
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let before = applied_migrations(&pool).await?;
        let old = old_functions(&pool).await?;
        // Fail after CREATE FUNCTION has executed, proving SQLx rolls back DDL
        // as well as its ledger. This trigger exists only in the throwaway DB.
        sqlx::raw_sql("CREATE SCHEMA migration_failure; \
            CREATE FUNCTION migration_failure.reject_created_function() RETURNS event_trigger LANGUAGE plpgsql AS $$ \
            BEGIN RAISE EXCEPTION 'synthetic failure after owner-source function creation'; END; $$; \
            CREATE EVENT TRIGGER owner_source_failure ON ddl_command_end WHEN TAG IN ('CREATE FUNCTION') \
            EXECUTE FUNCTION migration_failure.reject_created_function();").execute(&pool).await?;
        pool.close().await;
        let error = ensure_schema(&db.url).await.err().context("forced migration failure was accepted")?;
        anyhow::ensure!(format!("{error:#}").contains("synthetic failure after owner-source function creation"));
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == before);
        anyhow::ensure!(sqlx::query_scalar::<_, bool>("SELECT to_regprocedure($1) IS NULL").bind(SIGNATURE).fetch_one(&pool).await?);
        anyhow::ensure!(old_functions(&pool).await? == old);
        sqlx::raw_sql("DROP EVENT TRIGGER owner_source_failure; DROP SCHEMA migration_failure CASCADE;").execute(&pool).await?;
        pool.close().await;
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        definition(&pool).await?;
        pool.close().await;
        Ok(())
    }.await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn owner_source_rollback_replays_staged25_only_in_disposable_application_schema()
-> anyhow::Result<()> {
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        definition(&pool).await?;
        seed(&pool).await?;
        seed_platform_credential(&pool, "source-discarded", Some("credential-user-a"), None, "Discarded").await?;
        seed_platform_credential_material(&pool, "source-discarded", 1).await?;
        let old = old_functions(&pool).await?;
        sqlx::raw_sql("CREATE SCHEMA rollback_boundary; CREATE TABLE rollback_boundary.keep(id integer); \
            INSERT INTO rollback_boundary.keep VALUES(1); DROP SCHEMA public CASCADE; CREATE SCHEMA public;").execute(&pool).await?;
        pool.close().await;
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let ledger = applied_migrations(&pool).await?;
        anyhow::ensure!(ledger.len() == 25 && ledger[24].0 == 25);
        let prior_checksum: String = sqlx::query_scalar("SELECT encode(checksum,'hex') FROM public._sqlx_migrations WHERE version=25 AND success").fetch_one(&pool).await?;
        anyhow::ensure!(prior_checksum == ACCEPTED_STAGED25);
        anyhow::ensure!(sqlx::query_scalar::<_, bool>("SELECT to_regprocedure($1) IS NULL").bind(SIGNATURE).fetch_one(&pool).await?);
        anyhow::ensure!(sqlx::query_scalar::<_, i32>("SELECT id FROM rollback_boundary.keep").fetch_one(&pool).await? == 1);
        anyhow::ensure!(sqlx::query_scalar::<_, bool>("SELECT NOT EXISTS(SELECT 1 FROM public.platform_credentials) AND NOT EXISTS(SELECT 1 FROM public.platform_credential_material)").fetch_one(&pool).await?);
        anyhow::ensure!(old_functions(&pool).await? == old);
        let fingerprint: String = sqlx::query_scalar(include_str!("../../../tests/data/application_schema_fingerprint.sql")).fetch_one(&pool).await?;
        anyhow::ensure!(fingerprint == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);
        pool.close().await;
        Ok(())
    }.await;
    result.and(db.drop().await)
}
