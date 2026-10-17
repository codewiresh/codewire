//! Owner-source authority helper: exact privileges and concurrent revocation fences.

use super::*;

const SIGNATURE: &str = "public.codewire_platform_lock_owner_source_authority(text,text,text)";
const CALL: &str =
    "SELECT public.codewire_platform_lock_owner_source_authority($1::text,$2::text,$3::text)";
const WAIT: Duration = Duration::from_secs(5);

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
    let _ = body;
    Ok(definition.clone())
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
