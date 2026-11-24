//! Membership revocations (#3586): after an upgrade, every removed
//! `org_members` row writes one `membership` row and a wake-up, an
//! organization's move to `deleting` writes one `organization` row and staying
//! there writes none, a rolled-back change writes nothing, the table refuses a
//! row whose columns don't fit its kind, and the rollback restores the
//! earlier schema.

use std::collections::BTreeSet;

use sqlx::postgres::PgListener;

use super::*;

/// The version of the migration this file tests.
const VERSION: i64 = 54;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// The history up to and including `version`, so later migrations don't
/// change what this test measures.
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

type Logged = (String, String, String, Option<String>);

async fn logged(pool: &PgPool) -> anyhow::Result<BTreeSet<Logged>> {
    let rows: Vec<Logged> = sqlx::query_as(
        "SELECT kind, credential_id, user_id, org_id FROM credential_revocations \
         WHERE kind IN ('membership', 'organization')",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().collect())
}

fn row(kind: &str, user_id: &str, org_id: &str) -> Logged {
    (
        kind.into(),
        org_id.into(),
        user_id.into(),
        Some(org_id.into()),
    )
}

const DELETING: &str = "UPDATE organizations SET deletion_state = 'deleting', \
     deletion_generation = deletion_generation + 1, \
     deletion_operation_id = 'synthetic-operation', deletion_workflow_id = 'synthetic-workflow', \
     deletion_requested_at = now(), deletion_phase = 'synthetic_phase', \
     deletion_failure_code = NULL WHERE id = $1";

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn membership_revocations_log_each_removal_and_deletion_start_once_and_roll_back()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(VERSION - 1).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&db.url)
            .await?;
        sqlx::raw_sql(
            "INSERT INTO users (id, email) VALUES \
                 ('owner', 'owner@example.test'), \
                 ('removed', 'removed@example.test'), \
                 ('leaver', 'leaver@example.test'), \
                 ('deleted-account', 'deleted-account@example.test'), \
                 ('kept', 'kept@example.test'); \
             INSERT INTO organizations (id, name, slug, created_by) VALUES \
                 ('org-a', 'a', 'org-a', 'owner'), \
                 ('org-b', 'b', 'org-b', 'owner'), \
                 ('org-c', 'c', 'org-c', 'owner'); \
             INSERT INTO org_members (id, org_id, user_id, role) VALUES \
                 ('m1', 'org-a', 'owner', 'owner'), \
                 ('m2', 'org-a', 'removed', 'member'), \
                 ('m3', 'org-a', 'leaver', 'member'), \
                 ('m4', 'org-a', 'deleted-account', 'member'), \
                 ('m5', 'org-a', 'kept', 'member'), \
                 ('m6', 'org-b', 'owner', 'owner'), \
                 ('m7', 'org-c', 'owner', 'owner'), \
                 ('m8', 'org-c', 'kept', 'member');",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        through(VERSION).run(&pool).await?;
        anyhow::ensure!(
            fingerprint(&pool).await? != previous,
            "the migration changes the schema"
        );
        let mut listener = PgListener::connect(&db.url).await?;
        listener.listen("credential_revocations").await?;

        // A removal and leaving delete the row; an account deletion and an
        // organization's finalize remove it by cascade.
        sqlx::raw_sql(
            "DELETE FROM org_members WHERE id IN ('m2', 'm3'); \
             DELETE FROM users WHERE id = 'deleted-account'; \
             DELETE FROM organizations WHERE id = 'org-c';",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(
            logged(&pool).await?
                == BTreeSet::from([
                    row("membership", "removed", "org-a"),
                    row("membership", "leaver", "org-a"),
                    row("membership", "deleted-account", "org-a"),
                    row("membership", "owner", "org-c"),
                    row("membership", "kept", "org-c"),
                ]),
            "each removed membership is logged once, whatever removed it"
        );
        let wake = tokio::time::timeout(std::time::Duration::from_secs(5), listener.recv())
            .await
            .map_err(|_| anyhow::anyhow!("no wake-up on credential_revocations"))??;
        anyhow::ensure!(wake.payload().is_empty(), "the wake-up carries no payload");

        // The deletion starting is one row for the organization; staying
        // there, or a change that doesn't start one, writes nothing.
        sqlx::raw_sql("DELETE FROM credential_revocations")
            .execute(&pool)
            .await?;
        sqlx::query(DELETING).bind("org-a").execute(&pool).await?;
        sqlx::query("UPDATE organizations SET deletion_phase = 'later_phase' WHERE id = 'org-a'")
            .execute(&pool)
            .await?;
        sqlx::query(DELETING).bind("org-a").execute(&pool).await?;
        sqlx::query("UPDATE organizations SET name = 'b2' WHERE id = 'org-b'")
            .execute(&pool)
            .await?;
        let rows: Vec<Logged> = sqlx::query_as(
            "SELECT kind, credential_id, user_id, org_id FROM credential_revocations",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            rows == vec![(
                "organization".to_owned(),
                "org-a".to_owned(),
                String::new(),
                Some("org-a".to_owned())
            )],
            "the deletion starting writes one row naming only the organization: {rows:?}"
        );

        // A rolled-back removal or deletion start writes nothing.
        let mut tx = pool.begin().await?;
        sqlx::query("DELETE FROM org_members WHERE id = 'm6'")
            .execute(&mut *tx)
            .await?;
        sqlx::query(DELETING)
            .bind("org-b")
            .execute(&mut *tx)
            .await?;
        tx.rollback().await?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM credential_revocations")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(count == 1, "a rolled-back change writes nothing");

        refuses_rows_that_do_not_fit_their_kind(&pool).await?;
        listener.unlisten_all().await?;
        roll_back(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

/// The table refuses a row whose columns don't fit its kind.
async fn refuses_rows_that_do_not_fit_their_kind(pool: &PgPool) -> anyhow::Result<()> {
    for bad in [
        "INSERT INTO credential_revocations (kind, credential_id, user_id) \
         VALUES ('membership', 'org-a', 'kept')",
        "INSERT INTO credential_revocations (kind, credential_id, user_id, org_id) \
         VALUES ('membership', 'other', 'kept', 'org-a')",
        "INSERT INTO credential_revocations (kind, credential_id, user_id, org_id) \
         VALUES ('organization', 'org-a', 'kept', 'org-a')",
        "INSERT INTO credential_revocations (kind, credential_id, user_id, org_id) \
         VALUES ('session', 's', 'kept', 'org-a')",
    ] {
        anyhow::ensure!(
            sqlx::query(bad).execute(pool).await.is_err(),
            "refused: {bad}"
        );
    }
    Ok(())
}

/// Rollback: the triggers and functions, the new kinds' rows, the earlier
/// check, then the index and the column.
async fn roll_back(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(
        "DROP TRIGGER org_members_revoke_streams_on_delete ON org_members; \
         DROP TRIGGER organizations_revoke_streams_on_deleting ON organizations; \
         DROP FUNCTION codewire_revoke_membership_streams(); \
         DROP FUNCTION codewire_revoke_organization_streams(); \
         DROP FUNCTION codewire_record_organization_revocation(text, text, text); \
         DELETE FROM credential_revocations WHERE kind IN ('membership', 'organization'); \
         ALTER TABLE credential_revocations DROP CONSTRAINT credential_revocations_kind_columns_check; \
         ALTER TABLE credential_revocations DROP CONSTRAINT credential_revocations_kind_check; \
         ALTER TABLE credential_revocations ADD CONSTRAINT credential_revocations_kind_check \
             CHECK (kind IN ('user', 'session', 'oauth_token', 'oauth_grant', 'api_key')); \
         DROP INDEX credential_revocations_org_idx; \
         ALTER TABLE credential_revocations DROP COLUMN org_id;",
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// The triggers run as the role doing the DML, and the writer they call grants
/// no EXECUTE to PUBLIC, so the DML must run as the owner, as the services do
/// (#5166). A non-superuser owner that ran the migrations removes a member and
/// starts a deletion; a role granted the same DML that isn't the owner is
/// refused, so a future restricted writer fails here first.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL with synthetic role creation"]
async fn the_triggers_need_the_dml_to_run_as_the_owner() -> anyhow::Result<()> {
    // Fixed public synthetic credential, used only with these disposable roles.
    const PASSWORD: &str = "synthetic-fence-owner-test-only";
    let admin_url = std::env::var("TEST_DATABASE_URL")?;
    let db = TestDatabase::create(&admin_url).await?;
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let owner = format!("cw_fence_owner_{suffix}");
    let writer = format!("cw_fence_writer_{suffix}");
    let mut created = Vec::new();
    let result = async {
        let mut admin = PgConnection::connect(&db.url).await?;
        for role in [&owner, &writer] {
            sqlx::query(&format!(
                "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{PASSWORD}'",
                quote_ident(role)
            ))
            .execute(&mut admin)
            .await?;
            created.push(role.clone());
        }
        sqlx::query(&format!(
            "ALTER DATABASE {} OWNER TO {}",
            quote_ident(&db.name),
            quote_ident(&owner)
        ))
        .execute(&mut admin)
        .await?;
        sqlx::query(&format!("ALTER SCHEMA public OWNER TO {}", quote_ident(&owner)))
            .execute(&mut admin)
            .await?;
        admin.close().await?;
        let connect_as = |role: &str| -> anyhow::Result<String> {
            let mut url = url::Url::parse(&db.url)?;
            url.set_username(role)
                .map_err(|_| anyhow::anyhow!("synthetic role username"))?;
            url.set_password(Some(PASSWORD))
                .map_err(|_| anyhow::anyhow!("synthetic role password"))?;
            Ok(url.to_string())
        };

        // The owner runs the migrations, as the services do at startup.
        let owner_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&connect_as(&owner)?)
            .await?;
        through(VERSION).run(&owner_pool).await?;
        sqlx::raw_sql(
            "INSERT INTO users (id, email) VALUES \
                 ('owner', 'owner@example.test'), ('removed', 'removed@example.test'), \
                 ('kept', 'kept@example.test'); \
             INSERT INTO organizations (id, name, slug, created_by) VALUES ('org-a', 'a', 'org-a', 'owner'); \
             INSERT INTO org_members (id, org_id, user_id, role) VALUES \
                 ('m1', 'org-a', 'owner', 'owner'), ('m2', 'org-a', 'removed', 'member'), \
                 ('m3', 'org-a', 'kept', 'member');",
        )
        .execute(&owner_pool)
        .await?;
        for grant in [
            format!("GRANT USAGE ON SCHEMA public TO {}", quote_ident(&writer)),
            format!("GRANT SELECT, DELETE ON org_members TO {}", quote_ident(&writer)),
            format!("GRANT SELECT, UPDATE ON organizations TO {}", quote_ident(&writer)),
        ] {
            sqlx::query(&grant).execute(&owner_pool).await?;
        }

        sqlx::query("DELETE FROM org_members WHERE id = 'm2'")
            .execute(&owner_pool)
            .await?;
        sqlx::query(DELETING).bind("org-a").execute(&owner_pool).await?;
        anyhow::ensure!(
            logged(&owner_pool).await?
                == BTreeSet::from([
                    row("membership", "removed", "org-a"),
                    row("organization", "", "org-a"),
                ]),
            "the owner's removal and deletion start each write their row"
        );

        let writer_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&connect_as(&writer)?)
            .await?;
        let refused = sqlx::query("DELETE FROM org_members WHERE id = 'm3'")
            .execute(&writer_pool)
            .await;
        writer_pool.close().await;
        let code = match &refused {
            Err(sqlx::Error::Database(error)) => error.code().map(|code| code.into_owned()),
            _ => None,
        };
        anyhow::ensure!(
            code.as_deref() == Some("42501"),
            "a role that isn't the owner can't remove a member through the trigger"
        );
        let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM org_members WHERE id = 'm3'")
            .fetch_one(&owner_pool)
            .await?;
        anyhow::ensure!(kept == 1, "the refused removal changed nothing");
        owner_pool.close().await;
        Ok(())
    }
    .await;
    let dropped = db.drop().await;
    let cleanup = async {
        let mut admin = PgConnection::connect(&admin_url).await?;
        for role in &created {
            sqlx::query(&format!("DROP ROLE {}", quote_ident(role)))
                .execute(&mut admin)
                .await?;
        }
        admin.close().await?;
        anyhow::Ok(())
    }
    .await;
    result.and(dropped).and(cleanup)
}
