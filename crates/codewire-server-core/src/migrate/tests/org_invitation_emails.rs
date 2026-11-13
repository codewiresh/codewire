//! Organization invitation email outbox (0021, #3847): an upgrade from the
//! shape before it adds an empty table and changes no invitation; a row
//! belongs to one invitation, holds only the statuses, roles and bounds the
//! sender writes, and goes with its invitation; the rollback (drop the table)
//! restores the earlier schema.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// The history up to and including `version`, so this test keeps proving
/// 0021 from the shape before it after later migrations land.
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

/// Inserts a pending outbox row for `invitation`, then applies `update` (an
/// SQL `SET` list) to it in the same transaction; the error names the
/// refusing constraint, and a refusal leaves no row.
async fn outbox(
    pool: &PgPool,
    invitation: &str,
    update: Option<&str>,
) -> Result<(), Option<String>> {
    let constraint = |error: sqlx::Error| match error {
        sqlx::Error::Database(error) => error.constraint().map(str::to_owned),
        _ => None,
    };
    let mut tx = pool.begin().await.map_err(|_| None)?;
    sqlx::query(
        "INSERT INTO org_invitation_emails \
         (invitation_id, recipient, org_id, org_name, org_slug, inviter, role) \
         VALUES ($1, 'invitee@example.test', 'outbox-org', 'Org', 'outbox-org', \
                 'Inviter', 'member')",
    )
    .bind(invitation)
    .execute(&mut *tx)
    .await
    .map_err(constraint)?;
    if let Some(update) = update {
        sqlx::query(&format!(
            "UPDATE org_invitation_emails SET {update} WHERE invitation_id = $1"
        ))
        .bind(invitation)
        .execute(&mut *tx)
        .await
        .map_err(constraint)?;
    }
    tx.commit().await.map_err(constraint)
}

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
struct Invitation {
    id: String,
    email: String,
    status: String,
}

async fn invitations(pool: &PgPool) -> anyhow::Result<Vec<Invitation>> {
    Ok(
        sqlx::query_as("SELECT id, email, status FROM org_invitations ORDER BY id")
            .fetch_all(pool)
            .await?,
    )
}

/// A new outbox row's state.
#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
struct Fresh {
    status: String,
    attempts: i32,
    due: bool,
    claimed: bool,
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn org_invitation_emails_upgrade_constrains_rows_and_rolls_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(20).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed_platform_credential_owners(&pool).await?;
        sqlx::raw_sql(
            "INSERT INTO organizations(id,name,slug,created_by) \
             VALUES ('outbox-org','Org','outbox-org','credential-user-a'); \
             INSERT INTO org_invitations(id,org_id,email,role,invited_by,token_hash,expires_at) \
             VALUES ('outbox-a','outbox-org','a@example.test','member','credential-user-a', \
                     repeat('a', 64), NOW() + INTERVAL '7 days'), \
                    ('outbox-b','outbox-org','b@example.test','admin','credential-user-a', \
                     repeat('b', 64), NOW() + INTERVAL '7 days');",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;
        let invitations = invitations(&pool).await?;

        through(21).run(&pool).await?;
        anyhow::ensure!(
            fingerprint(&pool).await? != previous,
            "0021 changes the schema"
        );
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM org_invitation_emails")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(rows == 0, "the upgrade queues no email");
        anyhow::ensure!(
            self::invitations(&pool).await? == invitations,
            "0021 changes no invitation"
        );

        // A new row is pending, unclaimed and due at once.
        outbox(&pool, "outbox-a", None)
            .await
            .map_err(|c| anyhow::anyhow!("first row: {c:?}"))?;
        let fresh: Fresh = sqlx::query_as(
            "SELECT status, attempts, next_attempt_at <= now() AS due, \
                    claimed_until IS NOT NULL AS claimed \
             FROM org_invitation_emails WHERE invitation_id = 'outbox-a'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(
            fresh
                == Fresh {
                    status: "pending".into(),
                    attempts: 0,
                    due: true,
                    claimed: false
                }
        );

        let refusals = [
            (
                "outbox-a",
                None,
                "org_invitation_emails_pkey",
                "an invitation has one email",
            ),
            (
                "outbox-missing",
                None,
                "org_invitation_emails_invitation_id_fkey",
                "an email belongs to an invitation",
            ),
            (
                "outbox-b",
                Some("role = 'viewer'"),
                "org_invitation_emails_role_check",
                "the role is an organization role",
            ),
            (
                "outbox-b",
                Some("status = 'sending'"),
                "org_invitation_emails_status_check",
                "the status is one the sender writes",
            ),
            (
                "outbox-b",
                Some("attempts = -1"),
                "org_invitation_emails_attempts_check",
                "attempts never go below zero",
            ),
            (
                "outbox-b",
                Some("last_error = repeat('x', 201)"),
                "org_invitation_emails_last_error_check",
                "the reason is bounded",
            ),
            (
                "outbox-b",
                Some("last_error = ''"),
                "org_invitation_emails_last_error_check",
                "a reason is never empty",
            ),
            (
                "outbox-b",
                Some("status = 'sent'"),
                "org_invitation_emails_sent_at_check",
                "a sent email records when",
            ),
            (
                "outbox-b",
                Some("sent_at = now()"),
                "org_invitation_emails_sent_at_check",
                "only a sent email records when",
            ),
            (
                "outbox-b",
                Some("status = 'failed', claimed_until = now()"),
                "org_invitation_emails_claim_check",
                "only a pending email is claimed",
            ),
        ];
        for (invitation, update, constraint, why) in refusals {
            anyhow::ensure!(
                outbox(&pool, invitation, update).await == Err(Some(constraint.to_owned())),
                "{why}"
            );
        }
        outbox(
            &pool,
            "outbox-b",
            Some("status = 'sent', sent_at = now(), attempts = 1, last_error = NULL"),
        )
        .await
        .map_err(|c| anyhow::anyhow!("sent row: {c:?}"))?;

        // A row goes with its invitation.
        sqlx::query("DELETE FROM org_invitations WHERE id = 'outbox-a'")
            .execute(&pool)
            .await?;
        let left: Vec<String> =
            sqlx::query_scalar("SELECT invitation_id FROM org_invitation_emails")
                .fetch_all(&pool)
                .await?;
        anyhow::ensure!(
            left == ["outbox-b"],
            "deleting the invitation deletes its email"
        );

        // Rollback: dropping the table restores the earlier shape.
        sqlx::query("DROP TABLE org_invitation_emails")
            .execute(&pool)
            .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
