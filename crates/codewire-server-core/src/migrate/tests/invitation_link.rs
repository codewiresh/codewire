//! The invitation link (0036, #4121, #3840): an `invitation_link`
//! verification lives only while its invitation is pending. The upgrade keeps
//! every row; the rollback restores the 0028 shape.

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

/// The purposes left for `identifier`, in order.
async fn verifications_for(pool: &PgPool, identifier: &str) -> anyhow::Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT purpose FROM verifications WHERE identifier = $1 ORDER BY purpose",
    )
    .bind(identifier)
    .fetch_all(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn invitation_link_lives_only_while_its_invitation_is_pending_and_rolls_back()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(35).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        for statement in [
            "INSERT INTO users (id, email, email_verified) VALUES ('owner', 'owner@example.test', true)",
            "INSERT INTO organizations (id, name, slug, created_by) VALUES ('org', 'Org', 'org', 'owner')",
        ] {
            sqlx::query(statement).execute(&pool).await?;
        }
        for invitation in ["accepted", "revoked", "expired", "renewed", "deleted"] {
            sqlx::query(
                "INSERT INTO org_invitations (id, org_id, email, role, invited_by, status, expires_at, token_hash) \
                 VALUES ($1, 'org', $2, 'member', 'owner', 'pending', NOW() + interval '7 days', \
                         encode(sha256(convert_to($1, 'UTF8')), 'hex'))",
            )
            .bind(invitation)
            .bind(format!("{invitation}@example.test"))
            .execute(&pool)
            .await?;
        }
        let previous = fingerprint(&pool).await?;
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM verifications")
            .fetch_one(&pool)
            .await?;

        through(36).run(&pool).await?;
        anyhow::ensure!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM verifications")
                .fetch_one(&pool)
                .await?
                == rows,
            "0036 changes no row"
        );
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        // Each invitation gets a link, and one also has another purpose's row
        // under the same identifier, which nothing here touches.
        for invitation in ["accepted", "revoked", "expired", "renewed", "deleted"] {
            sqlx::query(
                "INSERT INTO verifications (id, identifier, purpose, token_hash, expires_at) \
                 VALUES ($1, $1, 'invitation_link', encode(sha256(convert_to($1, 'UTF8')), 'hex'), \
                         NOW() + interval '7 days')",
            )
            .bind(invitation)
            .execute(&pool)
            .await?;
        }
        sqlx::query(
            "INSERT INTO verifications (id, identifier, purpose, token_hash, expires_at) \
             VALUES ('other-purpose', 'accepted', 'email_verification', encode(sha256('other'::bytea), 'hex'), \
                     NOW() + interval '1 day')",
        )
        .execute(&pool)
        .await?;
        let unknown = sqlx::query(
            "INSERT INTO verifications (id, identifier, purpose, token_hash, expires_at) \
             VALUES ('unknown', 'renewed', 'invitation_accept', encode(sha256('unknown'::bytea), 'hex'), \
                     NOW() + interval '1 day')",
        )
        .execute(&pool)
        .await;
        anyhow::ensure!(
            matches!(&unknown, Err(sqlx::Error::Database(error))
                if error.constraint() == Some("verifications_purpose_check")),
            "only the four purposes: {unknown:?}"
        );

        // Closing an invitation, by any status, or deleting it forgets its
        // link; a change that leaves it pending keeps it.
        for statement in [
            "UPDATE org_invitations SET status = 'accepted', accepted_at = NOW() WHERE id = 'accepted'",
            "UPDATE org_invitations SET status = 'revoked' WHERE id = 'revoked'",
            "UPDATE org_invitations SET status = 'expired' WHERE id = 'expired'",
            "UPDATE org_invitations SET expires_at = NOW() + interval '1 day', status = 'pending' WHERE id = 'renewed'",
            "DELETE FROM org_invitations WHERE id = 'deleted'",
        ] {
            sqlx::query(statement).execute(&pool).await?;
        }
        for (invitation, left) in [
            ("accepted", &["email_verification"][..]),
            ("revoked", &[]),
            ("expired", &[]),
            ("renewed", &["invitation_link"]),
            ("deleted", &[]),
        ] {
            anyhow::ensure!(
                verifications_for(&pool, invitation).await? == left,
                "{invitation}: {:?}",
                verifications_for(&pool, invitation).await?
            );
        }

        // Rollback: drop the triggers and the function, forget the links and
        // restore the previous purpose check.
        for statement in [
            "DROP TRIGGER org_invitations_closed_forget_links ON org_invitations",
            "DROP TRIGGER org_invitations_deleted_forget_links ON org_invitations",
            "DROP FUNCTION codewire_invitation_forgets_its_links()",
            "DELETE FROM verifications WHERE purpose = 'invitation_link'",
            "ALTER TABLE verifications DROP CONSTRAINT verifications_purpose_check",
            "ALTER TABLE verifications ADD CONSTRAINT verifications_purpose_check \
             CHECK (purpose = ANY (ARRAY['email_verification'::text, 'password_reset'::text, 'resend_verification'::text]))",
        ] {
            sqlx::query(statement).execute(&pool).await?;
        }
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
