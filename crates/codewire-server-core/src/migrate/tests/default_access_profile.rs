//! Default credential profile (0003, #3550): an upgrade from 0002 gives each
//! user with personal profiles their oldest one as the default and nobody
//! else a default; the table admits only the user's own personal profile,
//! refuses the deletion of a default profile, and goes with its user. Its
//! rollback (drop the table and the added key) restores the 0002 schema.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

async fn seed(pool: &PgPool) -> anyhow::Result<()> {
    seed_platform_credential_owners(pool).await?;
    // User A has two personal profiles; the older one, created later by ID
    // order, is the backfilled default. User B has none. Organization A has
    // one, which never gets a default.
    sqlx::raw_sql(
        "BEGIN; \
         INSERT INTO platform_access_profiles(id,user_id,organization_id,name,current_revision,created_at) VALUES \
         ('profile-a-newer','credential-user-a',NULL,'newer',1,now()), \
         ('profile-a-older','credential-user-a',NULL,'older',1,now()-interval '1 day'), \
         ('profile-org-a',NULL,'credential-org-a','shared',1,now()-interval '2 days'); \
         INSERT INTO platform_access_profile_revisions(profile_id,revision) VALUES \
         ('profile-a-newer',1),('profile-a-older',1),('profile-org-a',1); \
         COMMIT;",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn defaults(pool: &PgPool) -> anyhow::Result<Vec<(String, String)>> {
    Ok(sqlx::query_as(
        "SELECT user_id,profile_id FROM platform_access_profile_defaults ORDER BY user_id",
    )
    .fetch_all(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn default_access_profile_upgrade_backfills_the_oldest_and_refuses_deleting_it()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        // The shape before 0003: the baseline and 0002, with profiles.
        let before = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(2).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        let mut connection = PgConnection::connect(&db.url).await?;
        before.run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        seed(&pool).await?;
        let previous = fingerprint(&pool).await?;
        anyhow::ensure!(previous != ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);

        ensure_schema(&db.url).await?;
        anyhow::ensure!(fingerprint(&pool).await? == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);
        anyhow::ensure!(
            defaults(&pool).await?
                == [("credential-user-a".to_owned(), "profile-a-older".to_owned())],
            "backfill: {:?}",
            defaults(&pool).await?
        );

        // Each refusal in its own transaction.
        for (sql, code) in [
            // Another user's profile, an organization profile, a missing one.
            (
                "UPDATE platform_access_profile_defaults SET user_id='credential-user-b'",
                "23503",
            ),
            (
                "INSERT INTO platform_access_profile_defaults(user_id,profile_id) \
                 VALUES('credential-user-b','profile-a-newer')",
                "23503",
            ),
            (
                "UPDATE platform_access_profile_defaults SET profile_id='profile-org-a'",
                "23503",
            ),
            (
                "UPDATE platform_access_profile_defaults SET profile_id='missing'",
                "23503",
            ),
            // A second default for the same user.
            (
                "INSERT INTO platform_access_profile_defaults(user_id,profile_id) \
                 VALUES('credential-user-a','profile-a-newer')",
                "23505",
            ),
            // Deleting the default profile.
            (
                "DELETE FROM platform_access_profiles WHERE id='profile-a-older'",
                "23503",
            ),
        ] {
            let mut tx = pool.begin().await?;
            let error = sqlx::query(sql)
                .execute(&mut *tx)
                .await
                .expect_err("invalid default accepted");
            anyhow::ensure!(
                error.as_database_error().and_then(|e| e.code()).as_deref() == Some(code),
                "{sql}: {error}"
            );
            tx.rollback().await?;
        }

        // A profile that is not the default can be deleted; the default moves
        // only to the user's own profile.
        sqlx::query("UPDATE platform_access_profile_defaults SET profile_id='profile-a-newer'")
            .execute(&pool)
            .await?;
        sqlx::query("DELETE FROM platform_access_profiles WHERE id='profile-a-older'")
            .execute(&pool)
            .await?;
        // The default goes with its user, together with their profiles. User
        // A created both organizations, so those go first.
        sqlx::raw_sql(
            "DELETE FROM organizations WHERE created_by='credential-user-a'; \
             DELETE FROM users WHERE id='credential-user-a';",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(defaults(&pool).await?.is_empty());
        let profiles: i64 = sqlx::query_scalar("SELECT count(*) FROM platform_access_profiles")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(profiles == 0);

        // Rollback: dropping what 0003 added restores the 0002 schema.
        sqlx::raw_sql(
            "DROP TABLE platform_access_profile_defaults; \
             ALTER TABLE platform_access_profiles DROP CONSTRAINT platform_access_profiles_id_user_id_key;",
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
