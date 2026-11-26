//! A binding's user-token confirmation (0060, #5688): the upgrade leaves every
//! binding as it was; at most one confirmation is set; the column names a user
//! and clears with them; an older binary's read of a user token's binding finds
//! no confirmation; the rollback restores the 0059 shape.

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

/// Whether `statement` is refused by the constraint `constraint`.
async fn refused_by(pool: &PgPool, statement: &str, constraint: &str) -> anyhow::Result<bool> {
    Ok(match sqlx::query(statement).execute(pool).await {
        Err(sqlx::Error::Database(error)) => error.constraint() == Some(constraint),
        Err(error) => return Err(error.into()),
        Ok(_) => false,
    })
}

async fn confirmations(pool: &PgPool) -> anyhow::Result<(Option<String>, Option<String>)> {
    Ok(sqlx::query_as(
        "SELECT personal_owner_confirmed_by, personal_owner_confirmed_by_user_token \
         FROM platform_environment_access_bindings WHERE environment_id = 'confirm-env'",
    )
    .fetch_one(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_binding_records_which_credential_confirmed_it_and_rolls_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(59).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed_platform_credential_owners(&pool).await?;
        sqlx::raw_sql(
            "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
             VALUES ('confirm-preset','credential-org-a','P','p', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
             INSERT INTO environments(id,org_id,created_by,preset_id,type,state,desired_state, \
             project_spec) \
             VALUES ('confirm-env','credential-org-a','credential-user-a','confirm-preset', \
             'sandbox','running','started', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
             INSERT INTO platform_access_profiles(id,user_id,name,current_revision) \
             VALUES ('confirm-profile','credential-user-a','Work',1); \
             INSERT INTO platform_access_profile_revisions(profile_id,revision) \
             VALUES ('confirm-profile',1); \
             INSERT INTO platform_environment_access_bindings \
             (environment_id,profile_id,profile_revision,personal_owner_confirmed_by) \
             VALUES ('confirm-env','confirm-profile',1,'credential-user-a');",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        through(60).run(&pool).await?;
        // An existing binding is a sign-in's, as it was.
        anyhow::ensure!(
            confirmations(&pool).await? == (Some("credential-user-a".into()), None),
            "an existing binding"
        );

        // At most one confirmation.
        anyhow::ensure!(
            refused_by(
                &pool,
                "UPDATE platform_environment_access_bindings \
                 SET personal_owner_confirmed_by_user_token = 'credential-user-a'",
                "platform_env_access_bindings_one_personal_confirmation",
            )
            .await?,
            "both confirmations are refused"
        );
        sqlx::query(
            "UPDATE platform_environment_access_bindings SET personal_owner_confirmed_by = NULL, \
             personal_owner_confirmed_by_user_token = 'credential-user-a'",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(
            confirmations(&pool).await? == (None, Some("credential-user-a".into())),
            "a user token's confirmation"
        );
        // What an older binary reads of that binding: no confirmation, so it
        // denies the binding's personal grants.
        let older: Option<String> = sqlx::query_scalar(
            "SELECT personal_owner_confirmed_by FROM platform_environment_access_bindings \
             WHERE environment_id = 'confirm-env'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(older.is_none(), "an older binary finds {older:?}");

        // The column names a user, and clears when that user is deleted.
        anyhow::ensure!(
            refused_by(
                &pool,
                "UPDATE platform_environment_access_bindings \
                 SET personal_owner_confirmed_by_user_token = 'no-such-user'",
                "platform_env_access_bindings_user_token_confirmation_fkey",
            )
            .await?,
            "an unknown user is refused"
        );
        sqlx::query(
            "UPDATE platform_environment_access_bindings \
             SET personal_owner_confirmed_by_user_token = 'credential-user-b'",
        )
        .execute(&pool)
        .await?;
        sqlx::query("DELETE FROM users WHERE id = 'credential-user-b'")
            .execute(&pool)
            .await?;
        anyhow::ensure!(
            confirmations(&pool).await? == (None, None),
            "a deleted user's confirmation clears"
        );

        // Rollback: drop the column, with its check and key.
        sqlx::raw_sql(
            "ALTER TABLE platform_environment_access_bindings \
             DROP COLUMN personal_owner_confirmed_by_user_token;",
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
