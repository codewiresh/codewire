//! Owner-local placeholder roots (0051, #6191): one sealed root per user,
//! shaped like credential material, deleted with its user, with no privilege
//! for PUBLIC; the rollback restores the earlier shape.

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

/// One sealed root row for `user` with `ciphertext_bytes` of ciphertext.
fn root(user: &str, ciphertext_bytes: usize) -> String {
    format!(
        "INSERT INTO platform_local_placeholder_roots (user_id, kek_provider, key_name, \
         key_version, wrapped_dek, wrapped_format, ciphertext, nonce, format) VALUES \
         ('{user}', 'openbao-transit', 'codewire-credentials', 1, '\\x01', 1, \
          decode(repeat('00', {ciphertext_bytes}), 'hex'), decode(repeat('00', 12), 'hex'), 1)"
    )
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn local_placeholder_roots_upgrade_holds_one_sealed_root_per_user_and_rolls_back()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(50).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        sqlx::raw_sql(
            "INSERT INTO users (id, email) VALUES \
               ('root-user', 'root@example.test'), ('root-other', 'other@example.test');",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;
        through(51).run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        anyhow::ensure!(refused(&pool, &root("root-user", 48)).await.is_none());
        // One root per user, only for a user that exists, and only a sealed
        // 32-byte root.
        anyhow::ensure!(refused(&pool, &root("root-user", 48)).await.as_deref() == Some("23505"));
        anyhow::ensure!(
            refused(&pool, &root("root-missing", 48)).await.as_deref() == Some("23503")
        );
        anyhow::ensure!(refused(&pool, &root("root-other", 47)).await.as_deref() == Some("23514"));
        anyhow::ensure!(
            refused(
                &pool,
                &root("root-other", 48).replace("'openbao-transit'", "'local'")
            )
            .await
            .as_deref()
                == Some("23514")
        );
        let public: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.role_table_grants \
             WHERE table_name = 'platform_local_placeholder_roots' AND grantee = 'PUBLIC')",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(
            !public,
            "PUBLIC holds a privilege on local placeholder roots"
        );

        // Deleting the user deletes their root.
        sqlx::query("DELETE FROM users WHERE id = 'root-user'")
            .execute(&pool)
            .await?;
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM platform_local_placeholder_roots")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(left == 0);

        sqlx::raw_sql("DROP TABLE platform_local_placeholder_roots")
            .execute(&pool)
            .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
