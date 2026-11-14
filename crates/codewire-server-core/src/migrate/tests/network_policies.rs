//! Platform network policies (0025, #4000): an upgrade from the shape before
//! it keeps every existing row and adds the policy, revision and selection
//! tables; their constraints refuse what the service never stores; a revision
//! never changes except for losing a deleted author; a selected policy cannot
//! be deleted; deleting an organization deletes its policies and selections;
//! and the rollback restores the earlier shape.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

fn constraint<T>(result: Result<T, sqlx::Error>) -> Option<String> {
    match result {
        Err(sqlx::Error::Database(error)) => error.constraint().map(str::to_owned),
        _ => None,
    }
}

fn refusal<T>(result: Result<T, sqlx::Error>) -> Option<String> {
    match result {
        Err(sqlx::Error::Database(error)) => Some(error.message().to_owned()),
        _ => None,
    }
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

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn network_policies_upgrade_keeps_rows_constrains_new_ones_and_rolls_back()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(24).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        sqlx::raw_sql(
            "INSERT INTO users (id, email) VALUES \
               ('policy-admin', 'admin@example.test'), \
               ('policy-author', 'author@example.test'); \
             INSERT INTO organizations (id, name, slug, created_by) VALUES \
               ('policy-org', 'Policies', 'policy-org', 'policy-admin'), \
               ('policy-gone', 'Gone', 'policy-gone', 'policy-admin'); \
             INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) VALUES \
               ('policy-preset', 'policy-org', 'Preset', 'ready', '{}'::jsonb), \
               ('policy-gone-preset', 'policy-gone', 'Preset', 'ready', '{}'::jsonb); \
             INSERT INTO environments (id, org_id, created_by, type, preset_id, project_spec) VALUES \
               ('policy-env', 'policy-org', 'policy-admin', 'sandbox', 'policy-preset', '{}'::jsonb), \
               ('policy-builtin-env', 'policy-org', 'policy-admin', 'sandbox', 'policy-preset', '{}'::jsonb), \
               ('policy-gone-env', 'policy-gone', 'policy-admin', 'sandbox', 'policy-gone-preset', '{}'::jsonb);",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        through(25).run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);
        let kept: i64 = sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM users WHERE id LIKE 'policy-%') \
                  + (SELECT count(*) FROM organizations WHERE id LIKE 'policy-%') \
                  + (SELECT count(*) FROM environments WHERE id LIKE 'policy-%')",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(kept == 7, "existing rows are kept: {kept}");

        // What the service stores fits.
        let insert_policy = |org: &'static str, name: &'static str| {
            sqlx::query_scalar::<_, String>(
                "INSERT INTO platform_network_policies (org_id, name, current_revision) \
                 VALUES ($1, $2, 1) RETURNING id",
            )
            .bind(org)
            .bind(name)
        };
        let policy = insert_policy("policy-org", "web").fetch_one(&pool).await?;
        let gone = insert_policy("policy-gone", "web").fetch_one(&pool).await?;
        for (id, author) in [(&policy, "policy-author"), (&gone, "policy-admin")] {
            sqlx::query(
                "INSERT INTO platform_network_policy_revisions \
                   (policy_id, revision, document, digest, created_by) \
                 VALUES ($1, 1, '\\x7b7d'::bytea, decode(repeat('ab', 32), 'hex'), $2)",
            )
            .bind(id)
            .bind(author)
            .execute(&pool)
            .await?;
        }
        sqlx::query(
            "INSERT INTO platform_environment_network_policies (environment_id, policy_id) VALUES \
               ('policy-env', $1), ('policy-gone-env', $2); \
             ",
        )
        .bind(&policy)
        .bind(&gone)
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO platform_environment_network_policies (environment_id, builtin) \
             VALUES ('policy-builtin-env', 'locked')",
        )
        .execute(&pool)
        .await?;

        // What it never stores is refused, naming the constraint.
        for (name, expected) in [
            ("Web", "platform_network_policies_name_check"),
            ("-web", "platform_network_policies_name_check"),
            ("open", "platform_network_policies_name_check"),
            ("locked", "platform_network_policies_name_check"),
            ("hosted-default", "platform_network_policies_name_check"),
            ("web", "platform_network_policies_org_name_key"),
        ] {
            let refused = constraint(insert_policy("policy-org", name).fetch_one(&pool).await);
            anyhow::ensure!(refused.as_deref() == Some(expected), "{name}: {refused:?}");
        }
        for (set, expected) in [
            (
                "current_revision = 0",
                "platform_network_policies_current_revision_check",
            ),
            (
                "current_revision = 10001",
                "platform_network_policies_current_revision_check",
            ),
        ] {
            let refused = sqlx::query(&format!(
                "UPDATE platform_network_policies SET {set} WHERE id = $1"
            ))
            .bind(&policy)
            .execute(&pool)
            .await;
            anyhow::ensure!(
                constraint(refused).as_deref() == Some(expected),
                "{set} was not refused by {expected}"
            );
        }
        for (values, expected) in [
            (
                "2, '\\x7b7d'::bytea, '\\x00'::bytea",
                "platform_network_policy_revisions_digest_check",
            ),
            (
                "2, ''::bytea, decode(repeat('ab', 32), 'hex')",
                "platform_network_policy_revisions_document_check",
            ),
            (
                "0, '\\x7b7d'::bytea, decode(repeat('ab', 32), 'hex')",
                "platform_network_policy_revisions_revision_check",
            ),
            (
                "1, '\\x7b7d'::bytea, decode(repeat('ab', 32), 'hex')",
                "platform_network_policy_revisions_pkey",
            ),
        ] {
            let refused = sqlx::query(&format!(
                "INSERT INTO platform_network_policy_revisions \
                   (policy_id, revision, document, digest) VALUES ($1, {values})"
            ))
            .bind(&policy)
            .execute(&pool)
            .await;
            anyhow::ensure!(
                constraint(refused).as_deref() == Some(expected),
                "{values} was not refused by {expected}"
            );
        }
        for (columns, values, expected) in [
            (
                "environment_id",
                "'policy-env-missing'",
                "platform_environment_network_policies_selection_check",
            ),
            (
                "environment_id, builtin",
                "'policy-env-missing', 'hosted-default'",
                "platform_environment_network_policies_builtin_check",
            ),
            (
                "environment_id, policy_id, builtin",
                "'policy-env-missing', 'p', 'open'",
                "platform_environment_network_policies_selection_check",
            ),
        ] {
            let refused = sqlx::query(&format!(
                "INSERT INTO platform_environment_network_policies ({columns}) VALUES ({values})"
            ))
            .execute(&pool)
            .await;
            anyhow::ensure!(
                constraint(refused).as_deref() == Some(expected),
                "{values} was not refused by {expected}"
            );
        }
        for set in [
            "enforced_digest = decode(repeat('ab', 32), 'hex')",
            "enforced_at = now()",
            "enforced_revision = 1, enforced_digest = '\\x00'::bytea, enforced_at = now()",
        ] {
            let refused = sqlx::query(&format!(
                "UPDATE platform_environment_network_policies SET {set} \
                 WHERE environment_id = 'policy-env'"
            ))
            .execute(&pool)
            .await;
            anyhow::ensure!(
                constraint(refused).as_deref()
                    == Some("platform_environment_network_policies_enforced_check"),
                "{set} was not refused"
            );
        }
        sqlx::query(
            "UPDATE platform_environment_network_policies \
             SET enforced_revision = 1, enforced_digest = decode(repeat('ab', 32), 'hex'), \
                 enforced_at = now() \
             WHERE environment_id = 'policy-env'",
        )
        .execute(&pool)
        .await?;

        // A revision never changes, except that deleting its author clears
        // created_by.
        for set in [
            "document = '\\x5b5d'::bytea",
            "digest = decode(repeat('cd', 32), 'hex')",
            "created_by = 'policy-admin'",
            "created_at = now() - interval '1 day'",
        ] {
            let refused = sqlx::query(&format!(
                "UPDATE platform_network_policy_revisions SET {set} WHERE policy_id = $1"
            ))
            .bind(&policy)
            .execute(&pool)
            .await;
            anyhow::ensure!(
                refusal(refused).as_deref() == Some("a network policy revision is immutable"),
                "{set} was accepted"
            );
        }
        sqlx::query("DELETE FROM users WHERE id = 'policy-author'")
            .execute(&pool)
            .await?;
        let author: Option<String> = sqlx::query_scalar(
            "SELECT created_by FROM platform_network_policy_revisions WHERE policy_id = $1",
        )
        .bind(&policy)
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(author.is_none(), "{author:?}");

        // A selected policy cannot be deleted; deleting the environment frees it.
        let refused = sqlx::query("DELETE FROM platform_network_policies WHERE id = $1")
            .bind(&policy)
            .execute(&pool)
            .await;
        anyhow::ensure!(
            constraint(refused).as_deref()
                == Some("platform_environment_network_policies_policy_id_fkey")
        );

        // Organization deletion removes its environments and presets, then the
        // organization: its environments' selections, its policies and their
        // revisions go with them.
        sqlx::raw_sql(
            "DELETE FROM environments WHERE org_id = 'policy-gone'; \
             DELETE FROM environment_presets WHERE org_id = 'policy-gone'; \
             DELETE FROM organizations WHERE id = 'policy-gone';",
        )
        .execute(&pool)
        .await?;
        let left: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM platform_network_policies WHERE id = $1), \
                    (SELECT count(*) FROM platform_network_policy_revisions WHERE policy_id = $1), \
                    (SELECT count(*) FROM platform_environment_network_policies \
                      WHERE environment_id = 'policy-gone-env')",
        )
        .bind(&gone)
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(left == (0, 0, 0), "{left:?}");

        sqlx::query("DELETE FROM environments WHERE id = 'policy-env'")
            .execute(&pool)
            .await?;
        sqlx::query("DELETE FROM platform_network_policies WHERE id = $1")
            .bind(&policy)
            .execute(&pool)
            .await?;

        // Rollback: dropping the tables and the trigger function restores the
        // earlier shape.
        sqlx::raw_sql(
            "DROP TABLE platform_environment_network_policies, \
                        platform_network_policy_revisions, platform_network_policies; \
             DROP FUNCTION codewire_network_policy_revision_immutable();",
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
