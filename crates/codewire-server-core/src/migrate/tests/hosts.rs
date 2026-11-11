//! Hosts (0015, #3609): an upgrade from 0014 keeps every existing row and
//! adds the hosts and host_grants tables; their constraints refuse what the
//! service never stores; a live name is unique per organization while a key
//! is unique for good; deleting an account or an organization deletes its
//! hosts and their grants; and the rollback (drop both tables) restores the
//! 0014 shape.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// Inserts one host from extra columns and values over a valid row with key
/// byte `key`; the error is the constraint's refusal.
async fn insert(
    pool: &PgPool,
    name: &str,
    key: u8,
    columns: &str,
    values: &str,
) -> Result<String, sqlx::Error> {
    sqlx::query_scalar(&format!(
        "INSERT INTO hosts (org_id, owner_user_id, name, platform, capability_version, \
         public_key{columns}) \
         VALUES ('hosts-org', 'hosts-owner', $1, 'linux-x86_64-kvm', 1, \
         decode(repeat(lpad(to_hex($2), 2, '0'), 32), 'hex'){values}) RETURNING id"
    ))
    .bind(name)
    .bind(i32::from(key))
    .fetch_one(pool)
    .await
}

fn constraint(result: Result<String, sqlx::Error>) -> Option<String> {
    match result {
        Err(sqlx::Error::Database(error)) => error.constraint().map(str::to_owned),
        _ => None,
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn hosts_upgrade_keeps_existing_rows_constrains_new_ones_and_rolls_back() -> anyhow::Result<()>
{
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        // The shape before 0015, with two accounts and an organization.
        let before = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(14).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        let mut connection = PgConnection::connect(&db.url).await?;
        before.run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        sqlx::query(
            "INSERT INTO users (id, email) VALUES \
             ('hosts-owner', 'owner@example.test'), \
             ('hosts-member', 'member@example.test')",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) VALUES \
             ('hosts-org', 'Hosts', 'hosts-org', 'hosts-member'), \
             ('hosts-gone', 'Gone', 'hosts-gone', 'hosts-member')",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        let through_0015 = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(15).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        through_0015.run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);
        let kept: i64 = sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM users WHERE id LIKE 'hosts-%') \
                  + (SELECT count(*) FROM organizations WHERE id LIKE 'hosts-%')",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(kept == 4, "existing rows are kept: {kept}");

        // What the service stores fits: a new host provides nothing.
        let host = insert(&pool, "build-box", 1, "", "").await?;
        let (provide, organization_grant): (bool, bool) =
            sqlx::query_as("SELECT provide, organization_grant FROM hosts WHERE id = $1")
                .bind(&host)
                .fetch_one(&pool)
                .await?;
        anyhow::ensure!(!provide && !organization_grant);
        insert(
            &pool,
            "providing",
            2,
            ", provide, max_vms, max_vcpus, max_memory_mib, max_disk_gib",
            ", true, 2, 8, 8192, 200",
        )
        .await?;
        sqlx::query("INSERT INTO host_grants (host_id, user_id) VALUES ($1, 'hosts-member')")
            .bind(&host)
            .execute(&pool)
            .await?;

        // What it never stores is refused, naming the constraint.
        let probe = insert(&pool, "probe", 9, "", "").await?;
        for (set, expected) in [
            ("name = 'Build'", "hosts_name_check"),
            ("name = '-a'", "hosts_name_check"),
            ("platform = 'windows'", "hosts_platform_check"),
            ("capability_version = 0", "hosts_capability_version_check"),
            ("public_key = '\\x00'::bytea", "hosts_public_key_check"),
            ("max_vms = 0", "hosts_limits_check"),
            ("max_memory_mib = 255", "hosts_limits_check"),
            ("provide = true", "hosts_provide_needs_max_vms_check"),
            ("revoked_by = 'hosts-owner'", "hosts_revoked_by_needs_revoked_at_check"),
            ("owner_user_id = 'no-such-user'", "hosts_owner_user_id_fkey"),
        ] {
            let refused = sqlx::query_scalar::<_, String>(&format!(
                "UPDATE hosts SET {set} WHERE id = $1 RETURNING id"
            ))
            .bind(&probe)
            .fetch_one(&pool)
            .await;
            anyhow::ensure!(
                constraint(refused).as_deref() == Some(expected),
                "{set} was not refused by {expected}"
            );
        }
        sqlx::query("DELETE FROM hosts WHERE id = $1")
            .bind(&probe)
            .execute(&pool)
            .await?;
        // A live name once per organization; a key once anywhere.
        for (name, key, expected) in [
            ("build-box", 3, "hosts_org_name_key"),
            ("other", 1, "hosts_public_key_key"),
        ] {
            let refused = constraint(insert(&pool, name, key, "", "").await);
            anyhow::ensure!(refused.as_deref() == Some(expected), "{name}: {refused:?}");
        }

        // A revoked host's name is free again; its key is not.
        sqlx::query("UPDATE hosts SET revoked_at = now() WHERE id = $1")
            .bind(&host)
            .execute(&pool)
            .await?;
        insert(&pool, "build-box", 4, "", "").await?;
        anyhow::ensure!(
            constraint(insert(&pool, "rebuilt", 1, "", "").await).as_deref()
                == Some("hosts_public_key_key")
        );

        // Deleting the organization deletes its hosts and their grants;
        // deleting the account deletes the account's hosts.
        sqlx::query(
            "UPDATE hosts SET org_id = 'hosts-gone' WHERE name = 'build-box' AND revoked_at IS NOT NULL",
        )
        .execute(&pool)
        .await?;
        sqlx::query("DELETE FROM organizations WHERE id = 'hosts-gone'")
            .execute(&pool)
            .await?;
        let left: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM hosts WHERE id = $1), \
                    (SELECT count(*) FROM host_grants WHERE host_id = $1)",
        )
        .bind(&host)
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(left == (0, 0), "{left:?}");
        sqlx::query("DELETE FROM users WHERE id = 'hosts-owner'")
            .execute(&pool)
            .await?;
        let hosts: i64 = sqlx::query_scalar("SELECT count(*) FROM hosts")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(hosts == 0, "{hosts}");

        // Rollback: dropping both tables restores the 0014 shape.
        sqlx::query("DROP TABLE host_grants, hosts")
            .execute(&pool)
            .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
