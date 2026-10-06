//! Disposable-PostgreSQL proof for the daemon access store: write-once SSH
//! host keys trusted only at the environment's current generation, the
//! generation the live binding carries, and enabled transport zones. Only
//! synthetic rows in an isolated test database are used.

use anyhow::{Result, ensure};

use super::*;
use crate::test_database_support::TestDatabase;

const CREATOR: &str = "host-key-creator";
const ORGANIZATION: &str = "host-key-organization";
const PRESET: &str = "host-key-preset";
const NAMESPACE: &str = "binding-sandboxes";
const ENV: &str = "550e8400-e29b-41d4-a716-446655440000";
const POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
const NEXT_POD: &str = "a1560db3-8899-40c9-b521-500f223b04fb";
const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
const OTHER_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHoVDsBGpvXjHq1Mc3BJ6ANWjUtpnGxFp1yfCaeHRu3T";

async fn seed(db: &TestDatabase, generation: i64) -> Result<()> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ($1,$2,'Host key','host-key', \
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .bind(PRESET)
    .bind(ORGANIZATION)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments \
         (id,org_id,created_by,preset_id,type,state,desired_state,project_spec, \
          environment_operation_generation) \
         VALUES ($1,$2,$3,$4,'sandbox','running','started', \
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb,$5)",
    )
    .bind(ENV)
    .bind(ORGANIZATION)
    .bind(CREATOR)
    .bind(PRESET)
    .bind(generation)
    .execute(&db.pool)
    .await?;
    Ok(())
}

async fn set_generation(db: &TestDatabase, generation: i64) -> Result<()> {
    sqlx::query("UPDATE environments SET environment_operation_generation = $2 WHERE id = $1")
        .bind(ENV)
        .bind(generation)
        .execute(&db.pool)
        .await?;
    Ok(())
}

async fn stored(db: &TestDatabase) -> Result<Vec<(i64, String, String)>> {
    Ok(sqlx::query_as(
        "SELECT operation_generation, pod_uid, public_key FROM sandbox_ssh_host_keys \
         WHERE environment_id = $1 ORDER BY 1",
    )
    .bind(ENV)
    .fetch_all(&db.pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_host_keys_are_write_once_and_trusted_only_at_the_current_generation() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, 3).await?;
        let store = PgBindingStore::from_pool(db.pool.clone());
        ensure!(current_host_key(&db.pool, ENV).await?.is_none());

        let record = |generation, pod, key| store.record_host_key(ENV, generation, pod, key);
        ensure!(record(3, POD, KEY).await? == HostKeyRecord::Recorded);
        ensure!(record(3, POD, KEY).await? == HostKeyRecord::Unchanged);
        ensure!(record(3, POD, OTHER_KEY).await? == HostKeyRecord::Conflict);
        ensure!(stored(&db).await? == vec![(3, POD.to_owned(), KEY.to_owned())]);
        ensure!(current_host_key(&db.pool, ENV).await? == Some((3, KEY.to_owned())));

        // A start, stop or resize moves the generation: the old key is no
        // longer trusted, before and after the next one is recorded.
        set_generation(&db, 4).await?;
        ensure!(current_host_key(&db.pool, ENV).await?.is_none());
        ensure!(record(4, NEXT_POD, OTHER_KEY).await? == HostKeyRecord::Recorded);
        ensure!(stored(&db).await? == vec![(4, NEXT_POD.to_owned(), OTHER_KEY.to_owned())]);
        ensure!(current_host_key(&db.pool, ENV).await? == Some((4, OTHER_KEY.to_owned())));

        // A late call for a superseded generation never displaces the
        // current key and is never trusted.
        ensure!(record(3, POD, KEY).await? == HostKeyRecord::Recorded);
        ensure!(current_host_key(&db.pool, ENV).await? == Some((4, OTHER_KEY.to_owned())));
        ensure!(record(4, NEXT_POD, KEY).await? == HostKeyRecord::Conflict);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_live_binding_carries_the_environment_generation() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, 5).await?;
        let pod_name = format!("sandbox-{ENV}");
        sqlx::query(
            "INSERT INTO sandbox_workspace_bindings \
             (pod_uid,environment_id,namespace,pod_name,claim_uid,sandbox_uid, \
              operation_generation,managed_credential_clients,credential_scope) \
             VALUES ($1,$2,$3,$4,'c0ffee00-e29b-41d4-a716-446655440000', \
             '5a4db0c5-e29b-41d4-a716-446655440000',3,'','pod')",
        )
        .bind(POD)
        .bind(ENV)
        .bind(NAMESPACE)
        .bind(&pod_name)
        .execute(&db.pool)
        .await?;
        sqlx::query(
            "INSERT INTO sandbox_environment_backend \
             (environment_id,namespace,sandbox_claim_name,sandbox_claim_uid,pod_uid,bound_at) \
             VALUES ($1,$2,$3,'c0ffee00-e29b-41d4-a716-446655440000',$4,now())",
        )
        .bind(ENV)
        .bind(NAMESPACE)
        .bind(&pod_name)
        .bind(POD)
        .execute(&db.pool)
        .await?;
        let store = PgBindingStore::from_pool(db.pool.clone());
        let binding = store
            .live_binding(POD, NAMESPACE, &pod_name)
            .await?
            .expect("a live binding");
        // The binding's own generation, and the environment's current one
        // that peer tokens and host keys are bound to.
        ensure!(binding.operation_generation == 3 && binding.environment_generation == 5);
        set_generation(&db, 6).await?;
        let binding = store
            .live_binding(POD, NAMESPACE, &pod_name)
            .await?
            .expect("a live binding");
        ensure!(binding.environment_generation == 6);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_only_enabled_transport_zones_are_read() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        crate::runtime_transport::sync_catalog_json(
            &db.pool,
            r#"{"version":1,"zones":[
                {"name":"dev-hel1","runtime_region":"hel1","peer_relay":{
                    "public_endpoints":["198.51.100.4:41641"],
                    "allocator_url":"http://codewire-udp-relay.dev.svc.cluster.local:8095/internal/udp-relay/allocations",
                    "bind_addrs":["10.0.0.4:41641"]}},
                {"name":"dev-off","runtime_region":"hel1","enabled":false}
            ]}"#,
        )
        .await?;
        let store = PgBindingStore::from_pool(db.pool.clone());
        let zone = store.transport_zone("dev-hel1").await?.expect("enabled zone");
        let relay = zone.peer_relay.expect("peer relay");
        ensure!(relay.public_endpoints == vec!["198.51.100.4:41641".to_owned()]);
        ensure!(relay.allocator_url.ends_with("/internal/udp-relay/allocations"));
        ensure!(store.transport_zone("dev-off").await?.is_none());
        ensure!(store.transport_zone("unknown").await?.is_none());
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_app_ports_follow_expose_and_unexpose() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, 3).await?;
        let store = PgBindingStore::from_pool(db.pool.clone());
        let expose = |port: i32, label: &'static str| {
            sqlx::query(
                "INSERT INTO environment_ports (environment_id, port, label, access) \
                 VALUES ($1, $2, $3, 'creator')",
            )
            .bind(ENV)
            .bind(port)
            .bind(label)
            .execute(&db.pool)
        };
        ensure!(store.app_ports(ENV).await?.is_empty());
        // Exposed ports are the grant's and the push's set, ascending.
        expose(5173, "vite").await?;
        expose(3000, "web").await?;
        ensure!(store.app_ports(ENV).await? == vec![3000, 5173]);
        ensure!(exposed_app_ports(&db.pool, ENV).await? == vec![3000, 5173]);
        // An unexposed port leaves the set at once, while its DNS cleanup is
        // still pending.
        sqlx::query(
            "UPDATE environment_ports SET deletion_requested_at = NOW() \
             WHERE environment_id = $1 AND port = 5173",
        )
        .bind(ENV)
        .execute(&db.pool)
        .await?;
        ensure!(store.app_ports(ENV).await? == vec![3000]);
        // Another environment's ports never appear.
        ensure!(
            store
                .app_ports("6f1c1e2a-0000-4000-8000-000000000000")
                .await?
                .is_empty()
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
