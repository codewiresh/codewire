// Versions 1–6 accepted at canonical 9a22ecb46f1f22fbefc83c1bcf7b7dd3fe296df3. These independent SHA-384
// pins prevent an edited historical migration from redefining upgrade proof.
const NETWORK_DELETION_PRIOR_CHECKSUMS: [&str; 6] = [
    "e50b41adb01f071dbdc882d54cdae187ea705f3d96e221fac7edfed574f9f0c575eb80f39999c1287b34f4857c560ee1",
    "d5b897f586e7409bdd3cc48d71be52d08aef773d1d92171733b3dc765a2475ec0513a40704b2c3b88e616de5dae47dc1",
    "ca5021fd087254fade88c3c6c17b7d495d4e522efb5eef5f97b56f969cafc7ca33866419db7fea47ca68eb2741c61534",
    "f63b9b6d4f8661a592efbfd80cd32dc6ca6e60d447463dcdcf5af55cb2dec56bcef8a035788f787716ea0364f3154a71",
    "3371c84f0b82e09c28a1bb4f4e9ce09c8ba9e99cb80acd54b3f0b7e5898b4e9f7070c9878e9c5ba4bc6600cf9db496a0",
    "3aa2bb1cd6ca2e98d8340e413849a06c2935ec15e15a8a01c3d3a8437f94c348b1d5c77b3fdf8dbba8afbdf8e38aa403",
];

fn prior_network_deletion_migrator() -> anyhow::Result<Migrator> {
    let migrations = MESH_MIGRATOR.iter().take(6).cloned().collect::<Vec<_>>();
    anyhow::ensure!(migrations.len() == NETWORK_DELETION_PRIOR_CHECKSUMS.len());
    for (migration, expected) in migrations.iter().zip(NETWORK_DELETION_PRIOR_CHECKSUMS) {
        let actual = migration
            .checksum
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        anyhow::ensure!(
            actual == expected,
            "accepted Mesh migration {} changed",
            migration.version
        );
    }
    Ok(Migrator {
        migrations: std::borrow::Cow::Owned(migrations),
        ..Migrator::DEFAULT
    })
}

fn deletion_node(network_id: &str) -> NodeRecord {
    NodeRecord {
        network_id: network_id.to_owned(),
        name: "pending-node".to_owned(),
        peer_url: String::new(),
        github_id: None,
        owner_subject: "owner".to_owned(),
        authorized_by: "owner".to_owned(),
        enrollment_id: "pending-enrollment".to_owned(),
        authorized_at: Utc::now(),
        last_seen_at: Utc::now(),
    }
}

async fn seed_deletion_metadata(store: &dyn MeshStore, network_id: &str) -> anyhow::Result<()> {
    let now = Utc::now();
    store
        .network_create_with_owner(network_id, "org", "owner", now)
        .await?;
    store
        .network_member_upsert(NetworkMember {
            network_id: network_id.to_owned(),
            subject: "member".to_owned(),
            role: NETWORK_ROLE_MEMBER.to_owned(),
            created_at: now,
            created_by: "owner".to_owned(),
        })
        .await?;
    store
        .invite_create(Invite {
            id: "pending-invite".to_owned(),
            network_id: network_id.to_owned(),
            organization_id: "org".to_owned(),
            created_by_user_id: "owner".to_owned(),
            code_hash: "synthetic-invite-hash".to_owned(),
            expires_at: now + Duration::hours(1),
            created_at: now,
        })
        .await?;
    store
        .node_enrollment_create(NodeEnrollment {
            id: "pending-enrollment".to_owned(),
            network_id: network_id.to_owned(),
            owner_subject: "owner".to_owned(),
            issued_by: "owner".to_owned(),
            node_name: "pending-node".to_owned(),
            token_hash: "synthetic-enrollment-hash".to_owned(),
            uses_remaining: 1,
            expires_at: now + Duration::hours(1),
            created_at: now,
            redeemed_at: None,
        })
        .await?;
    store
        .group_create(Group {
            network_id: network_id.to_owned(),
            name: "group".to_owned(),
            created_at: now,
            created_by: "owner".to_owned(),
        })
        .await?;
    store
        .group_member_add(GroupMember {
            network_id: network_id.to_owned(),
            group_name: "group".to_owned(),
            node_name: "pending-node".to_owned(),
            session_name: "session".to_owned(),
            created_at: now,
        })
        .await?;
    store
        .kv_set(network_id, "settings", "key", vec![1, 2], None)
        .await?;
    store
        .access_grant_create(AccessGrant {
            id: "grant".to_owned(),
            network_id: network_id.to_owned(),
            target_node: "pending-node".to_owned(),
            session_id: None,
            session_name: String::new(),
            verbs: vec!["read".to_owned()],
            audience_subject_kind: "user".to_owned(),
            audience_subject_id: "member".to_owned(),
            audience_display: String::new(),
            issued_by: "owner".to_owned(),
            created_at: now,
            expires_at: now + Duration::hours(1),
            revoked_at: None,
        })
        .await?;
    store
        .task_event_create(TaskEvent {
            event_id: "event".to_owned(),
            network_id: network_id.to_owned(),
            node_name: "pending-node".to_owned(),
            session_id: 1,
            session_name: "session".to_owned(),
            summary: "synthetic task".to_owned(),
            state: "done".to_owned(),
            timestamp: now.to_rfc3339(),
        })
        .await?;
    Ok(())
}

async fn verify_network_deletion_contract(store: &dyn MeshStore) -> anyhow::Result<()> {
    let network_id = "network-delete";
    seed_deletion_metadata(store, network_id).await?;
    store
        .network_create_with_owner("retained", "other-org", "other-owner", Utc::now())
        .await?;
    store
        .kv_set("retained", "settings", "key", vec![3], None)
        .await?;
    for (org, subject) in [
        ("wrong-org", "owner"),
        ("org", "member"),
        ("org", "stranger"),
    ] {
        assert!(matches!(
            store
                .network_delete_by_owner(network_id, org, subject)
                .await,
            Err(StoreError::Forbidden)
        ));
    }
    store.node_register(deletion_node(network_id)).await?;
    assert!(matches!(
        store
            .network_delete_by_owner(network_id, "org", "owner")
            .await,
        Err(StoreError::NetworkNotEmpty)
    ));
    anyhow::ensure!(store.network_member_count(network_id).await? == 2);
    anyhow::ensure!(store.invite_list(network_id).await?.len() == 1);
    store.node_delete(network_id, "pending-node").await?;
    store
        .network_delete_by_owner(network_id, "org", "owner")
        .await?;
    anyhow::ensure!(store.network_organization_id(network_id).await?.is_none());
    anyhow::ensure!(store.network_member_count(network_id).await? == 0);
    anyhow::ensure!(store.invite_list(network_id).await?.is_empty());
    anyhow::ensure!(
        store
            .node_enrollment_get_by_token_hash("synthetic-enrollment-hash")
            .await?
            .is_none()
    );
    anyhow::ensure!(store.group_list(network_id).await?.is_empty());
    anyhow::ensure!(
        store
            .group_member_list(network_id, "group")
            .await?
            .is_empty()
    );
    anyhow::ensure!(store.group_policy_get(network_id, "group").await?.is_none());
    anyhow::ensure!(store.kv_get(network_id, "settings", "key").await?.is_none());
    anyhow::ensure!(
        store
            .access_grant_list(network_id, AccessGrantFilter::default())
            .await?
            .is_empty()
    );
    anyhow::ensure!(
        store
            .task_events_after(
                TaskFilter {
                    network_id: network_id.to_owned(),
                    ..Default::default()
                },
                0
            )
            .await?
            .is_empty()
    );
    anyhow::ensure!(store.kv_get("retained", "settings", "key").await? == Some(vec![3]));
    anyhow::ensure!(store.network_member_count("retained").await? == 1);
    assert!(matches!(
        store
            .network_delete_by_owner(network_id, "org", "owner")
            .await,
        Err(StoreError::NotFound)
    ));
    for (org, subject) in [("org", "owner"), ("other-org", "other-owner")] {
        assert!(matches!(
            store
                .network_create_with_owner(network_id, org, subject, Utc::now())
                .await,
            Err(StoreError::NetworkRetired)
        ));
    }
    anyhow::ensure!(
        store
            .kv_set(network_id, "settings", "late", vec![0], None)
            .await
            .is_err()
    );
    anyhow::ensure!(
        store
            .node_register(deletion_node(network_id))
            .await
            .is_err()
    );
    anyhow::ensure!(
        store
            .invite_consume_and_join("synthetic-invite-hash", Utc::now(), "org", "late-member")
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn network_deletion_memory_contract() -> anyhow::Result<()> {
    verify_network_deletion_contract(&MemoryStore::new()).await
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn network_deletion_upgrade_contract_and_disposable_rollback() -> anyhow::Result<()> {
    let test_db = TestDatabase::create(&test_database_url()?).await?;
    let result = async {
        let pool = PgPoolOptions::new().max_connections(4).connect(&test_db.url).await?;
        prior_network_deletion_migrator()?.run(&pool).await?;
        let prior = applied_migrations(&pool).await?;
        sqlx::raw_sql("CREATE SCHEMA retained_schema; CREATE TABLE retained_schema.marker (value int); INSERT INTO retained_schema.marker VALUES (7); INSERT INTO networks VALUES ('prior-network', now(), 'prior-org'); INSERT INTO network_members VALUES ('prior-network', 'prior-owner', 'owner', now(), 'prior-owner'); INSERT INTO kv VALUES ('prior-network', 'settings', 'key', '\\x0102', NULL);").execute(&pool).await?;
        let store = PostgresMeshStore::connect(&test_db.url).await?;
        let applied = applied_migrations(&pool).await?;
        anyhow::ensure!(applied[..6] == prior);
        anyhow::ensure!(store.kv_get("prior-network", "settings", "key").await? == Some(vec![1, 2]));
        verify_network_deletion_contract(&store).await?;
        let restarted = PostgresMeshStore::connect(&test_db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == applied);
        assert!(matches!(restarted.network_create_with_owner("network-delete", "org", "owner", Utc::now()).await, Err(StoreError::NetworkRetired)));
        drop(restarted);
        drop(store);
        // Only this disposable database's public schema is reset; unrelated
        // schemas, other databases and external credentials are outside scope.
        sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public;").execute(&pool).await?;
        prior_network_deletion_migrator()?.run(&pool).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == prior);
        anyhow::ensure!(sqlx::query_scalar::<_, i32>("SELECT value FROM retained_schema.marker").fetch_one(&pool).await? == 7);
        anyhow::ensure!(!sqlx::query_scalar::<_, bool>("SELECT to_regclass('public.retired_network_names') IS NOT NULL").fetch_one(&pool).await?);
        anyhow::ensure!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM networks").fetch_one(&pool).await? == 0);
        Ok(())
    }.await;
    let cleanup = test_db.drop().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn network_deletion_upgrade_refuses_orphans_without_cleanup() -> anyhow::Result<()> {
    let test_db = TestDatabase::create(&test_database_url()?).await?;
    let result = async {
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&test_db.url)
            .await?;
        prior_network_deletion_migrator()?.run(&pool).await?;
        let prior = applied_migrations(&pool).await?;
        sqlx::query("INSERT INTO kv VALUES ('orphan-network', 'settings', 'key', '\\x0102', NULL)")
            .execute(&pool)
            .await?;
        anyhow::ensure!(PostgresMeshStore::connect(&test_db.url).await.is_err());
        anyhow::ensure!(applied_migrations(&pool).await? == prior);
        anyhow::ensure!(
            sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT value FROM kv WHERE network_id = 'orphan-network'"
            )
            .fetch_one(&pool)
            .await?
                == vec![1, 2]
        );
        anyhow::ensure!(
            !sqlx::query_scalar::<_, bool>(
                "SELECT to_regclass('public.retired_network_names') IS NOT NULL"
            )
            .fetch_one(&pool)
            .await?
        );
        Ok(())
    }
    .await;
    let cleanup = test_db.drop().await;
    result.and(cleanup)
}

async fn wait_for_deletion_lock(pool: &PgPool, query_prefix: &str) -> anyhow::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid() AND wait_event_type = 'Lock' AND query LIKE $1)",
            )
            .bind(format!("{query_prefix}%"))
            .fetch_one(pool)
            .await?;
            if waiting { return anyhow::Ok(()); }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.context("operation did not reach its expected PostgreSQL lock")?
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn network_deletion_serializes_enrollment_and_late_writes() -> anyhow::Result<()> {
    let test_db = TestDatabase::create(&test_database_url()?).await?;
    let result = async {
        let store = Arc::new(PostgresMeshStore::connect(&test_db.url).await?);
        seed_deletion_metadata(store.as_ref(), "race-network").await?;

        // Hold the node table so redemption can acquire its parent lock but
        // cannot insert yet. Deletion must wait and then observe its node.
        let mut hold = store.pool.begin().await?;
        sqlx::query("LOCK TABLE nodes IN SHARE MODE")
            .execute(&mut *hold)
            .await?;
        let redeem_store = store.clone();
        let redeem = tokio::spawn(async move {
            redeem_store
                .node_enrollment_consume_and_register(
                    "synthetic-enrollment-hash",
                    Utc::now(),
                    deletion_node("race-network"),
                )
                .await
        });
        wait_for_deletion_lock(&store.pool, "\n            INSERT INTO nodes").await?;
        let deleting_store = store.clone();
        let deleting = tokio::spawn(async move {
            deleting_store
                .network_delete_by_owner("race-network", "org", "owner")
                .await
        });
        wait_for_deletion_lock(&store.pool, "SELECT organization_id FROM networks").await?;
        hold.commit().await?;
        anyhow::ensure!(redeem.await??.is_some());
        assert!(matches!(deleting.await?, Err(StoreError::NetworkNotEmpty)));
        store.node_delete("race-network", "pending-node").await?;
        let mut pending = store
            .node_enrollment_get_by_token_hash("synthetic-enrollment-hash")
            .await?
            .context("revoked enrollment metadata disappeared")?;
        pending.id = "late-enrollment".to_owned();
        pending.token_hash = "synthetic-late-enrollment-hash".to_owned();
        pending.uses_remaining = 1;
        pending.redeemed_at = None;
        store.node_enrollment_create(pending).await?;

        // Hold a cascade target. Deletion now owns the parent and has inserted
        // its tombstone, but neither deletion nor retirement has committed.
        let mut hold = store.pool.begin().await?;
        sqlx::query("SELECT key FROM kv WHERE network_id = 'race-network' FOR UPDATE")
            .fetch_all(&mut *hold)
            .await?;
        let deleting_store = store.clone();
        let deleting = tokio::spawn(async move {
            deleting_store
                .network_delete_by_owner("race-network", "org", "owner")
                .await
        });
        wait_for_deletion_lock(&store.pool, "DELETE FROM networks").await?;
        let recreating_store = store.clone();
        let recreating = tokio::spawn(async move {
            recreating_store
                .network_create_with_owner("race-network", "other-org", "other-owner", Utc::now())
                .await
        });
        wait_for_deletion_lock(&store.pool, "\n            INSERT INTO networks").await?;
        let writing_store = store.clone();
        let writing = tokio::spawn(async move {
            writing_store
                .kv_set("race-network", "settings", "late", vec![3], None)
                .await
        });
        wait_for_deletion_lock(&store.pool, "\n            INSERT INTO kv").await?;
        let enrolling_store = store.clone();
        let enrolling = tokio::spawn(async move {
            let mut node = deletion_node("race-network");
            node.enrollment_id = "late-enrollment".to_owned();
            enrolling_store
                .node_enrollment_consume_and_register(
                    "synthetic-late-enrollment-hash",
                    Utc::now(),
                    node,
                )
                .await
        });
        wait_for_deletion_lock(&store.pool, "SELECT network_id FROM networks").await?;
        hold.commit().await?;
        deleting.await??;
        assert!(matches!(recreating.await?, Err(StoreError::NetworkRetired)));
        anyhow::ensure!(writing.await?.is_err());
        anyhow::ensure!(enrolling.await?.is_err());
        anyhow::ensure!(
            store
                .network_organization_id("race-network")
                .await?
                .is_none()
        );
        anyhow::ensure!(
            store
                .kv_get("race-network", "settings", "late")
                .await?
                .is_none()
        );
        anyhow::ensure!(store.node_list("race-network").await?.is_empty());
        anyhow::ensure!(store.network_member_count("race-network").await? == 0);
        Ok(())
    }
    .await;
    let cleanup = test_db.drop().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn network_deletion_failure_and_cancellation_roll_back_retirement() -> anyhow::Result<()> {
    let test_db = TestDatabase::create(&test_database_url()?).await?;
    let result = async {
        let store = Arc::new(PostgresMeshStore::connect(&test_db.url).await?);
        seed_deletion_metadata(store.as_ref(), "rollback-network").await?;
        sqlx::raw_sql("CREATE FUNCTION reject_network_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic deletion failure'; END $$; CREATE TRIGGER reject_network_delete BEFORE DELETE ON networks FOR EACH ROW EXECUTE FUNCTION reject_network_delete();").execute(&store.pool).await?;
        anyhow::ensure!(store.network_delete_by_owner("rollback-network", "org", "owner").await.is_err());
        anyhow::ensure!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM retired_network_names").fetch_one(&store.pool).await? == 0);
        anyhow::ensure!(store.network_member_count("rollback-network").await? == 2);
        sqlx::query("DROP TRIGGER reject_network_delete ON networks").execute(&store.pool).await?;

        let mut hold = store.pool.begin().await?;
        sqlx::query("SELECT key FROM kv WHERE network_id = 'rollback-network' FOR UPDATE").fetch_all(&mut *hold).await?;
        let deleting_store = store.clone();
        let deleting = tokio::spawn(async move { deleting_store.network_delete_by_owner("rollback-network", "org", "owner").await });
        wait_for_deletion_lock(&store.pool, "DELETE FROM networks").await?;
        deleting.abort();
        anyhow::ensure!(deleting.await.unwrap_err().is_cancelled());
        hold.commit().await?;
        // Acquiring the parent waits for SQLx's dropped transaction rollback.
        let mut after = store.pool.begin().await?;
        lock_network(&mut after, "rollback-network").await?;
        anyhow::ensure!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM retired_network_names").fetch_one(&mut *after).await? == 0);
        after.commit().await?;
        anyhow::ensure!(store.invite_list("rollback-network").await?.len() == 1);
        anyhow::ensure!(store.kv_get("rollback-network", "settings", "key").await? == Some(vec![1, 2]));
        store.network_delete_by_owner("rollback-network", "org", "owner").await?;
        Ok(())
    }.await;
    let cleanup = test_db.drop().await;
    result.and(cleanup)
}
