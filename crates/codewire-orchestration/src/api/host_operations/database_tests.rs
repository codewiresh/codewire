//! What the host-operation seam promises (#3609, slice 2): an operation is
//! enqueued once under its ID, one at a time per environment, and only for
//! an environment placed on its host; only the host's current session takes
//! it, even across an attach; its answer is recorded once; a pending one can
//! be withdrawn; a waiter wakes when it finishes and gives up at its
//! deadline; and a host's report of an older generation never replaces a
//! newer one.

use super::*;
use crate::test_database_support::TestDatabase;

/// An organization, its owner, one host and two environments on it.
async fn seed(db: &TestDatabase) -> anyhow::Result<String> {
    db.organization("ops-org").await?;
    sqlx::query("INSERT INTO users (id, email) VALUES ('ops-owner', 'ops@example.test')")
        .execute(&db.pool)
        .await?;
    let host: String = sqlx::query_scalar(
        "INSERT INTO hosts (org_id, owner_user_id, name, platform, capability_version, \
         public_key) VALUES ('ops-org', 'ops-owner', 'ops-box', 'linux-x86_64-kvm', 1, \
         decode(repeat('07', 32), 'hex')) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) \
         VALUES ('ops-preset', 'ops-org', 'Preset', 'ready', '{}'::jsonb)",
    )
    .execute(&db.pool)
    .await?;
    for id in ["ops-env-1", "ops-env-2"] {
        sqlx::query(
            "INSERT INTO environments (id, org_id, created_by, type, preset_id, project_spec, \
             runtime_backend, host_id) \
             VALUES ($1, 'ops-org', 'ops-owner', 'sandbox', 'ops-preset', '{}'::jsonb, 'host', $2)",
        )
        .bind(id)
        .bind(&host)
        .execute(&db.pool)
        .await?;
    }
    Ok(host)
}

fn create<'a>(id: &'a str, host: &'a str, environment: &'a str) -> NewHostOperation<'a> {
    NewHostOperation {
        operation_id: id,
        host_id: host,
        environment_id: environment,
        expected_generation: 0,
        kind: HostOperationKind::Create,
        payload: b"\x0a\x02vm",
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_an_operation_is_enqueued_once_and_one_at_a_time_per_environment() -> anyhow::Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        let host = seed(&db).await?;
        let first = enqueue(&db.pool, &create("op-1", &host, "ops-env-1")).await?;
        anyhow::ensure!(first.state == HostOperationState::Pending);
        anyhow::ensure!(first.payload == b"\x0a\x02vm");

        // The same request again is the same operation.
        let again = enqueue(&db.pool, &create("op-1", &host, "ops-env-1")).await?;
        anyhow::ensure!(again == first);

        // A different request under the same ID is refused.
        let changes: [fn(&mut NewHostOperation<'_>); 4] = [
            |operation| operation.payload = b"\x0a\x02vn",
            |operation| operation.environment_id = "ops-env-2",
            |operation| operation.expected_generation = 1,
            |operation| operation.kind = HostOperationKind::Destroy,
        ];
        for change in changes {
            let mut changed = create("op-1", &host, "ops-env-1");
            change(&mut changed);
            anyhow::ensure!(
                matches!(
                    enqueue(&db.pool, &changed).await,
                    Err(HostOperationError::Collision { .. })
                ),
                "{changed:?}"
            );
        }

        // A second unfinished operation for the environment waits its turn;
        // another environment's does not.
        anyhow::ensure!(matches!(
            enqueue(&db.pool, &create("op-2", &host, "ops-env-1")).await,
            Err(HostOperationError::Busy { .. })
        ));
        enqueue(&db.pool, &create("op-3", &host, "ops-env-2")).await?;
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_only_the_current_session_takes_operations_and_an_answer_counts_once()
-> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let host = seed(&db).await?;
        let old = begin_session(&db.pool, &host).await?.unwrap();
        let current = begin_session(&db.pool, &host).await?.unwrap();
        anyhow::ensure!(current == old + 1, "{old} then {current}");

        enqueue(&db.pool, &create("op-1", &host, "ops-env-1")).await?;
        enqueue(&db.pool, &create("op-2", &host, "ops-env-2")).await?;

        // The superseded session takes nothing; the current one takes both,
        // oldest first, and a second claim finds nothing left.
        anyhow::ensure!(claim_pending(&db.pool, &host, old).await?.is_empty());
        let claimed = claim_pending(&db.pool, &host, current).await?;
        let ids: Vec<&str> = claimed.iter().map(|o| o.operation_id.as_str()).collect();
        anyhow::ensure!(ids == ["op-1", "op-2"], "{ids:?}");
        anyhow::ensure!(claimed.iter().all(|o| o.state
            == HostOperationState::Sent {
                session_generation: current
            }));
        anyhow::ensure!(claim_pending(&db.pool, &host, current).await?.is_empty());

        // After a reattach, both are still sent and unanswered.
        let reattached = begin_session(&db.pool, &host).await?.unwrap();
        let unanswered = sent_unanswered(&db.pool, &host).await?;
        anyhow::ensure!(unanswered.len() == 2);

        // An answer counts once, from any session of the host, and never
        // from another host.
        let done = HostOperationOutcome::Done {
            result: b"\x08\x01".to_vec(),
        };
        anyhow::ensure!(!complete(&db.pool, "some-other-host", "op-1", &done).await?);
        anyhow::ensure!(complete(&db.pool, &host, "op-1", &done).await?);
        anyhow::ensure!(!complete(&db.pool, &host, "op-1", &done).await?);
        let failed = HostOperationOutcome::Failed {
            result: None,
            reason: "the supervisor refused: not enough memory".into(),
        };
        anyhow::ensure!(complete(&db.pool, &host, "op-2", &failed).await?);
        anyhow::ensure!(
            get(&db.pool, "op-1").await?.unwrap().state
                == HostOperationState::Done {
                    result: b"\x08\x01".to_vec()
                }
        );
        anyhow::ensure!(
            get(&db.pool, "op-2").await?.unwrap().state
                == HostOperationState::Failed {
                    result: None,
                    reason: "the supervisor refused: not enough memory".into()
                }
        );
        anyhow::ensure!(sent_unanswered(&db.pool, &host).await?.is_empty());

        // A failure the host gave no reason for says so.
        enqueue(&db.pool, &create("op-3", &host, "ops-env-2")).await?;
        claim_pending(&db.pool, &host, reattached).await?;
        let unexplained = HostOperationOutcome::Failed {
            result: None,
            reason: String::new(),
        };
        anyhow::ensure!(complete(&db.pool, &host, "op-3", &unexplained).await?);
        anyhow::ensure!(matches!(
            get(&db.pool, "op-3").await?.unwrap().state,
            HostOperationState::Failed { reason, .. } if reason == "no reason given"
        ));

        // A pending operation is never answered before it was sent.
        enqueue(&db.pool, &create("op-4", &host, "ops-env-1")).await?;
        anyhow::ensure!(!complete(&db.pool, &host, "op-4", &done).await?);

        // A revoked host gets no session, and its pending work stays put.
        sqlx::query("UPDATE hosts SET revoked_at = now() WHERE id = $1")
            .bind(&host)
            .execute(&db.pool)
            .await?;
        anyhow::ensure!(begin_session(&db.pool, &host).await?.is_none());
        anyhow::ensure!(claim_pending(&db.pool, &host, reattached).await?.is_empty());
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_waiter_wakes_when_its_operation_finishes_and_gives_up_at_its_deadline()
-> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let host = seed(&db).await?;
        enqueue(&db.pool, &create("op-1", &host, "ops-env-1")).await?;
        let session = begin_session(&db.pool, &host).await?.unwrap();
        claim_pending(&db.pool, &host, session).await?;

        // Nothing answers: the waiter gives up at its deadline.
        let started = std::time::Instant::now();
        let waited = wait_finished(&db.pool, "op-1", Duration::from_millis(300)).await;
        anyhow::ensure!(matches!(waited, Err(HostOperationError::TimedOut { .. })));
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );

        // The host answers while the waiter waits: it wakes at its next
        // read, a second apart while the operation is young.
        let waiter = {
            let pool = db.pool.clone();
            tokio::spawn(async move {
                let started = std::time::Instant::now();
                let finished = wait_finished(&pool, "op-1", Duration::from_secs(30)).await;
                (finished, started.elapsed())
            })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        let done = HostOperationOutcome::Done {
            result: b"\x08\x01".to_vec(),
        };
        anyhow::ensure!(complete(&db.pool, &host, "op-1", &done).await?);
        let (finished, elapsed) = waiter.await?;
        anyhow::ensure!(finished?.state.is_finished());
        anyhow::ensure!(elapsed < Duration::from_secs(5), "woke after {elapsed:?}");

        // A finished operation returns at once; an unknown one is an error.
        wait_finished(&db.pool, "op-1", Duration::from_millis(1)).await?;
        anyhow::ensure!(matches!(
            wait_finished(&db.pool, "no-such-op", Duration::from_secs(1)).await,
            Err(HostOperationError::Unknown { .. })
        ));
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_hosts_report_of_an_older_generation_never_replaces_a_newer_one() -> anyhow::Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        let host = seed(&db).await?;
        anyhow::ensure!(
            latest_observation(&db.pool, &host, "ops-env-1")
                .await?
                .is_none()
        );
        let local = uuid::Uuid::new_v4();
        let observed = |generation, state| HostEnvironmentObservation {
            environment_id: "ops-env-1".into(),
            local_environment_id: local,
            generation,
            state,
            error_code: (state == HostEnvironmentState::Error).then(|| "image_pull".into()),
            vcpus: 2,
            memory_mib: 4096,
            disk_bytes: 40 << 30,
            ssh_host_key: (state == HostEnvironmentState::Running)
                .then(|| "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== guest".into()),
        };
        anyhow::ensure!(
            record_observation(&db.pool, &host, &observed(2, HostEnvironmentState::Running))
                .await?
        );
        // A late report of the previous boot is kept out.
        anyhow::ensure!(
            !record_observation(&db.pool, &host, &observed(1, HostEnvironmentState::Stopped))
                .await?
        );
        // The same generation's next report replaces it.
        anyhow::ensure!(
            record_observation(&db.pool, &host, &observed(2, HostEnvironmentState::Stopped))
                .await?
        );
        let (latest, _) = latest_observation(&db.pool, &host, "ops-env-1")
            .await?
            .unwrap();
        anyhow::ensure!(
            latest == observed(2, HostEnvironmentState::Stopped),
            "{latest:?}"
        );
        anyhow::ensure!(
            record_observation(&db.pool, &host, &observed(3, HostEnvironmentState::Error)).await?
        );
        let (latest, _) = latest_observation(&db.pool, &host, "ops-env-1")
            .await?
            .unwrap();
        anyhow::ensure!(
            latest == observed(3, HostEnvironmentState::Error),
            "{latest:?}"
        );

        // A VM the control plane does not know is still recorded.
        let mut orphan = observed(5, HostEnvironmentState::Running);
        orphan.environment_id = "forgotten".into();
        anyhow::ensure!(record_observation(&db.pool, &host, &orphan).await?);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_an_operation_is_only_for_an_environment_placed_on_its_unrevoked_host()
-> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let host = seed(&db).await?;
        let other: String = sqlx::query_scalar(
            "INSERT INTO hosts (org_id, owner_user_id, name, platform, capability_version, \
             public_key) VALUES ('ops-org', 'ops-owner', 'ops-other', 'linux-x86_64-kvm', 1, \
             decode(repeat('08', 32), 'hex')) RETURNING id",
        )
        .fetch_one(&db.pool)
        .await?;
        sqlx::query(
            "INSERT INTO environments (id, org_id, created_by, type, preset_id, project_spec) \
             VALUES ('ops-env-k8s', 'ops-org', 'ops-owner', 'sandbox', 'ops-preset', '{}'::jsonb)",
        )
        .execute(&db.pool)
        .await?;

        // Another host's environment, a cluster environment, or none at all.
        for (host_id, environment) in [
            (other.as_str(), "ops-env-1"),
            (host.as_str(), "ops-env-k8s"),
            (host.as_str(), "no-such-environment"),
        ] {
            anyhow::ensure!(
                matches!(
                    enqueue(&db.pool, &create("op-x", host_id, environment)).await,
                    Err(HostOperationError::NotPlaced { .. })
                ),
                "{host_id} {environment}"
            );
        }

        // A revoked host is sent nothing more.
        sqlx::query("UPDATE hosts SET revoked_at = now() WHERE id = $1")
            .bind(&host)
            .execute(&db.pool)
            .await?;
        anyhow::ensure!(matches!(
            enqueue(&db.pool, &create("op-x", &host, "ops-env-1")).await,
            Err(HostOperationError::Revoked { .. })
        ));
        anyhow::ensure!(get(&db.pool, "op-x").await?.is_none());

        // An environment is only ever placed on a host of its own
        // organization.
        db.organization("ops-other-org").await?;
        sqlx::query(
            "INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) \
             VALUES ('ops-other-preset', 'ops-other-org', 'Preset', 'ready', '{}'::jsonb)",
        )
        .execute(&db.pool)
        .await?;
        let crossed = sqlx::query(
            "INSERT INTO environments (id, org_id, created_by, type, preset_id, project_spec, \
             runtime_backend, host_id) VALUES ('ops-env-crossed', 'ops-other-org', 'ops-owner', \
             'sandbox', 'ops-other-preset', '{}'::jsonb, 'host', $1)",
        )
        .bind(&other)
        .execute(&db.pool)
        .await;
        anyhow::ensure!(
            matches!(&crossed, Err(sqlx::Error::Database(error))
                if error.constraint() == Some("environments_host_id_fkey")),
            "{crossed:?}"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_an_attach_waits_for_a_claim_in_flight_and_then_resends_what_it_sent()
-> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let host = seed(&db).await?;
        let old = begin_session(&db.pool, &host).await?.unwrap();
        enqueue(&db.pool, &create("op-1", &host, "ops-env-1")).await?;

        // The old session's claim is in flight, not yet committed.
        let mut claim = db.pool.begin().await?;
        let claimed = claim_pending(&mut *claim, &host, old).await?;
        anyhow::ensure!(claimed.len() == 1);

        // A new attach waits for it rather than slipping in underneath.
        let attach = tokio::spawn({
            let pool = db.pool.clone();
            let host = host.clone();
            async move { begin_session(&pool, &host).await }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        anyhow::ensure!(
            !attach.is_finished(),
            "the attach did not wait for the claim"
        );
        claim.commit().await?;
        let current = attach.await??.unwrap();
        anyhow::ensure!(current == old + 1);

        // So the new session finds the operation sent, and sends it again.
        let unanswered = sent_unanswered(&db.pool, &host).await?;
        anyhow::ensure!(
            unanswered.len() == 1
                && unanswered[0].state
                    == HostOperationState::Sent {
                        session_generation: old
                    },
            "{unanswered:?}"
        );
        // The old session claims nothing more.
        enqueue(&db.pool, &create("op-2", &host, "ops-env-2")).await?;
        anyhow::ensure!(claim_pending(&db.pool, &host, old).await?.is_empty());
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_pending_operation_can_be_withdrawn_and_a_sent_one_cannot() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let host = seed(&db).await?;
        enqueue(&db.pool, &create("op-1", &host, "ops-env-1")).await?;
        anyhow::ensure!(
            open_for_environment(&db.pool, "ops-env-1")
                .await?
                .is_some_and(|operation| operation.operation_id == "op-1")
        );
        anyhow::ensure!(withdraw(&db.pool, "op-1").await?);
        anyhow::ensure!(open_for_environment(&db.pool, "ops-env-1").await?.is_none());
        // Its waiter learns it is gone.
        anyhow::ensure!(matches!(
            wait_finished(&db.pool, "op-1", Duration::from_secs(1)).await,
            Err(HostOperationError::Unknown { .. })
        ));

        // The environment is free for the next one; once sent, only the
        // host's answer ends it.
        enqueue(&db.pool, &create("op-2", &host, "ops-env-1")).await?;
        let session = begin_session(&db.pool, &host).await?.unwrap();
        claim_pending(&db.pool, &host, session).await?;
        anyhow::ensure!(!withdraw(&db.pool, "op-2").await?);
        anyhow::ensure!(open_for_environment(&db.pool, "ops-env-1").await?.is_some());
        Ok(())
    }
    .await;
    db.finish(result).await
}
