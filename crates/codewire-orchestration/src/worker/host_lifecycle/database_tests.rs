//! The host lifecycle against a real schema (#3609 slice 2): each activity
//! sends one operation through the seam, a fake host session claims and
//! answers it, recording a done answer's report first as the real session
//! does, and the environment ends where the host's answer puts it.
//! Nothing here can reach the cluster: the host path takes no runtime driver.

use anyhow::{Result, ensure};
use serde_json::to_value;

use super::*;
use crate::api::host_operations::{
    HostEnvironmentObservation, HostEnvironmentState, HostOperation, HostOperationOutcome,
};
use crate::test_database_support::TestDatabase;

const CREATOR: &str = "host-lifecycle-creator";
const ENVIRONMENT: &str = "6a1f3c52-8b04-4d71-9e25-0f4d3b8c7a19";
const ORGANIZATION: &str = "host-lifecycle-organization";
const VM: &str = "1c9e7a40-3f25-4b86-a0d7-5e2b8f6c4d31";
/// An earlier command's operation.
const EARLIER: &str = "3e8a5f17-9c42-4d06-b7e1-2a6d0c9f8b53";
/// How long a test waits for something that must happen before it fails.
const HANG_GUARD: Duration = Duration::from_secs(30);

/// An online host with room, and a pending environment placed on it at
/// operation generation 1. Returns the host's ID.
async fn seed(db: &TestDatabase) -> Result<String> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    let host_id: String = sqlx::query_scalar(
        "INSERT INTO hosts (org_id, owner_user_id, name, platform, capability_version, \
         public_key, provide, max_vms, last_seen_at) VALUES ($1, $2, 'box', \
         'linux-x86_64-kvm', 2, decode(repeat('09', 32), 'hex'), true, 1, now()) RETURNING id",
    )
    .bind(ORGANIZATION)
    .bind(CREATOR)
    .fetch_one(&db.pool)
    .await?;
    let project = to_value(codewire_project::ProjectSpec::default())?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ('host-lifecycle-preset',$1,'Host','host',$2)",
    )
    .bind(ORGANIZATION)
    .bind(&project)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state, \
         environment_operation_generation,isolation_tier,project_spec,runtime_backend,host_id) \
         VALUES ($1,$2,$3,'sandbox','host-lifecycle-preset','pending','started',1,'standard', \
         $4,'host',$5)",
    )
    .bind(ENVIRONMENT)
    .bind(ORGANIZATION)
    .bind(CREATOR)
    .bind(&project)
    .bind(&host_id)
    .execute(&db.pool)
    .await?;
    Ok(host_id)
}

/// A new command: the API's intent change, at operation `generation`.
async fn command(db: &TestDatabase, desired: &str, generation: i64) -> Result<ActivityAuthority> {
    sqlx::query(
        "UPDATE environments SET desired_state = $2, environment_operation_generation = $3 \
         WHERE id = $1",
    )
    .bind(ENVIRONMENT)
    .bind(desired)
    .bind(generation)
    .execute(&db.pool)
    .await?;
    ActivityAuthority::capture(&db.pool, ENVIRONMENT, generation).await
}

fn scope(at: i64) -> OperationScope {
    OperationScope {
        workflow_run_id: "run-1".into(),
        scheduled_at_unix_nanos: at,
    }
}

/// The host's next operation, claimed as its session would.
async fn claim(db: &TestDatabase, host_id: &str) -> Result<HostOperation> {
    let session = host_operations::begin_session(&db.pool, host_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("the host is revoked"))?;
    let give_up = Instant::now() + HANG_GUARD;
    loop {
        let mut claimed = host_operations::claim_pending(&db.pool, host_id, session).await?;
        if let Some(operation) = claimed.pop() {
            ensure!(claimed.is_empty(), "more than one operation: {claimed:?}");
            return Ok(operation);
        }
        ensure!(Instant::now() < give_up, "no operation reached the host");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Waits until the environment is in `wanted`.
async fn entered(db: &TestDatabase, wanted: &str) -> Result<()> {
    let give_up = Instant::now() + HANG_GUARD;
    loop {
        if state(db).await?.0 == wanted {
            return Ok(());
        }
        ensure!(
            Instant::now() < give_up,
            "the environment never became {wanted}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn done(state: proto::HostEnvironmentState, generation: u64) -> HostOperationOutcome {
    result(
        proto::HostEnvironmentObservation {
            environment_id: ENVIRONMENT.into(),
            local_environment_id: VM.into(),
            generation,
            state: state.into(),
            ..Default::default()
        }
        .into(),
    )
}

fn result(outcome: proto::__buffa::oneof::host_operation_result::Outcome) -> HostOperationOutcome {
    HostOperationOutcome::Done {
        result: buffa::Message::encode_to_vec(&proto::HostOperationResult {
            outcome: Some(outcome),
            ..Default::default()
        }),
    }
}

/// Claims the host's next operation, answers it with `outcome`, and returns
/// what the host was sent.
async fn answer_next(
    db: &TestDatabase,
    host_id: &str,
    outcome: HostOperationOutcome,
) -> Result<proto::HostOperation> {
    let operation = claim(db, host_id).await?;
    complete_as_session(db, host_id, &operation.operation_id, &outcome).await?;
    Ok(buffa::Message::decode(&mut operation.payload.as_slice())?)
}

/// Completes an operation as the host's session does: a done answer's
/// report of this environment is recorded before the operation completes.
async fn complete_as_session(
    db: &TestDatabase,
    host_id: &str,
    operation_id: &str,
    outcome: &HostOperationOutcome,
) -> Result<()> {
    use proto::__buffa::oneof::host_operation_result::Outcome;

    if let HostOperationOutcome::Done { result } = outcome {
        let result: proto::HostOperationResult = buffa::Message::decode(&mut result.as_slice())?;
        if let Some(Outcome::Done(report)) = result.outcome
            && report.environment_id == ENVIRONMENT
        {
            let state = match report.state.as_known() {
                Some(proto::HostEnvironmentState::HOST_ENVIRONMENT_STATE_RUNNING) => {
                    HostEnvironmentState::Running
                }
                Some(proto::HostEnvironmentState::HOST_ENVIRONMENT_STATE_STOPPED) => {
                    HostEnvironmentState::Stopped
                }
                Some(proto::HostEnvironmentState::HOST_ENVIRONMENT_STATE_ABSENT) => {
                    HostEnvironmentState::Absent
                }
                other => anyhow::bail!("no fake report for {other:?}"),
            };
            host_operations::record_observation(
                &db.pool,
                host_id,
                &HostEnvironmentObservation {
                    environment_id: ENVIRONMENT.into(),
                    local_environment_id: uuid::Uuid::parse_str(&report.local_environment_id)?,
                    generation: i64::try_from(report.generation)?,
                    state,
                    error_code: None,
                    vcpus: i32::try_from(report.vcpus)?,
                    memory_mib: i32::try_from(report.memory_mib)?,
                    disk_bytes: i64::try_from(report.disk_bytes)?,
                    ssh_host_key: None,
                },
            )
            .await?;
        }
    }
    ensure!(
        host_operations::complete(&db.pool, host_id, operation_id, outcome).await?,
        "the answer was not recorded"
    );
    Ok(())
}

/// An earlier command's create, still open.
async fn earlier_create(db: &TestDatabase, host_id: &str) -> Result<()> {
    host_operations::enqueue(
        &db.pool,
        &NewHostOperation {
            operation_id: EARLIER,
            host_id,
            environment_id: ENVIRONMENT,
            expected_generation: 0,
            kind: HostOperationKind::Create,
            payload: b"an earlier create",
        },
    )
    .await?;
    Ok(())
}

/// How many `complete` rows the environment's log has: what `cw create` and
/// `cw start` wait for.
async fn completions(db: &TestDatabase) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM environment_logs WHERE environment_id = $1 AND phase = 'complete'",
    )
    .bind(ENVIRONMENT)
    .fetch_one(&db.pool)
    .await?)
}

/// Whether the environment's read and session admission both say it has
/// no setup left to wait for.
async fn set_up(db: &TestDatabase) -> Result<bool> {
    let row = sqlx::query(&format!(
        "SELECT {} FROM environments e {} WHERE e.id = $1",
        crate::api::environments::ENV_SELECT_COLS,
        crate::api::environments::ENV_SELECT_JOINS
    ))
    .bind(ENVIRONMENT)
    .fetch_one(&db.pool)
    .await?;
    let read = crate::api::environments::scan_environment(&row)?.setup_complete;
    let admitted =
        crate::api::environment_daemon::setup_admits_sessions(&db.pool, ENVIRONMENT).await?;
    ensure!(read == admitted, "read {read}, admission {admitted}");
    Ok(read)
}

async fn operations(db: &TestDatabase) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM host_operations")
        .fetch_one(&db.pool)
        .await?)
}

async fn state(db: &TestDatabase) -> Result<(String, Option<String>)> {
    Ok(
        sqlx::query_as("SELECT state, error_reason FROM environments WHERE id = $1")
            .bind(ENVIRONMENT)
            .fetch_one(&db.pool)
            .await?,
    )
}

/// Creates the environment, the host answering `outcome`; returns what the
/// host was sent.
async fn create_answered(
    db: &TestDatabase,
    host_id: &str,
    outcome: HostOperationOutcome,
) -> Result<proto::HostOperation> {
    let authority = ActivityAuthority::capture(&db.pool, ENVIRONMENT, 1).await?;
    let scope = scope(10);
    let (created, sent) = tokio::join!(
        create(&db.pool, &authority, &scope),
        answer_next(db, host_id, outcome)
    );
    created?;
    sent
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_host_create_runs_once_the_host_reports_the_vm_running() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let host_id = seed(&db).await?;
        let sent = create_answered(
            &db,
            &host_id,
            done(
                proto::HostEnvironmentState::HOST_ENVIRONMENT_STATE_RUNNING,
                1,
            ),
        )
        .await?;
        ensure!(sent.environment_id == ENVIRONMENT, "{sent:?}");
        ensure!(
            matches!(
                sent.kind,
                Some(proto::__buffa::oneof::host_operation::Kind::Create(_))
            ),
            "{sent:?}"
        );
        ensure!(state(&db).await? == ("running".into(), None));
        let (observed, _) = host_operations::latest_observation(&db.pool, &host_id, ENVIRONMENT)
            .await?
            .ok_or_else(|| anyhow::anyhow!("the VM was not recorded"))?;
        ensure!(observed.local_environment_id.to_string() == VM);
        ensure!(observed.generation == 1 && observed.state == HostEnvironmentState::Running);
        // `cw create` ends on the `complete` row, and a session opens at once.
        ensure!(completions(&db).await? == 1);
        ensure!(set_up(&db).await?, "a host environment waits for setup");
        // Nothing on the host would apply a platform policy, so none is
        // selected after create either.
        sqlx::query(
            "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $2, $3, 'member')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(ORGANIZATION)
        .bind(CREATOR)
        .execute(&db.pool)
        .await?;
        let user = codewire_server_core::auth::AuthUser {
            user_id: CREATOR.into(),
            org_id: None,
            is_admin: false,
            via_api_key: false,
        };
        let refused = crate::api::network_policies::select_for_environment(
            &db.pool,
            &user,
            ORGANIZATION,
            ENVIRONMENT,
            "locked",
        )
        .await;
        ensure!(
            matches!(
                &refused,
                Err(codewire_server_core::AppError::Coded { code, .. })
                    if *code == "host_network_policy_unsupported"
            ),
            "{refused:?}"
        );
        let selections: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM platform_environment_network_policies WHERE environment_id = $1",
        )
        .bind(ENVIRONMENT)
        .fetch_one(&db.pool)
        .await?;
        ensure!(selections == 0, "{selections} selections");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_retried_create_after_the_environment_ran_sends_nothing_new_and_stays_running()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let host_id = seed(&db).await?;
        create_answered(
            &db,
            &host_id,
            done(
                proto::HostEnvironmentState::HOST_ENVIRONMENT_STATE_RUNNING,
                1,
            ),
        )
        .await?;
        // Temporal retries the same activity: the same operation, already
        // answered, so no second VM is asked for.
        let authority = ActivityAuthority::capture(&db.pool, ENVIRONMENT, 1).await?;
        create(&db.pool, &authority, &scope(10)).await?;
        let operations = operations(&db).await?;
        ensure!(operations == 1, "{operations} operations");
        ensure!(completions(&db).await? == 1, "a retry wrote a second row");
        // An attempt that ended running before its row: the retry writes it.
        sqlx::query("DELETE FROM environment_logs WHERE environment_id = $1")
            .bind(ENVIRONMENT)
            .execute(&db.pool)
            .await?;
        create(&db.pool, &authority, &scope(10)).await?;
        ensure!(completions(&db).await? == 1, "the retry wrote no row");
        ensure!(state(&db).await? == ("running".into(), None));
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_host_refusing_a_create_leaves_the_environment_in_error_with_its_words() -> Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        let host_id = seed(&db).await?;
        create_answered(
            &db,
            &host_id,
            result(
                proto::HostOperationFailure {
                    code: "invalid_argument".into(),
                    message: "vcpus must be 1 to 32".into(),
                    ..Default::default()
                }
                .into(),
            ),
        )
        .await?;
        ensure!(
            state(&db).await?
                == (
                    "error".into(),
                    Some("vcpus must be 1 to 32 (invalid_argument)".into())
                )
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_create_answered_with_another_environments_vm_ends_in_error() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let host_id = seed(&db).await?;
        create_answered(
            &db,
            &host_id,
            result(
                proto::HostEnvironmentObservation {
                    environment_id: "0b7d2e94-1c38-4f65-8a20-d6e9f3b1c457".into(),
                    local_environment_id: VM.into(),
                    generation: 1,
                    state: proto::HostEnvironmentState::HOST_ENVIRONMENT_STATE_RUNNING.into(),
                    ..Default::default()
                }
                .into(),
            ),
        )
        .await?;
        // The real session refuses such an answer too, and keeps no report.
        let (now, reason) = state(&db).await?;
        ensure!(now == "error", "left {now} ({reason:?})");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_stop_start_and_destroy_each_name_the_vm_the_host_last_reported_once() -> Result<()> {
    use proto::__buffa::oneof::host_operation::Kind;
    use proto::HostEnvironmentState as Vm;

    let db = TestDatabase::create().await?;
    let result = async {
        let host_id = seed(&db).await?;
        create_answered(&db, &host_id, done(Vm::HOST_ENVIRONMENT_STATE_RUNNING, 1)).await?;

        let steps = [
            (
                Change::Stop,
                "stopped",
                2,
                Vm::HOST_ENVIRONMENT_STATE_STOPPED,
                "stopped",
            ),
            (
                Change::Start,
                "started",
                3,
                Vm::HOST_ENVIRONMENT_STATE_RUNNING,
                "running",
            ),
            (
                Change::Destroy,
                "destroyed",
                4,
                Vm::HOST_ENVIRONMENT_STATE_ABSENT,
                "destroyed",
            ),
        ];
        for (expected_generation, (change, desired, step, vm, ends)) in (1..).zip(steps) {
            // One workflow run makes every command, at the operation
            // generation its create claimed: only the scope tells them apart.
            let authority = command(&db, desired, 1).await?;
            let host_generation = expected_generation + 1;
            let scope = scope(10 + step);
            let (changed, sent) = tokio::join!(
                super::change(&db.pool, &authority, &scope, change),
                answer_next(&db, &host_id, done(vm, host_generation))
            );
            changed?;
            let sent = sent?;
            ensure!(
                sent.local_environment_id == VM && sent.expected_generation == expected_generation,
                "{change:?} sent {sent:?}"
            );
            ensure!(
                matches!(
                    (change, &sent.kind),
                    (Change::Stop, Some(Kind::Stop(_)))
                        | (Change::Start, Some(Kind::Start(_)))
                        | (Change::Destroy, Some(Kind::Destroy(_)))
                ),
                "{change:?} sent {sent:?}"
            );
            let (now, reason) = state(&db).await?;
            ensure!(now == ends, "{change:?} left {now} ({reason:?})");
            // Only a start ends on a `complete` row, after create's, and a
            // retry of it writes no second one.
            let wanted = if change == Change::Stop { 1 } else { 2 };
            // Temporal retries it after it finished: nothing new is sent.
            super::change(&db.pool, &authority, &scope, change).await?;
            let operations = operations(&db).await?;
            ensure!(
                operations == 1 + i64::try_from(expected_generation)?,
                "{change:?} retried: {operations} operations"
            );
            ensure!(state(&db).await?.0 == ends, "{change:?} retried");
            let completions = completions(&db).await?;
            ensure!(
                completions == wanted,
                "{change:?}: {completions} complete rows"
            );
        }
        let cleaned: bool = sqlx::query_scalar(
            "SELECT external_cleanup_completed_at IS NOT NULL FROM environments WHERE id = $1",
        )
        .bind(ENVIRONMENT)
        .fetch_one(&db.pool)
        .await?;
        ensure!(cleaned, "destroy left no cleanup marker");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_destroying_an_environment_the_host_never_reported_sends_nothing() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let authority = command(&db, "destroyed", 2).await?;
        change(&db.pool, &authority, &scope(20), Change::Destroy).await?;
        let operations = operations(&db).await?;
        ensure!(operations == 0, "{operations} operations");
        let (now, reason) = state(&db).await?;
        ensure!(now == "destroyed", "left {now} ({reason:?})");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_destroy_withdraws_a_create_the_host_never_took() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let host_id = seed(&db).await?;
        earlier_create(&db, &host_id).await?;
        let authority = command(&db, "destroyed", 2).await?;
        change(&db.pool, &authority, &scope(20), Change::Destroy).await?;
        // The host never saw it, so nothing was made and nothing is sent.
        ensure!(operations(&db).await? == 0);
        let (now, reason) = state(&db).await?;
        ensure!(now == "destroyed", "left {now} ({reason:?})");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_command_waits_out_an_operation_the_host_took_and_never_withdraws_it() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let host_id = seed(&db).await?;
        earlier_create(&db, &host_id).await?;
        ensure!(claim(&db, &host_id).await?.operation_id == EARLIER);
        let authority = command(&db, "destroyed", 2).await?;
        let next = operation_id(ENVIRONMENT, &scope(20), HostOperationKind::Destroy);
        // The host took the create and has not answered. The next command
        // waits to its deadline: it neither goes on nor withdraws it.
        let settled = settle_open(
            &db.pool,
            &authority,
            ENVIRONMENT,
            &next,
            Instant::now() + Duration::from_secs(1),
        )
        .await?;
        ensure!(
            !settled,
            "the command went on past an operation the host took"
        );
        ensure!(
            operations(&db).await? == 1,
            "the host's operation was withdrawn"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_destroy_waits_for_a_create_the_host_took_and_destroys_the_vm_it_made() -> Result<()> {
    use proto::HostEnvironmentState as Vm;

    let db = TestDatabase::create().await?;
    let result = async {
        let host_id = seed(&db).await?;
        earlier_create(&db, &host_id).await?;
        ensure!(claim(&db, &host_id).await?.operation_id == EARLIER);
        let authority = command(&db, "destroyed", 2).await?;
        let scope = scope(20);
        let host = async {
            // The create finishes only after the destroy has begun, so the
            // destroy meets it as an operation the host took.
            entered(&db, "destroying").await?;
            complete_as_session(
                &db,
                &host_id,
                EARLIER,
                &done(Vm::HOST_ENVIRONMENT_STATE_RUNNING, 1),
            )
            .await?;
            answer_next(&db, &host_id, done(Vm::HOST_ENVIRONMENT_STATE_ABSENT, 2)).await
        };
        let (destroyed, sent) =
            tokio::join!(change(&db.pool, &authority, &scope, Change::Destroy), host);
        destroyed?;
        let sent = sent?;
        ensure!(
            matches!(
                sent.kind,
                Some(proto::__buffa::oneof::host_operation::Kind::Destroy(_))
            ) && sent.local_environment_id == VM
                && sent.expected_generation == 1,
            "{sent:?}"
        );
        let (now, reason) = state(&db).await?;
        ensure!(now == "destroyed", "left {now} ({reason:?})");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_create_the_host_never_answers_ends_in_error_and_is_withdrawn() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let authority = ActivityAuthority::capture(&db.pool, ENVIRONMENT, 1).await?;
        create_until(
            &db.pool,
            &authority,
            &scope(10),
            Instant::now() + Duration::from_secs(1),
        )
        .await?;
        ensure!(state(&db).await? == ("error".into(), Some(UNANSWERED.into())));
        // Nothing runs when the host comes back.
        ensure!(operations(&db).await? == 0);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_command_for_a_revoked_host_ends_in_error_and_sends_nothing() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let host_id = seed(&db).await?;
        create_answered(
            &db,
            &host_id,
            done(
                proto::HostEnvironmentState::HOST_ENVIRONMENT_STATE_RUNNING,
                1,
            ),
        )
        .await?;
        sqlx::query("UPDATE hosts SET revoked_at = now() WHERE id = $1")
            .bind(&host_id)
            .execute(&db.pool)
            .await?;
        let authority = command(&db, "stopped", 2).await?;
        change(&db.pool, &authority, &scope(20), Change::Stop).await?;
        ensure!(
            state(&db).await?
                == (
                    "error".into(),
                    Some("the environment's host was revoked".into())
                )
        );
        ensure!(operations(&db).await? == 1);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_destroying_an_environment_on_a_revoked_host_ends_destroyed_and_sends_nothing()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let host_id = seed(&db).await?;
        create_answered(
            &db,
            &host_id,
            done(
                proto::HostEnvironmentState::HOST_ENVIRONMENT_STATE_RUNNING,
                1,
            ),
        )
        .await?;
        sqlx::query("UPDATE hosts SET revoked_at = now() WHERE id = $1")
            .bind(&host_id)
            .execute(&db.pool)
            .await?;
        // A revoked host never connects again, so a delete must not wait
        // for it or fail on every retry.
        let authority = command(&db, "destroyed", 2).await?;
        change(&db.pool, &authority, &scope(20), Change::Destroy).await?;
        let (now, reason) = state(&db).await?;
        ensure!(now == "destroyed", "left {now} ({reason:?})");
        ensure!(operations(&db).await? == 1);
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// Revokes the host as `revoke_host` does: the mark and the end of its
/// unfinished operations, in one transaction.
async fn revoke(db: &TestDatabase, host_id: &str) -> Result<()> {
    let mut transaction = db.pool.begin().await?;
    sqlx::query("UPDATE hosts SET revoked_at = now() WHERE id = $1")
        .bind(host_id)
        .execute(&mut *transaction)
        .await?;
    host_operations::end_for_revoked_host(&mut transaction, host_id).await?;
    transaction.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_destroy_the_host_took_ends_destroyed_when_the_host_is_revoked() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let host_id = seed(&db).await?;
        create_answered(
            &db,
            &host_id,
            done(
                proto::HostEnvironmentState::HOST_ENVIRONMENT_STATE_RUNNING,
                1,
            ),
        )
        .await?;
        let authority = command(&db, "destroyed", 2).await?;
        let scope = scope(20);
        let host = async {
            // The host takes the destroy and is revoked before it answers.
            claim(&db, &host_id).await?;
            revoke(&db, &host_id).await
        };
        let (destroyed, revoked) =
            tokio::join!(change(&db.pool, &authority, &scope, Change::Destroy), host);
        destroyed?;
        revoked?;
        let (now, reason) = state(&db).await?;
        ensure!(now == "destroyed", "left {now} ({reason:?})");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_delete_does_not_wait_for_what_a_revoked_host_took() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let host_id = seed(&db).await?;
        earlier_create(&db, &host_id).await?;
        ensure!(claim(&db, &host_id).await?.operation_id == EARLIER);
        revoke(&db, &host_id).await?;
        // The create the host took ended with the revocation, so the delete
        // meets no open operation and has no VM to reach.
        let authority = command(&db, "destroyed", 2).await?;
        change_until(
            &db.pool,
            &authority,
            &scope(20),
            Change::Destroy,
            Instant::now() + Duration::from_secs(5),
        )
        .await?;
        let (now, reason) = state(&db).await?;
        ensure!(now == "destroyed", "left {now} ({reason:?})");
        Ok(())
    }
    .await;
    db.finish(result).await
}
