//! Disposable-PostgreSQL proof for environment Mesh membership (#3350): a code
//! is used once, only for the Pod and generation it was issued to, only while
//! that Pod is the live binding and the attaching user still qualifies; the
//! recheck tells live, stale and gone members apart; and the stored rows hold
//! no code. Only synthetic rows in an isolated test database are used.

use anyhow::{Result, ensure};

use super::store::{self, AttachmentReport, IssueOutcome, MemberRef, MemberStatus};
use super::*;
use crate::test_database_support::TestDatabase;

const CREATOR: &str = "mesh-creator";
const ORGANIZATION: &str = "mesh-organization";
const OTHER_ORGANIZATION: &str = "mesh-other-organization";
const PRESET: &str = "mesh-preset";
const NAMESPACE: &str = "mesh-sandboxes";
const ENV: &str = "6f1c1a52-38a3-4d6c-9f4e-0e0f7d0b5a11";
const POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
const NEXT_POD: &str = "a1560db3-8899-40c9-b521-500f223b04fb";
const NETWORK: &str = "work";

async fn seed(db: &TestDatabase, generation: i64) -> Result<()> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    db.organization(OTHER_ORGANIZATION).await?;
    sqlx::query(
        "INSERT INTO org_members (id,org_id,user_id,role) VALUES ('mesh-member',$1,$2,'member')",
    )
    .bind(ORGANIZATION)
    .bind(CREATOR)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ($1,$2,'Mesh','mesh', \
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .bind(PRESET)
    .bind(ORGANIZATION)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments \
         (id,org_id,created_by,preset_id,type,name,state,desired_state,project_spec, \
          environment_operation_generation) \
         VALUES ($1,$2,$3,$4,'sandbox','app-1','running','started', \
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb,$5)",
    )
    .bind(ENV)
    .bind(ORGANIZATION)
    .bind(CREATOR)
    .bind(PRESET)
    .bind(generation)
    .execute(&db.pool)
    .await?;
    let mut transaction = db.pool.begin().await?;
    store::insert_attachment(
        &mut transaction,
        ENV,
        &Attachment {
            org_id: ORGANIZATION.into(),
            network_id: NETWORK.into(),
            node_name: "app-1".into(),
        },
        CREATOR,
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

/// Bind `pod` at `generation` and point the backend at it, as a claim-time
/// bind does.
async fn bind(db: &TestDatabase, pod: &str, generation: i64) -> Result<()> {
    sqlx::query(
        "INSERT INTO sandbox_workspace_bindings \
         (pod_uid,environment_id,namespace,pod_name,claim_uid,sandbox_uid, \
          operation_generation,managed_credential_clients,credential_scope) \
         VALUES ($1,$2,$3,$4,'c0ffee00-e29b-41d4-a716-446655440000', \
         '5a4db0c5-e29b-41d4-a716-446655440000',$5,'','pod')",
    )
    .bind(pod)
    .bind(ENV)
    .bind(NAMESPACE)
    .bind(format!("sandbox-{pod}"))
    .bind(generation)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO sandbox_environment_backend \
         (environment_id,namespace,sandbox_claim_name,sandbox_claim_uid,pod_uid,bound_at) \
         VALUES ($1,$2,$3,'c0ffee00-e29b-41d4-a716-446655440000',$4,now()) \
         ON CONFLICT (environment_id) DO UPDATE \
         SET pod_uid = EXCLUDED.pod_uid, bound_at = EXCLUDED.bound_at",
    )
    .bind(ENV)
    .bind(NAMESPACE)
    .bind(format!("sandbox-{ENV}"))
    .bind(pod)
    .execute(&db.pool)
    .await?;
    Ok(())
}

async fn release(db: &TestDatabase, pod: &str) -> Result<()> {
    sqlx::query("UPDATE sandbox_workspace_bindings SET released_at = now() WHERE pod_uid = $1")
        .bind(pod)
        .execute(&db.pool)
        .await?;
    Ok(())
}

async fn execute(db: &TestDatabase, sql: &str) -> Result<()> {
    sqlx::query(sql).bind(ENV).execute(&db.pool).await?;
    Ok(())
}

/// Issue a code for `pod` at `generation`, as the binding listener does.
async fn issue(db: &TestDatabase, pod: &str, generation: i64) -> Result<String> {
    let code = generate_enrollment_code()?;
    let outcome = issue_enrollment(
        &db.pool,
        ENV,
        pod,
        generation,
        &enrollment_code_sha256(&code),
    )
    .await?;
    ensure!(outcome == IssueOutcome::Issued, "{outcome:?}");
    Ok(code)
}

async fn redeem(db: &TestDatabase, code: &str) -> Result<Option<store::Member>> {
    Ok(store::redeem_enrollment(
        &db.pool,
        &enrollment_code_sha256(code),
        ORGANIZATION,
        NETWORK,
    )
    .await?)
}

fn member(pod: &str, generation: i64) -> MemberRef {
    MemberRef {
        environment_id: ENV.into(),
        org_id: ORGANIZATION.into(),
        network_id: NETWORK.into(),
        pod_uid: pod.into(),
        operation_generation: generation,
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_code_admits_once_and_only_its_live_pod_and_generation() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, 3).await?;
        bind(&db, POD, 3).await?;

        // Another organization or network never consumes the code.
        let code = issue(&db, POD, 3).await?;
        let digest = enrollment_code_sha256(&code);
        ensure!(
            store::redeem_enrollment(&db.pool, &digest, OTHER_ORGANIZATION, NETWORK)
                .await?
                .is_none()
        );
        ensure!(
            store::redeem_enrollment(&db.pool, &digest, ORGANIZATION, "other")
                .await?
                .is_none()
        );
        let admitted = redeem(&db, &code).await?.expect("the live Pod's code");
        ensure!(
            admitted
                == store::Member {
                    environment_id: ENV.into(),
                    org_id: ORGANIZATION.into(),
                    network_id: NETWORK.into(),
                    node_name: "app-1".into(),
                    pod_uid: POD.into(),
                    operation_generation: 3,
                    attached_by_user_id: CREATOR.into(),
                }
        );
        // Used once.
        ensure!(redeem(&db, &code).await?.is_none());
        // The table holds only digests.
        let stored: Vec<String> =
            sqlx::query_scalar("SELECT code_sha256 FROM environment_mesh_enrollments")
                .fetch_all(&db.pool)
                .await?;
        ensure!(stored.iter().all(|value| !value.contains(&code[8..])));

        // An expired code is refused.
        let expired = issue(&db, POD, 3).await?;
        sqlx::query(
            "UPDATE environment_mesh_enrollments \
             SET issued_at = now() - interval '2 minutes', \
                 expires_at = now() - interval '1 minute' WHERE code_sha256 = $1",
        )
        .bind(enrollment_code_sha256(&expired))
        .execute(&db.pool)
        .await?;
        ensure!(redeem(&db, &expired).await?.is_none());

        // A new generation (stop/start, or any new operation run) refuses a
        // code captured before it.
        let before_generation = issue(&db, POD, 3).await?;
        execute(&db, "UPDATE environments SET environment_operation_generation = 4 WHERE id = $1")
            .await?;
        ensure!(redeem(&db, &before_generation).await?.is_none());

        // Pod replacement refuses a code issued to the replaced Pod.
        let replaced = issue(&db, POD, 4).await?;
        release(&db, POD).await?;
        bind(&db, NEXT_POD, 4).await?;
        ensure!(redeem(&db, &replaced).await?.is_none());
        let next = issue(&db, NEXT_POD, 4).await?;
        ensure!(redeem(&db, &next).await?.is_some_and(|member| member.pod_uid == NEXT_POD));

        // The attaching user leaving the organization, or being disabled,
        // refuses further codes.
        let after_leaving = issue(&db, NEXT_POD, 4).await?;
        execute(&db, "DELETE FROM org_members WHERE id = 'mesh-member' AND $1 <> ''").await?;
        ensure!(redeem(&db, &after_leaving).await?.is_none());
        sqlx::query(
            "INSERT INTO org_members (id,org_id,user_id,role) VALUES ('mesh-member',$1,$2,'member')",
        )
        .bind(ORGANIZATION)
        .bind(CREATOR)
        .execute(&db.pool)
        .await?;
        let disabled = issue(&db, NEXT_POD, 4).await?;
        sqlx::query("UPDATE users SET enabled = false WHERE id = $1")
            .bind(CREATOR)
            .execute(&db.pool)
            .await?;
        ensure!(redeem(&db, &disabled).await?.is_none());
        sqlx::query("UPDATE users SET enabled = true WHERE id = $1")
            .bind(CREATOR)
            .execute(&db.pool)
            .await?;

        // Stop and destroy refuse codes too.
        let stopping = issue(&db, NEXT_POD, 4).await?;
        execute(&db, "UPDATE environments SET desired_state = 'stopped', state = 'stopping' WHERE id = $1")
            .await?;
        ensure!(redeem(&db, &stopping).await?.is_none());
        execute(&db, "UPDATE environments SET desired_state = 'started', state = 'running' WHERE id = $1")
            .await?;
        let deleting = issue(&db, NEXT_POD, 4).await?;
        execute(&db, "UPDATE environments SET deletion_requested_at = now() WHERE id = $1").await?;
        ensure!(redeem(&db, &deleting).await?.is_none());
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_recheck_tells_live_stale_and_gone_members_apart() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, 3).await?;
        bind(&db, POD, 3).await?;
        let other_network = MemberRef {
            network_id: "other".into(),
            ..member(POD, 3)
        };
        let unknown = MemberRef {
            environment_id: "00000000-0000-4000-8000-000000000000".into(),
            ..member(POD, 3)
        };
        let statuses = store::check_members(
            &db.pool,
            &[
                member(POD, 3),
                member("", 0),
                member(POD, 2),
                member(NEXT_POD, 3),
                other_network,
                unknown,
            ],
        )
        .await?;
        ensure!(
            statuses
                == [
                    MemberStatus::Live,
                    MemberStatus::Live,
                    MemberStatus::Stale,
                    MemberStatus::Stale,
                    MemberStatus::Gone,
                    MemberStatus::Gone,
                ],
            "{statuses:?}"
        );

        // Stopped: the stream is stale, the node may stay.
        release(&db, POD).await?;
        execute(&db, "UPDATE environments SET desired_state = 'stopped', state = 'stopped' WHERE id = $1")
            .await?;
        let statuses = store::check_members(&db.pool, &[member(POD, 3), member("", 0)]).await?;
        ensure!(statuses == [MemberStatus::Stale, MemberStatus::Live], "{statuses:?}");

        // The attaching user leaves the organization: gone.
        execute(&db, "DELETE FROM org_members WHERE id = 'mesh-member' AND $1 <> ''").await?;
        let statuses = store::check_members(&db.pool, &[member("", 0)]).await?;
        ensure!(statuses == [MemberStatus::Gone], "{statuses:?}");
        sqlx::query(
            "INSERT INTO org_members (id,org_id,user_id,role) VALUES ('mesh-member',$1,$2,'member')",
        )
        .bind(ORGANIZATION)
        .bind(CREATOR)
        .execute(&db.pool)
        .await?;

        // Destroying, then the row removed: gone.
        execute(&db, "UPDATE environments SET state = 'destroying', desired_state = 'destroyed' WHERE id = $1")
            .await?;
        let statuses = store::check_members(&db.pool, &[member("", 0)]).await?;
        ensure!(statuses == [MemberStatus::Gone], "{statuses:?}");
        ensure!(store::check_members(&db.pool, &[]).await?.is_empty());
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_issuing_is_bounded_and_reports_read_only_for_the_current_pod() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, 3).await?;
        bind(&db, POD, 3).await?;
        for _ in 0..MAX_OUTSTANDING_ENROLLMENTS {
            issue(&db, POD, 3).await?;
        }
        let refused =
            issue_enrollment(&db.pool, ENV, POD, 3, &"0".repeat(64)).await?;
        ensure!(refused == IssueOutcome::Exhausted, "{refused:?}");
        // Expired and used codes are removed on the next issue.
        execute(
            &db,
            "UPDATE environment_mesh_enrollments SET issued_at = now() - interval '2 minutes', \
             expires_at = now() - interval '1 minute' WHERE environment_id = $1",
        )
        .await?;
        issue(&db, POD, 3).await?;
        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM environment_mesh_enrollments")
                .fetch_one(&db.pool)
                .await?;
        ensure!(rows == 1, "{rows}");
        // A code may not outlive 60 seconds.
        let too_long = sqlx::query(
            "UPDATE environment_mesh_enrollments SET expires_at = issued_at + interval '61 seconds'",
        )
        .execute(&db.pool)
        .await;
        ensure!(too_long.is_err());

        // An environment without an attachment gets no code.
        ensure!(
            issue_enrollment(
                &db.pool,
                "00000000-0000-4000-8000-000000000000",
                POD,
                3,
                &"1".repeat(64)
            )
            .await?
                == IssueOutcome::NotAttached
        );

        // A report shows only while its Pod is the backend's Pod.
        let view = || async {
            sqlx::query_as::<_, (Option<String>, Option<String>, Option<String>)>(&format!(
                "SELECT mesh_network_id, mesh_network_state, mesh_network_failure FROM \
                 (SELECT {} FROM environments e {} WHERE e.id = $1) v",
                crate::api::environments::ENV_SELECT_COLS,
                crate::api::environments::ENV_SELECT_JOINS
            ))
            .bind(ENV)
            .fetch_one(&db.pool)
            .await
        };
        ensure!(view().await? == (Some(NETWORK.into()), Some("pending".into()), None));
        ensure!(
            report_attachment(&db.pool, ENV, POD, AttachmentReport::Failed("not_a_member")).await?
        );
        ensure!(
            view().await?
                == (
                    Some(NETWORK.into()),
                    Some("failed".into()),
                    Some("not_a_member".into())
                )
        );
        ensure!(report_attachment(&db.pool, ENV, POD, AttachmentReport::Attached).await?);
        ensure!(view().await? == (Some(NETWORK.into()), Some("attached".into()), None));
        release(&db, POD).await?;
        bind(&db, NEXT_POD, 3).await?;
        ensure!(view().await? == (Some(NETWORK.into()), Some("pending".into()), None));
        // Only the closed set of failures is stored.
        ensure!(
            report_attachment(&db.pool, ENV, NEXT_POD, AttachmentReport::Failed("other"))
                .await
                .is_err()
        );

        // The attachment and its codes go with the environment.
        execute(&db, "DELETE FROM environments WHERE id = $1").await?;
        let left: i64 = sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM environment_mesh_attachments) + \
                    (SELECT count(*) FROM environment_mesh_enrollments)",
        )
        .fetch_one(&db.pool)
        .await?;
        ensure!(left == 0, "{left}");
        Ok(())
    }
    .await;
    db.finish(result).await
}
