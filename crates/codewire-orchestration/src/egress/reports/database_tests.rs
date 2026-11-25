//! The hosted egress report store against PostgreSQL (#4000, P2b).

use anyhow::Context as _;

use super::*;
use crate::test_database_support::TestDatabase;

const ORG: &str = "org-reports";
const OWNER: &str = "org-reports-owner";
const ENV: &str = "env-reports";
const NAMESPACE: &str = "dev-sandboxes";
const POD: &str = "0b8f6a52-0f6c-4a59-9f43-1b1f0c3a9e01";
const OTHER_POD: &str = "0b8f6a52-0f6c-4a59-9f43-1b1f0c3a9e02";
const DIGEST: [u8; 32] = [7; 32];

async fn environment(db: &TestDatabase) -> anyhow::Result<()> {
    db.organization(ORG).await?;
    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING")
        .bind(OWNER)
        .bind(format!("{OWNER}@example.test"))
        .execute(&db.pool)
        .await?;
    sqlx::query(
        "INSERT INTO environment_presets (id, org_id, name, slug, project_spec) \
         VALUES ($1, $2, 'Preset', $1, '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .bind(format!("{ORG}-preset"))
    .bind(ORG)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments \
         (id, org_id, created_by, preset_id, type, name, state, desired_state, project_spec) \
         VALUES ($1, $2, $3, $4, 'sandbox', $1, 'running', 'started', \
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .bind(ENV)
    .bind(ORG)
    .bind(OWNER)
    .bind(format!("{ORG}-preset"))
    .execute(&db.pool)
    .await?;
    Ok(())
}

/// Binds `pod` as the environment's current Pod, as the bind transaction
/// does, including the enforcement row's environment.
async fn bind(db: &TestDatabase, pod: &str) -> anyhow::Result<()> {
    let mut tx = db.pool.begin().await?;
    sqlx::query(
        "UPDATE sandbox_workspace_bindings SET released_at = now() \
         WHERE environment_id = $1 AND released_at IS NULL",
    )
    .bind(ENV)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO sandbox_workspace_bindings \
         (pod_uid,environment_id,namespace,pod_name,claim_uid,sandbox_uid, \
          operation_generation,managed_credential_clients,credential_scope) \
         VALUES ($1,$2,$3,$4,'c0ffee00-e29b-41d4-a716-446655440000', \
         '5a4db0c5-e29b-41d4-a716-446655440000',1,'','pod')",
    )
    .bind(pod)
    .bind(ENV)
    .bind(NAMESPACE)
    .bind(format!("ws-{pod}"))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO sandbox_environment_backend \
         (environment_id,namespace,sandbox_claim_name,sandbox_claim_uid,pod_uid,bound_at) \
         VALUES ($1,$2,$3,'c0ffee00-e29b-41d4-a716-446655440000',$4,now()) \
         ON CONFLICT (environment_id) DO UPDATE SET pod_uid = EXCLUDED.pod_uid, bound_at = now()",
    )
    .bind(ENV)
    .bind(NAMESPACE)
    .bind(format!("claim-{ENV}"))
    .bind(pod)
    .execute(&mut *tx)
    .await?;
    record_bind(&mut tx, pod, ENV).await?;
    tx.commit().await?;
    Ok(())
}

#[derive(sqlx::FromRow, Debug, PartialEq, Eq)]
struct EnforcementRow {
    environment_id: Option<String>,
    node: String,
    state: String,
    revision: Option<i32>,
}

async fn enforcement(db: &TestDatabase, pod: &str) -> anyhow::Result<Option<EnforcementRow>> {
    Ok(sqlx::query_as(
        "SELECT environment_id, node, state, revision FROM sandbox_egress_enforcement WHERE pod_uid = $1",
    )
    .bind(pod)
    .fetch_optional(&db.pool)
    .await?)
}

fn refused(destination: &str, port: u16, first: u64, last: u64, count: u64) -> ReportedRecord {
    ReportedRecord {
        destination: ReportedDestination::Name(destination.to_owned()),
        address: None,
        transport: Transport::Tcp { port },
        outcome: Some(RefusalReason::NameNotAllowed),
        policy_reference: "platform:web".to_owned(),
        policy_revision: 2,
        policy_digest: DIGEST,
        first_seen_unix_ms: first,
        last_seen_unix_ms: last,
        count,
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_pods_environment_comes_only_from_its_bind() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        environment(&db).await?;
        // A warm member reports before any bind: no environment.
        record_enforcement(&db.pool, POD, "runtime-a", &Enforcement::Disconnected).await?;
        let unbound = enforcement(&db, POD).await?.unwrap();
        anyhow::ensure!(unbound.environment_id.is_none() && unbound.node == "runtime-a");

        // The bind sets it and keeps the reported state.
        bind(&db, POD).await?;
        let bound = enforcement(&db, POD).await?.unwrap();
        anyhow::ensure!(bound.environment_id.as_deref() == Some(ENV), "{bound:?}");
        anyhow::ensure!(bound.state == "disconnected");

        // A later report changes state, never the environment.
        record_enforcement(
            &db.pool,
            POD,
            "runtime-a",
            &Enforcement::Enforced {
                revision: 2,
                digest: DIGEST,
            },
        )
        .await?;
        let enforced = enforcement(&db, POD).await?.unwrap();
        anyhow::ensure!(
            enforced
                == EnforcementRow {
                    environment_id: Some(ENV.to_owned()),
                    node: "runtime-a".to_owned(),
                    state: "enforced".to_owned(),
                    revision: Some(2),
                },
            "{enforced:?}"
        );
        anyhow::Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_records_fold_into_the_bound_environment_and_stay_bounded() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        environment(&db).await?;
        // An unbound Pod has no log.
        record_enforcement(&db.pool, POD, "runtime-a", &Enforcement::Disconnected).await?;
        anyhow::ensure!(
            !record_records(&db.pool, POD, &[refused("a.example", 443, 1, 2, 1)]).await?
        );
        bind(&db, POD).await?;

        // Repeats fold: counts add, the window widens.
        record_records(
            &db.pool,
            POD,
            &[refused("example.com", 443, 2_000, 3_000, 2)],
        )
        .await?;
        record_records(
            &db.pool,
            POD,
            &[refused("example.com", 443, 1_000, 5_000, 3)],
        )
        .await?;
        let (count, first, last): (
            i64,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        ) = sqlx::query_as(
            "SELECT count, first_seen, last_seen FROM environment_egress_records \
                 WHERE environment_id = $1 AND destination = 'example.com'",
        )
        .bind(ENV)
        .fetch_one(&db.pool)
        .await?;
        anyhow::ensure!(count == 5, "{count}");
        anyhow::ensure!(first.timestamp_millis() == 1_000 && last.timestamp_millis() == 5_000);

        // The bound holds, the least recently seen go first.
        let limit = u64::try_from(EGRESS_RECORD_LIMIT)?;
        let many: Vec<ReportedRecord> = (0..limit)
            .map(|port| {
                let port = u16::try_from(port + 1)?;
                Ok(refused(
                    "bulk.example",
                    port,
                    10_000 + u64::from(port),
                    10_000 + u64::from(port),
                    1,
                ))
            })
            .collect::<anyhow::Result<_>>()?;
        for chunk in many.chunks(MAX_RECORDS_PER_REPORT) {
            record_records(&db.pool, POD, chunk).await?;
        }
        let (rows, kept_oldest): (i64, bool) = sqlx::query_as(
            "SELECT count(*), bool_or(destination = 'example.com') FROM environment_egress_records \
             WHERE environment_id = $1",
        )
        .bind(ENV)
        .fetch_one(&db.pool)
        .await?;
        anyhow::ensure!(rows == i64::try_from(EGRESS_RECORD_LIMIT)?, "{rows}");
        anyhow::ensure!(!kept_oldest, "the least recently seen record is trimmed");

        // Too many in one report is refused before any write.
        let oversized = vec![refused("x.example", 1, 1, 1, 1); MAX_RECORDS_PER_REPORT + 1];
        anyhow::ensure!(matches!(
            record_records(&db.pool, POD, &oversized).await,
            Err(ReportError::TooManyRecords)
        ));
        anyhow::Ok(())
    }
    .await;
    db.finish(result).await
}

#[derive(sqlx::FromRow, Debug, PartialEq, Eq)]
struct AuditRow {
    org_id: String,
    environment_id: String,
    subject: String,
    count: i64,
    actor_type: String,
    withheld: Option<bool>,
}

/// The refusals the audit log holds, as their subjects, oldest first.
async fn audit_rows(db: &TestDatabase) -> anyhow::Result<Vec<AuditRow>> {
    Ok(sqlx::query_as(
        "SELECT org_id, environment_id, subject, count, actor_type, \
                (detail->>'withheld')::boolean AS withheld \
           FROM sandbox_audit_pending WHERE kind = 'refused' ORDER BY first_at, subject",
    )
    .fetch_all(&db.pool)
    .await?)
}

fn ms(at: chrono::DateTime<chrono::Utc>) -> anyhow::Result<u64> {
    Ok(u64::try_from(at.timestamp_millis())?)
}

/// SPEC.md "The refusal path": each refused record is a `refused` event of
/// the Sandbox, under the environment its binding names and never one a
/// report gives, its count the report's delta, folded per subject and hour.
/// A pass is no event; a name that failed the host check is one, withheld;
/// a Pod bound to no environment writes nothing.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_refused_records_are_the_sandboxs_refused_events_folded_per_hour() -> anyhow::Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        environment(&db).await?;
        let now = chrono::Utc::now();
        let earlier = now - chrono::TimeDelta::hours(2);

        // A warm member's refusals go nowhere.
        record_enforcement(&db.pool, POD, "runtime-a", &Enforcement::Disconnected).await?;
        let at = ms(now)?;
        anyhow::ensure!(
            !record_records(&db.pool, POD, &[refused("a.example", 443, at, at, 1)]).await?
        );
        anyhow::ensure!(audit_rows(&db).await?.is_empty(), "unbound writes nothing");

        bind(&db, POD).await?;
        let withheld = ReportedRecord {
            destination: ReportedDestination::Withheld,
            ..refused("", 22, at, at, 4)
        };
        let pass = ReportedRecord {
            outcome: None,
            ..refused("passed.example", 443, at, at, 9)
        };
        record_records(
            &db.pool,
            POD,
            &[refused("example.com", 443, at, at, 2), withheld, pass],
        )
        .await?;
        // The next report's delta adds to the same hour's fold.
        record_records(&db.pool, POD, &[refused("example.com", 443, at, at, 3)]).await?;
        // The same subject in another hour is another fold.
        let before = ms(earlier)?;
        record_records(
            &db.pool,
            POD,
            &[refused("example.com", 443, before, before, 1)],
        )
        .await?;

        let row = |subject: &str, count: i64, withheld: bool| AuditRow {
            org_id: ORG.to_owned(),
            environment_id: ENV.to_owned(),
            subject: subject.to_owned(),
            count,
            actor_type: "sandbox".to_owned(),
            withheld: Some(withheld),
        };
        let rows = audit_rows(&db).await?;
        anyhow::ensure!(
            rows == [
                row("example.com|tcp|443|name_not_allowed|web|2", 1, false),
                row("(withheld)|tcp|22|name_not_allowed|web|2", 4, true),
                row("example.com|tcp|443|name_not_allowed|web|2", 5, false),
            ],
            "{rows:#?}"
        );
        // The records table names every row, so it keeps no withheld one.
        let named: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM environment_egress_records WHERE destination = ''",
        )
        .fetch_one(&db.pool)
        .await?;
        anyhow::ensure!(named == 0);
        anyhow::Ok(())
    }
    .await;
    db.finish(result).await
}

/// SPEC.md "Sandbox audit log": a refusal names its policy as the read
/// words it. A `platform:id:` reference is looked up in the Sandbox's own
/// organization; one it doesn't hold, another organization's included, is
/// recorded with no name, its revision kept, and never with the id.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_refusal_under_a_stored_policy_id_names_the_organizations_policy() -> anyhow::Result<()>
{
    const OTHER_ORG: &str = "org-reports-other";
    const MINE: &str = "6b1f7c55-2a4f-4b8e-9d4b-1f2e3d4c5b61";
    const THEIRS: &str = "6b1f7c55-2a4f-4b8e-9d4b-1f2e3d4c5b62";
    const NOBODYS: &str = "6b1f7c55-2a4f-4b8e-9d4b-1f2e3d4c5b63";
    let db = TestDatabase::create().await?;
    let result = async {
        environment(&db).await?;
        db.organization(OTHER_ORG).await?;
        for (id, org, name) in [
            (MINE, ORG, "team-docs"),
            (THEIRS, OTHER_ORG, "their-secret"),
        ] {
            sqlx::query(
                "INSERT INTO platform_network_policies (id, org_id, name, current_revision) \
                 VALUES ($1, $2, $3, 2)",
            )
            .bind(id)
            .bind(org)
            .bind(name)
            .execute(&db.pool)
            .await?;
        }
        bind(&db, POD).await?;
        let at = u64::try_from(chrono::Utc::now().timestamp_millis())?;
        let under = |destination: &str, id: &str| ReportedRecord {
            policy_reference: format!("platform:id:{id}"),
            ..refused(destination, 443, at, at, 1)
        };
        record_records(
            &db.pool,
            POD,
            &[
                under("mine.example", MINE),
                under("theirs.example", THEIRS),
                under("nobodys.example", NOBODYS),
            ],
        )
        .await?;
        let rows: Vec<(String, Option<String>, Option<i64>)> = sqlx::query_as(
            "SELECT detail->>'destination', detail->>'policy', (detail->>'revision')::bigint \
               FROM sandbox_audit_pending WHERE kind = 'refused' ORDER BY 1",
        )
        .fetch_all(&db.pool)
        .await?;
        anyhow::ensure!(
            rows == [
                (
                    "mine.example".to_owned(),
                    Some("team-docs".to_owned()),
                    Some(2)
                ),
                ("nobodys.example".to_owned(), None, Some(2)),
                ("theirs.example".to_owned(), None, Some(2)),
            ],
            "{rows:?}"
        );
        let leaked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM sandbox_audit_pending \
              WHERE detail::text LIKE '%their-secret%' OR detail::text LIKE '%platform:id:%'",
        )
        .fetch_one(&db.pool)
        .await?;
        anyhow::ensure!(leaked == 0, "no other organization's name and no id");
        anyhow::Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_sweep_deletes_only_pods_that_are_gone() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        environment(&db).await?;
        bind(&db, POD).await?;
        // The environment moves to another Pod: the first one's row is stale.
        bind(&db, OTHER_POD).await?;
        // An unbound member that reported recently, and one that went quiet.
        record_enforcement(
            &db.pool,
            "warm-recent",
            "runtime-a",
            &Enforcement::Disconnected,
        )
        .await?;
        record_enforcement(
            &db.pool,
            "warm-gone",
            "runtime-a",
            &Enforcement::Disconnected,
        )
        .await?;
        sqlx::query(
            "UPDATE sandbox_egress_enforcement SET reported_at = now() - interval '1 hour' \
             WHERE pod_uid = 'warm-gone'",
        )
        .execute(&db.pool)
        .await?;

        // Re-placement already removed the moved-from Pod's row.
        anyhow::ensure!(enforcement(&db, POD).await?.is_none(), "the moved-from Pod");
        let swept = sweep(&db.pool).await?;
        anyhow::ensure!(swept == 1, "{swept}");
        anyhow::ensure!(enforcement(&db, "warm-gone").await?.is_none());
        anyhow::ensure!(
            enforcement(&db, OTHER_POD).await?.is_some(),
            "the current Pod stays"
        );
        anyhow::ensure!(enforcement(&db, "warm-recent").await?.is_some());

        // An unbind deletes its Pod's row; a report re-creating it while the
        // Pod is bound takes the environment back from the live binding.
        let mut tx = db.pool.begin().await?;
        release_pod(&mut tx, OTHER_POD).await?;
        tx.commit().await?;
        anyhow::ensure!(enforcement(&db, OTHER_POD).await?.is_none(), "released");
        record_enforcement(&db.pool, OTHER_POD, "runtime-a", &Enforcement::Disconnected).await?;
        let recreated = enforcement(&db, OTHER_POD).await?.unwrap();
        anyhow::ensure!(
            recreated.environment_id.as_deref() == Some(ENV),
            "{recreated:?}"
        );
        anyhow::Ok(())
    }
    .await;
    db.finish(result).await
}

async fn status(
    db: &TestDatabase,
) -> anyhow::Result<crate::api::network_policies::EnforcementView> {
    let row = sqlx::query(&format!(
        "SELECT {} FROM environments e {} WHERE e.id = $1",
        crate::api::environments::ENV_SELECT_COLS,
        crate::api::environments::ENV_SELECT_JOINS
    ))
    .bind(ENV)
    .fetch_one(&db.pool)
    .await?;
    let environment = crate::api::environments::scan_environment(&row)?;
    Ok(environment
        .network_policy
        .context("the environment reports its policy")?
        .enforcement)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_status_reads_what_the_current_pod_enforces() -> anyhow::Result<()> {
    use crate::api::network_policies::EnforcementView;
    let db = TestDatabase::create().await?;
    let result = async {
        environment(&db).await?;
        anyhow::ensure!(
            status(&db).await? == EnforcementView::Unconfirmed,
            "no Pod yet"
        );
        bind(&db, POD).await?;
        anyhow::ensure!(
            status(&db).await? == EnforcementView::Unconfirmed,
            "bound, no report"
        );

        // Nothing is selected, so open is: enforcing its digest is ENFORCED.
        let selected = *codewire_egress_policy::CompiledPolicy::open()
            .digest()
            .as_bytes();
        record_enforcement(
            &db.pool,
            POD,
            "runtime-a",
            &Enforcement::Enforced {
                revision: 0,
                digest: selected,
            },
        )
        .await?;
        anyhow::ensure!(matches!(status(&db).await?, EnforcementView::Enforced(_)));

        // Any other digest is an older revision still in force.
        record_enforcement(
            &db.pool,
            POD,
            "runtime-a",
            &Enforcement::Enforced {
                revision: 0,
                digest: DIGEST,
            },
        )
        .await?;
        anyhow::ensure!(matches!(status(&db).await?, EnforcementView::Enforcing(_)));

        record_enforcement(
            &db.pool,
            POD,
            "runtime-a",
            &Enforcement::FailedClosed {
                detail: FailureCode::SelfCheckFailed,
            },
        )
        .await?;
        anyhow::ensure!(
            status(&db).await?
                == EnforcementView::FailedClosed(
                    crate::api::network_policies::FailedClosedReason::SelfCheckFailed
                )
        );

        // A report nobody has refreshed for longer than the bound says nothing.
        record_enforcement(
            &db.pool,
            POD,
            "runtime-a",
            &Enforcement::Enforced {
                revision: 0,
                digest: selected,
            },
        )
        .await?;
        anyhow::ensure!(
            matches!(status(&db).await?, EnforcementView::Enforced(_)),
            "fresh"
        );
        sqlx::query(
            "UPDATE sandbox_egress_enforcement \
             SET reported_at = now() - make_interval(mins => $2) WHERE pod_uid = $1",
        )
        .bind(POD)
        .bind(i32::try_from(
            crate::api::network_policies::ENFORCEMENT_REPORT_STALE_MINUTES + 1,
        )?)
        .execute(&db.pool)
        .await?;
        anyhow::ensure!(status(&db).await? == EnforcementView::Unconfirmed, "stale");

        // A report for a Pod the environment has moved away from is not its status.
        bind(&db, OTHER_POD).await?;
        anyhow::ensure!(
            status(&db).await? == EnforcementView::Unconfirmed,
            "the new Pod"
        );
        anyhow::Ok(())
    }
    .await;
    db.finish(result).await
}

async fn stored_refusal(db: &TestDatabase, pod: &str) -> anyhow::Result<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT lockdown_refusal FROM sandbox_egress_enforcement WHERE pod_uid = $1",
    )
    .bind(pod)
    .fetch_one(&db.pool)
    .await?)
}

/// Every refusal the lockdown check can name. The match fails to compile
/// when one is added, so the stored column's constraint is checked for it.
fn every_lockdown_refusal() -> [LockdownRefusal; 6] {
    let every = [
        LockdownRefusal::NotBrokerMode,
        LockdownRefusal::NotLabelledForItsBinding,
        LockdownRefusal::PolicyUnmanaged,
        LockdownRefusal::PolicyMissing,
        LockdownRefusal::PolicyDiffers {
            policy: "extra".to_owned(),
        },
        LockdownRefusal::PolicyDoesNotSelect,
    ];
    for refusal in &every {
        match refusal {
            LockdownRefusal::NotBrokerMode
            | LockdownRefusal::NotLabelledForItsBinding
            | LockdownRefusal::PolicyUnmanaged
            | LockdownRefusal::PolicyMissing
            | LockdownRefusal::PolicyDiffers { .. }
            | LockdownRefusal::PolicyDoesNotSelect => {}
        }
    }
    every
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_lockdown_refusal_is_the_status_until_the_lockdown_passes_or_the_pod_moves()
-> anyhow::Result<()> {
    use crate::api::network_policies::{EnforcementView, FailedClosedReason};
    let not_applied = EnforcementView::FailedClosed(FailedClosedReason::LockdownNotApplied);
    let db = TestDatabase::create().await?;
    let result = async {
        environment(&db).await?;
        bind(&db, POD).await?;
        for refusal in every_lockdown_refusal() {
            record_lockdown_refusal(&db.pool, POD, &refusal).await?;
            anyhow::ensure!(stored_refusal(&db, POD).await?.as_deref() == Some(refusal.reason()));
        }
        record_lockdown_refusal(&db.pool, POD, &LockdownRefusal::PolicyMissing).await?;
        anyhow::ensure!(status(&db).await? == not_applied, "refused");
        anyhow::ensure!(
            stored_refusal(&db, POD).await?.as_deref() == Some("policy_missing"),
            "the exact refusal is kept for operators"
        );

        // Nothing cw-egress reports, and no age, replaces it.
        let selected = *codewire_egress_policy::CompiledPolicy::open()
            .digest()
            .as_bytes();
        for report in [
            Enforcement::Enforced {
                revision: 0,
                digest: selected,
            },
            Enforcement::Disconnected,
        ] {
            record_enforcement(&db.pool, POD, "runtime-a", &report).await?;
            anyhow::ensure!(status(&db).await? == not_applied, "after {report:?}");
        }
        sqlx::query(
            "UPDATE sandbox_egress_enforcement \
             SET reported_at = now() - interval '1 day' WHERE pod_uid = $1",
        )
        .bind(POD)
        .execute(&db.pool)
        .await?;
        anyhow::ensure!(status(&db).await? == not_applied, "at any age");
        // The bind transaction announcing the same environment keeps it.
        let mut tx = db.pool.begin().await?;
        record_bind(&mut tx, POD, ENV).await?;
        tx.commit().await?;
        anyhow::ensure!(status(&db).await? == not_applied, "the same binding");

        // A passing check clears it; the report is the status again.
        clear_lockdown_refusal(&db.pool, POD).await?;
        anyhow::ensure!(stored_refusal(&db, POD).await?.is_none(), "cleared");
        anyhow::ensure!(
            status(&db).await? == EnforcementView::Unconfirmed,
            "stale report"
        );

        // A bind to another environment clears it.
        record_lockdown_refusal(
            &db.pool,
            POD,
            &LockdownRefusal::PolicyDiffers {
                policy: "extra".to_owned(),
            },
        )
        .await?;
        sqlx::query(
            "INSERT INTO environments \
             (id, org_id, created_by, preset_id, type, name, state, desired_state, project_spec) \
             SELECT 'env-reports-other', org_id, created_by, preset_id, type, 'other', state, \
                    desired_state, project_spec FROM environments WHERE id = $1",
        )
        .bind(ENV)
        .execute(&db.pool)
        .await?;
        let mut tx = db.pool.begin().await?;
        record_bind(&mut tx, POD, "env-reports-other").await?;
        tx.commit().await?;
        anyhow::ensure!(stored_refusal(&db, POD).await?.is_none(), "bound elsewhere");

        // The release removes the Pod's row, refusal and all.
        record_lockdown_refusal(
            &db.pool,
            POD,
            &LockdownRefusal::PolicyDiffers {
                policy: "extra".to_owned(),
            },
        )
        .await?;
        let mut tx = db.pool.begin().await?;
        release_pod(&mut tx, POD).await?;
        tx.commit().await?;
        anyhow::ensure!(enforcement(&db, POD).await?.is_none(), "released");
        anyhow::Ok(())
    }
    .await;
    db.finish(result).await
}
