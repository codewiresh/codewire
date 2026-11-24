//! A Pod's interception trust record against PostgreSQL (#6200, 0052).

use std::collections::HashSet;
use std::time::Duration;

use super::*;
use crate::test_database_support::TestDatabase;

const POD: &str = "4f1c2b8e-6a3d-4e5f-9a7b-1c2d3e4f5a60";
const OTHER_POD: &str = "4f1c2b8e-6a3d-4e5f-9a7b-1c2d3e4f5a61";
const NEW_POD: &str = "4f1c2b8e-6a3d-4e5f-9a7b-1c2d3e4f5a62";

async fn recorded(db: &TestDatabase, pod: &str) -> anyhow::Result<Option<bool>> {
    Ok(
        sqlx::query_scalar(
            "SELECT ca_given FROM sandbox_pod_interception_trust WHERE pod_uid = $1",
        )
        .bind(pod)
        .fetch_optional(&db.pool)
        .await?,
    )
}

/// The first answer is kept: a later record of the other answer reads the
/// first, and the trigger refuses any UPDATE, the same answer included.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_pods_trust_is_recorded_once() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        anyhow::ensure!(record(&db.pool, POD, true).await?);
        anyhow::ensure!(record(&db.pool, POD, false).await?);
        anyhow::ensure!(!record(&db.pool, OTHER_POD, false).await?);
        anyhow::ensure!(!record(&db.pool, OTHER_POD, true).await?);
        for ca_given in [false, true] {
            let update = sqlx::query(
                "UPDATE sandbox_pod_interception_trust SET ca_given = $2 WHERE pod_uid = $1",
            )
            .bind(POD)
            .bind(ca_given)
            .execute(&db.pool)
            .await;
            let refused = matches!(
                &update,
                Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("23514")
            );
            anyhow::ensure!(refused, "UPDATE to {ca_given} was not refused: {update:?}");
        }
        anyhow::ensure!(recorded(&db, POD).await? == Some(true));
        anyhow::ensure!(
            record(&db.pool, "not-a-pod-uid", true).await.is_err(),
            "a UID that is not a Pod UID is refused"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// An admission and a bind racing on two connections, in both orders: the one
/// whose insert commits first decides, and the other, waiting on it, reads
/// that answer, never its own.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_of_two_racing_first_writers_the_first_to_commit_decides() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        for (pod, first) in [(POD, true), (OTHER_POD, false)] {
            let mut holder = db.pool.begin().await?;
            sqlx::query(
                "INSERT INTO sandbox_pod_interception_trust (pod_uid, ca_given) VALUES ($1, $2)",
            )
            .bind(pod)
            .bind(first)
            .execute(&mut *holder)
            .await?;
            let pool = db.pool.clone();
            let second = tokio::spawn(async move { record(&pool, pod, !first).await });
            // The second writer waits on the first's uncommitted row.
            tokio::time::sleep(Duration::from_millis(200)).await;
            anyhow::ensure!(!second.is_finished(), "the second writer did not wait");
            holder.commit().await?;
            let answered = tokio::time::timeout(Duration::from_secs(10), second).await???;
            anyhow::ensure!(
                answered == first,
                "{pod}: the second writer kept its own answer"
            );
            anyhow::ensure!(recorded(&db, pod).await? == Some(first));
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// The sweep deletes the record of a Pod the list doesn't name, keeps a
/// listed Pod's, and keeps one written after the list began even when the
/// list doesn't name it.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_sweep_deletes_only_listed_gone_pods() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        record(&db.pool, POD, true).await?;
        record(&db.pool, OTHER_POD, false).await?;
        let listed_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT now()")
            .fetch_one(&db.pool)
            .await?;
        // Admitted after the list began, so missing from it.
        record(&db.pool, NEW_POD, true).await?;
        let live: HashSet<String> = [OTHER_POD.to_owned()].into();
        anyhow::ensure!(sweep(&db.pool, &live, listed_at).await? == 1);
        anyhow::ensure!(recorded(&db, POD).await?.is_none());
        anyhow::ensure!(recorded(&db, OTHER_POD).await? == Some(false));
        anyhow::ensure!(recorded(&db, NEW_POD).await? == Some(true));
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// A list that fails deletes nothing, however old the records are.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_failed_list_deletes_nothing() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        record(&db.pool, POD, true).await?;
        sqlx::query(
            "ALTER TABLE sandbox_pod_interception_trust DISABLE TRIGGER sandbox_pod_interception_trust_immutable",
        )
        .execute(&db.pool)
        .await?;
        sqlx::query(
            "UPDATE sandbox_pod_interception_trust SET recorded_at = now() - interval '1 day'",
        )
        .execute(&db.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE sandbox_pod_interception_trust ENABLE TRIGGER sandbox_pod_interception_trust_immutable",
        )
        .execute(&db.pool)
        .await?;
        for status in [500, 410] {
            let pods = tests::pods(tests::failing(status));
            anyhow::ensure!(sweep_once(&db.pool, &pods).await.is_err(), "{status}");
            anyhow::ensure!(recorded(&db, POD).await? == Some(true), "{status}");
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}
