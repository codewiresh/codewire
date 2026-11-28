//! Disposable-PostgreSQL proof of a Pod's front-door row (#6290, #4003): each
//! admission replaces its reported set and capability, and a refused first
//! bind's names and bound-secret refusal stay through later admissions.

use anyhow::{Result, ensure};

use super::*;
use crate::test_database_support::TestDatabase;

const POD: &str = "0f6c2a8e-3b1d-4c5e-9a7f-2d4b6e8a0c13";

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_refusal_outlives_later_admissions() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let pool = &db.pool;
        ensure!(
            read(pool, POD).await?.is_none(),
            "no report before an admission"
        );
        ensure!(unserved(pool, POD).await?.is_none());
        let first = FrontDoorReport {
            hosts: BTreeSet::from(["api.anthropic.com:443".to_owned()]),
            bound_routes: false,
        };
        record(pool, POD, &first).await?;
        ensure!(read(pool, POD).await? == Some(first.clone()));
        ensure!(unserved(pool, POD).await?.is_none(), "not refused");
        record_unserved(pool, POD, &["github.com".to_owned()]).await?;
        let wider = FrontDoorReport {
            hosts: BTreeSet::from([
                "api.anthropic.com:443".to_owned(),
                "github.com:443".to_owned(),
            ]),
            bound_routes: false,
        };
        record(pool, POD, &wider).await?;
        ensure!(
            read(pool, POD).await? == Some(wider),
            "the admission replaced the set"
        );
        ensure!(
            unserved(pool, POD).await? == Some(vec!["github.com".to_owned()]),
            "the refusal stays"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// #4003: an admission replaces whether the front door serves bound-secret
/// routes with its hosts, and a first bind's bound-secret refusal stays on
/// the row through later admissions; the table takes only the three codes.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_bound_routes_follow_the_admission_and_a_refusal_stays() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let pool = &db.pool;
        let report = |bound_routes| FrontDoorReport {
            hosts: BTreeSet::from(["api.anthropic.com:443".to_owned()]),
            bound_routes,
        };
        record(pool, POD, &report(true)).await?;
        ensure!(read(pool, POD).await? == Some(report(true)));
        ensure!(refusal(pool, POD).await?.is_none(), "not refused");
        record_refusal(
            pool,
            POD,
            "bound_host_conflict",
            "api.fancy.example is named by both FANCY_TOKEN and OTHER_TOKEN",
        )
        .await?;
        record(pool, POD, &report(false)).await?;
        ensure!(
            read(pool, POD).await? == Some(report(false)),
            "the admission replaced the capability"
        );
        ensure!(
            refusal(pool, POD).await?
                == Some(RecordedRefusal {
                    code: "bound_host_conflict".into(),
                    reason: "api.fancy.example is named by both FANCY_TOKEN and OTHER_TOKEN".into(),
                }),
            "the refusal stays"
        );
        ensure!(
            record_refusal(pool, POD, "something_else", "a sentence")
                .await
                .is_err(),
            "only the three codes are kept"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
