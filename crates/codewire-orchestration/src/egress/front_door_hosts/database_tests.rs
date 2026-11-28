//! Disposable-PostgreSQL proof of a Pod's front-door row (#6290): each
//! admission replaces its reported set, and a refused first bind's names stay
//! through later admissions.

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
        let first = BTreeSet::from(["api.anthropic.com:443".to_owned()]);
        record(pool, POD, &first).await?;
        ensure!(read(pool, POD).await? == Some(first.clone()));
        ensure!(unserved(pool, POD).await?.is_none(), "not refused");
        record_unserved(pool, POD, &["github.com".to_owned()]).await?;
        let wider = BTreeSet::from([
            "api.anthropic.com:443".to_owned(),
            "github.com:443".to_owned(),
        ]);
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
