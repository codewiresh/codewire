//! Every durable refresh transition logs one line naming the credential, the
//! attempt and its generations, and never a value (#5957, #4002). Explicit
//! --ignored execution requires TEST_DATABASE_URL.

use std::io::Write;
use std::sync::{Arc, Mutex};

use anyhow::{Result, ensure};
use uuid::Uuid;

use super::support::*;
use super::{create, promoted, started};

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("log capture poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    /// The transition lines for one attempt.
    fn text(&self) -> String {
        let bytes = self.0.lock().map(|bytes| bytes.clone()).unwrap_or_default();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn lines_for(&self, attempt: Uuid) -> Vec<String> {
        self.text()
            .lines()
            .filter(|line| line.contains("provider credential refresh transition"))
            .filter(|line| line.contains(&attempt.to_string()))
            .map(str::to_owned)
            .collect()
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn each_refresh_transition_logs_its_attempt_and_generations_and_no_value() -> Result<()> {
    // The whole process's log: a subscriber on this test's thread alone
    // misses events while the binary's other tests run beside it. Lines are
    // told apart by attempt id, so theirs don't matter.
    let captured = Captured::default();
    let writer = captured.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish(),
    )?;
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("refresh-transitions").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));

        // Reserved, started, staged and committed, with the generations
        // moving once. Staging again, as a lost acknowledgement does, logs
        // nothing more.
        let record = create(&store, &owner, "Committed").await?;
        let (attempt, permit) = started(&store, &owner, &record).await?;
        let encrypted = permit.prepare_result(&value(NEW_VALUE))?;
        store.stage_oauth_refresh(&encrypted).await?;
        store.stage_oauth_refresh(&encrypted).await?;
        let after = store
            .promote_oauth_refresh(&owner, &record.metadata.id, record.version, attempt)
            .await?;
        ensure!(after == promoted(record.version));
        let lines = captured.lines_for(attempt);
        ensure!(lines.len() == 4, "{lines:#?}");
        for (line, outcome) in lines
            .iter()
            .zip(["reserved", "started", "staged", "committed"])
        {
            ensure!(line.contains(&format!("outcome=\"{outcome}\"")), "{line}");
            ensure!(line.contains(record.metadata.id.as_str()), "{line}");
            ensure!(
                line.contains(&format!(
                    "material_generation={}",
                    record.version.material_generation
                )),
                "{line}"
            );
        }
        ensure!(lines[3].contains(&format!(
            "material_generation_after={}",
            after.material_generation
        )));

        // A failed attempt: the credential needs Reconnect.
        let record = create(&store, &owner, "Failed").await?;
        let (attempt, permit) = started(&store, &owner, &record).await?;
        store.fail_oauth_refresh(permit).await?;
        let lines = captured.lines_for(attempt);
        ensure!(lines.len() == 3, "{lines:#?}");
        ensure!(lines[2].contains("outcome=\"failed\""), "{}", lines[2]);

        // A reservation released before it started.
        let record = create(&store, &owner, "Cancelled").await?;
        let attempt = Uuid::new_v4();
        store
            .begin_oauth_refresh(&owner, &record.metadata.id, record.version, attempt)
            .await?;
        store
            .cancel_oauth_refresh(&owner, &record.metadata.id, record.version, attempt)
            .await?;
        let lines = captured.lines_for(attempt);
        ensure!(lines.len() == 2, "{lines:#?}");
        ensure!(lines[1].contains("outcome=\"cancelled\""), "{}", lines[1]);

        let all = captured.text();
        for secret in [OLD_VALUE, NEW_VALUE] {
            ensure!(
                !all.contains(std::str::from_utf8(secret)?),
                "a value was logged"
            );
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}
