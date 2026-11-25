//! A stopping owner drains a pending device approval instead of cancelling
//! it, and every enrollment that stores nothing ends with a definite reason
//! (#6535).

use super::*;

/// The closed terminal error: its Connect code and the service's fixed text.
async fn terminal(stream: &mut ConnectStream, code: &str, message: &str) -> Result<()> {
    let value = stream.next().await?.context("missing terminal error")?;
    ensure!(
        value["error"]["code"] == code && value["error"]["message"] == message,
        "unexpected closed Connect error: {value}"
    );
    ensure!(stream.next().await?.is_none());
    Ok(())
}

async fn challenged_github(h: &Harness) -> Result<ConnectStream> {
    let mut stream = h.rpc.enroll_github_request(Auth::Alice, json!({})).await?;
    let frame = stream.next().await?.context("missing GitHub challenge")?;
    ensure!(frame["challenge"]["userCode"] == USER_CODE);
    Ok(stream)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_drain_lets_a_pending_approval_publish_and_admits_nothing_new() -> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        let mut stream = challenged_github(&h).await?;
        let owner = h.owner.clone();
        let drain = tokio::spawn(async move { owner.drain(HANG_GUARD).await });
        h.wait_drain_started().await?;
        // Nothing new is admitted: neither another enrollment nor a unary
        // mutation.
        h.rpc
            .enroll(Auth::Alice, "admitted-while-draining")
            .await?
            .error("unavailable")
            .await?;
        h.assert_admission_closed().await?;
        // The pending approval is not cancelled, and the drain waits for it.
        tokio::time::sleep(Duration::from_millis(200)).await;
        ensure!(
            !h.owner.stop.is_cancelled(),
            "the drain cancelled admitted work"
        );
        ensure!(!drain.is_finished(), "the drain ended before the approval");
        h.release()?;
        let metadata = stream.committed().await?;
        ensure!(metadata["provider"] == "github");
        tokio::time::timeout(HANG_GUARD, drain)
            .await??
            .map_err(|error| anyhow::anyhow!("drain: {error:?}"))?;
        ensure!(h.count().await? == 1);
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn an_approval_still_pending_at_the_drain_limit_ends_not_published() -> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        let mut stream = h.rpc.enroll(Auth::Alice, "pending-at-the-limit").await?;
        stream.challenge().await?;
        tokio::time::timeout(HANG_GUARD, h.owner.drain(Duration::from_millis(300)))
            .await?
            .map_err(|error| anyhow::anyhow!("drain: {error:?}"))?;
        ensure!(
            h.owner.stop.is_cancelled(),
            "the limit did not cancel the approval"
        );
        terminal(
            &mut stream,
            "failed_precondition",
            "credential enrollment did not reach publication; no platform credential was stored",
        )
        .await?;
        ensure!(h.count().await? == 0);
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_device_code_that_expires_unapproved_says_so_and_stores_nothing() -> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        h.expire();
        let mut stream = challenged_github(&h).await?;
        terminal(
            &mut stream,
            "deadline_exceeded",
            "the device approval timed out; no platform credential was stored",
        )
        .await?;
        h.drained().await?;
        ensure!(h.count().await? == 0);
        Ok(())
    }
    .await;
    h.finish(result).await
}
