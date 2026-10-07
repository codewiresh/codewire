//! The SSH proxy opens its workspace SSH stream under the environment runtime
//! lease. A client that leaves during that port-forward must not strand the
//! lease `active`, which would block every external cleanup in the
//! organization.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use codewire_server_core::org_deletion::resolve_organization_mutation_lease;
use tokio::sync::oneshot;

use super::open_fenced_ssh_stream;
use crate::api::runtime_lease_test_support::{LeaseFixture, drop_caller_after_operation_starts};

/// Stands in for the port-forwarded stream; dropping it closes the stream.
struct StreamProbe(Arc<AtomicBool>);

impl Drop for StreamProbe {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_stream_opened_after_the_client_left_releases_the_lease_and_closes() {
    let fixture = LeaseFixture::seed("synthetic-ssh-proxy").await;

    // A client that stays receives the stream and the lease is released.
    let stream = open_fenced_ssh_stream(&fixture.pool, &fixture.id, &fixture.id, async {
        Ok("ssh stream")
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(stream, "ssh stream");
    fixture.assert_no_unresolved_leases().await;

    // A client that leaves during the port-forward detaches only itself.
    let closed = Arc::new(AtomicBool::new(false));
    let probe = StreamProbe(Arc::clone(&closed));
    let (entered_tx, entered_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel::<()>();
    drop_caller_after_operation_starts(
        open_fenced_ssh_stream(&fixture.pool, &fixture.id, &fixture.id, async move {
            let _ = entered_tx.send(());
            let _ = finish_rx.await;
            Ok(probe)
        }),
        entered_rx,
    )
    .await;
    let lease_id = fixture.only_unresolved_lease("active").await;
    assert!(
        !closed.load(Ordering::SeqCst),
        "the admitted port-forward must not be cancelled with its client"
    );
    let _ = finish_tx.send(());
    let settled = fixture.settled_lease(&lease_id).await;
    assert_eq!(settled.state, "released");
    assert_eq!(settled.recovery_code, None);
    // Nobody can bridge the late stream, so the owner drops and closes it.
    tokio::time::timeout(Duration::from_secs(5), async {
        while !closed.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a stream opened after the client left is closed");
    fixture.assert_no_unresolved_leases().await;

    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_failed_port_forward_after_the_client_left_requires_resolution() {
    let fixture = LeaseFixture::seed("synthetic-ssh-proxy").await;

    // A client that stays sees the failure; the outcome is still unknown.
    let failure = open_fenced_ssh_stream(&fixture.pool, &fixture.id, &fixture.id, async {
        Err::<(), _>(anyhow::anyhow!("synthetic workspace SSH connect failure"))
    })
    .await
    .unwrap();
    assert!(failure.is_err());
    let lease_id = fixture.only_unresolved_lease("resolution_required").await;
    let settled = fixture.settled_lease(&lease_id).await;
    assert_eq!(
        settled.recovery_code.as_deref(),
        Some("environment_runtime_dispatch_ambiguous")
    );
    resolve_organization_mutation_lease(&fixture.pool, &lease_id)
        .await
        .unwrap();

    // A client that leaves first cannot turn that evidence into an active
    // lease: the owner still records it.
    let (entered_tx, entered_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel::<()>();
    drop_caller_after_operation_starts(
        open_fenced_ssh_stream(&fixture.pool, &fixture.id, &fixture.id, async move {
            let _ = entered_tx.send(());
            let _ = finish_rx.await;
            Err::<(), _>(anyhow::anyhow!("synthetic workspace SSH connect failure"))
        }),
        entered_rx,
    )
    .await;
    let lease_id = fixture.only_unresolved_lease("active").await;
    let _ = finish_tx.send(());
    let settled = fixture.settled_lease(&lease_id).await;
    assert_eq!(settled.state, "resolution_required");
    assert_eq!(
        settled.recovery_code.as_deref(),
        Some("environment_runtime_dispatch_ambiguous")
    );

    fixture.cleanup().await;
}
