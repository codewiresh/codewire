use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures::poll;

use super::*;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn canceled_blocking_load_retains_capacity_until_job_finishes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("synthetic-key-buffer");
    std::fs::write(&path, b"synthetic private buffer").unwrap();
    let capacity = Arc::new(Semaphore::new(1));
    let (entered, started) = oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let saw_cancellation = Arc::new(AtomicBool::new(false));
    let job_capacity = capacity.clone();
    let observed = saw_cancellation.clone();
    let caller = tokio::spawn(async move {
        run_file_job(&job_capacity, move |completion| {
            let bytes = read_regular_blocking(&path, 64, || completion.is_closed())?;
            let _ = entered.send(());
            // A deterministic stand-in for an already-entered OS operation.
            // Dropping `release` on a failed assertion also drains this fixture.
            let _ = blocked.recv_timeout(TEST_TIMEOUT);
            observed.store(completion.is_closed(), Ordering::SeqCst);
            Ok(bytes)
        })
        .await
    });
    tokio::time::timeout(TEST_TIMEOUT, started)
        .await
        .unwrap()
        .unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert_eq!(capacity.available_permits(), 0);

    let attempted = Arc::new(AtomicBool::new(false));
    let attempted_by_job = attempted.clone();
    assert_eq!(
        run_file_job(&capacity, move |_| {
            attempted_by_job.store(true, Ordering::SeqCst);
            Ok(Zeroizing::new(Vec::new()))
        })
        .await
        .unwrap_err(),
        TlsError::Files
    );
    assert!(!attempted.load(Ordering::SeqCst));
    release.send(()).unwrap();
    let available = tokio::time::timeout(TEST_TIMEOUT, capacity.clone().acquire_owned())
        .await
        .unwrap()
        .unwrap();
    assert!(saw_cancellation.load(Ordering::SeqCst));
    drop(available);
    assert_eq!(capacity.available_permits(), 1);
    assert_eq!(
        &*run_file_job(&capacity, |_| Ok(Zeroizing::new(b"new load".to_vec())))
            .await
            .unwrap(),
        b"new load"
    );
}

#[test]
fn canceled_queued_load_skips_file_io_and_releases_capacity() {
    // The sole blocking thread is gated so cancellation occurs before the
    // queued file job can begin; no timing assumption substitutes for the gate.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (entered, started) = oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            let _ = entered.send(());
            let _ = blocked.recv_timeout(TEST_TIMEOUT);
        });
        tokio::time::timeout(TEST_TIMEOUT, started)
            .await
            .unwrap()
            .unwrap();
        let capacity = Arc::new(Semaphore::new(1));
        let attempted = Arc::new(AtomicBool::new(false));
        let attempted_by_job = attempted.clone();
        let mut caller = Box::pin(run_file_job(&capacity, move |_| {
            attempted_by_job.store(true, Ordering::SeqCst);
            Ok(Zeroizing::new(Vec::new()))
        }));
        assert!(poll!(caller.as_mut()).is_pending());
        assert_eq!(capacity.available_permits(), 0);
        drop(caller);
        assert_eq!(capacity.available_permits(), 0);
        release.send(()).unwrap();
        tokio::time::timeout(TEST_TIMEOUT, blocker)
            .await
            .unwrap()
            .unwrap();
        let available = tokio::time::timeout(TEST_TIMEOUT, capacity.clone().acquire_owned())
            .await
            .unwrap()
            .unwrap();
        assert!(!attempted.load(Ordering::SeqCst));
        drop(available);
        assert_eq!(capacity.available_permits(), 1);
    });
}
