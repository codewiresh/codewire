use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use super::*;

/// A heartbeat that succeeds or fails from a script; past its end, it succeeds.
#[derive(Clone, Default)]
struct Script(Arc<Mutex<VecDeque<bool>>>);

#[async_trait]
impl Heartbeat for Script {
    async fn write(&mut self, _key: i64) -> bool {
        self.0.lock().unwrap().pop_front().unwrap_or(true)
    }
}

/// Written at once, then `failed` writes in a row fail.
fn failing_for(failed: usize) -> Script {
    Script(Arc::new(Mutex::new(
        std::iter::once(true)
            .chain(std::iter::repeat_n(false, failed))
            .collect(),
    )))
}

async fn until(start: Instant, at: Duration) {
    tokio::time::sleep_until(start + at).await;
}

#[tokio::test(start_paused = true)]
async fn failed_heartbeats_shorter_than_the_fence_change_nothing() {
    let start = Instant::now();
    // Last written at 0 s; ten failures two seconds apart from 5 s to 23 s.
    let (fenced, watch) = watch::channel(Fence::default());
    tokio::spawn(beat(failing_for(10), 7, fenced));
    let mut ever = false;
    for second in 1..=120 {
        until(start, Duration::from_secs(second)).await;
        ever |= watch.borrow().up;
    }
    assert!(!ever, "a short failure fenced the process");
}

#[tokio::test(start_paused = true)]
async fn a_minute_without_a_heartbeat_fences_until_the_next_one_is_written() {
    let start = Instant::now();
    // Last written at 0 s; forty failures from 5 s to 83 s, then written.
    let (fenced, watch) = watch::channel(Fence::default());
    tokio::spawn(beat(failing_for(40), 7, fenced));
    until(start, Duration::from_secs(50)).await;
    assert!(!watch.borrow().up, "fenced before the fence");
    until(start, Duration::from_secs(70)).await;
    assert!(
        watch.borrow().up,
        "not fenced 70 s after the last heartbeat"
    );
    until(start, Duration::from_secs(100)).await;
    assert!(
        !watch.borrow().up,
        "still fenced after a heartbeat was written"
    );
}

#[tokio::test(start_paused = true)]
async fn a_fenced_process_admits_no_runtime_lease_and_its_holders_see_it() {
    let (owner, switch) = LeaseOwner::switchable();
    let waiting = tokio::spawn(owner.admit().expect("not yet fenced"));
    switch.fence();
    tokio::time::timeout(Duration::from_secs(1), waiting)
        .await
        .expect("a holder sees the fence")
        .unwrap();
    assert!(matches!(
        owner.admit().map(|_| ()),
        Err(AppError::ServiceUnavailable(_))
    ));
}

/// A heartbeat whose writes each take `delay`, then succeed or fail from a
/// script; past its end each succeeds at once.
#[derive(Clone)]
struct Slow {
    writes: Arc<Mutex<VecDeque<(Duration, bool)>>>,
}

#[async_trait]
impl Heartbeat for Slow {
    async fn write(&mut self, _key: i64) -> bool {
        let next = self.writes.lock().unwrap().pop_front();
        let (delay, written) = next.unwrap_or((Duration::ZERO, true));
        tokio::time::sleep(delay).await;
        written
    }
}

#[tokio::test(start_paused = true)]
async fn a_process_frozen_through_a_successful_write_still_fences_its_holders() {
    // Written at once; the next write spans a six-minute freeze and then
    // succeeds, as a resumed process's first one does.
    let writes = [(Duration::ZERO, true), (Duration::from_secs(360), true)];
    let (fence, watch) = watch::channel(Fence::default());
    let owner = LeaseOwner {
        key: Some(7),
        fenced: watch,
        raised_during_admission: None,
    };
    let holder = tokio::spawn(owner.admit().expect("not yet fenced"));
    tokio::spawn(beat(
        Slow {
            writes: Arc::new(Mutex::new(writes.into())),
        },
        7,
        fence,
    ));
    tokio::time::timeout(Duration::from_secs(400), holder)
        .await
        .expect("a holder that acted through the freeze was not stopped")
        .unwrap();
    // The heartbeat succeeded, so the fence is down again for new work.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(owner.admit().is_ok());
}

#[tokio::test(start_paused = true)]
async fn writes_that_hang_for_their_whole_timeout_fence_within_77_seconds() {
    let start = Instant::now();
    // Written at once; every later write hangs its whole 5 s and fails.
    let writes = std::iter::once((Duration::ZERO, true))
        .chain(std::iter::repeat_n((INCARNATION_CHECK, false), 40))
        .collect();
    let (fence, watch) = watch::channel(Fence::default());
    tokio::spawn(beat(
        Slow {
            writes: Arc::new(Mutex::new(writes)),
        },
        7,
        fence,
    ));
    until(start, INCARNATION_FENCE).await;
    assert!(!watch.borrow().up, "fenced before the fence");
    until(start, Duration::from_secs(77)).await;
    assert!(
        watch.borrow().up,
        "not fenced 77 s after the last heartbeat"
    );
}

#[tokio::test(start_paused = true)]
async fn a_process_without_an_incarnation_is_never_fenced() {
    let none = LeaseOwner::none();
    assert_eq!(none.key(), None);
    let fenced = none.admit().expect("never fenced");
    assert!(
        tokio::time::timeout(Duration::from_secs(3600), fenced)
            .await
            .is_err()
    );
}

#[test]
fn the_sweep_waits_well_past_the_latest_fence() {
    // The last success, then a write that hangs for its whole timeout, then
    // retries each taking a timeout and a pause: the fence comes at most this
    // long after the last successful heartbeat.
    let latest_fence =
        INCARNATION_CHECK * 2 + INCARNATION_FENCE + INCARNATION_RETRY + INCARNATION_CHECK;
    assert!(latest_fence <= Duration::from_secs(77));
    assert!(INCARNATION_GRACE >= latest_fence * 3);
}

#[tokio::test(start_paused = true)]
async fn admission_takes_the_fence_before_its_check_so_no_later_fence_is_missed() {
    // A fence raised after admission, while the holder is still on its way to
    // its wait (an upgrade, a lease admission, an issue), ends that wait.
    let (owner, switch) = LeaseOwner::switchable();
    let fenced = owner.admit().expect("not yet fenced");
    switch.fence();
    tokio::time::timeout(Duration::from_secs(1), fenced)
        .await
        .expect("a fence raised after admission was missed");
    // And a fence already raised refuses admission itself.
    assert!(owner.admit().is_err());
}

#[tokio::test(start_paused = true)]
async fn a_fence_raised_inside_admission_is_never_missed() {
    // The process fences between admission taking the fence and checking it.
    // In the right order the check refuses; in the wrong order admission
    // would succeed and hand back a fence that never completes.
    let owner = LeaseOwner::fencing_during_admission();
    match owner.admit() {
        Err(AppError::ServiceUnavailable(_)) => {}
        Err(other) => panic!("admission failed for another reason: {other:?}"),
        Ok(fenced) => tokio::time::timeout(Duration::from_secs(1), fenced)
            .await
            .expect("a fence raised inside admission was missed"),
    }
}
