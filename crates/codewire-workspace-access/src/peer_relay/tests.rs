use std::sync::atomic::{AtomicUsize, Ordering};

use codewire_tailnet::disco::DiscoPrivate;
use rand::rngs::OsRng;

use super::*;

use direct_udp::PeerRelayEndpointState::{Active, Missing, Negotiating};

#[tokio::test]
async fn relay_bind_endpoint_overrides_advertised_addr_ports() {
    let advertised = UDPRelayEndpoint {
        server_disco: DiscoPrivate::generate(&mut OsRng).public(),
        client_disco: [
            DiscoPrivate::generate(&mut OsRng).public(),
            DiscoPrivate::generate(&mut OsRng).public(),
        ],
        lamport_id: 1,
        vni: 42,
        bind_lifetime: Duration::from_secs(10),
        steady_state_lifetime: Duration::from_secs(60),
        addr_ports: vec!["203.0.113.35:41641".parse().unwrap()],
    };

    let bind = relay_bind_endpoint(&advertised, &["127.0.0.1:41641".into()])
        .await
        .unwrap();

    assert_eq!(bind.addr_ports, vec!["127.0.0.1:41641".parse().unwrap()]);
    assert_eq!(bind.vni, advertised.vni);
    assert_eq!(
        advertised.addr_ports,
        vec!["203.0.113.35:41641".parse().unwrap()]
    );
}

fn key(byte: u8) -> PeerRelayKey {
    PeerRelayKey {
        peer: NodePublic::from_raw([byte; 32]),
        peer_disco: DiscoPublic::from_raw([byte.wrapping_add(0x80); 32]),
    }
}

fn relay(state: direct_udp::PeerRelayEndpointState) -> impl FnMut(PeerRelayKey) -> PeerPathState {
    move |_| PeerPathState::relay(state)
}

/// A tracker that has seen `key` since `seen`, and the time its direct
/// grace ends.
fn tracking(key: PeerRelayKey, seen: Instant) -> (PeerRelayAllocationTracker, Instant) {
    let mut tracker = PeerRelayAllocationTracker::default();
    tracker.replace_peers(seen, [key]);
    (tracker, seen + PEER_RELAY_DIRECT_GRACE)
}

#[test]
fn a_new_peer_has_its_direct_grace_before_a_relay_is_allocated() {
    let key = key(0x11);
    let seen = Instant::now();
    let (mut tracker, due) = tracking(key, seen);

    assert!(
        tracker
            .begin_pending(due - Duration::from_millis(1), relay(Missing))
            .is_empty(),
        "a client that may still prove a direct path gets no relay yet"
    );
    assert_eq!(tracker.begin_pending(due, relay(Missing)), vec![key]);
    assert!(
        tracker.begin_pending(due, relay(Missing)).is_empty(),
        "one allocation at a time per peer"
    );
}

#[test]
fn a_peer_with_a_direct_path_gets_no_relay_and_loses_its_pending_one() {
    let direct = key(0x11);
    let relayed = key(0x12);
    let seen = Instant::now();
    let mut tracker = PeerRelayAllocationTracker::default();
    tracker.replace_peers(seen, [direct, relayed]);
    let due = seen + PEER_RELAY_DIRECT_GRACE;

    let started = tracker.begin_pending(due, |key| PeerPathState {
        direct: key == direct,
        relay: Missing,
    });
    assert_eq!(
        started,
        vec![relayed],
        "only the peer without a direct path"
    );

    // The relayed peer proves a direct path while its allocation waits.
    assert!(
        tracker
            .begin_pending(due + Duration::from_millis(100), |_| PeerPathState {
                direct: true,
                relay: Missing,
            })
            .is_empty()
    );
    let state = tracker.state();
    assert_eq!(state.in_flight_count, 0);
    assert_eq!(state.cancelled, 1, "the pending allocation is cancelled");
}

#[test]
fn a_failed_allocation_retries_without_another_peer_update() {
    let key = key(0x11);
    let (mut tracker, due) = tracking(key, Instant::now());
    assert_eq!(tracker.begin_pending(due, relay(Missing)), vec![key]);

    let failed = due + Duration::from_millis(40);
    let failure = tracker.finish_failure(key, failed);
    assert_eq!(failure.attempts, 1);
    assert_eq!(failure.failures, 1);
    assert!(
        tracker
            .begin_pending(
                failed + PEER_RELAY_ALLOCATION_RETRY_DELAY - Duration::from_millis(1),
                relay(Missing),
            )
            .is_empty(),
        "the retry delay still suppresses rapid duplicates"
    );
    assert_eq!(
        tracker.begin_pending(failed + PEER_RELAY_ALLOCATION_RETRY_DELAY, relay(Missing)),
        vec![key],
        "the failed attempt retries without another peer snapshot"
    );
}

#[test]
fn a_negotiating_relay_leaves_its_retries_to_the_tailnet() {
    let key = key(0x11);
    let (mut tracker, due) = tracking(key, Instant::now());
    assert_eq!(tracker.begin_pending(due, relay(Missing)), vec![key]);
    let success = tracker.finish_success(key, due);
    assert_eq!(success.queued_count, 1);
    assert!(
        tracker
            .begin_pending(
                due + PEER_RELAY_ALLOCATION_RETRY_DELAY * 4,
                relay(Negotiating)
            )
            .is_empty(),
        "a fresh negotiating relay leaves bind and CallMeMaybe retry ownership to codewire-tailnet"
    );
}

#[test]
fn a_used_relay_that_expires_is_reallocated_at_once() {
    let key = key(0x11);
    let (mut tracker, due) = tracking(key, Instant::now());
    assert_eq!(tracker.begin_pending(due, relay(Missing)), vec![key]);
    tracker.finish_success(key, due);
    assert!(
        tracker
            .begin_pending(due + Duration::from_millis(100), relay(Negotiating))
            .is_empty()
    );
    assert!(
        tracker
            .begin_pending(due + Duration::from_millis(200), relay(Active))
            .is_empty()
    );
    assert_eq!(
        tracker.begin_pending(due + Duration::from_secs(2), relay(Missing)),
        vec![key],
        "an active relay that expires is reallocated without another peer snapshot"
    );
}

#[test]
fn a_success_the_tailnet_never_registers_is_retried() {
    let key = key(0x11);
    let (mut tracker, due) = tracking(key, Instant::now());
    assert_eq!(tracker.begin_pending(due, relay(Missing)), vec![key]);
    tracker.finish_success(key, due);
    assert!(
        tracker
            .begin_pending(
                due + PEER_RELAY_REGISTRATION_GRACE - Duration::from_millis(1),
                relay(Missing)
            )
            .is_empty()
    );
    let expired = due + PEER_RELAY_REGISTRATION_GRACE;
    assert!(
        tracker.begin_pending(expired, relay(Missing)).is_empty(),
        "an unregistered relay is a miss, retried after the retry delay"
    );
    assert_eq!(
        tracker.begin_pending(expired + PEER_RELAY_ALLOCATION_RETRY_DELAY, relay(Missing)),
        vec![key],
        "a successful response cannot leave an unregistered relay permanently queued"
    );
}

/// A DERP-only client never takes up the relay it is offered. Each unused
/// relay doubles the wait before the next, up to a minute, so such a client
/// does not spend the Pod's call budget every few seconds.
#[test]
fn relays_a_peer_never_takes_up_are_offered_less_and_less_often() {
    let key = key(0x11);
    let (mut tracker, mut now) = tracking(key, Instant::now());
    let mut waits = Vec::new();
    let mut last_start = None;
    for _ in 0..12 {
        // The next attempt starts at the first tick the tracker allows.
        let started = loop {
            if tracker.begin_pending(now, relay(Missing)) == vec![key] {
                break now;
            }
            now += Duration::from_millis(50);
        };
        if let Some(previous_expiry) = last_start {
            waits.push(started.duration_since(previous_expiry));
        }
        tracker.finish_success(key, started);
        now = started + Duration::from_millis(100);
        assert!(tracker.begin_pending(now, relay(Negotiating)).is_empty());
        // The relay's bind lifetime ends without the peer binding it.
        now += Duration::from_secs(3);
        assert!(tracker.begin_pending(now, relay(Missing)).is_empty());
        last_start = Some(now);
    }
    let expected = [
        250, 500, 1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000, 60_000,
    ];
    for (wait, expected_ms) in waits.iter().zip(expected) {
        let expected = Duration::from_millis(expected_ms);
        assert!(
            *wait >= expected && *wait < expected + Duration::from_millis(60),
            "waits after unused relays: {waits:?}"
        );
    }

    // Once the peer uses a relay, the next expiry is reallocated at once.
    let started = loop {
        if tracker.begin_pending(now, relay(Missing)) == vec![key] {
            break now;
        }
        now += Duration::from_millis(50);
    };
    tracker.finish_success(key, started);
    assert!(
        tracker
            .begin_pending(started + Duration::from_millis(100), relay(Active))
            .is_empty()
    );
    assert_eq!(
        tracker.begin_pending(started + Duration::from_secs(60), relay(Missing)),
        vec![key]
    );
}

#[test]
fn a_departed_peers_allocation_is_cancelled_and_a_late_answer_is_ignored() {
    let key = key(0x11);
    let (mut tracker, due) = tracking(key, Instant::now());
    assert_eq!(tracker.begin_pending(due, relay(Missing)), vec![key]);

    tracker.replace_peers(due, []);
    let state = tracker.state();
    assert_eq!(state.in_flight_count, 0);
    assert_eq!(state.cancelled, 1);

    // An answer that raced the cancellation cannot resurrect queued state.
    let success = tracker.finish_success(key, due + Duration::from_millis(30));
    assert_eq!(success.queued_count, 0);
    assert_eq!(success.peer_count, 0);

    // The same peer coming back is a new client: a fresh grace, one
    // allocation.
    let back = due + Duration::from_secs(1);
    tracker.replace_peers(back, [key]);
    assert!(tracker.begin_pending(back, relay(Missing)).is_empty());
    assert_eq!(
        tracker.begin_pending(back + PEER_RELAY_DIRECT_GRACE, relay(Missing)),
        vec![key]
    );
}

#[tokio::test]
async fn cancelling_a_departed_peer_aborts_its_running_allocation() {
    let key = key(0x11);
    let (mut tracker, due) = tracking(key, Instant::now());
    assert_eq!(tracker.begin_pending(due, relay(Missing)), vec![key]);
    let task = tokio::spawn(std::future::pending::<()>());
    tracker.attach(key, task.abort_handle());

    tracker.replace_peers(due, []);
    let joined = task.await.unwrap_err();
    assert!(joined.is_cancelled());
}

#[test]
fn a_new_disco_identity_starts_a_new_allocation() {
    let old_key = key(0x11);
    let new_key = PeerRelayKey {
        peer: old_key.peer,
        peer_disco: DiscoPublic::from_raw([0x33; 32]),
    };
    let (mut tracker, due) = tracking(old_key, Instant::now());
    assert_eq!(tracker.begin_pending(due, relay(Missing)), vec![old_key]);
    tracker.finish_success(old_key, due);
    assert!(
        tracker
            .begin_pending(due + Duration::from_millis(100), relay(Active))
            .is_empty()
    );

    let rotated = due + Duration::from_millis(200);
    tracker.replace_peers(rotated, [new_key]);
    assert_eq!(
        tracker.begin_pending(rotated + PEER_RELAY_DIRECT_GRACE, |key| {
            assert_eq!(key, new_key);
            PeerPathState::relay(Missing)
        }),
        vec![new_key],
        "a new disco identity for the same node must start a new relay allocation"
    );
}

/// A backend whose admission takes `admit_wait` and whose calls take
/// `call_time`.
struct SlowBackend {
    admit_wait: Duration,
    call_time: Duration,
    calls: AtomicUsize,
}

#[async_trait]
impl PeerRelayBackend for SlowBackend {
    async fn admit(&self) {
        tokio::time::sleep(self.admit_wait).await;
    }

    async fn allocate(
        &self,
        _client_disco: [DiscoPublic; 2],
        _generation: u32,
    ) -> Result<UDPRelayEndpoint> {
        unreachable!("these tests drive admitted_attempt directly")
    }
}

impl SlowBackend {
    fn new(admit_wait: Duration, call_time: Duration) -> Self {
        Self {
            admit_wait,
            call_time,
            calls: AtomicUsize::new(0),
        }
    }

    async fn call(&self) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.call_time).await;
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn the_attempt_deadline_starts_when_the_call_is_admitted() {
    // Eight seconds behind other calls, then a 35 ms answer: within a 5 s
    // attempt deadline, because the queue has its own limit.
    let backend = SlowBackend::new(Duration::from_secs(8), Duration::from_millis(35));
    let started = Instant::now();
    admitted_attempt(
        &backend,
        "test",
        PEER_RELAY_ALLOCATION_QUEUE_LIMIT,
        Duration::from_secs(5),
        backend.call(),
    )
    .await
    .expect("the queue wait does not count against the attempt");
    assert_eq!(started.elapsed(), Duration::from_millis(8_035));

    // An admitted call that is slow still times out.
    let slow = SlowBackend::new(Duration::ZERO, Duration::from_secs(6));
    let error = admitted_attempt(
        &slow,
        "test",
        PEER_RELAY_ALLOCATION_QUEUE_LIMIT,
        Duration::from_secs(5),
        slow.call(),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("attempt timed out"));
}

#[tokio::test(start_paused = true)]
async fn a_call_that_waits_past_the_queue_limit_is_never_made() {
    let backend = SlowBackend::new(
        PEER_RELAY_ALLOCATION_QUEUE_LIMIT + Duration::from_secs(1),
        Duration::from_millis(35),
    );
    let error = admitted_attempt(
        &backend,
        "test",
        PEER_RELAY_ALLOCATION_QUEUE_LIMIT,
        Duration::from_secs(5),
        backend.call(),
    )
    .await
    .unwrap_err();
    let exceeded = error
        .downcast_ref::<QueueWaitExceeded>()
        .expect("reported as a queue wait, not an attempt timeout");
    assert_eq!(exceeded.waited, PEER_RELAY_ALLOCATION_QUEUE_LIMIT);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn a_call_budget_admits_its_burst_then_its_rate_in_arrival_order() {
    let budget = Arc::new(CallBudget::new(0.5, 3));
    let started = Instant::now();
    let admitted = Arc::new(Mutex::new(Vec::new()));
    let mut waiters = Vec::new();
    for caller in 0..6 {
        let budget = budget.clone();
        let admitted = admitted.clone();
        waiters.push(tokio::spawn(async move {
            budget.admit().await;
            admitted
                .lock()
                .unwrap()
                .push((caller, started.elapsed().as_millis()));
        }));
        tokio::task::yield_now().await;
    }
    for waiter in waiters {
        waiter.await.unwrap();
    }
    assert_eq!(
        *admitted.lock().unwrap(),
        [(0, 0), (1, 0), (2, 0), (3, 2_000), (4, 4_000), (5, 6_000)]
    );
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_waiter_takes_nothing_from_the_budget() {
    let budget = Arc::new(CallBudget::new(0.5, 1));
    budget.admit().await;
    let started = Instant::now();
    let abandoned = {
        let budget = budget.clone();
        tokio::spawn(async move { budget.admit().await })
    };
    tokio::time::sleep(Duration::from_secs(1)).await;
    abandoned.abort();
    let _ = abandoned.await;
    budget.admit().await;
    assert_eq!(
        started.elapsed(),
        Duration::from_secs(2),
        "the next caller gets the token the abandoned one never took"
    );
}

/// A refill a rounding error short of a whole token admits the call, and a
/// real shortfall waits at least a millisecond: a zero-length wait would spin
/// without the clock moving.
#[test]
fn a_call_budget_never_waits_zero() {
    let budget = CallBudget::new(0.5, 3);
    let now = Instant::now();
    let mut state = CallBudgetState {
        tokens: 1.0 - 1e-15,
        updated: now,
    };
    assert_eq!(budget.try_take(&mut state, now), None);
    assert_eq!(state.tokens, 0.0);

    let mut state = CallBudgetState {
        tokens: 1.0 - 1e-6,
        updated: now,
    };
    assert_eq!(budget.try_take(&mut state, now), Some(CALL_BUDGET_MIN_WAIT));

    let mut state = CallBudgetState {
        tokens: 0.0,
        updated: now,
    };
    assert_eq!(
        budget.try_take(&mut state, now),
        Some(Duration::from_secs(2))
    );
    assert_eq!(
        budget.try_take(&mut state, now + Duration::from_secs(2)),
        None
    );
}
