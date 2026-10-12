//! Paused-time proof of the relay's epoch schedule with synthetic epochs; the
//! parent module proves the real epoch's admission against generated RPCs.
use super::*;

/// What the test tells one synthetic epoch to do.
enum Control {
    /// Report the daemon's Open, with the broker's expiry `ahead` (if any).
    Admit { unix: u64, ahead: Option<Duration> },
    /// Report the daemon's Open and end in the same poll.
    AdmitThenEnd,
    /// End before an Open, as a refused successor does.
    Refuse,
    /// End by itself, as when its broker ends it.
    End(Result<(), DrainFailure>),
}

struct Synthetic {
    started_at: Instant,
    succeeds: Option<u64>,
    control: mpsc::UnboundedSender<Control>,
    /// When it observed cancellation and finished draining.
    drained: oneshot::Receiver<Instant>,
}

impl Synthetic {
    fn send(&self, control: Control) {
        self.control.send(control).unwrap();
    }

    fn admit(&self, unix: u64, ahead: Option<u64>) {
        self.send(Control::Admit {
            unix,
            ahead: ahead.map(Duration::from_secs),
        });
    }

    fn not_cancelled(&mut self) {
        assert!(matches!(
            self.drained.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
    }
}

const DRAIN: Duration = Duration::from_secs(1);

/// Each start reports itself on `starts`; a cancelled epoch takes [`DRAIN`].
fn synthetic(
    starts: mpsc::UnboundedSender<Synthetic>,
) -> impl FnMut(EpochStart) -> EpochFuture<'static> {
    move |start: EpochStart| {
        let (control, mut commands) = mpsc::unbounded_channel();
        let (drained_tx, drained) = oneshot::channel();
        starts
            .send(Synthetic {
                started_at: Instant::now(),
                succeeds: start.succeeds,
                control,
                drained,
            })
            .unwrap();
        let EpochStart {
            cancellation,
            admitted,
            ..
        } = start;
        Box::pin(async move {
            let mut admitted = Some(admitted);
            let mut admit = |expiry| {
                let _ = admitted.take().expect("admitted once").send(Admitted {
                    expiry,
                    lifetime_ends: Instant::now() + EPOCH_MAX_LIFETIME,
                });
            };
            loop {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => {
                        tokio::time::sleep(DRAIN).await;
                        let _ = drained_tx.send(Instant::now());
                        return Ok(());
                    }
                    command = commands.recv() => match command {
                        Some(Control::Admit { unix, ahead }) => admit(ahead.map(|ahead| BrokerExpiry {
                            unix,
                            at: Instant::now() + ahead,
                        })),
                        Some(Control::AdmitThenEnd) => {
                            admit(None);
                            return Ok(());
                        }
                        Some(Control::Refuse) | None => return Ok(()),
                        Some(Control::End(result)) => return result,
                    }
                }
            }
        })
    }
}

struct Relay {
    origin: Instant,
    starts: mpsc::UnboundedReceiver<Synthetic>,
    admissible: watch::Sender<bool>,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), DrainFailure>>,
}

impl Relay {
    /// A relay whose environment is running from the start.
    fn start() -> Self {
        Self::start_admissible(true)
    }

    fn start_admissible(admissible: bool) -> Self {
        let (starts_tx, starts) = mpsc::unbounded_channel();
        let (stop, stopped) = oneshot::channel::<()>();
        let (admissible, admission) = watch::channel(admissible);
        let task = tokio::spawn(relay(Uuid::nil(), admission, synthetic(starts_tx), async {
            let _ = stopped.await;
        }));
        Self {
            origin: Instant::now(),
            starts,
            admissible,
            stop: Some(stop),
            task,
        }
    }

    fn set_admissible(&self, admissible: bool) {
        self.admissible.send_replace(admissible);
    }

    async fn next(&mut self) -> Synthetic {
        self.starts.recv().await.expect("relay is running")
    }

    fn at(&self, seconds: u64) -> Instant {
        self.origin + Duration::from_secs(seconds)
    }

    /// No epoch starts until `seconds`.
    async fn none_until(&mut self, seconds: u64) {
        assert!(
            tokio::time::timeout_at(self.at(seconds), self.starts.recv())
                .await
                .is_err()
        );
    }

    async fn stop(mut self) -> Result<(), DrainFailure> {
        let _ = self.stop.take().unwrap().send(());
        self.task.await.unwrap()
    }
}

#[tokio::test(start_paused = true)]
async fn the_successor_starts_ninety_seconds_before_the_current_epoch_ends() {
    let mut relay = Relay::start();
    let mut first = relay.next().await;
    assert_eq!((first.started_at, first.succeeds), (relay.origin, None));
    first.admit(1_200, Some(200));
    let mut second = relay.next().await;
    assert_eq!(
        (second.started_at, second.succeeds),
        (relay.at(110), Some(1_200))
    );
    // Admitting the successor leaves the previous epoch to its broker.
    second.admit(1_850, Some(650));
    tokio::time::sleep_until(relay.at(200)).await;
    first.not_cancelled();
    first.send(Control::End(Ok(())));
    // Here the relay's own 600 s lifetime ends first: 110 + 600 - 90.
    let third = relay.next().await;
    assert_eq!(
        (third.started_at, third.succeeds),
        (relay.at(620), Some(1_850))
    );
    second.not_cancelled();
    let stopped = Instant::now();
    relay.stop().await.unwrap();
    // Both live epochs were cancelled and drained together.
    assert_eq!(Instant::now(), stopped + DRAIN);
    assert_eq!(second.drained.await.unwrap(), stopped + DRAIN);
    assert_eq!(third.drained.await.unwrap(), stopped + DRAIN);
    assert!(first.drained.await.is_err());
}

#[tokio::test(start_paused = true)]
async fn a_refused_successor_backs_off_from_three_to_fifteen_seconds_until_the_epoch_ends() {
    let mut relay = Relay::start();
    let mut first = relay.next().await;
    first.admit(1_120, Some(120));
    // 3, 6 and 12 seconds apart, then at most 15.
    for at in [30, 33, 39, 51, 66, 81, 96, 111] {
        let candidate = relay.next().await;
        assert_eq!(
            (candidate.started_at, candidate.succeeds),
            (relay.at(at), Some(1_120))
        );
        candidate.send(Control::Refuse);
    }
    // The attempt at 111 s was the last: the current epoch ends at 120 s.
    relay.none_until(120).await;
    first.not_cancelled();
    first.send(Control::End(Ok(())));
    // Then a fresh epoch starts as before, after the usual delay.
    let fresh = relay.next().await;
    assert_eq!((fresh.started_at, fresh.succeeds), (relay.at(121), None));
    relay.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_missing_expiry_falls_back_to_renewing_after_the_epoch_ends() {
    let mut relay = Relay::start();
    let first = relay.next().await;
    first.send(Control::Admit {
        unix: 0,
        ahead: None,
    });
    relay.none_until(700).await;
    first.send(Control::End(Ok(())));
    let second = relay.next().await;
    assert_eq!((second.started_at, second.succeeds), (relay.at(701), None));
    // A fresh epoch that fails before admission is retried the same way.
    second.send(Control::Refuse);
    let third = relay.next().await;
    assert_eq!((third.started_at, third.succeeds), (relay.at(702), None));
    relay.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn shutdown_cancels_and_drains_both_epochs() {
    for admit_successor in [false, true] {
        let mut relay = Relay::start();
        let first = relay.next().await;
        first.admit(1_120, Some(120));
        let mut second = relay.next().await;
        if admit_successor {
            second.admit(1_700, Some(600));
            tokio::task::yield_now().await;
            second.not_cancelled();
        }
        let stopped = Instant::now();
        relay.stop().await.unwrap();
        assert_eq!(Instant::now(), stopped + DRAIN);
        assert_eq!(first.drained.await.unwrap(), stopped + DRAIN);
        assert_eq!(second.drained.await.unwrap(), stopped + DRAIN);
    }
}

#[tokio::test(start_paused = true)]
async fn a_drain_failure_on_any_epoch_is_fatal() {
    for retiring_fails in [true, false] {
        let mut relay = Relay::start();
        let first = relay.next().await;
        first.admit(1_120, Some(120));
        let second = relay.next().await;
        let (failing, survivor) = if retiring_fails {
            // The draining predecessor fails while its successor serves.
            second.admit(1_700, Some(600));
            (first, second)
        } else {
            // The starting successor fails while its predecessor serves.
            (second, first)
        };
        failing.send(Control::End(Err(DrainFailure)));
        assert!(relay.task.await.unwrap().is_err());
        // The other epoch was cancelled and awaited before the relay failed.
        assert!(survivor.drained.await.is_ok());
    }
}

#[tokio::test(start_paused = true)]
async fn a_successor_admitted_and_ended_at_once_still_retires_its_predecessor() {
    let mut relay = Relay::start();
    let mut first = relay.next().await;
    first.admit(1_120, Some(120));
    let second = relay.next().await;
    second.send(Control::AdmitThenEnd);
    // The daemon drained the predecessor for it, so the relay keeps it
    // relaying and starts a fresh epoch alongside, not a third one.
    let mut fresh = relay.next().await;
    assert_eq!((fresh.started_at, fresh.succeeds), (relay.at(31), None));
    first.not_cancelled();
    fresh.admit(1_800, Some(600));
    first.send(Control::End(Ok(())));
    // The fresh epoch then renews normally.
    let next = relay.next().await;
    assert_eq!(
        (next.started_at, next.succeeds),
        (relay.at(31 + 510), Some(1_800))
    );
    fresh.not_cancelled();
    relay.stop().await.unwrap();
}

#[test]
fn successor_backoff_doubles_from_three_to_at_most_fifteen_seconds() {
    let delays: Vec<_> = (0..6)
        .map(|refusals| successor_backoff(refusals).as_secs())
        .collect();
    assert_eq!(delays, [3, 6, 12, 15, 15, 15]);
    assert_eq!(successor_backoff(u32::MAX), SUCCESSOR_RETRY_MAX);
}

#[tokio::test(start_paused = true)]
async fn an_admitted_successor_resets_the_backoff() {
    let mut relay = Relay::start();
    let first = relay.next().await;
    first.admit(1_300, Some(300));
    for at in [210, 213] {
        let refused = relay.next().await;
        assert_eq!(refused.started_at, relay.at(at));
        refused.send(Control::Refuse);
    }
    let successor = relay.next().await;
    assert_eq!(successor.started_at, relay.at(219));
    successor.admit(1_900, Some(600));
    first.send(Control::End(Ok(())));
    // Its own successor, at 219 + 600 - 90, is retried after 3 s again.
    let refused = relay.next().await;
    assert_eq!(refused.started_at, relay.at(729));
    refused.send(Control::Refuse);
    let retried = relay.next().await;
    assert_eq!(
        (retried.started_at, retried.succeeds),
        (relay.at(732), Some(1_900))
    );
    relay.stop().await.unwrap();
}

/// The broker refuses every epoch until the environment is running, which
/// follows the binding by the whole cold start. The relay spends no attempt
/// before, and starts its first epoch the moment it can be admitted.
#[tokio::test(start_paused = true)]
async fn the_first_epoch_starts_the_moment_the_broker_can_admit_it() {
    let mut relay = Relay::start_admissible(false);
    relay.none_until(30).await;
    relay.set_admissible(true);
    let mut first = relay.next().await;
    // At that instant, not after a retry delay.
    assert_eq!((first.started_at, first.succeeds), (relay.at(30), None));
    first.admit(1_620, Some(600));
    // Admitted on that first attempt: nothing else starts before its
    // successor, 90 seconds before it ends at 630 s.
    relay.none_until(539).await;
    first.not_cancelled();
    relay.stop().await.unwrap();
}

/// A refusal while the environment can be admitted is retried as before; once
/// it cannot (it is stopping), no fresh epoch is attempted until it can again.
#[tokio::test(start_paused = true)]
async fn fresh_epochs_wait_while_the_broker_cannot_admit_them() {
    let mut relay = Relay::start();
    let refused = relay.next().await;
    assert_eq!(refused.started_at, relay.origin);
    refused.send(Control::Refuse);
    let retried = relay.next().await;
    assert_eq!(retried.started_at, relay.at(1));
    relay.set_admissible(false);
    retried.send(Control::Refuse);
    relay.none_until(60).await;
    relay.set_admissible(true);
    let resumed = relay.next().await;
    assert_eq!((resumed.started_at, resumed.succeeds), (relay.at(60), None));
    relay.stop().await.unwrap();
}

/// Every admission log states when its epoch ends: the Kind journey reads it
/// to keep an authority change clear of the relay's next renewal.
#[test]
fn an_admission_reports_the_time_until_its_epoch_ends() {
    let now = Instant::now();
    assert_eq!(ends_in_ms(None, now), 0);
    let renewal = Renewal {
        expires_at_unix: 1,
        ends_at: now + Duration::from_secs(510),
        successor_at: now + Duration::from_secs(420),
    };
    assert_eq!(ends_in_ms(Some(renewal), now), 510_000);
    assert_eq!(ends_in_ms(Some(renewal), now + Duration::from_secs(600)), 0);
}

/// The relay's and the workspace's tokens expire 40 seconds apart and kubelet
/// rotates the later one late (#2641): a successor admitted with only those
/// 40 seconds overlaps the current epoch, and once its predecessor has ended
/// its own successor is admitted with overlap as soon as the later token
/// rotates. No epoch ends without a successor already serving.
#[tokio::test(start_paused = true)]
async fn a_successor_that_extends_by_less_than_its_lead_still_overlaps() {
    let mut relay = Relay::start();
    let mut first = relay.next().await;
    first.admit(1_200, Some(200));
    let mut second = relay.next().await;
    assert_eq!(
        (second.started_at, second.succeeds),
        (relay.at(110), Some(1_200))
    );
    // Only the earlier token rotated: 40 seconds more, ending at 240.
    second.admit(1_240, Some(130));
    // Its successor is due at 150, but starts only once the first epoch,
    // left to its broker, has ended at 200.
    relay.none_until(200).await;
    first.not_cancelled();
    first.send(Control::End(Ok(())));
    let third = relay.next().await;
    assert_eq!(
        (third.started_at, third.succeeds),
        (relay.at(200), Some(1_240))
    );
    // The later token has not rotated yet: refused, and tried again.
    third.send(Control::Refuse);
    let mut fourth = relay.next().await;
    assert_eq!(
        (fourth.started_at, fourth.succeeds),
        (relay.at(203), Some(1_240))
    );
    fourth.admit(1_840, Some(637));
    // The second epoch serves its pending requests until its own end.
    tokio::time::sleep_until(relay.at(240)).await;
    second.not_cancelled();
    fourth.not_cancelled();
    second.send(Control::End(Ok(())));
    // Here the relay's own lifetime ends first: 203 + 600 - 90.
    let fifth = relay.next().await;
    assert_eq!(
        (fifth.started_at, fifth.succeeds),
        (relay.at(713), Some(1_840))
    );
    drop(fifth);
    relay.stop().await.unwrap();
}
