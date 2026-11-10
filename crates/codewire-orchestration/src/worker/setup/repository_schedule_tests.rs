use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use tokio::sync::oneshot;

use super::{SETUP_REPOSITORY_CONCURRENCY, observe_repository_chains};

#[derive(Default)]
struct State {
    active: Cell<usize>,
    maximum: Cell<usize>,
    started: RefCell<Vec<usize>>,
    observed: RefCell<Vec<usize>>,
    dropped_early: Cell<usize>,
    cancelled: Cell<bool>,
}

struct RunningChain {
    state: Rc<State>,
    observed: bool,
}

impl Drop for RunningChain {
    fn drop(&mut self) {
        self.state.active.set(self.state.active.get() - 1);
        if !self.observed {
            self.state
                .dropped_early
                .set(self.state.dropped_early.get() + 1);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Command,
    Cancelled,
}

async fn chain(
    index: usize,
    state: Rc<State>,
    release: oneshot::Receiver<Result<(), Failure>>,
) -> Result<usize, Failure> {
    // Model the unchanged authority/reaping check before actual workspace exec.
    if state.cancelled.get() {
        return Err(Failure::Cancelled);
    }
    state.started.borrow_mut().push(index);
    state.active.set(state.active.get() + 1);
    state
        .maximum
        .set(state.maximum.get().max(state.active.get()));
    let mut running = RunningChain {
        state: state.clone(),
        observed: false,
    };
    let result = release
        .await
        .expect("test driver retains every started chain");
    state.observed.borrow_mut().push(index);
    running.observed = true;
    result.map(|()| index)
}

fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn repository_scheduler_queues_more_than_bridge_capacity_without_bursting() {
    const CHAINS: usize = 33;
    assert_eq!(SETUP_REPOSITORY_CONCURRENCY, 4);
    let state = Rc::new(State::default());
    let (mut releases, receivers): (Vec<_>, Vec<_>) = (0..CHAINS)
        .map(|_| {
            let (tx, rx) = oneshot::channel();
            (Some(tx), rx)
        })
        .unzip();
    let jobs = receivers
        .into_iter()
        .enumerate()
        .map(|(index, release)| chain(index, state.clone(), release));
    let mut run = Box::pin(observe_repository_chains(jobs));
    assert!(poll(run.as_mut()).is_pending());
    assert_eq!(state.started.borrow().len(), SETUP_REPOSITORY_CONCURRENCY);

    for first in (0..CHAINS).step_by(SETUP_REPOSITORY_CONCURRENCY) {
        let end = (first + SETUP_REPOSITORY_CONCURRENCY).min(CHAINS);
        // Out-of-order completion must not change the existing error ordering.
        for index in (first..end).rev() {
            releases[index].take().unwrap().send(Ok(())).unwrap();
        }
        let result = poll(run.as_mut());
        assert!(state.maximum.get() <= SETUP_REPOSITORY_CONCURRENCY);
        if end == CHAINS {
            let Poll::Ready(results) = result else {
                panic!("all chains are released")
            };
            assert_eq!(results, (0..CHAINS).map(Ok).collect::<Vec<_>>());
        } else {
            assert!(result.is_pending());
            assert_eq!(
                state.started.borrow().len(),
                (end + SETUP_REPOSITORY_CONCURRENCY).min(CHAINS)
            );
        }
    }
    assert_eq!(state.observed.borrow().len(), CHAINS);
    assert_eq!(state.active.get(), 0);
    assert_eq!(state.dropped_early.get(), 0);
}

#[test]
fn repository_scheduler_observes_started_siblings_before_returning_an_error() {
    const CHAINS: usize = 9;
    let state = Rc::new(State::default());
    let (mut releases, receivers): (Vec<_>, Vec<_>) = (0..CHAINS)
        .map(|_| {
            let (tx, rx) = oneshot::channel();
            (Some(tx), rx)
        })
        .unzip();
    let jobs = receivers
        .into_iter()
        .enumerate()
        .map(|(index, release)| chain(index, state.clone(), release));
    let mut run = Box::pin(observe_repository_chains(jobs));
    assert!(poll(run.as_mut()).is_pending());
    releases[0]
        .take()
        .unwrap()
        .send(Err(Failure::Command))
        .unwrap();
    assert!(poll(run.as_mut()).is_pending());
    assert_eq!(state.observed.borrow().as_slice(), &[0]);
    assert_eq!(state.active.get(), SETUP_REPOSITORY_CONCURRENCY);
    assert_eq!(state.dropped_early.get(), 0);

    for release in releases.into_iter().flatten() {
        release.send(Ok(())).unwrap();
    }
    let Poll::Ready(results) = poll(run.as_mut()) else {
        panic!("all siblings are released")
    };
    assert_eq!(results[0], Err(Failure::Command));
    assert_eq!(results[1..], (1..CHAINS).map(Ok).collect::<Vec<_>>());
    assert_eq!(state.observed.borrow().len(), CHAINS);
    assert_eq!(state.active.get(), 0);
    assert_eq!(state.dropped_early.get(), 0);
}

#[test]
fn repository_scheduler_cancellation_fences_queue_without_dropping_started_siblings() {
    const CHAINS: usize = 33;
    let state = Rc::new(State::default());
    let (mut releases, receivers): (Vec<_>, Vec<_>) = (0..CHAINS)
        .map(|_| {
            let (tx, rx) = oneshot::channel();
            (Some(tx), rx)
        })
        .unzip();
    let jobs = receivers
        .into_iter()
        .enumerate()
        .map(|(index, release)| chain(index, state.clone(), release));
    let mut run = Box::pin(observe_repository_chains(jobs));
    assert!(poll(run.as_mut()).is_pending());
    state.cancelled.set(true);
    releases[0]
        .take()
        .unwrap()
        .send(Err(Failure::Cancelled))
        .unwrap();
    assert!(poll(run.as_mut()).is_pending());
    assert_eq!(state.started.borrow().len(), SETUP_REPOSITORY_CONCURRENCY);
    assert_eq!(state.active.get(), SETUP_REPOSITORY_CONCURRENCY - 1);

    for release in releases
        .iter_mut()
        .take(SETUP_REPOSITORY_CONCURRENCY)
        .skip(1)
    {
        release
            .take()
            .unwrap()
            .send(Err(Failure::Cancelled))
            .unwrap();
    }
    let Poll::Ready(results) = poll(run.as_mut()) else {
        panic!("all started siblings are observed")
    };
    assert_eq!(results, vec![Err(Failure::Cancelled); CHAINS]);
    assert_eq!(state.started.borrow().len(), SETUP_REPOSITORY_CONCURRENCY);
    assert_eq!(state.observed.borrow().len(), SETUP_REPOSITORY_CONCURRENCY);
    assert_eq!(state.active.get(), 0);
    assert_eq!(state.dropped_early.get(), 0);
}

/// A nested repository is cloned only after every repository at a lower
/// depth has finished, and a failed depth starts nothing deeper (#4024).
#[tokio::test(flavor = "current_thread")]
async fn nested_repositories_clone_depth_by_depth_and_stop_after_a_failure() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let make = |name: &'static str, fail: bool| {
        let events = Rc::clone(&events);
        async move {
            events.borrow_mut().push(format!("start {name}"));
            tokio::task::yield_now().await;
            events.borrow_mut().push(format!("end {name}"));
            if fail {
                anyhow::bail!("{name} failed");
            }
            Ok(name)
        }
    };
    // root/a and root/a/b inside root; z beside it.
    let depths = [1, 0, 2, 0];
    let results = super::observe_repository_levels(
        vec![
            make("a", false),
            make("root", false),
            make("b", false),
            make("z", false),
        ],
        &depths,
    )
    .await;
    assert_eq!(
        results.into_iter().map(Result::unwrap).collect::<Vec<_>>(),
        ["root", "z", "a", "b"]
    );
    let order = events.borrow().clone();
    let at = |event: &str| order.iter().position(|seen| seen == event).unwrap();
    assert!(at("end root") < at("start a") && at("end z") < at("start a"));
    assert!(at("end a") < at("start b"));

    events.borrow_mut().clear();
    let results = super::observe_repository_levels(
        vec![make("a", false), make("root", true), make("b", false)],
        &[1, 0, 2],
    )
    .await;
    assert_eq!(results.len(), 1);
    assert!(results[0].is_err());
    assert_eq!(*events.borrow(), ["start root", "end root"]);
}
