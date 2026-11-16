//! The network worker's late-answer reports, read on its control socket while
//! the VM runs (#4965): what `cw info` shows as egress unavailable.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::SystemTime;

use super::{RunnerError, RunningVm};
use crate::network_worker::{LATE_STATUS_FRAME_LEN, LateStatusFrame};

/// Egress refused because the egress broker is past its deadline: how many
/// requests it refused in all, and since when.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EgressUnavailable {
    pub(crate) late_answers: u64,
    pub(crate) since: SystemTime,
}

/// The worker's latest report, written by the ingress forwarder that reads
/// the control socket and read by the runner service's `info`.
#[derive(Clone, Debug, Default)]
pub(crate) struct EgressStatusCell(Arc<StdMutex<EgressStatusState>>);

#[derive(Debug, Default)]
struct EgressStatusState {
    pending: Vec<u8>,
    unavailable: Option<EgressUnavailable>,
}

impl EgressStatusCell {
    pub(crate) fn unavailable(&self) -> Option<EgressUnavailable> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .unavailable
    }

    /// Read what the worker wrote once `control` is `readable`. Only whole
    /// late-status frames are taken; the end of the stream, a read error or
    /// any other bytes fail the forwarder closed, as any byte from the worker
    /// did before.
    pub(super) fn read_from(
        &self,
        control: &tokio::net::UnixStream,
        readable: std::io::Result<()>,
    ) -> Result<(), RunnerError> {
        readable.map_err(|_| RunnerError::IngressControl)?;
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            let mut bytes = [0_u8; LATE_STATUS_FRAME_LEN];
            let wanted = LATE_STATUS_FRAME_LEN - state.pending.len();
            match control.try_read(&mut bytes[..wanted]) {
                Ok(0) => return Err(RunnerError::IngressControl),
                Ok(read) => state.pending.extend_from_slice(&bytes[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(_) => return Err(RunnerError::IngressControl),
            }
            if let Ok(frame) = <[u8; LATE_STATUS_FRAME_LEN]>::try_from(state.pending.as_slice()) {
                state.pending.clear();
                state.record(LateStatusFrame::decode(&frame).ok_or(RunnerError::IngressControl)?);
            }
        }
    }
}

impl EgressStatusState {
    fn record(&mut self, frame: LateStatusFrame) {
        self.unavailable = frame.refusing_for.map(|refusing| {
            let now = SystemTime::now();
            EgressUnavailable {
                late_answers: frame.late_answers,
                since: now.checked_sub(refusing).unwrap_or(now),
            }
        });
    }
}

impl RunningVm {
    /// Whether this VM's egress broker is past its deadline, as its network
    /// worker last reported.
    pub(crate) fn egress_unavailable(&self) -> Option<EgressUnavailable> {
        self.network_worker.as_ref()?.egress_status.unavailable()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn pair() -> (tokio::net::UnixStream, std::os::unix::net::UnixStream) {
        let (runner, worker) = std::os::unix::net::UnixStream::pair().unwrap();
        runner.set_nonblocking(true).unwrap();
        (tokio::net::UnixStream::from_std(runner).unwrap(), worker)
    }

    fn frame(late_answers: u64, refusing_for: Option<Duration>) -> [u8; LATE_STATUS_FRAME_LEN] {
        LateStatusFrame {
            late_answers,
            refusing_for,
        }
        .encode()
    }

    /// The count and the time crossing from the worker are recorded, also
    /// from a frame split across reads, and an answered-again frame clears
    /// them.
    #[tokio::test]
    async fn the_runner_records_and_clears_what_the_worker_reports() {
        use std::io::Write as _;
        let (runner, mut worker) = pair();
        let cell = EgressStatusCell::default();
        let late = frame(3, Some(Duration::from_secs(90)));
        worker.write_all(&late[..10]).unwrap();
        cell.read_from(&runner, runner.readable().await).unwrap();
        assert_eq!(cell.unavailable(), None);
        worker.write_all(&late[10..]).unwrap();
        cell.read_from(&runner, runner.readable().await).unwrap();
        let unavailable = cell.unavailable().unwrap();
        assert_eq!(unavailable.late_answers, 3);
        let refusing = SystemTime::now().duration_since(unavailable.since).unwrap();
        assert!(refusing >= Duration::from_secs(90), "{refusing:?}");

        worker.write_all(&frame(3, None)).unwrap();
        cell.read_from(&runner, runner.readable().await).unwrap();
        assert_eq!(cell.unavailable(), None);
    }

    /// Anything but a late-status frame, or the worker going away, still
    /// fails the forwarder closed.
    #[tokio::test]
    async fn any_other_bytes_still_fail_closed() {
        use std::io::Write as _;
        let (runner, mut worker) = pair();
        let mut other = frame(1, None);
        other[0] ^= 1;
        worker.write_all(&other).unwrap();
        assert!(matches!(
            EgressStatusCell::default().read_from(&runner, runner.readable().await),
            Err(RunnerError::IngressControl)
        ));

        let (runner, worker) = pair();
        drop(worker);
        assert!(matches!(
            EgressStatusCell::default().read_from(&runner, runner.readable().await),
            Err(RunnerError::IngressControl)
        ));
    }
}
