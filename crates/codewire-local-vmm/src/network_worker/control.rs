//! The worker's side of its control socket once it is ready: the runner's
//! Mesh ingress frames in, and out the acknowledgement of each (#5084) and
//! the egress broker's late answers (#4965). Everything out is one frame of
//! [`LATE_STATUS_FRAME_LEN`] bytes, written whole by this one task, which
//! the runner tells apart by its magic.

use std::time::Duration;

use codewire_egress_broker::ipc::{LateAnswerStatus, LateAnswerWatch};
use tokio::time::Instant;

use super::*;
use crate::mesh_ingress_ack::mesh_ingress_ack;

/// The least time between two late-answer frames. The worker wakes when the
/// broker's late answers change, and a frame goes out only when the count
/// rose or requests are answered again, so at most one a second while the
/// broker stays late.
const LATE_STATUS_INTERVAL: Duration = Duration::from_secs(1);

const LATE_STATUS_MAGIC: &[u8; 8] = b"CWNETWL1";

/// The broker's late answers, with a wake when they change; `None` for a
/// broker with no deadline of its own.
pub(super) type LateStatus = Option<LateAnswerWatch>;

/// One late-answer frame: the magic, the count, and how long the broker has
/// been refusing in milliseconds plus one, or 0 once requests are answered
/// again.
pub(crate) const LATE_STATUS_FRAME_LEN: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LateStatusFrame {
    pub(crate) late_answers: u64,
    pub(crate) refusing_for: Option<Duration>,
}

impl LateStatusFrame {
    pub(crate) fn encode(self) -> [u8; LATE_STATUS_FRAME_LEN] {
        let refusing = self.refusing_for.map_or(0, |refusing| {
            u64::try_from(refusing.as_millis())
                .unwrap_or(u64::MAX - 1)
                .min(u64::MAX - 1)
                + 1
        });
        let mut frame = [0_u8; LATE_STATUS_FRAME_LEN];
        frame[..8].copy_from_slice(LATE_STATUS_MAGIC);
        frame[8..16].copy_from_slice(&self.late_answers.to_be_bytes());
        frame[16..].copy_from_slice(&refusing.to_be_bytes());
        frame
    }

    /// The frame `bytes` holds, or `None` for anything else.
    pub(crate) fn decode(bytes: &[u8; LATE_STATUS_FRAME_LEN]) -> Option<Self> {
        if &bytes[..8] != LATE_STATUS_MAGIC {
            return None;
        }
        let late_answers = u64::from_be_bytes(bytes[8..16].try_into().ok()?);
        let refusing = u64::from_be_bytes(bytes[16..].try_into().ok()?);
        Some(Self {
            late_answers,
            refusing_for: refusing.checked_sub(1).map(Duration::from_millis),
        })
    }
}

/// What the worker last told the runner, and when it may tell it again.
#[derive(Debug, Default)]
struct LateReport {
    late_answers: u64,
    refusing: bool,
    next_frame: Option<Instant>,
}

impl LateReport {
    /// The frame to send for `status` at `now`: when the count rose while
    /// refusing, or once refusing ended. A frame holds the next one back
    /// until `LATE_STATUS_INTERVAL` has passed.
    fn next(&mut self, status: Option<LateAnswerStatus>, now: Instant) -> Option<LateStatusFrame> {
        let status = status?;
        let refusing = status.refusing_for.is_some();
        let send =
            (refusing && status.late_answers != self.late_answers) || (self.refusing && !refusing);
        self.late_answers = status.late_answers;
        self.refusing = refusing;
        if send {
            self.next_frame = Some(now + LATE_STATUS_INTERVAL);
        }
        send.then_some(LateStatusFrame {
            late_answers: status.late_answers,
            refusing_for: status.refusing_for,
        })
    }

    /// When a change seen now may be reported.
    fn due(&self, now: Instant) -> Instant {
        self.next_frame.map_or(now, |next| next.max(now))
    }
}

/// Completes when `late` changes; never for a broker with no deadline.
async fn late_changed(late: &LateStatus) {
    match late {
        Some(watch) => watch.changed().await,
        None => std::future::pending().await,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_ingress_control(
    control: tokio::net::UnixStream,
    status: oneshot::Receiver<&'static [u8]>,
    inbound: mpsc::Sender<InboundGuestStream>,
    mesh_key: Zeroizing<[u8; MESH_INGRESS_CONTROL_KEY_LEN]>,
    mesh_ingress_ports: Vec<u16>,
    vm_id: Uuid,
    generation: u64,
    late: LateStatus,
) -> Result<(), NetworkWorkerError> {
    let status = status.await.map_err(|_| NetworkWorkerError::StatusIo)?;
    write_worker_control_descriptor(control.as_raw_fd(), status)
        .map_err(|_| NetworkWorkerError::StatusIo)?;
    if status != WORKER_READY_MESSAGE {
        return Err(NetworkWorkerError::Protocol);
    }

    let mut mesh_receiver = MeshIngressControlReceiver::new(vm_id, generation, &mesh_ingress_ports)
        .map_err(|_| NetworkWorkerError::Protocol)?;
    let mut reported = LateReport::default();
    // A change seen and not yet reported: its frame waits for `due`.
    let mut changed: Option<Instant> = None;
    let mut frame = [0_u8; MESH_INGRESS_CONTROL_FRAME_LEN];
    let mut filled = 0;
    loop {
        // Readiness, the watch and the sleep are all cancel-safe (a wait that
        // doesn't finish keeps the watch's wake), and a Mesh frame's bytes
        // are kept across wakes, so a frame is always read whole.
        let due = changed.unwrap_or_else(Instant::now);
        let report = tokio::select! {
            readable = control.readable() => {
                readable.map_err(|_| NetworkWorkerError::FrameIo)?;
                false
            }
            () = late_changed(&late), if changed.is_none() => {
                changed = Some(reported.due(Instant::now()));
                continue;
            }
            () = tokio::time::sleep_until(due), if changed.is_some() => true,
        };
        if report {
            changed = None;
            let status = late.as_ref().map(LateAnswerWatch::status);
            if let Some(status) = reported.next(status, Instant::now()) {
                write_control_bytes(&control, &status.encode()).await?;
            }
            continue;
        }
        // Tokio's reads use recvfrom(2), which this worker denies; read(2)
        // is the audited path for its fixed-size control records.
        let read = control.try_io(Interest::READABLE, || {
            read_worker_bytes(control.as_raw_fd(), &mut frame[filled..])
        });
        match read {
            Ok(0) => return Err(NetworkWorkerError::FrameIo),
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => return Err(NetworkWorkerError::FrameIo),
        }
        if filled < frame.len() {
            continue;
        }
        filled = 0;
        if !is_mesh_ingress_control_frame(&frame) {
            return Err(NetworkWorkerError::Protocol);
        }
        let frame = mesh_receiver
            .decode(&frame, &mesh_key)
            .map_err(|_| NetworkWorkerError::Protocol)?;
        let descriptor = receive_mesh_ingress_descriptor(&control).await?;
        // The worker holds the connection now. The runner keeps its own copy
        // until this frame (#5084).
        write_control_bytes(&control, &mesh_ingress_ack(frame.sequence)).await?;
        let guest_port = frame.binding.guest_port;
        let stream =
            transferred_stream(descriptor).map_err(|_| NetworkWorkerError::InheritedDescriptor)?;
        inbound
            .send(InboundGuestStream {
                guest_port,
                stream: Box::pin(stream),
            })
            .await
            .map_err(|_| NetworkWorkerError::Engine)?;
    }
}

/// Write `bytes` with write(2), as the worker's status messages are.
async fn write_control_bytes(
    control: &tokio::net::UnixStream,
    mut bytes: &[u8],
) -> Result<(), NetworkWorkerError> {
    while !bytes.is_empty() {
        let sent = control
            .async_io(Interest::WRITABLE, || {
                send_worker_bytes(control.as_raw_fd(), bytes)
            })
            .await
            .map_err(|_| NetworkWorkerError::StatusIo)?;
        if sent == 0 {
            return Err(NetworkWorkerError::StatusIo);
        }
        bytes = &bytes[sent..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_late_status_frame_round_trips_and_nothing_else_decodes() {
        for frame in [
            LateStatusFrame {
                late_answers: 3,
                refusing_for: Some(Duration::from_millis(12_500)),
            },
            LateStatusFrame {
                late_answers: 3,
                refusing_for: Some(Duration::ZERO),
            },
            LateStatusFrame {
                late_answers: 3,
                refusing_for: None,
            },
        ] {
            assert_eq!(LateStatusFrame::decode(&frame.encode()), Some(frame));
        }
        let mut other = LateStatusFrame {
            late_answers: 1,
            refusing_for: None,
        }
        .encode();
        other[0] ^= 1;
        assert_eq!(LateStatusFrame::decode(&other), None);
    }

    fn next(report: &mut LateReport, status: Option<LateAnswerStatus>) -> Option<LateStatusFrame> {
        report.next(status, Instant::now())
    }

    /// A frame when the count rises while refusing, and one when refusing
    /// ends; nothing while it is unchanged, or for a broker with no deadline.
    #[test]
    fn the_worker_reports_only_a_change() {
        let refusing = |late_answers, seconds| {
            Some(LateAnswerStatus {
                late_answers,
                refusing_for: Some(Duration::from_secs(seconds)),
            })
        };
        let mut report = LateReport::default();
        assert_eq!(next(&mut report, None), None);
        assert_eq!(
            next(
                &mut report,
                Some(LateAnswerStatus {
                    late_answers: 0,
                    refusing_for: None
                })
            ),
            None
        );
        assert_eq!(
            next(&mut report, refusing(1, 0)).map(|frame| frame.late_answers),
            Some(1)
        );
        assert_eq!(next(&mut report, refusing(1, 1)), None);
        assert_eq!(
            next(&mut report, refusing(4, 2)).map(|frame| frame.late_answers),
            Some(4)
        );
        assert_eq!(
            next(
                &mut report,
                Some(LateAnswerStatus {
                    late_answers: 4,
                    refusing_for: None
                })
            ),
            Some(LateStatusFrame {
                late_answers: 4,
                refusing_for: None
            })
        );
        assert_eq!(
            next(
                &mut report,
                Some(LateAnswerStatus {
                    late_answers: 4,
                    refusing_for: None
                })
            ),
            None
        );
    }

    /// A frame holds the next one back for a second: a change seen sooner is
    /// reported once the second is up, with what is true then.
    #[test]
    fn late_frames_are_at_least_a_second_apart() {
        let start = Instant::now();
        let refusing = |late_answers| {
            Some(LateAnswerStatus {
                late_answers,
                refusing_for: Some(Duration::ZERO),
            })
        };
        let mut report = LateReport::default();
        assert_eq!(report.due(start), start);
        assert!(report.next(refusing(1), start).is_some());
        let soon = start + Duration::from_millis(200);
        assert_eq!(report.due(soon), start + LATE_STATUS_INTERVAL);
        let later = start + Duration::from_secs(5);
        assert_eq!(report.due(later), later);
        // An unchanged status sends nothing and leaves the wait as it was.
        assert_eq!(report.next(refusing(1), soon), None);
        assert_eq!(report.due(soon), start + LATE_STATUS_INTERVAL);
    }
}
