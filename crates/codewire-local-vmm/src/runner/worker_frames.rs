//! What the network worker says on its control socket once it is ready,
//! read in one place.
//!
//! Everything is one frame of [`WORKER_FRAME_LEN`] bytes, told apart by its
//! first eight: the egress broker's late answers (#4965,
//! `super::egress_status`) and the acknowledgement of a Mesh connection the
//! runner passed (#5084, `super::mesh_ingress_pass`). Either can come at any
//! time, also between a Mesh connection and its acknowledgement. The end of
//! the stream, a read error or any other frame fails the ingress forwarder
//! closed.

use super::RunnerError;
use super::egress_status::EgressStatusCell;
use super::mesh_ingress_pass::MeshIngressPass;
use crate::mesh_ingress_ack::{MESH_INGRESS_ACK_LEN, acknowledged_sequence};
use crate::network_worker::{LATE_STATUS_FRAME_LEN, LateStatusFrame};

const WORKER_FRAME_LEN: usize = LATE_STATUS_FRAME_LEN;
const _: () = assert!(MESH_INGRESS_ACK_LEN == WORKER_FRAME_LEN);

/// The runner's reading of the worker's frames. A frame read in part is kept
/// for the next wake.
#[derive(Default)]
pub(super) struct WorkerFrames {
    frame: [u8; WORKER_FRAME_LEN],
    filled: usize,
}

impl WorkerFrames {
    /// Takes every whole frame the worker has written, without waiting, once
    /// `control` is `readable`: a late-status frame to `egress`, an
    /// acknowledgement to `mesh`.
    pub(super) fn read(
        &mut self,
        control: &tokio::net::UnixStream,
        readable: std::io::Result<()>,
        egress: &EgressStatusCell,
        mesh: &mut MeshIngressPass,
    ) -> Result<(), RunnerError> {
        readable.map_err(|_| RunnerError::IngressControl)?;
        loop {
            match control.try_read(&mut self.frame[self.filled..]) {
                Ok(0) => return Err(RunnerError::IngressControl),
                Ok(read) => self.filled += read,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(_) => return Err(RunnerError::IngressControl),
            }
            if self.filled < WORKER_FRAME_LEN {
                continue;
            }
            self.filled = 0;
            if let Some(status) = LateStatusFrame::decode(&self.frame) {
                egress.record(status);
            } else if let Some(sequence) = acknowledged_sequence(&self.frame) {
                mesh.held(sequence)?;
            } else {
                return Err(RunnerError::IngressControl);
            }
        }
    }

    /// The Mesh connection in flight has waited to its limit. An
    /// acknowledgement the worker has already written still counts, however
    /// late this task came to read it; otherwise the connection is closed.
    pub(super) fn at_mesh_limit(
        &mut self,
        control: &tokio::net::UnixStream,
        egress: &EgressStatusCell,
        mesh: &mut MeshIngressPass,
    ) -> Result<(), RunnerError> {
        self.read(control, Ok(()), egress, mesh)?;
        mesh.unacknowledged()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use tokio::io::AsyncWriteExt as _;

    use super::super::mesh_ingress_pass::tests::{
        KEY, closes, connection, control, ended, pass, received,
    };
    use super::*;
    use crate::mesh_ingress_ack::mesh_ingress_ack;

    fn late_status(
        late_answers: u64,
        refusing_for: Option<Duration>,
    ) -> [u8; LATE_STATUS_FRAME_LEN] {
        LateStatusFrame {
            late_answers,
            refusing_for,
        }
        .encode()
    }

    /// The reader as the forwarder's loop drives it, with what it feeds.
    struct Runner {
        control: tokio::net::UnixStream,
        frames: WorkerFrames,
        egress: EgressStatusCell,
        mesh: MeshIngressPass,
    }

    impl Runner {
        fn new(control: tokio::net::UnixStream) -> Self {
            Self {
                control,
                frames: WorkerFrames::default(),
                egress: EgressStatusCell::default(),
                mesh: pass(),
            }
        }

        /// Writes `bytes` as the worker and lets the runner read them.
        async fn said(
            &mut self,
            worker: &mut tokio::net::UnixStream,
            bytes: &[u8],
        ) -> Result<(), RunnerError> {
            worker.write_all(bytes).await.unwrap();
            let readable = self.control.readable().await;
            self.frames
                .read(&self.control, readable, &self.egress, &mut self.mesh)
        }

        fn late_answers(&self) -> Option<u64> {
            self.egress
                .unavailable()
                .map(|unavailable| unavailable.late_answers)
        }
    }

    /// The count and the time crossing from the worker are recorded, also
    /// from a frame split across reads, and an answered-again frame clears
    /// them.
    #[tokio::test]
    async fn the_runner_records_and_clears_what_the_worker_reports() {
        let (runner, mut worker) = control();
        let mut runner = Runner::new(runner);
        let late = late_status(3, Some(Duration::from_secs(90)));
        runner.said(&mut worker, &late[..10]).await.unwrap();
        assert_eq!(runner.egress.unavailable(), None);
        runner.said(&mut worker, &late[10..]).await.unwrap();
        let unavailable = runner.egress.unavailable().unwrap();
        assert_eq!(unavailable.late_answers, 3);
        let refusing = SystemTime::now().duration_since(unavailable.since).unwrap();
        assert!(refusing >= Duration::from_secs(90), "{refusing:?}");

        runner
            .said(&mut worker, &late_status(3, None))
            .await
            .unwrap();
        assert_eq!(runner.egress.unavailable(), None);
    }

    /// Late-status frames and acknowledgements alternate on the one socket,
    /// each split across writes and two sharing a write. Each reaches only
    /// its own reader: a late-status frame between a Mesh connection and its
    /// acknowledgement leaves that connection in flight and held, and an
    /// acknowledgement leaves the egress status as it was.
    #[tokio::test]
    async fn late_status_frames_and_acknowledgements_interleave() {
        let (runner, mut worker) = control();
        let mut runner = Runner::new(runner);
        let refusing = Some(Duration::from_secs(1));

        let (accepted, mut first) = connection();
        runner
            .mesh
            .send(&mut runner.control, &KEY, accepted)
            .await
            .unwrap();
        drop(received(&mut worker).await);
        let status = late_status(1, refusing);
        runner.said(&mut worker, &status[..5]).await.unwrap();
        assert_eq!(runner.late_answers(), None);
        runner.said(&mut worker, &status[5..]).await.unwrap();
        assert_eq!(runner.late_answers(), Some(1));
        assert!(!runner.mesh.idle(), "a late-status frame acknowledged");
        assert!(!ended(&mut first), "the runner let go without its word");

        let ack = mesh_ingress_ack(1);
        runner.said(&mut worker, &ack[..23]).await.unwrap();
        assert!(!runner.mesh.idle());
        runner.said(&mut worker, &ack[23..]).await.unwrap();
        assert!(runner.mesh.idle());
        assert!(closes(first).await);
        assert_eq!(runner.late_answers(), Some(1));

        let (accepted, mut second) = connection();
        runner
            .mesh
            .send(&mut runner.control, &KEY, accepted)
            .await
            .unwrap();
        drop(received(&mut worker).await);
        // The end of one frame, a whole one and the start of the next in
        // each write.
        let mut stream = Vec::new();
        stream.extend_from_slice(&late_status(2, refusing));
        stream.extend_from_slice(&late_status(3, refusing));
        stream.extend_from_slice(&mesh_ingress_ack(2));
        stream.extend_from_slice(&late_status(4, None));
        runner.said(&mut worker, &stream[..7]).await.unwrap();
        assert_eq!(runner.late_answers(), Some(1));
        runner.said(&mut worker, &stream[7..55]).await.unwrap();
        assert_eq!(runner.late_answers(), Some(3));
        assert!(!runner.mesh.idle());
        assert!(!ended(&mut second));
        runner.said(&mut worker, &stream[55..80]).await.unwrap();
        assert!(runner.mesh.idle());
        assert!(closes(second).await);
        assert_eq!(runner.late_answers(), Some(3));
        runner.said(&mut worker, &stream[80..]).await.unwrap();
        assert_eq!(runner.egress.unavailable(), None);
    }

    /// An acknowledgement the worker wrote in time counts when the runner's
    /// loop reaches the limit before it reads: the connection is not closed
    /// under the worker that holds it, and is not counted as unacknowledged.
    #[tokio::test(start_paused = true)]
    async fn an_acknowledgement_already_written_counts_at_the_limit() {
        let (runner, mut worker) = control();
        let mut runner = Runner::new(runner);
        let mut kept = Vec::new();
        for sequence in 1..=3 {
            let (accepted, mut transport) = connection();
            runner
                .mesh
                .send(&mut runner.control, &KEY, accepted)
                .await
                .unwrap();
            kept.push(received(&mut worker).await);
            worker.write_all(&mesh_ingress_ack(sequence)).await.unwrap();
            runner.mesh.limit().await;
            runner
                .frames
                .at_mesh_limit(&runner.control, &runner.egress, &mut runner.mesh)
                .unwrap();
            assert!(runner.mesh.idle());
            assert!(
                !ended(&mut transport),
                "closed under the worker that holds it"
            );
        }
    }

    /// With no acknowledgement written, the limit closes the connection.
    #[tokio::test(start_paused = true)]
    async fn the_limit_closes_a_connection_with_no_acknowledgement() {
        let (runner, mut worker) = control();
        let mut runner = Runner::new(runner);
        let (accepted, mut transport) = connection();
        runner
            .mesh
            .send(&mut runner.control, &KEY, accepted)
            .await
            .unwrap();
        let _held = received(&mut worker).await;
        runner.mesh.limit().await;
        runner
            .frames
            .at_mesh_limit(&runner.control, &runner.egress, &mut runner.mesh)
            .unwrap();
        assert!(runner.mesh.idle());
        assert!(ended(&mut transport));
    }

    /// Any other frame, a malformed acknowledgement, one for a connection
    /// not yet sent, or the worker going away fails the forwarder closed.
    #[tokio::test]
    async fn anything_else_fails_closed() {
        let mut other_magic = late_status(1, None);
        other_magic[0] ^= 1;
        let mut padded = mesh_ingress_ack(1);
        padded[23] = 1;
        for said in [
            other_magic,
            mesh_ingress_ack(0),
            padded,
            mesh_ingress_ack(2),
        ] {
            let (runner, mut worker) = control();
            let mut runner = Runner::new(runner);
            let (accepted, _transport) = connection();
            runner
                .mesh
                .send(&mut runner.control, &KEY, accepted)
                .await
                .unwrap();
            let _held = received(&mut worker).await;
            assert!(
                matches!(
                    runner.said(&mut worker, &said).await,
                    Err(RunnerError::IngressControl)
                ),
                "{said:?}"
            );
        }

        let (runner, worker) = control();
        let mut runner = Runner::new(runner);
        drop(worker);
        let readable = runner.control.readable().await;
        assert!(matches!(
            runner
                .frames
                .read(&runner.control, readable, &runner.egress, &mut runner.mesh),
            Err(RunnerError::IngressControl)
        ));
    }
}
