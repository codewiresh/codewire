//! Passing a Mesh connection the runner accepted to the network worker, and
//! keeping the runner's copy until the worker has it (#5084,
//! `crate::mesh_ingress_ack`).
//!
//! A pass is three events of the ingress forwarder's loop, so the loop never
//! waits for the worker's answer: [`MeshIngressPass::send`] while no
//! connection is in flight, the worker's acknowledgement, which
//! `super::worker_frames` reads, and the limit.

use super::*;
use crate::diagnostic_log::{DiagnosticLog, LogField, record};
use crate::mesh_ingress_ack::Silence;

/// The runner's passing of Mesh connections to the network worker, one at a
/// time.
pub(super) struct MeshIngressPass {
    vm_id: Uuid,
    generation: u64,
    /// The next connection's sequence on the control channel.
    sequence: u64,
    /// How long the runner keeps a sent connection for its acknowledgement.
    ack_timeout: Duration,
    in_flight: Option<InFlight>,
    silence: Silence,
    log: Option<DiagnosticLog>,
}

/// The connection the worker was sent and has not acknowledged: the runner's
/// copy of it, and until when the runner keeps that copy.
struct InFlight {
    sequence: u64,
    accepted: AcceptedMeshIngress,
    limit: tokio::time::Instant,
}

impl MeshIngressPass {
    pub(super) fn new(vm_id: Uuid, generation: u64, ack_timeout: Duration) -> Self {
        Self {
            vm_id,
            generation,
            sequence: 1,
            ack_timeout,
            in_flight: None,
            silence: Silence::default(),
            log: DiagnosticLog::inherited(),
        }
    }

    /// Whether the next connection may be sent: none is in flight.
    pub(super) fn idle(&self) -> bool {
        self.in_flight.is_none()
    }

    /// Sends `accepted` to the worker and keeps the runner's copy as the
    /// connection in flight. Refused while another is in flight.
    pub(super) async fn send(
        &mut self,
        control: &mut tokio::net::UnixStream,
        key: &[u8; MESH_INGRESS_CONTROL_KEY_LEN],
        accepted: AcceptedMeshIngress,
    ) -> Result<(), RunnerError> {
        if self.in_flight.is_some() {
            return Err(RunnerError::IngressControl);
        }
        let sequence = self.sequence;
        self.sequence = sequence.checked_add(1).ok_or(RunnerError::IngressControl)?;
        transfer_mesh_ingress_connection(
            control,
            key,
            self.vm_id,
            self.generation,
            sequence,
            &accepted,
        )
        .await?;
        // The worker's time to answer runs from when it has been sent the
        // connection: a send held up by a full channel does not use it up.
        let limit = tokio::time::Instant::now() + self.ack_timeout;
        self.in_flight = Some(InFlight {
            sequence,
            accepted,
            limit,
        });
        Ok(())
    }

    /// The worker says it holds the connection with `sequence`. For the one
    /// in flight the runner lets go of its copy. For an earlier one the
    /// acknowledgement came after the runner closed it, and changes nothing.
    /// One for a connection not yet sent is not this protocol.
    pub(super) fn held(&mut self, sequence: u64) -> Result<(), RunnerError> {
        if sequence >= self.sequence {
            return Err(RunnerError::IngressControl);
        }
        if self
            .in_flight
            .as_ref()
            .is_some_and(|in_flight| in_flight.sequence == sequence)
        {
            self.in_flight = None;
            self.silence.acknowledged();
        }
        Ok(())
    }

    /// Completes when the connection in flight has waited to its limit, and
    /// never while none is in flight.
    pub(super) async fn limit(&self) {
        match &self.in_flight {
            Some(in_flight) => tokio::time::sleep_until(in_flight.limit).await,
            None => std::future::pending().await,
        }
    }

    /// Closes the connection in flight, which the worker did not acknowledge
    /// in time, so its client sees it end, and records it. The third in a
    /// row ends the forwarder.
    pub(super) fn unacknowledged(&mut self) -> Result<(), RunnerError> {
        let Some(InFlight {
            sequence, accepted, ..
        }) = self.in_flight.take()
        else {
            return Ok(());
        };
        // The worker may hold a copy, dead or alive. Either way the
        // connection ends for its client now, not when the copy is noticed.
        // Already shut down by its peer is as good.
        let _ = accepted.stream.shutdown(std::net::Shutdown::Both);
        record(
            self.log.as_ref(),
            "mesh_ingress_unacknowledged",
            &[
                ("sequence", LogField::Count(sequence)),
                (
                    "guest_port",
                    LogField::Count(u64::from(accepted.binding.guest_port)),
                ),
            ],
        );
        self.silence
            .unacknowledged()
            .map_err(|_| RunnerError::IngressControl)
    }
}

async fn transfer_mesh_ingress_connection(
    control: &mut tokio::net::UnixStream,
    key: &[u8; MESH_INGRESS_CONTROL_KEY_LEN],
    vm_id: Uuid,
    generation: u64,
    sequence: u64,
    accepted: &AcceptedMeshIngress,
) -> Result<(), RunnerError> {
    let frame = MeshIngressControlFrame::encode(vm_id, generation, sequence, accepted.binding, key)
        .map_err(|_| RunnerError::IngressControl)?;
    let deadline = tokio::time::Instant::now() + INGRESS_CONTROL_TIMEOUT;
    tokio::time::timeout_at(deadline, async {
        control.write_all(&frame).await?;
        control.flush().await
    })
    .await
    .map_err(|_| RunnerError::IngressControl)?
    .map_err(|_| RunnerError::IngressControl)?;
    transfer_worker_descriptor(
        control,
        accepted.stream.as_raw_fd(),
        deadline,
        send_mesh_ingress_descriptor,
    )
    .await
    .map_err(|_| RunnerError::IngressControl)
}

#[cfg(test)]
pub(super) mod tests {
    use std::os::unix::net::UnixStream as StdUnixStream;

    use super::*;
    use crate::mesh_ingress::{MESH_INGRESS_CONTROL_FRAME_LEN, MeshIngressBinding};
    use crate::mesh_ingress_ack::MESH_INGRESS_ACK_TIMEOUT;
    use crate::network_worker::receive_mesh_ingress_descriptor;

    pub(in crate::runner) const KEY: [u8; MESH_INGRESS_CONTROL_KEY_LEN] =
        [0x4d; MESH_INGRESS_CONTROL_KEY_LEN];
    /// Generous, so a loaded host fails only a missing event.
    pub(in crate::runner) const WAIT: Duration = Duration::from_secs(30);

    pub(in crate::runner) fn control() -> (tokio::net::UnixStream, tokio::net::UnixStream) {
        tokio::net::UnixStream::pair().unwrap()
    }

    pub(in crate::runner) fn pass() -> MeshIngressPass {
        MeshIngressPass::new(Uuid::from_u128(7), 1, MESH_INGRESS_ACK_TIMEOUT)
    }

    /// A Mesh connection as the runner accepts it, and the Mesh transport's
    /// end of it.
    pub(in crate::runner) fn connection() -> (AcceptedMeshIngress, StdUnixStream) {
        let (stream, transport) = StdUnixStream::pair().unwrap();
        let binding = MeshIngressBinding::new(3_000).unwrap();
        (AcceptedMeshIngress { binding, stream }, transport)
    }

    /// The worker's side of one pass: the control frame, then the connection.
    pub(in crate::runner) async fn received(worker: &mut tokio::net::UnixStream) -> OwnedFd {
        let mut frame = [0_u8; MESH_INGRESS_CONTROL_FRAME_LEN];
        tokio::time::timeout(WAIT, worker.read_exact(&mut frame))
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(WAIT, receive_mesh_ingress_descriptor(worker))
            .await
            .unwrap()
            .unwrap()
    }

    /// Whether the Mesh transport's end has seen its connection end: false
    /// while any copy of the other end is open and not shut down.
    pub(in crate::runner) fn ended(transport: &mut StdUnixStream) -> bool {
        transport.set_nonblocking(true).unwrap();
        match transport.read(&mut [0_u8; 1]) {
            Ok(0) => true,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
            other => panic!("the Mesh transport's end read {other:?}"),
        }
    }

    /// Waits for the Mesh transport's end to see its connection end, which
    /// it does once every copy of the other end is closed. Waited for, not
    /// looked at once: a test beside this one that starts a process holds a
    /// copy of every descriptor from its fork to its exec.
    pub(in crate::runner) async fn closes(transport: StdUnixStream) -> bool {
        transport.set_nonblocking(true).unwrap();
        let mut transport = tokio::net::UnixStream::from_std(transport).unwrap();
        matches!(
            tokio::time::timeout(WAIT, transport.read(&mut [0_u8; 1])).await,
            Ok(Ok(0))
        )
    }

    /// The worker here closes the connection it receives at once, so the
    /// Mesh transport's end sees the end of its stream exactly when the
    /// runner lets go of its own copy: not before the worker's
    /// acknowledgement, and at it. Sending never waits for that
    /// acknowledgement.
    #[tokio::test]
    async fn the_runners_copy_of_a_mesh_connection_stays_open_until_the_worker_acknowledges() {
        let (mut runner, mut worker) = control();
        let (accepted, mut transport) = connection();
        let mut pass = pass();
        assert!(pass.idle());
        tokio::time::timeout(WAIT, pass.send(&mut runner, &KEY, accepted))
            .await
            .expect("sending waited for the worker")
            .unwrap();
        assert!(!pass.idle());

        drop(received(&mut worker).await);
        assert!(!ended(&mut transport), "the runner still holds its copy");

        pass.held(1).unwrap();
        assert!(pass.idle());
        assert!(
            closes(transport).await,
            "the runner let go once the worker acknowledged"
        );
    }

    /// One connection at a time: a second is refused while the first is in
    /// flight, and the first stays as it was.
    #[tokio::test]
    async fn a_second_connection_is_not_sent_while_one_is_in_flight() {
        let (mut runner, mut worker) = control();
        let mut pass = pass();
        let (first, mut first_transport) = connection();
        pass.send(&mut runner, &KEY, first).await.unwrap();
        let _held = received(&mut worker).await;

        let (second, _second_transport) = connection();
        assert!(matches!(
            pass.send(&mut runner, &KEY, second).await,
            Err(RunnerError::IngressControl)
        ));
        assert!(!pass.idle());
        assert!(!ended(&mut first_transport));
    }

    /// A worker that takes a connection and says nothing: the limit comes
    /// two seconds after the send, the runner closes that connection, so the
    /// Mesh transport's end sees it end although the worker still holds a
    /// copy, and goes on. The third in a row ends the forwarder.
    #[tokio::test(start_paused = true)]
    async fn a_connection_the_worker_does_not_acknowledge_is_closed_and_the_third_ends_the_forwarder()
     {
        let (mut runner, mut worker) = control();
        let mut pass = pass();
        let mut kept = Vec::new();
        for connection_number in 1..=3 {
            let (accepted, mut transport) = connection();
            let asked = tokio::time::Instant::now();
            pass.send(&mut runner, &KEY, accepted).await.unwrap();
            kept.push(received(&mut worker).await);
            pass.limit().await;
            assert_eq!(asked.elapsed(), MESH_INGRESS_ACK_TIMEOUT);
            assert!(!ended(&mut transport), "closed only at the event");

            let closed = pass.unacknowledged();
            assert!(pass.idle());
            assert!(
                ended(&mut transport),
                "the runner did not close the unacknowledged connection"
            );
            if connection_number < 3 {
                closed.unwrap();
            } else {
                assert!(matches!(closed, Err(RunnerError::IngressControl)));
            }
        }
    }

    /// The worker's time to answer starts when it has been sent the
    /// connection, not when the runner began to send: a send that waited a
    /// second for room in the channel still leaves the whole limit.
    #[tokio::test(start_paused = true)]
    async fn the_limit_runs_from_the_end_of_the_send() {
        let (mut runner, mut worker) = control();
        let mut filled = 0;
        while let Ok(written) = runner.try_write(&[0_u8; 4096]) {
            filled += written;
        }
        let (accepted, _transport) = connection();
        let mut pass = pass();
        let began = tokio::time::Instant::now();
        let held_up = Duration::from_secs(1);
        {
            let send = pass.send(&mut runner, &KEY, accepted);
            tokio::pin!(send);
            assert!(
                tokio::time::timeout(held_up, &mut send).await.is_err(),
                "the send did not wait for room in the channel"
            );
            worker.read_exact(&mut vec![0_u8; filled]).await.unwrap();
            send.await.unwrap();
        }
        let _held = received(&mut worker).await;
        pass.limit().await;
        assert_eq!(began.elapsed(), held_up + MESH_INGRESS_ACK_TIMEOUT);
    }

    /// An acknowledgement between two unacknowledged connections starts the
    /// count again.
    #[tokio::test(start_paused = true)]
    async fn an_acknowledged_connection_starts_the_count_again() {
        let (mut runner, mut worker) = control();
        let mut pass = pass();
        let mut kept = Vec::new();
        for sequence in 1..=5 {
            let (accepted, _transport) = connection();
            pass.send(&mut runner, &KEY, accepted).await.unwrap();
            kept.push(received(&mut worker).await);
            if sequence == 3 {
                pass.held(sequence).unwrap();
            } else {
                pass.unacknowledged().unwrap();
            }
        }
    }

    /// An acknowledgement that comes after the runner gave up on its
    /// connection changes nothing, between connections or during the next.
    /// One for a connection not yet sent is not this protocol.
    #[tokio::test(start_paused = true)]
    async fn a_late_acknowledgement_is_ignored_and_one_ahead_is_refused() {
        let (mut runner, mut worker) = control();
        let mut pass = pass();
        assert!(matches!(pass.held(1), Err(RunnerError::IngressControl)));

        let (accepted, _transport) = connection();
        pass.send(&mut runner, &KEY, accepted).await.unwrap();
        let _first = received(&mut worker).await;
        pass.unacknowledged().unwrap();
        pass.held(1).unwrap();

        let (accepted, mut transport) = connection();
        pass.send(&mut runner, &KEY, accepted).await.unwrap();
        let _second = received(&mut worker).await;
        pass.held(1).unwrap();
        assert!(
            !pass.idle(),
            "the first connection's word is not the second's"
        );
        assert!(!ended(&mut transport));
        assert!(matches!(pass.held(3), Err(RunnerError::IngressControl)));
    }
}
