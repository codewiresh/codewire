//! The acknowledgement of a Mesh connection passed between host processes
//! (#5084).
//!
//! A Mesh connection to a local VM is passed twice as a Unix stream: from the
//! Mesh transport to the runner, and from the runner to the network worker.
//! On macOS a socket whose only reference is a descriptor in flight can be
//! disposed of once its sender has closed its last copy, so each sender keeps
//! its copy until the receiver says it holds the connection
//! (`docs/dev/MACOS-CLI.md`). The receiver answers each control frame's
//! connection with one frame, [`mesh_ingress_ack`], naming the control
//! frame's sequence.
//!
//! A sender passes one connection at a time and waits for that frame, to
//! [`MESH_INGRESS_ACK_TIMEOUT`], before the next, so it never holds more than
//! one copy. A connection not acknowledged in time is the sender's to close:
//! letting go of it silently would be the same loss again.
//! [`MAX_UNACKNOWLEDGED_IN_A_ROW`] of them end the sender's channel, as a
//! receiver that has stopped answering.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::AsyncReadExt as _;
use tokio::sync::watch;

/// How long a sender keeps a passed connection for its acknowledgement.
pub(crate) const MESH_INGRESS_ACK_TIMEOUT: Duration = Duration::from_secs(2);
/// Connections unacknowledged in a row that end the sender's channel.
pub(crate) const MAX_UNACKNOWLEDGED_IN_A_ROW: u8 = 3;

/// The magic, the sequence as a big-endian `u64` and eight zero bytes. The
/// length is the network worker's late-status frame's, so everything the
/// worker says to the runner once it is ready is one frame of this length,
/// told apart by its magic (`runner::worker_frames`).
pub(crate) const MESH_INGRESS_ACK_LEN: usize = 24;
const ACK_MAGIC: &[u8; 8] = b"CWMESHA1";

/// The receiver's frame for the connection the control frame with `sequence`
/// announced: it holds that connection now.
pub(crate) fn mesh_ingress_ack(sequence: u64) -> [u8; MESH_INGRESS_ACK_LEN] {
    let mut frame = [0_u8; MESH_INGRESS_ACK_LEN];
    frame[..8].copy_from_slice(ACK_MAGIC);
    frame[8..16].copy_from_slice(&sequence.to_be_bytes());
    frame
}

/// The sequence an acknowledgement names. None for anything but the magic, a
/// sequence from 1 and eight zero bytes: an acknowledgement is matched to its
/// connection, never guessed.
pub(crate) fn acknowledged_sequence(frame: &[u8; MESH_INGRESS_ACK_LEN]) -> Option<u64> {
    let (magic, rest) = frame.split_first_chunk::<8>()?;
    let (sequence, padding) = rest.split_first_chunk::<8>()?;
    let sequence = u64::from_be_bytes(*sequence);
    (magic == ACK_MAGIC && sequence != 0 && padding.iter().all(|byte| *byte == 0))
        .then_some(sequence)
}

/// What a sender learned about the connection it passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Passed {
    /// The receiver holds it; the sender lets go of its copy.
    Acknowledged,
    /// The receiver said nothing in time; the sender closes the connection.
    Unacknowledged,
}

/// Why a sender's channel ends.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AcknowledgementError {
    #[error("the Mesh ingress receiver closed its channel")]
    Closed,
    #[error("the Mesh ingress receiver said something that is not an acknowledgement")]
    Protocol,
    #[error("the Mesh ingress receiver stopped acknowledging connections")]
    Silent,
}

/// A sender's count of the connections its receiver left unacknowledged in a
/// row.
#[derive(Debug, Default)]
pub(crate) struct Silence(u8);

impl Silence {
    pub(crate) fn acknowledged(&mut self) {
        self.0 = 0;
    }

    /// One more connection the receiver said nothing about in time.
    pub(crate) fn unacknowledged(&mut self) -> Result<(), AcknowledgementError> {
        self.0 += 1;
        if self.0 >= MAX_UNACKNOWLEDGED_IN_A_ROW {
            return Err(AcknowledgementError::Silent);
        }
        Ok(())
    }
}

/// The two ends of a sender's acknowledgements on a channel that carries
/// nothing else toward it: the Mesh transport's channel to the runner. The
/// end of that stream is also how the transport learns its runner is gone,
/// so one task reads `channel` for as long as the sender lives
/// ([`AcknowledgementReader::read`]), and the sender waits on what that task
/// read ([`Acknowledgements::of`]).
pub(crate) fn acknowledgements(
    channel: tokio::net::unix::OwnedReadHalf,
) -> (Acknowledgements, AcknowledgementReader) {
    let passed = Arc::new(AtomicU64::new(0));
    let (acknowledged_tx, acknowledged) = watch::channel(0);
    (
        Acknowledgements {
            passed: Arc::clone(&passed),
            acknowledged,
            silence: Silence::default(),
        },
        AcknowledgementReader {
            channel,
            passed,
            acknowledged: acknowledged_tx,
        },
    )
}

/// A sender's wait for the acknowledgement of the connection it passed.
pub(crate) struct Acknowledgements {
    /// The sequence of the last connection the sender passed.
    passed: Arc<AtomicU64>,
    /// The latest sequence the receiver acknowledged.
    acknowledged: watch::Receiver<u64>,
    silence: Silence,
}

impl Acknowledgements {
    /// The sender is about to pass the connection with `sequence`: from now
    /// on its acknowledgement is one the receiver may send.
    pub(crate) fn passing(&self, sequence: u64) {
        self.passed.store(sequence, Ordering::SeqCst);
    }

    /// Waits, to `limit`, for the receiver's acknowledgement of the
    /// connection with `sequence`, which the sender has just passed.
    pub(crate) async fn of(
        &mut self,
        sequence: u64,
        limit: tokio::time::Instant,
    ) -> Result<Passed, AcknowledgementError> {
        let acknowledged = self
            .acknowledged
            .wait_for(|acknowledged| *acknowledged >= sequence);
        match tokio::time::timeout_at(limit, acknowledged).await {
            Ok(Ok(_)) => {
                self.silence.acknowledged();
                Ok(Passed::Acknowledged)
            }
            // The reader has ended: the receiver closed the channel or said
            // something else on it.
            Ok(Err(_)) => Err(AcknowledgementError::Closed),
            Err(_) => {
                self.silence.unacknowledged()?;
                Ok(Passed::Unacknowledged)
            }
        }
    }
}

/// The one reader of the receiver's side of a sender's channel.
pub struct AcknowledgementReader {
    channel: tokio::net::unix::OwnedReadHalf,
    passed: Arc<AtomicU64>,
    acknowledged: watch::Sender<u64>,
}

impl AcknowledgementReader {
    /// Reads the receiver's acknowledgements until the receiver closes the
    /// channel, which is `Ok`. An acknowledgement of an earlier connection
    /// came after its sender gave up on it and changes nothing. One of a
    /// connection not yet passed, or any other byte, is not this protocol.
    pub async fn read(mut self) -> Result<(), AcknowledgementError> {
        let mut frame = [0_u8; MESH_INGRESS_ACK_LEN];
        let mut filled = 0;
        loop {
            match self.channel.read(&mut frame[filled..]).await {
                Ok(0) => return Ok(()),
                Ok(read) => filled += read,
                Err(_) => return Err(AcknowledgementError::Closed),
            }
            let magic = filled.min(ACK_MAGIC.len());
            if frame[..magic] != ACK_MAGIC[..magic] {
                return Err(AcknowledgementError::Protocol);
            }
            if filled < MESH_INGRESS_ACK_LEN {
                continue;
            }
            filled = 0;
            let sequence = acknowledged_sequence(&frame).ok_or(AcknowledgementError::Protocol)?;
            if sequence > self.passed.load(Ordering::SeqCst) {
                return Err(AcknowledgementError::Protocol);
            }
            self.acknowledged.send_if_modified(|acknowledged| {
                let later = sequence > *acknowledged;
                if later {
                    *acknowledged = sequence;
                }
                later
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt as _;

    use super::*;

    type Reading = tokio::task::JoinHandle<Result<(), AcknowledgementError>>;

    /// A sender's acknowledgements with their reader running, and the
    /// receiver's end of the channel.
    fn channel() -> (Acknowledgements, Reading, tokio::net::UnixStream) {
        let (sender, receiver) = tokio::net::UnixStream::pair().unwrap();
        let (sender, _write) = sender.into_split();
        let (acknowledgements, reader) = acknowledgements(sender);
        (acknowledgements, tokio::spawn(reader.read()), receiver)
    }

    #[test]
    fn an_acknowledgement_is_read_strictly() {
        let mut expected = *b"CWMESHA1\0\0\0\0\0\0\0\x07\0\0\0\0\0\0\0\0";
        assert_eq!(mesh_ingress_ack(7), expected);
        assert_eq!(acknowledged_sequence(&expected), Some(7));
        assert_eq!(
            acknowledged_sequence(&mesh_ingress_ack(u64::MAX)),
            Some(u64::MAX)
        );

        assert_eq!(acknowledged_sequence(&mesh_ingress_ack(0)), None);
        for byte in [0, 7, 16, 23] {
            let mut malformed = mesh_ingress_ack(7);
            malformed[byte] ^= 1;
            assert_eq!(acknowledged_sequence(&malformed), None, "byte {byte}");
        }
        expected[..8].copy_from_slice(b"CWNETWL1");
        assert_eq!(acknowledged_sequence(&expected), None);
    }

    /// The sender's wait ends on the acknowledgement of the connection it
    /// passed and on nothing else: one of an earlier connection changes
    /// nothing, and a frame written in two parts is one frame.
    #[tokio::test(start_paused = true)]
    async fn the_wait_ends_on_this_connections_acknowledgement() {
        let (mut acknowledgements, _reading, mut receiver) = channel();
        let limit = tokio::time::Instant::now() + Duration::from_secs(30);
        acknowledgements.passing(1);
        acknowledgements.passing(2);
        receiver.write_all(&mesh_ingress_ack(1)).await.unwrap();
        receiver
            .write_all(&mesh_ingress_ack(2)[..11])
            .await
            .unwrap();
        let wait = acknowledgements.of(2, limit);
        tokio::pin!(wait);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut wait)
                .await
                .is_err(),
            "an earlier connection's acknowledgement and half a frame end nothing"
        );
        receiver
            .write_all(&mesh_ingress_ack(2)[11..])
            .await
            .unwrap();
        assert_eq!(wait.await, Ok(Passed::Acknowledged));
    }

    /// A receiver that says nothing leaves the connection unacknowledged at
    /// the limit, and the third in a row ends the channel. One that answers
    /// in between starts the count again, and an acknowledgement that comes
    /// after its limit is not taken for the next connection's.
    #[tokio::test(start_paused = true)]
    async fn a_silent_receiver_ends_the_channel_at_the_third_in_a_row() {
        let (mut acknowledgements, reading, mut receiver) = channel();
        let pass = async |acknowledgements: &mut Acknowledgements, sequence| {
            acknowledgements.passing(sequence);
            let limit = tokio::time::Instant::now() + MESH_INGRESS_ACK_TIMEOUT;
            acknowledgements.of(sequence, limit).await
        };
        assert_eq!(
            pass(&mut acknowledgements, 1).await,
            Ok(Passed::Unacknowledged)
        );
        receiver.write_all(&mesh_ingress_ack(1)).await.unwrap();
        assert_eq!(
            pass(&mut acknowledgements, 2).await,
            Ok(Passed::Unacknowledged)
        );
        receiver.write_all(&mesh_ingress_ack(3)[..9]).await.unwrap();
        acknowledgements.passing(3);
        receiver.write_all(&mesh_ingress_ack(3)[9..]).await.unwrap();
        assert_eq!(
            pass(&mut acknowledgements, 3).await,
            Ok(Passed::Acknowledged)
        );
        assert_eq!(
            pass(&mut acknowledgements, 4).await,
            Ok(Passed::Unacknowledged)
        );
        assert_eq!(
            pass(&mut acknowledgements, 5).await,
            Ok(Passed::Unacknowledged)
        );
        assert_eq!(
            pass(&mut acknowledgements, 6).await,
            Err(AcknowledgementError::Silent)
        );
        assert!(!reading.is_finished(), "silence is the sender's to judge");
    }

    /// Anything but an acknowledgement, or one of a connection not yet
    /// passed, ends the reader as not this protocol, at the first byte that
    /// shows it, and the sender's wait with it.
    #[tokio::test]
    async fn anything_else_ends_the_channel() {
        let limit = || tokio::time::Instant::now() + Duration::from_secs(30);
        let mut padded = mesh_ingress_ack(2);
        padded[23] = 1;
        for said in [
            &mesh_ingress_ack(3)[..],
            &mesh_ingress_ack(0),
            &padded,
            b"x",
            b"CWMESHI1",
        ] {
            let (mut acknowledgements, reading, mut receiver) = channel();
            acknowledgements.passing(2);
            receiver.write_all(said).await.unwrap();
            assert_eq!(
                acknowledgements.of(2, limit()).await,
                Err(AcknowledgementError::Closed),
                "{said:?}"
            );
            assert_eq!(
                reading.await.unwrap(),
                Err(AcknowledgementError::Protocol),
                "{said:?}"
            );
        }
    }

    /// The receiver closing the channel ends the reader without an error,
    /// which is how a sender's process learns its receiver is gone, and
    /// ends a wait in progress.
    #[tokio::test]
    async fn the_receiver_closing_the_channel_ends_the_reader() {
        let (mut acknowledgements, reading, receiver) = channel();
        acknowledgements.passing(1);
        drop(receiver);
        assert_eq!(reading.await.unwrap(), Ok(()));
        let limit = tokio::time::Instant::now() + Duration::from_secs(30);
        assert_eq!(
            acknowledgements.of(1, limit).await,
            Err(AcknowledgementError::Closed)
        );
    }
}
