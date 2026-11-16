//! The descriptors the runner passes to the network worker while it starts
//! (#4916).
//!
//! A sender keeps its own copy of a socket it passes until the receiver has
//! answered for it. On macOS, a Unix socket whose only reference is a
//! descriptor in flight can arrive dead under load once its sender has closed
//! its last copy. The worker answers each pass with a status frame, so the
//! runner's copies stay open until that frame, bounded by the start's
//! deadline.

use std::io;
use std::os::fd::{AsRawFd, RawFd};

use super::{
    NetworkWorkerStartup, RunnerError, classify_network_worker_startup_error,
    read_worker_status_frame, reap_failed_network_worker_startup, transfer_worker_descriptor,
};

/// Which half of a pass failed. The runner reaps the worker after a failed
/// transfer, and reads the worker's own exit after a failed answer.
#[derive(Debug)]
enum PassError {
    Transfer(RunnerError),
    Answer(RunnerError),
}

/// Pass each of `descriptors` to the worker, in order, and return the status
/// frame that answers them. A failure ends the worker's startup.
pub(super) async fn pass_to_worker<D: AsRawFd>(
    startup: &mut NetworkWorkerStartup,
    bootstrap: &mut tokio::net::UnixStream,
    descriptors: Vec<D>,
    deadline: tokio::time::Instant,
    transfer: fn(RawFd, RawFd) -> io::Result<()>,
) -> Result<Vec<u8>, RunnerError> {
    match pass_until_answered(bootstrap, descriptors, deadline, transfer).await {
        Ok(status) => Ok(status),
        Err(PassError::Transfer(error)) => {
            reap_failed_network_worker_startup(startup).await?;
            Err(error)
        }
        Err(PassError::Answer(error)) => {
            Err(classify_network_worker_startup_error(startup, error).await?)
        }
    }
}

async fn pass_until_answered<D: AsRawFd>(
    bootstrap: &mut tokio::net::UnixStream,
    descriptors: Vec<D>,
    deadline: tokio::time::Instant,
    transfer: fn(RawFd, RawFd) -> io::Result<()>,
) -> Result<Vec<u8>, PassError> {
    for descriptor in &descriptors {
        transfer_worker_descriptor(bootstrap, descriptor.as_raw_fd(), deadline, transfer)
            .await
            .map_err(PassError::Transfer)?;
    }
    let status = read_worker_status_frame(bootstrap, deadline)
        .await
        .map_err(PassError::Answer);
    // Only now: the worker has answered for them, or the deadline has passed.
    drop(descriptors);
    status
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;
    use crate::network_worker::{receive_mesh_ingress_descriptor, send_mesh_ingress_descriptor};

    /// Generous, so a loaded host fails only a missing event.
    const WAIT: Duration = Duration::from_secs(30);

    /// The worker here closes the socket it receives at once, so the peer of
    /// that socket sees the end of its stream exactly when the runner lets go
    /// of its own copy: not before the worker's answer, and right after it.
    #[tokio::test]
    async fn the_runners_copy_of_a_passed_socket_stays_open_until_the_worker_answers() {
        let (mut runner, mut worker) = tokio::net::UnixStream::pair().unwrap();
        let (passed, mut peer) = tokio::net::UnixStream::pair().unwrap();
        let deadline = tokio::time::Instant::now() + WAIT;
        let pass = tokio::spawn(async move {
            pass_until_answered(
                &mut runner,
                vec![passed],
                deadline,
                send_mesh_ingress_descriptor,
            )
            .await
        });

        drop(receive_mesh_ingress_descriptor(&worker).await.unwrap());
        let mut byte = [0_u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), peer.read(&mut byte))
                .await
                .is_err(),
            "the runner still holds its copy"
        );

        worker.write_all(b"answered\n").await.unwrap();
        assert_eq!(pass.await.unwrap().unwrap(), b"answered\n");
        assert_eq!(
            tokio::time::timeout(WAIT, peer.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0,
            "the runner let go once the worker answered"
        );
    }
}
