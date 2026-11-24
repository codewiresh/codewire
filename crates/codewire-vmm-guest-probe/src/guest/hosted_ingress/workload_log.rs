//! The hosted workload's output, out to the host (#5602, cw-security's
//! conditions on comment 134050). Under Kata the hosted daemon's stdout and
//! stderr are its container's log; in a standard Pod's boot they reach the Pod
//! log this way instead.
//!
//! Guest init holds a pipe for the guest's life. Its write end is passed into
//! the workspace container, whose init gives it to the hosted workload alone
//! as stdout and stderr. Guest init reads the other end in whole lines and
//! writes them to [`HOSTED_LOG_VSOCK_PORT`] on the host, connecting out; the
//! host never writes back. Nothing here waits on the host: a line that finds
//! the buffer full is dropped, so a slow or absent reader never blocks the
//! workload.

use std::io::BufReader;
use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};
use std::sync::OnceLock;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::time::Duration;

use anyhow::{Context as _, Result};
use tokio::io::AsyncWriteExt as _;
use tokio_vsock::{VMADDR_CID_HOST, VsockAddr, VsockStream};

use crate::hosted_control::{HOSTED_LOG_MAX_LINE, HOSTED_LOG_VSOCK_PORT, hosted_guest};

/// Lines held while the host is not reading; more are dropped.
const BUFFERED_LINES: usize = 256;
/// How long to wait before connecting again after a failure.
const RECONNECT: Duration = Duration::from_millis(500);
/// How long to wait before reading again after a read error.
const READ_RETRY: Duration = Duration::from_millis(100);

/// The pipe's write end, which the workspace container receives.
static WRITER: OnceLock<OwnedFd> = OnceLock::new();

/// Makes the pipe and starts forwarding it, once, in a standard Pod's boot; a
/// local VM's boot makes neither.
pub(in crate::guest) fn hold(command_line: &str) -> Result<()> {
    if !hosted_guest(command_line) || WRITER.get().is_some() {
        return Ok(());
    }
    let (reader, writer) = pipe().context("make the log pipe")?;
    // Above every descriptor runc's child places (3 to 5), so placing the
    // others can never overwrite it.
    let writer = rustix::io::fcntl_dupfd_cloexec(&writer, 10).context("move the log pipe")?;
    let (lines, pending) = std::sync::mpsc::sync_channel(BUFFERED_LINES);
    std::thread::Builder::new()
        .name("codewire-hosted-log-read".to_owned())
        .spawn(move || read_lines(BufReader::new(std::fs::File::from(reader)), &lines))
        .context("spawn the hosted log reader")?;
    std::thread::Builder::new()
        .name("codewire-hosted-log-send".to_owned())
        .spawn(move || send_lines(pending))
        .context("spawn the hosted log sender")?;
    // Set once here; `hold` returned above if it was set.
    let _ = WRITER.set(writer);
    Ok(())
}

/// A close-on-exec pipe: its read end, then its write end.
fn pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut ends = [0; 2];
    // SAFETY: `ends` has room for the two descriptors pipe2 writes.
    if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: pipe2 succeeded, so both are open descriptors owned here alone.
    Ok(unsafe {
        (
            <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(ends[0]),
            <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(ends[1]),
        )
    })
}

/// The pipe's write end, which runc passes into the container as descriptor
/// 5, after the readiness channel and the daemon's listener.
pub(in crate::guest) fn writer_fd() -> Option<RawFd> {
    WRITER.get().map(|writer| writer.as_raw_fd())
}

/// Reads whole lines and queues them without ever waiting: a full queue
/// drops the line. This holds the pipe's only read end, and the workload's
/// stdout and stderr would fail with EPIPE once it closed, so it returns only
/// at the end of the input: with nothing left to send to, or after a read
/// error, it reads on and drops what it reads.
fn read_lines(mut reader: impl std::io::BufRead, lines: &SyncSender<Vec<u8>>) {
    let mut queue = Some(lines);
    loop {
        match read_line(&mut reader) {
            Ok(Some(line)) => {
                if let Some(sender) = queue
                    && let Err(TrySendError::Disconnected(_)) = sender.try_send(line)
                {
                    queue = None;
                }
            }
            Ok(None) => return,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => std::thread::sleep(READ_RETRY),
        }
    }
}

/// One line with its newline, at most one byte more than
/// [`HOSTED_LOG_MAX_LINE`] before it, so the host can tell a longer line and
/// mark it truncated; the rest is read and dropped. `None` at the end.
fn read_line(reader: &mut impl std::io::BufRead) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let mut seen = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if !seen {
                return Ok(None);
            }
            break;
        }
        seen = true;
        let (taken, ended) = match available.iter().position(|byte| *byte == b'\n') {
            Some(newline) => (newline + 1, true),
            None => (available.len(), false),
        };
        let room = (HOSTED_LOG_MAX_LINE + 1).saturating_sub(line.len());
        let kept = available[..taken]
            .iter()
            .take(room)
            .filter(|byte| **byte != b'\n');
        line.extend(kept);
        reader.consume(taken);
        if ended {
            break;
        }
    }
    line.push(b'\n');
    Ok(Some(line))
}

/// Connects to the host and writes each queued line, connecting again after
/// any failure. Only ever writes.
fn send_lines(pending: Receiver<Vec<u8>>) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        // Without a runtime nothing is sent; the reader drains the pipe and
        // drops every line.
        return;
    };
    runtime.block_on(async move {
        let mut host: Option<VsockStream> = None;
        while let Ok(line) = pending.recv() {
            if host.is_none() {
                host = VsockStream::connect(VsockAddr::new(VMADDR_CID_HOST, HOSTED_LOG_VSOCK_PORT))
                    .await
                    .ok();
            }
            let Some(stream) = host.as_mut() else {
                // The host is not listening yet: this line is dropped.
                tokio::time::sleep(RECONNECT).await;
                continue;
            };
            if stream.write_all(&line).await.is_err() {
                host = None;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines_of(input: &[u8]) -> Vec<Vec<u8>> {
        let mut reader = BufReader::with_capacity(16, input);
        std::iter::from_fn(|| read_line(&mut reader).unwrap()).collect()
    }

    #[test]
    fn lines_are_cut_whole_and_a_long_one_keeps_one_byte_over_its_limit() {
        let long = vec![b'a'; HOSTED_LOG_MAX_LINE + 100];
        let mut input = b"one\ntwo\n".to_vec();
        input.extend(&long);
        input.extend(b"\nlast");
        let lines = lines_of(&input);
        assert_eq!(lines[0], b"one\n");
        assert_eq!(lines[1], b"two\n");
        assert_eq!(lines[2].len(), HOSTED_LOG_MAX_LINE + 2);
        assert_eq!(lines[3], b"last\n");
        assert_eq!(lines.len(), 4);
    }

    #[test]
    fn a_full_queue_drops_lines_instead_of_waiting() {
        let (lines, pending) = std::sync::mpsc::sync_channel(2);
        let input = b"1\n2\n3\n4\n".to_vec();
        // Nothing receives until the reader has finished: it must not wait.
        read_lines(BufReader::new(&input[..]), &lines);
        drop(lines);
        assert_eq!(
            pending.iter().collect::<Vec<_>>(),
            [b"1\n".to_vec(), b"2\n".to_vec()]
        );
    }

    #[test]
    fn with_nothing_left_to_send_to_the_reader_still_drains_its_input() {
        let (lines, pending) = std::sync::mpsc::sync_channel(2);
        drop(pending);
        let input = b"1\n2\n3\n".to_vec();
        let mut reader = BufReader::new(&input[..]);
        read_lines(&mut reader, &lines);
        assert!(std::io::BufRead::fill_buf(&mut reader).unwrap().is_empty());
    }

    /// Fails its first read as interrupted, then reads its input.
    struct InterruptedOnce<'a>(bool, &'a [u8]);

    impl std::io::Read for InterruptedOnce<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if !self.0 {
                self.0 = true;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            self.1.read(buffer)
        }
    }

    #[test]
    fn an_interrupted_read_is_read_again() {
        let (lines, pending) = std::sync::mpsc::sync_channel(4);
        read_lines(BufReader::new(InterruptedOnce(false, b"1\n2\n")), &lines);
        drop(lines);
        assert_eq!(
            pending.iter().collect::<Vec<_>>(),
            [b"1\n".to_vec(), b"2\n".to_vec()]
        );
    }

    #[test]
    fn a_local_vms_boot_makes_no_pipe() {
        hold("console=ttyS0 rdinit=/init panic=-1").unwrap();
        assert_eq!(writer_fd(), None);
    }
}
