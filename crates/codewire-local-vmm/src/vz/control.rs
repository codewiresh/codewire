//! The runner's end of a schema 3 helper's control channel (#4654): one
//! `socketpair`, whose other end the helper inherits by number. Messages are
//! JSON lines of at most 4 KiB, as the helper's `ControlProtocol.swift`
//! defines them. A request names an operation and nothing else; replies and
//! the one event carry numbers and the machine identifier only.

use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};

use crate::runner::RunnerError;

/// The helper's `ControlRequest.maxLineBytes`.
const MAX_LINE_BYTES: u64 = 4096;
/// A machine identifier's data representation is a small property list; its
/// base64 is far below this.
const MAX_MACHINE_IDENTIFIER_CHARS: usize = 2048;
/// The helper sends `started` as its VM begins to run, well before the
/// guest's vsock endpoint is up, so this only bounds a missing event.
const STARTED_TIMEOUT: Duration = Duration::from_secs(10);

/// How the control channel failed, so a caller can tell a timeout from a
/// closed channel from a message the protocol does not allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VzControlFailure {
    Timeout,
    Closed,
    Protocol,
    Io,
    /// An earlier failure left the channel out of step: a late reply would
    /// answer the wrong request, so every later one is refused.
    Broken,
}

impl VzControlFailure {
    /// What failed, for the runner's error and its log.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "no answer in time",
            Self::Closed => "the helper closed it",
            Self::Protocol => "the helper sent a message the protocol does not allow",
            Self::Io => "the socket failed",
            Self::Broken => "it failed before and is out of step",
        }
    }
}

impl From<VzControlFailure> for RunnerError {
    fn from(failure: VzControlFailure) -> Self {
        RunnerError::VzControl(failure.as_str())
    }
}

/// Both ends of a new control channel. `UnixStream::pair` marks both
/// close-on-exec right after `socketpair`; every spawn in the runner runs the
/// close-on-exec sweep, so neither end reaches another child in between, and
/// the helper's spawn clears the flag on its own end only (cw-security,
/// condition 1).
pub(crate) struct ControlPair {
    runner: tokio::net::UnixStream,
    helper: UnixStream,
}

impl ControlPair {
    /// Must run within a tokio runtime: the runner's end is registered with
    /// it now, so handing the channel over after the spawn cannot fail.
    pub(crate) fn new() -> Result<Self, RunnerError> {
        let (runner, helper) = UnixStream::pair().map_err(|_| VzControlFailure::Io)?;
        runner
            .set_nonblocking(true)
            .map_err(|_| VzControlFailure::Io)?;
        let runner = tokio::net::UnixStream::from_std(runner).map_err(|_| VzControlFailure::Io)?;
        Ok(Self { runner, helper })
    }

    /// The end the helper inherits.
    pub(crate) fn helper(&self) -> BorrowedFd<'_> {
        self.helper.as_fd()
    }

    /// The runner's end, for tests that check where it is held.
    #[cfg(test)]
    pub(crate) fn runner_for_test(&self) -> BorrowedFd<'_> {
        self.runner.as_fd()
    }

    /// Close this process's copy of the helper's end, now that the helper has
    /// inherited it, and keep the runner's.
    pub(crate) fn into_control(self) -> VzControl {
        drop(self.helper);
        VzControl {
            stream: BufReader::new(self.runner),
            next_id: 1,
            broken: false,
        }
    }
}

/// The runner's end, held for the VM's life. Dropping it closes the channel,
/// and the helper stops its VM (cw-security, condition 4). Any failure
/// breaks it for good: a read cut short by a timeout is not resumable, and a
/// late reply carries an old id.
pub(crate) struct VzControl {
    stream: BufReader<tokio::net::UnixStream>,
    broken: bool,
    next_id: u64,
}

impl std::fmt::Debug for VzControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("VzControl").finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// The requests a capture sends. The helper also takes `stop`, but the runner
/// stops a VM by closing the channel (cw-security, condition 4).
pub(crate) enum VzOperation {
    Pause,
    Save,
    Resume,
}

impl VzOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pause => "pause",
            Self::Save => "save",
            Self::Resume => "resume",
        }
    }
}

/// The helper's answer to one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VzReply {
    Done {
        milliseconds: u64,
    },
    /// Virtualization.framework refused it: its `VZError.Code`, or 0.
    Failed {
        code: i64,
    },
    /// Not allowed in the VM's present state.
    Refused,
}

/// Every field any message may carry; each message uses a fixed subset.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    id: Option<u64>,
    result: Option<String>,
    ms: Option<u64>,
    code: Option<i64>,
    event: Option<String>,
    #[serde(rename = "machineIdentifier")]
    machine_identifier: Option<String>,
}

impl VzControl {
    /// The machine identifier the helper reports once its VM runs.
    pub(crate) async fn started(&mut self) -> Result<String, VzControlFailure> {
        self.unless_broken()?;
        let result = match tokio::time::timeout(STARTED_TIMEOUT, self.read_message()).await {
            Err(_) => Err(VzControlFailure::Timeout),
            Ok(Err(failure)) => Err(failure),
            Ok(Ok(Message {
                event: Some(event),
                machine_identifier: Some(identifier),
                id: None,
                result: None,
                ms: None,
                code: None,
            })) if event == "started" && is_machine_identifier(&identifier) => Ok(identifier),
            Ok(Ok(_)) => Err(VzControlFailure::Protocol),
        };
        self.breaking(result)
    }

    /// Refuse every later request: the helper broke the protocol in a way
    /// this end found outside a read, such as reporting another machine
    /// identifier than the one it was given.
    pub(crate) fn mark_broken(&mut self) {
        self.broken = true;
    }

    fn unless_broken(&self) -> Result<(), VzControlFailure> {
        if self.broken {
            Err(VzControlFailure::Broken)
        } else {
            Ok(())
        }
    }

    fn breaking<T>(&mut self, result: Result<T, VzControlFailure>) -> Result<T, VzControlFailure> {
        if result.is_err() {
            self.broken = true;
        }
        result
    }

    /// Send one request and wait, at most `timeout`, for its reply.
    pub(crate) async fn request(
        &mut self,
        operation: VzOperation,
        timeout: Duration,
    ) -> Result<VzReply, VzControlFailure> {
        self.unless_broken()?;
        let id = self.next_id;
        self.next_id += 1;
        let line = format!("{{\"id\":{id},\"op\":\"{}\"}}\n", operation.as_str());
        let exchange = async {
            self.stream
                .get_mut()
                .write_all(line.as_bytes())
                .await
                .map_err(|_| VzControlFailure::Io)?;
            let reply = self.read_message().await?;
            if reply.id != Some(id) || reply.event.is_some() || reply.machine_identifier.is_some() {
                return Err(VzControlFailure::Protocol);
            }
            match (reply.result.as_deref(), reply.ms, reply.code) {
                (Some("done"), Some(milliseconds), None) => Ok(VzReply::Done { milliseconds }),
                (Some("failed"), None, Some(code)) => Ok(VzReply::Failed { code }),
                (Some("refused"), None, None) => Ok(VzReply::Refused),
                _ => Err(VzControlFailure::Protocol),
            }
        };
        let result = tokio::time::timeout(timeout, exchange)
            .await
            .unwrap_or(Err(VzControlFailure::Timeout));
        self.breaking(result)
    }

    /// Resume the VM, whatever state the channel is in: a request that went
    /// unanswered or failed may have left it paused. On a working channel
    /// this is an ordinary request, true when the helper resumed it. On a
    /// broken one the request is written and its reply never read, the one
    /// write a broken channel still makes, so the VM resumes if the helper
    /// can; the answer is unknown, so false.
    pub(crate) async fn resume(&mut self, timeout: Duration) -> bool {
        if !self.broken {
            return matches!(
                self.request(VzOperation::Resume, timeout).await,
                Ok(VzReply::Done { .. })
            );
        }
        let id = self.next_id;
        self.next_id += 1;
        let line = format!(
            "{{\"id\":{id},\"op\":\"{}\"}}\n",
            VzOperation::Resume.as_str()
        );
        // Best effort: the channel is already broken, and the answer would be
        // unknown either way.
        let _ =
            tokio::time::timeout(timeout, self.stream.get_mut().write_all(line.as_bytes())).await;
        false
    }

    /// One line, at most `MAX_LINE_BYTES` before its newline. EOF, an
    /// over-long line or one that is not a message fails.
    async fn read_message(&mut self) -> Result<Message, VzControlFailure> {
        let mut line = Vec::new();
        let read = (&mut self.stream)
            .take(MAX_LINE_BYTES + 1)
            .read_until(b'\n', &mut line)
            .await
            .map_err(|_| VzControlFailure::Io)?;
        if read == 0 {
            return Err(VzControlFailure::Closed);
        }
        if line.pop() != Some(b'\n') {
            return Err(VzControlFailure::Protocol);
        }
        serde_json::from_slice(&line).map_err(|_| VzControlFailure::Protocol)
    }
}

/// Base64 of a data representation: what the helper's `started` event and
/// `vz.json`'s `machineIdentifier` carry, and what the runner keeps.
pub(crate) fn is_machine_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_MACHINE_IDENTIFIER_CHARS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake helper end: what it writes, the runner reads.
    fn channel() -> (VzControl, tokio::net::UnixStream) {
        let pair = ControlPair::new().unwrap();
        let helper = pair.helper.try_clone().unwrap();
        helper.set_nonblocking(true).unwrap();
        let control = pair.into_control();
        (control, tokio::net::UnixStream::from_std(helper).unwrap())
    }

    #[tokio::test]
    async fn the_started_event_carries_the_machine_identifier() {
        let (mut control, mut helper) = channel();
        helper
            .write_all(b"{\"event\":\"started\",\"machineIdentifier\":\"YnBsaXN0MDA=\"}\n")
            .await
            .unwrap();
        assert_eq!(control.started().await.unwrap(), "YnBsaXN0MDA=");
    }

    #[tokio::test]
    async fn anything_else_first_is_refused() {
        for line in [
            &b"{\"id\":1,\"result\":\"done\",\"ms\":3}\n"[..],
            b"{\"event\":\"started\",\"machineIdentifier\":\"not base64!\"}\n",
            b"{\"event\":\"started\",\"machineIdentifier\":\"YQ==\",\"path\":\"/x\"}\n",
            b"{\"event\":\"stopped\",\"machineIdentifier\":\"YQ==\"}\n",
            b"not json\n",
        ] {
            let (mut control, mut helper) = channel();
            helper.write_all(line).await.unwrap();
            assert!(
                control.started().await.is_err(),
                "{}",
                String::from_utf8_lossy(line)
            );
        }
    }

    #[tokio::test]
    async fn eof_and_an_over_long_line_are_failures() {
        let (mut control, helper) = channel();
        drop(helper);
        assert_eq!(control.started().await, Err(VzControlFailure::Closed));

        let (mut control, mut helper) = channel();
        let mut long = vec![b'a'; MAX_LINE_BYTES as usize + 1];
        long.push(b'\n');
        helper.write_all(&long).await.unwrap();
        assert_eq!(control.started().await, Err(VzControlFailure::Protocol));
    }

    /// A broken channel still sends a resume, so a VM an unanswered pause
    /// may have paused does not stay paused; its reply is never read.
    #[tokio::test(start_paused = true)]
    async fn a_broken_channel_still_sends_a_resume() {
        let (mut control, helper) = channel();
        let (read, _write) = helper.into_split();
        let mut read = tokio::io::BufReader::new(read);
        assert_eq!(
            control
                .request(VzOperation::Pause, Duration::from_secs(1))
                .await,
            Err(VzControlFailure::Timeout)
        );
        assert!(!control.resume(Duration::from_secs(1)).await);
        let mut pause = String::new();
        read.read_line(&mut pause).await.unwrap();
        let mut resume = String::new();
        read.read_line(&mut resume).await.unwrap();
        assert_eq!(pause, "{\"id\":1,\"op\":\"pause\"}\n");
        assert_eq!(resume, "{\"id\":2,\"op\":\"resume\"}\n");
    }

    /// A timed-out wait cannot be resumed, so a late reply never answers a
    /// later request: the channel refuses everything after any failure.
    #[tokio::test(start_paused = true)]
    async fn a_timeout_breaks_the_channel_for_good() {
        let (mut control, mut helper) = channel();
        assert_eq!(control.started().await, Err(VzControlFailure::Timeout));
        helper
            .write_all(b"{\"event\":\"started\",\"machineIdentifier\":\"YQ==\"}\n")
            .await
            .unwrap();
        assert_eq!(control.started().await, Err(VzControlFailure::Broken));
        assert_eq!(
            control
                .request(VzOperation::Pause, Duration::from_secs(3600))
                .await,
            Err(VzControlFailure::Broken)
        );
    }

    #[tokio::test]
    async fn a_request_is_exactly_an_id_and_an_operation_and_its_reply_matches() {
        let (mut control, helper) = channel();
        let (read, mut write) = helper.into_split();
        let mut read = tokio::io::BufReader::new(read);
        let fake = tokio::spawn(async move {
            let mut requests = Vec::new();
            for reply in [
                "{\"id\":1,\"result\":\"done\",\"ms\":5}\n",
                "{\"id\":2,\"result\":\"failed\",\"code\":11}\n",
                "{\"id\":3,\"result\":\"refused\"}\n",
                "{\"id\":9,\"result\":\"done\",\"ms\":1}\n",
            ] {
                let mut line = String::new();
                read.read_line(&mut line).await.unwrap();
                requests.push(line);
                write.write_all(reply.as_bytes()).await.unwrap();
            }
            requests
        });
        // A bound no run reaches: the result never depends on the machine's
        // speed.
        let timeout = Duration::from_secs(3600);
        assert_eq!(
            control.request(VzOperation::Pause, timeout).await.unwrap(),
            VzReply::Done { milliseconds: 5 }
        );
        assert_eq!(
            control.request(VzOperation::Save, timeout).await.unwrap(),
            VzReply::Failed { code: 11 }
        );
        assert_eq!(
            control.request(VzOperation::Resume, timeout).await.unwrap(),
            VzReply::Refused
        );
        // A reply to another request is a protocol failure, and the channel
        // refuses everything after it.
        assert_eq!(
            control.request(VzOperation::Pause, timeout).await,
            Err(VzControlFailure::Protocol)
        );
        assert_eq!(
            control.request(VzOperation::Pause, timeout).await,
            Err(VzControlFailure::Broken)
        );
        assert_eq!(
            fake.await.unwrap(),
            [
                "{\"id\":1,\"op\":\"pause\"}\n",
                "{\"id\":2,\"op\":\"save\"}\n",
                "{\"id\":3,\"op\":\"resume\"}\n",
                "{\"id\":4,\"op\":\"pause\"}\n",
            ]
        );
    }
}
