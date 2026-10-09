//! Closed private stdin frames. No path, command, environment or token field.
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::time::Instant;

use codewire_cw_release::identity::{
    CwPayloadIdentity, MAX_IDENTITY_BYTES, canonical_json, is_sha256_hex,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::Result;

pub(super) const MAX_JSON: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Code {
    InvalidFrame,
    UnsupportedImage,
    UnsafeState,
    ReadOnly,
    UnmanagedEntry,
    StaleSelection,
    PendingSelection,
    CandidateRefused,
    StageExists,
    MissingStage,
    InputIncomplete,
    Deadline,
    Io,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectionExpectation {
    pub generation: u64,
    pub current: Option<String>,
    pub previous: Option<String>,
}

impl SelectionExpectation {
    fn validate(&self) -> Result<()> {
        if (self.generation == 0) != self.current.is_none()
            || self
                .previous
                .as_ref()
                .is_some_and(|v| !is_sha256_hex(v) || self.current.as_ref() == Some(v))
            || self.current.as_ref().is_some_and(|v| !is_sha256_hex(v))
            || (self.generation == 0 && self.previous.is_some())
        {
            Err(Code::InvalidFrame)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Correlation {
    pub request_id: Uuid,
    pub pod_uid: Uuid,
    pub binding_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub schema_version: u32,
    pub request_id: Uuid,
    pub pod_uid: Uuid,
    pub binding_sha256: String,
    pub action: Action,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Action {
    Status,
    Bootstrap {
        identity: CwPayloadIdentity,
        expected: SelectionExpectation,
    },
    Stage {
        identity: CwPayloadIdentity,
        expected: SelectionExpectation,
    },
    Update {
        identity: CwPayloadIdentity,
        expected: SelectionExpectation,
    },
    Rollback {
        identity: CwPayloadIdentity,
        expected: SelectionExpectation,
    },
    Cleanup {
        bootstrap: Option<CwPayloadIdentity>,
        candidate: Option<CwPayloadIdentity>,
    },
}

impl Request {
    pub(super) fn correlation(&self) -> Correlation {
        Correlation {
            request_id: self.request_id,
            pod_uid: self.pod_uid,
            binding_sha256: self.binding_sha256.clone(),
        }
    }

    pub(super) fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.request_id.is_nil()
            || self.pod_uid.is_nil()
            || !is_sha256_hex(&self.binding_sha256)
        {
            return Err(Code::InvalidFrame);
        }
        match &self.action {
            Action::Status => {}
            Action::Bootstrap {
                identity: payload,
                expected,
            } => {
                identity(payload)?;
                expected.validate()?;
                if expected.generation != 0 {
                    return Err(Code::InvalidFrame);
                }
            }
            Action::Stage {
                identity: payload,
                expected,
            }
            | Action::Update {
                identity: payload,
                expected,
            }
            | Action::Rollback {
                identity: payload,
                expected,
            } => {
                identity(payload)?;
                expected.validate()?;
                if expected.generation == 0
                    || (expected.generation == u64::MAX
                        && expected.current.as_ref() != Some(&payload.sha256))
                {
                    return Err(Code::InvalidFrame);
                }
            }
            Action::Cleanup {
                bootstrap,
                candidate,
            } => {
                for payload in [bootstrap, candidate].into_iter().flatten() {
                    identity(payload)?
                }
            }
        }
        if canonical_json(self).map_err(|_| Code::InvalidFrame)?.len() > MAX_JSON {
            return Err(Code::InvalidFrame);
        }
        Ok(())
    }
}

pub(super) fn identity(identity: &CwPayloadIdentity) -> Result<()> {
    if identity.target != "x86_64-unknown-linux-musl"
        || identity.validate().is_err()
        || canonical_json(identity)
            .map_err(|_| Code::CandidateRefused)?
            .len()
            > MAX_IDENTITY_BYTES
    {
        Err(Code::CandidateRefused)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObservedSelection {
    pub generation: u64,
    pub current: Option<CwPayloadIdentity>,
    pub previous: Option<CwPayloadIdentity>,
    pub pending: bool,
    pub consistent: bool,
    pub retained_count: usize,
}

impl ObservedSelection {
    pub(super) fn absent() -> Self {
        Self {
            generation: 0,
            current: None,
            previous: None,
            pending: false,
            consistent: true,
            retained_count: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ReplyBody {
    Status {
        supported_image: bool,
        bootstrap: Option<CwPayloadIdentity>,
        selection: Box<ObservedSelection>,
    },
    Staged {
        sha256: String,
        size: u64,
    },
    Selected {
        sha256: String,
        generation: u64,
        previous_sha256: Option<String>,
        changed: bool,
    },
    Cleaned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Outcome {
    Succeeded { result: ReplyBody },
    Refused { code: Code },
    Unknown { code: Code },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reply {
    schema_version: u32,
    correlation: Correlation,
    outcome: Outcome,
}

impl Reply {
    pub(super) fn new(correlation: Correlation, outcome: Outcome) -> Self {
        Self {
            schema_version: 1,
            correlation,
            outcome,
        }
    }
    pub(super) fn exit_code(&self) -> i32 {
        match self.outcome {
            Outcome::Succeeded { .. } => 0,
            Outcome::Refused { .. } => 3,
            Outcome::Unknown { .. } => 4,
        }
    }
}

pub(super) fn read_request(reader: &mut impl Read) -> Result<Request> {
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .map_err(|_| Code::InputIncomplete)?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_JSON {
        return Err(Code::InvalidFrame);
    }
    let mut data = vec![0_u8; length];
    reader
        .read_exact(&mut data)
        .map_err(|_| Code::InputIncomplete)?;
    let request: Request = serde_json::from_slice(&data).map_err(|_| Code::InvalidFrame)?;
    request.validate()?;
    if canonical_json(&request).map_err(|_| Code::InvalidFrame)? != data {
        return Err(Code::InvalidFrame);
    }
    Ok(request)
}

pub(super) fn require_eof(reader: &mut impl Read) -> Result<()> {
    let mut byte = [0];
    match reader.read(&mut byte) {
        Ok(0) => Ok(()),
        _ => Err(Code::InvalidFrame),
    }
}

pub(super) fn write_reply(writer: &mut impl Write, reply: &Reply) -> Result<()> {
    let data = canonical_json(reply).map_err(|_| Code::Io)?;
    if data.len() > MAX_JSON {
        return Err(Code::UnsafeState);
    }
    writer
        .write_all(&(data.len() as u32).to_le_bytes())
        .map_err(|_| Code::Io)?;
    writer.write_all(&data).map_err(|_| Code::Io)?;
    writer.flush().map_err(|_| Code::Io)
}

struct BoundedFd {
    file: File,
    deadline: Instant,
    original_flags: i32,
}

impl BoundedFd {
    fn duplicate(fd: i32, deadline: Instant) -> Result<Self> {
        // SAFETY: duplicate a live standard IO FD without taking its ownership.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(Code::Io);
        }
        // SAFETY: fcntl returned a new owned FD above.
        let file = unsafe { File::from_raw_fd(duplicate) };
        // The private single-threaded child owns these IO open descriptions.
        // SAFETY: only fixed fcntl arguments and this held FD are used.
        let original_flags = unsafe { libc::fcntl(duplicate, libc::F_GETFL) };
        if original_flags < 0
            || unsafe { libc::fcntl(duplicate, libc::F_SETFL, original_flags | libc::O_NONBLOCK) }
                < 0
        {
            return Err(Code::Io);
        }
        Ok(Self {
            file,
            deadline,
            original_flags,
        })
    }

    fn ready(&self, event: i16) -> std::io::Result<()> {
        loop {
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "runtime IO deadline")
                })?;
            let millis = remaining.as_millis().min(i32::MAX as u128).max(1) as i32;
            let mut p = libc::pollfd {
                fd: self.file.as_raw_fd(),
                events: event,
                revents: 0,
            };
            // SAFETY: p is one initialized pollfd, valid for this synchronous call.
            let result = unsafe { libc::poll(&raw mut p, 1, millis) };
            if result > 0 {
                return Ok(());
            }
            if result == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "runtime IO deadline",
                ));
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

impl Drop for BoundedFd {
    fn drop(&mut self) {
        // SAFETY: this held duplicated FD remains live until its field drops.
        unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_SETFL, self.original_flags) };
    }
}

pub(super) struct BoundedInput(BoundedFd);
impl BoundedInput {
    pub(super) fn stdin(deadline: Instant) -> Result<Self> {
        BoundedFd::duplicate(0, deadline).map(Self)
    }
    #[cfg(test)]
    pub(super) fn fixture(fd: i32, deadline: Instant) -> Result<Self> {
        BoundedFd::duplicate(fd, deadline).map(Self)
    }
}
impl Read for BoundedInput {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            self.0.ready(libc::POLLIN)?;
            match self.0.file.read(buffer) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                other => return other,
            }
        }
    }
}
pub(super) struct BoundedOutput(BoundedFd);
impl BoundedOutput {
    pub(super) fn stdout(deadline: Instant) -> Result<Self> {
        BoundedFd::duplicate(1, deadline).map(Self)
    }
}
impl Write for BoundedOutput {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            self.0.ready(libc::POLLOUT)?;
            match self.0.file.write(buffer) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                other => return other,
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.file.flush()
    }
}
