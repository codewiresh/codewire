//! Private one-launch framing, shared by native and runc final launchers.
//! The daemon authenticates the outer helper before handing this channel to
//! the actual launcher. Only that launcher generates the recipient key.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustix::event::{PollFd, PollFlags, Timespec, poll};

use crate::{
    EnvironmentProjection, MAX_PROJECTION_LIFETIME_MS, MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES,
    ProjectionContext, ProjectionRecipient,
};

pub const LAUNCH_CONTEXT_BYTES: usize = 72;
pub const MAX_LAUNCH_CIPHERTEXT_BYTES: usize = MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES;
pub const LAUNCH_READY: u8 = 1;
pub const LAUNCH_COMMIT: u8 = 2;
pub const LAUNCH_EXEC_PENDING: u8 = 3;
pub const LAUNCH_EXEC_FAILED: u8 = 4;
/// Conservative whole-exec bound, additionally capped by the current ARG_MAX.
pub const MAX_LAUNCH_EXEC_BYTES: usize = 1024 * 1024;
// Current private framing only: context, names-only overrides, recipient,
// sealed projection, Ready, Commit. Retired framing is not inferred or retried.
const MAGIC: &[u8; 8] = b"CWLAUN02";

/// Encode explicit command/terminal override NAMES, never their values. The
/// authenticated launch owner supplies this transient merge provenance; it is
/// not a protected-source selector and does not alter projection authority.
pub fn encode_override_names(names: &BTreeSet<String>) -> io::Result<Vec<u8>> {
    let mut length = 0_usize;
    for name in names {
        validate_override_name(name.as_bytes())?;
        length = length
            .checked_add(name.len())
            .and_then(|length| length.checked_add(1))
            .filter(|length| *length <= MAX_LAUNCH_EXEC_BYTES)
            .ok_or_else(invalid_launch)?;
    }
    let mut encoded = Vec::with_capacity(length + 4);
    encoded.extend_from_slice(&(length as u32).to_be_bytes());
    for name in names {
        encoded.extend_from_slice(name.as_bytes());
        encoded.push(0);
    }
    Ok(encoded)
}

fn validate_override_name(name: &[u8]) -> io::Result<()> {
    if name.is_empty() || name.contains(&0) || name.contains(&b'=') {
        return Err(invalid_launch());
    }
    Ok(())
}

fn decode_override_names(encoded: &[u8]) -> io::Result<BTreeSet<OsString>> {
    if encoded.len() > MAX_LAUNCH_EXEC_BYTES || (!encoded.is_empty() && encoded.last() != Some(&0))
    {
        return Err(invalid_launch());
    }
    let mut names = BTreeSet::new();
    if encoded.is_empty() {
        return Ok(names);
    }
    for name in encoded[..encoded.len() - 1].split(|byte| *byte == 0) {
        validate_override_name(name)?;
        let name = OsString::from(std::str::from_utf8(name).map_err(|_| invalid_launch())?);
        if names.last().is_some_and(|previous| previous >= &name) {
            return Err(invalid_launch());
        }
        names.insert(name);
    }
    Ok(names)
}

fn read_override_names(channel: &mut Channel) -> io::Result<BTreeSet<OsString>> {
    let mut length = [0; 4];
    channel.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_LAUNCH_EXEC_BYTES {
        return Err(invalid_launch());
    }
    let mut encoded = vec![0; length];
    channel.read_exact(&mut encoded)?;
    decode_override_names(&encoded)
}

pub fn now_unix_ms() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or_else(invalid_launch)
}

pub fn encode_context(context: &ProjectionContext) -> io::Result<[u8; LAUNCH_CONTEXT_BYTES]> {
    context
        .validate_at(now_unix_ms()?)
        .map_err(|_| invalid_launch())?;
    let mut bytes = [0; LAUNCH_CONTEXT_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..24].copy_from_slice(&context.environment_id);
    bytes[24..32].copy_from_slice(&context.operation_generation.to_be_bytes());
    bytes[32..64].copy_from_slice(&context.selection_sha256);
    bytes[64..72].copy_from_slice(&context.deadline_unix_ms.to_be_bytes());
    Ok(bytes)
}

fn decode_context(bytes: &[u8; LAUNCH_CONTEXT_BYTES]) -> io::Result<ProjectionContext> {
    if &bytes[..8] != MAGIC {
        return Err(invalid_launch());
    }
    let context = ProjectionContext {
        environment_id: bytes[8..24].try_into().map_err(|_| invalid_launch())?,
        operation_generation: u64::from_be_bytes(
            bytes[24..32].try_into().map_err(|_| invalid_launch())?,
        ),
        selection_sha256: bytes[32..64].try_into().map_err(|_| invalid_launch())?,
        deadline_unix_ms: u64::from_be_bytes(
            bytes[64..72].try_into().map_err(|_| invalid_launch())?,
        ),
    };
    context
        .validate_at(now_unix_ms()?)
        .map_err(|_| invalid_launch())?;
    Ok(context)
}

/// Connect only to the launching parent, in its owner-private directory.
/// The server independently authenticates this process's exact PID and UID.
#[cfg(target_os = "linux")]
pub fn connect_to_parent(path: &Path) -> io::Result<UnixStream> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let parent = path.parent().ok_or_else(invalid_launch)?;
    let directory = std::fs::symlink_metadata(parent)?;
    let socket = std::fs::symlink_metadata(path)?;
    let uid = rustix::process::geteuid();
    if !path.is_absolute()
        || !directory.is_dir()
        || directory.uid() != uid.as_raw()
        || directory.mode() & 0o777 != 0o700
        || !socket.file_type().is_socket()
        || socket.uid() != uid.as_raw()
        || socket.mode() & 0o777 != 0o600
    {
        return Err(invalid_launch());
    }
    // A full local backlog must not turn helper startup into an unbounded
    // blocking connect. For this pre-bound, one-client rendezvous, any pending
    // or full-queue result is a closed launch, not an ambient retry route.
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
    let address = SocketAddrUnix::new(path).map_err(|_| invalid_launch())?;
    let descriptor = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| invalid_launch())?;
    rustix::net::connect(&descriptor, &address).map_err(|_| invalid_launch())?;
    let stream = UnixStream::from(descriptor);
    let peer = rustix::net::sockopt::socket_peercred(&stream).map_err(|_| invalid_launch())?;
    if Some(peer.pid) != rustix::process::getppid()
        || peer.pid.as_raw_nonzero().get() <= 1
        || peer.uid != uid
    {
        return Err(invalid_launch());
    }
    Ok(stream)
}

/// Entry point for the hidden native helper. It must be dispatched before
/// configuration, login, runtime creation or logging in the ordinary CLI.
#[cfg(target_os = "linux")]
pub fn run_environment_launcher(path: &Path, command: &[OsString]) -> io::Result<()> {
    let parent = rustix::process::getppid()
        .filter(|pid| pid.as_raw_nonzero().get() > 1)
        .ok_or_else(invalid_launch)?;
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
        .map_err(|_| invalid_launch())?;
    if rustix::process::getppid() != Some(parent) {
        return Err(invalid_launch());
    }
    exec_from_channel(connect_to_parent(path)?, command)
}

/// Called only by the final launcher. This consumes and closes the private
/// channel before exec; no projection is returned to a supervisor or daemon.
pub fn exec_from_channel(stream: UnixStream, command: &[OsString]) -> io::Result<()> {
    exec_from_channel_inner(stream, command, None)
}

/// Bootstrap-only value-blind exec-status channel. The trusted helper marks
/// this descriptor close-on-exec: admission followed by EOF is the normal
/// successful exec transition; any returned failure emits a fixed byte.
pub fn exec_from_channel_with_status(
    stream: UnixStream,
    command: &[OsString],
    mut status: UnixStream,
) -> io::Result<()> {
    rustix::io::fcntl_setfd(&status, rustix::io::FdFlags::CLOEXEC)?;
    let result = exec_from_channel_inner(stream, command, Some(&mut status));
    let _ = status.write_all(&[LAUNCH_EXEC_FAILED]);
    result
}

fn exec_from_channel_inner(
    stream: UnixStream,
    command: &[OsString],
    status: Option<&mut UnixStream>,
) -> io::Result<()> {
    let mut channel = Channel::new(stream)?;
    let mut encoded = [0; LAUNCH_CONTEXT_BYTES];
    channel.read_exact(&mut encoded)?;
    let context = decode_context(&encoded)?;
    channel.deadline = channel.deadline.min(
        Instant::now()
            + Duration::from_millis(
                context
                    .deadline_unix_ms
                    .checked_sub(now_unix_ms()?)
                    .ok_or_else(invalid_launch)?,
            ),
    );
    let overrides = read_override_names(&mut channel)?;
    let base: BTreeMap<_, _> = std::env::vars_os().collect();
    // A provenance name must refer to an already supplied command value,
    // including an explicitly empty value. Never silently invent a value.
    if overrides.iter().any(|name| !base.contains_key(name)) {
        return Err(invalid_launch());
    }
    let recipient = ProjectionRecipient::new();
    channel.write_all(&recipient.public_key())?;
    let mut length = [0; 4];
    channel.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_LAUNCH_CIPHERTEXT_BYTES {
        return Err(invalid_launch());
    }
    let mut ciphertext = vec![0; length];
    channel.read_exact(&mut ciphertext)?;
    let projection = recipient
        .open(&ciphertext, &context, now_unix_ms()?)
        .map_err(|_| invalid_launch())?;
    let environment = merged_environment(base, &projection, &overrides);
    validate_exec_size(command, &environment)?;
    channel.write_all(&[LAUNCH_READY])?;
    let mut commit = [0];
    channel.read_exact(&mut commit)?;
    if commit != [LAUNCH_COMMIT] {
        return Err(invalid_launch());
    }
    context
        .validate_at(now_unix_ms()?)
        .map_err(|_| invalid_launch())?;
    drop(channel);
    if let Some(status) = status {
        status.write_all(&[LAUNCH_EXEC_PENDING])?;
    }
    // Only this short-lived launcher owns the plaintext merged environment.
    // On success exec replaces it; errors are fixed and never format values.
    let _error = std::process::Command::new(&command[0])
        .args(&command[1..])
        .env_clear()
        .envs(&environment)
        .exec();
    Err(invalid_launch())
}

fn merged_environment(
    base: impl IntoIterator<Item = (OsString, OsString)>,
    projection: &EnvironmentProjection,
    overrides: &BTreeSet<OsString>,
) -> BTreeMap<OsString, OsString> {
    let mut environment: BTreeMap<_, _> = base.into_iter().collect();
    for (key, value) in projection.entries() {
        if !overrides.contains(&OsString::from(key)) {
            environment.insert(OsString::from(key), OsString::from(value));
        }
    }
    environment
}

fn validate_exec_size(
    command: &[OsString],
    environment: &BTreeMap<OsString, OsString>,
) -> io::Result<()> {
    if command.is_empty() || command[0].is_empty() {
        return Err(invalid_launch());
    }
    let pointer_bytes = (command
        .len()
        .checked_add(environment.len())
        .and_then(|n| n.checked_add(2))
        .and_then(|n| n.checked_mul(std::mem::size_of::<usize>())))
    .ok_or_else(invalid_launch)?;
    let mut size = pointer_bytes;
    let page = rustix::param::page_size();
    let string_limit = page
        .checked_mul(32)
        .filter(|size| *size > 0)
        .ok_or_else(invalid_launch)?;
    for argument in command {
        let bytes = argument.as_bytes();
        if bytes.contains(&0) || bytes.len() + 1 > string_limit {
            return Err(invalid_launch());
        }
        size = size
            .checked_add(bytes.len() + 1)
            .ok_or_else(invalid_launch)?;
    }
    for (key, value) in environment {
        let key = key.as_bytes();
        let value = value.as_bytes();
        let length = key
            .len()
            .checked_add(value.len())
            .and_then(|n| n.checked_add(2))
            .ok_or_else(invalid_launch)?;
        if key.is_empty()
            || key.contains(&0)
            || key.contains(&b'=')
            || value.contains(&0)
            || length > string_limit
        {
            return Err(invalid_launch());
        }
        size = size.checked_add(length).ok_or_else(invalid_launch)?;
    }
    let stack = rustix::process::getrlimit(rustix::process::Resource::Stack).current;
    if size > exec_budget_for_stack(stack) {
        return Err(invalid_launch());
    }
    Ok(())
}

fn exec_budget_for_stack(stack: Option<u64>) -> usize {
    // Linux fs/exec.c:bprm_stack_limits uses the current stack soft limit / 4
    // and the fixed ARG_MAX=131072 floor (not the machine's current page size).
    // The 1-MiB product cap is below Linux's 6-MiB ceiling. Leave additional
    // space for executable/interpreter and auxiliary kernel accounting.
    let kernel_limit = stack
        .map(|bytes| usize::try_from(bytes / 4).unwrap_or(usize::MAX))
        .unwrap_or(MAX_LAUNCH_EXEC_BYTES)
        .max(128 * 1024);
    MAX_LAUNCH_EXEC_BYTES.min(kernel_limit.saturating_sub(32 * 1024))
}

struct Channel {
    stream: UnixStream,
    deadline: Instant,
}
impl Channel {
    fn new(stream: UnixStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            deadline: Instant::now() + Duration::from_millis(MAX_PROJECTION_LIFETIME_MS),
        })
    }
    fn wait(&self, events: PollFlags) -> io::Result<()> {
        loop {
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(invalid_launch)?;
            let mut descriptors = [PollFd::new(&self.stream, events)];
            let timeout = Timespec::try_from(remaining).map_err(|_| invalid_launch())?;
            match poll(&mut descriptors, Some(&timeout)) {
                Ok(ready) if ready > 0 => return Ok(()),
                Err(rustix::io::Errno::INTR) => continue,
                _ => return Err(invalid_launch()),
            }
        }
    }
    fn read_exact(&mut self, mut bytes: &mut [u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            self.wait(PollFlags::IN)?;
            match self.stream.read(bytes) {
                Ok(0) => return Err(invalid_launch()),
                Ok(n) => {
                    bytes = &mut bytes[n..];
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(invalid_launch()),
            }
        }
        Ok(())
    }
    fn write_all(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            self.wait(PollFlags::OUT)?;
            match self.stream.write(bytes) {
                Ok(0) => return Err(invalid_launch()),
                Ok(n) => {
                    bytes = &bytes[n..];
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(invalid_launch()),
            }
        }
        Ok(())
    }
}

fn invalid_launch() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "environment launch denied or expired",
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
