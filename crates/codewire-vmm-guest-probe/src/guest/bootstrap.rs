//! Finite bootstrap control on the existing trusted PID-1 readiness socket.
//! Only descriptors cross this protocol. Ciphertext and recipient framing stay
//! on the separate one-shot channel, owned by the final workspace-exec process.

use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::AsFd;

use codewire_daemon::execution::{
    BOOTSTRAP_FINISH, BOOTSTRAP_PROJECTION_SOCKET_NAME, BootstrapPhase,
};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};

use super::*;

const PRELUDE: &[u8; 7] = b"CWBOOT\x01";
const REQUEST: u8 = 0xb0;
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) struct BootstrapChild {
    required: bool,
    control: UnixStream,
}

impl BootstrapChild {
    pub(super) fn receive(deadline: Instant) -> Result<Self> {
        // FD 3 was already validated and made CLOEXEC by workspace PID 1.
        let descriptor = unsafe { BorrowedFd::borrow_raw(WORKSPACE_READY_FD) };
        let control = UnixStream::from(rustix::io::fcntl_dupfd_cloexec(descriptor, 5)?);
        Self::receive_from(control, deadline)
    }

    fn receive_from(mut control: UnixStream, deadline: Instant) -> Result<Self> {
        control.set_nonblocking(true)?;
        let mut prelude = [0; 8];
        read_bounded(&mut control, &mut prelude, bounded_deadline(deadline))?;
        ensure!(
            &prelude[..7] == PRELUDE && prelude[7] <= 1,
            "invalid bootstrap projection prelude"
        );
        Ok(Self {
            required: prelude[7] == 1,
            control,
        })
    }

    pub(super) fn channel(
        &self,
        phase: BootstrapPhase,
        deadline: Instant,
    ) -> Result<Option<UnixStream>> {
        if !self.required {
            return Ok(None);
        }
        let deadline = bounded_deadline(deadline);
        let mut control = &self.control;
        write_bounded(&mut control, &[REQUEST, phase as u8], deadline)?;
        receive_descriptor(&self.control, phase as u8, deadline).map(Some)
    }
}

pub(super) struct BootstrapParent {
    required: bool,
    daemon_pid: u32,
    used: u8,
}

impl BootstrapParent {
    pub(super) fn new(required: bool, daemon_pid: u32) -> Self {
        Self {
            required,
            daemon_pid,
            used: 0,
        }
    }

    pub(super) fn prelude(&self, control: &mut UnixStream, deadline: Instant) -> Result<()> {
        let mut bytes = [0; 8];
        bytes[..7].copy_from_slice(PRELUDE);
        bytes[7] = u8::from(self.required);
        write_bounded(control, &bytes, bounded_deadline(deadline))
    }

    /// Returns true when the readiness parser must wait or a phase was served.
    pub(super) fn advance(&mut self, control: &mut UnixStream, deadline: Instant) -> Result<bool> {
        let mut bytes = [0; 2];
        let length =
            match rustix::net::recv(&*control, &mut bytes, RecvFlags::PEEK | RecvFlags::DONTWAIT) {
                Ok((_, length)) => length,
                Err(RustixErrno::AGAIN) => return Ok(true),
                Err(error) => return Err(error).context("inspect bootstrap phase"),
            };
        if length == 0 || bytes[0] != REQUEST {
            return Ok(false);
        }
        if length < bytes.len() {
            return Ok(true);
        }
        let phase = BootstrapPhase::from_byte(bytes[1])
            .ok_or_else(|| anyhow::anyhow!("invalid bootstrap phase"))?;
        let bit = 1 << (phase as u8 - 1);
        ensure!(
            self.required && self.used & bit == 0,
            "bootstrap projection phase denied"
        );
        self.used |= bit;
        read_bounded(control, &mut bytes, bounded_deadline(deadline))?;
        let channel = self.connect(phase as u8, deadline)?;
        send_descriptor(control, &channel, phase as u8, bounded_deadline(deadline))?;
        Ok(true)
    }

    pub(super) fn finish(&self, deadline: Instant) -> Result<()> {
        if !self.required {
            return Ok(());
        }
        let mut channel = self.connect(BOOTSTRAP_FINISH, deadline)?;
        let mut acknowledgement = [0];
        read_bounded(
            &mut channel,
            &mut acknowledgement,
            bounded_deadline(deadline),
        )?;
        ensure!(
            acknowledgement == [BOOTSTRAP_FINISH],
            "bootstrap projection finish denied"
        );
        Ok(())
    }

    fn connect(&self, phase: u8, deadline: Instant) -> Result<UnixStream> {
        use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
        let deadline = bounded_deadline(deadline);
        let parent = Path::new(RUNC_PROCESS_PATH);
        let metadata = fs::symlink_metadata(parent)?;
        ensure!(
            metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o777 == 0o700,
            "bootstrap projection directory is not root-private"
        );
        let path = parent.join(BOOTSTRAP_PROJECTION_SOCKET_NAME);
        let address = SocketAddrUnix::new(&path)?;
        loop {
            ensure_workspace_start_active(deadline, &POWEROFF_REQUESTED)?;
            let descriptor = rustix::net::socket_with(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                None,
            )?;
            match rustix::net::connect(&descriptor, &address) {
                Ok(()) => {
                    let metadata = fs::symlink_metadata(&path)?;
                    ensure!(
                        metadata.file_type().is_socket()
                            && metadata.uid() == 0
                            && metadata.mode() & 0o777 == 0o600,
                        "bootstrap projection socket is not root-private"
                    );
                    let mut stream = UnixStream::from(descriptor);
                    let peer = rustix::net::sockopt::socket_peercred(&stream)?;
                    ensure!(
                        peer.uid.as_raw() == 0
                            && peer.pid.as_raw_nonzero().get() as u32 == self.daemon_pid,
                        "bootstrap projection daemon identity mismatch"
                    );
                    write_bounded(&mut stream, &[phase], deadline)?;
                    return Ok(stream);
                }
                Err(RustixErrno::NOENT | RustixErrno::CONNREFUSED | RustixErrno::AGAIN) => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => return Err(error).context("connect bootstrap projection channel"),
            }
        }
    }
}

fn bounded_deadline(deadline: Instant) -> Instant {
    deadline.min(Instant::now() + CHANNEL_TIMEOUT)
}

fn read_bounded(stream: &mut impl Read, mut bytes: &mut [u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        ensure_workspace_start_active(deadline, &POWEROFF_REQUESTED)?;
        match stream.read(bytes) {
            Ok(0) => bail!("bootstrap projection channel closed"),
            Ok(length) => bytes = &mut bytes[length..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error).context("read bootstrap projection control"),
        }
    }
    Ok(())
}

fn write_bounded(stream: &mut impl Write, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        ensure_workspace_start_active(deadline, &POWEROFF_REQUESTED)?;
        match stream.write(bytes) {
            Ok(0) => bail!("bootstrap projection channel closed"),
            Ok(length) => bytes = &bytes[length..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error).context("write bootstrap projection control"),
        }
    }
    Ok(())
}

fn send_descriptor(
    control: &UnixStream,
    channel: &UnixStream,
    phase: u8,
    deadline: Instant,
) -> Result<()> {
    let descriptors = [channel.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    loop {
        ensure_workspace_start_active(deadline, &POWEROFF_REQUESTED)?;
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        ensure!(
            ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)),
            "bootstrap descriptor frame is invalid"
        );
        match rustix::net::sendmsg(
            control,
            &[IoSlice::new(&[phase])],
            &mut ancillary,
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        ) {
            Ok(1) => return Ok(()),
            Ok(_) => bail!("bootstrap descriptor frame is invalid"),
            Err(RustixErrno::AGAIN | RustixErrno::INTR) => thread::sleep(Duration::from_millis(20)),
            Err(error) => return Err(error).context("send bootstrap projection descriptor"),
        }
    }
}

fn receive_descriptor(control: &UnixStream, phase: u8, deadline: Instant) -> Result<UnixStream> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    loop {
        ensure_workspace_start_active(deadline, &POWEROFF_REQUESTED)?;
        let mut bytes = [0];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        match rustix::net::recvmsg(
            control,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut ancillary,
            RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
        ) {
            Ok(message) => {
                ensure!(
                    message.bytes == 1
                        && bytes == [phase]
                        && !message
                            .flags
                            .intersects(ReturnFlags::CTRUNC | ReturnFlags::TRUNC),
                    "bootstrap descriptor frame is invalid"
                );
                let mut descriptors = Vec::with_capacity(2);
                for message in ancillary.drain() {
                    match message {
                        RecvAncillaryMessage::ScmRights(rights) => descriptors.extend(rights),
                        _ => bail!("bootstrap descriptor frame is invalid"),
                    }
                }
                ensure!(
                    descriptors.len() == 1,
                    "bootstrap descriptor count is invalid"
                );
                let descriptor = descriptors.pop().expect("one validated descriptor");
                let metadata = rustix::fs::fstat(&descriptor)?;
                ensure!(
                    RustixFileType::from_raw_mode(metadata.st_mode) == RustixFileType::Socket,
                    "bootstrap projection descriptor is not a socket"
                );
                return Ok(UnixStream::from(descriptor));
            }
            Err(RustixErrno::AGAIN | RustixErrno::INTR) => thread::sleep(Duration::from_millis(20)),
            Err(error) => return Err(error).context("receive bootstrap projection descriptor"),
        }
    }
}

/// Equivalent to a bounded exec-error pipe: Pending followed by CLOEXEC EOF
/// admits the target exec, not application health. Any explicit failure closes
/// startup. As with ordinary spawn, a fatal signal at the final exec boundary
/// can race observation; this is not an application-readiness protocol.
pub(super) fn wait_exec_status(
    child: &mut std::process::Child,
    mut status: UnixStream,
    deadline: Instant,
) -> Result<()> {
    use codewire_workload_secrets::launcher::{LAUNCH_EXEC_FAILED, LAUNCH_EXEC_PENDING};
    let deadline = bounded_deadline(deadline);
    let mut pending = false;
    let result = status
        .set_nonblocking(true)
        .context("bound projected workspace exec status")
        .and_then(|()| {
            loop {
                ensure_workspace_start_active(deadline, &POWEROFF_REQUESTED)?;
                let mut byte = [0];
                match status.read(&mut byte) {
                    Ok(0) => {
                        ensure!(pending, "projected workspace command was not admitted");
                        // Do not turn background startup into a health check: a
                        // successfully executed application may already have
                        // exited, including nonzero. Exec failures have their
                        // own fixed Failed byte before this CLOEXEC close.
                        return Ok(());
                    }
                    Ok(1) if byte[0] == LAUNCH_EXEC_PENDING && !pending => pending = true,
                    Ok(1) if byte[0] == LAUNCH_EXEC_FAILED => {
                        bail!("projected workspace command admission failed")
                    }
                    Ok(_) => bail!("projected workspace exec status is invalid"),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20))
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error).context("observe projected workspace exec"),
                }
            }
        });
    if result.is_err() {
        stop_workspace_install(child)?;
    }
    result
}

#[cfg(test)]
mod tests;
