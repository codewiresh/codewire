use std::fs;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use codewire_vmm_guest_probe::NetworkKey;
use uuid::Uuid;
use zeroize::Zeroize;

use super::binding::{Binding, Control, FRAME_LEN, Profile, Role, Status};
use super::descriptor as fd;
use super::packet::{self, CharacterStream, FixtureBroker};
use super::process::{self, OwnedChild};
use super::{Result, invalid};
use crate::network_worker;

const RUNTIME: Duration = Duration::from_secs(120);
const PREPARE: Duration = Duration::from_secs(20);

pub(super) fn entry(arguments: Vec<String>) -> Result<()> {
    entry_for(arguments, Profile::ConsolePair)
}

pub(super) fn entry_for(arguments: Vec<String>, profile: Profile) -> Result<()> {
    if unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) } == libc::SIG_ERR
        || unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) } == libc::SIG_ERR
    {
        return Err(invalid());
    }
    match arguments.as_slice() {
        [role] if role == "guest" || role == "service" => {
            if unsafe { libc::getpid() } != 1 {
                return Err(invalid());
            }
            // PID1 is still single-threaded. Kernel init's environment is not
            // inherited by any worker, adapter or protocol task.
            for (key, _) in std::env::vars_os() {
                unsafe {
                    std::env::remove_var(key);
                }
            }
            mount_minimal()?;
            let deadline = Instant::now() + RUNTIME;
            let binding = match profile {
                Profile::ConsolePair => {
                    Binding::read(Role::parse(role)?, deadline.min(Instant::now() + PREPARE))?
                }
                #[cfg(feature = "macos-product-network-fixture")]
                Profile::ProductNetwork => Binding::read_for(
                    Role::parse(role)?,
                    deadline.min(Instant::now() + PREPARE),
                    profile,
                )?,
            };
            let packet =
                fd::discover_port(fd::PACKET_PORT, deadline.min(Instant::now() + PREPARE))?;
            let status =
                fd::discover_port(fd::STATUS_PORT, deadline.min(Instant::now() + PREPARE))?;
            let control =
                fd::discover_port(fd::CONTROL_PORT, deadline.min(Instant::now() + PREPARE))?;
            fd::distinct(&[packet.as_raw_fd(), status.as_raw_fd(), control.as_raw_fd()])?;
            let mut context = Context {
                binding,
                status,
                control,
                deadline,
                output_sequence: 1,
                input_sequence: 1,
                input: [0; FRAME_LEN],
                position: 0,
            };
            let result = if context.binding.role == Role::Guest {
                guest(&mut context, packet)
            } else {
                match profile {
                    Profile::ConsolePair => service(&mut context, packet),
                    #[cfg(feature = "macos-product-network-fixture")]
                    Profile::ProductNetwork => {
                        super::product_runtime::service(&mut context, packet)
                    }
                }
            };
            if result.is_err() {
                let _ = context.status(Status::Failed);
            }
            result
        }
        [mode, identity, generation] if mode == "worker" => {
            process::child_invariants(&[4])?;
            let identity = Uuid::parse_str(identity).map_err(|_| invalid())?;
            let generation = generation.parse::<u64>().map_err(|_| invalid())?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let result = runtime.block_on(async {
                tokio::time::timeout(RUNTIME, async {
                    match profile {
                        Profile::ConsolePair => {
                            network_worker::run_inherited_worker_with_broker(
                                identity,
                                generation,
                                Arc::new(FixtureBroker::new(true)),
                            )
                            .await
                        }
                        #[cfg(feature = "macos-product-network-fixture")]
                        Profile::ProductNetwork => {
                            network_worker::run_inherited_worker(identity, generation).await
                        }
                    }
                })
                .await
            });
            let code = match result {
                Ok(Ok(())) => 0,
                Ok(Err(error)) => error.exit_code(),
                Err(_) => 70,
            };
            drop(runtime);
            std::process::exit(code);
        }
        [mode] if mode == "adapter" => process::adapter(),
        #[cfg(feature = "macos-product-network-fixture")]
        [mode] if mode == "endpoint" && profile == Profile::ProductNetwork => {
            super::product_network::run_inherited_endpoint()
        }
        #[cfg(feature = "macos-product-network-fixture")]
        [mode, identity, generation] if mode == "broker" && profile == Profile::ProductNetwork => {
            process::child_invariants(&[4])?;
            let identity = Uuid::parse_str(identity).map_err(|_| invalid())?;
            let generation = generation.parse::<u64>().map_err(|_| invalid())?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let result = runtime.block_on(async {
                tokio::time::timeout(
                    RUNTIME,
                    crate::egress_broker::run_inherited_egress_broker(identity, generation),
                )
                .await
            });
            let code = match result {
                Ok(Ok(())) => 0,
                Ok(Err(error)) => error.exit_code(),
                Err(_) => 70,
            };
            drop(runtime);
            std::process::exit(code);
        }
        _ => Err(invalid()),
    }
}

fn mount_minimal() -> Result<()> {
    for (path, source, flags, data) in [
        (
            "/dev",
            "devtmpfs",
            libc::MS_NOSUID | libc::MS_NOEXEC,
            "mode=0755",
        ),
        (
            "/proc",
            "proc",
            libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
            "",
        ),
        (
            "/sys",
            "sysfs",
            libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
            "",
        ),
    ] {
        fs::create_dir_all(path)?;
        let path = std::ffi::CString::new(path).map_err(|_| invalid())?;
        let source = std::ffi::CString::new(source).map_err(|_| invalid())?;
        let data = std::ffi::CString::new(data).map_err(|_| invalid())?;
        if unsafe {
            libc::mount(
                source.as_ptr(),
                path.as_ptr(),
                source.as_ptr(),
                flags,
                data.as_ptr().cast(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(super) fn poweroff() -> ! {
    if unsafe { libc::getpid() } != 1 {
        std::process::exit(70);
    }
    unsafe {
        libc::reboot(libc::RB_POWER_OFF);
    }
    // Failed poweroff is never reported as successful VM termination. The
    // retained native owner enforces its independent deadline and stop bound.
    loop {
        unsafe {
            libc::pause();
        }
    }
}

pub(super) struct Context {
    pub(super) binding: Binding,
    status: OwnedFd,
    pub(super) control: OwnedFd,
    pub(super) deadline: Instant,
    output_sequence: u64,
    input_sequence: u64,
    input: [u8; FRAME_LEN],
    position: usize,
}

impl Context {
    pub(super) fn status(&mut self, code: Status) -> Result<()> {
        let bytes = self.binding.status(code, self.output_sequence);
        fd::write_all(
            self.status.as_raw_fd(),
            &bytes,
            self.deadline.min(Instant::now() + Duration::from_secs(1)),
        )?;
        self.output_sequence = self.output_sequence.checked_add(1).ok_or_else(invalid)?;
        Ok(())
    }
    fn reaped(&mut self, worker: i32, adapter: i32) -> Result<()> {
        let bytes = self.binding.reaped(self.output_sequence, worker, adapter)?;
        fd::write_all(
            self.status.as_raw_fd(),
            &bytes,
            Instant::now() + Duration::from_secs(1),
        )?;
        self.output_sequence = self.output_sequence.checked_add(1).ok_or_else(invalid)?;
        Ok(())
    }
    #[cfg(feature = "macos-product-network-fixture")]
    pub(super) fn product_reaped(&mut self, waits: [i32; 4]) -> Result<()> {
        let bytes = self.binding.product_reaped(self.output_sequence, waits)?;
        fd::write_all(
            self.status.as_raw_fd(),
            &bytes,
            self.deadline.min(Instant::now() + Duration::from_secs(1)),
        )?;
        self.output_sequence = self.output_sequence.checked_add(1).ok_or_else(invalid)?;
        Ok(())
    }
    pub(super) fn read_control(&mut self) -> Result<Option<Control>> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        match fd::read_some(self.control.as_raw_fd(), &mut self.input[self.position..]) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(count) => self.position += count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
        if self.position != FRAME_LEN {
            return Ok(None);
        }
        let command = self.binding.control(&self.input, self.input_sequence)?;
        self.input_sequence = self.input_sequence.checked_add(1).ok_or_else(invalid)?;
        self.position = 0;
        Ok(Some(command))
    }
    async fn async_control(&mut self) -> Result<Control> {
        loop {
            if let Some(command) = self.read_control()? {
                return Ok(command);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    fn wait_control(&mut self) -> Result<Control> {
        loop {
            if let Some(command) = self.read_control()? {
                return Ok(command);
            }
            fd::poll(
                &mut [fd::pollfd(self.control.as_raw_fd(), libc::POLLIN)],
                self.deadline,
            )?;
        }
    }
    pub(super) fn cancelled(&mut self) -> Result<()> {
        self.status(Status::Cancelled)?;
        // The parent's authenticated acknowledgement proves it received the
        // final status before PID1 can power off and discard queued port bytes.
        self.await_poweroff()
    }
    fn await_poweroff(&mut self) -> Result<()> {
        let seconds = match self.binding.profile {
            Profile::ConsolePair => 5,
            // The product parent waits both normal cancellation facts before
            // either poweroff. Its 10s cancellation phase must fit this wait.
            #[cfg(feature = "macos-product-network-fixture")]
            Profile::ProductNetwork => 15,
        };
        self.deadline = self
            .deadline
            .min(Instant::now() + Duration::from_secs(seconds));
        if self.wait_control()? != Control::PowerOff {
            return Err(invalid());
        }
        Ok(())
    }
}

fn guest(context: &mut Context, packet: OwnedFd) -> Result<()> {
    context.status(Status::PortsReady)?;
    match context.wait_control()? {
        Control::Start => {}
        Control::Cancel => {
            drop(packet);
            return context.cancelled();
        }
        _ => return Err(invalid()),
    }
    let key =
        NetworkKey::from_derived_bytes(*context.binding.network_key).map_err(|_| invalid())?;
    context.binding.network_key.zeroize();
    let vm_id = context.binding.vm_id;
    let generation = context.binding.generation;
    let profile = context.binding.profile;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let packet = runtime.block_on(async {
        let mut stream = CharacterStream::new(packet)?;
        context.status(Status::GuestArmed)?;
        let session = tokio::select! {
            command = context.async_control() => {
                if command? != Control::Cancel { return Err(invalid()); }
                context.status(Status::Cancelled)?;
                return Ok(None);
            }
            result = tokio::time::timeout(Duration::from_secs(10), packet::authenticate(&mut stream, key, vm_id, generation)) => result.map_err(|_| invalid())??,
        };
        context.status(Status::HostReady)?;
        tokio::select! {
            command = context.async_control() => {
                if command? != Control::Cancel { return Err(invalid()); }
                context.status(Status::Cancelled)?;
                return Ok(None);
            }
            result = tokio::time::timeout(Duration::from_secs(15), packet::traffic_for(&mut stream, session, profile)) => result.map_err(|_| invalid())??,
        }
        context.status(Status::PacketCompleted)?;
        Ok::<_, io::Error>(Some(stream.into_inner()))
    })?;
    drop(runtime);
    let Some(packet) = packet else {
        return context.await_poweroff();
    };
    let mut packet = Some(packet);
    loop {
        match context.wait_control()? {
            Control::Cancel => {
                drop(packet.take());
                return context.cancelled();
            }
            Control::ClosePacket if packet.is_some() => {
                drop(packet.take());
                context.status(Status::PacketClosed)?;
            }
            _ => return Err(invalid()),
        }
    }
}

pub(super) struct LineReader {
    bytes: [u8; 64],
    length: usize,
    pub(super) closed: bool,
}
impl LineReader {
    pub(super) fn new() -> Self {
        Self {
            bytes: [0; 64],
            length: 0,
            closed: false,
        }
    }
    pub(super) fn read(&mut self, source: i32) -> Result<Option<Vec<u8>>> {
        if self.closed {
            return Ok(None);
        }
        let mut byte = [0];
        loop {
            match fd::read_some(source, &mut byte) {
                Ok(0) => {
                    self.closed = true;
                    if self.length != 0 {
                        return Err(invalid());
                    }
                    return Ok(None);
                }
                Ok(1) => {
                    if self.length == self.bytes.len() {
                        return Err(invalid());
                    }
                    self.bytes[self.length] = byte[0];
                    self.length += 1;
                    if byte[0] == b'\n' {
                        let line = self.bytes[..self.length].to_vec();
                        self.length = 0;
                        return Ok(Some(line));
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(None);
                }
                _ => return Err(invalid()),
            }
        }
    }
}

struct ServiceChildren {
    worker: OwnedChild,
    adapter: Option<OwnedChild>,
    adapter_control: Option<UnixStream>,
}
impl ServiceChildren {
    fn cleanup(&mut self) -> Result<(i32, i32)> {
        if let Some(channel) = &self.adapter_control {
            let _ = fd::write_all(
                channel.as_raw_fd(),
                &[process::ADAPTER_STOP],
                Instant::now() + Duration::from_millis(100),
            );
        }
        let graceful = Instant::now() + Duration::from_millis(500);
        while Instant::now() < graceful {
            let worker_done = self.worker.poll()?.is_some();
            let adapter_done = match self.adapter.as_mut() {
                Some(child) => child.poll()?.is_some(),
                None => true,
            };
            if worker_done && adapter_done {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let worker = self
            .worker
            .terminate(Instant::now() + Duration::from_secs(2))?
            .into_raw();
        let adapter = match self.adapter.as_mut() {
            Some(child) => child
                .terminate(Instant::now() + Duration::from_secs(2))?
                .into_raw(),
            None => return Err(invalid()),
        };
        Ok((worker, adapter))
    }
}

fn service(context: &mut Context, packet: OwnedFd) -> Result<()> {
    let (bootstrap, worker_bootstrap) = UnixStream::pair()?;
    bootstrap.set_nonblocking(true)?;
    let key =
        NetworkKey::from_derived_bytes(*context.binding.network_key).map_err(|_| invalid())?;
    let bytes = network_worker::encode_worker_bootstrap(
        context.binding.vm_id,
        context.binding.generation,
        &key,
    )
    .map_err(|_| invalid())?;
    let worker = process::spawn(
        Path::new("/init"),
        &[
            "worker".into(),
            context.binding.vm_id.to_string(),
            context.binding.generation.to_string(),
        ],
        &[(worker_bootstrap.as_raw_fd(), 4)],
    )?;
    drop(worker_bootstrap);
    fd::write_all(
        bootstrap.as_raw_fd(),
        bytes.as_ref(),
        context
            .deadline
            .min(Instant::now() + Duration::from_secs(1)),
    )?;
    drop(bytes);
    drop(key);
    context.binding.network_key.zeroize();
    let mut children = ServiceChildren {
        worker,
        adapter: None,
        adapter_control: None,
    };
    let result = service_loop(context, packet, &bootstrap, &mut children);
    // Even ordinary failures must retain child ownership until bounded reaping.
    let cleanup = children.cleanup();
    let (worker, adapter) = cleanup?;
    context.reaped(worker, adapter)?;
    result?;
    if worker != 37 << 8 || adapter != 0 {
        return Err(invalid());
    }
    context.cancelled()
}

fn service_loop(
    context: &mut Context,
    packet: OwnedFd,
    bootstrap: &UnixStream,
    children: &mut ServiceChildren,
) -> Result<()> {
    let prepare_deadline = context.deadline.min(Instant::now() + PREPARE);
    let mut packet = Some(packet);
    let mut network = None;
    let mut line = LineReader::new();
    let mut worker_prepared = false;
    let mut adapter_prepared = false;
    let mut prepared_sent = false;
    let mut started = false;
    let mut ready = false;
    let mut observed = false;
    let mut observing = None;
    let mut adapter_terminal = None;
    loop {
        if let Some(message) = line.read(bootstrap.as_raw_fd())? {
            if !worker_prepared && message == network_worker::WORKER_PREPARED_MESSAGE {
                worker_prepared = true;
                let (parent, child) = UnixStream::pair()?;
                let (worker_network, adapter_network) = UnixStream::pair()?;
                parent.set_nonblocking(true)?;
                child.set_nonblocking(true)?;
                worker_network.set_nonblocking(true)?;
                adapter_network.set_nonblocking(true)?;
                let adapter = process::spawn(
                    Path::new("/init"),
                    &["adapter".into()],
                    &[
                        (packet.as_ref().ok_or_else(invalid)?.as_raw_fd(), 3),
                        (adapter_network.as_raw_fd(), 4),
                        (child.as_raw_fd(), 5),
                    ],
                )?;
                children.adapter = Some(adapter);
                children.adapter_control = Some(parent);
                network = Some(worker_network);
            } else if started && !ready && message == network_worker::WORKER_READY_MESSAGE {
                ready = true;
                context.status(Status::WorkerReady)?;
            } else {
                return Err(invalid());
            }
        }
        if line.closed && !ready {
            return Err(invalid());
        }
        if let Some(control) = &children.adapter_control {
            let mut byte = [0];
            match fd::read_some(control.as_raw_fd(), &mut byte) {
                Ok(1) if !adapter_prepared && byte[0] == process::ADAPTER_PREPARED => {
                    adapter_prepared = true
                }
                Ok(1) if adapter_prepared && adapter_terminal.is_none() => {
                    if !observed {
                        return Err(invalid());
                    }
                    if byte[0] != process::ADAPTER_CHAR_EOF {
                        return Err(invalid());
                    }
                    adapter_terminal = Some(byte[0]);
                    if observing.take().is_some() {
                        context.status(Status::EofObserved)?;
                    }
                }
                Ok(0) if adapter_terminal.is_some() => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                _ => return Err(invalid()),
            }
        }
        // Consume final adapter evidence before checking a simultaneously
        // reaped child; actual char EOF is not overwritten by its consequence.
        if let Some(status) = children.worker.poll()?
            && (!observed || status.code() != Some(37))
        {
            return Err(invalid());
        }
        if let Some(child) = &mut children.adapter
            && let Some(status) = child.poll()?
            && (!observed
                || adapter_terminal != Some(process::ADAPTER_CHAR_EOF)
                || !status.success())
        {
            return Err(invalid());
        }
        if worker_prepared && adapter_prepared && !prepared_sent {
            context.status(Status::Prepared)?;
            prepared_sent = true;
        }
        if let Some(command) = context.read_control()? {
            match command {
                Control::Cancel => return Ok(()),
                Control::Start if prepared_sent && !started => {
                    network_worker::send_worker_network_descriptor(
                        bootstrap.as_raw_fd(),
                        network.as_ref().ok_or_else(invalid)?.as_raw_fd(),
                    )?;
                    drop(network.take());
                    drop(packet.take());
                    fd::write_all(
                        children
                            .adapter_control
                            .as_ref()
                            .ok_or_else(invalid)?
                            .as_raw_fd(),
                        &[process::ADAPTER_GO],
                        context
                            .deadline
                            .min(Instant::now() + Duration::from_secs(1)),
                    )?;
                    started = true;
                }
                Control::ObserveEof if ready && !observed => {
                    observed = true;
                    context.status(Status::EofArmed)?;
                    observing = Some(Instant::now() + Duration::from_secs(2));
                }
                _ => return Err(invalid()),
            }
        }
        if observing.is_some_and(|deadline| Instant::now() >= deadline) {
            observing = None;
            context.status(Status::NoEofObserved)?;
        }
        if !prepared_sent && Instant::now() >= prepare_deadline {
            return Err(invalid());
        }
        fd::poll(
            &mut [fd::pollfd(context.control.as_raw_fd(), libc::POLLIN)],
            context
                .deadline
                .min(Instant::now() + Duration::from_millis(50)),
        )?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn fixture() -> (Context, UnixStream, UnixStream) {
        let mut sealed = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1, "role": "guest", "vmID": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            "generation": 7, "runNonce": "11".repeat(32),
            "networkKey": "22".repeat(32), "statusKey": "33".repeat(32)
        }))
        .unwrap();
        sealed.resize(4096, 0);
        let binding = Binding::decode(&sealed, Role::Guest).unwrap();
        let (status, status_peer) = UnixStream::pair().unwrap();
        let (control, control_peer) = UnixStream::pair().unwrap();
        status.set_nonblocking(true).unwrap();
        control.set_nonblocking(true).unwrap();
        (
            Context {
                binding,
                status: status.into(),
                control: control.into(),
                deadline: Instant::now() + Duration::from_secs(2),
                input_sequence: 1,
                output_sequence: 1,
                input: [0; FRAME_LEN],
                position: 0,
            },
            status_peer,
            control_peer,
        )
    }

    #[test]
    fn partial_control_never_restarts_deadline_or_accepts_stale_sequence() {
        let (mut context, _status, mut peer) = fixture();
        let frame = context.binding.test_control(Control::Start, 1);
        peer.write_all(&frame[..64]).unwrap();
        assert!(context.read_control().unwrap().is_none());
        peer.write_all(&frame[64..]).unwrap();
        assert_eq!(context.read_control().unwrap(), Some(Control::Start));
        peer.write_all(&frame).unwrap();
        assert!(context.read_control().is_err());
        let (mut context, _status, mut peer) = fixture();
        peer.write_all(&frame[..64]).unwrap();
        assert!(context.read_control().unwrap().is_none());
        context.deadline = Instant::now();
        peer.write_all(&frame[64..]).unwrap();
        assert_eq!(
            context.read_control().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn guest_rejects_poweroff_before_cancel_and_requires_ack_after_status() {
        for first in [Control::PowerOff, Control::ClosePacket, Control::ObserveEof] {
            let (mut context, _status, mut peer) = fixture();
            peer.write_all(&context.binding.test_control(first, 1))
                .unwrap();
            let (packet, _opposite) = UnixStream::pair().unwrap();
            assert!(guest(&mut context, packet.into()).is_err());
        }
        let (mut context, mut status, mut peer) = fixture();
        peer.write_all(&context.binding.test_control(Control::Cancel, 1))
            .unwrap();
        peer.write_all(&context.binding.test_control(Control::PowerOff, 2))
            .unwrap();
        let (packet, mut opposite) = UnixStream::pair().unwrap();
        guest(&mut context, packet.into()).unwrap();
        let mut frames = [0; 2 * FRAME_LEN];
        status.read_exact(&mut frames).unwrap();
        assert_eq!(
            &frames[..FRAME_LEN],
            &context.binding.status(Status::PortsReady, 1)
        );
        assert_eq!(
            &frames[FRAME_LEN..],
            &context.binding.status(Status::Cancelled, 2)
        );
        let mut byte = [0];
        assert_eq!(opposite.read(&mut byte).unwrap(), 0);
        let (mut context, _status, mut peer) = fixture();
        peer.write_all(&context.binding.test_control(Control::Cancel, 1))
            .unwrap();
        drop(peer);
        let (packet, _opposite) = UnixStream::pair().unwrap();
        assert!(guest(&mut context, packet.into()).is_err());
    }
}
