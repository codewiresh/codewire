//! PID1-only orchestration for the fixed production-worker/broker fixture.
//! No packet bytes, broker IPC frames or provider material pass through PID1.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::time::{Duration, Instant};

use codewire_vmm_guest_probe::NetworkKey;
use rand::{RngCore, rngs::OsRng};
use zeroize::{Zeroize, Zeroizing};

use super::binding::{Control, Profile, Role, Status};
use super::descriptor as fd;
use super::process::{self, OwnedChild};
use super::product_network::{
    ENDPOINT_CANCEL_MESSAGE, ENDPOINT_COMPLETED_MESSAGE, ENDPOINT_READY_MESSAGE,
    prepare_service_topology,
};
use super::runtime::{Context, LineReader};
use super::{Result, invalid};
use crate::{egress_broker, network_worker};

const PREPARE: Duration = Duration::from_secs(20);
const CANCEL: Duration = Duration::from_secs(5);
const ABORT: Duration = Duration::from_secs(2);
const EXPECTED_WAITS: [i32; 4] = [37 << 8, 0, 72 << 8, 0];
const RESOLVER: &[u8] = b"nameserver 127.0.0.1\n";
const WORKER: usize = 0;
const ADAPTER: usize = 1;
const BROKER: usize = 2;
const ENDPOINT: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Endpoint,
    BrokerPrepared,
    BrokerReady,
    WorkerPrepared,
    WorkerBrokerReady,
    Adapter,
    Start,
    WorkerReady,
    Running,
}

struct Progress {
    stage: Stage,
    endpoint_completed: bool,
    endpoint_published: bool,
    broker_transferred: bool,
    eof_armed: bool,
    eof_decided: bool,
    adapter_terminal: Option<u8>,
    cancelled: bool,
    ingress_closed: bool,
    waits: [Option<i32>; 4],
}

impl Progress {
    fn new() -> Self {
        Self {
            stage: Stage::Endpoint,
            endpoint_completed: false,
            endpoint_published: false,
            broker_transferred: false,
            eof_armed: false,
            eof_decided: false,
            adapter_terminal: None,
            cancelled: false,
            ingress_closed: false,
            waits: [None; 4],
        }
    }

    fn advance(&mut self, expected: Stage, next: Stage) -> Result<()> {
        if self.cancelled || self.stage != expected {
            return Err(invalid());
        }
        self.stage = next;
        Ok(())
    }

    fn endpoint_complete(&mut self) -> Result<()> {
        if self.endpoint_completed
            || !matches!(self.stage, Stage::WorkerReady | Stage::Running)
            || self.cancelled
        {
            return Err(invalid());
        }
        self.endpoint_completed = true;
        Ok(())
    }

    fn publish_endpoint(&mut self) -> bool {
        if self.stage == Stage::Running
            && self.endpoint_completed
            && self.waits[ENDPOINT] == Some(0)
            && !self.endpoint_published
        {
            self.endpoint_published = true;
            true
        } else {
            false
        }
    }

    fn observe_eof(&mut self) -> Result<()> {
        if self.stage != Stage::Running || !self.endpoint_published || self.eof_armed {
            return Err(invalid());
        }
        self.eof_armed = true;
        Ok(())
    }

    fn adapter_terminal(&mut self, value: u8) -> Result<()> {
        if self.adapter_terminal.is_some()
            || !self.endpoint_published
            || !((value == process::ADAPTER_CHAR_EOF && self.eof_armed)
                || (value == process::ADAPTER_CANCELLED && self.cancelled))
        {
            return Err(invalid());
        }
        self.adapter_terminal = Some(value);
        Ok(())
    }

    fn cancel(&mut self) -> Result<()> {
        if self.cancelled
            || self.stage != Stage::Running
            || !self.endpoint_published
            || !self.eof_decided
            || !self.broker_transferred
        {
            return Err(invalid());
        }
        self.cancelled = true;
        Ok(())
    }

    fn closure_admitted(&self) -> bool {
        self.endpoint_published
            && self.broker_transferred
            && ((self.eof_armed && self.adapter_terminal == Some(process::ADAPTER_CHAR_EOF))
                || (self.cancelled && self.ingress_closed))
    }

    fn exited(&mut self, role: usize, raw: i32) -> Result<()> {
        if role >= self.waits.len() || raw != EXPECTED_WAITS[role] {
            return Err(invalid());
        }
        let admitted = match role {
            ENDPOINT => self.endpoint_completed,
            ADAPTER => self.adapter_terminal.is_some(),
            WORKER | BROKER => self.closure_admitted(),
            _ => false,
        };
        if !admitted {
            return Err(invalid());
        }
        self.waits[role] = Some(raw);
        Ok(())
    }

    fn final_waits(&self) -> Result<Option<[i32; 4]>> {
        if !self.cancelled || !self.ingress_closed || !self.eof_decided {
            return Err(invalid());
        }
        if self.waits.iter().any(Option::is_none) {
            return Ok(None);
        }
        if self.waits != EXPECTED_WAITS.map(Some) || !self.closure_admitted() {
            return Err(invalid());
        }
        Ok(Some(EXPECTED_WAITS))
    }
}

#[derive(Default)]
struct Children {
    children: [Option<OwnedChild>; 4],
    endpoint_control: Option<UnixStream>,
    broker_control: Option<UnixStream>,
    worker_control: Option<UnixStream>,
    adapter_control: Option<UnixStream>,
    packet: Option<OwnedFd>,
    network: Option<UnixStream>,
}

impl Children {
    fn spawn(&mut self, role: usize, args: &[String], mappings: &[(i32, i32)]) -> Result<()> {
        if self.children[role].is_some() {
            return Err(invalid());
        }
        self.children[role] = Some(process::spawn(Path::new("/init"), args, mappings)?);
        Ok(())
    }

    fn observe(&mut self, role: usize) -> Result<Option<i32>> {
        if let Some(child) = &mut self.children[role]
            && let Some(status) = child.poll()?
        {
            return Ok(Some(status.into_raw()));
        }
        Ok(None)
    }

    fn drop_channels(&mut self) {
        drop(self.endpoint_control.take());
        drop(self.broker_control.take());
        drop(self.worker_control.take());
        drop(self.adapter_control.take());
        drop(self.packet.take());
        drop(self.network.take());
    }

    fn abort(&mut self) -> Result<()> {
        // One aggregate bound, not four fresh per-child budgets. Every retained
        // child is visited even if an earlier signal/reap is uncertain. This
        // forced cleanup is never an input to the successful wait receipt.
        let deadline = Instant::now() + ABORT;
        for (channel, message) in [
            (&self.endpoint_control, ENDPOINT_CANCEL_MESSAGE),
            (&self.adapter_control, &[process::ADAPTER_STOP][..]),
        ] {
            if let Some(channel) = channel {
                let _ = fd::write_all(
                    channel.as_raw_fd(),
                    message,
                    deadline.min(Instant::now() + Duration::from_millis(100)),
                );
            }
        }
        self.drop_channels();
        let mut failure = None;
        for child in self.children.iter_mut().flatten() {
            if let Err(error) = child.terminate(deadline) {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

struct Bootstraps {
    broker: Option<Zeroizing<Vec<u8>>>,
    worker: Option<Zeroizing<Vec<u8>>>,
}

fn fresh_key(excluded: &[&[u8; 32]]) -> Result<Zeroizing<[u8; 32]>> {
    for _ in 0..8 {
        let mut key = Zeroizing::new([0; 32]);
        OsRng.try_fill_bytes(key.as_mut()).map_err(|_| invalid())?;
        if key.iter().any(|byte| *byte != 0) && !excluded.iter().any(|other| **other == *key) {
            return Ok(key);
        }
    }
    Err(invalid())
}

fn bootstraps(context: &mut Context) -> Result<Bootstraps> {
    let key =
        NetworkKey::from_derived_bytes(*context.binding.network_key).map_err(|_| invalid())?;
    let broker = fresh_key(&[&context.binding.network_key])?;
    let host_port = fresh_key(&[&context.binding.network_key, &broker])?;
    let mesh = fresh_key(&[&context.binding.network_key, &broker, &host_port])?;
    let broker_bytes = egress_broker::encode_developer_egress_broker_bootstrap(
        context.binding.vm_id,
        context.binding.generation,
        &broker,
    )
    .map_err(|_| invalid())?;
    let worker_bytes = network_worker::encode_product_worker_bootstrap(
        context.binding.vm_id,
        context.binding.generation,
        &key,
        &broker,
        &host_port,
        &mesh,
        &[],
    )
    .map_err(|_| invalid())?;
    context.binding.network_key.zeroize();
    Ok(Bootstraps {
        broker: Some(Zeroizing::new(broker_bytes.to_vec())),
        worker: Some(Zeroizing::new(worker_bytes.to_vec())),
    })
}

fn check_resolver(file: &mut File, path: &Path, owner: u32) -> Result<()> {
    let held = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if !held.is_file()
        || !named.is_file()
        || held.uid() != owner
        || held.nlink() != 1
        || held.mode() & 0o7777 != 0o600
        || held.len() != RESOLVER.len() as u64
        || (held.dev(), held.ino()) != (named.dev(), named.ino())
    {
        return Err(invalid());
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = [0; RESOLVER.len()];
    file.read_exact(&mut bytes)?;
    if bytes != RESOLVER {
        return Err(invalid());
    }
    Ok(())
}

fn prepare_resolver() -> Result<()> {
    if unsafe { libc::getpid() } != 1 || unsafe { libc::geteuid() } != 0 {
        return Err(invalid());
    }
    match DirBuilder::new().mode(0o755).create("/etc") {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let directory = fs::symlink_metadata("/etc")?;
    if !directory.is_dir() || directory.uid() != 0 || directory.mode() & 0o022 != 0 {
        return Err(invalid());
    }
    // The sealed fixture initramfs has no resolver file. Never overwrite or
    // accept a preexisting/symlinked config; the real broker reads only this
    // fixed root-owned file during its unchanged resolver initialization.
    let path = Path::new("/etc/resolv.conf");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(RESOLVER)?;
    file.sync_all()?;
    check_resolver(&mut file, path, 0)?;
    let after = fs::symlink_metadata("/etc")?;
    if (directory.dev(), directory.ino()) != (after.dev(), after.ino()) {
        return Err(invalid());
    }
    Ok(())
}

fn pair() -> Result<(UnixStream, UnixStream)> {
    let (parent, child) = UnixStream::pair()?;
    parent.set_nonblocking(true)?;
    Ok((parent, child))
}

fn write(channel: &UnixStream, bytes: &[u8], deadline: Instant) -> Result<()> {
    fd::write_all(
        channel.as_raw_fd(),
        bytes,
        deadline.min(Instant::now() + Duration::from_secs(1)),
    )
}

pub(super) fn service(context: &mut Context, packet: OwnedFd) -> Result<()> {
    if context.binding.profile != Profile::ProductNetwork || context.binding.role != Role::Service {
        return Err(invalid());
    }
    prepare_resolver()?;
    let topology = prepare_service_topology()?;
    let mut records = bootstraps(context)?;
    let mut children = Children {
        packet: Some(packet),
        ..Children::default()
    };
    let result = (|| {
        context.status(Status::TopologyReady)?;
        let listener = topology.into_listener();
        let (parent, child) = pair()?;
        child.set_nonblocking(true)?;
        children.spawn(
            ENDPOINT,
            &["endpoint".into()],
            &[(listener.as_raw_fd(), 3), (child.as_raw_fd(), 4)],
        )?;
        children.endpoint_control = Some(parent);
        drop(child);
        drop(listener);
        service_loop(context, &mut records, &mut children)
    })();
    match result {
        Ok(waits) => {
            children.drop_channels();
            drop(children);
            context.product_reaped(waits)?;
            context.cancelled()
        }
        Err(error) => {
            children.abort()?;
            Err(error)
        }
    }
}

fn spawn_bootstrapped(
    children: &mut Children,
    role: usize,
    name: &str,
    context: &Context,
    bytes: &mut Option<Zeroizing<Vec<u8>>>,
) -> Result<UnixStream> {
    let (parent, child) = pair()?;
    children.spawn(
        role,
        &[
            name.into(),
            context.binding.vm_id.to_string(),
            context.binding.generation.to_string(),
        ],
        &[(child.as_raw_fd(), 4)],
    )?;
    drop(child);
    let bytes = bytes.take().ok_or_else(invalid)?;
    write(&parent, bytes.as_ref(), context.deadline)?;
    Ok(parent)
}

fn spawn_adapter(children: &mut Children) -> Result<()> {
    let (parent, child) = pair()?;
    child.set_nonblocking(true)?;
    let (worker, adapter) = pair()?;
    adapter.set_nonblocking(true)?;
    children.spawn(
        ADAPTER,
        &["adapter".into()],
        &[
            (children.packet.as_ref().ok_or_else(invalid)?.as_raw_fd(), 3),
            (adapter.as_raw_fd(), 4),
            (child.as_raw_fd(), 5),
        ],
    )?;
    children.adapter_control = Some(parent);
    children.network = Some(worker);
    Ok(())
}

fn service_loop(
    context: &mut Context,
    records: &mut Bootstraps,
    children: &mut Children,
) -> Result<[i32; 4]> {
    let prepare_deadline = context.deadline.min(Instant::now() + PREPARE);
    let mut progress = Progress::new();
    let mut endpoint_line = LineReader::new();
    let mut broker_line = LineReader::new();
    let mut worker_line = LineReader::new();
    let mut adapter_closed = false;
    let mut observe_deadline = None;
    let mut cancel_deadline = None;
    loop {
        if Instant::now() >= context.deadline {
            return Err(invalid());
        }
        // Sample owned waits first, but validate them only after draining the
        // corresponding status streams below. A child can write its terminal
        // marker and exit between any nonblocking read and a subsequent poll;
        // read-then-poll alone would spuriously reject that valid ordering.
        // A newly observed exit in the next iteration receives a fresh drain.
        let mut observed_waits = [None; 4];
        for (role, observed) in observed_waits.iter_mut().enumerate() {
            *observed = children.observe(role)?;
        }
        let endpoint = children
            .endpoint_control
            .as_ref()
            .ok_or_else(invalid)?
            .as_raw_fd();
        while let Some(message) = endpoint_line.read(endpoint)? {
            if message == ENDPOINT_READY_MESSAGE {
                progress.advance(Stage::Endpoint, Stage::BrokerPrepared)?;
                context.status(Status::EndpointReady)?;
                children.broker_control = Some(spawn_bootstrapped(
                    children,
                    BROKER,
                    "broker",
                    context,
                    &mut records.broker,
                )?);
            } else if message == ENDPOINT_COMPLETED_MESSAGE {
                progress.endpoint_complete()?;
            } else {
                return Err(invalid());
            }
        }
        if endpoint_line.closed && !progress.endpoint_completed {
            return Err(invalid());
        }

        // This startup reader stops at Ready. The exact same endpoint becomes
        // authenticated broker IPC: PID1 never reads it after handing it off.
        if matches!(progress.stage, Stage::BrokerPrepared | Stage::BrokerReady) {
            let channel = children.broker_control.as_ref().ok_or_else(invalid)?;
            if let Some(message) = broker_line.read(channel.as_raw_fd())? {
                if message == egress_broker::EGRESS_BROKER_PREPARED_MESSAGE {
                    progress.advance(Stage::BrokerPrepared, Stage::BrokerReady)?;
                    context.status(Status::BrokerPrepared)?;
                    write(
                        channel,
                        egress_broker::EGRESS_BROKER_CONFINE_MESSAGE,
                        context.deadline,
                    )?;
                } else if message == egress_broker::EGRESS_BROKER_READY_MESSAGE {
                    progress.advance(Stage::BrokerReady, Stage::WorkerPrepared)?;
                    context.status(Status::BrokerReady)?;
                    children.worker_control = Some(spawn_bootstrapped(
                        children,
                        WORKER,
                        "worker",
                        context,
                        &mut records.worker,
                    )?);
                } else {
                    return Err(invalid());
                }
            }
            if broker_line.closed {
                return Err(invalid());
            }
        }
        if let Some(channel) = &children.worker_control {
            while let Some(message) = worker_line.read(channel.as_raw_fd())? {
                if message == network_worker::WORKER_PREPARED_MESSAGE {
                    progress.advance(Stage::WorkerPrepared, Stage::WorkerBrokerReady)?;
                    let broker = children.broker_control.take().ok_or_else(invalid)?;
                    network_worker::send_worker_broker_descriptor(
                        channel.as_raw_fd(),
                        broker.as_raw_fd(),
                    )?;
                    drop(broker);
                    progress.broker_transferred = true;
                } else if message == network_worker::WORKER_BROKER_READY_MESSAGE {
                    progress.advance(Stage::WorkerBrokerReady, Stage::Adapter)?;
                    context.status(Status::WorkerBrokerReady)?;
                    // Spawn after this read loop to avoid borrowing the live
                    // ingress/control stream across mutation of child owners.
                } else if message == network_worker::WORKER_READY_MESSAGE {
                    progress.advance(Stage::WorkerReady, Stage::Running)?;
                    context.status(Status::WorkerReady)?;
                } else {
                    return Err(invalid());
                }
            }
        }
        if progress.stage == Stage::Adapter && children.children[ADAPTER].is_none() {
            spawn_adapter(children)?;
        }
        // Consume completion bytes before validating the sampled owned wait.
        // Only this specifically completed exit0 is allowed before cancellation.
        if let Some(raw) = observed_waits[ENDPOINT] {
            progress.exited(ENDPOINT, raw)?;
        }
        if progress.publish_endpoint() {
            context.status(Status::EndpointCompleted)?;
        }

        if !adapter_closed && let Some(channel) = &children.adapter_control {
            loop {
                let mut byte = [0];
                match fd::read_some(channel.as_raw_fd(), &mut byte) {
                    Ok(1) if byte[0] == process::ADAPTER_PREPARED => {
                        progress.advance(Stage::Adapter, Stage::Start)?;
                        context.status(Status::Prepared)?;
                    }
                    Ok(1) => {
                        progress.adapter_terminal(byte[0])?;
                        if byte[0] == process::ADAPTER_CHAR_EOF && !progress.eof_decided {
                            observe_deadline = None;
                            progress.eof_decided = true;
                            context.status(Status::EofObserved)?;
                        }
                    }
                    Ok(0) if progress.adapter_terminal.is_some() => {
                        adapter_closed = true;
                        break;
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) =>
                    {
                        break;
                    }
                    _ => return Err(invalid()),
                }
            }
        }
        // Raw37/72 are allowed before Cancel only after an armed *actual*
        // character EOF, never merely because the no-EOF observation expired.
        // They remain withheld from the reaped receipt until admitted Cancel.
        if worker_line.closed && !progress.closure_admitted() {
            return Err(invalid());
        }
        for role in [ADAPTER, WORKER, BROKER] {
            if let Some(raw) = observed_waits[role] {
                progress.exited(role, raw)?;
            }
        }

        if observe_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            observe_deadline = None;
            progress.eof_decided = true;
            context.status(Status::NoEofObserved)?;
        }
        if let Some(control) = context.read_control()? {
            match control {
                Control::Start => {
                    progress.advance(Stage::Start, Stage::WorkerReady)?;
                    if !progress.broker_transferred || children.broker_control.is_some() {
                        return Err(invalid());
                    }
                    network_worker::send_worker_network_descriptor(
                        children
                            .worker_control
                            .as_ref()
                            .ok_or_else(invalid)?
                            .as_raw_fd(),
                        children.network.as_ref().ok_or_else(invalid)?.as_raw_fd(),
                    )?;
                    drop(children.network.take());
                    drop(children.packet.take());
                    write(
                        children.adapter_control.as_ref().ok_or_else(invalid)?,
                        &[process::ADAPTER_GO],
                        context.deadline,
                    )?;
                }
                Control::ObserveEof => {
                    progress.observe_eof()?;
                    context.status(Status::EofArmed)?;
                    observe_deadline = Some(Instant::now() + Duration::from_secs(2));
                }
                Control::Cancel => {
                    progress.cancel()?;
                    let deadline = context.deadline.min(Instant::now() + CANCEL);
                    cancel_deadline = Some(deadline);
                    if children.broker_control.is_some()
                        || children.network.is_some()
                        || children.packet.is_some()
                    {
                        return Err(invalid());
                    }
                    if progress.adapter_terminal.is_none() {
                        write(
                            children.adapter_control.as_ref().ok_or_else(invalid)?,
                            &[process::ADAPTER_STOP],
                            deadline,
                        )?;
                    }
                    drop(children.worker_control.take());
                    progress.ingress_closed = true;
                }
                _ => return Err(invalid()),
            }
        }
        if Instant::now() >= context.deadline
            || (progress.stage != Stage::Running && Instant::now() >= prepare_deadline)
            || cancel_deadline.is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(invalid());
        }
        if progress.cancelled
            && let Some(waits) = progress.final_waits()?
        {
            return Ok(waits);
        }
        let mut polls = vec![fd::pollfd(context.control.as_raw_fd(), libc::POLLIN)];
        if !endpoint_line.closed {
            polls.push(fd::pollfd(endpoint, libc::POLLIN));
        }
        if matches!(progress.stage, Stage::BrokerPrepared | Stage::BrokerReady)
            && let Some(channel) = &children.broker_control
        {
            polls.push(fd::pollfd(channel.as_raw_fd(), libc::POLLIN));
        }
        if !worker_line.closed
            && let Some(channel) = &children.worker_control
        {
            polls.push(fd::pollfd(channel.as_raw_fd(), libc::POLLIN));
        }
        if !adapter_closed && let Some(channel) = &children.adapter_control {
            polls.push(fd::pollfd(channel.as_raw_fd(), libc::POLLIN));
        }
        fd::poll(
            &mut polls,
            context
                .deadline
                .min(Instant::now() + Duration::from_millis(20)),
        )?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running() -> Progress {
        let mut p = Progress::new();
        for (before, after) in [
            (Stage::Endpoint, Stage::BrokerPrepared),
            (Stage::BrokerPrepared, Stage::BrokerReady),
            (Stage::BrokerReady, Stage::WorkerPrepared),
            (Stage::WorkerPrepared, Stage::WorkerBrokerReady),
            (Stage::WorkerBrokerReady, Stage::Adapter),
            (Stage::Adapter, Stage::Start),
            (Stage::Start, Stage::WorkerReady),
            (Stage::WorkerReady, Stage::Running),
        ] {
            p.advance(before, after).unwrap();
        }
        p.broker_transferred = true;
        p.endpoint_complete().unwrap();
        p.exited(ENDPOINT, 0).unwrap();
        assert!(p.publish_endpoint());
        p
    }

    #[test]
    fn preparation_rejects_skipped_duplicate_and_early_start_steps() {
        let mut p = Progress::new();
        assert!(p.advance(Stage::Start, Stage::WorkerReady).is_err());
        assert!(
            p.advance(Stage::WorkerPrepared, Stage::WorkerBrokerReady)
                .is_err()
        );
        p.advance(Stage::Endpoint, Stage::BrokerPrepared).unwrap();
        assert!(p.advance(Stage::Endpoint, Stage::BrokerPrepared).is_err());
        assert!(p.cancel().is_err());
        assert!(p.endpoint_complete().is_err());
    }

    #[test]
    fn endpoint_completion_is_consumed_before_reap_and_published_after_host_ready() {
        let mut p = Progress::new();
        p.stage = Stage::WorkerReady;
        assert!(p.exited(ENDPOINT, 0).is_err());
        p.endpoint_complete().unwrap();
        assert!(p.endpoint_complete().is_err());
        assert!(p.exited(ENDPOINT, 70 << 8).is_err());
        p.exited(ENDPOINT, 0).unwrap();
        assert!(!p.publish_endpoint());
        p.advance(Stage::WorkerReady, Stage::Running).unwrap();
        assert!(p.publish_endpoint());
        assert!(!p.publish_endpoint());
    }

    #[test]
    fn no_eof_timeout_does_not_admit_worker_or_broker_exit() {
        let mut p = running();
        p.observe_eof().unwrap();
        p.eof_decided = true;
        for role in [WORKER, BROKER] {
            assert!(p.exited(role, EXPECTED_WAITS[role]).is_err());
        }
        assert!(p.final_waits().is_err());
        assert!(p.adapter_terminal(process::ADAPTER_UNIX_EOF).is_err());
        assert!(p.adapter_terminal(process::ADAPTER_CANCELLED).is_err());
    }

    #[test]
    fn actual_armed_eof_allows_early_exits_but_not_a_precancel_receipt() {
        let mut p = running();
        assert!(p.adapter_terminal(process::ADAPTER_CHAR_EOF).is_err());
        p.observe_eof().unwrap();
        p.adapter_terminal(process::ADAPTER_CHAR_EOF).unwrap();
        p.eof_decided = true;
        for role in [WORKER, ADAPTER, BROKER] {
            p.exited(role, EXPECTED_WAITS[role]).unwrap();
        }
        assert!(p.final_waits().is_err());
        p.cancel().unwrap();
        assert!(p.final_waits().is_err());
        p.ingress_closed = true;
        assert_eq!(p.final_waits().unwrap(), Some(EXPECTED_WAITS));
    }

    #[test]
    fn cancellation_requires_all_facts_and_exact_nonsignal_waits() {
        let mut p = running();
        assert!(p.cancel().is_err());
        p.observe_eof().unwrap();
        p.eof_decided = true;
        p.cancel().unwrap();
        assert!(p.cancel().is_err());
        assert!(p.exited(WORKER, EXPECTED_WAITS[WORKER]).is_err());
        p.ingress_closed = true;
        p.adapter_terminal(process::ADAPTER_CANCELLED).unwrap();
        for role in [WORKER, ADAPTER, BROKER] {
            for raw in [-1, libc::SIGKILL, 70 << 8] {
                assert!(p.exited(role, raw).is_err());
            }
            p.exited(role, EXPECTED_WAITS[role]).unwrap();
        }
        assert_eq!(p.final_waits().unwrap(), Some(EXPECTED_WAITS));
    }

    #[test]
    fn resolver_validation_rejects_wrong_bytes_permissions_and_aliases() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resolv.conf");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(RESOLVER).unwrap();
        let owner = unsafe { libc::geteuid() };
        check_resolver(&mut file, &path, owner).unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(check_resolver(&mut file, &path, owner).is_err());
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        let alias = directory.path().join("alias");
        fs::hard_link(&path, &alias).unwrap();
        assert!(check_resolver(&mut file, &path, owner).is_err());
        fs::remove_file(alias).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"nameserver 127.0.0.2\n").unwrap();
        assert!(check_resolver(&mut file, &path, owner).is_err());
    }
}
