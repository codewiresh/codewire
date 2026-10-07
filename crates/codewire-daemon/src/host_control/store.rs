use std::collections::BTreeMap;
use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use codewire_daemon_proto::daemon::v1;
use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{Error, Mutation, Receipt, Scope, canonical_uuid, valid_sha256};

#[cfg(test)]
mod tests;

const DIRECTORY: &str = "host-control";
const SCHEMA: &str = "codewire.host-control-book/v1";
const MAX_GRANTS: usize = 128;
const MAX_REQUESTS: usize = 1024;
const MAX_BOOK_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 20;
const LAUNCH_STAGES: &str = "launch-stages";
const MAX_SESSION_METADATA_BYTES: usize = 128 * 1024;

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LaunchCut {
    Created,
    OutputSynced,
    MetadataSynced,
    Published,
    ParentSynced,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    scope: Scope,
    verbs: Vec<i32>,
    revoked: bool,
}

impl Grant {
    fn to_wire(&self) -> v1::HostControlGrant {
        v1::HostControlGrant {
            grant_id: self.scope.grant_id.clone(),
            environment_id: self.scope.environment_id.clone(),
            org_id: self.scope.org_id.clone(),
            network_id: self.scope.network_id.clone(),
            caller_key: self.scope.caller_key.to_vec(),
            target_key: self.scope.target_key.to_vec(),
            verbs: self.verbs.clone(),
            revision: self.scope.grant_revision,
            revoked: self.revoked,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Book {
    schema: String,
    environment_id: String,
    generation: u64,
    previous_sha256: Option<String>,
    grant_revision: u64,
    #[serde(deserialize_with = "unique_map")]
    grants: BTreeMap<String, Grant>,
    #[serde(deserialize_with = "unique_map")]
    requests: BTreeMap<String, Receipt>,
}

fn unique_map<'de, D, V>(deserializer: D) -> Result<BTreeMap<String, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    struct Visitor<V>(std::marker::PhantomData<V>);
    impl<'de, V: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<V> {
        type Value = BTreeMap<String, V>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded map without duplicate keys")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut values = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, V>()? {
                if values.len() >= MAX_REQUESTS || values.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate or excessive entry"));
                }
            }
            Ok(values)
        }
    }
    deserializer.deserialize_map(Visitor(std::marker::PhantomData))
}

impl Book {
    fn empty(environment_id: &str) -> Self {
        Self {
            schema: SCHEMA.into(),
            environment_id: environment_id.into(),
            generation: 0,
            previous_sha256: None,
            grant_revision: 0,
            grants: BTreeMap::new(),
            requests: BTreeMap::new(),
        }
    }

    fn validate(&self, environment_id: &str) -> Result<(), Error> {
        if self.schema != SCHEMA
            || self.environment_id != environment_id
            || self.generation == 0
            || self.grants.len() > MAX_GRANTS
            || self.requests.len() > MAX_REQUESTS
        {
            return Err(Error::Storage);
        }
        canonical_uuid(&self.environment_id).map_err(|_| Error::Storage)?;
        match (&self.previous_sha256, self.generation) {
            (None, 1) => {}
            (Some(value), 2..) => valid_sha256(value).map_err(|_| Error::Storage)?,
            _ => return Err(Error::Storage),
        }
        for (id, grant) in &self.grants {
            grant.scope.validate().map_err(|_| Error::Storage)?;
            if id != &grant.scope.grant_id
                || grant.scope.environment_id != environment_id
                || grant.scope.grant_revision > self.grant_revision
            {
                return Err(Error::Storage);
            }
            validate_verbs(&grant.verbs).map_err(|_| Error::Storage)?;
        }
        for (id, receipt) in &self.requests {
            receipt.origin.validate().map_err(|_| Error::Storage)?;
            if id != &receipt.origin.request_id
                || receipt.origin.scope.environment_id != environment_id
                || receipt.generation == 0
                || !matches!(
                    v1::HostControlVerb::try_from(receipt.verb),
                    Ok(v1::HostControlVerb::Launch
                        | v1::HostControlVerb::Input
                        | v1::HostControlVerb::Stop
                        | v1::HostControlVerb::ManagedLaunch
                        | v1::HostControlVerb::ManagedMessage
                        | v1::HostControlVerb::ManagedSteer
                        | v1::HostControlVerb::ManagedInterrupt
                        | v1::HostControlVerb::ManagedStop
                        | v1::HostControlVerb::ManagedRestart)
                )
                || v1::HostControlRequestPhase::try_from(receipt.phase).is_err()
                || receipt.phase == v1::HostControlRequestPhase::Unspecified as i32
                || v1::SessionLifecycleState::try_from(receipt.session_state).is_err()
                || !valid_reason(&receipt.reason)
                || (receipt.input_acknowledged
                    && (!super::managed::is_input(receipt.verb)
                        || receipt.phase != v1::HostControlRequestPhase::Completed as i32))
            {
                return Err(Error::Storage);
            }
            if super::managed::is_managed(receipt.verb) {
                super::canonical_uuid(&receipt.driver_id).map_err(|_| Error::Storage)?;
                if receipt.session_id != format!("session-{}", receipt.driver_id)
                    || receipt.requested_generation == 0
                {
                    return Err(Error::Storage);
                }
                if super::managed::is_input(receipt.verb)
                    && receipt.message_id != receipt.origin.request_id
                {
                    return Err(Error::Storage);
                }
                if (receipt.verb == v1::HostControlVerb::ManagedLaunch as i32
                    && (!receipt.message_id.is_empty()
                        && receipt.message_id != receipt.origin.request_id
                        || receipt.requested_generation != 1))
                    || (matches!(receipt.verb, 9 | 10) && !receipt.message_id.is_empty())
                {
                    return Err(Error::Storage);
                }
                if !receipt.message_id.is_empty() {
                    super::canonical_uuid(&receipt.message_id).map_err(|_| Error::Storage)?;
                }
                let next = receipt.requested_generation.checked_add(1);
                if receipt.generation != receipt.requested_generation
                    && !(receipt.verb == v1::HostControlVerb::ManagedRestart as i32
                        && Some(receipt.generation) == next
                        && matches!(
                            v1::HostControlRequestPhase::try_from(receipt.phase),
                            Ok(v1::HostControlRequestPhase::Completed
                                | v1::HostControlRequestPhase::Unknown)
                        ))
                {
                    return Err(Error::Storage);
                }
                if receipt.verb == v1::HostControlVerb::ManagedRestart as i32
                    && receipt.phase == v1::HostControlRequestPhase::Completed as i32
                    && Some(receipt.generation) != next
                {
                    return Err(Error::Storage);
                }
            } else if !receipt.driver_id.is_empty() || !receipt.message_id.is_empty() {
                return Err(Error::Storage);
            }
            let phase =
                v1::HostControlRequestPhase::try_from(receipt.phase).map_err(|_| Error::Storage)?;
            let state = v1::SessionLifecycleState::try_from(receipt.session_state)
                .map_err(|_| Error::Storage)?;
            let initial = state == v1::SessionLifecycleState::Unspecified
                && receipt.exit_code.is_none()
                && !receipt.input_acknowledged;
            match phase {
                v1::HostControlRequestPhase::Pending | v1::HostControlRequestPhase::Issued => {
                    if !initial
                        || receipt.cleanup_unknown
                        || receipt.reason
                            != if phase == v1::HostControlRequestPhase::Pending {
                                "pending"
                            } else {
                                "issued"
                            }
                    {
                        return Err(Error::Storage);
                    }
                }
                v1::HostControlRequestPhase::Rejected => {
                    if !initial
                        || receipt.cleanup_unknown
                        || !matches!(
                            receipt.reason.as_str(),
                            "invalid_request"
                                | "grant_or_origin_refused"
                                | "identity_or_revision_conflict"
                                | "capacity_exhausted"
                                | "storage_unknown"
                                | "owner_closed"
                                | "generation_or_process_unavailable"
                        )
                    {
                        return Err(Error::Storage);
                    }
                }
                v1::HostControlRequestPhase::Completed => {
                    if receipt.cleanup_unknown
                        || matches!(
                            state,
                            v1::SessionLifecycleState::Unspecified
                                | v1::SessionLifecycleState::Starting
                                | v1::SessionLifecycleState::Stopping
                        )
                        || (super::managed::is_stop(receipt.verb)
                            && state == v1::SessionLifecycleState::Running)
                        || receipt.input_acknowledged != super::managed::is_input(receipt.verb)
                        || receipt.reason
                            != if receipt.input_acknowledged {
                                "input_acknowledged"
                            } else {
                                "completed"
                            }
                    {
                        return Err(Error::Storage);
                    }
                }
                v1::HostControlRequestPhase::Unknown => {
                    if !receipt.cleanup_unknown
                        || receipt.input_acknowledged
                        || !matches!(
                            receipt.reason.as_str(),
                            "effect_unknown" | "recovered_unknown" | "cleanup_unknown"
                        )
                    {
                        return Err(Error::Storage);
                    }
                }
                _ => return Err(Error::Storage),
            }
            super::session_id(&receipt.session_id).map_err(|_| Error::Storage)?;
            let grant = self
                .grants
                .get(&receipt.origin.scope.grant_id)
                .ok_or(Error::Storage)?;
            if !grant.scope.same_principal(&receipt.origin.scope)
                || receipt.origin.scope.grant_revision > grant.scope.grant_revision
                || (super::managed::is_launch(receipt.verb)
                    && receipt.session_id != format!("session-{id}"))
            {
                return Err(Error::Storage);
            }
        }
        Ok(())
    }
}

fn valid_reason(value: &str) -> bool {
    matches!(
        value,
        "pending"
            | "issued"
            | "completed"
            | "input_acknowledged"
            | "effect_unknown"
            | "recovered_unknown"
            | "invalid_request"
            | "grant_or_origin_refused"
            | "identity_or_revision_conflict"
            | "capacity_exhausted"
            | "storage_unknown"
            | "owner_closed"
            | "generation_or_process_unavailable"
            | "cleanup_unknown"
    )
}

fn validate_verbs(verbs: &[i32]) -> Result<(), Error> {
    if verbs.is_empty()
        || verbs.len() > 11
        || !verbs.windows(2).all(|pair| pair[0] < pair[1])
        || verbs.iter().any(|verb| {
            !matches!(
                v1::HostControlVerb::try_from(*verb),
                Ok(v1::HostControlVerb::Read
                    | v1::HostControlVerb::Launch
                    | v1::HostControlVerb::Input
                    | v1::HostControlVerb::Stop
                    | v1::HostControlVerb::ManagedLaunch
                    | v1::HostControlVerb::ManagedMessage
                    | v1::HostControlVerb::ManagedSteer
                    | v1::HostControlVerb::ManagedInterrupt
                    | v1::HostControlVerb::ManagedStop
                    | v1::HostControlVerb::ManagedRestart
                    | v1::HostControlVerb::ManagedRead)
            )
        })
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl Identity {
    fn regular(metadata: &Metadata) -> Result<Self, Error> {
        // SAFETY: geteuid reads the process identity.
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() > MAX_BOOK_BYTES
        {
            return Err(Error::Storage);
        }
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            len: metadata.len(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

struct DirectoryPin {
    file: File,
    path: PathBuf,
    identity: (u64, u64),
    leaf: bool,
}

impl DirectoryPin {
    fn admit(file: File, path: PathBuf, leaf: bool) -> Result<Self, Error> {
        let metadata = file.metadata().map_err(|_| Error::Storage)?;
        Self::validate(&path, &metadata, leaf)?;
        Ok(Self {
            file,
            path,
            identity: (metadata.dev(), metadata.ino()),
            leaf,
        })
    }
    fn validate(path: &Path, metadata: &Metadata, leaf: bool) -> Result<(), Error> {
        // SAFETY: geteuid reads the process identity.
        let uid = unsafe { libc::geteuid() };
        let sticky_tmp =
            path == Path::new("/tmp") && metadata.uid() == 0 && metadata.mode() & 0o7777 == 0o1777;
        if !metadata.is_dir()
            || (!matches!(metadata.uid(), 0) && metadata.uid() != uid)
            || (!sticky_tmp && metadata.mode() & 0o022 != 0)
            || (leaf && (metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700))
        {
            return Err(Error::Storage);
        }
        Ok(())
    }
    fn check(&self) -> Result<(), Error> {
        let held = self.file.metadata().map_err(|_| Error::Storage)?;
        let named = std::fs::symlink_metadata(&self.path).map_err(|_| Error::Storage)?;
        Self::validate(&self.path, &held, self.leaf)?;
        Self::validate(&self.path, &named, self.leaf)?;
        if (held.dev(), held.ino()) != self.identity || (named.dev(), named.ino()) != self.identity
        {
            return Err(Error::Storage);
        }
        Ok(())
    }
}

struct Snapshot {
    name: String,
    generation: u64,
    file: File,
    identity: Identity,
    digest: String,
}

pub(super) struct Store {
    pins: Vec<DirectoryPin>,
    lock: File,
    lock_identity: Identity,
    snapshots: Vec<Snapshot>,
    book: Book,
    poisoned: bool,
    #[cfg(test)]
    pub fail_next_publication: bool,
    #[cfg(test)]
    pub fail_next_finish: bool,
    #[cfg(test)]
    pub launch_cut: Option<LaunchCut>,
    #[cfg(test)]
    pub crash_at_cut: bool,
}

impl Store {
    pub fn open(state_root: &Path, environment_id: &str) -> Result<Self, Error> {
        canonical_uuid(environment_id)?;
        if !state_root.is_absolute()
            || std::fs::canonicalize(state_root).map_err(|_| Error::Storage)? != state_root
        {
            return Err(Error::Storage);
        }
        let mut pins = Vec::new();
        let root_fd = rustix::fs::open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::Storage)?;
        pins.push(DirectoryPin::admit(
            root_fd.into(),
            PathBuf::from("/"),
            false,
        )?);
        let mut path = PathBuf::from("/");
        for part in state_root.components() {
            match part {
                Component::RootDir => continue,
                Component::Normal(name) => {
                    path.push(name);
                    let fd = rustix::fs::openat(
                        &pins.last().ok_or(Error::Storage)?.file,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_| Error::Storage)?;
                    pins.push(DirectoryPin::admit(
                        fd.into(),
                        path.clone(),
                        path == state_root,
                    )?);
                }
                _ => return Err(Error::Storage),
            }
        }
        let state = &pins.last().ok_or(Error::Storage)?.file;
        match rustix::fs::mkdirat(state, DIRECTORY, Mode::from_raw_mode(0o700)) {
            Ok(()) => rustix::fs::fsync(state).map_err(|_| Error::Storage)?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err(Error::Storage),
        }
        let fd = rustix::fs::openat(
            state,
            DIRECTORY,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::Storage)?;
        pins.push(DirectoryPin::admit(
            fd.into(),
            state_root.join(DIRECTORY),
            true,
        )?);
        let directory = &pins.last().ok_or(Error::Storage)?.file;
        let lock_fd = match rustix::fs::openat(
            directory,
            "owner.lock",
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => {
                rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o600)).map_err(|_| Error::Storage)?;
                rustix::fs::fsync(&fd).map_err(|_| Error::Storage)?;
                rustix::fs::fsync(directory).map_err(|_| Error::Storage)?;
                fd
            }
            Err(rustix::io::Errno::EXIST) => rustix::fs::openat(
                directory,
                "owner.lock",
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Error::Storage)?,
            Err(_) => return Err(Error::Storage),
        };
        let lock: File = lock_fd.into();
        let lock_identity = Identity::regular(&lock.metadata().map_err(|_| Error::Storage)?)?;
        // SAFETY: flock operates on this owned descriptor, never a saved PID.
        if lock_identity.len != 0
            || unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
        {
            return Err(Error::Storage);
        }
        let mut snapshots = Vec::new();
        let mut books = BTreeMap::new();
        let entries = std::fs::read_dir(state_root.join(DIRECTORY)).map_err(|_| Error::Storage)?;
        for (count, entry) in entries.enumerate() {
            if count >= MAX_DIRECTORY_ENTRIES {
                return Err(Error::Storage);
            }
            let name = entry
                .map_err(|_| Error::Storage)?
                .file_name()
                .into_string()
                .map_err(|_| Error::Storage)?;
            if name == "owner.lock" {
                continue;
            }
            if name == LAUNCH_STAGES {
                let stages = open_private_directory(directory, LAUNCH_STAGES)?;
                check_stages(&stages, &state_root.join(DIRECTORY).join(LAUNCH_STAGES))?;
                continue;
            }
            if let Some(raw) = name
                .strip_prefix(".txn-")
                .and_then(|v| v.strip_suffix(".tmp"))
            {
                canonical_uuid(raw).map_err(|_| Error::Storage)?;
                // Interrupted private stages are preserved. They confer no
                // admission and are never removed using filename authority.
                let _ = read_leaf(directory, &name)?;
                continue;
            }
            let generation = snapshot_generation(&name)?;
            if snapshots.len() >= 3 {
                return Err(Error::Storage);
            }
            let (file, identity, bytes) = read_leaf(directory, &name)?;
            let book: Book = serde_json::from_slice(&bytes).map_err(|_| Error::Storage)?;
            book.validate(environment_id)?;
            if book.generation != generation || books.insert(generation, book).is_some() {
                return Err(Error::Storage);
            }
            snapshots.push(Snapshot {
                name,
                generation,
                file,
                identity,
                digest: format!("{:x}", Sha256::digest(&bytes)),
            });
        }
        snapshots.sort_by_key(|entry| entry.generation);
        for pair in snapshots.windows(2) {
            let next = books.get(&pair[1].generation).ok_or(Error::Storage)?;
            if pair[0].generation.checked_add(1) != Some(pair[1].generation)
                || next.previous_sha256.as_deref() != Some(&pair[0].digest)
            {
                return Err(Error::Storage);
            }
        }
        if snapshots.len() == 1 && snapshots[0].generation != 1 {
            return Err(Error::Storage);
        }
        let book = books
            .pop_last()
            .map(|(_, book)| book)
            .unwrap_or_else(|| Book::empty(environment_id));
        let mut store = Self {
            pins,
            lock,
            lock_identity,
            snapshots,
            book,
            poisoned: false,
            #[cfg(test)]
            fail_next_publication: false,
            #[cfg(test)]
            fail_next_finish: false,
            #[cfg(test)]
            launch_cut: None,
            #[cfg(test)]
            crash_at_cut: false,
        };
        store.check()?;
        // A crash after NOREPLACE and before pruning may retain three complete
        // adjacent snapshots. First fsync the admitted latest name, then prune
        // only the verified oldest inode before another publication.
        if store.snapshots.len() > 2 {
            rustix::fs::fsync(store.directory()).map_err(|_| Error::Storage)?;
            store.prune_snapshots()?;
        }
        if store.book.generation == 0 {
            store.publish(store.book.clone())?;
        } else if store.book.requests.values().any(Receipt::unsettled) {
            let mut next = store.book.clone();
            for receipt in next.requests.values_mut().filter(|v| v.unsettled()) {
                receipt.phase = v1::HostControlRequestPhase::Unknown as i32;
                receipt.reason = "recovered_unknown".into();
                receipt.cleanup_unknown = true;
                receipt.input_acknowledged = false;
            }
            store.publish(next)?;
        }
        Ok(store)
    }

    fn directory(&self) -> &File {
        &self
            .pins
            .last()
            .expect("store holds private directory")
            .file
    }
    fn check(&self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Storage);
        }
        for pin in &self.pins {
            pin.check()?;
        }
        check_leaf(
            self.directory(),
            "owner.lock",
            &self.lock,
            self.lock_identity,
        )?;
        for snapshot in &self.snapshots {
            check_leaf(
                self.directory(),
                &snapshot.name,
                &snapshot.file,
                snapshot.identity,
            )?;
        }
        self.check_stage_bindings()?;
        Ok(())
    }

    fn check_stage_bindings(&self) -> Result<(), Error> {
        let fd = match rustix::fs::openat(
            self.directory(),
            LAUNCH_STAGES,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(()),
            Err(_) => return Err(Error::Storage),
        };
        let stages = File::from(fd);
        let path = self
            .pins
            .last()
            .ok_or(Error::Storage)?
            .path
            .join(LAUNCH_STAGES);
        check_stages(&stages, &path)?;
        for entry in std::fs::read_dir(path).map_err(|_| Error::Storage)? {
            let name = entry
                .map_err(|_| Error::Storage)?
                .file_name()
                .into_string()
                .map_err(|_| Error::Storage)?;
            let request_id = name.strip_prefix("session-").ok_or(Error::Storage)?;
            let receipt = self.book.requests.get(request_id).ok_or(Error::Storage)?;
            if receipt.session_id != name
                || !super::managed::is_launch(receipt.verb)
                || !matches!(
                    v1::HostControlRequestPhase::try_from(receipt.phase),
                    Ok(v1::HostControlRequestPhase::Issued | v1::HostControlRequestPhase::Unknown)
                )
            {
                return Err(Error::Storage);
            }
            let stage = open_private_directory(&stages, &name)?;
            match rustix::fs::statat(&stage, "session.json", AtFlags::SYMLINK_NOFOLLOW) {
                Ok(_) => {
                    let (_, _, bytes) = read_leaf(&stage, "session.json")?;
                    crate::durable_session::SessionEngine::admit_host_control_stage(
                        &bytes,
                        &receipt.origin,
                    )?;
                }
                Err(rustix::io::Errno::NOENT) => {}
                Err(_) => return Err(Error::Storage),
            }
        }
        Ok(())
    }

    fn publish(&mut self, mut next: Book) -> Result<(), Error> {
        self.check()?;
        next.generation = self.book.generation.checked_add(1).ok_or(Error::Capacity)?;
        next.previous_sha256 = self.snapshots.last().map(|v| v.digest.clone());
        next.validate(&self.book.environment_id)?;
        let bytes = serde_json::to_vec(&next).map_err(|_| Error::Storage)?;
        if bytes.len() as u64 > MAX_BOOK_BYTES {
            return Err(Error::Capacity);
        }
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_publication) {
            return Err(Error::Storage);
        }
        let name = format!("book-{:020}.json", next.generation);
        let temporary = format!(".txn-{}.tmp", Uuid::new_v4());
        let fd = rustix::fs::openat(
            self.directory(),
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| Error::Storage)?;
        let mut file: File = fd.into();
        rustix::fs::fchmod(&file, Mode::from_raw_mode(0o600)).map_err(|_| Error::Storage)?;
        let original = Identity::regular(&file.metadata().map_err(|_| Error::Storage)?)?;
        let publication = (|| {
            file.write_all(&bytes).map_err(|_| Error::Storage)?;
            file.sync_all().map_err(|_| Error::Storage)?;
            let identity = Identity::regular(&file.metadata().map_err(|_| Error::Storage)?)?;
            if (identity.dev, identity.ino) != (original.dev, original.ino)
                || identity.len != bytes.len() as u64
            {
                return Err(Error::Storage);
            }
            check_leaf(self.directory(), &temporary, &file, identity)?;
            self.check()?;
            rustix::fs::renameat_with(
                self.directory(),
                &temporary,
                self.directory(),
                &name,
                RenameFlags::NOREPLACE,
            )
            .map_err(|_| Error::Storage)?;
            rustix::fs::fsync(self.directory()).map_err(|_| Error::Storage)?;
            let identity = Identity::regular(&file.metadata().map_err(|_| Error::Storage)?)?;
            check_leaf(self.directory(), &name, &file, identity)?;
            Ok(identity)
        })();
        let identity = match publication {
            Ok(identity) => identity,
            Err(error) => {
                // Remove only this still-private exact inode. An uncertain
                // published entry or foreign replacement is retained.
                if let Ok(metadata) = file.metadata()
                    && let Ok(identity) = Identity::regular(&metadata)
                    && (identity.dev, identity.ino) == (original.dev, original.ino)
                    && check_leaf(self.directory(), &temporary, &file, identity).is_ok()
                {
                    let _ = rustix::fs::unlinkat(self.directory(), &temporary, AtFlags::empty());
                }
                self.poisoned = true;
                return Err(error);
            }
        };
        self.book = next;
        self.snapshots.push(Snapshot {
            name,
            generation: self.book.generation,
            file,
            identity,
            digest: format!("{:x}", Sha256::digest(&bytes)),
        });
        self.prune_snapshots()
    }

    fn prune_snapshots(&mut self) -> Result<(), Error> {
        while self.snapshots.len() > 2 {
            let old = &self.snapshots[0];
            if check_leaf(self.directory(), &old.name, &old.file, old.identity).is_err()
                || rustix::fs::unlinkat(self.directory(), &old.name, AtFlags::empty()).is_err()
                || rustix::fs::fsync(self.directory()).is_err()
            {
                self.poisoned = true;
                return Err(Error::Storage);
            }
            self.snapshots.remove(0);
        }
        Ok(())
    }

    pub fn authorize(&self, scope: &Scope, verb: v1::HostControlVerb) -> Result<(), Error> {
        self.check()?;
        scope.validate()?;
        if scope.environment_id != self.book.environment_id {
            return Err(Error::Denied);
        }
        let grant = self.book.grants.get(&scope.grant_id).ok_or(Error::Denied)?;
        if grant.revoked || grant.scope != *scope || !grant.verbs.contains(&(verb as i32)) {
            return Err(Error::Denied);
        }
        Ok(())
    }

    /// Publish a whole complete session, never a half-created directory in the
    /// legacy session inventory. A failed unpublished stage remains evidence
    /// only: no code recovers a stage into a new process admission.
    pub fn publish_session(&self, request: &Mutation, metadata: &[u8]) -> Result<(), Error> {
        self.check()?;
        let receipt = self
            .book
            .requests
            .get(&request.request_id)
            .ok_or(Error::Conflict)?;
        if receipt.origin != request.origin()
            || !super::managed::is_launch(receipt.verb)
            || receipt.phase != v1::HostControlRequestPhase::Issued as i32
            || metadata.len() > MAX_SESSION_METADATA_BYTES
        {
            return Err(Error::Conflict);
        }
        let state_root = &self.pins[self.pins.len() - 2].file;
        let sessions = open_private_directory(state_root, "sessions")?;
        match rustix::fs::mkdirat(self.directory(), LAUNCH_STAGES, Mode::from_raw_mode(0o700)) {
            Ok(()) => rustix::fs::fsync(self.directory()).map_err(|_| Error::Storage)?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err(Error::Storage),
        }
        let stages = open_private_directory(self.directory(), LAUNCH_STAGES)?;
        let path = self
            .pins
            .last()
            .ok_or(Error::Storage)?
            .path
            .join(LAUNCH_STAGES);
        check_stages(&stages, &path)?;
        rustix::fs::mkdirat(&stages, &receipt.session_id, Mode::from_raw_mode(0o700))
            .map_err(|_| Error::Storage)?;
        let stage = open_private_directory(&stages, &receipt.session_id)?;
        let identity = directory_identity(&stage)?;
        #[cfg(test)]
        self.cut(LaunchCut::Created)?;
        write_stage_leaf(&stage, "output.bin", &[])?;
        #[cfg(test)]
        self.cut(LaunchCut::OutputSynced)?;
        write_stage_leaf(&stage, "session.json", metadata)?;
        rustix::fs::fsync(&stage).map_err(|_| Error::Storage)?;
        rustix::fs::fsync(&stages).map_err(|_| Error::Storage)?;
        #[cfg(test)]
        self.cut(LaunchCut::MetadataSynced)?;
        self.check()?;
        if directory_identity(&open_private_directory(&stages, &receipt.session_id)?)? != identity {
            return Err(Error::Storage);
        }
        rustix::fs::renameat_with(
            &stages,
            &receipt.session_id,
            &sessions,
            &receipt.session_id,
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| Error::Storage)?;
        #[cfg(test)]
        self.cut(LaunchCut::Published)?;
        // Both names and the entire complete directory must be durable before
        // start_process is reachable.
        rustix::fs::fsync(&sessions).map_err(|_| Error::Storage)?;
        rustix::fs::fsync(&stages).map_err(|_| Error::Storage)?;
        #[cfg(test)]
        self.cut(LaunchCut::ParentSynced)?;
        if directory_identity(&stage)? != identity
            || directory_identity(&open_private_directory(&sessions, &receipt.session_id)?)?
                != identity
        {
            return Err(Error::Storage);
        }
        Ok(())
    }

    pub fn grants(&self) -> Result<v1::HostControlGrantsResponse, Error> {
        self.check()?;
        Ok(v1::HostControlGrantsResponse {
            environment_id: self.book.environment_id.clone(),
            book_revision: self.book.grant_revision,
            grants: self.book.grants.values().map(Grant::to_wire).collect(),
        })
    }

    pub fn put_grant(
        &mut self,
        request: v1::HostControlPutGrantRequest,
    ) -> Result<v1::HostControlGrantsResponse, Error> {
        self.check()?;
        if request.expected_book_revision != self.book.grant_revision {
            return Err(Error::Conflict);
        }
        let value = request.grant.ok_or(Error::Invalid)?;
        let mut verbs = value.verbs;
        verbs.sort_unstable();
        validate_verbs(&verbs)?;
        if value.revoked {
            return Err(Error::Invalid);
        }
        let mut scope = Scope::from_wire(v1::HostControlScope {
            environment_id: value.environment_id,
            org_id: value.org_id,
            network_id: value.network_id,
            caller_key: value.caller_key,
            target_key: value.target_key,
            grant_id: value.grant_id,
            expected_grant_revision: value.revision.max(1),
        })?;
        if scope.environment_id != self.book.environment_id {
            return Err(Error::Denied);
        }
        scope.grant_revision = match self.book.grants.get(&scope.grant_id) {
            Some(old) => {
                if !old.scope.same_principal(&scope) || old.scope.grant_revision != value.revision {
                    return Err(Error::Conflict);
                }
                old.scope
                    .grant_revision
                    .checked_add(1)
                    .ok_or(Error::Capacity)?
            }
            None => {
                if value.revision != 0 {
                    return Err(Error::Conflict);
                }
                if self.book.grants.len() >= MAX_GRANTS {
                    return Err(Error::Capacity);
                }
                1
            }
        };
        let mut next = self.book.clone();
        next.grant_revision = next.grant_revision.checked_add(1).ok_or(Error::Capacity)?;
        next.grants.insert(
            scope.grant_id.clone(),
            Grant {
                scope,
                verbs,
                revoked: false,
            },
        );
        self.publish(next)?;
        self.grants()
    }

    pub fn revoke_grant(
        &mut self,
        request: v1::HostControlRevokeGrantRequest,
    ) -> Result<v1::HostControlGrantsResponse, Error> {
        self.check()?;
        canonical_uuid(&request.grant_id)?;
        if request.expected_book_revision != self.book.grant_revision {
            return Err(Error::Conflict);
        }
        let mut next = self.book.clone();
        let grant = next
            .grants
            .get_mut(&request.grant_id)
            .ok_or(Error::Denied)?;
        if grant.scope.grant_revision != request.expected_grant_revision
            || request.expected_grant_revision == 0
        {
            return Err(Error::Conflict);
        }
        grant.scope.grant_revision = grant
            .scope
            .grant_revision
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        grant.revoked = true;
        next.grant_revision = next.grant_revision.checked_add(1).ok_or(Error::Capacity)?;
        self.publish(next)?;
        self.grants()
    }

    pub fn find(&self, request_id: &str) -> Result<Option<Receipt>, Error> {
        self.check()?;
        Ok(self.book.requests.get(request_id).cloned())
    }

    pub fn register(&mut self, request: &Mutation) -> Result<Receipt, Error> {
        self.authorize(&request.scope, request.verb())?;
        if self.book.requests.len() >= MAX_REQUESTS {
            return Err(Error::Capacity);
        }
        if self.book.requests.contains_key(&request.request_id) {
            return Err(Error::Conflict);
        }
        let receipt = Receipt::pending(request);
        let mut next = self.book.clone();
        next.requests
            .insert(request.request_id.clone(), receipt.clone());
        self.publish(next)?;
        Ok(receipt)
    }

    pub fn issue(&mut self, request: &Mutation) -> Result<Receipt, Error> {
        self.authorize(&request.scope, request.verb())?;
        let mut next = self.book.clone();
        let receipt = next
            .requests
            .get_mut(&request.request_id)
            .ok_or(Error::Conflict)?;
        if receipt.origin != request.origin()
            || receipt.phase != v1::HostControlRequestPhase::Pending as i32
        {
            return Err(Error::Conflict);
        }
        receipt.phase = v1::HostControlRequestPhase::Issued as i32;
        receipt.reason = "issued".into();
        let result = receipt.clone();
        self.publish(next)?;
        Ok(result)
    }

    pub fn finish(
        &mut self,
        request: &Mutation,
        outcome: Result<v1::SessionRecord, Error>,
    ) -> Result<Receipt, Error> {
        self.check()?;
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_finish) {
            return Err(Error::Storage);
        }
        let mut next = self.book.clone();
        let receipt = next
            .requests
            .get_mut(&request.request_id)
            .ok_or(Error::Conflict)?;
        if receipt.origin != request.origin() || !receipt.unsettled() {
            return Err(Error::Conflict);
        }
        match outcome {
            Ok(record) => {
                if receipt.phase != v1::HostControlRequestPhase::Issued as i32
                    || record.session_id != receipt.session_id
                    || record.launch_generation
                        != if request.verb() == v1::HostControlVerb::ManagedRestart {
                            receipt
                                .requested_generation
                                .checked_add(1)
                                .ok_or(Error::Conflict)?
                        } else {
                            receipt.generation
                        }
                {
                    return Err(Error::Conflict);
                }
                receipt.phase = if record.cleanup_unknown {
                    v1::HostControlRequestPhase::Unknown
                } else {
                    v1::HostControlRequestPhase::Completed
                } as i32;
                receipt.session_state = record.state;
                receipt.generation = record.launch_generation;
                receipt.exit_code = record.exit_code;
                receipt.cleanup_unknown = record.cleanup_unknown;
                receipt.input_acknowledged =
                    super::managed::is_input(request.verb() as i32) && !record.cleanup_unknown;
                receipt.reason = if record.cleanup_unknown {
                    "cleanup_unknown"
                } else if receipt.input_acknowledged {
                    "input_acknowledged"
                } else {
                    "completed"
                }
                .into();
            }
            Err(error) => {
                if receipt.phase == v1::HostControlRequestPhase::Issued as i32 {
                    receipt.phase = v1::HostControlRequestPhase::Unknown as i32;
                    receipt.reason = "effect_unknown".into();
                    receipt.cleanup_unknown = true;
                } else {
                    receipt.phase = v1::HostControlRequestPhase::Rejected as i32;
                    receipt.reason = error.reason().into();
                }
            }
        }
        let result = receipt.clone();
        self.publish(next)?;
        Ok(result)
    }

    #[cfg(test)]
    fn cut(&self, cut: LaunchCut) -> Result<(), Error> {
        if self.launch_cut == Some(cut) {
            if self.crash_at_cut {
                // Deliberate abrupt death only in the exact isolated test
                // helper: no monitor/process has been spawned at these cuts.
                unsafe {
                    libc::_exit(77);
                }
            }
            return Err(Error::Storage);
        }
        Ok(())
    }
}

fn snapshot_generation(name: &str) -> Result<u64, Error> {
    let raw = name
        .strip_prefix("book-")
        .and_then(|v| v.strip_suffix(".json"))
        .ok_or(Error::Storage)?;
    if raw.len() != 20 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Storage);
    }
    let generation = raw.parse::<u64>().map_err(|_| Error::Storage)?;
    if generation == 0 || format!("{generation:020}") != raw {
        return Err(Error::Storage);
    }
    Ok(generation)
}

fn read_leaf(directory: &File, name: &str) -> Result<(File, Identity, Vec<u8>), Error> {
    let fd = rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::Storage)?;
    let mut file: File = fd.into();
    let identity = Identity::regular(&file.metadata().map_err(|_| Error::Storage)?)?;
    let mut bytes = Vec::with_capacity(identity.len as usize);
    (&mut file)
        .take(MAX_BOOK_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Storage)?;
    if bytes.len() as u64 != identity.len {
        return Err(Error::Storage);
    }
    check_leaf(directory, name, &file, identity)?;
    Ok((file, identity, bytes))
}

fn check_leaf(directory: &File, name: &str, file: &File, identity: Identity) -> Result<(), Error> {
    let held = Identity::regular(&file.metadata().map_err(|_| Error::Storage)?)?;
    let fd = rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::Storage)?;
    let named = Identity::regular(&File::from(fd).metadata().map_err(|_| Error::Storage)?)?;
    if held != identity || named != identity {
        return Err(Error::Storage);
    }
    Ok(())
}

fn directory_identity(file: &File) -> Result<(u64, u64), Error> {
    let metadata = file.metadata().map_err(|_| Error::Storage)?;
    // SAFETY: geteuid reads the process identity.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(Error::Storage);
    }
    Ok((metadata.dev(), metadata.ino()))
}

fn open_private_directory(parent: &File, name: &str) -> Result<File, Error> {
    let fd = rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::Storage)?;
    let file: File = fd.into();
    directory_identity(&file)?;
    Ok(file)
}

fn write_stage_leaf(directory: &File, name: &str, bytes: &[u8]) -> Result<(), Error> {
    let fd = rustix::fs::openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| Error::Storage)?;
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o600)).map_err(|_| Error::Storage)?;
    let mut file: File = fd.into();
    file.write_all(bytes).map_err(|_| Error::Storage)?;
    file.sync_all().map_err(|_| Error::Storage)?;
    let identity = Identity::regular(&file.metadata().map_err(|_| Error::Storage)?)?;
    if identity.len != bytes.len() as u64 {
        return Err(Error::Storage);
    }
    check_leaf(directory, name, &file, identity)
}

fn check_stages(directory: &File, path: &Path) -> Result<(), Error> {
    let identity = directory_identity(directory)?;
    let named = std::fs::symlink_metadata(path).map_err(|_| Error::Storage)?;
    if !named.is_dir() || (named.dev(), named.ino()) != identity {
        return Err(Error::Storage);
    }
    for (count, entry) in std::fs::read_dir(path)
        .map_err(|_| Error::Storage)?
        .enumerate()
    {
        if count >= MAX_REQUESTS {
            return Err(Error::Capacity);
        }
        let name = entry
            .map_err(|_| Error::Storage)?
            .file_name()
            .into_string()
            .map_err(|_| Error::Storage)?;
        super::session_id(&name).map_err(|_| Error::Storage)?;
        let stage = open_private_directory(directory, &name)?;
        let stage_path = path.join(&name);
        let mut entries = 0;
        for item in std::fs::read_dir(&stage_path).map_err(|_| Error::Storage)? {
            entries += 1;
            if entries > 2 {
                return Err(Error::Storage);
            }
            let leaf = item
                .map_err(|_| Error::Storage)?
                .file_name()
                .into_string()
                .map_err(|_| Error::Storage)?;
            if !matches!(leaf.as_str(), "session.json" | "output.bin") {
                return Err(Error::Storage);
            }
            let (_, identity, _) = read_leaf(&stage, &leaf)?;
            if (leaf == "output.bin" && identity.len != 0)
                || (leaf == "session.json" && identity.len > MAX_SESSION_METADATA_BYTES as u64)
            {
                return Err(Error::Storage);
            }
        }
    }
    if directory_identity(directory)? != identity {
        return Err(Error::Storage);
    }
    Ok(())
}
