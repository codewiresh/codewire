//! Fixed Linux ordinary-user CW selection inside an existing platform Pod.
//!
//! This role never resolves CLI/provider configuration, replaces a daemon or
//! admits a managed credential helper. The service owns authority, the original
//! Pod channel and its Issued journal checkpoint. This role owns only bounded
//! ordinary-user file effects. Its Store is writable by the same UID; generation
//! CAS is not an atomic compare of every observed field or a tamper boundary.

mod fs;
mod launcher;

pub use launcher::redirect_from;
mod wire;

#[cfg(test)]
mod tests;

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::time::{Duration, Instant};

use codewire_cw_release::identity::{CwPayloadIdentity, Platform, canonical_json};
use codewire_cw_release::store::{self, Admission, Candidate, EntryState, Store, StoreError};

use self::fs::{Dir, FileId, HeldFile, Paths, Tree};
pub(crate) use self::wire::{Action, Reply, ReplyBody, Request, SelectionExpectation};
use self::wire::{BoundedInput, BoundedOutput, Code, Correlation, Outcome};

pub(crate) const ROLE: &str = "__platform-cw-runtime";
const ROLE_BUDGET: Duration = Duration::from_secs(120);
const LOCK_BUDGET: Duration = Duration::from_secs(10);
const JOB: &str = "job.json";
const JOB_TEMP: &str = ".job.tmp";
const COPY_BYTES: usize = 64 * 1024;

type Result<T> = std::result::Result<T, Code>;

/// The binary calls this before creating an async runtime or loading settings.
/// The sole argument after argv[0] is the fixed role; data arrives on stdin.
pub fn run_from<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString>,
{
    let args: Vec<_> = args.into_iter().map(Into::into).take(4).collect();
    if args.len() != 2 || args[1] != ROLE || user() != (1000, 1000) {
        return 2;
    }
    // This is an early, single-threaded private process. The alarm also bounds
    // file syscalls which a userspace stdin deadline cannot interrupt. Death
    // after any possible effect yields no receipt and is Unknown to the owner.
    if arm_deadline(ROLE_BUDGET.as_secs() as u32 + 1).is_err() {
        return 2;
    }
    let deadline = Instant::now() + ROLE_BUDGET;
    let mut input = match BoundedInput::stdin(deadline) {
        Ok(input) => input,
        Err(_) => return 2,
    };
    let request = match wire::read_request(&mut input) {
        Ok(request) => request,
        Err(_) => return 2,
    };
    let correlation = request.correlation();
    let mut engine = Engine::new(Paths::fixed(), deadline);
    let result = engine.execute(&request, &mut input);
    let reply = match result {
        Ok(body) => Reply::new(correlation, Outcome::Succeeded { result: body }),
        Err(code) if engine.effects_started => Reply::new(correlation, Outcome::Unknown { code }),
        Err(code) => Reply::new(correlation, Outcome::Refused { code }),
    };
    let exit = reply.exit_code();
    match BoundedOutput::stdout(deadline).and_then(|mut out| wire::write_reply(&mut out, &reply)) {
        Ok(()) => exit,
        Err(_) => 4,
    }
}

fn user() -> (u32, u32) {
    // SAFETY: these queries have no pointer arguments or effects.
    unsafe { (libc::geteuid(), libc::getegid()) }
}

fn arm_deadline(seconds: u32) -> Result<()> {
    // Ignored dispositions and blocked masks survive exec. The private role
    // must not inherit an ineffective alarm from its launcher. This runs only
    // at the early, single-threaded role boundary, before file effects.
    // SAFETY: both initialized signal sets/action remain live during these
    // fixed Linux calls; no handler or pointer escapes this function.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = libc::SIG_DFL;
        let mut unblocked: libc::sigset_t = std::mem::zeroed();
        if libc::sigemptyset(&raw mut action.sa_mask) != 0
            || libc::sigaction(libc::SIGALRM, &raw const action, std::ptr::null_mut()) != 0
            || libc::sigemptyset(&raw mut unblocked) != 0
            || libc::sigaddset(&raw mut unblocked, libc::SIGALRM) != 0
            || libc::sigprocmask(
                libc::SIG_UNBLOCK,
                &raw const unblocked,
                std::ptr::null_mut(),
            ) != 0
        {
            return Err(Code::Io);
        }
        libc::alarm(seconds);
    }
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
struct Slot {
    identity: CwPayloadIdentity,
    file: FileId,
    state: SlotState,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
enum SlotState {
    Receiving,
    Ready,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
struct Job {
    schema_version: u32,
    correlation: Correlation,
    directory: FileId,
    bootstrap: Option<Slot>,
    candidate: Option<Slot>,
}

impl Job {
    fn new(correlation: Correlation, directory: &Dir) -> Result<Self> {
        Ok(Self {
            schema_version: 1,
            correlation,
            directory: directory.id()?,
            bootstrap: None,
            candidate: None,
        })
    }

    fn read(directory: &Dir, correlation: &Correlation) -> Result<Self> {
        let data = directory.read(JOB, wire::MAX_JSON, 0o400)?;
        let job: Self = serde_json::from_slice(&data).map_err(|_| Code::UnsafeState)?;
        if job.schema_version != 1
            || job.correlation != *correlation
            || job.directory != directory.id()?
            || canonical_json(&job).map_err(|_| Code::UnsafeState)? != data
        {
            return Err(Code::UnsafeState);
        }
        for slot in [&job.bootstrap, &job.candidate].into_iter().flatten() {
            wire::identity(&slot.identity)?;
        }
        Ok(job)
    }

    fn write(&self, directory: &Dir) -> Result<()> {
        if self.directory != directory.id()? {
            return Err(Code::UnsafeState);
        }
        directory.atomic_json(JOB, JOB_TEMP, self)
    }
}

struct Engine {
    paths: Paths,
    deadline: Instant,
    effects_started: bool,
    #[cfg(test)]
    image_fixture: Option<(PathBuf, CwPayloadIdentity)>,
    #[cfg(test)]
    before_bootstrap_publication: Option<Box<dyn FnOnce() -> Result<()> + Send>>,
    #[cfg(test)]
    before_bootstrap_selection: Option<Box<dyn FnOnce() -> Result<()> + Send>>,
}

impl Engine {
    fn new(paths: Paths, deadline: Instant) -> Self {
        Self {
            paths,
            deadline,
            effects_started: false,
            #[cfg(test)]
            image_fixture: None,
            #[cfg(test)]
            before_bootstrap_publication: None,
            #[cfg(test)]
            before_bootstrap_selection: None,
        }
    }

    fn budget(&self) -> Result<()> {
        if Instant::now() >= self.deadline {
            Err(Code::Deadline)
        } else {
            Ok(())
        }
    }

    fn execute(&mut self, request: &Request, input: &mut impl Read) -> Result<ReplyBody> {
        request.validate()?;
        self.budget()?;
        if !matches!(request.action, Action::Stage { .. }) {
            wire::require_eof(input)?;
        }
        if matches!(request.action, Action::Status) {
            return self.status();
        }
        // Admit the known original role before ordinary-user mutations. A GNU
        // build, missing provenance or unknown record cannot become image A.
        let (mut image, image_identity) = self.image()?;
        match &request.action {
            Action::Bootstrap { identity, expected } => {
                if *identity != image_identity {
                    return Err(Code::UnsupportedImage);
                }
                self.bootstrap(request, expected, identity, &mut image)
            }
            Action::Stage { identity, expected } => self.stage(request, expected, identity, input),
            Action::Update { identity, expected } => self.update(request, expected, identity),
            Action::Rollback { identity, expected } => self.rollback(expected, identity),
            Action::Cleanup {
                bootstrap,
                candidate,
            } => self.cleanup(request, bootstrap, candidate),
            Action::Status => unreachable!(),
        }
    }

    fn image(&self) -> Result<(File, CwPayloadIdentity)> {
        #[cfg(test)]
        if let Some((path, identity)) = &self.image_fixture {
            let mut file = HeldFile::open(path, identity.size, 0o500)?.into_file();
            crate::build_record::admit_incoming(&mut file, path, identity, host()?)
                .map_err(|_| Code::UnsupportedImage)?;
            return Ok((file, identity.clone()));
        }
        let decoded = crate::build_record::embedded().map_err(|_| Code::UnsupportedImage)?;
        let identity = crate::build_record::executable_identity(
            &decoded,
            &crate::build_record::BUILD_RECORD,
            Path::new("/proc/self/exe"),
            host()?,
        )
        .map_err(|_| Code::UnsupportedImage)?;
        wire::identity(&identity).map_err(|_| Code::UnsupportedImage)?;
        // The original image path is fixed. No managed-entry/PATH resolution or
        // arbitrary incoming executable is used to choose the service's role.
        if std::fs::read_link("/proc/self/exe").map_err(|_| Code::UnsupportedImage)?
            != Path::new("/codewire/bin/cw")
        {
            return Err(Code::UnsupportedImage);
        }
        // Intentional kernel self-image seam, held throughout admission/copy.
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/proc/self/exe")
            .map_err(|_| Code::UnsupportedImage)?;
        let metadata = file.metadata().map_err(|_| Code::UnsupportedImage)?;
        use std::os::unix::fs::MetadataExt as _;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o6022 != 0 {
            return Err(Code::UnsupportedImage);
        }
        crate::build_record::admit_incoming(
            &mut file,
            Path::new("/proc/self/exe"),
            &identity,
            host()?,
        )
        .map_err(|_| Code::UnsupportedImage)?;
        Ok((file, identity))
    }

    fn status(&self) -> Result<ReplyBody> {
        let bootstrap = self.image().ok().map(|(_, identity)| identity);
        let tree = Tree::open(&self.paths, false)?;
        let _lock = tree.read_lock(self.deadline)?;
        let selection = snapshot(&tree, &self.paths)?;
        Ok(ReplyBody::Status {
            supported_image: bootstrap.is_some(),
            bootstrap,
            selection: Box::new(selection),
        })
    }

    fn preflight(&self, expected: &SelectionExpectation) -> Result<()> {
        let tree = Tree::open(&self.paths, false)?;
        tree.require_writable_parents()?;
        require_selection(&snapshot(&tree, &self.paths)?, expected)
    }

    fn mutation_tree(&mut self) -> Result<Tree> {
        // Parent creation, lock publication and stage IO are effects even when
        // selection has not yet changed. Never label their uncertain outcome a
        // proven no-effect refusal.
        self.effects_started = true;
        Tree::open(&self.paths, true)
    }

    fn bootstrap(
        &mut self,
        request: &Request,
        expected: &SelectionExpectation,
        identity: &CwPayloadIdentity,
        image: &mut File,
    ) -> Result<ReplyBody> {
        self.preflight(expected)?;
        let tree = self.mutation_tree()?;
        let _lock = tree.mutation_lock(self.deadline)?;
        require_selection(&snapshot(&tree, &self.paths)?, expected)?;
        let directory = tree.new_job(&request.correlation())?;
        let mut job = Job::new(request.correlation(), &directory)?;
        job.write(&directory)?;
        image.seek(SeekFrom::Start(0)).map_err(|_| Code::Io)?;
        let source_before = fs::Stamp::of(image)?;
        self.receive_slot(&directory, &mut job, true, identity, image, false)?;
        if fs::Stamp::of(image)? != source_before {
            return Err(Code::CandidateRefused);
        }
        let candidate = candidate(&directory, true, identity)?;
        tree.check()?;
        self.budget()?;
        require_selection(&snapshot(&tree, &self.paths)?, expected)?;
        #[cfg(test)]
        if let Some(pause) = self.before_bootstrap_publication.take() {
            pause()?;
        }
        // General install deliberately permits selecting in an existing Store.
        // Bootstrap is stricter: never adopt a racing writer's root/entry, and
        // use generation CAS even between our new root and initial selection.
        let store = Store::create(&self.paths.store, &self.paths.entry, LOCK_BUDGET)
            .map_err(store_error)?;
        tree.check()?;
        self.budget()?;
        #[cfg(test)]
        if let Some(pause) = self.before_bootstrap_selection.take() {
            pause()?;
        }
        let (_, selected) = store
            .publish_and_select(&candidate, Some(0))
            .map_err(store_error)?;
        tree.check()?;
        selected_reply(&store, expected, identity, &selected)
    }

    fn stage(
        &mut self,
        request: &Request,
        expected: &SelectionExpectation,
        identity: &CwPayloadIdentity,
        input: &mut impl Read,
    ) -> Result<ReplyBody> {
        self.preflight(expected)?;
        let tree = self.mutation_tree()?;
        let _lock = tree.mutation_lock(self.deadline)?;
        require_selection(&snapshot(&tree, &self.paths)?, expected)?;
        let correlation = request.correlation();
        let (directory, mut job) = match tree.existing_job(&correlation)? {
            Some(directory) => {
                let job = Job::read(&directory, &correlation)?;
                if job
                    .bootstrap
                    .as_ref()
                    .is_none_or(|v| v.state != SlotState::Ready)
                    || job.candidate.is_some()
                {
                    return Err(Code::StageExists);
                }
                validate_slot(&directory, true, job.bootstrap.as_ref().expect("checked"))?;
                (directory, job)
            }
            None => {
                let directory = tree.new_job(&correlation)?;
                let job = Job::new(correlation, &directory)?;
                job.write(&directory)?;
                (directory, job)
            }
        };
        self.receive_slot(&directory, &mut job, false, identity, input, true)?;
        tree.check()?;
        Ok(ReplyBody::Staged {
            sha256: identity.sha256.clone(),
            size: identity.size,
        })
    }

    fn receive_slot(
        &self,
        directory: &Dir,
        job: &mut Job,
        bootstrap: bool,
        identity: &CwPayloadIdentity,
        input: &mut impl Read,
        require_eof: bool,
    ) -> Result<()> {
        wire::identity(identity)?;
        let pending = slot_name(bootstrap, SlotState::Receiving);
        let mut file = directory.create_file(pending, 0o600)?;
        let slot = Slot {
            identity: identity.clone(),
            file: FileId::of(&file)?,
            state: SlotState::Receiving,
        };
        if bootstrap {
            job.bootstrap = Some(slot);
        } else {
            job.candidate = Some(slot);
        }
        job.write(directory)?;
        let mut remaining = identity.size;
        let mut buffer = vec![0_u8; COPY_BYTES];
        while remaining > 0 {
            self.budget()?;
            let wanted = remaining.min(buffer.len() as u64) as usize;
            input
                .read_exact(&mut buffer[..wanted])
                .map_err(|_| Code::InputIncomplete)?;
            file.write_all(&buffer[..wanted]).map_err(|_| Code::Io)?;
            remaining -= wanted as u64;
        }
        if require_eof {
            wire::require_eof(input)?;
        }
        file.sync_all().map_err(|_| Code::Io)?;
        crate::build_record::admit_incoming(
            &mut file,
            &directory.path().join(pending),
            identity,
            host()?,
        )
        .map_err(|_| Code::CandidateRefused)?;
        self.budget()?;
        directory.finish_file(
            pending,
            slot_name(bootstrap, SlotState::Ready),
            &file,
            0o500,
        )?;
        let slot = if bootstrap {
            &mut job.bootstrap
        } else {
            &mut job.candidate
        };
        slot.as_mut().expect("slot recorded").state = SlotState::Ready;
        job.write(directory)
    }

    fn update(
        &mut self,
        request: &Request,
        expected: &SelectionExpectation,
        identity: &CwPayloadIdentity,
    ) -> Result<ReplyBody> {
        self.preflight(expected)?;
        let tree = self.mutation_tree()?;
        let _lock = tree.mutation_lock(self.deadline)?;
        let directory = tree
            .existing_job(&request.correlation())?
            .ok_or(Code::MissingStage)?;
        let job = Job::read(&directory, &request.correlation())?;
        let slot = job.candidate.as_ref().ok_or(Code::MissingStage)?;
        if slot.identity != *identity || slot.state != SlotState::Ready {
            return Err(Code::CandidateRefused);
        }
        let _held = validate_slot(&directory, false, slot)?;
        let store = open_store(&tree, &self.paths)?.ok_or(Code::StaleSelection)?;
        require_selection(&store_snapshot(&store)?, expected)?;
        tree.check()?;
        self.budget()?;
        let (_, selected) = store
            .publish_and_select(
                &candidate(&directory, false, identity)?,
                Some(expected.generation),
            )
            .map_err(store_error)?;
        tree.check()?;
        selected_reply(&store, expected, identity, &selected)
    }

    fn rollback(
        &mut self,
        expected: &SelectionExpectation,
        identity: &CwPayloadIdentity,
    ) -> Result<ReplyBody> {
        self.preflight(expected)?;
        let tree = self.mutation_tree()?;
        let _lock = tree.mutation_lock(self.deadline)?;
        let store = open_store(&tree, &self.paths)?.ok_or(Code::StaleSelection)?;
        require_selection(&store_snapshot(&store)?, expected)?;
        let record = store.verify(&identity.sha256).map_err(store_error)?;
        if record.payload.as_ref() != Some(identity) {
            return Err(Code::CandidateRefused);
        }
        let executable = store.version_executable(&identity.sha256);
        let mut held = HeldFile::open(&executable, identity.size, 0o555)?;
        crate::build_record::admit_incoming(held.file_mut(), &executable, identity, host()?)
            .map_err(|_| Code::CandidateRefused)?;
        tree.check()?;
        self.budget()?;
        let selected = store
            .rollback(Some(&identity.sha256), Some(expected.generation))
            .map_err(store_error)?;
        held.check()?;
        tree.check()?;
        selected_reply(&store, expected, identity, &selected)
    }

    fn cleanup(
        &mut self,
        request: &Request,
        bootstrap: &Option<CwPayloadIdentity>,
        candidate: &Option<CwPayloadIdentity>,
    ) -> Result<ReplyBody> {
        let tree = Tree::open(&self.paths, false)?;
        let lock = tree.existing_mutation_lock(self.deadline)?;
        let Some(directory) = tree.existing_job(&request.correlation())? else {
            return Ok(ReplyBody::Cleaned);
        };
        // A request directory without its original coordination lock has lost
        // custody. Observation must not recreate that lock or delete the job.
        let _lock = lock.ok_or(Code::UnsafeState)?;
        let job = Job::read(&directory, &request.correlation())?;
        if job.bootstrap.as_ref().map(|v| &v.identity) != bootstrap.as_ref()
            || job.candidate.as_ref().map(|v| &v.identity) != candidate.as_ref()
        {
            return Err(Code::UnsafeState);
        }
        let mut members = vec![JOB];
        let manifest = directory.held_file(JOB, wire::MAX_JSON as u64, 0o400)?;
        let mut held = Vec::new();
        for (is_bootstrap, slot) in [(true, &job.bootstrap), (false, &job.candidate)] {
            if let Some(slot) = slot {
                let file = validate_slot(&directory, is_bootstrap, slot)?;
                members.push(slot_name(is_bootstrap, slot.state));
                held.push((slot_name(is_bootstrap, slot.state), file));
            }
        }
        directory.require_inventory(&members)?;
        tree.check()?;
        self.budget()?;
        self.effects_started = true;
        for (name, file) in held {
            directory.unlink_held(name, &file)?;
        }
        directory.unlink_held(JOB, &manifest)?;
        tree.remove_job(&request.correlation(), &directory)?;
        Ok(ReplyBody::Cleaned)
    }
}

fn slot_name(bootstrap: bool, state: SlotState) -> &'static str {
    match (bootstrap, state) {
        (true, SlotState::Receiving) => ".bootstrap.pending",
        (true, SlotState::Ready) => "bootstrap.cw",
        (false, SlotState::Receiving) => ".candidate.pending",
        (false, SlotState::Ready) => "candidate.cw",
    }
}

fn validate_slot(directory: &Dir, bootstrap: bool, slot: &Slot) -> Result<HeldFile> {
    wire::identity(&slot.identity)?;
    let name = slot_name(bootstrap, slot.state);
    let mode = match slot.state {
        SlotState::Receiving => 0o600,
        SlotState::Ready => 0o500,
    };
    let mut file = directory.held_file(name, slot.identity.size, mode)?;
    if file.id()? != slot.file {
        return Err(Code::UnsafeState);
    }
    if slot.state == SlotState::Ready {
        crate::build_record::admit_incoming(
            file.file_mut(),
            &directory.path().join(name),
            &slot.identity,
            host()?,
        )
        .map_err(|_| Code::CandidateRefused)?;
        file.check()?;
    }
    Ok(file)
}

fn candidate(directory: &Dir, bootstrap: bool, identity: &CwPayloadIdentity) -> Result<Candidate> {
    wire::identity(identity)?;
    Ok(Candidate {
        executable: directory
            .path()
            .join(slot_name(bootstrap, SlotState::Ready)),
        admission: Admission::Pinned {
            identity: identity.clone(),
            sha256: identity.sha256.clone(),
        },
    })
}

fn host() -> Result<Platform> {
    Platform::host().ok_or(Code::UnsupportedImage)
}

fn open_store(tree: &Tree, paths: &Paths) -> Result<Option<Store>> {
    let Some(directory) = tree.store()? else {
        return Ok(None);
    };
    let store = Store::open(&paths.store, LOCK_BUDGET).map_err(store_error)?;
    store.require_entry(&paths.entry).map_err(store_error)?;
    directory.check(false)?;
    tree.check()?;
    Ok(Some(store))
}

fn snapshot(tree: &Tree, paths: &Paths) -> Result<wire::ObservedSelection> {
    match open_store(tree, paths)? {
        Some(store) => store_snapshot(&store),
        None => {
            if tree.entry_present()? {
                return Err(Code::UnmanagedEntry);
            }
            Ok(wire::ObservedSelection::absent())
        }
    }
}

fn store_snapshot(store: &Store) -> Result<wire::ObservedSelection> {
    let status = store.status().map_err(store_error)?;
    let payload = |sha: &Option<String>| -> Result<Option<CwPayloadIdentity>> {
        let Some(sha) = sha else { return Ok(None) };
        let record = store.verify(sha).map_err(store_error)?;
        let identity = record.payload.ok_or(Code::UnsupportedImage)?;
        wire::identity(&identity)?;
        // The generic Store verifies its hash/header/record. Before projecting
        // provenance as a full CW identity, also compare the unique compiled
        // record in the held bytes, using this CLI's borrowed marker.
        let executable = store.version_executable(sha);
        let mut held = HeldFile::open(&executable, identity.size, 0o555)?;
        crate::build_record::admit_incoming(held.file_mut(), &executable, &identity, host()?)
            .map_err(|_| Code::CandidateRefused)?;
        held.check()?;
        Ok(Some(identity))
    };
    let current = payload(&status.current)?;
    let previous = payload(&status.previous)?;
    Ok(wire::ObservedSelection {
        generation: status.generation,
        current,
        previous,
        pending: status.pending.is_some(),
        consistent: status.consistent && matches!(status.entry_state, EntryState::Managed { .. }),
        retained_count: status.versions.len(),
    })
}

fn require_selection(
    observed: &wire::ObservedSelection,
    expected: &SelectionExpectation,
) -> Result<()> {
    if observed.pending {
        return Err(Code::PendingSelection);
    }
    if !observed.consistent
        || observed.generation != expected.generation
        || observed.current.as_ref().map(|v| &v.sha256) != expected.current.as_ref()
        || observed.previous.as_ref().map(|v| &v.sha256) != expected.previous.as_ref()
    {
        return Err(Code::StaleSelection);
    }
    Ok(())
}

fn selected_reply(
    store: &Store,
    prior: &SelectionExpectation,
    identity: &CwPayloadIdentity,
    selected: &store::Selected,
) -> Result<ReplyBody> {
    let changed = prior.current.as_deref() != Some(&identity.sha256);
    let generation = prior
        .generation
        .checked_add(u64::from(changed))
        .ok_or(Code::StaleSelection)?;
    let previous = if changed {
        &prior.current
    } else {
        &prior.previous
    };
    if selected.current != identity.sha256
        || selected.generation != generation
        || selected.previous != *previous
        || selected.changed != changed
    {
        return Err(Code::StaleSelection);
    }
    let actual = store_snapshot(store)?;
    require_selection(
        &actual,
        &SelectionExpectation {
            generation,
            current: Some(identity.sha256.clone()),
            previous: previous.clone(),
        },
    )?;
    if actual.current.as_ref() != Some(identity) {
        return Err(Code::CandidateRefused);
    }
    Ok(ReplyBody::Selected {
        sha256: selected.current.clone(),
        generation: selected.generation,
        previous_sha256: selected.previous.clone(),
        changed: selected.changed,
    })
}

fn store_error(error: StoreError) -> Code {
    match error {
        StoreError::GenerationMismatch { .. } => Code::StaleSelection,
        StoreError::NotWritable { .. } => Code::ReadOnly,
        StoreError::UnmanagedEntry { .. } | StoreError::ExternallyChanged { .. } => {
            Code::UnmanagedEntry
        }
        StoreError::LockTimeout(_) => Code::Deadline,
        _ => Code::UnsafeState,
    }
}
