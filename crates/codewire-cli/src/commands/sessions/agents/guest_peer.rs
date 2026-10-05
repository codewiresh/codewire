//! Guest-only custody of one managed provider and every process it leaves.
//!
//! The guest driver calls [`prepare`] to record an owner-private receipt whose
//! cleanup is unknown, then launches this same executable as `cw _agent-peer`.
//! That guardian proves it is the prepared driver's direct child, arms parent
//! death delivery, becomes a child subreaper and only then starts the provider
//! with the driver's native stdin, stdout and stderr inherited unchanged. It
//! never writes frames or chatter to native stdio; its diagnostics go to a
//! private journal beside the receipt.
//!
//! Driver death, SIGTERM/SIGINT/SIGHUP or provider exit starts family cleanup.
//! Repeated rounds bind each direct child's exact birth through a pidfd, signal
//! it, escalate to SIGKILL and reap, so detached and double-forked tools are
//! adopted and stopped as their parents die. The receipt becomes clean only
//! after `waitpid` reports `ECHILD`; anything less stays unknown and fences a
//! restart. Custody covers process descendants only: work handed to another
//! service is outside it, and SIGKILL of the guardian itself leaves the
//! receipt unknown.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

const RECEIPT_VERSION: u32 = 1;
const CURRENT_POINTER: &str = "peer-current.json";
/// Serializes custody preparation. Never held with another state lock.
const PREPARE_LOCK: &str = "peer.lock";
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const TERM_GRACE: Duration = Duration::from_secs(3);
const CLEANUP_DEADLINE: Duration = Duration::from_secs(30);
const MONITOR_INTERVAL: Duration = Duration::from_secs(1);
const CLEANUP_INTERVAL: Duration = Duration::from_millis(50);
const PERSIST_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const FINAL_PERSIST_ATTEMPTS: u32 = 20;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024;
const MAX_EVENT_BYTES: usize = 512;
const MAX_PEER_ERROR_BYTES: usize = 2 * 1024;
const MAX_TIMESTAMP_BYTES: usize = 64;
const STOP_SIGNALS: [(libc::c_int, &str); 3] = [
    (libc::SIGTERM, "SIGTERM"),
    (libc::SIGINT, "SIGINT"),
    (libc::SIGHUP, "SIGHUP"),
];

// ---------------------------------------------------------------------------
// Durable custody records
// ---------------------------------------------------------------------------

/// Immutable binding of one guardian instance to its conversation, session,
/// driver process birth and boot. `peer-current.json` holds the current one.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct PeerIdentity {
    pub(super) environment_id: String,
    pub(super) driver_id: String,
    pub(super) session_id: String,
    pub(super) instance_id: String,
    pub(super) driver_started_at: String,
    pub(super) boot_id: String,
    pub(super) driver_pid: u32,
    pub(super) driver_start_ticks: u64,
}

/// Per-instance custody state. It names processes only; provider launch
/// values never appear here.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct PeerReceipt {
    pub(super) version: u32,
    pub(super) identity: PeerIdentity,
    pub(super) guardian_pid: Option<u32>,
    pub(super) guardian_start_ticks: Option<u64>,
    pub(super) provider_pid: Option<u32>,
    pub(super) cleanup_unknown: bool,
    pub(super) finished_at: Option<String>,
    pub(super) exit_code: Option<i32>,
    pub(super) error: Option<String>,
}

impl PeerIdentity {
    /// Exact conversation binding plus a process birth from the current boot.
    fn validate(
        &self,
        environment_id: &str,
        driver_id: &str,
        session_id: &str,
    ) -> anyhow::Result<()> {
        validate_names(environment_id, driver_id, session_id)?;
        if self.environment_id != environment_id
            || self.driver_id != driver_id
            || self.session_id != session_id
        {
            anyhow::bail!("guest peer custody belongs to another conversation or session");
        }
        canonical_uuid(&self.instance_id)?;
        validate_timestamp(&self.driver_started_at)?;
        if !valid_pid(self.driver_pid) {
            anyhow::bail!("guest peer custody records an invalid driver process");
        }
        if self.boot_id != current_boot_id()? {
            anyhow::bail!(
                "guest peer custody was recorded during another boot; its cleanup is unknown"
            );
        }
        Ok(())
    }
}

impl PeerReceipt {
    fn unknown(identity: PeerIdentity) -> Self {
        Self {
            version: RECEIPT_VERSION,
            identity,
            guardian_pid: None,
            guardian_start_ticks: None,
            provider_pid: None,
            cleanup_unknown: true,
            finished_at: None,
            exit_code: None,
            error: None,
        }
    }

    fn clean(&self) -> bool {
        !self.cleanup_unknown && self.finished_at.is_some()
    }

    fn validate(&self, identity: &PeerIdentity) -> anyhow::Result<()> {
        let claimed = self.guardian_pid.is_some();
        let consistent = self.version == RECEIPT_VERSION
            && self.identity == *identity
            && claimed == self.guardian_start_ticks.is_some()
            && self.guardian_pid.is_none_or(valid_pid)
            && self
                .provider_pid
                .is_none_or(|pid| claimed && valid_pid(pid))
            && self.cleanup_unknown == self.finished_at.is_none()
            && (self.cleanup_unknown || claimed)
            && (self.exit_code.is_none() || !self.cleanup_unknown)
            && self
                .error
                .as_ref()
                .is_none_or(|error| error.len() <= MAX_PEER_ERROR_BYTES);
        if !consistent {
            anyhow::bail!("guest peer receipt does not match its custody instance");
        }
        if let Some(finished_at) = &self.finished_at {
            validate_timestamp(finished_at)?;
        }
        Ok(())
    }
}

/// Record a new guardian instance before anything is spawned. Refuses while the
/// current receipt is unknown, unfinished, mismatched or from another boot.
pub(super) fn prepare(
    dir: &Path,
    environment_id: &str,
    driver_id: &str,
    session_id: &str,
    driver_started_at: &str,
) -> anyhow::Result<PeerIdentity> {
    validate_names(environment_id, driver_id, session_id)?;
    validate_timestamp(driver_started_at)?;
    canonical_driver_dir(dir, driver_id)?;
    let _lock = StateLock::acquire(&dir.join(PREPARE_LOCK))?;
    require_clean_previous(dir, environment_id, driver_id, session_id)?;
    let driver_pid = std::process::id();
    let identity = PeerIdentity {
        environment_id: environment_id.to_owned(),
        driver_id: driver_id.to_owned(),
        session_id: session_id.to_owned(),
        instance_id: uuid::Uuid::new_v4().to_string(),
        driver_started_at: driver_started_at.to_owned(),
        boot_id: current_boot_id()?,
        driver_pid,
        driver_start_ticks: process_stat(driver_pid)
            .context("read the driver process birth")?
            .start_ticks,
    };
    let path = receipt_path(dir, &identity.instance_id)?;
    match fs::symlink_metadata(&path) {
        Ok(_) => anyhow::bail!(
            "guest peer instance {} already exists",
            identity.instance_id
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // The unknown receipt is durable before the pointer names it, and both
    // precede any guardian or provider process.
    write_private_json(&path, &PeerReceipt::unknown(identity.clone()))?;
    write_private_json(&dir.join(CURRENT_POINTER), &identity)?;
    Ok(identity)
}

/// The receipt named by the current pointer. An absent pointer is `None`; a
/// missing, mismatched or other-boot receipt is an error. Unknown stays unknown.
pub(super) fn current_receipt(
    dir: &Path,
    environment_id: &str,
    driver_id: &str,
    session_id: &str,
) -> anyhow::Result<Option<PeerReceipt>> {
    validate_names(environment_id, driver_id, session_id)?;
    canonical_driver_dir(dir, driver_id)?;
    let Some(identity) = read_optional::<PeerIdentity>(&dir.join(CURRENT_POINTER))? else {
        return Ok(None);
    };
    identity.validate(environment_id, driver_id, session_id)?;
    read_receipt(dir, &identity).map(Some)
}

/// [`current_receipt`], refusing custody whose cleanup is not proven.
pub(super) fn require_clean_previous(
    dir: &Path,
    environment_id: &str,
    driver_id: &str,
    session_id: &str,
) -> anyhow::Result<Option<PeerReceipt>> {
    let receipt = current_receipt(dir, environment_id, driver_id, session_id)?;
    if let Some(receipt) = &receipt
        && !receipt.clean()
    {
        anyhow::bail!("previous guest peer cleanup is unknown; restart is fenced");
    }
    Ok(receipt)
}

pub(super) fn read_receipt(dir: &Path, identity: &PeerIdentity) -> anyhow::Result<PeerReceipt> {
    identity.validate(
        &identity.environment_id,
        &identity.driver_id,
        &identity.session_id,
    )?;
    canonical_driver_dir(dir, &identity.driver_id)?;
    let receipt: PeerReceipt = read_record(&receipt_path(dir, &identity.instance_id)?)
        .context("guest peer receipt is missing or unreadable")?;
    receipt.validate(identity)?;
    Ok(receipt)
}

/// Ask the exact recorded guardian birth to clean up with SIGTERM. The guardian
/// is never killed; an exited guardian is accepted only with a clean receipt.
pub(super) fn signal_guardian(dir: &Path, identity: &PeerIdentity) -> anyhow::Result<()> {
    let receipt = read_receipt(dir, identity)?;
    if receipt.clean() {
        return Ok(());
    }
    let (Some(pid), Some(ticks)) = (receipt.guardian_pid, receipt.guardian_start_ticks) else {
        anyhow::bail!("guest peer guardian has not recorded its process birth; cleanup is unknown");
    };
    let signaled = terminate_birth(pid, ticks).context("signal the guest peer guardian")?;
    if signaled || read_receipt(dir, identity)?.clean() {
        return Ok(());
    }
    anyhow::bail!("guest peer guardian exited without proving family cleanup; cleanup is unknown")
}

/// SIGTERM one exact process birth. False when that birth has exited.
fn terminate_birth(pid: u32, ticks: u64) -> io::Result<bool> {
    let process = match pidfd_open(pid) {
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => return Ok(false),
        process => process?,
    };
    // Read the birth after opening. A pidfd whose process was reaped before
    // the read can no longer be signaled, so a reused PID is never hit.
    if process_stat(pid).ok().map(|stat| stat.start_ticks) != Some(ticks) {
        return Ok(false);
    }
    match pidfd_signal(&process, libc::SIGTERM) {
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(false),
        Err(error) => Err(error),
        // An unreaped zombie accepts signals but can no longer act on one.
        Ok(()) => pidfd_exited(&process).map(|exited| !exited),
    }
}

// ---------------------------------------------------------------------------
// Guardian process
// ---------------------------------------------------------------------------

#[derive(Debug, clap::Args)]
pub(crate) struct AgentPeerArgs {
    #[arg(long, help = "Guest environment ID")]
    pub(crate) environment: String,
    #[arg(long, help = "Managed conversation driver ID")]
    pub(crate) driver_id: String,
    #[arg(long, help = "Bound driver session ID")]
    pub(crate) session_id: String,
    #[arg(long, help = "Prepared guardian instance ID")]
    pub(crate) instance_id: String,
    #[arg(long, help = "Driver start time recorded in the prepared instance")]
    pub(crate) driver_started_at: String,
    #[arg(long, help = "Prepared driver process ID")]
    pub(crate) driver_pid: u32,
    #[arg(long, help = "Prepared driver process start ticks")]
    pub(crate) driver_start_ticks: u64,
    #[arg(long, help = "Admitted owner-private guest state directory")]
    pub(crate) guest_root: PathBuf,
    #[arg(long, help = "Installed provider executable")]
    pub(crate) program: PathBuf,
    #[arg(
        long,
        help = "Retain member-host family custody outside the driver process group"
    )]
    pub(crate) host_member_custody: bool,
    #[arg(last = true, help = "Provider arguments")]
    pub(crate) arguments: Vec<String>,
}

#[derive(Clone, Copy)]
struct Custody {
    term_grace: Duration,
    deadline: Duration,
}

const CUSTODY: Custody = Custody {
    term_grace: TERM_GRACE,
    deadline: CLEANUP_DEADLINE,
};

pub(crate) async fn run_agent_peer(args: AgentPeerArgs) -> anyhow::Result<()> {
    let environment = DriverEnvironment::Guest {
        id: args.environment.clone(),
        root: args.guest_root.clone(),
    };
    anyhow::ensure!(
        super::platform_control::marker(&environment, &args.driver_id)?.is_none(),
        "platform guardian requires its fixed private role"
    );
    // Custody runs synchronously on this thread. The provider's parent-death
    // signal follows the thread that forks it, and this thread outlives it.
    agent_peer(args, CUSTODY).map_err(|error| anyhow::anyhow!(bounded_error(&format!("{error:#}"))))
}
pub(super) async fn run_platform_peer(
    args: AgentPeerArgs,
    environment: Vec<(String, String)>,
) -> anyhow::Result<()> {
    agent_peer_projected(args, CUSTODY, Some(&environment))
        .map_err(|_| anyhow::anyhow!("platform guardian refused"))
}

/// Returns only after the family is reaped. A nonzero provider status exits
/// this process with that status once the clean receipt is durable.
fn agent_peer(args: AgentPeerArgs, custody: Custody) -> anyhow::Result<()> {
    agent_peer_projected(args, custody, None)
}
fn agent_peer_projected(
    args: AgentPeerArgs,
    custody: Custody,
    environment: Option<&[(String, String)]>,
) -> anyhow::Result<()> {
    let mut guardian = Guardian::admit(&args, custody)?;
    if args.host_member_custody {
        super::host_control::admit_member_guardian(
            &args.guest_root,
            &args.environment,
            &args.driver_id,
            &args.session_id,
        )?;
        // The host daemon may finish the dead driver's original process group.
        // The guardian retains the provider/adopted family independently and
        // remains the sole publisher of a complete ECHILD receipt.
        if unsafe { libc::setsid() } < 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    let failure = match environment {
        Some(values) => guardian.start_projected(&args.program, &args.arguments, Some(values)),
        None => guardian.start(&args.program, &args.arguments),
    }
    .err()
    .map(|error| bounded_error(&format!("{error:#}")));
    let reason = match &failure {
        Some(failure) => format!("startup failed: {failure}"),
        None => guardian.monitor(),
    };
    guardian.cleanup(&reason);
    guardian.finish(failure)
}

/// One exact direct child birth. Signals go only through its pidfd.
struct Birth {
    fd: OwnedFd,
    terminated: bool,
    killed: bool,
}

enum Reap {
    Live,
    Empty,
    Failed(io::Error),
}

struct Guardian {
    receipt_path: PathBuf,
    receipt: PeerReceipt,
    journal: Journal,
    custody: Custody,
    wake: Option<OwnedFd>,
    driver: Option<OwnedFd>,
    provider_pid: Option<u32>,
    provider_status: Option<libc::c_int>,
    births: BTreeMap<u32, Birth>,
    persist_due: Option<Instant>,
    last_note: Option<String>,
}

impl Guardian {
    /// The private prepared pointer, not these arguments, names the identity.
    /// Failures here leave the prepared receipt untouched.
    fn admit(args: &AgentPeerArgs, custody: Custody) -> anyhow::Result<Self> {
        validate_names(&args.environment, &args.driver_id, &args.session_id)?;
        if !normalized_absolute(&args.guest_root) {
            anyhow::bail!("--guest-root must be a normalized absolute directory below /");
        }
        if !args.program.is_absolute() {
            anyhow::bail!("--program must be an absolute path");
        }
        let dir = args.guest_root.join("agents").join(&args.driver_id);
        canonical_driver_dir(&dir, &args.driver_id)?;
        let identity: PeerIdentity = read_record(&dir.join(CURRENT_POINTER))
            .context("guest peer custody was not prepared")?;
        identity.validate(&args.environment, &args.driver_id, &args.session_id)?;
        if identity.instance_id != args.instance_id
            || identity.driver_started_at != args.driver_started_at
            || identity.driver_pid != args.driver_pid
            || identity.driver_start_ticks != args.driver_start_ticks
        {
            anyhow::bail!("guest peer arguments do not match the prepared custody instance");
        }
        // Held until exit: no second guardian can claim this instance.
        let journal = Journal::claim(&dir.join(format!("peer-{}.journal", identity.instance_id)))?;
        let mut receipt = read_receipt(&dir, &identity)?;
        if receipt.guardian_pid.is_some() || !receipt.cleanup_unknown {
            anyhow::bail!("guest peer custody instance was already claimed");
        }
        let guardian = std::process::id();
        receipt.guardian_pid = Some(guardian);
        receipt.guardian_start_ticks = Some(
            process_stat(guardian)
                .context("read the guardian process birth")?
                .start_ticks,
        );
        Ok(Self {
            receipt_path: receipt_path(&dir, &identity.instance_id)?,
            receipt,
            journal,
            custody,
            wake: None,
            driver: None,
            provider_pid: None,
            provider_status: None,
            births: BTreeMap::new(),
            persist_due: None,
            last_note: None,
        })
    }

    /// Everything that must hold before the provider exists, then the spawn.
    /// Under the instance lock an unclaimed receipt proves no earlier family,
    /// so a failure here is still finished only after `ECHILD`.
    fn start(&mut self, program: &Path, arguments: &[String]) -> anyhow::Result<()> {
        self.start_projected(program, arguments, None)
    }
    fn start_projected(
        &mut self,
        program: &Path,
        arguments: &[String],
        environment: Option<&[(String, String)]>,
    ) -> anyhow::Result<()> {
        self.wake = Some(install_signal_handlers().context("install guardian signal handling")?);
        // Armed before the parent check: a driver exit in between still
        // reaches the installed handler instead of being missed.
        prctl_set(libc::PR_SET_PDEATHSIG, libc::SIGTERM as libc::c_ulong)
            .context("arm driver death notification")?;
        self.driver = Some(bind_driver(&self.receipt.identity)?);
        prctl_set(libc::PR_SET_CHILD_SUBREAPER, 1).context("become the family subreaper")?;
        fs::metadata("/proc/thread-self/children")
            .context("this kernel cannot list guardian children; family custody is unavailable")?;
        self.persist_now().context("claim guest peer custody")?;
        self.journal.record(&format!(
            "claimed custody guardian_pid={} threads={}",
            std::process::id(),
            fs::read_dir("/proc/self/task").map_or(0, Iterator::count)
        ));
        if let Some(signal) = take_stop_signal() {
            anyhow::bail!("guardian received {signal} before the provider started");
        }
        seal_inherited_descriptors().context("close private descriptors before the provider")?;
        let pid = spawn_provider(program, arguments, environment)?;
        self.provider_pid = Some(pid);
        self.receipt.provider_pid = Some(pid);
        self.persist();
        // The unreaped provider cannot be recycled, so this binds its birth.
        let birth = bind_child(pid, std::process::id())
            .context("bind the provider process birth")?
            .context("the provider process birth could not be bound")?;
        self.births.insert(pid, birth.0);
        self.journal.record(&format!(
            "provider started pid={pid} start_ticks={}",
            birth.1
        ));
        Ok(())
    }

    /// Wait for a stop request, driver death or provider exit.
    fn monitor(&mut self) -> String {
        loop {
            if let Some(signal) = take_stop_signal() {
                return format!("received {signal}");
            }
            match self.driver.as_ref().map(pidfd_exited) {
                Some(Ok(true)) => {
                    self.driver = None;
                    return "driver exited".into();
                }
                Some(Err(error)) => self.note(format!("watch the driver process: {error}")),
                _ => {}
            }
            match self.reap() {
                Reap::Empty => return "provider exited".into(),
                Reap::Failed(error) => self.note(format!("reap the provider family: {error}")),
                Reap::Live => {}
            }
            if self.provider_status.is_some() {
                return "provider exited".into();
            }
            self.retry_persist();
            self.pause(true, MONITOR_INTERVAL);
        }
    }

    /// Kill, reap and adopt in rounds until `waitpid` reports `ECHILD`. Never
    /// gives up: past the deadline the receipt says so and stays unknown.
    fn cleanup(&mut self, reason: &str) {
        self.journal.record(&format!("cleanup started: {reason}"));
        let started = Instant::now();
        let mut escalated = false;
        let mut overdue = false;
        loop {
            match self.reap() {
                Reap::Empty => break,
                Reap::Failed(error) => self.note(format!("reap the provider family: {error}")),
                Reap::Live => {}
            }
            if let Err(error) = self.adopt() {
                self.note(format!("survey the provider family: {error}"));
            }
            let elapsed = started.elapsed();
            if !escalated && elapsed >= self.custody.term_grace {
                escalated = true;
                self.journal
                    .record("escalating remaining family to SIGKILL");
            }
            self.signal_family(escalated);
            if !overdue && elapsed >= self.custody.deadline {
                overdue = true;
                let error = format!(
                    "family cleanup exceeded {:?}; custody continues",
                    self.custody.deadline
                );
                self.journal.record(&error);
                self.receipt.error = Some(error);
                self.persist();
            }
            self.retry_persist();
            self.pause(false, CLEANUP_INTERVAL);
        }
        self.births.clear();
        self.journal
            .record("cleanup proven: waitpid reported no remaining children");
    }

    fn finish(mut self, failure: Option<String>) -> anyhow::Result<()> {
        let exit_code = self.provider_status.map(exit_code_of);
        self.receipt.cleanup_unknown = false;
        self.receipt.finished_at = Some(now());
        self.receipt.exit_code = exit_code;
        self.receipt.error = failure.clone();
        let mut attempts = 1;
        while let Err(error) = self.persist_now() {
            if attempts >= FINAL_PERSIST_ATTEMPTS {
                self.journal
                    .record(&format!("record finished custody failed: {error:#}"));
                return Err(error.context("record guest peer cleanup; it remains unknown"));
            }
            attempts += 1;
            std::thread::sleep(Duration::from_millis(100));
        }
        self.journal
            .record(&format!("finished exit_code={exit_code:?}"));
        if let Some(failure) = failure {
            anyhow::bail!(failure);
        }
        match exit_code {
            Some(0) => Ok(()),
            Some(code) => std::process::exit(code),
            None => anyhow::bail!("guest peer guardian finished without a provider status"),
        }
    }

    fn reap(&mut self) -> Reap {
        loop {
            let mut status = 0;
            // SAFETY: status is a valid out-pointer and WNOHANG never blocks.
            // __WALL includes children with a non-SIGCHLD exit signal, so
            // ECHILD really means no child of any kind remains.
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG | libc::__WALL) };
            if pid > 0 {
                let pid = pid as u32;
                self.births.remove(&pid);
                if self.provider_pid == Some(pid) && self.provider_status.is_none() {
                    self.provider_status = Some(status);
                    self.journal
                        .record(&format!("provider exited code={}", exit_code_of(status)));
                }
                continue;
            }
            if pid == 0 {
                return Reap::Live;
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EINTR) => {}
                Some(libc::ECHILD) => return Reap::Empty,
                _ => return Reap::Failed(error),
            }
        }
    }

    /// Bind every direct child not yet bound, including newly adopted orphans.
    /// Only this process's own task children lists are read.
    fn adopt(&mut self) -> io::Result<()> {
        let guardian = std::process::id();
        let mut failure = None;
        for pid in survey_children()? {
            if self.births.contains_key(&pid) {
                continue;
            }
            match bind_child(pid, guardian) {
                Ok(Some((birth, ticks))) => {
                    self.journal
                        .record(&format!("adopted pid={pid} start_ticks={ticks}"));
                    self.births.insert(pid, birth);
                }
                Ok(None) => {}
                Err(error) => failure = Some(error),
            }
        }
        failure.map_or(Ok(()), Err)
    }

    /// SIGTERM the provider first and then the others; after the grace period
    /// SIGKILL every bound birth still alive. Never signals this process.
    fn signal_family(&mut self, escalated: bool) {
        let provider = self
            .provider_pid
            .filter(|pid| self.births.contains_key(pid));
        let others = self
            .births
            .keys()
            .copied()
            .filter(|pid| Some(*pid) != provider);
        let order: Vec<u32> = provider.into_iter().chain(others).collect();
        let mut failures = Vec::new();
        for pid in order {
            let Some(birth) = self.births.get_mut(&pid) else {
                continue;
            };
            let signal = if escalated {
                (!birth.killed).then_some(libc::SIGKILL)
            } else {
                (!birth.terminated).then_some(libc::SIGTERM)
            };
            let Some(signal) = signal else {
                continue;
            };
            match pidfd_signal(&birth.fd, signal) {
                Err(error) if error.raw_os_error() != Some(libc::ESRCH) => {
                    failures.push(format!("signal pid={pid}: {error}"));
                    continue;
                }
                _ => {}
            }
            if signal == libc::SIGKILL {
                birth.killed = true;
            } else {
                birth.terminated = true;
            }
        }
        for failure in failures {
            self.note(failure);
        }
    }

    /// Sleep until a signal arrives or the timeout passes. While monitoring,
    /// driver or provider exit also wakes it; cleanup wakes on SIGCHLD.
    fn pause(&self, watch: bool, timeout: Duration) {
        let mut fds: Vec<libc::pollfd> = self
            .wake
            .iter()
            .chain(watch.then_some(self.driver.as_ref()).flatten())
            .chain(
                watch
                    .then(|| self.provider_pid.and_then(|pid| self.births.get(&pid)))
                    .flatten()
                    .map(|birth| &birth.fd),
            )
            .map(|fd| libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let millis = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: fds holds initialized pollfd entries for the whole call.
        unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, millis) };
        if let Some(wake) = &self.wake {
            let mut buffer = [0_u8; 64];
            // SAFETY: buffer is writable for its length; the pipe is nonblocking.
            while unsafe { libc::read(wake.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) }
                > 0
            {}
        }
    }

    fn persist_now(&self) -> anyhow::Result<()> {
        write_private_json(&self.receipt_path, &self.receipt)
    }

    /// A failed write is retried later; it never interrupts custody.
    fn persist(&mut self) {
        match self.persist_now() {
            Ok(()) => self.persist_due = None,
            Err(error) => {
                self.persist_due = Some(Instant::now() + PERSIST_RETRY_INTERVAL);
                self.note(format!("record the guest peer receipt: {error:#}"));
            }
        }
    }

    fn retry_persist(&mut self) {
        if self.persist_due.is_some_and(|due| Instant::now() >= due) {
            self.persist();
        }
    }

    /// Journal repeated per-round failures once until they change.
    fn note(&mut self, event: String) {
        if self.last_note.as_deref() != Some(event.as_str()) {
            self.journal.record(&event);
            self.last_note = Some(event);
        }
    }
}

fn spawn_provider(
    program: &Path,
    arguments: &[String],
    environment: Option<&[(String, String)]>,
) -> anyhow::Result<u32> {
    let guardian = std::process::id();
    let platform = environment.is_some();
    let mut command = std::process::Command::new(program);
    // Native stdin, stdout and stderr are inherited unchanged.
    command.args(arguments);
    if let Some(environment) = environment {
        command
            .env_clear()
            .envs(environment.iter().map(|(k, v)| (k, v)));
    }
    // SAFETY: the hook runs after fork and before exec. It calls only the
    // async-signal-safe prctl and getppid and allocates nothing.
    unsafe {
        command.pre_exec(move || {
            prctl_set(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong)?;
            // The guardian may have exited before the signal was armed.
            if std::os::unix::process::parent_id() != guardian {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            if platform {
                prctl_set(libc::PR_SET_NO_NEW_PRIVS, 1)?;
            }
            Ok(())
        });
    }
    let child = command.spawn().context("start the guest provider")?;
    // Only the custody loop reaps; dropping Child neither waits nor kills.
    Ok(child.id())
}

/// The driver must be this process's parent and the prepared birth.
fn bind_driver(identity: &PeerIdentity) -> anyhow::Result<OwnedFd> {
    let parent = std::os::unix::process::parent_id();
    if parent != identity.driver_pid {
        anyhow::bail!("guest peer guardian must be a direct child of its prepared driver");
    }
    let driver = pidfd_open(parent).context("open the driver process")?;
    let birth = process_stat(parent).context("read the driver process birth")?;
    // Still the parent after both reads, so the driver had not exited and the
    // pidfd and stat described the same birth.
    if birth.start_ticks != identity.driver_start_ticks
        || std::os::unix::process::parent_id() != parent
    {
        anyhow::bail!("guest peer guardian's parent is not the prepared driver process birth");
    }
    Ok(driver)
}

/// Bind one direct child birth, or `None` when `pid` is no longer this
/// process's unreaped child.
fn bind_child(pid: u32, parent: u32) -> io::Result<Option<(Birth, u64)>> {
    let gone = |error: &io::Error| matches!(error.raw_os_error(), Some(libc::ESRCH | libc::ENOENT));
    let fd = match pidfd_open(pid) {
        Err(error) if gone(&error) => return Ok(None),
        fd => fd?,
    };
    let stat = match process_stat(pid) {
        Err(error) if gone(&error) => return Ok(None),
        stat => stat?,
    };
    if stat.ppid != parent {
        return Ok(None);
    }
    // Signal 0 succeeds only while this pidfd's process is unreaped, so the
    // stat read above described it rather than a reuse of the number.
    match pidfd_signal(&fd, 0) {
        Err(error) if gone(&error) => Ok(None),
        Err(error) => Err(error),
        Ok(()) => Ok(Some((
            Birth {
                fd,
                terminated: false,
                killed: false,
            },
            stat.start_ticks,
        ))),
    }
}

fn survey_children() -> io::Result<BTreeSet<u32>> {
    let mut children = BTreeSet::new();
    for task in fs::read_dir("/proc/self/task")? {
        let list = match fs::read_to_string(task?.path().join("children")) {
            Ok(list) => list,
            // A thread that exits mid-survey hands its children to a live one.
            Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
                continue;
            }
            Err(error) => return Err(error),
        };
        for pid in list.split_ascii_whitespace() {
            children.insert(pid.parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "malformed child process list")
            })?);
        }
    }
    Ok(children)
}

/// Only native stdio may cross into the provider.
fn seal_inherited_descriptors() -> io::Result<()> {
    let mut descriptors = Vec::new();
    for entry in fs::read_dir("/proc/self/fd")? {
        if let Some(fd) = entry?
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<libc::c_int>().ok())
            .filter(|fd| *fd > 2)
        {
            descriptors.push(fd);
        }
    }
    for fd in descriptors {
        // SAFETY: F_GETFD and F_SETFD only read or set this process's
        // close-on-exec flag for the descriptor number.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            let error = io::Error::last_os_error();
            // The directory listing's own descriptor has closed.
            if error.raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            return Err(error);
        }
        // SAFETY: as above.
        if flags & libc::FD_CLOEXEC == 0
            && unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

static SIGNAL_WAKE: AtomicI32 = AtomicI32::new(-1);
static SIGNALS_SEEN: AtomicU32 = AtomicU32::new(0);

extern "C" fn record_signal(signal: libc::c_int) {
    // SAFETY: errno is thread-local and is restored before returning.
    let errno = unsafe { *libc::__errno_location() };
    if (0..32).contains(&signal) {
        SIGNALS_SEEN.fetch_or(1 << signal, Ordering::SeqCst);
    }
    let wake = SIGNAL_WAKE.load(Ordering::SeqCst);
    if wake >= 0 {
        let byte = 1_u8;
        // SAFETY: write is async-signal-safe. A full nonblocking pipe already
        // holds a pending wakeup, so a short write needs no retry.
        unsafe { libc::write(wake, (&raw const byte).cast(), 1) };
    }
    // SAFETY: as above.
    unsafe { *libc::__errno_location() = errno };
}

/// Stop signals and SIGCHLD set a flag and wake the custody loop from any
/// thread. Returns the wakeup pipe's read end.
fn install_signal_handlers() -> io::Result<OwnedFd> {
    let mut fds = [0; 2];
    // SAFETY: fds is a writable two-element array for pipe2's result.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 returned two new descriptors owned by this process. The
    // write end is deliberately never closed: handlers may run until exit.
    let wake = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    SIGNAL_WAKE.store(fds[1], Ordering::SeqCst);
    // SAFETY: a zeroed sigset_t is valid storage for sigemptyset.
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: mask is valid writable storage.
    unsafe { libc::sigemptyset(&mut mask) };
    for signal in STOP_SIGNALS
        .iter()
        .map(|(signal, _)| *signal)
        .chain([libc::SIGCHLD])
    {
        // SAFETY: a zeroed sigaction is a valid starting value.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = record_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        action.sa_flags = libc::SA_RESTART
            | if signal == libc::SIGCHLD {
                libc::SA_NOCLDSTOP
            } else {
                0
            };
        // SAFETY: both sets are valid storage; the handler is async-signal-safe
        // and the action outlives the call.
        let installed = unsafe {
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaddset(&mut mask, signal);
            libc::sigaction(signal, &action, std::ptr::null_mut())
        };
        if installed != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // An inherited blocked mask would otherwise delay stop requests here.
    // SAFETY: mask is initialized and the old mask is not requested.
    let result = unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &mask, std::ptr::null_mut()) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    Ok(wake)
}

fn take_stop_signal() -> Option<&'static str> {
    let mask = STOP_SIGNALS
        .iter()
        .fold(0_u32, |mask, (signal, _)| mask | 1 << signal);
    let seen = SIGNALS_SEEN.fetch_and(!mask, Ordering::SeqCst) & mask;
    STOP_SIGNALS
        .iter()
        .find(|(signal, _)| seen & 1 << signal != 0)
        .map(|(_, name)| *name)
}

fn prctl_set(option: libc::c_int, value: libc::c_ulong) -> io::Result<()> {
    let unused: libc::c_ulong = 0;
    // SAFETY: these scalar prctl options affect only the calling process or
    // thread and read no memory. prctl is also async-signal-safe.
    if unsafe { libc::prctl(option, value, unused, unused, unused) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Process identity
// ---------------------------------------------------------------------------

struct ProcessStat {
    ppid: u32,
    start_ticks: u64,
}

fn process_stat(pid: u32) -> io::Result<ProcessStat> {
    parse_stat(&fs::read_to_string(format!("/proc/{pid}/stat"))?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed process stat"))
}

fn parse_stat(stat: &str) -> Option<ProcessStat> {
    // Fields after the last ") " start at field 3 (state): PPID is field 4
    // and the start time is field 22.
    let (_, fields) = stat.rsplit_once(") ")?;
    let fields: Vec<&str> = fields.split_ascii_whitespace().collect();
    Some(ProcessStat {
        ppid: fields.get(1)?.parse().ok()?,
        start_ticks: fields.get(19)?.parse().ok()?,
    })
}

fn pidfd_open(pid: u32) -> io::Result<OwnedFd> {
    if !valid_pid(pid) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    // SAFETY: pidfd_open takes scalar arguments and returns a new descriptor,
    // always close-on-exec, or -1.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel returned a new descriptor owned only by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(raw as libc::c_int) })
}

fn pidfd_signal(fd: &OwnedFd, signal: libc::c_int) -> io::Result<()> {
    // SAFETY: fd is a live pidfd; a null siginfo requests default sender data.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn pidfd_exited(fd: &OwnedFd) -> io::Result<bool> {
    let mut pollfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: pollfd is one initialized entry and a zero timeout never blocks.
    let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result == 1 && pollfd.revents & (libc::POLLIN | libc::POLLHUP) != 0)
}

fn exit_code_of(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

fn valid_pid(pid: u32) -> bool {
    pid != 0 && pid <= i32::MAX as u32
}

fn current_boot_id() -> anyhow::Result<String> {
    let boot = fs::read_to_string(BOOT_ID_PATH).context("read the current boot ID")?;
    canonical_uuid(boot.trim()).context("the current boot ID is malformed")
}

// ---------------------------------------------------------------------------
// Validation and private storage
// ---------------------------------------------------------------------------

fn validate_names(environment_id: &str, driver_id: &str, session_id: &str) -> anyhow::Result<()> {
    canonical_uuid(environment_id)?;
    canonical_uuid(driver_id)?;
    match session_id.strip_prefix("session-").map(canonical_uuid) {
        Some(Ok(_)) => Ok(()),
        _ => anyhow::bail!("session ID must be a canonical session-<uuid> identifier"),
    }
}

fn validate_timestamp(value: &str) -> anyhow::Result<()> {
    if value.len() > MAX_TIMESTAMP_BYTES || DateTime::parse_from_rfc3339(value).is_err() {
        anyhow::bail!("guest peer timestamps must be RFC 3339");
    }
    Ok(())
}

fn normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.parent().is_some()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str()
}

/// `<guest root>/agents/<driver id>`, owner-private at each level and free of
/// symlinks, so a path argument cannot redirect custody records.
fn canonical_driver_dir(dir: &Path, driver_id: &str) -> anyhow::Result<()> {
    let driver_id = canonical_uuid(driver_id)?;
    let agents = dir.parent();
    let root = agents.and_then(Path::parent);
    let (Some(agents), Some(root)) = (agents, root) else {
        anyhow::bail!("guest peer custody requires the canonical managed conversation directory");
    };
    let canonical = dir.is_absolute()
        && dir.file_name() == Some(OsStr::new(&driver_id))
        && agents.file_name() == Some(OsStr::new("agents"))
        && root.parent().is_some()
        && fs::canonicalize(dir).ok().as_deref() == Some(dir);
    if !canonical {
        anyhow::bail!("guest peer custody requires the canonical managed conversation directory");
    }
    for path in [root, agents, dir] {
        existing_private_dir(path)?;
    }
    Ok(())
}

/// The per-instance receipt file inside a driver directory. Refuses a
/// non-canonical instance ID, so callers cannot name another file.
pub(super) fn receipt_path(dir: &Path, instance_id: &str) -> anyhow::Result<PathBuf> {
    Ok(dir.join(format!("peer-{}.json", canonical_uuid(instance_id)?)))
}

/// One bounded line with control characters replaced.
fn bounded_error(text: &str) -> String {
    let line: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    match truncate_utf8(&line, MAX_PEER_ERROR_BYTES - '…'.len_utf8()) {
        (line, true) => format!("{line}…"),
        (line, false) => line,
    }
}

/// Bounded private event log. Its exclusive lock is the instance claim.
struct Journal {
    file: fs::File,
    written: u64,
}

impl Journal {
    fn claim(path: &Path) -> anyhow::Result<Self> {
        let file = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("open guest peer journal {}", path.display()))?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.uid() != euid() || meta.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("guest peer journal must be an owner-private file");
        }
        // SAFETY: the descriptor stays owned by the returned journal.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                anyhow::bail!("another guardian already owns this guest peer instance");
            }
            return Err(error).context("lock the guest peer journal");
        }
        Ok(Self {
            written: meta.len(),
            file,
        })
    }

    /// Diagnostics only: a failed or full journal never interrupts custody.
    fn record(&mut self, event: &str) {
        if self.written >= MAX_JOURNAL_BYTES {
            return;
        }
        let (event, _) = truncate_utf8(&bounded_error(event), MAX_EVENT_BYTES);
        let mut line = format!("{} {event}\n", now());
        if self.written + line.len() as u64 > MAX_JOURNAL_BYTES {
            line = "journal limit reached\n".into();
            self.written = MAX_JOURNAL_BYTES;
        }
        if self.file.write_all(line.as_bytes()).is_ok() {
            self.written += line.len() as u64;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt as _;
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::{Child, Command, Stdio};

    const ROLE_ENV: &str = "CW_GUEST_PEER_TEST_ROLE";
    const SPEC_ENV: &str = "CW_GUEST_PEER_TEST_SPEC";
    const WAIT: Duration = Duration::from_secs(30);
    const FAMILY: [&str; 5] = ["provider", "resistant", "detached", "nested", "grandchild"];

    /// Provider family: a TERM-resistant direct tool, a double-forked tool in
    /// a new session, and a tool whose TERM-resistant child is orphaned when
    /// it dies. Each records `$$` atomically before becoming `sleep`.
    const PROVIDER: &str = r#"d=$1
record() { echo "$2" > "$d/$1.tmp"; mv "$d/$1.tmp" "$d/$1.pid"; }
case $2 in
provider)
  sh "$0" "$d" resistant &
  sh "$0" "$d" detach
  sh "$0" "$d" nested &
  record provider $$
  for name in resistant detached nested grandchild; do
    while [ ! -s "$d/$name.pid" ]; do sleep 0.01; done
  done
  : > "$d/ready"
  case $3 in
  hold) exec sleep 1000 ;;
  ignore-term) trap '' TERM; exec sleep 1000 ;;
  exit-on-eof) cat > /dev/null; exit 3 ;;
  esac ;;
resistant) trap '' TERM HUP INT; record resistant $$; exec sleep 1000 ;;
detach) setsid sh "$0" "$d" detached & exit 0 ;;
detached) trap '' TERM HUP INT; record detached $$; exec sleep 1000 ;;
nested) sh "$0" "$d" grandchild & record nested $$; exec sleep 1000 ;;
grandchild) trap '' TERM HUP INT; record grandchild $$; exec sleep 1000 ;;
echo)
  ls -l "/proc/$$/fd" > "$d/fds"
  printf 'out\000\377'
  cat
  printf 'err' >&2 ;;
esac
"#;

    #[derive(serde::Serialize, serde::Deserialize)]
    struct DriverSpec {
        root: PathBuf,
        work: PathBuf,
        environment_id: String,
        driver_id: String,
        session_id: String,
        program: PathBuf,
        arguments: Vec<String>,
        input: Vec<u8>,
        /// Native stdin closes once this path exists.
        close_input_when: Option<PathBuf>,
        term_grace_ms: u64,
        deadline_ms: u64,
        #[serde(default)]
        host_member_custody: bool,
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct GuardianSpec {
        argv: Vec<String>,
        native_fds: bool,
        term_grace_ms: u64,
        deadline_ms: u64,
    }

    /// Re-entry point for the isolated driver and guardian subprocesses. The
    /// parallel test runner never becomes a subreaper.
    #[test]
    fn subprocess_role() {
        let Ok(role) = std::env::var(ROLE_ENV) else {
            return;
        };
        let spec = std::env::var(SPEC_ENV).unwrap();
        std::process::exit(match role.as_str() {
            "driver" => driver_role(serde_json::from_str(&spec).unwrap()),
            "guardian" => guardian_role(serde_json::from_str(&spec).unwrap()),
            _ => 2,
        });
    }

    fn role(role: &str, spec: &impl serde::Serialize) -> Command {
        let module = module_path!();
        let test = format!(
            "{}::subprocess_role",
            module.split_once("::").map_or(module, |(_, path)| path)
        );
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                test.as_str(),
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "--quiet",
            ])
            .env(ROLE_ENV, role)
            .env(SPEC_ENV, serde_json::to_string(spec).unwrap())
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        command
    }

    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [0; 2];
        // SAFETY: fds is a writable two-element array.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: pipe2 returned two new descriptors owned by this process.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    /// A close-on-exec duplicate above the guardian's fixed targets 3..=6.
    fn high(fd: OwnedFd) -> OwnedFd {
        // SAFETY: F_DUPFD_CLOEXEC returns a new descriptor or -1.
        let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 100) };
        assert!(raw >= 100);
        // SAFETY: raw is a new descriptor owned by this process.
        unsafe { OwnedFd::from_raw_fd(raw) }
    }

    fn write_atomic(path: &Path, contents: impl AsRef<[u8]>) {
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, contents).unwrap();
        fs::rename(temporary, path).unwrap();
    }

    /// Plays the production driver: prepares custody, then launches the
    /// guardian with piped native stdio from this long-lived thread.
    fn driver_role(spec: DriverSpec) -> i32 {
        let dir = spec.root.join("agents").join(&spec.driver_id);
        let identity = prepare(
            &dir,
            &spec.environment_id,
            &spec.driver_id,
            &spec.session_id,
            &now(),
        )
        .unwrap();
        write_atomic(
            &spec.work.join("identity.json"),
            serde_json::to_vec(&identity).unwrap(),
        );
        let mut argv = vec!["cw".to_owned()];
        for (flag, value) in [
            ("--environment", identity.environment_id.clone()),
            ("--driver-id", identity.driver_id.clone()),
            ("--session-id", identity.session_id.clone()),
            ("--instance-id", identity.instance_id.clone()),
            ("--driver-started-at", identity.driver_started_at.clone()),
            ("--driver-pid", identity.driver_pid.to_string()),
            (
                "--driver-start-ticks",
                identity.driver_start_ticks.to_string(),
            ),
            ("--guest-root", spec.root.display().to_string()),
            ("--program", spec.program.display().to_string()),
        ] {
            argv.extend([flag.to_owned(), value]);
        }
        if spec.host_member_custody {
            argv.push("--host-member-custody".into());
        }
        argv.push("--".into());
        argv.extend(spec.arguments.iter().cloned());
        let (input_read, input_write) = pipe();
        let (output_read, output_write) = pipe();
        let (error_read, error_write) = pipe();
        // Lands on guardian descriptor 6 without close-on-exec; the provider
        // must still never see it.
        let canary = fs::File::create(spec.work.join("private-canary")).unwrap();
        let native = [
            high(input_read),
            high(output_write),
            high(error_write),
            high(canary.into()),
        ];
        let raw = native.each_ref().map(AsRawFd::as_raw_fd);
        let mut command = role(
            "guardian",
            &GuardianSpec {
                argv,
                native_fds: true,
                term_grace_ms: spec.term_grace_ms,
                deadline_ms: spec.deadline_ms,
            },
        );
        command.stderr(Stdio::null());
        // SAFETY: dup2 is async-signal-safe; every source is above 3..=6.
        unsafe {
            command.pre_exec(move || {
                for (target, fd) in (3..).zip(raw) {
                    if libc::dup2(fd, target) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut guardian = command.spawn().unwrap();
        drop(native);
        let copy = |fd: OwnedFd, path: PathBuf| {
            std::thread::spawn(move || {
                let mut output = fs::File::create(path).unwrap();
                io::copy(&mut fs::File::from(fd), &mut output).unwrap();
            })
        };
        let output = copy(output_read, spec.work.join("native.out"));
        let error = copy(error_read, spec.work.join("native.err"));
        let mut input = fs::File::from(input_write);
        input.write_all(&spec.input).unwrap();
        if let Some(release) = spec.close_input_when {
            std::thread::spawn(move || {
                while !release.exists() {
                    std::thread::sleep(Duration::from_millis(10));
                }
                drop(input);
            });
        } else {
            std::mem::forget(input);
        }
        let status = guardian.wait().unwrap();
        let status = status.code().map_or_else(
            || format!("signal {}", status.signal().unwrap_or_default()),
            |code| code.to_string(),
        );
        write_atomic(&spec.work.join("guardian.status"), status);
        // Escaped processes may hold native output open indefinitely.
        output.join().unwrap();
        error.join().unwrap();
        write_atomic(&spec.work.join("native.done"), "");
        0
    }

    fn guardian_role(spec: GuardianSpec) -> i32 {
        if spec.native_fds {
            for (source, target) in [(3, 0), (4, 1), (5, 2)] {
                // SAFETY: the driver role placed these descriptors here.
                unsafe {
                    assert_eq!(libc::dup2(source, target), target);
                    libc::close(source);
                }
            }
        }
        #[derive(clap::Parser)]
        struct PeerCli {
            #[command(flatten)]
            args: AgentPeerArgs,
        }
        let cli = <PeerCli as clap::Parser>::try_parse_from(&spec.argv).unwrap();
        let custody = Custody {
            term_grace: Duration::from_millis(spec.term_grace_ms),
            deadline: Duration::from_millis(spec.deadline_ms),
        };
        match agent_peer(cli.args, custody) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("{}", bounded_error(&format!("{error:#}")));
                1
            }
        }
    }

    struct Fixture {
        _temp: tempfile::TempDir,
        root: PathBuf,
        dir: PathBuf,
        work: PathBuf,
        environment_id: String,
        driver_id: String,
        session_id: String,
    }

    fn fixture() -> Fixture {
        let temp = tempfile::Builder::new()
            .prefix("cw-guest-peer-")
            .tempdir()
            .unwrap();
        let base = fs::canonicalize(temp.path()).unwrap();
        let driver_id = uuid::Uuid::new_v4().to_string();
        let root = base.join("guest");
        let dir = root.join("agents").join(&driver_id);
        let work = base.join("work");
        for path in [&root, &root.join("agents"), &dir, &work] {
            fs::DirBuilder::new().mode(0o700).create(path).unwrap();
        }
        fs::write(work.join("provider.sh"), PROVIDER).unwrap();
        Fixture {
            _temp: temp,
            root,
            dir,
            work,
            environment_id: uuid::Uuid::new_v4().to_string(),
            driver_id,
            session_id: format!("session-{}", uuid::Uuid::new_v4()),
        }
    }

    impl Fixture {
        fn spec(&self, mode: &[&str]) -> DriverSpec {
            let mut arguments = vec![
                self.work.join("provider.sh").display().to_string(),
                self.work.display().to_string(),
            ];
            arguments.extend(mode.iter().map(|value| (*value).to_owned()));
            DriverSpec {
                root: self.root.clone(),
                work: self.work.clone(),
                environment_id: self.environment_id.clone(),
                driver_id: self.driver_id.clone(),
                session_id: self.session_id.clone(),
                program: "/bin/sh".into(),
                arguments,
                input: Vec::new(),
                close_input_when: None,
                term_grace_ms: 1000,
                deadline_ms: 30_000,
                host_member_custody: false,
            }
        }

        fn prepare(&self) -> anyhow::Result<PeerIdentity> {
            prepare(
                &self.dir,
                &self.environment_id,
                &self.driver_id,
                &self.session_id,
                &now(),
            )
        }

        fn current(&self) -> anyhow::Result<Option<PeerReceipt>> {
            current_receipt(
                &self.dir,
                &self.environment_id,
                &self.driver_id,
                &self.session_id,
            )
        }

        fn require_clean(&self) -> anyhow::Result<Option<PeerReceipt>> {
            require_clean_previous(
                &self.dir,
                &self.environment_id,
                &self.driver_id,
                &self.session_id,
            )
        }

        fn write_receipt(&self, receipt: &PeerReceipt) {
            write_private_json(
                &receipt_path(&self.dir, &receipt.identity.instance_id).unwrap(),
                receipt,
            )
            .unwrap();
        }

        fn diagnostics(&self) -> String {
            ["driver.stderr", "native.err"]
                .iter()
                .map(|name| {
                    let text = fs::read_to_string(self.work.join(name)).unwrap_or_default();
                    format!("{name}: {text}")
                })
                .chain(
                    fs::read_dir(&self.dir)
                        .into_iter()
                        .flatten()
                        .flatten()
                        .filter_map(|entry| {
                            let name = entry.file_name().into_string().ok()?;
                            if !name.ends_with(".journal") {
                                return None;
                            }
                            Some(format!(
                                "{name}: {}",
                                fs::read_to_string(entry.path()).ok()?
                            ))
                        }),
                )
                .collect::<Vec<_>>()
                .join("\n")
        }

        fn wait_for<T>(&self, what: &str, mut ready: impl FnMut() -> Option<T>) -> T {
            let deadline = Instant::now() + WAIT;
            loop {
                if let Some(value) = ready() {
                    return value;
                }
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for {what}\n{}",
                    self.diagnostics()
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        fn identity(&self) -> PeerIdentity {
            let path = self.work.join("identity.json");
            self.wait_for("prepared identity", || {
                serde_json::from_slice(&fs::read(&path).ok()?).ok()
            })
        }

        /// Exact births of the provider family, captured while all are alive.
        fn family(&self) -> Vec<(&'static str, u32, u64)> {
            self.wait_for("provider family", || {
                self.work.join("ready").exists().then_some(())
            });
            FAMILY
                .iter()
                .map(|name| {
                    let pid: u32 = fs::read_to_string(self.work.join(format!("{name}.pid")))
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    (*name, pid, process_stat(pid).unwrap().start_ticks)
                })
                .collect()
        }

        fn receipt_where(
            &self,
            identity: &PeerIdentity,
            what: &str,
            accept: impl Fn(&PeerReceipt) -> bool,
        ) -> PeerReceipt {
            self.wait_for(what, || {
                read_receipt(&self.dir, identity)
                    .ok()
                    .filter(|receipt| accept(receipt))
            })
        }

        fn guardian_status(&self) -> String {
            let path = self.work.join("guardian.status");
            self.wait_for("guardian exit", || fs::read_to_string(&path).ok())
        }

        fn native_output(&self, name: &str) -> Vec<u8> {
            let done = self.work.join("native.done");
            self.wait_for("native output EOF", || done.exists().then_some(()));
            fs::read(self.work.join(name)).unwrap()
        }
    }

    fn alive(pid: u32, ticks: u64) -> bool {
        process_stat(pid).is_ok_and(|stat| stat.start_ticks == ticks)
    }

    /// SIGKILLs any recorded exact birth that a failing test left behind.
    struct Leftovers(Vec<(u32, u64)>);

    impl Drop for Leftovers {
        fn drop(&mut self) {
            for (pid, ticks) in &self.0 {
                if let Ok(fd) = pidfd_open(*pid)
                    && alive(*pid, *ticks)
                {
                    let _ = pidfd_signal(&fd, libc::SIGKILL);
                }
            }
        }
    }

    /// A child of the test runner itself, sharing its process group with the
    /// guardian family and running the same program name.
    struct Sentinel(Child);

    impl Sentinel {
        fn spawn() -> Self {
            Self(Command::new("sleep").arg("1000").spawn().unwrap())
        }

        fn birth(&self) -> (u32, u64) {
            let pid = self.0.id();
            (pid, process_stat(pid).unwrap().start_ticks)
        }

        fn alive(&mut self) -> bool {
            self.0.try_wait().unwrap().is_none()
        }
    }

    impl Drop for Sentinel {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    struct DriverProcess(Child);

    impl DriverProcess {
        fn spawn(fixture: &Fixture, spec: &DriverSpec) -> Self {
            let mut command = role("driver", spec);
            if spec.host_member_custody {
                command.process_group(0);
            }
            command.stderr(fs::File::create(fixture.work.join("driver.stderr")).unwrap());
            Self(command.spawn().unwrap())
        }
    }

    impl Drop for DriverProcess {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn assert_family_gone(fixture: &Fixture, family: &[(&str, u32, u64)]) {
        for (name, pid, ticks) in family {
            assert!(
                !alive(*pid, *ticks),
                "{name} pid {pid} survived cleanup\n{}",
                fixture.diagnostics()
            );
        }
    }

    fn launched(
        fixture: &Fixture,
        spec: &DriverSpec,
    ) -> (
        DriverProcess,
        PeerIdentity,
        Vec<(&'static str, u32, u64)>,
        Leftovers,
    ) {
        let driver = DriverProcess::spawn(fixture, spec);
        let identity = fixture.identity();
        let family = fixture.family();
        let leftovers = Leftovers(
            family
                .iter()
                .map(|(_, pid, ticks)| (*pid, *ticks))
                .collect(),
        );
        (driver, identity, family, leftovers)
    }

    #[test]
    fn driver_sigkill_leaves_the_guardian_to_reap_a_detached_term_resistant_family() {
        let fixture = fixture();
        let mut sentinel = Sentinel::spawn();
        let spec = fixture.spec(&["provider", "hold"]);
        let (mut driver, identity, family, mut leftovers) = launched(&fixture, &spec);
        let receipt =
            fixture.receipt_where(&identity, "provider birth", |r| r.provider_pid.is_some());
        let guardian = (
            receipt.guardian_pid.unwrap(),
            receipt.guardian_start_ticks.unwrap(),
        );
        leftovers.0.push(guardian);
        assert_eq!(receipt.provider_pid, Some(family[0].1));
        assert!(receipt.cleanup_unknown && receipt.finished_at.is_none());
        assert!(fixture.require_clean().is_err());
        assert!(fixture.prepare().is_err(), "prepare must reuse the fence");

        driver.0.kill().unwrap();
        driver.0.wait().unwrap();
        assert!(
            alive(guardian.0, guardian.1),
            "guardian must outlive its driver"
        );

        let receipt = fixture.receipt_where(&identity, "clean custody", PeerReceipt::clean);
        assert_eq!(receipt.exit_code, Some(128 + libc::SIGTERM));
        assert_eq!(receipt.error, None);
        assert_family_gone(&fixture, &family);
        fixture.wait_for("guardian exit", || {
            (!alive(guardian.0, guardian.1)).then_some(())
        });
        assert!(sentinel.alive(), "an unrelated process was signaled");
        let journal = fs::read_to_string(
            fixture
                .dir
                .join(format!("peer-{}.journal", identity.instance_id)),
        )
        .unwrap();
        assert!(journal.contains("cleanup started"), "{journal}");
        assert!(journal.contains("adopted pid="), "{journal}");
        assert!(fixture.require_clean().unwrap().unwrap().clean());
    }

    #[test]
    fn member_host_driver_group_sigkill_preserves_guardian_until_exact_family_echild() {
        let mut fixture = fixture();
        fixture.session_id = format!("session-{}", fixture.driver_id);
        // Synthetic target-owned origin, not a claim of authenticated network
        // admission. The guardian reads the real closed marker and kernel birth.
        write_private_json(&fixture.dir.join("member-origin.json"),&json!({
            "version":1,"origin":{"request_id":fixture.driver_id,"fingerprint":"ab".repeat(32),
                "scope":{"environment_id":fixture.environment_id,"org_id":"test-org","network_id":"test-network",
                    "caller_key":vec![1u8;32],"target_key":vec![2u8;32],"grant_id":uuid::Uuid::new_v4().to_string(),"grant_revision":1}},
            "driver_id":fixture.driver_id,"session_id":fixture.session_id,"parent_generation":null})).unwrap();
        let mut sentinel = Sentinel::spawn();
        let mut spec = fixture.spec(&["provider", "hold"]);
        spec.host_member_custody = true;
        let (mut driver, identity, family, mut leftovers) = launched(&fixture, &spec);
        let receipt = fixture.receipt_where(&identity, "member provider birth", |r| {
            r.provider_pid.is_some()
        });
        let guardian = (
            receipt.guardian_pid.unwrap(),
            receipt.guardian_start_ticks.unwrap(),
        );
        leftovers.0.push(guardian);
        assert_eq!(
            unsafe { libc::getpgid(driver.0.id() as i32) },
            driver.0.id() as i32
        );
        assert_eq!(
            unsafe { libc::getsid(guardian.0 as i32) },
            guardian.0 as i32
        );
        assert_ne!(
            unsafe { libc::getpgid(guardian.0 as i32) },
            driver.0.id() as i32
        );
        assert!(fixture.require_clean().is_err());
        // Exact isolated driver group, as in the owning durable monitor's
        // cleanup after a driver crash. No unowned group is ever signaled.
        assert_eq!(
            unsafe { libc::kill(-(driver.0.id() as i32), libc::SIGKILL) },
            0
        );
        driver.0.wait().unwrap();
        let receipt = fixture.receipt_where(&identity, "member ECHILD receipt", PeerReceipt::clean);
        assert_eq!(receipt.error, None);
        assert_eq!(receipt.exit_code, Some(128 + libc::SIGTERM));
        assert_family_gone(&fixture, &family);
        fixture.wait_for("member guardian exit", || {
            (!alive(guardian.0, guardian.1)).then_some(())
        });
        assert!(sentinel.alive());
        let journal = fs::read_to_string(
            fixture
                .dir
                .join(format!("peer-{}.journal", identity.instance_id)),
        )
        .unwrap();
        assert!(journal.contains("adopted pid="), "{journal}");
        assert!(fixture.require_clean().unwrap().unwrap().clean());
    }

    #[test]
    fn provider_exit_reaps_leftover_family_and_returns_the_provider_status() {
        let fixture = fixture();
        let mut sentinel = Sentinel::spawn();
        let mut spec = fixture.spec(&["provider", "exit-on-eof"]);
        let release = fixture.work.join("release");
        spec.close_input_when = Some(release.clone());
        let (_driver, identity, family, _leftovers) = launched(&fixture, &spec);
        fs::write(release, b"").unwrap();

        let receipt = fixture.receipt_where(&identity, "clean custody", PeerReceipt::clean);
        assert_eq!(receipt.exit_code, Some(3));
        assert_eq!(receipt.error, None);
        assert_eq!(fixture.guardian_status(), "3");
        assert_family_gone(&fixture, &family);
        assert!(sentinel.alive(), "an unrelated process was signaled");
    }

    #[test]
    fn signal_guardian_escalates_a_term_resistant_provider_and_keeps_overdue_cleanup_unknown() {
        let fixture = fixture();
        let mut sentinel = Sentinel::spawn();
        let mut spec = fixture.spec(&["provider", "ignore-term"]);
        spec.term_grace_ms = 1500;
        spec.deadline_ms = 300;
        let (mut driver, identity, family, mut leftovers) = launched(&fixture, &spec);
        let receipt =
            fixture.receipt_where(&identity, "provider birth", |r| r.provider_pid.is_some());
        leftovers.0.push((
            receipt.guardian_pid.unwrap(),
            receipt.guardian_start_ticks.unwrap(),
        ));

        signal_guardian(&fixture.dir, &identity).unwrap();
        let overdue = fixture.receipt_where(&identity, "overdue cleanup", |r| {
            r.error.as_deref().is_some_and(|e| e.contains("exceeded"))
        });
        assert!(overdue.cleanup_unknown && overdue.finished_at.is_none());
        assert!(fixture.require_clean().is_err());

        let receipt = fixture.receipt_where(&identity, "clean custody", PeerReceipt::clean);
        assert_eq!(receipt.exit_code, Some(128 + libc::SIGKILL));
        assert_eq!(receipt.error, None);
        assert_eq!(fixture.guardian_status(), "137");
        assert_family_gone(&fixture, &family);
        assert!(sentinel.alive(), "an unrelated process was signaled");
        // A clean receipt is accepted without signaling anything.
        signal_guardian(&fixture.dir, &identity).unwrap();
        assert!(driver.0.wait().unwrap().success());
    }

    #[test]
    fn native_stdio_reaches_the_provider_byte_for_byte_without_private_descriptors() {
        let fixture = fixture();
        let mut spec = fixture.spec(&["echo"]);
        spec.input = b"in\x01\n".to_vec();
        spec.close_input_when = Some(fixture.work.clone());
        let _driver = DriverProcess::spawn(&fixture, &spec);
        let identity = fixture.identity();
        assert_eq!(fixture.guardian_status(), "0", "{}", fixture.diagnostics());
        assert_eq!(fixture.native_output("native.out"), b"out\0\xffin\x01\n");
        assert_eq!(fixture.native_output("native.err"), b"err");
        let receipt = read_receipt(&fixture.dir, &identity).unwrap();
        assert!(receipt.clean() && receipt.exit_code == Some(0) && receipt.error.is_none());

        let script = fixture.work.join("provider.sh").display().to_string();
        let listing = fs::read_to_string(fixture.work.join("fds")).unwrap();
        let mut stdio = 0;
        for line in listing.lines().filter(|line| line.contains(" -> ")) {
            let (left, target) = line.split_once(" -> ").unwrap();
            let fd: i32 = left.rsplit(' ').next().unwrap().parse().unwrap();
            if fd <= 2 {
                assert!(target.starts_with("pipe:"), "{listing}");
                stdio += 1;
            } else {
                // Only the shell's own script descriptor may remain.
                assert_eq!(
                    target, script,
                    "provider inherited a private descriptor\n{listing}"
                );
            }
        }
        assert_eq!(stdio, 3, "{listing}");
        assert!(!listing.contains("private-canary"), "{listing}");
    }

    #[test]
    fn guardian_sigkill_kills_the_provider_by_parent_death_and_leaves_custody_unknown() {
        let fixture = fixture();
        let spec = fixture.spec(&["provider", "hold"]);
        let (_driver, identity, family, mut leftovers) = launched(&fixture, &spec);
        let receipt =
            fixture.receipt_where(&identity, "provider birth", |r| r.provider_pid.is_some());
        let guardian = (
            receipt.guardian_pid.unwrap(),
            receipt.guardian_start_ticks.unwrap(),
        );
        leftovers.0.push(guardian);
        // Only this test kills a guardian. Adopted tools then escape custody
        // (the leftovers guard removes them); the receipt must say unknown.
        let process = pidfd_open(guardian.0).unwrap();
        assert!(alive(guardian.0, guardian.1));
        pidfd_signal(&process, libc::SIGKILL).unwrap();
        assert_eq!(fixture.guardian_status(), "signal 9");
        let (_, provider, ticks) = family[0];
        fixture.wait_for("provider parent-death signal", || {
            (!alive(provider, ticks)).then_some(())
        });
        let receipt = read_receipt(&fixture.dir, &identity).unwrap();
        assert!(receipt.cleanup_unknown && receipt.finished_at.is_none());
        assert!(fixture.require_clean().is_err());
        assert!(fixture.prepare().is_err());
        let error = format!(
            "{:#}",
            signal_guardian(&fixture.dir, &identity).unwrap_err()
        );
        assert!(error.contains("cleanup is unknown"), "{error}");
    }

    #[test]
    fn provider_start_failure_finishes_after_echild_without_launch_values() {
        let fixture = fixture();
        let mut spec = fixture.spec(&[]);
        spec.program = fixture.work.join("absent-provider");
        spec.arguments = vec!["launch-value-canary".into()];
        spec.close_input_when = Some(fixture.work.clone());
        let _driver = DriverProcess::spawn(&fixture, &spec);
        let identity = fixture.identity();
        assert_eq!(fixture.guardian_status(), "1");
        let receipt = read_receipt(&fixture.dir, &identity).unwrap();
        assert!(receipt.clean() && receipt.provider_pid.is_none() && receipt.exit_code.is_none());
        assert!(receipt.guardian_pid.is_some());
        let error = receipt.error.unwrap();
        assert!(error.contains("start the guest provider"), "{error}");
        let native_error = String::from_utf8(fixture.native_output("native.err")).unwrap();
        assert!(
            native_error.contains("start the guest provider"),
            "{native_error}"
        );
        assert_eq!(native_error.lines().count(), 1, "{native_error}");
        for name in [
            format!("peer-{}.json", identity.instance_id),
            format!("peer-{}.journal", identity.instance_id),
        ] {
            let text = fs::read_to_string(fixture.dir.join(name)).unwrap();
            assert!(!text.contains("absent-provider") && !text.contains("launch-value-canary"));
        }
    }

    fn peer_argv(fixture: &Fixture, identity: &PeerIdentity) -> Vec<String> {
        let mut argv = vec!["cw".to_owned()];
        for (flag, value) in [
            ("--environment", identity.environment_id.clone()),
            ("--driver-id", identity.driver_id.clone()),
            ("--session-id", identity.session_id.clone()),
            ("--instance-id", identity.instance_id.clone()),
            ("--driver-started-at", identity.driver_started_at.clone()),
            ("--driver-pid", identity.driver_pid.to_string()),
            (
                "--driver-start-ticks",
                identity.driver_start_ticks.to_string(),
            ),
            ("--guest-root", fixture.root.display().to_string()),
            ("--program", "/bin/true".to_owned()),
        ] {
            argv.extend([flag.to_owned(), value]);
        }
        argv.push("--".into());
        argv
    }

    fn run_guardian(fixture: &Fixture, argv: Vec<String>, via_shell: bool) -> (i32, String) {
        let spec = GuardianSpec {
            argv,
            native_fds: false,
            term_grace_ms: 1000,
            deadline_ms: 30_000,
        };
        let stderr = fixture
            .work
            .join(format!("guardian-{}.stderr", uuid::Uuid::new_v4()));
        let mut command = role("guardian", &spec);
        if via_shell {
            // Two commands defeat the shell's exec optimization, so the shell
            // stays the guardian's parent.
            let inner = command;
            command = Command::new("/bin/sh");
            command
                .arg("-c")
                .arg("\"$@\"; exit $?")
                .arg("sh")
                .arg(inner.get_program())
                .args(inner.get_args())
                .envs(
                    inner
                        .get_envs()
                        .filter_map(|(key, value)| Some((key, value?))),
                )
                .stdin(Stdio::null())
                .stdout(Stdio::null());
        }
        command.stderr(fs::File::create(&stderr).unwrap());
        let status = command.status().unwrap();
        (status.code().unwrap(), fs::read_to_string(stderr).unwrap())
    }

    #[test]
    fn guardian_refuses_unprepared_mismatched_or_foreign_parent_launches() {
        let fixture = fixture();
        let unprepared = PeerIdentity {
            environment_id: fixture.environment_id.clone(),
            driver_id: fixture.driver_id.clone(),
            session_id: fixture.session_id.clone(),
            instance_id: uuid::Uuid::new_v4().to_string(),
            driver_started_at: now(),
            boot_id: current_boot_id().unwrap(),
            driver_pid: std::process::id(),
            driver_start_ticks: process_stat(std::process::id()).unwrap().start_ticks,
        };
        let (code, stderr) = run_guardian(&fixture, peer_argv(&fixture, &unprepared), false);
        assert_eq!(code, 1);
        assert!(stderr.contains("not prepared"), "{stderr}");
        assert!(fixture.current().unwrap().is_none());

        // This test process is the prepared driver.
        let identity = fixture.prepare().unwrap();
        let mut argv = peer_argv(&fixture, &identity);
        let instance = argv.iter().position(|arg| arg == "--instance-id").unwrap() + 1;
        argv[instance] = uuid::Uuid::new_v4().to_string();
        let (code, stderr) = run_guardian(&fixture, argv, false);
        assert_eq!(code, 1);
        assert!(stderr.contains("do not match"), "{stderr}");
        let mut argv = peer_argv(&fixture, &identity);
        let root = argv.iter().position(|arg| arg == "--guest-root").unwrap() + 1;
        argv[root] = format!("{}/../guest", fixture.root.display());
        let (code, stderr) = run_guardian(&fixture, argv, false);
        assert_eq!(code, 1);
        assert!(stderr.contains("normalized"), "{stderr}");
        let untouched = read_receipt(&fixture.dir, &identity).unwrap();
        assert_eq!(untouched, PeerReceipt::unknown(identity.clone()));

        let (code, stderr) = run_guardian(&fixture, peer_argv(&fixture, &identity), true);
        assert_eq!(code, 1);
        assert!(stderr.contains("direct child"), "{stderr}");
        // Under the instance lock nothing was ever spawned, so the instance is
        // finished after ECHILD rather than left fencing the conversation.
        let receipt = read_receipt(&fixture.dir, &identity).unwrap();
        assert!(receipt.clean() && receipt.provider_pid.is_none());
        assert!(receipt.error.unwrap().contains("direct child"));
    }

    #[test]
    fn prepare_records_unknown_custody_before_its_pointer_and_fences_reuse() {
        let fixture = fixture();
        assert!(fixture.current().unwrap().is_none());
        assert!(fixture.require_clean().unwrap().is_none());
        let identity = fixture.prepare().unwrap();
        let me = std::process::id();
        assert_eq!(identity.driver_pid, me);
        assert_eq!(
            identity.driver_start_ticks,
            process_stat(me).unwrap().start_ticks
        );
        assert_eq!(identity.boot_id, current_boot_id().unwrap());
        let receipt = fixture.current().unwrap().unwrap();
        assert_eq!(receipt, PeerReceipt::unknown(identity.clone()));
        assert_eq!(read_receipt(&fixture.dir, &identity).unwrap(), receipt);
        for name in [
            CURRENT_POINTER.to_owned(),
            format!("peer-{}.json", identity.instance_id),
        ] {
            let mode = fs::metadata(fixture.dir.join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let error = fixture.require_clean().unwrap_err().to_string();
        assert!(error.contains("unknown"), "{error}");
        assert!(fixture.prepare().is_err());
        assert_eq!(fixture.current().unwrap().unwrap().identity, identity);
        assert!(signal_guardian(&fixture.dir, &identity).is_err());
    }

    #[test]
    fn clean_custody_admits_the_next_instance() {
        let fixture = fixture();
        let first = fixture.prepare().unwrap();
        let mut receipt = PeerReceipt::unknown(first.clone());
        receipt.guardian_pid = Some(4242);
        receipt.guardian_start_ticks = Some(1);
        receipt.cleanup_unknown = false;
        receipt.finished_at = Some(now());
        receipt.exit_code = Some(0);
        fixture.write_receipt(&receipt);
        assert_eq!(fixture.require_clean().unwrap(), Some(receipt.clone()));
        let second = fixture.prepare().unwrap();
        assert_ne!(second.instance_id, first.instance_id);
        assert_eq!(fixture.current().unwrap().unwrap().identity, second);
        assert_eq!(read_receipt(&fixture.dir, &first).unwrap(), receipt);
    }

    #[test]
    fn missing_mismatched_or_inconsistent_receipts_are_refused() {
        let fixture = fixture();
        let identity = fixture.prepare().unwrap();
        let other = uuid::Uuid::new_v4().to_string();
        assert!(
            current_receipt(
                &fixture.dir,
                &other,
                &fixture.driver_id,
                &fixture.session_id
            )
            .is_err()
        );
        let session = format!("session-{other}");
        assert!(
            current_receipt(
                &fixture.dir,
                &fixture.environment_id,
                &fixture.driver_id,
                &session
            )
            .is_err()
        );
        assert!(
            current_receipt(
                &fixture.dir,
                &fixture.environment_id,
                &other,
                &fixture.session_id
            )
            .is_err()
        );

        let path = receipt_path(&fixture.dir, &identity.instance_id).unwrap();
        let original = fs::read(&path).unwrap();
        let mut extra: serde_json::Value = serde_json::from_slice(&original).unwrap();
        extra["launch"] = json!("value");
        write_private_json(&path, &extra).unwrap();
        assert!(fixture.current().is_err());

        let mut foreign = PeerReceipt::unknown(identity.clone());
        foreign.identity.driver_pid += 1;
        write_private_json(&path, &foreign).unwrap();
        assert!(fixture.current().is_err());

        let mut open = PeerReceipt::unknown(identity.clone());
        open.cleanup_unknown = false;
        write_private_json(&path, &open).unwrap();
        assert!(fixture.current().is_err());
        assert!(fixture.require_clean().is_err());

        fs::remove_file(&path).unwrap();
        assert!(fixture.current().is_err());
        assert!(read_receipt(&fixture.dir, &identity).is_err());
        assert!(fixture.prepare().is_err());
    }

    #[test]
    fn custody_from_another_boot_is_refused_even_when_clean() {
        let fixture = fixture();
        let identity = fixture.prepare().unwrap();
        let mut stale = identity.clone();
        stale.boot_id = uuid::Uuid::new_v4().to_string();
        let mut receipt = PeerReceipt::unknown(stale.clone());
        receipt.guardian_pid = Some(4242);
        receipt.guardian_start_ticks = Some(1);
        receipt.cleanup_unknown = false;
        receipt.finished_at = Some(now());
        fixture.write_receipt(&receipt);
        write_private_json(&fixture.dir.join(CURRENT_POINTER), &stale).unwrap();
        let error = format!("{:#}", fixture.current().unwrap_err());
        assert!(error.contains("another boot"), "{error}");
        assert!(fixture.require_clean().is_err());
        assert!(fixture.prepare().is_err());
        assert!(read_receipt(&fixture.dir, &stale).is_err());
        assert!(signal_guardian(&fixture.dir, &stale).is_err());
    }

    #[test]
    fn custody_requires_the_canonical_private_driver_directory() {
        let fixture = fixture();
        let alias = fixture.work.join("alias");
        std::os::unix::fs::symlink(&fixture.root, &alias).unwrap();
        let aliased = alias.join("agents").join(&fixture.driver_id);
        let prepare_at = |dir: &Path, driver_id: &str| {
            prepare(
                dir,
                &fixture.environment_id,
                driver_id,
                &fixture.session_id,
                &now(),
            )
        };
        assert!(prepare_at(&aliased, &fixture.driver_id).is_err());
        let relative = Path::new("guest/agents").join(&fixture.driver_id);
        assert!(prepare_at(&relative, &fixture.driver_id).is_err());
        let other = uuid::Uuid::new_v4().to_string();
        assert!(prepare_at(&fixture.dir, &other).is_err());
        assert!(
            prepare(
                &fixture.dir,
                &fixture.environment_id,
                &fixture.driver_id,
                "session-x",
                &now()
            )
            .is_err()
        );
        assert!(
            prepare(
                &fixture.dir,
                &fixture.environment_id,
                &fixture.driver_id,
                &fixture.session_id,
                "yesterday"
            )
            .is_err()
        );
        fs::set_permissions(&fixture.dir, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(prepare_at(&fixture.dir, &fixture.driver_id).is_err());
        fs::set_permissions(&fixture.dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!fixture.dir.join(CURRENT_POINTER).exists());
        prepare_at(&fixture.dir, &fixture.driver_id).unwrap();
        assert!(fixture.dir.join(CURRENT_POINTER).exists());
    }

    #[test]
    fn signal_guardian_signals_only_the_exact_recorded_guardian_birth_with_sigterm() {
        let fixture = fixture();
        let mut sentinel = Sentinel::spawn();
        let (pid, ticks) = sentinel.birth();
        let identity = fixture.prepare().unwrap();
        let mut receipt = PeerReceipt::unknown(identity.clone());
        assert!(signal_guardian(&fixture.dir, &identity).is_err());

        receipt.guardian_pid = Some(pid);
        receipt.guardian_start_ticks = Some(ticks + 1);
        fixture.write_receipt(&receipt);
        assert!(signal_guardian(&fixture.dir, &identity).is_err());
        assert!(sentinel.alive(), "a reused guardian PID was signaled");

        let mut exited = Command::new("/bin/true").spawn().unwrap();
        let exited_pid = exited.id();
        exited.wait().unwrap();
        receipt.guardian_pid = Some(exited_pid);
        receipt.guardian_start_ticks = Some(1);
        fixture.write_receipt(&receipt);
        let error = format!(
            "{:#}",
            signal_guardian(&fixture.dir, &identity).unwrap_err()
        );
        assert!(error.contains("cleanup is unknown"), "{error}");

        // An exited but unreaped guardian still accepts signals.
        let mut zombie = Command::new("/bin/true").spawn().unwrap();
        let zombie_pid = zombie.id();
        // SAFETY: a zeroed siginfo_t is valid writable storage for waitid.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: info is writable; WNOWAIT leaves the child unreaped.
        let waited = unsafe {
            libc::waitid(
                libc::P_PID,
                zombie_pid,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        assert_eq!(waited, 0);
        receipt.guardian_pid = Some(zombie_pid);
        receipt.guardian_start_ticks = Some(process_stat(zombie_pid).unwrap().start_ticks);
        fixture.write_receipt(&receipt);
        let error = format!(
            "{:#}",
            signal_guardian(&fixture.dir, &identity).unwrap_err()
        );
        assert!(error.contains("cleanup is unknown"), "{error}");
        zombie.wait().unwrap();

        let mut clean = receipt.clone();
        clean.guardian_pid = Some(pid);
        clean.guardian_start_ticks = Some(ticks);
        clean.cleanup_unknown = false;
        clean.finished_at = Some(now());
        fixture.write_receipt(&clean);
        signal_guardian(&fixture.dir, &identity).unwrap();
        assert!(sentinel.alive(), "a clean receipt must not signal");

        receipt.guardian_pid = Some(pid);
        receipt.guardian_start_ticks = Some(ticks);
        fixture.write_receipt(&receipt);
        signal_guardian(&fixture.dir, &identity).unwrap();
        let status = sentinel.0.wait().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGTERM));
    }

    #[test]
    fn proc_stat_parser_uses_the_last_close_paren() {
        let mut fields = vec!["S".to_owned(), "77".to_owned()];
        fields.extend((5..=21).map(|field| field.to_string()));
        fields.push("987654".to_owned());
        fields.extend((23..=52).map(|field| field.to_string()));
        let stat = parse_stat(&format!("123 (tricky ) name) {}", fields.join(" "))).unwrap();
        assert_eq!((stat.ppid, stat.start_ticks), (77, 987654));
    }
}
