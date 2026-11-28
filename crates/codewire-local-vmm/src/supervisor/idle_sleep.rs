//! Local Linux VM idle suspend and idle hibernate policy & monitor (#5529,
//! protocol 32, `docs/dev/LOCAL-VM-SLEEP.md`).
//!
//! Policy persists per VM at `vms/<id>/hibernate/idle.json` (mode `0600`
//! inside `0700`) so it survives stop/start, hibernate, and supervisor restart
//! without altering the SQLite schema, and is automatically cleaned up on
//! delete (`state::cleanup_trashed_vm`).
//!
//! Activity is tracked on the host without waking sleeping VMs:
//! - VMM process CPU time (`/proc/<vmm_pid>/stat` on Linux, >= 10% of 1 vCPU)
//! - Guest daemon `GetActivity(include_guest_cpu: false)` (only while awake)
//! - Inbound host-port traffic (`RunnerInfo.last_host_port_activity_unix_ms`)
//! - Supervisor-side SSH streams, local HTTPS requests, VM starts/wakes, and
//!   checkpoints.

use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
#[cfg(target_os = "linux")]
use std::time::Duration;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tonic::Status;
use uuid::Uuid;

use super::Supervisor;
use super::hibernate;
#[cfg(target_os = "linux")]
use super::{StoredEnvironmentState, artifact_generation_for_boot};
use crate::control::v1;
#[cfg(target_os = "linux")]
use crate::diagnostic_log::{self, LogField};
use crate::host::path::PrivateRoot;
use crate::state::HIBERNATE_DIRECTORY;

const IDLE_POLICY_FILE: &str = "idle.json";
const SCHEMA_VERSION: u32 = 1;
const MAX_POLICY_BYTES: u64 = 16 * 1024;

/// How often the supervisor sweeps running VMs with idle sleep enabled.
#[cfg(target_os = "linux")]
const IDLE_SLEEP_SWEEP: Duration = Duration::from_secs(10);
/// Sliding window for VMM CPU sampling (`docs/dev/LOCAL-VM-SLEEP.md`: 10% of
/// one CPU over a minute, i.e. 6 seconds of CPU time in 60 seconds).
#[cfg(target_os = "linux")]
const CPU_WINDOW: Duration = Duration::from_secs(60);
/// Minimum elapsed window before evaluating the 10% VMM CPU ratio so transient
/// jitter cannot falsely trigger or miss a burn.
#[cfg(target_os = "linux")]
const CPU_MIN_WINDOW: Duration = Duration::from_secs(5);
/// Timeout for polling a running, awake guest daemon's `GetActivity` RPC.
#[cfg(target_os = "linux")]
const DAEMON_ACTIVITY_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::supervisor) struct IdlePolicy {
    pub schema_version: u32,
    pub idle_suspend_seconds: u32,
    pub idle_hibernate_seconds: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_hibernate_skip_reason: Option<String>,
}

impl IdlePolicy {
    pub(in crate::supervisor) fn new(
        idle_suspend_seconds: u32,
        idle_hibernate_seconds: u32,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            idle_suspend_seconds,
            idle_hibernate_seconds,
            idle_hibernate_skip_reason: None,
        }
    }

    pub(in crate::supervisor) fn is_enabled(&self) -> bool {
        self.idle_suspend_seconds > 0 || self.idle_hibernate_seconds > 0
    }
}

/// Validates idle suspend and hibernate timeouts using the exact shared
/// `codewire_project` bounds and ordering rules (`5m`..=`7d`, `0` = off, and
/// `idle_hibernate > idle_suspend` when both are enabled).
pub(in crate::supervisor) fn validate_idle_policy(
    idle_suspend_seconds: u32,
    idle_hibernate_seconds: u32,
) -> Result<(), Status> {
    #[cfg(not(target_os = "linux"))]
    if idle_suspend_seconds > 0 || idle_hibernate_seconds > 0 {
        return Err(Status::unimplemented(
            "local VM sleep is supported only on Linux",
        ));
    }
    let suspend = i32::try_from(idle_suspend_seconds)
        .map_err(|_| Status::invalid_argument("idle_suspend_seconds is out of range"))?;
    let hibernate = i32::try_from(idle_hibernate_seconds)
        .map_err(|_| Status::invalid_argument("idle_hibernate_seconds is out of range"))?;
    codewire_project::validate_idle_suspend_seconds(suspend)
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
    codewire_project::validate_idle_hibernate_seconds(hibernate)
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
    codewire_project::validate_idle_hibernate_after_suspend(suspend, hibernate)
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
    Ok(())
}

/// Reads persisted idle policy for `environment_id`, returning `Default` (both
/// off) when absent or unreadable.
pub(in crate::supervisor) fn read_policy(engine_root: &Path, environment_id: Uuid) -> IdlePolicy {
    let hib = hibernate::hibernate_dir(engine_root, environment_id);
    let Ok(hib_root) = PrivateRoot::open(&hib) else {
        return IdlePolicy::default();
    };
    let Ok(bytes) =
        hibernate::read_regular_nofollow(&hib_root.path().join(IDLE_POLICY_FILE), MAX_POLICY_BYTES)
    else {
        return IdlePolicy::default();
    };
    let Ok(policy) = serde_json::from_slice::<IdlePolicy>(&bytes) else {
        return IdlePolicy::default();
    };
    if policy.schema_version != SCHEMA_VERSION {
        return IdlePolicy::default();
    }
    policy
}

/// Persists `policy` under `vms/<id>/hibernate/idle.json` (mode `0600` inside
/// `0700`). When both timeouts are 0 and there is no skip reason, removes the
/// file cleanly.
pub(in crate::supervisor) fn write_policy(
    engine_root: &Path,
    environment_id: Uuid,
    policy: &IdlePolicy,
) -> io::Result<()> {
    let hib = hibernate::hibernate_dir(engine_root, environment_id);
    if !policy.is_enabled() && policy.idle_hibernate_skip_reason.is_none() {
        if let Ok(hib_root) = PrivateRoot::open(&hib) {
            let _ = fs::remove_file(hib_root.path().join(IDLE_POLICY_FILE));
            let _ = hibernate::sync_dir(hib_root.path());
            hibernate::remove_dir_if_empty(&hib);
        }
        return Ok(());
    }
    let engine = PrivateRoot::open(engine_root).map_err(hibernate::path_io)?;
    let vms = engine
        .ensure_dir(Path::new("vms"), 0o700)
        .map_err(hibernate::path_io)?;
    let vms_root = PrivateRoot::open(&vms).map_err(hibernate::path_io)?;
    let vm = vms_root
        .ensure_dir(Path::new(&environment_id.to_string()), 0o700)
        .map_err(hibernate::path_io)?;
    let vm_root = PrivateRoot::open(&vm).map_err(hibernate::path_io)?;
    let dir = vm_root
        .ensure_dir(Path::new(HIBERNATE_DIRECTORY), 0o700)
        .map_err(hibernate::path_io)?;
    let hib_root = PrivateRoot::open(&dir).map_err(hibernate::path_io)?;

    let mut stored = policy.clone();
    stored.schema_version = SCHEMA_VERSION;
    let bytes = serde_json::to_vec(&stored)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    hibernate::write_private_atomic(hib_root.path(), IDLE_POLICY_FILE, &bytes)?;
    hibernate::sync_dir(hib_root.path())?;
    Ok(())
}

/// Records why an automatic idle hibernate was skipped (e.g. insufficient free
/// disk space) without altering the configured timeouts.
#[cfg(any(target_os = "linux", test))]
pub(in crate::supervisor) fn record_skip_reason(
    engine_root: &Path,
    environment_id: Uuid,
    reason: String,
) {
    let mut policy = read_policy(engine_root, environment_id);
    if !policy.is_enabled() {
        return;
    }
    policy.idle_hibernate_skip_reason = Some(reason);
    let _ = write_policy(engine_root, environment_id, &policy);
}

/// Clears any recorded idle-hibernate skip reason while preserving configured
/// timeouts.
pub(in crate::supervisor) fn clear_skip_reason(engine_root: &Path, environment_id: Uuid) {
    let mut policy = read_policy(engine_root, environment_id);
    if policy.idle_hibernate_skip_reason.take().is_some() {
        let _ = write_policy(engine_root, environment_id, &policy);
    }
}

/// Populates `idle_suspend_seconds`, `idle_hibernate_seconds`, and
/// `idle_hibernate_skip_reason` on `environment`.
pub(in crate::supervisor) fn apply_to_environment(
    engine_root: &Path,
    environment: &mut v1::Environment,
) {
    let Ok(id) = Uuid::parse_str(&environment.id) else {
        return;
    };
    let policy = read_policy(engine_root, id);
    environment.idle_suspend_seconds = policy.idle_suspend_seconds;
    environment.idle_hibernate_seconds = policy.idle_hibernate_seconds;
    environment.idle_hibernate_skip_reason = policy.idle_hibernate_skip_reason.unwrap_or_default();
}

/// In-memory per-environment activity clock owned by [`Supervisor`].
#[derive(Default)]
pub(in crate::supervisor) struct IdleTracker {
    entries: Mutex<HashMap<Uuid, EnvActivity>>,
}

#[derive(Debug)]
struct EnvActivity {
    #[cfg(target_os = "linux")]
    generation: u64,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    last_activity: Instant,
    #[cfg(target_os = "linux")]
    last_daemon_active_secs: Option<i64>,
    #[cfg(target_os = "linux")]
    last_host_port_activity_ms: i64,
    #[cfg(target_os = "linux")]
    vmm_pid: u32,
    #[cfg(target_os = "linux")]
    cpu_samples: VecDeque<(Instant, u64)>,
}

impl EnvActivity {
    fn new(generation: u64, now: Instant) -> Self {
        #[cfg(not(target_os = "linux"))]
        let _ = generation;
        Self {
            #[cfg(target_os = "linux")]
            generation,
            last_activity: now,
            #[cfg(target_os = "linux")]
            last_daemon_active_secs: None,
            #[cfg(target_os = "linux")]
            last_host_port_activity_ms: 0,
            #[cfg(target_os = "linux")]
            vmm_pid: 0,
            #[cfg(target_os = "linux")]
            cpu_samples: VecDeque::new(),
        }
    }
}

impl IdleTracker {
    /// Records that `environment_id` started or woke at `generation`.
    pub(in crate::supervisor) fn note_started(&self, environment_id: Uuid, generation: u64) {
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.insert(environment_id, EnvActivity::new(generation, now));
    }

    /// Records fresh supervisor-observed activity (resume, SSH frame, local
    /// HTTPS request, checkpoint).
    pub(in crate::supervisor) fn note_activity(&self, environment_id: Uuid) {
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = entries.get_mut(&environment_id) {
            entry.last_activity = now;
        }
    }

    /// Removes tracking for a stopped, hibernated, or deleted environment.
    pub(in crate::supervisor) fn forget(&self, environment_id: Uuid) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&environment_id);
    }

    /// Returns elapsed idle time for `(environment_id, generation)` without
    /// mutating `last_activity` (creating a fresh entry if unseen).
    #[cfg(target_os = "linux")]
    fn elapsed_since_activity(&self, environment_id: Uuid, generation: u64) -> Duration {
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries
            .entry(environment_id)
            .or_insert_with(|| EnvActivity::new(generation, now));
        if entry.generation != generation {
            *entry = EnvActivity::new(generation, now);
        }
        now.saturating_duration_since(entry.last_activity)
    }

    /// Incorporates fresh awake-only signals (host-port activity, VMM CPU ticks,
    /// and guest daemon `GetActivity`) and returns elapsed idle duration.
    #[cfg(target_os = "linux")]
    fn observe_awake(&self, sample: AwakeSample) -> Duration {
        let AwakeSample {
            environment_id,
            generation,
            vmm_pid,
            vmm_cpu_ticks,
            clk_tck,
            host_port_activity_ms,
            daemon_active_secs,
        } = sample;
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries
            .entry(environment_id)
            .or_insert_with(|| EnvActivity::new(generation, now));
        if entry.generation != generation {
            *entry = EnvActivity::new(generation, now);
        }

        if host_port_activity_ms > entry.last_host_port_activity_ms {
            entry.last_host_port_activity_ms = host_port_activity_ms;
            entry.last_activity = now;
        }

        if let Some(seen) = daemon_active_secs {
            match entry.last_daemon_active_secs {
                None => {
                    // First sample after start/adoption establishes the
                    // baseline without resetting the clock if it predates
                    // boot, while noting any newer activity going forward.
                    entry.last_daemon_active_secs = Some(seen);
                }
                Some(prev) if seen > prev => {
                    entry.last_daemon_active_secs = Some(seen);
                    entry.last_activity = now;
                }
                Some(_) => {}
            }
        }

        if vmm_pid != 0 {
            if entry.vmm_pid != vmm_pid {
                entry.vmm_pid = vmm_pid;
                entry.cpu_samples.clear();
            }
            if let Some(ticks) = vmm_cpu_ticks {
                entry.cpu_samples.push_back((now, ticks));
                while entry
                    .cpu_samples
                    .front()
                    .is_some_and(|(t, _)| now.saturating_duration_since(*t) > CPU_WINDOW)
                {
                    // Keep one sample at or just past the 60s boundary so the
                    // window stays ~60s wide instead of collapsing.
                    if entry.cpu_samples.len() <= 2 {
                        break;
                    }
                    entry.cpu_samples.pop_front();
                }
                if cpu_window_busy(&entry.cpu_samples, clk_tck, CPU_MIN_WINDOW) {
                    entry.last_activity = now;
                }
            }
        }

        now.saturating_duration_since(entry.last_activity)
    }
}

/// Awake-only host and guest activity signals sampled on one monitor sweep.
#[cfg(target_os = "linux")]
struct AwakeSample {
    environment_id: Uuid,
    generation: u64,
    vmm_pid: u32,
    vmm_cpu_ticks: Option<u64>,
    clk_tck: u64,
    host_port_activity_ms: i64,
    daemon_active_secs: Option<i64>,
}

/// What the idle sleep monitor should do for one running environment.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdleAction {
    None,
    Suspend,
    Hibernate,
}

#[cfg(any(target_os = "linux", test))]
fn decide_idle_action(
    is_suspended: bool,
    elapsed: std::time::Duration,
    idle_suspend_seconds: u32,
    idle_hibernate_seconds: u32,
) -> IdleAction {
    let elapsed_secs = elapsed.as_secs();
    if idle_hibernate_seconds > 0 && elapsed_secs >= u64::from(idle_hibernate_seconds) {
        return IdleAction::Hibernate;
    }
    if !is_suspended && idle_suspend_seconds > 0 && elapsed_secs >= u64::from(idle_suspend_seconds)
    {
        return IdleAction::Suspend;
    }
    IdleAction::None
}

/// Parses `utime + stime` (fields 14 and 15, 1-indexed) from Linux
/// `/proc/<pid>/stat`, safely handling process names containing spaces or
/// parentheses by locating the last `')'`.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_stat_cpu_ticks(stat: &str) -> Option<u64> {
    let after_comm = stat.rsplit_once(')')?.1;
    let mut fields = after_comm.split_whitespace();
    // After ')': field 3 is state (index 0), ..., field 14 is utime (index 11),
    // field 15 is stime (index 12).
    let utime: u64 = fields.nth(11)?.parse().ok()?;
    let stime: u64 = fields.next()?.parse().ok()?;
    Some(utime.saturating_add(stime))
}

#[cfg(target_os = "linux")]
fn read_vmm_cpu_ticks(pid: u32) -> Option<u64> {
    if pid == 0 {
        return None;
    }
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_proc_stat_cpu_ticks(&stat)
}

#[cfg(target_os = "linux")]
fn linux_clk_tck() -> u64 {
    // SAFETY: `sysconf(_SC_CLK_TCK)` is a standard read-only POSIX query.
    let raw = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    u64::try_from(raw).ok().filter(|v| *v > 0).unwrap_or(100)
}

/// True when the VMM consumed at least 10% of one CPU across the sampled
/// window (matching `docs/dev/LOCAL-VM-SLEEP.md`: 6 seconds of CPU time per
/// minute).
#[cfg(any(target_os = "linux", test))]
fn cpu_window_busy(
    samples: &std::collections::VecDeque<(Instant, u64)>,
    clk_tck: u64,
    min_window: std::time::Duration,
) -> bool {
    let (Some(&(first_at, first_ticks)), Some(&(last_at, last_ticks))) =
        (samples.front(), samples.back())
    else {
        return false;
    };
    let wall = last_at.saturating_duration_since(first_at);
    if wall < min_window || clk_tck == 0 {
        return false;
    }
    let Some(delta_ticks) = last_ticks.checked_sub(first_ticks) else {
        return false;
    };
    let cpu_ms = u128::from(delta_ticks) * 1_000 / u128::from(clk_tck);
    let wall_ms = wall.as_millis();
    wall_ms > 0 && cpu_ms.saturating_mul(10) >= wall_ms
}

#[cfg(target_os = "linux")]
async fn query_daemon_activity(access: &v1::DaemonAccess) -> Option<i64> {
    use crate::hybrid_vsock::HybridVsockTarget;
    use codewire_daemon::DaemonAuthToken;
    use codewire_daemon_proto::DAEMON_AUTH_TOKEN_HEADER;
    use codewire_daemon_proto::daemon::v1::{
        GetActivityRequest, daemon_service_client::DaemonServiceClient,
    };

    let capability = zeroize::Zeroizing::new(access.generation_capability.clone());
    let _valid = DaemonAuthToken::new(capability.as_str()).ok()?;
    let target = HybridVsockTarget::new(
        std::path::PathBuf::from(&access.hybrid_socket),
        access.guest_port,
    )
    .ok()?;
    let header: tonic::metadata::MetadataValue<tonic::metadata::Ascii> =
        capability.as_str().parse().ok()?;
    tokio::time::timeout(DAEMON_ACTIVITY_TIMEOUT, async move {
        let channel = target.connect_channel().await.ok()?;
        let mut client = DaemonServiceClient::new(channel);
        let mut request = tonic::Request::new(GetActivityRequest {
            include_guest_cpu: false,
        });
        request
            .metadata_mut()
            .insert(DAEMON_AUTH_TOKEN_HEADER, header);
        let response = client.get_activity(request).await.ok()?.into_inner();
        response.last_active_at.map(|ts| ts.seconds)
    })
    .await
    .ok()
    .flatten()
}

#[cfg(target_os = "linux")]
impl Supervisor {
    /// Background monitor enforcing per-VM `--idle-suspend` and
    /// `--idle-hibernate` timeouts on Linux (#5529).
    pub(super) async fn run_idle_sleep_monitor(self: Arc<Self>) {
        let clk_tck = linux_clk_tck();
        let mut sweeps = tokio::time::interval(IDLE_SLEEP_SWEEP);
        sweeps.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        sweeps.tick().await;
        loop {
            sweeps.tick().await;
            self.sweep_idle_environments(clk_tck).await;
        }
    }

    async fn sweep_idle_environments(&self, clk_tck: u64) {
        let engine_root = self.config.engine_root();
        let running: Vec<(Uuid, String, u64, String, u32, IdlePolicy)> = {
            let core = self.core();
            core.state
                .environments
                .values()
                .filter(|env| env.state == StoredEnvironmentState::Running)
                .filter_map(|env| {
                    let policy = read_policy(&engine_root, env.id);
                    if !policy.is_enabled() {
                        return None;
                    }
                    let artifact = artifact_generation_for_boot(env, false).ok()?.to_owned();
                    Some((
                        env.id,
                        env.name.clone(),
                        env.generation,
                        artifact,
                        env.memory_mib,
                        policy,
                    ))
                })
                .collect()
        };

        for (id, name, generation, artifact_generation, memory_mib, policy) in running {
            let Ok(mut runner) = self
                .runner_client_for_artifact(&name, &artifact_generation)
                .await
            else {
                continue;
            };
            let Ok(info) = runner.info().await else {
                continue;
            };
            if info.state != v1::EnvironmentState::Running as i32 || info.generation != generation {
                continue;
            }
            let is_suspended = info.suspended_at_unix_ms > 0;
            let elapsed = if is_suspended {
                // Suspended VMs are NEVER probed so their idle clock advances
                // smoothly toward `idle_hibernate` without waking.
                self.idle_tracker.elapsed_since_activity(id, generation)
            } else {
                let vmm_ticks = read_vmm_cpu_ticks(info.vmm_pid);
                let daemon_active = match runner.daemon_access().await {
                    Ok(access) => query_daemon_activity(&access).await,
                    Err(_) => None,
                };
                self.idle_tracker.observe_awake(AwakeSample {
                    environment_id: id,
                    generation,
                    vmm_pid: info.vmm_pid,
                    vmm_cpu_ticks: vmm_ticks,
                    clk_tck,
                    host_port_activity_ms: info.last_host_port_activity_unix_ms,
                    daemon_active_secs: daemon_active,
                })
            };

            match decide_idle_action(
                is_suspended,
                elapsed,
                policy.idle_suspend_seconds,
                policy.idle_hibernate_seconds,
            ) {
                IdleAction::None => {}
                IdleAction::Suspend => {
                    self.try_idle_suspend(&name, id, generation).await;
                }
                IdleAction::Hibernate => {
                    self.try_idle_hibernate(&name, id, generation, memory_mib)
                        .await;
                }
            }
        }
    }

    async fn try_idle_suspend(&self, name: &str, expected_id: Uuid, expected_generation: u64) {
        let Ok(_lease) = self.quiet_lease(name).await else {
            return;
        };
        let Ok(env) = self.environment(name) else {
            return;
        };
        if env.id != expected_id
            || env.state != StoredEnvironmentState::Running
            || env.generation != expected_generation
        {
            return;
        }
        let policy = read_policy(&self.config.engine_root(), env.id);
        let elapsed = self
            .idle_tracker
            .elapsed_since_activity(env.id, env.generation);
        if policy.idle_suspend_seconds == 0
            || elapsed.as_secs() < u64::from(policy.idle_suspend_seconds)
        {
            return;
        }
        let Ok(artifact) = artifact_generation_for_boot(&env, false) else {
            return;
        };
        let Ok(mut runner) = self.runner_client_for_artifact(name, artifact).await else {
            return;
        };
        if runner
            .suspend_vm(env.id, env.generation, Uuid::new_v4(), "idle")
            .await
            .is_ok()
        {
            diagnostic_log::record(
                self.log.as_deref(),
                "idle_suspend_applied",
                &[
                    ("environment", LogField::Id(env.id)),
                    ("generation", LogField::Count(env.generation)),
                ],
            );
        }
    }

    async fn try_idle_hibernate(
        &self,
        name: &str,
        expected_id: Uuid,
        expected_generation: u64,
        memory_mib: u32,
    ) {
        let Ok(_lease) = self.quiet_lease(name).await else {
            return;
        };
        let Ok(env) = self.environment(name) else {
            return;
        };
        if env.id != expected_id
            || env.state != StoredEnvironmentState::Running
            || env.generation != expected_generation
        {
            return;
        }
        let engine_root = self.config.engine_root();
        let policy = read_policy(&engine_root, env.id);
        let elapsed = self
            .idle_tracker
            .elapsed_since_activity(env.id, env.generation);
        if policy.idle_hibernate_seconds == 0
            || elapsed.as_secs() < u64::from(policy.idle_hibernate_seconds)
        {
            return;
        }
        let space_root = engine_root.clone();
        let space_check = tokio::task::spawn_blocking(move || {
            hibernate::require_hibernate_space(&space_root, memory_mib)
        })
        .await;
        match space_check {
            Ok(Ok(())) => {}
            Ok(Err(status)) => {
                record_skip_reason(&engine_root, env.id, status.message().to_owned());
                diagnostic_log::record(
                    self.log.as_deref(),
                    "idle_hibernate_skipped",
                    &[
                        ("environment", LogField::Id(env.id)),
                        ("reason", LogField::Name("insufficient_space")),
                    ],
                );
                return;
            }
            Err(_) => return,
        }
        if self
            .hibernate_environment_under_lease(name, Some(expected_id), "idle")
            .await
            .is_ok()
        {
            clear_skip_reason(&engine_root, env.id);
            self.idle_tracker.forget(env.id);
            diagnostic_log::record(
                self.log.as_deref(),
                "idle_hibernate_applied",
                &[
                    ("environment", LogField::Id(env.id)),
                    ("generation", LogField::Count(env.generation)),
                ],
            );
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl Supervisor {
    pub(super) async fn run_idle_sleep_monitor(self: Arc<Self>) {
        // Local VM sleep is Linux-only (#5529).
        let _ = self;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn idle_policy_validation_enforces_bounds_and_ordering() {
        validate_idle_policy(0, 0).unwrap();
        validate_idle_policy(300, 0).unwrap();
        validate_idle_policy(0, 300).unwrap();
        validate_idle_policy(300, 600).unwrap();
        validate_idle_policy(900, 21_600).unwrap();
        assert!(validate_idle_policy(299, 0).is_err());
        assert!(validate_idle_policy(0, 299).is_err());
        let err = validate_idle_policy(600, 600).unwrap_err();
        assert!(
            err.message().contains("idle_hibernate"),
            "{}",
            err.message()
        );
        assert!(err.message().contains("10m"), "{}", err.message());
        let err = validate_idle_policy(900, 600).unwrap_err();
        assert!(
            err.message().contains("idle_hibernate"),
            "{}",
            err.message()
        );
        assert!(err.message().contains("15m"), "{}", err.message());
    }

    #[test]
    fn idle_policy_persists_records_skip_and_cleans_when_off() {
        let engine = tempfile::tempdir().unwrap();
        fs::set_permissions(engine.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let id = Uuid::new_v4();

        assert_eq!(read_policy(engine.path(), id), IdlePolicy::default());

        let policy = IdlePolicy::new(900, 21_600);
        write_policy(engine.path(), id, &policy).unwrap();
        assert_eq!(read_policy(engine.path(), id), policy);

        record_skip_reason(engine.path(), id, "needs 3.0 GiB free".to_owned());
        assert_eq!(
            read_policy(engine.path(), id)
                .idle_hibernate_skip_reason
                .as_deref(),
            Some("needs 3.0 GiB free")
        );

        clear_skip_reason(engine.path(), id);
        assert_eq!(
            read_policy(engine.path(), id).idle_hibernate_skip_reason,
            None
        );

        // Turning both off removes idle.json cleanly.
        write_policy(engine.path(), id, &IdlePolicy::new(0, 0)).unwrap();
        assert!(
            !hibernate::hibernate_dir(engine.path(), id)
                .join(IDLE_POLICY_FILE)
                .exists()
        );
    }

    #[test]
    fn proc_stat_parser_handles_spaces_and_parens_in_comm() {
        let stat = "12345 (cloud-hyper (v54)) S 1 2 3 4 5 6 7 8 9 10 420 80 0 0 20 0 4";
        assert_eq!(parse_proc_stat_cpu_ticks(stat), Some(500));
        assert_eq!(parse_proc_stat_cpu_ticks("12345 (bad) S 1 2"), None);
    }

    #[test]
    fn cpu_window_flags_ten_percent_of_one_cpu_and_ignores_idle() {
        let base = Instant::now();
        let mut idle = VecDeque::new();
        idle.push_back((base, 1_000));
        // 5.9 seconds of CPU over 60 seconds = 9.83% -> idle.
        idle.push_back((base + Duration::from_secs(60), 1_590));
        assert!(!cpu_window_busy(&idle, 100, Duration::from_secs(5)));

        let mut busy = VecDeque::new();
        busy.push_back((base, 1_000));
        // 6.0 seconds of CPU over 60 seconds = 10.0% -> busy.
        busy.push_back((base + Duration::from_secs(60), 1_600));
        assert!(cpu_window_busy(&busy, 100, Duration::from_secs(5)));

        // Too short a window never flags busy.
        let mut short = VecDeque::new();
        short.push_back((base, 1_000));
        short.push_back((base + Duration::from_secs(2), 1_200));
        assert!(!cpu_window_busy(&short, 100, Duration::from_secs(5)));
    }

    #[test]
    fn idle_action_transitions_running_to_suspend_then_hibernate() {
        assert_eq!(
            decide_idle_action(false, Duration::from_secs(299), 300, 600),
            IdleAction::None
        );
        assert_eq!(
            decide_idle_action(false, Duration::from_secs(300), 300, 600),
            IdleAction::Suspend
        );
        assert_eq!(
            decide_idle_action(true, Duration::from_secs(599), 300, 600),
            IdleAction::None
        );
        assert_eq!(
            decide_idle_action(true, Duration::from_secs(600), 300, 600),
            IdleAction::Hibernate
        );
        // Direct running -> hibernate when idle_suspend is off.
        assert_eq!(
            decide_idle_action(false, Duration::from_secs(600), 0, 600),
            IdleAction::Hibernate
        );
    }
}
