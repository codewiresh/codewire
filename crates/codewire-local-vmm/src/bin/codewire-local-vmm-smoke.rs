//! Qualified-host driver for the additive Cloud Hypervisor feasibility slice.
//!
//! This is deliberately not a user-facing CLI. The checked-in shell entrypoint
//! admits exact artifacts, supplies disposable private roots, and bounds this
//! process. Output is a controlled receipt: guest serial data, ambient host
//! environment values, and daemon credentials are never emitted.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("codewire-local-vmm-smoke requires Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    if let Err(error) = linux::entry().await {
        eprintln!("{}", linux::top_level_failure_message(error.as_ref()));
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{BTreeMap, BTreeSet};
    use std::error::Error;
    use std::fs::{self, File, Metadata};
    use std::future::Future;
    use std::io::{self, Read, Seek, SeekFrom};
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use codewire_daemon::client::{SessionClient, SessionClientError, v1};
    use codewire_local_vmm::ch_api::VmInfo;
    use codewire_local_vmm::linux::runner::ExitClass;
    use codewire_local_vmm::linux::state::{StateDiskIdentity, VmPhase};
    use codewire_local_vmm::{
        CloudHypervisorRunner, CreateVmRequest, LiveProcess, PreparedVm, ProcessIdentity,
        RecoveryError, RunnerConfig, RunningVm, VmPaths,
    };
    use serde_json::Value;
    use tonic::Code;
    use uuid::Uuid;

    type SmokeResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

    const STATE_DISK_BYTES: u64 = 256 * 1024 * 1024;
    const DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(15);
    const SESSION_TIMEOUT: Duration = Duration::from_secs(10);
    const VM_EXIT_TIMEOUT: Duration = Duration::from_secs(15);
    const MAX_SESSION_OUTPUT: usize = 64 * 1024;
    const PROBE_PTY_TERM: &str = "xterm-256color";
    const PROBE_PTY_WIDTH: i32 = 80;
    const PROBE_PTY_HEIGHT: i32 = 24;
    const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;
    const EXT4_MAGIC_OFFSET: usize = 0x38;
    const EXT4_UUID_OFFSET: usize = 0x68;
    const EXT4_PROBE_BYTES: usize = 0x78;
    const TOP_LEVEL_FAILURE_MESSAGE: &str =
        "codewire-local-vmm-smoke: ERROR: qualified-host proof failed";

    /// Never render the boxed error: tonic status text and error sources may
    /// contain guest-controlled bytes or credentials reflected by a peer.
    pub(super) fn top_level_failure_message(_error: &(dyn Error + Send + Sync)) -> &'static str {
        TOP_LEVEL_FAILURE_MESSAGE
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Run,
        Cleanup,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct RunResources {
        vcpus: u8,
        memory_mib: u32,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Args {
        mode: Mode,
        artifact_root: PathBuf,
        artifact_lock: PathBuf,
        state_root: PathBuf,
        vm_id: Uuid,
        outside_disk: Option<PathBuf>,
        resources: Option<RunResources>,
    }

    pub async fn entry() -> SmokeResult<()> {
        let arguments = match Args::parse(std::env::args().skip(1)) {
            Ok(Some(arguments)) => arguments,
            Ok(None) => {
                print_usage();
                return Ok(());
            }
            Err(error) => {
                print_usage();
                return Err(error);
            }
        };
        match arguments.mode {
            Mode::Run => run(arguments).await,
            Mode::Cleanup => cleanup(arguments).await,
        }
    }

    impl Args {
        fn parse(arguments: impl IntoIterator<Item = String>) -> SmokeResult<Option<Self>> {
            let mut arguments = arguments.into_iter();
            let Some(mode) = arguments.next() else {
                return Err(failure("missing run or cleanup subcommand"));
            };
            if matches!(mode.as_str(), "-h" | "--help") {
                if arguments.next().is_some() {
                    return Err(failure("--help accepts no arguments"));
                }
                return Ok(None);
            }
            let mode = match mode.as_str() {
                "run" => Mode::Run,
                "cleanup" => Mode::Cleanup,
                _ => return Err(failure("unknown smoke subcommand")),
            };
            let mut artifact_root = None;
            let mut artifact_lock = None;
            let mut state_root = None;
            let mut vm_id = None;
            let mut outside_disk = None;
            let mut vcpus = None;
            let mut memory_mib = None;
            while let Some(flag) = arguments.next() {
                let value = arguments
                    .next()
                    .ok_or_else(|| failure("smoke flag requires a value"))?;
                let destination = match flag.as_str() {
                    "--artifact-root" => &mut artifact_root,
                    "--artifact-lock" => &mut artifact_lock,
                    "--state-root" => &mut state_root,
                    "--outside-disk" if mode == Mode::Run => &mut outside_disk,
                    "--vm-id" => {
                        if vm_id.is_some() {
                            return Err(failure("duplicate smoke flag"));
                        }
                        vm_id = Some(
                            Uuid::parse_str(&value)
                                .map_err(|_| failure("--vm-id is not a UUID"))?,
                        );
                        continue;
                    }
                    "--cpus" if mode == Mode::Run => {
                        if vcpus.is_some() {
                            return Err(failure("duplicate smoke flag"));
                        }
                        vcpus = Some(parse_vcpus(&value)?);
                        continue;
                    }
                    "--memory-mib" if mode == Mode::Run => {
                        if memory_mib.is_some() {
                            return Err(failure("duplicate smoke flag"));
                        }
                        memory_mib = Some(parse_memory_mib(&value)?);
                        continue;
                    }
                    _ => return Err(failure("unknown or invalid smoke flag")),
                };
                if destination.is_some() {
                    return Err(failure("duplicate smoke flag"));
                }
                *destination = Some(PathBuf::from(value));
            }
            let resources = match mode {
                Mode::Run => Some(RunResources {
                    vcpus: vcpus.ok_or_else(|| failure("--cpus is required for run"))?,
                    memory_mib: memory_mib
                        .ok_or_else(|| failure("--memory-mib is required for run"))?,
                }),
                Mode::Cleanup => None,
            };
            let result = Self {
                mode,
                artifact_root: artifact_root
                    .ok_or_else(|| failure("--artifact-root is required"))?,
                artifact_lock: artifact_lock
                    .ok_or_else(|| failure("--artifact-lock is required"))?,
                state_root: state_root.ok_or_else(|| failure("--state-root is required"))?,
                vm_id: vm_id.ok_or_else(|| failure("--vm-id is required"))?,
                outside_disk,
                resources,
            };
            if result.mode == Mode::Run && result.outside_disk.is_none() {
                return Err(failure("--outside-disk is required for run"));
            }
            for path in [
                &result.artifact_root,
                &result.artifact_lock,
                &result.state_root,
            ] {
                if !path.is_absolute() {
                    return Err(failure("all smoke paths must be absolute"));
                }
            }
            if result
                .outside_disk
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
            {
                return Err(failure("all smoke paths must be absolute"));
            }
            Ok(Some(result))
        }

        fn runner_config(&self) -> RunnerConfig {
            RunnerConfig {
                state_root: self.state_root.clone(),
                artifact_root: self.artifact_root.clone(),
                artifact_lock: self.artifact_lock.clone(),
            }
        }
    }

    fn print_usage() {
        eprintln!(
            "usage:\n  codewire-local-vmm-smoke run --artifact-root PATH --artifact-lock PATH --state-root PATH --vm-id UUID --outside-disk PATH --cpus COUNT --memory-mib MIB\n  codewire-local-vmm-smoke cleanup --artifact-root PATH --artifact-lock PATH --state-root PATH --vm-id UUID"
        );
    }

    fn parse_vcpus(value: &str) -> SmokeResult<u8> {
        if !is_canonical_decimal(value) {
            return Err(failure(
                "--cpus must be a decimal integer from 1 through 32",
            ));
        }
        let value = value
            .parse::<u8>()
            .map_err(|_| failure("--cpus must be a decimal integer from 1 through 32"))?;
        if !(1..=32).contains(&value) {
            return Err(failure(
                "--cpus must be a decimal integer from 1 through 32",
            ));
        }
        Ok(value)
    }

    fn parse_memory_mib(value: &str) -> SmokeResult<u32> {
        if !is_canonical_decimal(value) {
            return Err(failure(
                "--memory-mib must be a decimal integer from 128 through 65536",
            ));
        }
        let value = value.parse::<u32>().map_err(|_| {
            failure("--memory-mib must be a decimal integer from 128 through 65536")
        })?;
        if !(128..=65_536).contains(&value) {
            return Err(failure(
                "--memory-mib must be a decimal integer from 128 through 65536",
            ));
        }
        Ok(value)
    }

    fn is_canonical_decimal(value: &str) -> bool {
        !value.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && (value.len() == 1 || !value.starts_with('0'))
    }

    async fn run(arguments: Args) -> SmokeResult<()> {
        let outside_disk = arguments
            .outside_disk
            .as_deref()
            .ok_or_else(|| failure("outside disk missing after argument admission"))?;
        validate_outside_ext4(
            outside_disk,
            &arguments.artifact_root,
            &arguments.state_root,
        )?;

        let runner = CloudHypervisorRunner::new(arguments.runner_config()).await?;
        let preflight = runner.preflight()?;
        observation("host.architecture", preflight.architecture);
        observation("host.landlock_abi", preflight.landlock_abi);
        observation("host.kvm", preflight.kvm.display());
        observation("host.vhost_vsock", preflight.vhost_vsock.display());
        observation("vmm.seccomp", "kill");
        observation("vmm.landlock", "native");

        // The concrete lifecycle calls are kept together so every error path
        // can be reconciled by the cleanup subcommand. No credential leaves a
        // RunningVm handle or this block.
        run_lifecycle(&runner, &arguments, outside_disk).await
    }

    async fn run_lifecycle(
        runner: &CloudHypervisorRunner,
        arguments: &Args,
        outside_disk: &Path,
    ) -> SmokeResult<()> {
        let resources = arguments
            .resources
            .ok_or_else(|| failure("run resource configuration is missing"))?;
        observation("vm.requested_vcpus", resources.vcpus);
        observation("vm.requested_memory_mib", resources.memory_mib);
        let prepared_one = runner.prepare(request(1, arguments, resources)).await?;
        let fixture_paths = prepared_one.paths().clone();
        require_prepared_identity(&prepared_one, arguments.vm_id, 1)?;
        let disk_identity = prepared_one.state_disk_identity().clone();
        observation("vm.id", arguments.vm_id);
        observation("vm.state_disk", fixture_paths.state_disk.display());
        observation("vm.state_disk.dev", disk_identity.file.device);
        observation("vm.state_disk.inode", disk_identity.file.inode);
        observation("vm.state_disk.size", disk_identity.file.size);
        observation("vm.state_disk.ext4_uuid", disk_identity.filesystem_uuid);
        let token_one = prepared_one.auth_token_fingerprint();
        let mut first = runner.start(prepared_one).await?;
        require_running_identity(&first, arguments.vm_id, 1, &disk_identity)?;
        if first.auth_token_fingerprint() != token_one {
            return Err(failure("daemon token changed between prepare and start"));
        }
        let first_process = first.process_identity().clone();
        observe_process(&first_process);

        let first_client = connect_ready_daemon(&first).await?;
        observation("guest.daemon_ready", true);
        require_vmm_process_confinement(&first_process)?;
        require_supervisor_socket_boundary()?;
        require_wrong_token_rejected(
            first
                .connect_daemon_with_token("cw-smoke-intentionally-wrong-token")
                .await,
        )
        .await?;
        observation("guest.wrong_token_rejected", true);
        require_pty_identity(&first_client, arguments.vm_id, 1).await?;
        observation("guest.identity_verified", true);
        observation("guest.pty_verified", true);
        require_network_probe(&run_guest_command(&first_client, &["network-check"]).await?)?;
        observation("guest.no_network_verified", true);
        let nonce = format!("cw-smoke-{}", arguments.vm_id.simple());
        require_nonce_written(&run_guest_command(&first_client, &["write-nonce", &nonce]).await?)?;
        observation("guest.nonce_fsynced", true);

        let info_before = first.api().info().await?;
        let boundary_before = require_live_configuration(
            &info_before,
            first.paths(),
            cid_for(arguments.vm_id),
            resources,
        )?;
        if let Some(actual_bytes) = info_before.memory_actual_size {
            observation("vmm.memory_actual_bytes", actual_bytes);
        }
        require_runtime_endpoints(first.paths())?;
        let descriptors = require_fd_boundary(first.process_identity(), first.paths())?;
        observe_fds(&descriptors);
        let denied = first
            .api()
            .assert_disk_addition_denied(outside_disk)
            .await?;
        first.api().ping().await?;
        require_daemon(&first_client).await?;
        let info_after = first.api().info().await?;
        let boundary_after = require_live_configuration(
            &info_after,
            first.paths(),
            cid_for(arguments.vm_id),
            resources,
        )?;
        require_unchanged_live_boundary(&boundary_before, &boundary_after)?;
        observation("vmm.landlock_disk_probe_http_status", denied.get());
        observation(
            "vmm.live_device_boundary",
            "two-block-disks-plus-vsock-only",
        );

        let poweroff_session = launch_poweroff(&first_client).await?;
        drop(first_client);
        match first.wait_for_exit(VM_EXIT_TIMEOUT).await? {
            ExitClass::GuestShutdown => {}
            ExitClass::StillRunning => {
                return Err(failure("guest-initiated poweroff did not stop the VMM"));
            }
            ExitClass::VmmFailure(_) => {
                return Err(failure(
                    "guest-initiated poweroff was classified as VMM failure",
                ));
            }
        }
        drop(first);
        wait_for_identity_to_end(&first_process).await?;
        require_stale_identity_cannot_adopt_replacement(&first_process)?;
        observation("vm.generation.1.exit", "guest-shutdown");

        let prepared_two = runner.prepare(request(2, arguments, resources)).await?;
        require_prepared_identity(&prepared_two, arguments.vm_id, 2)?;
        require_same_disk(&disk_identity, prepared_two.state_disk_identity())?;
        let token_two = prepared_two.auth_token_fingerprint();
        if token_two == token_one {
            return Err(failure(
                "daemon token fingerprint was reused across generations",
            ));
        }
        let mut second = runner.start(prepared_two).await?;
        require_running_identity(&second, arguments.vm_id, 2, &disk_identity)?;
        let second_client = connect_ready_daemon(&second).await?;
        require_identity(
            &run_guest_command(&second_client, &["identity"]).await?,
            arguments.vm_id,
            2,
        )?;
        require_nonce_read(
            &run_guest_command(&second_client, &["read-nonce"]).await?,
            &nonce,
        )?;
        require_saved_poweroff_marker(&second_client, &poweroff_session, arguments.vm_id, 1)
            .await?;
        let second_process = second.process_identity().clone();
        drop(second_client);
        match second.force_kill_for_test().await? {
            ExitClass::VmmFailure(_) => {}
            ExitClass::StillRunning => return Err(failure("hard-killed VMM remained running")),
            ExitClass::GuestShutdown => {
                return Err(failure(
                    "hard-killed VMM was misclassified as guest shutdown",
                ));
            }
        }
        drop(second);
        wait_for_identity_to_end(&second_process).await?;
        observation("vm.generation.2.exit", "vmm-failure");

        let prepared_three = runner.prepare(request(3, arguments, resources)).await?;
        require_same_disk(&disk_identity, prepared_three.state_disk_identity())?;
        let token_three = prepared_three.auth_token_fingerprint();
        if token_three == token_one || token_three == token_two {
            return Err(failure("daemon token fingerprint repeated after crash"));
        }
        let third = runner.start(prepared_three).await?;
        let third_client = connect_ready_daemon(&third).await?;
        require_identity(
            &run_guest_command(&third_client, &["identity"]).await?,
            arguments.vm_id,
            3,
        )?;
        require_nonce_read(
            &run_guest_command(&third_client, &["read-nonce"]).await?,
            &nonce,
        )?;
        let third_process = third.process_identity().clone();
        drop(third_client);

        // Dropping this handle simulates loss of the owning in-process task
        // while the supervisor process remains alive. Reconciliation must use
        // the exact persisted birth identity rather than a numeric PID. An
        // actual supervisor-process death is fail-closed by PDEATHSIG for this
        // spike; live adoption across a supervisor restart is deferred.
        drop(third);
        let recovered = runner.recover(arguments.vm_id)?;
        if recovered.state().phase != VmPhase::Running
            || recovered.state().generation != 3
            || recovered.state().process != third_process
            || recovered.paths().state_disk != fixture_paths.state_disk
        {
            return Err(failure("orphan recovery adopted the wrong VM identity"));
        }
        recovered.terminate_orphan().await?;
        drop(recovered);
        wait_for_identity_to_end(&third_process).await?;
        observation(
            "vm.generation.3.recovery",
            "identity-checked-orphan-terminated",
        );

        let prepared_four = runner.prepare(request(4, arguments, resources)).await?;
        require_same_disk(&disk_identity, prepared_four.state_disk_identity())?;
        let token_four = prepared_four.auth_token_fingerprint();
        if [token_one, token_two, token_three].contains(&token_four) {
            return Err(failure(
                "daemon token fingerprint repeated after orphan recovery",
            ));
        }
        let mut fourth = runner.start(prepared_four).await?;
        let fourth_client = connect_ready_daemon(&fourth).await?;
        require_identity(
            &run_guest_command(&fourth_client, &["identity"]).await?,
            arguments.vm_id,
            4,
        )?;
        require_nonce_read(
            &run_guest_command(&fourth_client, &["read-nonce"]).await?,
            &nonce,
        )?;
        let fourth_process = fourth.process_identity().clone();
        drop(fourth_client);
        match fourth.stop().await? {
            ExitClass::GuestShutdown => {}
            ExitClass::StillRunning => return Err(failure("final VM stop remained running")),
            ExitClass::VmmFailure(_) => {
                return Err(failure("final VM stop required a failure signal"));
            }
        }
        drop(fourth);
        wait_for_identity_to_end(&fourth_process).await?;
        runner.delete_stopped(arguments.vm_id)?;
        require_deleted(&fixture_paths, &arguments.state_root)?;
        observation("vm.cleanup", "complete");
        Ok(())
    }

    async fn cleanup(arguments: Args) -> SmokeResult<()> {
        let runner = CloudHypervisorRunner::new(arguments.runner_config()).await?;
        runner
            .terminate_tracked_for_cleanup(arguments.vm_id)
            .await?;
        runner.delete_stopped(arguments.vm_id)?;
        Ok(())
    }

    fn request(generation: u64, arguments: &Args, resources: RunResources) -> CreateVmRequest {
        CreateVmRequest {
            vm_id: arguments.vm_id,
            generation,
            vsock_cid: cid_for(arguments.vm_id),
            daemon_vsock_port: 7_777,
            state_disk_bytes: STATE_DISK_BYTES,
            vcpus: resources.vcpus,
            memory_mib: resources.memory_mib,
        }
    }

    fn require_prepared_identity(
        prepared: &PreparedVm,
        vm_id: Uuid,
        generation: u64,
    ) -> SmokeResult<()> {
        if prepared.vm_id() != vm_id
            || prepared.generation() != generation
            || prepared
                .paths()
                .vm_dir
                .file_name()
                .and_then(|name| name.to_str())
                != Some(vm_id.to_string().as_str())
        {
            return Err(failure(
                "prepared VM identity does not match its private tree",
            ));
        }
        if prepared.auth_token_fingerprint().len() != 64 {
            return Err(failure("prepared daemon token fingerprint is malformed"));
        }
        Ok(())
    }

    fn require_running_identity(
        running: &RunningVm,
        vm_id: Uuid,
        generation: u64,
        disk: &StateDiskIdentity,
    ) -> SmokeResult<()> {
        if running.vm_id() != vm_id
            || running.generation() != generation
            || running.state_disk_identity() != disk
        {
            return Err(failure(
                "running VM identity differs from its prepared state",
            ));
        }
        Ok(())
    }

    fn require_same_disk(
        expected: &StateDiskIdentity,
        actual: &StateDiskIdentity,
    ) -> SmokeResult<()> {
        if expected != actual {
            return Err(failure(
                "state disk identity or ext4 UUID changed across generations",
            ));
        }
        Ok(())
    }

    fn observe_process(identity: &ProcessIdentity) {
        observation("vmm.pid", identity.pid);
        observation("vmm.host_boot_id", &identity.boot_id);
        observation("vmm.start_time_ticks", identity.start_time_ticks);
        observation("vmm.executable", identity.executable.display());
        observation("vmm.executable.dev", identity.executable_file.device);
        observation("vmm.executable.inode", identity.executable_file.inode);
        observation("vmm.executable.size", identity.executable_file.size);
        observation("vmm.executable.sha256", &identity.executable_sha256);
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ProcessConfinement {
        seccomp: u32,
        seccomp_filters: u32,
        no_new_privs: u32,
        cap_inh: u128,
        cap_prm: u128,
        cap_eff: u128,
        cap_amb: u128,
    }

    fn require_vmm_process_confinement(identity: &ProcessIdentity) -> SmokeResult<()> {
        if ProcessIdentity::capture(identity.pid)? != *identity {
            return Err(failure(
                "VMM process identity changed before confinement inspection",
            ));
        }
        let leader_status = fs::read_to_string(format!("/proc/{0}/task/{0}/status", identity.pid))?;
        let leader = parse_process_confinement(&leader_status)?;
        if !matches!(leader.seccomp, 0 | 2)
            || leader.no_new_privs != 1
            || !capability_sets_empty(&leader)
        {
            return Err(failure(
                "VMM leader lacks its required no-new-privileges/capability boundary",
            ));
        }
        let mut workers = 0_u32;
        let mut filtered_workers = 0_u32;
        let mut unfiltered_workers = 0_u32;
        let mut weak_filter_workers = 0_u32;
        let mut minimum_worker_filters = u32::MAX;
        let mut maximum_worker_filters = 0_u32;
        for entry in fs::read_dir(format!("/proc/{}/task", identity.pid))? {
            let entry = entry?;
            let tid = entry
                .file_name()
                .to_string_lossy()
                .parse::<u32>()
                .map_err(|_| failure("VMM task identifier is malformed"))?;
            let status = fs::read_to_string(entry.path().join("status"))?;
            let confinement = parse_process_confinement(&status)?;
            if tid == identity.pid {
                if confinement != leader {
                    return Err(failure("VMM leader status changed during task inspection"));
                }
                continue;
            }
            if confinement.no_new_privs != 1 || !capability_sets_empty(&confinement) {
                return Err(failure(
                    "VMM task lacks no-new-privileges or retains capabilities",
                ));
            }
            workers = workers
                .checked_add(1)
                .ok_or_else(|| failure("VMM task count overflowed"))?;
            match confinement.seccomp {
                2 => filtered_workers += 1,
                0 => unfiltered_workers += 1,
                _ => return Err(failure("VMM worker has an unexpected seccomp mode")),
            }
            if confinement.seccomp_filters <= leader.seccomp_filters {
                weak_filter_workers += 1;
            }
            minimum_worker_filters = minimum_worker_filters.min(confinement.seccomp_filters);
            maximum_worker_filters = maximum_worker_filters.max(confinement.seccomp_filters);
        }
        // Cloud Hypervisor v53 applies role-specific filters inside its VMM,
        // API, vCPU, and virtio worker threads. Its process leader performs
        // startup, applies Landlock, and waits for those threads, but is not
        // itself seccomp-filtered. Accept a filtered leader as a future
        // hardening, while requiring every guest-processing worker observed at
        // daemon readiness to have SECCOMP_MODE_FILTER.
        if !matches!(leader.seccomp, 0 | 2)
            || workers == 0
            || filtered_workers != workers
            || unfiltered_workers != 0
            || weak_filter_workers != 0
        {
            observation("vmm.worker_count", workers);
            observation("vmm.filtered_worker_count", filtered_workers);
            observation("vmm.unfiltered_worker_count", unfiltered_workers);
            observation("vmm.weak_filter_worker_count", weak_filter_workers);
            return Err(failure(
                "VMM worker-thread seccomp confinement is not active",
            ));
        }
        if ProcessIdentity::capture(identity.pid)? != *identity {
            return Err(failure(
                "VMM process identity changed during confinement inspection",
            ));
        }
        observation("vmm.leader_seccomp", leader.seccomp);
        observation("vmm.leader_seccomp_filters", leader.seccomp_filters);
        observation("vmm.worker_count", workers);
        observation("vmm.filtered_worker_count", filtered_workers);
        observation("vmm.unfiltered_worker_count", unfiltered_workers);
        observation("vmm.weak_filter_worker_count", weak_filter_workers);
        observation("vmm.minimum_worker_seccomp_filters", minimum_worker_filters);
        observation("vmm.maximum_worker_seccomp_filters", maximum_worker_filters);
        observation("vmm.worker_seccomp_verified", true);
        observation("vmm.all_tasks_no_new_privs_verified", true);
        observation("vmm.all_tasks_capability_sets_empty_verified", true);
        Ok(())
    }

    fn parse_process_confinement(status: &str) -> SmokeResult<ProcessConfinement> {
        let seccomp = parse_status_decimal(unique_status_value(status, "Seccomp")?)?;
        let seccomp_filters =
            parse_status_decimal(unique_status_value(status, "Seccomp_filters")?)?;
        let no_new_privs = parse_status_decimal(unique_status_value(status, "NoNewPrivs")?)?;
        let cap_inh = parse_status_hex(unique_status_value(status, "CapInh")?)?;
        let cap_prm = parse_status_hex(unique_status_value(status, "CapPrm")?)?;
        let cap_eff = parse_status_hex(unique_status_value(status, "CapEff")?)?;
        let cap_amb = parse_status_hex(unique_status_value(status, "CapAmb")?)?;
        Ok(ProcessConfinement {
            seccomp,
            seccomp_filters,
            no_new_privs,
            cap_inh,
            cap_prm,
            cap_eff,
            cap_amb,
        })
    }

    fn capability_sets_empty(confinement: &ProcessConfinement) -> bool {
        confinement.cap_inh == 0
            && confinement.cap_prm == 0
            && confinement.cap_eff == 0
            && confinement.cap_amb == 0
    }

    fn unique_status_value<'a>(status: &'a str, field: &str) -> SmokeResult<&'a str> {
        let mut values = status.lines().filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name == field).then_some(value.trim())
        });
        let value = values
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| failure("VMM process status is missing a confinement field"))?;
        if values.next().is_some() {
            return Err(failure("VMM process status repeats a confinement field"));
        }
        Ok(value)
    }

    fn parse_status_decimal(value: &str) -> SmokeResult<u32> {
        if !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(failure(
                "VMM process status has a malformed confinement field",
            ));
        }
        value
            .parse()
            .map_err(|_| failure("VMM process status has an out-of-range confinement field"))
    }

    fn parse_status_hex(value: &str) -> SmokeResult<u128> {
        if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(failure(
                "VMM process status has a malformed confinement field",
            ));
        }
        u128::from_str_radix(value, 16)
            .map_err(|_| failure("VMM process status has an out-of-range confinement field"))
    }

    async fn wait_for_identity_to_end(identity: &ProcessIdentity) -> SmokeResult<()> {
        let deadline = Instant::now() + VM_EXIT_TIMEOUT;
        loop {
            match ProcessIdentity::capture(identity.pid) {
                Ok(current) if current == *identity => {}
                Ok(_) => return Ok(()),
                Err(RecoveryError::ReadProcess(error))
                    if error.kind() == io::ErrorKind::NotFound =>
                {
                    return Ok(());
                }
                Err(RecoveryError::ProcessExited | RecoveryError::IdentityMismatch) => {
                    return Ok(());
                }
                Err(error) => return Err(Box::new(error)),
            }
            if Instant::now() >= deadline {
                return Err(failure(
                    "VMM process identity did not terminate within its bound",
                ));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn require_runtime_endpoints(paths: &VmPaths) -> SmokeResult<()> {
        for directory in [
            &paths.vm_dir,
            &paths.api_dir,
            &paths.vsock_dir,
            &paths.disks_dir,
            &paths.seed_dir,
            &paths.diagnostics_dir,
        ] {
            let metadata = fs::symlink_metadata(directory)?;
            if !metadata.is_dir()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o777 != 0o700
            {
                return Err(failure("runtime directory identity or mode is unsafe"));
            }
        }
        for socket in [&paths.api_socket, &paths.vsock_socket] {
            let metadata = fs::symlink_metadata(socket)?;
            if !metadata.file_type().is_socket() {
                return Err(failure("runtime endpoint is not a Unix socket"));
            }
            require_metadata_mode(&metadata, 0o600)?;
            let label = if socket == &paths.api_socket {
                "vmm.api_socket"
            } else {
                "vmm.vsock_socket"
            };
            observation(&format!("{label}.path"), socket.display());
            observation(&format!("{label}.dev"), metadata.dev());
            observation(&format!("{label}.inode"), metadata.ino());
        }
        for file in [
            &paths.state_disk,
            &paths.lock_file,
            &paths.state_file,
            &paths.serial_log,
            &paths.vmm_log,
            &paths.event_monitor,
        ] {
            let metadata = fs::symlink_metadata(file)?;
            if !metadata.is_file() {
                return Err(failure("runtime mutable path is not a regular file"));
            }
            require_metadata_mode(&metadata, 0o600)?;
        }
        for diagnostic in [&paths.serial_log, &paths.vmm_log, &paths.event_monitor] {
            if fs::symlink_metadata(diagnostic)?.len() != 0 {
                return Err(failure(
                    "reserved diagnostic placeholder contains unbounded output",
                ));
            }
        }
        observation("vmm.unbounded_diagnostic_sinks_disabled", true);
        let seed = fs::symlink_metadata(&paths.seed_disk)?;
        if !seed.is_file() {
            return Err(failure("runtime seed is not a regular file"));
        }
        require_metadata_mode(&seed, 0o400)?;
        Ok(())
    }

    fn require_deleted(paths: &VmPaths, state_root: &Path) -> SmokeResult<()> {
        if paths.vm_dir.exists()
            || paths.api_socket.exists()
            || paths.vsock_socket.exists()
            || paths.state_disk.exists()
        {
            return Err(failure("VM deletion left state or a control endpoint"));
        }
        let vms = state_root.join("vms");
        if vms.exists() && fs::read_dir(vms)?.next().transpose()?.is_some() {
            return Err(failure("VM deletion left an orphan inventory entry"));
        }
        Ok(())
    }

    fn cid_for(vm_id: Uuid) -> u32 {
        let bytes = vm_id.as_bytes();
        let mixed = u32::from_be_bytes([bytes[0], bytes[5], bytes[10], bytes[15]]);
        3 + mixed % (u32::MAX - 4)
    }

    fn observation(name: &str, value: impl std::fmt::Display) {
        println!("observation {name}={value}");
    }

    fn failure(message: impl Into<String>) -> Box<dyn Error + Send + Sync> {
        Box::new(io::Error::other(message.into()))
    }

    async fn require_daemon(client: &SessionClient) -> SmokeResult<()> {
        client.require_ready().await?;
        let health = client.get_health().await?;
        if health.state != v1::DaemonState::Ready as i32 {
            return Err(failure("authenticated daemon health is not ready"));
        }
        Ok(())
    }

    async fn connect_ready_daemon(running: &RunningVm) -> SmokeResult<SessionClient> {
        wait_for_daemon_ready_with_timeout(
            DAEMON_READY_TIMEOUT,
            Duration::from_millis(50),
            || async {
                let client = running.daemon_client().await.ok()?;
                require_daemon(&client).await.ok()?;
                Some(client)
            },
        )
        .await
    }

    async fn wait_for_daemon_ready_with_timeout<T, Attempt, AttemptFuture>(
        timeout: Duration,
        retry_interval: Duration,
        mut attempt: Attempt,
    ) -> SmokeResult<T>
    where
        Attempt: FnMut() -> AttemptFuture,
        AttemptFuture: Future<Output = Option<T>>,
    {
        tokio::time::timeout(timeout, async move {
            loop {
                if let Some(ready) = attempt().await {
                    return ready;
                }
                tokio::time::sleep(retry_interval).await;
            }
        })
        .await
        .map_err(|_| failure("authenticated guest daemon did not become ready within its bound"))
    }

    async fn require_wrong_token_rejected(
        result: Result<SessionClient, impl Error>,
    ) -> SmokeResult<()> {
        let client =
            result.map_err(|_| failure("wrong-token transport did not reach the daemon"))?;
        match client.require_ready().await {
            Err(SessionClientError::Status(status)) if status.code() == Code::Unauthenticated => {
                Ok(())
            }
            Err(_) => Err(failure(
                "wrong daemon token failed for a reason other than unauthenticated",
            )),
            Ok(()) => Err(failure("wrong daemon token was accepted")),
        }
    }

    fn launch_request(command: Vec<String>) -> v1::LaunchSessionRequest {
        v1::LaunchSessionRequest {
            command,
            working_dir: "/".to_owned(),
            env: Vec::new(),
            pty: false,
            term: String::new(),
            width: 0,
            height: 0,
        }
    }

    async fn require_pty_identity(
        client: &SessionClient,
        vm_id: Uuid,
        generation: u64,
    ) -> SmokeResult<()> {
        let command = vec!["/init".to_owned(), "identity".to_owned()];
        let admitted = client
            .launch(v1::LaunchSessionRequest {
                command: command.clone(),
                working_dir: "/".to_owned(),
                env: Vec::new(),
                pty: true,
                term: PROBE_PTY_TERM.to_owned(),
                width: PROBE_PTY_WIDTH,
                height: PROBE_PTY_HEIGHT,
            })
            .await?;
        if admitted.command != command || admitted.session_id.is_empty() || !admitted.pty {
            return Err(failure(
                "guest PTY identity session was not durably admitted",
            ));
        }
        let record = wait_for_terminal_session(client, &admitted.session_id).await?;
        if record.session_id != admitted.session_id
            || record.command != command
            || !record.pty
            || record.state != v1::SessionLifecycleState::Exited as i32
            || record.exit_code != Some(0)
        {
            return Err(failure(
                "guest PTY identity session did not exit successfully",
            ));
        }
        let output = read_session_pty(client, &record.session_id).await?;
        require_identity(&normalize_pty_crlf(&output), vm_id, generation)
    }

    fn normalize_pty_crlf(output: &str) -> String {
        output.replace("\r\n", "\n")
    }

    async fn run_guest_command(client: &SessionClient, arguments: &[&str]) -> SmokeResult<String> {
        let mut command = vec!["/init".to_owned()];
        command.extend(arguments.iter().map(|argument| (*argument).to_owned()));
        let record = client.launch(launch_request(command.clone())).await?;
        let record = wait_for_terminal_session(client, &record.session_id).await?;
        if record.command != command
            || record.state != v1::SessionLifecycleState::Exited as i32
            || record.exit_code != Some(0)
        {
            if arguments == ["network-check"] {
                observe_network_failure_class(client, &record.session_id).await;
            }
            return Err(failure("guest probe session did not exit successfully"));
        }
        read_session_stdout(client, &record.session_id).await
    }

    async fn observe_network_failure_class(client: &SessionClient, session_id: &str) {
        let Ok(response) = client
            .read_output(v1::ReadSessionOutputRequest {
                session_id: session_id.to_owned(),
                offset: 0,
                limit: MAX_SESSION_OUTPUT as u64,
            })
            .await
        else {
            observation("guest.network_failure_class", "output-unavailable");
            return;
        };
        let mut output = Vec::new();
        for chunk in response.chunks {
            if output.len().saturating_add(chunk.data.len()) > MAX_SESSION_OUTPUT {
                observation("guest.network_failure_class", "output-oversized");
                return;
            }
            output.extend_from_slice(&chunk.data);
        }
        let class = [
            ("non-loopback network interface", "interface"),
            ("non-loopback IPv6 route", "ipv6-route"),
            ("non-loopback route", "ipv4-route"),
            ("open TCP canary socket", "tcp-open"),
            ("guest TCP canary", "tcp-connect"),
            ("open UDP canary socket", "udp-open"),
            ("guest UDP canary", "udp-connect"),
            ("open DNS canary socket", "dns-open"),
            ("guest DNS canary", "dns-connect"),
            ("open ICMP canary socket", "icmp-open"),
            ("guest ICMP canary", "icmp-connect"),
        ]
        .into_iter()
        .find_map(|(needle, class)| {
            output
                .windows(needle.len())
                .any(|window| window == needle.as_bytes())
                .then_some(class)
        })
        .unwrap_or("unclassified");
        // Never render the guest-controlled bytes. Only this fixed allowlisted
        // classification reaches the controlled receipt.
        observation("guest.network_failure_class", class);
    }

    async fn launch_poweroff(client: &SessionClient) -> SmokeResult<String> {
        let command = vec!["/init".to_owned(), "poweroff".to_owned()];
        let record = client.launch(launch_request(command.clone())).await?;
        if record.command != command || record.session_id.is_empty() {
            return Err(failure("guest poweroff session was not durably admitted"));
        }
        Ok(record.session_id)
    }

    async fn wait_for_terminal_session(
        client: &SessionClient,
        session_id: &str,
    ) -> SmokeResult<v1::SessionRecord> {
        let deadline = Instant::now() + SESSION_TIMEOUT;
        loop {
            let record = client.get(session_id).await?;
            let state = v1::SessionLifecycleState::try_from(record.state)
                .unwrap_or(v1::SessionLifecycleState::Unspecified);
            if matches!(
                state,
                v1::SessionLifecycleState::Stopped
                    | v1::SessionLifecycleState::Exited
                    | v1::SessionLifecycleState::Failed
                    | v1::SessionLifecycleState::Interrupted
            ) {
                return Ok(record);
            }
            if Instant::now() >= deadline {
                return Err(failure("guest probe session readiness timed out"));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn read_session_stdout(client: &SessionClient, session_id: &str) -> SmokeResult<String> {
        let response = client
            .read_output(v1::ReadSessionOutputRequest {
                session_id: session_id.to_owned(),
                offset: 0,
                limit: MAX_SESSION_OUTPUT as u64,
            })
            .await?;
        if !response.eof || response.next_offset > MAX_SESSION_OUTPUT as u64 {
            return Err(failure("guest probe output is incomplete or oversized"));
        }
        let mut stdout = Vec::new();
        for chunk in response.chunks {
            match v1::SessionOutputStream::try_from(chunk.stream)
                .unwrap_or(v1::SessionOutputStream::Unspecified)
            {
                v1::SessionOutputStream::Stdout => stdout.extend_from_slice(&chunk.data),
                v1::SessionOutputStream::Stderr if chunk.data.is_empty() => {}
                _ => return Err(failure("guest probe emitted unexpected output stream data")),
            }
            if stdout.len() > MAX_SESSION_OUTPUT {
                return Err(failure("guest probe output exceeded its bound"));
            }
        }
        String::from_utf8(stdout).map_err(|_| failure("guest probe output is not UTF-8"))
    }

    async fn read_session_pty(client: &SessionClient, session_id: &str) -> SmokeResult<String> {
        let response = client
            .read_output(v1::ReadSessionOutputRequest {
                session_id: session_id.to_owned(),
                offset: 0,
                limit: MAX_SESSION_OUTPUT as u64,
            })
            .await?;
        if !response.eof || response.next_offset > MAX_SESSION_OUTPUT as u64 {
            return Err(failure("guest PTY output is incomplete or oversized"));
        }
        let mut output = Vec::new();
        for chunk in response.chunks {
            if v1::SessionOutputStream::try_from(chunk.stream) != Ok(v1::SessionOutputStream::Pty) {
                return Err(failure("guest PTY emitted an unexpected output stream"));
            }
            output.extend_from_slice(&chunk.data);
            if output.len() > MAX_SESSION_OUTPUT {
                return Err(failure("guest PTY output exceeded its bound"));
            }
        }
        String::from_utf8(output).map_err(|_| failure("guest PTY output is not UTF-8"))
    }

    async fn require_saved_poweroff_marker(
        client: &SessionClient,
        session_id: &str,
        vm_id: Uuid,
        generation: u64,
    ) -> SmokeResult<()> {
        let records = client.list().await?;
        let record = records
            .iter()
            .find(|record| record.session_id == session_id)
            .ok_or_else(|| failure("durable poweroff session disappeared after restart"))?;
        if record.command != ["/init", "poweroff"] {
            return Err(failure("durable poweroff session command changed"));
        }
        let output = read_session_stdout(client, session_id).await?;
        let expected = format!("CWPOWEROFF1 accepted vm_id={vm_id} generation={generation}\n");
        if output != expected {
            return Err(failure("durable poweroff acceptance marker is missing"));
        }
        Ok(())
    }

    fn require_identity(output: &str, vm_id: Uuid, generation: u64) -> SmokeResult<()> {
        let expected = format!("CWIDENTITY1 vm_id={vm_id} generation={generation}\n");
        if output != expected {
            return Err(failure(
                "guest identity does not match the requested generation",
            ));
        }
        Ok(())
    }

    fn require_nonce_written(output: &str) -> SmokeResult<()> {
        if output != "CWNONCE1 written\n" {
            return Err(failure("guest nonce write was not acknowledged"));
        }
        Ok(())
    }

    fn require_nonce_read(output: &str, nonce: &str) -> SmokeResult<()> {
        if output != format!("CWNONCE1 {nonce}\n") {
            return Err(failure("durable nonce changed across VM generations"));
        }
        Ok(())
    }

    fn require_network_probe(output: &str) -> SmokeResult<()> {
        if output != "CWNETWORK1 loopback-only\n" {
            return Err(failure("guest network boundary probe did not pass"));
        }
        Ok(())
    }

    #[derive(Debug, Clone, PartialEq)]
    struct LiveBoundary {
        config: Value,
        device_tree: Value,
    }

    fn require_live_configuration(
        info: &VmInfo,
        paths: &VmPaths,
        expected_vsock_cid: u32,
        resources: RunResources,
    ) -> SmokeResult<LiveBoundary> {
        if !info
            .state
            .as_deref()
            .is_some_and(|state| state.eq_ignore_ascii_case("running"))
        {
            return Err(failure("Cloud Hypervisor vm.info is not running"));
        }
        // ChApi rejects the complete vm.info body above its fixed 1 MiB bound
        // before JSON decoding, so preserving this whole subtree is bounded.
        let device_tree = info
            .additional
            .get("device_tree")
            .filter(|value| !value.is_null())
            .ok_or_else(|| failure("Cloud Hypervisor vm.info omitted its live device tree"))?;
        let config = info
            .additional
            .get("config")
            .and_then(Value::as_object)
            .ok_or_else(|| failure("Cloud Hypervisor vm.info omitted its live configuration"))?;
        let cpus = config
            .get("cpus")
            .and_then(Value::as_object)
            .ok_or_else(|| failure("Cloud Hypervisor vm.info omitted its CPU configuration"))?;
        let expected_vcpus = u64::from(resources.vcpus);
        if cpus.get("boot_vcpus").and_then(Value::as_u64) != Some(expected_vcpus)
            || cpus.get("max_vcpus").and_then(Value::as_u64) != Some(expected_vcpus)
        {
            return Err(failure(
                "Cloud Hypervisor live CPU configuration differs from the request",
            ));
        }
        let memory = config
            .get("memory")
            .and_then(Value::as_object)
            .ok_or_else(|| failure("Cloud Hypervisor vm.info omitted its memory configuration"))?;
        let expected_memory_bytes = u64::from(resources.memory_mib) * 1024 * 1024;
        if memory.get("size").and_then(Value::as_u64) != Some(expected_memory_bytes) {
            return Err(failure(
                "Cloud Hypervisor live memory configuration differs from the request",
            ));
        }
        for key in [
            "net",
            "fs",
            "pmem",
            "devices",
            "user_devices",
            "vdpa",
            "generic_vhost_user",
            "vhost_user",
            "vfio",
            "tpm",
            "migration",
            "landlock_rules",
            "preserved_fds",
        ] {
            if config.get(key).is_some_and(nonempty_json) {
                return Err(failure(format!(
                    "Cloud Hypervisor vm.info contains forbidden {key} configuration"
                )));
            }
        }
        let disks = config
            .get("disks")
            .and_then(Value::as_array)
            .ok_or_else(|| failure("Cloud Hypervisor vm.info omitted its disks"))?;
        if disks.len() != 2 {
            return Err(failure(
                "Cloud Hypervisor live configuration has unexpected disks",
            ));
        }
        if config.get("landlock_enable") != Some(&Value::Bool(true)) {
            return Err(failure(
                "Cloud Hypervisor live configuration does not enable native Landlock",
            ));
        }
        let state_path = paths.state_disk.to_string_lossy();
        let seed_path = paths.seed_disk.to_string_lossy();
        let mut saw_state = false;
        let mut saw_seed = false;
        for disk in disks {
            let disk = disk
                .as_object()
                .ok_or_else(|| failure("Cloud Hypervisor live disk is not an object"))?;
            if disk.get("vhost_user").and_then(Value::as_bool) != Some(false)
                || disk.get("backing_files").and_then(Value::as_bool) != Some(false)
                || disk.get("direct").and_then(Value::as_bool) != Some(false)
            {
                return Err(failure(
                    "Cloud Hypervisor live disk enables an unadmitted backing mechanism",
                ));
            }
            let path = disk.get("path").and_then(Value::as_str);
            let serial = disk.get("serial").and_then(Value::as_str);
            let readonly = disk.get("readonly").and_then(Value::as_bool);
            let id = disk.get("id").and_then(Value::as_str);
            let sparse = disk.get("sparse").and_then(Value::as_bool);
            match (path, id, serial, readonly, sparse) {
                (Some(path), Some("cw-state"), Some("CWSTATE1"), Some(false), Some(true))
                    if path == state_path =>
                {
                    saw_state = true;
                }
                (Some(path), Some("cw-seed"), Some("CWSEED1"), Some(true), Some(false))
                    if path == seed_path =>
                {
                    saw_seed = true;
                }
                _ => return Err(failure("Cloud Hypervisor live disk identity drifted")),
            }
            if !disk
                .get("image_type")
                .and_then(Value::as_str)
                .is_some_and(|image_type| image_type.eq_ignore_ascii_case("raw"))
            {
                return Err(failure("Cloud Hypervisor live disk is not explicit raw"));
            }
            if !disk
                .get("lock_granularity")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("full"))
            {
                return Err(failure(
                    "Cloud Hypervisor live disk lacks full-file locking",
                ));
            }
        }
        if !saw_state || !saw_seed {
            return Err(failure(
                "Cloud Hypervisor live disks lack required serial identities",
            ));
        }
        let vsock = config
            .get("vsock")
            .and_then(Value::as_object)
            .ok_or_else(|| failure("Cloud Hypervisor vm.info omitted hybrid vsock"))?;
        if vsock.get("id").and_then(Value::as_str) != Some("cw-vsock")
            || vsock.get("socket").and_then(Value::as_str)
                != Some(paths.vsock_socket.to_string_lossy().as_ref())
            || vsock.get("cid").and_then(Value::as_u64) != Some(u64::from(expected_vsock_cid))
        {
            return Err(failure("Cloud Hypervisor live vsock identity drifted"));
        }
        Ok(LiveBoundary {
            config: Value::Object(config.clone()),
            device_tree: device_tree.clone(),
        })
    }

    fn require_unchanged_live_boundary(
        before: &LiveBoundary,
        after: &LiveBoundary,
    ) -> SmokeResult<()> {
        if after.config != before.config {
            return Err(failure(
                "Cloud Hypervisor live configuration changed after denied disk probe",
            ));
        }
        if after.device_tree != before.device_tree {
            return Err(failure(
                "Cloud Hypervisor live device tree changed after denied disk probe",
            ));
        }
        Ok(())
    }

    fn nonempty_json(value: &Value) -> bool {
        match value {
            Value::Null => false,
            Value::Bool(value) => *value,
            Value::String(value) => !value.is_empty(),
            Value::Array(value) => !value.is_empty(),
            Value::Object(value) => !value.is_empty(),
            Value::Number(_) => true,
        }
    }

    fn validate_outside_ext4(
        path: &Path,
        artifact_root: &Path,
        state_root: &Path,
    ) -> SmokeResult<()> {
        let canonical = fs::canonicalize(path)?;
        if canonical != path || path.starts_with(artifact_root) || path.starts_with(state_root) {
            return Err(failure(
                "Landlock negative disk must be canonical and outside every admitted tree",
            ));
        }
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() < STATE_DISK_BYTES
        {
            return Err(failure(
                "Landlock negative disk identity or permissions are unsafe",
            ));
        }
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(EXT4_SUPERBLOCK_OFFSET))?;
        let mut superblock = [0_u8; EXT4_PROBE_BYTES];
        file.read_exact(&mut superblock)?;
        if superblock[EXT4_MAGIC_OFFSET..EXT4_MAGIC_OFFSET + 2] != [0x53, 0xef]
            || superblock[EXT4_UUID_OFFSET..EXT4_UUID_OFFSET + 16]
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(failure("Landlock negative disk is not usable ext4"));
        }
        Ok(())
    }

    #[derive(Debug)]
    struct FdReport {
        cwd: PathBuf,
        targets: BTreeMap<u32, PathBuf>,
        socket_domains: BTreeMap<u32, i32>,
        unix_paths: BTreeSet<PathBuf>,
    }

    fn require_supervisor_socket_boundary() -> SmokeResult<()> {
        let identity = ProcessIdentity::capture(std::process::id())?;
        let live = LiveProcess::recover(&identity)?;
        let mut socket_fds = Vec::new();
        for entry in fs::read_dir(format!("/proc/{}/fd", identity.pid))? {
            let entry = entry?;
            let fd = entry
                .file_name()
                .to_string_lossy()
                .parse::<u32>()
                .map_err(|_| failure("supervisor descriptor number is malformed"))?;
            let target = fs::read_link(entry.path())?;
            let text = target.to_string_lossy();
            if text.starts_with("socket:") {
                socket_inode(&text)
                    .ok_or_else(|| failure("supervisor socket descriptor target is malformed"))?;
                socket_fds.push(fd);
            }
        }
        for fd in socket_fds {
            let foreign_fd = i32::try_from(fd)
                .map_err(|_| failure("supervisor socket descriptor number exceeds pidfd_getfd"))?;
            let domain = live.socket_domain_for_fd(foreign_fd).map_err(|_| {
                failure("exact pidfd socket classification failed for the supervisor")
            })?;
            require_non_network_socket_domain(fd, domain)?;
        }
        if ProcessIdentity::capture(identity.pid)? != identity {
            return Err(failure(
                "supervisor process identity changed during descriptor inspection",
            ));
        }
        observation("supervisor.socket_boundary_verified", true);
        Ok(())
    }

    fn require_fd_boundary(identity: &ProcessIdentity, paths: &VmPaths) -> SmokeResult<FdReport> {
        if ProcessIdentity::capture(identity.pid)? != *identity {
            return Err(failure(
                "VMM process identity changed before descriptor inspection",
            ));
        }
        let live = LiveProcess::recover(identity)?;
        let cwd = fs::read_link(format!("/proc/{}/cwd", identity.pid))?;
        if cwd.as_path() != paths.vm_dir.as_path() {
            return Err(failure(
                "VMM working directory is not its private VM directory",
            ));
        }
        let mut targets = BTreeMap::new();
        let mut socket_inodes = BTreeSet::new();
        let mut socket_domains = BTreeMap::new();
        for entry in fs::read_dir(format!("/proc/{}/fd", identity.pid))? {
            let entry = entry?;
            let fd = entry
                .file_name()
                .to_string_lossy()
                .parse::<u32>()
                .map_err(|_| failure("VMM descriptor number is malformed"))?;
            let target = fs::read_link(entry.path())?;
            let text = target.to_string_lossy();
            if matches!(
                text.as_ref(),
                "/dev/net/tun" | "/dev/net/tap" | "/dev/vhost-net"
            ) || text.starts_with("/dev/tap")
            {
                return Err(failure("VMM owns a host network-device descriptor"));
            }
            if text.starts_with("socket:") {
                let inode = socket_inode(&text)
                    .ok_or_else(|| failure("VMM socket descriptor target is malformed"))?;
                let foreign_fd = i32::try_from(fd)
                    .map_err(|_| failure("VMM socket descriptor number exceeds pidfd_getfd"))?;
                let domain = live.socket_domain_for_fd(foreign_fd).map_err(|error| {
                    failure(format!(
                        "exact pidfd socket classification failed for VMM fd {fd}: {error}"
                    ))
                })?;
                require_non_network_socket_domain(fd, domain)?;
                socket_inodes.insert(inode);
                socket_domains.insert(fd, domain);
            }
            targets.insert(fd, target);
        }
        if targets.is_empty() {
            return Err(failure("VMM descriptor inspection returned no descriptors"));
        }

        let unix = unix_socket_paths(identity.pid)?;
        let unix_paths = unix
            .into_iter()
            .filter_map(|(inode, path)| socket_inodes.contains(&inode).then_some(path))
            .collect::<BTreeSet<_>>();
        for required in [&paths.api_socket, &paths.vsock_socket] {
            if !unix_paths.contains(required) {
                return Err(failure(
                    "VMM does not own an expected private Unix listener",
                ));
            }
        }
        let reverse_prefix = format!("{}_", paths.vsock_socket.display());
        if unix_paths
            .iter()
            .any(|path| path.to_string_lossy().starts_with(&reverse_prefix))
        {
            return Err(failure("VMM owns an undeclared reverse-vsock listener"));
        }
        for entry in fs::read_dir(&paths.vsock_dir)? {
            let path = entry?.path();
            if path != paths.vsock_socket {
                return Err(failure(
                    "hybrid-vsock directory contains an undeclared endpoint",
                ));
            }
        }
        if ProcessIdentity::capture(identity.pid)? != *identity {
            return Err(failure(
                "VMM process identity changed during descriptor inspection",
            ));
        }
        if fs::read_link(format!("/proc/{}/cwd", identity.pid))? != cwd {
            return Err(failure(
                "VMM working directory changed during descriptor inspection",
            ));
        }
        Ok(FdReport {
            cwd,
            targets,
            socket_domains,
            unix_paths,
        })
    }

    fn socket_inode(target: &str) -> Option<u64> {
        target
            .strip_prefix("socket:[")?
            .strip_suffix(']')?
            .parse()
            .ok()
    }

    fn require_non_network_socket_domain(fd: u32, domain: i32) -> SmokeResult<()> {
        if matches!(domain, libc::AF_INET | libc::AF_INET6) {
            return Err(failure(format!(
                "VMM fd {fd} is an AF_INET/AF_INET6 socket"
            )));
        }
        Ok(())
    }

    fn unix_socket_paths(pid: u32) -> SmokeResult<BTreeMap<u64, PathBuf>> {
        let contents = fs::read_to_string(format!("/proc/{pid}/net/unix"))?;
        let mut result = BTreeMap::new();
        for line in contents.lines().skip(1) {
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            if fields.len() < 7 {
                return Err(failure("kernel Unix socket table is malformed"));
            }
            let inode = fields[6]
                .parse()
                .map_err(|_| failure("kernel Unix socket inode is malformed"))?;
            if let Some(path) = fields.get(7) {
                result.insert(inode, PathBuf::from(path));
            }
        }
        Ok(result)
    }

    fn observe_fds(report: &FdReport) {
        observation("vmm.cwd", report.cwd.display());
        observation("vmm.fd_count", report.targets.len());
        observation("vmm.socket_count", report.socket_domains.len());
        observation("vmm.unix_listener_count", report.unix_paths.len());
        for (fd, target) in &report.targets {
            observation(&format!("vmm.fd.{fd}"), target.display());
        }
        for (fd, domain) in &report.socket_domains {
            observation(&format!("vmm.socket.{fd}.domain"), domain);
        }
    }

    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn require_stale_identity_cannot_adopt_replacement(
        old_identity: &ProcessIdentity,
    ) -> SmokeResult<()> {
        let child = Command::new("/usr/bin/sleep")
            .arg("60")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut child = ChildGuard(child);
        let mut stale = old_identity.clone();
        stale.pid = child.0.id();
        if LiveProcess::recover(&stale).is_ok() {
            return Err(failure("stale VMM identity adopted a replacement process"));
        }
        if child.0.try_wait()?.is_some() {
            return Err(failure("replacement-process probe exited unexpectedly"));
        }
        observation("vmm.pid_reuse_rejected", true);
        Ok(())
    }

    fn require_metadata_mode(metadata: &Metadata, mode: u32) -> SmokeResult<()> {
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != mode
            || metadata.nlink() != 1
        {
            return Err(failure(
                "runtime endpoint identity or permissions are unsafe",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn args(values: &[&str]) -> SmokeResult<Option<Args>> {
            Args::parse(values.iter().map(|value| (*value).to_owned()))
        }

        #[test]
        fn top_level_failure_text_never_renders_the_error_chain() {
            const ATTACKER_MARKER: &str = "CW_ATTACKER_SECRET_TOKEN_MARKER";
            let attacker_controlled_error = failure(ATTACKER_MARKER);
            let rendered = top_level_failure_message(attacker_controlled_error.as_ref());
            assert_eq!(rendered, TOP_LEVEL_FAILURE_MESSAGE);
            assert!(!rendered.contains(ATTACKER_MARKER));
        }

        #[test]
        fn pty_output_normalizes_crlf_and_nothing_else() {
            assert_eq!(
                normalize_pty_crlf("first\r\nsecond\nthird\rfourth"),
                "first\nsecond\nthird\rfourth"
            );
        }

        #[test]
        fn process_confinement_parser_requires_unique_exact_fields() {
            let status = "Name:\tcloud-hypervisor\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n";
            assert_eq!(
                parse_process_confinement(status).unwrap(),
                ProcessConfinement {
                    seccomp: 2,
                    seccomp_filters: 1,
                    no_new_privs: 1,
                    cap_inh: 0,
                    cap_prm: 0,
                    cap_eff: 0,
                    cap_amb: 0,
                }
            );
            assert!(
                parse_process_confinement("CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp:\t2\nSeccomp_filters:\t1\n")
                    .is_err()
            );
            assert!(
                parse_process_confinement("CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\nSeccomp:\tfilter\nSeccomp_filters:\t1\n")
                    .is_err()
            );
        }

        #[tokio::test]
        async fn daemon_readiness_deadline_bounds_an_attempt_that_never_returns() {
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                wait_for_daemon_ready_with_timeout(
                    Duration::from_millis(25),
                    Duration::from_millis(5),
                    || async { std::future::pending::<Option<()>>().await },
                ),
            )
            .await
            .expect("daemon readiness helper exceeded its outer test bound");

            assert!(result.is_err());
        }

        fn test_paths() -> VmPaths {
            let vm_dir = PathBuf::from("/state/vms/00000000-0000-4000-8000-000000000001");
            let api_dir = vm_dir.join("api");
            let vsock_dir = vm_dir.join("vsock");
            let disks_dir = vm_dir.join("disks");
            let seed_dir = vm_dir.join("seed");
            let diagnostics_dir = vm_dir.join("diagnostics");
            VmPaths {
                api_socket: api_dir.join("api.sock"),
                vsock_socket: vsock_dir.join("vsock.sock"),
                state_disk: disks_dir.join("state.raw"),
                seed_disk: seed_dir.join("seed.raw"),
                serial_log: diagnostics_dir.join("serial.log"),
                vmm_log: diagnostics_dir.join("vmm.log"),
                event_monitor: diagnostics_dir.join("events.json"),
                lock_file: vm_dir.join("vm.lock"),
                state_file: vm_dir.join("state.json"),
                vm_dir,
                api_dir,
                vsock_dir,
                disks_dir,
                seed_dir,
                diagnostics_dir,
            }
        }

        fn test_resources() -> RunResources {
            RunResources {
                vcpus: 2,
                memory_mib: 768,
            }
        }

        fn exact_vm_info(paths: &VmPaths, resources: RunResources) -> VmInfo {
            let config = serde_json::json!({
                "landlock_enable": true,
                "landlock_rules": null,
                "preserved_fds": null,
                "cpus": {
                    "boot_vcpus": resources.vcpus,
                    "max_vcpus": resources.vcpus
                },
                "memory": {
                    "size": u64::from(resources.memory_mib) * 1024 * 1024
                },
                "net": null,
                "fs": null,
                "pmem": null,
                "devices": null,
                "user_devices": null,
                "vdpa": null,
                "tpm": null,
                "disks": [
                    {
                        "path": paths.state_disk,
                        "id": "cw-state",
                        "serial": "CWSTATE1",
                        "readonly": false,
                        "direct": false,
                        "vhost_user": false,
                        "backing_files": false,
                        "sparse": true,
                        "image_type": "Raw",
                        "lock_granularity": "Full"
                    },
                    {
                        "path": paths.seed_disk,
                        "id": "cw-seed",
                        "serial": "CWSEED1",
                        "readonly": true,
                        "direct": false,
                        "vhost_user": false,
                        "backing_files": false,
                        "sparse": false,
                        "image_type": "Raw",
                        "lock_granularity": "Full"
                    }
                ],
                "vsock": {
                    "cid": 7,
                    "socket": paths.vsock_socket,
                    "id": "cw-vsock"
                }
            });
            VmInfo {
                state: Some("Running".to_owned()),
                memory_actual_size: Some(512 * 1024 * 1024),
                additional: BTreeMap::from([
                    ("config".to_owned(), config),
                    (
                        "device_tree".to_owned(),
                        serde_json::json!({
                            "cw-state": {"id": "cw-state"},
                            "cw-seed": {"id": "cw-seed"},
                            "cw-vsock": {"id": "cw-vsock"}
                        }),
                    ),
                ]),
            }
        }

        #[test]
        fn run_arguments_require_every_bounded_path() {
            let parsed = args(&[
                "run",
                "--artifact-root",
                "/artifacts",
                "--artifact-lock",
                "/artifacts/lock.json",
                "--state-root",
                "/state",
                "--vm-id",
                "00000000-0000-4000-8000-000000000001",
                "--outside-disk",
                "/outside/ext4.raw",
                "--cpus",
                "2",
                "--memory-mib",
                "768",
            ])
            .unwrap()
            .unwrap();
            assert_eq!(parsed.mode, Mode::Run);
            assert_eq!(
                parsed.outside_disk,
                Some(PathBuf::from("/outside/ext4.raw"))
            );
            assert_eq!(parsed.resources, Some(test_resources()));
            let request = request(9, &parsed, parsed.resources.unwrap());
            assert_eq!(request.vcpus, 2);
            assert_eq!(request.memory_mib, 768);
        }

        #[test]
        fn run_arguments_require_valid_unique_resources() {
            let base = [
                "run",
                "--artifact-root",
                "/artifacts",
                "--artifact-lock",
                "/artifacts/lock.json",
                "--state-root",
                "/state",
                "--vm-id",
                "00000000-0000-4000-8000-000000000001",
                "--outside-disk",
                "/outside/ext4.raw",
            ];
            assert!(args(&base).is_err());
            let mut missing_memory = base.to_vec();
            missing_memory.extend(["--cpus", "1"]);
            assert!(args(&missing_memory).is_err());
            let mut missing_cpus = base.to_vec();
            missing_cpus.extend(["--memory-mib", "512"]);
            assert!(args(&missing_cpus).is_err());

            for invalid_cpus in ["0", "33", "+1", "01", "not-a-number"] {
                let mut values = base.to_vec();
                values.extend(["--cpus", invalid_cpus, "--memory-mib", "512"]);
                assert!(args(&values).is_err());
            }
            for invalid_memory in ["127", "65537", "+128", "0128", "not-a-number"] {
                let mut values = base.to_vec();
                values.extend(["--cpus", "1", "--memory-mib", invalid_memory]);
                assert!(args(&values).is_err());
            }

            let mut duplicate_cpus = base.to_vec();
            duplicate_cpus.extend(["--cpus", "1", "--cpus", "2", "--memory-mib", "512"]);
            assert!(args(&duplicate_cpus).is_err());

            let mut duplicate_memory = base.to_vec();
            duplicate_memory.extend(["--cpus", "1", "--memory-mib", "512", "--memory-mib", "1024"]);
            assert!(args(&duplicate_memory).is_err());
        }

        #[test]
        fn cleanup_refuses_an_outside_disk_or_relative_paths() {
            assert!(
                args(&[
                    "cleanup",
                    "--artifact-root",
                    "relative",
                    "--artifact-lock",
                    "/artifacts/lock.json",
                    "--state-root",
                    "/state",
                    "--vm-id",
                    "00000000-0000-4000-8000-000000000001",
                ])
                .is_err()
            );
            for flag in ["--cpus", "--memory-mib"] {
                assert!(
                    args(&[
                        "cleanup",
                        "--artifact-root",
                        "/artifacts",
                        "--artifact-lock",
                        "/artifacts/lock.json",
                        "--state-root",
                        "/state",
                        "--vm-id",
                        "00000000-0000-4000-8000-000000000001",
                        flag,
                        "512",
                    ])
                    .is_err()
                );
            }
            assert!(
                args(&[
                    "cleanup",
                    "--artifact-root",
                    "/artifacts",
                    "--artifact-lock",
                    "/artifacts/lock.json",
                    "--state-root",
                    "/state",
                    "--vm-id",
                    "00000000-0000-4000-8000-000000000001",
                    "--outside-disk",
                    "/outside/ext4.raw",
                ])
                .is_err()
            );
        }

        #[test]
        fn socket_inode_parser_is_exact() {
            assert_eq!(socket_inode("socket:[1234]"), Some(1234));
            assert_eq!(socket_inode("socket:[1234] trailing"), None);
            assert_eq!(socket_inode("pipe:[1234]"), None);
        }

        #[test]
        fn internet_socket_domains_are_rejected_without_proc_table_membership() {
            assert!(require_non_network_socket_domain(7, libc::AF_INET).is_err());
            assert!(require_non_network_socket_domain(8, libc::AF_INET6).is_err());
            assert!(require_non_network_socket_domain(9, libc::AF_UNIX).is_ok());
        }

        #[test]
        fn empty_forbidden_configuration_values_are_allowed() {
            for value in [
                Value::Null,
                Value::Bool(false),
                Value::String(String::new()),
                Value::Array(Vec::new()),
                Value::Object(serde_json::Map::new()),
            ] {
                assert!(!nonempty_json(&value));
            }
            assert!(nonempty_json(&serde_json::json!([{"id": "forbidden"}])));
        }

        #[test]
        fn live_configuration_contract_rejects_an_ip_device() {
            let paths = test_paths();
            let resources = test_resources();
            let valid = exact_vm_info(&paths, resources);
            require_live_configuration(&valid, &paths, 7, resources).unwrap();

            let mut invalid = exact_vm_info(&paths, resources);
            invalid.additional.get_mut("config").unwrap()["net"] =
                serde_json::json!([{"id": "forbidden-net"}]);
            assert!(require_live_configuration(&invalid, &paths, 7, resources).is_err());
        }

        #[test]
        fn live_configuration_contract_rejects_resource_drift() {
            let paths = test_paths();
            let resources = test_resources();

            let mut wrong_cpus = exact_vm_info(&paths, resources);
            wrong_cpus.additional.get_mut("config").unwrap()["cpus"]["max_vcpus"] =
                serde_json::json!(resources.vcpus + 1);
            assert!(require_live_configuration(&wrong_cpus, &paths, 7, resources).is_err());

            let mut wrong_memory = exact_vm_info(&paths, resources);
            wrong_memory.additional.get_mut("config").unwrap()["memory"]["size"] =
                serde_json::json!(u64::from(resources.memory_mib + 1) * 1024 * 1024);
            assert!(require_live_configuration(&wrong_memory, &paths, 7, resources).is_err());
        }

        #[test]
        fn live_boundary_requires_and_compares_the_bounded_device_tree() {
            let paths = test_paths();
            let resources = test_resources();
            let before =
                require_live_configuration(&exact_vm_info(&paths, resources), &paths, 7, resources)
                    .unwrap();

            let mut absent = exact_vm_info(&paths, resources);
            absent.additional.remove("device_tree");
            assert!(require_live_configuration(&absent, &paths, 7, resources).is_err());

            let mut null = exact_vm_info(&paths, resources);
            null.additional
                .insert("device_tree".to_owned(), Value::Null);
            assert!(require_live_configuration(&null, &paths, 7, resources).is_err());

            let mut drifted = exact_vm_info(&paths, resources);
            drifted.additional.get_mut("device_tree").unwrap()["unexpected"] =
                serde_json::json!({"id": "partial-hotplug"});
            let after = require_live_configuration(&drifted, &paths, 7, resources).unwrap();
            assert!(require_unchanged_live_boundary(&before, &after).is_err());
        }

        #[test]
        fn cid_is_stable_and_never_reserved() {
            let vm_id = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
            assert_eq!(cid_for(vm_id), cid_for(vm_id));
            assert!((3..u32::MAX).contains(&cid_for(vm_id)));
        }
    }
}
