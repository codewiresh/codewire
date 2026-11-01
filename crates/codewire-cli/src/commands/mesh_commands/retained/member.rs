//! Linux host-member custody. Delegated member control needs a subreaper and
//! pidfds, which macOS has no public form of (docs/dev/MACOS-CLI.md), so a
//! later `cw` adopts a member helper by its pidfd here; the local Mesh uses
//! the shared owner model instead (`owner.rs`).
use super::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;

const MAX_COMMAND: usize = 16 * 1024;
const MAX_EXECUTABLE: u64 = 256 * 1024 * 1024;
const NONCE_ENV: &str = "CW_LOCAL_HELPER_NONCE";

/// Member cleanup retains the original descriptor, rather than treating equal
/// JSON bytes in a replacement inode as ownership of the original record.
pub(crate) struct MemberRecord {
    name: String,
    file: File,
    stamp: FileStamp,
    bytes: Vec<u8>,
}

impl MemberRecord {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl StateDir {
    pub(crate) fn hold_member_record(&self, name: &str) -> anyhow::Result<Option<MemberRecord>> {
        anyhow::ensure!(
            matches!(
                name,
                "member-runtime.json" | "member-ready.json" | "member-starting.json"
            ),
            "member cleanup record name is invalid"
        );
        let Some(mut file) = self.named_file(name, libc::O_RDONLY, MAX_STATE)? else {
            return Ok(None);
        };
        let before = private_file(&file, MAX_STATE)?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_STATE as u64 + 1)
            .read_to_end(&mut bytes)?;
        let record = MemberRecord {
            name: name.into(),
            file,
            stamp: stamp(&before),
            bytes,
        };
        self.validate_member_record(&record)?;
        Ok(Some(record))
    }

    pub(crate) fn validate_member_record(&self, record: &MemberRecord) -> anyhow::Result<()> {
        self.check(true)?;
        anyhow::ensure!(
            record.bytes.len() <= MAX_STATE,
            "member record exceeds its bound"
        );
        let held = private_file(&record.file, MAX_STATE)?;
        let current = fs::symlink_metadata(self.path.join(&record.name))?;
        anyhow::ensure!(
            record.stamp == stamp(&held) && record.stamp == stamp(&current),
            "member record identity changed before cleanup"
        );
        anyhow::ensure!(
            self.read(&record.name)?.as_deref() == Some(record.bytes()),
            "member record bytes changed before cleanup"
        );
        self.check(true)
    }

    pub(crate) fn remove_member_record(&self, record: &MemberRecord) -> anyhow::Result<()> {
        self.validate_member_record(record)?;
        let name = std::ffi::CString::new(record.name.as_str())?;
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        self.directory.sync_all()?;
        Ok(())
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutableIdentity {
    pub(crate) path: PathBuf,
    dev: u64,
    ino: u64,
    size: u64,
    sha256: String,
}

impl ExecutableIdentity {
    pub(crate) fn admit(path: &Path) -> anyhow::Result<Self> {
        let path = fs::canonicalize(path).context("resolve the member helper executable")?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)?;
        let before = file.metadata()?;
        anyhow::ensure!(
            before.is_file()
                && before.nlink() == 1
                && before.mode() & 0o111 != 0
                && before.mode() & 0o6000 == 0
                && before.mode() & 0o022 == 0
                && (before.uid() == euid() || before.uid() == 0)
                && before.len() >= 4
                && before.len() <= MAX_EXECUTABLE,
            "the member helper must be an owner-controlled bounded executable"
        );
        let mut header = [0; 4];
        file.read_exact(&mut header)?;
        anyhow::ensure!(
            header == *b"\x7fELF",
            "the member helper must be a native ELF executable"
        );
        let mut hasher = Sha256::new();
        hasher.update(header);
        let mut buffer = [0; 64 * 1024];
        let mut size = 4;
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            size += count as u64;
            anyhow::ensure!(
                size <= MAX_EXECUTABLE,
                "helper executable grew beyond its bound"
            );
            hasher.update(&buffer[..count]);
        }
        anyhow::ensure!(
            size == before.len()
                && stamp(&before) == stamp(&file.metadata()?)
                && stamp(&before) == stamp(&fs::symlink_metadata(&path)?),
            "helper executable changed during admission"
        );
        Ok(Self {
            path,
            dev: before.dev(),
            ino: before.ino(),
            size,
            sha256: format!("{:x}", hasher.finalize()),
        })
    }
}

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HelperRole {
    HostMember,
    /// A plain child for the custody tests: its arguments are its path only.
    #[cfg(test)]
    Fixture,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum HelperConfiguration {
    HostMember(MemberConfiguration),
    #[cfg(test)]
    Fixture,
}

/// A member helper's launch: everything its arguments carry.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemberConfiguration {
    pub(crate) directory: PathBuf,
    pub(crate) environment_id: String,
    pub(crate) host_root: PathBuf,
    pub(crate) origin: String,
    pub(crate) org: String,
    pub(crate) network: String,
    pub(crate) control_key: String,
    pub(crate) wg_key: String,
    pub(crate) derp_only: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessCustody {
    schema_version: u32,
    pid: u32,
    uid: u32,
    boot_id: String,
    start_ticks: u64,
    executable: ExecutableIdentity,
    role: HelperRole,
    arguments: Vec<String>,
    configuration: HelperConfiguration,
    launch_nonce: String,
}

fn read_proc(directory: &File, name: &str, limit: usize) -> anyhow::Result<Vec<u8>> {
    let mut file = open_at(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )?;
    let mut bytes = Vec::new();
    (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= limit,
        "helper process metadata exceeds its bound"
    );
    Ok(bytes)
}

fn boot_id() -> anyhow::Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/proc/sys/kernel/random/boot_id")?;
    let mut bytes = Vec::new();
    (&mut file).take(65).read_to_end(&mut bytes)?;
    let value = std::str::from_utf8(&bytes)?.trim();
    anyhow::ensure!(
        value.len() == 36 && value.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
        "invalid kernel boot identity"
    );
    Ok(value.to_owned())
}

fn process_birth(directory: &File) -> anyhow::Result<u64> {
    let stat = read_proc(directory, "stat", 4096)?;
    let stat = std::str::from_utf8(&stat)?;
    let (_, fields) = stat
        .rsplit_once(") ")
        .context("invalid helper process stat")?;
    let fields = fields.split_whitespace().collect::<Vec<_>>();
    anyhow::ensure!(
        fields.len() > 19 && !matches!(fields[0], "Z" | "X"),
        "helper process is terminal"
    );
    let birth = fields[19].parse()?;
    anyhow::ensure!(birth != 0, "helper process birth is missing");
    Ok(birth)
}

pub(crate) struct PinnedProcess {
    pidfd: OwnedFd,
    proc_directory: File,
}

impl PinnedProcess {
    fn open(pid: u32) -> anyhow::Result<Self> {
        anyhow::ensure!(
            pid > 0 && pid <= i32::MAX as u32,
            "invalid helper process identity"
        );
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error()).context("pin helper process");
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let proc_directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(format!("/proc/{pid}"))?;
        let handle = Self {
            pidfd,
            proc_directory,
        };
        anyhow::ensure!(
            !handle.exited()? && handle.proc_directory.metadata()?.uid() == euid(),
            "helper process is not live and owned"
        );
        Ok(handle)
    }

    fn exited(&self) -> anyhow::Result<bool> {
        let mut descriptor = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if result < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        anyhow::ensure!(
            descriptor.revents & (libc::POLLNVAL | libc::POLLERR) == 0,
            "helper process handle became invalid"
        );
        Ok(descriptor.revents & (libc::POLLIN | libc::POLLHUP) != 0)
    }

    fn validate(&self, custody: &ProcessCustody) -> anyhow::Result<()> {
        custody.validate_binding()?;
        anyhow::ensure!(
            custody.schema_version == 1
                && custody.uid == euid()
                && custody.start_ticks != 0
                && custody.boot_id == boot_id()?
                && !self.exited()?,
            "helper process birth ownership is unknown"
        );
        anyhow::ensure!(
            self.proc_directory.metadata()?.uid() == custody.uid
                && process_birth(&self.proc_directory)? == custody.start_ticks,
            "helper process birth changed"
        );
        anyhow::ensure!(
            ExecutableIdentity::admit(&custody.executable.path)? == custody.executable,
            "retained helper executable changed"
        );
        // This is a held proc directory for the pidfd-admitted process, not a
        // pathname traversal that could read a recycled numeric PID.
        let executable = open_at(
            &self.proc_directory,
            "exe",
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0,
        )?;
        let metadata = executable.metadata()?;
        anyhow::ensure!(
            metadata.dev() == custody.executable.dev
                && metadata.ino() == custody.executable.ino
                && metadata.len() == custody.executable.size,
            "helper process executable does not match its retained path"
        );
        let mut expected = Vec::new();
        for argument in &custody.arguments {
            expected.extend_from_slice(argument.as_bytes());
            expected.push(0);
        }
        anyhow::ensure!(
            expected.len() <= MAX_COMMAND
                && read_proc(&self.proc_directory, "cmdline", MAX_COMMAND)? == expected,
            "helper process role or arguments changed"
        );
        // These helpers receive an explicitly cleared, credential-free launch
        // environment. Check only that owned projection; never log its bytes.
        let environment = read_proc(&self.proc_directory, "environ", MAX_STATE)?;
        let mut projection = BTreeMap::new();
        for field in environment
            .split(|byte| *byte == 0)
            .filter(|field| !field.is_empty())
        {
            let field =
                std::str::from_utf8(field).context("invalid helper environment projection")?;
            let (name, value) = field
                .split_once('=')
                .context("invalid helper environment projection")?;
            if matches!(name, "RUST_LOG" | "RUST_BACKTRACE") {
                continue;
            }
            anyhow::ensure!(
                projection
                    .insert(name.to_owned(), value.to_owned())
                    .is_none(),
                "duplicate helper environment projection key"
            );
        }
        anyhow::ensure!(
            projection == launch_environment(&custody.configuration, &custody.launch_nonce),
            "helper launch configuration or nonce changed"
        );
        anyhow::ensure!(
            process_birth(&self.proc_directory)? == custody.start_ticks && !self.exited()?,
            "helper process exited during validation"
        );
        Ok(())
    }

    fn signal(&self, signal: i32) -> anyhow::Result<()> {
        if self.exited()? {
            return Ok(());
        }
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error()).context("signal exact owned helper");
        }
        Ok(())
    }

    async fn wait(&self, duration: Duration) -> anyhow::Result<bool> {
        let deadline = tokio::time::Instant::now() + duration;
        loop {
            if self.exited()? {
                return Ok(true);
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub(crate) async fn terminate(&self) -> anyhow::Result<()> {
        self.signal(libc::SIGTERM)?;
        if !self.wait(Duration::from_secs(2)).await? {
            self.signal(libc::SIGKILL)?;
            anyhow::ensure!(
                self.wait(Duration::from_secs(2)).await?,
                "owned helper did not exit"
            );
        }
        Ok(())
    }
}

impl ProcessCustody {
    fn expected_arguments(
        executable: &Path,
        role: HelperRole,
        configuration: &HelperConfiguration,
    ) -> anyhow::Result<Vec<String>> {
        let mut arguments = vec![
            executable
                .to_str()
                .context("helper executable path is not UTF-8")?
                .to_owned(),
        ];
        match (role, configuration) {
            (
                HelperRole::HostMember,
                HelperConfiguration::HostMember(MemberConfiguration {
                    directory,
                    environment_id,
                    host_root,
                    origin,
                    org,
                    network,
                    control_key,
                    wg_key,
                    derp_only,
                }),
            ) => {
                arguments.extend([
                    "__host-member".into(),
                    "--directory".into(),
                    directory
                        .to_str()
                        .context("member directory invalid")?
                        .into(),
                    "--environment".into(),
                    environment_id.clone(),
                    "--host-root".into(),
                    host_root
                        .to_str()
                        .context("member host root invalid")?
                        .into(),
                    "--origin".into(),
                    origin.clone(),
                    "--org".into(),
                    org.clone(),
                    "--network".into(),
                    network.clone(),
                    "--control-key".into(),
                    control_key.clone(),
                    "--wg-key".into(),
                    wg_key.clone(),
                    "--derp-only".into(),
                    derp_only.to_string(),
                ]);
            }
            #[cfg(test)]
            (HelperRole::Fixture, HelperConfiguration::Fixture) => {}
            #[cfg(test)]
            _ => anyhow::bail!("helper role and configuration disagree"),
        }
        anyhow::ensure!(
            arguments.iter().map(|s| s.len() + 1).sum::<usize>() <= MAX_COMMAND,
            "helper launch arguments exceed their bound"
        );
        Ok(arguments)
    }

    fn validate_binding(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            Self::expected_arguments(&self.executable.path, self.role, &self.configuration)?
                == self.arguments,
            "helper role/configuration binding changed"
        );
        anyhow::ensure!(
            uuid::Uuid::parse_str(&self.launch_nonce).is_ok(),
            "helper launch nonce is invalid"
        );
        match &self.configuration {
            HelperConfiguration::HostMember(MemberConfiguration {
                environment_id,
                directory,
                host_root,
                origin,
                org,
                network,
                control_key,
                wg_key,
                ..
            }) => {
                anyhow::ensure!(
                    uuid::Uuid::parse_str(environment_id).is_ok()
                        && directory.is_absolute()
                        && host_root.is_absolute()
                        && origin.len() <= 2048
                        && !org.is_empty()
                        && org.len() <= 128
                        && !network.is_empty()
                        && network.len() <= 128
                        && [control_key, wg_key].iter().all(|key| key.len() == 64
                            && key
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
                    "member retained configuration is invalid"
                );
            }
            #[cfg(test)]
            HelperConfiguration::Fixture => {}
        }
        Ok(())
    }

    fn capture(
        child: &std::process::Child,
        executable: ExecutableIdentity,
        role: HelperRole,
        arguments: Vec<String>,
        configuration: HelperConfiguration,
        launch_nonce: String,
    ) -> anyhow::Result<(Self, PinnedProcess)> {
        let handle = PinnedProcess::open(child.id())?;
        let value = Self {
            schema_version: 1,
            pid: child.id(),
            uid: euid(),
            boot_id: boot_id()?,
            start_ticks: process_birth(&handle.proc_directory)?,
            executable,
            role,
            arguments,
            configuration,
            launch_nonce,
        };
        handle.validate(&value)?;
        Ok((value, handle))
    }

    fn pin(&self, pid: u32, binary: &str) -> anyhow::Result<PinnedProcess> {
        anyhow::ensure!(
            self.pid == pid && self.executable.path == Path::new(binary),
            "helper runtime identity does not match its record"
        );
        let handle = PinnedProcess::open(pid)?;
        handle.validate(self)?;
        Ok(handle)
    }

    pub(crate) fn pin_member(&self) -> anyhow::Result<PinnedProcess> {
        anyhow::ensure!(
            self.role == HelperRole::HostMember,
            "retained process is not a member helper"
        );
        self.pin(
            self.pid,
            self.executable
                .path
                .to_str()
                .context("member executable invalid")?,
        )
    }
    pub(crate) fn member_configuration(&self) -> anyhow::Result<&MemberConfiguration> {
        self.validate_binding()?;
        match (self.role, &self.configuration) {
            (HelperRole::HostMember, HelperConfiguration::HostMember(configuration)) => {
                Ok(configuration)
            }
            #[cfg(test)]
            _ => anyhow::bail!("retained process is not a member helper"),
        }
    }
    pub(crate) fn member_nonce(&self) -> &str {
        &self.launch_nonce
    }
    pub(crate) fn member_pid(&self) -> u32 {
        self.pid
    }
    /// A retained private record proves a prior admitted incarnation. Absence
    /// or a different birth proves only that incarnation ended; it grants no
    /// authority to signal a numeric replacement or stop delegated sessions.
    pub(crate) fn member_terminal(&self) -> anyhow::Result<bool> {
        self.member_configuration()?;
        anyhow::ensure!(
            self.schema_version == 1
                && self.uid == euid()
                && self.pid > 0
                && self.pid <= i32::MAX as u32
                && self.start_ticks > 0
                && uuid::Uuid::parse_str(&self.boot_id)
                    .is_ok_and(|id| !id.is_nil() && id.to_string() == self.boot_id),
            "member retained birth identity unavailable"
        );
        anyhow::ensure!(
            ExecutableIdentity::admit(&self.executable.path)? == self.executable,
            "retained member image changed or disappeared"
        );
        if self.boot_id != boot_id()? {
            return Ok(true);
        }
        let directory = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(format!("/proc/{}", self.pid))
        {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(error) => return Err(error.into()),
        };
        let bytes = read_proc(&directory, "stat", 4096)?;
        let text = std::str::from_utf8(&bytes)?;
        let fields = text
            .rsplit_once(") ")
            .context("member birth metadata unavailable")?
            .1
            .split_whitespace()
            .collect::<Vec<_>>();
        anyhow::ensure!(fields.len() > 19, "member birth metadata unavailable");
        let start: u64 = fields[19].parse()?;
        anyhow::ensure!(start > 0, "member kernel birth identity unavailable");
        if start != self.start_ticks {
            return Ok(true);
        }
        if !matches!(fields[0], "Z" | "X") {
            return Ok(false);
        }
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, self.pid, 0) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error()).context("pin terminal member incarnation");
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let mut item = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        anyhow::ensure!(
            unsafe { libc::poll(&mut item, 1, 0) } >= 0
                && item.revents & (libc::POLLERR | libc::POLLNVAL) == 0,
            "member terminal custody unavailable"
        );
        // The held proc directory still proves the captured birth; the pidfd
        // supplies actual terminal state, rather than trusting a state string.
        let after = read_proc(&directory, "stat", 4096)?;
        anyhow::ensure!(
            after == bytes,
            "member birth changed during terminal admission"
        );
        Ok(item.revents & (libc::POLLIN | libc::POLLHUP) != 0)
    }
}

/// A member helper has no provider/shell descendants. Its enrollment is sent
/// once through stdin, never durable argv, environment, config or log output.
pub(crate) struct OwnedMember {
    child: std::process::Child,
    handle: PinnedProcess,
    pub(crate) custody: ProcessCustody,
    retained: bool,
}
impl OwnedMember {
    pub(crate) fn retain(mut self) -> ProcessCustody {
        self.retained = true;
        self.custody.clone()
    }
    pub(crate) fn live(&self) -> anyhow::Result<()> {
        self.handle.validate(&self.custody)
    }
}
impl Drop for OwnedMember {
    fn drop(&mut self) {
        if !self.retained {
            let _ = self.handle.signal(libc::SIGKILL);
            let _ = self.child.wait();
        }
    }
}
pub(crate) fn spawn_member(
    directory: &StateDir,
    executable: ExecutableIdentity,
    configuration: HelperConfiguration,
    enrollment: &[u8],
) -> anyhow::Result<OwnedMember> {
    anyhow::ensure!(
        matches!(configuration, HelperConfiguration::HostMember(_))
            && !enrollment.is_empty()
            && enrollment.len() <= 8192,
        "member enrollment or role invalid"
    );
    let arguments = ProcessCustody::expected_arguments(
        &executable.path,
        HelperRole::HostMember,
        &configuration,
    )?;
    let log = directory.log("member-helper.log")?;
    let nonce = uuid::Uuid::new_v4().to_string();
    let mut command = ProcessCommand::new(&executable.path);
    command
        .arg0(&arguments[0])
        .args(&arguments[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log));
    configure_environment(&mut command, &configuration, &nonce);
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().context("start exact member helper")?;
    let (custody, handle) = match ProcessCustody::capture(
        &child,
        executable,
        HelperRole::HostMember,
        arguments,
        configuration,
        nonce,
    ) {
        Ok(value) => value,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let mut owned = OwnedMember {
        child,
        handle,
        custody,
        retained: false,
    };
    let mut input = owned
        .child
        .stdin
        .take()
        .context("member bootstrap pipe absent")?;
    input.write_all(enrollment)?;
    drop(input);
    owned.live()?;
    Ok(owned)
}

fn launch_environment(
    configuration: &HelperConfiguration,
    nonce: &str,
) -> BTreeMap<String, String> {
    // Every member's launch environment is its nonce alone.
    let _ = configuration;
    BTreeMap::from([(NONCE_ENV.to_owned(), nonce.to_owned())])
}

pub(crate) fn configure_environment(
    command: &mut ProcessCommand,
    configuration: &HelperConfiguration,
    nonce: &str,
) {
    command
        .env_clear()
        .envs(local_service_logging_environment())
        .envs(launch_environment(configuration, nonce));
}

#[cfg(test)]
mod tests;
