//! Linux local-helper custody. Selection changes never retire a live helper.
//! These are owner processes, not a sandbox or a boundary against the same UID.
use super::*;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;

const MAX_STATE: usize = 64 * 1024;
const MAX_COMMAND: usize = 16 * 1024;
const MAX_EXECUTABLE: u64 = 256 * 1024 * 1024;
const LOCK: &str = "mesh-control.lock";
const STARTING: &str = "mesh-starting.json";
const NONCE_ENV: &str = "CW_LOCAL_HELPER_NONCE";
pub(crate) const MESH_ROLE: &str = "__local-mesh";
pub(crate) const DERP_ROLE: &str = "__local-derp";

fn euid() -> u32 {
    // SAFETY: geteuid has no arguments or effects.
    unsafe { libc::geteuid() }
}

fn open_at(directory: &File, name: &str, flags: i32, mode: u32) -> anyhow::Result<File> {
    let name = std::ffi::CString::new(name)?;
    // All callers provide one fixed basename. NOFOLLOW is deliberate for state
    // and proc files; the kernel's proc/exe seam is the sole explicit exception.
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[derive(PartialEq, Eq)]
struct FileStamp {
    dev: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    bytes: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn stamp(value: &fs::Metadata) -> FileStamp {
    FileStamp {
        dev: value.dev(),
        inode: value.ino(),
        uid: value.uid(),
        mode: value.mode(),
        links: value.nlink(),
        bytes: value.len(),
        modified: (value.mtime(), value.mtime_nsec()),
        changed: (value.ctime(), value.ctime_nsec()),
    }
}

fn private_file(file: &File, maximum: usize) -> anyhow::Result<fs::Metadata> {
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == euid()
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == 0o600
            && metadata.len() <= maximum as u64,
        "local Mesh state is not a bounded owner-private regular file"
    );
    Ok(metadata)
}

pub(crate) struct StateDir {
    path: PathBuf,
    directory: File,
}

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
    pub(crate) fn open(path: &Path, create: bool) -> anyhow::Result<Option<Self>> {
        if create {
            match fs::DirBuilder::new().mode(0o700).create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error).context("create private local Mesh directory"),
            }
        }
        let directory = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error).context("open private local Mesh directory"),
        };
        let value = Self {
            path: path.to_owned(),
            directory,
        };
        value.check(create)?;
        Ok(Some(value))
    }

    fn check(&self, writable: bool) -> anyhow::Result<()> {
        let fd = self.directory.metadata()?;
        let path = fs::symlink_metadata(&self.path)?;
        anyhow::ensure!(
            fd.is_dir()
                && path.is_dir()
                && fd.dev() == path.dev()
                && fd.ino() == path.ino()
                && fd.uid() == euid()
                && fd.mode() & 0o7077 == 0
                && fd.mode() & 0o500 == 0o500,
            "local Mesh directory ownership changed"
        );
        if writable {
            anyhow::ensure!(fd.mode() & 0o200 != 0, "local Mesh directory is read-only");
        }
        Ok(())
    }

    fn named_file(&self, name: &str, flags: i32, maximum: usize) -> anyhow::Result<Option<File>> {
        self.check(false)?;
        let file = match open_at(
            &self.directory,
            name,
            flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0o600,
        ) {
            Ok(file) => file,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error).context("open local Mesh state"),
        };
        let metadata = private_file(&file, maximum)?;
        let path = fs::symlink_metadata(self.path.join(name))?;
        anyhow::ensure!(
            stamp(&metadata) == stamp(&path),
            "local Mesh state identity changed"
        );
        self.check(false)?;
        Ok(Some(file))
    }

    pub(crate) fn read(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let Some(mut file) = self.named_file(name, libc::O_RDONLY, MAX_STATE)? else {
            return Ok(None);
        };
        let before = file.metadata()?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_STATE as u64 + 1)
            .read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() <= MAX_STATE && stamp(&before) == stamp(&file.metadata()?),
            "local Mesh state changed during read"
        );
        let current = fs::symlink_metadata(self.path.join(name))?;
        anyhow::ensure!(
            stamp(&before) == stamp(&current),
            "local Mesh state pathname changed"
        );
        self.check(false)?;
        Ok(Some(bytes))
    }

    pub(crate) fn write(&self, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
        self.check(true)?;
        anyhow::ensure!(
            bytes.len() <= MAX_STATE,
            "local Mesh state exceeds its bound"
        );
        let before = self.read(name)?;
        let temporary = format!(".mesh-state-{}", uuid::Uuid::new_v4().simple());
        let mut file = open_at(
            &self.directory,
            &temporary,
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
            0o600,
        )?;
        let result = (|| -> anyhow::Result<()> {
            private_file(&file, MAX_STATE)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            self.check(true)?;
            anyhow::ensure!(
                before == self.read(name)?,
                "local Mesh state changed before publication"
            );
            let from = std::ffi::CString::new(temporary.as_str())?;
            let to = std::ffi::CString::new(name)?;
            let result = if before.is_none() {
                unsafe {
                    libc::syscall(
                        libc::SYS_renameat2,
                        self.directory.as_raw_fd(),
                        from.as_ptr(),
                        self.directory.as_raw_fd(),
                        to.as_ptr(),
                        libc::RENAME_NOREPLACE,
                    ) as i32
                }
            } else {
                unsafe {
                    libc::renameat(
                        self.directory.as_raw_fd(),
                        from.as_ptr(),
                        self.directory.as_raw_fd(),
                        to.as_ptr(),
                    )
                }
            };
            if result != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            self.directory.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            // This name was created exclusively by this call, inside the held
            // private directory. Never remove the destination after uncertain ACK.
            let _ = self.remove(&temporary, Some(bytes));
        }
        result
    }

    pub(crate) fn remove(&self, name: &str, expected: Option<&[u8]>) -> anyhow::Result<()> {
        self.check(true)?;
        let Some(bytes) = self.read(name)? else {
            return Ok(());
        };
        if let Some(expected) = expected {
            anyhow::ensure!(
                bytes == expected,
                "local Mesh record changed before cleanup"
            );
        }
        let name = std::ffi::CString::new(name)?;
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        self.directory.sync_all()?;
        Ok(())
    }

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

    pub(crate) fn log(&self, name: &str) -> anyhow::Result<File> {
        self.check(true)?;
        if let Some(file) =
            self.named_file(name, libc::O_WRONLY | libc::O_APPEND, 64 * 1024 * 1024)?
        {
            return Ok(file);
        }
        let file = open_at(
            &self.directory,
            name,
            libc::O_WRONLY
                | libc::O_APPEND
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
            0o600,
        )?;
        private_file(&file, 64 * 1024 * 1024)?;
        self.check(true)?;
        Ok(file)
    }

    pub(crate) async fn lock(&self) -> anyhow::Result<ControlLock> {
        self.check(true)?;
        let file = match self.named_file(LOCK, libc::O_RDWR, 0)? {
            Some(file) => file,
            None => match open_at(
                &self.directory,
                LOCK,
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
                0o600,
            ) {
                Ok(file) => file,
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) =>
                {
                    self.named_file(LOCK, libc::O_RDWR, 0)?
                        .context("local Mesh lock disappeared")?
                }
                Err(error) => return Err(error),
            },
        };
        private_file(&file, 0)?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            anyhow::ensure!(
                matches!(error.raw_os_error(), Some(libc::EWOULDBLOCK | libc::EINTR)),
                "local Mesh lock failed: {error}"
            );
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "local Mesh control lock timed out"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let locked = ControlLock(file);
        locked.check(self)?;
        Ok(locked)
    }
}

pub(crate) struct ControlLock(File);
impl ControlLock {
    fn check(&self, directory: &StateDir) -> anyhow::Result<()> {
        directory.check(true)?;
        let current = directory
            .named_file(LOCK, libc::O_RDONLY, 0)?
            .context("local Mesh lock disappeared")?;
        anyhow::ensure!(
            stamp(&self.0.metadata()?) == stamp(&current.metadata()?),
            "local Mesh lock pathname changed"
        );
        Ok(())
    }
}
impl Drop for ControlLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
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
        let path = fs::canonicalize(path).context("resolve local Mesh helper executable")?;
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
            "local Mesh override must be an owner-controlled bounded executable"
        );
        let mut header = [0; 4];
        file.read_exact(&mut header)?;
        anyhow::ensure!(
            header == *b"\x7fELF",
            "Linux local Mesh overrides must be native ELF executables"
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
    EmbeddedMesh,
    EmbeddedDerp,
    ExternalMesh,
    ExternalDerp,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum HelperConfiguration {
    HostMember {
        directory: PathBuf,
        environment_id: String,
        host_root: PathBuf,
        origin: String,
        org: String,
        network: String,
        control_key: String,
        wg_key: String,
        derp_only: bool,
    },
    Mesh {
        base_url: String,
        listen_addr: String,
        derp_url: Option<String>,
        organization_id: String,
        api_key_hash: String,
    },
    Derp {
        url: String,
        listen_addr: String,
    },
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
                HelperConfiguration::HostMember {
                    directory,
                    environment_id,
                    host_root,
                    origin,
                    org,
                    network,
                    control_key,
                    wg_key,
                    derp_only,
                },
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
            (
                HelperRole::EmbeddedMesh | HelperRole::ExternalMesh,
                HelperConfiguration::Mesh {
                    base_url,
                    listen_addr,
                    derp_url,
                    ..
                },
            ) => {
                if role == HelperRole::EmbeddedMesh {
                    arguments.push(MESH_ROLE.to_owned());
                }
                arguments.extend([
                    "--base-url".to_owned(),
                    base_url.clone(),
                    "--listen".to_owned(),
                    listen_addr.clone(),
                ]);
                if let Some(url) = derp_url {
                    arguments.extend(["--derp-url".to_owned(), url.clone()]);
                }
            }
            (
                HelperRole::EmbeddedDerp | HelperRole::ExternalDerp,
                HelperConfiguration::Derp { .. },
            ) => {
                if role == HelperRole::EmbeddedDerp {
                    arguments.push(DERP_ROLE.to_owned());
                }
            }
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
        if let HelperConfiguration::Mesh {
            organization_id,
            api_key_hash,
            ..
        } = &self.configuration
        {
            anyhow::ensure!(
                !organization_id.is_empty()
                    && organization_id.len() <= 256
                    && api_key_hash.len() == 64
                    && api_key_hash.bytes().all(|b| b.is_ascii_hexdigit()),
                "helper authorization projection is invalid"
            );
        }
        if let HelperConfiguration::HostMember {
            environment_id,
            directory,
            host_root,
            origin,
            org,
            network,
            control_key,
            wg_key,
            ..
        } = &self.configuration
        {
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
    pub(crate) fn member_configuration(&self) -> anyhow::Result<&HelperConfiguration> {
        self.validate_binding()?;
        anyhow::ensure!(
            self.role == HelperRole::HostMember,
            "retained process is not a member helper"
        );
        Ok(&self.configuration)
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
        matches!(configuration, HelperConfiguration::HostMember { .. })
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

struct OwnedHelper {
    child: std::process::Child,
    handle: PinnedProcess,
    custody: ProcessCustody,
    retained: bool,
}

impl OwnedHelper {
    async fn stop(&mut self) -> anyhow::Result<()> {
        self.handle.terminate().await?;
        self.child.wait()?;
        self.retained = true;
        Ok(())
    }
}

impl Drop for OwnedHelper {
    fn drop(&mut self) {
        if !self.retained {
            // Cancellation before durable publication stops only this exact
            // newly launched child. The starting intent remains for diagnosis.
            let _ = self.handle.signal(libc::SIGKILL);
        }
    }
}

fn spawn_helper(
    directory: &StateDir,
    executable: ExecutableIdentity,
    role: HelperRole,
    configuration: HelperConfiguration,
) -> anyhow::Result<OwnedHelper> {
    let arguments = ProcessCustody::expected_arguments(&executable.path, role, &configuration)?;
    let log_name = match &configuration {
        HelperConfiguration::HostMember { .. } => {
            anyhow::bail!("member helper requires its dedicated launch adapter")
        }
        HelperConfiguration::Mesh { .. } => LOCAL_MESH_LOG_FILE,
        HelperConfiguration::Derp { .. } => LOCAL_DERP_LOG_FILE,
    };
    let log = directory.log(log_name)?;
    let mut command = ProcessCommand::new(&executable.path);
    command
        .arg0(&arguments[0])
        .args(&arguments[1..])
        .env_clear()
        .envs(local_service_logging_environment())
        .stdin(Stdio::null())
        .stderr(Stdio::from(log.try_clone()?))
        .stdout(Stdio::from(log));
    let launch_nonce = uuid::Uuid::new_v4().to_string();
    configure_environment(&mut command, &configuration, &launch_nonce);
    // A local service must not share the invoking terminal's process group.
    unsafe {
        command.pre_exec(|| {
            if libc::prctl(
                libc::PR_SET_NO_NEW_PRIVS,
                1 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            ) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .context("start exact retained local Mesh helper")?;
    match ProcessCustody::capture(
        &child,
        executable,
        role,
        arguments,
        configuration,
        launch_nonce,
    ) {
        Ok((custody, handle)) => Ok(OwnedHelper {
            child,
            handle,
            custody,
            retained: false,
        }),
        Err(error) => {
            // Child is still held and unreaped. Its numeric identity cannot be
            // recycled here; no persisted PID is ever sent through this seam.
            let _ = child.kill();
            let _ = child.wait();
            Err(error)
        }
    }
}

fn launch_environment(
    configuration: &HelperConfiguration,
    nonce: &str,
) -> BTreeMap<String, String> {
    let mut projection = BTreeMap::from([(NONCE_ENV.to_owned(), nonce.to_owned())]);
    match configuration {
        HelperConfiguration::HostMember { .. } => {}
        HelperConfiguration::Mesh {
            organization_id,
            api_key_hash,
            ..
        } => {
            projection.insert(
                "CODEWIRE_MESH_LOCAL_ORGANIZATION_ID".to_owned(),
                organization_id.clone(),
            );
            projection.insert(
                "CODEWIRE_MESH_LOCAL_API_KEY_HASH".to_owned(),
                api_key_hash.clone(),
            );
        }
        HelperConfiguration::Derp { listen_addr, .. } => {
            projection.insert("PORT".to_owned(), "-1".to_owned());
            projection.insert("TLS_LISTEN_ADDR".to_owned(), listen_addr.clone());
            projection.insert("STUN_LISTEN_ADDR".to_owned(), "-1".to_owned());
        }
    }
    projection
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

#[derive(serde::Serialize)]
struct StartingIntent<'a> {
    operation_id: &'a str,
    mesh: Option<&'a ProcessCustody>,
    derp: Option<&'a ProcessCustody>,
}

fn write_intent(
    directory: &StateDir,
    operation_id: &str,
    mesh: Option<&OwnedHelper>,
    derp: Option<&OwnedHelper>,
) -> anyhow::Result<()> {
    directory.write(
        STARTING,
        &serde_json::to_vec(&StartingIntent {
            operation_id,
            mesh: mesh.map(|helper| &helper.custody),
            derp: derp.map(|helper| &helper.custody),
        })?,
    )
}

pub(crate) fn validate_runtime(
    runtime: &LocalMeshRuntime,
) -> anyhow::Result<(PinnedProcess, Option<PinnedProcess>)> {
    let custody = runtime
        .custody
        .as_ref()
        .context("local Mesh custody is unknown; retained legacy record was not adopted")?;
    let HelperConfiguration::Mesh {
        base_url,
        listen_addr,
        derp_url,
        ..
    } = &custody.configuration
    else {
        anyhow::bail!("local Mesh record has the wrong helper role");
    };
    anyhow::ensure!(
        base_url == &runtime.base_url
            && listen_addr == &runtime.listen_addr
            && derp_url.as_deref() == runtime.derp.as_ref().map(|derp| derp.url.as_str()),
        "local Mesh configuration binding changed"
    );
    let mesh = custody.pin(runtime.pid, &runtime.binary)?;
    let derp = runtime
        .derp
        .as_ref()
        .map(|derp| -> anyhow::Result<PinnedProcess> {
            let custody = derp
                .custody
                .as_ref()
                .context("local DERP custody is unknown")?;
            let HelperConfiguration::Derp { url, listen_addr } = &custody.configuration else {
                anyhow::bail!("local DERP record has the wrong helper role")
            };
            anyhow::ensure!(
                url == &derp.url && listen_addr == &derp.listen_addr,
                "local DERP configuration binding changed"
            );
            custody.pin(derp.pid, &derp.binary)
        })
        .transpose()?;
    Ok((mesh, derp))
}

pub(crate) fn validate_owner(
    runtime: &LocalMeshRuntime,
    owner: &LocalMeshOwnerContext,
) -> anyhow::Result<()> {
    validate_runtime(runtime)?;
    let Some(ProcessCustody {
        configuration: HelperConfiguration::Mesh {
            organization_id, ..
        },
        ..
    }) = runtime.custody.as_ref()
    else {
        anyhow::bail!("local Mesh owner has no admitted runtime binding");
    };
    anyhow::ensure!(
        owner.schema_version == 1
            && owner.auth_source == LocalMeshOwnerAuthSource::StandaloneLocal
            && config::same_mesh_url(&owner.mesh_url, &runtime.base_url)
            && &owner.organization_id == organization_id,
        "local Mesh owner projection differs from the owned running helper"
    );
    Ok(())
}

pub(crate) fn unresolved_start(data_dir: &Path) -> anyhow::Result<bool> {
    match StateDir::open(data_dir, false)? {
        Some(directory) => Ok(directory.read(STARTING)?.is_some()),
        None => Ok(false),
    }
}

pub(crate) async fn up(paths: &ResolvePaths, args: MeshUpArgs) -> anyhow::Result<MeshUpReport> {
    let directory =
        StateDir::open(&paths.mesh_data_dir, true)?.context("local Mesh directory is absent")?;
    let lock = directory.lock().await?;
    anyhow::ensure!(
        directory.read(STARTING)?.is_none(),
        "local Mesh startup has an unresolved retained intent; no helper was adopted or replaced"
    );
    if let Some(runtime) = load_local_mesh_runtime(&paths.mesh_data_dir)? {
        let _handles = validate_runtime(&runtime)?;
        let owner = load_local_mesh_owner_context(&paths.mesh_data_dir)?
            .context("live local Mesh owner projection is absent")?;
        validate_owner(&runtime, &owner)?;
        anyhow::ensure!(
            local_mesh_runtime_matches_args(&runtime, &args),
            "live local Mesh configuration differs; explicitly run cw mesh down before changing it"
        );
        // An omitted override follows the running original A, not today's B.
        if let Some(path) = args.binary.as_ref() {
            anyhow::ensure!(
                ExecutableIdentity::admit(path)?.path == Path::new(&runtime.binary),
                "local Mesh override differs from the owned running helper"
            );
        }
        if let Some(path) = args.derp_binary.as_ref() {
            let derp = runtime
                .derp
                .as_ref()
                .context("running local Mesh has no DERP helper")?;
            anyhow::ensure!(
                ExecutableIdentity::admit(path)?.path == Path::new(&derp.binary),
                "local DERP override differs from the owned running helper"
            );
        }
        lock.check(&directory)?;
        return Ok(mesh_up_report(false, &runtime));
    }
    // Preflight fixed executable/config state before minting local identity or
    // spawning. The public owner projection is never a reason to adopt a PID.
    let mesh_executable =
        ExecutableIdentity::admit(&locate_codewire_mesh_binary(args.binary.as_ref())?)?;
    let derp_executable = if args.no_derp {
        None
    } else {
        Some(ExecutableIdentity::admit(&locate_codewire_derp_binary(
            args.derp_binary.as_ref(),
        )?)?)
    };
    directory.read(LOCAL_MESH_OWNER_CONTEXT_FILE)?;
    let mut mesh_config: config::MeshConfig = match directory.read("config.toml")? {
        None => config::MeshConfig::default(),
        Some(bytes) => toml::from_str(
            std::str::from_utf8(&bytes)
                .map_err(|_| anyhow::anyhow!("invalid bounded local Mesh configuration"))?,
        )
        .map_err(|_| anyhow::anyhow!("invalid bounded local Mesh configuration"))?,
    };
    let local_identity = match mesh_config
        .local_identity
        .as_ref()
        .filter(|value| value.is_complete())
    {
        Some(identity) => identity.clone(),
        None => {
            let identity = config::new_local_mesh_identity();
            mesh_config.local_identity = Some(identity.clone());
            lock.check(&directory)?;
            directory.write(
                "config.toml",
                toml::to_string_pretty(&mesh_config)?.as_bytes(),
            )?;
            identity
        }
    };
    let selected_network = mesh_config
        .mesh_selected_network
        .clone()
        .and_then(|network| trimmed_str(&network).map(str::to_owned));
    let auto_connect = selected_network.is_some() && mesh_config.mesh_auto_connect.unwrap_or(false);
    let spec = local_mesh_start_spec(paths, &args, local_identity)?;
    let operation_id = uuid::Uuid::new_v4().to_string();
    lock.check(&directory)?;
    write_intent(&directory, &operation_id, None, None)?;
    let mut mesh = None;
    let mut derp = None;
    let start = async {
        if let (Some(executable), Some(spec)) = (derp_executable, &spec.derp) {
            lock.check(&directory)?;
            derp = Some(spawn_helper(
                &directory,
                executable,
                if args.derp_binary.is_none() {
                    HelperRole::EmbeddedDerp
                } else {
                    HelperRole::ExternalDerp
                },
                HelperConfiguration::Derp {
                    url: spec.url.clone(),
                    listen_addr: spec.listen_addr.clone(),
                },
            )?);
            write_intent(&directory, &operation_id, None, derp.as_ref())?;
        }
        lock.check(&directory)?;
        mesh = Some(spawn_helper(
            &directory,
            mesh_executable,
            if args.binary.is_none() {
                HelperRole::EmbeddedMesh
            } else {
                HelperRole::ExternalMesh
            },
            HelperConfiguration::Mesh {
                base_url: spec.base_url.clone(),
                listen_addr: spec.listen_addr.clone(),
                derp_url: spec.derp.as_ref().map(|derp| derp.url.clone()),
                organization_id: spec.local_identity.organization_id.clone(),
                api_key_hash: spec.local_identity.api_key_hash(),
            },
        )?);
        write_intent(&directory, &operation_id, mesh.as_ref(), derp.as_ref())?;
        tokio::time::timeout(
            Duration::from_secs(5),
            wait_for_standalone_mesh_catalog(
                paths,
                &spec,
                &spec.local_identity.organization_id,
                selected_network.as_deref(),
            ),
        )
        .await
        .context("local Mesh readiness timed out")??;
        let mesh = mesh.as_ref().context("local Mesh was not launched")?;
        let runtime = LocalMeshRuntime {
            pid: mesh.child.id(),
            base_url: spec.base_url.clone(),
            listen_addr: spec.listen_addr.clone(),
            binary: mesh.custody.executable.path.display().to_string(),
            log_path: spec.log_path.display().to_string(),
            started_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            custody: Some(mesh.custody.clone()),
            derp: derp
                .as_ref()
                .zip(spec.derp.as_ref())
                .map(|(helper, spec)| LocalDerpRuntime {
                    pid: helper.child.id(),
                    url: spec.url.clone(),
                    listen_addr: spec.listen_addr.clone(),
                    binary: helper.custody.executable.path.display().to_string(),
                    log_path: spec.log_path.display().to_string(),
                    custody: Some(helper.custody.clone()),
                }),
        };
        validate_runtime(&runtime)?;
        lock.check(&directory)?;
        mesh_config.mesh_url = Some(spec.base_url.clone());
        mesh_config.mesh_auth_token = Some(spec.local_identity.api_key.clone());
        directory.write(
            "config.toml",
            toml::to_string_pretty(&mesh_config)?.as_bytes(),
        )?;
        save_local_mesh_owner_context(
            &paths.mesh_data_dir,
            &LocalMeshOwnerContext {
                schema_version: 1,
                auth_source: LocalMeshOwnerAuthSource::StandaloneLocal,
                mesh_url: spec.base_url.clone(),
                organization_id: spec.local_identity.organization_id.clone(),
                selected_network,
                auto_connect,
            },
        )?;
        save_local_mesh_runtime(&paths.mesh_data_dir, &runtime)?;
        // A failed fsync/ACK after publication retains the startup intent. It
        // cannot be silently cleared into a new launch by a later controller.
        let intent = directory
            .read(STARTING)?
            .context("local Mesh startup intent disappeared")?;
        directory.remove(STARTING, Some(&intent))?;
        Ok::<_, anyhow::Error>(runtime)
    }
    .await;
    match start {
        Ok(runtime) => {
            if let Some(helper) = mesh.as_mut() {
                helper.retained = true;
            }
            if let Some(helper) = derp.as_mut() {
                helper.retained = true;
            }
            Ok(mesh_up_report(true, &runtime))
        }
        Err(error) => {
            // Keep all records if publication may already have happened.
            let mut cleanup = Ok(());
            if let Some(helper) = mesh.as_mut() {
                cleanup = helper.stop().await;
            }
            if let Some(helper) = derp.as_mut() {
                cleanup = cleanup.and(helper.stop().await);
            }
            if cleanup.is_ok() && directory.read(LOCAL_MESH_RUNTIME_FILE)?.is_none() {
                let intent = directory.read(STARTING)?;
                directory.remove(STARTING, intent.as_deref())?;
            }
            if let Err(cleanup) = cleanup {
                return Err(error.context(format!("owned helper cleanup is unresolved: {cleanup}")));
            }
            Err(error)
        }
    }
}

pub(crate) async fn down(paths: &ResolvePaths) -> anyhow::Result<MeshDownReport> {
    let Some(directory) = StateDir::open(&paths.mesh_data_dir, false)? else {
        return Ok(MeshDownReport {
            stopped: false,
            pid: None,
            state: "not_running".to_owned(),
        });
    };
    let lock = directory.lock().await?;
    anyhow::ensure!(
        directory.read(STARTING)?.is_none(),
        "local Mesh startup custody is unresolved; all records were retained"
    );
    let Some(bytes) = directory.read(LOCAL_MESH_RUNTIME_FILE)? else {
        return Ok(MeshDownReport {
            stopped: false,
            pid: None,
            state: "not_running".to_owned(),
        });
    };
    let runtime: LocalMeshRuntime = serde_json::from_slice(&bytes)?;
    // Pin and validate BOTH helpers before the first signal. A partial unknown
    // record must not permit disruption of its other currently live helper.
    let (mesh, derp) = validate_runtime(&runtime)?;
    lock.check(&directory)?;
    anyhow::ensure!(
        directory.read(LOCAL_MESH_RUNTIME_FILE)?.as_deref() == Some(&bytes),
        "local Mesh record changed before shutdown"
    );
    mesh.terminate().await?;
    if let Some(derp) = derp {
        derp.terminate().await?;
    }
    directory.remove(LOCAL_MESH_RUNTIME_FILE, Some(&bytes))?;
    remove_mesh_owner_context_for_auth_source(
        &paths.mesh_data_dir,
        LocalMeshOwnerAuthSource::StandaloneLocal,
    )?;
    Ok(MeshDownReport {
        stopped: true,
        pid: Some(runtime.pid),
        state: "stopped".to_owned(),
    })
}

#[cfg(test)]
mod tests;
