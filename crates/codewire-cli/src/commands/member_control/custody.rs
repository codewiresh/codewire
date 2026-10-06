//! Connect-only private owner admission. The socket supplies the initial
//! pidfd; numeric SO_PEERCRED + pidfd_open cannot prove the socket's birth.
use super::super::mesh_commands::retained::ExecutableIdentity;
use super::{super::HostEnvironment, store};
use anyhow::{Context, ensure};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::Arc;

pub(super) struct OwnerPin {
    pidfd: OwnedFd,
    proc: File,
    pid: u32,
    birth: u64,
    boot: String,
    socket: PathBuf,
    socket_id: (u64, u64),
    executable: ExecutableIdentity,
    argv: Vec<u8>,
}
fn proc_read(proc: &File, name: &str, maximum: usize) -> anyhow::Result<Vec<u8>> {
    let name = std::ffi::CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            proc.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    ensure!(fd >= 0, "member owner metadata is unavailable");
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= maximum,
        "member owner metadata bound exceeded"
    );
    Ok(bytes)
}
fn birth(proc: &File) -> anyhow::Result<u64> {
    let bytes = proc_read(proc, "stat", 4096)?;
    let text = std::str::from_utf8(&bytes)?;
    let fields = text
        .rsplit_once(") ")
        .context("member owner stat invalid")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    ensure!(
        fields.len() > 19 && !matches!(fields[0], "Z" | "X"),
        "member owner is terminal"
    );
    let value = fields[19].parse()?;
    ensure!(value != 0, "member owner birth unavailable");
    Ok(value)
}
fn boot() -> anyhow::Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open("/proc/sys/kernel/random/boot_id")?;
    let mut bytes = Vec::new();
    (&mut file).take(65).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 64, "member boot metadata invalid");
    Ok(std::str::from_utf8(&bytes)?.trim().into())
}
fn socket_pidfd(stream: &tokio::net::UnixStream) -> anyhow::Result<(OwnedFd, u32)> {
    const SO_PEERPIDFD: libc::c_int = 77;
    let mut fd: libc::c_int = -1;
    let mut size = std::mem::size_of_val(&fd) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            (&mut fd as *mut libc::c_int).cast(),
            &mut size,
        )
    };
    ensure!(
        result == 0 && size as usize == std::mem::size_of_val(&fd) && fd >= 0,
        "kernel socket-derived member owner custody unavailable"
    );
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    ensure!(
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == 0,
        "member owner pidfd CLOEXEC unavailable"
    );
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))?;
    ensure!(info.len() <= 4096, "member owner pidfd metadata invalid");
    let pid: u32 = info
        .lines()
        .find_map(|s| s.strip_prefix("Pid:\t"))
        .context("member owner pidfd has no birth")?
        .parse()?;
    ensure!(
        pid > 0 && stream.peer_cred()?.pid() == Some(pid as i32),
        "member owner peer identity unavailable"
    );
    Ok((fd, pid))
}
impl OwnerPin {
    pub async fn admit(environment: &HostEnvironment) -> anyhow::Result<Arc<Self>> {
        ensure!(
            environment.state == "running",
            "member requires an already running host owner"
        );
        let root = environment.root();
        store::admit_chain(&root)?;
        let socket = root.join("daemon.sock");
        let metadata = std::fs::symlink_metadata(&socket)?;
        ensure!(
            metadata.file_type().is_socket()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o7777 == 0o600,
            "member owner socket must be private"
        );
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::net::UnixStream::connect(&socket),
        )
        .await??;
        ensure!(
            stream.peer_cred()?.uid() == unsafe { libc::geteuid() },
            "member owner UID changed"
        );
        let (pidfd, pid) = socket_pidfd(&stream)?;
        let proc = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(format!("/proc/{pid}"))?;
        let image = std::fs::read_link(format!("/proc/self/fd/{}/exe", proc.as_raw_fd()))?;
        let executable = ExecutableIdentity::admit(&image)?;
        let arguments = [
            executable
                .path
                .to_str()
                .context("member owner path invalid")?
                .to_owned(),
            "_host-daemon".into(),
            "--environment".into(),
            environment.id.clone(),
            "--registry-root".into(),
            root.parent()
                .context("member owner registry missing")?
                .to_str()
                .context("member owner registry invalid")?
                .into(),
        ];
        let argv = arguments
            .iter()
            .flat_map(|s| s.as_bytes().iter().copied().chain([0]))
            .collect::<Vec<_>>();
        let value = Arc::new(Self {
            birth: birth(&proc)?,
            boot: boot()?,
            pidfd,
            proc,
            pid,
            socket,
            socket_id: (metadata.dev(), metadata.ino()),
            executable,
            argv,
        });
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        let mut fd = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        ensure!(
            unsafe { libc::poll(&mut fd, 1, 0) } == 0 && fd.revents == 0,
            "retained member owner exited or became ambiguous"
        );
        ensure!(
            self.proc.metadata()?.uid() == unsafe { libc::geteuid() }
                && birth(&self.proc)? == self.birth
                && boot()? == self.boot,
            "member owner birth changed"
        );
        let metadata = std::fs::symlink_metadata(&self.socket)?;
        ensure!(
            metadata.file_type().is_socket()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o7777 == 0o600
                && (metadata.dev(), metadata.ino()) == self.socket_id,
            "member owner socket was replaced"
        );
        ensure!(
            ExecutableIdentity::admit(&self.executable.path)? == self.executable,
            "retained member owner executable changed"
        );
        let exe_path = PathBuf::from(format!("/proc/self/fd/{}/exe", self.proc.as_raw_fd()));
        let image = std::fs::metadata(exe_path)?;
        let expected = std::fs::symlink_metadata(&self.executable.path)?;
        ensure!(
            (image.dev(), image.ino()) == (expected.dev(), expected.ino())
                && proc_read(&self.proc, "cmdline", 16 * 1024)? == self.argv,
            "member owner executable or fixed role changed"
        );
        Ok(())
    }
    pub async fn client(
        self: &Arc<Self>,
        environment: &HostEnvironment,
    ) -> anyhow::Result<codewire_daemon::client::HostControlClient> {
        self.validate()?;
        let pin = Arc::clone(self);
        let connector = tower::service_fn(move |_| {
            let pin = Arc::clone(&pin);
            async move {
                let check = || {
                    pin.validate().map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "retained member owner unavailable",
                        )
                    })
                };
                check()?;
                let stream = tokio::net::UnixStream::connect(&pin.socket).await?;
                let (_pidfd, pid) = socket_pidfd(&stream).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "member owner peer unavailable",
                    )
                })?;
                if pid != pin.pid || stream.peer_cred()?.uid() != unsafe { libc::geteuid() } {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "member owner peer replaced",
                    ));
                }
                check()?;
                Ok(hyper_util::rt::TokioIo::new(stream))
            }
        });
        let channel = tonic::transport::Endpoint::from_static("http://codewire-host-member")
            .connect_timeout(std::time::Duration::from_secs(3))
            .timeout(std::time::Duration::from_secs(10))
            .connect_with_connector(connector)
            .await?;
        let dir = store::Directory::open(&environment.root(), false)?;
        let token: String = dir
            .read("daemon-token.json")?
            .context("member owner capability unavailable")?;
        let client = codewire_daemon::client::HostControlClient::from_channel(
            channel,
            token,
            environment.id.clone(),
        )?;
        client.require_ready().await?;
        self.validate()?;
        Ok(client)
    }
}

#[cfg(test)]
mod kernel_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[tokio::test]
    async fn member_socket_pidfd_is_cloexec_same_birth_and_replaced_socket_refuses() {
        struct SocketOwner(std::process::Child);
        impl Drop for SocketOwner {
            fn drop(&mut self) {
                let _ = self.0.kill();
                self.0.wait().expect("reap the exact socket-owner child");
            }
        }
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = temp.path().join("owner.sock");
        // Use a bounded native ELF for this kernel-only witness. A debug
        // libtest image can exceed the unchanged production executable cap.
        let mut owner = SocketOwner(
            std::process::Command::new("/usr/bin/python3")
                .args([
                    "-I",
                    "-B",
                    "-c",
                    "import os, socket, sys; os.umask(0o077); s = socket.socket(socket.AF_UNIX); \
                     s.bind(sys.argv[1]); s.listen(1); os.chmod(sys.argv[1], 0o600); \
                     c, _ = s.accept(); c.recv(1)",
                ])
                .arg(&socket)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            assert!(owner.0.try_wait().unwrap().is_none(), "socket owner exited");
            if std::fs::symlink_metadata(&socket)
                .is_ok_and(|meta| meta.file_type().is_socket() && meta.mode() & 0o7777 == 0o600)
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "socket owner not ready"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::net::UnixStream::connect(&socket),
        )
        .await
        .unwrap()
        .unwrap();
        let (pidfd, pid) = socket_pidfd(&stream).unwrap();
        assert_eq!(pid, owner.0.id());
        assert_ne!(
            unsafe { libc::fcntl(pidfd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        let proc = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(format!("/proc/{pid}"))
            .unwrap();
        let image = std::fs::read_link(format!("/proc/{pid}/exe")).unwrap();
        let executable = ExecutableIdentity::admit(&image).unwrap();
        let argv = proc_read(&proc, "cmdline", 16 * 1024).unwrap();
        let meta = std::fs::symlink_metadata(&socket).unwrap();
        // This is a real kernel pin/image witness, not genuine cw
        // role/provenance or host product acceptance.
        let pin = OwnerPin {
            birth: birth(&proc).unwrap(),
            boot: boot().unwrap(),
            pidfd,
            proc,
            pid,
            socket: socket.clone(),
            socket_id: (meta.dev(), meta.ino()),
            executable,
            argv,
        };
        pin.validate().unwrap();
        std::fs::remove_file(&socket).unwrap();
        let replacement = tokio::net::UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(pin.validate().is_err());
        drop(replacement);
    }
    #[tokio::test]
    async fn member_private_connector_refuses_a_wrong_role_without_owner_effects() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = temp.path().join("daemon.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let environment = HostEnvironment {
            id: uuid::Uuid::new_v4().to_string(),
            name: "synthetic".into(),
            path: temp.path().into(),
            created_at: String::new(),
            state: "running".into(),
            runtime_root: Some(temp.path().into()),
        };
        assert!(OwnerPin::admit(&environment).await.is_err());
        assert!(!temp.path().join("daemon.log").exists());
        assert!(!temp.path().join("daemon-token.json").exists());
        drop(listener);
    }
}
