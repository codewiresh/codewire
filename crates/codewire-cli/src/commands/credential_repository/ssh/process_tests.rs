//! Real stock-SSH parent lifetime, independent of provider authentication.
//! Every subprocess is this exact isolated fixture or the fixed SSH binary.

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt as _;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::*;

const ROLE: &str = "CODEWIRE_TEST_SSH_PARENT_ROLE";
const FIXTURE: &str =
    "commands::credential_repository::ssh::process_tests::ssh_parent_lifetime_fixture";
const LIMIT: Duration = Duration::from_secs(5);

fn fixture_command(role: &str, runtime: &Path, port: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", FIXTURE, "--nocapture"])
        .env_clear()
        .env(ROLE, role)
        .env(SSH_HELPER_RUNTIME_ENV, runtime)
        .env(SSH_HELPER_PORT_ENV, port)
        .env(SSH_HELPER_HOST_ENV, "127.0.0.1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // Only fixed fixture failures/public host trust can reach stderr;
        // no server handshake or credential operation occurs in this proof.
        .stderr(Stdio::inherit());
    command
}

fn announce(runtime: &Path, role: u8) -> UnixStream {
    let mut stream = UnixStream::connect(runtime.join("control")).unwrap();
    stream.set_read_timeout(Some(LIMIT)).unwrap();
    stream.set_write_timeout(Some(LIMIT)).unwrap();
    stream.write_all(&[role]).unwrap();
    stream.write_all(&std::process::id().to_be_bytes()).unwrap();
    stream
}

#[test]
fn ssh_parent_lifetime_fixture() {
    let Ok(role) = std::env::var(ROLE) else {
        return;
    };
    let runtime = PathBuf::from(std::env::var_os(SSH_HELPER_RUNTIME_ENV).unwrap());
    let port = std::env::var(SSH_HELPER_PORT_ENV).unwrap();
    match role.as_str() {
        "executor" => {
            // SAFETY: this isolated test subprocess adopts only its own
            // descendants so it can prove actual SSH reap after Git exits.
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
                0
            );
            let mut control = announce(&runtime, b'E');
            let mut git = fixture_command("git", &runtime, &port)
                .env(SSH_HELPER_OWNER_ENV, std::process::id().to_string())
                .spawn()
                .unwrap();
            let mut pid = [0; 4];
            control.read_exact(&mut pid).unwrap();
            let ssh_pid = i32::try_from(u32::from_be_bytes(pid)).unwrap();
            assert!(ssh_pid > 1 && ssh_pid != git.id() as i32);
            git.kill().unwrap();
            assert_eq!(git.wait().unwrap().signal(), Some(libc::SIGKILL));
            let deadline = Instant::now() + LIMIT;
            loop {
                let mut status = 0;
                // SAFETY: waitpid does not signal a PID. The exact helper is
                // now this fixture's adopted child, not an ambient process.
                let result = unsafe { libc::waitpid(ssh_pid, &mut status, libc::WNOHANG) };
                if result == ssh_pid {
                    assert_eq!(
                        std::process::ExitStatus::from_raw(status).signal(),
                        Some(libc::SIGKILL)
                    );
                    break;
                }
                assert_eq!(result, 0);
                assert!(Instant::now() < deadline, "stock SSH outlived Git");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        "git" => {
            let _control = announce(&runtime, b'G');
            let mut shim = fixture_command("shim", &runtime, &port)
                .env(
                    SSH_HELPER_OWNER_ENV,
                    std::env::var(SSH_HELPER_OWNER_ENV).unwrap(),
                )
                .spawn()
                .unwrap();
            // Only the executor may kill Git. Never directly signal SSH:
            // that would manufacture the parent-death result being asserted.
            // The root's group guard owns all timeout/failure cleanup.
            let status = shim.wait().unwrap();
            panic!("stock SSH exited before the executor killed Git: {status}");
        }
        "shim" => {
            drop(announce(&runtime, b'H'));
            run_git_ssh_helper(vec![
                "git@127.0.0.1".into(),
                "git-upload-pack 'synthetic.git'".into(),
            ])
            .unwrap();
            unreachable!("stock SSH replaces this fixture process");
        }
        _ => panic!("unknown isolated fixture role"),
    }
}

struct OwnedExecutor(Child);

impl Drop for OwnedExecutor {
    fn drop(&mut self) {
        // Reserve the unreaped leader PID through cleanup, as production does.
        // SAFETY: this child alone created the same-numbered process group.
        unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL) };
        let _ = self.0.wait();
    }
}

#[test]
fn stock_ssh_is_killed_and_reaped_when_its_git_parent_exits() {
    let runtime = tempfile::tempdir().unwrap();
    std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let control = UnixListener::bind(runtime.path().join("control")).unwrap();
    control.set_nonblocking(true).unwrap();
    let _agent = UnixListener::bind(runtime.path().join("agent")).unwrap();
    std::fs::set_permissions(
        runtime.path().join("agent"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    server.set_nonblocking(true).unwrap();
    let port = server.local_addr().unwrap().port().to_string();
    let public_key = codewire_protected_store::ssh_material::generate_ed25519().unwrap();
    std::fs::write(
        runtime.path().join("known_hosts"),
        format!("[127.0.0.1]:{port} {}\n", public_key.public_key().openssh()),
    )
    .unwrap();
    std::fs::set_permissions(
        runtime.path().join("known_hosts"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let mut command = fixture_command("executor", runtime.path(), &port);
    // SAFETY: the post-fork hook performs only fixed scalar syscalls. No
    // authority or provider material is present in any of these processes.
    unsafe {
        command.pre_exec(|| {
            crate::commands::credential_authority::confine_spawned_process()?;
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let executor = OwnedExecutor(command.spawn().unwrap());
    let deadline = Instant::now() + LIMIT;
    let mut channels = std::collections::BTreeMap::new();
    while channels.len() < 3 {
        match control.accept() {
            Ok((mut stream, _)) => {
                stream.set_read_timeout(Some(LIMIT)).unwrap();
                stream.set_write_timeout(Some(LIMIT)).unwrap();
                let mut message = [0; 5];
                stream.read_exact(&mut message).unwrap();
                assert!(matches!(message[0], b'E' | b'G' | b'H'));
                assert!(
                    channels
                        .insert(message[0], (stream, message[1..].to_vec()))
                        .is_none()
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "fixture startup timed out");
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("fixture control failed: {error}"),
        }
    }
    let mut connection = loop {
        match server.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "stock SSH did not connect");
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("fixture connection failed: {error}"),
        }
    };
    connection.set_read_timeout(Some(LIMIT)).unwrap();
    let mut banner = [0; 4];
    connection.read_exact(&mut banner).unwrap();
    assert_eq!(&banner, b"SSH-");
    // The banner proves the production trampoline actually execed stock SSH.
    // Keep its handshake waiting, then kill Git through the owned executor.
    let pid = channels.get(&b'H').unwrap().1.clone();
    channels.get_mut(&b'E').unwrap().0.write_all(&pid).unwrap();
    let mut tail = Vec::new();
    connection.take(1024).read_to_end(&mut tail).unwrap();
    assert!(
        tail.len() < 1024,
        "expected actual SSH socket EOF, not the byte limit"
    );
    let child = rustix::process::Pid::from_raw(executor.0.id() as i32).unwrap();
    let status = loop {
        assert!(Instant::now() < deadline, "executor did not prove SSH reap");
        let status = rustix::process::waitid(
            rustix::process::WaitId::Pid(child),
            rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT,
        )
        .unwrap();
        if let Some(status) = status {
            break status;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.exit_status(), Some(0));
    drop(executor);
}
