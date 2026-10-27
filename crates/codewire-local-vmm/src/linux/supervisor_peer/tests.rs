use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::process::{Child, Command, Stdio};

use codewire_cw_release::store::{Admission, Candidate, Store};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixListener;
use tower::ServiceExt as _;

use super::*;
use crate::supervisor::{NativeSupervisorClient, SupervisorError};
use crate::uds::{capture_supervisor_peer, supervisor_peer_connector};

struct Sentinel(Child);

impl Drop for Sentinel {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// A real stored ELF interpreter, real fixed role argv and real kernel UDS peer.
// This proves synthetic admission, not genuine cw build or product behavior.
struct Fixture {
    parent: tempfile::TempDir,
    child: Child,
    config: NativeRuntimeConfig,
}

impl Fixture {
    fn start(managed: bool, extra: &[&str]) -> Self {
        let parent = tempfile::Builder::new()
            .prefix("cw-sp-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(fs::canonicalize("/var/tmp").unwrap())
            .unwrap();
        let root = parent.path().join("runtime");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let source = fs::canonicalize("/usr/bin/python3").unwrap();
        let executable = if managed {
            let store = Store::create(
                &parent.path().join("store"),
                &parent.path().join("entry"),
                Duration::from_secs(1),
            )
            .unwrap();
            let published = store
                .publish(&Candidate {
                    executable: source,
                    admission: Admission::SelfInstall {
                        package_version: "0.1.0".into(),
                    },
                })
                .unwrap();
            store.version_executable(&published.record.sha256)
        } else {
            let path = parent.path().join("unmanaged");
            fs::copy(source, &path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
            path
        };
        let config = NativeRuntimeConfig {
            root: root.clone(),
            artifact_root: parent.path().join("artifacts"),
            artifact_lock: parent.path().join("artifacts.lock"),
            mesh_data_dir: parent.path().join("mesh"),
            platform_config_dir: parent.path().join("platform"),
            credential_authority_root: parent.path().join("authority"),
            executable,
        };
        fs::write(
            root.join("__native-supervisor"),
            r#"
import os, socket, sys, time
root = sys.argv[sys.argv.index('--root') + 1]
path = os.environ['CW_TEST_SUPERVISOR_SOCKET']
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
os.chmod(path, 0o600)
s.listen(16)
s.settimeout(0.05)
with open(root + '/ready', 'w') as f: f.write(str(os.getpid()))
end = time.monotonic() + 60
while time.monotonic() < end:
    if os.path.exists(root + '/replace-executable'):
        os.execv('/usr/bin/sleep', ['/usr/bin/sleep', '60'])
    try: peer, _ = s.accept()
    except socket.timeout: continue
    with peer:
        peer.settimeout(0.2)
        try: data = peer.recv(4096)
        except socket.timeout: data = b''
        if data:
            with open(root + '/received', 'ab') as f: f.write(data)
"#,
        )
        .unwrap();
        crate::socket_dir::prepare(&config.root).unwrap();
        let mut command = Command::new(&config.executable);
        command
            .args(config.supervisor_argv().into_iter().skip(1))
            .args(extra)
            .env_clear()
            .env("CW_TEST_SUPERVISOR_SOCKET", config.supervisor_socket())
            .env("HOME", parent.path())
            .env("LC_ALL", "C")
            .current_dir(&root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = crate::spawn_written(|| command.spawn()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !root.join("ready").exists() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "synthetic peer exited before binding"
            );
            assert!(Instant::now() < deadline, "synthetic peer bind deadline");
            std::thread::sleep(Duration::from_millis(5));
        }
        Self {
            parent,
            child,
            config,
        }
    }

    fn request(&self) -> NativeRuntimeConfig {
        self.config
            .with_supervisor_executable(fs::canonicalize("/usr/bin/true").unwrap())
            .unwrap()
    }

    fn record(&self) -> PathBuf {
        self.config.executable.with_file_name("identity.json")
    }

    fn marker_request(&self) -> NativeRuntimeConfig {
        let path = self.parent.path().join("must-not-start");
        fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf forbidden > '{}'\n",
                self.parent.path().join("spawned").display()
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
        self.config.with_supervisor_executable(path).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        fn removable(path: &Path) {
            if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()) {
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
                if let Ok(entries) = fs::read_dir(path) {
                    for entry in entries.flatten() {
                        removable(&entry.path());
                    }
                }
            }
        }
        removable(self.parent.path());
    }
}

async fn pin(fixture: &Fixture) -> Arc<SupervisorPeerPin> {
    capture_supervisor_peer(
        &fixture.config.supervisor_socket(),
        Some(&fixture.request()),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn retained_peer_binds_real_birth_image_role_provenance_and_all_configuration_inputs() {
    let fixture = Fixture::start(true, &[]);
    let request = fixture.request();
    let pin = pin(&fixture).await;
    assert_eq!(pin.peer.pid(), fixture.child.id());
    assert_eq!(pin.peer, ProcessBirth::observe(fixture.child.id()).unwrap());
    assert!(
        pin.peer
            .is(&ProcessIdentity::capture(fixture.child.id()).unwrap())
    );
    assert_eq!(pin.peer.executable(), fixture.config.executable);
    assert_eq!(
        pin.configuration_digest(),
        Some(fixture.config.configuration_digest())
    );
    assert_ne!(
        pin.configuration_digest(),
        Some(request.configuration_digest())
    );
    assert_eq!(pin.argv, fixture.config.supervisor_argv());
    // Another version than the requested one: its provenance was admitted.
    assert_ne!(request.executable, fixture.config.executable);
    // SAFETY: inspect our retained owned descriptor without changing it.
    assert_ne!(
        unsafe { libc::fcntl(pin.pidfd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    let mut stream = supervisor_peer_connector(pin.clone())
        .oneshot("http://codewire-local-control".parse().unwrap())
        .await
        .unwrap()
        .into_inner();
    stream.write_all(b"accepted synthetic bytes").await.unwrap();
    drop(stream);
    let deadline = Instant::now() + Duration::from_secs(2);
    while fs::read(fixture.config.root.join("received"))
        .ok()
        .as_deref()
        != Some(b"accepted synthetic bytes")
    {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        fs::read(fixture.config.root.join("received")).unwrap(),
        b"accepted synthetic bytes"
    );
}

#[tokio::test]
async fn configured_peer_refuses_every_other_path_and_role_extension() {
    let mut fixture = Fixture::start(true, &[]);
    let identity = SocketIdentity::capture(&fixture.config.supervisor_socket()).unwrap();
    for field in 0..6 {
        let mut request = fixture.request();
        match field {
            0 => request.root = request.root.with_file_name("other-runtime"),
            1 => request.artifact_root = request.artifact_root.with_file_name("other-artifacts"),
            2 => request.artifact_lock = request.artifact_lock.with_file_name("other.lock"),
            3 => request.mesh_data_dir = request.mesh_data_dir.with_file_name("other-mesh"),
            4 => {
                request.platform_config_dir =
                    request.platform_config_dir.with_file_name("other-platform")
            }
            _ => {
                request.credential_authority_root = request
                    .credential_authority_root
                    .with_file_name("other-authority")
            }
        }
        assert!(
            capture_supervisor_peer(&fixture.config.supervisor_socket(), Some(&request))
                .await
                .is_err()
        );
        identity
            .revalidate(&fixture.config.supervisor_socket())
            .unwrap();
        assert!(fixture.child.try_wait().unwrap().is_none());
    }
    let extra = Fixture::start(true, &["--unadmitted"]);
    assert!(
        capture_supervisor_peer(&extra.config.supervisor_socket(), Some(&extra.request()))
            .await
            .is_err()
    );
}

/// Provenance is admitted once per process birth (#2549). A new admission
/// needs the store to retain the version; an admitted peer is re-observed by
/// its birth and file, which a rewritten executable no longer matches.
#[tokio::test]
async fn retained_peer_refuses_unmanaged_missing_and_rewritten_versions() {
    let unmanaged = Fixture::start(false, &[]);
    // A supervisor of this root's role whose executable no store holds (a
    // development build) is named, with its recovery, before its executable
    // is read (#3548).
    let refusal = match capture_supervisor_peer(
        &unmanaged.config.supervisor_socket(),
        Some(&unmanaged.request()),
    )
    .await
    {
        Err(crate::uds::UdsError::SupervisorPeerAdmission(refusal)) => refusal,
        other => panic!("an unmanaged peer was not refused as unverified: {other:?}"),
    };
    assert_eq!(
        refusal,
        crate::uds::SupervisorRefusal::Unverified {
            pid: unmanaged.child.id(),
            executable: unmanaged.config.executable.clone(),
        }
    );
    let recovery = refusal.recovery().unwrap();
    assert!(recovery.contains(&format!("kill {}", unmanaged.child.id())));
    assert!(recovery.contains(&format!(
        "`{} --local ls`",
        unmanaged.config.executable.display()
    )));
    assert!(refusal.to_string().contains(&recovery));
    assert!(!refusal.to_string().contains("identity changed"));
    let mut fixture = Fixture::start(true, &[]);
    let pin = pin(&fixture).await;
    let socket = fixture.config.supervisor_socket();
    let record = fixture.record();
    let original = fs::read(&record).unwrap();
    fs::set_permissions(record.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_file(&record).unwrap();
    fs::set_permissions(record.parent().unwrap(), fs::Permissions::from_mode(0o555)).unwrap();
    assert!(
        capture_supervisor_peer(&socket, Some(&fixture.request()))
            .await
            .is_err()
    );
    pin.revalidate(Instant::now() + ADMISSION_TIMEOUT).unwrap();
    fs::set_permissions(record.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&record, &original).unwrap();
    fs::set_permissions(&record, fs::Permissions::from_mode(0o444)).unwrap();
    fs::set_permissions(record.parent().unwrap(), fs::Permissions::from_mode(0o555)).unwrap();
    capture_supervisor_peer(&socket, Some(&fixture.request()))
        .await
        .unwrap();
    // Mode, size and links restored; only the change time records the write.
    std::thread::sleep(Duration::from_millis(20));
    let executable = &fixture.config.executable;
    fs::set_permissions(executable, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(executable, fs::Permissions::from_mode(0o555)).unwrap();
    assert!(pin.revalidate(Instant::now() + ADMISSION_TIMEOUT).is_err());
    assert!(fixture.child.try_wait().unwrap().is_none());
}

#[tokio::test]
async fn private_and_public_connector_clones_refuse_replacement_before_any_payload() {
    let mut fixture = Fixture::start(true, &[]);
    let pin = pin(&fixture).await;
    let socket = fixture.config.supervisor_socket();
    fs::remove_file(&socket).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    let replacement = super::super::path::set_socket_private(&socket).unwrap();
    for _ in 0..2 {
        assert!(
            supervisor_peer_connector(pin.clone())
                .oneshot("http://codewire-local-control".parse().unwrap())
                .await
                .is_err()
        );
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        replacement.revalidate(&socket).unwrap();
    }
    assert!(fixture.child.try_wait().unwrap().is_none());
}

/// A refused endpoint starts a replacement, but only a supervisor that takes
/// the lock may replace the socket. This replacement exits without binding,
/// so the client reports that and the original socket is left untouched.
#[tokio::test]
async fn dead_peer_starts_a_replacement_but_never_unlinks_the_socket_itself() {
    let mut fixture = Fixture::start(true, &[]);
    let pin = pin(&fixture).await;
    let socket = fixture.config.supervisor_socket();
    let identity = SocketIdentity::capture(&socket).unwrap();
    let request = fixture.marker_request();
    fixture.child.kill().unwrap();
    fixture.child.wait().unwrap();
    assert!(pin.revalidate(Instant::now() + ADMISSION_TIMEOUT).is_err());
    let error = NativeSupervisorClient::connect_or_start(&request)
        .await
        .err()
        .expect("a replacement that never binds cannot serve");
    assert!(
        matches!(&error, SupervisorError::EndpointNotReplaced(path) if *path == socket),
        "{error:?}"
    );
    assert!(fixture.parent.path().join("spawned").exists());
    identity.revalidate(&socket).unwrap();
}

#[tokio::test]
async fn deleted_live_image_refuses_reuse_without_stopping_or_spawning() {
    let mut fixture = Fixture::start(true, &[]);
    let pin = pin(&fixture).await;
    let request = fixture.marker_request();
    let socket = fixture.config.supervisor_socket();
    let identity = SocketIdentity::capture(&socket).unwrap();
    fs::set_permissions(
        fixture.config.executable.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::remove_file(&fixture.config.executable).unwrap();
    assert!(pin.revalidate(Instant::now() + ADMISSION_TIMEOUT).is_err());
    assert!(
        NativeSupervisorClient::connect_or_start(&request)
            .await
            .is_err()
    );
    assert!(fixture.child.try_wait().unwrap().is_none());
    assert!(!fixture.parent.path().join("spawned").exists());
    identity.revalidate(&socket).unwrap();
}

#[tokio::test]
async fn same_birth_exec_divergence_refuses_without_signalling_an_unrelated_process() {
    let mut fixture = Fixture::start(true, &[]);
    let pin = pin(&fixture).await;
    let mut sentinel = Sentinel(Command::new("/usr/bin/sleep").arg("30").spawn().unwrap());
    fs::write(
        fixture.config.root.join("replace-executable"),
        b"owned fixture",
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while fs::read_link(format!("/proc/{}/exe", fixture.child.id())).unwrap()
        == pin.peer.executable()
    {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(pin.revalidate(Instant::now() + ADMISSION_TIMEOUT).is_err());
    assert!(fixture.child.try_wait().unwrap().is_none());
    assert!(sentinel.0.try_wait().unwrap().is_none());
}

#[tokio::test]
async fn a_handoff_ends_only_the_admitted_supervisor_and_sees_it_exit() {
    use std::os::unix::process::ExitStatusExt as _;
    let mut fixture = Fixture::start(true, &[]);
    let pin = pin(&fixture).await;
    pin.require_role().unwrap();
    let watch = pin.watch_exit().unwrap();
    assert!(!watch.exited().unwrap());
    let ended = pin.terminate().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ended.exited().unwrap() {
        assert!(
            Instant::now() < deadline,
            "the ended supervisor did not exit"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(watch.exited().unwrap());
    assert_eq!(fixture.child.wait().unwrap().signal(), Some(libc::SIGTERM));
    // An exited supervisor is never signalled again; the socket it left goes
    // only while it is the one this pin admitted.
    assert!(pin.terminate().is_err());
    assert!(fixture.config.supervisor_socket().exists());
    pin.remove_stale_socket().unwrap();
    assert!(!fixture.config.supervisor_socket().exists());
}

#[tokio::test]
async fn a_peer_admitted_without_a_configuration_is_never_ended() {
    let mut fixture = Fixture::start(true, &[]);
    let unpinned = capture_supervisor_peer(&fixture.config.supervisor_socket(), None)
        .await
        .unwrap();
    assert!(matches!(unpinned.require_role(), Err(PeerError::Role)));
    assert!(matches!(unpinned.watch_exit(), Err(PeerError::Role)));
    assert!(matches!(unpinned.terminate(), Err(PeerError::Role)));
    std::thread::sleep(Duration::from_millis(100));
    assert!(fixture.child.try_wait().unwrap().is_none());
}
