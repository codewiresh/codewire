//! Synthetic transport/crypto/Store proof. None of these keys or executables
//! are product release assets, and no public origin or live provider is used.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use codewire_cw_release::identity::{ReleaseTarget, canonical_json};
use codewire_cw_release::release::{ChannelEnvelope, ChannelPointer, ObjectRef};
use codewire_cw_release::store::{DEFAULT_LOCK_TIMEOUT, Store};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use super::*;
use crate::build_record::tests as records;

const SYNTHETIC_RUSTC: &str = "rustc 1.93.0 (synthetic 2026-01-01)";

struct TestKey {
    directory: tempfile::TempDir,
    socket_directory: PathBuf,
    socket_identity: (u64, u64),
    agent: Child,
    fingerprint: String,
    public: Vec<u8>,
    fake_time: Option<Cell<u64>>,
}

impl TestKey {
    fn new(expired: bool) -> Self {
        let directory = tempfile::Builder::new()
            .prefix("cw-public-crypto-")
            .tempdir()
            .unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        // This GnuPG build derives non-default-home sockets under /run/user
        // even with an isolated HOME. Admit and create only its new hashed
        // directory; never use the owner's default socket or start a helper.
        let derived = Command::new("/usr/bin/gpgconf")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", directory.path())
            .args(["--homedir"])
            .arg(directory.path())
            .args(["--list-dirs", "agent-socket"])
            .output()
            .unwrap();
        assert!(derived.status.success());
        let socket_path = PathBuf::from(String::from_utf8(derived.stdout).unwrap().trim());
        let socket_directory = socket_path.parent().unwrap().to_owned();
        assert_eq!(socket_path.file_name().unwrap(), "S.gpg-agent");
        // Without /run/user/<uid> (a CI container) GnuPG keeps the socket in
        // the private homedir itself.
        if socket_directory != directory.path().canonicalize().unwrap() {
            assert!(
                socket_directory
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("d.")
            );
            let parent = fs::symlink_metadata(socket_directory.parent().unwrap()).unwrap();
            assert!(
                parent.is_dir()
                    && parent.uid() == unsafe { libc::geteuid() }
                    && parent.mode() & 0o022 == 0
            );
        }
        // gpgconf itself creates this derived empty directory on this build.
        // It is selected by the new random private homedir, never the default.
        let info = fs::symlink_metadata(&socket_directory).unwrap();
        assert!(
            info.is_dir()
                && info.uid() == unsafe { libc::geteuid() }
                && info.mode() & 0o7777 == 0o700
        );
        assert_eq!(fs::read_dir(&socket_directory).unwrap().count(), 0);
        let info = fs::symlink_metadata(&socket_directory).unwrap();
        let socket_identity = (info.dev(), info.ino());
        // --daemon forks even with --no-detach. Supervised socket activation
        // keeps the actual synthetic agent in the child that this fixture owns.
        let listener = UnixListener::bind(&socket_path).unwrap();
        let listener_fd = listener.as_raw_fd();
        #[cfg(target_os = "linux")]
        let parent = std::process::id();
        let diagnostics = File::create(directory.path().join("agent.log")).unwrap();
        let mut command = Command::new("/usr/bin/python3");
        command.env_clear().env("PATH","/usr/bin:/bin").env("HOME",directory.path())
            .env("LISTEN_FDS","1").env("LISTEN_FDNAMES","std")
            .args(["-c", "import os,sys; e=dict(os.environ); e['LISTEN_PID']=str(os.getpid()); os.execve('/usr/bin/gpg-agent',['gpg-agent','--no-options','--homedir',sys.argv[1],'--supervised','--disable-scdaemon'],e)"])
            .arg(directory.path()).stdin(Stdio::null()).stdout(Stdio::null()).stderr(diagnostics);
        unsafe {
            command.pre_exec(move || {
                #[cfg(target_os = "linux")]
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0
                    || libc::getppid() != parent as libc::pid_t
                {
                    return Err(std::io::Error::other("synthetic agent parent changed"));
                }
                if listener_fd != 3 && libc::dup2(listener_fd, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let agent = command.spawn().unwrap();
        let mut key = Self {
            directory,
            socket_directory,
            socket_identity,
            agent,
            fingerprint: String::new(),
            public: Vec::new(),
            // Faked from 2000-01-01. Every gpg process would restart a
            // ticking faked clock at the same instant, so a key created a
            // second into one run was "in the future" to the next on a loaded
            // host. Each run instead freezes its clock a minute after the last
            // run's, so every later signature is strictly newer.
            fake_time: expired.then_some(Cell::new(946_684_800)),
        };
        drop(listener);
        let deadline = Instant::now() + Duration::from_secs(5);
        #[cfg(target_os = "linux")]
        while fs::read_link(format!("/proc/{}/exe", key.agent.id()))
            .is_ok_and(|p| p != Path::new("/usr/bin/gpg-agent"))
        {
            assert!(
                key.agent.try_wait().unwrap().is_none(),
                "owned synthetic agent exited before ready: {}",
                fs::read_to_string(key.directory.path().join("agent.log")).unwrap()
            );
            assert!(
                Instant::now() < deadline,
                "owned synthetic agent readiness deadline"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        key.run(&[
            "--quick-generate-key",
            "CW Disposable Fixture <fixture@example.invalid>",
            "rsa3072",
            "sign",
            if expired { "1d" } else { "0" },
        ]);
        let listing = key.run(&["--with-colons", "--list-keys"]);
        key.fingerprint = String::from_utf8(listing)
            .unwrap()
            .lines()
            .find(|line| line.starts_with("fpr:"))
            .unwrap()
            .split(':')
            .nth(9)
            .unwrap()
            .to_owned();
        key.public = key.run(&["--armor", "--export", &key.fingerprint]);
        key
    }

    fn run(&self, arguments: &[&str]) -> Vec<u8> {
        let mut command = Command::new("/usr/bin/gpg");
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .args([
                "--batch",
                "--yes",
                "--no-options",
                "--no-autostart",
                "--disable-dirmngr",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--homedir",
            ])
            .arg(self.directory.path());
        if let Some(time) = &self.fake_time {
            command.args(["--faked-system-time", &format!("{}!", time.get())]);
            time.set(time.get() + 60);
        }
        let output = command
            .args(arguments)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "synthetic GPG fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stdout.len() <= 64 * 1024,
            "synthetic fixture output bound"
        );
        output.stdout
    }

    fn sign(&self, bytes: &[u8]) -> Vec<u8> {
        let path = self
            .directory
            .path()
            .join(format!("message-{}", uuid::Uuid::new_v4()));
        fs::write(&path, bytes).unwrap();
        self.run(&[
            "--armor",
            "--output",
            "-",
            "--detach-sign",
            path.to_str().unwrap(),
        ])
    }

    fn revoke(&mut self) {
        let revocation = fs::read_to_string(
            self.directory
                .path()
                .join("openpgp-revocs.d")
                .join(format!("{}.rev", self.fingerprint)),
        )
        .unwrap();
        let start = revocation
            .find(":-----BEGIN PGP PUBLIC KEY BLOCK-----")
            .unwrap();
        let path = self.directory.path().join("revocation.asc");
        fs::write(&path, &revocation.as_bytes()[start + 1..]).unwrap();
        self.run(&["--import", path.to_str().unwrap()]);
        self.public = self.run(&["--armor", "--export", &self.fingerprint]);
    }
}

impl Drop for TestKey {
    fn drop(&mut self) {
        let _ = self.agent.kill();
        self.agent
            .wait()
            .expect("reap exact owned synthetic agent before private-home deletion");
        let info = fs::symlink_metadata(&self.socket_directory).unwrap();
        assert_eq!((info.dev(), info.ino()), self.socket_identity);
        fs::remove_dir_all(&self.socket_directory).unwrap();
    }
}

fn verifier(key: &TestKey) -> ReleaseKey {
    ReleaseKey::import(&key.public, &key.fingerprint).unwrap()
}

// GnuPG signs and the built-in verifier admits, as a release does.
#[test]
fn actual_disposable_key_verifies_exact_bytes_and_rejects_tampering() {
    let key = TestKey::new(false);
    let signature = key.sign(b"canonical public release\n");
    let verifier = verifier(&key);
    verifier
        .verify(b"canonical public release\n", &signature)
        .unwrap();
    assert!(verifier.verify(b"changed release\n", &signature).is_err());
    assert!(
        verifier
            .verify(b"canonical public release\n", b"not armor")
            .is_err()
    );
}

#[test]
fn actual_compiled_public_key_import_is_bound_to_its_primary_pin() {
    ReleaseKey::import(TRUST_KEY, TRUST_FINGERPRINT).unwrap();
}

#[test]
fn actual_wrong_expired_revoked_and_subkey_keys_fail_closed() {
    let good = TestKey::new(false);
    let wrong = TestKey::new(false);
    let signature = good.sign(b"release\n");
    assert!(verifier(&wrong).verify(b"release\n", &signature).is_err());

    let expired = TestKey::new(true);
    assert!(ReleaseKey::import(&expired.public, &expired.fingerprint).is_err());

    let mut expired_signature = TestKey::new(true);
    expired_signature.run(&["--quick-set-expire", &expired_signature.fingerprint, "0"]);
    expired_signature.public =
        expired_signature.run(&["--armor", "--export", &expired_signature.fingerprint]);
    let data = expired_signature
        .directory
        .path()
        .join("expired-signature.data");
    fs::write(&data, b"release\n").unwrap();
    let signature = expired_signature.run(&[
        "--default-sig-expire",
        "1d",
        "--armor",
        "--output",
        "-",
        "--detach-sign",
        data.to_str().unwrap(),
    ]);
    assert!(
        verifier(&expired_signature)
            .verify(b"release\n", &signature)
            .is_err()
    );

    let mut revoked = TestKey::new(false);
    revoked.revoke();
    assert!(ReleaseKey::import(&revoked.public, &revoked.fingerprint).is_err());

    let mut subkey = TestKey::new(false);
    subkey.run(&[
        "--quick-add-key",
        &subkey.fingerprint,
        "rsa3072",
        "sign",
        "0",
    ]);
    subkey.public = subkey.run(&["--armor", "--export", &subkey.fingerprint]);
    assert!(ReleaseKey::import(&subkey.public, &subkey.fingerprint).is_err());
}

fn object(key: String, bytes: &[u8]) -> ObjectRef {
    ObjectRef {
        key,
        sha256: format!("{:x}", Sha256::digest(bytes)),
        size: bytes.len() as u64,
    }
}

fn asset(target: ReleaseTarget, version: &str) -> Vec<u8> {
    let mut bytes = vec![0_u8; 64];
    let platform = target.platform();
    match platform.os {
        codewire_cw_release::identity::Os::Linux => {
            bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
            bytes[16] = 3;
            bytes[18] = if platform.arch == codewire_cw_release::identity::Arch::X86_64 {
                62
            } else {
                183
            };
        }
        codewire_cw_release::identity::Os::Macos => {
            bytes[..4].copy_from_slice(&0xfeed_facf_u32.to_le_bytes());
            let cpu = if platform.arch == codewire_cw_release::identity::Arch::X86_64 {
                0x0100_0007_u32
            } else {
                0x0100_000c
            };
            bytes[4..8].copy_from_slice(&cpu.to_le_bytes());
            bytes[12..16].copy_from_slice(&2_u32.to_le_bytes());
        }
    }
    bytes.extend_from_slice(&records::framed(&records::json(
        version,
        target.as_str(),
        true,
    )));
    if target == ReleaseTarget::X86_64UnknownLinuxMusl {
        bytes.splice(64..64, [0_u8; 56]);
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64] = 1;
    }
    bytes
}

struct Distribution {
    key: TestKey,
    version: String,
    objects: BTreeMap<String, Vec<u8>>,
    manifest: Value,
    identity: CwPayloadIdentity,
}

impl Distribution {
    fn new(version: &str) -> Self {
        Self::with_key(version, TestKey::new(false), None)
    }

    fn with_key(version: &str, key: TestKey, host_payload: Option<Vec<u8>>) -> Self {
        let mut objects = BTreeMap::new();
        let mut entries = Vec::new();
        let mut targets = ReleaseTarget::ALL;
        targets.sort_by_key(|target| target.as_str());
        let mut selected = None;
        for target in targets {
            let payload = if target == records::host().release_target() {
                host_payload
                    .clone()
                    .unwrap_or_else(|| asset(target, version))
            } else {
                asset(target, version)
            };
            let digest = format!("{:x}", Sha256::digest(&payload));
            let identity = CwPayloadIdentity {
                schema_version: 2,
                protocol_version: 1,
                record_version: 1,
                package_version: version.into(),
                target: target.as_str().into(),
                source_revision: records::REVISION.into(),
                source_tree_sha256: records::TREE.into(),
                rustc: SYNTHETIC_RUSTC.into(),
                sha256: digest.clone(),
                size: payload.len() as u64,
            };
            let reference = object(format!("cw/v1/blobs/sha256/{digest}"), &payload);
            let mut entry = json!({"target":target.as_str(),"asset_name":format!("cw-{version}-{}",target.as_str()),"identity":identity,"executable":reference});
            if target == ReleaseTarget::X86_64UnknownLinuxMusl {
                entry["oci"] = json!({"index_sha256":"e".repeat(64),"manifest_sha256":"f".repeat(64),"archive":{"key":format!("cw/v1/blobs/sha256/{}","1".repeat(64)),"sha256":"1".repeat(64),"size":1000}});
                entry["runtime_pack"] = json!({"key":format!("cw/v1/blobs/sha256/{}","2".repeat(64)),"sha256":"2".repeat(64),"size":1000});
                entry["runtime_lock"] = json!({"key":format!("cw/v1/blobs/sha256/{}","3".repeat(64)),"sha256":"3".repeat(64),"size":100});
            }
            objects.insert(reference.key, payload);
            entries.push(entry);
            if target == records::host().release_target() {
                selected = Some(identity);
            }
        }
        let sums: String = entries
            .iter()
            .map(|entry| {
                format!(
                    "{}  {}\n",
                    entry["identity"]["sha256"].as_str().unwrap(),
                    entry["asset_name"].as_str().unwrap()
                )
            })
            .collect();
        let signature = key.sign(sums.as_bytes());
        let checksums = json!({"file":object(release_key(version,"SHA256SUMS"),sums.as_bytes()),"signature":object(release_key(version,"SHA256SUMS.asc"),&signature)});
        objects.insert(release_key(version, "SHA256SUMS"), sums.into_bytes());
        objects.insert(release_key(version, "SHA256SUMS.asc"), signature);
        let manifest = json!({"schema":"codewire.cw.release/v1","release_tag":version,"package_version":version,
            "tag_object_sha":"c".repeat(40),"source_revision":records::REVISION,"source_tree_sha256":records::TREE,
            "rustc":SYNTHETIC_RUSTC,"signing_fingerprint":key.fingerprint,"checksums":checksums,"targets":entries});
        let mut value = Self {
            key,
            version: version.into(),
            objects,
            manifest,
            identity: selected.unwrap(),
        };
        value.sign_manifest();
        value
    }

    fn sign_manifest(&mut self) {
        let bytes = canonical_json(&self.manifest).unwrap();
        let signature = self.key.sign(&bytes);
        let pointer = ChannelPointer {
            channel: "stable".into(),
            release_tag: self.version.clone(),
            release: object(release_key(&self.version, "release.json"), &bytes),
            release_signature: object(release_key(&self.version, "release.json.asc"), &signature),
        };
        let envelope = ChannelEnvelope {
            schema: "codewire.cw.channel/v1".into(),
            signature: String::from_utf8(self.key.sign(&pointer.signing_bytes().unwrap())).unwrap(),
            pointer,
        };
        self.objects
            .insert(release_key(&self.version, "release.json"), bytes);
        self.objects
            .insert(release_key(&self.version, "release.json.asc"), signature);
        self.objects.insert(
            "cw/v1/channels/stable.json".into(),
            canonical_json(&envelope).unwrap(),
        );
    }

    fn replace_host(&mut self, bytes: Vec<u8>) {
        let target = self.manifest["targets"]
            .as_array()
            .unwrap()
            .iter()
            .position(|e| e["target"] == self.identity.target)
            .unwrap();
        self.identity.sha256 = format!("{:x}", Sha256::digest(&bytes));
        self.identity.size = bytes.len() as u64;
        let reference = object(
            format!("cw/v1/blobs/sha256/{}", self.identity.sha256),
            &bytes,
        );
        self.manifest["targets"][target]["identity"] =
            serde_json::to_value(&self.identity).unwrap();
        self.manifest["targets"][target]["executable"] = serde_json::to_value(&reference).unwrap();
        self.objects.insert(reference.key, bytes);
        self.resign_checksums();
    }

    fn resign_checksums(&mut self) {
        let sums: String = self.manifest["targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                format!(
                    "{}  {}\n",
                    e["identity"]["sha256"].as_str().unwrap(),
                    e["asset_name"].as_str().unwrap()
                )
            })
            .collect();
        let signature = self.key.sign(sums.as_bytes());
        self.manifest["checksums"] = json!({"file":object(release_key(&self.version,"SHA256SUMS"),sums.as_bytes()),"signature":object(release_key(&self.version,"SHA256SUMS.asc"),&signature)});
        self.objects
            .insert(release_key(&self.version, "SHA256SUMS"), sums.into_bytes());
        self.objects
            .insert(release_key(&self.version, "SHA256SUMS.asc"), signature);
        self.sign_manifest();
    }

    async fn mount(&self, server: &MockServer) {
        for (key, body) in &self.objects {
            Mock::given(method("GET"))
                .and(path(format!("/{key}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
                .mount(server)
                .await;
        }
    }

    async fn fetch(&self, server: &MockServer, stable: bool) -> anyhow::Result<FetchedRelease> {
        let scratch = Arc::new(scratch::Scratch::new().unwrap());
        let http =
            http::FixedHttp::synthetic(&format!("{}/", server.uri()), Duration::from_secs(10))
                .unwrap();
        let selection = if stable {
            Selection::Stable
        } else {
            Selection::Version(self.version.clone())
        };
        controlled(
            fetch_inner(
                selection,
                records::host(),
                &http,
                scratch.clone(),
                &self.key.public,
                &self.key.fingerprint,
            ),
            scratch,
            Duration::from_secs(10),
            std::future::pending(),
        )
        .await
    }
}

#[tokio::test]
async fn full_signed_version_and_channel_streams_admit_without_execution() {
    let dist = Distribution::new("v1.2.3");
    let server = MockServer::start().await;
    dist.mount(&server).await;
    for stable in [false, true] {
        let release = dist.fetch(&server, stable).await.unwrap();
        assert_eq!(release.identity, dist.identity);
        assert_eq!(release._file.metadata().unwrap().mode() & 0o7777, 0o600);
        assert_eq!(release._file.metadata().unwrap().nlink(), 1);
        let bytes = fs::read(&release.candidate().executable).unwrap();
        assert_eq!(
            bytes,
            dist.objects[&format!("cw/v1/blobs/sha256/{}", dist.identity.sha256)]
        );
        let scratch_path = release.scratch.path().to_owned();
        release.cleanup().unwrap();
        assert!(!scratch_path.exists());
    }
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 11);
    for request in requests {
        assert_eq!(request.method.as_str(), "GET");
        assert!(!request.headers.contains_key("authorization"));
        assert!(!request.headers.contains_key("cookie"));
        assert!(request.url.query().is_none());
        assert!(request.body.is_empty());
    }
}

struct Managed {
    _dir: tempfile::TempDir,
    store: Store,
}

impl Managed {
    fn new(dist: &Distribution) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        fs::create_dir(&bin).unwrap();
        let store = Store::create(
            &dir.path().join("store"),
            &bin.join("cw"),
            DEFAULT_LOCK_TIMEOUT,
        )
        .unwrap();
        let executable = dir.path().join("initial-cw");
        fs::write(
            &executable,
            &dist.objects[&format!("cw/v1/blobs/sha256/{}", dist.identity.sha256)],
        )
        .unwrap();
        store
            .publish_and_select(
                &Candidate {
                    executable,
                    admission: Admission::Pinned {
                        identity: dist.identity.clone(),
                        sha256: dist.identity.sha256.clone(),
                    },
                },
                Some(0),
            )
            .unwrap();
        Self { _dir: dir, store }
    }

    fn unchanged(&self, before: &codewire_cw_release::store::Status) {
        assert_eq!(&self.store.status().unwrap(), before);
        let record = self
            .store
            .verify(before.current.as_deref().unwrap())
            .unwrap();
        assert_eq!(Some(record.sha256.as_str()), before.current.as_deref());
    }
}

impl Drop for Managed {
    fn drop(&mut self) {
        // Only the known synthetic fixture's immutable version directories.
        for entry in fs::read_dir(self.store.root().join("versions")).unwrap() {
            let path = entry.unwrap().path();
            if fs::symlink_metadata(&path).unwrap().is_dir() {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
    }
}

#[tokio::test]
async fn actual_signed_store_selection_cas_and_local_rollback_preserve_old_bytes() {
    let a = Distribution::new("v1.2.3");
    let managed = Managed::new(&a);
    let b = Distribution::new("v1.2.4");
    let server = MockServer::start().await;
    b.mount(&server).await;
    let before = managed.store.status().unwrap();
    let current = managed.store.verify(&a.identity.sha256).unwrap();
    let release = b.fetch(&server, true).await.unwrap();
    let old_path = managed
        .store
        .root()
        .join("versions")
        .join(&a.identity.sha256)
        .join("cw");
    let mut held = File::open(&old_path).unwrap();
    let old_metadata = held.metadata().unwrap();
    let (_published, selected) = crate::update::commit_public(
        &managed.store,
        before.generation,
        Some(&current),
        true,
        &release,
    )
    .unwrap();
    assert_eq!(selected.current, b.identity.sha256);
    release.cleanup().unwrap();
    assert_eq!(
        (
            held.metadata().unwrap().dev(),
            held.metadata().unwrap().ino()
        ),
        (old_metadata.dev(), old_metadata.ino())
    );
    let mut observed = Vec::new();
    std::io::Read::read_to_end(&mut held, &mut observed).unwrap();
    assert_eq!(
        observed,
        a.objects[&format!("cw/v1/blobs/sha256/{}", a.identity.sha256)]
    );
    let state = managed.store.status().unwrap();
    let rolled = managed
        .store
        .rollback(None, Some(state.generation))
        .unwrap();
    assert_eq!(rolled.current, a.identity.sha256);
    let fresh = managed.store.status().unwrap();
    let release = b.fetch(&server, true).await.unwrap();
    assert!(
        crate::update::commit_public(
            &managed.store,
            before.generation,
            Some(&current),
            true,
            &release
        )
        .is_err()
    );
    release.cleanup().unwrap();
    managed.unchanged(&fresh);
}

#[cfg(target_os = "linux")]
fn assert_dead_and_reaped(pidfd: &File, pid: i32) {
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&mut poll, 1, 0) }, 1);
    assert_ne!(poll.revents & libc::POLLIN, 0);
    assert_eq!(
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

/// Spawn an executable this test process just wrote or copied. A concurrent
/// test's fork child holds the write descriptor until its own exec, so the
/// kernel briefly refuses this exec with ETXTBSY; retry only that, bounded.
#[cfg(target_os = "linux")]
fn spawn_written<T>(mut spawn: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    for _ in 1..50 {
        match spawn() {
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(Duration::from_millis(20));
            }
            result => return result,
        }
    }
    spawn()
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn signed_public_selection_and_rollback_leave_a_running_owned_elf_untouched() {
    use std::os::fd::FromRawFd as _;
    let directory =
        tempfile::tempdir_in(std::env::current_exe().unwrap().parent().unwrap()).unwrap();
    let bin = directory.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let store = Store::create(
        &directory.path().join("store"),
        &bin.join("cw"),
        DEFAULT_LOCK_TIMEOUT,
    )
    .unwrap();
    // A is an ordinary installer component fixture, not a product release.
    // Only this already trusted local sleep ELF is executed, never fetched B.
    let (published, _) = store
        .publish_and_select(
            &Candidate {
                executable: PathBuf::from("/usr/bin/sleep"),
                admission: Admission::SelfInstall {
                    package_version: "v1.2.3".into(),
                },
            },
            Some(0),
        )
        .unwrap();
    let mut command = Command::new(store.version_executable(&published.sha256));
    command
        .env_clear()
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = spawn_written(|| command.spawn()).unwrap();
    struct Owned(Child);
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = self.0.kill();
            self.0.wait().unwrap();
        }
    }
    let mut owned = Owned(child);
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, owned.0.id(), 0) as i32 };
    assert!(fd >= 0);
    let pidfd = unsafe { File::from_raw_fd(fd) };
    let deadline = Instant::now() + Duration::from_secs(2);
    let expected_path = store.version_executable(&published.sha256);
    while fs::read_link(format!("/proc/{}/exe", owned.0.id()))
        .is_ok_and(|path| path != expected_path)
    {
        assert!(owned.0.try_wait().unwrap().is_none());
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let original = File::open(format!("/proc/{}/exe", owned.0.id())).unwrap();
    let metadata = original.metadata().unwrap();
    let before = store.status().unwrap();
    let current = store.verify(&published.sha256).unwrap();
    let b = Distribution::new("v1.2.4");
    let server = MockServer::start().await;
    b.mount(&server).await;
    let fetched = b.fetch(&server, true).await.unwrap();
    let (_published, selection) =
        crate::update::commit_public(&store, before.generation, Some(&current), true, &fetched)
            .unwrap();
    assert_eq!(selection.current, b.identity.sha256);
    fetched.cleanup().unwrap();
    let after = store.status().unwrap();
    assert_eq!(
        store
            .rollback(None, Some(after.generation))
            .unwrap()
            .current,
        current.sha256
    );
    assert!(owned.0.try_wait().unwrap().is_none());
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&mut poll, 1, 0) }, 0);
    assert_eq!(
        fs::read_link(format!("/proc/{}/exe", owned.0.id())).unwrap(),
        expected_path
    );
    let info = original.metadata().unwrap();
    assert_eq!(
        (info.dev(), info.ino(), info.len()),
        (metadata.dev(), metadata.ino(), metadata.len())
    );
    assert_eq!(store.verify(&current.sha256).unwrap(), current);
    let pid = owned.0.id() as i32;
    drop(owned);
    assert_dead_and_reaped(&pidfd, pid);
    // All owned actors are dead before only these two immutable directories
    // are made removable. No chmod occurs during the selection assertions.
    for digest in [&current.sha256, &b.identity.sha256] {
        fs::set_permissions(
            store.root().join("versions").join(digest),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
}

#[tokio::test]
async fn signed_stable_downgrade_and_equal_version_different_digest_have_no_store_effects() {
    let a = Distribution::new("v1.2.3");
    let managed = Managed::new(&a);
    let before = managed.store.status().unwrap();
    let current = managed.store.verify(&a.identity.sha256).unwrap();
    for offered in ["v1.2.2", "v1.2.3"] {
        let mut b = Distribution::new(offered);
        if offered == "v1.2.3" {
            let old_key = format!("cw/v1/blobs/sha256/{}", b.identity.sha256);
            let mut bytes = b.objects[&old_key].clone();
            bytes.extend_from_slice(b"distinct padding");
            b.replace_host(bytes);
        }
        let server = MockServer::start().await;
        b.mount(&server).await;
        let release = b.fetch(&server, true).await.unwrap();
        assert!(
            crate::update::commit_public(
                &managed.store,
                before.generation,
                Some(&current),
                true,
                &release
            )
            .is_err()
        );
        release.cleanup().unwrap();
        managed.unchanged(&before);
    }
}

async fn raw_response(
    response: Vec<u8>,
    timeout: Duration,
    delay: Duration,
) -> (http::FixedHttp, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        loop {
            let mut buffer = [0; 1024];
            let n = socket.read(&mut buffer).await.unwrap();
            assert!(n > 0 && request.len() + n <= 16 * 1024);
            request.extend_from_slice(&buffer[..n]);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(request.starts_with(b"GET /cw/v1/releases/v1.2.3/release.json HTTP/1.1\r\n"));
        tokio::time::sleep(delay).await;
        let _ = socket.write_all(&response).await;
    });
    (
        http::FixedHttp::synthetic(&format!("http://{address}/"), timeout).unwrap(),
        task,
    )
}

#[tokio::test]
async fn actual_wire_refuses_redirect_status_encoding_length_and_stream_overflow() {
    let key = "cw/v1/releases/v1.2.3/release.json";
    let cases:Vec<Vec<u8>>=vec![
        b"HTTP/1.1 302 Found\r\nLocation: https://example.invalid/\r\nContent-Length: 1\r\n\r\nx".to_vec(),
        b"HTTP/1.1 206 Partial Content\r\nContent-Length: 1\r\n\r\nx".to_vec(),
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 1\r\n\r\nx".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\n\r\nx".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 33\r\n\r\nx".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n21\r\n012345678901234567890123456789012\r\n0\r\n\r\n".to_vec(),
    ];
    for response in cases {
        let (http, task) = raw_response(response, Duration::from_secs(2), Duration::ZERO).await;
        assert!(http.read(key, 32, None).await.is_err());
        task.await.unwrap();
    }
    let (http, task) = raw_response(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n0\r\n\r\n".to_vec(),
        Duration::from_secs(2),
        Duration::ZERO,
    )
    .await;
    assert_eq!(http.read(key, 4, None).await.unwrap(), b"data");
    task.await.unwrap();
    let (http, task) = raw_response(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata".to_vec(),
        Duration::from_millis(40),
        Duration::from_millis(250),
    )
    .await;
    assert!(http.read(key, 4, None).await.is_err());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn executable_unknown_length_is_bounded_by_signed_size_and_exact_eof() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    for (body, size, accepted) in [
        (b"four".as_slice(), 4, true),
        (b"three".as_slice(), 4, false),
        (b"four".as_slice(), 5, false),
    ] {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 4096];
            assert!(stream.read(&mut buffer).await.unwrap() > 0);
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let http =
            http::FixedHttp::synthetic(&format!("http://{address}/"), Duration::from_secs(2))
                .unwrap();
        let reference = ObjectRef {
            key: format!("cw/v1/blobs/sha256/{}", "a".repeat(64)),
            sha256: "a".repeat(64),
            size,
        };
        let scratch = scratch::Scratch::new().unwrap();
        let mut file = scratch.create("cw").unwrap();
        assert_eq!(
            http.executable(&reference, &mut file).await.is_ok(),
            accepted
        );
        task.await.unwrap();
        scratch.cleanup().unwrap();
    }
}

#[tokio::test]
async fn closed_route_refusal_happens_before_any_connection() {
    let server = MockServer::start().await;
    let http =
        http::FixedHttp::synthetic(&format!("{}/", server.uri()), Duration::from_secs(1)).unwrap();
    for key in [
        "https://example.invalid/cw",
        "cw/v1/../release.json",
        "cw/v1/releases/v1.2.3/release.json?x=y",
        "cw/v1/channels/dev.json",
        "cw/v1/blobs/sha256/../../file",
        "cw/v1/releases/v1.2.3%2fother/release.json",
    ] {
        assert!(http.read(key, 32, None).await.is_err());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn proxy_child_uses_the_same_no_proxy_builder() {
    let Ok(origin) = std::env::var("CW_RELEASE_TEST_ORIGIN") else {
        return;
    };
    let http = http::FixedHttp::synthetic(&origin, Duration::from_secs(2)).unwrap();
    assert_eq!(
        http.read("cw/v1/releases/v1.2.3/release.json", 4, None)
            .await
            .unwrap(),
        b"data"
    );
}

#[tokio::test]
async fn ambient_proxy_is_ignored_in_an_isolated_real_child() {
    let target = MockServer::start().await;
    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cw/v1/releases/v1.2.3/release.json"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"data"))
        .mount(&target)
        .await;
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("CW_RELEASE_TEST_ORIGIN", format!("{}/", target.uri()))
        .env("HTTP_PROXY", proxy.uri())
        .env("HTTPS_PROXY", proxy.uri())
        .env("ALL_PROXY", proxy.uri())
        .env("http_proxy", proxy.uri())
        .env("https_proxy", proxy.uri())
        .env("all_proxy", proxy.uri())
        .args([
            "--exact",
            "public_fetch::tests::proxy_child_uses_the_same_no_proxy_builder",
            "--nocapture",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = tokio::process::Command::from(command);
    let result = tokio::time::timeout(Duration::from_secs(30), child.kill_on_drop(true).output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        String::from_utf8(result.stdout)
            .unwrap()
            .contains("1 passed")
    );
    assert_eq!(target.received_requests().await.unwrap().len(), 1);
    assert!(proxy.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn signed_and_unsigned_transport_failures_do_not_mutate_store() {
    let initial = Distribution::new("v1.2.3");
    let managed = Managed::new(&initial);
    let before = managed.store.status().unwrap();
    let mut offered = Distribution::new("v1.2.4");
    let original_objects = offered.objects.clone();
    let original_manifest = offered.manifest.clone();
    let original_identity = offered.identity.clone();
    for mode in 0..9 {
        offered.objects = original_objects.clone();
        offered.manifest = original_manifest.clone();
        offered.identity = original_identity.clone();
        match mode {
            0 => {
                offered
                    .objects
                    .get_mut(&release_key(&offered.version, "release.json"))
                    .unwrap()[0] = b' ';
            }
            1 => {
                offered.manifest["unknown"] = json!(true);
                offered.sign_manifest();
            }
            2 => {
                offered.manifest["targets"]
                    .as_array_mut()
                    .unwrap()
                    .swap(0, 1);
                offered.sign_manifest();
            }
            3 => {
                let mut bytes = asset(records::host().release_target(), "v9.9.9");
                bytes.push(b'x');
                offered.replace_host(bytes);
            }
            4 => {
                let mut bytes = asset(records::host().release_target(), &offered.version);
                bytes[0] = b'x';
                offered.replace_host(bytes);
            }
            5 => {
                offered
                    .objects
                    .get_mut(&format!("cw/v1/blobs/sha256/{}", offered.identity.sha256))
                    .unwrap()
                    .push(b'x');
            }
            6 => {
                offered
                    .objects
                    .get_mut(&format!("cw/v1/blobs/sha256/{}", offered.identity.sha256))
                    .unwrap()[70] ^= 1;
            }
            7 => {
                let bytes = b"a checksum list with missing assets\n";
                let signature = offered.key.sign(bytes);
                offered.manifest["checksums"] = json!({"file":object(release_key(&offered.version,"SHA256SUMS"),bytes),"signature":object(release_key(&offered.version,"SHA256SUMS.asc"),&signature)});
                offered
                    .objects
                    .insert(release_key(&offered.version, "SHA256SUMS"), bytes.to_vec());
                offered
                    .objects
                    .insert(release_key(&offered.version, "SHA256SUMS.asc"), signature);
                offered.sign_manifest();
            }
            _ => {
                let bytes = serde_json::to_vec_pretty(&offered.manifest).unwrap();
                let signature = offered.key.sign(&bytes);
                offered
                    .objects
                    .insert(release_key(&offered.version, "release.json"), bytes);
                offered
                    .objects
                    .insert(release_key(&offered.version, "release.json.asc"), signature);
            }
        }
        let server = MockServer::start().await;
        offered.mount(&server).await;
        assert!(offered.fetch(&server, false).await.is_err(), "mode {mode}");
        managed.unchanged(&before);
    }
}

#[tokio::test]
async fn total_deadline_and_cancellation_refuse_before_store_and_remove_known_scratch() {
    let initial = Distribution::new("v1.2.3");
    let managed = Managed::new(&initial);
    let before = managed.store.status().unwrap();
    let offered = Distribution::new("v1.2.4");
    for canceled in [false, true] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/{}",
                release_key(&offered.version, "release.json")
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(500))
                    .set_body_bytes(
                        offered.objects[&release_key(&offered.version, "release.json")].clone(),
                    ),
            )
            .mount(&server)
            .await;
        let scratch = Arc::new(scratch::Scratch::new().unwrap());
        let path = scratch.path().to_owned();
        let http =
            http::FixedHttp::synthetic(&format!("{}/", server.uri()), Duration::from_secs(2))
                .unwrap();
        let operation = fetch_inner(
            Selection::Version(offered.version.clone()),
            records::host(),
            &http,
            scratch.clone(),
            &offered.key.public,
            &offered.key.fingerprint,
        );
        let cancel = async {
            if canceled {
                tokio::time::sleep(Duration::from_millis(60)).await;
                Ok(())
            } else {
                std::future::pending().await
            }
        };
        let timeout = if canceled {
            Duration::from_secs(2)
        } else {
            Duration::from_millis(60)
        };
        let error = controlled(operation, scratch.clone(), timeout, cancel)
            .await
            .err()
            .expect("must refuse");
        assert!(
            error.to_string().contains(if canceled {
                "canceled"
            } else {
                "total deadline"
            }),
            "{error:#}"
        );
        assert!(!path.exists());
        managed.unchanged(&before);
    }
}

#[test]
fn changed_private_scratch_identity_is_retained_without_touching_replacement() {
    let parent = tempfile::tempdir().unwrap();
    let scratch = scratch::Scratch::new_in(parent.path()).unwrap();
    let path = scratch.path().to_owned();
    let original = parent.path().join("original");
    fs::rename(&path, &original).unwrap();
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(path.join("sentinel"), b"preserve").unwrap();
    assert!(scratch.cleanup().is_err());
    drop(scratch);
    assert_eq!(fs::read(path.join("sentinel")).unwrap(), b"preserve");
    assert!(original.exists());
}

#[test]
fn writable_parent_is_refused_before_any_scratch_or_download() {
    let parent = tempfile::tempdir().unwrap();
    for mode in [0o777, 0o775, 0o707] {
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            scratch::Scratch::new_in(parent.path()).is_err(),
            "mode {mode:o}"
        );
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }
    if unsafe { libc::geteuid() } != 0 {
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(scratch::Scratch::new_in(parent.path()).is_err());
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let scratch = scratch::Scratch::new_in(parent.path()).unwrap();
    scratch.create("cw").unwrap();
    scratch.cleanup().unwrap();
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[test]
fn replaced_ancestor_refuses_the_download_and_retains_unknown_cleanup() {
    let fixture = tempfile::tempdir().unwrap();
    let parent = fixture.path().join("parent");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let scratch = scratch::Scratch::new_in(&parent).unwrap();
    let leaf = scratch.path().file_name().unwrap().to_owned();
    let retained = fixture.path().join("retained-parent");
    fs::rename(&parent, &retained).unwrap();
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(parent.join("sentinel"), b"synthetic replacement").unwrap();
    // Same-user test deliberately changes the name. Production refuses the
    // contradiction before creating the downloaded executable.
    assert!(scratch.create("cw").is_err());
    assert!(!retained.join(&leaf).join("cw").exists());
    assert!(scratch.cleanup().is_err());
    drop(scratch);
    assert!(retained.join(leaf).is_dir());
    assert_eq!(
        fs::read(parent.join("sentinel")).unwrap(),
        b"synthetic replacement"
    );
}

#[test]
fn retained_ancestor_permissions_are_rechecked_before_the_download() {
    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let scratch = scratch::Scratch::new_in(parent.path()).unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(scratch.create("cw").is_err());
    assert!(!scratch.path().join("cw").exists());
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    scratch.check_paths().unwrap();
    scratch.cleanup().unwrap();
}

fn pinned(bytes: &[u8]) -> BlobRef {
    BlobRef {
        sha256: format!("{:x}", Sha256::digest(bytes)),
        size: bytes.len() as u64,
    }
}

async fn serve_blob(server: &MockServer, digest: &str, body: &[u8]) {
    Mock::given(method("GET"))
        .and(path(format!("/cw/v1/blobs/sha256/{digest}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
        .mount(server)
        .await;
}

async fn fetch_pinned(server: &MockServer, blobs: &[BlobRef]) -> anyhow::Result<FetchedRuntime> {
    let scratch = Arc::new(scratch::Scratch::new().unwrap());
    let http =
        http::FixedHttp::synthetic(&format!("{}/", server.uri()), Duration::from_secs(10)).unwrap();
    controlled(
        fetch_runtime_inner(blobs, &http, scratch.clone()),
        scratch,
        Duration::from_secs(10),
        std::future::pending(),
    )
    .await
}

#[tokio::test]
async fn pinned_runtime_blobs_stream_exactly_and_refuse_other_bytes() {
    let server = MockServer::start().await;
    let kernel = b"synthetic kernel".to_vec();
    let root = b"synthetic guest root".to_vec();
    serve_blob(&server, &pinned(&kernel).sha256, &kernel).await;
    serve_blob(&server, &pinned(&root).sha256, &root).await;

    // Each pinned blob is fetched once and read back from the held file.
    let fetched = fetch_pinned(&server, &[pinned(&kernel), pinned(&root), pinned(&kernel)])
        .await
        .unwrap();
    for bytes in [&kernel, &root] {
        let mut read = Vec::new();
        fetched
            .open(&pinned(bytes).sha256)
            .unwrap()
            .read_to_end(&mut read)
            .unwrap();
        assert_eq!(&read, bytes);
    }
    assert!(matches!(
        fetched.open(&"0".repeat(64)),
        Err(InstallError::MissingBlob { .. })
    ));
    fetched.cleanup().unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);

    // The origin's bytes must be exactly the pinned ones.
    let pinned_other = pinned(b"the bytes cw pins");
    serve_blob(&server, &pinned_other.sha256, b"the bytes cw pinz").await;
    let error = fetch_pinned(&server, &[pinned_other]).await.err().unwrap();
    assert!(format!("{error:#}").contains("pinned SHA-256"), "{error:#}");

    let short = pinned(b"a longer pinned object");
    serve_blob(&server, &short.sha256, b"a longer").await;
    assert!(fetch_pinned(&server, &[short]).await.is_err());

    let missing = pinned(b"never published");
    assert!(fetch_pinned(&server, &[missing]).await.is_err());

    let invalid = BlobRef {
        sha256: "not a digest".into(),
        size: 1,
    };
    assert!(fetch_pinned(&server, &[invalid]).await.is_err());
}
