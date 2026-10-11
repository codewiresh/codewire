//! Apple's OpenSSH tools behind the same owner on macOS, with a private
//! on-disk runtime instead of a Linux tmpfs. This crate forbids unsafe code,
//! so these tests create the FIFO with `/usr/bin/mkfifo` and leave descriptor
//! hygiene to the composer's hook, which the CLI tests separately.

use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use codewire_protected_store::ssh_material::{decode_protected_material, import_openssh};

use super::protocol::{SIGN_REQUEST, put_string};
use super::*;

fn mkfifo(path: &Path) -> std::io::Result<()> {
    let status = std::process::Command::new("/usr/bin/mkfifo")
        .args(["-m", "600"])
        .arg(path)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("mkfifo failed"))
    }
}

fn no_preparation(_: &mut Command) {}

struct Synthetic {
    _root: tempfile::TempDir,
    runtime: PathBuf,
    fixtures: PathBuf,
    askpass: PathBuf,
}

impl Synthetic {
    fn new() -> Self {
        // A short root keeps the agent socket under Darwin's 104-byte bound
        // whatever TMPDIR the test runner was given.
        let root = tempfile::Builder::new()
            .prefix("cw-ssh-")
            .tempdir_in("/private/tmp")
            .unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = root.path().join("runtime");
        let fixtures = root.path().join("fixtures");
        for path in [&runtime, &fixtures] {
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let askpass = root.path().join("askpass");
        std::fs::write(&askpass, ASKPASS_HELPER).unwrap();
        std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o500)).unwrap();
        Self {
            _root: root,
            runtime,
            fixtures,
            askpass,
        }
    }

    fn config(&self) -> Result<SshAgentConfig, SshAgentError> {
        SshAgentConfig::new(
            self.runtime.clone(),
            "/usr/bin/ssh-agent".into(),
            "/usr/bin/ssh-add".into(),
            self.askpass.clone(),
            DarwinProcessPrimitives {
                prepare_child: no_preparation,
                make_fifo: mkfifo,
            },
        )
    }

    fn owner(&self) -> SshAgentOwner {
        SshAgentOwner::new(self.config().unwrap())
    }

    async fn key(&self, algorithm: &str, passphrase: &str) -> Zeroizing<Vec<u8>> {
        let path = self.fixtures.join(format!("key-{}", uuid::Uuid::new_v4()));
        let mut command = Command::new("/usr/bin/ssh-keygen");
        command
            .env_clear()
            .env("HOME", &self.fixtures)
            .current_dir(&self.fixtures)
            .args([
                "-q",
                "-t",
                algorithm,
                "-C",
                "PRIVATE_COMMENT_CANARY",
                "-N",
                passphrase,
                "-f",
            ])
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        if algorithm == "rsa" {
            command.args(["-b", "2048"]);
        }
        assert!(command.status().await.unwrap().success());
        Zeroizing::new(std::fs::read(path).unwrap())
    }

    /// The one staging directory holds exactly the agent socket and FIFO.
    fn assert_staging_holds_only_socket_and_fifo(&self) {
        let entries = std::fs::read_dir(&self.runtime)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1, "one staging directory per agent");
        let staging = &entries[0];
        let name = staging.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with(".cw-") && name.len() == 36, "{name}");
        let mut kinds = std::fs::read_dir(staging)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let kind = entry.file_type().unwrap();
                let label = if kind.is_socket() {
                    "socket"
                } else if kind.is_fifo() {
                    "fifo"
                } else {
                    "other"
                };
                (entry.file_name().into_string().unwrap(), label)
            })
            .collect::<Vec<_>>();
        kinds.sort();
        assert_eq!(
            kinds,
            [
                ("a".to_owned(), "socket"),
                ("askpass.fifo".to_owned(), "fifo")
            ]
        );
    }

    fn assert_clean(&self) {
        assert_eq!(std::fs::read_dir(&self.runtime).unwrap().count(), 0);
    }
}

fn sign_request(identity: &SshPublicIdentity, flags: u32, data: &[u8]) -> Vec<u8> {
    let mut request = vec![SIGN_REQUEST];
    put_string(&mut request, identity.key_blob());
    put_string(&mut request, data);
    request.extend_from_slice(&flags.to_be_bytes());
    request
}

#[tokio::test]
async fn apple_openssh_signs_with_one_selected_key_and_stages_only_a_socket_and_fifo() {
    let synthetic = Synthetic::new();
    let owner = synthetic.owner();
    for (kind, passphrase) in [("ed25519", ""), ("rsa", "SYNTHETIC_RSA_PASSPHRASE")] {
        let agent = owner
            .start(
                synthetic.key(kind, passphrase).await,
                Some(Zeroizing::new(passphrase.as_bytes().to_vec())),
                Instant::now() + Duration::from_secs(30),
            )
            .unwrap()
            .ready()
            .await
            .unwrap();
        synthetic.assert_staging_holds_only_socket_and_fifo();
        let identity = agent.public_identity().clone();
        let response = agent.request(&[REQUEST_IDENTITIES]).await.unwrap();
        assert_eq!(
            SshPublicIdentity::from_agent_response(&response).unwrap(),
            identity
        );
        assert!(!String::from_utf8_lossy(&response).contains("PRIVATE_COMMENT_CANARY"));
        let flags: &[u32] = if kind == "rsa" { &[2, 4] } else { &[0] };
        for flags in flags {
            let request = sign_request(&identity, *flags, b"synthetic selected-key signing data");
            let response = agent.request(&request).await.unwrap();
            identity
                .validate_signature(
                    &response,
                    identity.admit_request(&request).unwrap().unwrap(),
                )
                .unwrap();
        }
        for operation in [17, 18, 19, 25, 27] {
            assert_eq!(
                agent.request(&[operation]).await,
                Err(SshAgentError::Denied)
            );
        }
        agent.cancel_and_drain().await.unwrap();
        synthetic.assert_clean();
    }
    owner.shutdown().await.unwrap();
    synthetic.assert_clean();
}

#[tokio::test]
async fn one_shot_signatures_drain_before_returning_and_wrong_passphrases_are_value_blind() {
    let synthetic = Synthetic::new();
    let owner = synthetic.owner();
    let raw = synthetic.key("ed25519", "SYNTHETIC_PASSPHRASE").await;
    let (_, protected) = import_openssh(
        raw.clone(),
        Some(Zeroizing::new(b"SYNTHETIC_PASSPHRASE".to_vec())),
    )
    .unwrap()
    .into_parts();
    let material = decode_protected_material(protected).unwrap();
    let request = codewire_daemon_proto::codewire::bridge::v1::CredentialSshSignRequest {
        public_key_blob: material.public_key().key_blob().to_vec(),
        data: b"synthetic one-operation SSH challenge".to_vec(),
        flags: 0,
    };
    let signature = sign_once(
        &owner,
        material,
        request,
        Instant::now() + Duration::from_secs(30),
        std::future::pending(),
    )
    .await
    .unwrap();
    assert!(!signature.is_empty());
    synthetic.assert_clean();
    assert_eq!(owner.capacity.available_permits(), MAX_AGENTS);

    let wrong = owner
        .start(
            raw,
            Some(Zeroizing::new(b"WRONG_PASSPHRASE_CANARY".to_vec())),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap()
        .ready()
        .await;
    let error = match wrong {
        Err(error) => error,
        Ok(_) => panic!("a wrong passphrase was admitted"),
    };
    assert!(!format!("{error:?} {error}").contains("CANARY"));
    owner.shutdown().await.unwrap();
    synthetic.assert_clean();
}

#[test]
fn the_runtime_must_be_a_private_directory() {
    let synthetic = Synthetic::new();
    assert!(synthetic.config().is_ok());
    std::fs::set_permissions(&synthetic.runtime, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        synthetic.config(),
        Err(SshAgentError::Configuration)
    ));
    std::fs::set_permissions(&synthetic.runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = synthetic.fixtures.join("runtime-link");
    std::os::unix::fs::symlink(&synthetic.runtime, &link).unwrap();
    assert!(
        SshAgentConfig::new(
            link,
            "/usr/bin/ssh-agent".into(),
            "/usr/bin/ssh-add".into(),
            synthetic.askpass.clone(),
            DarwinProcessPrimitives {
                prepare_child: no_preparation,
                make_fifo: mkfifo,
            },
        )
        .is_err()
    );
}

/// An agent killed from outside fails its operation, drains cleanly and
/// leaves the owner able to start the next agent.
#[tokio::test]
async fn an_externally_killed_agent_drains_and_the_owner_stays_healthy() {
    let synthetic = Synthetic::new();
    let owner = synthetic.owner();
    let key = synthetic.key("ed25519", "").await;
    let agent = owner
        .start(key.clone(), None, Instant::now() + Duration::from_secs(30))
        .unwrap()
        .ready()
        .await
        .unwrap();
    let killed = std::process::Command::new("/usr/bin/pkill")
        .args(["-9", "-f"])
        .arg(format!("ssh-agent -D -a {}", synthetic.runtime.display()))
        .status()
        .unwrap();
    assert!(killed.success(), "the agent was found and killed");
    let request = sign_request(agent.public_identity(), 0, b"after the agent died");
    assert!(agent.request(&request).await.is_err());
    agent.cancel_and_drain().await.unwrap();
    synthetic.assert_clean();
    let next = owner
        .start(key, None, Instant::now() + Duration::from_secs(30))
        .unwrap()
        .ready()
        .await
        .unwrap();
    let request = sign_request(next.public_identity(), 0, b"a fresh agent signs");
    assert!(next.request(&request).await.is_ok());
    next.cancel_and_drain().await.unwrap();
    owner.shutdown().await.unwrap();
    synthetic.assert_clean();
}

/// Agents killed at any phase of one-shot signing (start, import, signing)
/// fail only their own signature; every worker still drains cleanly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agents_killed_at_any_phase_never_latch_a_cleanup_failure() {
    let synthetic = Synthetic::new();
    let owner = synthetic.owner();
    let raw = synthetic.key("ed25519", "SYNTHETIC_KILL_PASSPHRASE").await;
    let stop = Arc::new(AtomicBool::new(false));
    let pattern = format!("ssh-agent -D -a {}", synthetic.runtime.display());
    let killer = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut kills = 0;
            while !stop.load(Ordering::Acquire) {
                let status = std::process::Command::new("/usr/bin/pkill")
                    .args(["-9", "-f", &pattern])
                    .status()
                    .unwrap();
                kills += usize::from(status.success());
                std::thread::sleep(std::time::Duration::from_millis(7));
            }
            kills
        })
    };
    let mut outcomes = std::collections::BTreeMap::<String, usize>::new();
    for _ in 0..12 {
        let (_, protected) = import_openssh(
            raw.clone(),
            Some(Zeroizing::new(b"SYNTHETIC_KILL_PASSPHRASE".to_vec())),
        )
        .unwrap()
        .into_parts();
        let material = decode_protected_material(protected).unwrap();
        let request = codewire_daemon_proto::codewire::bridge::v1::CredentialSshSignRequest {
            public_key_blob: material.public_key().key_blob().to_vec(),
            data: b"synthetic signing under agent kills".to_vec(),
            flags: 0,
        };
        let result = sign_once(
            &owner,
            material,
            request,
            Instant::now() + Duration::from_secs(4),
            std::future::pending(),
        )
        .await;
        *outcomes
            .entry(format!("{:?}", result.map(|_| ())))
            .or_default() += 1;
    }
    stop.store(true, Ordering::Release);
    let kills = killer.join().unwrap();
    assert!(kills > 0, "the killer found agents to kill");
    assert!(
        !outcomes.contains_key(&format!("{:?}", Err::<(), _>(SshAgentError::Cleanup))),
        "{outcomes:?}"
    );
    owner.shutdown().await.unwrap();
    synthetic.assert_clean();
}
