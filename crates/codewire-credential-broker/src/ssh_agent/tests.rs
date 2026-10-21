use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::protocol::{MAX_DATA_BYTES, SIGN_REQUEST, put_string};
use super::*;
use crate::process_test_support::isolated_process_fixture;

mod one_shot;
#[path = "../../../codewire-daemon/tests/support/proc_children.rs"]
mod proc_children;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    ImportSpawned,
    FifoConnected,
    Ready,
    SignDispatched,
    BeforeCleanup,
}

pub(super) struct PhaseProbe {
    phase: Phase,
    reached: Mutex<Option<oneshot::Sender<PhaseEvidence>>>,
    resume: tokio::sync::Notify,
    panic: bool,
}

struct ProcessEvidence {
    descriptor: OwnedFd,
    direct_child: bool,
}

struct PhaseEvidence {
    processes: Vec<ProcessEvidence>,
    home: PathBuf,
}

impl PhaseEvidence {
    async fn assert_dead(&self, require_reaped: bool) {
        for process in &self.processes {
            // A pidfd refers to this exact process even if its numeric PID is
            // subsequently reused. Readiness is the kernel's exit signal.
            let descriptor =
                tokio::io::unix::AsyncFd::new(process.descriptor.try_clone().unwrap()).unwrap();
            drop(
                tokio::time::timeout(Duration::from_secs(5), descriptor.readable())
                    .await
                    .expect("owned process did not exit")
                    .unwrap(),
            );
            if process.direct_child && require_reaped {
                let status = rustix::process::waitid(
                    WaitId::PidFd(process.descriptor.as_fd()),
                    WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
                );
                assert!(
                    matches!(status, Err(rustix::io::Errno::CHILD)),
                    "owned child was not reaped"
                );
            }
        }
    }
}

impl SshAgentConfig {
    pub(super) async fn reach_phase(
        &self,
        phase: Phase,
        home: &PrivateProviderHome,
        agent: Option<&GroupChild>,
        add: Option<&GroupChild>,
    ) {
        let Some(probe) = &self.phase_probe else {
            return;
        };
        if probe.phase != phase {
            return;
        }
        let mut processes = Vec::new();
        let mut observe = |pid: Pid, direct_child: bool| {
            processes.push(ProcessEvidence {
                descriptor: rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
                    .unwrap(),
                direct_child,
            });
        };
        for child in [agent, add].into_iter().flatten() {
            if let Some(pid) = child.pid {
                observe(pid, true);
            }
        }
        if phase == Phase::FifoConnected {
            // Only the explicit synthetic ssh-add's own children are inspected.
            // The connected FIFO barrier keeps askpass/cat alive here.
            let pid = add.and_then(|child| child.pid).unwrap().as_raw_pid();
            let children = proc_children::child_pids(u32::try_from(pid).unwrap()).unwrap();
            assert_eq!(
                children.len(),
                1,
                "expected exactly one owned askpass consumer"
            );
            for child in children {
                observe(Pid::from_raw(i32::try_from(child).unwrap()).unwrap(), false);
            }
        }
        let reached = probe
            .reached
            .lock()
            .unwrap()
            .take()
            .expect("phase reached twice");
        assert!(
            reached
                .send(PhaseEvidence {
                    processes,
                    home: home.path().to_owned()
                })
                .is_ok()
        );
        probe.resume.notified().await;
        assert!(!probe.panic, "synthetic SSH worker panic");
    }
}

async fn phase_reached(receiver: oneshot::Receiver<PhaseEvidence>) -> PhaseEvidence {
    tokio::time::timeout(Duration::from_secs(10), receiver)
        .await
        .expect("worker did not reach selected phase")
        .unwrap()
}

fn identity_response(blob: &[u8], comment: &[u8]) -> Vec<u8> {
    let mut response = vec![12];
    response.extend_from_slice(&1_u32.to_be_bytes());
    put_string(&mut response, blob);
    put_string(&mut response, comment);
    response
}

fn ed25519_identity() -> SshPublicIdentity {
    let mut blob = Vec::new();
    put_string(&mut blob, b"ssh-ed25519");
    put_string(&mut blob, &[7; 32]);
    SshPublicIdentity::from_agent_response(&identity_response(&blob, b"PRIVATE_COMMENT_CANARY"))
        .unwrap()
}

fn rsa_identity() -> SshPublicIdentity {
    let mut blob = Vec::new();
    put_string(&mut blob, b"ssh-rsa");
    put_string(&mut blob, &[1, 0, 1]);
    let mut modulus = vec![0; 257];
    modulus[1] = 0x80;
    modulus[256] = 1;
    put_string(&mut blob, &modulus);
    SshPublicIdentity::from_agent_response(&identity_response(&blob, b"discard")).unwrap()
}

fn sign_request(identity: &SshPublicIdentity, flags: u32, data: &[u8]) -> Vec<u8> {
    let mut request = vec![SIGN_REQUEST];
    put_string(&mut request, identity.key_blob());
    put_string(&mut request, data);
    request.extend_from_slice(&flags.to_be_bytes());
    request
}

fn signature_response(algorithm: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut signature = Vec::new();
    put_string(&mut signature, algorithm);
    put_string(&mut signature, bytes);
    let mut response = vec![14];
    put_string(&mut response, &signature);
    response
}

#[test]
fn protocol_offers_one_identity_and_discards_arbitrary_comment() {
    let identity = ed25519_identity();
    assert_eq!(identity.algorithm(), SshKeyAlgorithm::Ed25519);
    let response = identity.identities_response();
    assert!(!String::from_utf8_lossy(&response).contains("CANARY"));
    assert_eq!(
        SshPublicIdentity::from_agent_response(&response).unwrap(),
        identity
    );
    assert_eq!(identity.admit_request(&[11]), Ok(None));
    assert!(identity.admit_request(&[11, 0]).is_err());
    let mut extra = identity_response(identity.key_blob(), b"");
    extra[4] = 2;
    assert!(SshPublicIdentity::from_agent_response(&extra).is_err());
}

#[test]
fn protocol_denies_all_mutations_extensions_and_unknown_messages() {
    let identity = ed25519_identity();
    for message in 0..=u8::MAX {
        if message == 11 || message == 13 {
            continue;
        }
        assert_eq!(
            identity.admit_request(&[message]),
            Err(SshAgentError::Denied),
            "message {message}"
        );
    }
}

#[test]
fn protocol_requires_exact_key_and_only_supported_signature_flags() {
    let identity = ed25519_identity();
    assert_eq!(
        identity.admit_request(&sign_request(&identity, 0, b"data")),
        Ok(Some(b"ssh-ed25519".as_slice()))
    );
    for flags in [1, 2, 4, 6, u32::MAX] {
        assert!(
            identity
                .admit_request(&sign_request(&identity, flags, b"data"))
                .is_err()
        );
    }
    let rsa = rsa_identity();
    assert_eq!(rsa.algorithm(), SshKeyAlgorithm::Rsa { bits: 2048 });
    for (flags, algorithm) in [(2, b"rsa-sha2-256"), (4, b"rsa-sha2-512")] {
        assert_eq!(
            rsa.admit_request(&sign_request(&rsa, flags, b"data")),
            Ok(Some(algorithm.as_slice()))
        );
    }
    for flags in [0, 1, 3, 6, u32::MAX] {
        assert!(
            rsa.admit_request(&sign_request(&rsa, flags, b"data"))
                .is_err(),
            "flags {flags}"
        );
    }
    assert!(
        identity
            .admit_request(&sign_request(&rsa, 4, b"data"))
            .is_err()
    );
}

#[test]
fn protocol_checks_truncation_trailing_bytes_and_bounds() {
    let identity = ed25519_identity();
    let valid = sign_request(&identity, 0, b"data");
    for length in 0..valid.len() {
        assert!(identity.admit_request(&valid[..length]).is_err());
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(identity.admit_request(&trailing).is_err());
    assert!(
        identity
            .admit_request(&sign_request(&identity, 0, &[]))
            .is_err()
    );
    assert!(
        identity
            .admit_request(&sign_request(&identity, 0, &vec![1; MAX_DATA_BYTES]))
            .is_ok()
    );
    assert!(
        identity
            .admit_request(&sign_request(&identity, 0, &vec![1; MAX_DATA_BYTES + 1]))
            .is_err()
    );
    let mut overflow = valid;
    overflow[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(identity.admit_request(&overflow).is_err());
}

#[test]
fn protocol_rejects_wrong_or_malformed_signature_responses() {
    let identity = ed25519_identity();
    let response = signature_response(b"ssh-ed25519", &[1; 64]);
    identity
        .validate_signature(&response, b"ssh-ed25519")
        .unwrap();
    for length in 0..response.len() {
        assert!(
            identity
                .validate_signature(&response[..length], b"ssh-ed25519")
                .is_err()
        );
    }
    assert!(
        identity
            .validate_signature(&signature_response(b"ssh-rsa", &[1; 64]), b"ssh-ed25519")
            .is_err()
    );
    assert!(
        identity
            .validate_signature(
                &signature_response(b"ssh-ed25519", &[1; 63]),
                b"ssh-ed25519"
            )
            .is_err()
    );
    let rsa = rsa_identity();
    assert!(
        rsa.validate_signature(&signature_response(b"ssh-rsa", &[1; 256]), b"rsa-sha2-512")
            .is_err()
    );
}

#[test]
fn protocol_rejects_unsupported_public_key_forms() {
    for algorithm in [
        b"ecdsa-sha2-nistp256".as_slice(),
        b"ssh-ed25519-cert-v01@openssh.com",
        b"sk-ssh-ed25519@openssh.com",
    ] {
        let mut blob = Vec::new();
        put_string(&mut blob, algorithm);
        put_string(&mut blob, &[1; 32]);
        assert!(SshPublicIdentity::from_agent_response(&identity_response(&blob, b"")).is_err());
    }
}

#[tokio::test]
async fn framing_rejects_oversized_empty_and_truncated_frames_before_allocation() {
    for header in [0_u32, (MAX_FRAME_BYTES + 1) as u32, u32::MAX] {
        let mut input = header.to_be_bytes().as_slice().to_vec();
        assert!(read_frame(&mut input.as_slice()).await.is_err());
        input.zeroize();
    }
    for frame in [&[0, 0][..], &[0, 0, 0, 2, 11][..]] {
        let mut input = frame;
        assert!(read_frame(&mut input).await.is_err());
    }
    assert!(read_frame(&mut &b""[..]).await.unwrap().is_none());
}

#[tokio::test]
async fn framing_accepts_split_headers_and_bodies() {
    let (mut writer, mut reader) = tokio::io::duplex(1);
    let task = tokio::spawn(async move {
        for byte in [0, 0, 0, 1, 11] {
            writer.write_all(&[byte]).await.unwrap();
        }
    });
    assert_eq!(&**read_frame(&mut reader).await.unwrap().unwrap(), &[11]);
    task.await.unwrap();
}

struct Synthetic {
    _root: tempfile::TempDir,
    runtime: PathBuf,
    fixtures: PathBuf,
}

impl Synthetic {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("cw-ssh-test-")
            .tempdir_in("/dev/shm")
            .expect("SSH synthetic tests require tmpfs");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = root.path().join("runtime");
        let fixtures = root.path().join("fixtures");
        for path in [&runtime, &fixtures] {
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            _root: root,
            runtime,
            fixtures,
        }
    }
    fn owner(&self) -> SshAgentOwner {
        SshAgentOwner::new(
            SshAgentConfig::new(
                self.runtime.clone(),
                "/usr/bin/ssh-agent".into(),
                "/usr/bin/ssh-add".into(),
                Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ssh_agent/askpass.sh"),
            )
            .unwrap(),
        )
    }
    fn owner_at(
        &self,
        phase: Phase,
        panic: bool,
    ) -> (
        SshAgentOwner,
        Arc<PhaseProbe>,
        oneshot::Receiver<PhaseEvidence>,
    ) {
        let (sender, receiver) = oneshot::channel();
        let probe = Arc::new(PhaseProbe {
            phase,
            reached: Mutex::new(Some(sender)),
            resume: tokio::sync::Notify::new(),
            panic,
        });
        let mut owner = self.owner();
        Arc::get_mut(&mut owner.config).unwrap().phase_probe = Some(probe.clone());
        (owner, probe, receiver)
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
    fn assert_clean(&self) {
        assert_eq!(std::fs::read_dir(&self.runtime).unwrap().count(), 0);
    }
}

#[tokio::test]
async fn openssh_selected_ed25519_and_rsa_sign_without_ambient_agent_or_key_reads() {
    isolated_process_fixture(
        "ssh_agent::tests::openssh_selected_ed25519_and_rsa_sign_without_ambient_agent_or_key_reads",
        async {
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
                let identity = agent.public_identity();
                let response = agent.request(&[11]).await.unwrap();
                assert_eq!(
                    SshPublicIdentity::from_agent_response(&response).unwrap(),
                    *identity
                );
                assert!(!String::from_utf8_lossy(&response).contains("PRIVATE_COMMENT_CANARY"));
                let flags: &[u32] = if kind == "rsa" { &[2, 4] } else { &[0] };
                for flags in flags {
                    let request = sign_request(identity, *flags, b"synthetic selected-key signing data");
                    let response = agent.request(&request).await.unwrap();
                    identity
                        .validate_signature(
                            &response,
                            identity.admit_request(&request).unwrap().unwrap(),
                        )
                        .unwrap();
                }
                for operation in [17, 18, 19, 20, 21, 22, 23, 25, 26, 27] {
                    assert_eq!(
                        agent.request(&[operation]).await,
                        Err(SshAgentError::Denied)
                    );
                }
                assert!(agent.request(&[11]).await.is_ok());
            }
            owner.shutdown().await.unwrap();
            owner.shutdown().await.unwrap();
            synthetic.assert_clean();
        },
    )
    .await;
}

#[tokio::test]
async fn openssh_encrypted_ed25519_uses_single_private_fifo_and_value_blind_errors() {
    isolated_process_fixture(
        "ssh_agent::tests::openssh_encrypted_ed25519_uses_single_private_fifo_and_value_blind_errors",
        async {
            let synthetic = Synthetic::new();
            let owner = synthetic.owner();
            let key = synthetic.key("ed25519", "SYNTHETIC_PASSPHRASE").await;
            let agent = owner
                .start(
                    key.clone(),
                    Some(Zeroizing::new(b"SYNTHETIC_PASSPHRASE".to_vec())),
                    Instant::now() + Duration::from_secs(30),
                )
                .unwrap()
                .ready()
                .await
                .unwrap();
            assert!(
                agent
                    .request(&sign_request(agent.public_identity(), 0, b"data"))
                    .await
                    .is_ok()
            );
            let bad = owner
                .start(
                    key,
                    Some(Zeroizing::new(b"WRONG_PASSPHRASE_CANARY".to_vec())),
                    Instant::now() + Duration::from_secs(2),
                )
                .unwrap()
                .ready()
                .await;
            let error = match bad {
                Err(error) => error,
                Ok(_) => panic!("wrong passphrase admitted"),
            };
            assert!(!format!("{error:?} {error}").contains("CANARY"));
            drop(agent);
            owner.shutdown().await.unwrap();
            synthetic.assert_clean();
        },
    )
    .await;
}

#[tokio::test]
async fn dropped_pending_start_and_ready_handles_are_owned_until_shutdown() {
    isolated_process_fixture(
        "ssh_agent::tests::dropped_pending_start_and_ready_handles_are_owned_until_shutdown",
        async {
            let synthetic = Synthetic::new();
            let key = synthetic.key("ed25519", "SYNTHETIC_PASSPHRASE").await;
            for phase in [Phase::ImportSpawned, Phase::FifoConnected, Phase::Ready] {
                let (owner, probe, reached) = synthetic.owner_at(phase, false);
                let pending = owner
                    .start(
                        key.clone(),
                        Some(Zeroizing::new(b"SYNTHETIC_PASSPHRASE".to_vec())),
                        Instant::now() + Duration::from_secs(30),
                    )
                    .unwrap();
                let drain = pending.drain_handle();
                let waiter = tokio::spawn(pending.ready());
                let evidence = phase_reached(reached).await;
                assert!(evidence.home.is_dir());
                match phase {
                    Phase::Ready => {
                        probe.resume.notify_one();
                        let agent = waiter.await.unwrap().unwrap();
                        drop(agent);
                    }
                    _ => {
                        waiter.abort();
                        match waiter.await {
                            Err(error) => assert!(error.is_cancelled()),
                            Ok(_) => panic!("aborted startup waiter completed"),
                        }
                    }
                }
                drain.cancel_and_drain().await.unwrap();
                drain.cancel_and_drain().await.unwrap();
                owner.shutdown().await.unwrap();
                evidence.assert_dead(true).await;
                assert!(!evidence.home.exists());
                synthetic.assert_clean();
            }
        },
    )
    .await;
}

#[tokio::test]
async fn one_agent_drain_cancels_signing_without_stopping_an_unrelated_agent() {
    let synthetic = Synthetic::new();
    let (owner, _probe, reached) = synthetic.owner_at(Phase::SignDispatched, false);
    let first = Arc::new(
        owner
            .start(
                synthetic.key("ed25519", "").await,
                None,
                Instant::now() + Duration::from_secs(30),
            )
            .unwrap()
            .ready()
            .await
            .unwrap(),
    );
    let second = owner
        .start(
            synthetic.key("ed25519", "").await,
            None,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap()
        .ready()
        .await
        .unwrap();
    assert_eq!(owner.capacity.available_permits(), MAX_AGENTS - 2);
    assert_eq!(std::fs::read_dir(&synthetic.runtime).unwrap().count(), 2);

    let first_drain = first.drain_handle();
    let signing_agent = first.clone();
    let signing = tokio::spawn(async move {
        let request = sign_request(
            signing_agent.public_identity(),
            0,
            b"synthetic per-agent signing cancellation",
        );
        signing_agent.request(&request).await
    });
    let evidence = phase_reached(reached).await;
    assert_eq!(evidence.processes.len(), 1);
    first_drain.cancel_and_drain().await.unwrap();
    assert_eq!(signing.await.unwrap(), Err(SshAgentError::Cancelled));
    evidence.assert_dead(true).await;
    assert!(!evidence.home.exists());
    assert_eq!(owner.capacity.available_permits(), MAX_AGENTS - 1);
    assert_eq!(std::fs::read_dir(&synthetic.runtime).unwrap().count(), 1);
    assert!(second.request(&[11]).await.is_ok());
    first_drain.cancel_and_drain().await.unwrap();

    second.cancel_and_drain().await.unwrap();
    second.cancel_and_drain().await.unwrap();
    assert_eq!(second.request(&[11]).await, Err(SshAgentError::Cancelled));
    assert_eq!(owner.capacity.available_permits(), MAX_AGENTS);
    owner.shutdown().await.unwrap();
    owner.shutdown().await.unwrap();
    drop(first);
    synthetic.assert_clean();
}

#[tokio::test]
async fn shutdown_during_dispatched_signing_drains_the_exact_agent() {
    let synthetic = Synthetic::new();
    let (owner, _probe, reached) = synthetic.owner_at(Phase::SignDispatched, false);
    let agent = Arc::new(
        owner
            .start(
                synthetic.key("ed25519", "").await,
                None,
                Instant::now() + Duration::from_secs(30),
            )
            .unwrap()
            .ready()
            .await
            .unwrap(),
    );
    let request = sign_request(
        agent.public_identity(),
        0,
        b"synthetic signing cancellation",
    );
    let request_agent = agent.clone();
    let signing = tokio::spawn(async move { request_agent.request(&request).await });
    let evidence = phase_reached(reached).await;
    assert_eq!(evidence.processes.len(), 1);
    assert!(evidence.home.is_dir());
    owner.shutdown().await.unwrap();
    assert!(signing.await.unwrap().is_err());
    evidence.assert_dead(true).await;
    assert!(!evidence.home.exists());
    drop(agent);
    synthetic.assert_clean();
}

#[tokio::test]
async fn worker_panic_is_latched_and_owned_children_are_drained_before_cleanup() {
    isolated_process_fixture(
        "ssh_agent::tests::worker_panic_is_latched_and_owned_children_are_drained_before_cleanup",
        async {
            let synthetic = Synthetic::new();
            let (owner, probe, reached) = synthetic.owner_at(Phase::FifoConnected, true);
            let pending = owner
                .start(
                    synthetic.key("ed25519", "SYNTHETIC_PASSPHRASE").await,
                    Some(Zeroizing::new(b"SYNTHETIC_PASSPHRASE".to_vec())),
                    Instant::now() + Duration::from_secs(30),
                )
                .unwrap();
            let drain = pending.drain_handle();
            let waiter = tokio::spawn(pending.ready());
            let evidence = phase_reached(reached).await;
            assert_eq!(
                evidence.processes.len(),
                3,
                "agent, add and askpass must be owned"
            );
            assert!(evidence.home.is_dir());
            probe.resume.notify_one();
            assert!(waiter.await.unwrap().is_err());
            assert_eq!(drain.cancel_and_drain().await, Err(SshAgentError::Cleanup));
            assert_eq!(drain.cancel_and_drain().await, Err(SshAgentError::Cleanup));
            assert_eq!(owner.shutdown().await, Err(SshAgentError::Cleanup));
            assert_eq!(owner.shutdown().await, Err(SshAgentError::Cleanup));
            evidence.assert_dead(true).await;
            assert!(!evidence.home.exists());
            synthetic.assert_clean();
        },
    )
    .await;
}

#[tokio::test]
async fn panic_during_cleanup_is_observed_and_retains_unproven_staging() {
    let synthetic = Synthetic::new();
    let (owner, probe, reached) = synthetic.owner_at(Phase::BeforeCleanup, true);
    let agent = owner
        .start(
            synthetic.key("ed25519", "").await,
            None,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap()
        .ready()
        .await
        .unwrap();
    let drain = agent.drain_handle();
    drop(agent);
    let evidence = phase_reached(reached).await;
    probe.resume.notify_one();
    assert_eq!(drain.cancel_and_drain().await, Err(SshAgentError::Cleanup));
    assert_eq!(drain.cancel_and_drain().await, Err(SshAgentError::Cleanup));
    assert_eq!(owner.shutdown().await, Err(SshAgentError::Cleanup));
    assert_eq!(owner.shutdown().await, Err(SshAgentError::Cleanup));
    evidence.assert_dead(false).await;
    assert!(evidence.home.is_dir(), "unproven staging must be retained");
    // Synthetic fixture cleanup occurs only after exact process-death evidence.
}

#[tokio::test]
async fn abandoned_per_agent_drain_wait_does_not_steal_cleanup_completion() {
    let synthetic = Synthetic::new();
    let (owner, probe, reached) = synthetic.owner_at(Phase::BeforeCleanup, false);
    let agent = owner
        .start(
            synthetic.key("ed25519", "").await,
            None,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap()
        .ready()
        .await
        .unwrap();
    let drain = agent.drain_handle();
    let abandoned_drain = drain.clone();
    let waiter = tokio::spawn(async move { abandoned_drain.cancel_and_drain().await });
    let evidence = phase_reached(reached).await;
    assert!(evidence.home.is_dir());
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    probe.resume.notify_one();
    drain.cancel_and_drain().await.unwrap();
    drain.cancel_and_drain().await.unwrap();
    evidence.assert_dead(true).await;
    assert!(!evidence.home.exists());
    assert_eq!(agent.request(&[11]).await, Err(SshAgentError::Cancelled));
    owner.shutdown().await.unwrap();
    synthetic.assert_clean();
}

#[tokio::test]
async fn shutdown_cancels_ready_agent_and_rejects_new_workers() {
    let synthetic = Synthetic::new();
    let owner = synthetic.owner();
    let key = synthetic.key("ed25519", "").await;
    let agent = owner
        .start(key.clone(), None, Instant::now() + Duration::from_secs(30))
        .unwrap()
        .ready()
        .await
        .unwrap();
    owner.shutdown().await.unwrap();
    assert_eq!(agent.request(&[11]).await, Err(SshAgentError::Cancelled));
    assert!(
        owner
            .start(key, None, Instant::now() + Duration::from_secs(30))
            .is_err()
    );
    synthetic.assert_clean();
}

#[tokio::test]
async fn bridge_rechecks_authority_before_releasing_even_a_valid_signature() {
    let synthetic = Synthetic::new();
    let owner = synthetic.owner();
    let agent = owner
        .start(
            synthetic.key("ed25519", "").await,
            None,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap()
        .ready()
        .await
        .unwrap();
    let request = sign_request(agent.public_identity(), 0, b"data");
    let (mut client, server) = tokio::io::duplex(MAX_FRAME_BYTES);
    let calls = AtomicUsize::new(0);
    let serving = agent.serve_connection(server, CancellationToken::new(), || async {
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(())
        } else {
            Err(SshAgentError::Denied)
        }
    });
    let using = async {
        write_frame(&mut client, &request).await.unwrap();
        assert_eq!(
            &**read_frame(&mut client).await.unwrap().unwrap(),
            &[FAILURE]
        );
        drop(client);
    };
    let (result, ()) = tokio::join!(serving, using);
    result.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    owner.shutdown().await.unwrap();
    synthetic.assert_clean();
}

#[tokio::test]
async fn stock_ssh_keygen_signs_through_filtered_bridge_and_verifies_the_signature() {
    let synthetic = Synthetic::new();
    let owner = synthetic.owner();
    let agent = Arc::new(
        owner
            .start(
                synthetic.key("ed25519", "").await,
                None,
                Instant::now() + Duration::from_secs(30),
            )
            .unwrap()
            .ready()
            .await
            .unwrap(),
    );
    let public = synthetic.fixtures.join("selected.pub");
    std::fs::write(
        &public,
        format!(
            "ssh-ed25519 {} codewire-selected-key\n",
            STANDARD.encode(agent.public_identity().key_blob())
        ),
    )
    .unwrap();
    let socket = synthetic.fixtures.join("bridge.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let serving_agent = agent.clone();
    let serving = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        serving_agent
            .serve_connection(stream, CancellationToken::new(), || async { Ok(()) })
            .await
    });
    let mut child = Command::new("/usr/bin/ssh-keygen")
        .env_clear()
        .env("HOME", &synthetic.fixtures)
        .env("SSH_AUTH_SOCK", &socket)
        .args(["-Y", "sign", "-U", "-f"])
        .arg(&public)
        .args(["-n", "codewire-agent-test"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"synthetic signed message")
        .await
        .unwrap();
    let output = child.wait_with_output().await.unwrap();
    assert!(output.status.success());
    serving.await.unwrap().unwrap();
    let signature = synthetic.fixtures.join("signature");
    std::fs::write(&signature, output.stdout).unwrap();
    let mut verify = Command::new("/usr/bin/ssh-keygen")
        .env_clear()
        .env("HOME", &synthetic.fixtures)
        .args(["-Y", "check-novalidate", "-n", "codewire-agent-test", "-s"])
        .arg(signature)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    verify
        .stdin
        .take()
        .unwrap()
        .write_all(b"synthetic signed message")
        .await
        .unwrap();
    assert!(verify.wait().await.unwrap().success());
    drop(agent);
    owner.shutdown().await.unwrap();
    synthetic.assert_clean();
}

#[test]
fn configuration_and_material_reject_nonprivate_or_unsupported_inputs() {
    let synthetic = Synthetic::new();
    assert!(
        SshAgentConfig::new(
            "/dev/shm".into(),
            "/usr/bin/ssh-agent".into(),
            "/usr/bin/ssh-add".into(),
            "/bin/false".into()
        )
        .is_err()
    );
    assert!(validate_material(b"not a key", None).is_err());
    let framing =
        b"-----BEGIN OPENSSH PRIVATE KEY-----\ninvalid\n-----END OPENSSH PRIVATE KEY-----";
    for passphrase in [b"a\nb".as_slice(), b"a\0b", b"a\rb"] {
        assert!(validate_material(framing, Some(passphrase)).is_err());
    }
    assert!(validate_material(framing, Some(&vec![1; MAX_PASSPHRASE_BYTES + 1])).is_err());
    synthetic.assert_clean();
}

#[test]
fn helper_admission_binds_exact_bytes_owner_modes_and_nonreplaceable_path() {
    let synthetic = Synthetic::new();
    let path = synthetic.fixtures.join("askpass.sh");
    std::fs::write(&path, ASKPASS_HELPER).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(validate_askpass_helper(&path).unwrap(), path);
    for mode in [0o720, 0o702, 0o600] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(validate_askpass_helper(&path).is_err());
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut changed = ASKPASS_HELPER.to_vec();
    *changed.last_mut().unwrap() = b' ';
    std::fs::write(&path, changed).unwrap();
    assert!(validate_askpass_helper(&path).is_err());
    std::fs::write(&path, ASKPASS_HELPER).unwrap();
    let alias = synthetic.fixtures.join("alias");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(validate_askpass_helper(&alias).is_err());
    let hardlink = synthetic.fixtures.join("hardlink");
    std::fs::hard_link(&path, &hardlink).unwrap();
    assert!(validate_askpass_helper(&path).is_err());
    std::fs::remove_file(hardlink).unwrap();
    std::fs::set_permissions(&synthetic.fixtures, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(validate_askpass_helper(&path).is_err());
}

#[tokio::test]
async fn helper_change_after_config_is_rejected_before_starting_material_tools() {
    let synthetic = Synthetic::new();
    let helper = synthetic.fixtures.join("askpass.sh");
    std::fs::write(&helper, ASKPASS_HELPER).unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = SshAgentConfig::new(
        synthetic.runtime.clone(),
        "/usr/bin/ssh-agent".into(),
        "/usr/bin/ssh-add".into(),
        helper.clone(),
    )
    .unwrap();
    let owner = SshAgentOwner::new(config);
    std::fs::write(helper, b"#!/bin/sh\nexit 0\n").unwrap();
    let result = owner
        .start(
            synthetic.key("ed25519", "").await,
            None,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap()
        .ready()
        .await;
    assert!(matches!(result, Err(SshAgentError::Configuration)));
    owner.shutdown().await.unwrap();
    synthetic.assert_clean();
}
