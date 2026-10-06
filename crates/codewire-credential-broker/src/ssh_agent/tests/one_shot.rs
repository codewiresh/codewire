use codewire_gateway_proto::codewire::bridge::v1;
use codewire_protected_store::ssh_material::{
    SshAgentMaterial, decode_protected_material, generate_ed25519, import_openssh,
};

use super::*;
use crate::process_test_support::isolated_process_fixture;

fn material() -> SshAgentMaterial {
    let (_, protected) = generate_ed25519().unwrap().into_parts();
    decode_protected_material(protected).unwrap()
}

fn request(material: &SshAgentMaterial, flags: u32) -> v1::CredentialSshSignRequest {
    v1::CredentialSshSignRequest {
        public_key_blob: material.public_key().key_blob().to_vec(),
        data: b"synthetic one-operation SSH challenge".to_vec(),
        flags,
    }
}

#[tokio::test]
async fn one_shot_signatures_return_after_cleanup_for_generated_and_encrypted_keys() {
    isolated_process_fixture(
        "ssh_agent::tests::one_shot::one_shot_signatures_return_after_cleanup_for_generated_and_encrypted_keys",
        async {
            let synthetic = Synthetic::new();
            let owner = synthetic.owner();
            for (kind, passphrase, flags) in [
                ("ed25519", "", 0),
                ("rsa", "SYNTHETIC_ONE_SHOT_PASSPHRASE", 2),
                ("rsa", "SYNTHETIC_ONE_SHOT_PASSPHRASE", 4),
            ] {
                let raw = synthetic.key(kind, passphrase).await;
                let passphrase =
                    (!passphrase.is_empty()).then(|| Zeroizing::new(passphrase.as_bytes().to_vec()));
                let (_, protected) = import_openssh(raw, passphrase).unwrap().into_parts();
                let material = decode_protected_material(protected).unwrap();
                let request = request(&material, flags);
                let blob = sign_once(
                    &owner,
                    material,
                    request,
                    Instant::now() + Duration::from_secs(30),
                    std::future::pending(),
                )
                .await
                .unwrap();
                assert!(!blob.is_empty());
                synthetic.assert_clean();
                assert_eq!(owner.capacity.available_permits(), MAX_AGENTS);
            }
            owner.shutdown().await.unwrap();
        },
    )
    .await;
}

#[tokio::test]
async fn one_shot_wrong_key_invalid_flags_expiry_and_precancel_start_nothing() {
    let synthetic = Synthetic::new();
    let owner = synthetic.owner();
    for case in 0..5 {
        let material = material();
        let mut request = request(&material, 0);
        let cancellation = CancellationToken::new();
        let deadline = match case {
            2 => Instant::now(),
            4 => Instant::now() + Duration::from_secs(31),
            _ => Instant::now() + Duration::from_secs(30),
        };
        match case {
            0 => request.public_key_blob = vec![7],
            1 => request.flags = 1,
            3 => cancellation.cancel(),
            _ => {}
        }
        assert!(
            sign_once(
                &owner,
                material,
                request,
                deadline,
                cancellation.cancelled()
            )
            .await
            .is_err()
        );
        synthetic.assert_clean();
        assert_eq!(owner.capacity.available_permits(), MAX_AGENTS);
    }
    owner.shutdown().await.unwrap();
}

#[tokio::test]
async fn one_shot_cancellation_at_start_sign_and_cleanup_never_bypasses_drain() {
    for phase in [
        Phase::ImportSpawned,
        Phase::Ready,
        Phase::SignDispatched,
        Phase::BeforeCleanup,
    ] {
        let synthetic = Synthetic::new();
        let (owner, probe, reached) = synthetic.owner_at(phase, false);
        let owner = Arc::new(owner);
        let material = material();
        let request = request(&material, 0);
        let cancellation = CancellationToken::new();
        let task = tokio::spawn({
            let owner = Arc::clone(&owner);
            let cancellation = cancellation.clone();
            async move {
                sign_once(
                    &owner,
                    material,
                    request,
                    Instant::now() + Duration::from_secs(30),
                    cancellation.cancelled(),
                )
                .await
            }
        });
        let evidence = phase_reached(reached).await;
        cancellation.cancel();
        tokio::task::yield_now().await;
        if phase == Phase::BeforeCleanup {
            // Earlier work-phase probes are cancellation-safe: cleanup may
            // legitimately finish as soon as cancellation drops that wait.
            // This independent cleanup barrier cannot be selected away.
            assert!(
                !task.is_finished(),
                "cancellation must wait for exact worker drain"
            );
        }
        probe.resume.notify_one();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(10), task)
                .await
                .unwrap()
                .unwrap(),
            Err(SshAgentError::Cancelled)
        );
        evidence.assert_dead(true).await;
        synthetic.assert_clean();
        assert_eq!(owner.capacity.available_permits(), MAX_AGENTS);
        owner.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn one_shot_cleanup_failure_discards_signature_and_closes_owner_admission() {
    let synthetic = Synthetic::new();
    let (owner, probe, reached) = synthetic.owner_at(Phase::BeforeCleanup, true);
    let owner = Arc::new(owner);
    let material = material();
    let request = request(&material, 0);
    let task = tokio::spawn({
        let owner = Arc::clone(&owner);
        async move {
            sign_once(
                &owner,
                material,
                request,
                Instant::now() + Duration::from_secs(30),
                std::future::pending(),
            )
            .await
        }
    });
    let evidence = phase_reached(reached).await;
    probe.resume.notify_one();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap(),
        Err(SshAgentError::Cleanup)
    );
    evidence.assert_dead(false).await;
    let (_, protected) = generate_ed25519().unwrap().into_parts();
    let next = decode_protected_material(protected).unwrap();
    let (key, passphrase) = next.into_parts();
    assert!(matches!(
        owner.start(key, passphrase, Instant::now() + Duration::from_secs(30)),
        Err(SshAgentError::Unavailable)
    ));
    assert_eq!(owner.shutdown().await, Err(SshAgentError::Cleanup));
}
