use super::*;
use std::sync::atomic::AtomicUsize;

fn scope() -> Scope {
    Scope {
        cancel: CancellationToken::new(),
        epoch: CancellationToken::new(),
        deadline: Instant::now() + Duration::from_secs(20),
        deadline_unix_ms: u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
            + 20_000,
    }
}

fn service() -> (tempfile::TempDir, Arc<Service>) {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::Builder::new()
        .prefix("cw-platform-ssh-")
        .tempdir_in("/dev/shm")
        .unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let owner = Arc::new(SshAgentOwner::new(
        crate::ssh_agent::SshAgentConfig::new(
            root.path().to_owned(),
            "/usr/bin/ssh-agent".into(),
            "/usr/bin/ssh-add".into(),
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ssh_agent/askpass.sh"),
        )
        .unwrap(),
    ));
    (
        root,
        Service::new(
            owner,
            Arc::new(Mutex::new(true)),
            TaskTracker::new(),
            CancellationToken::new(),
        ),
    )
}

#[tokio::test]
async fn service_capacity_precedes_work_and_is_shared_between_epochs() {
    let (_root, service) = service();
    let first = service.epoch();
    let second = service.epoch();
    let mut releases = Vec::new();
    let mut receivers = Vec::new();
    for index in 0..MAX_OPERATIONS {
        let (release, blocked) = oneshot::channel();
        let receiver = service
            .spawn(
                if index % 2 == 0 { &first } else { &second },
                &scope(),
                async move {
                    blocked.await.unwrap();
                    Ok(())
                },
            )
            .unwrap();
        releases.push(release);
        receivers.push(receiver);
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    assert!(matches!(
        service.spawn(&second, &scope(), async move {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
        Err(BrokerLeaseError::Unavailable)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(service.permits.available_permits(), 0);
    for release in releases {
        release.send(()).unwrap();
    }
    for receiver in receivers {
        receiver.await.unwrap().unwrap();
    }
    first.drain().await.unwrap();
    second.drain().await.unwrap();
    service.workers.close();
    service.workers.wait().await;
    assert_eq!(service.permits.available_permits(), MAX_OPERATIONS as usize);
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn lost_waiter_keeps_epoch_drain_and_service_capacity_until_terminal() {
    let (_root, service) = service();
    let epoch = service.epoch();
    let (release, blocked) = oneshot::channel();
    let receiver = service
        .spawn(&epoch, &scope(), async move {
            blocked.await.unwrap();
            Ok(())
        })
        .unwrap();
    drop(receiver);
    let drain = epoch.drain();
    tokio::pin!(drain);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut drain)
            .await
            .is_err()
    );
    assert_eq!(
        service.permits.available_permits(),
        MAX_OPERATIONS as usize - 1
    );
    release.send(()).unwrap();
    drain.await.unwrap();
    assert_eq!(service.permits.available_permits(), MAX_OPERATIONS as usize);
    service.workers.close();
    service.workers.wait().await;
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn closed_admission_and_failed_cleanup_never_acknowledge_new_work() {
    let (_root, service) = service();
    let epoch = service.epoch();
    *service.accepting.lock().unwrap() = false;
    assert!(matches!(
        service.spawn(&epoch, &scope(), async { Ok(()) }),
        Err(BrokerLeaseError::Unavailable)
    ));
    *service.accepting.lock().unwrap() = true;
    service.failed.store(true, Ordering::Release);
    assert!(matches!(
        service.spawn(&epoch, &scope(), async { Ok(()) }),
        Err(BrokerLeaseError::Unavailable)
    ));
    assert!(service.workers.is_empty());
    assert_eq!(
        service.shutdown().await,
        Err(PlatformRuntimeError::Unavailable)
    );
}

#[tokio::test]
async fn worker_unwind_is_durable_epoch_and_service_cleanup_failure() {
    let (_root, service) = service();
    let epoch = service.epoch();
    let receiver = service
        .spawn::<()>(&epoch, &scope(), async {
            panic!("synthetic operation panic")
        })
        .unwrap();
    assert!(receiver.await.is_err());
    assert_eq!(epoch.drain().await, Err(BrokerLeaseError::Unavailable));
    service.workers.close();
    service.workers.wait().await;
    assert_eq!(
        service.shutdown().await,
        Err(PlatformRuntimeError::Unavailable)
    );
}

#[tokio::test]
async fn retired_epoch_refuses_late_registration_without_retiring_other_epochs() {
    let (_root, service) = service();
    let retired = service.epoch();
    let fresh = service.epoch();
    retired.drain().await.unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    assert!(
        service
            .spawn(&retired, &scope(), async move {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    service
        .spawn(&fresh, &scope(), async { Ok(()) })
        .unwrap()
        .await
        .unwrap()
        .unwrap();
    fresh.drain().await.unwrap();
    service.workers.close();
    service.workers.wait().await;
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn narrowed_grant_deadline_survives_retained_result_queue() {
    let (_root, service) = service();
    let epoch = service.epoch();
    let initial = scope();
    let mut narrowed = initial.clone();
    narrowed.deadline = Instant::now() + Duration::from_secs(1);
    let deadline = narrowed.deadline;
    let receiver = service
        .spawn(&epoch, &initial, async { Ok(narrowed) })
        .unwrap();
    // Let the owned work complete, then delay the caller's release check.
    service.workers.close();
    service.workers.wait().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(Instant::now() >= deadline);
    assert!(initial.check().is_ok());
    assert_eq!(
        receiver.await.unwrap().unwrap().check(),
        Err(BrokerLeaseError::Denied)
    );
    tokio::time::resume();
    epoch.drain().await.unwrap();
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn cancelled_expired_or_retired_ssh_never_starts_crypto() {
    for scenario in 0..3 {
        let mut scope = scope();
        match scenario {
            0 => scope.cancel.cancel(),
            1 => scope.epoch.cancel(),
            _ => scope.deadline = Instant::now(),
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let result = prepare_retained(&scope, move || {
            observed.fetch_add(1, Ordering::SeqCst);
            Err(SshMaterialError::InvalidBundle)
        })
        .await;
        assert_eq!(result.err(), Some(BrokerLeaseError::Denied));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn cancellation_and_expiry_keep_crypto_owned_until_join() {
    for expire in [false, true] {
        let mut scope = scope();
        scope.deadline = Instant::now() + Duration::from_secs(1);
        let cancel = scope.cancel.clone();
        let deadline = scope.deadline;
        let (entered, started) = oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let exited = Arc::new(AtomicBool::new(false));
        let worker_exited = exited.clone();
        let task = tokio::spawn(async move {
            prepare_retained(&scope, move || {
                let _ = entered.send(());
                blocked.recv().unwrap();
                worker_exited.store(true, Ordering::Release);
                Err(SshMaterialError::InvalidBundle)
            })
            .await
        });
        started.await.unwrap();
        if expire {
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(1)).await;
            assert!(Instant::now() >= deadline);
        } else {
            cancel.cancel();
        }
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert!(!task.is_finished());
        assert!(!exited.load(Ordering::Acquire));
        release.send(()).unwrap();
        assert_eq!(task.await.unwrap().err(), Some(BrokerLeaseError::Denied));
        assert!(exited.load(Ordering::Acquire));
        if expire {
            tokio::time::resume();
        }
    }
}

#[tokio::test]
async fn retained_crypto_panic_is_closed_and_joined() {
    let result = prepare_retained(&scope(), || panic!("synthetic worker panic")).await;
    assert_eq!(result.err(), Some(BrokerLeaseError::Unavailable));
}

#[tokio::test]
async fn original_deadline_never_extends_and_ready_result_is_rechecked() {
    let mut scope = scope();
    let original = scope.deadline;
    scope
        .clamp_expiry(super::super::unix_now().unwrap() + 3600)
        .unwrap();
    assert_eq!(scope.deadline, original);
    assert_eq!(
        scope.clone().clamp_expiry(u64::MAX),
        Err(BrokerLeaseError::Denied)
    );
    let cancel = scope.cancel.clone();
    let result = scope
        .wait(async {
            cancel.cancel();
            Ok(())
        })
        .await;
    assert_eq!(result, Err(BrokerLeaseError::Denied));
}

#[test]
fn public_identity_parser_does_not_accept_mismatched_fingerprint_or_provider() {
    let (metadata, public) = public_metadata();
    // This pure parser accepts metadata, not a store handle or protected bytes.
    assert_eq!(public_identity_metadata(&metadata).unwrap(), public);
    assert!(allowed_flags(&public, 0));
    for flags in [1, 2, 3, 4, u32::MAX] {
        assert!(!allowed_flags(&public, flags));
    }
    let mut invalid = metadata.clone();
    invalid.ssh_public_key.as_mut().unwrap().fingerprint = format!("SHA256:{}", "A".repeat(43));
    assert_eq!(
        public_identity_metadata(&invalid).err(),
        Some(BrokerLeaseError::InvalidResponse)
    );
    invalid = metadata;
    invalid.provider = codewire_access::ProviderId::parse("openai").unwrap();
    assert_eq!(
        public_identity_metadata(&invalid).err(),
        Some(BrokerLeaseError::Denied)
    );
}

fn public_metadata() -> (CredentialMetadata, SshPublicKey) {
    use codewire_access::{
        CredentialId, CredentialStatus, OwnerId, ProviderId, SshPublicKeyMetadata,
    };
    let prepared = codewire_protected_store::ssh_material::generate_ed25519().unwrap();
    let public = prepared.public_key().clone();
    let owner = Owner::User(OwnerId::parse("synthetic-owner").unwrap());
    let metadata = CredentialMetadata {
        id: CredentialId::parse("synthetic-ssh").unwrap(),
        provider: ProviderId::parse("ssh").unwrap(),
        authentication_kind: CredentialAuthKind::SshKey,
        owner,
        placement: Placement::Platform,
        display_name: "synthetic".into(),
        status: CredentialStatus::Active,
        expires_at_unix: None,
        account_hint: None,
        revocation_generation: 1,
        ssh_public_key: Some(SshPublicKeyMetadata {
            openssh: public.openssh().into(),
            fingerprint: public.fingerprint().into(),
        }),
    };
    (metadata, public)
}

#[tokio::test]
async fn rechecked_session_expiry_narrows_the_retained_result_deadline() {
    use codewire_access::{AccessProfileId, EnvironmentId};
    let (_root, service) = service();
    let epoch = service.epoch();
    let (metadata, _) = public_metadata();
    let initial = scope();
    let mut narrowed = initial.clone();
    let expiry = super::super::unix_now().unwrap() + 2;
    let permission = GrantPermission {
        operation: BrokerOperationId::parse("ssh-sign").unwrap(),
        route: BrokerRouteId::parse("ssh-agent").unwrap(),
    };
    let before = Admission {
        grant: DerivedGrant {
            environment_id: EnvironmentId::parse("synthetic-environment").unwrap(),
            environment_generation: 1,
            profile_id: AccessProfileId::parse("synthetic-profile").unwrap(),
            profile_revision: 1,
            capability_slot: CapabilitySlot::parse("ssh").unwrap(),
            credential_id: metadata.id.clone(),
            credential_revocation_generation: 1,
            expires_at_unix: Some(expiry + 60),
            permissions: std::collections::BTreeSet::from([permission.clone()]),
        },
        record: CredentialRecord {
            metadata,
            version: CredentialVersion {
                revocation_generation: 1,
                material_generation: 1,
            },
        },
        permission,
    };
    let mut after = Admission {
        record: before.record.clone(),
        grant: before.grant.clone(),
        permission: before.permission.clone(),
    };
    after.grant.expires_at_unix = Some(expiry);
    // The binding is unchanged; only the current authenticated expiry narrows.
    assert!(same_grant_binding(&before.grant, &after.grant));
    revalidate_admission(&mut narrowed, &before, &after).unwrap();
    assert_eq!(narrowed.deadline_unix_ms, expiry * 1000);
    assert!(narrowed.deadline < initial.deadline);
    let deadline = narrowed.deadline;
    after.grant.expires_at_unix = before.grant.expires_at_unix;
    revalidate_admission(&mut narrowed, &before, &after).unwrap();
    assert_eq!(narrowed.deadline, deadline);
    let receiver = service
        .spawn(&epoch, &initial, async { Ok(narrowed) })
        .unwrap();
    service.workers.close();
    service.workers.wait().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(initial.check().is_ok());
    assert_eq!(
        receiver.await.unwrap().unwrap().check(),
        Err(BrokerLeaseError::Denied)
    );
    tokio::time::resume();
    epoch.drain().await.unwrap();
    service.shutdown().await.unwrap();
}
