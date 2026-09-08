use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[test]
fn ssh_input_bounds_are_checked_before_blocking_admission() {
    assert!(Input::Generate.validate().is_ok());
    for key in [Vec::new(), vec![b'x'; MAX_OPENSSH_PRIVATE_KEY_BYTES + 1]] {
        assert_eq!(
            Input::Import {
                private_key: Zeroizing::new(key),
                passphrase: None
            }
            .validate(),
            Err(Error::InvalidInput)
        );
    }
    for passphrase in [
        Vec::new(),
        vec![b'x'; MAX_SSH_PASSPHRASE_BYTES + 1],
        b"hidden\n".to_vec(),
        b"hidden\0".to_vec(),
    ] {
        assert_eq!(
            Input::Import {
                private_key: Zeroizing::new(b"synthetic-not-parsed-yet".to_vec()),
                passphrase: Some(Zeroizing::new(passphrase)),
            }
            .validate(),
            Err(Error::InvalidInput)
        );
    }
}

#[test]
fn ssh_expiry_must_be_future_and_representable_before_crypto() {
    let now = 1_800_000_000;
    for expiry in [0, now - 1, now, i64::MAX as u64 + 1, u64::MAX] {
        assert_eq!(validate_expiry(Some(expiry), now), Err(Error::InvalidInput));
    }
    assert_eq!(validate_expiry(None, now), Ok(()));
    assert_eq!(validate_expiry(Some(now + 1), now), Ok(()));
}

#[tokio::test]
async fn cancelled_or_expired_ssh_never_starts_crypto() {
    for cancelled in [false, true] {
        let cancel = CancellationToken::new();
        if cancelled {
            cancel.cancel();
        }
        let called = Arc::new(AtomicBool::new(false));
        let observed = called.clone();
        let deadline = if cancelled {
            Instant::now() + SSH_PREPARATION_TIMEOUT
        } else {
            Instant::now()
        };
        let result = prepare_retained(&cancel, deadline, move || {
            observed.store(true, Ordering::SeqCst);
            generate_ed25519()
        })
        .await;
        assert_eq!(
            result.err(),
            Some(if cancelled {
                Error::Cancelled
            } else {
                Error::Expired
            })
        );
        assert!(!called.load(Ordering::SeqCst));
    }
}

#[tokio::test]
async fn ssh_cancel_and_original_deadline_retain_worker_until_joined() {
    for expire in [false, true] {
        let cancel = CancellationToken::new();
        let worker_cancel = cancel.clone();
        let (entered, started) = oneshot::channel();
        let (release, held) = std::sync::mpsc::channel();
        let exited = Arc::new(AtomicBool::new(false));
        let worker_exited = exited.clone();
        let deadline = Instant::now() + SSH_PREPARATION_TIMEOUT;
        let mut task = tokio::spawn(async move {
            prepare_retained(&worker_cancel, deadline, move || {
                let _ = entered.send(());
                held.recv().expect("synthetic release");
                worker_exited.store(true, Ordering::SeqCst);
                generate_ed25519()
            })
            .await
        });
        started.await.unwrap();
        if expire {
            tokio::time::pause();
            tokio::time::advance(SSH_PREPARATION_TIMEOUT).await;
            assert!(Instant::now() >= deadline);
        } else {
            cancel.cancel();
        }
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert!(!task.is_finished(), "cancel detached live private crypto");
        assert!(!exited.load(Ordering::SeqCst));
        release.send(()).unwrap();
        let result = (&mut task).await.unwrap();
        assert_eq!(
            result.err(),
            Some(if expire {
                Error::Expired
            } else {
                Error::Cancelled
            })
        );
        assert!(exited.load(Ordering::SeqCst));
        if expire {
            tokio::time::resume();
        }
    }
}

#[tokio::test]
async fn ssh_crypto_parser_errors_are_closed_and_success_is_derived() {
    let cancel = CancellationToken::new();
    let invalid = prepare_retained(&cancel, Instant::now() + SSH_PREPARATION_TIMEOUT, || {
        import_openssh(Zeroizing::new(b"private-invalid-canary".to_vec()), None)
    })
    .await;
    assert_eq!(invalid.err(), Some(Error::InvalidInput));
    let prepared = prepare_retained(
        &cancel,
        Instant::now() + SSH_PREPARATION_TIMEOUT,
        generate_ed25519,
    )
    .await
    .unwrap();
    assert!(prepared.public_key().openssh().starts_with("ssh-ed25519 "));
    assert!(prepared.public_key().fingerprint().starts_with("SHA256:"));
}
