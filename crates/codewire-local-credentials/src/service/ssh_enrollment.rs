//! Bounded SSH enrollment: generating or importing an SSH identity runs on a
//! capped set of blocking workers that shutdown and the request can cancel.

use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use codewire_protected_store::ssh_material::SshMaterialError;
use tokio::sync::watch;
use tonic::Status;

use crate::LocalCredentialError;

pub(super) const MAX_SSH_ENROLLMENT_WORKERS: u32 = 8;
pub(super) const SSH_ENROLLMENT_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(super) struct SshEnrollmentWorkers {
    pub(super) permits: Arc<tokio::sync::Semaphore>,
    shutdown: watch::Sender<bool>,
    /// Requests whose caller went away before their answer, which a test
    /// waits on instead of a clock.
    #[cfg(test)]
    abandoned: Arc<AtomicUsize>,
}

pub(super) struct SshEnrollmentCancellation {
    shutdown: watch::Receiver<bool>,
    request: watch::Receiver<bool>,
}

impl SshEnrollmentCancellation {
    pub(super) fn is_cancelled(&self) -> bool {
        *self.shutdown.borrow() || *self.request.borrow()
    }
}

/// Dropped with its request: a caller that goes away cancels the enrollment,
/// which is undone if it has not been published yet (#5413).
struct SshEnrollmentRequestGuard {
    cancelled: watch::Sender<bool>,
    #[cfg(test)]
    answered: bool,
    #[cfg(test)]
    abandoned: Arc<AtomicUsize>,
}

impl Drop for SshEnrollmentRequestGuard {
    fn drop(&mut self) {
        self.cancelled.send_replace(true);
        #[cfg(test)]
        if !self.answered {
            self.abandoned.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl SshEnrollmentWorkers {
    pub(super) fn new() -> Self {
        let (shutdown, _) = watch::channel(false);
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(
                MAX_SSH_ENROLLMENT_WORKERS as usize,
            )),
            shutdown,
            #[cfg(test)]
            abandoned: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(super) async fn run<T>(
        &self,
        operation: impl FnOnce(SshEnrollmentCancellation) -> Result<T, Status> + Send + 'static,
    ) -> Result<T, Status>
    where
        T: Send + 'static,
    {
        let shutdown = self.shutdown.subscribe();
        if *shutdown.borrow() {
            return Err(Status::unavailable(
                "local SSH credential enrollment is stopping",
            ));
        }
        let permit = Arc::clone(&self.permits)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("local SSH enrollment workers are busy"))?;
        if *shutdown.borrow() {
            return Err(Status::unavailable(
                "local SSH credential enrollment is stopping",
            ));
        }
        let (request_cancelled, request) = watch::channel(false);
        #[cfg_attr(not(test), allow(unused_mut))]
        let mut request_guard = SshEnrollmentRequestGuard {
            cancelled: request_cancelled,
            #[cfg(test)]
            answered: false,
            #[cfg(test)]
            abandoned: Arc::clone(&self.abandoned),
        };
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            operation(SshEnrollmentCancellation { shutdown, request })
        })
        .await
        .map_err(|_| Status::internal("local SSH enrollment worker failed"))?;
        #[cfg(test)]
        {
            request_guard.answered = true;
        }
        drop(request_guard);
        result
    }

    #[cfg(test)]
    pub(super) fn probe(&self) -> SshEnrollmentProbe {
        SshEnrollmentProbe {
            permits: Arc::clone(&self.permits),
            shutdown: self.shutdown.subscribe(),
            abandoned: Arc::clone(&self.abandoned),
        }
    }

    pub(super) async fn shutdown(&self) {
        self.shutdown.send_replace(true);
        if let Ok(permits) = Arc::clone(&self.permits)
            .acquire_many_owned(MAX_SSH_ENROLLMENT_WORKERS)
            .await
        {
            drop(permits);
        }
    }
}

/// What a test sees of the enrollment workers, so it waits on the
/// authority's own state instead of a wall clock: how many requests hold a
/// worker, and when shutdown has closed publication.
#[cfg(test)]
pub(crate) struct SshEnrollmentProbe {
    permits: Arc<tokio::sync::Semaphore>,
    shutdown: watch::Receiver<bool>,
    abandoned: Arc<AtomicUsize>,
}

#[cfg(test)]
impl SshEnrollmentProbe {
    /// Requests admitted to a worker and not yet finished.
    pub(crate) fn admitted(&self) -> usize {
        MAX_SSH_ENROLLMENT_WORKERS as usize - self.permits.available_permits()
    }

    /// Requests whose caller went away before their answer; each one's
    /// enrollment fails its publication check from then on.
    pub(crate) fn abandoned(&self) -> usize {
        self.abandoned.load(Ordering::SeqCst)
    }

    /// Returns once shutdown has closed publication: every admitted
    /// enrollment fails its publication check from then on.
    pub(crate) async fn stopping(&mut self) {
        // An error means the workers are gone with the server, so nothing
        // can publish any more either.
        let _ = self.shutdown.wait_for(|stopping| *stopping).await;
    }
}

pub(super) fn ssh_enrollment_check(
    deadline: Instant,
    cancelled: &SshEnrollmentCancellation,
) -> Result<(), LocalCredentialError> {
    if cancelled.is_cancelled() {
        Err(LocalCredentialError::SshEnrollmentClosed)
    } else if Instant::now() >= deadline {
        Err(LocalCredentialError::SshEnrollmentDeadlineElapsed)
    } else {
        Ok(())
    }
}

pub(super) fn validate_ssh_expiry(expires_at_unix: Option<u64>) -> Result<(), Status> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Status::internal("local credential authority time is invalid"))?
        .as_secs();
    validate_ssh_expiry_at(expires_at_unix, now)
}

pub(super) fn validate_ssh_expiry_at(expires_at_unix: Option<u64>, now: u64) -> Result<(), Status> {
    if expires_at_unix.is_some_and(|value| value <= now || i64::try_from(value).is_err()) {
        Err(Status::invalid_argument(
            "SSH credential expiry must be a future Unix timestamp",
        ))
    } else {
        Ok(())
    }
}

pub(super) fn status_for_ssh_material_error(error: SshMaterialError) -> Status {
    match error {
        SshMaterialError::EntropyUnavailable => {
            Status::unavailable("SSH key generation entropy is unavailable")
        }
        _ => Status::invalid_argument(error.to_string()),
    }
}
