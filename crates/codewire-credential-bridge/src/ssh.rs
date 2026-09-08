//! Closed, material-free SSH operations on the admitted bridge epoch.
//! This is neither an agent socket nor key/algorithm authorization: those
//! boundaries remain with the adapter and the selected-agent authority.

use codewire_gateway_proto::ssh::{
    SshOperation, remaining_deadline, validate_request, validate_response,
};

use super::*;

pub(super) struct PendingSsh {
    pub epoch: u64,
    operation: SshOperation,
    deadline_unix_ms: u64,
    deadline: tokio::time::Instant,
    // None retains the shared budget and ID until a valid terminal response or
    // epoch loss, even when the outbound cancellation queue is full.
    pub response: Option<oneshot::Sender<Result<v1::CredentialSshResponse, Status>>>,
}

impl CredentialBridge {
    /// Forward one bounded identities/sign operation to the admitted authority.
    /// The caller supplies a fresh canonical request ID and original deadline;
    /// neither is rewritten or retried. Closed operation failures are returned
    /// unchanged. Transport, deadline and framing failures return a status.
    ///
    /// This method does not select a key or grant signing permission. It is not
    /// exposed through HTTP, and cannot return private key material.
    pub async fn relay_ssh(
        &self,
        request: v1::CredentialSshRequest,
    ) -> Result<v1::CredentialSshResponse, Status> {
        let operation = validate_request(&request)?;
        let deadline_unix_ms = request.deadline_unix_ms;
        let deadline = tokio::time::Instant::now() + remaining_deadline(deadline_unix_ms)?;
        let request_id = request.request_id.clone();
        let (response_tx, response_rx) = oneshot::channel();
        let (epoch, output) = {
            let state = self.inner.lock().await;
            let active = state.active.as_ref().ok_or_else(ssh_unavailable)?;
            check_deadline(deadline_unix_ms, deadline)?;
            if state.in_flight() >= CREDENTIAL_BRIDGE_MAX_IN_FLIGHT
                || state.contains_request(&request_id)
            {
                return Err(ssh_limit());
            }
            (active.epoch, active.output.clone())
        };
        // Waiting for output capacity owns no registered request. Cancellation
        // here therefore leaves no unsent tombstone behind.
        let permit = tokio::time::timeout_at(
            deadline.min(tokio::time::Instant::now() + HOST_SEND_TIMEOUT),
            output.reserve_owned(),
        )
        .await
        .map_err(|_| {
            check_deadline(deadline_unix_ms, deadline)
                .err()
                .unwrap_or_else(ssh_unavailable)
        })?
        .map_err(|_| ssh_unavailable())?;
        {
            let mut state = self.inner.lock().await;
            require_active_epoch(&state, epoch)?;
            check_deadline(deadline_unix_ms, deadline)?;
            if state.in_flight() >= CREDENTIAL_BRIDGE_MAX_IN_FLIGHT
                || state.contains_request(&request_id)
            {
                return Err(ssh_limit());
            }
            state.ssh.insert(
                request_id.clone(),
                PendingSsh {
                    epoch,
                    operation,
                    deadline_unix_ms,
                    deadline,
                    response: Some(response_tx),
                },
            );
            // No await between registration and dispatch, under the epoch lock.
            permit.send(Ok(guest_message(
                v1::credential_bridge_guest_message::Payload::Ssh(request),
            )));
        }
        let mut cancellation = PendingCancellation::new(self.clone(), request_id.clone(), epoch);
        let response = match tokio::time::timeout_at(deadline, response_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(ssh_unavailable()),
            Err(_) => {
                self.cancel(&request_id, epoch).await;
                Err(ssh_expired())
            }
        };
        cancellation.disarm();
        let response = response?;
        // Recheck after acquiring the lock: waiting for it must not extend the
        // original deadline or release a signature from a replaced epoch.
        let state = self.inner.lock().await;
        require_active_epoch(&state, epoch)?;
        check_deadline(deadline_unix_ms, deadline)?;
        Ok(response)
    }

    pub(super) async fn apply_ssh_response(
        &self,
        epoch: u64,
        response: v1::CredentialSshResponse,
    ) -> Result<(), Status> {
        let mut state = self.inner.lock().await;
        require_active_epoch(&state, epoch)?;
        let pending = state
            .ssh
            .get(&response.request_id)
            .ok_or_else(invalid_host_frame)?;
        if pending.epoch != epoch {
            return Err(invalid_host_frame());
        }
        // Validate before removal, including cancelled requests. A wrong-kind
        // response cannot clear a different family's entry or a tombstone.
        validate_response(&response, pending.operation)?;
        let live = check_deadline(pending.deadline_unix_ms, pending.deadline);
        let pending = state
            .ssh
            .remove(&response.request_id)
            .ok_or_else(invalid_host_frame)?;
        if let Some(sender) = pending.response {
            // A valid late terminal drains its slot, but is never released.
            // A cancelled receiver is normal and does not poison the epoch.
            let _ = sender.send(live.map(|()| response));
        }
        Ok(())
    }
}

pub(super) fn take_ssh(state: &mut BridgeState, epoch: u64) -> Vec<PendingSsh> {
    let ids: Vec<_> = state
        .ssh
        .iter()
        .filter(|(_, pending)| pending.epoch == epoch)
        .map(|(id, _)| id.clone())
        .collect();
    ids.into_iter()
        .filter_map(|id| state.ssh.remove(&id))
        .collect()
}

pub(super) fn fail_ssh(pending: Vec<PendingSsh>) {
    for request in pending {
        if let Some(sender) = request.response {
            let _ = sender.send(Err(ssh_unavailable()));
        }
    }
}

fn check_deadline(deadline_unix_ms: u64, deadline: tokio::time::Instant) -> Result<(), Status> {
    if tokio::time::Instant::now() >= deadline {
        return Err(ssh_expired());
    }
    remaining_deadline(deadline_unix_ms)
        .map(|_| ())
        .map_err(|_| ssh_expired())
}

fn ssh_expired() -> Status {
    Status::deadline_exceeded("SSH bridge request expired")
}

fn ssh_unavailable() -> Status {
    Status::unavailable("SSH bridge authority is unavailable")
}

fn ssh_limit() -> Status {
    Status::resource_exhausted("SSH bridge request limit reached")
}

#[cfg(test)]
mod tests;
