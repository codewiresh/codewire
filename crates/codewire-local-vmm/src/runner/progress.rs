//! Reading a guest's authenticated boot progress over its hybrid vsock.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NetworkProgressAttemptError {
    Retry,
    Timeout,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NetworkProgressGoal {
    NetworkReady,
    Terminal,
    /// An image disk builder's layers are ready (#4646). Linux builds image
    /// disks first.
    #[cfg(target_os = "linux")]
    LayersReady,
}

pub(super) async fn wait_for_network_progress_attempt(
    hybrid: &HybridVsockTarget,
    token: &str,
    vm_id: Uuid,
    generation: u64,
    deadline: tokio::time::Instant,
    goal: NetworkProgressGoal,
    mut times: Option<&mut GuestStageTimes>,
) -> Result<GuestBootStage, NetworkProgressAttemptError> {
    let connected = tokio::time::timeout_at(
        deadline,
        hybrid.connect_guest_port(GUEST_PROGRESS_VSOCK_PORT),
    )
    .await
    .map_err(|_| NetworkProgressAttemptError::Timeout)?;
    let mut stream = match connected {
        Ok(stream) => stream,
        Err(
            HybridVsockError::InvalidSocketPath
            | HybridVsockError::InvalidGuestPort
            | HybridVsockError::SocketIdentity(_),
        ) => return Err(NetworkProgressAttemptError::Rejected),
        Err(_) => return Err(NetworkProgressAttemptError::Retry),
    };

    let mut challenge = [0_u8; PROGRESS_CHALLENGE_LEN];
    while challenge.iter().all(|byte| *byte == 0) {
        OsRng.fill_bytes(&mut challenge);
    }
    let request = ProgressRequest {
        vm_id,
        generation,
        challenge,
    };
    match tokio::time::timeout_at(deadline, async {
        stream.write_all(&request.encode()).await?;
        stream.flush().await
    })
    .await
    {
        Err(_) => return Err(NetworkProgressAttemptError::Timeout),
        Ok(Err(_)) => return Err(NetworkProgressAttemptError::Retry),
        Ok(Ok(())) => {}
    }

    let mut sequence = 0_u64;
    let mut stage = None;
    for _ in 0..NETWORK_WORKER_PROGRESS_FRAME_LIMIT {
        let mut bytes = [0_u8; PROGRESS_FRAME_LEN];
        match tokio::time::timeout_at(deadline, stream.read_exact(&mut bytes)).await {
            Err(_) => return Err(NetworkProgressAttemptError::Timeout),
            Ok(Err(_)) => return Err(NetworkProgressAttemptError::Retry),
            Ok(Ok(_)) => {}
        }
        let frame = ProgressFrame::decode(&bytes, &challenge, token, vm_id, generation)
            .map_err(|_| NetworkProgressAttemptError::Rejected)?;
        if frame.sequence <= sequence || stage.is_some_and(|previous| frame.stage < previous) {
            return Err(NetworkProgressAttemptError::Rejected);
        }
        sequence = frame.sequence;
        stage = Some(frame.stage);
        if let Some(times) = times.as_deref_mut() {
            times.record(frame.stage);
        }
        if frame.stage.is_failure()
            || match goal {
                NetworkProgressGoal::NetworkReady => {
                    frame.stage >= GuestBootStage::RootGenerationReady
                }
                NetworkProgressGoal::Terminal => frame.stage.is_terminal(),
                #[cfg(target_os = "linux")]
                NetworkProgressGoal::LayersReady => frame.stage >= GuestBootStage::RootLayersReady,
            }
        {
            return Ok(frame.stage);
        }
    }
    Err(NetworkProgressAttemptError::Rejected)
}
