//! Shared canonical durable-session identity, output and Stop/Stopped proof.
//! Callers supply only their compiled fixture request and fixed expected output.
use super::{Result, invalid};
use codewire_daemon::client::{SessionClient, SessionClientError, v1};
use std::future::Future;
use std::time::Duration;
use uuid::{Uuid, Variant, Version};
const OPERATION_DEADLINE: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const MAX_OUTPUT_BYTES: usize = 256;

pub(super) async fn prove(
    client: &SessionClient,
    request: v1::LaunchSessionRequest,
    expected: &[u8],
) -> Result<()> {
    if expected.is_empty() || expected.len() > MAX_OUTPUT_BYTES {
        return Err(invalid().into());
    }
    let admitted = rpc(client.launch(request.clone())).await?;
    let session_id = admitted.session_id.clone();
    // Establish ownership before enabling any targeted cleanup. A malformed or
    // substituted launch response must never authorize Stop on its claimed ID.
    if !owned_launch(&admitted, &request, &session_id)? {
        return Err(invalid().into());
    }
    let result = prove_owned_session(client, &request, &session_id, admitted, expected).await;
    if result.is_err() {
        // This is bounded best-effort cleanup only. The parent still owns VM
        // teardown, and no claim is made that a failed RPC stopped the child.
        let _ = tokio::time::timeout(OPERATION_DEADLINE, client.stop(&session_id)).await;
    }
    result
}

async fn prove_owned_session(
    client: &SessionClient,
    request: &v1::LaunchSessionRequest,
    session_id: &str,
    admitted: v1::SessionRecord,
    expected: &[u8],
) -> Result<()> {
    if lifecycle(&admitted)? != v1::SessionLifecycleState::Running || admitted.exit_code.is_some() {
        return Err(invalid().into());
    }

    require_single_session(client, request, session_id, false, expected).await?;
    let running = wait_for_running_output(client, request, session_id, expected).await?;
    if running.output_end_offset != expected.len() as u64 {
        return Err(invalid().into());
    }

    let fetched = rpc(client.get(session_id)).await?;
    if !record_matches_request(&fetched, request, session_id)
        || lifecycle(&fetched)? != v1::SessionLifecycleState::Running
        || fetched.exit_code.is_some()
        || fetched.output_end_offset != expected.len() as u64
    {
        return Err(invalid().into());
    }
    require_single_session(client, request, session_id, false, expected).await?;

    let stopped = rpc(client.stop(session_id)).await?;
    require_stopped(&stopped, request, session_id, expected)?;
    let fetched = rpc(client.get(session_id)).await?;
    require_stopped(&fetched, request, session_id, expected)?;
    require_complete_output(client, session_id, expected).await?;
    require_single_session(client, request, session_id, true, expected).await
}

async fn wait_for_running_output(
    client: &SessionClient,
    request: &v1::LaunchSessionRequest,
    session_id: &str,
    expected: &[u8],
) -> Result<v1::SessionRecord> {
    tokio::time::timeout(OPERATION_DEADLINE, async {
        loop {
            let record = rpc(client.get(session_id)).await?;
            if !record_matches_request(&record, request, session_id) || record.exit_code.is_some() {
                return Err(invalid().into());
            }
            match lifecycle(&record)? {
                v1::SessionLifecycleState::Starting | v1::SessionLifecycleState::Running => {}
                _ => return Err(invalid().into()),
            }
            if record.output_end_offset > expected.len() as u64 {
                return Err(invalid().into());
            }
            let (output, caught_up) = read_output(client, session_id, expected).await?;
            if running_output_complete(&record, request, session_id, &output, caught_up, expected)?
            {
                return Ok(record);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .map_err(|_| invalid())?
}

async fn require_complete_output(
    client: &SessionClient,
    session_id: &str,
    expected: &[u8],
) -> Result<()> {
    let (output, caught_up) = read_output(client, session_id, expected).await?;
    if output != expected || !caught_up {
        return Err(invalid().into());
    }
    Ok(())
}

async fn read_output(
    client: &SessionClient,
    session_id: &str,
    expected: &[u8],
) -> Result<(Vec<u8>, bool)> {
    let response = rpc(client.read_output(v1::ReadSessionOutputRequest {
        session_id: session_id.to_owned(),
        offset: 0,
        limit: MAX_OUTPUT_BYTES as u64,
        allow_history_gap: false,
    }))
    .await?;
    validate_output(response, expected)
}

async fn require_single_session(
    client: &SessionClient,
    request: &v1::LaunchSessionRequest,
    session_id: &str,
    stopped: bool,
    expected: &[u8],
) -> Result<()> {
    let sessions = rpc(client.list()).await?;
    let [record] = sessions.as_slice() else {
        return Err(invalid().into());
    };
    if stopped {
        require_stopped(record, request, session_id, expected)
    } else if record_matches_request(record, request, session_id)
        && lifecycle(record)? == v1::SessionLifecycleState::Running
        && record.exit_code.is_none()
    {
        Ok(())
    } else {
        Err(invalid().into())
    }
}

fn require_stopped(
    record: &v1::SessionRecord,
    request: &v1::LaunchSessionRequest,
    session_id: &str,
    expected: &[u8],
) -> Result<()> {
    if record_matches_request(record, request, session_id)
        && lifecycle(record)? == v1::SessionLifecycleState::Stopped
        && record.exit_code.is_none()
        && record.output_end_offset == expected.len() as u64
        && record.finished_at.is_some()
    {
        Ok(())
    } else {
        Err(invalid().into())
    }
}

fn record_matches_request(
    record: &v1::SessionRecord,
    request: &v1::LaunchSessionRequest,
    session_id: &str,
) -> bool {
    record.session_id == session_id
        && record.command == request.command
        && record.working_dir == request.working_dir
        && record.pty == request.pty
        && record.created_at.is_some()
}

pub(super) fn owned_launch(
    record: &v1::SessionRecord,
    request: &v1::LaunchSessionRequest,
    session_id: &str,
) -> Result<bool> {
    let Some(encoded) = session_id.strip_prefix("session-") else {
        return Ok(false);
    };
    let Ok(identifier) = Uuid::parse_str(encoded) else {
        return Ok(false);
    };
    Ok(identifier.hyphenated().to_string() == encoded
        && identifier.get_version() == Some(Version::Random)
        && identifier.get_variant() == Variant::RFC4122
        && record_matches_request(record, request, session_id)
        && lifecycle(record)? == v1::SessionLifecycleState::Running
        && record.exit_code.is_none())
}

pub(super) fn running_output_complete(
    record: &v1::SessionRecord,
    request: &v1::LaunchSessionRequest,
    session_id: &str,
    output: &[u8],
    caught_up: bool,
    expected: &[u8],
) -> Result<bool> {
    if !record_matches_request(record, request, session_id)
        || record.exit_code.is_some()
        || !matches!(
            lifecycle(record)?,
            v1::SessionLifecycleState::Starting | v1::SessionLifecycleState::Running
        )
        || record.output_end_offset > expected.len() as u64
    {
        return Err(invalid().into());
    }
    if output == expected {
        if !caught_up {
            return Err(invalid().into());
        }
        // Output and metadata are published independently. A complete output
        // read paired with the preceding stale cursor means re-poll, not fail.
        return Ok(lifecycle(record)? == v1::SessionLifecycleState::Running
            && record.output_end_offset == expected.len() as u64);
    }
    Ok(false)
}

fn lifecycle(record: &v1::SessionRecord) -> Result<v1::SessionLifecycleState> {
    v1::SessionLifecycleState::try_from(record.state)
        .ok()
        .filter(|state| *state != v1::SessionLifecycleState::Unspecified)
        .ok_or_else(|| invalid().into())
}

pub(super) fn validate_output(
    response: v1::ReadSessionOutputResponse,
    expected: &[u8],
) -> Result<(Vec<u8>, bool)> {
    // Daemon EOF means caught up to the currently retained cursor; it does not
    // mean that the still-running session process exited.
    let caught_up = response.eof;
    let mut offset = 0_u64;
    let mut output = Vec::new();
    for chunk in response.chunks {
        if chunk.data.is_empty()
            || chunk.offset != offset
            || chunk.next_offset
                != chunk
                    .offset
                    .checked_add(chunk.data.len() as u64)
                    .ok_or_else(invalid)?
            || v1::SessionOutputStream::try_from(chunk.stream)
                != Ok(v1::SessionOutputStream::Stdout)
        {
            return Err(invalid().into());
        }
        offset = chunk.next_offset;
        output.extend_from_slice(&chunk.data);
        if output.len() > MAX_OUTPUT_BYTES || !expected.starts_with(&output) {
            return Err(invalid().into());
        }
    }
    if response.next_offset != offset {
        return Err(invalid().into());
    }
    Ok((output, caught_up))
}

pub(super) async fn rpc<T, F>(future: F) -> Result<T>
where
    F: Future<Output = std::result::Result<T, SessionClientError>>,
{
    tokio::time::timeout(OPERATION_DEADLINE, future)
        .await
        .map_err(|_| invalid())?
        .map_err(Into::into)
}
