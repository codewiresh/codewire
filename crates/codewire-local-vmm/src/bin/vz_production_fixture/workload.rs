//! Fixed synthetic workload proof for the opt-in production-boot fixture.
//!
//! This is deliberately not a general command runner. The fresh fixture must
//! have no durable sessions before this proof, and every command and expected
//! byte is compiled in here.

use std::future::Future;
use std::time::Duration;

use codewire_daemon::client::{SessionClient, SessionClientError, v1};
use uuid::{Uuid, Variant, Version};

use super::{Result, invalid};

const OPERATION_DEADLINE: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const MAX_OUTPUT_BYTES: usize = 256;
const TRANSIENT_STDOUT: &[u8] = b"out\xff";
const TRANSIENT_STDERR: &[u8] = b"err\xfe";
const SESSION_STDOUT: &[u8] = b"session-ready\n";

fn transient_request(working_dir: &str) -> v1::ExecStartRequest {
    v1::ExecStartRequest {
        command: vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "printf 'out\\377'; printf 'err\\376' >&2; exit 23".to_owned(),
        ],
        working_dir: working_dir.to_owned(),
        env: Vec::new(),
    }
}

fn session_request(working_dir: &str) -> v1::LaunchSessionRequest {
    v1::LaunchSessionRequest {
        command: vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "printf 'session-ready\\n'; exec /bin/sleep 300".to_owned(),
        ],
        working_dir: working_dir.to_owned(),
        env: Vec::new(),
        pty: false,
        term: String::new(),
        width: 0,
        height: 0,
    }
}

pub(super) async fn prove(client: &SessionClient) -> Result<()> {
    prove_in(client, "/workspace").await
}

async fn prove_in(client: &SessionClient, working_dir: &str) -> Result<()> {
    // Empty is a fixture-specific fresh-setup invariant, not a general product
    // rule. It lets this proof reject both pre-existing and foreign sessions.
    if !rpc(client.list()).await?.is_empty() {
        return Err(invalid().into());
    }

    prove_transient(client, working_dir).await?;
    if !rpc(client.list()).await?.is_empty() {
        return Err(invalid().into());
    }

    prove_session(client, working_dir).await
}

async fn prove_transient(client: &SessionClient, working_dir: &str) -> Result<()> {
    let mut stream = rpc(client.exec_transient(transient_request(working_dir))).await?;
    let mut proof = TransientProof::default();
    loop {
        let message = tokio::time::timeout(OPERATION_DEADLINE, stream.message())
            .await
            .map_err(|_| invalid())??;
        match message {
            Some(message) => proof.observe(message)?,
            None => return proof.finish(),
        }
    }
}

async fn prove_session(client: &SessionClient, working_dir: &str) -> Result<()> {
    let request = session_request(working_dir);
    let admitted = rpc(client.launch(request.clone())).await?;
    let session_id = admitted.session_id.clone();
    // Establish ownership before enabling any targeted cleanup. A malformed or
    // substituted launch response must never authorize Stop on its claimed ID.
    if !owned_launch(&admitted, &request, &session_id)? {
        return Err(invalid().into());
    }
    let result = prove_owned_session(client, &request, &session_id, admitted).await;
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
) -> Result<()> {
    if lifecycle(&admitted)? != v1::SessionLifecycleState::Running || admitted.exit_code.is_some() {
        return Err(invalid().into());
    }

    require_single_session(client, request, session_id, false).await?;
    let running = wait_for_running_output(client, request, session_id).await?;
    if running.output_end_offset != SESSION_STDOUT.len() as u64 {
        return Err(invalid().into());
    }

    let fetched = rpc(client.get(session_id)).await?;
    if !record_matches_request(&fetched, request, session_id)
        || lifecycle(&fetched)? != v1::SessionLifecycleState::Running
        || fetched.exit_code.is_some()
        || fetched.output_end_offset != SESSION_STDOUT.len() as u64
    {
        return Err(invalid().into());
    }
    require_single_session(client, request, session_id, false).await?;

    let stopped = rpc(client.stop(session_id)).await?;
    require_stopped(&stopped, request, session_id)?;
    let fetched = rpc(client.get(session_id)).await?;
    require_stopped(&fetched, request, session_id)?;
    require_complete_output(client, session_id).await?;
    require_single_session(client, request, session_id, true).await
}

async fn wait_for_running_output(
    client: &SessionClient,
    request: &v1::LaunchSessionRequest,
    session_id: &str,
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
            if record.output_end_offset > SESSION_STDOUT.len() as u64 {
                return Err(invalid().into());
            }
            let (output, caught_up) = read_output(client, session_id).await?;
            if running_output_complete(&record, request, session_id, &output, caught_up)? {
                return Ok(record);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .map_err(|_| invalid())?
}

async fn require_complete_output(client: &SessionClient, session_id: &str) -> Result<()> {
    let (output, caught_up) = read_output(client, session_id).await?;
    if output != SESSION_STDOUT || !caught_up {
        return Err(invalid().into());
    }
    Ok(())
}

async fn read_output(client: &SessionClient, session_id: &str) -> Result<(Vec<u8>, bool)> {
    let response = rpc(client.read_output(v1::ReadSessionOutputRequest {
        session_id: session_id.to_owned(),
        offset: 0,
        limit: MAX_OUTPUT_BYTES as u64,
    }))
    .await?;
    validate_output(response)
}

async fn require_single_session(
    client: &SessionClient,
    request: &v1::LaunchSessionRequest,
    session_id: &str,
    stopped: bool,
) -> Result<()> {
    let sessions = rpc(client.list()).await?;
    let [record] = sessions.as_slice() else {
        return Err(invalid().into());
    };
    if stopped {
        require_stopped(record, request, session_id)
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
) -> Result<()> {
    if record_matches_request(record, request, session_id)
        && lifecycle(record)? == v1::SessionLifecycleState::Stopped
        && record.exit_code.is_none()
        && record.output_end_offset == SESSION_STDOUT.len() as u64
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

fn owned_launch(
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

fn running_output_complete(
    record: &v1::SessionRecord,
    request: &v1::LaunchSessionRequest,
    session_id: &str,
    output: &[u8],
    caught_up: bool,
) -> Result<bool> {
    if !record_matches_request(record, request, session_id)
        || record.exit_code.is_some()
        || !matches!(
            lifecycle(record)?,
            v1::SessionLifecycleState::Starting | v1::SessionLifecycleState::Running
        )
        || record.output_end_offset > SESSION_STDOUT.len() as u64
    {
        return Err(invalid().into());
    }
    if output == SESSION_STDOUT {
        if !caught_up {
            return Err(invalid().into());
        }
        // Output and metadata are published independently. A complete output
        // read paired with the preceding stale cursor means re-poll, not fail.
        return Ok(lifecycle(record)? == v1::SessionLifecycleState::Running
            && record.output_end_offset == SESSION_STDOUT.len() as u64);
    }
    Ok(false)
}

fn lifecycle(record: &v1::SessionRecord) -> Result<v1::SessionLifecycleState> {
    v1::SessionLifecycleState::try_from(record.state)
        .ok()
        .filter(|state| *state != v1::SessionLifecycleState::Unspecified)
        .ok_or_else(|| invalid().into())
}

fn validate_output(response: v1::ReadSessionOutputResponse) -> Result<(Vec<u8>, bool)> {
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
        if output.len() > MAX_OUTPUT_BYTES || !SESSION_STDOUT.starts_with(&output) {
            return Err(invalid().into());
        }
    }
    if response.next_offset != offset {
        return Err(invalid().into());
    }
    Ok((output, caught_up))
}

async fn rpc<T, F>(future: F) -> Result<T>
where
    F: Future<Output = std::result::Result<T, SessionClientError>>,
{
    tokio::time::timeout(OPERATION_DEADLINE, future)
        .await
        .map_err(|_| invalid())?
        .map_err(Into::into)
}

#[derive(Default)]
struct TransientProof {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit: Option<i32>,
}

impl TransientProof {
    fn observe(&mut self, message: v1::ExecMessage) -> Result<()> {
        if self.exit.is_some() {
            return Err(invalid().into());
        }
        match message.payload {
            Some(v1::exec_message::Payload::Stdout(bytes)) => {
                append_exact(&mut self.stdout, &bytes, TRANSIENT_STDOUT)
            }
            Some(v1::exec_message::Payload::Stderr(bytes)) => {
                append_exact(&mut self.stderr, &bytes, TRANSIENT_STDERR)
            }
            Some(v1::exec_message::Payload::Exit(status)) => {
                self.exit = Some(status.code);
                Ok(())
            }
            _ => Err(invalid().into()),
        }
    }

    fn finish(self) -> Result<()> {
        if self.stdout == TRANSIENT_STDOUT
            && self.stderr == TRANSIENT_STDERR
            && self.exit == Some(23)
        {
            Ok(())
        } else {
            Err(invalid().into())
        }
    }
}

fn append_exact(output: &mut Vec<u8>, bytes: &[u8], expected: &[u8]) -> Result<()> {
    let length = output.len().checked_add(bytes.len()).ok_or_else(invalid)?;
    if bytes.is_empty()
        || length > MAX_OUTPUT_BYTES
        || length > expected.len()
        || expected.get(output.len()..length) != Some(bytes)
    {
        return Err(invalid().into());
    }
    output.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
pub(super) async fn prove_in_test(client: &SessionClient, working_dir: &str) -> Result<()> {
    prove_in(client, working_dir).await
}

#[cfg(test)]
pub(super) fn transient_messages(messages: Vec<v1::ExecMessage>) -> Result<()> {
    let mut proof = TransientProof::default();
    for message in messages {
        proof.observe(message)?;
    }
    proof.finish()
}

#[cfg(test)]
pub(super) fn output_response(response: v1::ReadSessionOutputResponse) -> Result<(Vec<u8>, bool)> {
    validate_output(response)
}

#[cfg(test)]
pub(super) fn running_output_for_test(
    record: &v1::SessionRecord,
    working_dir: &str,
    output: &[u8],
    caught_up: bool,
) -> Result<bool> {
    running_output_complete(
        record,
        &session_request(working_dir),
        &record.session_id,
        output,
        caught_up,
    )
}

#[cfg(test)]
pub(super) fn owned_launch_for_test(record: &v1::SessionRecord, working_dir: &str) -> Result<bool> {
    owned_launch(record, &session_request(working_dir), &record.session_id)
}
