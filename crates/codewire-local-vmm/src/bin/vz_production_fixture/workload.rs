//! Fixed synthetic workload proof for the opt-in production-boot fixture.
//!
//! This is deliberately not a general command runner. The fresh fixture must
//! have no durable sessions before this proof, and every command and expected
//! byte is compiled in here.

use std::time::Duration;

use super::session::{self, rpc};
use codewire_daemon::client::{SessionClient, v1};

use super::{Result, invalid};

const OPERATION_DEADLINE: Duration = Duration::from_secs(5);
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
        name: String::new(),
        parent_session_id: None,
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
    session::prove(client, session_request(working_dir), SESSION_STDOUT).await
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
    session::validate_output(response, SESSION_STDOUT)
}

#[cfg(test)]
pub(super) fn running_output_for_test(
    record: &v1::SessionRecord,
    working_dir: &str,
    output: &[u8],
    caught_up: bool,
) -> Result<bool> {
    session::running_output_complete(
        record,
        &session_request(working_dir),
        &record.session_id,
        output,
        caught_up,
        SESSION_STDOUT,
    )
}

#[cfg(test)]
pub(super) fn owned_launch_for_test(record: &v1::SessionRecord, working_dir: &str) -> Result<bool> {
    session::owned_launch(record, &session_request(working_dir), &record.session_id)
}
