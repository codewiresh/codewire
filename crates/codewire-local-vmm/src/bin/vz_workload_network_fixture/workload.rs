//! One compiled real-workspace session and the existing guest poweroff action.
use codewire_daemon::client::{SessionClient, v1};
use codewire_vmm_guest_probe::Seed;
use tokio::sync::oneshot;

use super::{Result, invalid, session};

pub(super) const SESSION_STDOUT: &[u8] = b"workload-network-ready\n";

pub(super) fn request(working_dir: &str) -> v1::LaunchSessionRequest {
    v1::LaunchSessionRequest {
        name: String::new(),
        parent_session_id: None,
        command: vec!["/bin/sh".into(), "-c".into(),
            "/run/codewire-runtime/init macos-workload-network-client && printf 'workload-network-ready\\n' && exec /bin/sleep 300".into()],
        working_dir: working_dir.into(),
        env: vec![], pty: false, term: String::new(), width: 0, height: 0,
    }
}

pub(super) async fn prove(client: &SessionClient) -> Result<()> {
    if !session::rpc(client.list()).await?.is_empty() {
        return Err(invalid().into());
    }
    session::prove(client, request("/workspace"), SESSION_STDOUT).await
}

fn poweroff_request() -> v1::ExecStartRequest {
    v1::ExecStartRequest {
        command: vec!["/run/codewire-runtime/init".into(), "poweroff".into()],
        working_dir: "/workspace".into(),
        env: vec![],
    }
}

pub(super) struct PoweroffProof {
    expected: Vec<u8>,
    observed: usize,
    exit: bool,
}

impl PoweroffProof {
    pub(super) fn new(seed: &Seed) -> Self {
        Self {
            expected: format!(
                "CWPOWEROFF1 accepted vm_id={} generation={}\n",
                seed.vm_id(),
                seed.generation()
            )
            .into_bytes(),
            observed: 0,
            exit: false,
        }
    }

    pub(super) fn accepted(&self) -> bool {
        self.observed == self.expected.len()
    }

    pub(super) fn observe(&mut self, message: v1::ExecMessage) -> Result<()> {
        if self.exit {
            return Err(invalid().into());
        }
        match message.payload {
            Some(v1::exec_message::Payload::Stdout(bytes)) => {
                let end = self.observed.checked_add(bytes.len()).ok_or_else(invalid)?;
                if bytes.is_empty()
                    || self.expected.get(self.observed..end) != Some(bytes.as_slice())
                {
                    return Err(invalid().into());
                }
                self.observed = end;
            }
            Some(v1::exec_message::Payload::Exit(status))
                if status.code == 0 && self.accepted() =>
            {
                self.exit = true
            }
            _ => return Err(invalid().into()),
        }
        Ok(())
    }

    pub(super) fn closed(&self, error: Option<tonic::Code>) -> Result<()> {
        if self.accepted()
            && matches!(
                error,
                None | Some(tonic::Code::Unavailable | tonic::Code::Cancelled)
            )
        {
            Ok(())
        } else {
            Err(invalid().into())
        }
    }
}

pub(super) async fn poweroff(
    client: &SessionClient,
    seed: &Seed,
    accepted: oneshot::Sender<()>,
) -> Result<()> {
    let mut stream = session::rpc(client.exec_transient(poweroff_request())).await?;
    let mut proof = PoweroffProof::new(seed);
    let mut accepted = Some(accepted);
    loop {
        match stream.message().await {
            Ok(Some(message)) => {
                proof.observe(message)?;
                if proof.accepted()
                    && let Some(sender) = accepted.take()
                {
                    sender.send(()).map_err(|_| invalid())?;
                }
            }
            Ok(None) => return proof.closed(None),
            Err(error) => return proof.closed(Some(error.code())),
        }
        // Retain the actual RPC after acceptance: dropping it here could kill
        // its transient child between stdout.flush and signaling guest PID1.
        // Completion still requires the parent's independent actual VM stops.
    }
}
