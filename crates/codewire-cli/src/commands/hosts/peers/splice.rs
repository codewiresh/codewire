//! A host peer's tailnet port 22 (#3609, slice 3 design §7): each
//! connection is spliced into the supervisor's SSH for the peer's own VM at
//! its own boot. Nothing listens on the host. The splice is marked remote,
//! so it counts against the remote budget and leaves the owner's local one
//! alone; the mark is this agent's declaration on the owner's socket, a fair
//! share, not a security boundary.

use async_trait::async_trait;
use codewire_local_vmm::control::v1 as local;
use codewire_tailnet::netstack::TcpStream as TailnetStream;
use codewire_workspace_access::daemon_tailnet::TailnetSshServer;
use tokio::sync::watch;

use super::PeerKey;

/// Bytes buffered between the tailnet stream and the supervisor stream.
const SPLICE_BUFFER: usize = 64 * 1024;

pub(super) struct SupervisorSplice {
    /// The supervisor's name for the VM.
    name: String,
    vm: PeerKey,
    /// Set when the peer stops; every connection it spliced ends with it.
    end: watch::Receiver<bool>,
}

impl SupervisorSplice {
    pub(super) fn new(name: String, vm: PeerKey, end: watch::Receiver<bool>) -> Self {
        Self { name, vm, end }
    }

    async fn splice(&self, mut stream: TailnetStream) {
        let Ok(mut client) = super::super::super::native::native_client().await else {
            return;
        };
        // Only this peer's VM at this peer's boot, so no connection reaches
        // another VM or a later boot of this one.
        match client.get(&self.name).await {
            Ok(environment) if serves(&environment, &self.vm) => {}
            _ => return,
        }
        let open = local::SshStreamOpen {
            environment_id: self.vm.local_environment_id.to_string(),
            remote: true,
        };
        // The supervisor's side reads from a pipe this connection owns, so
        // dropping the connection ends that read too.
        let (mut ours, theirs) = tokio::io::duplex(SPLICE_BUFFER);
        let (from_client, to_client) = tokio::io::split(theirs);
        tokio::select! {
            _ = client.pipe_ssh(open, from_client, to_client) => {}
            _ = tokio::io::copy_bidirectional(&mut stream, &mut ours) => {}
        }
    }
}

/// Whether the supervisor's `environment` is the VM `vm` names, running at
/// its boot generation.
pub(super) fn serves(environment: &local::Environment, vm: &PeerKey) -> bool {
    environment.id == vm.local_environment_id.to_string()
        && environment.generation == vm.generation
        && local::EnvironmentState::try_from(environment.state)
            == Ok(local::EnvironmentState::Running)
}

#[async_trait]
impl TailnetSshServer for SupervisorSplice {
    async fn serve(&self, stream: TailnetStream) {
        let mut end = self.end.clone();
        tokio::select! {
            () = self.splice(stream) => {}
            _ = end.wait_for(|ended| *ended) => {}
        }
    }
}
