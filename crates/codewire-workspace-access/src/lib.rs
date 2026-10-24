//! Workspace access for Codewire environments: the SSH server (with SFTP and
//! SCP) that serves an environment's sessions through its workspace daemon,
//! the daemon client it uses, SSH host-key handling, and the environment's
//! tailnet peer machinery.

pub mod daemon;
#[cfg(unix)]
pub mod daemon_access;
pub mod daemon_mesh;
#[cfg(unix)]
pub mod daemon_tailnet;
pub mod host_key;
pub mod peer_relay;
pub mod scp;
pub mod sftp;
pub mod ssh;
