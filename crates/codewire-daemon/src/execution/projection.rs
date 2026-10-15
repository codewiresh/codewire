use std::os::unix::fs::{MetadataExt, PermissionsExt};

use codewire_workload_secrets::launcher::{
    LAUNCH_COMMIT, LAUNCH_READY, encode_context, encode_override_names, now_unix_ms,
};
use codewire_workload_secrets::{PROJECTION_REQUEST_LIFETIME_MS, ProjectionContext};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

use super::*;
use crate::config::Config;
use crate::credential_bridge::CredentialBridge;

pub(super) struct LaunchRendezvous {
    listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
    context: ProjectionContext,
    bridge: CredentialBridge,
    override_names: std::collections::BTreeSet<String>,
    wait_for_initial_host: bool,
    committed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl PreparedProcess {
    pub(crate) fn prepare_configured(
        (config, bridge): (&Config, &CredentialBridge),
        command: &[String],
        working_directory: &str,
        environment: &crate::env::ProcessEnvironment,
        terminal: bool,
        width: u16,
        height: u16,
    ) -> io::Result<Self> {
        let Some(projection) = config.launch_projection.as_ref() else {
            return Self::prepare(
                &config.process_execution,
                command,
                working_directory,
                &environment.entries,
                terminal,
                width,
                height,
            );
        };
        let identity = config.credential_bridge.as_ref().ok_or_else(denied)?;
        // Validate names-only framing before allocating a spec/socket or
        // requesting any protected projection. Values retain their old path.
        encode_override_names(&environment.override_names)?;
        let context = ProjectionContext {
            environment_id: *identity.environment_id.as_bytes(),
            operation_generation: identity.environment_generation,
            selection_sha256: projection.selection_sha256,
            deadline_unix_ms: now_unix_ms()?
                .checked_add(PROJECTION_REQUEST_LIFETIME_MS)
                .ok_or_else(denied)?,
        };
        context.validate_at(now_unix_ms()?).map_err(|_| denied())?;
        let mut execution = config.process_execution.clone();
        match &mut execution {
            ProcessExecution::Runc(runc) => {
                // Fixed helper-only marker; never inferred from environment or
                // optional socket presence by the final launcher.
                if runc.process_wrapper.len() != 2 || runc.process_wrapper[1] != "workspace-exec" {
                    return Err(denied());
                }
                runc.process_wrapper.push("--projection-fd=3".into());
            }
            ProcessExecution::Native => {
                let native = projection.native.as_ref().ok_or_else(denied)?;
                validate_native_helper(&native.helper_path)?;
                validate_process_directory(&native.process_directory)?;
            }
        }
        let mut prepared = Self::prepare(
            &execution,
            command,
            working_directory,
            &environment.entries,
            terminal,
            width,
            height,
        )?;
        let socket = match (&execution, prepared.pending_process_spec.as_ref()) {
            (ProcessExecution::Runc(_), Some(spec)) => spec.with_extension("sock"),
            (ProcessExecution::Native, None) => {
                let native = projection.native.as_ref().ok_or_else(denied)?;
                let socket = native
                    .process_directory
                    .join(format!("{}.sock", Uuid::new_v4()));
                prepared.program = native.helper_path.as_os_str().to_owned();
                prepared.arguments = [
                    OsString::from("__environment-launch"),
                    OsString::from("--projection-socket"),
                    socket.as_os_str().to_owned(),
                    OsString::from("--"),
                ]
                .into_iter()
                .chain(command.iter().map(OsString::from))
                .collect();
                socket
            }
            _ => return Err(denied()),
        };
        // Never remove pre-existing objects. Unique socket path and validated
        // private parent are independent of request-provided work directories.
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::symlink_metadata(&socket)?;
        prepared.launch = Some(LaunchRendezvous {
            listener,
            path: socket,
            device: metadata.dev(),
            inode: metadata.ino(),
            context,
            bridge: bridge.clone(),
            override_names: environment.override_names.clone(),
            wait_for_initial_host: identity.transport == crate::CredentialBridgeTransport::Hosted,
            committed: prepared.launch_committed.clone(),
        });
        Ok(prepared)
    }
}

impl LaunchRendezvous {
    pub(super) async fn deliver(self, pid: u32) -> io::Result<()> {
        let remaining = self
            .context
            .deadline_unix_ms
            .checked_sub(now_unix_ms()?)
            .ok_or_else(denied)?;
        tokio::time::timeout(std::time::Duration::from_millis(remaining), async {
            let (channel, _) = self.listener.accept().await?;
            let peer = channel.peer_cred()?;
            if peer.pid().and_then(|pid| u32::try_from(pid).ok()) != Some(pid)
                || peer.uid() != unsafe { libc::geteuid() }
            {
                return Err(denied());
            }
            relay_accepted_launch(
                channel,
                self.context.clone(),
                &self.bridge,
                self.wait_for_initial_host,
                &self.override_names,
                &self.committed,
            )
            .await
        })
        .await
        .map_err(|_| denied())?
    }
}

impl Drop for LaunchRendezvous {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| metadata.dev() == self.device && metadata.ino() == self.inode)
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// The sole daemon-side launch framing implementation. The accepting owner
/// authenticates and pins its peer; this operation has no source selector.
pub(super) async fn relay_accepted_launch(
    mut channel: tokio::net::UnixStream,
    context: ProjectionContext,
    bridge: &CredentialBridge,
    wait_for_initial_host: bool,
    override_names: &std::collections::BTreeSet<String>,
    committed: &std::sync::atomic::AtomicBool,
) -> io::Result<()> {
    let overrides = encode_override_names(override_names)?;
    let remaining = context
        .deadline_unix_ms
        .checked_sub(now_unix_ms()?)
        .ok_or_else(denied)?;
    tokio::time::timeout(std::time::Duration::from_millis(remaining), async {
        channel.write_all(&encode_context(&context)?).await?;
        channel.write_all(&overrides).await?;
        let mut recipient = [0; 32];
        channel.read_exact(&mut recipient).await?;
        if wait_for_initial_host {
            // Startup and Hosted setup may wait for the first authenticated host.
            // Keep the exact context/deadline; never replay a request or wait
            // for a previously admitted, disconnected host to return.
            bridge
                .wait_for_initial_host(&context)
                .await
                .map_err(|_| denied())?;
        }
        let sealed = bridge
            .project_environment_for_recipient(context, recipient)
            .await
            .map_err(|_| denied())?;
        let length = u32::try_from(sealed.ciphertext().len()).map_err(|_| denied())?;
        channel.write_all(&length.to_be_bytes()).await?;
        channel.write_all(sealed.ciphertext()).await?;
        let mut ready = [0];
        channel.read_exact(&mut ready).await?;
        if ready != [LAUNCH_READY] {
            return Err(denied());
        }
        sealed.validate().await.map_err(|_| denied())?;
        // Final exec follows this commit; already inherited values cannot be
        // revoked. Peer/lifecycle owners must cancel this future on shutdown.
        commit_launch(&mut channel, committed).await
    })
    .await
    .map_err(|_| denied())?
}

/// Tells the launcher to execute. `committed` is set before the byte is
/// written: from here on the program may start, so no later failure, timeout
/// or cancellation is a denial a Resume could undo (#2769).
async fn commit_launch(
    channel: &mut tokio::net::UnixStream,
    committed: &std::sync::atomic::AtomicBool,
) -> io::Result<()> {
    committed.store(true, std::sync::atomic::Ordering::SeqCst);
    channel.write_all(&[LAUNCH_COMMIT]).await?;
    channel.shutdown().await
}

fn validate_native_helper(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.mode() & 0o111 == 0
        || metadata.mode() & 0o022 != 0
        || ![0, unsafe { libc::geteuid() }].contains(&metadata.uid())
        || fs::canonicalize(path)? != path
    {
        return Err(denied());
    }
    // Installation binds this file to the normal checked-in cw binary. The
    // configuration is owner supplied, never an RPC-selectable executable.
    Ok(())
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "environment launch denied or expired",
    )
}

#[cfg(test)]
mod tests;
