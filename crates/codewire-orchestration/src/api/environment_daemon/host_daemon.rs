//! A host environment's daemon (#3609, slice 2): reached through a tunnel
//! from its host's session on this replica, and authorized with the running
//! generation's daemon capability, as `cw --local` reaches a local VM's.

use std::sync::{Mutex, PoisonError};

use hyper_util::rt::TokioIo;
use zeroize::Zeroizing;

use super::*;
use crate::api::host_tunnels::{HostTunnels, TUNNEL_OPEN_SECS, TunnelTarget};

/// Where the first tunnel's capability waits for the caller. Only the first
/// is kept, until taken; a later connection's is dropped at once, so the
/// channel holds none.
enum CapabilitySlot {
    Waiting,
    Opened(Zeroizing<String>),
    Taken,
}

/// A channel to the daemon of `target`, and the capability its requests
/// carry. Each connection the channel makes is one tunnel.
pub(super) async fn host_daemon_channel(
    tunnels: Arc<HostTunnels>,
    target: TunnelTarget,
    budget: DaemonRequestBudget,
) -> AppResult<(Channel, String)> {
    let capability = Arc::new(Mutex::new(CapabilitySlot::Waiting));
    let opened_capability = Arc::clone(&capability);
    let environment_id = target.environment_id.clone();
    let channel = Endpoint::from_static("http://codewire-host-tunnel")
        // The tunnel's own open bound decides, so a slow host is answered
        // `TimedOut`, not cut off before it.
        .connect_timeout(Duration::from_secs(TUNNEL_OPEN_SECS + 1))
        .executor(codewire_server_core::span_free::DetachedExecutor);
    let channel = match budget.timeout() {
        Some(timeout) => channel.timeout(timeout),
        None => channel,
    }
    .connect_with_connector(tower::service_fn(move |_| {
        let tunnels = Arc::clone(&tunnels);
        let target = target.clone();
        let opened_capability = Arc::clone(&opened_capability);
        async move {
            let opened = tunnels.open(&target).await.map_err(std::io::Error::other)?;
            let mut slot = opened_capability
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if matches!(*slot, CapabilitySlot::Waiting) {
                *slot = CapabilitySlot::Opened(opened.daemon_capability);
            }
            Ok::<_, std::io::Error>(TokioIo::new(opened.stream))
        }
    }))
    .await
    .map_err(|error| {
        let error = daemon_connect_failure(error);
        tracing::warn!(environment_id, %error, "open host environment daemon tunnel failed");
        AppError::ServiceUnavailable("the environment's host is unavailable; try again".into())
    })?;
    let slot = std::mem::replace(
        &mut *capability.lock().unwrap_or_else(PoisonError::into_inner),
        CapabilitySlot::Taken,
    );
    let CapabilitySlot::Opened(token) = slot else {
        return Err(AppError::InternalMsg(
            "the host tunnel opened without a capability".into(),
        ));
    };
    // The client API takes a plain String for now (#4577); it lives only for
    // this call.
    Ok((channel, token.as_str().to_owned()))
}
