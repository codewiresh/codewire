//! Claim-time wake knock for a paused `standard` warm-pool Pod (#5602,
//! `docs/dev/IDLE-STOP.md`, "Suspend"): once orchestration records a binding
//! for a `standard` Pod, one best-effort TCP connect to its port `7777` trips
//! `pod-runtime`'s `serve_published` wake path (`~50 ms`), resuming vCPUs,
//! delivering any renewed kubelet tokens while frozen, and thawing the guest
//! daemon so its `BindWorkspace` call completes immediately.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::sandbox::template::{RUNTIME_PROFILE_STANDARD, WORKSPACE_DAEMON_PORT};

/// Bound on one best-effort claim wake knock so an unreachable Pod never
/// leaks a background task.
const CLAIM_WAKE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How often [`super::bind_before_ready`] re-reads the whole chain past the
/// fast window while the caller waits.
pub(super) const EARLY_BIND_POLL: Duration = Duration::from_millis(500);
/// Warm adoption converges within a few hundred milliseconds of its claim.
pub(super) const EARLY_BIND_FAST_WINDOW: Duration = Duration::from_secs(2);
pub(super) const EARLY_BIND_FAST_POLL: Duration = Duration::from_millis(100);

pub(super) fn early_bind_poll(waited: Duration) -> Duration {
    if waited < EARLY_BIND_FAST_WINDOW {
        EARLY_BIND_FAST_POLL
    } else {
        EARLY_BIND_POLL
    }
}

/// Returns the `(pod_ip, port)` socket address to knock for a newly bound
/// `standard` Pod, or `None` for any other runtime profile or an invalid IP.
pub(super) fn claim_wake_target(runtime_profile: &str, pod_ip: &str) -> Option<SocketAddr> {
    if runtime_profile != RUNTIME_PROFILE_STANDARD {
        return None;
    }
    let ip: IpAddr = pod_ip.trim().parse().ok()?;
    let port = u16::try_from(WORKSPACE_DAEMON_PORT).ok()?;
    Some(SocketAddr::new(ip, port))
}

/// Fires one detached, best-effort TCP connect to `pod_ip:7777` when `env` is
/// a `standard` Sandbox so a paused warm-pool member wakes immediately after
/// its binding commits.
pub(super) fn wake_bound_standard_pod(environment_id: &str, runtime_profile: &str, pod_ip: &str) {
    let Some(target) = claim_wake_target(runtime_profile, pod_ip) else {
        return;
    };
    spawn_claim_wake_knock(environment_id.to_owned(), target);
}

pub(super) fn spawn_claim_wake_knock(
    environment_id: String,
    target: SocketAddr,
) -> tokio::task::JoinHandle<bool> {
    tokio::spawn(async move {
        match tokio::time::timeout(
            CLAIM_WAKE_CONNECT_TIMEOUT,
            tokio::net::TcpStream::connect(target),
        )
        .await
        {
            Ok(Ok(_stream)) => {
                tracing::debug!(
                    environment_id,
                    %target,
                    "sent claim wake knock to bound standard pod"
                );
                true
            }
            Ok(Err(error)) => {
                tracing::debug!(
                    environment_id,
                    %target,
                    %error,
                    "claim wake knock could not connect to bound standard pod"
                );
                false
            }
            Err(_) => {
                tracing::debug!(
                    environment_id,
                    %target,
                    "claim wake knock timed out connecting to bound standard pod"
                );
                false
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn claim_wake_target_selects_standard_profile_with_valid_ip_only() {
        assert_eq!(
            claim_wake_target("standard", "10.244.0.15"),
            Some(SocketAddr::from((Ipv4Addr::new(10, 244, 0, 15), 7777)))
        );
        assert_eq!(claim_wake_target("commodity", "10.244.0.15"), None);
        assert_eq!(claim_wake_target("", "10.244.0.15"), None);
        assert_eq!(claim_wake_target("standard", ""), None);
        assert_eq!(claim_wake_target("standard", "pod.example.internal"), None);
    }

    #[tokio::test]
    async fn claim_wake_knock_connects_to_target_port() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.is_ok() });

        let knocked = spawn_claim_wake_knock("env-warm-wake".to_owned(), addr)
            .await
            .unwrap();
        assert!(knocked);
        assert!(accept.await.unwrap());
    }
}
