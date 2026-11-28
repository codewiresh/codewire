//! Claim-time wake knock for a paused `standard` warm-pool Pod (#5602, #6718,
//! `docs/dev/IDLE-STOP.md`, "Suspend"): once orchestration records a binding
//! for a `standard` Pod — or reconciles an already-recorded binding during
//! create, start or resize — one best-effort TCP connect to its port `7777`
//! trips `pod-runtime`'s `serve_published` wake path (`~50 ms`), resuming
//! vCPUs, delivering any renewed kubelet tokens while frozen, and thawing the
//! guest daemon so its `BindWorkspace` call completes immediately.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::super::env_data::EnvironmentRow;
use super::WriteOutcome;
use crate::sandbox::template::{RUNTIME_PROFILE_STANDARD, WORKSPACE_DAEMON_PORT};

/// Bound on one best-effort claim wake knock so an unreachable Pod never
/// leaks a background task.
const CLAIM_WAKE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Non-running bindable states in which an already-recorded
/// (`WriteOutcome::Unchanged`) `standard` binding still wakes on retry or
/// reconcile (#6718).
///
/// Only `running` Sandboxes can be user- or idle-suspended (`suspended_at`),
/// so excluding `running` (and any unknown state) guarantees an intentionally
/// suspended Sandbox is never woken by an unchanged reconcile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetryWakeState {
    Pending,
    Creating,
    Starting,
    Resizing,
}

impl RetryWakeState {
    fn parse(state: &str) -> Option<Self> {
        match state {
            "pending" => Some(Self::Pending),
            "creating" => Some(Self::Creating),
            "starting" => Some(Self::Starting),
            "resizing" => Some(Self::Resizing),
            _ => None,
        }
    }
}

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

/// Whether a committed binding write should send a wake knock to a `standard`
/// Pod.
///
/// - `WriteOutcome::Recorded` always wakes: this call just bound a fresh Pod
///   UID that may be paused in the warm pool waiting for its claim.
/// - `WriteOutcome::Unchanged` wakes only when both `env_state` and every
///   fenced state in `states` are non-running startup/recovery states. Because
///   the fenced transaction already verified `environments.state IN states`,
///   requiring every allowed state to exclude `running` guarantees a suspended
///   `running` Sandbox is never woken.
pub(super) fn should_wake_bound_standard_pod(
    outcome: WriteOutcome,
    env_state: &str,
    states: &[&str],
) -> bool {
    match outcome {
        WriteOutcome::Recorded => true,
        WriteOutcome::Unchanged => {
            !states.is_empty()
                && RetryWakeState::parse(env_state).is_some()
                && states
                    .iter()
                    .all(|state| RetryWakeState::parse(state).is_some())
        }
    }
}

/// Returns the `(pod_ip, port)` socket address to knock for a `standard` Pod,
/// or `None` for any other runtime profile or an invalid IP.
pub(super) fn claim_wake_target(runtime_profile: &str, pod_ip: &str) -> Option<SocketAddr> {
    let port = u16::try_from(WORKSPACE_DAEMON_PORT).ok()?;
    claim_wake_target_on_port(runtime_profile, pod_ip, port)
}

fn claim_wake_target_on_port(runtime_profile: &str, pod_ip: &str, port: u16) -> Option<SocketAddr> {
    if runtime_profile != RUNTIME_PROFILE_STANDARD {
        return None;
    }
    let ip: IpAddr = pod_ip.trim().parse().ok()?;
    Some(SocketAddr::new(ip, port))
}

/// Returns the wake socket address for a committed binding write, or `None`
/// when this outcome/state must not wake, for any non-`standard` runtime
/// profile, or for an invalid IP.
pub(super) fn claim_wake_target_for_bind(
    outcome: WriteOutcome,
    env_state: &str,
    states: &[&str],
    runtime_profile: &str,
    pod_ip: &str,
) -> Option<SocketAddr> {
    if !should_wake_bound_standard_pod(outcome, env_state, states) {
        return None;
    }
    claim_wake_target(runtime_profile, pod_ip)
}

#[cfg(test)]
tokio::task_local! {
    static TEST_WAKE_OBSERVER: std::sync::Arc<std::sync::Mutex<Vec<(String, SocketAddr)>>>;
}

/// Runs `future` while capturing every wake target [`wake_bound_standard_pod`]
/// would knock in this task instead of dialing the network.
#[cfg(test)]
pub(super) async fn capture_wake_knocks<F, T>(future: F) -> (T, Vec<(String, SocketAddr)>)
where
    F: std::future::Future<Output = T>,
{
    let recorded = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let value = TEST_WAKE_OBSERVER
        .scope(std::sync::Arc::clone(&recorded), future)
        .await;
    let knocks = recorded
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    (value, knocks)
}

/// Fires one detached, best-effort TCP connect to `pod_ip:7777` when `env` is
/// a `standard` Sandbox whose binding write should wake a paused warm-pool
/// member.
pub(super) fn wake_bound_standard_pod(
    outcome: WriteOutcome,
    env: &EnvironmentRow,
    states: &[&str],
    pod_ip: &str,
) {
    let Some(target) =
        claim_wake_target_for_bind(outcome, &env.state, states, &env.runtime_profile, pod_ip)
    else {
        return;
    };
    #[cfg(test)]
    if TEST_WAKE_OBSERVER
        .try_with(|recorded| {
            recorded
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((env.id.clone(), target));
        })
        .is_ok()
    {
        return;
    }
    spawn_claim_wake_knock(env.id.clone(), target);
}

#[cfg(test)]
fn wake_bound_standard_pod_on_port(
    outcome: WriteOutcome,
    env_id: &str,
    env_state: &str,
    states: &[&str],
    runtime_profile: &str,
    pod_ip: &str,
    port: u16,
) -> Option<tokio::task::JoinHandle<bool>> {
    if !should_wake_bound_standard_pod(outcome, env_state, states) {
        return None;
    }
    let target = claim_wake_target_on_port(runtime_profile, pod_ip, port)?;
    Some(spawn_claim_wake_knock(env_id.to_owned(), target))
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

    #[test]
    fn unchanged_binding_wakes_only_on_create_start_and_resize_states_for_standard() {
        let expected = Some(SocketAddr::from((Ipv4Addr::new(10, 244, 0, 15), 7777)));
        // Freshly recorded bindings always wake for a standard Pod.
        for state in ["pending", "creating", "starting", "resizing", "running"] {
            assert_eq!(
                claim_wake_target_for_bind(
                    WriteOutcome::Recorded,
                    state,
                    &[state],
                    "standard",
                    "10.244.0.15",
                ),
                expected,
                "Recorded should wake in state {state}"
            );
        }

        // #6718: retry/reconcile with an already-committed binding wakes on
        // create, start and resize paths so a re-paused warm-pool member wakes.
        for (state, states) in [
            ("pending", &["pending"][..]),
            ("creating", &["creating"][..]),
            ("creating", &["pending", "creating", "starting"][..]),
            ("starting", &["starting"][..]),
            ("resizing", &["resizing"][..]),
        ] {
            assert_eq!(
                claim_wake_target_for_bind(
                    WriteOutcome::Unchanged,
                    state,
                    states,
                    "standard",
                    "10.244.0.15",
                ),
                expected,
                "Unchanged should wake for state={state} states={states:?}"
            );
        }

        // Never wake a running (potentially user- or idle-suspended) Sandbox or
        // any non-startup state on WriteOutcome::Unchanged, nor when the fenced
        // state set allows `running`.
        for (state, states) in [
            ("running", &["running"][..]),
            ("creating", &["creating", "running"][..]),
            ("creating", &[][..]),
            ("suspended", &["suspended"][..]),
            ("suspending", &["suspending"][..]),
            ("stopped", &["stopped"][..]),
            ("stopping", &["stopping"][..]),
            ("error", &["error"][..]),
            ("destroyed", &["destroyed"][..]),
        ] {
            assert_eq!(
                claim_wake_target_for_bind(
                    WriteOutcome::Unchanged,
                    state,
                    states,
                    "standard",
                    "10.244.0.15",
                ),
                None,
                "Unchanged must not wake for state={state} states={states:?}"
            );
        }

        // Non-standard profiles and invalid/empty IPs never wake on Unchanged.
        for (profile, ip) in [
            ("commodity", "10.244.0.15"),
            ("confidential", "10.244.0.15"),
            ("", "10.244.0.15"),
            ("standard", ""),
            ("standard", "not-an-ip"),
        ] {
            assert_eq!(
                claim_wake_target_for_bind(
                    WriteOutcome::Unchanged,
                    "creating",
                    &["creating"],
                    profile,
                    ip,
                ),
                None,
                "Unchanged must not wake for profile={profile:?} ip={ip:?}"
            );
        }
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

    #[tokio::test]
    async fn unchanged_create_reconcile_fires_tcp_wake_knock_and_running_does_not() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move { listener.accept().await.is_ok() });

        let handle = wake_bound_standard_pod_on_port(
            WriteOutcome::Unchanged,
            "env-warm-retry",
            "creating",
            &["creating"],
            "standard",
            "127.0.0.1",
            port,
        )
        .expect("unchanged standard create reconcile must dispatch a wake knock");
        assert!(handle.await.unwrap());
        assert!(accept.await.unwrap());

        assert!(
            wake_bound_standard_pod_on_port(
                WriteOutcome::Unchanged,
                "env-suspended-running",
                "running",
                &["running"],
                "standard",
                "127.0.0.1",
                port,
            )
            .is_none(),
            "unchanged running reconcile must not dispatch a wake knock"
        );
        assert!(
            wake_bound_standard_pod_on_port(
                WriteOutcome::Unchanged,
                "env-commodity-retry",
                "creating",
                &["creating"],
                "commodity",
                "127.0.0.1",
                port,
            )
            .is_none(),
            "commodity create reconcile must not dispatch a wake knock"
        );
    }
}
