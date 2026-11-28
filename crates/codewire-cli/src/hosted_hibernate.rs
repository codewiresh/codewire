//! The hosted daemon's hibernate and post-restore re-bind in a `standard` VM
//! (#6647, `docs/dev/SANDBOX-SLEEP.md`).
//!
//! When orchestrated hibernate begins:
//! 1. `hold_for_hibernate` closes tailnet/coordinator/DERP (`PlatformQuiet::hold`)
//!    and pauses any broker egress stream.
//! 2. `ask_hibernate` asks `pod-runtime` over vsock 7784 to arm
//!    hibernate-on-SIGTERM. On refusal or transport error, `release_on_refusal`
//!    releases `PlatformQuiet` so the Sandbox continues running normally.
//! 3. After restore in the new Pod, `wait_for_restore_and_rebind`:
//!    - Waits for guest PID 1's immutable read-only restore settings file
//!      (`/run/codewire-hosted/restore/settings.json`) to carry a strictly
//!      newer `restore_generation`.
//!    - Shuts down the old Pod's `hosted_access::serve` task and awaits its
//!      exit so old `:2222` and old tailnet/disco sockets are completely gone,
//!      and stops the old Pod's broker egress stream.
//!    - Runs `BindWorkspace` over the new Pod's interface (`pod_dial`) and
//!      restarts broker egress concurrently (matching cold boot): `EgressService.Admit`
//!      reports the new Pod's front door hosts (#6290) so `BindWorkspace` can
//!      succeed and record the interception decision (C5), after which the
//!      egress retry is admitted and completes its self-check, then refreshes
//!      the guest's front-door CA bundle (or runs guest-carried self-check
//!      before binding).
//!    - Installs the new binding (`0400` `/codewire/run/daemon/credential`)
//!      and updates `app_ports` while keeping `PlatformQuiet` held.
//! 4. After `codewire-daemon` rotates the credential bridge and installs the
//!    new daemon credential (`complete_hosted_rebind`), `on_rebind_serving`
//!    releases `PlatformQuiet`, spawns a fresh `hosted_access::serve` (new
//!    SSH host key + new tailnet node/disco keys), and sends `rebind-ok\n`
//!    over vsock 7784 so `pod-runtime` deletes the memory file and opens Pod
//!    ports `7777` and `2222`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use codewire_daemon::WorkspaceBindingConfig;
use codewire_daemon::app_ports::AppPortsSender;
use codewire_daemon::hibernate::{HibernatePlatform, Pending, ReboundIdentity};
use codewire_daemon::hosted_state::HostedStatePaths;
use codewire_daemon::local_transport::LocalDaemonConnector;
use codewire_daemon::platform_refusal::PlatformRefusal;
use codewire_vmm_guest_probe::hosted_control::RestoreSettingsFile;
use codewire_workspace_access::quiet::PlatformQuiet;
use tokio::sync::{Mutex, watch};

use crate::hosted_access;
use crate::hosted_binding::{self, BindTiming, BindingClient, BindingRoots};
use crate::hosted_egress::{self, EgressHandle};

const RESTORE_SETTINGS_POLL: Duration = Duration::from_millis(50);
const REBIND_OK_ATTEMPTS: u32 = 10;
const REBIND_OK_RETRY: Duration = Duration::from_millis(200);

pub(crate) struct AccessTask {
    shutdown: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
}

impl AccessTask {
    pub(crate) fn new(shutdown: watch::Sender<bool>, join: tokio::task::JoinHandle<()>) -> Self {
        Self { shutdown, join }
    }

    async fn stop(self) -> Result<(), String> {
        self.stop_within(Duration::from_secs(5)).await
    }

    async fn stop_within(self, limit: Duration) -> Result<(), String> {
        let _ = self.shutdown.send(true);
        let abort = self.join.abort_handle();
        match tokio::time::timeout(limit, self.join).await {
            Ok(_) => Ok(()),
            Err(_) => {
                abort.abort();
                Err("timed out shutting down old workspace access before re-bind".to_owned())
            }
        }
    }
}

pub(crate) struct HostedHibernateConfig {
    pub binding_config: WorkspaceBindingConfig,
    pub paths: HostedStatePaths,
    pub timing: BindTiming,
    pub quiet: PlatformQuiet,
    pub connector: LocalDaemonConnector,
    pub app_ports: AppPortsSender,
    pub exec_shell: String,
    pub daemon_port: Option<u16>,
    pub measured: bool,
    pub carried: bool,
    pub refusal: Option<PlatformRefusal>,
    pub derp_extra_roots: codewire_tailnet::platform_dial::PlatformRoots,
    pub egress: Option<EgressHandle>,
    pub identity_tokens: crate::hosted_identity::SandboxTokens,
}

struct PendingAccess {
    bound: hosted_access::BoundAccess,
    client: Arc<BindingClient>,
}

pub(crate) struct HostedHibernate {
    config: HostedHibernateConfig,
    access: Mutex<Option<AccessTask>>,
    pending_access: Mutex<Option<PendingAccess>>,
    restore_settings_path: PathBuf,
    last_restore_generation: AtomicU64,
}

impl HostedHibernate {
    pub(crate) fn new(config: HostedHibernateConfig, access: AccessTask) -> Self {
        Self {
            config,
            access: Mutex::new(Some(access)),
            pending_access: Mutex::new(None),
            restore_settings_path: PathBuf::from(
                codewire_daemon_proto::HOSTED_DAEMON_RESTORE_SETTINGS_FILE,
            ),
            last_restore_generation: AtomicU64::new(0),
        }
    }

    async fn rebind_after_restore(&self) -> Result<ReboundIdentity, String> {
        let min_generation = self.last_restore_generation.load(Ordering::SeqCst);
        let settings =
            wait_for_restore_settings(&self.restore_settings_path, min_generation).await?;

        // Shut down the old Pod's workspace access (SSH :2222, tailnet, Mesh)
        // and stop the old Pod's broker egress stream before binding as the
        // new Pod. Fail re-bind closed (aborting the stuck task) if access
        // shutdown times out.
        if let Some(old_access) = self.access.lock().await.take() {
            old_access.stop().await?;
        }
        if let Some(handle) = self.config.egress.as_ref() {
            handle.stop_stream();
        }

        let new_pod_uid = settings
            .environment
            .get(codewire_daemon_proto::WORKSPACE_POD_UID_ENV)
            .filter(|uid| !uid.is_empty())
            .cloned()
            .ok_or_else(|| "restore settings missing CODEWIRE_POD_UID".to_owned())?;
        let new_binding_url = settings
            .environment
            .get(codewire_daemon_proto::WORKSPACE_BINDING_URL_ENV)
            .cloned();

        let restored_config = self
            .config
            .binding_config
            .for_restored_pod(new_pod_uid.clone(), new_binding_url)
            .map_err(|error| format!("invalid restored Pod binding config: {error}"))?;

        let lookup = |name: &str| {
            settings
                .environment
                .get(name)
                .cloned()
                .or_else(|| std::env::var(name).ok())
        };
        let os_lookup = |name: &str| lookup(name).map(std::ffi::OsString::from);

        let broker = codewire_daemon::BrokerPlatform::from_lookup(&os_lookup)
            .map_err(|error| format!("invalid restored broker platform settings: {error}"))?;
        let egress_settings = broker
            .as_ref()
            .map(|broker| hosted_egress::EgressSettings::from_broker(broker, &new_pod_uid, lookup))
            .transpose()
            .map_err(|error| format!("invalid restored egress settings: {error:#}"))?;
        let route = egress_settings
            .as_ref()
            .map(hosted_egress::EgressSettings::binding_route);

        let roots = match restored_config.measured() {
            Some(measured) => BindingRoots::Measured(measured.binding_roots_pem()),
            None => BindingRoots::Mounted(restored_config.tls_roots_file()),
        };
        let client = Arc::new(
            BindingClient::routed(
                restored_config.binding_url(),
                roots,
                restored_config.token_path(),
                self.config.timing,
                route,
            )
            .map_err(|error| format!("configure restored binding client: {error:#}"))?,
        );

        if self.config.carried {
            let dns = lookup(codewire_daemon_proto::CLUSTER_DNS_IP_ENV);
            let passed = hosted_egress::guest_carried_self_check(
                dns.and_then(|dns| dns.trim().parse().ok()),
            )
            .await
            .map_err(|error| format!("restored guest-carried self-check failed: {error:#}"))?;
            client.set_guest_carried_self_check(passed);
        }

        // Run `BindWorkspace` (over `pod_dial`) and broker egress restart
        // concurrently, matching cold boot (`hosted_daemon::bind_with_check_and_pause`):
        // - `BindWorkspace` waits for `EgressService.Admit` to report the Pod's
        //   front-door hosts (#6290 / `front_door_serves`), returning 503 until
        //   an admission attempt has reported.
        // - `EgressService.Admit` waits for `BindWorkspace` to record the Pod's
        //   interception decision (C5 / `egress::service::intercepts`),
        //   returning 503 until `BindWorkspace` succeeds.
        // Running them sequentially in either order deadlocks; running them
        // concurrently resolves the two-step handshake while keeping ports
        // 7777/2222 and PlatformQuiet closed until both pass.
        let (bound, trust) = run_bind_and_broker_egress_concurrently(
            hosted_binding::bind_until_accepted(&client, &restored_config),
            async {
                if let (Some(handle), Some(egress_settings)) =
                    (self.config.egress.as_ref(), egress_settings)
                    && !self.config.carried
                {
                    let trust = handle
                        .restart(
                            egress_settings,
                            self.config.refusal.clone().unwrap_or_default(),
                        )
                        .await
                        .map_err(|error| {
                            format!("restored Pod egress self-check failed: {error:#}")
                        })?;
                    Ok(Some(trust))
                } else {
                    Ok(None)
                }
            },
        )
        .await?;
        if let Some(trust) = trust {
            let mut interception = bound
                .binding
                .interception()
                .then(|| codewire_access::Interception::new(None));
            hosted_egress::install_trust(&trust, &mut interception)
                .map_err(|error| format!("install restored egress trust: {error:#}"))?;
        }
        self.config
            .paths
            .install_binding(&bound.binding)
            .map_err(|error| format!("install restored binding: {error:#}"))?;

        self.last_restore_generation
            .store(settings.restore_generation, Ordering::SeqCst);

        let _ = self.config.app_ports.send(
            bound
                .access
                .as_ref()
                .map(|grant| grant.app_ports().clone())
                .unwrap_or_default(),
        );

        let platform = broker
            .as_ref()
            .zip(self.config.refusal.clone())
            .map(|(broker, refusal)| {
                hosted_egress::daemon_platform(
                    broker,
                    refusal,
                    self.config.derp_extra_roots.clone(),
                )
            });
        // Rotate the shared identity-socket and token-file cache onto the new
        // Pod's binding client and drop any tokens cached before hibernate.
        crate::hosted_identity::replace_client(&self.config.identity_tokens, client.clone());
        let identity_tokens = self.config.identity_tokens.clone();

        // Hold the new workspace access (fresh per-generation SSH host key +
        // fresh tailnet node & disco keys) until `codewire-daemon` finishes
        // `complete_hosted_rebind` and calls `on_rebind_serving`.
        *self.pending_access.lock().await = Some(PendingAccess {
            bound: hosted_access::BoundAccess {
                environment_id: bound.binding.environment_id(),
                generation: bound.binding.operation_generation(),
                daemon_credential: bound.binding.daemon_credential().clone(),
                grant: bound.access.clone(),
                daemon_port: self.config.daemon_port,
                exec_shell: self.config.exec_shell.clone(),
                measured: self.config.measured,
                platform,
                identity_tokens,
            },
            client,
        });

        Ok(ReboundIdentity {
            daemon_credential: bound.binding.daemon_credential().clone(),
            environment_id: bound.binding.environment_id(),
            operation_generation: bound.binding.operation_generation(),
        })
    }

    async fn start_rebound_access(&self) {
        let Some(pending) = self.pending_access.lock().await.take() else {
            return;
        };
        self.config.quiet.release();
        let (access_shutdown, access_shutdown_rx) = watch::channel(false);
        let access = hosted_access::serve(
            self.config.paths.clone(),
            pending.bound,
            self.config.connector.clone(),
            pending.client,
            self.config.app_ports.clone(),
            self.config.quiet.clone(),
            access_shutdown_rx,
        );
        let join = tokio::spawn(async move {
            if let Err(error) = access.await {
                tracing::error!(
                    error = %format!("{error:#}"),
                    "restored workspace access stopped"
                );
            }
        });
        *self.access.lock().await = Some(AccessTask::new(access_shutdown, join));
    }
}

impl HibernatePlatform for HostedHibernate {
    fn hold_for_hibernate(&self) {
        self.config.quiet.hold();
        self.config.identity_tokens.clear_cache();
    }

    fn release_on_refusal(&self) {
        self.config.quiet.release();
    }

    fn ask_hibernate(&self) -> Pending<'_, std::io::Result<bool>> {
        Box::pin(codewire_vmm_guest_probe::hosted_control::request_hibernate())
    }

    fn wait_for_restore_and_rebind(&self) -> Pending<'_, Result<ReboundIdentity, String>> {
        Box::pin(self.rebind_after_restore())
    }

    fn on_rebind_serving(&self) -> Pending<'_, ()> {
        Box::pin(async {
            self.start_rebound_access().await;
            for attempt in 1..=REBIND_OK_ATTEMPTS {
                match codewire_vmm_guest_probe::hosted_control::notify_rebind_complete().await {
                    Ok(true) => {
                        tracing::info!("notified Pod runtime that post-restore re-bind succeeded");
                        return;
                    }
                    Ok(false) => {
                        tracing::warn!(attempt, "Pod runtime refused rebind-ok notification");
                        return;
                    }
                    Err(error) => {
                        tracing::warn!(
                            attempt,
                            error = %error,
                            "could not notify Pod runtime of rebind-ok"
                        );
                    }
                }
                if attempt < REBIND_OK_ATTEMPTS {
                    tokio::time::sleep(REBIND_OK_RETRY).await;
                }
            }
        })
    }
}

/// Polls `path` (mounted read-only by guest PID 1 at
/// `/run/codewire-hosted/restore/settings.json`) until it parses cleanly and
/// carries `restore_generation > last_seen_generation`.
async fn wait_for_restore_settings(
    path: &Path,
    last_seen_generation: u64,
) -> Result<RestoreSettingsFile, String> {
    loop {
        if let Some(settings) = read_newer_restore_settings(path, last_seen_generation)? {
            return Ok(settings);
        }
        tokio::time::sleep(RESTORE_SETTINGS_POLL).await;
    }
}

fn read_newer_restore_settings(
    path: &Path,
    last_seen_generation: u64,
) -> Result<Option<RestoreSettingsFile>, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("read restore settings file: {error}")),
    };
    let parsed: RestoreSettingsFile = match serde_json::from_slice(&bytes) {
        Ok(parsed) => parsed,
        Err(_) => return Ok(None),
    };
    if parsed.restore_generation > last_seen_generation {
        return Ok(Some(parsed));
    }
    Ok(None)
}

/// Runs `bind` and `restart_egress` concurrently so `EgressService.Admit` can
/// report the Pod's front-door hosts (#6290) for `BindWorkspace` while
/// `BindWorkspace` records the Pod's interception decision (C5) for
/// `EgressService.Admit`. Fails closed (cancelling `bind`) if `restart_egress`
/// returns an error.
async fn run_bind_and_broker_egress_concurrently<B, T, BindFut, EgressFut>(
    bind: BindFut,
    restart_egress: EgressFut,
) -> Result<(B, T), String>
where
    BindFut: std::future::Future<Output = B>,
    EgressFut: std::future::Future<Output = Result<T, String>>,
{
    tokio::try_join!(async move { Ok::<B, String>(bind.await) }, restart_egress)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[tokio::test]
    async fn restore_runs_bind_and_broker_egress_concurrently_for_two_step_handshake_and_fails_closed()
     {
        // Models the live #6290 + C5 two-step handshake:
        // 1. Egress admission reports front-door hosts.
        // 2. BindWorkspace waits for front-door hosts, then records interception.
        // 3. Egress admission waits for interception, then completes self-check.
        // Any sequential ordering (egress-first or bind-first) deadlocks.
        let (front_door_tx, front_door_rx) = tokio::sync::oneshot::channel::<()>();
        let (interception_tx, interception_rx) = tokio::sync::oneshot::channel::<()>();

        let (bound, trust) = tokio::time::timeout(
            Duration::from_secs(2),
            run_bind_and_broker_egress_concurrently(
                async move {
                    front_door_rx.await.unwrap();
                    interception_tx.send(()).unwrap();
                    "bound-ok"
                },
                async move {
                    front_door_tx.send(()).unwrap();
                    interception_rx.await.unwrap();
                    Ok("trust-ok")
                },
            ),
        )
        .await
        .expect("concurrent bind + broker egress handshake must not deadlock")
        .unwrap();
        assert_eq!(bound, "bound-ok");
        assert_eq!(trust, "trust-ok");

        // A failed restored egress self-check fails closed without returning
        // the binding for installation, even if bind has not completed yet.
        let err = run_bind_and_broker_egress_concurrently(
            std::future::pending::<&'static str>(),
            async { Err::<&'static str, String>("egress self-check failed".to_owned()) },
        )
        .await
        .unwrap_err();
        assert_eq!(err, "egress self-check failed");
    }

    #[test]
    fn restore_settings_poll_accepts_only_strictly_newer_generations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");

        // Absent file returns None.
        assert_eq!(read_newer_restore_settings(&path, 0).unwrap(), None);

        // Generation 2 is accepted when last seen is 0.
        let mut env = BTreeMap::new();
        env.insert(
            codewire_daemon_proto::WORKSPACE_POD_UID_ENV.to_owned(),
            "11111111-1111-4111-8111-111111111111".to_owned(),
        );
        let gen2 = RestoreSettingsFile {
            restore_generation: 2,
            environment: env.clone(),
        };
        std::fs::write(&path, serde_json::to_vec(&gen2).unwrap()).unwrap();
        assert_eq!(
            read_newer_restore_settings(&path, 0).unwrap(),
            Some(gen2.clone())
        );

        // Same or older generation is ignored (read-only mount semantics).
        assert_eq!(read_newer_restore_settings(&path, 2).unwrap(), None);
        assert_eq!(read_newer_restore_settings(&path, 3).unwrap(), None);

        // Strictly newer generation 3 is accepted.
        let gen3 = RestoreSettingsFile {
            restore_generation: 3,
            environment: env,
        };
        std::fs::write(&path, serde_json::to_vec(&gen3).unwrap()).unwrap();
        assert_eq!(read_newer_restore_settings(&path, 2).unwrap(), Some(gen3));
    }

    #[tokio::test]
    async fn access_task_stop_aborts_and_errors_on_timeout() {
        let (tx, _rx) = watch::channel(false);
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancelled_on_drop = Arc::clone(&cancelled);
        struct FlagOnDrop(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for FlagOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let join = tokio::spawn(async move {
            let _guard = FlagOnDrop(cancelled_on_drop);
            std::future::pending::<()>().await;
        });
        let task = AccessTask::new(tx, join);
        let err = task
            .stop_within(Duration::from_millis(20))
            .await
            .unwrap_err();
        assert!(err.contains("timed out"), "{err}");
        // Yield once so the aborted task runs its Drop handler.
        tokio::task::yield_now().await;
        assert!(
            cancelled.load(Ordering::SeqCst),
            "stuck old hosted_access task must be aborted on timeout"
        );
    }
}
