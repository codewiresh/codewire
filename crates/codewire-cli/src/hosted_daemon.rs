//! The bound hosted daemon's start: bind, install the binding, then serve.

use anyhow::Context as _;

#[cfg(target_os = "linux")]
use crate::{hosted_access, hosted_egress};
use crate::{hosted_binding, serve_hosted_daemon};

/// Identity-free Pod (Program #2238 B2): mark local readiness, bind, install
/// the bound credential, then prepare Codex's home and listen.
///
/// Nothing listens before an accepted binding: no TCP listener (the daemon's
/// 7777, SSH's 2222, the bridge's loopback 38081) and no UDP socket (the
/// tailnet's 31000). SSH on 2222 has `none` auth, so its NetworkPolicy is its
/// only authorization. The warm-pool template's NetworkPolicy admits
/// orchestration's identity to unbound members on TCP 7777 and 2222 from
/// birth (#3626). A listener there before the bind would hand a shell to
/// anyone holding that identity. `hosted_binding`'s `nothing_listens` tests
/// pin this.
pub(crate) async fn run_bound_hosted_daemon(
    config: codewire_daemon::WorkspaceBindingConfig,
) -> anyhow::Result<()> {
    run_bound_hosted_daemon_with(
        config,
        codewire_daemon::hosted_state::HostedStatePaths::default(),
        hosted_binding::BindTiming::default(),
    )
    .await
}

/// [`run_bound_hosted_daemon`] with its state paths and binding pacing given,
/// so a test runs it unprivileged and fast. Production passes the defaults.
pub(crate) async fn run_bound_hosted_daemon_with(
    config: codewire_daemon::WorkspaceBindingConfig,
    paths: codewire_daemon::hosted_state::HostedStatePaths,
    timing: hosted_binding::BindTiming,
) -> anyhow::Result<()> {
    paths
        .mark_ready()
        .context("write hosted daemon readiness marker")?;
    // A confidential workspace (B2c) trusts only its measured roots for the
    // binding listener, never the host-supplied mounted ones.
    let roots = match config.measured() {
        Some(measured) => hosted_binding::BindingRoots::Measured(measured.binding_roots_pem()),
        None => hosted_binding::BindingRoots::Mounted(config.tls_roots_file()),
    };
    tracing::info!(
        measured = config.measured().is_some(),
        "hosted environment daemon waiting for its workspace binding"
    );
    // A broker-mode Pod's default route is its egress TUN (#4000): it reaches
    // the binding and its other platform peers at their configured addresses
    // by the Pod interface, and serves nothing until its first egress
    // self-check has passed.
    #[cfg(target_os = "linux")]
    if config.broker().is_some() {
        hosted_egress::prove_pod_interface()?;
    }
    // A standard Pod's guest carries the daemon's egress (#5602): its
    // platform dials keep broker mode's literal routes, with no egress loop.
    #[cfg(target_os = "linux")]
    let carried = hosted_egress::guest_carried(config.broker().is_some())?;
    // Either way it carries the daemon, which only a standard guest's can
    // suspend (#5529).
    #[cfg(target_os = "linux")]
    let standard_guest = hosted_egress::standard_guest()?;
    #[cfg(target_os = "linux")]
    let egress = config
        .broker()
        .map(|broker| {
            hosted_egress::EgressSettings::from_broker(broker, config.pod_uid(), |name| {
                std::env::var(name).ok()
            })
        })
        .transpose()?;
    // What the tailnet refuses in broker mode, reported by GetHealth.
    #[cfg(target_os = "linux")]
    let refusal = config
        .broker()
        .map(|_| codewire_daemon::platform_refusal::PlatformRefusal::default());
    // The relay's certificate may chain to the deployment's own authority,
    // mounted with the coordinator's; a confidential workspace trusts the
    // WebPKI roots only.
    #[cfg(target_os = "linux")]
    let derp_extra_roots = hosted_egress::derp_extra_roots(
        config.broker().is_some(),
        config.measured().is_some(),
        std::path::Path::new(codewire_daemon_proto::COORDINATOR_EXTRA_ROOTS_MOUNT_PATH),
        "ca.crt",
    )
    .context("read the deployment's extra roots for its DERP relay")?;
    #[cfg(target_os = "linux")]
    let platform = config
        .broker()
        .zip(refusal.clone())
        .map(|(broker, refusal)| hosted_egress::daemon_platform(broker, refusal, derp_extra_roots));
    #[cfg(target_os = "linux")]
    let route = egress
        .as_ref()
        .map(hosted_egress::EgressSettings::binding_route);
    #[cfg(not(target_os = "linux"))]
    let route = None;
    let client = std::sync::Arc::new(
        hosted_binding::BindingClient::routed(
            config.binding_url(),
            roots,
            config.token_path(),
            timing,
            route,
        )
        .context("configure workspace binding client")?,
    );
    // Only the Linux access server distinguishes a measured daemon.
    #[cfg(target_os = "linux")]
    let measured = config.measured().is_some();
    // Start the egress check / stream alongside workspace binding so the 2 s
    // silent-UDP self-check overlaps readiness and binding on cold creates and
    // finishes before claim on warm-pool members (#6200, #5602). A failing
    // check exits while unbound, and `serve_after` never starts serving until
    // it passes.
    #[cfg(target_os = "linux")]
    let check = {
        let client = client.clone();
        let health = refusal.as_ref().map(|refusal| refusal.egress());
        async move {
            if carried {
                let dns = std::env::var(codewire_daemon_proto::CLUSTER_DNS_IP_ENV).ok();
                let passed = hosted_egress::guest_carried_self_check(
                    dns.and_then(|dns| dns.trim().parse().ok()),
                )
                .await?;
                // Its host key carries the result, which orchestration checks.
                client.set_guest_carried_self_check(passed);
                Ok(None)
            } else if let Some(egress) = egress {
                let trust = hosted_egress::start(egress, health.unwrap_or_default()).await?;
                Ok(Some(trust))
            } else {
                Ok(None)
            }
        }
    };
    #[cfg(not(target_os = "linux"))]
    let check = std::future::ready(anyhow::Ok(()));
    let (bound, check) =
        bind_with_check(hosted_binding::bind_until_accepted(&client, &config), check).await?;
    paths
        .install_binding(&bound.binding)
        .context("install hosted daemon binding")?;
    // The binding was accepted for exactly this Pod.
    let pod_uid = config.pod_uid().to_owned();
    let daemon_config = config.into_config(&bound.binding);
    #[cfg(target_os = "linux")]
    hosted_egress::refuse_carried_interception(carried, daemon_config.interception.is_some())?;
    #[cfg(target_os = "linux")]
    codewire_daemon::login_cleanup::clear_logins_for_bound_environment(
        &daemon_config,
        bound.binding.environment_id(),
    );
    // The saved project defaults and Git author (#3684), before the access
    // task can record the host key: orchestration's access proof therefore
    // comes after this write. No defaults, as from an older server, reports
    // nothing, and setup writes them itself.
    let defaults = apply_defaults(&daemon_config, &bound).await;
    // Nothing serves until the egress self-check has passed (cw-security,
    // #4000, #5602): `serve_after` never creates or polls the serving future
    // after a failed check, so nothing listens and no host key is recorded.
    serve_after(check.finish(), |trust| {
        let _ = &trust;
        serve_bound(BoundServe {
            #[cfg(target_os = "linux")]
            trust,
            #[cfg(target_os = "linux")]
            refusal,
            #[cfg(target_os = "linux")]
            measured,
            #[cfg(target_os = "linux")]
            platform,
            #[cfg(target_os = "linux")]
            standard_guest,
            paths,
            bound,
            daemon_config,
            client,
            pod_uid,
            defaults,
        })
    })
    .await
}

/// The pre-bind egress check state returned by [`bind_with_check`].
enum PendingCheck<T> {
    Ready(Option<T>),
    Running(Option<tokio::task::JoinHandle<anyhow::Result<T>>>),
}

impl<T> Drop for PendingCheck<T> {
    fn drop(&mut self) {
        if let Self::Running(Some(handle)) = self {
            handle.abort();
        }
    }
}

impl<T> PendingCheck<T> {
    async fn finish(mut self) -> anyhow::Result<T> {
        match &mut self {
            Self::Ready(value) => value
                .take()
                .ok_or_else(|| anyhow::anyhow!("egress self-check result already consumed")),
            Self::Running(handle) => match handle.take() {
                Some(handle) => flatten_check(handle.await),
                None => anyhow::bail!("egress self-check task already consumed"),
            },
        }
    }
}

fn flatten_check<T>(
    result: Result<anyhow::Result<T>, tokio::task::JoinError>,
) -> anyhow::Result<T> {
    result.map_err(|error| anyhow::anyhow!("egress self-check panicked: {error}"))?
}

/// Runs `bind` and `check` together. If `check` fails while the daemon is
/// still unbound, returns that error at once so an unhealthy unbound Pod exits
/// instead of staying ready in a warm pool. If `check` passes first, keeps
/// waiting for `bind` and returns an already-passed result. If `bind` wins,
/// returns the still-running task so post-bind setup overlaps with it while
/// [`serve_after`] still gates serving on it.
async fn bind_with_check<B, T: Send + 'static>(
    bind: impl std::future::Future<Output = B>,
    check: impl std::future::Future<Output = anyhow::Result<T>> + Send + 'static,
) -> anyhow::Result<(B, PendingCheck<T>)> {
    let mut handle = tokio::spawn(check);
    tokio::pin!(bind);
    tokio::select! {
        bound = &mut bind => Ok((bound, PendingCheck::Running(Some(handle)))),
        result = &mut handle => {
            let value = flatten_check(result)?;
            Ok((bind.await, PendingCheck::Ready(Some(value))))
        }
    }
}

/// The bind's saved project defaults applied, or nothing when the server
/// sent none.
async fn apply_defaults(
    daemon_config: &codewire_daemon::Config,
    bound: &hosted_binding::BoundWorkspace,
) -> Option<codewire_daemon::workspace_defaults::DefaultsOutcome> {
    let defaults = bound.defaults.as_ref()?;
    Some(
        codewire_daemon::workspace_defaults::apply(
            daemon_config,
            bound.binding.operation_generation(),
            defaults,
        )
        .await,
    )
}

/// Runs `check`, then calls `serve` only once `check` has passed. After a
/// failed check `serve` is never called, so nothing in it starts.
async fn serve_after<T, Fut>(
    check: impl std::future::Future<Output = anyhow::Result<T>>,
    serve: impl FnOnce(T) -> Fut,
) -> anyhow::Result<()>
where
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let passed = check.await?;
    serve(passed).await
}

/// What the bound daemon serves with, once bound.
struct BoundServe {
    /// The first broker egress session's trust, ready to install before serving.
    #[cfg(target_os = "linux")]
    trust: Option<codewire_network_session::EgressTrust>,
    #[cfg(target_os = "linux")]
    refusal: Option<codewire_daemon::platform_refusal::PlatformRefusal>,
    #[cfg(target_os = "linux")]
    measured: bool,
    #[cfg(target_os = "linux")]
    platform: Option<codewire_workspace_access::platform::DaemonPlatform>,
    /// A standard VM's guest carries this daemon, in either egress mode,
    /// which can then suspend.
    #[cfg(target_os = "linux")]
    standard_guest: bool,
    paths: codewire_daemon::hosted_state::HostedStatePaths,
    bound: hosted_binding::BoundWorkspace,
    daemon_config: codewire_daemon::Config,
    client: std::sync::Arc<hosted_binding::BindingClient>,
    pod_uid: String,
    defaults: Option<codewire_daemon::workspace_defaults::DefaultsOutcome>,
}

/// Installs the egress trust, starts workspace access and serves the bound
/// daemon until it exits.
async fn serve_bound(serve: BoundServe) -> anyhow::Result<()> {
    let BoundServe {
        #[cfg(target_os = "linux")]
        trust,
        #[cfg(target_os = "linux")]
        refusal,
        #[cfg(target_os = "linux")]
        measured,
        #[cfg(target_os = "linux")]
        platform,
        #[cfg(target_os = "linux")]
        standard_guest,
        paths,
        bound,
        daemon_config,
        client,
        pod_uid,
        defaults,
    } = serve;
    #[cfg(target_os = "linux")]
    let mut daemon_config = daemon_config;
    #[cfg(target_os = "linux")]
    if let Some(trust) = trust {
        // The egress trust is installed here, before serving (#4001, #6072).
        hosted_egress::install_trust(&trust, &mut daemon_config.interception)?;
    }
    // Workspace access (#2460): the daemon serves SSH itself, reaching its
    // own gRPC service in-process, and the environment's application ports
    // on its tailnet address.
    let (connector, local) = codewire_daemon::local_transport::local_transport();
    let (app_ports, _) = tokio::sync::watch::channel(
        bound
            .access
            .as_ref()
            .map(|grant| grant.app_ports().clone())
            .unwrap_or_default(),
    );
    #[cfg(target_os = "linux")]
    {
        // Idle stop's activity (#3384): inbound traffic through the access
        // server, and the Sandbox's CPU each minute. A daemon that starts, or
        // restarts mid-build, counts as use, so its restart never ends the
        // Sandbox before its CPU is next sampled.
        codewire_daemon::activity::touch();
        codewire_workspace_access::activity::set_hook(codewire_daemon::activity::touch);
        let _cpu_sampler = codewire_daemon::activity::spawn_cpu_sampler();
        let (_access_shutdown, access_shutdown_rx) = tokio::sync::watch::channel(false);
        let daemon_port = daemon_config
            .listen_addr
            .parse::<std::net::SocketAddr>()
            .map(|address| address.port())
            .ok();
        // One token cache for the identity socket and the token files.
        let identity_tokens = crate::hosted_identity::tokens(client.clone());
        // Held closed while the daemon suspends, which only a daemon a
        // standard VM's guest carries does, guest-carried or broker (#5529).
        let quiet = codewire_workspace_access::quiet::PlatformQuiet::new();
        if standard_guest {
            codewire_daemon::suspend::install(std::sync::Arc::new(
                crate::hosted_suspend::HostedSuspend::new(quiet.clone(), client.clone()),
            ));
        }
        let access = hosted_access::serve(
            paths.clone(),
            hosted_access::BoundAccess {
                environment_id: bound.binding.environment_id(),
                generation: bound.binding.operation_generation(),
                daemon_credential: bound.binding.daemon_credential().clone(),
                grant: bound.access.clone(),
                daemon_port,
                exec_shell: codewire_daemon::env::default_shell_for(&daemon_config),
                measured,
                platform,
                identity_tokens: identity_tokens.clone(),
            },
            connector,
            client.clone(),
            app_ports.clone(),
            quiet,
            access_shutdown_rx,
        );
        tokio::spawn(async move {
            // The sender lives as long as the access task, which ends with
            // the daemon process.
            let _keep = _access_shutdown;
            if let Err(error) = access.await {
                tracing::error!(error = %format!("{error:#}"), "workspace access stopped");
            }
        });
        crate::hosted_identity::spawn(&paths.identity_socket, identity_tokens);
    }
    // Only the Linux access server uses the connector, paths and client.
    #[cfg(not(target_os = "linux"))]
    drop((connector, paths, client));
    serve_hosted_daemon(
        daemon_config,
        true,
        Some(local),
        Some(app_ports),
        Some(pod_uid),
        defaults,
        #[cfg(target_os = "linux")]
        refusal,
        #[cfg(not(target_os = "linux"))]
        None,
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::{bind_with_check, serve_after};

    #[tokio::test]
    async fn a_failed_check_never_starts_what_it_serves() {
        let served = Arc::new(AtomicBool::new(false));
        let failed = serve_after(async { anyhow::bail!("a probe was answered") }, |()| {
            let served = served.clone();
            async move {
                served.store(true, Ordering::SeqCst);
                Ok(())
            }
        })
        .await;
        assert!(failed.is_err());
        assert!(!served.load(Ordering::SeqCst));

        serve_after(async { Ok(42_u32) }, |value| {
            let served = served.clone();
            async move {
                assert_eq!(value, 42);
                served.store(true, Ordering::SeqCst);
                Ok(())
            }
        })
        .await
        .unwrap();
        assert!(served.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn a_check_that_passes_before_bind_makes_post_bind_wait_immediate() {
        let (bind_tx, bind_rx) = tokio::sync::oneshot::channel();
        let driver = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            bind_tx.send("bound").unwrap();
        });
        let (bound, pending) = bind_with_check(async move { bind_rx.await.unwrap() }, async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            Ok("trust")
        })
        .await
        .unwrap();
        driver.await.unwrap();
        assert_eq!(bound, "bound");

        let after_bind = tokio::time::Instant::now();
        let value = pending.finish().await.unwrap();
        assert_eq!(value, "trust");
        assert_eq!(after_bind.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn a_check_that_fails_while_unbound_stops_before_bind_completes() {
        let error = bind_with_check::<(), ()>(std::future::pending::<()>(), async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            anyhow::bail!("a probe was answered")
        })
        .await
        .err()
        .expect("a failing check must return an error while unbound");
        assert!(
            error.to_string().contains("a probe was answered"),
            "{error}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_bind_that_completes_first_still_gates_serving_on_the_running_check() {
        let (bound, pending) = bind_with_check(
            async {
                tokio::time::sleep(Duration::from_millis(400)).await;
                "bound"
            },
            async {
                tokio::time::sleep(Duration::from_secs(2)).await;
                Ok("trust")
            },
        )
        .await
        .unwrap();
        assert_eq!(bound, "bound");
        let started = tokio::time::Instant::now();
        let served = Arc::new(AtomicBool::new(false));
        serve_after(pending.finish(), |value| {
            let served = served.clone();
            async move {
                assert_eq!(value, "trust");
                served.store(true, Ordering::SeqCst);
                Ok(())
            }
        })
        .await
        .unwrap();
        assert!(served.load(Ordering::SeqCst));
        // Overlapped with the 400 ms bind, only ~1.6 s remained after bind.
        assert!(started.elapsed() <= Duration::from_millis(1_700));

        // If the still-running check fails after bind, serving never starts.
        let (_, failing) = bind_with_check(async { "bound" }, async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            anyhow::bail!("probe reached")
        })
        .await
        .unwrap();
        let served_after_fail = Arc::new(AtomicBool::new(false));
        let err = serve_after(failing.finish(), |()| {
            let served_after_fail = served_after_fail.clone();
            async move {
                served_after_fail.store(true, Ordering::SeqCst);
                Ok(())
            }
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("probe reached"), "{err}");
        assert!(!served_after_fail.load(Ordering::SeqCst));
    }
}
