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
    let bound = hosted_binding::bind_until_accepted(&client, &config).await;
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
    #[cfg(target_os = "linux")]
    let check = {
        let client = client.clone();
        async move {
            if carried {
                let dns = std::env::var(codewire_daemon_proto::CLUSTER_DNS_IP_ENV).ok();
                let passed = hosted_egress::guest_carried_self_check(
                    dns.and_then(|dns| dns.trim().parse().ok()),
                )
                .await?;
                // Its host key carries the result, which orchestration checks.
                client.set_guest_carried_self_check(passed);
            }
            Ok(())
        }
    };
    #[cfg(not(target_os = "linux"))]
    let check = std::future::ready(Ok(()));
    // A guest-carried daemon serves nothing until its self-check has passed
    // (cw-security, #5602): `serve_after` never polls the serving future
    // after a failed check, so nothing listens and no host key is recorded.
    // A standard Pod's `access_ready` is therefore evidence the check passed.
    serve_after(
        check,
        serve_bound(BoundServe {
            // A guest-carried daemon keeps the settings for its literal
            // routes (the binding's above) and runs no egress loop.
            #[cfg(target_os = "linux")]
            egress: egress.filter(|_| !carried),
            #[cfg(target_os = "linux")]
            refusal,
            #[cfg(target_os = "linux")]
            measured,
            #[cfg(target_os = "linux")]
            platform,
            paths,
            bound,
            daemon_config,
            client,
            pod_uid,
            defaults,
        }),
    )
    .await
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

/// Runs `check`, then `serve` only once `check` has passed. `serve` is a
/// future, so after a failed check it is never polled and nothing in it
/// starts.
async fn serve_after(
    check: impl std::future::Future<Output = anyhow::Result<()>>,
    serve: impl std::future::Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    check.await?;
    serve.await
}

/// What the bound daemon serves with, once bound.
struct BoundServe {
    #[cfg(target_os = "linux")]
    egress: Option<hosted_egress::EgressSettings>,
    #[cfg(target_os = "linux")]
    refusal: Option<codewire_daemon::platform_refusal::PlatformRefusal>,
    #[cfg(target_os = "linux")]
    measured: bool,
    #[cfg(target_os = "linux")]
    platform: Option<codewire_workspace_access::platform::DaemonPlatform>,
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
        egress,
        #[cfg(target_os = "linux")]
        refusal,
        #[cfg(target_os = "linux")]
        measured,
        #[cfg(target_os = "linux")]
        platform,
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
    if let Some(egress) = egress {
        // The egress trust is installed here, before serving (#4001, #6072).
        let health = refusal.as_ref().map(|refusal| refusal.egress());
        let trust = hosted_egress::start(egress, health.unwrap_or_default()).await?;
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

    use super::serve_after;

    #[tokio::test]
    async fn a_failed_check_never_starts_what_it_serves() {
        let served = Arc::new(AtomicBool::new(false));
        let serve = {
            let served = served.clone();
            async move {
                served.store(true, Ordering::SeqCst);
                Ok(())
            }
        };
        let failed = serve_after(async { anyhow::bail!("a probe was answered") }, serve).await;
        assert!(failed.is_err());
        assert!(!served.load(Ordering::SeqCst));

        let serve = {
            let served = served.clone();
            async move {
                served.store(true, Ordering::SeqCst);
                Ok(())
            }
        };
        serve_after(async { Ok(()) }, serve).await.unwrap();
        assert!(served.load(Ordering::SeqCst));
    }
}
