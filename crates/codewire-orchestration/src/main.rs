//! `codewire-orchestration` — entry point.
//!
//! Serves health/readiness plus two execution planes that share the
//! same handlers:
//!
//! - the Temporal worker (`TEMPORAL_HOST_PORT`) — the only trigger
//!   path after the D3 NATS retirement (owner decision 2026-06-12)
//! - leader-gated background loops (`WORKER_LOOPS`): the env reconciler,
//!   sandbox-liveness, and billing-session controller, whose enqueues
//!   SignalWithStart workflows; the warm-pool reconciler, inert until
//!   `SANDBOX_WARM_POOL_SHAPES` names a shape; plus the per-replica
//!   `image-cache` reconciler for the runtime-node image cache DaemonSet
//!
//! NATS is gone: there is no consumer plane and no `TENANT_LOCKS`
//! distributed lock — one workflow per environment id serializes
//! commands structurally.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use axum::middleware;
use codewire_orchestration::confidential_storage::{ConfidentialStorageManager, FeatureFlags};
use codewire_orchestration::worker::{self, cloudflare::CloudflareClient};
use codewire_server_core::{AppBuilder, ServiceConfig};
use tokio::net::TcpListener;

const DEFAULT_WORKER_LOOPS: &[&str] = &[
    "env-reconciler",
    "sandbox-liveness",
    "billing-session",
    "image-cache",
    "warm-pool",
];
const CONNECT_SYNTHETIC_USER_IDS_ENV: &str = "CONNECT_SYNTHETIC_USER_IDS";

const PUBLIC_CONNECT_METHODS: [&str; 1] = ["/codewire.v1.OrganizationService/GetInvitationByToken"];
const ORCHESTRATION_INTERNAL_CONNECT_PORT_ENV: &str = "ORCHESTRATION_INTERNAL_CONNECT_PORT";
const DEFAULT_ORCHESTRATION_INTERNAL_CONNECT_PORT: u16 = 8085;
const ORCHESTRATION_WORKSPACE_BINDING_PORT_ENV: &str =
    codewire_orchestration::workspace_binding::ORCHESTRATION_WORKSPACE_BINDING_PORT_ENV;

fn env_list(name: &str) -> Vec<String> {
    env_list_from(std::env::var(name).ok().as_deref())
}

fn env_list_from(value: Option<&str>) -> Vec<String> {
    value
        .map(parse_env_list)
        .unwrap_or_else(|| DEFAULT_WORKER_LOOPS.iter().map(|s| s.to_string()).collect())
}

fn parse_env_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_synthetic_user_ids(value: Option<&str>) -> anyhow::Result<BTreeSet<String>> {
    let Some(value) = value else {
        return Ok(BTreeSet::new());
    };
    if value.is_empty() {
        return Ok(BTreeSet::new());
    }

    let mut user_ids = BTreeSet::new();
    for (index, user_id) in value.split(',').enumerate() {
        if user_id.is_empty() || user_id.trim() != user_id || user_id.chars().any(char::is_control)
        {
            anyhow::bail!(
                "{CONNECT_SYNTHETIC_USER_IDS_ENV} entry {} must be a nonempty exact user ID",
                index + 1
            );
        }
        if !user_ids.insert(user_id.to_owned()) {
            anyhow::bail!(
                "{CONNECT_SYNTHETIC_USER_IDS_ENV} entry {} duplicates an earlier user ID",
                index + 1
            );
        }
    }
    Ok(user_ids)
}

fn internal_connect_bind_addr(
    public_bind_addr: SocketAddr,
    configured_port: Option<&str>,
) -> anyhow::Result<SocketAddr> {
    listener_bind_addr(
        public_bind_addr,
        ORCHESTRATION_INTERNAL_CONNECT_PORT_ENV,
        configured_port,
        DEFAULT_ORCHESTRATION_INTERNAL_CONNECT_PORT,
    )
}

fn workspace_binding_bind_addr(
    public_bind_addr: SocketAddr,
    configured_port: Option<&str>,
) -> anyhow::Result<SocketAddr> {
    listener_bind_addr(
        public_bind_addr,
        ORCHESTRATION_WORKSPACE_BINDING_PORT_ENV,
        configured_port,
        codewire_gateway_proto::WORKSPACE_BINDING_PORT,
    )
}

fn listener_bind_addr(
    public_bind_addr: SocketAddr,
    variable: &str,
    configured_port: Option<&str>,
    default_port: u16,
) -> anyhow::Result<SocketAddr> {
    let port = match configured_port
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => value
            .parse::<u16>()
            .with_context(|| format!("{variable}={value:?} must be a TCP port"))?,
        None => default_port,
    };
    Ok(SocketAddr::new(public_bind_addr.ip(), port))
}

struct Listeners {
    public: TcpListener,
    internal: TcpListener,
    workspace_binding: TcpListener,
}

/// Bind every orchestration listener before any one serves. If a later port
/// cannot bind, the earlier listeners are dropped while this error unwinds, so
/// startup cannot leave a partial process running.
async fn bind_listeners(
    public_bind_addr: SocketAddr,
    internal_bind_addr: SocketAddr,
    workspace_binding_bind_addr: SocketAddr,
) -> anyhow::Result<Listeners> {
    let public = TcpListener::bind(public_bind_addr)
        .await
        .with_context(|| format!("bind public orchestration listener {public_bind_addr}"))?;
    let internal = TcpListener::bind(internal_bind_addr)
        .await
        .with_context(|| format!("bind internal orchestration listener {internal_bind_addr}"))?;
    let workspace_binding = TcpListener::bind(workspace_binding_bind_addr)
        .await
        .with_context(|| {
            format!("bind workspace-binding orchestration listener {workspace_binding_bind_addr}")
        })?;
    tracing::info!(
        %public_bind_addr,
        %internal_bind_addr,
        %workspace_binding_bind_addr,
        "orchestration listeners bound"
    );
    Ok(Listeners {
        public,
        internal,
        workspace_binding,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = ServiceConfig::from_env("orchestration")?;
    codewire_server_core::obs::init(&cfg)?;
    let internal_connect_bind_addr = internal_connect_bind_addr(
        cfg.bind_addr,
        std::env::var(ORCHESTRATION_INTERNAL_CONNECT_PORT_ENV)
            .ok()
            .as_deref(),
    )?;
    let workspace_binding_bind_addr = workspace_binding_bind_addr(
        cfg.bind_addr,
        std::env::var(ORCHESTRATION_WORKSPACE_BINDING_PORT_ENV)
            .ok()
            .as_deref(),
    )?;
    let listeners = bind_listeners(
        cfg.bind_addr,
        internal_connect_bind_addr,
        workspace_binding_bind_addr,
    )
    .await?;

    codewire_server_core::migrate::ensure_schema_logged(&cfg.database_url).await?;
    let pool = codewire_server_core::db::connect(&cfg.database_url).await?;
    codewire_orchestration::resize_metrics::start_active_refresh(pool.clone());
    let confidential_storage_flags = FeatureFlags::from_env()?;

    let loops = env_list("WORKER_LOOPS");

    // The Temporal worker is mandatory: it is the only env lifecycle
    // execution path. A missing TEMPORAL_HOST_PORT is fatal (mirroring
    // Go's requiresTemporal handling) rather than silently degrading.
    let host_port = std::env::var("TEMPORAL_HOST_PORT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("codewire-orchestration requires TEMPORAL_HOST_PORT (NATS is retired)")
        })?;
    let namespace = std::env::var("TEMPORAL_NAMESPACE").unwrap_or_else(|_| "default".into());
    let task_queue = std::env::var("TEMPORAL_TASK_QUEUE")
        .unwrap_or_else(|_| codewire_orchestration::temporal::DEFAULT_TASK_QUEUE.into());

    // The trigger client (reconciler enqueues + the #38 API write
    // endpoints) SignalWithStarts the environment workflow. Connection
    // failure is fatal — there is no fallback path.
    let temporal_trigger = Arc::new(
        codewire_orchestration::temporal::TemporalTrigger::connect(
            &host_port,
            &namespace,
            &task_queue,
        )
        .await?,
    );

    // Ambient kube client (in-cluster or KUBECONFIG). Unavailable
    // mirrors the Go worker with a nil sandbox backend: setup health
    // checks pass and workspace execs fail warn-only.
    let kube = match kube::Client::try_default().await {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!(error = %e, "kube client unavailable; workspace exec disabled");
            None
        }
    };
    let confidential_storage = ConfidentialStorageManager::from_env(
        pool.clone(),
        confidential_storage_flags,
        kube.clone(),
    )?
    .map(Arc::new);

    let sandbox_cfg = worker::create::SandboxWorkerCfg::from_env();
    if kube.is_some()
        && let Err(error) = sandbox_cfg.require_workspace_binding_config()
    {
        panic!("{error}");
    }
    let synced_zones = codewire_orchestration::runtime_transport::sync_catalog_json(
        &pool,
        &sandbox_cfg.runtime_transport_zones_json,
    )
    .await?;
    if !synced_zones.is_empty() {
        tracing::info!(
            count = synced_zones.len(),
            "runtime transport-zone catalog synced"
        );
    }

    let secrets = Arc::new(worker::secrets::SecretStore::from_env_with_kube(
        pool.clone(),
        kube.clone(),
    )?);
    let ctx = Arc::new(worker::WorkerContext {
        pool: pool.clone(),
        cloudflare: CloudflareClient::from_env(),
        preview_base_domain: std::env::var("PREVIEW_BASE_DOMAIN").unwrap_or_default(),
        kube: kube.clone(),
        secrets: secrets.clone(),
        sandbox_cfg,
        confidential_storage: confidential_storage.clone(),
        temporal_trigger: temporal_trigger.clone(),
    });

    // Leader-gated background loops: the orchestration replicas elect a
    // leader to run the default Rust-owned loops. WORKER_LOOPS remains an
    // explicit override for focused local diagnostics.
    if !loops.is_empty() {
        worker::loops::start_loops(ctx.clone(), cfg.database_url.clone(), &loops);
    }

    // Temporal worker (#36): runs the EnvironmentWorkflow + PortDnsWorkflow
    // and their activities on the shared handlers.
    codewire_orchestration::temporal::spawn_temporal_worker(
        ctx.clone(),
        host_port,
        namespace,
        task_queue,
    );

    // Environments surface (#38): reads (slice 1) + lifecycle intents
    // (slice 2), served behind the same auth stack as billing; edge
    // stays on Go until the remaining write methods port (path-shared
    // routing).
    let auth = codewire_server_core::auth::AuthState { pool: pool.clone() };
    let synthetic_user_ids = parse_synthetic_user_ids(
        std::env::var(CONNECT_SYNTHETIC_USER_IDS_ENV)
            .ok()
            .as_deref(),
    )?;
    let environment_daemon_endpoints =
        codewire_orchestration::api::environment_daemon::EnvironmentDaemonEndpointOverrides::from_testing_config(
            codewire_server_core::connect_testing::enabled(),
            std::env::var(
                codewire_orchestration::api::environment_daemon::TEST_DAEMON_ENDPOINTS_ENV,
            )
            .ok()
            .as_deref(),
        )?;
    // One LISTEN connection serves every StreamLogs follower in this process.
    let environment_logs =
        codewire_orchestration::api::log_notifications::EnvironmentLogNotifications::new(
            codewire_orchestration::api::log_notifications::MAX_LIVE_FOLLOWS_PER_ACCOUNT,
        );
    codewire_orchestration::api::log_notifications::spawn_environment_log_listener(
        pool.clone(),
        environment_logs.clone(),
    );
    let api_state = codewire_orchestration::api::ApiState {
        pool: pool.clone(),
        preview_base_domain: std::env::var("PREVIEW_BASE_DOMAIN").unwrap_or_default(),
        frontend_url: std::env::var("FRONTEND_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:5173".into()),
        http_client: codewire_orchestration::api::preview::http_client()?,
        temporal_trigger,
        secrets: secrets.clone(),
        auth: auth.clone(),
        // Ambient kube client for the exec proxy; unavailable mirrors
        // Go's nil sandbox client (the route then 503s).
        kube,
        environment_daemon_endpoints,
        // Shared session secret for the internal gateway-binding token
        // issuance (Go: cfg.SessionSecret).
        session_secret: cfg.session_secret.clone(),
        sandbox_cfg: ctx.sandbox_cfg.clone(),
        confidential_storage_flags,
        environment_logs,
    };

    let connect_auth = codewire_server_core::connect::ConnectAuthLayer::authenticated(auth.clone())
        .allow_public(PUBLIC_CONNECT_METHODS)
        .synthetic_user_ids(synthetic_user_ids);
    let connect_admin = codewire_server_core::connect::ConnectAuthLayer::admin(auth.clone());
    let mesh_authorization = codewire_server_core::connect::MeshAuthorizationLayer::new(
        auth.clone(),
        cfg.session_secret.clone(),
        codewire_orchestration::connect::mesh_authorization::MESH_AUTHORIZATION_CALLER,
        codewire_orchestration::connect::mesh_authorization::MESH_AUTHORIZATION_METHOD,
    );

    // The workspace-binding listener is reachable from every tenant workload,
    // so it serves only WorkspaceBindingService under its own connection,
    // request and database limits. No health, metrics, REST, mesh or gateway
    // route shares port 8087, and this service is mounted nowhere else.
    let workspace_binding_notifications =
        Arc::new(codewire_orchestration::workspace_binding::BindingNotifications::default());
    codewire_orchestration::workspace_binding::spawn_binding_notification_listener(
        pool.clone(),
        workspace_binding_notifications.clone(),
    );
    let workspace_binding_app = codewire_orchestration::workspace_binding::app(
        codewire_orchestration::workspace_binding::workspace_binding_router(Arc::new(
            codewire_orchestration::workspace_binding::WorkspaceBindingState::new(
                api_state.kube.clone(),
                Arc::new(
                    codewire_orchestration::workspace_binding::PgBindingStore::connect_lazy(
                        &cfg.database_url,
                    )?,
                ),
                workspace_binding_notifications,
                &api_state.sandbox_cfg.sandbox_namespace,
                &cfg.session_secret,
            ),
        )),
    );

    // The internal listener is intentionally a minimal cluster-local surface:
    // no health, REST, public Connect, or edge-routed routes share port 8085.
    let internal_app = AppBuilder::new("codewire-orchestration-internal")
        .with_connect_routes(
            codewire_orchestration::connect::internal::gateway_binding_router(api_state.clone()),
        )
        .with_unary_connect_routes_mesh_authorization(
            codewire_orchestration::connect::mesh_authorization::router(pool.clone()),
            mesh_authorization,
        )
        .into_router();

    // The Transit canary costs OpenBao round trips, so a background loop
    // verifies it and `/readyz` reads the latest fail-closed verdict (#2430).
    let secret_readiness = worker::secret_readiness::SecretReadiness::spawn(
        worker::secret_readiness::SecretReadinessPolicy::default(),
        move || {
            let secrets = secrets.clone();
            async move { secrets.verify_readiness().await }
        },
    );
    let app = AppBuilder::new("codewire-orchestration")
        .with_health_and_db_probe(pool.clone(), move || {
            let ready = secret_readiness.is_ready();
            async move { ready }
        })
        .with_unary_connect_routes_auth(
            codewire_orchestration::connect::api_keys::router(pool.clone()),
            connect_auth.clone(),
        )
        .with_unary_connect_routes_auth(
            codewire_orchestration::connect::account::router(api_state.clone()),
            connect_auth.clone(),
        )
        .with_unary_connect_routes_auth(
            codewire_orchestration::connect::admin::router(api_state.clone()),
            connect_admin,
        )
        .with_unary_connect_routes_auth(
            codewire_orchestration::connect::environment_setup::router(api_state.clone()),
            connect_auth.clone(),
        )
        .with_unary_connect_routes_auth(
            codewire_orchestration::connect::presets::router(api_state.clone()),
            connect_auth.clone(),
        )
        .with_unary_connect_routes_auth(
            codewire_orchestration::connect::secrets::router(api_state.clone()),
            connect_auth.clone(),
        )
        .with_unary_connect_routes_auth(
            codewire_orchestration::connect::access_profiles::router(api_state.pool.clone()),
            connect_auth.clone(),
        )
        .with_unary_connect_routes_auth(
            codewire_orchestration::connect::credentials::router(api_state.pool.clone()),
            connect_auth.clone(),
        )
        .with_unary_connect_routes_auth(
            codewire_orchestration::connect::ports::router(api_state.clone()),
            connect_auth.clone(),
        )
        .with_unary_connect_routes_auth(
            codewire_orchestration::connect::organizations::router(api_state.clone()),
            connect_auth.clone(),
        )
        .with_unary_connect_routes_auth(
            codewire_orchestration::connect::environment::router(api_state.clone()),
            connect_auth.clone(),
        )
        .with_connect_routes_auth(
            codewire_orchestration::connect::exec::router(api_state.clone()),
            connect_auth.clone(),
        )
        .with_connect_routes_auth_and_protocol_policy(
            codewire_orchestration::connect::environment_session::router(api_state.clone()),
            connect_auth.clone(),
            codewire_server_core::connect::ProtocolPolicy::ConnectAndGrpc,
        )
        .with_connect_routes_auth(
            codewire_orchestration::connect::file::router(api_state.clone()),
            connect_auth,
        )
        // Connect conformance probe (doc 03 D8) — no-op unless
        // CONNECT_TESTING_SURFACE=1 (dev-stack/CI/kind only).
        .with_connect_testing_surface(auth.clone())
        .with_routes(codewire_orchestration::api::router(api_state.clone(), auth))
        .into_router()
        .layer(middleware::from_fn_with_state(
            api_state,
            codewire_orchestration::api::preview::preview_proxy_middleware,
        ));

    tokio::try_join!(
        codewire_server_core::serve_with_listener(app, listeners.public),
        codewire_server_core::serve_with_listener(internal_app, listeners.internal),
        codewire_server_core::bounded_http1::serve_bounded_http1(
            workspace_binding_app,
            listeners.workspace_binding,
            codewire_orchestration::workspace_binding::LISTENER_LIMITS,
        ),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_connect_listener_defaults_to_8085_on_the_public_bind_ip() {
        let public = SocketAddr::from(([127, 0, 0, 1], 8084));
        assert_eq!(
            internal_connect_bind_addr(public, None).unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 8085))
        );
    }

    #[test]
    fn workspace_binding_listener_defaults_to_8087_on_the_public_bind_ip() {
        let public = SocketAddr::from(([127, 0, 0, 1], 8084));
        assert_eq!(
            workspace_binding_bind_addr(public, None).unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 8087))
        );
        assert_eq!(
            workspace_binding_bind_addr(public, Some(" 18087 ")).unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 18087))
        );
        assert!(workspace_binding_bind_addr(public, Some("binding")).is_err());
    }

    async fn free_addr() -> SocketAddr {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        probe.local_addr().unwrap()
    }

    /// Every listener but `busy` binds; startup must fail and release them.
    async fn assert_listener_setup_fails_closed(busy: usize) {
        let blocker = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut addrs = [free_addr().await, free_addr().await, free_addr().await];
        addrs[busy] = blocker.local_addr().unwrap();
        assert!(bind_listeners(addrs[0], addrs[1], addrs[2]).await.is_err());
        for (index, addr) in addrs.iter().enumerate() {
            if index != busy {
                assert!(
                    TcpListener::bind(addr).await.is_ok(),
                    "listener {index} leaked"
                );
            }
        }
    }

    #[tokio::test]
    async fn listener_setup_fails_when_public_port_is_busy() {
        assert_listener_setup_fails_closed(0).await;
    }

    #[tokio::test]
    async fn listener_setup_fails_closed_when_internal_port_is_busy() {
        assert_listener_setup_fails_closed(1).await;
    }

    #[tokio::test]
    async fn listener_setup_fails_closed_when_workspace_binding_port_is_busy() {
        assert_listener_setup_fails_closed(2).await;
    }

    #[test]
    fn worker_loops_default_to_rust_owned_set() {
        assert_eq!(
            env_list_from(None),
            vec![
                "env-reconciler",
                "sandbox-liveness",
                "billing-session",
                "image-cache",
                "warm-pool",
            ]
        );
    }

    #[test]
    fn worker_loops_empty_override_disables_loops() {
        assert!(env_list_from(Some("")).is_empty());
    }

    #[test]
    fn worker_loops_parse_trimmed_override() {
        assert_eq!(
            env_list_from(Some(" env-reconciler, sandbox-liveness ,, ")),
            vec!["env-reconciler", "sandbox-liveness"]
        );
    }

    #[test]
    fn synthetic_user_ids_default_empty_and_parse_exact_values() {
        assert!(parse_synthetic_user_ids(None).unwrap().is_empty());
        assert!(parse_synthetic_user_ids(Some("")).unwrap().is_empty());
        assert_eq!(
            parse_synthetic_user_ids(Some("user-a,user-b")).unwrap(),
            BTreeSet::from(["user-a".to_owned(), "user-b".to_owned()])
        );
    }

    #[test]
    fn synthetic_user_ids_reject_malformed_or_ambiguous_values() {
        for value in [
            ",",
            "user-a,",
            ",user-a",
            "user-a,,user-b",
            " user-a",
            "user-a ",
            "user-a, user-b",
            "user-a,user-a",
            "user-a\n",
        ] {
            assert!(
                parse_synthetic_user_ids(Some(value)).is_err(),
                "value must reject: {value:?}"
            );
        }
    }

    #[test]
    fn public_connect_allowlist_contains_only_invitation_lookup() {
        assert_eq!(
            PUBLIC_CONNECT_METHODS,
            ["/codewire.v1.OrganizationService/GetInvitationByToken"]
        );
    }
}
