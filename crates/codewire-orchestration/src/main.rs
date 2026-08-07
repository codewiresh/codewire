//! `codewire-orchestration` — entry point.
//!
//! Serves health/readiness plus two execution planes that share the
//! same handlers:
//!
//! - the Temporal worker (`TEMPORAL_HOST_PORT`) — the only trigger
//!   path after the D3 NATS retirement (owner decision 2026-06-12)
//! - leader-gated background loops (`WORKER_LOOPS`): the env reconciler,
//!   sandbox-liveness, warm-pool reconciler, and billing-session
//!   controller, whose enqueues SignalWithStart workflows
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
    "warm-pool-reconciler",
    "billing-session",
];
const CONNECT_SYNTHETIC_USER_IDS_ENV: &str = "CONNECT_SYNTHETIC_USER_IDS";

const PUBLIC_CONNECT_METHODS: [&str; 1] = ["/codewire.v1.OrganizationService/GetInvitationByToken"];
const ORCHESTRATION_INTERNAL_CONNECT_PORT_ENV: &str = "ORCHESTRATION_INTERNAL_CONNECT_PORT";
const DEFAULT_ORCHESTRATION_INTERNAL_CONNECT_PORT: u16 = 8085;

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
    let port = match configured_port
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => value.parse::<u16>().with_context(|| {
            format!("{ORCHESTRATION_INTERNAL_CONNECT_PORT_ENV}={value:?} must be a TCP port")
        })?,
        None => DEFAULT_ORCHESTRATION_INTERNAL_CONNECT_PORT,
    };
    Ok(SocketAddr::new(public_bind_addr.ip(), port))
}

/// Bind both orchestration listeners before either one serves. If the internal
/// port cannot bind, the public listener is dropped while this error unwinds,
/// so startup cannot leave a public-only process running.
async fn bind_listeners(
    public_bind_addr: SocketAddr,
    internal_bind_addr: SocketAddr,
) -> anyhow::Result<(TcpListener, TcpListener)> {
    let public_listener = TcpListener::bind(public_bind_addr)
        .await
        .with_context(|| format!("bind public orchestration listener {public_bind_addr}"))?;
    let internal_listener = TcpListener::bind(internal_bind_addr)
        .await
        .with_context(|| format!("bind internal orchestration listener {internal_bind_addr}"))?;
    tracing::info!(%public_bind_addr, %internal_bind_addr, "orchestration listeners bound");
    Ok((public_listener, internal_listener))
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
    let (public_listener, internal_listener) =
        bind_listeners(cfg.bind_addr, internal_connect_bind_addr).await?;

    codewire_server_core::migrate::ensure_schema_logged(&cfg.database_url).await?;
    let pool = codewire_server_core::db::connect(&cfg.database_url).await?;
    codewire_orchestration::resize_metrics::start_active_refresh(pool.clone());
    let confidential_storage_flags = FeatureFlags::from_env()?;
    let confidential_storage =
        ConfidentialStorageManager::from_env(pool.clone(), confidential_storage_flags)?
            .map(Arc::new);

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

    let sandbox_cfg = worker::create::SandboxWorkerCfg::from_env();
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

    let ctx = Arc::new(worker::WorkerContext {
        pool: pool.clone(),
        cloudflare: CloudflareClient::from_env(),
        preview_base_domain: std::env::var("PREVIEW_BASE_DOMAIN").unwrap_or_default(),
        kube,
        secrets: worker::secrets::SecretStore::from_env(pool.clone()),
        github_cfg: worker::github::GitHubAppConfig::from_env(),
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
    let api_state = codewire_orchestration::api::ApiState {
        pool: pool.clone(),
        preview_base_domain: std::env::var("PREVIEW_BASE_DOMAIN").unwrap_or_default(),
        frontend_url: std::env::var("FRONTEND_URL")
            .unwrap_or_else(|_| "http://localhost:5173".into()),
        http_client: reqwest::Client::new(),
        temporal_trigger,
        anthropic_api_key: std::env::var("ANTHROPIC_API_KEY").unwrap_or_default(),
        github_cfg: worker::github::GitHubAppConfig::from_env(),
        secrets: Arc::new(worker::secrets::SecretStore::from_env(pool.clone())),
        auth: auth.clone(),
        // Ambient kube client for the exec proxy; unavailable mirrors
        // Go's nil sandbox client (the route then 503s).
        kube: kube::Client::try_default().await.ok(),
        // Shared session secret for the internal gateway-binding token
        // issuance (Go: cfg.SessionSecret).
        session_secret: cfg.session_secret.clone(),
        sandbox_cfg: ctx.sandbox_cfg.clone(),
        confidential_storage_flags,
    };

    let connect_auth = codewire_server_core::connect::ConnectAuthLayer::authenticated(auth.clone())
        .allow_public(PUBLIC_CONNECT_METHODS)
        .synthetic_user_ids(synthetic_user_ids);
    let connect_admin = codewire_server_core::connect::ConnectAuthLayer::admin(auth.clone());
    let connect_environment =
        codewire_server_core::connect::ConnectAuthLayer::environment_token(auth.clone());
    let mesh_authorization = codewire_server_core::connect::MeshAuthorizationLayer::new(
        auth.clone(),
        cfg.session_secret.clone(),
        codewire_orchestration::connect::mesh_authorization::MESH_AUTHORIZATION_CALLER,
        codewire_orchestration::connect::mesh_authorization::MESH_AUTHORIZATION_METHOD,
    );

    // The internal listener is intentionally a minimal cluster-local surface:
    // no health, REST, public Connect, or edge-routed routes share port 8085.
    let internal_app = AppBuilder::new("codewire-orchestration-internal")
        .with_connect_routes(
            codewire_orchestration::connect::internal::gateway_binding_router(api_state.clone()),
        )
        .with_unary_connect_routes_auth(
            codewire_orchestration::connect::internal::environment_credentials_router(
                api_state.clone(),
            ),
            connect_environment,
        )
        .with_unary_connect_routes_mesh_authorization(
            codewire_orchestration::connect::mesh_authorization::router(pool.clone()),
            mesh_authorization,
        )
        .into_router();

    let app = AppBuilder::new("codewire-orchestration")
        .with_health_and_db(pool.clone())
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
            codewire_orchestration::connect::github::router(api_state.clone()),
            connect_auth.clone(),
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
        codewire_server_core::serve_with_listener(app, public_listener),
        codewire_server_core::serve_with_listener(internal_app, internal_listener),
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

    #[tokio::test]
    async fn listener_setup_fails_closed_when_internal_port_is_busy() {
        let busy_internal = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let internal_addr = busy_internal.local_addr().unwrap();
        let public_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let public_addr = public_probe.local_addr().unwrap();
        drop(public_probe);

        assert!(bind_listeners(public_addr, internal_addr).await.is_err());
        // A failed internal bind released the pre-bound public listener.
        let rebound_public = TcpListener::bind(public_addr).await;
        assert!(rebound_public.is_ok());
    }

    #[tokio::test]
    async fn listener_setup_fails_when_public_port_is_busy() {
        let busy_public = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let public_addr = busy_public.local_addr().unwrap();
        let internal_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let internal_addr = internal_probe.local_addr().unwrap();
        drop(internal_probe);

        assert!(bind_listeners(public_addr, internal_addr).await.is_err());
        let rebound_internal = TcpListener::bind(internal_addr).await;
        assert!(rebound_internal.is_ok());
    }

    #[test]
    fn worker_loops_default_to_rust_owned_set() {
        assert_eq!(
            env_list_from(None),
            vec![
                "env-reconciler",
                "sandbox-liveness",
                "warm-pool-reconciler",
                "billing-session",
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
