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
//!   `SANDBOX_WARM_POOL_SHAPES` names a shape; the credential relay, inert
//!   without the platform credential runtime; plus the per-replica
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
use codewire_tls::{ServerTlsFiles, TlsListener};
use tokio::net::TcpListener;

const DEFAULT_WORKER_LOOPS: &[&str] = &[
    "env-reconciler",
    "sandbox-liveness",
    "billing-session",
    "image-cache",
    "warm-pool",
    "credential-relay",
];
const CONNECT_SYNTHETIC_USER_IDS_ENV: &str = "CONNECT_SYNTHETIC_USER_IDS";

const PUBLIC_CONNECT_METHODS: [&str; 1] = ["/codewire.v1.OrganizationService/GetInvitationByToken"];
// The internal Connect app (Mesh authorization) is served only behind TLS.
const ORCHESTRATION_INTERNAL_TLS_PORT_ENV: &str = "ORCHESTRATION_INTERNAL_TLS_PORT";
const DEFAULT_ORCHESTRATION_INTERNAL_TLS_PORT: u16 =
    codewire_daemon_proto::ORCHESTRATION_INTERNAL_TLS_PORT;
const ORCHESTRATION_INTERNAL_TLS_CERT_FILE_ENV: &str = "ORCHESTRATION_INTERNAL_TLS_CERT_FILE";
const ORCHESTRATION_INTERNAL_TLS_KEY_FILE_ENV: &str = "ORCHESTRATION_INTERNAL_TLS_KEY_FILE";
const ORCHESTRATION_WORKSPACE_BINDING_PORT_ENV: &str =
    codewire_orchestration::workspace_binding::ORCHESTRATION_WORKSPACE_BINDING_PORT_ENV;

/// Public origin of the coordinator a workspace daemon joins its tailnet
/// through. Defaults to the public API origin, whose ingress routes
/// `CoordinatorService` to the coordinator.
const SANDBOX_PUBLIC_COORDINATOR_URL_ENV: &str = "CODEWIRE_SANDBOX_PUBLIC_COORDINATOR_URL";

fn sandbox_public_coordinator_url(configured: Option<&str>, api_base_url: &str) -> String {
    configured
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(api_base_url.trim())
        .trim_end_matches('/')
        .to_owned()
}

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

fn internal_tls_bind_addr(
    public_bind_addr: SocketAddr,
    configured_port: Option<&str>,
) -> anyhow::Result<SocketAddr> {
    listener_bind_addr(
        public_bind_addr,
        ORCHESTRATION_INTERNAL_TLS_PORT_ENV,
        configured_port,
        DEFAULT_ORCHESTRATION_INTERNAL_TLS_PORT,
    )
}

/// The mounted identity of the internal TLS listener: both files or neither.
/// Neither serves no internal API at all.
fn internal_tls_files(
    cert_file: Option<&str>,
    key_file: Option<&str>,
) -> anyhow::Result<Option<ServerTlsFiles>> {
    fn present(value: Option<&str>) -> Option<&str> {
        value.map(str::trim).filter(|value| !value.is_empty())
    }
    match (present(cert_file), present(key_file)) {
        (None, None) => Ok(None),
        (Some(cert_file), Some(key_file)) => Ok(Some(
            ServerTlsFiles::new(cert_file.into(), key_file.into()).with_context(|| {
                format!(
                    "{ORCHESTRATION_INTERNAL_TLS_CERT_FILE_ENV} and \
                     {ORCHESTRATION_INTERNAL_TLS_KEY_FILE_ENV} must be distinct absolute files"
                )
            })?,
        )),
        _ => anyhow::bail!(
            "{ORCHESTRATION_INTERNAL_TLS_CERT_FILE_ENV} and \
             {ORCHESTRATION_INTERNAL_TLS_KEY_FILE_ENV} must be set together"
        ),
    }
}

/// Inside a cluster, Mesh reaches the internal API, so it is served there,
/// and only over TLS. A process outside a cluster (the checked-in
/// `scripts/dev/dev-stack.sh` and integration verification, which blanks
/// `KUBERNETES_SERVICE_HOST`) has no Mesh to serve and runs without it; there
/// is no plaintext form.
fn internal_tls_required(in_cluster: bool, tls_configured: bool) -> anyhow::Result<()> {
    anyhow::ensure!(
        !in_cluster || tls_configured,
        "inside a cluster the internal API is served only over TLS: set \
         {ORCHESTRATION_INTERNAL_TLS_CERT_FILE_ENV} and {ORCHESTRATION_INTERNAL_TLS_KEY_FILE_ENV}"
    );
    Ok(())
}

/// Fail closed unless the public roots workspaces mount exist in the sandbox
/// namespace and verify the mounted leaf for the names their clients use. A
/// daemon rendered against missing or mismatched roots would otherwise retry
/// its binding forever.
async fn verify_internal_tls_roots(
    kube: Option<&kube::Client>,
    files: &ServerTlsFiles,
    sandbox_namespace: &str,
    roots_configmap: &str,
    server_namespace: &str,
) -> anyhow::Result<()> {
    let kube = kube.context(
        "the internal TLS listener needs the Kubernetes API to check its published roots",
    )?;
    anyhow::ensure!(
        !server_namespace.trim().is_empty(),
        "the internal TLS listener needs POD_NAMESPACE for its DNS name"
    );
    let configmaps: kube::Api<k8s_openapi::api::core::v1::ConfigMap> =
        kube::Api::namespaced(kube.clone(), sandbox_namespace);
    let roots = configmaps
        .get_opt(roots_configmap)
        .await
        .with_context(|| format!("read ConfigMap {sandbox_namespace}/{roots_configmap}"))?
        .with_context(|| {
            format!(
                "internal TLS roots ConfigMap {sandbox_namespace}/{roots_configmap} does not exist"
            )
        })?
        .data
        .and_then(|mut data| data.remove("ca.crt"))
        .with_context(|| {
            format!(
                "internal TLS roots ConfigMap {sandbox_namespace}/{roots_configmap} has no ca.crt"
            )
        })?;
    // Mesh verifies the internal API's name; workspace daemons verify the
    // binding listener's name with the same roots.
    for host in [
        codewire_orchestration::sandbox::template::orchestration_internal_tls_host(
            server_namespace,
        ),
        codewire_orchestration::worker::create::workspace_binding_tls_host(server_namespace),
    ] {
        files
            .verify_against_roots(roots.as_bytes(), &host)
            .await
            .with_context(|| {
                format!(
                    "the internal TLS leaf is not trusted for {host} by ConfigMap \
                     {sandbox_namespace}/{roots_configmap}"
                )
            })?;
    }
    Ok(())
}

/// The binding listener's public roots that confidential workspaces measure
/// (Program #2238 B2c): the issuing CA that cert-manager publishes as
/// `ca.crt` beside the mounted internal leaf. It comes from orchestration's
/// own Secret, never the tenant-namespace ConfigMap, and must verify that
/// leaf for the binding listener's name. Best effort: without it no
/// confidential workspace renders, and nothing else depends on it. A CA
/// change applies to confidential renders after the next restart.
async fn confidential_binding_roots(
    files: Option<&ServerTlsFiles>,
    cert_file: Option<&str>,
    server_namespace: &str,
) -> String {
    let (Some(files), Some(cert_file)) = (files, cert_file) else {
        return String::new();
    };
    let Some(ca_file) = std::path::Path::new(cert_file.trim())
        .parent()
        .map(|directory| directory.join("ca.crt"))
    else {
        return String::new();
    };
    let pem = match tokio::fs::read(&ca_file).await {
        Ok(pem)
            if pem.len() <= codewire_daemon_proto::WORKSPACE_MEASURED_BINDING_ROOTS_MAX_BYTES =>
        {
            pem
        }
        Ok(_) => {
            tracing::error!(
                "internal TLS issuing CA is too large to measure; confidential workspaces are unavailable"
            );
            return String::new();
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!(
                "no internal TLS issuing CA beside the leaf; confidential workspaces are unavailable"
            );
            return String::new();
        }
        Err(error) => {
            tracing::error!(error = %error, "read internal TLS issuing CA; confidential workspaces are unavailable");
            return String::new();
        }
    };
    let host = codewire_orchestration::worker::create::workspace_binding_tls_host(server_namespace);
    if let Err(error) = files.verify_against_roots(&pem, &host).await {
        tracing::error!(error = %error, "the internal TLS issuing CA does not verify the binding listener; confidential workspaces are unavailable");
        return String::new();
    }
    match String::from_utf8(pem) {
        Ok(pem) => pem,
        Err(_) => {
            tracing::error!(
                "internal TLS issuing CA is not text; confidential workspaces are unavailable"
            );
            String::new()
        }
    }
}

fn workspace_binding_bind_addr(
    public_bind_addr: SocketAddr,
    configured_port: Option<&str>,
) -> anyhow::Result<SocketAddr> {
    listener_bind_addr(
        public_bind_addr,
        ORCHESTRATION_WORKSPACE_BINDING_PORT_ENV,
        configured_port,
        codewire_daemon_proto::WORKSPACE_BINDING_PORT,
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
    /// The TLS internal listener; `None` when no internal API is served.
    internal: Option<TcpListener>,
    workspace_binding: TcpListener,
}

/// Bind every orchestration listener before any one serves. If a later port
/// cannot bind, the earlier listeners are dropped while this error unwinds, so
/// startup cannot leave a partial process running.
async fn bind_listeners(
    public_bind_addr: SocketAddr,
    internal_bind_addr: Option<SocketAddr>,
    workspace_binding_bind_addr: SocketAddr,
) -> anyhow::Result<Listeners> {
    let public = TcpListener::bind(public_bind_addr)
        .await
        .with_context(|| format!("bind public orchestration listener {public_bind_addr}"))?;
    let internal = match internal_bind_addr {
        Some(addr) => Some(
            TcpListener::bind(addr)
                .await
                .with_context(|| format!("bind internal TLS orchestration listener {addr}"))?,
        ),
        None => None,
    };
    let workspace_binding = TcpListener::bind(workspace_binding_bind_addr)
        .await
        .with_context(|| {
            format!("bind workspace-binding orchestration listener {workspace_binding_bind_addr}")
        })?;
    tracing::info!(
        %public_bind_addr,
        ?internal_bind_addr,
        %workspace_binding_bind_addr,
        "orchestration listeners bound"
    );
    Ok(Listeners {
        public,
        internal,
        workspace_binding,
    })
}

/// The deployment names the images every workspace runs; there are no
/// defaults (docs/CONFIGURATION.md).
fn require_runtime_images() -> anyhow::Result<()> {
    use codewire_orchestration::sandbox::runtime_images;
    runtime_images::init().map_err(anyhow::Error::msg)?;
    if std::env::var(runtime_images::DAEMON_IMAGE_ENV).is_ok_and(|image| !image.trim().is_empty()) {
        Ok(())
    } else {
        anyhow::bail!(runtime_images::missing(runtime_images::DAEMON_IMAGE_ENV))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = ServiceConfig::from_env("orchestration")?;
    let tracing_guard = codewire_server_core::obs::init_with_traces(&cfg)?;
    require_runtime_images()?;
    let workspace_binding_bind_addr = workspace_binding_bind_addr(
        cfg.bind_addr,
        std::env::var(ORCHESTRATION_WORKSPACE_BINDING_PORT_ENV)
            .ok()
            .as_deref(),
    )?;
    let internal_tls = internal_tls_files(
        std::env::var(ORCHESTRATION_INTERNAL_TLS_CERT_FILE_ENV)
            .ok()
            .as_deref(),
        std::env::var(ORCHESTRATION_INTERNAL_TLS_KEY_FILE_ENV)
            .ok()
            .as_deref(),
    )?;
    internal_tls_required(
        std::env::var("KUBERNETES_SERVICE_HOST").is_ok_and(|host| !host.trim().is_empty()),
        internal_tls.is_some(),
    )?;
    if let Some(files) = &internal_tls {
        // Fail closed: a configured identity that cannot serve never starts.
        // Each handshake then reloads the mounted files, so rotation needs no
        // restart.
        files
            .validate()
            .await
            .context("validate the internal TLS listener identity")?;
    }
    let internal_bind_addr = internal_tls
        .as_ref()
        .map(|_| {
            internal_tls_bind_addr(
                cfg.bind_addr,
                std::env::var(ORCHESTRATION_INTERNAL_TLS_PORT_ENV)
                    .ok()
                    .as_deref(),
            )
        })
        .transpose()?;
    let listeners = bind_listeners(
        cfg.bind_addr,
        internal_bind_addr,
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
    // Span-free connections (#3581): a request that opens a connection
    // must not keep its span open for the connection's life.
    let kube = match codewire_server_core::span_free::kube_client_default().await {
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

    let mut sandbox_cfg = worker::create::SandboxWorkerCfg::from_env();
    if kube.is_some()
        && let Err(error) = sandbox_cfg.require_workspace_binding_config()
    {
        panic!("{error}");
    }
    if let Some(files) = &internal_tls {
        verify_internal_tls_roots(
            kube.as_ref(),
            files,
            &sandbox_cfg.sandbox_namespace,
            codewire_orchestration::sandbox::template::ORCHESTRATION_INTERNAL_ROOTS_CONFIGMAP,
            &sandbox_cfg.pod_namespace,
        )
        .await?;
    }
    sandbox_cfg.confidential_binding_roots_pem = confidential_binding_roots(
        internal_tls.as_ref(),
        std::env::var(ORCHESTRATION_INTERNAL_TLS_CERT_FILE_ENV)
            .ok()
            .as_deref(),
        &sandbox_cfg.pod_namespace,
    )
    .await;
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
    // #3572: a replica that runs the warm-pool loop, starting while a release
    // rotates its pools, reports ready and starts its Temporal worker only once
    // its own revision's pools have a ready member (bounded), so a release
    // hands over from full pools. Any other start is warm at once.
    let (pools_warm_sender, pools_warm) = tokio::sync::watch::channel(true);
    if loops.iter().any(|name| name == "warm-pool") {
        pools_warm_sender.send_replace(false);
        let ctx = ctx.clone();
        tokio::spawn(async move {
            worker::warm_pool::warm_own_pools(ctx, pools_warm_sender).await;
        });
    }

    // Temporal worker (#36): runs the EnvironmentWorkflow + PortDnsWorkflow
    // and their activities on the shared handlers.
    {
        let ctx = ctx.clone();
        let mut pools_warm = pools_warm.clone();
        tokio::spawn(async move {
            worker::warm_pool::pools_warmed(&mut pools_warm).await;
            codewire_orchestration::temporal::spawn_temporal_worker(
                ctx, host_port, namespace, task_queue,
            );
        });
    }

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
        // Shared session secret for daemon tokens and preview authorization.
        session_secret: cfg.session_secret.clone(),
        terminal_ticket_replays: std::sync::Arc::new(
            codewire_orchestration::api::terminal::TerminalTicketReplayCache::default(),
        ),
        org_slugs: std::sync::Arc::new(codewire_orchestration::api::preview::OrgSlugCache::new(
            std::time::Duration::from_secs(5),
        )),
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
    // request and database limits. No health, metrics, REST or mesh
    // route shares port 8087, and this service is mounted nowhere else.
    let workspace_binding_notifications =
        Arc::new(codewire_orchestration::workspace_binding::BindingNotifications::default());
    codewire_orchestration::workspace_binding::spawn_binding_notification_listener(
        pool.clone(),
        workspace_binding_notifications.clone(),
    );
    // Its daemons get the public coordinator and relay endpoints; the relay
    // allocator and its token stay here.
    let workspace_binding_state = Arc::new(
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
        )
        .with_access(
            codewire_orchestration::workspace_binding::AccessSettings {
                coordinator_url: sandbox_public_coordinator_url(
                    std::env::var(SANDBOX_PUBLIC_COORDINATOR_URL_ENV)
                        .ok()
                        .as_deref(),
                    &api_state.sandbox_cfg.api_base_url,
                ),
                mesh_url: api_state.sandbox_cfg.mesh_public_url.clone(),
            },
            Arc::new(
                codewire_orchestration::workspace_binding::HttpRelayAllocator::new(Some(
                    api_state.sandbox_cfg.udp_relay_allocator_token.clone(),
                )),
            ),
        ),
    );
    // There is no plaintext form: inside a cluster it serves TLS with the
    // internal identity, and outside one no workspace exists to call it, so
    // it is not served.
    let workspace_binding_tls = internal_tls
        .clone()
        .map(codewire_orchestration::workspace_binding::WorkspaceBindingTls);
    let workspace_binding_app = codewire_orchestration::workspace_binding::app(
        codewire_orchestration::workspace_binding::workspace_binding_router(
            workspace_binding_state,
        ),
    );

    // The internal listener is intentionally a minimal cluster-local surface:
    // no health, REST, public Connect, or edge-routed routes share its TLS
    // port 8088.
    let internal_app = AppBuilder::new("codewire-orchestration-internal")
        .with_unary_connect_routes_mesh_authorization(
            codewire_orchestration::connect::mesh_authorization::router(pool.clone()),
            mesh_authorization,
        )
        // Hosted Mesh's questions about environment members (#3350), behind
        // a service-only credential signed with this hop's own derived key.
        .with_unary_connect_routes_internal_service(
            codewire_orchestration::environment_mesh::environment_mesh_router(pool.clone()),
            codewire_orchestration::environment_mesh::internal_service_layer(&cfg.session_secret)?,
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
            let ready = secret_readiness.is_ready() && *pools_warm.borrow();
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
            codewire_orchestration::connect::environment_cw_runtime::router(api_state.clone()),
            connect_auth.clone(),
        )
        .with_unary_connect_routes_auth(
            codewire_orchestration::connect::environment_agent::router(api_state.clone()),
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

    let internal_tls = match (listeners.internal, internal_tls) {
        (Some(listener), Some(files)) => Some((
            TlsListener::new(listener, files).context("internal TLS listener")?,
            internal_app,
        )),
        _ => None,
    };
    let served = tokio::try_join!(
        codewire_server_core::serve_with_listener(app, listeners.public),
        async {
            match internal_tls {
                Some((listener, app)) => {
                    codewire_server_core::serve_with_axum_listener(app, listener).await
                }
                None => Ok(()),
            }
        },
        async {
            match workspace_binding_tls {
                Some(tls) => {
                    codewire_server_core::bounded_http1::serve_bounded_http1_upgraded(
                        workspace_binding_app,
                        listeners.workspace_binding,
                        codewire_orchestration::workspace_binding::LISTENER_LIMITS,
                        tls,
                    )
                    .await
                }
                None => Ok(()),
            }
        },
    );
    // Flush queued spans before the process exits.
    tracing_guard.shutdown().await;
    served?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Distinct free addresses: every probe is held until all are chosen, so
    /// the kernel cannot hand one port out twice.
    async fn free_addrs<const N: usize>() -> [SocketAddr; N] {
        let mut probes = Vec::with_capacity(N);
        for _ in 0..N {
            probes.push(TcpListener::bind("127.0.0.1:0").await.unwrap());
        }
        std::array::from_fn(|index| probes[index].local_addr().unwrap())
    }

    /// Every listener but `busy` binds; startup must fail and release them.
    async fn assert_listener_setup_fails_closed(busy: usize) {
        let blocker = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut addrs = free_addrs::<3>().await;
        addrs[busy] = blocker.local_addr().unwrap();
        assert!(
            bind_listeners(addrs[0], Some(addrs[1]), addrs[2])
                .await
                .is_err()
        );
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

    #[tokio::test]
    async fn without_an_internal_identity_no_internal_listener_binds() {
        let [public, binding] = free_addrs::<2>().await;
        let listeners = bind_listeners(public, None, binding).await.unwrap();
        assert!(listeners.internal.is_none());
    }

    #[test]
    fn workspace_daemons_join_the_public_coordinator() {
        assert_eq!(
            sandbox_public_coordinator_url(None, "https://dev.codewire.sh/"),
            "https://dev.codewire.sh"
        );
        assert_eq!(
            sandbox_public_coordinator_url(Some(" "), "https://dev.codewire.sh"),
            "https://dev.codewire.sh"
        );
        assert_eq!(
            sandbox_public_coordinator_url(
                Some("https://coordinator.example/"),
                "https://dev.codewire.sh"
            ),
            "https://coordinator.example"
        );
    }

    #[test]
    fn inside_a_cluster_the_internal_api_requires_its_tls_identity() {
        internal_tls_required(true, true).unwrap();
        internal_tls_required(false, true).unwrap();
        internal_tls_required(false, false).unwrap();
        let error = internal_tls_required(true, false).unwrap_err().to_string();
        assert!(error.contains("only over TLS"), "{error}");
    }

    #[test]
    fn internal_tls_listener_defaults_to_8088_and_needs_both_identity_files() {
        let public = SocketAddr::from(([127, 0, 0, 1], 8084));
        assert_eq!(
            internal_tls_bind_addr(public, None).unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 8088))
        );
        assert!(internal_tls_files(None, None).unwrap().is_none());
        assert!(internal_tls_files(Some(" "), Some("")).unwrap().is_none());
        assert!(
            internal_tls_files(Some("/run/tls/tls.crt"), Some("/run/tls/tls.key"))
                .unwrap()
                .is_some()
        );
        for (cert, key) in [
            (Some("/run/tls/tls.crt"), None),
            (None, Some("/run/tls/tls.key")),
            (Some("tls.crt"), Some("/run/tls/tls.key")),
            (Some("/run/tls/tls.crt"), Some("/run/tls/tls.crt")),
        ] {
            assert!(internal_tls_files(cert, key).is_err(), "{cert:?} {key:?}");
        }
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
                "credential-relay",
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
