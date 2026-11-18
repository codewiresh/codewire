//! Mesh process assembly.
//!
//! Mesh exposes generated Connect services plus its typed internal coordinator.
//! Health and readiness probes are the only raw HTTP endpoints.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Router;
use codewire_server_core::http::{AppBuilder, never_shared_cached};
use tokio::net::TcpListener;

use crate::Config;
use crate::mesh_authorization::MeshAuthorizationAdapter;
use crate::product::MeshProductService;
use crate::store::{SharedStore, store_from_config};

/// How long a stopping replica that shares its registry stays up unready
/// before it ends its sessions, so the load balancer has stopped sending it
/// new ones (#3542).
const DRAIN_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) config: Config,
    pub(crate) product: MeshProductService,
    pub(crate) mesh_coordinate: crate::mesh_coordinate::MeshCoordinateState,
    /// Set once the process is stopping: `/readyz` then fails.
    pub(crate) draining: Arc<AtomicBool>,
}

impl AppState {
    pub(crate) fn new(config: Config, store: SharedStore) -> Self {
        let mesh_authorization = MeshAuthorizationAdapter::from_config(
            config.mesh_authorization.as_ref(),
            config.local_authorization.as_ref(),
        );
        // Hosted Mesh answers hosted environment members through orchestration
        // (#3350); a standalone Mesh has no environments.
        let environment_members = config
            .mesh_authorization
            .as_ref()
            .and_then(crate::environment_members::EnvironmentMembersClient::from_config);
        let product = MeshProductService::new(store.clone(), mesh_authorization)
            .with_environment_members(environment_members);
        Self {
            config,
            product,
            mesh_coordinate: crate::mesh_coordinate::MeshCoordinateState::new(),
            draining: Arc::new(AtomicBool::new(false)),
        }
    }
}

pub async fn serve<F>(config: Config, shutdown: F) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let http_listener = TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("listen codewire-mesh {}", config.bind_addr))?;
    let http_addr = http_listener
        .local_addr()
        .context("read codewire-mesh listener addr")?;

    tracing::info!(
        listen_addr = %http_addr,
        base_url = %config.base_url,
        "codewire mesh service listening"
    );

    let store = store_from_config(&config)
        .await
        .context("initialize codewire-mesh store")?;
    let mut state = AppState::new(config, store);
    // Mesh reaches NATS in the background: a NATS outage at startup leaves it
    // serving its own sessions, never crash-looping (#3542).
    let sharing = state
        .config
        .nats
        .clone()
        .map(|nats| state.mesh_coordinate.share_in_background(nats));
    // DERP's client admission lookup (#2844), on its own listener so no
    // ingress route reaches it.
    let derp_verify = match state.config.derp_verify_addr {
        Some(addr) => {
            let listener = TcpListener::bind(addr)
                .await
                .with_context(|| format!("listen codewire-mesh DERP verify {addr}"))?;
            tracing::info!(listen_addr = %addr, "codewire mesh DERP verify listening");
            let router = crate::derp_verify::router(state.mesh_coordinate.clone());
            Some(tokio::spawn(
                async move { axum::serve(listener, router).await },
            ))
        }
        None => None,
    };
    let recheck = state
        .product
        .environment_members()
        .is_some()
        .then(|| crate::environment_members::spawn_recheck(state.clone()));
    let store_recheck = state
        .mesh_coordinate
        .is_shared()
        .then(|| crate::mesh_coordinate::spawn_store_recheck(state.clone()));
    let coordinate = state.mesh_coordinate.clone();
    let draining = state.draining.clone();
    let router = router_from_state(state);
    // A replica sharing its registry turns unready, waits, then ends its
    // sessions without deleting their records: each reconnects to another
    // replica, and its partners see it updated, never removed (#3542).
    let shutdown = async move {
        shutdown.await;
        if coordinate.is_shared() {
            draining.store(true, Ordering::Release);
            tokio::time::sleep(DRAIN_WAIT).await;
            coordinate.drain().await;
        }
    };
    let result = axum::serve(http_listener, router)
        .with_graceful_shutdown(shutdown)
        .await
        .context("serve codewire-mesh HTTP");
    for task in sharing.into_iter().chain(store_recheck) {
        task.abort();
    }
    if let Some(derp_verify) = derp_verify {
        derp_verify.abort();
    }
    if let Some(recheck) = recheck {
        recheck.abort();
    }
    result
}

pub fn router(config: Config) -> Router {
    let store = Arc::new(crate::store::MemoryStore::new());
    router_with_store(config, store)
}

pub fn router_with_store(config: Config, store: SharedStore) -> Router {
    router_from_state(AppState::new(config, store))
}

/// A router that lists a node offline once its session has been silent for
/// `offline_after`, for tests that cannot wait the production 45 s (#2697).
#[doc(hidden)]
pub fn router_with_store_offline_after(
    config: Config,
    store: SharedStore,
    offline_after: std::time::Duration,
) -> Router {
    let mut state = AppState::new(config, store);
    state.mesh_coordinate =
        crate::mesh_coordinate::MeshCoordinateState::offline_after(offline_after);
    router_from_state(state)
}

/// Every Mesh response is `Cache-Control: no-store, private` with no
/// validators (`docs/dev/AUTH-POLICY.md`, #5054). The Connect services
/// authenticate in their handlers, so their idempotent GETs get no `private`
/// from a server-core auth layer; health and metrics are marked too, which
/// costs nothing.
pub(crate) fn router_from_state(state: AppState) -> Router {
    let draining = state.draining.clone();
    never_shared_cached(
        AppBuilder::new("mesh")
            .with_health_probe(move || {
                let ready = !draining.load(Ordering::Acquire);
                async move { ready }
            })
            .with_connect_routes(crate::connect::router(state.clone()))
            .with_connect_routes_and_protocol_policy(
                crate::mesh_coordinate::router(state),
                codewire_server_core::connect::ProtocolPolicy::ConnectAndGrpc,
            )
            .into_router(),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::response::Response;
    use codewire_server_core::auth::hash_api_key;
    use tower::ServiceExt;

    use super::{AppState, router_from_state};
    use crate::Config;
    use crate::config::LocalMeshAuthorizationConfig;
    use crate::store::MemoryStore;

    const ORG: &str = "org-mesh-no-store";
    const API_KEY: &str = "cw_mesh-no-store";

    fn config() -> Config {
        Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            base_url: "https://mesh.codewire.sh".to_string(),
            derp_url: None,
            stun_servers: Vec::new(),
            database_url: None,
            mesh_authorization: None,
            derp_verify_addr: None,
            local_authorization: Some(LocalMeshAuthorizationConfig {
                organization_id: ORG.to_string(),
                api_key_hash: hash_api_key(API_KEY),
            }),
            nats: None,
        }
    }

    async fn get(path: &str, api_key: Option<&str>) -> Response {
        let mut request = Request::get(path);
        if let Some(api_key) = api_key {
            request = request.header(header::AUTHORIZATION, format!("Bearer {api_key}"));
        }
        router_from_state(AppState::new(config(), Arc::new(MemoryStore::new())))
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    /// `ListMeshNetworks` as a Connect GET (an idempotent method) for `org`.
    fn list_networks_get(org: &str) -> String {
        format!(
            "/codewire.v1.MeshNetworkService/ListMeshNetworks?connect=v1&encoding=json&message=%7B%22orgId%22%3A%22{org}%22%7D"
        )
    }

    fn assert_never_shared_cached(response: &Response) {
        let headers = response.headers();
        assert_eq!(
            headers.get(header::CACHE_CONTROL).unwrap(),
            "no-store, private"
        );
        assert!(headers.get(header::ETAG).is_none());
        assert!(headers.get(header::LAST_MODIFIED).is_none());
    }

    #[tokio::test]
    async fn connect_get_answers_are_never_shared_cached() {
        for (path, api_key, status) in [
            (list_networks_get(ORG), Some(API_KEY), StatusCode::OK),
            (list_networks_get(ORG), None, StatusCode::UNAUTHORIZED),
            (
                list_networks_get("foreign-org"),
                Some(API_KEY),
                StatusCode::FORBIDDEN,
            ),
        ] {
            let response = get(&path, api_key).await;
            assert_eq!(response.status(), status, "{path} {api_key:?}");
            assert_never_shared_cached(&response);
        }
    }

    #[tokio::test]
    async fn readiness_and_unknown_paths_are_never_shared_cached() {
        let ready = get("/readyz", None).await;
        assert_eq!(ready.status(), StatusCode::OK);
        assert_never_shared_cached(&ready);

        let missing = get("/no-such-route", None).await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_never_shared_cached(&missing);
    }
}
