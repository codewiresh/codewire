//! Mesh process assembly.
//!
//! Mesh exposes generated Connect services plus its typed internal coordinator.
//! Health and readiness probes are the only raw HTTP endpoints.

use std::future::Future;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use codewire_server_core::http::AppBuilder;
use tokio::net::TcpListener;

use crate::Config;
use crate::mesh_authorization::MeshAuthorizationAdapter;
use crate::product::MeshProductService;
use crate::store::{SharedStore, store_from_config};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) config: Config,
    pub(crate) product: MeshProductService,
    pub(crate) mesh_coordinate: crate::mesh_coordinate::MeshCoordinateState,
}

impl AppState {
    fn new(config: Config, store: SharedStore) -> Self {
        let mesh_authorization = MeshAuthorizationAdapter::from_config(
            config.mesh_authorization.as_ref(),
            config.local_authorization.as_ref(),
        );
        let product = MeshProductService::new(store.clone(), mesh_authorization);
        Self {
            config,
            product,
            mesh_coordinate: crate::mesh_coordinate::MeshCoordinateState::new(),
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
    let router = router_from_state(AppState::new(config, store));
    axum::serve(http_listener, router)
        .with_graceful_shutdown(shutdown)
        .await
        .context("serve codewire-mesh HTTP")
}

pub fn router(config: Config) -> Router {
    let store = Arc::new(crate::store::MemoryStore::new());
    router_with_store(config, store)
}

pub fn router_with_store(config: Config, store: SharedStore) -> Router {
    router_from_state(AppState::new(config, store))
}

fn router_from_state(state: AppState) -> Router {
    AppBuilder::new("mesh")
        .with_health()
        .with_connect_routes(crate::connect::router(state.clone()))
        .with_connect_routes_and_protocol_policy(
            crate::mesh_coordinate::router(state),
            codewire_server_core::connect::ProtocolPolicy::ConnectAndGrpc,
        )
        .into_router()
}
