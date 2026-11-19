//! Orchestration's side of hosted egress (#4000): admitting a guest's egress
//! stream for the cw-egress on its node, the policy each sandbox enforces,
//! and what cw-egress reports back. Served as `EgressService` on the
//! internal-connect listener.
//!
//! cw-egress itself needs no Kubernetes Role or ClusterRole: orchestration
//! reviews every token and reads every Pod, with the TokenReview and Pod
//! access it already has.

use std::sync::Arc;

use sqlx::PgPool;

use crate::runtime::{RuntimeAttestation, RuntimeDriver};
use crate::workspace_binding::PgBindingStore;

pub mod admission;
pub mod assignment;
pub mod gateway_check;
pub mod lockdown;
pub mod reports;
pub mod service;
pub mod settings;

/// The service's state when hosted egress is on; `None` when it is off, and
/// then nothing serves `EgressService`. cw-egress runs in orchestration's own
/// namespace (`POD_NAMESPACE`), and its callers are accepted only from there.
pub fn service_state(
    settings: settings::EgressSettings,
    runtime: Option<Arc<dyn RuntimeDriver>>,
    database_url: &str,
    pool: PgPool,
    server_namespace: &str,
    sandbox_namespace: &str,
    front_doors: Option<Arc<crate::front_door::FrontDoorEpochs>>,
) -> anyhow::Result<Option<Arc<service::EgressServiceState>>> {
    if !settings.enabled {
        return Ok(None);
    }
    let runtime =
        runtime.ok_or_else(|| anyhow::anyhow!("hosted egress needs the Kubernetes runtime"))?;
    anyhow::ensure!(
        !server_namespace.trim().is_empty(),
        "hosted egress needs POD_NAMESPACE, the namespace cw-egress runs in"
    );
    let attestation: Arc<dyn RuntimeAttestation> = runtime;
    Ok(Some(Arc::new(service::EgressServiceState {
        attestation,
        bindings: Arc::new(PgBindingStore::connect_lazy(database_url)?),
        pool,
        server_namespace: server_namespace.to_owned(),
        sandbox_namespace: sandbox_namespace.to_owned(),
        // No deployment sets a platform allow (see `settings::PLATFORM_ALLOWS`).
        platform: Vec::new(),
        intercepts: assignment::interception_bindings(settings.interception)?,
        starts: Default::default(),
        front_doors,
    })))
}

/// The internal listener's router, with `EgressService` mounted when the
/// deployment turns hosted egress on. Every method authenticates cw-egress by
/// TokenReview of its own token, so the mount carries no layer;
/// WatchAssignment streams.
pub fn mount(
    app: codewire_server_core::http::AppBuilder,
    api: &crate::api::ApiState,
    database_url: &str,
    settings: settings::EgressSettings,
    front_doors: Option<Arc<crate::front_door::FrontDoorEpochs>>,
) -> anyhow::Result<axum::Router> {
    let state = service_state(
        settings,
        api.runtime.clone(),
        database_url,
        api.pool.clone(),
        &api.sandbox_cfg.pod_namespace,
        &api.sandbox_cfg.sandbox_namespace,
        front_doors,
    )?;
    Ok(match state {
        Some(state) => {
            spawn_report_sweep(state.pool.clone());
            app.with_connect_routes(service::egress_router(state))
        }
        None => app,
    }
    .into_router())
}

/// How often orchestration deletes the enforcement rows of Pods that are
/// gone ([`reports::sweep`]).
pub const REPORT_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5 * 60);

fn spawn_report_sweep(pool: PgPool) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(REPORT_SWEEP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match reports::sweep(&pool).await {
                Ok(0) => {}
                Ok(swept) => tracing::info!(swept, "swept egress enforcement rows of gone Pods"),
                Err(error) => tracing::warn!(%error, "egress enforcement sweep failed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> PgPool {
        PgPool::connect_lazy("postgres://unused@127.0.0.1:1/unused").unwrap()
    }

    #[tokio::test]
    async fn nothing_is_served_while_hosted_egress_is_off() {
        // Off needs nothing else: no runtime, no namespace.
        let state = service_state(
            settings::EgressSettings::default(),
            None,
            "postgres://unused",
            pool(),
            "",
            "",
            None,
        )
        .unwrap();
        assert!(state.is_none());
    }

    #[tokio::test]
    async fn on_without_a_runtime_or_a_namespace_fails_startup() {
        let on = || settings::EgressSettings {
            enabled: true,
            interception: false,
        };
        assert!(service_state(on(), None, "postgres://unused", pool(), "dev", "sb", None).is_err());
        // Startup builds the state without calling Kubernetes.
        let client = kube::Client::new(
            tower::service_fn(|_: axum::http::Request<kube::client::Body>| async {
                Ok::<_, std::convert::Infallible>(
                    axum::http::Response::builder()
                        .status(404)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
            }),
            "dev",
        );
        let runtime =
            crate::runtime::kubernetes::KubernetesDriver::shared(client, Default::default());
        assert!(
            service_state(
                on(),
                Some(runtime.clone()),
                "postgres://unused",
                pool(),
                " ",
                "sb",
                None
            )
            .is_err()
        );
        assert!(
            service_state(
                on(),
                Some(runtime.clone()),
                "postgres://unused",
                pool(),
                "dev",
                "sb",
                None
            )
            .unwrap()
            .is_some_and(|state| state.intercepts.is_empty())
        );
        let intercepting = settings::EgressSettings {
            enabled: true,
            interception: true,
        };
        let state = service_state(
            intercepting,
            Some(runtime),
            "postgres://unused",
            pool(),
            "dev",
            "sb",
            None,
        )
        .unwrap()
        .unwrap();
        assert!(!state.intercepts.is_empty());
    }
}
