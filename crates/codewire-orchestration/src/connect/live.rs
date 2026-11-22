//! Connect-RPC adapter for the dashboard's live change notices (#4762).
//!
//! The dashboard relays `Watch` to signed-in pages as Server-Sent Events.

use std::sync::Arc;

use buffa_types::Timestamp;
use codewire_daemon_bridge::drain::{Restart, end_at};
use codewire_proto::codewire::console::v1::{
    CreditChanged, LiveHeartbeat, LiveService, ResizeChanged, SandboxChanged, WatchRequest,
    WatchResponse, watch_response::Event,
};
use codewire_server_core::connect::{auth_user, rpc_app_error};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult, ServiceStream};

use codewire_server_core::AppBuilder;
use codewire_server_core::connect::ConnectAuthLayer;
use sqlx::PgPool;

use crate::api::ApiState;
use crate::api::live::{LiveEvent, LiveNotifications, open_live_watch};
use crate::drain::Drain;

const WATCH_RESTARTED: &str = "Codewire is restarting this server; watch again to continue";

/// Registers the LiveService RPC on its generated route.
pub fn router(state: ApiState) -> connectrpc::Router {
    router_for(state.pool, state.live, state.drain)
}

pub(crate) fn router_for(
    pool: PgPool,
    live: Arc<LiveNotifications>,
    drain: Drain,
) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(LiveConnectService { pool, live, drain }))
}

/// Mounts LiveService behind `auth` on the streaming mount. A watch lives for
/// minutes, so it must never take the unary dispatcher's 60-second deadline.
pub trait MountLive {
    fn with_live_watch(self, router: connectrpc::Router, auth: ConnectAuthLayer) -> Self;
}

impl MountLive for AppBuilder {
    fn with_live_watch(self, router: connectrpc::Router, auth: ConnectAuthLayer) -> Self {
        self.with_connect_routes_auth(router, auth)
    }
}

struct LiveConnectService {
    pool: PgPool,
    live: Arc<LiveNotifications>,
    drain: Drain,
}

#[allow(refining_impl_trait)]
impl LiveService for LiveConnectService {
    async fn watch(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, WatchRequest>,
    ) -> ServiceResult<ServiceStream<WatchResponse>> {
        let user = auth_user(&ctx)?.clone();
        let events = open_live_watch(&self.pool, &self.live, &user)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        let stream = futures::stream::unfold(events, |mut events| async move {
            let event = events.recv().await?;
            Some((Ok(proto_watch_event(event)), events))
        });
        connectrpc::Response::stream_ok(end_at(
            stream,
            Some(self.drain.signal(Restart::Deadline)),
            WATCH_RESTARTED,
        ))
    }
}

fn proto_watch_event(event: LiveEvent) -> WatchResponse {
    let event = match event {
        LiveEvent::Resync => Event::Resync(Box::default()),
        LiveEvent::Heartbeat(sent_at) => Event::Heartbeat(Box::new(LiveHeartbeat {
            sent_at: Some(Timestamp::from_unix(
                sent_at.timestamp(),
                sent_at.timestamp_subsec_nanos() as i32,
            ))
            .into(),
            ..Default::default()
        })),
        LiveEvent::Sandbox { org, environment } => Event::Sandbox(Box::new(SandboxChanged {
            org_id: org.to_string(),
            environment_id: environment.to_string(),
            ..Default::default()
        })),
        LiveEvent::Resize { org, environment } => Event::Resize(Box::new(ResizeChanged {
            org_id: org.to_string(),
            environment_id: environment.to_string(),
            ..Default::default()
        })),
        LiveEvent::Credit { org } => Event::Credit(Box::new(CreditChanged {
            org_id: org.to_string(),
            ..Default::default()
        })),
    };
    WatchResponse {
        event: Some(event),
        ..Default::default()
    }
}

#[cfg(test)]
mod database_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_live_event_maps_to_its_arm_with_ids_only() {
        let event = proto_watch_event(LiveEvent::Sandbox {
            org: "org".into(),
            environment: "env".into(),
        });
        let Some(Event::Sandbox(sandbox)) = event.event else {
            panic!("not a sandbox event");
        };
        assert_eq!(
            (sandbox.org_id.as_str(), sandbox.environment_id.as_str()),
            ("org", "env")
        );
        assert!(matches!(
            proto_watch_event(LiveEvent::Resync).event,
            Some(Event::Resync(_))
        ));
        assert!(matches!(
            proto_watch_event(LiveEvent::Credit { org: "org".into() }).event,
            Some(Event::Credit(_))
        ));
    }
}
