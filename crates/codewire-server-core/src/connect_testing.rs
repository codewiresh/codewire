//! The never-routed Connect conformance probe (doc 03 D8).
//!
//! `codewire.testing.v1.PingService` exists to prove mount + auth + error
//! wire-shape + edge routing before any product surface does. One shared
//! implementation here keeps orchestration and billing byte-identical
//! (D1's one-liner-per-surface rule): binaries call
//! [`AppBuilder::with_connect_testing_surface`](crate::AppBuilder::with_connect_testing_surface),
//! which mounts the probe only when `CONNECT_TESTING_SURFACE=1`.
//!
//! The flag is set by dev-stack, the migration-integration gate, and the
//! kind/local-kind test manifests — never by base or production deploy
//! manifests (D8). Production binaries carry this code but expose nothing;
//! with the flag unset the router is byte-identical to before the mount
//! existed.
//!
//! The methods deliberately span the three D3 auth modes, plus the
//! infrastructure's streaming fixture:
//!
//! - `PublicPing` — on the public allowlist (no credential),
//! - `Ping` — authenticated; rejects an empty `message` with
//!   `invalid_argument` + a `google.rpc.BadRequest` detail, exercising 01's
//!   renderer end to end through [`connect::rpc_app_error`](crate::connect::rpc_app_error),
//! - `AdminPing` — admin-elevated (`permission_denied` for non-admins),
//! - `StreamPing` — allowlisted server-streaming probe emitting a fixed,
//!   server-paced sequence so edge tests can prove streamed responses cross
//!   ingress-nginx incrementally (D5's buffering proof, WI-4).

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use codewire_proto::codewire::testing::v1::{
    AdminPingRequest, AdminPingResponse, PING_SERVICE_SERVICE_NAME, PingRequest, PingResponse,
    PingService, PublicPingRequest, PublicPingResponse, StreamPingRequest, StreamPingResponse,
};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult, ServiceStream};

use crate::auth::AuthState;
use crate::connect::{ConnectAuthLayer, auth_user, rpc_app_error};
use crate::error::{AppError, ValidationIssue};

/// Environment flag gating the probe mounts (D8). Only the exact value `1`
/// enables the surface.
pub const CONNECT_TESTING_SURFACE: &str = "CONNECT_TESTING_SURFACE";

/// Whether the current process should mount the probe service.
pub fn enabled() -> bool {
    enabled_from(std::env::var(CONNECT_TESTING_SURFACE).ok().as_deref())
}

/// [`enabled`], factored over the raw variable value for testability. Only
/// `"1"` enables — `true`/`yes`/whitespace variants stay off, keeping the
/// production default (unset → off) impossible to trip accidentally.
pub fn enabled_from(value: Option<&str>) -> bool {
    value == Some("1")
}

/// Number of messages [`ProbePingService`]'s `StreamPing` emits.
pub const STREAM_PING_TOTAL: u32 = 5;

/// Server-side pacing between `StreamPing` messages. Long enough that an
/// edge probe can distinguish incremental delivery from a single buffered
/// flush, short enough to keep e2e runs fast.
pub const STREAM_PING_INTERVAL: Duration = Duration::from_millis(300);

/// Builds the probe's Connect router and its D3 auth layer: authenticated
/// mount, `PublicPing` + `StreamPing` allowlisted, `AdminPing`
/// admin-elevated. Exposed so tests can mount the exact production wiring
/// without touching process environment.
pub fn router(auth: AuthState) -> (connectrpc::Router, ConnectAuthLayer) {
    let connect = connectrpc::Router::new().add_service(Arc::new(ProbePingService));
    let layer = ConnectAuthLayer::authenticated(auth)
        .allow_public([
            format!("/{PING_SERVICE_SERVICE_NAME}/PublicPing"),
            format!("/{PING_SERVICE_SERVICE_NAME}/StreamPing"),
        ])
        .admin_only([format!("/{PING_SERVICE_SERVICE_NAME}/AdminPing")]);
    (connect, layer)
}

/// The shared probe implementation (D8).
pub struct ProbePingService;

#[allow(refining_impl_trait)]
impl PingService for ProbePingService {
    async fn public_ping(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, PublicPingRequest>,
    ) -> ServiceResult<PublicPingResponse> {
        connectrpc::Response::ok(PublicPingResponse {
            message: "public pong".into(),
            ..Default::default()
        })
    }

    async fn ping(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, PingRequest>,
    ) -> ServiceResult<PingResponse> {
        // The auth layer already validated a credential; reading it back
        // here keeps the probe an end-to-end fixture for the extractor too.
        let user = auth_user(&ctx)?;
        let message = request.view().message;
        if message.is_empty() {
            // D8: exercise 01's renderer end to end — a 422-shaped
            // validation failure becomes `invalid_argument` with a
            // `google.rpc.BadRequest` detail (dotted field path per D3).
            let err = AppError::Validation {
                errors: vec![ValidationIssue {
                    path: Cow::Borrowed("/message"),
                    message: Cow::Borrowed("must not be empty"),
                }],
            };
            return Err(rpc_app_error(&err, &ctx));
        }
        let message = if message == "whoami" {
            user.user_id.clone()
        } else {
            message.to_owned()
        };
        connectrpc::Response::ok(PingResponse {
            message,
            ..Default::default()
        })
    }

    async fn admin_ping(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, AdminPingRequest>,
    ) -> ServiceResult<AdminPingResponse> {
        connectrpc::Response::ok(AdminPingResponse {
            message: "admin pong".into(),
            ..Default::default()
        })
    }

    async fn stream_ping(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, StreamPingRequest>,
    ) -> ServiceResult<ServiceStream<StreamPingResponse>> {
        // Fixed, server-paced sequence: message 0 immediately, then one
        // every STREAM_PING_INTERVAL. An edge that buffers the response
        // delivers everything in one burst; an unbuffered edge shows the
        // pacing — the observable D5's kind probe asserts on.
        let stream = futures::stream::unfold(0u32, |sequence| async move {
            if sequence >= STREAM_PING_TOTAL {
                return None;
            }
            if sequence > 0 {
                tokio::time::sleep(STREAM_PING_INTERVAL).await;
            }
            let msg = StreamPingResponse {
                sequence,
                total: STREAM_PING_TOTAL,
                ..Default::default()
            };
            Some((Ok(msg), sequence + 1))
        });
        connectrpc::Response::stream_ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_only_accepts_exactly_one() {
        assert!(enabled_from(Some("1")));
        for off in [
            None,
            Some(""),
            Some("0"),
            Some("true"),
            Some("yes"),
            Some(" 1"),
        ] {
            assert!(!enabled_from(off), "{off:?} must not enable the probe");
        }
    }
}
