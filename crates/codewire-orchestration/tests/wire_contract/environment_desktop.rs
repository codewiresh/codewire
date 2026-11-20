//! `codewire.v1.EnvironmentDesktopService` over the wire, in both Connect
//! codecs: who is refused
//! before the daemon is asked, and what an operator is told by a daemon
//! whose image has no desktop, which is what this harness runs.

use codewire_proto::codewire::v1::{
    EnvironmentDesktopServiceClient, EnvironmentDesktopState, GetDesktopRequest,
    StartDesktopRequest, StopDesktopRequest,
};
use connectrpc::client::HttpClient;
use connectrpc::{CodecFormat, ErrorCode, Protocol};

use super::{Auth, Harness, PRIMARY_ORG, assert_rpc_error};

const BACKEND_ENV: &str = "env_exec_contract_backend";
const STOPPED_ENV: &str = "env_environment_contract_start_binary";
const STARTING_ENV: &str = "env_environment_contract_state_starting";
const VIEWER_ENV: &str = "env_port_contract_viewer";
const MISSING_ENV: &str = "env_exec_contract_missing";
const MISSING_ORG: &str = "org_exec_contract_missing";

pub(super) async fn run(harness: &Harness) {
    assert_desktop_gates(harness).await;
    assert_an_image_without_a_desktop_says_so(harness).await;
}

/// The service is all unary, so it is on the Connect-only mount: there is no
/// gRPC route to exercise.
fn client(
    harness: &Harness,
    auth: Auth,
    codec: CodecFormat,
) -> EnvironmentDesktopServiceClient<HttpClient> {
    EnvironmentDesktopServiceClient::new(
        HttpClient::plaintext(),
        harness
            .client_config(auth, codec)
            .with_protocol(Protocol::Connect),
    )
}

/// A caller who may not open a terminal in the environment gets none of the
/// three calls, and so never a desktop's viewer password: each is refused
/// with the terminal's own answer, before any daemon is asked.
async fn assert_desktop_gates(harness: &Harness) {
    for codec in [CodecFormat::Proto, CodecFormat::Json] {
        for (auth, org_id, environment_id, code, message) in [
            (
                Auth::None,
                PRIMARY_ORG,
                BACKEND_ENV,
                ErrorCode::Unauthenticated,
                "unauthorized",
            ),
            (
                Auth::Admin,
                MISSING_ORG,
                BACKEND_ENV,
                ErrorCode::NotFound,
                "organization not found",
            ),
            (
                Auth::Admin,
                PRIMARY_ORG,
                MISSING_ENV,
                ErrorCode::PermissionDenied,
                "access denied",
            ),
            (
                Auth::User,
                PRIMARY_ORG,
                VIEWER_ENV,
                ErrorCode::PermissionDenied,
                "access denied",
            ),
            (
                Auth::Admin,
                PRIMARY_ORG,
                STOPPED_ENV,
                ErrorCode::FailedPrecondition,
                "environment must be running",
            ),
            (
                Auth::Admin,
                PRIMARY_ORG,
                STARTING_ENV,
                ErrorCode::Unavailable,
                "environment is starting",
            ),
        ] {
            let desktop = client(harness, auth, codec);
            let error = desktop
                .get_desktop(GetDesktopRequest {
                    org_id: org_id.into(),
                    environment_id: environment_id.into(),
                    ..Default::default()
                })
                .await
                .expect_err("GetDesktop must keep the target gate");
            assert_rpc_error(&error, code, message);
            let error = desktop
                .start_desktop(StartDesktopRequest {
                    org_id: org_id.into(),
                    environment_id: environment_id.into(),
                    ..Default::default()
                })
                .await
                .expect_err("StartDesktop must keep the target gate");
            assert_rpc_error(&error, code, message);
            let error = desktop
                .stop_desktop(StopDesktopRequest {
                    org_id: org_id.into(),
                    environment_id: environment_id.into(),
                    ..Default::default()
                })
                .await
                .expect_err("StopDesktop must keep the target gate");
            assert_rpc_error(&error, code, message);
        }
    }
}

/// An operator reaches the daemon. This harness's daemon runs in no
/// workspace image, so the desktop is unavailable: a read and a stop say so,
/// and a start is refused, each in the control plane's own sentence.
async fn assert_an_image_without_a_desktop_says_so(harness: &Harness) {
    for codec in [CodecFormat::Proto, CodecFormat::Json] {
        let desktop = client(harness, Auth::Admin, codec);
        let read = desktop
            .get_desktop(GetDesktopRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: BACKEND_ENV.into(),
                ..Default::default()
            })
            .await
            .expect("an operator reads the desktop's state")
            .into_owned()
            .desktop
            .as_option()
            .cloned()
            .expect("GetDesktop returns a desktop");
        assert_eq!(read.state, EnvironmentDesktopState::Unavailable);
        // The control plane's own sentence, never the daemon's text.
        assert_eq!(
            read.unavailable_reason,
            "this environment's image has no desktop; create the environment again on the current image"
        );
        assert!(read.running.as_option().is_none());

        let refused = desktop
            .start_desktop(StartDesktopRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: BACKEND_ENV.into(),
                ..Default::default()
            })
            .await
            .expect_err("an image without a desktop starts none");
        assert_rpc_error(
            &refused,
            ErrorCode::FailedPrecondition,
            "this environment's image has no desktop",
        );

        let stopped = desktop
            .stop_desktop(StopDesktopRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: BACKEND_ENV.into(),
                ..Default::default()
            })
            .await
            .expect("a stop of a desktop that cannot run still answers")
            .into_owned()
            .desktop
            .as_option()
            .cloned()
            .expect("StopDesktop returns a desktop");
        assert_eq!(stopped.state, EnvironmentDesktopState::Unavailable);
    }
}
