//! Connect-RPC adapter for an environment's desktop
//! (`codewire.v1.EnvironmentDesktopService`; `docs/dev/SANDBOX-DESKTOP.md`,
//! "Starting and stopping"). It names the vetted answer in the public
//! contract's words and adds nothing: the viewer password a running desktop
//! carries passes through to the authorized caller, under the no-store
//! policy every authenticated Connect response gets.

use std::sync::Arc;

use buffa_types::Timestamp;
use codewire_daemon_proto::daemon::v1 as daemon;
use codewire_proto::codewire::v1 as proto;
use codewire_server_core::connect::auth_user;
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};

use crate::api::ApiState;
use crate::api::environment_daemon::{
    get_environment_desktop_core, start_environment_desktop_core, stop_environment_desktop_core,
};
use crate::connect::workspace_rpc_error;

pub fn router(state: ApiState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(DesktopService { state }))
}

struct DesktopService {
    state: ApiState,
}

#[allow(refining_impl_trait)]
impl proto::EnvironmentDesktopService for DesktopService {
    async fn start_desktop(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::StartDesktopRequest>,
    ) -> ServiceResult<proto::StartDesktopResponse> {
        let user = auth_user(&ctx)?;
        let request = request.view();
        let desktop = start_environment_desktop_core(
            &self.state,
            user,
            request.org_id,
            request.environment_id,
        )
        .await
        .map_err(|error| workspace_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::StartDesktopResponse {
            desktop: Some(proto_desktop(desktop)).into(),
            ..Default::default()
        })
    }

    async fn get_desktop(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::GetDesktopRequest>,
    ) -> ServiceResult<proto::GetDesktopResponse> {
        let user = auth_user(&ctx)?;
        let request = request.view();
        let desktop =
            get_environment_desktop_core(&self.state, user, request.org_id, request.environment_id)
                .await
                .map_err(|error| workspace_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::GetDesktopResponse {
            desktop: Some(proto_desktop(desktop)).into(),
            ..Default::default()
        })
    }

    async fn stop_desktop(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::StopDesktopRequest>,
    ) -> ServiceResult<proto::StopDesktopResponse> {
        let user = auth_user(&ctx)?;
        let request = request.view();
        let desktop = stop_environment_desktop_core(
            &self.state,
            user,
            request.org_id,
            request.environment_id,
        )
        .await
        .map_err(|error| workspace_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::StopDesktopResponse {
            desktop: Some(proto_desktop(desktop)).into(),
            ..Default::default()
        })
    }
}

fn proto_desktop(desktop: daemon::Desktop) -> proto::EnvironmentDesktop {
    let state = match daemon::DesktopState::try_from(desktop.state) {
        Ok(daemon::DesktopState::Unavailable) => proto::EnvironmentDesktopState::Unavailable,
        Ok(daemon::DesktopState::Stopped) => proto::EnvironmentDesktopState::Stopped,
        Ok(daemon::DesktopState::Starting) => proto::EnvironmentDesktopState::Starting,
        Ok(daemon::DesktopState::Running) => proto::EnvironmentDesktopState::Running,
        Ok(daemon::DesktopState::Unspecified) | Err(_) => {
            proto::EnvironmentDesktopState::Unspecified
        }
    };
    proto::EnvironmentDesktop {
        state: state.into(),
        unavailable_reason: desktop.unavailable_reason,
        running: desktop.running.map(proto_running).into(),
        ..Default::default()
    }
}

fn proto_running(running: daemon::DesktopRunning) -> proto::EnvironmentDesktopRunning {
    proto::EnvironmentDesktopRunning {
        display: running.display,
        // The vetted answer names the desktop's one port, which fits.
        port: i32::try_from(running.port).unwrap_or_default(),
        started_at: running
            .started_at
            .map(|at| Timestamp::from_unix(at.seconds, at.nanos))
            .into(),
        viewer_password: running.viewer_password,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_running_desktop_keeps_every_field_and_each_state_has_its_name() {
        let mut details = daemon::DesktopRunning {
            display: ":1".into(),
            port: 5901,
            started_at: Some(Default::default()),
            viewer_password: "a1b2c3d4".into(),
        };
        if let Some(started_at) = details.started_at.as_mut() {
            started_at.seconds = 1_795_000_000;
            started_at.nanos = 7;
        }
        let running = proto_desktop(daemon::Desktop {
            state: daemon::DesktopState::Running as i32,
            unavailable_reason: String::new(),
            running: Some(details),
        });
        assert_eq!(running.state, proto::EnvironmentDesktopState::Running);
        let details = running.running.as_option().expect("running details");
        assert_eq!(details.display, ":1");
        assert_eq!(details.port, 5901);
        assert_eq!(
            details.started_at.as_option(),
            Some(&Timestamp::from_unix(1_795_000_000, 7))
        );
        assert_eq!(details.viewer_password, "a1b2c3d4");
        // The public message redacts it in debug output, as the daemon's does.
        assert!(!format!("{running:?}").contains("a1b2c3d4"));

        for (daemon_state, public) in [
            (
                daemon::DesktopState::Unavailable,
                proto::EnvironmentDesktopState::Unavailable,
            ),
            (
                daemon::DesktopState::Stopped,
                proto::EnvironmentDesktopState::Stopped,
            ),
            (
                daemon::DesktopState::Starting,
                proto::EnvironmentDesktopState::Starting,
            ),
            (
                daemon::DesktopState::Unspecified,
                proto::EnvironmentDesktopState::Unspecified,
            ),
        ] {
            let desktop = proto_desktop(daemon::Desktop {
                state: daemon_state as i32,
                unavailable_reason: "its launcher is not in the image".into(),
                running: None,
            });
            assert_eq!(desktop.state, public);
            assert!(desktop.running.as_option().is_none());
            assert_eq!(
                desktop.unavailable_reason,
                "its launcher is not in the image"
            );
        }
    }
}
