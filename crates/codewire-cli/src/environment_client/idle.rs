//! An environment's idle stop (#3384) and idle suspend (#5529).

use super::*;

impl EnvironmentClient {
    pub async fn set_environment_idle_stop(
        &self,
        org_id: &str,
        environment_id: &str,
        idle_stop_seconds: i32,
    ) -> anyhow::Result<StatusResponse> {
        let response = self
            .inner
            .set_environment_idle_stop(rpc::SetEnvironmentIdleStopRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                idle_stop_seconds,
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(StatusResponse {
            status: response.status,
        })
    }

    pub async fn set_environment_idle_suspend(
        &self,
        org_id: &str,
        environment_id: &str,
        idle_suspend_seconds: i32,
    ) -> anyhow::Result<StatusResponse> {
        let response = self
            .inner
            .set_environment_idle_suspend(rpc::SetEnvironmentIdleSuspendRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                idle_suspend_seconds,
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(StatusResponse {
            status: response.status,
        })
    }
}
