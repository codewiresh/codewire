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

    pub async fn suspend_environment(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<StatusResponse> {
        let response = self
            .inner
            .suspend_environment(rpc::SuspendEnvironmentRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(StatusResponse {
            status: response.status,
        })
    }

    pub async fn resume_environment(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<StatusResponse> {
        let response = self
            .inner
            .resume_environment(rpc::ResumeEnvironmentRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(StatusResponse {
            status: response.status,
        })
    }

    pub async fn set_environment_idle_hibernate(
        &self,
        org_id: &str,
        environment_id: &str,
        idle_hibernate_seconds: i32,
    ) -> anyhow::Result<StatusResponse> {
        let response = self
            .inner
            .set_environment_idle_hibernate(rpc::SetEnvironmentIdleHibernateRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                idle_hibernate_seconds,
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(StatusResponse {
            status: response.status,
        })
    }

    pub async fn hibernate_environment(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<StatusResponse> {
        let response = self
            .inner
            .hibernate_environment(rpc::HibernateEnvironmentRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(StatusResponse {
            status: response.status,
        })
    }
}
