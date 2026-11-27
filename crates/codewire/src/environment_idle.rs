//! An environment's own idle stop (#3384) and idle suspend (#5529) through
//! the canonical generated client.

use crate::*;

impl CodewireClient {
    pub async fn set_environment_idle_stop(
        &self,
        request: SetEnvironmentIdleStopRequest,
    ) -> Result<SetEnvironmentIdleStopResponse, ClientError> {
        self.environments
            .set_environment_idle_stop_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn set_environment_idle_suspend(
        &self,
        request: SetEnvironmentIdleSuspendRequest,
    ) -> Result<SetEnvironmentIdleSuspendResponse, ClientError> {
        self.environments
            .set_environment_idle_suspend_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn suspend_environment(
        &self,
        request: SuspendEnvironmentRequest,
    ) -> Result<SuspendEnvironmentResponse, ClientError> {
        self.environments
            .suspend_environment_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn resume_environment(
        &self,
        request: ResumeEnvironmentRequest,
    ) -> Result<ResumeEnvironmentResponse, ClientError> {
        self.environments
            .resume_environment_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn set_environment_idle_hibernate(
        &self,
        request: SetEnvironmentIdleHibernateRequest,
    ) -> Result<SetEnvironmentIdleHibernateResponse, ClientError> {
        self.environments
            .set_environment_idle_hibernate_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn hibernate_environment(
        &self,
        request: HibernateEnvironmentRequest,
    ) -> Result<HibernateEnvironmentResponse, ClientError> {
        self.environments
            .hibernate_environment_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }
}
