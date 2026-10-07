//! Explicit platform profile for one repository preparation. This is trusted
//! parent metadata, never a provider credential or a platform environment row.

use codewire_access::EnvironmentId;
use codewire_credential_bridge::CredentialBridge;
use codewire_daemon_proto::codewire::bridge::v1 as bridge;
use std::{path::Path, sync::Arc};
use tokio::{sync::watch, task::JoinHandle, time::Instant};
use tokio_stream::StreamExt as _;
use tonic::Status;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::platform_ingress::PlatformRepositoryGitIngress;
use super::{
    LocalCredentialRepositoryLeaseClient, LocalRepositoryGitProcessSpawner,
    LocalRepositoryProcessConfig, LocalRepositoryTransport, RepositoryExecutorError,
};
use crate::{PlatformCredentialBinding, RepositoryCredentialLeaseRequest, control::v1};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryPlatformAccess {
    pub environment_id: EnvironmentId,
    pub environment_generation: u64,
    pub binding: PlatformCredentialBinding,
}

/// Only the private inherited lease server can expose this job capability.
/// Deliberately not Debug: neither this value nor provider material is logged.
pub(crate) enum RepositoryPlatformCheckout {
    GitHub {
        endpoint: String,
        capability: Zeroizing<Vec<u8>>,
    },
    Ssh {
        bridge: CredentialBridge,
    },
}

/// Owned by the retained repository job, outside any cancelled operation.
pub(crate) struct PlatformRepositoryConnection {
    bridge: CredentialBridge,
    shutdown: watch::Sender<bool>,
    driver: Option<JoinHandle<()>>,
    ingress: Option<PlatformRepositoryGitIngress>,
}

impl PlatformRepositoryConnection {
    pub(crate) async fn connect(
        access: RepositoryPlatformAccess,
        connector: Arc<dyn crate::PlatformCredentialConnector>,
        deadline: Instant,
    ) -> Result<Self, Status> {
        let environment = Uuid::parse_str(access.environment_id.as_str())
            .map_err(|_| Status::invalid_argument("invalid repository identity"))?;
        let bridge = CredentialBridge::new(environment, access.environment_generation)?;
        let (prepared, mut output) = bridge.prepare_connection()?;
        let Some(Ok(bridge::CredentialBridgeGuestMessage {
            payload: Some(bridge::credential_bridge_guest_message::Payload::Ready(ready)),
        })) = output.next().await
        else {
            return Err(unavailable());
        };
        let input = tokio::time::timeout_at(
            deadline,
            connector.connect(access.binding, ready, Box::pin(output), deadline),
        )
        .await
        .map_err(|_| unavailable())??;
        let connection = prepared.activate(input).await?;
        let (shutdown, mut stopped) = watch::channel(false);
        let driver = tokio::spawn(connection.run_until(async move {
            if !*stopped.borrow() {
                let _ = stopped.changed().await;
            }
        }));
        Ok(Self {
            bridge,
            shutdown,
            driver: Some(driver),
            ingress: None,
        })
    }

    pub(crate) async fn prepare_checkout(
        &mut self,
        authorization: &RepositoryCredentialLeaseRequest,
        deadline: Instant,
    ) -> Result<Arc<RepositoryPlatformCheckout>, Status> {
        if super::validate_repository_lease_request(authorization)
            == Ok(LocalRepositoryTransport::Ssh)
        {
            return Ok(Arc::new(RepositoryPlatformCheckout::Ssh {
                bridge: self.bridge.clone(),
            }));
        }
        let ingress = PlatformRepositoryGitIngress::bind(
            &authorization.source,
            self.bridge.clone(),
            deadline,
        )
        .await
        .map_err(|_| unavailable())?;
        let checkout = Arc::new(RepositoryPlatformCheckout::GitHub {
            endpoint: ingress.endpoint().to_owned(),
            capability: Zeroizing::new(ingress.capability().as_bytes().to_vec()),
        });
        self.ingress = Some(ingress);
        Ok(checkout)
    }

    /// Completes every local owner even if an HTTP exchange failed. Remote
    /// broker operations keep their own retained lifetime; this is local proof.
    pub(crate) async fn close(&mut self) -> Result<(), Status> {
        let ingress_result = match self.ingress.as_mut() {
            Some(ingress) => ingress.close().await.map_err(|_| unavailable()),
            None => Ok(()),
        };
        self.shutdown.send_replace(true);
        let driver_result = match self.driver.as_mut() {
            Some(driver) => driver.await.map_err(|_| unavailable()),
            None => Ok(()),
        };
        self.driver = None;
        ingress_result.and(driver_result)
    }
}

impl Drop for PlatformRepositoryConnection {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
    }
}

fn unavailable() -> Status {
    Status::unavailable("platform repository connection unavailable")
}

/// Platform mode never connects to or reads the local OS credential store.
pub async fn run_platform_repository_executor(
    authority_stream: tokio::net::UnixStream,
    config: LocalRepositoryProcessConfig,
    credential_runtime_directory: &Path,
    git_executable: &Path,
    helper_executable: &Path,
    git_spawner: &dyn LocalRepositoryGitProcessSpawner,
) -> Result<(), RepositoryExecutorError> {
    config
        .validate()
        .map_err(|_| RepositoryExecutorError::InvalidConfiguration)?;
    if !config.platform_delegated
        || config.transport != LocalRepositoryTransport::GitHubOAuth
        || !git_executable.is_absolute()
        || !helper_executable.is_absolute()
    {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    super::executor::validate_private_staging_directory(&config.staging_directory)?;
    super::executor::validate_credential_runtime_directory(credential_runtime_directory)?;
    let mut leases =
        LocalCredentialRepositoryLeaseClient::connect(authority_stream, config.request_id)
            .await
            .map_err(|_| RepositoryExecutorError::LeaseUnavailable)?;
    leases
        .report_ready()
        .await
        .map_err(|_| RepositoryExecutorError::LeaseUnavailable)?;
    let checkout = leases
        .brokered_checkout()
        .await
        .map_err(|_| RepositoryExecutorError::LeaseUnavailable)?;
    let capability = Zeroizing::new(checkout.capability);
    super::executor::execute_brokered_git_repository(
        &config.staging_directory,
        credential_runtime_directory,
        git_executable,
        helper_executable,
        git_spawner,
        &checkout.source,
        &checkout.branch,
        &checkout.revision,
        &checkout.endpoint,
        &capability,
    )
    .await
}

impl RepositoryPlatformAccess {
    pub(crate) fn validate(
        &self,
        request: &RepositoryCredentialLeaseRequest,
    ) -> Result<(), Status> {
        self.binding.validate()?;
        let selection = &self.binding.selection;
        let valid_id = Uuid::parse_str(self.environment_id.as_str())
            .is_ok_and(|id| !id.is_nil() && id.to_string() == self.environment_id.as_str());
        if !valid_id
            || self.environment_generation == 0
            || self.environment_generation > i64::MAX as u64
            || selection.profile.as_ref().is_none_or(|(id, revision)| {
                id != request.profile_id.as_str() || *revision != request.profile_revision
            })
            || selection.organization_selected
            || selection.project_id.is_some()
            || selection.user_selected
        {
            return Err(Status::invalid_argument(
                "invalid platform repository selection",
            ));
        }
        Ok(())
    }

    pub(crate) fn into_proto(self) -> v1::RepositoryPlatformAccess {
        v1::RepositoryPlatformAccess {
            environment_id: self.environment_id.to_string(),
            environment_generation: self.environment_generation,
            binding: Some(self.binding.into_proto()),
        }
    }

    pub(crate) fn from_proto(value: v1::RepositoryPlatformAccess) -> Result<Self, Status> {
        Ok(Self {
            environment_id: EnvironmentId::parse(value.environment_id)
                .map_err(|_| Status::invalid_argument("invalid platform repository identity"))?,
            environment_generation: value.environment_generation,
            binding: PlatformCredentialBinding::from_proto(
                value.binding.ok_or_else(|| {
                    Status::invalid_argument("missing platform repository binding")
                })?,
            )?,
        })
    }
}
