//! The local credential authority as the broker's lease provider: a local
//! VM's operations, logins and refreshes, decided by the host's authority.

use super::*;

#[async_trait]
impl<S> BrokerLeaseProvider for codewire_local_credentials::LocalCredentialBrokerLeaseClient<S>
where
    S: codewire_protected_store::ProtectedStore + Clone + 'static,
{
    type Lease = codewire_local_credentials::CredentialOperationLease;
    type RefreshReservation = codewire_local_credentials::BrokerCredentialRefreshReservation;
    type StartedRefresh = codewire_local_credentials::StartedBrokerCredentialRefresh;

    async fn ssh_operation(
        &self,
        request: v1::CredentialSshRequest,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<v1::credential_ssh_response::Result, BrokerLeaseError> {
        if cancellation.is_cancelled() {
            return Err(BrokerLeaseError::Denied);
        }
        // Ordinary guest cancellation does not drop this unary call: retain
        // the broker slot until the authority finishes the original bounded
        // operation and its agent drain. The dispatcher suppresses the result.
        // Transport loss instead ends the epoch and relies on channel drain,
        // never on a local cancellation acknowledgement as remote proof.
        let mut client = self.clone();
        let response = codewire_local_credentials::LocalCredentialBrokerLeaseClient::ssh_operation(
            &mut client,
            request,
        )
        .await
        .map_err(|error| match error {
            codewire_local_credentials::BrokerLeaseChannelError::InvalidRequest => {
                BrokerLeaseError::InvalidRequest
            }
            codewire_local_credentials::BrokerLeaseChannelError::Denied => BrokerLeaseError::Denied,
            codewire_local_credentials::BrokerLeaseChannelError::InvalidResponse => {
                BrokerLeaseError::InvalidResponse
            }
            _ => BrokerLeaseError::Unavailable,
        })?;
        response.result.ok_or(BrokerLeaseError::InvalidResponse)
    }

    async fn project_environment(
        &self,
        request: v1::EnvironmentProjectionRequest,
    ) -> Result<Vec<u8>, BrokerLeaseError> {
        let request_id =
            Uuid::parse_str(&request.request_id).map_err(|_| BrokerLeaseError::InvalidRequest)?;
        if request_id.is_nil()
            || request_id.to_string() != request.request_id
            || !request.local_inventories.is_empty()
        {
            return Err(BrokerLeaseError::InvalidRequest);
        }
        let recipient = request
            .recipient_public_key
            .try_into()
            .map_err(|_| BrokerLeaseError::InvalidRequest)?;
        let selection = request
            .selection_sha256
            .try_into()
            .map_err(|_| BrokerLeaseError::InvalidRequest)?;
        codewire_local_credentials::LocalCredentialBrokerLeaseClient::project_environment(
            self,
            request_id,
            recipient,
            selection,
            request.deadline_unix_ms,
        )
        .await
        .map_err(|error| match error {
            codewire_local_credentials::BrokerLeaseChannelError::InvalidRequest => {
                BrokerLeaseError::InvalidRequest
            }
            codewire_local_credentials::BrokerLeaseChannelError::Denied => BrokerLeaseError::Denied,
            codewire_local_credentials::BrokerLeaseChannelError::InvalidResponse => {
                BrokerLeaseError::InvalidResponse
            }
            _ => BrokerLeaseError::Unavailable,
        })
    }

    async fn lease_operation(
        &self,
        request_id: Uuid,
        capability_slot: CapabilitySlot,
        operation: BrokerOperationId,
        route: BrokerRouteId,
    ) -> Result<Self::Lease, BrokerLeaseError> {
        let mut client = self.clone();
        codewire_local_credentials::LocalCredentialBrokerLeaseClient::lease_operation(
            &mut client,
            request_id,
            capability_slot,
            operation,
            route,
        )
        .await
        .map_err(|error| match error {
            codewire_local_credentials::BrokerLeaseChannelError::InvalidRequest => {
                BrokerLeaseError::InvalidRequest
            }
            codewire_local_credentials::BrokerLeaseChannelError::Denied => BrokerLeaseError::Denied,
            codewire_local_credentials::BrokerLeaseChannelError::RefreshInProgress => {
                BrokerLeaseError::Denied
            }
            codewire_local_credentials::BrokerLeaseChannelError::StaleRefresh => {
                BrokerLeaseError::Denied
            }
            codewire_local_credentials::BrokerLeaseChannelError::Unavailable => {
                BrokerLeaseError::Unavailable
            }
            codewire_local_credentials::BrokerLeaseChannelError::InvalidResponse => {
                BrokerLeaseError::InvalidResponse
            }
        })
    }

    /// The listed direct delivery exceptions on a local VM: the local
    /// authority admits only the host owner's own Active Codex ChatGPT login
    /// or Claude sign-in (docs/dev/SECRETS-AND-CREDENTIALS.md, "Direct
    /// delivery exceptions").
    async fn lease_codex_login(&self, request_id: Uuid) -> Result<Self::Lease, BrokerLeaseError> {
        let mut client = self.clone();
        codewire_local_credentials::LocalCredentialBrokerLeaseClient::lease_codex_login(
            &mut client,
            request_id,
        )
        .await
        .map_err(map_local_lease_error)
    }

    async fn lease_claude_login(&self, request_id: Uuid) -> Result<Self::Lease, BrokerLeaseError> {
        let mut client = self.clone();
        codewire_local_credentials::LocalCredentialBrokerLeaseClient::lease_claude_login(
            &mut client,
            request_id,
        )
        .await
        .map_err(map_local_lease_error)
    }

    async fn begin_credential_refresh(
        &self,
        request: BrokerCredentialRefreshRequest,
    ) -> Result<BrokerRefreshAdmission<Self::RefreshReservation>, BrokerRefreshError> {
        let mut client = self.clone();
        codewire_local_credentials::LocalCredentialBrokerLeaseClient::begin_credential_refresh(
            &mut client,
            request.refresh_id,
            request.request_id,
            request.grant,
            request.operation,
            request.route,
            request.material_generation,
        )
        .await
        .map(|admission| match admission {
            codewire_local_credentials::BrokerCredentialRefreshAdmission::Reserved(reservation) => {
                BrokerRefreshAdmission::Reserved(reservation)
            }
            codewire_local_credentials::BrokerCredentialRefreshAdmission::Recovered => {
                BrokerRefreshAdmission::Recovered
            }
        })
        .map_err(map_local_refresh_error)
    }

    async fn start_credential_refresh(
        &self,
        reservation: Self::RefreshReservation,
    ) -> Result<Self::StartedRefresh, BrokerRefreshError> {
        let mut client = self.clone();
        codewire_local_credentials::LocalCredentialBrokerLeaseClient::start_credential_refresh(
            &mut client,
            reservation,
        )
        .await
        .map_err(map_local_refresh_error)
    }

    async fn commit_credential_refresh(
        &self,
        permit: Self::StartedRefresh,
        material: CanonicalCodexOAuthBundle,
    ) -> Result<(), BrokerRefreshError> {
        commit_local_refresh(self, permit, material.into_bytes()).await
    }

    /// A rotated App bundle publishes through the same local journal as Codex:
    /// the next material generation, then the authority's promotion.
    async fn commit_github_app_refresh(
        &self,
        permit: Self::StartedRefresh,
        material: GitHubAppUserOAuthBundle,
    ) -> Result<(), BrokerRefreshError> {
        commit_local_refresh(self, permit, material.into_bytes()).await
    }

    /// A rotated Claude sign-in publishes through the same local journal.
    async fn commit_claude_oauth_refresh(
        &self,
        permit: Self::StartedRefresh,
        material: CanonicalClaudeOAuthBundle,
    ) -> Result<(), BrokerRefreshError> {
        commit_local_refresh(self, permit, material.into_bytes()).await
    }

    async fn abort_credential_refresh(
        &self,
        permit: Self::RefreshReservation,
    ) -> Result<(), BrokerRefreshError> {
        let mut client = self.clone();
        codewire_local_credentials::LocalCredentialBrokerLeaseClient::abort_credential_refresh(
            &mut client,
            permit,
        )
        .await
        .map_err(map_local_refresh_error)
    }

    async fn fail_credential_refresh(
        &self,
        permit: Self::StartedRefresh,
    ) -> Result<(), BrokerRefreshError> {
        let mut client = self.clone();
        codewire_local_credentials::LocalCredentialBrokerLeaseClient::fail_credential_refresh(
            &mut client,
            permit,
        )
        .await
        .map_err(map_local_refresh_error)
    }

    async fn wait_for_active_operations(&self) -> Result<(), BrokerRefreshError> {
        codewire_local_credentials::LocalCredentialBrokerLeaseClient::wait_for_protected_store_operations(
            self,
        )
        .await
        .map_err(map_local_refresh_error)
    }
}

async fn commit_local_refresh<S>(
    client: &codewire_local_credentials::LocalCredentialBrokerLeaseClient<S>,
    permit: codewire_local_credentials::StartedBrokerCredentialRefresh,
    mut bytes: Zeroizing<Vec<u8>>,
) -> Result<(), BrokerRefreshError>
where
    S: codewire_protected_store::ProtectedStore + Clone + 'static,
{
    let value = codewire_protected_store::ProtectedValue::new(std::mem::take(&mut *bytes))
        .map_err(|_| BrokerRefreshError::InvalidRequest)?;
    let mut client = client.clone();
    codewire_local_credentials::LocalCredentialBrokerLeaseClient::commit_credential_refresh(
        &mut client,
        permit,
        value,
    )
    .await
    .map_err(map_local_refresh_error)
}

fn map_local_refresh_error(
    error: codewire_local_credentials::BrokerLeaseChannelError,
) -> BrokerRefreshError {
    match error {
        codewire_local_credentials::BrokerLeaseChannelError::InvalidRequest => {
            BrokerRefreshError::InvalidRequest
        }
        codewire_local_credentials::BrokerLeaseChannelError::Denied => BrokerRefreshError::Denied,
        codewire_local_credentials::BrokerLeaseChannelError::Unavailable => {
            BrokerRefreshError::Unavailable
        }
        codewire_local_credentials::BrokerLeaseChannelError::InvalidResponse => {
            BrokerRefreshError::InvalidResponse
        }
        codewire_local_credentials::BrokerLeaseChannelError::RefreshInProgress => {
            BrokerRefreshError::InProgress
        }
        codewire_local_credentials::BrokerLeaseChannelError::StaleRefresh => {
            BrokerRefreshError::Stale
        }
    }
}

fn map_local_lease_error(
    error: codewire_local_credentials::BrokerLeaseChannelError,
) -> BrokerLeaseError {
    match error {
        codewire_local_credentials::BrokerLeaseChannelError::InvalidRequest => {
            BrokerLeaseError::InvalidRequest
        }
        codewire_local_credentials::BrokerLeaseChannelError::Denied => BrokerLeaseError::Denied,
        codewire_local_credentials::BrokerLeaseChannelError::RefreshInProgress => {
            BrokerLeaseError::Denied
        }
        codewire_local_credentials::BrokerLeaseChannelError::StaleRefresh => {
            BrokerLeaseError::Denied
        }
        codewire_local_credentials::BrokerLeaseChannelError::Unavailable => {
            BrokerLeaseError::Unavailable
        }
        codewire_local_credentials::BrokerLeaseChannelError::InvalidResponse => {
            BrokerLeaseError::InvalidResponse
        }
    }
}
