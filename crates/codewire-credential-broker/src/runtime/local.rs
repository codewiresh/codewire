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
        .map_err(map_local_unrefused_error)?;
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
        .map_err(map_local_unrefused_error)
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
            codewire_local_credentials::BrokerLeaseChannelError::Withheld(reason) => {
                BrokerLeaseError::ReconnectRequired(reason)
            }
            codewire_local_credentials::BrokerLeaseChannelError::RefreshInProgress => {
                BrokerLeaseError::Denied
            }
            codewire_local_credentials::BrokerLeaseChannelError::StaleRefresh => {
                BrokerLeaseError::Denied
            }
            codewire_local_credentials::BrokerLeaseChannelError::Unavailable
            | codewire_local_credentials::BrokerLeaseChannelError::RateLimited { .. } => {
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
    ) -> Result<(), CommitFailure<Self::StartedRefresh>> {
        commit_local_refresh(self, permit, material.into_bytes()).await
    }

    /// A rotated App bundle publishes through the same local journal as Codex:
    /// the next material generation, then the authority's promotion.
    async fn commit_github_app_refresh(
        &self,
        permit: Self::StartedRefresh,
        material: GitHubAppUserOAuthBundle,
    ) -> Result<(), CommitFailure<Self::StartedRefresh>> {
        commit_local_refresh(self, permit, material.into_bytes()).await
    }

    /// A rotated Claude sign-in publishes through the same local journal.
    async fn commit_claude_oauth_refresh(
        &self,
        permit: Self::StartedRefresh,
        material: CanonicalClaudeOAuthBundle,
    ) -> Result<(), CommitFailure<Self::StartedRefresh>> {
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

/// The authority stages the bundle (#5539); an unpublished one hands its
/// started refresh back, so the runtime can still record its failure.
async fn commit_local_refresh<S>(
    client: &codewire_local_credentials::LocalCredentialBrokerLeaseClient<S>,
    permit: codewire_local_credentials::StartedBrokerCredentialRefresh,
    mut bytes: Zeroizing<Vec<u8>>,
) -> Result<(), CommitFailure<codewire_local_credentials::StartedBrokerCredentialRefresh>>
where
    S: codewire_protected_store::ProtectedStore + Clone + 'static,
{
    let value = match codewire_protected_store::ProtectedValue::new(std::mem::take(&mut *bytes)) {
        Ok(value) => value,
        Err(_) => {
            return Err(CommitFailure::returned(
                permit,
                BrokerRefreshError::InvalidRequest,
            ));
        }
    };
    let mut client = client.clone();
    codewire_local_credentials::LocalCredentialBrokerLeaseClient::commit_credential_refresh(
        &mut client,
        permit,
        value,
    )
    .await
    .map_err(|unpublished| CommitFailure {
        started: unpublished.started,
        error: map_local_refresh_error(unpublished.error),
    })
}

fn map_local_refresh_error(
    error: codewire_local_credentials::BrokerLeaseChannelError,
) -> BrokerRefreshError {
    match error {
        codewire_local_credentials::BrokerLeaseChannelError::InvalidRequest => {
            BrokerRefreshError::InvalidRequest
        }
        // A withheld credential is not refreshed: its owner reconnects it.
        codewire_local_credentials::BrokerLeaseChannelError::Denied
        | codewire_local_credentials::BrokerLeaseChannelError::Withheld(_) => {
            BrokerRefreshError::Denied
        }
        // Never a denial: the sign-in is kept while the provider's wait runs.
        codewire_local_credentials::BrokerLeaseChannelError::Unavailable
        | codewire_local_credentials::BrokerLeaseChannelError::RateLimited { .. } => {
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

/// An SSH operation's or a projection's lease failure. Neither answers with
/// a refusal body to carry a withheld credential's reason, and a retry would
/// not change it, so it is a plain denial, never a retryable unavailable
/// (#5593).
fn map_local_unrefused_error(
    error: codewire_local_credentials::BrokerLeaseChannelError,
) -> BrokerLeaseError {
    match error {
        codewire_local_credentials::BrokerLeaseChannelError::InvalidRequest => {
            BrokerLeaseError::InvalidRequest
        }
        codewire_local_credentials::BrokerLeaseChannelError::Denied
        | codewire_local_credentials::BrokerLeaseChannelError::Withheld(_) => {
            BrokerLeaseError::Denied
        }
        codewire_local_credentials::BrokerLeaseChannelError::InvalidResponse => {
            BrokerLeaseError::InvalidResponse
        }
        _ => BrokerLeaseError::Unavailable,
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
        codewire_local_credentials::BrokerLeaseChannelError::Withheld(reason) => {
            BrokerLeaseError::ReconnectRequired(reason)
        }
        codewire_local_credentials::BrokerLeaseChannelError::RefreshInProgress => {
            BrokerLeaseError::Denied
        }
        codewire_local_credentials::BrokerLeaseChannelError::StaleRefresh => {
            BrokerLeaseError::Denied
        }
        codewire_local_credentials::BrokerLeaseChannelError::Unavailable
        | codewire_local_credentials::BrokerLeaseChannelError::RateLimited { .. } => {
            BrokerLeaseError::Unavailable
        }
        codewire_local_credentials::BrokerLeaseChannelError::InvalidResponse => {
            BrokerLeaseError::InvalidResponse
        }
    }
}

#[cfg(test)]
mod tests {
    use codewire_access::WithheldReason;
    use codewire_local_credentials::BrokerLeaseChannelError;

    use super::*;

    /// A local VM's withheld credential reaches the agent as the same
    /// refusal a hosted Sandbox gives it, is never refreshed, and is a plain
    /// denial where no refusal body can carry it (#5593).
    #[test]
    fn a_withheld_lease_is_the_reconnect_refusal_and_never_refreshes() {
        for reason in [
            WithheldReason::Revoked,
            WithheldReason::Expired,
            WithheldReason::NeedsReconnect,
        ] {
            assert_eq!(
                map_local_lease_error(BrokerLeaseChannelError::Withheld(reason)),
                BrokerLeaseError::ReconnectRequired(reason)
            );
            assert_eq!(
                map_local_refresh_error(BrokerLeaseChannelError::Withheld(reason)),
                BrokerRefreshError::Denied
            );
            assert_eq!(
                map_local_unrefused_error(BrokerLeaseChannelError::Withheld(reason)),
                BrokerLeaseError::Denied
            );
        }
        assert_eq!(
            map_local_lease_error(BrokerLeaseChannelError::Denied),
            BrokerLeaseError::Denied
        );
    }
}
