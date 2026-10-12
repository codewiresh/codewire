//! Typed internal client for the environment daemon's durable-session API.
//!
//! This is intentionally separate from the public `codewire-client` facade:
//! local environments use the internal daemon protocol with their managed
//! endpoint and daemon token, while platform environments use Connect through
//! the public environment-session service.

use std::sync::Arc;
use std::time::Duration;

use codewire_daemon_proto::codewire::bridge::v1 as bridge_v1;
pub use codewire_daemon_proto::daemon::v1;
use codewire_daemon_proto::ssh::{self, SshOperation};
use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES, DAEMON_AUTH_TOKEN_HEADER, DAEMON_CAPABILITY_ATTACH,
    DAEMON_CAPABILITY_SESSIONS,
};
pub use codewire_daemon_proto::{DAEMON_MINIMUM_PROTOCOL_VERSION, DAEMON_PROTOCOL_VERSION};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Streaming};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const HOSTED_WORKSPACE_AUTHORIZATION: &str = "x-codewire-workspace-authorization-bin";

mod hosted;
pub use hosted::HostedCredentialBridgeDrain;

/// The admitted hosted daemon response, still inactive until the broker opens
/// it. Its request producer remains owned by the separately returned drain.
pub type HostedCredentialBridgePrepared = (
    PreparedHostedCredentialBridge,
    Streaming<bridge_v1::CredentialBridgeGuestMessage>,
);

#[derive(Debug, thiserror::Error)]
pub enum SessionClientError {
    #[error("daemon endpoint is invalid")]
    InvalidEndpoint,
    #[error("local environment daemon credential is invalid")]
    InvalidCredential,
    #[error("connect to local environment daemon failed")]
    Connect,
    #[error("local environment daemon RPC: {0}")]
    Status(#[from] tonic::Status),
    #[error("local environment daemon request stream is closed")]
    RequestClosed,
    #[error("local environment daemon returned no session record")]
    MissingSessionRecord,
    #[error("local environment daemon is not ready: {message}")]
    NotReady { message: String },
    #[error("local environment daemon does not support required capability {capability}")]
    MissingCapability { capability: &'static str },
}

impl SessionClientError {
    /// Why the daemon will never start the session again, when it refused a
    /// restart for a reason that cannot change. `None` for every other
    /// failure: a later attempt may be admitted.
    pub fn never_restarts(&self) -> Option<crate::NeverRestarts> {
        match self {
            Self::Status(status) => crate::NeverRestarts::of(status),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct SessionClient {
    inner: v1::daemon_service_client::DaemonServiceClient<Channel>,
    auth_token: MetadataValue<tonic::metadata::Ascii>,
}

/// Private target-side facade. It never falls back to legacy Launch/Input/Stop
/// or starts an owner. A failed mutation reply is recovered only with Observe
/// of that same request ID; the caller must retain its original scope.
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct HostControlClient {
    inner: v1::host_control_service_client::HostControlServiceClient<Channel>,
    auth_token: MetadataValue<tonic::metadata::Ascii>,
    environment_id: String,
}

#[cfg(target_os = "linux")]
impl HostControlClient {
    pub fn from_channel(
        channel: Channel,
        daemon_token: impl AsRef<str>,
        environment_id: String,
    ) -> Result<Self, SessionClientError> {
        crate::host_control::canonical_uuid(&environment_id).map_err(|_| {
            tonic::Status::invalid_argument("host control requires canonical environment UUID")
        })?;
        Ok(Self {
            inner: v1::host_control_service_client::HostControlServiceClient::new(channel)
                .max_decoding_message_size(crate::host_control::HOST_CONTROL_MAX_MESSAGE_BYTES)
                .max_encoding_message_size(crate::host_control::HOST_CONTROL_MAX_MESSAGE_BYTES),
            auth_token: SessionClient::parse_auth_token(daemon_token)?,
            environment_id,
        })
    }

    fn authorized<T>(&self, value: T) -> Request<T> {
        let mut request = Request::new(value);
        request
            .metadata_mut()
            .insert(DAEMON_AUTH_TOKEN_HEADER, self.auth_token.clone());
        request
    }

    pub async fn require_ready(&self) -> Result<v1::HostControlInfoResponse, SessionClientError> {
        let mut client = self.inner.clone();
        let info = client
            .get_host_control_info(self.authorized(v1::HostControlInfoRequest {}))
            .await?
            .into_inner();
        if info.protocol_version != crate::host_control::HOST_CONTROL_PROTOCOL
            || info.environment_id != self.environment_id
            || !matches!(
                info.managed_agent_protocol_version,
                0 | crate::host_control::managed::PROTOCOL
            )
            || info.verbs
                != crate::host_control::managed::verbs(info.managed_agent_protocol_version != 0)
        {
            return Err(tonic::Status::failed_precondition(
                "host control protocol or identity is unavailable",
            )
            .into());
        }
        Ok(info)
    }

    pub async fn require_managed_ready(
        &self,
    ) -> Result<v1::HostControlInfoResponse, SessionClientError> {
        let info = self.require_ready().await?;
        if info.managed_agent_protocol_version != crate::host_control::managed::PROTOCOL {
            return Err(tonic::Status::failed_precondition(
                "member managed agents are unavailable on this owner",
            )
            .into());
        }
        Ok(info)
    }

    fn scope(&self, scope: Option<&v1::HostControlScope>) -> Result<(), SessionClientError> {
        let scope =
            scope.ok_or_else(|| tonic::Status::invalid_argument("missing host control scope"))?;
        crate::host_control::Scope::from_wire(scope.clone())
            .map_err(|_| tonic::Status::invalid_argument("invalid host control scope"))?;
        if scope.environment_id != self.environment_id {
            return Err(tonic::Status::failed_precondition(
                "host control environment identity changed",
            )
            .into());
        }
        Ok(())
    }

    fn grant_response(
        &self,
        response: v1::HostControlGrantsResponse,
    ) -> Result<v1::HostControlGrantsResponse, SessionClientError> {
        let mut ids = std::collections::BTreeSet::new();
        if response.environment_id != self.environment_id
            || response.grants.len() > 128
            || response.grants.iter().any(|grant| {
                let scope = v1::HostControlScope {
                    environment_id: grant.environment_id.clone(),
                    org_id: grant.org_id.clone(),
                    network_id: grant.network_id.clone(),
                    caller_key: grant.caller_key.clone(),
                    target_key: grant.target_key.clone(),
                    grant_id: grant.grant_id.clone(),
                    expected_grant_revision: grant.revision,
                };
                self.scope(Some(&scope)).is_err()
                    || !ids.insert(grant.grant_id.clone())
                    || grant.revision > response.book_revision
                    || grant.verbs.is_empty()
                    || grant.verbs.len() > 11
                    || !grant.verbs.windows(2).all(|pair| pair[0] < pair[1])
                    || grant.verbs.iter().any(|verb| {
                        !matches!(
                            v1::HostControlVerb::try_from(*verb),
                            Ok(v1::HostControlVerb::Read
                                | v1::HostControlVerb::Launch
                                | v1::HostControlVerb::Input
                                | v1::HostControlVerb::Stop
                                | v1::HostControlVerb::ManagedLaunch
                                | v1::HostControlVerb::ManagedMessage
                                | v1::HostControlVerb::ManagedSteer
                                | v1::HostControlVerb::ManagedInterrupt
                                | v1::HostControlVerb::ManagedStop
                                | v1::HostControlVerb::ManagedRestart
                                | v1::HostControlVerb::ManagedRead)
                        )
                    })
            })
        {
            return Err(tonic::Status::failed_precondition(
                "host control grant environment changed",
            )
            .into());
        }
        Ok(response)
    }

    pub async fn grants(&self) -> Result<v1::HostControlGrantsResponse, SessionClientError> {
        self.require_ready().await?;
        let mut client = self.inner.clone();
        let response = client
            .list_host_control_grants(self.authorized(v1::HostControlInfoRequest {}))
            .await?
            .into_inner();
        self.grant_response(response)
    }

    pub async fn put_grant(
        &self,
        request: v1::HostControlPutGrantRequest,
    ) -> Result<v1::HostControlGrantsResponse, SessionClientError> {
        if request
            .grant
            .as_ref()
            .is_none_or(|grant| grant.environment_id != self.environment_id)
        {
            return Err(tonic::Status::invalid_argument(
                "host control grant requires exact environment UUID",
            )
            .into());
        }
        self.require_ready().await?;
        let mut client = self.inner.clone();
        let response = client
            .put_host_control_grant(self.authorized(request))
            .await?
            .into_inner();
        self.grant_response(response)
    }

    pub async fn revoke_grant(
        &self,
        request: v1::HostControlRevokeGrantRequest,
    ) -> Result<v1::HostControlGrantsResponse, SessionClientError> {
        self.require_ready().await?;
        let mut client = self.inner.clone();
        let response = client
            .revoke_host_control_grant(self.authorized(request))
            .await?
            .into_inner();
        self.grant_response(response)
    }

    fn receipt(
        &self,
        response: v1::HostControlReceipt,
        request_id: &str,
        scope: &v1::HostControlScope,
    ) -> Result<v1::HostControlReceipt, SessionClientError> {
        if response.request_id != request_id
            || response.scope.as_ref() != Some(scope)
            || crate::host_control::valid_sha256(&response.fingerprint_sha256).is_err()
            || crate::host_control::session_id(&response.session_id).is_err()
            || response.launch_generation == 0
            || !matches!(
                v1::HostControlVerb::try_from(response.verb),
                Ok(v1::HostControlVerb::Launch
                    | v1::HostControlVerb::Input
                    | v1::HostControlVerb::Stop
                    | v1::HostControlVerb::ManagedLaunch
                    | v1::HostControlVerb::ManagedMessage
                    | v1::HostControlVerb::ManagedSteer
                    | v1::HostControlVerb::ManagedInterrupt
                    | v1::HostControlVerb::ManagedStop
                    | v1::HostControlVerb::ManagedRestart)
            )
            || v1::SessionLifecycleState::try_from(response.session_state).is_err()
            || (response.input_acknowledged
                && (!crate::host_control::managed::is_input(response.verb)
                    || response.phase != v1::HostControlRequestPhase::Completed as i32
                    || response.cleanup_unknown))
            || (response.phase == v1::HostControlRequestPhase::Completed as i32
                && (response.cleanup_unknown
                    || response.session_state == v1::SessionLifecycleState::Unspecified as i32))
            || (response.phase == v1::HostControlRequestPhase::Unknown as i32
                && !response.cleanup_unknown)
            || !matches!(
                v1::HostControlRequestPhase::try_from(response.phase),
                Ok(v1::HostControlRequestPhase::Pending
                    | v1::HostControlRequestPhase::Issued
                    | v1::HostControlRequestPhase::Completed
                    | v1::HostControlRequestPhase::Rejected
                    | v1::HostControlRequestPhase::Unknown)
            )
        {
            return Err(tonic::Status::failed_precondition(
                "host control receipt identity is unavailable; retain original request",
            )
            .into());
        }
        if crate::host_control::managed::is_managed(response.verb) {
            if crate::host_control::canonical_uuid(&response.driver_id).is_err()
                || response.session_id != format!("session-{}", response.driver_id)
                || (!response.message_id.is_empty()
                    && crate::host_control::canonical_uuid(&response.message_id).is_err())
            {
                return Err(
                    tonic::Status::failed_precondition("managed receipt binding differs").into(),
                );
            }
            if (crate::host_control::managed::is_input(response.verb)
                && response.message_id != response.request_id)
                || (response.verb == v1::HostControlVerb::ManagedLaunch as i32
                    && (response.driver_id != response.request_id
                        || response.launch_generation != 1
                        || (!response.message_id.is_empty()
                            && response.message_id != response.request_id)))
                || (matches!(response.verb, 9 | 10) && !response.message_id.is_empty())
            {
                return Err(tonic::Status::failed_precondition(
                    "managed receipt reservation differs",
                )
                .into());
            }
        } else if !response.driver_id.is_empty() || !response.message_id.is_empty() {
            return Err(tonic::Status::failed_precondition(
                "terminal receipt carries managed identity",
            )
            .into());
        }
        Ok(response)
    }

    fn mutation_receipt(
        &self,
        response: v1::HostControlReceipt,
        validated: &crate::host_control::Mutation,
    ) -> Result<v1::HostControlReceipt, SessionClientError> {
        let response = self.receipt(response, &validated.request_id, &validated.scope.to_wire())?;
        let reserved = crate::host_control::Receipt::pending(validated);
        let restarted = response.verb == v1::HostControlVerb::ManagedRestart as i32
            && matches!(
                v1::HostControlRequestPhase::try_from(response.phase),
                Ok(v1::HostControlRequestPhase::Completed | v1::HostControlRequestPhase::Unknown)
            )
            && Some(response.launch_generation) == reserved.generation.checked_add(1);
        if response.fingerprint_sha256 != validated.fingerprint
            || response.verb != validated.verb() as i32
            || response.session_id != reserved.session_id
            || response.driver_id != reserved.driver_id
            || response.message_id != reserved.message_id
            || (response.launch_generation != reserved.generation && !restarted)
            || (response.verb == v1::HostControlVerb::ManagedRestart as i32
                && response.phase == v1::HostControlRequestPhase::Completed as i32
                && !restarted)
        {
            return Err(tonic::Status::failed_precondition(
                "host control request fingerprint changed; retain original request",
            )
            .into());
        }
        Ok(response)
    }

    pub async fn mutate(
        &self,
        request: v1::HostControlMutationRequest,
    ) -> Result<v1::HostControlReceipt, SessionClientError> {
        self.scope(request.scope.as_ref())?;
        let validated = crate::host_control::Mutation::from_wire(request.clone())
            .map_err(|_| tonic::Status::invalid_argument("invalid host control mutation"))?;
        if crate::host_control::managed::is_managed(validated.verb() as i32) {
            self.require_managed_ready().await?;
        } else {
            self.require_ready().await?;
        }
        let mut client = self.inner.clone();
        let response = client
            .mutate_host_session(self.authorized(request))
            .await?
            .into_inner();
        self.mutation_receipt(response, &validated)
    }

    pub async fn observe(
        &self,
        request: v1::HostControlObserveRequest,
    ) -> Result<v1::HostControlReceipt, SessionClientError> {
        self.scope(request.scope.as_ref())?;
        crate::host_control::canonical_uuid(&request.request_id)
            .map_err(|_| tonic::Status::invalid_argument("invalid host control request UUID"))?;
        self.require_ready().await?;
        let mut client = self.inner.clone();
        let response = client
            .observe_host_request(self.authorized(request.clone()))
            .await?
            .into_inner();
        self.receipt(
            response,
            &request.request_id,
            request.scope.as_ref().expect("scope was validated"),
        )
    }

    pub async fn list(
        &self,
        request: v1::HostControlReadRequest,
    ) -> Result<v1::HostControlListSessionsResponse, SessionClientError> {
        self.scope(request.scope.as_ref())?;
        self.require_ready().await?;
        let mut client = self.inner.clone();
        let after = request.after_session_id.clone();
        let maximum = if request.page_limit == 0 {
            8
        } else {
            request.page_limit as usize
        };
        let response = client
            .list_host_sessions(self.authorized(request))
            .await?
            .into_inner();
        use prost::Message;
        let mut previous = after.as_str();
        if response.sessions.len() > maximum.min(8)
            || response.encoded_len() > 256 * 1024
            || response.sessions.iter().any(|record| {
                let refused = record.session_id.as_str() <= previous
                    || record.launch_generation == 0
                    || crate::host_control::session_id(&record.session_id).is_err();
                previous = &record.session_id;
                refused
            })
            || (!response.next_session_id.is_empty()
                && response
                    .sessions
                    .last()
                    .is_none_or(|record| response.next_session_id != record.session_id))
        {
            return Err(tonic::Status::failed_precondition(
                "host control page identity or bound changed",
            )
            .into());
        }
        Ok(response)
    }

    pub async fn get(
        &self,
        request: v1::HostControlReadRequest,
    ) -> Result<v1::SessionRecord, SessionClientError> {
        self.scope(request.scope.as_ref())?;
        self.require_ready().await?;
        let expected_id = request.session_id.clone();
        let mut client = self.inner.clone();
        let session = client
            .get_host_session(self.authorized(request))
            .await?
            .into_inner()
            .session
            .ok_or(SessionClientError::MissingSessionRecord)?;
        if session.session_id != expected_id || session.launch_generation == 0 {
            return Err(tonic::Status::failed_precondition(
                "host control session identity changed",
            )
            .into());
        }
        Ok(session)
    }

    pub async fn read_output(
        &self,
        request: v1::HostControlReadRequest,
    ) -> Result<v1::ReadSessionOutputResponse, SessionClientError> {
        self.scope(request.scope.as_ref())?;
        self.require_ready().await?;
        let mut client = self.inner.clone();
        Ok(client
            .read_host_session_output(self.authorized(request))
            .await?
            .into_inner())
    }

    pub async fn read_managed_chunks(
        &self,
        request: v1::HostControlManagedReadRequest,
    ) -> Result<Vec<v1::HostControlManagedRecordChunk>, SessionClientError> {
        self.scope(request.scope.as_ref())?;
        self.require_managed_ready().await?;
        let mut client = self.inner.clone();
        let mut stream = client
            .read_host_managed_session(self.authorized(request.clone()))
            .await?
            .into_inner();
        let mut chunks = Vec::new();
        let mut total = 0usize;
        while let Some(chunk) = stream.message().await? {
            total = total
                .checked_add(chunk.data.len())
                .ok_or_else(|| tonic::Status::resource_exhausted("managed record too large"))?;
            if total > crate::host_control::managed::MAX_RECORD_REPLY || chunks.len() >= 32 {
                return Err(tonic::Status::resource_exhausted("managed record too large").into());
            }
            chunks.push(chunk);
        }
        validate_host_managed_chunks(&request, &chunks)?;
        Ok(chunks)
    }
}

#[cfg(target_os = "linux")]
pub fn validate_host_managed_chunks(
    request: &v1::HostControlManagedReadRequest,
    chunks: &[v1::HostControlManagedRecordChunk],
) -> Result<Vec<u8>, SessionClientError> {
    use prost::Message;
    use sha2::{Digest, Sha256};
    let failure =
        || tonic::Status::failed_precondition("managed record framing or identity differs");
    let first = chunks.first().ok_or_else(failure)?;
    if first.total_bytes == 0
        || first.total_bytes > crate::host_control::managed::MAX_RECORD_REPLY as u64
        || chunks.len() > 32
        || crate::host_control::valid_sha256(&first.payload_sha256).is_err()
    {
        return Err(failure().into());
    }
    let mut bytes = Vec::with_capacity(first.total_bytes as usize);
    for chunk in chunks {
        if chunk.session_id != request.session_id
            || chunk.driver_id != request.driver_id
            || chunk.message_id != request.message_id
            || chunk.launch_generation != request.expected_launch_generation
            || chunk.offset != bytes.len() as u64
            || chunk.total_bytes != first.total_bytes
            || chunk.payload_sha256 != first.payload_sha256
            || chunk.data.is_empty()
            || chunk.encoded_len() + 1 > crate::host_control::managed::MAX_CHUNK
            || bytes.len() + chunk.data.len() > first.total_bytes as usize
        {
            return Err(failure().into());
        }
        bytes.extend_from_slice(&chunk.data);
    }
    if bytes.len() as u64 != first.total_bytes
        || format!("{:x}", Sha256::digest(&bytes)) != first.payload_sha256
    {
        return Err(failure().into());
    }
    Ok(bytes)
}

pub struct SessionAttachment {
    input: mpsc::Sender<v1::SessionAttachMessage>,
    output: Streaming<v1::SessionAttachMessage>,
    session_id: String,
}

#[cfg(all(test, target_os = "linux"))]
mod host_control_tests {
    use super::*;
    use crate::host_control::tests as fixture;

    fn client() -> HostControlClient {
        // No request is issued. A lazy channel supplies only the generated
        // wrapper type for these hostile response-admission fixtures.
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        HostControlClient::from_channel(channel, "synthetic-owner", fixture::scope().environment_id)
            .unwrap()
    }

    #[tokio::test]
    async fn host_control_client_requires_exact_mutation_session_generation_and_fingerprint() {
        let client = client();
        let request = fixture::stop(
            3,
            &fixture::scope(),
            &format!("session-{}", uuid::Uuid::from_u128(4)),
            7,
        );
        let receipt = v1::HostControlReceipt {
            request_id: request.request_id.clone(),
            scope: Some(request.scope.to_wire()),
            fingerprint_sha256: request.fingerprint.clone(),
            verb: v1::HostControlVerb::Stop as i32,
            phase: v1::HostControlRequestPhase::Completed as i32,
            session_id: format!("session-{}", uuid::Uuid::from_u128(4)),
            launch_generation: 7,
            session_state: v1::SessionLifecycleState::Stopped as i32,
            exit_code: None,
            cleanup_unknown: false,
            input_acknowledged: false,
            reason: "completed".into(),
            ..Default::default()
        };
        assert!(client.mutation_receipt(receipt.clone(), &request).is_ok());
        let mut changed = receipt.clone();
        changed.launch_generation = 8;
        assert!(client.mutation_receipt(changed, &request).is_err());
        let mut changed = receipt.clone();
        changed.session_id = format!("session-{}", uuid::Uuid::from_u128(5));
        assert!(client.mutation_receipt(changed, &request).is_err());
        let mut changed = receipt;
        changed.fingerprint_sha256 = "0".repeat(64);
        assert!(client.mutation_receipt(changed, &request).is_err());
    }

    #[tokio::test]
    async fn host_control_client_refuses_false_unknown_ack_and_unspecified_outcomes() {
        let client = client();
        let request = fixture::input(
            3,
            &fixture::scope(),
            &format!("session-{}", uuid::Uuid::from_u128(4)),
            1,
            b"public-fixture\n",
        );
        let receipt = v1::HostControlReceipt {
            request_id: request.request_id.clone(),
            scope: Some(request.scope.to_wire()),
            fingerprint_sha256: request.fingerprint.clone(),
            verb: v1::HostControlVerb::Input as i32,
            phase: v1::HostControlRequestPhase::Completed as i32,
            session_id: format!("session-{}", uuid::Uuid::from_u128(4)),
            launch_generation: 1,
            session_state: v1::SessionLifecycleState::Running as i32,
            exit_code: None,
            cleanup_unknown: false,
            input_acknowledged: true,
            reason: "input_acknowledged".into(),
            ..Default::default()
        };
        assert!(client.mutation_receipt(receipt.clone(), &request).is_ok());
        for field in ["unknown", "zero-state", "zero-verb", "foreign-scope"] {
            let mut changed = receipt.clone();
            match field {
                "unknown" => {
                    changed.phase = v1::HostControlRequestPhase::Unknown as i32;
                    changed.cleanup_unknown = true;
                }
                "zero-state" => changed.session_state = 0,
                "zero-verb" => changed.verb = 0,
                "foreign-scope" => changed.scope.as_mut().unwrap().caller_key = vec![9; 32],
                _ => unreachable!(),
            }
            assert!(
                client.mutation_receipt(changed, &request).is_err(),
                "{field}"
            );
        }
    }

    #[tokio::test]
    async fn host_control_client_refuses_duplicate_partial_or_foreign_grants() {
        let client = client();
        let mut grant = fixture::grant(&fixture::scope(), 0).grant.unwrap();
        grant.revision = 1;
        let response = v1::HostControlGrantsResponse {
            environment_id: fixture::scope().environment_id,
            book_revision: 1,
            grants: vec![grant.clone()],
        };
        assert!(client.grant_response(response.clone()).is_ok());
        let mut duplicate = response.clone();
        duplicate.grants.push(grant.clone());
        assert!(client.grant_response(duplicate).is_err());
        for field in ["key", "environment", "verb", "revision"] {
            let mut changed = response.clone();
            match field {
                "key" => changed.grants[0].caller_key.pop().map(|_| ()).unwrap(),
                "environment" => {
                    changed.grants[0].environment_id = uuid::Uuid::from_u128(90).to_string()
                }
                "verb" => changed.grants[0].verbs.push(999),
                "revision" => changed.grants[0].revision = 2,
                _ => unreachable!(),
            }
            assert!(client.grant_response(changed).is_err(), "{field}");
        }
    }

    #[tokio::test]
    async fn host_control_client_managed_receipts_preserve_reserved_ids_and_exact_restart_cas() {
        let client = client();
        let driver = uuid::Uuid::from_u128(4).to_string();
        let sid = format!("session-{driver}");
        for action in [
            v1::HostManagedAction::Message,
            v1::HostManagedAction::Restart,
        ] {
            let mutation =
                crate::host_control::Mutation::from_wire(v1::HostControlMutationRequest {
                    request_id: uuid::Uuid::from_u128(3).to_string(),
                    scope: Some(fixture::scope().to_wire()),
                    operation: Some(
                        v1::host_control_mutation_request::Operation::ManagedControl(
                            v1::HostControlManagedControl {
                                action: action as i32,
                                session_id: sid.clone(),
                                driver_id: driver.clone(),
                                expected_launch_generation: 7,
                                text: if action == v1::HostManagedAction::Message {
                                    "hello".into()
                                } else {
                                    String::new()
                                },
                                ..Default::default()
                            },
                        ),
                    ),
                })
                .unwrap();
            let mut response = crate::host_control::Receipt::pending(&mutation).to_wire();
            response.phase = v1::HostControlRequestPhase::Completed as i32;
            response.reason = "completed".into();
            response.session_state = v1::SessionLifecycleState::Running as i32;
            response.input_acknowledged = action == v1::HostManagedAction::Message;
            if action == v1::HostManagedAction::Restart {
                response.launch_generation = 8;
            }
            assert!(client.mutation_receipt(response.clone(), &mutation).is_ok());
            for field in ["driver", "message", "generation", "fingerprint", "scope"] {
                let mut changed = response.clone();
                match field {
                    "driver" => changed.driver_id = uuid::Uuid::new_v4().to_string(),
                    "message" => changed.message_id = uuid::Uuid::new_v4().to_string(),
                    "generation" => {
                        changed.launch_generation = if action == v1::HostManagedAction::Restart {
                            7
                        } else {
                            8
                        }
                    }
                    "fingerprint" => changed.fingerprint_sha256 = "ff".repeat(32),
                    "scope" => changed.scope.as_mut().unwrap().target_key[0] ^= 1,
                    _ => unreachable!(),
                }
                assert!(
                    client.mutation_receipt(changed, &mutation).is_err(),
                    "{action:?} {field}"
                );
            }
            response.phase = v1::HostControlRequestPhase::Unknown as i32;
            response.input_acknowledged = false;
            response.cleanup_unknown = true;
            response.reason = "unknown".into();
            assert!(client.mutation_receipt(response.clone(), &mutation).is_ok());
            if action == v1::HostManagedAction::Restart {
                response.launch_generation = 7;
                assert!(client.mutation_receipt(response.clone(), &mutation).is_ok());
                response.launch_generation = 9;
                assert!(client.mutation_receipt(response, &mutation).is_err());
            }
        }
    }
}

#[derive(Clone)]
pub struct SessionAttachmentInput {
    input: mpsc::Sender<v1::SessionAttachMessage>,
    session_id: String,
}

/// Authenticated host side of one generation-bound credential bridge.
///
/// Both directions carry only guest request bytes and broker-redacted response
/// bytes. This API has no credential field; callers must redact all protected
/// material before constructing response headers or body frames.
pub struct CredentialBridgeConnection {
    input: mpsc::Sender<bridge_v1::CredentialBridgeHostMessage>,
    output: Streaming<bridge_v1::CredentialBridgeGuestMessage>,
}

/// Cloneable response-only half of an authenticated credential bridge.
/// Callers must send only provider-filtered, already-redacted bytes.
#[derive(Clone)]
pub struct CredentialBridgeResponseSender {
    input: mpsc::Sender<bridge_v1::CredentialBridgeHostMessage>,
    _hosted_lifetime: Option<Arc<hosted::HostedLifetime>>,
}

/// An inactive hosted stream. No Open has been sent and no live daemon epoch
/// replaced. Its fixed-purpose token is never exposed by Debug or a session RPC.
pub struct PreparedHostedCredentialBridge {
    input: mpsc::Sender<bridge_v1::CredentialBridgeHostMessage>,
    ready: bridge_v1::CredentialBridgeReady,
    workspace_authorization: Zeroizing<Vec<u8>>,
    hosted_lifetime: Arc<hosted::HostedLifetime>,
}

impl PreparedHostedCredentialBridge {
    pub fn ready(&self) -> &bridge_v1::CredentialBridgeReady {
        &self.ready
    }
    pub fn workspace_authorization(&self) -> &[u8] {
        &self.workspace_authorization
    }

    /// Call only after the isolated broker returned authenticated admission
    /// headers for this stream's real Ready and both exact Pod tokens.
    /// `capabilities` are the optional operations that broker listed in those
    /// headers; the daemon sends such an operation only when its Open lists
    /// it. Only bounded, canonical names this build knows are forwarded.
    pub async fn activate(
        self,
        capabilities: &[String],
    ) -> Result<CredentialBridgeResponseSender, SessionClientError> {
        let mut forwarded = Vec::new();
        for capability in capabilities {
            if codewire_daemon_proto::CREDENTIAL_BRIDGE_KNOWN_CAPABILITIES
                .contains(&capability.as_str())
                && !forwarded.contains(capability)
                && forwarded.len() < codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_CAPABILITIES
            {
                forwarded.push(capability.clone());
            }
        }
        self.input
            .send(bridge_v1::CredentialBridgeHostMessage {
                payload: Some(bridge_v1::credential_bridge_host_message::Payload::Open(
                    bridge_v1::CredentialBridgeOpen {
                        protocol_version: self.ready.protocol_version,
                        environment_id: self.ready.environment_id.clone(),
                        environment_generation: self.ready.environment_generation,
                        capabilities: forwarded,
                    },
                )),
            })
            .await
            .map_err(|_| SessionClientError::RequestClosed)?;
        Ok(CredentialBridgeResponseSender {
            input: self.input,
            _hosted_lifetime: Some(self.hosted_lifetime),
        })
    }
}

impl SessionClient {
    /// Build a daemon client over a caller-provided transport channel.
    ///
    /// The channel may use TCP, a Unix socket, AF_VSOCK, or another tonic
    /// connector. Transport establishment and its host-side authorization are
    /// deliberately owned by the caller; daemon RPC authentication still uses
    /// the supplied token.
    pub fn from_channel(
        channel: Channel,
        daemon_token: impl AsRef<str>,
    ) -> Result<Self, SessionClientError> {
        let auth_token = Self::parse_auth_token(daemon_token)?;
        Ok(Self {
            inner: v1::daemon_service_client::DaemonServiceClient::new(channel)
                .max_decoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES),
            auth_token,
        })
    }

    pub async fn connect(
        endpoint: impl AsRef<str>,
        daemon_token: impl AsRef<str>,
    ) -> Result<Self, SessionClientError> {
        let endpoint = endpoint.as_ref().trim();
        let daemon_token = daemon_token.as_ref().trim();
        if daemon_token.is_empty() {
            return Err(SessionClientError::InvalidCredential);
        }
        let channel = Endpoint::from_shared(endpoint.to_string())
            .map_err(|_| SessionClientError::InvalidEndpoint)?
            .connect_timeout(Duration::from_secs(3))
            .connect()
            .await
            .map_err(|_| SessionClientError::Connect)?;
        Self::from_channel(channel, daemon_token)
    }

    fn parse_auth_token(
        daemon_token: impl AsRef<str>,
    ) -> Result<MetadataValue<tonic::metadata::Ascii>, SessionClientError> {
        let daemon_token = daemon_token.as_ref().trim();
        if daemon_token.is_empty() {
            return Err(SessionClientError::InvalidCredential);
        }
        let mut auth_token = MetadataValue::try_from(daemon_token)
            .map_err(|_| SessionClientError::InvalidCredential)?;
        auth_token.set_sensitive(true);
        Ok(auth_token)
    }

    pub async fn require_ready(&self) -> Result<(), SessionClientError> {
        let response = self
            .get_capabilities(&[DAEMON_CAPABILITY_SESSIONS, DAEMON_CAPABILITY_ATTACH])
            .await?;
        if response.state != v1::DaemonState::Ready as i32 {
            return Err(SessionClientError::NotReady {
                message: response.message,
            });
        }
        for capability in [DAEMON_CAPABILITY_SESSIONS, DAEMON_CAPABILITY_ATTACH] {
            if !response
                .capabilities
                .iter()
                .any(|value| value == capability)
            {
                return Err(SessionClientError::MissingCapability { capability });
            }
        }
        Ok(())
    }

    pub async fn get_capabilities(
        &self,
        required_capabilities: &[&str],
    ) -> Result<v1::GetCapabilitiesResponse, SessionClientError> {
        let mut client = self.inner.clone();
        Ok(client
            .get_capabilities(
                self.authorized(v1::GetCapabilitiesRequest {
                    protocol_version: DAEMON_PROTOCOL_VERSION,
                    required_capabilities: required_capabilities
                        .iter()
                        .map(|capability| (*capability).to_string())
                        .collect(),
                }),
            )
            .await?
            .into_inner())
    }

    pub async fn get_health(&self) -> Result<v1::GetHealthResponse, SessionClientError> {
        let mut client = self.inner.clone();
        Ok(client
            .get_health(self.authorized(v1::GetHealthRequest {}))
            .await?
            .into_inner())
    }

    /// Request the trusted guest's fixed lifecycle action, without starting a
    /// workload or resolving application values. VM exit, not this RPC's ACK,
    /// is the runner's completion proof; poweroff may close the transport first.
    pub async fn poweroff_guest(&self) -> Result<(), SessionClientError> {
        self.inner
            .clone()
            .poweroff_guest(self.authorized(v1::PoweroffGuestRequest {}))
            .await?;
        Ok(())
    }

    pub async fn open_credential_bridge(
        &self,
        environment_id: Uuid,
        environment_generation: u64,
    ) -> Result<CredentialBridgeConnection, SessionClientError> {
        self.open_credential_bridge_with_capabilities(environment_id, environment_generation, &[])
            .await
    }

    /// [`Self::open_credential_bridge`], listing the optional operations this
    /// host serves on the epoch. Only bounded, canonical names this build
    /// knows are sent; the daemon sends such an operation only when listed.
    pub async fn open_credential_bridge_with_capabilities(
        &self,
        environment_id: Uuid,
        environment_generation: u64,
        capabilities: &[&str],
    ) -> Result<CredentialBridgeConnection, SessionClientError> {
        if environment_id.is_nil() || environment_generation == 0 {
            return Err(SessionClientError::InvalidCredential);
        }
        let mut listed = Vec::new();
        for capability in capabilities {
            if codewire_daemon_proto::CREDENTIAL_BRIDGE_KNOWN_CAPABILITIES.contains(capability)
                && !listed.iter().any(|known: &String| known == capability)
                && listed.len() < codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_CAPABILITIES
            {
                listed.push((*capability).to_owned());
            }
        }
        let (input, receiver) = mpsc::channel(32);
        input
            .send(bridge_v1::CredentialBridgeHostMessage {
                payload: Some(bridge_v1::credential_bridge_host_message::Payload::Open(
                    bridge_v1::CredentialBridgeOpen {
                        protocol_version: codewire_daemon_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                        environment_id: environment_id.to_string(),
                        environment_generation,
                        capabilities: listed,
                    },
                )),
            })
            .await
            .map_err(|_| SessionClientError::RequestClosed)?;
        let mut client = self.inner.clone();
        let output = client
            .credential_bridge(self.authorized(ReceiverStream::new(receiver)))
            .await?
            .into_inner();
        Ok(CredentialBridgeConnection { input, output })
    }

    /// Prepare the existing private RPC without eagerly sending Open. Hosted
    /// daemons return token metadata and Ready before activation; local daemons
    /// do not support this ordering. The whole preparation has a finite bound.
    pub fn prepare_hosted_credential_bridge(
        &self,
        environment_id: Uuid,
        environment_generation: u64,
    ) -> Result<
        (
            HostedCredentialBridgeDrain,
            impl std::future::Future<
                Output = Result<HostedCredentialBridgePrepared, SessionClientError>,
            > + Send
            + 'static,
        ),
        SessionClientError,
    > {
        if environment_id.is_nil()
            || environment_generation == 0
            || environment_generation > i64::MAX as u64
        {
            return Err(SessionClientError::InvalidCredential);
        }
        let (input, body, hosted_lifetime, drain) = hosted::channel();
        let client_owner = self.clone();
        // The caller owns the drain BEFORE polling any network operation.
        // Dropping this future, a prepared result, or the last response sender
        // cancels the outgoing producer; callers still await its terminal ack.
        let preparation = async move {
            tokio::time::timeout(Duration::from_secs(5), async move {
                let mut client = client_owner.inner.clone();
                let response = client
                    .credential_bridge(client_owner.authorized(body))
                    .await?;
                let mut values = response
                    .metadata()
                    .get_all_bin(HOSTED_WORKSPACE_AUTHORIZATION)
                    .iter();
                let workspace = match (values.next(), values.next()) {
                    (Some(value), None) => value
                        .to_bytes()
                        .map_err(|_| SessionClientError::InvalidCredential)?,
                    _ => return Err(SessionClientError::InvalidCredential),
                };
                let workspace_authorization = Zeroizing::new(workspace.to_vec());
                let token = workspace_authorization
                    .strip_prefix(b"Bearer ")
                    .ok_or(SessionClientError::InvalidCredential)?;
                if token.is_empty()
                    || token.len() > 16 * 1024
                    || !token.iter().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    })
                {
                    return Err(SessionClientError::InvalidCredential);
                }
                let mut output = response.into_inner();
                let ready = output
                    .message()
                    .await?
                    .ok_or(SessionClientError::RequestClosed)?;
                let Some(bridge_v1::credential_bridge_guest_message::Payload::Ready(ready)) =
                    ready.payload
                else {
                    return Err(SessionClientError::InvalidCredential);
                };
                if ready.protocol_version
                    != codewire_daemon_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION
                    || ready.environment_id != environment_id.to_string()
                    || ready.environment_generation != environment_generation
                {
                    return Err(SessionClientError::InvalidCredential);
                }
                Ok((
                    PreparedHostedCredentialBridge {
                        input,
                        ready,
                        workspace_authorization,
                        hosted_lifetime,
                    },
                    output,
                ))
            })
            .await
            .map_err(|_| SessionClientError::Connect)?
        };
        Ok((drain, preparation))
    }

    pub async fn launch(
        &self,
        request: v1::LaunchSessionRequest,
    ) -> Result<v1::SessionRecord, SessionClientError> {
        if !request.name.is_empty() || request.parent_session_id.is_some() {
            self.require_capability(codewire_daemon_proto::DAEMON_CAPABILITY_SESSION_METADATA)
                .await?;
        }
        let mut client = self.inner.clone();
        Self::required_session(
            client
                .launch_session(self.authorized(request))
                .await?
                .into_inner()
                .session,
        )
    }

    pub async fn list(&self) -> Result<Vec<v1::SessionRecord>, SessionClientError> {
        let mut client = self.inner.clone();
        Ok(client
            .list_sessions(self.authorized(v1::ListSessionsRequest {}))
            .await?
            .into_inner()
            .sessions)
    }

    pub async fn get(&self, session_id: &str) -> Result<v1::SessionRecord, SessionClientError> {
        let mut client = self.inner.clone();
        Self::required_session(
            client
                .get_session(self.authorized(v1::GetSessionRequest {
                    session_id: session_id.to_string(),
                }))
                .await?
                .into_inner()
                .session,
        )
    }

    pub async fn stop(&self, session_id: &str) -> Result<v1::SessionRecord, SessionClientError> {
        let mut client = self.inner.clone();
        Self::required_session(
            client
                .stop_session(self.authorized(v1::StopSessionRequest {
                    session_id: session_id.to_string(),
                }))
                .await?
                .into_inner()
                .session,
        )
    }

    pub async fn restart(&self, session_id: &str) -> Result<v1::SessionRecord, SessionClientError> {
        self.restart_with_generation(session_id, None).await
    }

    pub async fn restart_with_generation(
        &self,
        session_id: &str,
        expected_launch_generation: Option<u64>,
    ) -> Result<v1::SessionRecord, SessionClientError> {
        let mut client = self.inner.clone();
        Self::required_session(
            client
                .restart_session(self.authorized(v1::RestartSessionRequest {
                    session_id: session_id.to_string(),
                    expected_launch_generation,
                }))
                .await?
                .into_inner()
                .session,
        )
    }

    async fn require_capability(&self, capability: &'static str) -> Result<(), SessionClientError> {
        let capabilities = self.get_capabilities(&[capability]).await?;
        Self::validate_capability(capabilities, capability)
    }

    fn validate_capability(
        capabilities: v1::GetCapabilitiesResponse,
        capability: &'static str,
    ) -> Result<(), SessionClientError> {
        if !capabilities
            .capabilities
            .iter()
            .any(|value| value == capability)
        {
            return Err(SessionClientError::MissingCapability { capability });
        }
        if capabilities.state != v1::DaemonState::Ready as i32 {
            return Err(SessionClientError::NotReady {
                message: capabilities.message,
            });
        }
        Ok(())
    }

    /// Acknowledged raw input. An ambiguous timeout is never retried.
    pub async fn send_input(
        &self,
        session_id: &str,
        data: Vec<u8>,
    ) -> Result<(), SessionClientError> {
        use codewire_daemon_proto::{
            DAEMON_CAPABILITY_SESSION_INPUT, SESSION_INPUT_MAX_BYTES, SESSION_INPUT_TIMEOUT,
        };
        if data.is_empty() || data.len() > SESSION_INPUT_MAX_BYTES {
            return Err(tonic::Status::invalid_argument(
                "session input must contain 1..65536 bytes",
            )
            .into());
        }
        tokio::time::timeout(SESSION_INPUT_TIMEOUT, async {
            self.require_capability(DAEMON_CAPABILITY_SESSION_INPUT).await?;
            let mut client = self.inner.clone();
            let mut request = self.authorized(v1::SendSessionInputRequest { session_id: session_id.into(), data });
            request.set_timeout(SESSION_INPUT_TIMEOUT);
            client.send_session_input(request).await?;
            Ok(())
        }).await.map_err(|_| SessionClientError::Status(tonic::Status::deadline_exceeded(
            "session input acknowledgement timed out; input may have been written; do not retry automatically")))?
    }

    pub async fn read_output(
        &self,
        request: v1::ReadSessionOutputRequest,
    ) -> Result<v1::ReadSessionOutputResponse, SessionClientError> {
        let mut client = self.inner.clone();
        Ok(client
            .read_session_output(self.authorized(request))
            .await?
            .into_inner())
    }

    /// Start one non-durable exec and close its stdin explicitly.
    ///
    /// The caller must retain and drain (or otherwise keep alive) the returned
    /// stream until the command or its transport ends. This is intended for
    /// private lifecycle control which must not create a user-visible durable
    /// session record.
    pub async fn exec_transient(
        &self,
        request: v1::ExecStartRequest,
    ) -> Result<Streaming<v1::ExecMessage>, SessionClientError> {
        let messages = tokio_stream::iter([
            v1::ExecMessage {
                payload: Some(v1::exec_message::Payload::Start(request)),
            },
            v1::ExecMessage {
                payload: Some(v1::exec_message::Payload::CloseStdin(())),
            },
        ]);
        let mut client = self.inner.clone();
        Ok(client
            .exec_session(self.authorized(messages))
            .await?
            .into_inner())
    }

    pub async fn attach(
        &self,
        session_id: impl Into<String>,
        output_offset: u64,
    ) -> Result<SessionAttachment, SessionClientError> {
        let session_id = session_id.into();
        let (input, rx) = mpsc::channel(32);
        input
            .send(v1::SessionAttachMessage {
                payload: Some(v1::session_attach_message::Payload::Attach(
                    v1::AttachSessionRequest {
                        session_id: session_id.clone(),
                        output_offset,
                    },
                )),
            })
            .await
            .map_err(|_| SessionClientError::RequestClosed)?;
        let mut client = self.inner.clone();
        let output = client
            .attach_session(self.authorized(ReceiverStream::new(rx)))
            .await?
            .into_inner();
        Ok(SessionAttachment {
            input,
            output,
            session_id,
        })
    }

    fn required_session(
        session: Option<v1::SessionRecord>,
    ) -> Result<v1::SessionRecord, SessionClientError> {
        session.ok_or(SessionClientError::MissingSessionRecord)
    }

    fn authorized<T>(&self, value: T) -> Request<T> {
        let mut request = Request::new(value);
        request
            .metadata_mut()
            .insert(DAEMON_AUTH_TOKEN_HEADER, self.auth_token.clone());
        request
    }
}

impl CredentialBridgeConnection {
    pub fn response_sender(&self) -> CredentialBridgeResponseSender {
        CredentialBridgeResponseSender {
            input: self.input.clone(),
            _hosted_lifetime: None,
        }
    }

    pub async fn receive(
        &mut self,
    ) -> Result<Option<bridge_v1::CredentialBridgeGuestMessage>, SessionClientError> {
        let message = self
            .output
            .message()
            .await
            .map_err(SessionClientError::from)?;
        if let Some(message) = &message {
            validate_credential_bridge_guest_message(message)?;
        }
        Ok(message)
    }

    pub async fn send_response_start(
        &self,
        response: bridge_v1::CredentialBridgeResponseStart,
    ) -> Result<(), SessionClientError> {
        self.response_sender().send_response_start(response).await
    }

    pub async fn send_response_body(
        &self,
        response: bridge_v1::CredentialBridgeResponseBody,
    ) -> Result<(), SessionClientError> {
        self.response_sender().send_response_body(response).await
    }

    pub async fn send_response_end(
        &self,
        response: bridge_v1::CredentialBridgeResponseEnd,
    ) -> Result<(), SessionClientError> {
        self.response_sender().send_response_end(response).await
    }

    pub async fn send_response_failure(
        &self,
        response: bridge_v1::CredentialBridgeResponseFailure,
    ) -> Result<(), SessionClientError> {
        self.response_sender().send_response_failure(response).await
    }

    pub async fn send_ssh(
        &self,
        response: bridge_v1::CredentialSshResponse,
    ) -> Result<(), SessionClientError> {
        self.response_sender().send_ssh(response).await
    }
}

impl CredentialBridgeResponseSender {
    pub async fn send_environment_projection(
        &self,
        response: bridge_v1::EnvironmentProjectionResponse,
    ) -> Result<(), SessionClientError> {
        self.send(
            bridge_v1::credential_bridge_host_message::Payload::EnvironmentProjection(response),
        )
        .await
    }

    /// Forward one opaque sealed Codex login or its closed failure. The relay
    /// never opens it; only the requesting daemon's recipient key can.
    pub async fn send_codex_login(
        &self,
        response: bridge_v1::CodexLoginResponse,
    ) -> Result<(), SessionClientError> {
        self.send(bridge_v1::credential_bridge_host_message::Payload::CodexLogin(response))
            .await
    }

    pub async fn send_claude_login(
        &self,
        response: bridge_v1::ClaudeLoginResponse,
    ) -> Result<(), SessionClientError> {
        self.send(bridge_v1::credential_bridge_host_message::Payload::ClaudeLogin(response))
            .await
    }

    pub async fn send_response_start(
        &self,
        response: bridge_v1::CredentialBridgeResponseStart,
    ) -> Result<(), SessionClientError> {
        self.send(bridge_v1::credential_bridge_host_message::Payload::ResponseStart(response))
            .await
    }

    pub async fn send_response_body(
        &self,
        response: bridge_v1::CredentialBridgeResponseBody,
    ) -> Result<(), SessionClientError> {
        self.send(bridge_v1::credential_bridge_host_message::Payload::ResponseBody(response))
            .await
    }

    pub async fn send_response_end(
        &self,
        response: bridge_v1::CredentialBridgeResponseEnd,
    ) -> Result<(), SessionClientError> {
        self.send(bridge_v1::credential_bridge_host_message::Payload::ResponseEnd(response))
            .await
    }

    pub async fn send_response_failure(
        &self,
        response: bridge_v1::CredentialBridgeResponseFailure,
    ) -> Result<(), SessionClientError> {
        self.send(bridge_v1::credential_bridge_host_message::Payload::ResponseFailure(response))
            .await
    }

    /// Forward a response already correlated and validated by the shared
    /// credential bridge. This transport repeats bounded shape validation;
    /// only the shared bridge owns the pending request's operation and may
    /// prove that a failure or success matches it.
    pub async fn send_ssh(
        &self,
        response: bridge_v1::CredentialSshResponse,
    ) -> Result<(), SessionClientError> {
        validate_ssh_response_shape(&response)?;
        self.send(bridge_v1::credential_bridge_host_message::Payload::Ssh(
            response,
        ))
        .await
    }

    async fn send(
        &self,
        payload: bridge_v1::credential_bridge_host_message::Payload,
    ) -> Result<(), SessionClientError> {
        self.input
            .send(bridge_v1::CredentialBridgeHostMessage {
                payload: Some(payload),
            })
            .await
            .map_err(|_| SessionClientError::RequestClosed)
    }
}

fn validate_credential_bridge_guest_message(
    message: &bridge_v1::CredentialBridgeGuestMessage,
) -> Result<(), SessionClientError> {
    // A malformed frame ends the epoch. The deadline is the request's own:
    // its handler refuses an out-of-range one with a typed failure, and the
    // epoch keeps serving every other request (#2763).
    if let Some(bridge_v1::credential_bridge_guest_message::Payload::Ssh(request)) =
        &message.payload
    {
        ssh::validate_request_shape(request).map_err(SessionClientError::Status)?;
    }
    Ok(())
}

fn validate_ssh_response_shape(
    response: &bridge_v1::CredentialSshResponse,
) -> Result<(), SessionClientError> {
    use bridge_v1::credential_ssh_response::Result;
    let operation = match response.result.as_ref() {
        Some(Result::Identity(_)) => SshOperation::Identities,
        Some(Result::Signature(_)) => SshOperation::Sign,
        // A closed failure is valid for either operation. Request correlation
        // remains in CredentialBridge::relay_ssh, not this shallow transport.
        Some(Result::Failure(_)) | None => SshOperation::Identities,
    };
    ssh::validate_response(response, operation).map_err(SessionClientError::Status)
}

#[cfg(test)]
#[path = "client/credential_bridge_tests.rs"]
mod credential_bridge_tests;

impl SessionAttachment {
    pub fn input_handle(&self) -> SessionAttachmentInput {
        SessionAttachmentInput {
            input: self.input.clone(),
            session_id: self.session_id.clone(),
        }
    }

    pub async fn next_event(
        &mut self,
    ) -> Result<Option<v1::SessionAttachMessage>, SessionClientError> {
        Ok(self.output.message().await?)
    }
}

impl SessionAttachmentInput {
    pub async fn send_input(&self, data: Vec<u8>) -> Result<(), SessionClientError> {
        self.send(v1::session_attach_message::Payload::Input(
            v1::SessionInput { data },
        ))
        .await
    }

    pub async fn resize(&self, width: i32, height: i32) -> Result<(), SessionClientError> {
        self.send(v1::session_attach_message::Payload::Resize(
            v1::ResizeRequest { width, height },
        ))
        .await
    }

    pub async fn detach(&self) -> Result<(), SessionClientError> {
        self.send(v1::session_attach_message::Payload::Detach(
            v1::DetachSessionRequest {
                session_id: self.session_id.clone(),
            },
        ))
        .await
    }

    async fn send(
        &self,
        payload: v1::session_attach_message::Payload,
    ) -> Result<(), SessionClientError> {
        self.input
            .send(v1::SessionAttachMessage {
                payload: Some(payload),
            })
            .await
            .map_err(|_| SessionClientError::RequestClosed)
    }
}

#[cfg(test)]
mod session_input_capability_tests {
    use super::*;
    #[test]
    fn old_daemon_rejects_new_input_and_metadata_capabilities_before_dispatch() {
        for capability in [
            codewire_daemon_proto::DAEMON_CAPABILITY_SESSION_INPUT,
            codewire_daemon_proto::DAEMON_CAPABILITY_SESSION_METADATA,
        ] {
            let old = v1::GetCapabilitiesResponse {
                state: v1::DaemonState::Ready as i32,
                capabilities: vec![
                    DAEMON_CAPABILITY_SESSIONS.into(),
                    DAEMON_CAPABILITY_ATTACH.into(),
                ],
                ..Default::default()
            };
            assert!(
                matches!(SessionClient::validate_capability(old, capability), Err(SessionClientError::MissingCapability { capability: actual }) if actual == capability)
            );
        }
    }
}
