//! Hosted environments as Mesh network members (#3350).
//!
//! A hosted environment's daemon opens a peer coordinate stream with a
//! one-use `cw_eenr_` code that orchestration issued to its live Pod. Mesh
//! never interprets that code itself: it redeems it with orchestration's
//! `EnvironmentMeshService`, over the cluster-internal TLS listener, with a
//! service-only credential signed with a key derived for this hop. Every
//! environment member Mesh holds is checked again at least every
//! [`RECHECK_MAX_AGE`]; a member whose Pod, generation, attachment or
//! attaching user no longer qualifies is closed or removed.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use axum::http::HeaderValue;
use axum::http::header::AUTHORIZATION;
use codewire_proto::codewire::internal::v1::{
    CheckEnvironmentMembersRequest, EnvironmentMeshMemberRef, EnvironmentMeshMemberStatus,
    EnvironmentMeshServiceClient, RedeemEnvironmentEnrollmentRequest,
};
use codewire_server_core::internal_hmac::{derive_internal_hmac_secret, issue_internal_hmac_token};
use codewire_tls::ConnectOriginTransport;
use connectrpc::client::{CallOptions, ClientConfig};
use connectrpc::{ConnectError, ErrorCode};
use thiserror::Error;

use crate::config::MeshAuthorizationConfig;

/// Prefix of an environment enrollment code, issued only by orchestration.
pub(crate) const ENVIRONMENT_ENROLLMENT_PREFIX: &str = "cw_eenr_";

/// The caller identity bound into this hop's credential.
pub(crate) const ENVIRONMENT_MESH_CALLER: &str = "codewire-mesh";

/// The derivation label of this hop's signing key, shared with orchestration.
pub(crate) const ENVIRONMENT_MESH_HMAC_LABEL: &str = "codewire/environment-mesh/v1";

const REDEEM_METHOD: &str =
    "codewire.internal.v1.EnvironmentMeshService/RedeemEnvironmentEnrollment";
const CHECK_METHOD: &str = "codewire.internal.v1.EnvironmentMeshService/CheckEnvironmentMembers";

/// The longest an environment member may go without a fresh decision from
/// orchestration (the 60-second authority rule).
pub(crate) const RECHECK_MAX_AGE: Duration = Duration::from_secs(60);

/// How often members are checked: well inside [`RECHECK_MAX_AGE`], so one
/// failed round does not close a live member.
pub(crate) const RECHECK_INTERVAL: Duration = Duration::from_secs(20);

/// Members named in one check call.
pub(crate) const CHECK_BATCH: usize = 256;

/// The owner subject of an environment's node row. A user subject never has
/// this form.
pub(crate) fn environment_owner_subject(environment_id: &str) -> String {
    format!("environment:{environment_id}")
}

/// The environment that owns a node row, if an environment does.
pub(crate) fn environment_of_owner(owner_subject: &str) -> Option<&str> {
    owner_subject
        .strip_prefix("environment:")
        .filter(|environment| !environment.is_empty())
}

/// One environment member, as orchestration admitted it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EnvironmentMember {
    pub environment_id: String,
    pub org_id: String,
    pub network_id: String,
    pub node_name: String,
    pub pod_uid: String,
    pub operation_generation: i64,
    pub attached_by_user_id: String,
}

/// A member to check. An empty `pod_uid` checks a node row with no stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MemberRef {
    pub environment_id: String,
    pub org_id: String,
    pub network_id: String,
    pub pod_uid: String,
    pub operation_generation: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MemberStatus {
    /// Still attached, and the named Pod and generation are live.
    Live,
    /// Still attached; the named Pod or generation is not. Close its stream.
    Stale,
    /// Destroyed, detached, or its attaching user left. Remove its node.
    Gone,
}

#[derive(Debug, Error)]
pub(crate) enum EnvironmentMembersError {
    /// Orchestration refused the code: unknown, used, expired, for another
    /// network, or its Pod is no longer live.
    #[error("environment enrollment was refused")]
    Refused,
    #[error("environment membership is unavailable")]
    Unavailable,
}

/// The client for orchestration's `EnvironmentMeshService`.
#[derive(Clone)]
pub(crate) struct EnvironmentMembersClient {
    url: String,
    hmac_key: String,
    tls_roots: PathBuf,
}

impl fmt::Debug for EnvironmentMembersClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvironmentMembersClient")
            .field("url", &self.url)
            .field("hmac_key", &"[redacted]")
            .field("tls_roots", &self.tls_roots)
            .finish()
    }
}

impl EnvironmentMembersClient {
    /// The client for hosted Mesh, which already reaches orchestration's
    /// internal listener for `MeshAuthorizationService`. `None` when the
    /// shared secret cannot derive this hop's key.
    pub(crate) fn from_config(config: &MeshAuthorizationConfig) -> Option<Self> {
        let hmac_key =
            derive_internal_hmac_secret(config.hmac_secret(), ENVIRONMENT_MESH_HMAC_LABEL).ok()?;
        Some(Self {
            url: config.url.clone(),
            hmac_key,
            tls_roots: config.tls_roots_file().to_path_buf(),
        })
    }

    fn client(
        &self,
    ) -> Result<EnvironmentMeshServiceClient<ConnectOriginTransport>, EnvironmentMembersError> {
        let config = ClientConfig::new(
            self.url
                .parse()
                .map_err(|_| EnvironmentMembersError::Unavailable)?,
        )
        .with_default_timeout(Duration::from_secs(5));
        let transport = ConnectOriginTransport::for_origin(&self.url, &self.tls_roots)
            .map_err(|_| EnvironmentMembersError::Unavailable)?;
        Ok(EnvironmentMeshServiceClient::new(transport, config))
    }

    fn options(&self, method: &str) -> Result<CallOptions, EnvironmentMembersError> {
        let token = issue_internal_hmac_token(
            &self.hmac_key,
            ENVIRONMENT_MESH_CALLER,
            method,
            chrono::Utc::now(),
        )
        .map_err(|_| EnvironmentMembersError::Unavailable)?;
        let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| EnvironmentMembersError::Unavailable)?;
        value.set_sensitive(true);
        CallOptions::default()
            .try_with_header(AUTHORIZATION, value)
            .map_err(|_| EnvironmentMembersError::Unavailable)
    }

    /// Redeems `code` for exactly `org_id` and `network_id`.
    pub(crate) async fn redeem(
        &self,
        code: &str,
        org_id: &str,
        network_id: &str,
    ) -> Result<EnvironmentMember, EnvironmentMembersError> {
        let response = self
            .client()?
            .redeem_environment_enrollment_with_options(
                RedeemEnvironmentEnrollmentRequest {
                    enrollment_code: code.to_owned(),
                    org_id: org_id.to_owned(),
                    network_id: network_id.to_owned(),
                    ..Default::default()
                },
                self.options(REDEEM_METHOD)?,
            )
            .await
            .map_err(rpc_error)?
            .into_owned();
        let member = response
            .member
            .as_option()
            .ok_or(EnvironmentMembersError::Unavailable)?;
        // Orchestration answers for exactly the scope asked; anything else is
        // not this request's member.
        if member.org_id != org_id || member.network_id != network_id {
            return Err(EnvironmentMembersError::Refused);
        }
        Ok(EnvironmentMember {
            environment_id: member.environment_id.clone(),
            org_id: member.org_id.clone(),
            network_id: member.network_id.clone(),
            node_name: member.node_name.clone(),
            pod_uid: member.pod_uid.clone(),
            operation_generation: member.operation_generation,
            attached_by_user_id: member.attached_by_user_id.clone(),
        })
    }

    /// The status of each member, in order, in batches of [`CHECK_BATCH`].
    pub(crate) async fn check(
        &self,
        members: &[MemberRef],
    ) -> Result<Vec<MemberStatus>, EnvironmentMembersError> {
        let mut statuses = Vec::with_capacity(members.len());
        for batch in members.chunks(CHECK_BATCH) {
            let response = self
                .client()?
                .check_environment_members_with_options(
                    CheckEnvironmentMembersRequest {
                        members: batch
                            .iter()
                            .map(|member| EnvironmentMeshMemberRef {
                                environment_id: member.environment_id.clone(),
                                org_id: member.org_id.clone(),
                                network_id: member.network_id.clone(),
                                pod_uid: member.pod_uid.clone(),
                                operation_generation: member.operation_generation,
                                ..Default::default()
                            })
                            .collect(),
                        ..Default::default()
                    },
                    self.options(CHECK_METHOD)?,
                )
                .await
                .map_err(rpc_error)?
                .into_owned();
            if response.statuses.len() != batch.len() {
                return Err(EnvironmentMembersError::Unavailable);
            }
            for status in &response.statuses {
                statuses.push(match status.as_known() {
                    Some(EnvironmentMeshMemberStatus::Live) => MemberStatus::Live,
                    Some(EnvironmentMeshMemberStatus::Stale) => MemberStatus::Stale,
                    Some(EnvironmentMeshMemberStatus::Gone) => MemberStatus::Gone,
                    // An answer Mesh does not understand is not a decision.
                    _ => return Err(EnvironmentMembersError::Unavailable),
                });
            }
        }
        Ok(statuses)
    }
}

fn rpc_error(error: ConnectError) -> EnvironmentMembersError {
    match error.code {
        ErrorCode::PermissionDenied => EnvironmentMembersError::Refused,
        _ => EnvironmentMembersError::Unavailable,
    }
}

/// Checks every environment member Mesh holds, once (#3350).
///
/// - A stream whose Pod and generation are live, whose attachment stands
///   and whose attaching user is still a network member is confirmed.
/// - Any other stream ends. Its node row stays unless the environment is
///   gone, so a stopped environment still shows as enrolled.
/// - A node row of a gone environment (destroyed, detached, or its
///   attaching user left the organization) is removed.
/// - When orchestration cannot answer, streams last confirmed longer ago than
///   [`RECHECK_MAX_AGE`] end: no decision outlives that age.
pub(crate) async fn recheck(state: &crate::server::AppState) {
    let Some(client) = state.product.environment_members() else {
        return;
    };
    let now = tokio::time::Instant::now();
    let sessions = state.mesh_coordinate.environment_sessions();
    let nodes = match state.product.environment_nodes(None).await {
        Ok(nodes) => nodes,
        Err(error) => {
            tracing::warn!(%error, "Mesh environment node listing failed");
            Vec::new()
        }
    };
    let mut members: Vec<MemberRef> = sessions
        .iter()
        .map(|session| {
            let member = &session.session.member;
            MemberRef {
                environment_id: member.environment_id.clone(),
                org_id: member.org_id.clone(),
                network_id: member.network_id.clone(),
                pod_uid: member.pod_uid.clone(),
                operation_generation: member.operation_generation,
            }
        })
        .collect();
    members.extend(
        nodes
            .iter()
            .map(|(network_id, _, environment_id, org_id)| MemberRef {
                environment_id: environment_id.clone(),
                org_id: org_id.clone(),
                network_id: network_id.clone(),
                pod_uid: String::new(),
                operation_generation: 0,
            }),
    );
    if members.is_empty() {
        return;
    }
    let statuses = match client.check(&members).await {
        Ok(statuses) => statuses,
        Err(error) => {
            tracing::warn!(%error, "Mesh environment member recheck failed");
            for session in &sessions {
                if now.duration_since(session.session.verified_at) > RECHECK_MAX_AGE {
                    state
                        .mesh_coordinate
                        .end_environment_session(session.peer_id, session.session_id);
                }
            }
            return;
        }
    };
    let (session_statuses, node_statuses) = statuses.split_at(sessions.len());
    for (session, status) in sessions.iter().zip(session_statuses) {
        let member = &session.session.member;
        let still_member = *status == MemberStatus::Live
            && state
                .product
                .is_network_member(&member.network_id, &member.attached_by_user_id)
                .await
                .unwrap_or(false);
        if still_member {
            state.mesh_coordinate.confirm_environment_session(
                session.peer_id,
                session.session_id,
                now,
            );
        } else {
            state
                .mesh_coordinate
                .end_environment_session(session.peer_id, session.session_id);
        }
    }
    for ((network_id, node_name, environment_id, _), status) in nodes.iter().zip(node_statuses) {
        if *status != MemberStatus::Gone {
            continue;
        }
        match state
            .product
            .remove_environment_node(network_id, node_name, environment_id)
            .await
        {
            Ok(()) => state.mesh_coordinate.revoke_node(network_id, node_name),
            Err(error) => tracing::warn!(%error, "Mesh environment node removal failed"),
        }
    }
}

/// Runs [`recheck`] every [`RECHECK_INTERVAL`] for the life of the process.
pub(crate) fn spawn_recheck(state: crate::server::AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(RECHECK_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            recheck(&state).await;
        }
    })
}

#[cfg(test)]
mod tests;
