//! Organization membership and invitations for `cw org` (#3840, #3847): the
//! caller's own invitations and accepting one by id, an organization's
//! members and removing one, and the outcome of a new invitation's email.

use std::time::Duration;

use codewire_client::{self as rpc, ErrorCode};
use serde::Serialize;

use super::{OrganizationClient, legacy_org_role, timestamp_to_rfc3339};
use crate::environment_client::display_client_error;

const INVITATION_EMAIL_POLL_INTERVAL: Duration = Duration::from_millis(500);
/// idp looks for new invitation emails every 2 seconds and a send is bounded
/// by 8, so a working deployment answers well inside this.
const INVITATION_EMAIL_POLL_WINDOW: Duration = Duration::from_secs(8);

/// A pending invitation addressed to the signed-in account.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct PendingInvitation {
    pub id: String,
    pub org_id: String,
    pub org_name: String,
    pub org_slug: String,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inviter_name: Option<String>,
    pub expires_at: String,
}

/// A member of an organization.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Member {
    pub user_id: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub role: String,
    pub assignments: Vec<String>,
    pub joined_at: String,
}

/// What accepting an invitation did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Acceptance {
    Joined {
        org_id: String,
    },
    /// The caller's email address is not verified, so the server refused.
    EmailUnverified,
}

/// What became of a new invitation's email, as the inviter can see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvitationEmail {
    Sent,
    /// Failed for good, or skipped; `reason` says why.
    NotSent {
        reason: String,
    },
    /// Still pending after a failed attempt that will be retried.
    Retrying {
        reason: String,
    },
    /// Still pending, no attempt failed yet.
    Queued,
    /// The server sends no invitation email.
    NotOffered,
    /// The outcome could not be read.
    Unknown {
        reason: String,
    },
}

impl OrganizationClient {
    pub async fn list_my_invitations(&self) -> anyhow::Result<Vec<PendingInvitation>> {
        let response = self
            .inner
            .list_my_invitations(rpc::ListMyInvitationsRequest::default())
            .await
            .map_err(display_client_error)?;
        Ok(response
            .invitations
            .into_iter()
            .map(|invitation| PendingInvitation {
                id: invitation.id,
                org_id: invitation.org_id,
                org_name: invitation.org_name,
                org_slug: invitation.org_slug,
                role: legacy_org_role(invitation.role.as_known()),
                inviter_name: invitation.inviter_name,
                expires_at: invitation
                    .expires_at
                    .into_option()
                    .map(timestamp_to_rfc3339)
                    .unwrap_or_default(),
            })
            .collect())
    }

    /// Accepts one of the caller's invitations by id: no token, the caller's
    /// verified address stands in for it.
    pub async fn accept_invitation(&self, invitation_id: &str) -> anyhow::Result<Acceptance> {
        match self
            .inner
            .accept_invitation(rpc::AcceptInvitationRequest {
                invitation_id: invitation_id.to_owned(),
                ..Default::default()
            })
            .await
        {
            Ok(response) => Ok(Acceptance::Joined {
                org_id: response.org_id,
            }),
            Err(error) if error.code() == ErrorCode::FailedPrecondition => {
                Ok(Acceptance::EmailUnverified)
            }
            Err(error) => Err(display_client_error(error)),
        }
    }

    pub async fn list_members(&self, org_id: &str) -> anyhow::Result<Vec<Member>> {
        let response = self
            .inner
            .list_members(rpc::ListMembersRequest {
                org_id: org_id.to_owned(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(response
            .members
            .into_iter()
            .map(|member| Member {
                user_id: member.user_id,
                email: member.email,
                name: member.name,
                role: legacy_org_role(member.role.as_known()),
                assignments: member.assignments,
                joined_at: member
                    .created_at
                    .into_option()
                    .map(timestamp_to_rfc3339)
                    .unwrap_or_default(),
            })
            .collect())
    }

    pub async fn remove_member(&self, org_id: &str, user_id: &str) -> anyhow::Result<()> {
        self.inner
            .remove_member(rpc::RemoveMemberRequest {
                org_id: org_id.to_owned(),
                user_id: user_id.to_owned(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(())
    }

    /// Waits briefly for a new invitation's email to be sent or refused, by
    /// reading the organization's invitations, and returns what it observed.
    /// It never fails: the invitation exists whatever its email does.
    pub async fn invitation_email(&self, org_id: &str, invitation_id: &str) -> InvitationEmail {
        self.invitation_email_with_policy(
            org_id,
            invitation_id,
            INVITATION_EMAIL_POLL_INTERVAL,
            INVITATION_EMAIL_POLL_WINDOW,
        )
        .await
    }

    pub(crate) async fn invitation_email_with_policy(
        &self,
        org_id: &str,
        invitation_id: &str,
        poll_interval: Duration,
        poll_window: Duration,
    ) -> InvitationEmail {
        let deadline = tokio::time::Instant::now() + poll_window;
        loop {
            let response = match self
                .inner
                .list_invitations(rpc::ListInvitationsRequest {
                    org_id: org_id.to_owned(),
                    ..Default::default()
                })
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    return InvitationEmail::Unknown {
                        reason: display_client_error(error).to_string(),
                    };
                }
            };
            let Some(invitation) = response
                .invitations
                .into_iter()
                .find(|invitation| invitation.id == invitation_id)
            else {
                return InvitationEmail::Unknown {
                    reason: "the invitation is no longer listed".to_owned(),
                };
            };
            let reason = |fallback: &str| {
                if invitation.email_error.trim().is_empty() {
                    fallback.to_owned()
                } else {
                    invitation.email_error.clone()
                }
            };
            let pending_error = !invitation.email_error.trim().is_empty();
            match invitation.email_status.as_known() {
                Some(rpc::InvitationEmailStatus::Sent) => return InvitationEmail::Sent,
                Some(rpc::InvitationEmailStatus::Failed) => {
                    return InvitationEmail::NotSent {
                        reason: reason("the email could not be sent"),
                    };
                }
                Some(rpc::InvitationEmailStatus::Skipped) => {
                    return InvitationEmail::NotSent {
                        reason: reason("the invitation was no longer pending"),
                    };
                }
                Some(rpc::InvitationEmailStatus::Pending) => {}
                Some(rpc::InvitationEmailStatus::Unspecified) => {
                    return InvitationEmail::NotOffered;
                }
                None => {
                    return InvitationEmail::Unknown {
                        reason: "the server reported an unknown email status".to_owned(),
                    };
                }
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return if pending_error {
                    InvitationEmail::Retrying {
                        reason: invitation.email_error,
                    }
                } else {
                    InvitationEmail::Queued
                };
            }
            tokio::time::sleep(poll_interval.min(deadline - now)).await;
        }
    }
}
