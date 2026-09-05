//! Connect-RPC adapter for organizations, members, assignments, and
//! invitations.
//!
//! This module maps the shared organization and assignment service logic to
//! protobuf, validates pagination, and renders Connect errors.

use std::borrow::Cow;
use std::sync::Arc;

use buffa::EnumValue;
use buffa_types::Timestamp;
use chrono::DateTime;
use codewire_proto::codewire::v1::{
    AcceptInvitationRequest, AcceptInvitationResponse, CreateInvitationRequest,
    CreateInvitationResponse, CreateOrganizationRequest, CreateOrganizationResponse,
    DeleteOrganizationRequest, DeleteOrganizationResponse, GetInvitationByTokenRequest,
    GetInvitationByTokenResponse, GetMemberAssignmentsRequest, GetMemberAssignmentsResponse,
    GetOrganizationRequest, GetOrganizationResponse, InvitationStatus, ListInvitationsRequest,
    ListInvitationsResponse, ListMembersRequest, ListMembersResponse, ListOrganizationsRequest,
    ListOrganizationsResponse, OrgInvitation as ProtoOrgInvitation, OrgMember as ProtoOrgMember,
    OrgRole, Organization as ProtoOrganization,
    OrganizationDeletionState as ProtoOrganizationDeletionState, OrganizationMembership,
    OrganizationService, RemoveMemberRequest, RemoveMemberResponse, RevokeInvitationRequest,
    RevokeInvitationResponse, UpdateMemberAssignmentsRequest, UpdateMemberAssignmentsResponse,
    UpdateMemberRoleRequest, UpdateMemberRoleResponse,
};
use codewire_server_core::connect::{auth_user, rpc_app_error};
use codewire_server_core::{AppError, AppResult, ValidationIssue};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};

use crate::api::ApiState;
use crate::api::assignments::{
    UpdateMemberAssignmentsBody, get_member_assignments_core, update_member_assignments_core,
};
use crate::api::organizations::{
    CreateOrgBody, InviteMemberBody, OrgInvitation, OrgMember, OrgWithMembers, OrgWithRole,
    Organization, OrganizationDeletionState, UpdateRoleBody, accept_invitation_core,
    create_invitation_core, create_organization_core, delete_organization_core,
    get_invitation_by_token_core, get_organization_core, list_invitations_core, list_members_core,
    list_organizations_core, remove_member_core, revoke_invitation_core, update_member_role_core,
};

/// Registers all fourteen OrganizationService RPCs on their generated routes.
pub fn router(state: ApiState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(OrganizationConnectService { state }))
}

struct OrganizationConnectService {
    state: ApiState,
}

#[allow(refining_impl_trait)]
impl OrganizationService for OrganizationConnectService {
    async fn list_organizations(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListOrganizationsRequest>,
    ) -> ServiceResult<ListOrganizationsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        validate_pagination(request.page_token).map_err(|error| rpc_app_error(&error, &ctx))?;
        let organizations = list_organizations_core(self.state.clone(), user)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?
            .into_iter()
            .map(proto_membership)
            .collect::<AppResult<Vec<_>>>()
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListOrganizationsResponse {
            organizations,
            next_page_token: String::new(),
            ..Default::default()
        })
    }

    async fn create_organization(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateOrganizationRequest>,
    ) -> ServiceResult<CreateOrganizationResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let name_missing = request.name.trim().is_empty();
        let slug_missing = request.slug.trim().is_empty();
        let organization = create_organization_core(
            self.state.clone(),
            user,
            CreateOrgBody {
                name: request.name,
                slug: request.slug,
            },
        )
        .await
        .map_err(|error| {
            let error = create_organization_validation(error, name_missing, slug_missing);
            rpc_app_error(&error, &ctx)
        })?;
        let organization =
            proto_organization(organization).map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(CreateOrganizationResponse {
            organization: Some(organization).into(),
            ..Default::default()
        })
    }

    async fn get_organization(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetOrganizationRequest>,
    ) -> ServiceResult<GetOrganizationResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let organization = get_organization_core(self.state.clone(), user, request.org_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        let response = proto_organization_with_members(organization)
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(response)
    }

    async fn delete_organization(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteOrganizationRequest>,
    ) -> ServiceResult<DeleteOrganizationResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let deleted = delete_organization_core(self.state.clone(), user, request.org_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(DeleteOrganizationResponse {
            operation_id: deleted.operation_id,
            state: proto_deletion_state(deleted.state).into(),
            ..Default::default()
        })
    }

    async fn list_members(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListMembersRequest>,
    ) -> ServiceResult<ListMembersResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        validate_pagination(&request.page_token).map_err(|error| rpc_app_error(&error, &ctx))?;
        let members = list_members_core(self.state.clone(), user, request.org_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?
            .into_iter()
            .map(proto_member)
            .collect::<AppResult<Vec<_>>>()
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListMembersResponse {
            members,
            next_page_token: String::new(),
            ..Default::default()
        })
    }

    async fn update_member_role(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateMemberRoleRequest>,
    ) -> ServiceResult<UpdateMemberRoleResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let role = api_role(request.role, false).map_err(|error| rpc_app_error(&error, &ctx))?;
        update_member_role_core(
            self.state.clone(),
            user,
            request.org_id,
            request.user_id,
            UpdateRoleBody { role },
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(UpdateMemberRoleResponse::default())
    }

    async fn remove_member(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RemoveMemberRequest>,
    ) -> ServiceResult<RemoveMemberResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        remove_member_core(self.state.clone(), user, request.org_id, request.user_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(RemoveMemberResponse::default())
    }

    async fn get_member_assignments(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetMemberAssignmentsRequest>,
    ) -> ServiceResult<GetMemberAssignmentsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let assignments = get_member_assignments_core(
            self.state.clone(),
            user,
            request.org_id,
            request.member_id,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(GetMemberAssignmentsResponse {
            assignments,
            ..Default::default()
        })
    }

    async fn update_member_assignments(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateMemberAssignmentsRequest>,
    ) -> ServiceResult<UpdateMemberAssignmentsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let assignments = update_member_assignments_core(
            self.state.clone(),
            user,
            request.org_id,
            request.member_id,
            UpdateMemberAssignmentsBody {
                assignments: request.assignments,
            },
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(UpdateMemberAssignmentsResponse {
            assignments,
            ..Default::default()
        })
    }

    async fn list_invitations(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListInvitationsRequest>,
    ) -> ServiceResult<ListInvitationsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        validate_pagination(&request.page_token).map_err(|error| rpc_app_error(&error, &ctx))?;
        let invitations = list_invitations_core(self.state.clone(), user, request.org_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?
            .into_iter()
            .map(proto_invitation)
            .collect::<AppResult<Vec<_>>>()
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListInvitationsResponse {
            invitations,
            next_page_token: String::new(),
            ..Default::default()
        })
    }

    async fn create_invitation(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateInvitationRequest>,
    ) -> ServiceResult<CreateInvitationResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let role = api_role(request.role, true).map_err(|error| rpc_app_error(&error, &ctx))?;
        let created = create_invitation_core(
            self.state.clone(),
            user,
            request.org_id,
            InviteMemberBody {
                email: request.email,
                role,
                assignments: request.assignments,
            },
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(CreateInvitationResponse {
            invitation: Some(
                proto_invitation(created.invitation)
                    .map_err(|error| rpc_app_error(&error, &ctx))?,
            )
            .into(),
            token: created.token,
            ..Default::default()
        })
    }

    async fn revoke_invitation(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RevokeInvitationRequest>,
    ) -> ServiceResult<RevokeInvitationResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        revoke_invitation_core(
            self.state.clone(),
            user,
            request.org_id,
            request.invitation_id,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(RevokeInvitationResponse::default())
    }

    async fn accept_invitation(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, AcceptInvitationRequest>,
    ) -> ServiceResult<AcceptInvitationResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let accepted = accept_invitation_core(self.state.clone(), user, request.token)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(AcceptInvitationResponse {
            org_id: accepted.org_id,
            ..Default::default()
        })
    }

    async fn get_invitation_by_token(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetInvitationByTokenRequest>,
    ) -> ServiceResult<GetInvitationByTokenResponse> {
        // Deliberately do not extract AuthUser: this exact method is the sole
        // public-method exemption on the authenticated codewire.v1 mount.
        let request = request.to_owned_message();
        let invitation = get_invitation_by_token_core(self.state.clone(), request.token)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(GetInvitationByTokenResponse {
            invitation: Some(
                proto_invitation(invitation).map_err(|error| rpc_app_error(&error, &ctx))?,
            )
            .into(),
            ..Default::default()
        })
    }
}

fn validate_pagination(page_token: &str) -> AppResult<()> {
    if page_token.is_empty() {
        Ok(())
    } else {
        Err(AppError::BadRequest("unrecognized page_token".into()))
    }
}

fn create_organization_validation(
    error: AppError,
    name_missing: bool,
    slug_missing: bool,
) -> AppError {
    let field = match (&error, name_missing, slug_missing) {
        (AppError::BadRequest(_), true, _) => Some(("/name", "name is required")),
        (AppError::BadRequest(_), false, true) => Some(("/slug", "slug is required")),
        (AppError::BadRequest(_), false, false) => Some((
            "/slug",
            "slug is reserved or does not match the canonical route-safe format",
        )),
        _ => None,
    };
    match field {
        Some((path, message)) => AppError::Validation {
            errors: vec![ValidationIssue {
                path: Cow::Borrowed(path),
                message: Cow::Borrowed(message),
            }],
        },
        None => error,
    }
}

fn api_role(role: EnumValue<OrgRole>, unspecified_is_member: bool) -> AppResult<String> {
    match role.as_known() {
        Some(OrgRole::Owner) => Ok("owner".into()),
        Some(OrgRole::Admin) => Ok("admin".into()),
        Some(OrgRole::Member) => Ok("member".into()),
        Some(OrgRole::Unspecified) if unspecified_is_member => Ok("member".into()),
        Some(OrgRole::Unspecified) => Err(AppError::BadRequest("role is required".into())),
        None => Err(AppError::BadRequest("role has an unknown value".into())),
    }
}

fn proto_role(role: &str) -> AppResult<OrgRole> {
    match role {
        "owner" => Ok(OrgRole::Owner),
        "admin" => Ok(OrgRole::Admin),
        "member" => Ok(OrgRole::Member),
        unexpected => {
            tracing::error!(role = unexpected, "stored organization role is invalid");
            Err(AppError::InternalMsg(
                "failed to map organization role".into(),
            ))
        }
    }
}

fn proto_invitation_status(status: &str) -> AppResult<InvitationStatus> {
    match status {
        "pending" => Ok(InvitationStatus::Pending),
        "accepted" => Ok(InvitationStatus::Accepted),
        "revoked" => Ok(InvitationStatus::Revoked),
        "expired" => Ok(InvitationStatus::Expired),
        unexpected => {
            tracing::error!(status = unexpected, "stored invitation status is invalid");
            Err(AppError::InternalMsg(
                "failed to map invitation status".into(),
            ))
        }
    }
}

fn proto_deletion_state(state: OrganizationDeletionState) -> ProtoOrganizationDeletionState {
    match state {
        OrganizationDeletionState::Active => ProtoOrganizationDeletionState::Active,
        OrganizationDeletionState::Deleting => ProtoOrganizationDeletionState::Deleting,
        OrganizationDeletionState::DeleteFailed => ProtoOrganizationDeletionState::DeleteFailed,
    }
}

fn proto_timestamp(value: &str) -> AppResult<Timestamp> {
    let value = DateTime::parse_from_rfc3339(value).map_err(|error| {
        tracing::error!(%error, timestamp = value, "organization timestamp invalid");
        AppError::InternalMsg("failed to map organization timestamp".into())
    })?;
    Ok(Timestamp::from_unix(
        value.timestamp(),
        value.timestamp_subsec_nanos() as i32,
    ))
}

fn proto_organization(organization: Organization) -> AppResult<ProtoOrganization> {
    Ok(ProtoOrganization {
        id: organization.id,
        name: organization.name,
        slug: organization.slug,
        created_by: organization.created_by,
        created_at: Some(proto_timestamp(&organization.created_at)?).into(),
        updated_at: Some(proto_timestamp(&organization.updated_at)?).into(),
        ..Default::default()
    })
}

fn proto_membership(membership: OrgWithRole) -> AppResult<OrganizationMembership> {
    let organization = ProtoOrganization {
        id: membership.id,
        name: membership.name,
        slug: membership.slug,
        created_by: membership.created_by,
        created_at: Some(proto_timestamp(&membership.created_at)?).into(),
        updated_at: Some(proto_timestamp(&membership.updated_at)?).into(),
        ..Default::default()
    };
    let trial_ends_at = membership
        .trial_ends_at
        .as_deref()
        .map(proto_timestamp)
        .transpose()?;
    Ok(OrganizationMembership {
        organization: Some(organization).into(),
        role: proto_role(&membership.role)?.into(),
        assignments: membership.assignments,
        billing_plan: membership.billing_plan,
        billing_status: membership.billing_status,
        trial_ends_at: trial_ends_at.into(),
        ..Default::default()
    })
}

fn proto_organization_with_members(
    organization: OrgWithMembers,
) -> AppResult<GetOrganizationResponse> {
    let members = organization
        .members
        .into_iter()
        .map(proto_member)
        .collect::<AppResult<Vec<_>>>()?;
    let proto = ProtoOrganization {
        id: organization.id,
        name: organization.name,
        slug: organization.slug,
        created_by: organization.created_by,
        created_at: Some(proto_timestamp(&organization.created_at)?).into(),
        updated_at: Some(proto_timestamp(&organization.updated_at)?).into(),
        deletion_state: organization
            .deletion_state
            .map(|state| proto_deletion_state(state).into()),
        deletion_operation_id: organization.deletion_operation_id,
        deletion_failure_code: organization.deletion_failure_code,
        ..Default::default()
    };
    Ok(GetOrganizationResponse {
        organization: Some(proto).into(),
        members,
        ..Default::default()
    })
}

fn proto_member(member: OrgMember) -> AppResult<ProtoOrgMember> {
    Ok(ProtoOrgMember {
        id: member.id,
        org_id: member.org_id,
        user_id: member.user_id,
        role: proto_role(&member.role)?.into(),
        email: member.email,
        name: member.name,
        image: member.image,
        assignments: member.assignments,
        created_at: Some(proto_timestamp(&member.created_at)?).into(),
        ..Default::default()
    })
}

fn proto_invitation(invitation: OrgInvitation) -> AppResult<ProtoOrgInvitation> {
    let accepted_at = invitation
        .accepted_at
        .as_deref()
        .map(proto_timestamp)
        .transpose()?;
    Ok(ProtoOrgInvitation {
        id: invitation.id,
        org_id: invitation.org_id,
        org_name: invitation.org_name,
        email: invitation.email,
        role: proto_role(&invitation.role)?.into(),
        invited_by: invitation.invited_by,
        inviter_name: invitation.inviter_name,
        status: proto_invitation_status(&invitation.status)?.into(),
        expires_at: Some(proto_timestamp(&invitation.expires_at)?).into(),
        created_at: Some(proto_timestamp(&invitation.created_at)?).into(),
        accepted_at: accepted_at.into(),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use codewire_server_core::connect_error::{ConnectCode, ConnectError, ConnectErrorDetail};

    use super::*;

    #[test]
    fn pagination_rejects_unknown_tokens() {
        assert!(validate_pagination("").is_ok());
        let error = validate_pagination("future").expect_err("unknown token must fail");
        assert_eq!(
            ConnectError::from_app_error(&error, None).code,
            ConnectCode::InvalidArgument
        );
    }

    #[test]
    fn create_validation_names_the_first_rejected_proto_field() {
        for (name_missing, slug_missing, want) in [(true, false, "name"), (false, true, "slug")] {
            let error = create_organization_validation(
                AppError::BadRequest("required field missing".into()),
                name_missing,
                slug_missing,
            );
            let rendered = ConnectError::from_app_error(&error, None);
            assert_eq!(rendered.code, ConnectCode::InvalidArgument);
            let ConnectErrorDetail::BadRequest(detail) = &rendered.details[0] else {
                panic!("missing BadRequest detail");
            };
            assert_eq!(detail.field_violations[0].field, want);
            assert!(!detail.field_violations[0].description.is_empty());
        }
    }

    #[test]
    fn role_mapping_defaults_only_invitation_creation() {
        assert_eq!(
            api_role(OrgRole::Unspecified.into(), true).unwrap(),
            "member"
        );
        assert!(api_role(OrgRole::Unspecified.into(), false).is_err());
        assert!(api_role(EnumValue::Unknown(99), true).is_err());
        for (proto, api) in [
            (OrgRole::Owner, "owner"),
            (OrgRole::Admin, "admin"),
            (OrgRole::Member, "member"),
        ] {
            assert_eq!(api_role(proto.into(), false).unwrap(), api);
            assert_eq!(proto_role(api).unwrap(), proto);
        }
    }

    #[test]
    fn composition_mapping_preserves_lifecycle_and_members() {
        let response = proto_organization_with_members(OrgWithMembers {
            id: "org_test".into(),
            name: "Test".into(),
            slug: "test".into(),
            created_by: "user_test".into(),
            created_at: "2026-07-20T00:00:00Z".into(),
            updated_at: "2026-07-20T00:00:01Z".into(),
            members: vec![OrgMember {
                id: "member_test".into(),
                org_id: "org_test".into(),
                user_id: "user_test".into(),
                role: "owner".into(),
                email: "owner@example.com".into(),
                name: None,
                image: None,
                assignments: vec!["viewer".into()],
                created_at: "2026-07-20T00:00:00Z".into(),
            }],
            deletion_state: Some(OrganizationDeletionState::DeleteFailed),
            deletion_operation_id: Some("op_test".into()),
            deletion_failure_code: Some("billing_unavailable".into()),
        })
        .unwrap();
        let json = serde_json::to_value(response).unwrap();
        assert_eq!(json["organization"]["id"], "org_test");
        assert_eq!(
            json["organization"]["deletionState"],
            "ORGANIZATION_DELETION_STATE_DELETE_FAILED"
        );
        assert_eq!(json["organization"]["deletionOperationId"], "op_test");
        assert_eq!(json["members"][0]["role"], "ORG_ROLE_OWNER");
        assert_eq!(json["members"][0]["assignments"][0], "viewer");
        assert!(json["members"][0].get("name").is_none());
    }

    #[test]
    fn invitation_mapping_preserves_optional_fields_and_enums() {
        let invitation = proto_invitation(OrgInvitation {
            id: "invite_test".into(),
            org_id: "org_test".into(),
            org_name: "Test".into(),
            email: "invitee@example.com".into(),
            role: "member".into(),
            invited_by: "user_test".into(),
            inviter_name: None,
            status: "pending".into(),
            expires_at: "2026-07-27T00:00:00Z".into(),
            created_at: "2026-07-20T00:00:00Z".into(),
            accepted_at: None,
        })
        .unwrap();
        let json = serde_json::to_value(invitation).unwrap();
        assert_eq!(json["role"], "ORG_ROLE_MEMBER");
        assert_eq!(json["status"], "INVITATION_STATUS_PENDING");
        assert!(json.get("inviterName").is_none());
        assert!(json.get("acceptedAt").is_none());
    }
}
