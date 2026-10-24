//! Generated Connect adapters for the retained Mesh product surface.
//!
//! This module maps protobuf values and canonical errors only. Authorization,
//! ownership, policy, and persistence live in `product`.

use buffa_types::google::protobuf::{Duration as ProtoDuration, Timestamp};
use chrono::{Duration, Utc};
use codewire_proto::codewire::v1::*;
use codewire_server_core::connect::rpc_app_error;
use codewire_server_core::{AppError, AppResult};
use connectrpc::{RequestContext, ServiceResult, handler_fn};

use crate::mesh_authorization::forwarded_mesh_credential;
use crate::product::{
    GroupView, KeyValueWrite, normalize_group_debug_policy, normalize_group_messages_policy,
    validate_group_name, validate_network_id,
};
use crate::server::AppState;
use crate::store::{
    GROUP_DEBUG_FULL, GROUP_DEBUG_NONE, GROUP_MESSAGES_OPEN, GroupMember, GroupPolicy, Invite,
    KVEntry, Network, NodeEnrollment, NodeRecord,
};

/// Register retained procedures individually.
pub(crate) fn router(state: AppState) -> connectrpc::Router {
    let list_networks_state = state.clone();
    let create_network_state = state.clone();
    let delete_network_state = state.clone();
    let join_network_state = state.clone();
    let list_nodes_state = state.clone();
    let revoke_node_state = state.clone();
    let create_enrollment_state = state.clone();
    let redeem_enrollment_state = state.clone();
    let list_invites_state = state.clone();
    let create_invite_state = state.clone();
    let delete_invite_state = state.clone();
    let list_groups_state = state.clone();
    let create_group_state = state.clone();
    let get_group_state = state.clone();
    let delete_group_state = state.clone();
    let set_policy_state = state.clone();
    let add_member_state = state.clone();
    let remove_member_state = state.clone();
    let list_kv_state = state.clone();
    let get_kv_state = state.clone();
    let set_kv_state = state.clone();

    connectrpc::Router::new()
        .route_idempotent(
            MESH_NETWORK_SERVICE_SERVICE_NAME,
            "ListMeshNetworks",
            handler_fn(move |ctx, request| {
                list_mesh_networks(list_networks_state.clone(), ctx, request)
            }),
        )
        .with_spec(MESH_NETWORK_SERVICE_LIST_MESH_NETWORKS_SPEC)
        .route(
            MESH_NETWORK_SERVICE_SERVICE_NAME,
            "CreateMeshNetwork",
            handler_fn(move |ctx, request| {
                create_mesh_network(create_network_state.clone(), ctx, request)
            }),
        )
        .with_spec(MESH_NETWORK_SERVICE_CREATE_MESH_NETWORK_SPEC)
        .route(
            MESH_NETWORK_SERVICE_SERVICE_NAME,
            "DeleteMeshNetwork",
            handler_fn(move |ctx, request| {
                delete_mesh_network(delete_network_state.clone(), ctx, request)
            }),
        )
        .with_spec(MESH_NETWORK_SERVICE_DELETE_MESH_NETWORK_SPEC)
        .route(
            MESH_NETWORK_SERVICE_SERVICE_NAME,
            "JoinMeshNetwork",
            handler_fn(move |ctx, request| {
                join_mesh_network(join_network_state.clone(), ctx, request)
            }),
        )
        .with_spec(MESH_NETWORK_SERVICE_JOIN_MESH_NETWORK_SPEC)
        .route_idempotent(
            MESH_NODE_SERVICE_SERVICE_NAME,
            "ListMeshNodes",
            handler_fn(move |ctx, request| list_mesh_nodes(list_nodes_state.clone(), ctx, request)),
        )
        .with_spec(MESH_NODE_SERVICE_LIST_MESH_NODES_SPEC)
        .route(
            MESH_NODE_SERVICE_SERVICE_NAME,
            "RevokeMeshNode",
            handler_fn(move |ctx, request| {
                revoke_mesh_node(revoke_node_state.clone(), ctx, request)
            }),
        )
        .with_spec(MESH_NODE_SERVICE_REVOKE_MESH_NODE_SPEC)
        .route(
            MESH_NODE_SERVICE_SERVICE_NAME,
            "CreateMeshNodeEnrollment",
            handler_fn(move |ctx, request| {
                create_mesh_node_enrollment(create_enrollment_state.clone(), ctx, request)
            }),
        )
        .with_spec(MESH_NODE_SERVICE_CREATE_MESH_NODE_ENROLLMENT_SPEC)
        .route(
            MESH_NODE_SERVICE_SERVICE_NAME,
            "RedeemMeshNodeEnrollment",
            handler_fn(move |ctx, request| {
                redeem_mesh_node_enrollment(redeem_enrollment_state.clone(), ctx, request)
            }),
        )
        .with_spec(MESH_NODE_SERVICE_REDEEM_MESH_NODE_ENROLLMENT_SPEC)
        .route_idempotent(
            MESH_INVITE_SERVICE_SERVICE_NAME,
            "ListMeshInvites",
            handler_fn(move |ctx, request| {
                list_mesh_invites(list_invites_state.clone(), ctx, request)
            }),
        )
        .with_spec(MESH_INVITE_SERVICE_LIST_MESH_INVITES_SPEC)
        .route(
            MESH_INVITE_SERVICE_SERVICE_NAME,
            "CreateMeshInvite",
            handler_fn(move |ctx, request| {
                create_mesh_invite(create_invite_state.clone(), ctx, request)
            }),
        )
        .with_spec(MESH_INVITE_SERVICE_CREATE_MESH_INVITE_SPEC)
        .route(
            MESH_INVITE_SERVICE_SERVICE_NAME,
            "DeleteMeshInvite",
            handler_fn(move |ctx, request| {
                delete_mesh_invite(delete_invite_state.clone(), ctx, request)
            }),
        )
        .with_spec(MESH_INVITE_SERVICE_DELETE_MESH_INVITE_SPEC)
        .route_idempotent(
            MESH_GROUP_SERVICE_SERVICE_NAME,
            "ListMeshGroups",
            handler_fn(move |ctx, request| {
                list_mesh_groups(list_groups_state.clone(), ctx, request)
            }),
        )
        .with_spec(MESH_GROUP_SERVICE_LIST_MESH_GROUPS_SPEC)
        .route(
            MESH_GROUP_SERVICE_SERVICE_NAME,
            "CreateMeshGroup",
            handler_fn(move |ctx, request| {
                create_mesh_group(create_group_state.clone(), ctx, request)
            }),
        )
        .with_spec(MESH_GROUP_SERVICE_CREATE_MESH_GROUP_SPEC)
        .route_idempotent(
            MESH_GROUP_SERVICE_SERVICE_NAME,
            "GetMeshGroup",
            handler_fn(move |ctx, request| get_mesh_group(get_group_state.clone(), ctx, request)),
        )
        .with_spec(MESH_GROUP_SERVICE_GET_MESH_GROUP_SPEC)
        .route(
            MESH_GROUP_SERVICE_SERVICE_NAME,
            "DeleteMeshGroup",
            handler_fn(move |ctx, request| {
                delete_mesh_group(delete_group_state.clone(), ctx, request)
            }),
        )
        .with_spec(MESH_GROUP_SERVICE_DELETE_MESH_GROUP_SPEC)
        .route(
            MESH_GROUP_SERVICE_SERVICE_NAME,
            "SetMeshGroupPolicy",
            handler_fn(move |ctx, request| {
                set_mesh_group_policy(set_policy_state.clone(), ctx, request)
            }),
        )
        .with_spec(MESH_GROUP_SERVICE_SET_MESH_GROUP_POLICY_SPEC)
        .route(
            MESH_GROUP_SERVICE_SERVICE_NAME,
            "AddMeshGroupMember",
            handler_fn(move |ctx, request| {
                add_mesh_group_member(add_member_state.clone(), ctx, request)
            }),
        )
        .with_spec(MESH_GROUP_SERVICE_ADD_MESH_GROUP_MEMBER_SPEC)
        .route(
            MESH_GROUP_SERVICE_SERVICE_NAME,
            "RemoveMeshGroupMember",
            handler_fn(move |ctx, request| {
                remove_mesh_group_member(remove_member_state.clone(), ctx, request)
            }),
        )
        .with_spec(MESH_GROUP_SERVICE_REMOVE_MESH_GROUP_MEMBER_SPEC)
        .route_idempotent(
            MESH_KEY_VALUE_SERVICE_SERVICE_NAME,
            "ListMeshKeyValues",
            handler_fn(move |ctx, request| {
                list_mesh_key_values(list_kv_state.clone(), ctx, request)
            }),
        )
        .with_spec(MESH_KEY_VALUE_SERVICE_LIST_MESH_KEY_VALUES_SPEC)
        .route_idempotent(
            MESH_KEY_VALUE_SERVICE_SERVICE_NAME,
            "GetMeshKeyValue",
            handler_fn(move |ctx, request| get_mesh_key_value(get_kv_state.clone(), ctx, request)),
        )
        .with_spec(MESH_KEY_VALUE_SERVICE_GET_MESH_KEY_VALUE_SPEC)
        .route(
            MESH_KEY_VALUE_SERVICE_SERVICE_NAME,
            "SetMeshKeyValue",
            handler_fn(move |ctx, request| set_mesh_key_value(set_kv_state.clone(), ctx, request)),
        )
        .with_spec(MESH_KEY_VALUE_SERVICE_SET_MESH_KEY_VALUE_SPEC)
        .route(
            MESH_KEY_VALUE_SERVICE_SERVICE_NAME,
            "DeleteMeshKeyValue",
            handler_fn(move |ctx, request| delete_mesh_key_value(state.clone(), ctx, request)),
        )
        .with_spec(MESH_KEY_VALUE_SERVICE_DELETE_MESH_KEY_VALUE_SPEC)
}

async fn list_mesh_networks(
    state: AppState,
    ctx: RequestContext,
    request: ListMeshNetworksRequest,
) -> ServiceResult<ListMeshNetworksResponse> {
    page(&request.page_token, request.page_size).map_err(|e| rpc_app_error(&e, &ctx))?;
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    let networks = state
        .product
        .list_networks(&request.org_id, credential)
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(ListMeshNetworksResponse {
        networks: networks.into_iter().map(proto_network).collect(),
        ..Default::default()
    })
}

async fn create_mesh_network(
    state: AppState,
    ctx: RequestContext,
    request: CreateMeshNetworkRequest,
) -> ServiceResult<CreateMeshNetworkResponse> {
    validate_network_id(&request.network_id).map_err(|e| rpc_app_error(&e, &ctx))?;
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    let network = state
        .product
        .create_network(&request.org_id, &request.network_id, credential)
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(CreateMeshNetworkResponse {
        network: Some(proto_network(network)).into(),
        ..Default::default()
    })
}

async fn join_mesh_network(
    state: AppState,
    ctx: RequestContext,
    request: JoinMeshNetworkRequest,
) -> ServiceResult<JoinMeshNetworkResponse> {
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    let network = state
        .product
        .join_network(&request.invite_code, credential)
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(JoinMeshNetworkResponse {
        network: Some(proto_network(network)).into(),
        ..Default::default()
    })
}

async fn delete_mesh_network(
    state: AppState,
    ctx: RequestContext,
    request: DeleteMeshNetworkRequest,
) -> ServiceResult<DeleteMeshNetworkResponse> {
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    state
        .product
        .delete_network(&request.org_id, &request.network_id, credential)
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    state
        .mesh_coordinate
        .revoke_network(request.network_id.trim());
    connectrpc::Response::ok(DeleteMeshNetworkResponse::default())
}

async fn list_mesh_nodes(
    state: AppState,
    ctx: RequestContext,
    request: ListMeshNodesRequest,
) -> ServiceResult<ListMeshNodesResponse> {
    page(&request.page_token, request.page_size).map_err(|e| rpc_app_error(&e, &ctx))?;
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    let nodes = state
        .product
        .list_nodes(&request.org_id, &request.network_id, credential)
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(ListMeshNodesResponse {
        nodes: nodes
            .into_iter()
            .map(|node| proto_node(&request.org_id, node))
            .collect(),
        ..Default::default()
    })
}

async fn revoke_mesh_node(
    state: AppState,
    ctx: RequestContext,
    request: RevokeMeshNodeRequest,
) -> ServiceResult<RevokeMeshNodeResponse> {
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    state
        .product
        .revoke_node(
            &request.org_id,
            &request.network_id,
            &request.node_name,
            credential,
        )
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    state
        .mesh_coordinate
        .revoke_node(request.network_id.trim(), request.node_name.trim());
    connectrpc::Response::ok(RevokeMeshNodeResponse::default())
}

async fn create_mesh_node_enrollment(
    state: AppState,
    ctx: RequestContext,
    request: CreateMeshNodeEnrollmentRequest,
) -> ServiceResult<CreateMeshNodeEnrollmentResponse> {
    let ttl = optional_ttl(request.ttl.as_option(), Duration::minutes(10))
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    let created = state
        .product
        .create_node_enrollment(
            &request.org_id,
            &request.network_id,
            &request.node_name,
            credential,
            ttl,
        )
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(CreateMeshNodeEnrollmentResponse {
        enrollment: Some(proto_enrollment(&request.org_id, created.enrollment)).into(),
        enrollment_code: created.enrollment_code,
        ..Default::default()
    })
}

async fn redeem_mesh_node_enrollment(
    state: AppState,
    ctx: RequestContext,
    request: RedeemMeshNodeEnrollmentRequest,
) -> ServiceResult<RedeemMeshNodeEnrollmentResponse> {
    let redeemed = state
        .product
        .redeem_node_enrollment(
            &request.enrollment_code,
            &request.node_name,
            &request.peer_url,
        )
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(RedeemMeshNodeEnrollmentResponse {
        node: Some(proto_node(&redeemed.organization_id, redeemed.node)).into(),
        enrollment: Some(proto_enrollment(
            &redeemed.organization_id,
            redeemed.enrollment,
        ))
        .into(),
        ..Default::default()
    })
}

async fn list_mesh_invites(
    state: AppState,
    ctx: RequestContext,
    request: ListMeshInvitesRequest,
) -> ServiceResult<ListMeshInvitesResponse> {
    page(&request.page_token, request.page_size).map_err(|e| rpc_app_error(&e, &ctx))?;
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    let invites = state
        .product
        .list_invites(&request.org_id, &request.network_id, credential)
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(ListMeshInvitesResponse {
        invites: invites.into_iter().map(proto_invite).collect(),
        ..Default::default()
    })
}

async fn create_mesh_invite(
    state: AppState,
    ctx: RequestContext,
    request: CreateMeshInviteRequest,
) -> ServiceResult<CreateMeshInviteResponse> {
    let ttl = optional_ttl(request.ttl.as_option(), Duration::hours(1))
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    let created = state
        .product
        .create_invite(&request.org_id, &request.network_id, credential, ttl)
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(CreateMeshInviteResponse {
        invite: Some(proto_invite(created.invite)).into(),
        invite_code: created.invite_code,
        ..Default::default()
    })
}

async fn delete_mesh_invite(
    state: AppState,
    ctx: RequestContext,
    request: DeleteMeshInviteRequest,
) -> ServiceResult<DeleteMeshInviteResponse> {
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    state
        .product
        .delete_invite(
            &request.org_id,
            &request.network_id,
            &request.invite_id,
            credential,
        )
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(DeleteMeshInviteResponse::default())
}

async fn list_mesh_groups(
    state: AppState,
    ctx: RequestContext,
    request: ListMeshGroupsRequest,
) -> ServiceResult<ListMeshGroupsResponse> {
    page(&request.page_token, request.page_size).map_err(|e| rpc_app_error(&e, &ctx))?;
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    let groups = state
        .product
        .list_groups(&request.org_id, &request.network_id, credential)
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(ListMeshGroupsResponse {
        groups: groups
            .into_iter()
            .map(|group| proto_group(&request.org_id, group))
            .collect(),
        ..Default::default()
    })
}

async fn create_mesh_group(
    state: AppState,
    ctx: RequestContext,
    request: CreateMeshGroupRequest,
) -> ServiceResult<CreateMeshGroupResponse> {
    validate_group_name(&request.name).map_err(|e| rpc_app_error(&e, &ctx))?;
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    let group = state
        .product
        .create_group(
            &request.org_id,
            &request.network_id,
            &request.name,
            credential,
        )
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(CreateMeshGroupResponse {
        group: Some(proto_group(&request.org_id, group)).into(),
        ..Default::default()
    })
}

async fn get_mesh_group(
    state: AppState,
    ctx: RequestContext,
    request: GetMeshGroupRequest,
) -> ServiceResult<GetMeshGroupResponse> {
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    let group = state
        .product
        .get_group(
            &request.org_id,
            &request.network_id,
            &request.group_name,
            credential,
        )
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(GetMeshGroupResponse {
        group: Some(proto_group(&request.org_id, group)).into(),
        ..Default::default()
    })
}

async fn delete_mesh_group(
    state: AppState,
    ctx: RequestContext,
    request: DeleteMeshGroupRequest,
) -> ServiceResult<DeleteMeshGroupResponse> {
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    state
        .product
        .delete_group(
            &request.org_id,
            &request.network_id,
            &request.group_name,
            credential,
        )
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(DeleteMeshGroupResponse::default())
}

async fn set_mesh_group_policy(
    state: AppState,
    ctx: RequestContext,
    request: SetMeshGroupPolicyRequest,
) -> ServiceResult<SetMeshGroupPolicyResponse> {
    let messages_policy = match request.messages_policy.as_known() {
        None
        | Some(MeshGroupMessagesPolicy::Unspecified)
        | Some(MeshGroupMessagesPolicy::InternalOnly) => "",
        Some(MeshGroupMessagesPolicy::Open) => GROUP_MESSAGES_OPEN,
    };
    let debug_policy = match request.debug_policy.as_known() {
        None
        | Some(MeshGroupDebugPolicy::Unspecified)
        | Some(MeshGroupDebugPolicy::ObserveOnly) => "",
        Some(MeshGroupDebugPolicy::None) => GROUP_DEBUG_NONE,
        Some(MeshGroupDebugPolicy::Full) => GROUP_DEBUG_FULL,
    };
    normalize_group_messages_policy(messages_policy).map_err(|e| rpc_app_error(&e, &ctx))?;
    normalize_group_debug_policy(debug_policy).map_err(|e| rpc_app_error(&e, &ctx))?;
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    let policy = state
        .product
        .set_group_policy(
            &request.org_id,
            &request.network_id,
            &request.group_name,
            messages_policy,
            debug_policy,
            credential,
        )
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(SetMeshGroupPolicyResponse {
        policy: Some(proto_group_policy(&request.org_id, policy)).into(),
        ..Default::default()
    })
}

async fn add_mesh_group_member(
    state: AppState,
    ctx: RequestContext,
    request: AddMeshGroupMemberRequest,
) -> ServiceResult<AddMeshGroupMemberResponse> {
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    let member = state
        .product
        .add_group_member(
            &request.org_id,
            &request.network_id,
            &request.group_name,
            &request.node_name,
            &request.session_name,
            credential,
        )
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(AddMeshGroupMemberResponse {
        member: Some(proto_group_member(&request.org_id, member)).into(),
        ..Default::default()
    })
}

async fn remove_mesh_group_member(
    state: AppState,
    ctx: RequestContext,
    request: RemoveMeshGroupMemberRequest,
) -> ServiceResult<RemoveMeshGroupMemberResponse> {
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    state
        .product
        .remove_group_member(
            &request.org_id,
            &request.network_id,
            &request.group_name,
            &request.node_name,
            &request.session_name,
            credential,
        )
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(RemoveMeshGroupMemberResponse::default())
}

async fn list_mesh_key_values(
    state: AppState,
    ctx: RequestContext,
    request: ListMeshKeyValuesRequest,
) -> ServiceResult<ListMeshKeyValuesResponse> {
    page(&request.page_token, request.page_size).map_err(|e| rpc_app_error(&e, &ctx))?;
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    let entries = state
        .product
        .list_key_values(
            &request.org_id,
            &request.network_id,
            &request.namespace,
            &request.prefix,
            credential,
        )
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(ListMeshKeyValuesResponse {
        entries: entries
            .into_iter()
            .map(|entry| {
                proto_kv(
                    &request.org_id,
                    &request.network_id,
                    &request.namespace,
                    entry,
                )
            })
            .collect(),
        ..Default::default()
    })
}

async fn get_mesh_key_value(
    state: AppState,
    ctx: RequestContext,
    request: GetMeshKeyValueRequest,
) -> ServiceResult<GetMeshKeyValueResponse> {
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    let entry = state
        .product
        .get_key_value(
            &request.org_id,
            &request.network_id,
            &request.namespace,
            &request.key,
            credential,
        )
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(GetMeshKeyValueResponse {
        entry: Some(proto_kv(
            &request.org_id,
            &request.network_id,
            &request.namespace,
            entry,
        ))
        .into(),
        ..Default::default()
    })
}

async fn set_mesh_key_value(
    state: AppState,
    ctx: RequestContext,
    request: SetMeshKeyValueRequest,
) -> ServiceResult<SetMeshKeyValueResponse> {
    let ttl =
        optional_optional_ttl(request.ttl.as_option()).map_err(|e| rpc_app_error(&e, &ctx))?;
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    let entry = state
        .product
        .set_key_value(
            KeyValueWrite {
                organization_id: &request.org_id,
                network_id: &request.network_id,
                namespace: &request.namespace,
                key: &request.key,
                value: request.value.to_vec(),
                ttl,
            },
            credential,
        )
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(SetMeshKeyValueResponse {
        entry: Some(proto_kv(
            &request.org_id,
            &request.network_id,
            &request.namespace,
            entry,
        ))
        .into(),
        ..Default::default()
    })
}

async fn delete_mesh_key_value(
    state: AppState,
    ctx: RequestContext,
    request: DeleteMeshKeyValueRequest,
) -> ServiceResult<DeleteMeshKeyValueResponse> {
    let credential = credential(&ctx).map_err(|e| rpc_app_error(&e, &ctx))?;
    state
        .product
        .delete_key_value(
            &request.org_id,
            &request.network_id,
            &request.namespace,
            &request.key,
            credential,
        )
        .await
        .map_err(|e| rpc_app_error(&e, &ctx))?;
    connectrpc::Response::ok(DeleteMeshKeyValueResponse::default())
}

fn credential(
    ctx: &RequestContext,
) -> AppResult<crate::mesh_authorization::ForwardedMeshCredential> {
    forwarded_mesh_credential(ctx.headers()).map_err(|_| AppError::Unauthorized)
}

fn page(page_token: &str, page_size: i32) -> AppResult<()> {
    if !page_token.is_empty() {
        return Err(AppError::BadRequest("unrecognized page_token".into()));
    }
    if page_size < 0 {
        return Err(AppError::BadRequest(
            "page_size must not be negative".into(),
        ));
    }
    Ok(())
}

fn optional_ttl(value: Option<&ProtoDuration>, default: Duration) -> AppResult<Duration> {
    optional_optional_ttl(value).map(|ttl| ttl.unwrap_or(default))
}

fn optional_optional_ttl(value: Option<&ProtoDuration>) -> AppResult<Option<Duration>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if !(-999_999_999..=999_999_999).contains(&value.nanos) {
        return Err(AppError::BadRequest("ttl is invalid".into()));
    }
    let nanos = value
        .seconds
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(i64::from(value.nanos)))
        .ok_or_else(|| AppError::BadRequest("ttl is invalid".into()))?;
    let ttl = Duration::nanoseconds(nanos);
    if ttl <= Duration::zero() {
        return Err(AppError::BadRequest("ttl must be positive".into()));
    }
    Ok(Some(ttl))
}

fn proto_network(network: Network) -> MeshNetwork {
    MeshNetwork {
        id: network.id,
        org_id: network.organization_id,
        created_at: Some(timestamp(network.created_at)).into(),
        node_count: network.node_count,
        invite_count: network.invite_count,
        ..Default::default()
    }
}

fn proto_node(org_id: &str, node: NodeRecord) -> MeshNode {
    MeshNode {
        org_id: org_id.to_owned(),
        network_id: node.network_id,
        name: node.name,
        peer_url: node.peer_url,
        connected: true,
        ..Default::default()
    }
}

fn proto_enrollment(org_id: &str, enrollment: NodeEnrollment) -> MeshNodeEnrollment {
    MeshNodeEnrollment {
        id: enrollment.id,
        org_id: org_id.to_owned(),
        network_id: enrollment.network_id,
        node_name: enrollment.node_name,
        owner_user_id: enrollment.owner_subject,
        issued_by_user_id: enrollment.issued_by,
        expires_at: Some(timestamp(enrollment.expires_at)).into(),
        created_at: Some(timestamp(enrollment.created_at)).into(),
        redeemed_at: enrollment.redeemed_at.map(timestamp).into(),
        ..Default::default()
    }
}

fn proto_invite(invite: Invite) -> MeshInvite {
    MeshInvite {
        id: invite.id,
        org_id: invite.organization_id,
        network_id: invite.network_id,
        created_by_user_id: invite.created_by_user_id,
        expires_at: Some(timestamp(invite.expires_at)).into(),
        created_at: Some(timestamp(invite.created_at)).into(),
        ..Default::default()
    }
}

fn proto_group(org_id: &str, view: GroupView) -> MeshGroup {
    MeshGroup {
        org_id: org_id.to_owned(),
        network_id: view.group.network_id,
        name: view.group.name,
        created_at: Some(timestamp(view.group.created_at)).into(),
        created_by_user_id: view.group.created_by,
        members: view
            .members
            .into_iter()
            .map(|member| proto_group_member(org_id, member))
            .collect(),
        policy: view
            .policy
            .map(|policy| proto_group_policy(org_id, policy))
            .into(),
        ..Default::default()
    }
}

fn proto_group_member(org_id: &str, member: GroupMember) -> MeshGroupMember {
    MeshGroupMember {
        org_id: org_id.to_owned(),
        network_id: member.network_id,
        group_name: member.group_name,
        node_name: member.node_name,
        session_name: member.session_name,
        created_at: Some(timestamp(member.created_at)).into(),
        ..Default::default()
    }
}

fn proto_group_policy(org_id: &str, policy: GroupPolicy) -> MeshGroupPolicy {
    MeshGroupPolicy {
        org_id: org_id.to_owned(),
        network_id: policy.network_id,
        group_name: policy.group_name,
        messages_policy: match policy.messages_policy.as_str() {
            GROUP_MESSAGES_OPEN => MeshGroupMessagesPolicy::Open,
            _ => MeshGroupMessagesPolicy::InternalOnly,
        }
        .into(),
        debug_policy: match policy.debug_policy.as_str() {
            GROUP_DEBUG_NONE => MeshGroupDebugPolicy::None,
            GROUP_DEBUG_FULL => MeshGroupDebugPolicy::Full,
            _ => MeshGroupDebugPolicy::ObserveOnly,
        }
        .into(),
        updated_at: Some(timestamp(policy.updated_at)).into(),
        ..Default::default()
    }
}

fn proto_kv(org_id: &str, network_id: &str, namespace: &str, entry: KVEntry) -> MeshKeyValue {
    MeshKeyValue {
        org_id: org_id.to_owned(),
        network_id: network_id.to_owned(),
        namespace: namespace.to_owned(),
        key: entry.key,
        value: entry.value,
        expires_at: entry.expires_at.map(timestamp).into(),
        ..Default::default()
    }
}

fn timestamp(value: chrono::DateTime<Utc>) -> Timestamp {
    Timestamp::from_unix(value.timestamp(), value.timestamp_subsec_nanos() as i32)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration as StdDuration;

    use codewire_client::{
        ClientConfig as CodewireClientConfig, CodewireClient, StaticTokenProvider,
    };
    use codewire_server_core::auth::hash_api_key;
    use connectrpc::client::{ClientConfig, HttpClient};
    use connectrpc::{ConnectError, ErrorCode};
    use reqwest::StatusCode;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::Config;
    use crate::config::LocalMeshAuthorizationConfig;
    use crate::store::{Invite, MemoryStore, MeshStore, NETWORK_ROLE_MEMBER, NodeEnrollment};

    const ORG: &str = "org-mesh-contract";
    const NETWORK: &str = "network-contract";
    const API_KEY: &str = "cw_mesh-contract";
    const UNKNOWN_BEARER: &str = "retired-environment-bearer";

    fn config() -> Config {
        Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            base_url: "https://mesh.codewire.sh".to_string(),
            derp_url: None,
            stun_servers: Vec::new(),
            database_url: None,
            mesh_authorization: None,
            derp_verify_addr: None,
            local_authorization: Some(LocalMeshAuthorizationConfig {
                organization_id: ORG.to_string(),
                api_key_hash: hash_api_key(API_KEY),
            }),
        }
    }

    async fn start(store: MemoryStore) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let app = crate::server::router_with_store(config(), Arc::new(store));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (addr, task)
    }

    fn client_config(addr: std::net::SocketAddr, credential: Option<&str>) -> ClientConfig {
        let config = ClientConfig::new(format!("http://{addr}").parse().unwrap());
        match credential {
            Some(credential) => {
                config.with_default_header("authorization", format!("Bearer {credential}"))
            }
            None => config,
        }
    }

    fn assert_code(error: ConnectError, expected: ErrorCode) {
        assert_eq!(error.code, expected, "{error:?}");
    }

    async fn seed_enrollment(
        store: &MemoryStore,
        code: &str,
        id: &str,
        node_name: &str,
        uses_remaining: i32,
        expires_at: chrono::DateTime<Utc>,
    ) {
        store
            .node_enrollment_create(NodeEnrollment {
                id: id.to_string(),
                network_id: NETWORK.to_string(),
                owner_subject: "user-mesh-contract".to_string(),
                issued_by: "user-mesh-contract".to_string(),
                node_name: node_name.to_string(),
                token_hash: format!("{:x}", Sha256::digest(code.as_bytes())),
                uses_remaining,
                expires_at,
                created_at: Utc::now(),
                redeemed_at: None,
            })
            .await
            .unwrap();
    }

    fn network_request() -> ListMeshNetworksRequest {
        ListMeshNetworksRequest {
            org_id: ORG.to_string(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn codewire_client_mesh_unary_calls_interoperate_over_http1_and_h2c() {
        let (addr, task) = start(MemoryStore::new()).await;
        let config = CodewireClientConfig::new(format!("http://{addr}")).expect("client config");

        let clients = [
            CodewireClient::with_http(
                config.clone(),
                StaticTokenProvider::new(API_KEY).expect("token"),
                reqwest::Client::new(),
            )
            .expect("HTTP/1.1 client"),
            CodewireClient::new(config, StaticTokenProvider::new(API_KEY).expect("token"))
                .expect("h2c client"),
        ];

        for client in clients {
            let response = tokio::time::timeout(
                StdDuration::from_secs(5),
                client.list_mesh_networks(network_request()),
            )
            .await
            .expect("Mesh unary request must not stall")
            .expect("list Mesh networks");
            assert!(response.networks.is_empty());
        }

        task.abort();
    }

    fn scoped_request_org(organization_id: &str) -> ListMeshNodesRequest {
        ListMeshNodesRequest {
            org_id: organization_id.to_string(),
            network_id: NETWORK.to_string(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn mesh_json_unary_http10_closes_without_keepalive_and_preserves_authorization() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (addr, task) = start(MemoryStore::new()).await;
        for (organization, credential, status, error_code) in [
            (ORG, Some(API_KEY), 200, None),
            (ORG, None, 401, Some("unauthenticated")),
            ("foreign-org", Some(API_KEY), 403, Some("permission_denied")),
        ] {
            let body = serde_json::json!({"orgId": organization}).to_string();
            let authorization = credential
                .map(|token| format!("Authorization: Bearer {token}\r\n"))
                .unwrap_or_default();
            // No Connection: close or write-half shutdown: HTTP/1.0 itself must close.
            let request = format!(
                "POST /codewire.v1.MeshNetworkService/ListMeshNetworks HTTP/1.0\r\nHost: {addr}\r\nContent-Type: application/json\r\nConnect-Protocol-Version: 1\r\nContent-Length: {}\r\n{authorization}\r\n{body}",
                body.len()
            );
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(StdDuration::from_secs(5), stream.read_to_end(&mut response))
                .await
                .expect("HTTP/1.0 unary response must reach EOF without client-forced close")
                .unwrap();
            let response = String::from_utf8(response).unwrap();
            let (headers, body) = response.split_once("\r\n\r\n").unwrap();
            assert!(
                headers.starts_with(&format!("HTTP/1.0 {status} ")),
                "{headers}"
            );
            let headers = headers.to_ascii_lowercase();
            assert!(!headers.contains("keep-alive"), "{headers}");
            assert!(!headers.contains("transfer-encoding: chunked"), "{headers}");
            if let Some(code) = error_code {
                let error: serde_json::Value = serde_json::from_str(body).unwrap();
                assert_eq!(error["code"], code);
            } else {
                let response: ListMeshNetworksResponse = serde_json::from_str(body).unwrap();
                assert!(response.networks.is_empty());
            }
        }
        task.abort();
    }

    #[tokio::test]
    async fn network_deletion_requires_owner_and_empty_nodes_and_retires_name() {
        let store = MemoryStore::new();
        store
            .network_create_with_owner(NETWORK, ORG, "local-owner:org-mesh-contract", Utc::now())
            .await
            .unwrap();
        let (addr, task) = start(store.clone()).await;
        let request = DeleteMeshNetworkRequest {
            org_id: ORG.to_owned(),
            network_id: NETWORK.to_owned(),
            ..Default::default()
        };
        for credential in [None, Some(UNKNOWN_BEARER), Some("cw_enr_synthetic-delete")] {
            let denied = MeshNetworkServiceClient::new(
                HttpClient::plaintext(),
                client_config(addr, credential),
            )
            .delete_mesh_network(request.clone())
            .await;
            assert!(denied.is_err());
            assert!(
                store
                    .network_organization_id(NETWORK)
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        let client = MeshNetworkServiceClient::new(
            HttpClient::plaintext(),
            client_config(addr, Some(API_KEY)),
        );
        assert_code(
            client
                .delete_mesh_network(DeleteMeshNetworkRequest {
                    org_id: "wrong-org".to_owned(),
                    ..request.clone()
                })
                .await
                .unwrap_err(),
            ErrorCode::PermissionDenied,
        );
        store
            .network_member_upsert(crate::store::NetworkMember {
                network_id: NETWORK.to_owned(),
                subject: "local-owner:org-mesh-contract".to_owned(),
                role: NETWORK_ROLE_MEMBER.to_owned(),
                created_at: Utc::now(),
                created_by: String::new(),
            })
            .await
            .unwrap();
        assert_code(
            client
                .delete_mesh_network(request.clone())
                .await
                .unwrap_err(),
            ErrorCode::PermissionDenied,
        );
        store
            .network_member_upsert(crate::store::NetworkMember {
                network_id: NETWORK.to_owned(),
                subject: "local-owner:org-mesh-contract".to_owned(),
                role: crate::store::NETWORK_ROLE_OWNER.to_owned(),
                created_at: Utc::now(),
                created_by: String::new(),
            })
            .await
            .unwrap();
        store
            .node_register(NodeRecord {
                network_id: NETWORK.to_owned(),
                name: "registered".to_owned(),
                peer_url: String::new(),
                github_id: None,
                owner_subject: "local-owner:org-mesh-contract".to_owned(),
                authorized_by: String::new(),
                enrollment_id: String::new(),
                authorized_at: Utc::now(),
                last_seen_at: Utc::now(),
            })
            .await
            .unwrap();
        assert_code(
            client
                .delete_mesh_network(request.clone())
                .await
                .unwrap_err(),
            ErrorCode::FailedPrecondition,
        );
        store.node_delete(NETWORK, "registered").await.unwrap();
        client.delete_mesh_network(request.clone()).await.unwrap();
        assert!(
            client
                .list_mesh_networks(network_request())
                .await
                .unwrap()
                .into_owned()
                .networks
                .is_empty()
        );
        assert_code(
            client.delete_mesh_network(request).await.unwrap_err(),
            ErrorCode::NotFound,
        );
        assert_code(
            client
                .create_mesh_network(CreateMeshNetworkRequest {
                    org_id: ORG.to_owned(),
                    network_id: NETWORK.to_owned(),
                    ..Default::default()
                })
                .await
                .unwrap_err(),
            ErrorCode::FailedPrecondition,
        );
        task.abort();
    }

    #[tokio::test]
    async fn all_retained_unary_rpcs_share_the_connect_domain_and_store() {
        let store = MemoryStore::new();
        let (addr, task) = start(store.clone()).await;
        let config = client_config(addr, Some(API_KEY));
        let network_client = MeshNetworkServiceClient::new(HttpClient::plaintext(), config.clone());
        let node_client = MeshNodeServiceClient::new(HttpClient::plaintext(), config.clone());
        let invite_client = MeshInviteServiceClient::new(HttpClient::plaintext(), config.clone());
        let group_client = MeshGroupServiceClient::new(HttpClient::plaintext(), config.clone());
        let kv_client = MeshKeyValueServiceClient::new(HttpClient::plaintext(), config);

        let created_network = network_client
            .create_mesh_network(CreateMeshNetworkRequest {
                org_id: ORG.to_string(),
                network_id: NETWORK.to_string(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(created_network.network.as_option().unwrap().id, NETWORK);
        let networks = network_client
            .list_mesh_networks(network_request())
            .await
            .unwrap()
            .into_owned();
        assert_eq!(networks.networks.len(), 1);

        store
            .node_register(NodeRecord {
                network_id: NETWORK.to_string(),
                name: "node-a".to_string(),
                peer_url: "https://node-a.mesh.test".to_string(),
                github_id: None,
                owner_subject: "user-mesh-contract".to_string(),
                authorized_by: "user-mesh-contract".to_string(),
                enrollment_id: "enrollment-seed".to_string(),
                authorized_at: Utc::now(),
                last_seen_at: Utc::now(),
            })
            .await
            .unwrap();
        let nodes = node_client
            .list_mesh_nodes(scoped_request_org(ORG))
            .await
            .unwrap()
            .into_owned();
        assert_eq!(nodes.nodes[0].name, "node-a");
        let enrollment = node_client
            .create_mesh_node_enrollment(CreateMeshNodeEnrollmentRequest {
                org_id: ORG.to_string(),
                network_id: NETWORK.to_string(),
                node_name: "node-b".to_string(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert!(enrollment.enrollment_code.starts_with("cw_enr_"));
        assert_eq!(
            enrollment.enrollment.as_option().unwrap().owner_user_id,
            "local-owner:org-mesh-contract"
        );

        let created_invite = invite_client
            .create_mesh_invite(CreateMeshInviteRequest {
                org_id: ORG.to_string(),
                network_id: NETWORK.to_string(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        let invite_id = created_invite.invite.as_option().unwrap().id.clone();
        assert!(created_invite.invite_code.starts_with("cw_inv_"));
        assert_ne!(invite_id, created_invite.invite_code);
        let invites = invite_client
            .list_mesh_invites(ListMeshInvitesRequest {
                org_id: ORG.to_string(),
                network_id: NETWORK.to_string(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(invites.invites[0].id, invite_id);

        let groups = group_client
            .list_mesh_groups(ListMeshGroupsRequest {
                org_id: ORG.to_string(),
                network_id: NETWORK.to_string(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert!(groups.groups.is_empty());
        group_client
            .create_mesh_group(CreateMeshGroupRequest {
                org_id: ORG.to_string(),
                network_id: NETWORK.to_string(),
                name: "contract".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
        let group = group_client
            .get_mesh_group(GetMeshGroupRequest {
                org_id: ORG.to_string(),
                network_id: NETWORK.to_string(),
                group_name: "contract".to_string(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(group.group.as_option().unwrap().name, "contract");
        let policy = group_client
            .set_mesh_group_policy(SetMeshGroupPolicyRequest {
                org_id: ORG.to_string(),
                network_id: NETWORK.to_string(),
                group_name: "contract".to_string(),
                messages_policy: MeshGroupMessagesPolicy::Open.into(),
                debug_policy: MeshGroupDebugPolicy::Full.into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(
            policy
                .policy
                .as_option()
                .unwrap()
                .messages_policy
                .as_known(),
            Some(MeshGroupMessagesPolicy::Open)
        );
        group_client
            .add_mesh_group_member(AddMeshGroupMemberRequest {
                org_id: ORG.to_string(),
                network_id: NETWORK.to_string(),
                group_name: "contract".to_string(),
                node_name: "node-a".to_string(),
                session_name: "session-a".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();

        let entries = kv_client
            .list_mesh_key_values(ListMeshKeyValuesRequest {
                org_id: ORG.to_string(),
                network_id: NETWORK.to_string(),
                namespace: "runtime".to_string(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert!(entries.entries.is_empty());
        kv_client
            .set_mesh_key_value(SetMeshKeyValueRequest {
                org_id: ORG.to_string(),
                network_id: NETWORK.to_string(),
                namespace: "runtime".to_string(),
                key: "key-a".to_string(),
                value: b"value-a".to_vec(),
                ..Default::default()
            })
            .await
            .unwrap();
        let entry = kv_client
            .get_mesh_key_value(GetMeshKeyValueRequest {
                org_id: ORG.to_string(),
                network_id: NETWORK.to_string(),
                namespace: "runtime".to_string(),
                key: "key-a".to_string(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(
            entry.entry.as_option().unwrap().value.as_slice(),
            b"value-a"
        );

        group_client
            .remove_mesh_group_member(RemoveMeshGroupMemberRequest {
                org_id: ORG.to_string(),
                network_id: NETWORK.to_string(),
                group_name: "contract".to_string(),
                node_name: "node-a".to_string(),
                session_name: "session-a".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
        group_client
            .delete_mesh_group(DeleteMeshGroupRequest {
                org_id: ORG.to_string(),
                network_id: NETWORK.to_string(),
                group_name: "contract".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
        kv_client
            .delete_mesh_key_value(DeleteMeshKeyValueRequest {
                org_id: ORG.to_string(),
                network_id: NETWORK.to_string(),
                namespace: "runtime".to_string(),
                key: "key-a".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
        node_client
            .revoke_mesh_node(RevokeMeshNodeRequest {
                org_id: ORG.to_string(),
                network_id: NETWORK.to_string(),
                node_name: "node-a".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
        invite_client
            .delete_mesh_invite(DeleteMeshInviteRequest {
                org_id: ORG.to_string(),
                network_id: NETWORK.to_string(),
                invite_id,
                ..Default::default()
            })
            .await
            .unwrap();

        let join_invite = invite_client
            .create_mesh_invite(CreateMeshInviteRequest {
                org_id: ORG.to_string(),
                network_id: NETWORK.to_string(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        let joined = network_client
            .join_mesh_network(JoinMeshNetworkRequest {
                invite_code: join_invite.invite_code,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(joined.network.as_option().unwrap().id, NETWORK);
        assert!(store.invite_list(NETWORK).await.unwrap().is_empty());
        assert_eq!(
            store
                .network_member_get(NETWORK, "local-owner:org-mesh-contract")
                .await
                .unwrap()
                .unwrap()
                .role,
            crate::store::NETWORK_ROLE_OWNER
        );

        let public_node_client =
            MeshNodeServiceClient::new(HttpClient::plaintext(), client_config(addr, None));
        let enrollment_code = enrollment.enrollment_code;
        let redeemed = public_node_client
            .redeem_mesh_node_enrollment(RedeemMeshNodeEnrollmentRequest {
                enrollment_code: enrollment_code.clone(),
                node_name: "node-b".to_string(),
                peer_url: "https://node-b.mesh.test".to_string(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        let redeemed_node = redeemed.node.as_option().unwrap();
        assert_eq!(redeemed_node.org_id, ORG);
        assert_eq!(redeemed_node.network_id, NETWORK);
        assert_eq!(redeemed_node.name, "node-b");
        assert_eq!(redeemed_node.peer_url, "https://node-b.mesh.test");
        let redeemed_enrollment = redeemed.enrollment.as_option().unwrap();
        assert_eq!(redeemed_enrollment.org_id, ORG);
        assert_eq!(redeemed_enrollment.network_id, NETWORK);
        assert_eq!(redeemed_enrollment.node_name, "node-b");
        assert!(redeemed_enrollment.redeemed_at.as_option().is_some());
        let second_use = public_node_client
            .redeem_mesh_node_enrollment(RedeemMeshNodeEnrollmentRequest {
                enrollment_code,
                node_name: "node-b".to_string(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_code(second_use, ErrorCode::PermissionDenied);
        task.abort();
    }

    #[tokio::test]
    async fn enrollment_redemption_enforces_lifecycle_and_name_contract() {
        let store = MemoryStore::new();
        store
            .network_create_with_owner(NETWORK, ORG, "local-owner:org-mesh-contract", Utc::now())
            .await
            .unwrap();
        seed_enrollment(
            &store,
            "cw_enr_expired",
            "enrollment-expired",
            "fixed-expired",
            1,
            Utc::now() - Duration::seconds(1),
        )
        .await;
        seed_enrollment(
            &store,
            "cw_enr_exhausted",
            "enrollment-exhausted",
            "fixed-exhausted",
            0,
            Utc::now() + Duration::hours(1),
        )
        .await;
        seed_enrollment(
            &store,
            "cw_enr_fixed",
            "enrollment-fixed",
            "fixed-node",
            1,
            Utc::now() + Duration::hours(1),
        )
        .await;
        seed_enrollment(
            &store,
            "cw_enr_free",
            "enrollment-free",
            "",
            1,
            Utc::now() + Duration::hours(1),
        )
        .await;
        let (addr, task) = start(store).await;
        let client = MeshNodeServiceClient::new(HttpClient::plaintext(), client_config(addr, None));

        for code in ["cw_enr_expired", "cw_enr_exhausted"] {
            assert_code(
                client
                    .redeem_mesh_node_enrollment(RedeemMeshNodeEnrollmentRequest {
                        enrollment_code: code.to_string(),
                        ..Default::default()
                    })
                    .await
                    .unwrap_err(),
                ErrorCode::PermissionDenied,
            );
        }

        assert_code(
            client
                .redeem_mesh_node_enrollment(RedeemMeshNodeEnrollmentRequest {
                    enrollment_code: "cw_enr_fixed".to_string(),
                    node_name: "wrong-node".to_string(),
                    ..Default::default()
                })
                .await
                .unwrap_err(),
            ErrorCode::PermissionDenied,
        );
        let fixed = client
            .redeem_mesh_node_enrollment(RedeemMeshNodeEnrollmentRequest {
                enrollment_code: "cw_enr_fixed".to_string(),
                peer_url: "https://fixed.mesh.test".to_string(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        let fixed_node = fixed.node.as_option().unwrap();
        assert_eq!(fixed_node.org_id, ORG);
        assert_eq!(fixed_node.network_id, NETWORK);
        assert_eq!(fixed_node.name, "fixed-node");
        assert_eq!(fixed_node.peer_url, "https://fixed.mesh.test");
        let fixed_enrollment = fixed.enrollment.as_option().unwrap();
        assert_eq!(fixed_enrollment.id, "enrollment-fixed");
        assert_eq!(fixed_enrollment.owner_user_id, "user-mesh-contract");
        assert_eq!(fixed_enrollment.issued_by_user_id, "user-mesh-contract");
        assert!(fixed_enrollment.redeemed_at.as_option().is_some());

        assert_code(
            client
                .redeem_mesh_node_enrollment(RedeemMeshNodeEnrollmentRequest {
                    enrollment_code: "cw_enr_free".to_string(),
                    ..Default::default()
                })
                .await
                .unwrap_err(),
            ErrorCode::InvalidArgument,
        );
        let free = client
            .redeem_mesh_node_enrollment(RedeemMeshNodeEnrollmentRequest {
                enrollment_code: "cw_enr_free".to_string(),
                node_name: "chosen-node".to_string(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(free.node.as_option().unwrap().name, "chosen-node");
        assert!(
            free.enrollment
                .as_option()
                .unwrap()
                .redeemed_at
                .as_option()
                .is_some()
        );
        task.abort();
    }

    #[tokio::test]
    async fn same_org_nonmember_is_hidden_and_forbidden_until_atomic_invite_join() {
        let store = MemoryStore::new();
        store
            .network_create_with_owner(NETWORK, ORG, "different-network-owner", Utc::now())
            .await
            .unwrap();
        store
            .network_create_with_owner(
                "network-cross-org",
                "org-cross-tenant",
                "local-owner:org-mesh-contract",
                Utc::now(),
            )
            .await
            .unwrap();
        let invite_code = "cw_inv_synthetic_membership_boundary";
        store
            .invite_create(Invite {
                id: "invite-membership-boundary".to_owned(),
                network_id: NETWORK.to_owned(),
                organization_id: ORG.to_owned(),
                created_by_user_id: "different-network-owner".to_owned(),
                code_hash: format!("{:x}", Sha256::digest(invite_code.as_bytes())),
                expires_at: Utc::now() + Duration::hours(1),
                created_at: Utc::now(),
            })
            .await
            .unwrap();
        let (addr, task) = start(store.clone()).await;
        let config = client_config(addr, Some(API_KEY));
        let network_client = MeshNetworkServiceClient::new(HttpClient::plaintext(), config.clone());
        let node_client = MeshNodeServiceClient::new(HttpClient::plaintext(), config.clone());
        let invite_client = MeshInviteServiceClient::new(HttpClient::plaintext(), config.clone());
        let kv_client = MeshKeyValueServiceClient::new(HttpClient::plaintext(), config);

        let hidden = network_client
            .list_mesh_networks(network_request())
            .await
            .unwrap()
            .into_owned();
        assert!(hidden.networks.is_empty());
        assert_code(
            node_client
                .list_mesh_nodes(scoped_request_org(ORG))
                .await
                .unwrap_err(),
            ErrorCode::PermissionDenied,
        );
        assert_code(
            node_client
                .list_mesh_nodes(ListMeshNodesRequest {
                    org_id: ORG.to_owned(),
                    network_id: "network-cross-org".to_owned(),
                    ..Default::default()
                })
                .await
                .unwrap_err(),
            ErrorCode::PermissionDenied,
        );
        assert_code(
            node_client
                .create_mesh_node_enrollment(CreateMeshNodeEnrollmentRequest {
                    org_id: ORG.to_owned(),
                    network_id: NETWORK.to_owned(),
                    node_name: "blocked-node".to_owned(),
                    ..Default::default()
                })
                .await
                .unwrap_err(),
            ErrorCode::PermissionDenied,
        );
        assert_code(
            kv_client
                .get_mesh_key_value(GetMeshKeyValueRequest {
                    org_id: ORG.to_owned(),
                    network_id: NETWORK.to_owned(),
                    namespace: "runtime".to_owned(),
                    key: "blocked".to_owned(),
                    ..Default::default()
                })
                .await
                .unwrap_err(),
            ErrorCode::PermissionDenied,
        );
        assert_code(
            network_client
                .create_mesh_network(CreateMeshNetworkRequest {
                    org_id: ORG.to_owned(),
                    network_id: NETWORK.to_owned(),
                    ..Default::default()
                })
                .await
                .unwrap_err(),
            ErrorCode::AlreadyExists,
        );

        network_client
            .join_mesh_network(JoinMeshNetworkRequest {
                invite_code: invite_code.to_owned(),
                ..Default::default()
            })
            .await
            .unwrap();
        let member = store
            .network_member_get(NETWORK, "local-owner:org-mesh-contract")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(member.role, NETWORK_ROLE_MEMBER);
        assert!(store.invite_list(NETWORK).await.unwrap().is_empty());
        assert_eq!(
            network_client
                .list_mesh_networks(network_request())
                .await
                .unwrap()
                .into_owned()
                .networks
                .len(),
            1
        );
        assert!(
            node_client
                .list_mesh_nodes(scoped_request_org(ORG))
                .await
                .unwrap()
                .into_owned()
                .nodes
                .is_empty()
        );
        node_client
            .create_mesh_node_enrollment(CreateMeshNodeEnrollmentRequest {
                org_id: ORG.to_owned(),
                network_id: NETWORK.to_owned(),
                node_name: "joined-node".to_owned(),
                ..Default::default()
            })
            .await
            .unwrap();
        kv_client
            .set_mesh_key_value(SetMeshKeyValueRequest {
                org_id: ORG.to_owned(),
                network_id: NETWORK.to_owned(),
                namespace: "runtime".to_owned(),
                key: "joined".to_owned(),
                value: b"synthetic-value".to_vec(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_code(
            invite_client
                .create_mesh_invite(CreateMeshInviteRequest {
                    org_id: ORG.to_owned(),
                    network_id: NETWORK.to_owned(),
                    ..Default::default()
                })
                .await
                .unwrap_err(),
            ErrorCode::PermissionDenied,
        );
        task.abort();
    }

    #[tokio::test]
    async fn retained_services_enforce_canonical_primary_auth_rows() {
        let store = MemoryStore::new();
        store
            .network_create_with_owner(NETWORK, ORG, "local-owner:org-mesh-contract", Utc::now())
            .await
            .unwrap();
        let (addr, task) = start(store).await;

        let unauthenticated = client_config(addr, None);
        assert_code(
            MeshNetworkServiceClient::new(HttpClient::plaintext(), unauthenticated.clone())
                .list_mesh_networks(network_request())
                .await
                .unwrap_err(),
            ErrorCode::Unauthenticated,
        );
        assert_code(
            MeshNodeServiceClient::new(HttpClient::plaintext(), unauthenticated.clone())
                .list_mesh_nodes(scoped_request_org(ORG))
                .await
                .unwrap_err(),
            ErrorCode::Unauthenticated,
        );
        assert_code(
            MeshInviteServiceClient::new(HttpClient::plaintext(), unauthenticated.clone())
                .list_mesh_invites(ListMeshInvitesRequest {
                    org_id: ORG.to_string(),
                    network_id: NETWORK.to_string(),
                    ..Default::default()
                })
                .await
                .unwrap_err(),
            ErrorCode::Unauthenticated,
        );
        assert_code(
            MeshGroupServiceClient::new(HttpClient::plaintext(), unauthenticated.clone())
                .list_mesh_groups(ListMeshGroupsRequest {
                    org_id: ORG.to_string(),
                    network_id: NETWORK.to_string(),
                    ..Default::default()
                })
                .await
                .unwrap_err(),
            ErrorCode::Unauthenticated,
        );
        assert_code(
            MeshKeyValueServiceClient::new(HttpClient::plaintext(), unauthenticated)
                .list_mesh_key_values(ListMeshKeyValuesRequest {
                    org_id: ORG.to_string(),
                    network_id: NETWORK.to_string(),
                    namespace: "runtime".to_string(),
                    ..Default::default()
                })
                .await
                .unwrap_err(),
            ErrorCode::Unauthenticated,
        );

        let unknown_bearer = client_config(addr, Some(UNKNOWN_BEARER));
        assert_code(
            MeshNetworkServiceClient::new(HttpClient::plaintext(), unknown_bearer.clone())
                .list_mesh_networks(network_request())
                .await
                .unwrap_err(),
            ErrorCode::Unauthenticated,
        );
        assert_code(
            MeshNodeServiceClient::new(HttpClient::plaintext(), unknown_bearer.clone())
                .list_mesh_nodes(scoped_request_org(ORG))
                .await
                .unwrap_err(),
            ErrorCode::Unauthenticated,
        );
        assert_code(
            MeshInviteServiceClient::new(HttpClient::plaintext(), unknown_bearer.clone())
                .list_mesh_invites(ListMeshInvitesRequest {
                    org_id: ORG.to_string(),
                    network_id: NETWORK.to_string(),
                    ..Default::default()
                })
                .await
                .unwrap_err(),
            ErrorCode::Unauthenticated,
        );
        assert_code(
            MeshGroupServiceClient::new(HttpClient::plaintext(), unknown_bearer.clone())
                .list_mesh_groups(ListMeshGroupsRequest {
                    org_id: ORG.to_string(),
                    network_id: NETWORK.to_string(),
                    ..Default::default()
                })
                .await
                .unwrap_err(),
            ErrorCode::Unauthenticated,
        );
        assert_code(
            MeshKeyValueServiceClient::new(HttpClient::plaintext(), unknown_bearer)
                .list_mesh_key_values(ListMeshKeyValuesRequest {
                    org_id: ORG.to_string(),
                    network_id: NETWORK.to_string(),
                    namespace: "runtime".to_string(),
                    ..Default::default()
                })
                .await
                .unwrap_err(),
            ErrorCode::Unauthenticated,
        );

        let api_key = client_config(addr, Some(API_KEY));
        assert_code(
            MeshNodeServiceClient::new(HttpClient::plaintext(), api_key.clone())
                .list_mesh_nodes(scoped_request_org("org-cross-tenant"))
                .await
                .unwrap_err(),
            ErrorCode::PermissionDenied,
        );
        assert_code(
            MeshInviteServiceClient::new(HttpClient::plaintext(), api_key.clone())
                .create_mesh_invite(CreateMeshInviteRequest {
                    org_id: ORG.to_string(),
                    network_id: NETWORK.to_string(),
                    ttl: Some(ProtoDuration::from_secs(-1)).into(),
                    ..Default::default()
                })
                .await
                .unwrap_err(),
            ErrorCode::InvalidArgument,
        );
        assert_code(
            MeshKeyValueServiceClient::new(HttpClient::plaintext(), api_key)
                .get_mesh_key_value(GetMeshKeyValueRequest {
                    org_id: ORG.to_string(),
                    network_id: NETWORK.to_string(),
                    namespace: "runtime".to_string(),
                    key: "missing".to_string(),
                    ..Default::default()
                })
                .await
                .unwrap_err(),
            ErrorCode::NotFound,
        );

        let response = reqwest::Client::new()
            .get(format!("http://{addr}/api/v1/networks?org_id={ORG}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        task.abort();
    }
}
