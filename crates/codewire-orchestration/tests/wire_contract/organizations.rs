use std::time::{SystemTime, UNIX_EPOCH};

use codewire_proto::codewire::v1::{ListOrganizationsRequest, OrganizationServiceClient};
use connectrpc::CodecFormat;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use super::{
    Auth, Harness, PRIMARY_ORG, SECONDARY_ORG, array, assert_bad_request, assert_connect_error,
};

const SERVICE: &str = "codewire.v1.OrganizationService";

pub(super) async fn run(harness: &Harness) {
    assert_auth_and_read_parity(harness).await;
    assert_invitation_public_read(harness).await;
    assert_create_validation_permission_and_delete(harness).await;
}

async fn call(harness: &Harness, method: &str, body: Value, auth: Auth<'_>) -> super::WireResponse {
    harness.connect_json(SERVICE, method, body, auth).await
}

async fn assert_auth_and_read_parity(harness: &Harness) {
    for method in [
        "ListOrganizations",
        "CreateOrganization",
        "GetOrganization",
        "DeleteOrganization",
        "ListMembers",
        "UpdateMemberRole",
        "RemoveMember",
        "GetMemberAssignments",
        "UpdateMemberAssignments",
        "ListInvitations",
        "CreateInvitation",
        "RevokeInvitation",
        "AcceptInvitation",
    ] {
        let response = call(harness, method, json!({}), Auth::None).await;
        assert_connect_error(
            &response,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "unauthorized",
        );
    }

    let mut binary_organizations = Vec::new();
    for codec in [CodecFormat::Proto, CodecFormat::Json] {
        let client = OrganizationServiceClient::new(
            connectrpc::client::HttpClient::plaintext(),
            harness.client_config(Auth::Admin, codec),
        );
        let listed = client
            .list_organizations(ListOrganizationsRequest::default())
            .await
            .expect("ListOrganizations codec round trip")
            .into_owned();
        assert_eq!(listed.organizations.len(), 2);
        assert!(listed.next_page_token.is_empty());
        if codec == CodecFormat::Proto {
            binary_organizations = listed.organizations;
        }
    }

    let rest = harness
        .rest(Method::GET, "/api/v1/organizations", None, Auth::Admin)
        .await;
    rest.assert_status(StatusCode::OK, "REST organization list");
    let rest = rest.json();
    let rest = array(&rest, "REST organizations");
    assert_eq!(rest.len(), binary_organizations.len());
    for (membership, rest) in binary_organizations.iter().zip(rest) {
        let org = membership
            .organization
            .as_option()
            .expect("organization membership");
        assert_eq!(org.id, rest["id"]);
        assert_eq!(org.name, rest["name"]);
        assert_eq!(org.slug, rest["slug"]);
    }

    let connect = call(
        harness,
        "GetOrganization",
        json!({"orgId": PRIMARY_ORG}),
        Auth::Admin,
    )
    .await;
    connect.assert_status(StatusCode::OK, "GetOrganization");
    let connect = connect.json();
    assert_eq!(connect["organization"]["id"], PRIMARY_ORG);
    assert_eq!(array(&connect["members"], "organization members").len(), 2);
    let rest = harness
        .rest(
            Method::GET,
            &format!("/api/v1/organizations/{PRIMARY_ORG}"),
            None,
            Auth::Admin,
        )
        .await;
    rest.assert_status(StatusCode::OK, "REST organization get");
    let rest = rest.json();
    assert_eq!(connect["organization"]["id"], rest["id"]);
    assert_eq!(connect["organization"]["name"], rest["name"]);
    assert_eq!(connect["organization"]["slug"], rest["slug"]);
    assert_eq!(connect["organization"]["createdBy"], rest["created_by"]);
    assert_eq!(
        array(&connect["members"], "Connect members").len(),
        array(&rest["members"], "REST members").len()
    );

    let pagination = call(
        harness,
        "ListOrganizations",
        json!({"pageToken": "future"}),
        Auth::Admin,
    )
    .await;
    assert_connect_error(
        &pagination,
        StatusCode::BAD_REQUEST,
        "invalid_argument",
        "unrecognized page_token",
    );
    let hidden = call(
        harness,
        "GetOrganization",
        json!({"orgId": SECONDARY_ORG}),
        Auth::User,
    )
    .await;
    assert_connect_error(&hidden, StatusCode::NOT_FOUND, "not_found", "");
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos()
}

async fn assert_invitation_public_read(harness: &Harness) {
    let created = call(
        harness,
        "CreateInvitation",
        json!({
            "orgId": PRIMARY_ORG,
            "email": format!("organization-contract-{}@example.com", nonce()),
            "role": "ORG_ROLE_UNSPECIFIED"
        }),
        Auth::Admin,
    )
    .await;
    created.assert_status(StatusCode::OK, "CreateInvitation");
    let invitation = created.json()["invitation"].clone();
    let id = invitation["id"].as_str().expect("invitation id").to_owned();
    let token = invitation["token"]
        .as_str()
        .expect("invitation token")
        .to_owned();
    assert_eq!(invitation["role"], "ORG_ROLE_MEMBER");
    assert_eq!(invitation["status"], "INVITATION_STATUS_PENDING");

    let message = serde_json::to_string(&json!({"token": token})).unwrap();
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("connect", "v1")
        .append_pair("encoding", "json")
        .append_pair("message", &message)
        .finish();
    let public = harness
        .rest(
            Method::GET,
            &format!("/{SERVICE}/GetInvitationByToken?{query}"),
            None,
            Auth::None,
        )
        .await;
    public.assert_status(StatusCode::OK, "public GetInvitationByToken");
    let public_invitation = public.json()["invitation"].clone();
    assert_eq!(public_invitation["id"], invitation["id"]);
    assert_eq!(public_invitation["token"], invitation["token"]);

    let unknown_message = serde_json::to_string(&json!({"token": "unknown"})).unwrap();
    let unknown_query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("connect", "v1")
        .append_pair("encoding", "json")
        .append_pair("message", &unknown_message)
        .finish();
    let unknown = harness
        .rest(
            Method::GET,
            &format!("/{SERVICE}/GetInvitationByToken?{unknown_query}"),
            None,
            Auth::None,
        )
        .await;
    assert_connect_error(&unknown, StatusCode::NOT_FOUND, "not_found", "");

    call(
        harness,
        "RevokeInvitation",
        json!({"orgId": PRIMARY_ORG, "invitationId": id}),
        Auth::Admin,
    )
    .await
    .assert_status(StatusCode::OK, "RevokeInvitation");
}

async fn assert_create_validation_permission_and_delete(harness: &Harness) {
    let slug = format!("organization-contract-{}", nonce());
    let created = call(
        harness,
        "CreateOrganization",
        json!({"name": "Organization Contract Lifecycle", "slug": slug}),
        Auth::Admin,
    )
    .await;
    created.assert_status(StatusCode::OK, "CreateOrganization");
    let organization = created.json()["organization"].clone();
    let id = organization["id"]
        .as_str()
        .expect("organization id")
        .to_owned();
    assert_eq!(organization["slug"], slug);

    let collision = call(
        harness,
        "CreateOrganization",
        json!({"name": "Organization Contract Collision", "slug": slug}),
        Auth::Admin,
    )
    .await;
    assert_connect_error(&collision, StatusCode::CONFLICT, "already_exists", "");
    let invalid = call(
        harness,
        "CreateOrganization",
        json!({"name": "", "slug": format!("{slug}-invalid")}),
        Auth::Admin,
    )
    .await;
    let body = assert_connect_error(
        &invalid,
        StatusCode::BAD_REQUEST,
        "invalid_argument",
        "validation failed",
    );
    assert_bad_request(&body, &["name"]);
    let denied = call(
        harness,
        "CreateInvitation",
        json!({"orgId": PRIMARY_ORG, "email": "denied@codewire.test", "role": "ORG_ROLE_MEMBER"}),
        Auth::User,
    )
    .await;
    assert_connect_error(&denied, StatusCode::FORBIDDEN, "permission_denied", "");

    let deleted = call(
        harness,
        "DeleteOrganization",
        json!({"orgId": id}),
        Auth::Admin,
    )
    .await;
    deleted.assert_status(StatusCode::OK, "DeleteOrganization");
    let deleted = deleted.json();
    assert!(deleted["operationId"].is_string());
    assert!(deleted["state"].is_string());
}
