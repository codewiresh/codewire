use std::collections::BTreeSet;

use codewire_proto::codewire::console::v1::{
    EnvironmentSetupServiceClient, GetEnvironmentCreateOptionsRequest,
};
use connectrpc::CodecFormat;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use super::{Auth, Harness, PRIMARY_ORG, array, assert_bad_request, assert_connect_error};

const SERVICE: &str = "codewire.console.v1.EnvironmentSetupService";
const OFFICIAL_PRESET: &str = "preset_contract_official";
const SECRET_PROJECT: &str = "sp_preset_contract_1";

pub(super) async fn run(harness: &Harness) {
    assert_options_embed_product_messages_and_match_rest(harness).await;
    assert_detection_errors_and_parity(harness).await;
    assert_ticket_acquisition(harness).await;
}

pub(super) async fn assert_detection_unconfigured(harness: &Harness) {
    let connect = call(
        harness,
        "DetectRepo",
        json!({"repoUrl": "codewire/codewire", "branch": "main"}),
        Auth::User,
    )
    .await;
    assert_connect_error(
        &connect,
        StatusCode::SERVICE_UNAVAILABLE,
        "unavailable",
        "AI detection is not configured",
    );

    let rest = harness
        .rest(
            Method::POST,
            "/api/v1/environment-create/detect",
            Some(json!({"repo_url": "codewire/codewire", "branch": "main"})),
            Auth::User,
        )
        .await;
    rest.assert_status(
        StatusCode::SERVICE_UNAVAILABLE,
        "REST detection-unconfigured parity",
    );
    assert_eq!(rest.json()["detail"], "AI detection is not configured");
}

async fn call(harness: &Harness, method: &str, body: Value, auth: Auth<'_>) -> super::WireResponse {
    harness.connect_json(SERVICE, method, body, auth).await
}

async fn assert_options_embed_product_messages_and_match_rest(harness: &Harness) {
    let connect = call(
        harness,
        "GetEnvironmentCreateOptions",
        json!({"orgId": PRIMARY_ORG}),
        Auth::User,
    )
    .await;
    connect.assert_status(StatusCode::OK, "GetEnvironmentCreateOptions");
    let connect = connect.json();
    let connect_presets = ids(&connect["presets"], "Connect option presets");
    let connect_projects = ids(&connect["secretProjects"], "Connect option secret projects");
    assert!(connect_presets.contains(OFFICIAL_PRESET));
    assert!(connect_projects.contains(SECRET_PROJECT));

    for codec in [CodecFormat::Proto, CodecFormat::Json] {
        let client = EnvironmentSetupServiceClient::new(
            connectrpc::client::HttpClient::plaintext(),
            harness.client_config(Auth::User, codec),
        );
        let options = client
            .get_environment_create_options(GetEnvironmentCreateOptionsRequest {
                org_id: PRIMARY_ORG.into(),
                ..Default::default()
            })
            .await
            .expect("GetEnvironmentCreateOptions codec round trip")
            .into_owned();
        assert!(
            options
                .presets
                .iter()
                .any(|preset| preset.id == OFFICIAL_PRESET)
        );
        assert!(
            options
                .secret_projects
                .iter()
                .any(|project| project.id == SECRET_PROJECT)
        );
    }

    let rest = harness
        .rest(
            Method::GET,
            &format!("/api/v1/organizations/{PRIMARY_ORG}/environment-create/options"),
            None,
            Auth::User,
        )
        .await;
    rest.assert_status(StatusCode::OK, "REST environment-create options");
    let rest = rest.json();
    assert_eq!(
        connect_presets,
        ids(&rest["presets"], "REST option presets")
    );
    assert_eq!(
        connect_projects,
        ids(&rest["secret_projects"], "REST option secret projects")
    );
    assert_eq!(
        connect["githubStatus"]["connected"]
            .as_bool()
            .unwrap_or(false),
        rest["github_status"]["connected"]
            .as_bool()
            .unwrap_or(false)
    );
}

async fn assert_detection_errors_and_parity(harness: &Harness) {
    let invalid = call(
        harness,
        "DetectRepo",
        json!({"repoUrl": "not-a-repository", "branch": "main"}),
        Auth::User,
    )
    .await;
    let body = assert_connect_error(
        &invalid,
        StatusCode::BAD_REQUEST,
        "invalid_argument",
        "validation failed",
    );
    assert_bad_request(&body, &["repo_url"]);

    let rest = harness
        .rest(
            Method::POST,
            "/api/v1/environment-create/detect",
            Some(json!({"repo_url": "not-a-repository", "branch": "main"})),
            Auth::User,
        )
        .await;
    rest.assert_status(StatusCode::BAD_REQUEST, "REST invalid repo URL parity");
    assert_eq!(
        rest.json()["detail"],
        "invalid repo URL: URL must contain owner/repo"
    );

    // Loopback makes the forge failure deterministic and hermetic: the core
    // reaches its real HTTP fetch boundary without contacting a third party.
    let forge = call(
        harness,
        "DetectRepo",
        json!({"repoUrl": "https://127.0.0.1/codewire/missing", "branch": "main"}),
        Auth::User,
    )
    .await;
    assert_connect_error(&forge, StatusCode::SERVICE_UNAVAILABLE, "unavailable", "");

    let rest = harness
        .rest(
            Method::POST,
            "/api/v1/environment-create/detect",
            Some(json!({
                "repo_url": "https://127.0.0.1/codewire/missing",
                "branch": "main"
            })),
            Auth::User,
        )
        .await;
    rest.assert_status(StatusCode::BAD_GATEWAY, "REST forge failure parity");
    assert!(
        rest.json()["detail"]
            .as_str()
            .is_some_and(|detail| detail.starts_with("failed to fetch repo:"))
    );
}

async fn assert_ticket_acquisition(harness: &Harness) {
    let unauthenticated = call(harness, "IssueTerminalTicket", json!({}), Auth::None).await;
    assert_connect_error(
        &unauthenticated,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        "",
    );

    let issued = call(harness, "IssueTerminalTicket", json!({}), Auth::User).await;
    issued.assert_status(StatusCode::OK, "IssueTerminalTicket");
    let body = issued.json();
    let ticket = body["ticket"]
        .as_str()
        .expect("IssueTerminalTicket ticket string");
    assert!(!ticket.is_empty());
    assert_eq!(
        ticket.matches('.').count(),
        1,
        "ticket must be payload.signature"
    );
}

fn ids(value: &Value, label: &str) -> BTreeSet<String> {
    array(value, label)
        .iter()
        .map(|item| {
            item["id"]
                .as_str()
                .unwrap_or_else(|| panic!("{label} item lacks id: {item}"))
                .to_owned()
        })
        .collect()
}
