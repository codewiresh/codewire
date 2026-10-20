//! CLI parsing and synthetic Connect selector calls; no product platform.
use super::*;
use buffa::Message as _;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ENVIRONMENT_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const ENVIRONMENT_B: &str = "11111111-1111-4111-8111-111111111111";
const GET_ENVIRONMENT_PATH: &str = "/codewire.v1.EnvironmentService/GetEnvironment";
const LIST_ENVIRONMENTS_PATH: &str = "/codewire.v1.EnvironmentService/ListEnvironments";
const GET_RUNTIME_PATH: &str = "/codewire.v1.EnvironmentCwRuntimeService/GetEnvironmentCwRuntime";

fn synthetic_clients(server: &MockServer) -> (EnvironmentClient, CodewireClient) {
    let platform = config::ResolvedPlatformConfig::static_token(
        server.uri(),
        "synthetic-runtime-selector-token",
        true,
        None,
    );
    (
        EnvironmentClient::new(&platform).unwrap(),
        codewire_client(&platform).unwrap(),
    )
}

async fn listed_environment(server: &MockServer, name: &str) {
    let response = codewire_client::ListEnvironmentsResponse {
        environments: vec![codewire_client::Environment {
            id: ENVIRONMENT_B.into(),
            org_id: "org".into(),
            name: name.into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    Mock::given(method("POST"))
        .and(path(LIST_ENVIRONMENTS_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/proto")
                .set_body_bytes(response.encode_to_vec()),
        )
        .mount(server)
        .await;
}

async fn uuid_failure_never_selects_namesake(http_status: u16, code: &str) {
    let server = MockServer::start().await;
    let failure = ResponseTemplate::new(http_status)
        .set_body_json(serde_json::json!({"code": code, "message": "synthetic refusal"}));
    Mock::given(method("POST"))
        .and(path(GET_ENVIRONMENT_PATH))
        .respond_with(failure.clone())
        .mount(&server)
        .await;
    listed_environment(&server, ENVIRONMENT_A).await;
    Mock::given(method("POST"))
        .and(path(GET_RUNTIME_PATH))
        .respond_with(failure)
        .mount(&server)
        .await;
    let (environment_client, client) = synthetic_clients(&server);
    let id = resolve_runtime_environment_id(&environment_client, "org", ENVIRONMENT_A)
        .await
        .unwrap();
    assert_eq!(
        id, ENVIRONMENT_A,
        "explicit UUID must never select its namesake"
    );
    assert!(status(&client, "org", &id).await.is_err());

    // The real generated runtime call can fail. Neither that error nor legacy
    // GetEnvironment errors authorize List, a different scope, or a mutation.
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "UUID lookup must perform no Get or List");
    assert_eq!(requests[0].url.path(), GET_RUNTIME_PATH);
    let request =
        rpc::GetEnvironmentCwRuntimeRequest::decode_from_slice(&requests[0].body).unwrap();
    assert_eq!(request.org_id, "org");
    assert_eq!(request.environment_id, ENVIRONMENT_A);
}

#[tokio::test]
async fn runtime_uuid_deleted_environment_cannot_select_namesake() {
    uuid_failure_never_selects_namesake(404, "not_found").await;
}

#[tokio::test]
async fn runtime_uuid_transport_refusal_cannot_select_namesake() {
    uuid_failure_never_selects_namesake(503, "unavailable").await;
}

#[tokio::test]
async fn runtime_uuid_authorization_refusal_cannot_select_namesake() {
    uuid_failure_never_selects_namesake(403, "permission_denied").await;
}

#[tokio::test]
async fn runtime_uuid_forms_normalize_without_lookup() {
    let server = MockServer::start().await;
    let (client, _) = synthetic_clients(&server);
    for reference in [
        ENVIRONMENT_A.to_owned(),
        ENVIRONMENT_A.to_uppercase(),
        ENVIRONMENT_A.replace('-', ""),
        format!("urn:uuid:{ENVIRONMENT_A}"),
        format!("{{{ENVIRONMENT_A}}}"),
        format!("  {ENVIRONMENT_A}  "),
    ] {
        assert_eq!(
            resolve_runtime_environment_id(&client, "org", &reference)
                .await
                .unwrap(),
            ENVIRONMENT_A,
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

async fn rejected_selectors_have_no_lookup_or_effect(references: &[&str]) {
    let server = MockServer::start().await;
    let (client, _) = synthetic_clients(&server);
    let mut unexpected = Vec::new();
    for reference in references {
        // A namesake exists for every invalid selector. Check the whole table
        // even on the old policy, so one refusal cannot hide another fallback.
        listed_environment(&server, reference).await;
        let result = resolve_runtime_environment_id(&client, "org", reference).await;
        let requests = server.received_requests().await.unwrap();
        if result.is_ok() || !requests.is_empty() {
            unexpected.push((*reference, result.is_ok(), requests.len()));
        }
        server.reset().await;
    }
    assert!(
        unexpected.is_empty(),
        "selectors resolved or performed lookup: {unexpected:?}"
    );
}

#[tokio::test]
async fn runtime_uuid_nil_refuses_without_lookup_or_effect() {
    rejected_selectors_have_no_lookup_or_effect(&[
        "00000000-0000-0000-0000-000000000000",
        "00000000000000000000000000000000",
        "{00000000-0000-0000-0000-000000000000}",
        "urn:uuid:00000000-0000-0000-0000-000000000000",
    ])
    .await;
}

#[tokio::test]
async fn runtime_uuid_explicit_malformed_refuses_without_lookup_or_effect() {
    rejected_selectors_have_no_lookup_or_effect(&[
        "550e8400-e29b-41d4-a716-44665544000g",
        "urn:uuid:not-a-uuid",
        "URN:UUID:not-a-uuid",
        "{not-a-uuid}",
        "{550e8400-e29b-41d4-a716-446655440000",
        "550e8400-e29b-41d4-a716-446655440000}",
        "",
        "  ",
    ])
    .await;
}

#[tokio::test]
async fn runtime_ordinary_name_and_prefix_keep_existing_resolution() {
    let server = MockServer::start().await;
    let (client, _) = synthetic_clients(&server);
    listed_environment(&server, "builder").await;
    for reference in ["builder", "  builder  ", "11111111"] {
        assert_eq!(
            resolve_runtime_environment_id(&client, "org", reference)
                .await
                .unwrap(),
            ENVIRONMENT_B,
        );
    }
    assert!(
        resolve_runtime_environment_id(&client, "org", "missing-name")
            .await
            .is_err()
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 4);
    assert!(
        requests
            .iter()
            .all(|request| request.url.path() == LIST_ENVIRONMENTS_PATH)
    );
}

fn command(flags: &[&str]) -> (Option<EnvironmentPlacement>, EnvRuntimeCommand) {
    let cli = Cli::try_parse_from(flags).unwrap();
    let (local, platform, EnvCommand::Runtime(args)) = env_operation(cli) else {
        panic!("runtime route")
    };
    (
        if platform {
            Some(EnvironmentPlacement::Platform)
        } else if local {
            Some(EnvironmentPlacement::Local)
        } else {
            None
        },
        args.command,
    )
}

#[test]
fn platform_parser_requires_source_pin_and_full_u64_generation() {
    let pin = "a".repeat(64);
    for generation in ["0", "18446744073709551615"] {
        let flags = [
            "cw",
            "--cloud",
            "runtime",
            "update",
            "env-a",
            "--from",
            "/owned/release",
            "--target-sha256",
            &pin,
            "--expected-generation",
            generation,
        ];
        let (placement, command) = command(&flags);
        assert!(super::super::validate_placement(placement, &command).is_ok());
        let EnvRuntimeCommand::Update(args) = command else {
            panic!("update")
        };
        assert_eq!(args.expected_generation, Some(generation.parse().unwrap()));
        assert!(
            args.source.is_none()
                && args.image_sha256.is_none()
                && args.expected_revision.is_none()
        );
        for missing in ["--from", "--target-sha256", "--expected-generation"] {
            let index = flags.iter().position(|v| *v == missing).unwrap();
            let missing: Vec<_> = flags
                .iter()
                .enumerate()
                .filter_map(|(i, v)| (!(i == index || i == index + 1)).then_some(*v))
                .collect();
            assert!(Cli::try_parse_from(missing).is_err());
        }
    }
    for generation in ["-1", "00", "18446744073709551616"] {
        assert!(
            Cli::try_parse_from([
                "cw",
                "--cloud",
                "runtime",
                "rollback",
                "env-a",
                "--expected-generation",
                generation
            ])
            .is_err()
        );
    }
}

#[test]
fn native_and_platform_fields_cannot_cross_before_effects() {
    let pin = "a".repeat(64);
    let (_, platform_command) = command(&[
        "cw",
        "--cloud",
        "runtime",
        "update",
        "env-a",
        "--from",
        "/owned/release",
        "--target-sha256",
        &pin,
        "--expected-generation",
        "0",
    ]);
    assert!(
        super::super::validate_placement(Some(EnvironmentPlacement::Local), &platform_command)
            .is_err()
    );
    assert!(super::super::validate_placement(None, &platform_command).is_err());
    let (_, native_command) = command(&[
        "cw",
        "--local",
        "runtime",
        "update",
        "vm-a",
        "--source",
        "/owned/lock",
        "--image-sha256",
        &pin,
        "--target-sha256",
        &pin,
        "--expected-revision",
        "2",
    ]);
    assert!(
        super::super::validate_placement(Some(EnvironmentPlacement::Platform), &native_command)
            .is_err()
    );
    assert!(
        super::super::validate_placement(Some(EnvironmentPlacement::Local), &native_command)
            .is_ok()
    );
    let (_, cancel) = command(&[
        "cw",
        "--cloud",
        "runtime",
        "cancel",
        "env-a",
        "--request-id",
        "550e8400-e29b-41d4-a716-446655440000",
    ]);
    assert!(
        super::super::validate_placement(Some(EnvironmentPlacement::Platform), &cancel).is_err()
    );
}

#[test]
fn exact_generation_pending_and_legacy_guards_preserve_selection_tuple() {
    let mut info = rpc::GetEnvironmentCwRuntimeResponse {
        supported_image: true,
        selection: Some(rpc::EnvironmentCwRuntimeSelection {
            generation: u64::MAX,
            consistent: true,
            current: Some(rpc::EnvironmentCwRuntimeIdentity {
                sha256: "a".repeat(64),
                ..Default::default()
            })
            .into(),
            previous: Some(rpc::EnvironmentCwRuntimeIdentity {
                sha256: "b".repeat(64),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };
    let value = expected(&info, u64::MAX).unwrap();
    assert_eq!(value.current_sha256, Some("a".repeat(64)));
    assert_eq!(value.previous_sha256, Some("b".repeat(64)));
    let json = serde_json::to_value(&value).unwrap();
    assert_eq!(json["generation"], u64::MAX.to_string());
    assert!(expected(&info, u64::MAX - 1).is_err());
    info.selection.as_option_mut().unwrap().pending = true;
    assert!(expected(&info, u64::MAX).is_err());
    info.selection.as_option_mut().unwrap().pending = false;
    info.supported_image = false;
    assert!(expected(&info, u64::MAX).is_err());
}
