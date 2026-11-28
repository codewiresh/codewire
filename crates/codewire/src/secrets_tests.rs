//! A secret's binding through the secret calls, against a synthetic server:
//! a listed secret arrives with its binding, each set sends exactly the
//! binding or `plain` it was given, and a set request never prints its value.

use buffa::Message as _;
use codewire_proto::codewire::v1::{
    SecretBasicPresentation, SecretBasicUserPresentation, SecretBinding, SecretHeaderPresentation,
    SecretMetadata, secret_binding,
};
use wiremock::matchers::{body_bytes, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::{ClientConfig, StaticTokenProvider};

const MARKER: &str = "never-log-this-secret-value";

/// Answers `rpc` once with `body`, only for a request whose bytes are
/// `request` when one is given.
async fn serve(server: &MockServer, rpc: &str, request: Option<Vec<u8>>, body: Vec<u8>) {
    let mock = Mock::given(method("POST"))
        .and(path(format!("/codewire.v1.SecretService/{rpc}")))
        .and(header("authorization", "Bearer test-token"));
    let mock = match request {
        Some(request) => mock.and(body_bytes(request)),
        None => mock,
    };
    mock.respond_with(
        ResponseTemplate::new(200)
            .insert_header("content-type", "application/proto")
            .set_body_bytes(body),
    )
    .expect(1)
    .mount(server)
    .await;
}

fn client(server: &MockServer) -> CodewireClient {
    CodewireClient::with_http(
        ClientConfig::new(server.uri()).expect("server URL"),
        StaticTokenProvider::new("test-token").expect("token"),
        reqwest::Client::new(),
    )
    .expect("client")
}

#[tokio::test]
async fn secret_calls_carry_a_binding_and_never_print_the_value() {
    let server = MockServer::start().await;
    let binding = SecretBinding {
        hosts: vec!["api.example.com".into()],
        presentation: Some(secret_binding::Presentation::from(
            SecretHeaderPresentation {
                headers: vec!["X-Api-Key".into()],
                scheme: Some("none".into()),
                ..Default::default()
            },
        )),
        prefix: "sk_".into(),
        binding_generation: 2,
        ..Default::default()
    };
    serve(
        &server,
        "ListSecrets",
        None,
        ListSecretsResponse {
            secrets: vec![SecretMetadata {
                key: "DATABASE_URL".into(),
                binding: Some(binding.clone()).into(),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec(),
    )
    .await;
    let set_secret = SetSecretRequest {
        org_id: "org_123".into(),
        key: "DATABASE_URL".into(),
        value: MARKER.into(),
        binding: Some(SecretBinding {
            hosts: vec!["git.example.com".into()],
            presentation: Some(SecretBasicPresentation::default().into()),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };
    serve(
        &server,
        "SetSecret",
        Some(set_secret.encode_to_vec()),
        SetSecretResponse::default().encode_to_vec(),
    )
    .await;
    let set_user_secret = SetUserSecretRequest {
        key: "GITHUB_TOKEN".into(),
        value: MARKER.into(),
        plain: true,
        ..Default::default()
    };
    serve(
        &server,
        "SetUserSecret",
        Some(set_user_secret.encode_to_vec()),
        SetUserSecretResponse::default().encode_to_vec(),
    )
    .await;
    let set_project_secret = SetProjectSecretRequest {
        org_id: "org_123".into(),
        secret_project_id: "sp_123".into(),
        key: "DATABASE_URL".into(),
        value: MARKER.into(),
        binding: Some(SecretBinding {
            hosts: vec!["api.pay.example.com".into()],
            presentation: Some(SecretBasicUserPresentation::default().into()),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };
    serve(
        &server,
        "SetProjectSecret",
        Some(set_project_secret.encode_to_vec()),
        SetProjectSecretResponse::default().encode_to_vec(),
    )
    .await;

    let client = client(&server);
    let listed = client
        .list_secrets(ListSecretsRequest {
            org_id: "org_123".into(),
            ..Default::default()
        })
        .await
        .expect("list organization secrets");
    assert_eq!(listed.secrets[0].binding.as_option(), Some(&binding));
    for printed in [
        format!("{set_secret:?}"),
        format!("{set_user_secret:?}"),
        format!("{set_project_secret:?}"),
    ] {
        assert!(!printed.contains(MARKER), "{printed}");
    }
    client
        .set_secret(set_secret)
        .await
        .expect("set organization secret");
    client
        .set_user_secret(set_user_secret)
        .await
        .expect("set user secret");
    client
        .set_project_secret(set_project_secret)
        .await
        .expect("set project secret");
}
