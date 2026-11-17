use super::*;
use crate::{ClientConfig, StaticTokenProvider};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const REQUEST: &str = "6a162b2b-a758-4c8c-bccb-794502c82f09";
const MUTATE: &str = "/codewire.v1.EnvironmentAgentService/MutateEnvironmentAgent";

fn scope() -> EnvironmentAgentScope {
    EnvironmentAgentScope {
        incarnation: Some(crate::cw_runtime::EnvironmentCwRuntimeIncarnation {
            org_id: "org".into(),
            environment_id: "env".into(),
            pod_uid: "original-pod".into(),
            binding_generation: u64::MAX,
            ..Default::default()
        })
        .into(),
        support_image_sha256: vec![7; 32],
        support_image_size: 123,
        ..Default::default()
    }
}
fn mutation() -> MutateEnvironmentAgentRequest {
    MutateEnvironmentAgentRequest {
        org_id: "org".into(),
        environment_id: "env".into(),
        request_id: REQUEST.into(),
        expected_scope: Some(scope()).into(),
        operation: Some(mutate_environment_agent_request::Operation::Control(
            Box::new(EnvironmentAgentControl {
                action: EnvironmentAgentAction::Stop.into(),
                session_id: "session".into(),
                driver_id: "driver".into(),
                expected_launch_generation: u64::MAX,
                ..Default::default()
            }),
        )),
        ..Default::default()
    }
}
async fn client(server: &MockServer) -> CodewireClient {
    CodewireClient::with_http(
        ClientConfig::new(server.uri()).unwrap(),
        StaticTokenProvider::new("synthetic-test-token").unwrap(),
        reqwest::Client::new(),
    )
    .unwrap()
}
fn response<M: buffa::Message>(value: &M) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("content-type", "application/proto")
        .set_body_bytes(value.encode_to_vec())
}

#[tokio::test]
async fn lost_response_keeps_original_uuid_and_observe_does_not_replay() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(MUTATE))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/proto")
                .set_body_bytes(vec![0xff]),
        )
        .expect(1)
        .mount(&server)
        .await;
    let saved = ObserveEnvironmentAgentResponse {
        operation: Some(EnvironmentAgentOperation {
            request_id: REQUEST.into(),
            scope: Some(scope()).into(),
            phase: EnvironmentAgentPhase::Unknown.into(),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };
    Mock::given(method("POST"))
        .and(path(
            "/codewire.v1.EnvironmentAgentService/ObserveEnvironmentAgent",
        ))
        .respond_with(response(&saved))
        .expect(1)
        .mount(&server)
        .await;
    let client = client(&server).await;
    let unknown = client
        .mutate_environment_agent(mutation())
        .await
        .unwrap_err();
    assert_eq!(unknown.request_id, REQUEST);
    let observed = client
        .observe_environment_agent(ObserveEnvironmentAgentRequest {
            org_id: "org".into(),
            environment_id: "env".into(),
            request_id: unknown.request_id,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(observed, saved);
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn changed_original_uuid_or_pod_is_unknown_without_retry() {
    for change_pod in [false, true] {
        let server = MockServer::start().await;
        let mut original = scope();
        if change_pod {
            original.incarnation = Some(crate::cw_runtime::EnvironmentCwRuntimeIncarnation {
                org_id: "org".into(),
                environment_id: "env".into(),
                pod_uid: "replacement-pod".into(),
                binding_generation: u64::MAX,
                ..Default::default()
            })
            .into();
        }
        let value = MutateEnvironmentAgentResponse {
            operation: Some(EnvironmentAgentOperation {
                request_id: if change_pod {
                    REQUEST
                } else {
                    "6d370dab-3d67-4d76-93c3-3bd31581fbe9"
                }
                .into(),
                scope: Some(original).into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path(MUTATE))
            .respond_with(response(&value))
            .expect(1)
            .mount(&server)
            .await;
        let error = client(&server)
            .await
            .mutate_environment_agent(mutation())
            .await
            .unwrap_err();
        assert_eq!(error.request_id, REQUEST);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn invalid_scope_uuid_and_oversized_mutation_have_no_transport_effect() {
    let server = MockServer::start().await;
    let client = client(&server).await;
    for kind in 0..3 {
        let mut request = mutation();
        match kind {
            0 => request.environment_id = "other".into(),
            1 => request.request_id = REQUEST.to_uppercase(),
            _ => {
                if let Some(mutate_environment_agent_request::Operation::Control(control)) =
                    &mut request.operation
                {
                    control.text = "x".repeat(256 * 1024);
                }
            }
        }
        assert!(client.mutate_environment_agent(request).await.is_err());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn record_scope_generation_and_digest_remain_exact_on_the_wire() {
    for mode in 0..3 {
        let server = MockServer::start().await;
        let data = b"{\"record\":1}".to_vec();
        let value = ReadEnvironmentAgentResponse {
            scope: Some(scope()).into(),
            session_id: "session".into(),
            driver_id: "driver".into(),
            launch_generation: if mode == 1 { u64::MAX - 1 } else { u64::MAX },
            kind: EnvironmentAgentRecordKind::Message.into(),
            message_id: REQUEST.into(),
            record_sha256: Sha256::digest(&data).to_vec(),
            record_json: if mode == 2 { b"changed".to_vec() } else { data },
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path(
                "/codewire.v1.EnvironmentAgentService/ReadEnvironmentAgent",
            ))
            .respond_with(response(&value))
            .expect(1)
            .mount(&server)
            .await;
        let result = client(&server)
            .await
            .read_environment_agent(ReadEnvironmentAgentRequest {
                org_id: "org".into(),
                environment_id: "env".into(),
                expected_scope: Some(scope()).into(),
                session_id: "session".into(),
                driver_id: "driver".into(),
                expected_launch_generation: u64::MAX,
                kind: EnvironmentAgentRecordKind::Message.into(),
                message_id: REQUEST.into(),
                ..Default::default()
            })
            .await;
        if mode == 0 {
            assert_eq!(result.unwrap(), value);
        } else {
            assert!(result.is_err());
        }
    }
}
