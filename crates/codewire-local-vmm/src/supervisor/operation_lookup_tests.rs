use super::tests::{project_environment, test_supervisor_core, test_supervisor_service};
use super::*;

async fn get(
    service: &SupervisorRpc,
    operation_id: &str,
    request_id: &str,
) -> Result<v1::Operation, Status> {
    service
        .get_operation(Request::new(v1::GetOperationRequest {
            operation_id: operation_id.to_owned(),
            request_id: request_id.to_owned(),
        }))
        .await
        .map(Response::into_inner)
}

/// A host agent asks whether it already sent a request: the request ID
/// names the operation journaled for it, the same one its own ID names.
#[tokio::test]
async fn a_request_id_names_the_operation_journaled_for_it() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let environment_id = core.environment("dev").unwrap().id;
    let request_id = Uuid::new_v4();
    let journaled = core
        .store
        .begin_operation(
            request_id,
            Some(environment_id),
            OperationKind::Stop,
            &serde_json::json!({"name": "dev"}),
        )
        .unwrap();
    let service = test_supervisor_service(core);

    let by_request = get(&service, "", &request_id.to_string()).await.unwrap();
    let by_id = get(&service, &journaled.operation_id.to_string(), "")
        .await
        .unwrap();
    assert_eq!(by_request.operation_id, journaled.operation_id.to_string());
    assert_eq!(by_request.request_id, request_id.to_string());
    assert_eq!(by_request, by_id);
}

#[tokio::test]
async fn an_unknown_request_id_is_not_found() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let service = test_supervisor_service(core);
    let status = get(&service, "", &Uuid::new_v4().to_string())
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
}

/// Exactly one of the two names the operation; a malformed or nil request
/// ID names none.
#[tokio::test]
async fn an_operation_is_named_by_exactly_one_valid_id() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let service = test_supervisor_service(core);
    let id = Uuid::new_v4().to_string();
    for (operation_id, request_id) in [
        ("", ""),
        (id.as_str(), id.as_str()),
        ("", "not-a-uuid"),
        ("", "00000000-0000-0000-0000-000000000000"),
    ] {
        let status = get(&service, operation_id, request_id).await.unwrap_err();
        assert_eq!(
            status.code(),
            tonic::Code::InvalidArgument,
            "{operation_id:?} {request_id:?}"
        );
    }
}
