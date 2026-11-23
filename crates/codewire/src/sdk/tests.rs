use buffa::Message as _;
use buffa_types::google::protobuf::Duration as ProtoDuration;
use wiremock::matchers::{body_bytes, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::{
    CreateEnvironmentResponse, DownloadFileResponse, FileEntry, GetEnvironmentResponse,
    StatFileResponse, UploadFileResponse,
};

const CREATE_ENVIRONMENT_PATH: &str = "/codewire.v1.EnvironmentService/CreateEnvironment";
const GET_ENVIRONMENT_PATH: &str = "/codewire.v1.EnvironmentService/GetEnvironment";
const EXEC_PATH: &str = "/codewire.v1.ExecService/Exec";
const DOWNLOAD_FILE_PATH: &str = "/codewire.v1.FileService/DownloadFile";
const UPLOAD_FILE_PATH: &str = "/codewire.v1.FileService/UploadFile";
const STAT_FILE_PATH: &str = "/codewire.v1.FileService/StatFile";

fn codewire(server: &MockServer) -> Codewire {
    Codewire::from_env_values(
        Some("test-key".into()),
        Some("org_test".into()),
        ClientConfig::new(server.uri()).expect("server URL"),
    )
    .expect("client")
}

fn unary(message: &impl buffa::Message) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("content-type", "application/proto")
        .set_body_bytes(message.encode_to_vec())
}

/// A Connect server stream: each message enveloped, then the end-of-stream frame.
fn stream<M: buffa::Message>(messages: &[M]) -> ResponseTemplate {
    let mut body = Vec::new();
    for message in messages {
        let payload = message.encode_to_vec();
        body.push(0);
        body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        body.extend_from_slice(&payload);
    }
    body.push(0x02);
    body.extend_from_slice(&2_u32.to_be_bytes());
    body.extend_from_slice(b"{}");
    ResponseTemplate::new(200)
        .insert_header("content-type", "application/connect+proto")
        .set_body_bytes(body)
}

fn environment(state: EnvironmentState) -> GetEnvironmentResponse {
    GetEnvironmentResponse {
        environment: Environment {
            id: "env_test".into(),
            org_id: "org_test".into(),
            state: state.into(),
            ..Default::default()
        }
        .into(),
        poll_interval: ProtoDuration::from(Duration::from_millis(1)).into(),
        ..Default::default()
    }
}

#[test]
fn from_env_needs_a_key_and_an_organization() {
    let config = || ClientConfig::new("https://codewire.test").expect("server URL");
    let no_key = Codewire::from_env_values(None, Some("org".into()), config())
        .err()
        .expect("no key");
    assert_eq!(no_key.code(), ErrorCode::Unauthenticated);
    assert!(
        no_key.to_string().contains(CODEWIRE_API_KEY_ENV),
        "{no_key}"
    );
    let no_org = Codewire::from_env_values(Some("key".into()), None, config())
        .err()
        .expect("no organization");
    assert_eq!(no_org.code(), ErrorCode::InvalidArgument);
    assert!(no_org.to_string().contains(CODEWIRE_ORG_ID_ENV), "{no_org}");
    let codewire =
        Codewire::from_env_values(Some("key".into()), Some("org".into()), config()).expect("ok");
    assert_eq!(codewire.org_id(), "org");
}

#[tokio::test]
async fn create_fills_the_organization_and_returns_a_handle() {
    let server = MockServer::start().await;
    let expected = CreateEnvironmentRequest {
        org_id: "org_test".into(),
        name: Some("sdk".into()),
        ..Default::default()
    };
    Mock::given(method("POST"))
        .and(path(CREATE_ENVIRONMENT_PATH))
        .and(header("authorization", "Bearer test-key"))
        .and(body_bytes(expected.encode_to_vec()))
        .respond_with(unary(&CreateEnvironmentResponse {
            environment: Environment {
                id: "env_test".into(),
                org_id: "org_test".into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        }))
        .expect(1)
        .mount(&server)
        .await;

    let handle = codewire(&server)
        .create_environment(CreateEnvironmentRequest {
            name: Some("sdk".into()),
            ..Default::default()
        })
        .await
        .expect("create");
    assert_eq!(handle.id(), "env_test");
}

#[tokio::test]
async fn wait_ready_polls_until_running() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(GET_ENVIRONMENT_PATH))
        .respond_with(unary(&environment(EnvironmentState::Starting)))
        .up_to_n_times(2)
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(GET_ENVIRONMENT_PATH))
        .respond_with(unary(&environment(EnvironmentState::Running)))
        .expect(1)
        .mount(&server)
        .await;

    let mut handle = codewire(&server)
        .environment("env_test")
        .await
        .expect("get");
    let ready = handle.wait_ready().await.expect("ready");
    assert_eq!(ready.state.as_known(), Some(EnvironmentState::Running));
}

#[tokio::test]
async fn wait_ready_stops_at_a_failed_environment_with_its_reason() {
    let server = MockServer::start().await;
    let mut failed = environment(EnvironmentState::Error);
    if let Some(environment) = failed.environment.as_option_mut() {
        environment.error_reason = "no capacity in the region".into();
    }
    Mock::given(method("POST"))
        .and(path(GET_ENVIRONMENT_PATH))
        .respond_with(unary(&failed))
        .mount(&server)
        .await;

    let mut handle = codewire(&server)
        .environment("env_test")
        .await
        .expect("get");
    let error = handle.wait_ready().await.expect_err("failed");
    assert_eq!(error.code(), ErrorCode::FailedPrecondition);
    assert!(
        error.to_string().contains("no capacity in the region"),
        "{error}"
    );
}

#[tokio::test]
async fn exec_fills_both_ids() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(GET_ENVIRONMENT_PATH))
        .respond_with(unary(&environment(EnvironmentState::Running)))
        .mount(&server)
        .await;
    let expected = ExecRequest {
        org_id: "org_test".into(),
        environment_id: "env_test".into(),
        command: vec!["uname".into(), "-a".into()],
        ..Default::default()
    };
    Mock::given(method("POST"))
        .and(path(EXEC_PATH))
        .and(body_bytes(expected.encode_to_vec()))
        .respond_with(unary(&ExecResponse {
            stdout: b"Linux\n".to_vec(),
            ..Default::default()
        }))
        .expect(1)
        .mount(&server)
        .await;

    let handle = codewire(&server)
        .environment("env_test")
        .await
        .expect("get");
    let output = handle
        .exec(ExecRequest {
            command: vec!["uname".into(), "-a".into()],
            ..Default::default()
        })
        .await
        .expect("exec");
    assert_eq!(output.stdout, b"Linux\n");
}

fn info(size: i64) -> DownloadFileResponse {
    DownloadFileResponse {
        payload: Some(download_file_response::Payload::Info(Box::new(FileEntry {
            size,
            ..Default::default()
        }))),
        ..Default::default()
    }
}

fn chunk(data: &[u8]) -> DownloadFileResponse {
    DownloadFileResponse {
        payload: Some(download_file_response::Payload::Chunk(data.to_vec())),
        ..Default::default()
    }
}

/// Serves `frames` as the download of /workspace/greeting.txt, and returns
/// the result of downloading it.
async fn download(frames: &[DownloadFileResponse]) -> Result<Vec<u8>, ClientError> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(GET_ENVIRONMENT_PATH))
        .respond_with(unary(&environment(EnvironmentState::Running)))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(DOWNLOAD_FILE_PATH))
        .respond_with(stream(frames))
        .expect(1)
        .mount(&server)
        .await;
    let handle = codewire(&server)
        .environment("env_test")
        .await
        .expect("get");
    handle.download("/workspace/greeting.txt").await
}

#[tokio::test]
async fn download_joins_the_chunks_after_the_file_info() {
    let contents = download(&[info(12), chunk(b"hello, "), chunk(b"world")])
        .await
        .expect("download");
    assert_eq!(contents, b"hello, world");
}

#[tokio::test]
async fn a_download_shorter_than_its_size_is_data_loss() {
    let error = download(&[info(20), chunk(b"hello, "), chunk(b"world")])
        .await
        .expect_err("short");
    assert_eq!(error.code(), ErrorCode::DataLoss);
    assert!(error.to_string().contains("12 of 20 bytes"), "{error}");
}

#[tokio::test]
async fn a_download_longer_than_its_size_is_data_loss() {
    let error = download(&[info(5), chunk(b"hello, "), chunk(b"world")])
        .await
        .expect_err("long");
    assert_eq!(error.code(), ErrorCode::DataLoss);
    assert!(
        error.to_string().contains("more than the 5 bytes"),
        "{error}"
    );
}

#[tokio::test]
async fn a_download_without_file_information_is_refused() {
    let error = download(&[chunk(b"hello")]).await.expect_err("no info");
    assert_eq!(error.code(), ErrorCode::Internal);
    let error = download(&[]).await.expect_err("empty");
    assert_eq!(error.code(), ErrorCode::Internal);
}

/// The messages in a Connect stream body, after its envelopes.
fn frames(mut body: &[u8]) -> Vec<UploadFileRequest> {
    let mut messages = Vec::new();
    while body.len() >= 5 {
        let length = u32::from_be_bytes(body[1..5].try_into().expect("length")) as usize;
        let (frame, rest) = body[5..].split_at(length);
        if body[0] & 0x02 == 0 {
            messages.push(UploadFileRequest::decode(&mut &frame[..]).expect("upload frame"));
        }
        body = rest;
    }
    messages
}

#[tokio::test]
async fn upload_sends_the_header_then_the_contents_in_chunks() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(GET_ENVIRONMENT_PATH))
        .respond_with(unary(&environment(EnvironmentState::Running)))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(UPLOAD_FILE_PATH))
        .respond_with(stream(&[UploadFileResponse::default()]))
        .expect(1)
        .mount(&server)
        .await;

    let contents: Vec<u8> = (0..UPLOAD_CHUNK + 10).map(|byte| byte as u8).collect();
    let handle = codewire(&server)
        .environment("env_test")
        .await
        .expect("get");
    handle
        .upload("/workspace/data.bin", contents.clone())
        .await
        .expect("upload");

    let requests = server.received_requests().await.expect("recorded");
    let upload = requests
        .iter()
        .find(|request| request.url.path() == UPLOAD_FILE_PATH)
        .expect("upload request");
    let sent = frames(&upload.body);
    let Some(upload_file_request::Payload::Header(header)) = &sent[0].payload else {
        panic!("the first frame is not the header: {:?}", sent[0]);
    };
    assert_eq!(
        (
            header.org_id.as_str(),
            header.environment_id.as_str(),
            header.path.as_str()
        ),
        ("org_test", "env_test", "/workspace/data.bin")
    );
    let chunks: Vec<&[u8]> = sent[1..]
        .iter()
        .map(|frame| match &frame.payload {
            Some(upload_file_request::Payload::Chunk(chunk)) => chunk.as_slice(),
            other => panic!("not a chunk: {other:?}"),
        })
        .collect();
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].len(), UPLOAD_CHUNK);
    assert_eq!(chunks.concat(), contents);
}

/// A Connect unary error as the platform renders it.
fn connect_error(error: connectrpc::ConnectError) -> ResponseTemplate {
    ResponseTemplate::new(error.http_status().as_u16())
        .insert_header("content-type", "application/json")
        .set_body_bytes(error.to_json())
}

/// A `not_found` whose ErrorInfo names `reason`, or with no ErrorInfo.
fn not_found_with_reason(message: &str, reason: Option<&str>) -> connectrpc::ConnectError {
    let error = connectrpc::ConnectError::not_found(message);
    match reason {
        Some(reason) => error.with_detail(connectrpc::ErrorDetail::from_message(
            "google.rpc.ErrorInfo",
            &codewire_proto::google::rpc::ErrorInfo {
                reason: reason.into(),
                ..Default::default()
            },
        )),
        None => error,
    }
}

/// Answers StatFile for env_test in org_test: `/workspace/f.txt` is a
/// 5-byte file, `/workspace/missing` is a missing file, `no-org` and
/// `other-reason` are not found for another cause, anything else is refused.
async fn stat_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(GET_ENVIRONMENT_PATH))
        .respond_with(unary(&environment(EnvironmentState::Running)))
        .mount(&server)
        .await;
    let request = |file: &str| StatFileRequest {
        org_id: "org_test".into(),
        environment_id: "env_test".into(),
        path: file.into(),
        ..Default::default()
    };
    Mock::given(method("POST"))
        .and(path(STAT_FILE_PATH))
        .and(body_bytes(request("/workspace/f.txt").encode_to_vec()))
        .respond_with(unary(&StatFileResponse {
            entry: FileEntry {
                name: "f.txt".into(),
                size: 5,
                mode: 0o100644,
                ..Default::default()
            }
            .into(),
            ..Default::default()
        }))
        .mount(&server)
        .await;
    for (file, error) in [
        (
            "/workspace/missing",
            not_found_with_reason("file not found", Some("FILE_NOT_FOUND")),
        ),
        (
            "/workspace/no-org",
            not_found_with_reason("organization not found", None),
        ),
        (
            "/workspace/other-reason",
            not_found_with_reason("environment not found", Some("ENVIRONMENT_NOT_FOUND")),
        ),
    ] {
        Mock::given(method("POST"))
            .and(path(STAT_FILE_PATH))
            .and(body_bytes(request(file).encode_to_vec()))
            .respond_with(connect_error(error))
            .mount(&server)
            .await;
    }
    Mock::given(method("POST"))
        .and(path(STAT_FILE_PATH))
        .respond_with(connect_error(connectrpc::ConnectError::invalid_argument(
            "file path is invalid or denied",
        )))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn stat_file_fills_both_ids_and_returns_the_entry() {
    let server = stat_server().await;
    let handle = codewire(&server)
        .environment("env_test")
        .await
        .expect("get");
    let entry = handle.stat_file("/workspace/f.txt").await.expect("stat");
    assert_eq!(
        (entry.name.as_str(), entry.size, entry.mode),
        ("f.txt", 5, 0o100644)
    );
    let missing = handle
        .stat_file("/workspace/missing")
        .await
        .expect_err("missing");
    assert_eq!(missing.code(), ErrorCode::NotFound);
    assert_eq!(missing.reason(), Some("FILE_NOT_FOUND"));
}

#[tokio::test]
async fn file_exists_is_false_only_for_a_missing_file() {
    let server = stat_server().await;
    let handle = codewire(&server)
        .environment("env_test")
        .await
        .expect("get");
    assert!(
        handle
            .file_exists("/workspace/f.txt")
            .await
            .expect("exists")
    );
    assert!(
        !handle
            .file_exists("/workspace/missing")
            .await
            .expect("missing")
    );
    for (file, code) in [
        ("/etc/passwd", ErrorCode::InvalidArgument),
        ("/workspace/no-org", ErrorCode::NotFound),
        ("/workspace/other-reason", ErrorCode::NotFound),
    ] {
        let refused = handle
            .file_exists(file)
            .await
            .expect_err("only a missing file is false");
        assert_eq!(refused.code(), code, "{file}");
    }
}
