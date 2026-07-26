//! Live ingress proof for WS06 WI-6 FileService.
//!
//! Exercises the first client-streaming public RPC with a payload larger than
//! 8 MiB, then proves list/download framing, byte identity, exec-first and
//! SFTP-fallback selection, and the still-dual-served REST file renderers.

use anyhow::Context as _;
use codewire_proto::codewire::v1::{
    DownloadFileRequest, DownloadFileResponse, FileServiceClient, ListFilesRequest,
    UploadFileHeader, UploadFileRequest, download_file_response, upload_file_request,
};
use connectrpc::client::{ClientConfig, HttpClient};
use connectrpc::{CodecFormat, ErrorCode};
use reqwest::header::{CONTENT_DISPOSITION, COOKIE};
use serde::Deserialize;

const CONNECT_PATH: &str = "/workspace/connect-file-service.bin";
const JSON_PATH: &str = "/workspace/connect-file-service-json.bin";
const REST_PATH: &str = "/workspace/rest-file-service.txt";
const EXEC_PATH: &str = "/workspace/exec-file-service.txt";
const TRANSFER_SIZE: usize = 8 * 1024 * 1024 + 12_345;
const JSON_TRANSFER_SIZE: usize = 3 * 64 * 1024 + 777;
const TRANSFER_CHUNK_SIZE: usize = 64 * 1024;
const REST_PAYLOAD: &[u8] = b"REST upload through the shared FileService layer\n";
const EXEC_PAYLOAD: &[u8] = b"exec-only FileService download\n";

#[derive(Debug, Deserialize)]
struct RestFileEntry {
    name: String,
    size: i64,
    is_dir: bool,
    mode: String,
    mod_time: String,
}

#[derive(Clone, Copy)]
enum DownloadMetadata {
    Sftp,
    ExecUnavailable,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_url = required_env("SMOKE_CONNECT_BASE_URL")?;
    let direct_base_url = required_env("SMOKE_DIRECT_BASE_URL")?;
    let org_id = required_env("SMOKE_ORG_ID")?;
    let sftp_environment_id = required_env("SMOKE_SFTP_ENVIRONMENT_ID")?;
    let exec_environment_id = required_env("SMOKE_EXEC_ENVIRONMENT_ID")?;
    let session_token = required_env("SMOKE_SESSION_TOKEN")?;
    let cookie = format!("codewire.session_token={session_token}");

    let config = ClientConfig::new(base_url.parse().context("parse Connect base URL")?)
        .with_default_header(COOKIE, cookie.clone());
    let client = FileServiceClient::new(HttpClient::plaintext(), config);
    let direct_config = ClientConfig::new(
        direct_base_url
            .parse()
            .context("parse direct Connect base URL")?,
    )
    .with_default_header(COOKIE, cookie.clone());
    let direct_client = FileServiceClient::new(HttpClient::plaintext(), direct_config);
    let expected = deterministic_payload(TRANSFER_SIZE);

    upload_connect(
        &client,
        &org_id,
        &sftp_environment_id,
        CONNECT_PATH,
        &expected,
    )
    .await?;
    list_connect(
        &client,
        &org_id,
        &sftp_environment_id,
        CONNECT_PATH,
        expected.len(),
    )
    .await?;
    expect_list_error(&client, &org_id, &sftp_environment_id).await?;
    // ingress-nginx consumes X-Accel-Buffering as an upstream control header;
    // the shared edge probe measures incremental delivery through ingress.
    let downloaded = download_connect(
        &client,
        &org_id,
        &sftp_environment_id,
        CONNECT_PATH,
        DownloadMetadata::Sftp,
        false,
    )
    .await?;
    anyhow::ensure!(
        downloaded == expected,
        "Connect SFTP fallback changed file bytes"
    );

    rest_sftp_parity(
        &base_url,
        &cookie,
        &client,
        &org_id,
        &sftp_environment_id,
        &expected,
    )
    .await?;

    let exec_downloaded = download_connect(
        &client,
        &org_id,
        &exec_environment_id,
        EXEC_PATH,
        DownloadMetadata::ExecUnavailable,
        false,
    )
    .await?;
    anyhow::ensure!(
        exec_downloaded == EXEC_PAYLOAD,
        "Connect exec-first download changed file bytes"
    );
    let direct_exec_downloaded = download_connect(
        &direct_client,
        &org_id,
        &exec_environment_id,
        EXEC_PATH,
        DownloadMetadata::ExecUnavailable,
        true,
    )
    .await?;
    anyhow::ensure!(
        direct_exec_downloaded == EXEC_PAYLOAD,
        "direct Connect exec-first download changed file bytes"
    );
    expect_download_error(
        &client,
        &org_id,
        &sftp_environment_id,
        "/workspace/file-service-missing",
        ErrorCode::NotFound,
    )
    .await?;
    expect_download_error(
        &client,
        &org_id,
        &exec_environment_id,
        "/workspace/file-service-missing",
        ErrorCode::NotFound,
    )
    .await?;
    expect_download_error(
        &client,
        &org_id,
        &sftp_environment_id,
        "/workspace",
        ErrorCode::InvalidArgument,
    )
    .await?;
    expect_download_error(
        &client,
        &org_id,
        &exec_environment_id,
        "/workspace",
        ErrorCode::InvalidArgument,
    )
    .await?;
    rest_exec_parity(&base_url, &cookie, &org_id, &exec_environment_id).await?;

    // ProtoJSON is a first-class Connect codec, not a client-language
    // behavior. Exercise it against the same real SFTP and exec backends.
    let json_config = ClientConfig::new(base_url.parse().context("parse Connect base URL")?)
        .with_default_header(COOKIE, cookie.clone())
        .with_codec_format(CodecFormat::Json);
    let json_client = FileServiceClient::new(HttpClient::plaintext(), json_config);
    let direct_json_config = ClientConfig::new(
        direct_base_url
            .parse()
            .context("parse direct Connect base URL")?,
    )
    .with_default_header(COOKIE, cookie)
    .with_codec_format(CodecFormat::Json);
    let direct_json_client = FileServiceClient::new(HttpClient::plaintext(), direct_json_config);
    let json_expected = deterministic_payload(JSON_TRANSFER_SIZE);
    upload_connect(
        &json_client,
        &org_id,
        &sftp_environment_id,
        JSON_PATH,
        &json_expected,
    )
    .await?;
    list_connect(
        &json_client,
        &org_id,
        &sftp_environment_id,
        JSON_PATH,
        json_expected.len(),
    )
    .await?;
    expect_list_error(&json_client, &org_id, &sftp_environment_id).await?;
    anyhow::ensure!(
        download_connect(
            &json_client,
            &org_id,
            &sftp_environment_id,
            JSON_PATH,
            DownloadMetadata::Sftp,
            false,
        )
        .await?
            == json_expected,
        "ProtoJSON SFTP fallback changed file bytes"
    );
    anyhow::ensure!(
        download_connect(
            &json_client,
            &org_id,
            &exec_environment_id,
            EXEC_PATH,
            DownloadMetadata::ExecUnavailable,
            false,
        )
        .await?
            == EXEC_PAYLOAD,
        "ProtoJSON exec-first download changed file bytes"
    );
    anyhow::ensure!(
        download_connect(
            &direct_json_client,
            &org_id,
            &exec_environment_id,
            EXEC_PATH,
            DownloadMetadata::ExecUnavailable,
            true,
        )
        .await?
            == EXEC_PAYLOAD,
        "direct ProtoJSON exec-first download changed file bytes"
    );
    for environment_id in [&sftp_environment_id, &exec_environment_id] {
        expect_download_error(
            &json_client,
            &org_id,
            environment_id,
            "/workspace/file-service-missing",
            ErrorCode::NotFound,
        )
        .await?;
        expect_download_error(
            &json_client,
            &org_id,
            environment_id,
            "/workspace",
            ErrorCode::InvalidArgument,
        )
        .await?;
    }

    println!(
        "file-service-smoke: binary and ProtoJSON client/server streams, exec primary, SFTP fallback, and REST parity green"
    );
    Ok(())
}

async fn expect_list_error<T>(
    client: &FileServiceClient<T>,
    org_id: &str,
    environment_id: &str,
) -> anyhow::Result<()>
where
    T: connectrpc::client::ClientTransport,
    <T::ResponseBody as connectrpc::http_body::Body>::Error: std::fmt::Display,
{
    let error = client
        .list_files(ListFilesRequest {
            org_id: org_id.into(),
            environment_id: environment_id.into(),
            path: "/workspace".into(),
            page_token: "unknown-contract-token".into(),
            ..Default::default()
        })
        .await
        .expect_err("unknown ListFiles page token must fail");
    anyhow::ensure!(
        error.code == ErrorCode::InvalidArgument,
        "ListFiles page-token code = {:?}: {:?}",
        error.code,
        error.message
    );
    Ok(())
}

async fn expect_download_error<T>(
    client: &FileServiceClient<T>,
    org_id: &str,
    environment_id: &str,
    path: &str,
    expected: ErrorCode,
) -> anyhow::Result<()>
where
    T: connectrpc::client::ClientTransport,
    T::ResponseBody: Unpin,
    <T::ResponseBody as connectrpc::http_body::Body>::Error: std::fmt::Display,
{
    let mut stream = client
        .download_file(DownloadFileRequest {
            org_id: org_id.into(),
            environment_id: environment_id.into(),
            path: path.into(),
            ..Default::default()
        })
        .await?;
    let error = match stream.message::<DownloadFileResponse>().await {
        Err(error) => error,
        Ok(Some(_)) => anyhow::bail!(
            "DownloadFile({environment_id}, {path}) produced data for an invalid target"
        ),
        Ok(None) => anyhow::bail!(
            "DownloadFile({environment_id}, {path}) ended successfully for an invalid target"
        ),
    };
    anyhow::ensure!(
        error.code == expected,
        "DownloadFile({environment_id}, {path}) code = {:?}, want {:?}: {:?}",
        error.code,
        expected,
        error.message
    );
    Ok(())
}

fn deterministic_payload(size: usize) -> Vec<u8> {
    (0..size)
        .map(|index| ((index * 31 + 17) % 251) as u8)
        .collect()
}

async fn upload_connect<T>(
    client: &FileServiceClient<T>,
    org_id: &str,
    environment_id: &str,
    path: &str,
    data: &[u8],
) -> anyhow::Result<()>
where
    T: connectrpc::client::ClientTransport,
    <T::ResponseBody as connectrpc::http_body::Body>::Error: std::fmt::Display,
{
    let header = UploadFileRequest {
        payload: Some(upload_file_request::Payload::Header(Box::new(
            UploadFileHeader {
                org_id: org_id.into(),
                environment_id: environment_id.into(),
                path: path.into(),
                ..Default::default()
            },
        ))),
        ..Default::default()
    };
    let chunks = data
        .chunks(TRANSFER_CHUNK_SIZE)
        .map(|chunk| UploadFileRequest {
            payload: Some(upload_file_request::Payload::Chunk(chunk.to_vec())),
            ..Default::default()
        });
    let response = client
        .upload_file(std::iter::once(header).chain(chunks))
        .await
        .context("UploadFile through ingress")?
        .into_owned();
    anyhow::ensure!(
        response.path == path,
        "UploadFile path = {:?}",
        response.path
    );
    anyhow::ensure!(
        response.size == data.len() as i64,
        "UploadFile size = {}, want {}",
        response.size,
        data.len()
    );
    Ok(())
}

async fn list_connect<T>(
    client: &FileServiceClient<T>,
    org_id: &str,
    environment_id: &str,
    path: &str,
    size: usize,
) -> anyhow::Result<()>
where
    T: connectrpc::client::ClientTransport,
    <T::ResponseBody as connectrpc::http_body::Body>::Error: std::fmt::Display,
{
    let response = client
        .list_files(ListFilesRequest {
            org_id: org_id.into(),
            environment_id: environment_id.into(),
            path: "/workspace".into(),
            ..Default::default()
        })
        .await
        .context("ListFiles through ingress")?
        .into_owned();
    anyhow::ensure!(
        response.next_page_token.is_empty(),
        "ListFiles returned a page token"
    );
    let name = path.rsplit('/').next().context("file name")?;
    let entry = response
        .entries
        .iter()
        .find(|entry| entry.name == name)
        .context("uploaded file absent from ListFiles")?;
    anyhow::ensure!(entry.size == size as i64, "ListFiles size = {}", entry.size);
    anyhow::ensure!(
        !entry.is_dir,
        "ListFiles marked uploaded file as a directory"
    );
    anyhow::ensure!(entry.mode != 0, "ListFiles returned an empty raw mode");
    anyhow::ensure!(entry.mod_time.is_set(), "ListFiles omitted mod_time");
    Ok(())
}

async fn download_connect<T>(
    client: &FileServiceClient<T>,
    org_id: &str,
    environment_id: &str,
    path: &str,
    expected_metadata: DownloadMetadata,
    require_no_buffering_header: bool,
) -> anyhow::Result<Vec<u8>>
where
    T: connectrpc::client::ClientTransport,
    T::ResponseBody: Unpin,
    <T::ResponseBody as connectrpc::http_body::Body>::Error: std::fmt::Display,
{
    let mut stream = client
        .download_file(DownloadFileRequest {
            org_id: org_id.into(),
            environment_id: environment_id.into(),
            path: path.into(),
            ..Default::default()
        })
        .await
        .context("open DownloadFile through ingress")?;
    if require_no_buffering_header {
        anyhow::ensure!(
            stream
                .headers()
                .get("x-accel-buffering")
                .and_then(|value| value.to_str().ok())
                == Some("no"),
            "DownloadFile({environment_id}, {path}) response lacks X-Accel-Buffering: no: {:?}",
            stream.headers()
        );
    }

    let mut info_size = None;
    let mut chunks = 0_usize;
    let mut data = Vec::new();
    while let Some(message) = stream
        .message::<DownloadFileResponse>()
        .await
        .context("receive DownloadFile frame")?
    {
        match message.to_owned_message().payload {
            Some(download_file_response::Payload::Info(info)) => {
                anyhow::ensure!(
                    info_size.is_none(),
                    "DownloadFile emitted duplicate info frames"
                );
                anyhow::ensure!(chunks == 0, "DownloadFile emitted info after data");
                anyhow::ensure!(!info.is_dir, "DownloadFile info marked file as a directory");
                anyhow::ensure!(
                    info.name == path.rsplit('/').next().unwrap_or_default(),
                    "DownloadFile info name mismatch: {}",
                    info.name
                );
                match expected_metadata {
                    DownloadMetadata::Sftp => {
                        anyhow::ensure!(info.mode != 0, "DownloadFile info omitted raw mode");
                        anyhow::ensure!(
                            info.mod_time.is_set(),
                            "DownloadFile info omitted mod_time"
                        );
                    }
                    DownloadMetadata::ExecUnavailable => {
                        anyhow::ensure!(
                            info.mode == 0,
                            "exec DownloadFile invented raw mode {}",
                            info.mode
                        );
                        anyhow::ensure!(
                            !info.mod_time.is_set(),
                            "exec DownloadFile invented mod_time"
                        );
                    }
                }
                info_size = Some(info.size);
            }
            Some(download_file_response::Payload::Chunk(chunk)) => {
                anyhow::ensure!(info_size.is_some(), "DownloadFile emitted data before info");
                chunks += 1;
                data.extend_from_slice(&chunk);
            }
            None => anyhow::bail!("DownloadFile emitted an empty frame"),
        }
    }
    anyhow::ensure!(
        info_size == Some(data.len() as i64),
        "DownloadFile info size mismatch"
    );
    anyhow::ensure!(chunks > 0, "DownloadFile emitted no data chunks");
    if data.len() > TRANSFER_CHUNK_SIZE {
        anyhow::ensure!(
            chunks > 1,
            "DownloadFile buffered a multi-chunk fixture into one frame"
        );
    }
    Ok(data)
}

async fn rest_sftp_parity<T>(
    base_url: &str,
    cookie: &str,
    connect: &FileServiceClient<T>,
    org_id: &str,
    environment_id: &str,
    expected: &[u8],
) -> anyhow::Result<()>
where
    T: connectrpc::client::ClientTransport,
    T::ResponseBody: Unpin,
    <T::ResponseBody as connectrpc::http_body::Body>::Error: std::fmt::Display,
{
    let http = reqwest::Client::new();
    let prefix =
        format!("{base_url}/api/v1/organizations/{org_id}/environments/{environment_id}/files");
    let entries = http
        .get(&prefix)
        .header(COOKIE, cookie)
        .query(&[("path", "/workspace")])
        .send()
        .await
        .context("REST list files")?
        .error_for_status()
        .context("REST list files status")?
        .json::<Vec<RestFileEntry>>()
        .await
        .context("decode REST list files")?;
    let entry = entries
        .iter()
        .find(|entry| entry.name == "connect-file-service.bin")
        .context("Connect upload absent from REST list")?;
    anyhow::ensure!(
        entry.size == expected.len() as i64,
        "REST list size mismatch"
    );
    anyhow::ensure!(!entry.is_dir, "REST list marked file as directory");
    anyhow::ensure!(!entry.mode.is_empty(), "REST list omitted octal mode");
    anyhow::ensure!(!entry.mod_time.is_empty(), "REST list omitted mod_time");

    let response = http
        .get(format!("{prefix}/download"))
        .header(COOKIE, cookie)
        .query(&[("path", CONNECT_PATH)])
        .send()
        .await
        .context("REST SFTP download")?
        .error_for_status()
        .context("REST SFTP download status")?;
    anyhow::ensure!(
        response.headers().contains_key(CONTENT_DISPOSITION),
        "REST download lost Content-Disposition"
    );
    let body = response.bytes().await.context("read REST SFTP download")?;
    anyhow::ensure!(
        body.as_ref() == expected,
        "REST SFTP download changed file bytes"
    );

    let upload_response = http
        .post(format!("{prefix}/upload"))
        .header(COOKIE, cookie)
        .query(&[("path", REST_PATH)])
        .body(REST_PAYLOAD)
        .send()
        .await
        .context("REST upload")?
        .error_for_status()
        .context("REST upload status")?;
    let upload_body: serde_json::Value = upload_response
        .json()
        .await
        .context("decode REST upload response")?;
    anyhow::ensure!(
        upload_body["path"] == REST_PATH,
        "REST upload path mismatch"
    );
    anyhow::ensure!(
        upload_body["size"] == REST_PAYLOAD.len() as i64,
        "REST upload size mismatch"
    );
    let downloaded = download_connect(
        connect,
        org_id,
        environment_id,
        REST_PATH,
        DownloadMetadata::Sftp,
        false,
    )
    .await?;
    anyhow::ensure!(
        downloaded == REST_PAYLOAD,
        "Connect did not observe REST upload bytes"
    );
    Ok(())
}

async fn rest_exec_parity(
    base_url: &str,
    cookie: &str,
    org_id: &str,
    environment_id: &str,
) -> anyhow::Result<()> {
    let response = reqwest::Client::new()
        .get(format!(
            "{base_url}/api/v1/organizations/{org_id}/environments/{environment_id}/files/cat"
        ))
        .header(COOKIE, cookie)
        .query(&[("path", EXEC_PATH)])
        .send()
        .await
        .context("REST exec-cat download")?
        .error_for_status()
        .context("REST exec-cat download status")?;
    let body = response
        .bytes()
        .await
        .context("read REST exec-cat download")?;
    anyhow::ensure!(
        body.as_ref() == EXEC_PAYLOAD,
        "REST exec-cat changed file bytes"
    );
    Ok(())
}

fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}
