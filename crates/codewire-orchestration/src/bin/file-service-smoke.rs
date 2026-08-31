//! Live ingress proof for WS06 WI-6 FileService.
//!
//! Exercises the first client-streaming public RPC with a payload larger than
//! 8 MiB, then proves daemon-native list/download framing, metadata, and byte
//! identity through both Connect codecs and both ingress paths.

use anyhow::Context as _;
use codewire_proto::codewire::v1::{
    DownloadFileRequest, DownloadFileResponse, FileServiceClient, ListFilesRequest,
    UploadFileHeader, UploadFileRequest, download_file_response, upload_file_request,
};
use connectrpc::client::{ClientConfig, HttpClient};
use connectrpc::{CodecFormat, ErrorCode};
use reqwest::header::COOKIE;

const CONNECT_PATH: &str = "/workspace/connect-file-service.bin";
const JSON_PATH: &str = "/workspace/connect-file-service-json/nested.bin";
const TRANSFER_SIZE: usize = 8 * 1024 * 1024 + 12_345;
const JSON_TRANSFER_SIZE: usize = 3 * 64 * 1024 + 777;
const TRANSFER_CHUNK_SIZE: usize = 64 * 1024;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_url = required_env("SMOKE_CONNECT_BASE_URL")?;
    let direct_base_url = required_env("SMOKE_DIRECT_BASE_URL")?;
    let org_id = required_env("SMOKE_ORG_ID")?;
    let environment_id = required_env("SMOKE_ENVIRONMENT_ID")?;
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

    upload_connect(&client, &org_id, &environment_id, CONNECT_PATH, &expected).await?;
    list_connect(
        &client,
        &org_id,
        &environment_id,
        CONNECT_PATH,
        expected.len(),
    )
    .await?;
    expect_list_error(&client, &org_id, &environment_id).await?;
    // ingress-nginx consumes X-Accel-Buffering as an upstream control header;
    // the shared edge probe measures incremental delivery through ingress.
    let downloaded =
        download_connect(&client, &org_id, &environment_id, CONNECT_PATH, false).await?;
    anyhow::ensure!(
        downloaded == expected,
        "Connect daemon download changed file bytes"
    );
    let direct_downloaded =
        download_connect(&direct_client, &org_id, &environment_id, CONNECT_PATH, true).await?;
    anyhow::ensure!(
        direct_downloaded == expected,
        "direct Connect daemon download changed file bytes"
    );
    expect_download_error(
        &client,
        &org_id,
        &environment_id,
        "/workspace/file-service-missing",
        ErrorCode::NotFound,
    )
    .await?;
    expect_download_error(
        &client,
        &org_id,
        &environment_id,
        "/workspace",
        ErrorCode::InvalidArgument,
    )
    .await?;
    // ProtoJSON is a first-class Connect codec, not a client-language
    // behavior. Exercise it against the same daemon-native backend.
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
        &environment_id,
        JSON_PATH,
        &json_expected,
    )
    .await?;
    list_connect(
        &json_client,
        &org_id,
        &environment_id,
        JSON_PATH,
        json_expected.len(),
    )
    .await?;
    expect_list_error(&json_client, &org_id, &environment_id).await?;
    anyhow::ensure!(
        download_connect(&json_client, &org_id, &environment_id, JSON_PATH, false).await?
            == json_expected,
        "ProtoJSON daemon download changed file bytes"
    );
    anyhow::ensure!(
        download_connect(
            &direct_json_client,
            &org_id,
            &environment_id,
            JSON_PATH,
            true,
        )
        .await?
            == json_expected,
        "direct ProtoJSON daemon download changed file bytes"
    );
    expect_download_error(
        &json_client,
        &org_id,
        &environment_id,
        "/workspace/file-service-missing",
        ErrorCode::NotFound,
    )
    .await?;
    expect_download_error(
        &json_client,
        &org_id,
        &environment_id,
        "/workspace",
        ErrorCode::InvalidArgument,
    )
    .await?;

    println!("file-service-smoke: daemon-native binary and ProtoJSON client/server streams green");
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
            path: path
                .rsplit_once('/')
                .map(|(parent, _)| parent)
                .filter(|parent| !parent.is_empty())
                .unwrap_or("/workspace")
                .into(),
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
                anyhow::ensure!(info.mode != 0, "DownloadFile info omitted raw mode");
                anyhow::ensure!(info.mod_time.is_set(), "DownloadFile info omitted mod_time");
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

fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}
