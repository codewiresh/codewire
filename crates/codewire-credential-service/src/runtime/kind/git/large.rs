//! A second synthetic repository for large Git transfers (#4280): a pushed
//! pack over the 4 MiB whole-body request limit, and a clone whose pack is
//! over the 256 MiB whole-body response limit. Request and response bodies
//! stream through stock `git http-backend` with no size limit; each transfer
//! is bounded by time instead. The repository lives in its own directory,
//! not the small private tmpfs, and exists only when the Kind harness selects
//! it with `CODEWIRE_KIND_GIT_LARGE_DIR` and `CODEWIRE_KIND_GIT_LARGE_MIB`.

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::body::Bytes;
use codewire_credential_broker::BrokerUpstreamError as Error;
use futures::{Stream, StreamExt as _};
use http::{HeaderMap, Method};
use tokio_util::sync::CancellationToken;

use super::process::{Failure, command, run, run_streaming};
use super::{github_authorization_is_synthetic, single};

/// Every URL of the large repository starts with this.
pub(in crate::runtime::kind) const REPOSITORY: &str =
    "https://github.com/synthetic-user/repository-large.git/";
const DIRECTORY: &str = "repository-large.git";
/// One transfer, including a slow clone of the largest selectable repository.
const TRANSFER_LIMIT: Duration = Duration::from_secs(20 * 60);
const PREPARE_LIMIT: Duration = Duration::from_secs(5 * 60);
const BLOB_BYTES: u64 = 16 * 1024 * 1024;
const CHUNK_BYTES: u64 = 1024 * 1024;
const MAX_MEBIBYTES: u64 = 2048;
const HEADER_LIMIT: usize = 4096;

pub(in crate::runtime::kind) type Input = Pin<Box<dyn Stream<Item = Result<Bytes, Error>> + Send>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::runtime::kind) enum Operation {
    FetchAdvertisement,
    PushAdvertisement,
    UploadPack,
    ReceivePack,
}

impl Operation {
    pub(in crate::runtime::kind) fn name(self) -> &'static str {
        match self {
            Self::FetchAdvertisement => "large_fetch_advertisement",
            Self::PushAdvertisement => "large_push_advertisement",
            Self::UploadPack => "large_upload_pack",
            Self::ReceivePack => "large_receive_pack",
        }
    }

    pub(in crate::runtime::kind) fn media_type(self) -> &'static str {
        match self {
            Self::FetchAdvertisement => "application/x-git-upload-pack-advertisement",
            Self::PushAdvertisement => "application/x-git-receive-pack-advertisement",
            Self::UploadPack => "application/x-git-upload-pack-result",
            Self::ReceivePack => "application/x-git-receive-pack-result",
        }
    }

    fn request_type(self) -> Option<&'static str> {
        match self {
            Self::UploadPack => Some("application/x-git-upload-pack-request"),
            Self::ReceivePack => Some("application/x-git-receive-pack-request"),
            _ => None,
        }
    }

    fn cgi(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::FetchAdvertisement => ("GET", "/info/refs", "service=git-upload-pack"),
            Self::PushAdvertisement => ("GET", "/info/refs", "service=git-receive-pack"),
            Self::UploadPack => ("POST", "/git-upload-pack", ""),
            Self::ReceivePack => ("POST", "/git-receive-pack", ""),
        }
    }
}

/// The harness's selection: a directory outside the private tmpfs, and the
/// repository's size in MiB of incompressible blobs.
pub(in crate::runtime::kind) struct Config {
    directory: PathBuf,
    mebibytes: u64,
}

impl Config {
    pub(in crate::runtime::kind) fn from_env() -> Result<Option<Self>, Error> {
        let directory = std::env::var_os("CODEWIRE_KIND_GIT_LARGE_DIR");
        let mebibytes = std::env::var("CODEWIRE_KIND_GIT_LARGE_MIB").ok();
        match (directory, mebibytes) {
            (None, None) => Ok(None),
            (Some(directory), Some(mebibytes)) => {
                Self::new(PathBuf::from(directory), &mebibytes).map(Some)
            }
            _ => Err(Error::Protocol),
        }
    }

    pub(in crate::runtime::kind) fn new(
        directory: PathBuf,
        mebibytes: &str,
    ) -> Result<Self, Error> {
        let mebibytes = mebibytes.parse::<u64>().map_err(|_| Error::Protocol)?;
        if !directory.is_absolute() || mebibytes == 0 || mebibytes > MAX_MEBIBYTES {
            return Err(Error::Protocol);
        }
        Ok(Self {
            directory,
            mebibytes,
        })
    }
}

/// The prepared repository: its directory and fixed `main` commit.
pub(in crate::runtime::kind) struct Large {
    pub(super) root: PathBuf,
    pub(super) commit: String,
    pub(super) mebibytes: u64,
}

/// One validated request.
pub(super) struct Request {
    pub(super) operation: Operation,
    protocol: Option<&'static str>,
    encoding: Option<&'static str>,
}

pub(super) fn validate(
    method: &Method,
    target: &url::Url,
    headers: &HeaderMap,
    has_body: bool,
) -> Result<Request, Error> {
    let rest = target
        .as_str()
        .strip_prefix(REPOSITORY)
        .ok_or(Error::Protocol)?;
    let operation = match (method, rest) {
        (&Method::GET, "info/refs?service=git-upload-pack") => Operation::FetchAdvertisement,
        (&Method::GET, "info/refs?service=git-receive-pack") => Operation::PushAdvertisement,
        (&Method::POST, "git-upload-pack") => Operation::UploadPack,
        (&Method::POST, "git-receive-pack") => Operation::ReceivePack,
        _ => return Err(Error::Protocol),
    };
    if !github_authorization_is_synthetic(single(headers, "authorization")?)
        || single(headers, "user-agent")? != Some(b"Codewire-Credential-Broker")
        || single(headers, "accept-encoding")? != Some(b"identity")
        || headers.keys().any(|name| {
            !matches!(
                name.as_str(),
                "authorization"
                    | "accept"
                    | "content-type"
                    | "content-encoding"
                    | "git-protocol"
                    | "user-agent"
                    | "accept-encoding"
            )
        })
    {
        return Err(Error::Protocol);
    }
    if let Some(accept) = single(headers, "accept")?
        && accept != b"*/*"
        && accept != operation.media_type().as_bytes()
    {
        return Err(Error::Protocol);
    }
    let protocol = match single(headers, "git-protocol")? {
        None => None,
        Some(b"version=1") => Some("version=1"),
        Some(b"version=2") => Some("version=2"),
        _ => return Err(Error::Protocol),
    };
    let media = single(headers, "content-type")?;
    let encoding = match single(headers, "content-encoding")? {
        None => None,
        Some(b"identity") => Some("identity"),
        Some(b"gzip") => Some("gzip"),
        _ => return Err(Error::Protocol),
    };
    match operation.request_type() {
        None if has_body || media.is_some() || encoding.is_some() => return Err(Error::Protocol),
        Some(expected) if !has_body || media != Some(expected.as_bytes()) => {
            return Err(Error::Protocol);
        }
        _ => {}
    }
    Ok(Request {
        operation,
        protocol,
        encoding,
    })
}

/// Create the bare repository with `mebibytes` of incompressible blobs, all
/// in one fast-import pack, and return its fixed commit.
pub(super) async fn prepare(config: &Config, stop: &CancellationToken) -> Result<Large, Failure> {
    let failed = || Failure {
        error: Error::Protocol,
        drained: true,
    };
    let root = config.directory.clone();
    let repository = root.join(DIRECTORY);
    // A restarted container keeps its emptyDir; start from nothing.
    if repository.exists() {
        std::fs::remove_dir_all(&repository).map_err(|_| failed())?;
    }
    run(
        command(&root).args([
            "init",
            "--quiet",
            "--bare",
            "--template=",
            "--initial-branch=main",
            "--object-format=sha1",
            DIRECTORY,
        ]),
        &[],
        stop,
    )
    .await?;
    let total = config.mebibytes * 1024 * 1024;
    let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
    let mut import = command(&root);
    import.args([
        &format!("--git-dir={DIRECTORY}"),
        "fast-import",
        "--quiet",
        "--done",
    ]);
    let (result, ()) = tokio::join!(
        run_streaming(
            &mut import,
            Box::pin(fast_import(total)),
            sender,
            stop,
            PREPARE_LIMIT,
        ),
        async { while receiver.recv().await.is_some() {} },
    );
    result?;
    let commit = run(
        command(&root).args([
            &format!("--git-dir={DIRECTORY}"),
            "rev-parse",
            "refs/heads/main",
        ]),
        &[],
        stop,
    )
    .await?;
    let commit = String::from_utf8(commit)
        .map_err(|_| failed())?
        .trim_end()
        .to_owned();
    if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(failed());
    }
    Ok(Large {
        root,
        commit,
        mebibytes: config.mebibytes,
    })
}

/// A deterministic fast-import stream: `total` bytes of pseudo-random blobs,
/// `BLOB_BYTES` each, then one commit adding them to `main`.
fn fast_import(total: u64) -> impl Stream<Item = Result<Bytes, Error>> + Send {
    let blobs = total.div_ceil(BLOB_BYTES);
    let mut pieces = Vec::new();
    for blob in 0..blobs {
        let size = BLOB_BYTES.min(total - blob * BLOB_BYTES);
        pieces.push(Piece::Text(format!(
            "blob\nmark :{}\ndata {size}\n",
            blob + 1
        )));
        let mut offset = 0;
        while offset < size {
            let len = CHUNK_BYTES.min(size - offset);
            pieces.push(Piece::Random { blob, len });
            offset += len;
        }
        pieces.push(Piece::Text("\n".to_owned()));
    }
    let mut commit = String::from(
        "commit refs/heads/main\n\
         author Synthetic <synthetic@example.invalid> 946684800 +0000\n\
         committer Synthetic <synthetic@example.invalid> 946684800 +0000\n\
         data 16\nsynthetic large\n",
    );
    for blob in 0..blobs {
        commit.push_str(&format!("M 100644 :{} blob-{blob:04}.bin\n", blob + 1));
    }
    commit.push_str("\ndone\n");
    pieces.push(Piece::Text(commit));
    let mut state = (None::<u64>, 0_u64);
    futures::stream::iter(pieces).map(move |piece| match piece {
        Piece::Text(text) => Ok(Bytes::from(text)),
        Piece::Random { blob, len } => {
            if state.0 != Some(blob) {
                // xorshift64* seeded per blob; never zero.
                state = (Some(blob), 0x9E37_79B9_7F4A_7C15 ^ (blob + 1));
            }
            let mut bytes = Vec::with_capacity(len as usize);
            while (bytes.len() as u64) < len {
                let mut x = state.1;
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                state.1 = x;
                bytes.extend_from_slice(&x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes());
            }
            bytes.truncate(len as usize);
            Ok(Bytes::from(bytes))
        }
    })
}

enum Piece {
    Text(String),
    Random { blob: u64, len: u64 },
}

/// Byte counts for the transfer's closing diagnostic.
#[derive(Default)]
pub(super) struct Counts {
    pub(super) request: AtomicU64,
}

/// Run one request's `http-backend`, its body fed from `input` and its CGI
/// output sent to `output` as it arrives.
pub(super) async fn run_request(
    root: &Path,
    request: &Request,
    input: Input,
    counts: Arc<Counts>,
    output: tokio::sync::mpsc::Sender<Result<Bytes, Error>>,
    stop: &CancellationToken,
) -> Result<(), Failure> {
    let (method, path, query) = request.operation.cgi();
    let mut command = command(root);
    command
        .args(["-c", "http.receivepack=true", "http-backend"])
        .env("GIT_PROJECT_ROOT", root)
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("REQUEST_METHOD", method)
        .env("PATH_INFO", format!("/{DIRECTORY}{path}"))
        .env("QUERY_STRING", query);
    // No CONTENT_LENGTH: http-backend reads the streamed body to its end.
    if let Some(media) = request.operation.request_type() {
        command.env("CONTENT_TYPE", media);
    }
    if let Some(encoding) = request.encoding {
        command.env("HTTP_CONTENT_ENCODING", encoding);
    }
    if let Some(protocol) = request.protocol {
        command.env("GIT_PROTOCOL", protocol);
    }
    let input = input.inspect(move |chunk| {
        if let Ok(chunk) = chunk {
            counts
                .request
                .fetch_add(chunk.len() as u64, Ordering::Relaxed);
        }
    });
    run_streaming(&mut command, Box::pin(input), output, stop, TRANSFER_LIMIT).await
}

/// Read the CGI header from the first output chunks and return the remaining
/// body bytes already received. Only Git's own success headers are accepted.
pub(super) async fn read_header(
    operation: Operation,
    receiver: &mut tokio::sync::mpsc::Receiver<Result<Bytes, Error>>,
) -> Result<Bytes, Error> {
    let mut buffer = Vec::new();
    let boundary = loop {
        if let Some(boundary) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break boundary;
        }
        if buffer.len() > HEADER_LIMIT {
            return Err(Error::Protocol);
        }
        match receiver.recv().await {
            Some(chunk) => buffer.extend_from_slice(&chunk?),
            None => return Err(Error::Protocol),
        }
    };
    let header = std::str::from_utf8(&buffer[..boundary]).map_err(|_| Error::Protocol)?;
    let mut media = false;
    for line in header.split("\r\n") {
        let (name, value) = line.split_once(':').ok_or(Error::Protocol)?;
        match name.to_ascii_lowercase().as_str() {
            "content-type" if !media && value.trim() == operation.media_type() => media = true,
            "expires" | "pragma" | "cache-control" => {}
            _ => return Err(Error::Protocol),
        }
    }
    if !media {
        return Err(Error::Protocol);
    }
    Ok(Bytes::copy_from_slice(&buffer[boundary + 4..]))
}
