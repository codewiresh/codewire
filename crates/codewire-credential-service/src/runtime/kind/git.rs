//! One authenticated synthetic GitHub repository, backed by stock Git inside
//! the existing non-promotable Kind credential-service fixture. No HTTP client
//! or listener. Git receives only public repository data and bounded Git bytes,
//! never the request's authorization or any enrollment/KEK material.

mod process;
#[cfg(test)]
mod tests;

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use codewire_credential_broker::BrokerUpstreamError as Error;
use codewire_credential_broker::provider_enrollment::validate_private_tmpfs_runtime;
use flate2::bufread::GzDecoder;
use http::{HeaderMap, Method};
use tempfile::TempDir;
use tokio::sync::Semaphore;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use process::{IO_LIMIT, command, run};

pub(super) const REVISION: &str = "78e440926ea15ee9644a69199694e39f6f06e3ce";
const CONTENT: &[u8] = b"initial-private-checkout-synthetic-v1\n";
const WIRE_LIMIT: usize = 4 * 1024 * 1024;
const ADVERTISEMENT: &str =
    "https://github.com/synthetic-user/repository-01.git/info/refs?service=git-upload-pack";
const UPLOAD_PACK: &str = "https://github.com/synthetic-user/repository-01.git/git-upload-pack";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Operation {
    Advertisement,
    UploadPack,
}

impl Operation {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Advertisement => "advertisement",
            Self::UploadPack => "upload_pack",
        }
    }

    pub(super) fn media_type(self) -> &'static str {
        match self {
            Self::Advertisement => "application/x-git-upload-pack-advertisement",
            Self::UploadPack => "application/x-git-upload-pack-result",
        }
    }
}

struct Request {
    operation: Operation,
    protocol: Option<&'static str>,
    body: Vec<u8>,
}

fn single<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a [u8]>, Error> {
    let mut values = headers.get_all(name).iter();
    let first = values.next().map(|value| value.as_bytes());
    if values.next().is_some() {
        return Err(Error::Protocol);
    }
    Ok(first)
}

fn validate(
    method: &Method,
    target: &url::Url,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Request, Error> {
    let operation = match (method, target.as_str()) {
        (&Method::GET, ADVERTISEMENT) => Operation::Advertisement,
        (&Method::POST, UPLOAD_PACK) => Operation::UploadPack,
        _ => return Err(Error::Protocol),
    };
    let authorization = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode("x-access-token:gho_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    );
    if single(headers, "authorization")? != Some(authorization.as_bytes())
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
    let encoding = single(headers, "content-encoding")?;
    let media = single(headers, "content-type")?;
    let body = match operation {
        Operation::Advertisement => {
            if !body.is_empty() || media.is_some() || encoding.is_some() {
                return Err(Error::Protocol);
            }
            Vec::new()
        }
        Operation::UploadPack => {
            if body.is_empty() || body.len() > WIRE_LIMIT {
                return Err(Error::ResourceLimit);
            }
            if media != Some(b"application/x-git-upload-pack-request") {
                return Err(Error::Protocol);
            }
            match encoding {
                None | Some(b"identity") => {
                    if body.len() > IO_LIMIT {
                        return Err(Error::ResourceLimit);
                    }
                    body.to_vec()
                }
                Some(b"gzip") => {
                    // One gzip member only, capped both on the wire and after
                    // expansion. No compressed bytes or header reach Git.
                    let mut decoder = GzDecoder::new(body);
                    let mut bytes = Vec::new();
                    decoder
                        .by_ref()
                        .take(IO_LIMIT as u64 + 1)
                        .read_to_end(&mut bytes)
                        .map_err(|_| Error::Protocol)?;
                    if bytes.is_empty() || bytes.len() > IO_LIMIT {
                        return Err(Error::ResourceLimit);
                    }
                    if !decoder.into_inner().is_empty() {
                        return Err(Error::Protocol);
                    }
                    bytes
                }
                _ => return Err(Error::Protocol),
            }
        }
    };
    Ok(Request {
        operation,
        protocol,
        body,
    })
}

struct Lifecycle {
    directory: Option<TempDir>,
    open: bool,
}

struct TaskCustody<'a> {
    failed: &'a AtomicBool,
    completed: bool,
}

impl Drop for TaskCustody<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.failed.store(true, Ordering::Release);
        }
    }
}

pub(super) struct Fixture {
    root: PathBuf,
    lifecycle: Mutex<Lifecycle>,
    tasks: TaskTracker,
    stop: CancellationToken,
    permits: Arc<Semaphore>,
    cleanup_failed: AtomicBool,
}

impl Fixture {
    pub(super) async fn create(runtime: &Path) -> Result<Arc<Self>, Error> {
        let mut directory = tempfile::Builder::new()
            .prefix("kind-git-fixture-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(runtime)
            .map_err(|_| Error::Protocol)?;
        validate_private_tmpfs_runtime(directory.path()).map_err(|_| Error::Protocol)?;
        // Retain on unwind/cancellation. Only explicit child drain permits close.
        directory.disable_cleanup(true);
        let root = directory.path().to_owned();
        let stop = CancellationToken::new();
        let result = prepare(&root, &stop).await;
        if let Err(error) = result {
            // A failed child drain must not be mistaken for safe removal.
            // This root contains public synthetic data, stays private and is
            // intentionally retained for the owning fixture's failure cleanup.
            let _ = directory.keep();
            return Err(error.error);
        }
        Ok(Arc::new(Self {
            root,
            lifecycle: Mutex::new(Lifecycle {
                directory: Some(directory),
                open: true,
            }),
            tasks: TaskTracker::new(),
            stop,
            permits: Arc::new(Semaphore::new(2)),
            cleanup_failed: AtomicBool::new(false),
        }))
    }

    pub(super) async fn execute(
        self: &Arc<Self>,
        method: &Method,
        target: &url::Url,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<(Operation, Vec<u8>), Error> {
        let request = validate(method, target, headers, body)?;
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::ResourceLimit)?;
        let task = {
            // Admission and tracker close share one lock: shutdown cannot miss
            // a just-admitted task, even if its HTTP owner is cancelled.
            let lifecycle = self.lifecycle.lock().map_err(|_| Error::Protocol)?;
            if !lifecycle.open {
                return Err(Error::Protocol);
            }
            let fixture = self.clone();
            self.tasks.spawn(async move {
                let _permit = permit;
                // A panic must poison cleanup even when the original HTTP
                // owner dropped its JoinHandle and cannot observe JoinError.
                let mut custody = TaskCustody {
                    failed: &fixture.cleanup_failed,
                    completed: false,
                };
                let result = fixture.respond(request).await;
                custody.completed = true;
                result
            })
        };
        task.await.map_err(|_| {
            self.cleanup_failed.store(true, Ordering::Release);
            Error::Protocol
        })?
    }

    async fn respond(&self, request: Request) -> Result<(Operation, Vec<u8>), Error> {
        let mut command = command(&self.root);
        command
            .arg("http-backend")
            .env("GIT_PROJECT_ROOT", &self.root)
            .env("GIT_HTTP_EXPORT_ALL", "1")
            .env("CONTENT_LENGTH", request.body.len().to_string());
        match request.operation {
            Operation::Advertisement => {
                command
                    .env("REQUEST_METHOD", "GET")
                    .env("PATH_INFO", "/repository.git/info/refs")
                    .env("QUERY_STRING", "service=git-upload-pack");
            }
            Operation::UploadPack => {
                command
                    .env("REQUEST_METHOD", "POST")
                    .env("PATH_INFO", "/repository.git/git-upload-pack")
                    .env("QUERY_STRING", "")
                    .env("CONTENT_TYPE", "application/x-git-upload-pack-request");
            }
        }
        if let Some(protocol) = request.protocol {
            command.env("GIT_PROTOCOL", protocol);
        }
        let bytes = run(&mut command, &request.body, &self.stop)
            .await
            .map_err(|failure| {
                if !failure.drained {
                    self.cleanup_failed.store(true, Ordering::Release);
                }
                failure.error
            })?;
        Ok((request.operation, response_body(request.operation, bytes)?))
    }

    pub(super) async fn close(&self) -> Result<(), Error> {
        {
            let mut lifecycle = self.lifecycle.lock().map_err(|_| Error::Protocol)?;
            lifecycle.open = false;
            self.stop.cancel();
            self.tasks.close();
        }
        tokio::time::timeout(
            process::CHILD_LIMIT + process::DRAIN_LIMIT,
            self.tasks.wait(),
        )
        .await
        .map_err(|_| Error::ResourceLimit)?;
        if self.cleanup_failed.load(Ordering::Acquire) {
            return Err(Error::Protocol);
        }
        let directory = self
            .lifecycle
            .lock()
            .map_err(|_| Error::Protocol)?
            .directory
            .take();
        if let Some(directory) = directory {
            directory.close().map_err(|_| Error::Protocol)?;
        }
        Ok(())
    }
}

async fn prepare(root: &Path, stop: &CancellationToken) -> Result<(), process::Failure> {
    run(
        command(root).args([
            "init",
            "--quiet",
            "--template=",
            "--initial-branch=main",
            "--object-format=sha1",
            "source",
        ]),
        &[],
        stop,
    )
    .await?;
    std::fs::write(root.join("source/proof.txt"), CONTENT).map_err(|_| process::Failure {
        error: Error::Protocol,
        drained: true,
    })?;
    run(
        command(root).args(["-C", "source", "add", "proof.txt"]),
        &[],
        stop,
    )
    .await?;
    run(
        command(root).args([
            "-C",
            "source",
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "commit",
            "--quiet",
            "--no-gpg-sign",
            "-m",
            "synthetic",
        ]),
        &[],
        stop,
    )
    .await?;
    // Fixed local-only transport is enabled for preparation, never a request.
    run(
        command(root).args([
            "-c",
            "protocol.file.allow=always",
            "clone",
            "--quiet",
            "--bare",
            "--template=",
            "source",
            "repository.git",
        ]),
        &[],
        stop,
    )
    .await?;
    let revision = run(
        command(root).args(["--git-dir=repository.git", "rev-parse", "HEAD"]),
        &[],
        stop,
    )
    .await?;
    if revision != format!("{REVISION}\n").as_bytes() {
        return Err(process::Failure {
            error: Error::Protocol,
            drained: true,
        });
    }
    Ok(())
}

fn response_body(operation: Operation, bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
    let boundary = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .filter(|boundary| *boundary <= 4096)
        .ok_or(Error::Protocol)?;
    let header = std::str::from_utf8(&bytes[..boundary]).map_err(|_| Error::Protocol)?;
    let mut media = false;
    for line in header.split("\r\n") {
        let (name, value) = line.split_once(':').ok_or(Error::Protocol)?;
        match name.to_ascii_lowercase().as_str() {
            "content-type" if !media && value.trim() == operation.media_type() => media = true,
            // Git's fixed CGI cache metadata does not escape this fixture.
            "expires" | "pragma" | "cache-control" => {}
            _ => return Err(Error::Protocol),
        }
    }
    if !media || boundary + 4 == bytes.len() {
        return Err(Error::Protocol);
    }
    Ok(bytes[boundary + 4..].to_vec())
}
