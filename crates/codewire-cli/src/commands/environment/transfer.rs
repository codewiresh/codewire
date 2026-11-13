//! `cw cp`'s transfers: a bounded stream each way, so a file of any size
//! moves without being held in memory (#3968), and large uploads in
//! resumable parts (#4373).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context as _, bail};
use codewire_proto::codewire::v1::{DownloadFileResponse, download_file_response};
use futures::stream::BoxStream;
use futures::{Stream, StreamExt as _};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};

/// The frame size the server's bridge already writes with, far below any
/// message limit.
pub(crate) const CHUNK_BYTES: usize = 64 * 1024;

/// Uploads the file at `source` through `send`, which gets the file's chunks
/// as they are read and returns the size the server stored. Returns the
/// bytes sent.
pub(crate) async fn upload_from_file<F, Fut>(source: &Path, send: F) -> anyhow::Result<u64>
where
    F: FnOnce(BoxStream<'static, Vec<u8>>) -> Fut,
    Fut: Future<Output = anyhow::Result<u64>>,
{
    let file = tokio::fs::File::open(source)
        .await
        .context("open local file")?;
    upload_from_reader(file, send).await
}

/// A read error drops the call, which aborts the upload so the server keeps
/// no partial file. Ending the stream instead would commit a short one.
async fn upload_from_reader<R, F, Fut>(reader: R, send: F) -> anyhow::Result<u64>
where
    R: AsyncRead + Unpin + Send + 'static,
    F: FnOnce(BoxStream<'static, Vec<u8>>) -> Fut,
    Fut: Future<Output = anyhow::Result<u64>>,
{
    let (stored, sent) = send_from_reader(reader, send).await?;
    let stored = stored?;
    if stored != sent {
        bail!("the server stored {stored} bytes of the {sent} sent");
    }
    Ok(sent)
}

/// Runs `send` on the reader's chunks, and returns its answer and the bytes
/// it was given. A read error drops the call instead of ending the stream.
async fn send_from_reader<R, F, Fut>(reader: R, send: F) -> anyhow::Result<(Fut::Output, u64)>
where
    R: AsyncRead + Unpin + Send + 'static,
    F: FnOnce(BoxStream<'static, Vec<u8>>) -> Fut,
    Fut: Future,
{
    let (failed, read_failure) = tokio::sync::oneshot::channel();
    let sent = Arc::new(AtomicU64::new(0));
    let chunks = read_chunks(reader, failed, Arc::clone(&sent)).boxed();
    let answer = tokio::select! {
        answer = send(chunks) => answer,
        Ok(error) = read_failure => {
            return Err(anyhow::Error::new(error).context("read local file"));
        }
    };
    Ok((answer, sent.load(Ordering::Relaxed)))
}

/// A part of a resumable upload is at most this big, well under the request
/// body cap of the CDN in front of the platform (#4373).
pub(crate) const PART_BYTES: u64 = 64 * 1024 * 1024;
/// A part, or the question of where to resume, is tried this many times in
/// all before the upload gives up.
const PART_ATTEMPTS: u32 = 5;
const PART_RETRY_BACKOFF: Duration = Duration::from_secs(1);

/// Why one part request did not land.
pub(crate) enum PartError {
    /// The server has no resumable uploads.
    Unsupported,
    Failed(anyhow::Error),
}

/// The server's answer to a part: the bytes it holds for the upload, and
/// whether the file is published.
pub(crate) struct PartHeld {
    pub(crate) size: u64,
    pub(crate) finished: bool,
}

#[derive(Debug)]
pub(crate) enum Resumable {
    /// The file is published.
    Uploaded,
    /// The server has no resumable uploads, and nothing was sent.
    Unsupported,
}

/// The name of one upload of `source` to `destination`. It changes when the
/// source changes, so a rerun of the same copy resumes it and a new copy of
/// an edited file starts afresh.
pub(crate) fn upload_id(
    source: &Path,
    environment_id: &str,
    destination: &str,
) -> anyhow::Result<String> {
    use sha2::Digest as _;
    let source = std::fs::canonicalize(source).context("open local file")?;
    let metadata = std::fs::metadata(&source).context("open local file")?;
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |since| since.as_nanos());
    let mut digest = sha2::Sha256::new();
    for field in [
        source.as_os_str().as_encoded_bytes(),
        &metadata.len().to_le_bytes(),
        &modified.to_le_bytes(),
        environment_id.as_bytes(),
        destination.as_bytes(),
    ] {
        digest.update(field);
        digest.update([0]);
    }
    Ok(digest.finalize()[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Uploads the file at `source` in parts through `send_part(offset, finish,
/// chunks)`, starting where the server's held bytes end, so a rerun after an
/// interruption resumes. A failed part is tried again from what the server
/// then holds.
pub(crate) async fn upload_resumable<F, Fut>(
    source: &Path,
    send_part: F,
) -> anyhow::Result<Resumable>
where
    F: FnMut(u64, bool, BoxStream<'static, Vec<u8>>) -> Fut,
    Fut: Future<Output = Result<PartHeld, PartError>>,
{
    upload_in_parts(source, PART_BYTES, send_part).await
}

async fn upload_in_parts<F, Fut>(
    source: &Path,
    part_bytes: u64,
    mut send_part: F,
) -> anyhow::Result<Resumable>
where
    F: FnMut(u64, bool, BoxStream<'static, Vec<u8>>) -> Fut,
    Fut: Future<Output = Result<PartHeld, PartError>>,
{
    let len = tokio::fs::metadata(source)
        .await
        .context("open local file")?
        .len();
    let mut attempts = 0;
    let Some(mut held) = held_by_server(&mut send_part, &mut attempts).await? else {
        return Ok(Resumable::Unsupported);
    };
    if held > len {
        bail!("the server holds {held} bytes of this {len}-byte upload; the source changed");
    }
    if held > 0 {
        eprintln!("Resuming the upload at {held} of {len} bytes");
    }
    loop {
        let part = part_bytes.min(len - held);
        let finish = held + part == len;
        let mut file = tokio::fs::File::open(source)
            .await
            .context("open local file")?;
        file.seek(std::io::SeekFrom::Start(held))
            .await
            .context("read local file")?;
        let (answer, sent) =
            send_from_reader(file.take(part), |chunks| send_part(held, finish, chunks)).await?;
        match answer {
            Ok(answer) => {
                attempts = 0;
                if sent != part || answer.size != held + part {
                    bail!(
                        "the server holds {} bytes after a part that ends at {}",
                        answer.size,
                        held + part
                    );
                }
                held = answer.size;
                if answer.finished {
                    return Ok(Resumable::Uploaded);
                }
                if finish {
                    bail!("the server did not publish the file after its last part");
                }
            }
            Err(PartError::Unsupported) => bail!("the server stopped taking upload parts"),
            Err(PartError::Failed(error)) => {
                retry_after(&mut attempts, error).await?;
                held = held_by_server(&mut send_part, &mut attempts)
                    .await?
                    .context("the server stopped taking upload parts")?;
                if held > len {
                    bail!("the server holds {held} bytes of this {len}-byte upload");
                }
            }
        }
    }
}

/// The bytes the server holds for the upload, or `None` when it has no
/// resumable uploads.
async fn held_by_server<F, Fut>(
    send_part: &mut F,
    attempts: &mut u32,
) -> anyhow::Result<Option<u64>>
where
    F: FnMut(u64, bool, BoxStream<'static, Vec<u8>>) -> Fut,
    Fut: Future<Output = Result<PartHeld, PartError>>,
{
    loop {
        match send_part(0, false, futures::stream::empty().boxed()).await {
            Ok(held) => return Ok(Some(held.size)),
            Err(PartError::Unsupported) => return Ok(None),
            Err(PartError::Failed(error)) => retry_after(attempts, error).await?,
        }
    }
}

/// Waits before another try, longer each time, or gives up with `error`.
async fn retry_after(attempts: &mut u32, error: anyhow::Error) -> anyhow::Result<()> {
    *attempts += 1;
    if *attempts >= PART_ATTEMPTS {
        return Err(error.context(format!("the upload failed {PART_ATTEMPTS} times in a row")));
    }
    tokio::time::sleep(PART_RETRY_BACKOFF * 2_u32.pow(*attempts - 1)).await;
    Ok(())
}

/// The reader's bytes in chunks of up to [`CHUNK_BYTES`]. On a read error it
/// reports the error through `failed` and then never ends.
fn read_chunks<R>(
    reader: R,
    failed: tokio::sync::oneshot::Sender<std::io::Error>,
    sent: Arc<AtomicU64>,
) -> impl Stream<Item = Vec<u8>> + Send + 'static
where
    R: AsyncRead + Unpin + Send + 'static,
{
    futures::stream::unfold(Some((reader, failed, sent)), |state| async move {
        let (mut reader, failed, sent) = state?;
        let mut chunk = vec![0; CHUNK_BYTES];
        let mut filled = 0;
        while filled < CHUNK_BYTES {
            match reader.read(&mut chunk[filled..]).await {
                Ok(0) => break,
                Ok(read) => filled += read,
                Err(error) => {
                    let _ = failed.send(error);
                    return std::future::pending().await;
                }
            }
        }
        if filled == 0 {
            return None;
        }
        chunk.truncate(filled);
        sent.fetch_add(filled as u64, Ordering::Relaxed);
        Some((chunk, Some((reader, failed, sent))))
    })
}

/// Writes a download to `destination` through a temporary file beside it,
/// renamed into place once every byte the server announced has arrived. On
/// any failure, Ctrl-C included, the temporary file is removed and the
/// destination is left as it was. Returns the bytes written.
pub(crate) async fn download_to_file<E>(
    destination: &Path,
    responses: impl Stream<Item = Result<DownloadFileResponse, E>>,
) -> anyhow::Result<u64>
where
    E: Into<anyhow::Error>,
{
    let destination = resolve_destination(destination).await?;
    let mut partial = Partial::create(&destination).await?;
    let written = tokio::select! {
        written = write_frames(&mut partial.file, responses) => written?,
        _ = tokio::signal::ctrl_c() => bail!("interrupted; {} is unchanged", destination.display()),
    };
    partial.commit(&destination).await?;
    Ok(written)
}

/// A link is followed, as `cp` does, so the file it names is replaced rather
/// than the link; a directory is refused before anything is transferred.
async fn resolve_destination(destination: &Path) -> anyhow::Result<PathBuf> {
    let destination = match tokio::fs::symlink_metadata(destination).await {
        Ok(metadata) if metadata.file_type().is_symlink() => tokio::fs::canonicalize(destination)
            .await
            .unwrap_or_else(|_| destination.to_path_buf()),
        _ => destination.to_path_buf(),
    };
    if tokio::fs::metadata(&destination)
        .await
        .is_ok_and(|metadata| metadata.is_dir())
    {
        bail!(
            "{} is a directory; name the file to write",
            destination.display()
        );
    }
    Ok(destination)
}

async fn write_frames<E>(
    file: &mut tokio::fs::File,
    responses: impl Stream<Item = Result<DownloadFileResponse, E>>,
) -> anyhow::Result<u64>
where
    E: Into<anyhow::Error>,
{
    let mut responses = std::pin::pin!(responses);
    let mut expected = None;
    let mut written = 0_u64;
    while let Some(response) = responses.next().await {
        match response.map_err(Into::into)?.payload {
            Some(download_file_response::Payload::Info(info)) if expected.is_none() => {
                if info.is_dir {
                    bail!("the remote path is a directory");
                }
                expected =
                    Some(u64::try_from(info.size).context("the server sent a negative size")?);
            }
            Some(download_file_response::Payload::Chunk(chunk)) if expected.is_some() => {
                file.write_all(&chunk).await.context("write local file")?;
                written += chunk.len() as u64;
            }
            _ => bail!("the server sent an unexpected download frame"),
        }
    }
    let expected = expected.context("the server sent no file information")?;
    if written != expected {
        bail!("received {written} of the {expected} bytes the server announced");
    }
    file.flush().await.context("write local file")?;
    file.sync_all().await.context("write local file")?;
    Ok(written)
}

/// The temporary file beside the destination, removed unless committed.
struct Partial {
    path: PathBuf,
    file: tokio::fs::File,
    committed: bool,
}

impl Partial {
    async fn create(destination: &Path) -> anyhow::Result<Self> {
        let name = destination
            .file_name()
            .with_context(|| format!("{} names no file", destination.display()))?;
        let mut partial_name = std::ffi::OsString::from(".");
        partial_name.push(name);
        partial_name.push(format!(".cw-partial-{:016x}", rand::random::<u64>()));
        let path = destination.with_file_name(partial_name);
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
            .context("create local file")?;
        // An existing destination keeps its permissions, as when it was
        // overwritten in place.
        if let Ok(metadata) = tokio::fs::metadata(destination).await {
            tokio::fs::set_permissions(&path, metadata.permissions())
                .await
                .context("create local file")?;
        }
        Ok(Self {
            path,
            file,
            committed: false,
        })
    }

    async fn commit(&mut self, destination: &Path) -> anyhow::Result<()> {
        tokio::fs::rename(&self.path, destination)
            .await
            .with_context(|| format!("move the download into {}", destination.display()))?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for Partial {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
#[path = "transfer/tests.rs"]
mod tests;
