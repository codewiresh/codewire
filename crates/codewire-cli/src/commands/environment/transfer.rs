//! `cw cp`'s transfers: a bounded stream each way, so a file of any size
//! moves without being held in memory (#3968).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context as _, bail};
use codewire_proto::codewire::v1::{DownloadFileResponse, download_file_response};
use futures::stream::BoxStream;
use futures::{Stream, StreamExt as _};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};

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
    let (failed, read_failure) = tokio::sync::oneshot::channel();
    let sent = Arc::new(AtomicU64::new(0));
    let chunks = read_chunks(reader, failed, Arc::clone(&sent)).boxed();
    let stored = tokio::select! {
        stored = send(chunks) => stored?,
        Ok(error) = read_failure => {
            return Err(anyhow::Error::new(error).context("read local file"));
        }
    };
    let sent = sent.load(Ordering::Relaxed);
    if stored != sent {
        bail!("the server stored {stored} bytes of the {sent} sent");
    }
    Ok(sent)
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
