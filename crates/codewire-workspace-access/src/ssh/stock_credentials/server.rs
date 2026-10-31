//! Test-only exact-key SSH peer; production gateway authentication is untouched.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use async_trait::async_trait;
use codewire_daemon_proto::daemon::v1;
use russh::{Channel, ChannelId, server};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::sync::oneshot;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::daemon::{
    DaemonClient, DaemonClientError, ExecDaemonSession, FileOpenOptions, FileSetStatRequest,
    PtyDaemonSession, PtyStart, SessionStart,
};

use super::{LIMIT, OwnedChild, clean_command, complete, limited, tracked};

// The pinned SFTP engine spawns internally and returns immediately. Retain an
// exact transport-drop ACK and make cancellation an EOF, then await the ACK.
// No detached SFTP transport is mistaken for an already-drained runner.
struct SftpStream<S> {
    stream: Option<S>,
    stop: Pin<Box<dyn Future<Output = ()> + Send>>,
    done: Option<oneshot::Sender<S>>,
}
impl<S: AsyncRead + Unpin> AsyncRead for SftpStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.stop.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(self.stream.as_mut().unwrap()).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for SftpStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.stop.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(self.stream.as_mut().unwrap()).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.stop.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(self.stream.as_mut().unwrap()).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(self.stream.as_mut().unwrap()).poll_shutdown(cx)
    }
}
impl<S> Drop for SftpStream<S> {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            let _ = done.send(self.stream.take().unwrap());
        }
    }
}

#[derive(Clone, Default)]
pub(super) struct Files(Arc<Mutex<HashMap<String, Vec<u8>>>>);

impl Files {
    pub(super) fn bytes(&self, path: &str) -> Vec<u8> {
        self.0.lock().unwrap().get(path).unwrap().clone()
    }
}

fn unsupported() -> DaemonClientError {
    DaemonClientError::Unsupported("bounded synthetic file operation")
}

#[async_trait]
impl DaemonClient for Files {
    async fn exec_session(&self, _: SessionStart) -> Result<ExecDaemonSession, DaemonClientError> {
        Err(unsupported())
    }
    async fn pty_session(&self, _: PtyStart) -> Result<PtyDaemonSession, DaemonClientError> {
        Err(unsupported())
    }
    async fn list(&self, _: &str) -> Result<Vec<v1::FileMetadata>, DaemonClientError> {
        Err(unsupported())
    }
    async fn stat(
        &self,
        path: &str,
        _: bool,
    ) -> Result<Option<v1::FileMetadata>, DaemonClientError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(path)
            .map(|data| v1::FileMetadata {
                name: path.rsplit('/').next().unwrap().into(),
                path: path.into(),
                size: data.len() as i64,
                mode: 0o600,
                ..Default::default()
            }))
    }
    async fn open_file(
        &self,
        path: &str,
        options: FileOpenOptions,
        _: u32,
    ) -> Result<(), DaemonClientError> {
        if !matches!(path, "/scp.bin" | "/sftp.bin") {
            return Err(unsupported());
        }
        let mut files = self.0.lock().unwrap();
        if options.create {
            files.entry(path.into()).or_default();
        }
        let file = files.get_mut(path).ok_or_else(unsupported)?;
        if options.truncate {
            file.clear();
        }
        Ok(())
    }
    async fn read_at(
        &self,
        path: &str,
        offset: i64,
        length: i64,
    ) -> Result<Vec<u8>, DaemonClientError> {
        let offset = usize::try_from(offset).map_err(|_| unsupported())?;
        let length = usize::try_from(length)
            .map_err(|_| unsupported())?
            .min(LIMIT);
        let files = self.0.lock().unwrap();
        let file = files.get(path).ok_or_else(unsupported)?;
        let start = offset.min(file.len());
        Ok(file[start..start.saturating_add(length).min(file.len())].to_vec())
    }
    async fn write_at(
        &self,
        path: &str,
        offset: i64,
        data: Vec<u8>,
    ) -> Result<i64, DaemonClientError> {
        let start = usize::try_from(offset).map_err(|_| unsupported())?;
        let end = start
            .checked_add(data.len())
            .filter(|end| *end <= LIMIT)
            .ok_or_else(unsupported)?;
        let mut files = self.0.lock().unwrap();
        let file = files.get_mut(path).ok_or_else(unsupported)?;
        file.resize(file.len().max(end), 0);
        file[start..end].copy_from_slice(&data);
        Ok(data.len() as i64)
    }
    async fn mkdir(&self, _: &str, _: u32) -> Result<(), DaemonClientError> {
        Err(unsupported())
    }
    async fn remove(&self, _: &str, _: bool) -> Result<(), DaemonClientError> {
        Err(unsupported())
    }
    async fn rename(&self, _: &str, _: &str) -> Result<(), DaemonClientError> {
        Err(unsupported())
    }
    async fn set_stat(&self, _: FileSetStatRequest) -> Result<(), DaemonClientError> {
        Ok(())
    }
    async fn readlink(&self, _: &str) -> Result<String, DaemonClientError> {
        Err(unsupported())
    }
}

pub(super) struct Peer {
    pub(super) expected: Arc<Mutex<ssh_key::PublicKey>>,
    pub(super) authenticated: Arc<std::sync::atomic::AtomicUsize>,
    pub(super) files: Files,
    pub(super) repository: std::path::PathBuf,
    pub(super) home: std::path::PathBuf,
    pub(super) stop: CancellationToken,
    pub(super) tasks: TaskTracker,
    pub(super) failed: Arc<std::sync::atomic::AtomicBool>,
    pub(super) channels: HashMap<ChannelId, Channel<server::Msg>>,
}

impl server::Handler for Peer {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        offer: server::PublicKeyOffer<'_>,
    ) -> Result<server::Auth, Self::Error> {
        Ok(
            if user == "synthetic" && *offer.public_key == *self.expected.lock().unwrap() {
                server::Auth::Accept
            } else {
                server::Auth::reject()
            },
        )
    }
    // Russh invokes this only AFTER validating the client's signature.
    async fn auth_publickey(
        &mut self,
        user: &str,
        verified: server::VerifiedPublicKey<'_>,
    ) -> Result<server::Auth, Self::Error> {
        let accepted =
            user == "synthetic" && *verified.public_key == *self.expected.lock().unwrap();
        if accepted {
            self.authenticated
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(if accepted {
            server::Auth::Accept
        } else {
            server::Auth::reject()
        })
    }
    // Trait defaults reject none, password, keyboard-interactive and certificates.
    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }
    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" {
            session.channel_failure(id)?;
            return Ok(());
        }
        let channel = self.channels.remove(&id).unwrap();
        session.channel_success(id)?;
        let files = self.files.clone();
        let stop = self.stop.clone();
        let handle = session.handle();
        tracked(&self.tasks, self.failed.clone(), async move {
            let runner = crate::sftp::DaemonSftpRunner::with_home_root(files, "/");
            let (done, completed) = oneshot::channel();
            runner
                .run(SftpStream {
                    stream: Some(channel.into_stream()),
                    stop: Box::pin(stop.clone().cancelled_owned()),
                    done: Some(done),
                })
                .await;
            let stream = complete(completed).await.unwrap();
            if !stop.is_cancelled() {
                complete(handle.exit_status_request(id, 0)).await.unwrap();
            }
            // The engine relinquished the exact channel. Publish terminal
            // status before ChannelStream's close-on-drop, as stock ssh needs.
            drop(stream);
        });
        Ok(())
    }
    async fn exec_request(
        &mut self,
        id: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let git = format!("git-upload-pack '{}'", self.repository.display());
        if data != b"synthetic-exec" && data != git.as_bytes() {
            session.channel_failure(id)?;
            return Ok(());
        }
        let channel = self.channels.remove(&id).unwrap();
        session.channel_success(id)?;
        let stop = self.stop.clone();
        let repository = self.repository.clone();
        let home = self.home.clone();
        let is_git = data == git.as_bytes();
        tracked(&self.tasks, self.failed.clone(), async move {
            if !is_git {
                channel.data(&b"selected-agent-exec\n"[..]).await.unwrap();
                channel.exit_status(7).await.unwrap();
                channel.eof().await.unwrap();
                channel.close().await.unwrap();
                return;
            }
            let mut command = clean_command("/usr/bin/git-upload-pack", &home);
            command.arg(&repository);
            let mut owned = OwnedChild::spawn(&mut command);
            let mut input = owned.child.stdin.take().unwrap();
            let mut output = owned.child.stdout.take().unwrap().take((LIMIT + 1) as u64);
            let stderr = owned.child.stderr.take().unwrap();
            let errors = tokio::spawn(limited(stderr));
            let (mut read, write) = channel.split();
            let mut reader = read.make_reader();
            let mut writer = write.make_writer();
            let result = {
                let to_git = async {
                    tokio::io::copy(&mut reader, &mut input).await?;
                    input.shutdown().await
                };
                let from_git = async {
                    let count = tokio::io::copy(&mut output, &mut writer).await?;
                    if count > LIMIT as u64 {
                        return Err(std::io::Error::other("synthetic Git output limit"));
                    }
                    owned.exited().await;
                    Ok::<_, std::io::Error>(())
                };
                tokio::pin!(to_git, from_git);
                // Git can wait for server exit before closing its SSH input.
                // Upload-pack stdout/exit, not client EOF, finishes this channel.
                let transfer = async {
                    tokio::select! {
                        result = &mut from_git => result,
                        result = &mut to_git => { result?; from_git.await },
                    }
                };
                tokio::select! {
                    biased;
                    () = stop.cancelled() => None,
                    result = tokio::time::timeout(super::COMMAND_TIMEOUT, transfer) => Some(result),
                }
            };
            drop(input);
            let status = owned.finish().await;
            assert!(complete(errors).await.unwrap().unwrap().len() < LIMIT);
            drop(writer);
            if !stop.is_cancelled() {
                assert!(matches!(result, Some(Ok(Ok(_)))));
                assert!(status.success(), "fixed upload-pack failed");
                write
                    .exit_status(status.code().unwrap() as u32)
                    .await
                    .unwrap();
                write.eof().await.unwrap();
                write.close().await.unwrap();
            }
        });
        Ok(())
    }
}
