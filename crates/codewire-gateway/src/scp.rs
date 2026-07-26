use async_trait::async_trait;
use codewire_gateway_proto::daemon::v1;
use russh::Channel;
use russh::server;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::daemon::{DaemonClient, DaemonClientError, FileOpenOptions, FileSetStatRequest};

const CHUNK_SIZE: i64 = 32 * 1024;
const MODE_DIR: u32 = 1 << 31;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScpCommand {
    source: bool,
    sink: bool,
    recursive: bool,
    preserve_time: bool,
    target_is_dir: bool,
    target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScpTimes {
    access_time: prost_types::Timestamp,
    mod_time: prost_types::Timestamp,
}

#[derive(Debug, thiserror::Error)]
pub enum ScpError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("daemon: {0}")]
    Daemon(#[from] DaemonClientError),
    #[error("{0}")]
    Protocol(String),
    #[error("ssh: {0}")]
    Ssh(#[from] russh::Error),
}

#[derive(Clone)]
pub struct DaemonScpRunner<C> {
    client: C,
}

impl<C> DaemonScpRunner<C> {
    pub fn new(client: C) -> Self {
        Self { client }
    }
}

impl<C> DaemonScpRunner<C>
where
    C: DaemonClient + Clone + Send + Sync + 'static,
{
    pub async fn run_channel(
        &self,
        command: Vec<String>,
        channel: Channel<server::Msg>,
    ) -> Result<(), ScpError> {
        let (mut read_half, write_half) = channel.split();
        let mut reader = BufReader::new(read_half.make_reader());
        let mut writer = write_half.make_writer();
        let exit_code = self.run_with_io(command, &mut reader, &mut writer).await?;
        writer.flush().await?;
        drop(writer);
        write_half.exit_status(exit_code).await?;
        write_half.eof().await?;
        write_half.close().await?;
        Ok(())
    }

    async fn run_with_io<R, W>(
        &self,
        command: Vec<String>,
        reader: &mut BufReader<R>,
        writer: &mut W,
    ) -> Result<u32, ScpError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let cmd = match parse_scp_command(&command) {
            Ok(Some(cmd)) => cmd,
            Ok(None) => {
                write_scp_message(writer, 2, "not an scp command").await?;
                return Ok(1);
            }
            Err(err) => {
                write_scp_message(writer, 2, &err.to_string()).await?;
                return Ok(1);
            }
        };

        let result = if cmd.sink {
            self.handle_sink(reader, writer, cmd).await
        } else if cmd.source {
            self.handle_source(reader, writer, cmd).await
        } else {
            Err(ScpError::Protocol("unsupported scp mode".into()))
        };

        match result {
            Ok(()) => Ok(0),
            Err(err) => {
                write_scp_message(writer, 2, &err.to_string()).await?;
                Ok(1)
            }
        }
    }

    async fn handle_sink<R, W>(
        &self,
        reader: &mut BufReader<R>,
        writer: &mut W,
        cmd: ScpCommand,
    ) -> Result<(), ScpError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        write_scp_ack(writer).await?;

        let root_info = self.client.stat(&cmd.target, false).await?;
        let root_is_dir = root_info
            .as_ref()
            .map(|entry| file_mode_is_dir(entry.mode))
            .unwrap_or(false);

        #[derive(Debug)]
        struct DirFrame {
            path: String,
            times: Option<ScpTimes>,
        }

        let mut stack: Vec<DirFrame> = Vec::new();
        let mut pending_times: Option<ScpTimes> = None;
        let mut root_consumed = false;

        loop {
            let mut line = String::new();
            let read = reader.read_line(&mut line).await?;
            if read == 0 {
                if stack.is_empty() {
                    return Ok(());
                }
                return Err(ScpError::Protocol(
                    "unexpected EOF in directory upload".into(),
                ));
            }
            let line = line.trim_end_matches('\n');
            if line.is_empty() {
                continue;
            }

            match line.as_bytes()[0] {
                b'T' => {
                    pending_times = Some(parse_scp_times(line)?);
                    write_scp_ack(writer).await?;
                }
                b'D' => {
                    if !cmd.recursive {
                        return Err(ScpError::Protocol(
                            "recursive scp upload is not enabled".into(),
                        ));
                    }
                    let (mode, _, name) = parse_scp_file_header(line)?;
                    let target_path = resolve_sink_path(
                        &cmd,
                        stack.last().map(|frame| frame.path.as_str()),
                        &mut root_consumed,
                        root_is_dir,
                        &name,
                    )?;
                    self.ensure_remote_dir(&target_path, mode).await?;
                    stack.push(DirFrame {
                        path: target_path,
                        times: pending_times.take(),
                    });
                    write_scp_ack(writer).await?;
                }
                b'C' => {
                    let (mode, size, name) = parse_scp_file_header(line)?;
                    let target_path = resolve_sink_path(
                        &cmd,
                        stack.last().map(|frame| frame.path.as_str()),
                        &mut root_consumed,
                        root_is_dir,
                        &name,
                    )?;
                    write_scp_ack(writer).await?;
                    self.copy_sink_file(reader, &target_path, size, mode)
                        .await?;
                    if let Some(times) = pending_times.take() {
                        self.client
                            .set_stat(FileSetStatRequest {
                                path: target_path,
                                size: None,
                                mode: None,
                                access_time: Some(times.access_time),
                                mod_time: Some(times.mod_time),
                            })
                            .await?;
                    }
                    write_scp_ack(writer).await?;
                }
                b'E' => {
                    let Some(frame) = stack.pop() else {
                        return Err(ScpError::Protocol("unexpected directory terminator".into()));
                    };
                    if let Some(times) = frame.times {
                        self.client
                            .set_stat(FileSetStatRequest {
                                path: frame.path,
                                size: None,
                                mode: None,
                                access_time: Some(times.access_time),
                                mod_time: Some(times.mod_time),
                            })
                            .await?;
                    }
                    write_scp_ack(writer).await?;
                }
                _ => {
                    return Err(ScpError::Protocol(format!(
                        "unsupported scp command: {line:?}"
                    )));
                }
            }
        }
    }

    async fn handle_source<R, W>(
        &self,
        reader: &mut BufReader<R>,
        writer: &mut W,
        cmd: ScpCommand,
    ) -> Result<(), ScpError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        read_scp_ack(reader).await?;
        let entry =
            self.client.stat(&cmd.target, false).await?.ok_or_else(|| {
                ScpError::Protocol(format!("scp source not found: {}", cmd.target))
            })?;
        if file_mode_is_dir(entry.mode) && !cmd.recursive {
            return Err(ScpError::Protocol(
                "scp source is a directory; use -r".into(),
            ));
        }
        self.send_entry(reader, writer, &cmd.target, entry, &cmd)
            .await
    }

    async fn send_entry<R, W>(
        &self,
        reader: &mut BufReader<R>,
        writer: &mut W,
        full_path: &str,
        entry: v1::FileMetadata,
        cmd: &ScpCommand,
    ) -> Result<(), ScpError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut stack = vec![(full_path.to_string(), entry, false)];
        while let Some((path, entry, closing)) = stack.pop() {
            if closing {
                writer.write_all(b"E\n").await?;
                read_scp_ack(reader).await?;
                continue;
            }

            let mode = entry.mode & 0o777;
            let mut name = base_name(&path);
            if name == "." || name == "/" {
                name = base_name(&entry.path);
            }

            if cmd.preserve_time {
                let seconds = entry.mod_time.as_ref().map(|ts| ts.seconds).unwrap_or(0);
                writer
                    .write_all(format!("T{seconds} 0 {seconds} 0\n").as_bytes())
                    .await?;
                read_scp_ack(reader).await?;
            }

            if file_mode_is_dir(entry.mode) {
                writer
                    .write_all(format!("D{mode:04o} 0 {name}\n").as_bytes())
                    .await?;
                read_scp_ack(reader).await?;

                let mut children = self.client.list(&path).await?;
                children.sort_by(|a, b| a.name.cmp(&b.name));
                stack.push((path.clone(), entry, true));
                for child in children.into_iter().rev() {
                    let child_path = join_path(&path, &child.name);
                    stack.push((child_path, child, false));
                }
                continue;
            }

            writer
                .write_all(format!("C{mode:04o} {} {name}\n", entry.size).as_bytes())
                .await?;
            read_scp_ack(reader).await?;

            let mut offset = 0;
            while offset < entry.size {
                let remaining = entry.size - offset;
                let length = remaining.min(CHUNK_SIZE);
                let data = self.client.read_at(&path, offset, length).await?;
                if data.is_empty() {
                    return Err(ScpError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "empty daemon read during scp source",
                    )));
                }
                writer.write_all(&data).await?;
                offset += data.len() as i64;
            }

            write_scp_ack(writer).await?;
            read_scp_ack(reader).await?;
        }
        Ok(())
    }

    async fn copy_sink_file<R>(
        &self,
        reader: &mut BufReader<R>,
        target_path: &str,
        size: i64,
        mode: u32,
    ) -> Result<(), ScpError>
    where
        R: AsyncRead + Unpin,
    {
        self.client
            .open_file(
                target_path,
                FileOpenOptions {
                    read: false,
                    write: true,
                    append: false,
                    create: true,
                    truncate: true,
                    exclusive: false,
                },
                mode,
            )
            .await?;

        let mut offset = 0;
        let mut buf = vec![0u8; CHUNK_SIZE as usize];
        while offset < size {
            let want = (size - offset).min(CHUNK_SIZE) as usize;
            reader.read_exact(&mut buf[..want]).await?;
            self.client
                .write_at(target_path, offset, buf[..want].to_vec())
                .await?;
            offset += want as i64;
        }

        let mut ack = [0u8; 1];
        reader.read_exact(&mut ack).await?;
        if ack[0] != 0 {
            return Err(ScpError::Protocol(
                "scp upload did not terminate cleanly".into(),
            ));
        }
        Ok(())
    }

    async fn ensure_remote_dir(&self, target_path: &str, mode: u32) -> Result<(), ScpError> {
        if let Some(entry) = self.client.stat(target_path, false).await? {
            if file_mode_is_dir(entry.mode) {
                return Ok(());
            }
            return Err(ScpError::Protocol(format!(
                "target exists and is not a directory: {target_path}"
            )));
        }
        self.client.mkdir(target_path, mode).await?;
        Ok(())
    }
}

#[async_trait]
pub trait ScpProtocolRunner: Send + Sync + 'static {
    async fn start_scp(
        &self,
        command: Vec<String>,
        channel: Channel<server::Msg>,
    ) -> Result<(), ScpError>;
}

#[async_trait]
impl<C> ScpProtocolRunner for DaemonScpRunner<C>
where
    C: DaemonClient + Clone + Send + Sync + 'static,
{
    async fn start_scp(
        &self,
        command: Vec<String>,
        channel: Channel<server::Msg>,
    ) -> Result<(), ScpError> {
        self.run_channel(command, channel).await
    }
}

pub fn is_scp_command(command: &[String]) -> bool {
    command.first().map(String::as_str) == Some("scp")
}

pub fn parse_scp_command(args: &[String]) -> Result<Option<ScpCommand>, ScpError> {
    if !is_scp_command(args) {
        return Ok(None);
    }

    let mut cmd = ScpCommand {
        source: false,
        sink: false,
        recursive: false,
        preserve_time: false,
        target_is_dir: false,
        target: String::new(),
    };

    for arg in &args[1..] {
        if arg.is_empty() {
            continue;
        }
        if !arg.starts_with('-') {
            cmd.target = arg.clone();
            continue;
        }
        for flag in arg[1..].chars() {
            match flag {
                'f' => cmd.source = true,
                't' => cmd.sink = true,
                'r' => cmd.recursive = true,
                'p' => cmd.preserve_time = true,
                'd' => cmd.target_is_dir = true,
                'q' | 'v' | 'O' | 'B' => {}
                _ => {
                    return Err(ScpError::Protocol(format!("unsupported scp flag: -{flag}")));
                }
            }
        }
    }

    if cmd.target.is_empty() {
        return Err(ScpError::Protocol("missing scp target".into()));
    }
    if cmd.source == cmd.sink {
        return Err(ScpError::Protocol("invalid scp mode".into()));
    }
    Ok(Some(cmd))
}

fn resolve_sink_path(
    cmd: &ScpCommand,
    current_dir: Option<&str>,
    root_consumed: &mut bool,
    root_is_dir: bool,
    name: &str,
) -> Result<String, ScpError> {
    if let Some(parent) = current_dir {
        return Ok(join_path(parent, name));
    }
    if cmd.target_is_dir || root_is_dir {
        return Ok(join_path(&cmd.target, name));
    }
    if *root_consumed {
        return Err(ScpError::Protocol(
            "scp target expects a single item".into(),
        ));
    }
    *root_consumed = true;
    Ok(cmd.target.clone())
}

fn parse_scp_file_header(line: &str) -> Result<(u32, i64, String), ScpError> {
    if line.len() < 2 {
        return Err(ScpError::Protocol("invalid scp header".into()));
    }
    let mut parts = line[1..].splitn(3, ' ');
    let mode_text = parts
        .next()
        .ok_or_else(|| ScpError::Protocol(format!("invalid scp header: {line:?}")))?;
    let mode =
        u32::from_str_radix(mode_text, 8).map_err(|err| ScpError::Protocol(err.to_string()))?;
    let size = parts
        .next()
        .ok_or_else(|| ScpError::Protocol(format!("invalid scp header: {line:?}")))?
        .parse::<i64>()
        .map_err(|err| ScpError::Protocol(err.to_string()))?;
    let name = parts
        .next()
        .ok_or_else(|| ScpError::Protocol(format!("invalid scp header: {line:?}")))?
        .to_string();
    Ok((mode, size, name))
}

fn parse_scp_times(line: &str) -> Result<ScpTimes, ScpError> {
    let parts = line[1..].split(' ').collect::<Vec<_>>();
    if parts.len() != 4 {
        return Err(ScpError::Protocol(format!(
            "invalid scp time header: {line:?}"
        )));
    }
    let mtime = parts[0]
        .parse::<i64>()
        .map_err(|err| ScpError::Protocol(err.to_string()))?;
    let atime = parts[2]
        .parse::<i64>()
        .map_err(|err| ScpError::Protocol(err.to_string()))?;
    Ok(ScpTimes {
        access_time: timestamp(atime),
        mod_time: timestamp(mtime),
    })
}

async fn read_scp_ack<R>(reader: &mut BufReader<R>) -> Result<(), ScpError>
where
    R: AsyncRead + Unpin,
{
    let code = reader.read_u8().await?;
    if code == 0 {
        return Ok(());
    }
    let mut message = String::new();
    let _ = reader.read_line(&mut message).await;
    let message = message.trim();
    if message.is_empty() {
        return Err(ScpError::Protocol("scp peer returned an error".into()));
    }
    Err(ScpError::Protocol(message.into()))
}

async fn write_scp_ack<W>(writer: &mut W) -> Result<(), ScpError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&[0]).await?;
    writer.flush().await?;
    Ok(())
}

async fn write_scp_message<W>(writer: &mut W, code: u8, message: &str) -> Result<(), ScpError>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(format!("{}{}\n", code as char, message).as_bytes())
        .await?;
    writer.flush().await?;
    Ok(())
}

fn file_mode_is_dir(mode: u32) -> bool {
    mode & MODE_DIR != 0
}

fn base_name(path: &str) -> String {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|part| !part.is_empty())
        .unwrap_or(".")
        .to_string()
}

fn join_path(base: &str, name: &str) -> String {
    if base == "/" {
        format!("/{name}")
    } else {
        format!("{}/{}", base.trim_end_matches('/'), name)
    }
}

fn timestamp(seconds: i64) -> prost_types::Timestamp {
    prost_types::Timestamp { seconds, nanos: 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::{ExecDaemonSession, PtyDaemonSession, SessionStart};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[test]
    fn parses_supported_scp_commands() {
        let cmd = parse_scp_command(&["scp".into(), "-tprd".into(), "/workspace/out".into()])
            .unwrap()
            .unwrap();
        assert!(cmd.sink);
        assert!(cmd.recursive);
        assert!(cmd.preserve_time);
        assert!(cmd.target_is_dir);
        assert_eq!(cmd.target, "/workspace/out");

        let err =
            parse_scp_command(&["scp".into(), "-x".into(), "/workspace/out".into()]).unwrap_err();
        assert!(err.to_string().contains("unsupported scp flag"));
    }

    #[tokio::test]
    async fn scp_upload_writes_file_via_daemon() {
        let client = MockDaemonClient::default();
        let runner = DaemonScpRunner::new(client.clone());
        let (server, client_stream) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(server);
            let mut read = BufReader::new(read);
            runner
                .run_with_io(
                    vec!["scp".into(), "-t".into(), "/workspace/scp.txt".into()],
                    &mut read,
                    &mut write,
                )
                .await
        });

        let client_task = tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(client_stream);
            let mut read = BufReader::new(read);
            read_scp_ack(&mut read).await.unwrap();
            write.write_all(b"C0644 14 local.txt\n").await.unwrap();
            read_scp_ack(&mut read).await.unwrap();
            write.write_all(b"hello from scp").await.unwrap();
            write.write_all(&[0]).await.unwrap();
            read_scp_ack(&mut read).await.unwrap();
        });

        let (exit_code, _) = tokio::try_join!(server_task, client_task).unwrap();
        assert_eq!(exit_code.unwrap(), 0);
        assert_eq!(
            client.file_bytes("/workspace/scp.txt").await,
            b"hello from scp"
        );
        assert_eq!(client.opened_mode("/workspace/scp.txt").await, Some(0o644));
    }

    #[tokio::test]
    async fn scp_download_reads_file_via_daemon() {
        let client = MockDaemonClient::default();
        client
            .insert_file("/workspace/scp.txt", 0o644, b"hello from scp")
            .await;
        let runner = DaemonScpRunner::new(client);
        let (server, client_stream) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(server);
            let mut read = BufReader::new(read);
            runner
                .run_with_io(
                    vec!["scp".into(), "-f".into(), "/workspace/scp.txt".into()],
                    &mut read,
                    &mut write,
                )
                .await
        });

        let client_task = tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(client_stream);
            let mut read = BufReader::new(read);
            write.write_all(&[0]).await.unwrap();
            let mut header = String::new();
            read.read_line(&mut header).await.unwrap();
            assert_eq!(header, "C0644 14 scp.txt\n");
            write.write_all(&[0]).await.unwrap();
            let mut data = vec![0u8; 14];
            read.read_exact(&mut data).await.unwrap();
            assert_eq!(data, b"hello from scp");
            read_scp_ack(&mut read).await.unwrap();
            write.write_all(&[0]).await.unwrap();
        });

        let (exit_code, _) = tokio::try_join!(server_task, client_task).unwrap();
        assert_eq!(exit_code.unwrap(), 0);
    }

    #[derive(Clone, Default)]
    struct MockDaemonClient {
        files: Arc<Mutex<HashMap<String, MockFile>>>,
        opened: Arc<Mutex<HashMap<String, u32>>>,
    }

    #[derive(Clone, Debug)]
    struct MockFile {
        mode: u32,
        data: Vec<u8>,
    }

    impl MockDaemonClient {
        async fn insert_file(&self, path: &str, mode: u32, data: &[u8]) {
            self.files.lock().await.insert(
                path.into(),
                MockFile {
                    mode,
                    data: data.to_vec(),
                },
            );
        }

        async fn file_bytes(&self, path: &str) -> Vec<u8> {
            self.files
                .lock()
                .await
                .get(path)
                .map(|file| file.data.clone())
                .unwrap_or_default()
        }

        async fn opened_mode(&self, path: &str) -> Option<u32> {
            self.opened.lock().await.get(path).copied()
        }
    }

    #[async_trait]
    impl DaemonClient for MockDaemonClient {
        async fn exec_session(
            &self,
            _start: SessionStart,
        ) -> Result<ExecDaemonSession, DaemonClientError> {
            Err(DaemonClientError::Unsupported("exec session"))
        }

        async fn pty_session(
            &self,
            _start: crate::daemon::PtyStart,
        ) -> Result<PtyDaemonSession, DaemonClientError> {
            Err(DaemonClientError::Unsupported("pty session"))
        }

        async fn list(&self, _path: &str) -> Result<Vec<v1::FileMetadata>, DaemonClientError> {
            Ok(Vec::new())
        }

        async fn stat(
            &self,
            path: &str,
            _follow: bool,
        ) -> Result<Option<v1::FileMetadata>, DaemonClientError> {
            Ok(self
                .files
                .lock()
                .await
                .get(path)
                .map(|file| v1::FileMetadata {
                    name: base_name(path),
                    path: path.into(),
                    size: file.data.len() as i64,
                    mode: file.mode,
                    mod_time: Some(timestamp(1_700_000_000)),
                    link_target: String::new(),
                }))
        }

        async fn open_file(
            &self,
            path: &str,
            _options: FileOpenOptions,
            perm: u32,
        ) -> Result<(), DaemonClientError> {
            self.opened.lock().await.insert(path.into(), perm);
            self.files.lock().await.insert(
                path.into(),
                MockFile {
                    mode: perm,
                    data: Vec::new(),
                },
            );
            Ok(())
        }

        async fn read_at(
            &self,
            path: &str,
            offset: i64,
            length: i64,
        ) -> Result<Vec<u8>, DaemonClientError> {
            let files = self.files.lock().await;
            let file = files
                .get(path)
                .ok_or(DaemonClientError::Unsupported("missing file"))?;
            let start = offset as usize;
            let end = (start + length as usize).min(file.data.len());
            Ok(file.data[start..end].to_vec())
        }

        async fn write_at(
            &self,
            path: &str,
            offset: i64,
            data: Vec<u8>,
        ) -> Result<i64, DaemonClientError> {
            let mut files = self.files.lock().await;
            let file = files
                .get_mut(path)
                .ok_or(DaemonClientError::Unsupported("missing file"))?;
            let start = offset as usize;
            if file.data.len() < start {
                file.data.resize(start, 0);
            }
            if file.data.len() < start + data.len() {
                file.data.resize(start + data.len(), 0);
            }
            file.data[start..start + data.len()].copy_from_slice(&data);
            Ok(data.len() as i64)
        }

        async fn mkdir(&self, path: &str, perm: u32) -> Result<(), DaemonClientError> {
            self.files.lock().await.insert(
                path.into(),
                MockFile {
                    mode: MODE_DIR | perm,
                    data: Vec::new(),
                },
            );
            Ok(())
        }

        async fn remove(&self, _path: &str, _dir: bool) -> Result<(), DaemonClientError> {
            Err(DaemonClientError::Unsupported("remove"))
        }

        async fn rename(&self, _old_path: &str, _new_path: &str) -> Result<(), DaemonClientError> {
            Err(DaemonClientError::Unsupported("rename"))
        }

        async fn set_stat(&self, _request: FileSetStatRequest) -> Result<(), DaemonClientError> {
            Ok(())
        }

        async fn readlink(&self, _path: &str) -> Result<String, DaemonClientError> {
            Err(DaemonClientError::Unsupported("readlink"))
        }
    }
}
