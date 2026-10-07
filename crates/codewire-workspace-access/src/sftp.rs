use std::collections::HashMap;
use std::env;

use codewire_daemon_proto::daemon::v1;
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};
use russh_sftp::server::StatusReply;

use crate::daemon::{DaemonClient, DaemonClientError, FileOpenOptions, FileSetStatRequest};

pub const DEFAULT_HOME_ROOT: &str = "/home/codewire";
pub const HOME_ROOT_ENV: &str = "CODEWIRE_HOME_ROOT";

#[derive(Clone)]
pub struct DaemonSftpRunner<C> {
    client: C,
    home_root: String,
}

impl<C> DaemonSftpRunner<C> {
    pub fn new(client: C) -> Self {
        Self {
            client,
            home_root: home_root_from_env(),
        }
    }

    pub fn with_home_root(client: C, home_root: impl Into<String>) -> Self {
        Self {
            client,
            home_root: clean_path(&home_root.into()),
        }
    }
}

impl<C> DaemonSftpRunner<C>
where
    C: DaemonClient + Clone + Send + Sync + 'static,
{
    pub async fn run<S>(&self, stream: S)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let handler =
            DaemonSftpHandler::with_home_root(self.client.clone(), self.home_root.clone());
        russh_sftp::server::run(stream, handler).await;
    }
}

pub struct DaemonSftpHandler<C> {
    client: C,
    home_root: String,
    next_handle: u64,
    files: HashMap<String, RemoteFileHandle>,
    dirs: HashMap<String, RemoteDirHandle>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteFileHandle {
    path: String,
    read: bool,
    write: bool,
}

#[derive(Debug, Clone)]
struct RemoteDirHandle {
    entries: Vec<v1::FileMetadata>,
    read_done: bool,
}

impl<C> DaemonSftpHandler<C> {
    pub fn new(client: C) -> Self {
        Self::with_home_root(client, home_root_from_env())
    }

    pub fn with_home_root(client: C, home_root: impl Into<String>) -> Self {
        Self {
            client,
            home_root: clean_path(&home_root.into()),
            next_handle: 0,
            files: HashMap::new(),
            dirs: HashMap::new(),
        }
    }

    fn next_file_handle(&mut self, path: String, options: FileOpenOptions) -> HandleState {
        self.next_handle += 1;
        let handle = format!("file:{}", self.next_handle);
        self.files.insert(
            handle.clone(),
            RemoteFileHandle {
                path,
                read: options.read || !options.write,
                write: options.write || options.append,
            },
        );
        HandleState { handle }
    }

    fn next_dir_handle(&mut self, entries: Vec<v1::FileMetadata>) -> HandleState {
        self.next_handle += 1;
        let handle = format!("dir:{}", self.next_handle);
        self.dirs.insert(
            handle.clone(),
            RemoteDirHandle {
                entries,
                read_done: false,
            },
        );
        HandleState { handle }
    }

    fn realpath_name(&self, id: u32, path: String) -> Name {
        Name {
            id,
            files: vec![File::dummy(self.realpath_value(&path))],
        }
    }

    fn realpath_value(&self, path: &str) -> String {
        let cleaned = clean_path(path);
        if cleaned == "." {
            return self.home_root.clone();
        }
        if cleaned.starts_with('/') {
            cleaned
        } else {
            clean_path(&format!("{}/{}", self.home_root, cleaned))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HandleState {
    handle: String,
}

impl<C> russh_sftp::server::Handler for DaemonSftpHandler<C>
where
    C: DaemonClient + Clone + Send + Sync + 'static,
{
    type Error = StatusReply;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported.into()
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let options = file_open_options_from_flags(pflags);
        self.client
            .open_file(&filename, options.clone(), file_mode_or(&attrs, 0o644))
            .await
            .map_err(status_from_daemon_error)?;
        let handle = self.next_file_handle(filename, options);
        Ok(Handle {
            id,
            handle: handle.handle,
        })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.files.remove(&handle);
        self.dirs.remove(&handle);
        Ok(ok_status(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let file = self
            .files
            .get(&handle)
            .cloned()
            .ok_or_else(|| StatusCode::NoSuchFile.with_message("unknown file handle"))?;
        if !file.read {
            return Err(StatusCode::PermissionDenied.with_message("file was not opened for read"));
        }
        let data = self
            .client
            .read_at(
                &file.path,
                i64::try_from(offset)
                    .map_err(|_| StatusCode::Failure.with_message("offset exceeds i64"))?,
                i64::from(len),
            )
            .await
            .map_err(status_from_daemon_error)?;
        if data.is_empty() {
            return Err(StatusCode::Eof.into());
        }
        Ok(Data { id, data })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let file = self
            .files
            .get(&handle)
            .cloned()
            .ok_or_else(|| StatusCode::NoSuchFile.with_message("unknown file handle"))?;
        if !file.write {
            return Err(StatusCode::PermissionDenied.with_message("file was not opened for write"));
        }
        let bytes_written = self
            .client
            .write_at(
                &file.path,
                i64::try_from(offset)
                    .map_err(|_| StatusCode::Failure.with_message("offset exceeds i64"))?,
                data.clone(),
            )
            .await
            .map_err(status_from_daemon_error)?;
        if bytes_written != i64::try_from(data.len()).unwrap_or(i64::MAX) {
            return Err(StatusCode::Failure.with_message("short write"));
        }
        Ok(ok_status(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.stat_path(id, &path, false).await
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let file = self
            .files
            .get(&handle)
            .cloned()
            .ok_or_else(|| StatusCode::NoSuchFile.with_message("unknown file handle"))?;
        self.stat_path(id, &file.path, true).await
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        self.set_path_stat(id, path, attrs).await
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let file = self
            .files
            .get(&handle)
            .cloned()
            .ok_or_else(|| StatusCode::NoSuchFile.with_message("unknown file handle"))?;
        self.set_path_stat(id, file.path, attrs).await
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let mut entries = self
            .client
            .list(&path)
            .await
            .map_err(status_from_daemon_error)?;
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let handle = self.next_dir_handle(entries);
        Ok(Handle {
            id,
            handle: handle.handle,
        })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let dir = self
            .dirs
            .get_mut(&handle)
            .ok_or_else(|| StatusCode::NoSuchFile.with_message("unknown directory handle"))?;
        if dir.read_done {
            return Err(StatusCode::Eof.into());
        }
        dir.read_done = true;
        Ok(Name {
            id,
            files: dir
                .entries
                .iter()
                .cloned()
                .map(file_from_metadata)
                .collect(),
        })
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        self.client
            .remove(&filename, false)
            .await
            .map_err(status_from_daemon_error)?;
        Ok(ok_status(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        self.client
            .mkdir(&path, file_mode_or(&attrs, 0o755))
            .await
            .map_err(status_from_daemon_error)?;
        Ok(ok_status(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        self.client
            .remove(&path, true)
            .await
            .map_err(status_from_daemon_error)?;
        Ok(ok_status(id))
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        Ok(self.realpath_name(id, path))
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.stat_path(id, &path, true).await
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        self.client
            .rename(&oldpath, &newpath)
            .await
            .map_err(status_from_daemon_error)?;
        Ok(ok_status(id))
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let target = self
            .client
            .readlink(&path)
            .await
            .map_err(status_from_daemon_error)?;
        Ok(Name {
            id,
            files: vec![File::dummy(target)],
        })
    }
}

impl<C> DaemonSftpHandler<C>
where
    C: DaemonClient + Clone + Send + Sync + 'static,
{
    async fn stat_path(&self, id: u32, path: &str, follow: bool) -> Result<Attrs, StatusReply> {
        let Some(entry) = self
            .client
            .stat(path, follow)
            .await
            .map_err(status_from_daemon_error)?
        else {
            return Err(StatusCode::NoSuchFile.into());
        };
        Ok(Attrs {
            id,
            attrs: file_attrs_from_metadata(entry),
        })
    }

    async fn set_path_stat(
        &self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, StatusReply> {
        self.client
            .set_stat(file_set_stat_request(path, attrs))
            .await
            .map_err(status_from_daemon_error)?;
        Ok(ok_status(id))
    }
}

pub fn file_open_options_from_flags(flags: OpenFlags) -> FileOpenOptions {
    FileOpenOptions {
        read: flags.contains(OpenFlags::READ),
        write: flags.contains(OpenFlags::WRITE),
        append: flags.contains(OpenFlags::APPEND),
        create: flags.contains(OpenFlags::CREATE),
        truncate: flags.contains(OpenFlags::TRUNCATE),
        exclusive: flags.contains(OpenFlags::EXCLUDE),
    }
}

pub fn file_set_stat_request(path: String, attrs: FileAttributes) -> FileSetStatRequest {
    FileSetStatRequest {
        path,
        size: attrs.size.and_then(|size| i64::try_from(size).ok()),
        mode: attrs.permissions.map(sftp_mode_to_go_mode),
        access_time: attrs.atime.map(timestamp_from_unix_seconds),
        mod_time: attrs.mtime.map(timestamp_from_unix_seconds),
    }
}

pub fn file_attrs_from_metadata(entry: v1::FileMetadata) -> FileAttributes {
    FileAttributes {
        size: Some(u64::try_from(entry.size).unwrap_or(0)),
        uid: Some(0),
        user: None,
        gid: Some(0),
        group: None,
        permissions: Some(go_mode_to_sftp_mode(entry.mode)),
        atime: None,
        mtime: entry.mod_time.map(|time| unix_seconds_u32(time.seconds)),
    }
}

pub fn file_from_metadata(entry: v1::FileMetadata) -> File {
    File::new(entry.name.clone(), file_attrs_from_metadata(entry))
}

fn file_mode_or(attrs: &FileAttributes, fallback: u32) -> u32 {
    attrs
        .permissions
        .map(|mode| sftp_mode_to_go_mode(mode) & 0o7777)
        .unwrap_or(fallback)
}

fn timestamp_from_unix_seconds(seconds: u32) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: i64::from(seconds),
        nanos: 0,
    }
}

fn unix_seconds_u32(seconds: i64) -> u32 {
    if seconds <= 0 {
        0
    } else {
        u32::try_from(seconds).unwrap_or(u32::MAX)
    }
}

fn ok_status(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".into(),
        language_tag: "en-US".into(),
    }
}

fn status_from_daemon_error(err: DaemonClientError) -> StatusReply {
    let code = match &err {
        DaemonClientError::Status(status) => match status.code() {
            tonic::Code::NotFound => StatusCode::NoSuchFile,
            tonic::Code::PermissionDenied => StatusCode::PermissionDenied,
            tonic::Code::Unimplemented => StatusCode::OpUnsupported,
            tonic::Code::InvalidArgument | tonic::Code::FailedPrecondition => {
                StatusCode::BadMessage
            }
            _ => StatusCode::Failure,
        },
        DaemonClientError::Unsupported(_) => StatusCode::OpUnsupported,
        _ => StatusCode::Failure,
    };
    code.with_message(err.to_string())
}

fn home_root_from_env() -> String {
    env::var(HOME_ROOT_ENV)
        .ok()
        .map(|value| clean_path(value.trim()))
        .filter(|value| !value.is_empty() && value != ".")
        .unwrap_or_else(|| DEFAULT_HOME_ROOT.into())
}

fn clean_path(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();

    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => match parts.last().copied() {
                Some("..") if !absolute => parts.push(".."),
                Some(_) => {
                    parts.pop();
                }
                None if !absolute => parts.push(".."),
                None => {}
            },
            part => parts.push(part),
        }
    }

    if absolute {
        if parts.is_empty() {
            "/".into()
        } else {
            format!("/{}", parts.join("/"))
        }
    } else if parts.is_empty() {
        ".".into()
    } else {
        parts.join("/")
    }
}

const GO_MODE_DIR: u32 = 1 << 31;
const GO_MODE_SYMLINK: u32 = 1 << 27;
const GO_MODE_DEVICE: u32 = 1 << 26;
const GO_MODE_NAMED_PIPE: u32 = 1 << 25;
const GO_MODE_SOCKET: u32 = 1 << 24;
const GO_MODE_CHAR_DEVICE: u32 = 1 << 21;

const SFTP_MODE_FIFO: u32 = 0o010000;
const SFTP_MODE_CHAR: u32 = 0o020000;
const SFTP_MODE_DIR: u32 = 0o040000;
const SFTP_MODE_BLOCK: u32 = 0o060000;
const SFTP_MODE_REG: u32 = 0o100000;
const SFTP_MODE_SYMLINK: u32 = 0o120000;
const SFTP_MODE_SOCKET: u32 = 0o140000;
const SFTP_MODE_TYPE_MASK: u32 = 0o170000;

pub fn go_mode_to_sftp_mode(mode: u32) -> u32 {
    let permissions = mode & 0o7777;
    let kind = if mode & GO_MODE_DIR != 0 {
        SFTP_MODE_DIR
    } else if mode & GO_MODE_SYMLINK != 0 {
        SFTP_MODE_SYMLINK
    } else if mode & GO_MODE_NAMED_PIPE != 0 {
        SFTP_MODE_FIFO
    } else if mode & GO_MODE_SOCKET != 0 {
        SFTP_MODE_SOCKET
    } else if mode & GO_MODE_DEVICE != 0 {
        if mode & GO_MODE_CHAR_DEVICE != 0 {
            SFTP_MODE_CHAR
        } else {
            SFTP_MODE_BLOCK
        }
    } else if mode & SFTP_MODE_TYPE_MASK != 0 {
        mode & SFTP_MODE_TYPE_MASK
    } else {
        SFTP_MODE_REG
    };
    kind | permissions
}

pub fn sftp_mode_to_go_mode(mode: u32) -> u32 {
    let permissions = mode & 0o7777;
    let kind = match mode & SFTP_MODE_TYPE_MASK {
        SFTP_MODE_DIR => GO_MODE_DIR,
        SFTP_MODE_SYMLINK => GO_MODE_SYMLINK,
        SFTP_MODE_FIFO => GO_MODE_NAMED_PIPE,
        SFTP_MODE_SOCKET => GO_MODE_SOCKET,
        SFTP_MODE_CHAR => GO_MODE_DEVICE | GO_MODE_CHAR_DEVICE,
        SFTP_MODE_BLOCK => GO_MODE_DEVICE,
        _ => 0,
    };
    kind | permissions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::{ExecDaemonSession, PtyDaemonSession, PtyStart, SessionStart};
    use russh_sftp::server::Handler;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum FileOp {
        Open {
            path: String,
            options: FileOpenOptions,
            perm: u32,
        },
        Read {
            path: String,
            offset: i64,
            length: i64,
        },
        Write {
            path: String,
            offset: i64,
            data: Vec<u8>,
        },
        List {
            path: String,
        },
        Stat {
            path: String,
            follow: bool,
        },
        Mkdir {
            path: String,
            perm: u32,
        },
        Remove {
            path: String,
            dir: bool,
        },
        Rename {
            old_path: String,
            new_path: String,
        },
        SetStat(FileSetStatRequest),
        Readlink {
            path: String,
        },
    }

    #[derive(Default)]
    struct RecordingFileClientState {
        ops: Vec<FileOp>,
        list_entries: Vec<v1::FileMetadata>,
        stat_entry: Option<v1::FileMetadata>,
        read_data: Vec<u8>,
        readlink_target: String,
    }

    #[derive(Clone, Default)]
    struct RecordingFileClient {
        state: Arc<Mutex<RecordingFileClientState>>,
    }

    impl RecordingFileClient {
        fn ops(&self) -> Vec<FileOp> {
            self.state.lock().unwrap().ops.clone()
        }

        fn with_state(update: impl FnOnce(&mut RecordingFileClientState)) -> Self {
            let client = Self::default();
            update(&mut client.state.lock().unwrap());
            client
        }
    }

    #[async_trait::async_trait]
    impl DaemonClient for RecordingFileClient {
        async fn exec_session(
            &self,
            _start: SessionStart,
        ) -> Result<ExecDaemonSession, DaemonClientError> {
            unimplemented!("SFTP tests do not start exec sessions")
        }

        async fn pty_session(
            &self,
            _start: PtyStart,
        ) -> Result<PtyDaemonSession, DaemonClientError> {
            unimplemented!("SFTP tests do not start pty sessions")
        }

        async fn list(&self, path: &str) -> Result<Vec<v1::FileMetadata>, DaemonClientError> {
            let mut state = self.state.lock().unwrap();
            state.ops.push(FileOp::List { path: path.into() });
            Ok(state.list_entries.clone())
        }

        async fn stat(
            &self,
            path: &str,
            follow: bool,
        ) -> Result<Option<v1::FileMetadata>, DaemonClientError> {
            let mut state = self.state.lock().unwrap();
            state.ops.push(FileOp::Stat {
                path: path.into(),
                follow,
            });
            Ok(state.stat_entry.clone())
        }

        async fn open_file(
            &self,
            path: &str,
            options: FileOpenOptions,
            perm: u32,
        ) -> Result<(), DaemonClientError> {
            self.state.lock().unwrap().ops.push(FileOp::Open {
                path: path.into(),
                options,
                perm,
            });
            Ok(())
        }

        async fn read_at(
            &self,
            path: &str,
            offset: i64,
            length: i64,
        ) -> Result<Vec<u8>, DaemonClientError> {
            let mut state = self.state.lock().unwrap();
            state.ops.push(FileOp::Read {
                path: path.into(),
                offset,
                length,
            });
            Ok(state.read_data.clone())
        }

        async fn write_at(
            &self,
            path: &str,
            offset: i64,
            data: Vec<u8>,
        ) -> Result<i64, DaemonClientError> {
            let mut state = self.state.lock().unwrap();
            state.ops.push(FileOp::Write {
                path: path.into(),
                offset,
                data: data.clone(),
            });
            Ok(i64::try_from(data.len()).unwrap())
        }

        async fn mkdir(&self, path: &str, perm: u32) -> Result<(), DaemonClientError> {
            self.state.lock().unwrap().ops.push(FileOp::Mkdir {
                path: path.into(),
                perm,
            });
            Ok(())
        }

        async fn remove(&self, path: &str, dir: bool) -> Result<(), DaemonClientError> {
            self.state.lock().unwrap().ops.push(FileOp::Remove {
                path: path.into(),
                dir,
            });
            Ok(())
        }

        async fn rename(&self, old_path: &str, new_path: &str) -> Result<(), DaemonClientError> {
            self.state.lock().unwrap().ops.push(FileOp::Rename {
                old_path: old_path.into(),
                new_path: new_path.into(),
            });
            Ok(())
        }

        async fn set_stat(&self, request: FileSetStatRequest) -> Result<(), DaemonClientError> {
            self.state
                .lock()
                .unwrap()
                .ops
                .push(FileOp::SetStat(request));
            Ok(())
        }

        async fn readlink(&self, path: &str) -> Result<String, DaemonClientError> {
            let mut state = self.state.lock().unwrap();
            state.ops.push(FileOp::Readlink { path: path.into() });
            Ok(state.readlink_target.clone())
        }
    }

    #[test]
    fn open_flags_map_to_daemon_options() {
        let options = file_open_options_from_flags(
            OpenFlags::READ
                | OpenFlags::WRITE
                | OpenFlags::APPEND
                | OpenFlags::CREATE
                | OpenFlags::TRUNCATE
                | OpenFlags::EXCLUDE,
        );
        assert_eq!(
            options,
            FileOpenOptions {
                read: true,
                write: true,
                append: true,
                create: true,
                truncate: true,
                exclusive: true,
            }
        );
    }

    #[test]
    fn go_file_modes_map_to_sftp_modes() {
        assert_eq!(go_mode_to_sftp_mode(0o644), SFTP_MODE_REG | 0o644);
        assert_eq!(
            go_mode_to_sftp_mode(GO_MODE_DIR | 0o755),
            SFTP_MODE_DIR | 0o755
        );
        assert_eq!(
            go_mode_to_sftp_mode(GO_MODE_SYMLINK | 0o777),
            SFTP_MODE_SYMLINK | 0o777
        );
        assert_eq!(
            sftp_mode_to_go_mode(SFTP_MODE_DIR | 0o755),
            GO_MODE_DIR | 0o755
        );
    }

    #[test]
    fn setstat_attrs_map_to_daemon_request() {
        let request = file_set_stat_request(
            "/workspace/a".into(),
            FileAttributes {
                size: Some(42),
                permissions: Some(SFTP_MODE_REG | 0o640),
                atime: Some(10),
                mtime: Some(11),
                ..FileAttributes::empty()
            },
        );
        assert_eq!(request.path, "/workspace/a");
        assert_eq!(request.size, Some(42));
        assert_eq!(request.mode, Some(0o640));
        assert_eq!(
            request.access_time,
            Some(prost_types::Timestamp {
                seconds: 10,
                nanos: 0,
            })
        );
        assert_eq!(
            request.mod_time,
            Some(prost_types::Timestamp {
                seconds: 11,
                nanos: 0,
            })
        );
    }

    #[test]
    fn realpath_matches_go_home_root_behavior() {
        let handler =
            DaemonSftpHandler::with_home_root(RecordingFileClient::default(), "/home/codewire");
        assert_eq!(handler.realpath_value("."), "/home/codewire");
        assert_eq!(
            handler.realpath_value("project/./src"),
            "/home/codewire/project/src"
        );
        assert_eq!(handler.realpath_value("../outside"), "/home/outside");
        assert_eq!(handler.realpath_value("/workspace//repo/.."), "/workspace");
    }

    #[tokio::test]
    async fn open_read_write_close_use_daemon_file_rpcs() {
        let client = RecordingFileClient::with_state(|state| {
            state.read_data = b"hello".to_vec();
        });
        let mut handler = DaemonSftpHandler::new(client.clone());

        let handle = handler
            .open(
                1,
                "/workspace/file.txt".into(),
                OpenFlags::READ | OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes {
                    permissions: Some(SFTP_MODE_REG | 0o600),
                    ..FileAttributes::empty()
                },
            )
            .await
            .unwrap()
            .handle;
        assert_eq!(
            handler.read(2, handle.clone(), 4, 16).await.unwrap().data,
            b"hello"
        );
        handler
            .write(3, handle.clone(), 9, b"world".to_vec())
            .await
            .unwrap();
        handler.close(4, handle).await.unwrap();

        assert_eq!(
            client.ops(),
            [
                FileOp::Open {
                    path: "/workspace/file.txt".into(),
                    options: FileOpenOptions {
                        read: true,
                        write: true,
                        append: false,
                        create: true,
                        truncate: false,
                        exclusive: false,
                    },
                    perm: 0o600,
                },
                FileOp::Read {
                    path: "/workspace/file.txt".into(),
                    offset: 4,
                    length: 16,
                },
                FileOp::Write {
                    path: "/workspace/file.txt".into(),
                    offset: 9,
                    data: b"world".to_vec(),
                },
            ]
        );
    }

    #[tokio::test]
    async fn opendir_readdir_sorts_entries_and_then_eofs() {
        let client = RecordingFileClient::with_state(|state| {
            state.list_entries = vec![
                metadata("z.txt", "/workspace/z.txt", 1, 0o644, 2),
                metadata("a.txt", "/workspace/a.txt", 1, 0o644, 1),
            ];
        });
        let mut handler = DaemonSftpHandler::new(client.clone());

        let handle = handler
            .opendir(1, "/workspace".into())
            .await
            .unwrap()
            .handle;
        let names = handler
            .readdir(2, handle.clone())
            .await
            .unwrap()
            .files
            .into_iter()
            .map(|file| file.filename)
            .collect::<Vec<_>>();
        assert_eq!(names, ["a.txt", "z.txt"]);
        let err = handler.readdir(3, handle).await.unwrap_err();
        assert_eq!(err.status_code, StatusCode::Eof);
        assert_eq!(
            client.ops(),
            [FileOp::List {
                path: "/workspace".into(),
            }]
        );
    }

    #[tokio::test]
    async fn stat_lstat_and_file_commands_use_daemon_file_rpcs() {
        let client = RecordingFileClient::with_state(|state| {
            state.stat_entry = Some(metadata("file.txt", "/workspace/file.txt", 12, 0o644, 99));
            state.readlink_target = "../target".into();
        });
        let mut handler = DaemonSftpHandler::new(client.clone());

        assert_eq!(
            handler
                .stat(1, "/workspace/file.txt".into())
                .await
                .unwrap()
                .attrs
                .size,
            Some(12)
        );
        handler.lstat(2, "/workspace/link".into()).await.unwrap();
        handler
            .mkdir(
                3,
                "/workspace/dir".into(),
                FileAttributes {
                    permissions: Some(SFTP_MODE_DIR | 0o750),
                    ..FileAttributes::empty()
                },
            )
            .await
            .unwrap();
        handler
            .remove(4, "/workspace/file.txt".into())
            .await
            .unwrap();
        handler.rmdir(5, "/workspace/dir".into()).await.unwrap();
        handler
            .rename(6, "/workspace/a".into(), "/workspace/b".into())
            .await
            .unwrap();
        handler
            .setstat(
                7,
                "/workspace/b".into(),
                FileAttributes {
                    size: Some(5),
                    ..FileAttributes::empty()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            handler
                .readlink(8, "/workspace/link".into())
                .await
                .unwrap()
                .files[0]
                .filename,
            "../target"
        );

        assert_eq!(
            client.ops(),
            [
                FileOp::Stat {
                    path: "/workspace/file.txt".into(),
                    follow: true,
                },
                FileOp::Stat {
                    path: "/workspace/link".into(),
                    follow: false,
                },
                FileOp::Mkdir {
                    path: "/workspace/dir".into(),
                    perm: 0o750,
                },
                FileOp::Remove {
                    path: "/workspace/file.txt".into(),
                    dir: false,
                },
                FileOp::Remove {
                    path: "/workspace/dir".into(),
                    dir: true,
                },
                FileOp::Rename {
                    old_path: "/workspace/a".into(),
                    new_path: "/workspace/b".into(),
                },
                FileOp::SetStat(FileSetStatRequest {
                    path: "/workspace/b".into(),
                    size: Some(5),
                    mode: None,
                    access_time: None,
                    mod_time: None,
                }),
                FileOp::Readlink {
                    path: "/workspace/link".into(),
                },
            ]
        );
    }

    fn metadata(name: &str, path: &str, size: i64, mode: u32, mod_time: i64) -> v1::FileMetadata {
        v1::FileMetadata {
            name: name.into(),
            path: path.into(),
            size,
            mode,
            mod_time: Some(prost_types::Timestamp {
                seconds: mod_time,
                nanos: 0,
            }),
            link_target: String::new(),
        }
    }
}
