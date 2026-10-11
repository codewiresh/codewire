//! Errors shared by the complete supervisor SQL codec and host stores.
use crate::host::path::PathError;
use std::io;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum SupervisorStoreError {
    #[error("native supervisor database identity changed while opening")]
    DatabaseIdentityChanged,
    #[error("native supervisor database is invalid")]
    InvalidDatabase,
    #[error(
        "native supervisor database schema is unsupported ({application_id}, {schema_version})"
    )]
    UnsupportedSchema {
        application_id: i64,
        schema_version: i64,
    },
    #[error("native supervisor state is invalid")]
    InvalidState,
    #[error("native supervisor boot identity is invalid")]
    InvalidBootId,
    #[error("native supervisor operation is invalid")]
    InvalidOperation,
    #[error("native supervisor operation request ID was reused with different input")]
    RequestCollision,
    #[error("native supervisor operation journal checkpoint conflicts with durable state")]
    JournalConflict,
    #[error("native supervisor operation was not found")]
    OperationNotFound,
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Path(#[from] PathError),
    #[error("filesystem operation failed for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}
