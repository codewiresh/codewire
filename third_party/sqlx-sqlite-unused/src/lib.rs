//! Never built. sqlx's SQLite driver is not used by Codewire, but Cargo still
//! resolves it, and its `links = "sqlite3"` claim would hold rusqlite on a
//! vulnerable bundled SQLite (#3980). See this directory's README.
compile_error!("sqlx's SQLite driver is not used by Codewire; see #3980");
