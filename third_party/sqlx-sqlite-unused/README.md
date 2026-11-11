# sqlx-sqlite (unused stand-in)

Codewire uses sqlx only with PostgreSQL and never enables its SQLite driver.
Cargo still resolves sqlx's optional `sqlx-sqlite` into `Cargo.lock`, and that
crate's `links = "sqlite3"` claim (through `libsqlite3-sys` below 0.38) would
keep `rusqlite` on a bundled SQLite affected by RUSTSEC-2026-0459. The root
`Cargo.toml` patches `sqlx-sqlite` with this crate: it declares the feature
names sqlx references, has no dependencies, and fails to compile if anything
ever builds it. `scripts/checks/repo_checks.py sqlx-sqlite-unused` refuses any
manifest that enables sqlx's SQLite driver and any lockfile that resolves the
real crate (#3980).

Its version must satisfy sqlx's exact `sqlx-sqlite` requirement, so bump it
together with sqlx. Delete this directory and the `[patch.crates-io]` entry once
sqlx's SQLite driver accepts `libsqlite3-sys` 0.39 or later.
