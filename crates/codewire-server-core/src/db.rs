//! Postgres connection pool helper.
//!
//! Wraps `sqlx::PgPool::connect` with sensible defaults matching the Go
//! side's `pgxpool`: max 25 connections, sane timeouts, lazy connection
//! verification at startup.

use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// How a service pool proves its connections are live.
///
/// sqlx's default pings every connection on every acquire. That is one extra
/// database round trip in front of every statement, which doubles the
/// latency of each query when the database is not on the same host: on
/// Production an orchestration query to the primary in another location paid
/// 74 ms instead of 37 ms. sqlx already pings each connection when it is
/// released and closes it if that fails, so a connection idle for less than
/// `reprove_after_idle` was proven live that recently and is used as is. A
/// longer-idle one is pinged first; if the ping fails it is closed and
/// replaced, and the caller never sees the failure.
///
/// A connection that dies within that window (a Postgres restart or failover
/// during active use, which fails in-flight statements anyway) fails the one
/// statement that next uses it and is then discarded on release.
///
/// The credential service uses the same check
/// (`codewire-credential-service` `runtime::database_pool_options`) with a
/// one-second window, which its many acquires per lease keep warm. Service
/// traffic is sparser: the dashboard polls every 5 to 10 seconds and the idle
/// queue hands out the longest-idle connection first, so a one-second window
/// would ping almost every statement after a quiet second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolHealth {
    /// A connection idle at least this long is pinged before it is used.
    pub reprove_after_idle: Duration,
}

impl PoolHealth {
    /// A connection released within the last 30 seconds is used without a
    /// ping. Polling traffic keeps connections inside it, and a connection
    /// lost in a database failover is still found within 30 seconds of idle.
    pub const DEFAULT: Self = Self {
        reprove_after_idle: Duration::from_secs(30),
    };
}

impl Default for PoolHealth {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The pool options every service shares, with `health` deciding when an
/// idle connection is pinged.
pub fn pool_options(health: PoolHealth) -> PgPoolOptions {
    let reprove_after_idle = health.reprove_after_idle;
    PgPoolOptions::new()
        .max_connections(25)
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Some(Duration::from_secs(10 * 60)))
        .max_lifetime(Some(Duration::from_secs(30 * 60)))
        .test_before_acquire(false)
        .before_acquire(move |connection, metadata| {
            Box::pin(async move {
                // A rejected connection is closed and replaced; the error is
                // not logged, as sqlx's own liveness check does not log it.
                Ok(metadata.idle_for < reprove_after_idle
                    || sqlx::Connection::ping(connection).await.is_ok())
            })
        })
}

/// Returns a connected pool for the given database URL.
pub async fn connect(url: &str) -> anyhow::Result<PgPool> {
    let pool = pool_options(PoolHealth::default()).connect(url).await?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_pools_do_not_ping_on_every_acquire() {
        let options = pool_options(PoolHealth::default());
        assert!(!options.get_test_before_acquire());
        assert_eq!(options.get_max_connections(), 25);
        assert_eq!(options.get_acquire_timeout(), Duration::from_secs(5));
        assert_eq!(
            options.get_idle_timeout(),
            Some(Duration::from_secs(10 * 60))
        );
        assert_eq!(
            options.get_max_lifetime(),
            Some(Duration::from_secs(30 * 60))
        );
        assert_eq!(
            PoolHealth::default().reprove_after_idle,
            Duration::from_secs(30)
        );
    }

    /// Round trips a statement costs through a link that delays every
    /// client-to-server write by `RTT`, measured in RTTs.
    mod database {
        use std::time::Instant;

        use anyhow::{Context as _, Result, ensure};
        use sqlx::Connection as _;
        use sqlx::postgres::PgConnectOptions;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::{TcpListener, TcpStream};

        use super::*;

        const RTT: Duration = Duration::from_millis(40);

        /// A loopback proxy that holds each client write for one `RTT`
        /// before forwarding it, preserving order, so every request and
        /// reply exchange costs one `RTT`.
        async fn delayed_link(upstream: std::net::SocketAddr) -> Result<std::net::SocketAddr> {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            tokio::spawn(async move {
                while let Ok((client, _)) = listener.accept().await {
                    let Ok(server) = TcpStream::connect(upstream).await else {
                        continue;
                    };
                    let (mut client_read, mut client_write) = client.into_split();
                    let (mut server_read, mut server_write) = server.into_split();
                    let (sender, mut receiver) =
                        tokio::sync::mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
                    tokio::spawn(async move {
                        let mut buffer = vec![0; 16 * 1024];
                        while let Ok(read) = client_read.read(&mut buffer).await {
                            if read == 0
                                || sender
                                    .send((Instant::now() + RTT, buffer[..read].to_vec()))
                                    .is_err()
                            {
                                break;
                            }
                        }
                    });
                    tokio::spawn(async move {
                        while let Some((due, bytes)) = receiver.recv().await {
                            tokio::time::sleep_until(due.into()).await;
                            if server_write.write_all(&bytes).await.is_err() {
                                break;
                            }
                        }
                        let _ = server_write.shutdown().await;
                    });
                    tokio::spawn(async move {
                        let _ = tokio::io::copy(&mut server_read, &mut client_write).await;
                    });
                }
            });
            Ok(address)
        }

        fn database_options() -> Result<PgConnectOptions> {
            Ok(std::env::var("TEST_DATABASE_URL")
                .context("TEST_DATABASE_URL")?
                .parse::<PgConnectOptions>()?)
        }

        async fn delayed_options() -> Result<PgConnectOptions> {
            let options = database_options()?;
            let upstream = tokio::net::lookup_host((options.get_host(), options.get_port()))
                .await?
                .next()
                .context("database address")?;
            let link = delayed_link(upstream).await?;
            Ok(options
                .host(&link.ip().to_string())
                .port(link.port())
                .ssl_mode(sqlx::postgres::PgSslMode::Disable))
        }

        /// Mean round trips per statement for `statements` serial statements
        /// on an already-open pool.
        async fn round_trips(pool: &PgPool, statements: u32) -> Result<f64> {
            let started = Instant::now();
            for _ in 0..statements {
                sqlx::query_scalar::<_, i32>("SELECT 1")
                    .fetch_one(pool)
                    .await?;
            }
            Ok(started.elapsed().as_secs_f64() / RTT.as_secs_f64() / f64::from(statements))
        }

        async fn warm(options: PgPoolOptions) -> Result<PgPool> {
            let pool = options
                .min_connections(4)
                .max_connections(4)
                .connect_with(delayed_options().await?)
                .await?;
            // Open every connection and prepare the statement on each.
            let mut held = Vec::new();
            for _ in 0..4 {
                let mut connection = pool.acquire().await?;
                sqlx::query_scalar::<_, i32>("SELECT 1")
                    .fetch_one(&mut *connection)
                    .await?;
                held.push(connection);
            }
            drop(held);
            tokio::time::sleep(RTT * 3).await;
            Ok(pool)
        }

        /// A statement on a recently used connection costs one round trip;
        /// sqlx's default costs two. A connection idle past the window is
        /// pinged again.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[ignore = "requires TEST_DATABASE_URL"]
        async fn recently_used_connections_skip_the_acquire_ping() -> Result<()> {
            let sqlx_default = warm(
                PgPoolOptions::new()
                    .acquire_timeout(Duration::from_secs(5))
                    .test_before_acquire(true),
            )
            .await?;
            let before = round_trips(&sqlx_default, 12).await?;
            sqlx_default.close().await;

            let shared = warm(pool_options(PoolHealth::default())).await?;
            let after = round_trips(&shared, 12).await?;
            // Polling: statements 1.5 s apart, past a one-second window but
            // well inside the shared one, use their connections as they are.
            let mut polled = 0.0;
            for _ in 0..4 {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                polled += round_trips(&shared, 1).await? / 4.0;
            }
            shared.close().await;

            // Past its window every idle connection is pinged again before
            // its next statement.
            let window = Duration::from_secs(1);
            let short = warm(pool_options(PoolHealth {
                reprove_after_idle: window,
            }))
            .await?;
            tokio::time::sleep(window + RTT * 5).await;
            let after_idle = round_trips(&short, 1).await?;
            short.close().await;

            let always = warm(pool_options(PoolHealth {
                reprove_after_idle: Duration::ZERO,
            }))
            .await?;
            let reproved = round_trips(&always, 12).await?;
            always.close().await;

            println!(
                "round trips per statement: sqlx default {before:.2}, \
                 shared pool {after:.2}, shared pool polled every 1.5 s {polled:.2}, \
                 reprove every acquire {reproved:.2}, first statement past the window {after_idle:.2}"
            );
            ensure!(
                polled < 1.4,
                "polled shared pool cost {polled:.2} round trips"
            );
            ensure!(
                after_idle > 1.8,
                "idle connection cost {after_idle:.2} round trips"
            );
            ensure!(before > 1.8, "sqlx default cost {before:.2} round trips");
            ensure!(after < 1.4, "shared pool cost {after:.2} round trips");
            ensure!(
                reproved > 1.8,
                "reprove-always cost {reproved:.2} round trips"
            );
            Ok(())
        }

        async fn database_backend(pool: &PgPool) -> Result<i32> {
            Ok(sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(pool)
                .await?)
        }

        /// A pooled connection whose backend died is used by at most one
        /// failing statement and then replaced. Past the reprove window it is
        /// replaced before any statement uses it.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[ignore = "requires TEST_DATABASE_URL"]
        async fn dead_pooled_connection_fails_at_most_one_statement() -> Result<()> {
            let options = database_options()?;
            let mut admin = sqlx::postgres::PgConnection::connect_with(&options).await?;
            for (reprove_after_idle, failed_statements) in
                [(Duration::from_secs(3600), 1), (Duration::ZERO, 0)]
            {
                // One connection, so every statement uses the same backend.
                let pool = pool_options(PoolHealth { reprove_after_idle })
                    .max_connections(1)
                    .connect_with(options.clone())
                    .await?;
                let dead = database_backend(&pool).await?;
                ensure!(
                    sqlx::query_scalar::<_, bool>("SELECT pg_terminate_backend($1, 5000)")
                        .bind(dead)
                        .fetch_one(&mut admin)
                        .await?,
                    "pooled backend did not terminate"
                );
                let mut failed = 0;
                let replacement = loop {
                    match database_backend(&pool).await {
                        Ok(backend) => break backend,
                        Err(_) if failed == 0 => failed += 1,
                        Err(error) => return Err(error),
                    }
                };
                ensure!(
                    failed == failed_statements && replacement != dead,
                    "reprove after {reprove_after_idle:?}: {failed} failed statements, \
                     replacement {replacement}, dead {dead}"
                );
                pool.close().await;
            }
            admin.close().await?;
            Ok(())
        }
    }
}
