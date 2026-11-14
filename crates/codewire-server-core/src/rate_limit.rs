//! Named rate limits over the shared `rate_limit` table (#3297).
//!
//! One counter serves every limit: [`consume`] is a single atomic statement
//! on the caller's connection, so concurrent requests can't overshoot and a
//! caller inside a transaction counts inside it. Each [`Limit`] has a code
//! default; a platform admin may set a global count for it, and a per-user
//! count where it is counted per user. The count in force is the user's,
//! else the global one, else the default ([`max_in_force`]). Windows stay in
//! code. A database error is an error: callers refuse, never let a request
//! through (#3256).

use chrono::{DateTime, Utc};
use sqlx::PgConnection;

/// A named limit: at most `default_max` requests per `window_secs`, counted
/// under keys `<key_prefix>:<subject>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit {
    /// The name an admin sees and a setting or override is stored under.
    pub name: &'static str,
    /// The `rate_limit` key prefix. Kept from before named limits, so counts
    /// carry over.
    pub key_prefix: &'static str,
    pub window_secs: i64,
    pub default_max: i32,
    /// Counted per user, so a per-user override applies.
    pub per_user: bool,
}

impl Limit {
    /// The `rate_limit` key for `subject`, such as a user id.
    pub fn key(&self, subject: &str) -> String {
        format!("{}:{subject}", self.key_prefix)
    }
}

/// Sandbox creates per user, as before named limits.
pub const SANDBOX_CREATE: Limit = Limit {
    name: "sandbox_create",
    key_prefix: "env_create",
    window_secs: 60,
    default_max: 10,
    per_user: true,
};

/// Sandbox starts per user, as before named limits.
pub const SANDBOX_START: Limit = Limit {
    name: "sandbox_start",
    key_prefix: "env_start",
    window_secs: 60,
    default_max: 10,
    per_user: true,
};

/// Snapshot creates per user, as before named limits.
pub const SNAPSHOT_CREATE: Limit = Limit {
    name: "snapshot_create",
    key_prefix: "snapshot_create",
    window_secs: 60,
    default_max: 10,
    per_user: true,
};

/// Email and provider sign-ups across the whole site (#3297), counted before
/// any other check. A per-address limit follows once nothing but the edge and
/// the dashboard can write the counted address.
pub const SIGNUP: Limit = Limit {
    name: "signup",
    key_prefix: "signup",
    window_secs: 3_600,
    default_max: 100,
    per_user: false,
};

/// Every named limit, in the order an admin sees them.
pub const LIMITS: &[Limit] = &[SANDBOX_CREATE, SANDBOX_START, SNAPSHOT_CREATE, SIGNUP];

/// What [`consume`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    /// The count in force.
    pub max: i32,
    /// When the current window ends and the count starts again.
    pub resets_at: DateTime<Utc>,
}

impl Decision {
    /// The refusal a person reads, naming the limit and when it resets:
    /// "at most 10 sandbox creates a minute; try again after 14:05:30 UTC".
    pub fn refusal(&self, what: &str, limit: &Limit) -> String {
        format!(
            "at most {} {what} {}; try again after {} UTC",
            self.max,
            window_phrase(limit.window_secs),
            self.resets_at.format("%H:%M:%S")
        )
    }
}

impl Decision {
    /// Whole seconds from `now` until the window resets, for `Retry-After`:
    /// at least 1, so a client never retries at once.
    pub fn retry_after_secs(&self, now: DateTime<Utc>) -> u64 {
        u64::try_from((self.resets_at - now).num_seconds())
            .unwrap_or(0)
            .max(1)
    }
}

fn window_phrase(window_secs: i64) -> String {
    match window_secs {
        60 => "a minute".to_owned(),
        3_600 => "an hour".to_owned(),
        86_400 => "a day".to_owned(),
        seconds => format!("every {seconds} seconds"),
    }
}

/// Counts one request against `key` and says whether it may go ahead. One
/// statement on `connection`: inside a transaction it counts inside it, and
/// the caller's rollback undoes it. A refused request still counts; in a
/// fixed window that never extends the wait. The window starts at the first
/// request and resets once it has passed (#3923). A caller taking two keys
/// takes them in one fixed order, broader first, so two requests can't
/// deadlock on each other's rows.
pub async fn consume(
    connection: &mut PgConnection,
    key: &str,
    window_secs: i64,
    max: i32,
    now: DateTime<Utc>,
) -> Result<Decision, sqlx::Error> {
    let now_ms = now.timestamp_millis();
    let window_ms = window_secs.saturating_mul(1_000);
    let (count, window_start): (i32, i64) = sqlx::query_as(
        r#"INSERT INTO rate_limit (id, key, count, last_request)
           VALUES ($1, $2, 1, $3)
           ON CONFLICT (key) DO UPDATE SET
               count = CASE WHEN rate_limit.last_request < $4 THEN 1
                            ELSE rate_limit.count + 1 END,
               last_request = CASE WHEN rate_limit.last_request < $4 THEN $3
                                   ELSE rate_limit.last_request END
           RETURNING count, last_request"#,
    )
    .bind(uuid::Uuid::new_v4().simple().to_string())
    .bind(key)
    .bind(now_ms)
    .bind(now_ms - window_ms)
    .fetch_one(connection)
    .await?;
    let resets_at = DateTime::<Utc>::from_timestamp_millis(window_start.saturating_add(window_ms))
        .unwrap_or(now);
    Ok(Decision {
        allowed: count <= max,
        max,
        resets_at,
    })
}

/// The count in force for `limit`: `user_id`'s override where the limit is
/// counted per user, else the admin's global count, else the code default.
pub async fn max_in_force(
    connection: &mut PgConnection,
    limit: &Limit,
    user_id: Option<&str>,
) -> Result<i32, sqlx::Error> {
    let user_id = user_id.filter(|_| limit.per_user);
    let set: Option<i32> = sqlx::query_scalar(
        r#"SELECT COALESCE(
               (SELECT max_requests FROM rate_limit_overrides
                 WHERE user_id = $1 AND name = $2),
               (SELECT max_requests FROM rate_limit_settings WHERE name = $2))"#,
    )
    .bind(user_id)
    .bind(limit.name)
    .fetch_one(connection)
    .await?;
    Ok(set.unwrap_or(limit.default_max))
}

/// Counts one request by `user_id` against a per-user `limit`, at the count
/// in force for them. The time is the database's, so replicas whose clocks
/// differ agree on where a window starts and ends.
pub async fn take_for_user(
    connection: &mut PgConnection,
    limit: &Limit,
    user_id: &str,
) -> Result<Decision, sqlx::Error> {
    let max = max_in_force(&mut *connection, limit, Some(user_id)).await?;
    let now = database_now(&mut *connection).await?;
    consume(connection, &limit.key(user_id), limit.window_secs, max, now).await
}

/// Counts one request against a limit with no per-user count, such as the
/// site-wide sign-up limit, under `subject`, at the admin's global count or
/// the default. The time is the database's, as in [`take_for_user`].
pub async fn take(
    connection: &mut PgConnection,
    limit: &Limit,
    subject: &str,
) -> Result<Decision, sqlx::Error> {
    let max = max_in_force(&mut *connection, limit, None).await?;
    let now = database_now(&mut *connection).await?;
    consume(connection, &limit.key(subject), limit.window_secs, max, now).await
}

/// The database's current time: `clock_timestamp()`, which advances within a
/// transaction, unlike `now()`.
async fn database_now(connection: &mut PgConnection) -> Result<DateTime<Utc>, sqlx::Error> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(connection)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_names_the_limit_and_when_it_resets() {
        let decision = Decision {
            allowed: false,
            max: 10,
            resets_at: DateTime::parse_from_rfc3339("2026-11-13T14:05:30Z")
                .unwrap()
                .to_utc(),
        };
        assert_eq!(
            decision.refusal("sandbox creates", &SANDBOX_CREATE),
            "at most 10 sandbox creates a minute; try again after 14:05:30 UTC"
        );
    }

    #[test]
    fn named_limits_keep_their_keys_and_are_unique() {
        assert_eq!(SANDBOX_CREATE.key("u1"), "env_create:u1");
        assert_eq!(SANDBOX_START.key("u1"), "env_start:u1");
        assert_eq!(SNAPSHOT_CREATE.key("u1"), "snapshot_create:u1");
        assert_eq!(SIGNUP.key("all"), "signup:all");
        let mut names: Vec<_> = LIMITS.iter().map(|limit| limit.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), LIMITS.len());
    }

    #[test]
    fn a_sign_up_refusal_says_an_hour_and_retry_after_counts_down_to_the_reset() {
        let at = |time: &str| DateTime::parse_from_rfc3339(time).unwrap().to_utc();
        let decision = Decision {
            allowed: false,
            max: 100,
            resets_at: at("2026-11-13T15:00:00Z"),
        };
        assert_eq!(
            decision.refusal("sign-ups", &SIGNUP),
            "at most 100 sign-ups an hour; try again after 15:00:00 UTC"
        );
        assert_eq!(decision.retry_after_secs(at("2026-11-13T14:59:30Z")), 30);
        // At or past the reset a client still waits a second, never zero.
        assert_eq!(decision.retry_after_secs(at("2026-11-13T15:00:00Z")), 1);
        assert_eq!(decision.retry_after_secs(at("2026-11-13T15:10:00Z")), 1);
    }
}
