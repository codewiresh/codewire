//! Limits on creating organization invitations (#4457). Every invitation
//! emails its invitee (#3847), so an account that could invite without bound
//! could send Codewire mail to any address. The checks run in the
//! invitation's own transaction, before anything is written: a refusal
//! writes no invitation and queues no email, and the counts it took roll
//! back with it.

use axum::http::StatusCode;
use chrono::{DateTime, NaiveDateTime, Utc};
use codewire_server_core::{AppError, AppResult};
use sqlx::PgConnection;

use super::super::environments::coded_owned;

/// Invitations one account may create in an hour, across all organizations.
pub(super) const PER_INVITER_PER_HOUR: i32 = 30;
/// Invitations one organization may create in an hour, from all its admins.
pub(super) const PER_ORGANIZATION_PER_HOUR: i32 = 60;
/// Pending, unexpired invitations one organization may hold.
pub(super) const PENDING_PER_ORGANIZATION: i64 = 200;
const WINDOW_MILLIS: i64 = 60 * 60 * 1000;
/// The machine-readable code of a refusal past any of the three limits.
const LIMIT_REACHED: &str = "invitation_limit_reached";

/// Refuses an inviter whose email is not verified, then takes one invitation
/// from the organization's and the inviter's hourly counts, then checks the
/// organization's pending invitations.
pub(super) async fn check(conn: &mut PgConnection, user_id: &str, org_id: &str) -> AppResult<()> {
    // Owner, 2026-11-13 (#4457): unverified people cannot send invitations,
    // as they cannot accept one.
    let verified: Option<bool> =
        sqlx::query_scalar("SELECT COALESCE(email_verified, false) FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(failed)?;
    if verified != Some(true) {
        return Err(coded_owned(
            StatusCode::BAD_REQUEST,
            "email_not_verified",
            "verify your email address before inviting members".to_owned(),
        ));
    }

    // The counts live in rate_limit rather than in org_invitations, which
    // deleting an organization empties. Every transaction takes the
    // organization's row before the inviter's, so two invitations cannot
    // deadlock, and holding the organization's row until commit makes the
    // pending count below see every invitation committed before this one.
    let now = Utc::now().timestamp_millis();
    take_one(
        conn,
        &format!("org_invite_org:{org_id}"),
        PER_ORGANIZATION_PER_HOUR,
        now,
    )
    .await?
    .map_err(|reset| {
        refused(format!(
            "invitation limit reached: an organization can send at most \
                 {PER_ORGANIZATION_PER_HOUR} invitations an hour; try again after {reset}"
        ))
    })?;
    take_one(
        conn,
        &format!("org_invite_user:{user_id}"),
        PER_INVITER_PER_HOUR,
        now,
    )
    .await?
    .map_err(|reset| {
        refused(format!(
            "invitation limit reached: one account can send at most \
                 {PER_INVITER_PER_HOUR} invitations an hour; try again after {reset}"
        ))
    })?;

    let (pending, next_expiry): (i64, Option<NaiveDateTime>) = sqlx::query_as(
        r#"SELECT COUNT(*), MIN(expires_at) FROM org_invitations
           WHERE org_id = $1 AND status = 'pending' AND expires_at > NOW()"#,
    )
    .bind(org_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(failed)?;
    if pending >= PENDING_PER_ORGANIZATION {
        let next = next_expiry.map_or_else(String::new, |at| {
            format!(" (the next expires {})", reset_time(at.and_utc()))
        });
        return Err(refused(format!(
            "invitation limit reached: an organization can hold at most \
             {PENDING_PER_ORGANIZATION} pending invitations; revoke one or wait \
             for one to expire{next}"
        )));
    }
    Ok(())
}

/// Counts one request against `key` in one statement, in a fixed window that
/// starts at the first request and resets once an hour has passed, the rule
/// of the other rate_limit counts (#3923). Returns the window's reset time
/// when the request is past `max`; the caller's rollback then undoes the
/// count.
async fn take_one(
    conn: &mut PgConnection,
    key: &str,
    max: i32,
    now: i64,
) -> AppResult<Result<(), String>> {
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
    .bind(now)
    .bind(now - WINDOW_MILLIS)
    .fetch_one(&mut *conn)
    .await
    .map_err(failed)?;
    if count <= max {
        return Ok(Ok(()));
    }
    let reset = DateTime::<Utc>::from_timestamp_millis(window_start + WINDOW_MILLIS)
        .unwrap_or_else(Utc::now);
    Ok(Err(reset_time(reset)))
}

fn reset_time(at: DateTime<Utc>) -> String {
    at.format("%b %-d %H:%M UTC").to_string()
}

fn refused(detail: String) -> AppError {
    coded_owned(StatusCode::TOO_MANY_REQUESTS, LIMIT_REACHED, detail)
}

/// A limit that cannot be read refuses the invitation rather than letting
/// it through.
fn failed(error: sqlx::Error) -> AppError {
    tracing::error!(error = %error, "organizations: invitation limit check failed");
    AppError::InternalMsg("failed to create invitation".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_times_name_the_day_and_minute_in_utc() {
        let at = DateTime::<Utc>::from_timestamp(1_794_578_700, 0).unwrap();
        assert_eq!(reset_time(at), "Nov 13 14:05 UTC");
    }

    #[test]
    fn refusals_render_as_resource_exhausted() {
        use codewire_server_core::connect_error::{ConnectCode, ConnectError};
        let rendered = ConnectError::from_app_error(&refused("limit".into()), None);
        assert_eq!(rendered.code, ConnectCode::ResourceExhausted);
    }
}
