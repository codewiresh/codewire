//! Feedback sent with `cw feedback` (#4061): validating and storing it under
//! its abuse limits, and the platform-admin list.
//!
//! Anyone may send feedback. A signed-in sender's row records their user and,
//! when they name one they belong to, their current organization; an
//! anonymous row records neither. The sender's address is never stored: the
//! row keeps only a keyed hash of it ([`ClientAddressKey`]), which the
//! anonymous limit counts by.
//!
//! The rows are their own rate-limit record. Each submission takes the
//! table's exclusive write lock, counts the sender's and everyone's rows of
//! the last hour, and inserts only under every limit, so concurrent senders
//! cannot overshoot one and a refusal knows exactly when the oldest counted
//! row leaves the window.

use std::borrow::Cow;
use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::internal_hmac::derive_internal_hmac_secret;
use codewire_server_core::{AppError, AppResult, ValidationIssue};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::{PgPool, Postgres, Row, Transaction};

#[cfg(test)]
mod database_tests;

/// The most a message may hold, in bytes of UTF-8 (10 KB).
pub const MAX_MESSAGE_BYTES: usize = 10 * 1024;
/// Feedback a signed-in user may send in an hour.
pub const PER_USER_PER_HOUR: i64 = 10;
/// Anonymous feedback one address may send in an hour.
pub const PER_ANONYMOUS_ADDRESS_PER_HOUR: i64 = 5;
/// Feedback everyone together may send in an hour.
pub const GLOBAL_PER_HOUR: i64 = 500;
/// The window every limit counts over.
const WINDOW: Duration = Duration::from_secs(60 * 60);

const MAX_CLI_VERSION_CHARS: usize = 64;
const MAX_PLATFORM_CHARS: usize = 32;
const MAX_ENVIRONMENT_ID_CHARS: usize = 128;

/// The label the address-hash key is derived under from the service's
/// session secret, so it is never the secret itself nor another service's
/// derived key.
pub const CLIENT_ADDRESS_KEY_LABEL: &str = "codewire/feedback-client-address/v1";

/// The key of the client-address hash: HMAC-SHA256 of the service's session
/// secret over [`CLIENT_ADDRESS_KEY_LABEL`]. Rotating the session secret
/// changes every hash, which only restarts the anonymous allowances.
#[derive(Clone)]
pub struct ClientAddressKey(String);

impl std::fmt::Debug for ClientAddressKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ClientAddressKey([redacted])")
    }
}

impl ClientAddressKey {
    pub fn derive(session_secret: &str) -> anyhow::Result<Self> {
        derive_internal_hmac_secret(session_secret, CLIENT_ADDRESS_KEY_LABEL)
            .map(Self)
            .map_err(|_| anyhow::anyhow!("the session secret for feedback is not set"))
    }

    /// Lowercase hex HMAC-SHA256 of the address an abuser controls as one
    /// unit: an IPv4 address (also when IPv4-mapped), or an IPv6 address's
    /// /64, since one host usually holds a whole /64.
    pub fn hash(&self, address: IpAddr) -> String {
        let unit = match address {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => v4.to_string(),
                None => {
                    let segments = v6.segments();
                    format!(
                        "{:x}:{:x}:{:x}:{:x}::/64",
                        segments[0], segments[1], segments[2], segments[3]
                    )
                }
            },
        };
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.0.as_bytes()).expect("HMAC accepts any key length");
        mac.update(unit.as_bytes());
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

/// Where the sender works.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    Local,
    Cloud,
}

impl Placement {
    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Cloud => "cloud",
        }
    }
}

/// One submission as the caller sent it.
#[derive(Clone, Debug, Default)]
pub struct NewFeedback<'a> {
    pub message: &'a str,
    pub cli_version: &'a str,
    pub os: &'a str,
    pub arch: &'a str,
    pub placement: Option<Placement>,
    pub environment_id: Option<&'a str>,
    pub org_id: Option<&'a str>,
}

/// The stored row's identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredFeedback {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub signed_in: bool,
}

/// Which limit refused a submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitScope {
    User,
    AnonymousAddress,
    Global,
}

#[derive(Debug)]
pub enum SubmitFeedbackError {
    /// The request is invalid or not allowed.
    Rejected(AppError),
    /// A limit is reached; the next submission fits after `retry_after`.
    Limited {
        scope: LimitScope,
        retry_after: Duration,
    },
}

impl From<AppError> for SubmitFeedbackError {
    fn from(error: AppError) -> Self {
        Self::Rejected(error)
    }
}

impl SubmitFeedbackError {
    /// The refusal a sender reads, naming when to try again.
    pub fn limited_message(scope: LimitScope, retry_after: Duration) -> String {
        let seconds = retry_after.as_secs();
        match scope {
            LimitScope::User => format!(
                "feedback is limited to {PER_USER_PER_HOUR} an hour per account; try again in {seconds} seconds"
            ),
            LimitScope::AnonymousAddress => format!(
                "anonymous feedback is limited to {PER_ANONYMOUS_ADDRESS_PER_HOUR} an hour from one address; try again in {seconds} seconds, or sign in"
            ),
            LimitScope::Global => format!(
                "Codewire is receiving too much feedback right now; try again in {seconds} seconds"
            ),
        }
    }
}

fn issue(path: &'static str, message: &'static str) -> ValidationIssue {
    ValidationIssue {
        path: Cow::Borrowed(path),
        message: Cow::Borrowed(message),
    }
}

fn platform_name(value: &str) -> bool {
    (1..=MAX_PLATFORM_CHARS).contains(&value.chars().count())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// The same rule as the table's `feedback_environment_id_check`.
fn environment_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=MAX_ENVIRONMENT_ID_CHARS).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Field checks, before any database access. They match the table's
/// constraints, so a refusal names the field instead of failing an insert.
pub fn validate(feedback: &NewFeedback<'_>) -> AppResult<()> {
    let mut errors = Vec::new();
    if feedback.message.trim().is_empty() {
        errors.push(issue("/message", "must not be empty"));
    } else if feedback.message.len() > MAX_MESSAGE_BYTES {
        errors.push(issue("/message", "must be at most 10240 bytes"));
    }
    let version_chars = feedback.cli_version.chars().count();
    if !(1..=MAX_CLI_VERSION_CHARS).contains(&version_chars)
        || feedback.cli_version.chars().any(char::is_control)
    {
        errors.push(issue(
            "/cli_version",
            "must be 1 to 64 characters without control characters",
        ));
    }
    if !platform_name(feedback.os) {
        errors.push(issue(
            "/os",
            "must be 1 to 32 letters, digits, '.', '_' or '-'",
        ));
    }
    if !platform_name(feedback.arch) {
        errors.push(issue(
            "/arch",
            "must be 1 to 32 letters, digits, '.', '_' or '-'",
        ));
    }
    if feedback
        .environment_id
        .is_some_and(|id| !environment_id(id))
    {
        errors.push(issue(
            "/environment_id",
            "must be 1 to 128 letters, digits, '.', '_' or '-', starting with a letter or digit",
        ));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(AppError::Validation { errors })
    }
}

/// The organization a signed-in sender's feedback records: the one they
/// name, which they must belong to (an API key only its own), else an API
/// key's own organization, else none. Anonymous senders name none.
async fn sender_organization(
    pool: &PgPool,
    user: Option<&AuthUser>,
    org_id: Option<&str>,
) -> AppResult<Option<String>> {
    let org_id = org_id.filter(|id| !id.is_empty());
    match (user, org_id) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(AppError::Validation {
            errors: vec![issue(
                "/org_id",
                "only signed-in feedback records an organization",
            )],
        }),
        (Some(user), Some(org_id)) => {
            codewire_server_core::org::require_org_member(pool, user, org_id).await?;
            Ok(Some(org_id.to_owned()))
        }
        (Some(user), None) => Ok(user.via_api_key.then(|| user.org_id.clone()).flatten()),
    }
}

/// Stores one submission if every limit allows it. `user` is the validated
/// caller, if any; `address` the client address the edge reported, if any.
pub async fn submit_feedback(
    pool: &PgPool,
    key: &ClientAddressKey,
    user: Option<&AuthUser>,
    address: Option<IpAddr>,
    feedback: &NewFeedback<'_>,
) -> Result<StoredFeedback, SubmitFeedbackError> {
    validate(feedback)?;
    let organization_id = sender_organization(pool, user, feedback.org_id).await?;
    let address_hash = address.map(|address| key.hash(address));
    let user_id = user.map(|user| user.user_id.as_str());

    let mut transaction = pool.begin().await.map_err(storage_error)?;
    // Serializes submissions (reads are not blocked), so each count below
    // sees every earlier insert and no limit is overshot.
    sqlx::query("LOCK TABLE feedback IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
    let sender = match user_id {
        Some(user_id) => Counted::User(user_id),
        None => Counted::AnonymousAddress(address_hash.as_deref()),
    };
    for counted in [sender, Counted::Global] {
        if let Some(retry_after) = limit_reached(&mut transaction, counted).await? {
            return Err(SubmitFeedbackError::Limited {
                scope: counted.scope(),
                retry_after,
            });
        }
    }
    let row = sqlx::query(
        r#"INSERT INTO feedback
               (user_id, organization_id, message, cli_version, os, arch,
                placement, environment_id, client_address_hash)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           RETURNING id, created_at"#,
    )
    .bind(user_id)
    .bind(organization_id)
    .bind(feedback.message)
    .bind(feedback.cli_version)
    .bind(feedback.os)
    .bind(feedback.arch)
    .bind(feedback.placement.map(Placement::as_str))
    .bind(feedback.environment_id)
    .bind(address_hash)
    .fetch_one(&mut *transaction)
    .await
    .map_err(storage_error)?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(StoredFeedback {
        id: row.try_get("id").map_err(storage_error)?,
        created_at: row.try_get("created_at").map_err(storage_error)?,
        signed_in: user_id.is_some(),
    })
}

/// The rows one limit counts.
#[derive(Clone, Copy)]
enum Counted<'a> {
    User(&'a str),
    /// Anonymous rows from one address hash; `None` is every anonymous row
    /// whose address was unknown.
    AnonymousAddress(Option<&'a str>),
    Global,
}

impl Counted<'_> {
    fn scope(self) -> LimitScope {
        match self {
            Self::User(_) => LimitScope::User,
            Self::AnonymousAddress(_) => LimitScope::AnonymousAddress,
            Self::Global => LimitScope::Global,
        }
    }

    fn limit(self) -> i64 {
        match self {
            Self::User(_) => PER_USER_PER_HOUR,
            Self::AnonymousAddress(_) => PER_ANONYMOUS_ADDRESS_PER_HOUR,
            Self::Global => GLOBAL_PER_HOUR,
        }
    }
}

/// When `counted` already holds its limit of rows in the last hour, how long
/// until the oldest of the newest `limit` leaves the window (at least a
/// second); `None` while another row fits.
async fn limit_reached(
    transaction: &mut Transaction<'_, Postgres>,
    counted: Counted<'_>,
) -> Result<Option<Duration>, SubmitFeedbackError> {
    // The window is measured on the database clock that stamps created_at.
    let filter = match counted {
        Counted::User(_) => "user_id = $3",
        Counted::AnonymousAddress(Some(_)) => "user_id IS NULL AND client_address_hash = $3",
        Counted::AnonymousAddress(None) => "user_id IS NULL AND client_address_hash IS NULL",
        Counted::Global => "TRUE",
    };
    let sql = format!(
        r#"SELECT ceil(extract(epoch FROM created_at + make_interval(secs => $1) - now()))::bigint
             FROM feedback
            WHERE created_at > now() - make_interval(secs => $1) AND {filter}
            ORDER BY created_at DESC
            OFFSET $2 LIMIT 1"#
    );
    let query = sqlx::query_scalar::<_, i64>(&sql)
        .bind(WINDOW.as_secs_f64())
        .bind(counted.limit() - 1);
    let query = match counted {
        Counted::User(value) | Counted::AnonymousAddress(Some(value)) => query.bind(value),
        Counted::AnonymousAddress(None) | Counted::Global => query,
    };
    let seconds = query
        .fetch_optional(&mut **transaction)
        .await
        .map_err(storage_error)?;
    Ok(seconds.map(|seconds| Duration::from_secs(seconds.max(1).unsigned_abs())))
}

fn storage_error(error: sqlx::Error) -> SubmitFeedbackError {
    tracing::error!(%error, "feedback: storage failed");
    SubmitFeedbackError::Rejected(AppError::ServiceUnavailable(
        "feedback could not be stored; try again later".into(),
    ))
}

// ── The admin list ─────────────────────────────────────────────────────────

/// The server default and maximum page sizes.
pub const DEFAULT_LIST_LIMIT: i64 = 50;
pub const MAX_LIST_LIMIT: i64 = 200;

/// Which senders the admin list shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SenderFilter {
    #[default]
    All,
    SignedIn,
    Anonymous,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedbackRow {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub user_id: Option<String>,
    pub user_email: Option<String>,
    pub organization_id: Option<String>,
    pub organization_name: Option<String>,
    pub message: String,
    pub cli_version: String,
    pub os: String,
    pub arch: String,
    pub placement: Option<String>,
    pub environment_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedbackPage {
    pub feedback: Vec<FeedbackRow>,
    /// Empty on the last page.
    pub next_page_token: String,
}

/// A page token: the last row's `created_at` in microseconds and its id.
fn encode_page_token(row: &FeedbackRow) -> String {
    format!("{}.{}", row.created_at.timestamp_micros(), row.id)
}

fn parse_page_token(token: &str) -> AppResult<Option<(DateTime<Utc>, String)>> {
    if token.is_empty() {
        return Ok(None);
    }
    let invalid = || AppError::BadRequest("page_token is not one this list returned".into());
    let (micros, id) = token.split_once('.').ok_or_else(invalid)?;
    let created_at = micros
        .parse::<i64>()
        .ok()
        .and_then(DateTime::from_timestamp_micros)
        .ok_or_else(invalid)?;
    if id.is_empty() {
        return Err(invalid());
    }
    Ok(Some((created_at, id.to_owned())))
}

/// Newest-first feedback for platform admins. The caller's admin standing is
/// the Connect admin mount's to enforce.
pub async fn list_feedback(
    pool: &PgPool,
    limit: i64,
    page_token: &str,
    sender: SenderFilter,
) -> AppResult<FeedbackPage> {
    if !(1..=MAX_LIST_LIMIT).contains(&limit) {
        return Err(AppError::BadRequest(
            format!("limit must be between 1 and {MAX_LIST_LIMIT}").into(),
        ));
    }
    let after = parse_page_token(page_token)?;
    let signed_in = match sender {
        SenderFilter::All => None,
        SenderFilter::SignedIn => Some(true),
        SenderFilter::Anonymous => Some(false),
    };
    let rows = sqlx::query(
        r#"SELECT f.id, f.created_at, f.user_id, u.email, f.organization_id, o.name,
                  f.message, f.cli_version, f.os, f.arch, f.placement, f.environment_id
             FROM feedback f
             LEFT JOIN users u ON u.id = f.user_id
             LEFT JOIN organizations o ON o.id = f.organization_id
            WHERE ($1::boolean IS NULL OR (f.user_id IS NOT NULL) = $1)
              AND ($2::timestamptz IS NULL OR (f.created_at, f.id) < ($2, $3))
            ORDER BY f.created_at DESC, f.id DESC
            LIMIT $4"#,
    )
    .bind(signed_in)
    .bind(after.as_ref().map(|(created_at, _)| *created_at))
    .bind(after.as_ref().map(|(_, id)| id.as_str()))
    .bind(limit + 1)
    .fetch_all(pool)
    .await
    .map_err(|error| {
        tracing::error!(%error, "admin: query feedback failed");
        AppError::InternalMsg("failed to query feedback".into())
    })?;

    let mut feedback = rows
        .iter()
        .map(|row| {
            Ok(FeedbackRow {
                id: row.try_get("id")?,
                created_at: row.try_get("created_at")?,
                user_id: row.try_get("user_id")?,
                user_email: row.try_get("email")?,
                organization_id: row.try_get("organization_id")?,
                organization_name: row.try_get("name")?,
                message: row.try_get("message")?,
                cli_version: row.try_get("cli_version")?,
                os: row.try_get("os")?,
                arch: row.try_get("arch")?,
                placement: row.try_get("placement")?,
                environment_id: row.try_get("environment_id")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(AppError::from)?;
    let next_page_token = if feedback.len() as i64 > limit {
        feedback.truncate(limit as usize);
        feedback.last().map(encode_page_token).unwrap_or_default()
    } else {
        String::new()
    };
    Ok(FeedbackPage {
        feedback,
        next_page_token,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feedback(message: &str) -> NewFeedback<'_> {
        NewFeedback {
            message,
            cli_version: "0.42.0",
            os: "linux",
            arch: "x86_64",
            ..NewFeedback::default()
        }
    }

    fn fields(result: AppResult<()>) -> Vec<String> {
        match result {
            Ok(()) => Vec::new(),
            Err(AppError::Validation { errors }) => errors
                .into_iter()
                .map(|issue| issue.path.into_owned())
                .collect(),
            Err(other) => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn a_message_holds_one_to_10240_bytes_and_not_only_whitespace() {
        assert!(fields(validate(&feedback("works"))).is_empty());
        assert!(fields(validate(&feedback(&"é".repeat(5120)))).is_empty());
        assert_eq!(fields(validate(&feedback(&"é".repeat(5121)))), ["/message"]);
        assert_eq!(fields(validate(&feedback(""))), ["/message"]);
        assert_eq!(fields(validate(&feedback(" \n\t "))), ["/message"]);
    }

    #[test]
    fn attached_fields_are_bounded() {
        let mut invalid = feedback("hi");
        invalid.cli_version = "";
        invalid.os = "linux os";
        invalid.arch = "";
        invalid.environment_id = Some("-leading-dash");
        assert_eq!(
            fields(validate(&invalid)),
            ["/cli_version", "/os", "/arch", "/environment_id"]
        );
        let mut valid = feedback("hi");
        valid.environment_id = Some("8f0c2b3e-1a2b-4c3d-9e8f-0a1b2c3d4e5f");
        valid.cli_version = "0.42.0-dev+abc";
        assert!(fields(validate(&valid)).is_empty());
        valid.cli_version = "0.42.0\n";
        assert_eq!(fields(validate(&valid)), ["/cli_version"]);
        let long_version = "1".repeat(65);
        valid.cli_version = &long_version;
        assert_eq!(fields(validate(&valid)), ["/cli_version"]);
        valid.cli_version = "1";
        let long_id = "a".repeat(129);
        valid.environment_id = Some(&long_id);
        assert_eq!(fields(validate(&valid)), ["/environment_id"]);
    }

    #[test]
    fn the_address_hash_is_keyed_and_groups_an_ipv6_64() {
        let key = ClientAddressKey::derive("synthetic-session-secret").unwrap();
        let other = ClientAddressKey::derive("another-session-secret").unwrap();
        let v4: IpAddr = "203.0.113.9".parse().unwrap();
        let hash = key.hash(v4);
        assert_eq!(hash.len(), 64);
        assert!(
            hash.bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        );
        assert!(!hash.contains("203"));
        assert_ne!(hash, other.hash(v4), "the hash depends on the key");
        assert_ne!(hash, key.hash("203.0.113.10".parse().unwrap()));
        assert_eq!(hash, key.hash("::ffff:203.0.113.9".parse().unwrap()));
        assert_eq!(
            key.hash("2001:db8:1:2::1".parse().unwrap()),
            key.hash("2001:db8:1:2:ffff::9".parse().unwrap()),
            "one /64 is one sender"
        );
        assert_ne!(
            key.hash("2001:db8:1:2::1".parse().unwrap()),
            key.hash("2001:db8:1:3::1".parse().unwrap())
        );
        assert!(ClientAddressKey::derive("").is_err());
        assert_eq!(format!("{key:?}"), "ClientAddressKey([redacted])");
    }

    #[test]
    fn a_refusal_names_when_to_retry() {
        let message =
            SubmitFeedbackError::limited_message(LimitScope::User, Duration::from_secs(1234));
        assert!(message.contains("try again in 1234 seconds"), "{message}");
        let message = SubmitFeedbackError::limited_message(
            LimitScope::AnonymousAddress,
            Duration::from_secs(5),
        );
        assert!(
            message.contains("try again in 5 seconds, or sign in"),
            "{message}"
        );
    }

    #[test]
    fn page_tokens_round_trip_and_refuse_garbage() {
        let row = FeedbackRow {
            id: "abc".into(),
            created_at: DateTime::from_timestamp_micros(1_793_712_000_123_456).unwrap(),
            user_id: None,
            user_email: None,
            organization_id: None,
            organization_name: None,
            message: "m".into(),
            cli_version: "1".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            placement: None,
            environment_id: None,
        };
        assert_eq!(
            parse_page_token(&encode_page_token(&row)).unwrap(),
            Some((row.created_at, "abc".to_owned()))
        );
        assert_eq!(parse_page_token("").unwrap(), None);
        for garbage in ["x", "12", "x.abc", "12.", "99999999999999999999.a"] {
            assert!(parse_page_token(garbage).is_err(), "{garbage}");
        }
    }
}
