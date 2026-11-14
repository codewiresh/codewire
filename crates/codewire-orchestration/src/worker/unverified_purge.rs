//! The reconciler's purge of email sign-ups that never verify (#4541).
//!
//! At most once an hour the leader selects up to 100 unverified email
//! sign-ups older than their lifetime and deletes each through the ordinary
//! account deletion, which checks every condition again with the account's
//! row locked. `UNVERIFIED_SIGNUP_PURGE` turns it off, makes it only report
//! what it would delete (the default), or makes it delete. Logs carry counts
//! and reasons, never an address.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use codewire_server_core::account_deletion::{
    KeptReason, PurgeMode, PurgeOutcome, UNVERIFIED_SIGNUP_LIFETIME_SECS, purge_unverified_signup,
    unverified_signup_candidates, unverified_signups_kept_for_holdings,
};

use super::WorkerContext;

pub const UNVERIFIED_SIGNUP_PURGE_ENV: &str = "UNVERIFIED_SIGNUP_PURGE";
/// A shorter lifetime, for proving the purge on Dev without waiting a week.
/// Never set in Production; refused below an hour.
pub const UNVERIFIED_SIGNUP_LIFETIME_ENV: &str = "UNVERIFIED_SIGNUP_LIFETIME_SECS";

const MIN_LIFETIME_SECS: i64 = 60 * 60;
const INTERVAL: Duration = Duration::from_secs(60 * 60);
const BATCH: i64 = 100;

/// What the purge does, from `UNVERIFIED_SIGNUP_PURGE`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PurgeSetting {
    Off,
    #[default]
    Report,
    Enforce,
}

/// The purge's configuration, read once at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnverifiedSignupPurge {
    pub setting: PurgeSetting,
    pub lifetime_secs: i64,
}

impl Default for UnverifiedSignupPurge {
    fn default() -> Self {
        Self {
            setting: PurgeSetting::default(),
            lifetime_secs: UNVERIFIED_SIGNUP_LIFETIME_SECS,
        }
    }
}

impl UnverifiedSignupPurge {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::parse(
            std::env::var(UNVERIFIED_SIGNUP_PURGE_ENV).ok().as_deref(),
            std::env::var(UNVERIFIED_SIGNUP_LIFETIME_ENV)
                .ok()
                .as_deref(),
        )
        .map_err(anyhow::Error::msg)
    }

    fn parse(setting: Option<&str>, lifetime: Option<&str>) -> Result<Self, String> {
        let setting = match setting.map(str::trim).unwrap_or_default() {
            "" | "report" => PurgeSetting::Report,
            "off" => PurgeSetting::Off,
            "enforce" => PurgeSetting::Enforce,
            other => {
                return Err(format!(
                    "{UNVERIFIED_SIGNUP_PURGE_ENV} must be off, report or enforce, not {other:?}"
                ));
            }
        };
        let lifetime_secs = match lifetime.map(str::trim).unwrap_or_default() {
            "" => UNVERIFIED_SIGNUP_LIFETIME_SECS,
            text => match text.parse::<i64>() {
                Ok(secs) if secs >= MIN_LIFETIME_SECS => secs,
                _ => {
                    return Err(format!(
                        "{UNVERIFIED_SIGNUP_LIFETIME_ENV} must be a whole number of seconds, \
                         at least {MIN_LIFETIME_SECS}"
                    ));
                }
            },
        };
        Ok(Self {
            setting,
            lifetime_secs,
        })
    }
}

/// When this process last ran the purge; the reconciler runs every 30 s.
static LAST_RUN: Mutex<Option<Instant>> = Mutex::new(None);

fn due(now: Instant) -> bool {
    let Ok(mut last) = LAST_RUN.lock() else {
        return false;
    };
    match *last {
        Some(previous) if now.duration_since(previous) < INTERVAL => false,
        _ => {
            *last = Some(now);
            true
        }
    }
}

/// Counts from one run, logged together.
#[derive(Debug, Default, PartialEq, Eq)]
struct Tally {
    deleted: usize,
    would_delete: usize,
    kept: usize,
    failed: usize,
}

pub(super) async fn purge_unverified_signups(ctx: &WorkerContext) {
    let config = ctx.unverified_signup_purge;
    let mode = match config.setting {
        PurgeSetting::Off => return,
        PurgeSetting::Report => PurgeMode::Report,
        PurgeSetting::Enforce => PurgeMode::Enforce,
    };
    if !due(Instant::now()) {
        return;
    }
    let candidates =
        match unverified_signup_candidates(&ctx.pool, config.lifetime_secs, BATCH).await {
            Ok(candidates) => candidates,
            Err(error) => {
                tracing::error!(error = %error, "reconciler: select unverified sign-ups");
                return;
            }
        };
    let mut tally = Tally::default();
    for user_id in &candidates {
        match purge_unverified_signup(&ctx.pool, user_id, config.lifetime_secs, mode).await {
            Ok(PurgeOutcome::Deleted(operation)) => {
                tally.deleted += 1;
                tracing::info!(
                    operation_id = operation.id,
                    "reconciler: unverified sign-up deletion begun"
                );
            }
            Ok(PurgeOutcome::WouldDelete) => tally.would_delete += 1,
            Ok(PurgeOutcome::Kept(reason)) => {
                tally.kept += 1;
                tracing::info!(
                    reason = kept_reason(reason),
                    "reconciler: unverified sign-up kept"
                );
            }
            Err(error) => {
                tally.failed += 1;
                tracing::warn!(error = %error, "reconciler: unverified sign-up purge failed");
            }
        }
    }
    let held = unverified_signups_kept_for_holdings(&ctx.pool, config.lifetime_secs)
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(error = %error, "reconciler: count unverified sign-ups that hold something");
            -1
        });
    tracing::info!(
        setting = ?config.setting,
        lifetime_secs = config.lifetime_secs,
        deleted = tally.deleted,
        would_delete = tally.would_delete,
        kept = tally.kept,
        failed = tally.failed,
        held,
        "reconciler: unverified sign-up purge"
    );
}

fn kept_reason(reason: KeptReason) -> &'static str {
    match reason {
        KeptReason::Gone => "gone",
        KeptReason::Verified => "verified",
        KeptReason::Vouched => "vouched",
        KeptReason::Admin => "admin",
        KeptReason::Young => "young",
        KeptReason::NotEmailSignUp => "not_email_sign_up",
        KeptReason::Holds(holding) => holding.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_purge_reports_unless_turned_off_or_on_and_a_typo_is_refused() {
        let parse = |setting, lifetime| UnverifiedSignupPurge::parse(setting, lifetime);
        for value in [None, Some(""), Some(" report ")] {
            assert_eq!(
                parse(value, None),
                Ok(UnverifiedSignupPurge::default()),
                "{value:?}"
            );
        }
        assert_eq!(parse(Some("off"), None).unwrap().setting, PurgeSetting::Off);
        assert_eq!(
            parse(Some("enforce"), None).unwrap().setting,
            PurgeSetting::Enforce
        );
        assert!(parse(Some("on"), None).is_err());
        assert!(parse(Some("Enforce"), None).is_err());
    }

    #[test]
    fn the_lifetime_is_seven_days_unless_a_shorter_one_of_an_hour_or_more_is_set() {
        let lifetime = |text| UnverifiedSignupPurge::parse(None, text).map(|c| c.lifetime_secs);
        assert_eq!(lifetime(None), Ok(7 * 24 * 60 * 60));
        assert_eq!(lifetime(Some("3600")), Ok(3600));
        for refused in ["3599", "0", "-1", "1h", "7.5"] {
            assert!(lifetime(Some(refused)).is_err(), "{refused}");
        }
    }

    #[test]
    fn each_reason_has_a_stable_log_name() {
        use codewire_server_core::account_deletion::Holding;
        assert_eq!(
            kept_reason(KeptReason::Holds(Holding::ProviderSignIn)),
            "provider_sign_in"
        );
        assert_eq!(kept_reason(KeptReason::Verified), "verified");
    }
}
