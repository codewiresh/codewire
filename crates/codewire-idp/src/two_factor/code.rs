//! A fresh second-factor code: an authenticator code in a later time step than
//! any already accepted, or an unused recovery code. Authenticator replacement
//! and adding a password both check one against the account's factor row,
//! locked, and record what was used only once every other check has passed,
//! so a refused request spends nothing.

use codewire_server_core::AppError;
use sqlx::{Postgres, Transaction};

use super::{constant_time_eq, current_totp_step, decrypt, encrypt, record_totp_step};
use crate::auth_session::unavailable;

pub(crate) const TOTP_DIGITS: usize = 6;
pub(crate) const RECOVERY_CODE_LENGTH: usize = 10;

pub(crate) fn compact(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect()
}

pub(crate) enum ProofKind {
    Authenticator(String),
    RecoveryCode(String),
    Unrecognized,
}

/// Accept a code as people type it: spaces and hyphens are ignored and a
/// recovery code is case-insensitive.
pub(crate) fn classify_proof(proof: &str) -> ProofKind {
    let proof = compact(proof);
    if proof.len() == TOTP_DIGITS && proof.bytes().all(|b| b.is_ascii_digit()) {
        ProofKind::Authenticator(proof)
    } else if proof.len() == RECOVERY_CODE_LENGTH && proof.bytes().all(|b| b.is_ascii_hexdigit()) {
        ProofKind::RecoveryCode(proof.to_ascii_lowercase())
    } else {
        ProofKind::Unrecognized
    }
}

/// The account's enrolled factor, read under its row lock. Callers hold the
/// account lock first, as every factor mutation does.
pub(crate) struct Factor {
    secret: String,
    encrypted_codes: Option<String>,
    last_step: Option<i64>,
}

/// `None` when the account has no enrolled factor.
pub(crate) async fn lock_factor(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
    session_secret: &str,
) -> Result<Option<Factor>, AppError> {
    let factor: Option<(Option<String>, Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT secret, backup_codes, last_totp_step FROM two_factor WHERE user_id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| unavailable())?;
    let Some((Some(encrypted_secret), encrypted_codes, last_step)) = factor else {
        return Ok(None);
    };
    let secret = decrypt(&encrypted_secret, session_secret).map_err(|_| unavailable())?;
    Ok(Some(Factor {
        secret,
        encrypted_codes,
        last_step,
    }))
}

/// What a code proves, before anything is recorded.
pub(crate) struct FactorCode {
    accepted_step: Option<i64>,
    remaining_codes: Option<Vec<String>>,
}

impl FactorCode {
    pub(crate) fn accepted(&self) -> bool {
        self.accepted_step.is_some() || self.remaining_codes.is_some()
    }

    pub(crate) fn used_recovery_code(&self) -> bool {
        self.remaining_codes.is_some()
    }

    /// Spend the code: remember the accepted step so it can't be used again,
    /// or store the recovery codes that remain.
    pub(crate) async fn record(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        session_secret: &str,
        user_id: &str,
    ) -> Result<(), AppError> {
        if let Some(step) = self.accepted_step {
            record_totp_step(tx, user_id, step).await?;
        }
        if let Some(codes) = &self.remaining_codes {
            store_recovery_codes(tx, session_secret, user_id, codes).await?;
        }
        Ok(())
    }
}

/// Check `proof` against the locked factor. Every candidate is compared in
/// constant time; nothing is recorded here.
pub(crate) fn check(factor: &Factor, proof: &str, email: &str, session_secret: &str) -> FactorCode {
    let mut accepted_step = None;
    let mut remaining_codes = None;
    match classify_proof(proof) {
        ProofKind::Authenticator(code) => {
            accepted_step = current_totp_step(&code, &factor.secret, email)
                .filter(|step| factor.last_step.is_none_or(|last| *step > last));
        }
        ProofKind::RecoveryCode(code) => {
            let codes = factor
                .encrypted_codes
                .as_deref()
                .and_then(|codes| decrypt(codes, session_secret).ok())
                .and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok())
                .unwrap_or_default();
            let mut matched = None;
            for (index, candidate) in codes.iter().enumerate() {
                if constant_time_eq(candidate.as_bytes(), code.as_bytes()) {
                    matched = Some(index);
                }
            }
            if let Some(index) = matched {
                let mut codes = codes;
                codes.remove(index);
                remaining_codes = Some(codes);
            }
        }
        ProofKind::Unrecognized => {}
    }
    FactorCode {
        accepted_step,
        remaining_codes,
    }
}

pub(crate) async fn store_recovery_codes(
    tx: &mut Transaction<'_, Postgres>,
    session_secret: &str,
    user_id: &str,
    codes: &[String],
) -> Result<(), AppError> {
    let json = serde_json::to_string(codes).map_err(|_| unavailable())?;
    let encrypted = encrypt(&json, session_secret).map_err(|_| unavailable())?;
    let updated = sqlx::query("UPDATE two_factor SET backup_codes = $2 WHERE user_id = $1")
        .bind(user_id)
        .bind(encrypted)
        .execute(&mut **tx)
        .await
        .map_err(|_| unavailable())?;
    if updated.rows_affected() != 1 {
        return Err(unavailable());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proofs_are_classified_without_guessing() {
        assert!(
            matches!(classify_proof(" 123 456 "), ProofKind::Authenticator(code) if code == "123456")
        );
        assert!(
            matches!(classify_proof("ABCDEF0123"), ProofKind::RecoveryCode(code) if code == "abcdef0123")
        );
        assert!(
            matches!(classify_proof("abcde-f0123"), ProofKind::RecoveryCode(code) if code == "abcdef0123")
        );
        assert!(matches!(classify_proof("1234567"), ProofKind::Unrecognized));
        assert!(matches!(classify_proof("12345a"), ProofKind::Unrecognized));
        assert!(matches!(
            classify_proof("ghijklmnop"),
            ProofKind::Unrecognized
        ));
    }
}
