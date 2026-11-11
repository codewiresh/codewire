//! The host session's storage and proof (#3609, slice 1): what
//! `HostAgentService.AttachHost` reads and writes.
//!
//! A host authenticates as itself. It signs a fresh challenge with the key it
//! enrolled ([`super::hosts`]), and every message it sends after that renews
//! `last_seen_at`, which is all "online" means. Each renewal is written only
//! while the host is not revoked, so a revocation is noticed at the host's
//! next message.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use sqlx::PgPool;

use super::hosts::HostPlatform;

/// The first line of the statement a host signs to attach.
pub const ATTACH_STATEMENT_CONTEXT: &str = "codewire-host-attach-v1";
/// How often the host pings: a third of the offline window, the Mesh rule.
pub const PING_INTERVAL_SECS: u32 = 15;
/// How often an attached host proves its key again.
pub const RECHALLENGE_INTERVAL_SECS: u32 = 600;
/// How long a host has to answer a challenge.
pub const PROOF_TIMEOUT_SECS: u32 = 30;
/// The bytes in a challenge nonce.
pub const NONCE_BYTES: usize = 32;

/// The bytes a host signs to answer `nonce`.
pub fn attach_statement(host_id: &str, nonce: &[u8]) -> Vec<u8> {
    let nonce: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{ATTACH_STATEMENT_CONTEXT}\n{host_id}\n{nonce}\n").into_bytes()
}

/// A fresh challenge.
pub fn new_nonce() -> [u8; NONCE_BYTES] {
    let mut nonce = [0; NONCE_BYTES];
    getrandom::fill(&mut nonce).expect("the operating system's random source");
    nonce
}

/// What the session needs to know about a host to admit it.
#[derive(Clone, Debug)]
pub struct AttachingHost {
    pub id: String,
    pub public_key: VerifyingKey,
    pub platform: Option<HostPlatform>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// A host row as the session reads it: ID, key, platform and revocation.
type AttachingRow = (String, Vec<u8>, String, Option<DateTime<Utc>>);

/// The host a session names, if one exists. A malformed ID names none.
pub async fn attaching_host(pool: &PgPool, host_id: &str) -> sqlx::Result<Option<AttachingHost>> {
    if uuid::Uuid::parse_str(host_id).is_err() {
        return Ok(None);
    }
    let row: Option<AttachingRow> =
        sqlx::query_as("SELECT id, public_key, platform, revoked_at FROM hosts WHERE id = $1")
            .bind(host_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.and_then(|(id, key, platform, revoked_at)| {
        let key = VerifyingKey::from_bytes(&<[u8; 32]>::try_from(key.as_slice()).ok()?).ok()?;
        Some(AttachingHost {
            id,
            public_key: key,
            platform: HostPlatform::parse(&platform),
            revoked_at,
        })
    }))
}

/// Whether `signature` signs the attach statement for `nonce` with the
/// host's key.
pub fn proves_key(host: &AttachingHost, nonce: &[u8], signature: &[u8]) -> bool {
    let Ok(signature) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    host.public_key
        .verify_strict(
            &attach_statement(&host.id, nonce),
            &Signature::from_bytes(&signature),
        )
        .is_ok()
}

/// Records that the host was just heard from. False when the host has been
/// revoked or removed since, and the session must end.
pub async fn heard_from(pool: &PgPool, host_id: &str) -> sqlx::Result<bool> {
    let touched =
        sqlx::query("UPDATE hosts SET last_seen_at = now() WHERE id = $1 AND revoked_at IS NULL")
            .bind(host_id)
            .execute(pool)
            .await?;
    Ok(touched.rows_affected() == 1)
}

/// Records the capability version a host reports, and that it was heard
/// from. False as for [`heard_from`].
pub async fn record_hello(
    pool: &PgPool,
    host_id: &str,
    capability_version: i32,
) -> sqlx::Result<bool> {
    let updated = sqlx::query(
        "UPDATE hosts SET capability_version = $2, last_seen_at = now(), updated_at = now()
          WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(host_id)
    .bind(capability_version)
    .execute(pool)
    .await?;
    Ok(updated.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::super::hosts::OFFLINE_AFTER_SECS;
    use super::*;

    fn host(key: &SigningKey) -> AttachingHost {
        AttachingHost {
            id: "00000000-0000-4000-8000-000000000001".into(),
            public_key: key.verifying_key(),
            platform: Some(HostPlatform::LinuxX86_64Kvm),
            revoked_at: None,
        }
    }

    #[test]
    fn the_attach_statement_binds_host_and_nonce() {
        assert_eq!(
            attach_statement("host-1", &[0xab, 0x01]),
            b"codewire-host-attach-v1\nhost-1\nab01\n"
        );
    }

    #[test]
    fn only_the_hosts_key_over_this_nonce_proves_it() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let host = host(&key);
        let nonce = new_nonce();
        let signature = key.sign(&attach_statement(&host.id, &nonce)).to_bytes();
        assert!(proves_key(&host, &nonce, &signature));
        // Another nonce, another host ID, another key, or a short signature
        // proves nothing.
        assert!(!proves_key(&host, &new_nonce(), &signature));
        let other_id = key.sign(&attach_statement("another", &nonce)).to_bytes();
        assert!(!proves_key(&host, &nonce, &other_id));
        let other_key = SigningKey::from_bytes(&[8; 32])
            .sign(&attach_statement(&host.id, &nonce))
            .to_bytes();
        assert!(!proves_key(&host, &nonce, &other_key));
        assert!(!proves_key(&host, &nonce, &signature[..63]));
        // An enrollment signature is not an attach proof.
        let enrollment = key
            .sign(&super::super::hosts::enrollment_statement(
                "org",
                "user",
                &key.verifying_key().to_bytes(),
            ))
            .to_bytes();
        assert!(!proves_key(&host, &nonce, &enrollment));
    }

    #[test]
    fn nonces_are_fresh() {
        assert_ne!(new_nonce(), new_nonce());
    }

    #[test]
    fn pings_come_three_times_per_offline_window() {
        assert_eq!(PING_INTERVAL_SECS * 3, OFFLINE_AFTER_SECS.unsigned_abs());
    }
}
