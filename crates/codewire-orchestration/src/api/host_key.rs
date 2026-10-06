//! The environment's SSH host key for clients (design L4): the public key the
//! workspace daemon of the environment's currently bound Pod recorded with
//! `RecordHostKey`. `cw ssh known-hosts` trusts exactly this key, so a
//! released or replaced Pod's key is never returned and no key is
//! `NOT_FOUND`, which the client treats as a refusal.

pub use crate::sandbox::host_keys::{HostKeyStore, RecordedHostKeys};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppError, AppResult};

use super::ApiState;
use super::environments::get_environment_core;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentHostKey {
    pub generation: i64,
    pub public_key_openssh: String,
}

/// Authorize exactly as GetEnvironment does, then return the key recorded by
/// the environment's currently bound Pod.
pub async fn get_environment_host_key_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
    store: &dyn HostKeyStore,
) -> AppResult<EnvironmentHostKey> {
    let environment = get_environment_core(state, user, org_id, environment_id).await?;
    let recorded = store
        .current_host_key(&environment.id)
        .await
        .map_err(|error| {
            tracing::warn!(environment_id = %environment.id, %error, "read environment host key failed");
            AppError::ServiceUnavailable("environment host key is unavailable".into())
        })?;
    current_key(recorded)
}

fn not_recorded() -> AppError {
    AppError::NotFound("no host key is recorded for the environment's bound Pod".into())
}

/// The bound Pod's recorded key, with the generation it was recorded at, only
/// as one canonical `ssh-ed25519 <base64>` line.
fn current_key(recorded: Option<(i64, String)>) -> AppResult<EnvironmentHostKey> {
    let (generation, key) = recorded.ok_or_else(not_recorded)?;
    if generation <= 0 {
        return Err(not_recorded());
    }
    let public_key_openssh = canonical_ed25519(&key).ok_or_else(|| {
        tracing::warn!("recorded environment host key is not a canonical Ed25519 key");
        not_recorded()
    })?;
    Ok(EnvironmentHostKey {
        generation,
        public_key_openssh,
    })
}

/// `ssh-ed25519 <base64 of the RFC 8709 wire blob>`, without a comment.
fn canonical_ed25519(key: &str) -> Option<String> {
    const ALGORITHM: &[u8] = b"ssh-ed25519";
    let mut fields = key.split_ascii_whitespace();
    let (Some("ssh-ed25519"), Some(encoded)) = (fields.next(), fields.next()) else {
        return None;
    };
    let blob = STANDARD.decode(encoded).ok()?;
    let mut expected = Vec::with_capacity(51);
    expected.extend_from_slice(&(ALGORITHM.len() as u32).to_be_bytes());
    expected.extend_from_slice(ALGORITHM);
    expected.extend_from_slice(&32_u32.to_be_bytes());
    (blob.len() == expected.len() + 32 && blob.starts_with(&expected))
        .then(|| format!("ssh-ed25519 {}", STANDARD.encode(&blob)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    fn key(seed: u8) -> String {
        let mut blob = Vec::new();
        blob.extend_from_slice(&11_u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32_u32.to_be_bytes());
        blob.extend_from_slice(&[seed; 32]);
        format!("ssh-ed25519 {}", STANDARD.encode(blob))
    }

    #[test]
    fn only_the_bound_pods_recorded_key_is_returned() {
        assert_eq!(
            current_key(Some((7, key(1)))).unwrap(),
            EnvironmentHostKey {
                generation: 7,
                public_key_openssh: key(1),
            }
        );
        // No key from the bound Pod, or an impossible generation, is not
        // found.
        for recorded in [None, Some((0, key(1))), Some((-7, key(1)))] {
            assert!(matches!(current_key(recorded), Err(AppError::NotFound(_))));
        }
    }

    #[test]
    fn only_a_canonical_ed25519_key_is_returned_without_its_comment() {
        assert_eq!(
            current_key(Some((3, format!("{}  daemon@env\n", key(2)))))
                .unwrap()
                .public_key_openssh,
            key(2)
        );
        let short = format!(
            "ssh-ed25519 {}",
            STANDARD.encode([&11_u32.to_be_bytes()[..], b"ssh-ed25519"].concat())
        );
        for invalid in [
            String::new(),
            "ssh-rsa AAAAB3NzaC1yc2E".into(),
            "ssh-ed25519".into(),
            "ssh-ed25519 not-base64!".into(),
            short,
            key(2).replace("ssh-ed25519 ", "ecdsa-sha2-nistp256 "),
        ] {
            assert!(
                matches!(
                    current_key(Some((3, invalid.clone()))),
                    Err(AppError::NotFound(_))
                ),
                "{invalid:?}"
            );
        }
    }

    struct Fixed(Result<Option<(i64, String)>, ()>);

    #[async_trait]
    impl HostKeyStore for Fixed {
        async fn current_host_key(
            &self,
            _environment_id: &str,
        ) -> Result<Option<(i64, String)>, sqlx::Error> {
            self.0.clone().map_err(|()| sqlx::Error::PoolTimedOut)
        }
    }

    #[tokio::test]
    async fn the_store_is_read_for_the_environment_and_fails_closed() {
        assert_eq!(
            Fixed(Ok(Some((4, key(3)))))
                .current_host_key("env")
                .await
                .unwrap(),
            Some((4, key(3)))
        );
        assert!(Fixed(Err(())).current_host_key("env").await.is_err());
        // The recorded store fails closed: an unreachable database is an
        // error, never "no key recorded".
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(200))
            .connect_lazy("postgres://synthetic@127.0.0.1:9/none")
            .unwrap();
        assert!(
            RecordedHostKeys(&pool)
                .current_host_key("env")
                .await
                .is_err()
        );
    }
}
