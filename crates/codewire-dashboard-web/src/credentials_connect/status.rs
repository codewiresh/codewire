//! The status word and tone a credential's row and its profiles read.

use codewire_proto::codewire::v1::{Credential, CredentialStatus};
use connectrpc::ConnectError;

use super::invalid_metadata;

/// A subscription token this close to its recorded expiry reads Expires soon.
const EXPIRES_SOON_SECONDS: u64 = 30 * 24 * 60 * 60;

/// The status a row and its profiles read. A Claude subscription token's
/// recorded expiry is shown as Expired once it passes and as Expires soon in
/// its last thirty days; every other form reads its service status alone.
pub(super) fn credential_status_at(
    credential: &Credential,
    form: &str,
    now: u64,
) -> Result<(&'static str, &'static str), ConnectError> {
    let status = credential_status(credential)?;
    // A revoked GitHub connection no longer reaches GitHub; Disconnect
    // removes its record (#4717 C6).
    if form == "github" && credential.status == CredentialStatus::Revoked {
        return Ok(("Disconnected", "danger"));
    }
    if form != "claude-token" || credential.status != CredentialStatus::Active {
        return Ok(status);
    }
    Ok(match credential.expires_at_unix {
        Some(expiry) if expiry <= now => ("Expired", "warning"),
        Some(expiry) if expiry - now <= EXPIRES_SOON_SECONDS => ("Expires soon", "warning"),
        _ => status,
    })
}

pub(super) fn credential_status(
    credential: &Credential,
) -> Result<(&'static str, &'static str), ConnectError> {
    if credential.status == CredentialStatus::Active {
        Ok(("Active", "success"))
    } else if credential.status == CredentialStatus::Revoked {
        Ok(("Revoked", "danger"))
    } else if credential.status == CredentialStatus::Expired {
        Ok(("Expired", "warning"))
    } else if credential.status == CredentialStatus::RefreshFailed {
        // The provider refused or lost the stored refresh token; only the
        // owner can restore it. Say what to do, not what failed.
        Ok(("Reconnect needed", "warning"))
    } else {
        Err(invalid_metadata())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_proto::codewire::v1::CredentialAuthenticationKind;

    fn credential(provider: &str, status: CredentialStatus) -> Credential {
        Credential {
            provider: provider.into(),
            authentication_kind: CredentialAuthenticationKind::Oauth.into(),
            status: status.into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_revoked_github_connection_reads_disconnected_and_others_revoked() {
        let revoked = credential("github", CredentialStatus::Revoked);
        assert_eq!(
            credential_status_at(&revoked, "github", 0).unwrap(),
            ("Disconnected", "danger")
        );
        let active = credential("github", CredentialStatus::Active);
        assert_eq!(
            credential_status_at(&active, "github", 0).unwrap(),
            ("Active", "success")
        );
        let codex = credential("openai", CredentialStatus::Revoked);
        assert_eq!(
            credential_status_at(&codex, "codex", 0).unwrap(),
            ("Revoked", "danger")
        );
    }
}
