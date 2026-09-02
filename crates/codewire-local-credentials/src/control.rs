//! Generated private transport contract for the owner-only local credential
//! authority. This package is intentionally separate from public Codewire APIs.

pub(crate) mod v1 {
    include!(concat!(
        env!("OUT_DIR"),
        "/codewire.local.credentials.v1.rs"
    ));
}

use zeroize::Zeroize as _;

impl std::fmt::Debug for v1::AddCredentialRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AddCredentialRequest")
            .field("provider", &self.provider)
            .field("authentication_kind", &self.authentication_kind)
            .field("display_name", &self.display_name)
            .field("account_hint", &self.account_hint)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Debug for v1::RotateCredentialMaterialRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RotateCredentialMaterialRequest")
            .field("credential_id", &self.credential_id)
            .field("material", &"[REDACTED]")
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

impl Drop for v1::AddCredentialRequest {
    fn drop(&mut self) {
        self.material.zeroize();
    }
}

impl Drop for v1::RotateCredentialMaterialRequest {
    fn drop(&mut self) {
        self.material.zeroize();
    }
}
