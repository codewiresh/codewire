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

impl std::fmt::Debug for v1::AddSshCredentialRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AddSshCredentialRequest")
            .field("name", &self.name)
            .field("private_key", &"[REDACTED]")
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_at_unix", &self.expires_at_unix)
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

impl Drop for v1::AddSshCredentialRequest {
    fn drop(&mut self) {
        self.private_key.zeroize();
        if let Some(passphrase) = &mut self.passphrase {
            passphrase.zeroize();
        }
    }
}

impl Drop for v1::RotateCredentialMaterialRequest {
    fn drop(&mut self) {
        self.material.zeroize();
    }
}

fn zeroize_workload_secret_value(value: &mut Vec<u8>) {
    value.zeroize();
}

impl Drop for v1::SetUserWorkloadSecretRequest {
    fn drop(&mut self) {
        zeroize_workload_secret_value(&mut self.value);
    }
}

impl Drop for v1::SetProjectWorkloadSecretRequest {
    fn drop(&mut self) {
        zeroize_workload_secret_value(&mut self.value);
    }
}

#[cfg(test)]
mod tests {
    use super::{v1, zeroize_workload_secret_value};

    #[allow(drop_bounds)]
    fn assert_explicit_drop<T: Drop>() {}

    #[test]
    fn user_workload_secret_drop_path_zeroizes_value_allocation() {
        let mut request = v1::SetUserWorkloadSecretRequest {
            key: "API_TOKEN".to_owned(),
            value: b"user-workload-secret".to_vec(),
        };
        let capacity = request.value.capacity();

        assert_explicit_drop::<v1::SetUserWorkloadSecretRequest>();
        zeroize_workload_secret_value(&mut request.value);

        assert!(request.value.is_empty());
        assert_eq!(request.value.capacity(), capacity);
        assert_eq!(request.key, "API_TOKEN");
    }

    #[test]
    fn project_workload_secret_drop_path_zeroizes_value_allocation() {
        let mut request = v1::SetProjectWorkloadSecretRequest {
            project_id: "0195f818-1fb2-7fc2-9157-a31895670cc8".to_owned(),
            key: "DATABASE_PASSWORD".to_owned(),
            value: b"project-workload-secret".to_vec(),
        };
        let capacity = request.value.capacity();

        assert_explicit_drop::<v1::SetProjectWorkloadSecretRequest>();
        zeroize_workload_secret_value(&mut request.value);

        assert!(request.value.is_empty());
        assert_eq!(request.value.capacity(), capacity);
        assert_eq!(request.key, "DATABASE_PASSWORD");
        assert_eq!(request.project_id, "0195f818-1fb2-7fc2-9157-a31895670cc8");
    }
}
