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

impl std::fmt::Debug for v1::BrokerCredentialRefreshCommitRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerCredentialRefreshCommitRequest")
            .field("refresh_id", &self.refresh_id)
            .field("request_id", &self.request_id)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

impl Drop for v1::BrokerCredentialRefreshCommitRequest {
    fn drop(&mut self) {
        self.material.zeroize();
    }
}

impl std::fmt::Debug for v1::RepositoryCredentialLeaseResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RepositoryCredentialLeaseResponse")
            .field("credential", &self.credential)
            .field("profile_id", &self.profile_id)
            .field("profile_revision", &self.profile_revision)
            .field("permission", &self.permission)
            .field("material_generation", &self.material_generation)
            .field("source", &self.source)
            .field("branch", &self.branch)
            .field("revision", &self.revision)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

impl Drop for v1::RepositoryCredentialLeaseResponse {
    fn drop(&mut self) {
        self.material.zeroize();
    }
}

impl std::fmt::Debug for v1::BoundSecretLeaseResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundSecretLeaseResponse")
            .field("refusal", &self.refusal)
            .field("binding", &self.binding)
            .field("value_version", &self.value_version)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl Drop for v1::BoundSecretLeaseResponse {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl std::fmt::Debug for v1::RevocationCredentialLeaseResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RevocationCredentialLeaseResponse")
            .field("credential_id", &self.credential_id)
            .field("material_generation", &self.material_generation)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

impl Drop for v1::RevocationCredentialLeaseResponse {
    fn drop(&mut self) {
        self.material.zeroize();
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

impl std::fmt::Debug for v1::BrokerBootSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerBootSecret")
            .field("purpose", &self.purpose)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{v1, zeroize_workload_secret_value};

    #[test]
    fn a_refresh_commit_debugs_without_its_material() {
        let request = v1::BrokerCredentialRefreshCommitRequest {
            refresh_id: "refresh".into(),
            request_id: "request".into(),
            material: b"refreshed-bundle-canary".to_vec(),
        };
        let printed = format!("{request:?}");
        assert!(printed.contains("refresh"), "{printed}");
        assert!(!printed.contains("refreshed-bundle-canary"), "{printed}");
        assert!(!printed.contains("114, 101, 102"), "{printed}");
    }

    /// A bound secret's lease reply (#4003) prints everything but its value,
    /// in neither its text nor its bytes, and zeroizes the value it drops.
    #[test]
    fn a_bound_secret_lease_debugs_without_its_value() {
        let response = v1::BoundSecretLeaseResponse {
            refusal: 0,
            binding: "{}".into(),
            value_version: 3,
            value: b"bound-value-canary".to_vec(),
        };
        let printed = format!("{response:?}");
        assert!(printed.contains("value_version: 3"), "{printed}");
        assert!(printed.contains("[REDACTED]"), "{printed}");
        assert!(!printed.contains("bound-value-canary"), "{printed}");
        assert!(!printed.contains("98, 111, 117"), "{printed}");
    }

    #[test]
    fn executor_leases_debug_without_their_material() {
        let repository = v1::RepositoryCredentialLeaseResponse {
            credential: None,
            profile_id: "profile".into(),
            profile_revision: 1,
            permission: None,
            material_generation: 2,
            source: "https://github.com/codewire/codewire".into(),
            branch: String::new(),
            revision: String::new(),
            material: b"repository-lease-canary".to_vec(),
        };
        let revocation = v1::RevocationCredentialLeaseResponse {
            credential_id: "credential".into(),
            material_generation: 3,
            material: b"revocation-lease-canary".to_vec(),
        };
        for printed in [format!("{repository:?}"), format!("{revocation:?}")] {
            assert!(printed.contains("[REDACTED]"), "{printed}");
            for needle in ["lease-canary", "108, 101, 97, 115, 101"] {
                assert!(!printed.contains(needle), "{printed}");
            }
        }
    }

    #[test]
    fn an_ensure_request_debugs_without_its_boot_secrets() {
        let request = v1::EnsureEnvironmentBrokerRequest {
            boot_secrets: vec![v1::BrokerBootSecret {
                purpose: v1::BrokerBootSecretPurpose::FrontDoorPairing as i32,
                value: b"boot-secret-canary".to_vec(),
            }],
            ..Default::default()
        };
        let debug = format!("{request:?}");
        assert!(debug.contains("[REDACTED]"), "{debug}");
        for needle in ["boot-secret-canary", "98, 111, 111, 116"] {
            assert!(!debug.contains(needle), "{debug}");
        }
    }

    #[allow(drop_bounds)]
    fn assert_explicit_drop<T: Drop>() {}

    #[test]
    fn user_workload_secret_drop_path_zeroizes_value_allocation() {
        let mut request = v1::SetUserWorkloadSecretRequest {
            key: "API_TOKEN".to_owned(),
            value: b"user-workload-secret".to_vec(),
            binding: None,
            plain: false,
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
            binding: None,
            plain: false,
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
