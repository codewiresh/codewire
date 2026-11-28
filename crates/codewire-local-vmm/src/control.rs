//! Generated private control protocol for the per-user local supervisor and
//! per-environment runner. This is not a public Codewire platform API.

pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/codewire.local.v1.rs"));
}

impl std::fmt::Debug for v1::BootSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BootSecret")
            .field("purpose", &self.purpose)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// The owner's own SSH stream to an environment: not a remote one.
impl From<uuid::Uuid> for v1::SshStreamOpen {
    fn from(environment_id: uuid::Uuid) -> Self {
        Self {
            environment_id: environment_id.to_string(),
            remote: false,
            session_environment_id: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::v1;

    #[test]
    fn a_boot_secret_debugs_without_its_value() {
        let response = v1::GetBootSecretsResponse {
            secrets: vec![v1::BootSecret {
                purpose: v1::BootSecretPurpose::FrontDoorPairing as i32,
                value: b"boot-secret-canary".to_vec(),
            }],
        };
        let debug = format!("{response:?}");
        assert!(debug.contains("[REDACTED]"), "{debug}");
        for needle in ["boot-secret-canary", "98, 111, 111, 116"] {
            assert!(!debug.contains(needle), "{debug}");
        }
    }
}
