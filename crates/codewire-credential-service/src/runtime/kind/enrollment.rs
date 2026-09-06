//! Env-clear official-login-shaped synthetic child, confined to private tmpfs.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use base64::Engine as _;
use codewire_credential_broker::codex_enrollment::CodexEnrollmentConfig;
use codewire_credential_broker::provider_enrollment::validate_private_tmpfs_runtime;
use serde_json::json;
use tempfile::TempDir;

use super::super::RuntimeError;
use super::provider::{ACCOUNT, access_token, refresh_token};

const SCRIPT: &str = include_str!(
    "../../../../codewire-credential-broker/src/codex_enrollment/tests/synthetic-codex.sh"
);

pub(super) struct Fixture {
    directory: TempDir,
}

impl Fixture {
    pub(super) fn create(runtime: &Path) -> Result<(Self, CodexEnrollmentConfig), RuntimeError> {
        let mut directory = tempfile::Builder::new()
            .prefix("kind-credential-fixture-")
            .tempdir_in(runtime)
            .map_err(|_| RuntimeError::Enrollment)?;
        validate_private_tmpfs_runtime(directory.path()).map_err(|_| RuntimeError::Enrollment)?;
        let id_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
            "email":"kind-fixture@example.test", "https://api.openai.com/auth":{"chatgpt_account_id":ACCOUNT}
        })).map_err(|_| RuntimeError::Enrollment)?);
        let access = access_token(0).map_err(|_| RuntimeError::Enrollment)?;
        let auth = serde_json::to_vec(&json!({"auth_mode":"chatgpt","OPENAI_API_KEY":null,
            "tokens":{"id_token":format!("e30.{id_payload}.synthetic-kind-signature"),"access_token":access,
            "refresh_token":refresh_token(0),"account_id":ACCOUNT}})).map_err(|_| RuntimeError::Enrollment)?;
        let script = directory.path().join("codex");
        for (name, bytes, mode) in [
            ("codex", SCRIPT.as_bytes(), 0o700),
            ("synthetic-auth.fixture.json", auth.as_slice(), 0o600),
            // Device completion is automatic in this non-network fixture.
            // The real enrollment owner still emits its challenge first.
            (
                "release",
                b"synthetic-kind-device-completion".as_slice(),
                0o600,
            ),
        ] {
            let path = directory.path().join(name);
            std::fs::write(&path, bytes).map_err(|_| RuntimeError::Enrollment)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .map_err(|_| RuntimeError::Enrollment)?;
        }
        let config =
            CodexEnrollmentConfig::new(script, directory.path().to_owned(), "/usr/bin:/bin".into())
                .map_err(|_| RuntimeError::Enrollment)?;
        // Once handed to the runtime, an implicit drop cannot prove drain.
        // Retain on cancellation/unwind too; only explicit success may close.
        directory.disable_cleanup(true);
        Ok((Self { directory }, config))
    }

    pub(super) fn close(self) -> Result<(), RuntimeError> {
        // TempDir::close reports removal failures without a Drop retry. Any
        // remaining files stay in private tmpfs, and no path enters the error.
        self.directory.close().map_err(|_| RuntimeError::Cleanup)
    }

    pub(super) fn retain(self) {
        let _ = self.directory.keep();
    }
}
