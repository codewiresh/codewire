//! Env-clear official-login-shaped synthetic child, confined to private tmpfs.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use base64::Engine as _;
use codewire_credential_broker::codex_enrollment::CodexEnrollmentConfig;
use codewire_credential_broker::github_enrollment::GitHubEnrollmentConfig;
use codewire_credential_broker::provider_enrollment::validate_private_tmpfs_runtime;
use serde_json::json;
use tempfile::TempDir;

use super::super::RuntimeError;
use super::provider::{ACCOUNT, access_token, refresh_token};

const SCRIPT: &str = include_str!(
    "../../../../codewire-credential-broker/src/codex_enrollment/tests/synthetic-codex.sh"
);
const GITHUB_SCRIPT: &str = include_str!(
    "../../../../codewire-credential-broker/src/github_enrollment/tests/synthetic-gh.sh"
);

pub(super) struct Fixture {
    directory: TempDir,
}

impl Fixture {
    pub(super) fn create(
        runtime: &Path,
    ) -> Result<(Self, CodexEnrollmentConfig, GitHubEnrollmentConfig), RuntimeError> {
        let mut directory = tempfile::Builder::new()
            .prefix("kind-credential-fixture-")
            .permissions(std::fs::Permissions::from_mode(0o700))
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
        let github_token = "gho_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let github_hosts = format!(
            "github.com:\n    users:\n        synthetic-user:\n            oauth_token: {github_token}\n    git_protocol: https\n    oauth_token: {github_token}\n    user: synthetic-user\n"
        );
        for (name, bytes, mode) in [
            ("codex", SCRIPT.as_bytes(), 0o700),
            ("gh", GITHUB_SCRIPT.as_bytes(), 0o700),
            ("hosts.fixture.yml", github_hosts.as_bytes(), 0o600),
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
        let github = GitHubEnrollmentConfig::new(
            directory.path().join("gh"),
            directory.path().to_owned(),
            "/usr/bin:/bin".into(),
        )
        .map_err(|_| RuntimeError::Enrollment)?;
        // Once handed to the runtime, an implicit drop cannot prove drain.
        // Retain on cancellation/unwind too; only explicit success may close.
        directory.disable_cleanup(true);
        Ok((Self { directory }, config, github))
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

#[cfg(target_os = "linux")]
#[test]
fn fixture_is_private_with_permissive_umask() {
    const CHILD: &str = "CODEWIRE_KIND_FIXTURE_MODE_CHILD";
    const TEST: &str = "runtime::kind::enrollment::fixture_is_private_with_permissive_umask";
    if std::env::var_os(CHILD).is_none() {
        // A process umask is global: isolate it from the parallel test runner.
        // The child receives no ambient homes, credentials or runtime paths.
        let result = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                "umask 022; exec \"$1\" --exact \"$2\" --nocapture",
                "fixture-mode",
            ])
            .arg(std::env::current_exe().unwrap())
            .arg(TEST)
            .env_clear()
            .env(CHILD, "1")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "isolated fixture mode check failed: {}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr),
        );
        assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed; 0 failed"));
        return;
    }
    let runtime = tempfile::Builder::new()
        .prefix("codewire-kind-fixture-mode-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/dev/shm")
        .unwrap();
    let (fixture, _codex_config, _github_config) = Fixture::create(runtime.path()).unwrap();
    validate_private_tmpfs_runtime(fixture.directory.path()).unwrap();
    assert_eq!(
        fixture
            .directory
            .path()
            .metadata()
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700,
    );
    fixture.close().unwrap();
}
