use super::*;
use crate::process_test_support::{assert_group_exited, observe_group};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;

use base64::Engine as _;

const PROMPT: &str = "\nWelcome to Codex [v\x1b[90m0.149.0\x1b[0m]\n\x1b[90mOpenAI's command-line coding agent\x1b[0m\n\nFollow these steps to sign in with ChatGPT using device code authorization:\n\n1. Open this link in your browser and sign in to your account\n   \x1b[94mhttps://auth.openai.com/codex/device\x1b[0m\n\n2. Enter this one-time code \x1b[90m(expires in 15 minutes)\x1b[0m\n   \x1b[94mABCD-EFGH\x1b[0m\n\n\x1b[90mContinue only if you started this login in Codex. If a website or another person gave you this code, cancel.\x1b[0m\n\n";

#[test]
fn pinned_prompt_accepts_every_chunk_boundary_and_only_typed_challenge() {
    for version in ["0.149.0", "0.153.4", "0.157.0"] {
        assert_pinned_prompt(&PROMPT.replace("0.149.0", version));
    }
}

fn assert_pinned_prompt(prompt: &str) {
    for split in 0..=prompt.len() {
        let mut parser = ChallengeParser::new(1234);
        let first = parser.push(&prompt.as_bytes()[..split]).unwrap();
        let second = parser.push(&prompt.as_bytes()[split..]).unwrap();
        let challenge = first.or(second).expect("one challenge");
        parser.finish().unwrap();
        assert_eq!(
            challenge.verification_url(),
            "https://auth.openai.com/codex/device"
        );
        assert_eq!(challenge.user_code(), "ABCD-EFGH");
        assert_eq!(challenge.expires_at_unix(), 1234);
        assert!(!format!("{challenge:?}").contains("ABCD"));
    }
    let mut parser = ChallengeParser::new(1234);
    let mut count = 0;
    for byte in prompt.bytes() {
        count += usize::from(parser.push(&[byte]).unwrap().is_some());
    }
    parser.finish().unwrap();
    assert_eq!(count, 1);
}

#[test]
fn prompt_rejects_wrong_url_codes_controls_duplicates_and_truncation() {
    let cases = [
        PROMPT.replace(
            "https://auth.openai.com/codex/device",
            "https://example.test/codex/device",
        ),
        PROMPT.replace(
            "https://auth.openai.com/codex/device",
            "https://auth.openai.com/codex/device?code=ABCD",
        ),
        PROMPT.replace("ABCD-EFGH", "bad code"),
        PROMPT.replace("ABCD-EFGH", "bad/code"),
        PROMPT.replace("ABCD-EFGH", "---"),
        PROMPT.replace("ABCD-EFGH", &"A".repeat(65)),
        PROMPT.replace("\x1b[94m", "\x1b[31m"),
        PROMPT.replace("ABCD-EFGH", "ABCD\x00EFGH"),
        PROMPT.replace(
            "If a website or another person gave you this code, cancel.",
            "Continue anyway.",
        ),
        format!("{PROMPT}{PROMPT}"),
        format!("{PROMPT}raw provider output\n"),
        "x".repeat(64 * 1024 + 1),
        "x".repeat(4097),
        PROMPT[..PROMPT.len() - 3].to_owned(),
    ];
    for version in ["0.149.0", "0.153.4", "0.157.0"] {
        for input in &cases {
            let input = input.replace("0.149.0", version);
            let mut parser = ChallengeParser::new(1234);
            assert!(
                parser
                    .push(input.as_bytes())
                    .and_then(|_| parser.finish())
                    .is_err()
            );
        }
    }
    // The upstream fixture's 4+4 example is not a provider format guarantee.
    let mut parser = ChallengeParser::new(1234);
    assert_eq!(
        parser
            .push(PROMPT.replace("ABCD-EFGH", "a1-Z9-12345").as_bytes())
            .unwrap()
            .unwrap()
            .user_code(),
        "a1-Z9-12345"
    );
    parser.finish().unwrap();
}

#[test]
fn unsupported_version_and_all_errors_are_closed_and_value_blind() {
    for version in ["0.150.0", "0.157.1", "0.158.0"] {
        let mut parser = ChallengeParser::new(1234);
        assert_eq!(
            parser
                .push(PROMPT.replace("0.149.0", version).as_bytes())
                .err(),
            Some(CodexEnrollmentError::UnsupportedVersion)
        );
    }
    for error in [
        CodexEnrollmentError::Configuration,
        CodexEnrollmentError::Unavailable,
        CodexEnrollmentError::Cancelled,
        CodexEnrollmentError::Expired,
        CodexEnrollmentError::InvalidOutput,
        CodexEnrollmentError::UnsupportedVersion,
        CodexEnrollmentError::Failed,
        CodexEnrollmentError::InvalidResult,
        CodexEnrollmentError::Cleanup,
    ] {
        assert!(std::error::Error::source(&error).is_none());
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains("ABCD") && !rendered.contains("synthetic"));
    }
}

struct Fixture {
    root: tempfile::TempDir,
    owner: CodexEnrollmentOwner,
}

impl Fixture {
    fn new() -> Self {
        let root = private_root();
        let id_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "email": "synthetic@example.test",
                "https://api.openai.com/auth": { "chatgpt_account_id": "synthetic-account" }
            }))
            .unwrap(),
        );
        let auth = serde_json::to_vec(&serde_json::json!({
            "auth_mode": "chatgpt", "OPENAI_API_KEY": null,
            "tokens": {
                "id_token": format!("e30.{id_payload}.c2ln"),
                "access_token": "synthetic-access-only", "refresh_token": "synthetic-refresh-only",
                "account_id": "synthetic-account"
            }
        }))
        .unwrap();
        std::fs::write(root.path().join("synthetic-auth.fixture.json"), auth).unwrap();
        let owner = CodexEnrollmentOwner::new(
            CodexEnrollmentConfig::new(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("src/codex_enrollment/tests/synthetic-codex.sh"),
                root.path().to_owned(),
                OsString::from("/usr/bin:/bin"),
            )
            .unwrap(),
        );
        Self { root, owner }
    }

    fn release(&self) {
        std::fs::write(self.root.path().join("release"), b"synthetic release").unwrap();
    }

    fn homes(&self) -> Vec<PathBuf> {
        std::fs::read_dir(self.root.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".codewire-provider-login-")
            })
            .collect()
    }

    async fn ready(&self) -> PendingCodexEnrollment {
        let mut pending = self.owner.start().unwrap();
        let challenge = tokio::time::timeout(Duration::from_secs(5), pending.challenge())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(challenge.user_code(), "ABCD-EFGH");
        assert_eq!(self.homes().len(), 1);
        let metadata = std::fs::metadata(&self.homes()[0]).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        pending
    }

    async fn completed(&self) -> CompletedCodexEnrollment {
        let pending = self.ready().await;
        self.release();
        tokio::time::timeout(Duration::from_secs(5), pending.complete())
            .await
            .unwrap()
            .unwrap()
    }

    async fn assert_clean(&self) {
        self.owner.shutdown().await.unwrap();
        assert!(self.homes().is_empty());
        assert!(self.owner.start().is_err());
    }
}

fn private_root() -> tempfile::TempDir {
    let root = tempfile::Builder::new()
        .prefix("codewire-enrollment-synthetic-")
        .tempdir_in("/dev/shm")
        .expect("synthetic tests require tmpfs, not a persistent fallback");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    root
}

#[test]
fn shared_runtime_rejects_nonprivate_nontmpfs_symlink_and_relative_configuration() {
    let root = private_root();
    validate_private_tmpfs_runtime(root.path()).unwrap();
    let link = root.path().join("runtime-link");
    symlink(root.path(), &link).unwrap();
    assert!(validate_private_tmpfs_runtime(&link).is_err());
    assert!(validate_private_tmpfs_runtime(Path::new(".")).is_err());
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(validate_private_tmpfs_runtime(root.path()).is_err());
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let disk = tempfile::tempdir().unwrap();
    std::fs::set_permissions(disk.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let stats = rustix::fs::fstatfs(std::fs::File::open(disk.path()).unwrap()).unwrap();
    if stats.f_type != 0x0102_1994 {
        assert!(validate_private_tmpfs_runtime(disk.path()).is_err());
    }
    assert!(
        CodexEnrollmentConfig::new(
            PathBuf::from("codex"),
            root.path().to_owned(),
            OsString::from("/usr/bin:/bin")
        )
        .is_err()
    );
    assert!(
        CodexEnrollmentConfig::new(
            PathBuf::from("/bin/sh"),
            root.path().to_owned(),
            OsString::from(".:/usr/bin")
        )
        .is_err()
    );
    assert!(
        crate::provider_enrollment::resolve_provider_executable(
            "sh",
            OsString::from("/usr/bin:/bin").as_os_str()
        )
        .unwrap()
        .is_absolute()
    );
    assert!(
        crate::provider_enrollment::resolve_provider_executable(
            "../sh",
            OsString::from("/bin").as_os_str()
        )
        .is_err()
    );
}

#[test]
fn private_result_rejects_file_modes_links_fifo_size_and_removes_all_staging() {
    let root = private_root();
    let home = PrivateProviderHome::create_in(root.path()).unwrap();
    let path = home.path().join("auth.json");
    std::fs::write(&path, b"synthetic").unwrap();
    for mode in [0o644, 0o400, 0o700, 0o1600] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(read_private_file(&home, "auth.json", 100).is_err());
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        &**read_private_file(&home, "auth.json", 100).unwrap(),
        b"synthetic"
    );
    assert!(read_private_file(&home, "auth.json", 2).is_err());
    std::fs::hard_link(&path, home.path().join("hard-link")).unwrap();
    assert!(read_private_file(&home, "auth.json", 100).is_err());
    std::fs::remove_file(home.path().join("hard-link")).unwrap();
    symlink(&path, home.path().join("auth-link")).unwrap();
    assert!(read_private_file(&home, "auth-link", 100).is_err());
    rustix::fs::mknodat(
        rustix::fs::CWD,
        home.path().join("fifo"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    assert!(read_private_file(&home, "fifo", 100).is_err());
    let removed = home.path().to_owned();
    home.remove().unwrap();
    assert!(!removed.exists());
}

#[tokio::test]
async fn completed_publication_cleans_private_home_without_logout() {
    for version in ["0.149.0", "0.153.4"] {
        assert_completed_publication(version).await;
    }
}

#[tokio::test]
async fn codex_0_157_0_completes_isolated_enrollment_and_cleans_private_home() {
    tokio::time::timeout(
        Duration::from_secs(15),
        assert_completed_publication("0.157.0"),
    )
    .await
    .expect("synthetic enrollment and cleanup must finish within the bound");
}

async fn assert_completed_publication(version: &str) {
    let fixture = Fixture::new();
    if version != "0.149.0" {
        std::fs::write(
            fixture.root.path().join(format!("codex-{version}")),
            b"synthetic version",
        )
        .unwrap();
    }
    let mut completed = fixture.completed().await;
    assert_eq!(
        completed.take_import().unwrap().account_hint(),
        Some("synthetic@example.test")
    );
    assert!(completed.take_import().is_err());
    let home = fixture.homes().pop().unwrap();
    assert!(home.join("auth.json").is_file());
    assert!(home.join("codex-login.log").is_file());
    completed
        .finish(CodexPublicationOutcome::Published)
        .await
        .unwrap();
    fixture.assert_clean().await;
    assert!(!fixture.root.path().join("logout.called").exists());
}

#[tokio::test]
async fn definite_rejection_alone_attempts_logout_before_cleanup() {
    let fixture = Fixture::new();
    fixture
        .completed()
        .await
        .finish(CodexPublicationOutcome::NotPublished)
        .await
        .unwrap();
    fixture.assert_clean().await;
    assert_eq!(
        std::fs::read_to_string(fixture.root.path().join("logout.called")).unwrap(),
        "logout\n"
    );
}

#[tokio::test]
async fn ambiguous_ack_and_dropped_completion_never_revoke_stored_material() {
    for explicit in [true, false] {
        let fixture = Fixture::new();
        let mut completed = fixture.completed().await;
        let imported = completed.take_import().unwrap();
        let (bundle, _) = imported.into_parts();
        assert!(!bundle.as_bytes().is_empty());
        if explicit {
            completed
                .finish(CodexPublicationOutcome::Unknown)
                .await
                .unwrap();
        } else {
            drop(completed);
        }
        fixture.assert_clean().await;
        assert!(!fixture.root.path().join("logout.called").exists());
        // Unknown ACK cannot destroy the caller's already-transferred bundle.
        assert!(!bundle.as_bytes().is_empty());
    }
}

#[tokio::test]
async fn publication_wait_keeps_original_deadline_and_preserves_a_late_commit() {
    let fixture = Fixture::new();
    let mut completed = fixture.completed().await;
    let imported = completed.take_import().unwrap();
    let (bundle, _) = imported.into_parts();
    let stored = std::sync::Mutex::new(None);
    let (acknowledge, acknowledgement) = oneshot::channel::<()>();

    // Almost the entire original login lifetime has already elapsed. Starting
    // publication must not grant it another lifetime or wait forever for an ACK.
    tokio::time::pause();
    tokio::time::advance(ENROLLMENT_LIFETIME - Duration::from_secs(1)).await;
    {
        let publication = completed.wait_for_publication(async {
            *stored.lock().unwrap() = Some(bundle);
            acknowledgement.await
        });
        tokio::pin!(publication);
        tokio::select! {
            biased;
            result = &mut publication => panic!("publication returned early: {result:?}"),
            _ = tokio::task::yield_now() => {},
        }
        assert!(stored.lock().unwrap().is_some());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(publication.await.err(), Some(CodexEnrollmentError::Expired));
    }
    tokio::time::resume();
    completed
        .finish(CodexPublicationOutcome::Unknown)
        .await
        .unwrap();
    fixture.assert_clean().await;
    assert!(
        acknowledge.send(()).is_err(),
        "the timed-out caller cannot accept a late ACK"
    );
    assert!(
        !stored
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .as_bytes()
            .is_empty()
    );
    assert!(!fixture.root.path().join("logout.called").exists());
}

#[tokio::test]
async fn cancellation_drains_wrapper_and_native_child_before_home_cleanup() {
    let fixture = Fixture::new();
    let pending = fixture.ready().await;
    let processes = observe_group(fixture.root.path());
    tokio::time::timeout(Duration::from_secs(5), pending.cancel())
        .await
        .unwrap()
        .unwrap();
    assert!(fixture.homes().is_empty());
    assert_group_exited(processes).await;
    fixture.release();
    assert!(!fixture.root.path().join("native.finished").exists());
    fixture.assert_clean().await;
}

#[tokio::test]
async fn owner_shutdown_drains_dropped_pending_and_rejects_new_admission() {
    let fixture = Fixture::new();
    let pending = fixture.ready().await;
    let processes = observe_group(fixture.root.path());
    drop(pending);
    tokio::time::timeout(Duration::from_secs(5), fixture.owner.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert_group_exited(processes).await;
    assert!(fixture.homes().is_empty());
    assert!(fixture.owner.start().is_err());
}

#[tokio::test]
async fn original_deadline_expires_pending_exchange_and_drains_the_group() {
    let fixture = Fixture::new();
    let mut pending = fixture.owner.start().unwrap();
    // The process remains blocked after printing a valid challenge; receiving it
    // does not restart the original lifetime.
    pending.challenge().await.unwrap();
    let processes = observe_group(fixture.root.path());
    tokio::time::pause();
    tokio::time::advance(ENROLLMENT_LIFETIME).await;
    tokio::time::resume();
    let result = tokio::time::timeout(Duration::from_secs(5), pending.complete())
        .await
        .unwrap();
    assert_eq!(result.err(), Some(CodexEnrollmentError::Expired));
    assert_group_exited(processes).await;
    fixture.assert_clean().await;
}

#[tokio::test]
async fn completed_deadline_and_shutdown_deny_late_import_without_logout() {
    let fixture = Fixture::new();
    let mut completed = fixture.completed().await;
    fixture.owner.shutdown().await.unwrap();
    assert_eq!(
        completed.take_import().err(),
        Some(CodexEnrollmentError::Cancelled)
    );
    completed
        .finish(CodexPublicationOutcome::NotPublished)
        .await
        .unwrap();
    assert!(!fixture.root.path().join("logout.called").exists());

    let fixture = Fixture::new();
    let mut completed = fixture.completed().await;
    // Advance the actual fixed deadline; the handle has no deadline setter.
    tokio::time::pause();
    tokio::time::advance(ENROLLMENT_LIFETIME).await;
    tokio::time::resume();
    assert_eq!(
        completed.take_import().err(),
        Some(CodexEnrollmentError::Expired)
    );
    completed
        .finish(CodexPublicationOutcome::Unknown)
        .await
        .unwrap();
    fixture.assert_clean().await;
}

#[tokio::test]
async fn enrollment_capacity_is_finite_and_shutdown_serializes_spawn() {
    let fixture = Fixture::new();
    let mut pending = Vec::new();
    for _ in 0..MAX_ENROLLMENTS {
        pending.push(fixture.owner.start().unwrap());
    }
    assert_eq!(
        fixture.owner.start().err(),
        Some(CodexEnrollmentError::Unavailable)
    );
    drop(pending);
    fixture.assert_clean().await;
}

#[tokio::test]
async fn invalid_output_or_result_cannot_publish_and_cleans_staging() {
    for invalid_output in [true, false] {
        let fixture = Fixture::new();
        if invalid_output {
            std::fs::write(fixture.root.path().join("invalid-output"), b"synthetic").unwrap();
        } else {
            std::fs::write(
                fixture.root.path().join("synthetic-auth.fixture.json"),
                b"not provider material",
            )
            .unwrap();
        }
        fixture.release();
        let pending = fixture.owner.start().unwrap();
        let error = tokio::time::timeout(Duration::from_secs(5), pending.complete())
            .await
            .unwrap()
            .err()
            .unwrap();
        assert_eq!(
            error,
            if invalid_output {
                CodexEnrollmentError::InvalidOutput
            } else {
                CodexEnrollmentError::InvalidResult
            }
        );
        assert!(!format!("{error} {error:?}").contains("synthetic"));
        fixture.assert_clean().await;
    }
}

#[tokio::test]
async fn failed_child_with_private_result_is_definitely_unpublished_and_logs_out() {
    let fixture = Fixture::new();
    std::fs::write(fixture.root.path().join("fail-after-result"), b"synthetic").unwrap();
    fixture.release();
    let pending = fixture.owner.start().unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), pending.complete())
            .await
            .unwrap()
            .err(),
        Some(CodexEnrollmentError::Failed)
    );
    fixture.assert_clean().await;
    assert_eq!(
        std::fs::read_to_string(fixture.root.path().join("logout.called")).unwrap(),
        "logout\n"
    );
}

#[tokio::test]
async fn unproven_pipe_drain_retains_tmpfs_and_never_reuses_reaped_signal_authority() {
    let root = private_root();
    let home = PrivateProviderHome::create_in(root.path()).unwrap();
    let retained = home.path().to_owned();
    let mut command = Command::new("/bin/sleep");
    command
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .kill_on_drop(true);
    let mut group = GroupChild::spawn(&mut command).unwrap();
    let pid = group.pid.unwrap();
    // A held synthetic pipe models inability to prove stream drain without
    // creating an escaped child or weakening process-group ownership.
    let (mut held_reader, _held_writer) = tokio::io::duplex(16);
    let result = group
        .stop_and_drain_with_timeout(
            &mut held_reader,
            &mut tokio::io::empty(),
            Duration::from_millis(10),
        )
        .await;
    assert_eq!(result, Err(CodexEnrollmentError::Cleanup));
    assert!(
        group.pid.is_none(),
        "no killpg authority may survive a possible reap"
    );
    // Explicitly finish the direct child's wait even on a heavily loaded host.
    group.child.wait().await.unwrap();
    assert!(
        rustix::process::waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT
        )
        .is_err()
    );
    home.retain();
    assert!(retained.is_dir());
    drop(group);
    // The test's exact disposable root removes its retained synthetic fixture.
}
