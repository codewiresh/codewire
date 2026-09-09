use super::*;
use crate::process_test_support::{
    assert_group_exited, observe_group, observe_process, ready_pid, wait_for_exit,
};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

const TOKEN: &str = "gho_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const PROMPT: &str = "\n! First copy your one-time code: ABCD-EFGH\nTo continue, open this URL in your web browser: https://github.com/login/device\n";
const SUCCESS: &str = "✓ Authentication complete.\n- gh config set -h github.com git_protocol https\n✓ Configured git protocol\n! Authentication credentials saved in plain text\n✓ Logged in as synthetic-user\n";
const VERSION: &str =
    "gh version 2.97.0 (2026-07-20)\nhttps://github.com/cli/cli/releases/tag/v2.97.0\n";

fn hosts(login: &str, token: &str) -> String {
    format!(
        "github.com:\n    users:\n        {login}:\n            oauth_token: {token}\n    git_protocol: https\n    oauth_token: {token}\n    user: {login}\n"
    )
}

#[test]
fn pinned_transcript_accepts_every_chunk_boundary_and_redacts_challenge() {
    let transcript = format!("{PROMPT}{SUCCESS}");
    for split in 0..=transcript.len() {
        let mut parser = ChallengeParser::new(1234);
        let first = parser.push(&transcript.as_bytes()[..split]).unwrap();
        let second = parser.push(&transcript.as_bytes()[split..]).unwrap();
        let challenge = first.or(second).unwrap();
        assert_eq!(
            challenge.verification_url(),
            "https://github.com/login/device"
        );
        assert_eq!(challenge.user_code(), "ABCD-EFGH");
        assert_eq!(challenge.expires_at_unix(), 1234);
        assert!(!format!("{challenge:?}").contains("ABCD"));
        assert_eq!(parser.finish().unwrap(), "synthetic-user");
    }
    let mut parser = ChallengeParser::new(1234);
    let mut challenges = 0;
    for byte in transcript.bytes() {
        challenges += usize::from(parser.push(&[byte]).unwrap().is_some());
    }
    assert_eq!(challenges, 1);
    parser.finish().unwrap();
}

#[test]
fn transcript_rejects_arbitrary_urls_codes_controls_duplicates_and_missing_terminal() {
    let transcript = format!("{PROMPT}{SUCCESS}");
    for changed in [
        transcript.replace("github.com/login/device", "example.test/login/device"),
        transcript.replace(
            "github.com/login/device",
            "github.com/login/device?code=ABCD",
        ),
        transcript.replace("ABCD-EFGH", "abcd-efgh"),
        transcript.replace("ABCD-EFGH", "ABCDE-FGH"),
        transcript.replace("ABCD-EFGH", "ABCD-\x1bEFG"),
        transcript.replace("synthetic-user", "user/secret"),
        transcript.replace("synthetic-user", "-user"),
        transcript.replace("synthetic-user", "user--name"),
        transcript.replace(
            "✓ Authentication complete.",
            "✓ Authentication complete.\x00",
        ),
        format!("{PROMPT}{transcript}"),
        format!("{transcript}unexpected\n"),
        transcript[..transcript.len() - 1].into(),
        PROMPT.into(),
        SUCCESS.into(),
        "x".repeat(4097),
        "\n".repeat(64 * 1024 + 1),
    ] {
        let mut parser = ChallengeParser::new(1234);
        assert!(
            parser
                .push(changed.as_bytes())
                .and_then(|_| parser.finish())
                .is_err()
        );
    }
    let mut parser = ChallengeParser::new(1234);
    assert!(
        parser
            .push(b"! First copy your one-time code: ABCD-EFGH\n")
            .unwrap()
            .is_none(),
        "never release a code before the exact fixed URL is observed"
    );
}

#[test]
fn executable_version_is_exact_and_bounded() {
    validate_version(VERSION.as_bytes()).unwrap();
    for changed in [
        VERSION.replace("2.97.0", "2.98.0"),
        VERSION.replace("2026-07-20", "development"),
        VERSION.replace("github.com", "example.test"),
        format!("{VERSION}extra\n"),
        VERSION.trim_end().to_owned(),
        "gh version 2.97.0\n".into(),
    ] {
        assert_eq!(
            validate_version(changed.as_bytes()),
            Err(GitHubEnrollmentError::UnsupportedVersion)
        );
    }
}

#[test]
fn hosts_import_accepts_only_same_verified_identity_and_ordinary_oauth_token() {
    let (token, login) = import_hosts(hosts("synthetic-user", TOKEN).as_bytes(), "synthetic-user")
        .unwrap()
        .into_parts();
    assert_eq!(&*token, TOKEN.as_bytes());
    assert_eq!(login.as_deref(), Some("synthetic-user"));
    import_hosts(hosts("\"1234\"", TOKEN).as_bytes(), "1234").unwrap();
    let original = hosts("synthetic-user", TOKEN);
    for changed in [
        original.replace("github.com", "example.test"),
        original.replace("git_protocol: https", "git_protocol: ssh"),
        original.replacen(TOKEN, "gho_Z123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", 1),
        original.replace("    user: synthetic-user", "    user: other-user"),
        original.replace("    users:", "    users: &alias"),
        format!("{original}    expires_at: 1234\n"),
        format!("{original}    expires_in: 3600\n"),
        format!("{original}    refresh_token: ghr_synthetic\n"),
        format!("{original}    user: synthetic-user\n"),
        format!("{original}{original}"),
        original.replace("gho_", "ghp_"),
        original.replace("gho_", "ghu_"),
        original.replace("gho_", "ghr_"),
        original.replace("gho_", "ghs_"),
        original.replace(TOKEN, "synthetic-token"),
        original.replace(TOKEN, "gho_short"),
        original.replace(TOKEN, &format!("gho_{}", "a".repeat(4096))),
        original.trim_end().into(),
    ] {
        assert!(import_hosts(changed.as_bytes(), "synthetic-user").is_err());
    }
    assert!(import_hosts(original.as_bytes(), "other-user").is_err());
}

#[test]
fn errors_have_no_material_or_source_chains() {
    for error in [
        GitHubEnrollmentError::Configuration,
        GitHubEnrollmentError::Unavailable,
        GitHubEnrollmentError::Cancelled,
        GitHubEnrollmentError::Expired,
        GitHubEnrollmentError::InvalidOutput,
        GitHubEnrollmentError::UnsupportedVersion,
        GitHubEnrollmentError::Failed,
        GitHubEnrollmentError::InvalidResult,
        GitHubEnrollmentError::Cleanup,
    ] {
        assert!(std::error::Error::source(&error).is_none());
        assert!(!format!("{error} {error:?}").contains(TOKEN));
    }
}

struct Fixture {
    root: tempfile::TempDir,
    owner: GitHubEnrollmentOwner,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("codewire-github-synthetic-")
            .tempdir_in("/dev/shm")
            .unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            root.path().join("hosts.fixture.yml"),
            hosts("synthetic-user", TOKEN),
        )
        .unwrap();
        let owner = GitHubEnrollmentOwner::new(
            GitHubEnrollmentConfig::new(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("src/github_enrollment/tests/synthetic-gh.sh"),
                root.path().into(),
                "/usr/bin:/bin".into(),
            )
            .unwrap(),
        );
        Self { root, owner }
    }
    fn flag(&self, flag: &str) {
        std::fs::write(self.root.path().join(flag), b"synthetic").unwrap();
    }
    fn homes(&self) -> Vec<PathBuf> {
        std::fs::read_dir(self.root.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".codewire-provider-login-")
            })
            .collect()
    }
    async fn ready(&self) -> PendingGitHubEnrollment {
        let mut pending = self.owner.start().unwrap();
        let challenge = tokio::time::timeout(Duration::from_secs(5), pending.challenge())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(challenge.user_code(), "ABCD-EFGH");
        let home = self.homes().pop().unwrap();
        let metadata = std::fs::metadata(home).unwrap();
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        pending
    }
    async fn completed(&self) -> CompletedGitHubEnrollment {
        let pending = self.ready().await;
        self.flag("release");
        tokio::time::timeout(Duration::from_secs(5), pending.complete())
            .await
            .unwrap()
            .unwrap()
    }
    async fn clean(&self) {
        self.owner.shutdown().await.unwrap();
        assert!(self.homes().is_empty());
        assert!(self.owner.start().is_err());
        assert!(!self.root.path().join("unexpected-command").exists());
    }
}

#[tokio::test]
async fn completed_import_is_single_use_and_every_disposition_cleans_without_logout() {
    for outcome in [
        GitHubPublicationOutcome::Published,
        GitHubPublicationOutcome::NotPublished,
        GitHubPublicationOutcome::Unknown,
    ] {
        let f = Fixture::new();
        let pending = f.ready().await;
        let processes = observe_group(f.root.path());
        f.flag("release");
        let mut completed = tokio::time::timeout(Duration::from_secs(5), pending.complete())
            .await
            .unwrap()
            .unwrap();
        let (token, login) = completed.take_import().unwrap().into_parts();
        assert_eq!(&*token, TOKEN.as_bytes());
        assert_eq!(login.as_deref(), Some("synthetic-user"));
        assert!(completed.take_import().is_err());
        assert!(f.homes()[0].join("login.log").exists());
        assert_group_exited(processes).await;
        completed.finish(outcome).await.unwrap();
        f.clean().await;
        assert_eq!(&*token, TOKEN.as_bytes());
    }
}

#[tokio::test]
async fn cancellation_and_dropped_waiter_retain_group_drain_before_cleanup() {
    for explicit in [true, false] {
        let f = Fixture::new();
        let pending = f.ready().await;
        let processes = observe_group(f.root.path());
        if explicit {
            pending.cancel().await.unwrap();
        } else {
            drop(pending);
        }
        f.clean().await;
        assert_group_exited(processes).await;
        assert!(!f.root.path().join("native.finished").exists());
    }
}

#[tokio::test]
async fn cancellation_before_challenge_drains_version_child() {
    let f = Fixture::new();
    f.flag("block-version");
    // Opening the shell redirection can precede writing its PID. Force that
    // state so file existence alone cannot be mistaken for child readiness.
    std::fs::write(f.root.path().join("version.pid"), b"").unwrap();
    let pending = f.owner.start().unwrap();
    let pid = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(pid) = ready_pid(&f.root.path().join("version.pid")) {
                break pid;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let process = observe_process(pid);
    pending.cancel().await.unwrap();
    f.clean().await;
    wait_for_exit(&process, Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert!(!f.root.path().join("wrapper.pid").exists());
}

#[tokio::test]
async fn unsupported_version_fails_before_login_and_malformed_result_never_completes() {
    for (flag, expected) in [
        ("wrong-version", GitHubEnrollmentError::UnsupportedVersion),
        ("unexpected-stdout", GitHubEnrollmentError::InvalidOutput),
        ("world-readable", GitHubEnrollmentError::InvalidResult),
        ("result-link", GitHubEnrollmentError::InvalidResult),
        ("fail-after-result", GitHubEnrollmentError::Failed),
    ] {
        let f = Fixture::new();
        f.flag(flag);
        f.flag("release");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), f.owner.start().unwrap().complete())
                .await
                .unwrap()
                .err(),
            Some(expected)
        );
        if flag == "wrong-version" {
            assert!(!f.root.path().join("wrapper.pid").exists());
        }
        f.clean().await;
    }
}

#[tokio::test]
async fn capacity_is_fail_fast_and_shutdown_drains_pending_and_completed_workers() {
    let f = Fixture::new();
    let pending: Vec<_> = (0..MAX_ENROLLMENTS)
        .map(|_| f.owner.start().unwrap())
        .collect();
    assert!(f.owner.start().is_err());
    f.owner.shutdown().await.unwrap();
    assert!(f.homes().is_empty());
    drop(pending);
    let f = Fixture::new();
    let completed = f.completed().await;
    f.owner.shutdown().await.unwrap();
    assert!(completed.check_active().is_err());
    completed
        .finish(GitHubPublicationOutcome::Unknown)
        .await
        .unwrap();
    f.clean().await;
}

#[tokio::test]
async fn dropped_completion_and_publication_timeout_do_not_revoke_transferred_token() {
    let f = Fixture::new();
    let mut completed = f.completed().await;
    let (token, _) = completed.take_import().unwrap().into_parts();
    drop(completed);
    f.clean().await;
    assert_eq!(&*token, TOKEN.as_bytes());

    let f = Fixture::new();
    let mut completed = f.completed().await;
    let (token, _) = completed.take_import().unwrap().into_parts();
    let stored = Mutex::new(None);
    tokio::time::pause();
    tokio::time::advance(ENROLLMENT_LIFETIME - Duration::from_secs(1)).await;
    let result = completed
        .wait_for_publication(async {
            *stored.lock().unwrap() = Some(token);
            std::future::pending::<()>().await
        })
        .await;
    assert_eq!(result, Err(GitHubEnrollmentError::Expired));
    tokio::time::resume();
    completed
        .finish(GitHubPublicationOutcome::Unknown)
        .await
        .unwrap();
    f.clean().await;
    assert_eq!(
        &**stored.lock().unwrap().as_ref().unwrap(),
        TOKEN.as_bytes()
    );
}

#[tokio::test]
async fn original_deadline_and_post_join_recheck_deny_late_success() {
    let f = Fixture::new();
    f.flag("block-version");
    let pending = f
        .owner
        .start_with_lifetime(Duration::from_millis(20))
        .unwrap();
    assert_eq!(
        pending.complete().await.err(),
        Some(GitHubEnrollmentError::Expired)
    );
    f.clean().await;
    assert_eq!(
        check_active(&CancellationToken::new(), Instant::now()),
        Err(GitHubEnrollmentError::Expired)
    );
}

#[test]
fn configuration_and_private_result_reject_ambient_paths_links_and_fifo() {
    let f = Fixture::new();
    assert!(GitHubEnrollmentConfig::new("gh".into(), f.root.path().into(), "/bin".into()).is_err());
    assert!(
        GitHubEnrollmentConfig::new("/bin/sh".into(), f.root.path().into(), ".:/bin".into())
            .is_err()
    );
    let link = f.root.path().join("runtime-link");
    symlink(f.root.path(), &link).unwrap();
    assert!(GitHubEnrollmentConfig::new("/bin/sh".into(), link, "/bin".into()).is_err());
    let home = PrivateProviderHome::create_in(f.root.path()).unwrap();
    let file = home.path().join("hosts.yml");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &file,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    assert!(read_private_file(&home, "hosts.yml", MAX_HOSTS_BYTES).is_err());
    home.remove().unwrap();
}

#[tokio::test]
async fn unproven_cleanup_latches_admission_and_staging_guard_retains_on_unwind() {
    let f = Fixture::new();
    let home = PrivateProviderHome::create_in(f.root.path()).unwrap();
    let path = home.path().to_owned();
    let guard = Staging(Some(home));
    assert!(
        std::panic::catch_unwind(|| {
            let _guard = guard;
            panic!("synthetic");
        })
        .is_err()
    );
    assert!(path.is_dir());
    f.owner.cleanup_failed.store(true, Ordering::Release);
    assert!(f.owner.start().is_err());
    assert_eq!(
        f.owner.shutdown().await,
        Err(GitHubEnrollmentError::Cleanup)
    );
}
