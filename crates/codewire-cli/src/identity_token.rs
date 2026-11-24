//! `cw identity token --resource URI` (`docs/dev/SANDBOX-IDENTITY.md`, "In
//! the Sandbox"): the Sandbox's identity token for one registered audience,
//! from the daemon's identity socket, on stdout with no newline. A refusal
//! goes to stderr with its name. Outside a cloud Sandbox there is no socket,
//! and the command says so and exits 2.

use std::fmt;
use std::io::Write as _;
use std::path::Path;

use clap::Args;

/// The exit status outside a cloud Sandbox.
pub const OUTSIDE_SANDBOX_EXIT_CODE: i32 = 2;

#[derive(Debug, Args)]
pub(crate) struct IdentityTokenArgs {
    #[arg(
        long,
        value_name = "URI",
        help = "The audience, as your organization registered it (https://…)"
    )]
    resource: String,
}

/// No identity socket: this is not a cloud Sandbox.
#[derive(Debug)]
pub(crate) struct OutsideSandbox;

impl fmt::Display for OutsideSandbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("`cw identity token` works only inside a cloud Sandbox")
    }
}

impl std::error::Error for OutsideSandbox {}

/// The status `error` exits with, when it is [`OutsideSandbox`].
pub fn exit_code(error: &anyhow::Error) -> Option<i32> {
    error
        .downcast_ref::<OutsideSandbox>()
        .map(|_| OUTSIDE_SANDBOX_EXIT_CODE)
}

#[cfg(unix)]
pub(crate) async fn identity_token(args: IdentityTokenArgs) -> anyhow::Result<()> {
    let socket = Path::new(codewire_daemon_proto::HOSTED_DAEMON_IDENTITY_SOCKET);
    let token = token_at(socket, &args.resource).await?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(token.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) async fn identity_token(_args: IdentityTokenArgs) -> anyhow::Result<()> {
    Err(OutsideSandbox.into())
}

#[cfg(unix)]
async fn token_at(socket: &Path, resource: &str) -> anyhow::Result<zeroize::Zeroizing<String>> {
    use codewire_daemon::identity_socket::{FetchError, IdentityRefusal, fetch};

    fetch(socket, resource).await.map_err(|error| match error {
        FetchError::NoSocket => OutsideSandbox.into(),
        FetchError::Refused(refusal) => {
            let why = match refusal {
                IdentityRefusal::InvalidTarget => {
                    "the resource is not an https URI your organization registered"
                }
                IdentityRefusal::NotRunning => "this Sandbox is not running",
                IdentityRefusal::IdentityStopped => {
                    "identity tokens are stopped for this Sandbox or its organization"
                }
                IdentityRefusal::ResourceExhausted => "too many token requests; try again shortly",
                IdentityRefusal::IdentityUnavailable => "identity tokens are unavailable right now",
                IdentityRefusal::KeyNotYetPublished => {
                    "the signing key is not published yet; tokens start within a day"
                }
            };
            // The name comes last: the error report capitalises the first
            // letter, and the name must stay exactly as the contract spells it.
            anyhow::anyhow!("{why} ({})", refusal.name())
        }
        FetchError::InvalidAnswer => {
            anyhow::anyhow!("the workspace daemon's answer was not a token (identity_unavailable)")
        }
    })
}

#[cfg(all(test, unix))]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    /// A socket that answers one request with `status` and `body`.
    async fn daemon(
        status: &'static str,
        body: &'static str,
    ) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let read = stream.read(&mut request).await.unwrap();
            assert!(
                std::str::from_utf8(&request[..read])
                    .unwrap()
                    .starts_with("GET /token?resource=https%3A%2F%2Fk8s.walk.example HTTP/1.1\r\n")
            );
            let answer = format!(
                "HTTP/1.1 {status}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(answer.as_bytes()).await.unwrap();
        });
        (directory, path)
    }

    async fn token(socket: &Path) -> anyhow::Result<zeroize::Zeroizing<String>> {
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            token_at(socket, "https://k8s.walk.example"),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn the_token_is_the_sockets_answer_exactly() {
        let (_directory, socket) = daemon("200 OK", "aGVhZA.Y2xhaW1z.c2ln").await;
        assert_eq!(
            token(&socket).await.unwrap().as_str(),
            "aGVhZA.Y2xhaW1z.c2ln"
        );
    }

    #[tokio::test]
    async fn a_refusal_names_itself() {
        for (status, name) in [
            ("400 Bad Request", "invalid_target"),
            ("403 Forbidden", "identity_stopped"),
            ("429 Too Many Requests", "resource_exhausted"),
            ("503 Service Unavailable", "identity_unavailable"),
            ("503 Service Unavailable", "key_not_yet_published"),
        ] {
            let (_directory, socket) = daemon(status, name).await;
            let error = token(&socket).await.unwrap_err();
            assert!(
                error.to_string().ends_with(&format!(" ({name})")),
                "{error}"
            );
            assert_eq!(exit_code(&error), None);
        }
    }

    #[tokio::test]
    async fn a_printed_refusal_keeps_its_name_as_written() {
        use crate::output::{Charset, Style};

        let (_directory, socket) = daemon("400 Bad Request", "invalid_target").await;
        let error = token(&socket).await.unwrap_err();
        assert_eq!(
            crate::error_report::render(&error, Style::new(false, Charset::Unicode)),
            "✗ The resource is not an https URI your organization registered (invalid_target)\n"
        );
    }

    #[tokio::test]
    async fn outside_a_cloud_sandbox_it_says_so_and_exits_2() {
        let missing = tempfile::tempdir().unwrap();
        let error = token(&missing.path().join("identity.sock"))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "`cw identity token` works only inside a cloud Sandbox"
        );
        assert_eq!(exit_code(&error), Some(2));
    }

    #[test]
    fn a_failure_exits_130_when_interrupted_2_outside_a_sandbox_and_1_otherwise() {
        use crate::commands::lifecycle_output::InterruptNotice;
        use crate::output::VmLocation;

        let interrupted = InterruptNotice::new(VmLocation::Local, "start", "app").error(true);
        assert_eq!(crate::failure_exit_code(&interrupted), 130);
        assert_eq!(crate::failure_exit_code(&OutsideSandbox.into()), 2);
        assert_eq!(crate::failure_exit_code(&anyhow::anyhow!("refused")), 1);
    }
}
