use std::ffi::OsStr;
use std::fs::{self, DirBuilder};
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use tempfile::TempDir;
use tokio::process::Command;
use uuid::Uuid;

use super::*;

const SOURCE: &str = "https://github.com/codewire/codewire.git";
const ENDPOINT: &str = "http://127.0.0.1:49152/_codewire/github/codewire/codewire.git";
const CAPABILITY: &[u8] = b"synthetic-platform-github-capability";

struct UnusedSpawner;

impl LocalRepositoryGitProcessSpawner for UnusedSpawner {
    fn spawn(&self, _command: &mut Command) -> io::Result<tokio::process::Child> {
        panic!("the command-inspection fixture must not spawn Git")
    }
}

#[test]
fn brokered_endpoint_is_an_exact_loopback_rewrite_of_the_provider_source() {
    validate_brokered_endpoint(SOURCE, ENDPOINT).unwrap();

    for endpoint in [
        "https://127.0.0.1:49152/_codewire/github/codewire/codewire.git",
        "http://localhost:49152/_codewire/github/codewire/codewire.git",
        "http://127.0.0.1/_codewire/github/codewire/codewire.git",
        "http://user@127.0.0.1:49152/_codewire/github/codewire/codewire.git",
        "http://127.0.0.1:49152/_codewire/github/other/codewire.git",
        "http://127.0.0.1:49152/_codewire/github/codewire/codewire.git/extra",
        "http://127.0.0.1:49152/_codewire/github/codewire/codewire.git?redirect=yes",
        "http://127.0.0.1:49152/_codewire/github/codewire/codewire.git#fragment",
    ] {
        assert!(
            validate_brokered_endpoint(SOURCE, endpoint).is_err(),
            "accepted {endpoint}"
        );
    }
    assert!(
        validate_brokered_endpoint("https://example.com/codewire/codewire.git", ENDPOINT).is_err()
    );
}

#[test]
fn brokered_helper_releases_one_capability_only_for_the_exact_endpoint() {
    let (temporary, socket, server) = credential_socket_fixture(CAPABILITY);
    let mut output = Vec::new();
    run_git_credential_helper_for_endpoint(
        "get",
        &socket,
        Some(ENDPOINT),
        &b"protocol=http\nhost=127.0.0.1:49152\npath=_codewire/github/codewire/codewire.git\nusername=x-access-token\n\n"[..],
        &mut output,
    )
    .unwrap();
    server.join().unwrap();
    drop(temporary);

    assert_eq!(
        output,
        b"username=x-access-token\npassword=synthetic-platform-github-capability\n\n"
    );
}

#[test]
fn brokered_helper_denies_every_mismatched_or_ambiguous_destination() {
    for request in [
        "protocol=https\nhost=127.0.0.1:49152\npath=_codewire/github/codewire/codewire.git\n\n",
        "protocol=http\nhost=localhost:49152\npath=_codewire/github/codewire/codewire.git\n\n",
        "protocol=http\nhost=127.0.0.1:49153\npath=_codewire/github/codewire/codewire.git\n\n",
        "protocol=http\nhost=127.0.0.1:49152\npath=_codewire/github/other/codewire.git\n\n",
        "protocol=http\nhost=127.0.0.1:49152\npath=_codewire/github/codewire/codewire.git\nusername=other\n\n",
        "protocol=http\nprotocol=http\nhost=127.0.0.1:49152\npath=_codewire/github/codewire/codewire.git\n\n",
        "protocol=http\nhost=127.0.0.1:49152\nhost=127.0.0.1:49152\npath=_codewire/github/codewire/codewire.git\n\n",
        "protocol=http\nhost=127.0.0.1:49152\npath=_codewire/github/codewire/codewire.git\npath=_codewire/github/codewire/codewire.git\n\n",
        "protocol=http\nhost=127.0.0.1:49152\npath=_codewire/github/codewire/codewire.git\npassword=attacker-controlled\n\n",
    ] {
        assert!(
            run_git_credential_helper_for_endpoint(
                "get",
                Path::new("/not-used"),
                Some(ENDPOINT),
                request.as_bytes(),
                Vec::new(),
            )
            .is_err(),
            "accepted {request:?}"
        );
    }
}

#[tokio::test]
async fn brokered_git_command_contains_only_public_routing_configuration() {
    let runtime = TempDir::new().unwrap();
    fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let execution = GitExecution {
        executable: Path::new("/usr/bin/git"),
        helper_executable: Path::new("/usr/bin/codewire-local"),
        credential_runtime_directory: runtime.path(),
        spawner: &UnusedSpawner,
        authentication: GitAuthentication::BrokeredGitHub {
            endpoint: ENDPOINT,
            capability: CAPABILITY,
        },
    };
    let command = execution.command(runtime.path(), true).unwrap();
    let arguments = command
        .command
        .as_std()
        .get_args()
        .map(OsStr::to_string_lossy)
        .collect::<Vec<_>>()
        .join(" ");
    let environment = command
        .command
        .as_std()
        .get_envs()
        .map(|(name, value)| {
            format!(
                "{}={}",
                name.to_string_lossy(),
                value.map_or_else(String::new, |value| value.to_string_lossy().into_owned())
            )
        })
        .collect::<Vec<_>>()
        .join(" ");

    assert!(arguments.contains("protocol.allow=never"));
    assert!(arguments.contains("protocol.http.allow=always"));
    assert!(arguments.contains("credential.useHttpPath=true"));
    assert!(arguments.contains("http.followRedirects=false"));
    assert!(!arguments.contains("http.followRedirects=initial"));
    assert!(arguments.contains("http.proxy="));
    assert!(arguments.contains("http.extraHeader="));
    assert!(arguments.contains("--brokered-endpoint"));
    assert!(arguments.contains(ENDPOINT));
    assert!(!arguments.contains("protocol.https.allow=always"));
    assert!(!arguments.contains(SOURCE));
    assert!(
        !arguments
            .as_bytes()
            .windows(CAPABILITY.len())
            .any(|part| part == CAPABILITY)
    );
    assert!(
        !environment
            .as_bytes()
            .windows(CAPABILITY.len())
            .any(|part| part == CAPABILITY)
    );
    assert!(!regular_files_contain(runtime.path(), CAPABILITY));

    drop(command);
    assert_eq!(fs::read_dir(runtime.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn brokered_checkout_rejects_invalid_inputs_before_spawning_git() {
    let temporary = TempDir::new().unwrap();
    let result = execute_brokered_git_repository(
        temporary.path(),
        temporary.path(),
        Path::new("/usr/bin/git"),
        Path::new("/usr/bin/codewire-local"),
        &UnusedSpawner,
        SOURCE,
        "main",
        "",
        "http://127.0.0.1:49152/_codewire/github/other/repository",
        CAPABILITY,
    )
    .await;
    assert!(matches!(
        result,
        Err(RepositoryExecutorError::InvalidConfiguration)
    ));

    let result = execute_brokered_git_repository(
        temporary.path(),
        temporary.path(),
        Path::new("/usr/bin/git"),
        Path::new("/usr/bin/codewire-local"),
        &UnusedSpawner,
        SOURCE,
        "main",
        "",
        ENDPOINT,
        b"contains a space",
    )
    .await;
    assert!(matches!(
        result,
        Err(RepositoryExecutorError::InvalidCredential)
    ));
}

#[test]
fn brokered_checkout_retains_the_shared_256_mib_response_ceiling() {
    assert_eq!(
        codewire_gateway_proto::CREDENTIAL_BRIDGE_MAX_RESPONSE_BYTES,
        256 * 1024 * 1024
    );
}

fn credential_socket_fixture(
    credential: &'static [u8],
) -> (TempDir, PathBuf, std::thread::JoinHandle<()>) {
    let temporary = TempDir::new().unwrap();
    let directory = temporary.path().join(format!("cwgr-{}", Uuid::new_v4()));
    DirBuilder::new().mode(0o700).create(&directory).unwrap();
    let socket = directory.join("c");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(credential).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
    });
    (temporary, socket, server)
}

fn regular_files_contain(root: &Path, needle: &[u8]) -> bool {
    fs::read_dir(root).unwrap().any(|entry| {
        let path = entry.unwrap().path();
        if path.is_dir() {
            regular_files_contain(&path, needle)
        } else if path.is_file() {
            fs::read(path)
                .unwrap()
                .windows(needle.len())
                .any(|part| part == needle)
        } else {
            false
        }
    })
}
