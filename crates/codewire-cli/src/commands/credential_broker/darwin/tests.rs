use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt as _;
use std::process::{Command, Stdio};

use clap::Parser as _;
use codewire_local_credentials::FILE_STORE_DIRECTORY;
use codewire_protected_store::{
    FileProtectedStore, KeychainProtectedStore, ProtectedEntryId, ProtectedStore as _,
    ProtectedValue,
};

use super::super::LocalCredentialBrokerArgs;
use super::*;

const CHILD_MARKER: &str = "CODEWIRE_TEST_BROKER_SEATBELT_CHILD";
const STORE_PATH: &str = "CODEWIRE_TEST_BROKER_SEATBELT_STORE";
const NETWORK: &str = "CODEWIRE_TEST_BROKER_SEATBELT_NETWORK";
const ENTRY: &str = "local/broker-seatbelt/material-v1";
const VALUE: &[u8] = b"synthetic-broker-seatbelt-value";
const SYNTHETIC_KEYCHAIN_PASSWORD: &str = "synthetic-broker-seatbelt-keychain";

#[derive(clap::Parser)]
struct Harness {
    #[command(flatten)]
    args: LocalCredentialBrokerArgs,
}

fn arguments(store: &[&str]) -> anyhow::Result<ChildStore> {
    let mut argv = vec![
        "broker",
        "--authority-fd",
        "3",
        "--environment-id",
        "e",
        "--environment-generation",
        "1",
        "--environment-name",
        "n",
        "--runner-socket",
        "/r/e.sock",
    ];
    argv.extend_from_slice(store);
    ChildStore::from_args(&Harness::try_parse_from(argv).unwrap().args.store)
}

#[test]
fn store_arguments_name_exactly_one_supported_store() {
    assert_eq!(
        arguments(&[
            "--protected-store",
            "file",
            "--protected-store-directory",
            "/private/root/protected-v1"
        ])
        .unwrap(),
        ChildStore::File {
            directory: PathBuf::from("/private/root/protected-v1")
        }
    );
    assert_eq!(
        arguments(&["--protected-store", "keychain"]).unwrap(),
        ChildStore::Keychain { keychain: None }
    );
    assert_eq!(
        arguments(&[
            "--protected-store",
            "keychain",
            "--keychain",
            "/private/tmp/test.keychain-db"
        ])
        .unwrap(),
        ChildStore::Keychain {
            keychain: Some(PathBuf::from("/private/tmp/test.keychain-db"))
        }
    );
    for refused in [
        &["--protected-store", "secret-service"][..],
        &["--protected-store", "file"],
        &[
            "--protected-store",
            "file",
            "--protected-store-directory",
            "/private/root/other",
        ],
        &[
            "--protected-store",
            "file",
            "--protected-store-directory",
            "relative/protected-v1",
        ],
        &[
            "--protected-store",
            "file",
            "--protected-store-directory",
            "/private/root/protected-v1",
            "--keychain",
            "/private/tmp/test.keychain-db",
        ],
        &[
            "--protected-store",
            "keychain",
            "--protected-store-directory",
            "/private/root/protected-v1",
        ],
        &[
            "--protected-store",
            "keychain",
            "--keychain",
            "/private/tmp/a\")(allow default)(\"",
        ],
    ] {
        assert!(arguments(refused).is_err(), "{refused:?}");
    }
}

#[test]
fn profiles_allow_only_the_selected_store_and_provider_https() {
    let file = ChildStore::File {
        directory: PathBuf::from("/private/root/protected-v1"),
    };
    assert_eq!(
        profile(&file, false, None).unwrap().to_str().unwrap(),
        concat!(
            "(version 1)\n(deny default)\n",
            "(allow file-read* (literal \"/private/root\") ",
            "(subpath \"/private/root/protected-v1\"))\n",
        )
    );
    let with_network = profile(&file, true, None).unwrap();
    assert!(
        with_network
            .to_str()
            .unwrap()
            .contains("(allow network-outbound (remote tcp \"*:443\"))\n")
    );
    let keychain = ChildStore::Keychain {
        keychain: Some(PathBuf::from("/private/tmp/test.keychain-db")),
    };
    let rules = profile(&keychain, false, None).unwrap();
    let rules = rules.to_str().unwrap();
    assert!(rules.contains("(allow process-exec (literal \"/usr/bin/security\"))"));
    assert!(rules.contains("(allow file-read* (literal \"/private/tmp/test.keychain-db\"))"));
    assert!(!rules.contains("network"));
    assert!(!rules.contains("Library/Keychains"));
    let login = profile(
        &ChildStore::Keychain { keychain: None },
        false,
        Some(Path::new("/Users/someone")),
    )
    .unwrap();
    assert!(
        login
            .to_str()
            .unwrap()
            .contains("(subpath \"/Users/someone/Library/Keychains\")")
    );
    assert!(profile(&ChildStore::Keychain { keychain: None }, false, None).is_err());
    assert!(
        profile(
            &ChildStore::Keychain { keychain: None },
            false,
            Some(Path::new("/Users/a\") (allow default) (\""))
        )
        .is_err()
    );
}

fn entry() -> ProtectedEntryId {
    ProtectedEntryId::parse(ENTRY).unwrap()
}

/// Re-run one test in a fresh process that installs the profile, so the
/// irreversible Seatbelt state never reaches the parent test binary.
fn run_child(test: &str, store: &Path, network: bool) {
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(test)
        .arg("--nocapture")
        .env(CHILD_MARKER, "1")
        .env(STORE_PATH, store)
        .env(NETWORK, if network { "1" } else { "0" })
        .status()
        .unwrap();
    assert!(status.success(), "confined child failed: {test}");
}

fn child_store() -> Option<(PathBuf, bool)> {
    std::env::var_os(CHILD_MARKER)?;
    Some((
        PathBuf::from(std::env::var_os(STORE_PATH).unwrap()),
        std::env::var_os(NETWORK).unwrap() == "1",
    ))
}

fn assert_denied<T: std::fmt::Debug>(result: std::io::Result<T>, what: &str) {
    let error = result.expect_err(what);
    assert_eq!(error.kind(), ErrorKind::PermissionDenied, "{what}: {error}");
}

/// Outside the selected store and provider HTTPS, everything is refused.
fn assert_common_denials(network: bool) {
    assert_denied(std::fs::File::open("/etc/hosts"), "unrelated file");
    assert_denied(
        Command::new("/usr/bin/true").status(),
        "unrelated executable",
    );
    assert_denied(
        std::net::TcpStream::connect("127.0.0.1:80"),
        "non-HTTPS port",
    );
    let https = std::net::TcpStream::connect("127.0.0.1:443");
    if network {
        // Nothing listens: the profile let the connection reach the stack.
        assert!(
            https
                .as_ref()
                .err()
                .is_none_or(|error| error.kind() != ErrorKind::PermissionDenied),
            "provider HTTPS was refused: {https:?}"
        );
    } else {
        assert_denied(https, "HTTPS without a selected provider");
    }
}

#[test]
fn file_store_profile_reads_only_the_entry_directory() {
    if let Some((directory, network)) = child_store() {
        let store = ChildStore::File {
            directory: directory.clone(),
        };
        confine(&store, network).unwrap();
        let value = store.open().unwrap().get(&entry()).unwrap().unwrap();
        assert_eq!(value.expose_secret(), VALUE);
        assert_denied(
            std::fs::read(directory.parent().unwrap().join("sibling")),
            "file beside the entry directory",
        );
        assert_common_denials(network);
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(root.path()).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(root.join("sibling"), b"unrelated").unwrap();
    let directory = root.join(FILE_STORE_DIRECTORY);
    FileProtectedStore::new(directory.clone())
        .unwrap()
        .put(&entry(), &ProtectedValue::from_slice(VALUE).unwrap())
        .unwrap();
    let test = "commands::credential_broker::darwin::tests::file_store_profile_reads_only_the_entry_directory";
    run_child(test, &directory, false);
    run_child(test, &directory, true);
}

struct ThrowawayKeychain {
    _directory: tempfile::TempDir,
    path: PathBuf,
}

impl ThrowawayKeychain {
    /// A synthetic keychain file; the login keychain is never named.
    fn create() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(directory.path())
            .unwrap()
            .join("broker-seatbelt.keychain-db");
        let keychain = Self {
            _directory: directory,
            path,
        };
        let path = keychain.path.to_str().unwrap();
        security(&["create-keychain", "-p", SYNTHETIC_KEYCHAIN_PASSWORD, path]);
        security(&["set-keychain-settings", path]);
        security(&["unlock-keychain", "-p", SYNTHETIC_KEYCHAIN_PASSWORD, path]);
        keychain
    }
}

impl Drop for ThrowawayKeychain {
    fn drop(&mut self) {
        let _ = Command::new(SECURITY_TOOL)
            .arg("delete-keychain")
            .arg(&self.path)
            .stderr(Stdio::null())
            .status();
    }
}

fn security(arguments: &[&str]) {
    let status = Command::new(SECURITY_TOOL)
        .args(arguments)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "security {}", arguments[0]);
}

#[test]
fn keychain_profile_reads_the_selected_keychain_through_security() {
    if let Some((keychain, network)) = child_store() {
        let store = ChildStore::Keychain {
            keychain: Some(keychain),
        };
        confine(&store, network).unwrap();
        let value = store.open().unwrap().get(&entry()).unwrap().unwrap();
        assert_eq!(value.expose_secret(), VALUE);
        assert_common_denials(network);
        return;
    }
    let keychain = ThrowawayKeychain::create();
    KeychainProtectedStore::with_keychain(keychain.path.clone())
        .unwrap()
        .put(&entry(), &ProtectedValue::from_slice(VALUE).unwrap())
        .unwrap();
    run_child(
        "commands::credential_broker::darwin::tests::keychain_profile_reads_the_selected_keychain_through_security",
        &keychain.path,
        false,
    );
}
