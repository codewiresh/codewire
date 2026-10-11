//! Shell-free Git-to-stock-SSH trampoline. No CLI configuration or key store.

use std::ffi::{OsStr, OsString};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use codewire_local_credentials::{
    SSH_HELPER_HOST_ENV, SSH_HELPER_OWNER_ENV, SSH_HELPER_PORT_ENV, SSH_HELPER_RUNTIME_ENV,
};
use codewire_project::{
    RepositorySshHost, canonical_repository_known_hosts, parse_repository_ssh_host,
};

use super::verify_common_confinement;

pub(crate) fn run_git_ssh_helper(arguments: Vec<OsString>) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    crate::prepare_local_credential_broker_process()?;
    verify_common_confinement()?;
    let owner = std::env::var(SSH_HELPER_OWNER_ENV)
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|value| *value > 1)
        .and_then(rustix::process::Pid::from_raw)
        .context("invalid repository SSH owner")?;
    let parent = rustix::process::getppid()
        .filter(|pid| pid.as_raw_pid() > 1 && *pid != owner)
        .context("invalid repository SSH parent")?;
    require_parent_session(parent, owner)?;
    // Darwin has no parent-death signal that survives exec: stock SSH stays
    // in the executor's process group, which its authority stops as a whole.
    #[cfg(target_os = "linux")]
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))?;
    require_parent_session(parent, owner)?;

    let host = std::env::var(SSH_HELPER_HOST_ENV).context("missing repository SSH host")?;
    let port = std::env::var(SSH_HELPER_PORT_ENV).context("missing repository SSH port")?;
    let source = format!(
        "ssh://{}:{port}/repository",
        if host.contains(':') {
            format!("[{host}]")
        } else {
            host.clone()
        }
    );
    let host_identity =
        parse_repository_ssh_host(&source)?.context("invalid repository SSH host")?;
    anyhow::ensure!(
        host_identity.host() == host && host_identity.port().to_string() == port,
        "noncanonical repository SSH host"
    );
    validate_git_arguments(&arguments, &host_identity)?;
    let runtime = std::env::var_os(SSH_HELPER_RUNTIME_ENV)
        .map(PathBuf::from)
        .context("missing repository SSH runtime")?;
    validate_runtime(&runtime, &source)?;
    let mut command = ssh_command(&runtime, &host_identity, &arguments);
    if std::env::var("GIT_PROTOCOL").ok().as_deref() == Some("version=2") {
        command.env("GIT_PROTOCOL", "version=2");
    }
    require_parent_session(parent, owner)?;
    // SSH itself closes extra descriptors too; close them before exec rather
    // than exposing any inherited Codewire capability even during startup.
    // SAFETY: this is the single-threaded early binary entrypoint. The syscall
    // only marks descriptors >=3 close-on-exec; stdio remains the existing
    // Git transport and authority-owned diagnostic/lifetime pipe.
    #[cfg(target_os = "linux")]
    if unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    // Darwin has no close_range: mark each descriptor >=3 close-on-exec.
    #[cfg(target_os = "macos")]
    codewire_local_vmm::darwin::process::mark_inherited_descriptors_close_on_exec();
    Err(command.exec()).context("start repository SSH")
}

fn require_parent_session(
    parent: rustix::process::Pid,
    owner: rustix::process::Pid,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        rustix::process::getppid() == Some(parent)
            && rustix::process::getsid(None).ok() == Some(owner)
            && rustix::process::getsid(Some(parent)).ok() == Some(owner),
        "repository SSH parent changed"
    );
    Ok(())
}

fn validate_runtime(runtime: &Path, source: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        runtime
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')),
        "repository SSH runtime cannot contain option interpolation"
    );
    let metadata = std::fs::symlink_metadata(runtime)?;
    let uid = rustix::process::getuid().as_raw();
    anyhow::ensure!(
        runtime.is_absolute()
            && std::fs::canonicalize(runtime)? == runtime
            && metadata.is_dir()
            && metadata.uid() == uid
            && metadata.permissions().mode() & 0o7777 == 0o700,
        "invalid repository SSH runtime"
    );
    let trust = runtime.join("known_hosts");
    let metadata = std::fs::symlink_metadata(&trust)?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == uid
            && metadata.permissions().mode() & 0o7777 == 0o600
            && metadata.len() <= codewire_project::MAX_REPOSITORY_KNOWN_HOSTS_BYTES as u64,
        "invalid repository SSH host trust"
    );
    let text = std::fs::read_to_string(trust)?;
    let pins = text.lines().map(str::to_owned).collect::<Vec<_>>();
    anyhow::ensure!(
        text.ends_with('\n') && canonical_repository_known_hosts(source, pins.clone())? == pins,
        "invalid repository SSH host trust"
    );
    let metadata = std::fs::symlink_metadata(runtime.join("agent"))?;
    anyhow::ensure!(
        metadata.file_type().is_socket()
            && metadata.uid() == uid
            && metadata.permissions().mode() & 0o7777 == 0o600,
        "invalid repository SSH agent"
    );
    Ok(())
}

fn validate_git_arguments(
    arguments: &[OsString],
    expected: &RepositorySshHost,
) -> anyhow::Result<()> {
    let mut index = 0;
    while let Some(option) = arguments
        .get(index)
        .and_then(|value| value.to_str())
        .filter(|value| value.starts_with('-'))
    {
        let value = arguments
            .get(index + 1)
            .and_then(|value| value.to_str())
            .context("invalid repository SSH arguments")?;
        anyhow::ensure!(
            matches!((option, value), ("-o", "SendEnv=GIT_PROTOCOL"))
                || (option == "-p" && value == expected.port().to_string()),
            "invalid repository SSH arguments"
        );
        index += 2;
    }
    anyhow::ensure!(
        arguments.len() == index + 2,
        "invalid repository SSH arguments"
    );
    let destination = arguments[index]
        .to_str()
        .context("invalid repository SSH destination")?;
    let (user, host) = destination
        .rsplit_once('@')
        .map_or((None, destination), |(user, host)| (Some(user), host));
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let authority = if host.contains(':') {
        format!("[{}]", host)
    } else {
        host.to_owned()
    };
    let authority = user.map_or_else(|| authority.clone(), |user| format!("{user}@{authority}"));
    let actual =
        parse_repository_ssh_host(&format!("ssh://{authority}:{}/repository", expected.port()))?
            .context("invalid repository SSH destination")?;
    anyhow::ensure!(&actual == expected, "repository SSH destination changed");
    let operation = arguments[index + 1]
        .to_str()
        .context("invalid repository SSH operation")?;
    anyhow::ensure!(
        valid_upload_pack(operation),
        "invalid repository SSH operation"
    );
    Ok(())
}

fn valid_upload_pack(operation: &str) -> bool {
    if operation.len() > 16 * 1024 || operation.chars().any(char::is_control) {
        return false;
    }
    let Some(argument) = operation.strip_prefix("git-upload-pack '") else {
        return false;
    };
    let bytes = argument.as_bytes();
    let mut index = 0;
    let mut decoded = Vec::new();
    while index < bytes.len() {
        if bytes[index] != b'\'' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 1 == bytes.len() {
            // Git's sq_quote_buf escapes apostrophes and exclamation marks by
            // ending the quote, escaping exactly one byte, then reopening it.
            // Re-encoding rejects any extra token or remote shell operation.
            let Ok(value) = String::from_utf8(decoded) else {
                return false;
            };
            let mut canonical = String::from("git-upload-pack '");
            for character in value.chars() {
                if matches!(character, '\'' | '!') {
                    canonical.push_str("'\\");
                    canonical.push(character);
                    canonical.push('\'');
                } else {
                    canonical.push(character);
                }
            }
            canonical.push('\'');
            return !value.is_empty() && canonical == operation;
        }
        if bytes.get(index + 1) != Some(&b'\\')
            || !matches!(bytes.get(index + 2), Some(b'\'' | b'!'))
            || bytes.get(index + 3) != Some(&b'\'')
        {
            return false;
        }
        decoded.push(bytes[index + 2]);
        index += 4;
    }
    false
}

fn ssh_command(
    runtime: &Path,
    host: &RepositorySshHost,
    arguments: &[OsString],
) -> std::process::Command {
    let mut command = std::process::Command::new("/usr/bin/ssh");
    command
        .env_clear()
        .env("LC_ALL", "C")
        .args(["-F", "/dev/null"]);
    for option in [
        "BatchMode=yes",
        "PreferredAuthentications=publickey",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "HostbasedAuthentication=no",
        "GSSAPIAuthentication=no",
        "IdentityFile=none",
        "CertificateFile=none",
        "PKCS11Provider=none",
        "SecurityKeyProvider=none",
        "AddKeysToAgent=no",
        "IdentitiesOnly=no",
        "StrictHostKeyChecking=yes",
        "GlobalKnownHostsFile=/dev/null",
        "ForwardAgent=no",
        "ClearAllForwardings=yes",
        "ControlMaster=no",
        "ControlPath=none",
        "ControlPersist=no",
        "ForkAfterAuthentication=no",
        "PermitLocalCommand=no",
        "ProxyCommand=none",
        "ProxyJump=none",
        "RequestTTY=no",
        "UpdateHostKeys=no",
        "VerifyHostKeyDNS=no",
        "PubkeyAcceptedAlgorithms=ssh-ed25519,rsa-sha2-512,rsa-sha2-256",
    ] {
        command.args([OsStr::new("-o"), OsStr::new(option)]);
    }
    for (key, value) in [
        ("HostName", OsString::from(host.host())),
        ("HostKeyAlias", OsString::from(host.known_hosts_name())),
        ("Port", OsString::from(host.port().to_string())),
        (
            "UserKnownHostsFile",
            runtime.join("known_hosts").into_os_string(),
        ),
        ("IdentityAgent", runtime.join("agent").into_os_string()),
    ] {
        let mut option = OsString::from(format!("{key}="));
        option.push(value);
        command.arg("-o").arg(option);
    }
    command.args(arguments);
    command
}

#[cfg(all(test, target_os = "linux"))]
mod process_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn host(source: &str) -> RepositorySshHost {
        parse_repository_ssh_host(source).unwrap().unwrap()
    }
    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn accepts_only_stock_git_upload_pack_for_exact_selected_destination() {
        let expected = host("ssh://git@example.com:2222/repo.git");
        assert!(
            validate_git_arguments(
                &args(&[
                    "-o",
                    "SendEnv=GIT_PROTOCOL",
                    "-p",
                    "2222",
                    "git@example.com",
                    "git-upload-pack 'repo.git'"
                ]),
                &expected
            )
            .is_ok()
        );
        for arguments in [
            vec!["-p", "22", "git@example.com", "git-upload-pack 'repo.git'"],
            vec![
                "-F",
                "/tmp/config",
                "git@example.com",
                "git-upload-pack 'repo.git'",
            ],
            vec!["git@other.example", "git-upload-pack 'repo.git'"],
            vec!["git@example.com", "git-receive-pack 'repo.git'"],
            vec![
                "-o",
                "ProxyCommand=evil",
                "git@example.com",
                "git-upload-pack 'repo.git'",
            ],
            vec!["git@example.com", "git-upload-pack 'repo.git'", "extra"],
        ] {
            assert!(validate_git_arguments(&args(&arguments), &expected).is_err());
        }
    }

    #[test]
    fn fixed_stock_flags_keep_only_the_selected_agent_and_exact_port_trust() {
        let command = ssh_command(
            Path::new("/run/owned"),
            &host("ssh://git@[2001:db8::1]:2222/repo"),
            &[],
        );
        let arguments = command
            .get_args()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        for expected in [
            "HostKeyAlias=[2001:db8::1]:2222",
            "Port=2222",
            "IdentityFile=none",
            "IdentitiesOnly=no",
            "IdentityAgent=/run/owned/agent",
            "UserKnownHostsFile=/run/owned/known_hosts",
            "GlobalKnownHostsFile=/dev/null",
            "ProxyCommand=none",
        ] {
            assert!(
                arguments.iter().any(|value| value == expected),
                "missing {expected}"
            );
        }
        assert_eq!(command.get_program(), "/usr/bin/ssh");
        assert_eq!(
            command.get_envs().collect::<Vec<_>>(),
            [(OsStr::new("LC_ALL"), Some(OsStr::new("C")))]
        );
    }

    #[test]
    fn upload_pack_accepts_one_exact_git_quoted_argument_not_remote_shell_syntax() {
        for operation in [
            "git-upload-pack 'repo.git'",
            "git-upload-pack 'repo'\\''name'",
            "git-upload-pack 'repo'\\!'name'",
            "git-upload-pack '/org/$literal;name.git'",
        ] {
            assert!(valid_upload_pack(operation), "{operation}");
        }
        for operation in [
            "git-upload-pack 'repo'; id; echo '",
            "git-upload-pack 'repo' 'other'",
            "git-upload-pack ''",
            "git-upload-pack 'repo'\\$'extra'",
            "git-upload-pack 'repo!name'",
            "git-upload-pack 'repo\nname'",
        ] {
            assert!(!valid_upload_pack(operation), "{operation}");
        }
    }

    #[test]
    fn stock_ssh_parses_the_pinned_agent_configuration_without_network_or_user_configuration() {
        let expected = host("ssh://git@[2001:db8::1]:2222/repo.git");
        let mut command = ssh_command(Path::new("/run/synthetic-ssh"), &expected, &[]);
        // -G prints effective configuration and exits without a connection.
        // -F /dev/null and fixed trust/identity settings remain intact.
        let output = command.args(["-G", "git@2001:db8::1"]).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let configuration = String::from_utf8(output.stdout).unwrap();
        for expected in [
            "hostname 2001:db8::1",
            "port 2222",
            "hostkeyalias [2001:db8::1]:2222",
            "identityagent /run/synthetic-ssh/agent",
            "identityfile none",
            "identitiesonly no",
            "userknownhostsfile /run/synthetic-ssh/known_hosts",
            "globalknownhostsfile /dev/null",
            "passwordauthentication no",
            "kbdinteractiveauthentication no",
            "forwardagent no",
        ] {
            assert!(
                configuration.lines().any(|line| line == expected),
                "missing {expected}"
            );
        }
    }

    #[test]
    fn runtime_interpolation_is_rejected_before_any_filesystem_read() {
        for path in [
            "/run/space here",
            "/run/%d",
            "/run/${HOME}",
            "/run/quote'",
            "/run/line\n",
        ] {
            let error =
                validate_runtime(Path::new(path), "ssh://git@example.test/repo").unwrap_err();
            assert_eq!(
                error.to_string(),
                "repository SSH runtime cannot contain option interpolation"
            );
        }
    }

    #[test]
    fn repository_transport_is_required_and_closed_in_the_private_cli() {
        use clap::Parser as _;
        let request = uuid::Uuid::new_v4().to_string();
        // A macOS executor also names its authority's store.
        let store: &[&str] = if cfg!(target_os = "macos") {
            &["--protected-store", "keychain"]
        } else {
            &[]
        };
        let base = [
            "cw",
            "__local-git-repository-executor",
            "--authority-fd",
            "3",
            "--request-id",
            &request,
            "--staging-directory",
            "/run/synthetic-repository",
        ]
        .into_iter()
        .chain(store.iter().copied())
        .collect::<Vec<_>>();
        assert!(crate::Cli::try_parse_from(base.iter().copied()).is_err());
        for transport in ["github-oauth", "ssh"] {
            assert!(
                crate::Cli::try_parse_from(base.iter().copied().chain(["--transport", transport]))
                    .is_ok()
            );
        }
        assert!(
            crate::Cli::try_parse_from(base.iter().copied().chain(["--transport", "auto"]))
                .is_err()
        );
    }
}
