//! Explicit SSH enrollment input. No ambient paths, agent lookup or key parsing.

use std::io::{BufRead, IsTerminal, Read, Write};
use std::os::unix::fs::OpenOptionsExt;

use anyhow::Context as _;
use zeroize::Zeroizing;

use crate::commands::{CredentialAddArgs, CredentialGenerateArgs, EchoGuard, trimmed_required};

// Early input bounds mirror the authority's authoritative OpenSSH limits.
const MAX_KEY_BYTES: usize = 64 * 1024;
const MAX_PASSPHRASE_BYTES: usize = 1024;

pub(crate) struct SshImport {
    pub(crate) private_key: Zeroizing<Vec<u8>>,
    pub(crate) passphrase: Option<Zeroizing<Vec<u8>>>,
}

fn enrollment_name(name: &str, expiry: Option<u64>) -> anyhow::Result<String> {
    let name = trimmed_required(name, "credential name")?;
    anyhow::ensure!(
        name.len() <= 256 && !name.chars().any(char::is_control),
        "invalid credential name"
    );
    if let Some(expiry) = expiry {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        anyhow::ensure!(
            expiry > now && i64::try_from(expiry).is_ok(),
            "credential expiry must be a future Unix timestamp"
        );
    }
    Ok(name.to_owned())
}

pub(crate) fn validate_generation(args: &CredentialGenerateArgs) -> anyhow::Result<String> {
    anyhow::ensure!(args.provider == "ssh", "key generation supports ssh only");
    enrollment_name(&args.name, args.expires_at)
}

pub(crate) fn validate_import(args: &CredentialAddArgs) -> anyhow::Result<String> {
    anyhow::ensure!(args.provider == "ssh", "SSH import requires provider ssh");
    anyhow::ensure!(
        args.account_hint.is_none(),
        "SSH credentials do not use --account-hint"
    );
    anyhow::ensure!(
        args.key_file
            .as_ref()
            .is_some_and(|path| !path.as_os_str().is_empty()),
        "add ssh requires an explicit --key-file PATH"
    );
    enrollment_name(&args.name, args.expires_at)
}

pub(crate) fn read_import(args: &CredentialAddArgs) -> anyhow::Result<SshImport> {
    validate_import(args)?;
    let path = args.key_file.as_ref().expect("validated explicit key file");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("open explicit SSH key file (must be a regular file, not a symlink)")?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "SSH key input must be a regular file"
    );
    let private_key = read_key(file)?;
    let interactive = std::io::stdin().is_terminal();
    if interactive {
        eprint!("SSH passphrase (empty for an unencrypted key): ");
        std::io::stderr()
            .flush()
            .context("flush SSH passphrase prompt")?;
    }
    let echo = if interactive {
        Some(EchoGuard::disable_if_tty()?)
    } else {
        None
    };
    let passphrase = read_passphrase(std::io::stdin().lock(), interactive);
    drop(echo);
    if interactive {
        eprintln!();
    }
    Ok(SshImport {
        private_key,
        passphrase: passphrase?,
    })
}

fn read_key(reader: impl Read) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take(MAX_KEY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .context("read explicit SSH key")?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_KEY_BYTES,
        "SSH key input is empty or exceeds 64 KiB"
    );
    Ok(bytes)
}

fn read_passphrase(
    reader: impl BufRead,
    interactive: bool,
) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut reader = reader.take(MAX_PASSPHRASE_BYTES as u64 + 3);
    if interactive {
        reader.read_until(b'\n', &mut bytes)?;
    } else {
        reader.read_to_end(&mut bytes)?;
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    anyhow::ensure!(
        bytes.len() <= MAX_PASSPHRASE_BYTES
            && !bytes.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n')),
        "invalid SSH passphrase input"
    );
    Ok((!bytes.is_empty()).then_some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_ssh_input_is_bounded_and_empty_passphrase_means_unencrypted() {
        assert!(read_key(&b""[..]).is_err());
        assert!(read_key(&vec![b'x'; MAX_KEY_BYTES][..]).is_ok());
        assert!(read_key(&vec![b'x'; MAX_KEY_BYTES + 1][..]).is_err());
        for input in [b"".as_slice(), b"\n", b"\r\n"] {
            assert!(read_passphrase(input, false).unwrap().is_none());
        }
        assert_eq!(
            &**read_passphrase(&b"synthetic passphrase\r\n"[..], false)
                .unwrap()
                .as_ref()
                .unwrap(),
            b"synthetic passphrase"
        );
        for input in [
            vec![b'x'; MAX_PASSPHRASE_BYTES + 1],
            b"one\ntwo".to_vec(),
            b"one\0two".to_vec(),
        ] {
            assert!(read_passphrase(input.as_slice(), false).is_err());
        }
        let mut hidden_suffix = vec![b'x'; MAX_PASSPHRASE_BYTES];
        hidden_suffix.extend_from_slice(b"\r\nx");
        assert!(read_passphrase(hidden_suffix.as_slice(), false).is_err());
    }

    #[test]
    fn ssh_selection_is_validated_without_opening_any_key_or_reading_stdin() {
        let mut args = CredentialAddArgs {
            provider: "ssh".into(),
            name: "work".into(),
            account_hint: None,
            expires_at: None,
            key_file: Some("/deliberately-absent-key".into()),
        };
        assert_eq!(validate_import(&args).unwrap(), "work");
        args.key_file = None;
        assert!(validate_import(&args).is_err());
        args.key_file = Some("/deliberately-absent-key".into());
        args.account_hint = Some("unexpected".into());
        assert!(validate_import(&args).is_err());
        args.account_hint = None;
        args.provider = "github".into();
        assert!(validate_import(&args).is_err());
        assert!(enrollment_name("name\ncontrol", None).is_err());
        assert!(enrollment_name("work", Some(1)).is_err());
    }
}
