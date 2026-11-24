//! Codewire's `gh` configuration in a local VM, on the guest's read-only
//! control mount.

use super::*;

/// Publish Codewire's `gh` configuration while the GitHub client is selected:
/// one file naming the workspace's credential ingress socket, so stock `gh`
/// reaches the GitHub API route through it, or, while the boot binds
/// GitHub's hosts, naming none, so `gh` speaks HTTPS to `api.github.com`
/// itself (#4001). The directory and file belong to the workspace user
/// (0700, 0600) and sit on the control mount, which the workspace sees
/// read-only; the user's own `~/.config/gh` is never touched.
pub(super) fn prepare_gh_projection(identity: &WorkspaceIdentity, seed: &Seed) -> Result<()> {
    prepare_gh_projection_at(
        Path::new(CONTAINER_GH_CONFIG_PATH),
        identity,
        seed.managed_credential_clients(),
        interception::from_seed(seed).as_ref(),
    )
}

pub(super) fn prepare_gh_projection_at(
    root: &Path,
    identity: &WorkspaceIdentity,
    clients: codewire_access::ManagedCredentialClients,
    interception: Option<&codewire_access::Interception>,
) -> Result<()> {
    let path = root.join(codewire_access::GH_CONFIG_FILE_NAME);
    let Some(projection) = clients
        .for_placement_intercepted(
            codewire_access::ManagedCredentialClientPlacement::Native,
            interception,
        )
        .gh
    else {
        // Both are Codewire's own. Unlink never follows a symlink, and a
        // directory holding anything else is left alone.
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("clear managed gh configuration"),
        }
        return match fs::remove_dir(root) {
            Ok(()) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::DirectoryNotEmpty
                        | io::ErrorKind::NotADirectory
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error).context("clear managed gh configuration directory"),
        };
    };
    create_dir(root, 0o700)?;
    lchown(root, identity.uid, identity.gid)?;
    write_durable(&path, projection.config_yml().as_bytes(), 0o600)
        .context("publish managed gh configuration")?;
    lchown(&path, identity.uid, identity.gid)?;
    let directory = fs::symlink_metadata(root).context("inspect managed gh directory")?;
    let metadata = fs::symlink_metadata(&path).context("inspect managed gh configuration")?;
    ensure!(
        directory.file_type().is_dir()
            && directory.uid() == identity.uid
            && directory.gid() == identity.gid
            && directory.permissions().mode() & 0o777 == 0o700
            && metadata.file_type().is_file()
            && metadata.uid() == identity.uid
            && metadata.gid() == identity.gid
            && metadata.permissions().mode() & 0o777 == 0o600
            && metadata.nlink() == 1,
        "managed gh configuration metadata is invalid"
    );
    let actual = read_bounded(&path, projection.config_yml().len().saturating_add(1))
        .context("verify managed gh configuration")?;
    ensure!(
        actual == projection.config_yml().as_bytes(),
        "managed gh configuration changed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// While the boot binds GitHub's hosts, the file names no socket, so
    /// `gh` speaks HTTPS to `api.github.com` itself (#4001).
    #[test]
    fn an_intercepted_github_configuration_names_no_socket() {
        let temporary = tempfile::TempDir::new().unwrap();
        let root = temporary.path().join("gh");
        let mut identity = super::super::tests::test_workspace_plan().identity;
        identity.uid = rustix::process::geteuid().as_raw();
        identity.gid = rustix::process::getegid().as_raw();
        let github =
            codewire_access::ManagedCredentialClients::from_profile_slots(["github"]).unwrap();
        let placeholder =
            codewire_access::CredentialPlaceholder::parse(&format!("cwp1_{}A", "D".repeat(42)))
                .unwrap();
        let interception = codewire_access::Interception::new(None)
            .with_github(placeholder, egress_trust::WORKSPACE_TRUST_BUNDLE_PATH);
        let config = root.join(codewire_access::GH_CONFIG_FILE_NAME);
        prepare_gh_projection_at(&root, &identity, github, Some(&interception)).unwrap();
        assert_eq!(fs::read_to_string(&config).unwrap(), "version: 1\n");
        // An interception without GitHub's placeholder keeps the socket.
        let anthropic_only = codewire_access::Interception::new(None);
        prepare_gh_projection_at(&root, &identity, github, Some(&anthropic_only)).unwrap();
        assert_eq!(
            fs::read_to_string(&config).unwrap(),
            "version: 1\nhttp_unix_socket: /run/codewire-host/credential.sock\n"
        );
    }
}
