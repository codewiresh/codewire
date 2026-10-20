#[test]
fn network_delete_requires_explicit_name_and_organization() {
    for args in [
        vec!["cw", "network", "delete", "--org", "org-alpha", "--yes"],
        vec!["cw", "network", "delete", "network-alpha", "--yes"],
    ] {
        assert_eq!(
            Cli::try_parse_from(args).unwrap_err().kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }
    let cli = Cli::try_parse_from([
        "cw",
        "network",
        "delete",
        "network-alpha",
        "--org",
        "org-alpha",
        "--yes",
    ])
    .unwrap();
    let Command::Network {
        command: NetworkCommand::Delete(args),
    } = cli.command
    else {
        panic!("expected network delete");
    };
    assert_eq!(args.name, "network-alpha");
    assert_eq!(args.org, "org-alpha");
    assert!(args.yes);
}

#[test]
fn deleted_network_clears_only_its_exact_selection() {
    // (selected Mesh, organization, network) against a deletion of
    // network-alpha in org-alpha on https://mesh.example.test.
    for (mesh_url, organization, network, cleared) in [
        ("https://mesh.example.test", "org-alpha", "network-alpha", true),
        ("https://mesh.example.test/", "org-alpha", "network-alpha", true),
        ("https://mesh.example.test", "org-alpha", "network-other", false),
        ("https://other.example.test", "org-alpha", "network-alpha", false),
        ("https://mesh.example.test", "org-other", "network-alpha", false),
    ] {
        let dir = private_mesh_data_fixture();
        let selection =
            NetworkSelection::new(MeshKind::Cloud, mesh_url, organization, network, true);
        save_network_selection(dir.path(), &selection).unwrap();
        let cleanup = clear_deleted_network_selection(
            dir.path(),
            "https://mesh.example.test",
            "org-alpha",
            "network-alpha",
        );
        if cleared {
            assert!(matches!(cleanup, mesh_commands::network_output::SelectionCleanup::Cleared), "{cleanup:?}");
            assert_eq!(load_network_selection(dir.path()).unwrap(), None);
        } else {
            assert!(matches!(cleanup, mesh_commands::network_output::SelectionCleanup::Untouched), "{cleanup:?}");
            assert_eq!(load_network_selection(dir.path()).unwrap(), Some(selection));
        }
    }
}

#[test]
fn deleted_network_without_a_selection_changes_nothing() {
    let dir = private_mesh_data_fixture();
    let cleanup = clear_deleted_network_selection(
        dir.path(),
        "https://mesh.example.test",
        "org-alpha",
        "network-alpha",
    );
    assert!(matches!(cleanup, mesh_commands::network_output::SelectionCleanup::Untouched), "{cleanup:?}");
    assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
}

#[test]
fn an_unreadable_selection_after_deletion_is_a_reported_partial_failure() {
    let dir = private_mesh_data_fixture();
    std::fs::write(dir.path().join("network_selection.json"), b"{").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            dir.path().join("network_selection.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let cleanup = clear_deleted_network_selection(
        dir.path(),
        "https://mesh.example.test",
        "org-alpha",
        "network-alpha",
    );
    let mesh_commands::network_output::SelectionCleanup::Failed(error) = cleanup else {
        panic!("expected a failed cleanup, got {cleanup:?}");
    };
    assert!(error.contains("cw network clear"), "{error}");
}
