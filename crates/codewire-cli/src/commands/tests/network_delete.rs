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
fn deleted_network_clears_only_its_matching_local_selection() {
    for (saved_name, default_url, owner_org, owner_name, clear_saved, clear_owner) in [
        (
            "network-alpha",
            "https://mesh.example.test",
            "org-alpha",
            "network-alpha",
            true,
            true,
        ),
        (
            "network-other",
            "https://mesh.example.test",
            "org-alpha",
            "network-other",
            false,
            false,
        ),
        (
            "network-alpha",
            "https://other.example.test",
            "org-alpha",
            "network-alpha",
            false,
            true,
        ),
        (
            "network-alpha",
            "https://mesh.example.test",
            "org-other",
            "network-alpha",
            true,
            false,
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        config::save_selected_mesh_network_preference(dir.path(), saved_name, true).unwrap();
        let context = LocalMeshOwnerContext {
            schema_version: 1,
            auth_source: LocalMeshOwnerAuthSource::HostedCurrent,
            mesh_url: "https://mesh.example.test".into(),
            organization_id: owner_org.into(),
            selected_network: Some(owner_name.into()),
            auto_connect: true,
        };
        save_local_mesh_owner_context(dir.path(), &context).unwrap();
        clear_deleted_network_selection(
            dir.path(),
            Some(default_url),
            "https://mesh.example.test",
            "org-alpha",
            "network-alpha",
        )
        .unwrap();
        let saved = config::load_mesh_config(dir.path()).unwrap();
        assert_eq!(
            saved.mesh_selected_network.as_deref(),
            (!clear_saved).then_some(saved_name)
        );
        assert_eq!(saved.mesh_auto_connect, (!clear_saved).then_some(true));
        let owner = load_local_mesh_owner_context(dir.path()).unwrap().unwrap();
        assert_eq!(
            owner.selected_network.as_deref(),
            (!clear_owner).then_some(owner_name)
        );
        assert_eq!(owner.auto_connect, !clear_owner);
        assert_eq!(owner.organization_id, owner_org);
    }
}

#[test]
fn deleted_network_preserves_owner_on_another_mesh_origin() {
    let dir = tempfile::tempdir().unwrap();
    let context = LocalMeshOwnerContext {
        schema_version: 1,
        auth_source: LocalMeshOwnerAuthSource::StandaloneLocal,
        mesh_url: "https://other.example.test".into(),
        organization_id: "org-alpha".into(),
        selected_network: Some("network-alpha".into()),
        auto_connect: true,
    };
    save_local_mesh_owner_context(dir.path(), &context).unwrap();
    clear_deleted_network_selection(
        dir.path(),
        Some("https://mesh.example.test"),
        "https://mesh.example.test",
        "org-alpha",
        "network-alpha",
    )
    .unwrap();
    assert_eq!(
        load_local_mesh_owner_context(dir.path()).unwrap(),
        Some(context)
    );
}

#[test]
fn deleted_network_environment_override_does_not_clear_saved_other_origin() {
    let dir = tempfile::tempdir().unwrap();
    config::save_mesh_connection(dir.path(), "https://saved.example.test", "synthetic-owner")
        .unwrap();
    config::save_selected_mesh_network_preference(dir.path(), "network-alpha", true).unwrap();
    clear_deleted_network_selection(
        dir.path(),
        Some("https://override.example.test"),
        "https://override.example.test",
        "org-alpha",
        "network-alpha",
    )
    .unwrap();
    let saved = config::load_mesh_config(dir.path()).unwrap();
    assert_eq!(
        saved.mesh_url.as_deref(),
        Some("https://saved.example.test")
    );
    assert_eq!(
        saved.mesh_selected_network.as_deref(),
        Some("network-alpha")
    );
    assert_eq!(saved.mesh_auto_connect, Some(true));
}
