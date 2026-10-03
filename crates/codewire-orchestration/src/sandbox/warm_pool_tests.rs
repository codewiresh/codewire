use super::*;
use crate::sandbox::shadow_warm_pool_name;
use crate::sandbox::template::{
    CredentialRuntimeTemplateConfig, DOCKER_MODE_GUEST_DIND, RUNTIME_PROFILE_COMMODITY,
    RUNTIME_PROFILE_RUNC, WorkspaceIdentity,
};

const NAMESPACE: &str = "dev-sandboxes";
const WORKSPACE_IMAGE: &str = "registry.example.invalid/codewire/workspace@sha256:1111111111111111111111111111111111111111111111111111111111111111";
const SUPPORT_IMAGE: &str = "registry.example.invalid/codewire/gateway@sha256:2222222222222222222222222222222222222222222222222222222222222222";
const DIND_IMAGE: &str = "docker.io/library/docker:29.7.1-dind@sha256:3333333333333333333333333333333333333333333333333333333333333333";
const BINDING_URL: &str =
    "http://codewire-orchestration-workspace-binding.dev.svc.cluster.local:8087";

fn shape(cpu_millicores: i64, memory_mib: i64, disk_gib: i64) -> WorkspaceShape {
    WorkspaceShape {
        cpu_millicores,
        memory_mib,
        disk_gib,
    }
}

/// Owner shapes, 2026-10-02.
fn owner_shapes() -> [WorkspaceShape; 2] {
    [shape(1000, 4096, 10), shape(2000, 8192, 10)]
}

fn pool_opts() -> TemplateOpts {
    TemplateOpts {
        image: WORKSPACE_IMAGE.into(),
        support_image: SUPPORT_IMAGE.into(),
        dind_image: DIND_IMAGE.into(),
        runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
        docker_mode: DOCKER_MODE_GUEST_DIND.into(),
        credential_runtime: Some(CredentialRuntimeTemplateConfig::synthetic(NAMESPACE)),
        workspace_identity: WorkspaceIdentity::Binding {
            binding_url: BINDING_URL.into(),
        },
        gateway_daemon_credential_from_binding: true,
        api_base_url: "https://codewire-dev.sh".into(),
        server_namespace: "dev".into(),
        cpu_millicores: 1000,
        memory_mib: 4096,
        disk_gib: 10,
        workspace_storage_class: "linstor-local".into(),
        kata_agent_policy_enabled: true,
        ..Default::default()
    }
}

fn render(opts: &TemplateOpts) -> WarmPoolObjects {
    render_warm_pool(NAMESPACE, opts, 2, false).unwrap()
}

fn key(shape: WorkspaceShape, storage_class: &str, sandbox: &str, server: &str) -> WarmPoolKey {
    WarmPoolKey::new(shape, storage_class, sandbox, server).unwrap()
}

#[test]
fn pool_names_are_the_exact_shape_and_a_placement_hash() {
    let [small, large] = owner_shapes();
    let name = key(small, "linstor-local", NAMESPACE, "dev").name();
    let suffix = name
        .strip_prefix("cw-pool-1000m-4096mi-10gi-")
        .expect("shape in the name");
    assert_eq!(suffix.len(), 8);
    assert!(
        suffix
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
    assert!(is_warm_pool_name(&name));
    assert_eq!(name, key(small, "linstor-local", NAMESPACE, "dev").name());
    assert!(
        key(large, "linstor-local", NAMESPACE, "dev")
            .name()
            .starts_with("cw-pool-2000m-8192mi-10gi-")
    );

    // Each placement input changes the hash; the shape alone does not.
    let placements = [
        key(small, "linstor-local", NAMESPACE, "dev").name(),
        key(small, "local-path", NAMESPACE, "dev").name(),
        key(small, "linstor-local", "prod-sandboxes", "dev").name(),
        key(small, "linstor-local", NAMESPACE, "prod").name(),
    ];
    let hashes: std::collections::BTreeSet<_> = placements
        .iter()
        .map(|name| &name[name.len() - 8..])
        .collect();
    assert_eq!(hashes.len(), placements.len());
    let hash = |name: String| name[name.len() - 8..].to_owned();
    assert_eq!(
        hash(key(small, "linstor-local", NAMESPACE, "dev").name()),
        hash(key(large, "linstor-local", NAMESPACE, "dev").name()),
    );

    // The longest valid name fits a Kubernetes label value.
    let max = i64::from(i32::MAX);
    let longest = key(shape(max, max, max), "linstor-local", NAMESPACE, "dev").name();
    assert!(longest.len() <= 63, "{longest}");
    assert!(is_warm_pool_name(&longest));
}

#[test]
fn pool_shapes_and_placements_are_validated() {
    let valid = shape(1000, 4096, 10);
    for bad in [
        shape(0, 4096, 10),
        shape(1000, 0, 10),
        shape(1000, 4096, 0),
        shape(-1, 4096, 10),
        shape(i64::from(i32::MAX) + 1, 4096, 10),
    ] {
        assert!(
            WarmPoolKey::new(bad, "linstor-local", NAMESPACE, "dev").is_err(),
            "{bad:?}"
        );
    }
    for (storage_class, sandbox, server) in [
        ("", NAMESPACE, "dev"),
        ("linstor-local", "", "dev"),
        ("linstor-local", NAMESPACE, ""),
        ("Linstor", NAMESPACE, "dev"),
        ("linstor-local", "dev sandboxes", "dev"),
        ("linstor-local", NAMESPACE, "-dev"),
    ] {
        assert!(WarmPoolKey::new(valid, storage_class, sandbox, server).is_err());
    }
}

/// `retire_legacy_shared_warm_pools` deletes `sandbox-warmpool-workspace*`
/// objects, and environment claims use `shadow-pool-*`. Neither family can
/// be a warm pool name, and no warm pool name is in either family.
#[test]
fn pool_names_are_disjoint_from_shadow_and_legacy_pools() {
    for shape in owner_shapes() {
        let name = key(shape, "linstor-local", NAMESPACE, "dev").name();
        assert!(!name.starts_with("shadow-pool-"));
        assert!(!name.starts_with("sandbox-warmpool-"));
        assert!(!is_warm_pool_name(&shadow_warm_pool_name(&name)));
    }
    for other in [
        "shadow-pool-workspace-3d6bb495-efac-419f-bf3a-91696e7c7ca4",
        "sandbox-warmpool-workspace-5513aec3",
        "sandbox-warmpool-workspace-2000m-4096mib-10gib-e1354543",
        "workspace-3d6bb495-efac-419f-bf3a-91696e7c7ca4",
    ] {
        assert!(!is_warm_pool_name(other), "{other}");
    }
    for malformed in [
        "cw-pool-1000m-4096mi-10gi",
        "cw-pool-1000m-4096mi-10gi-0123456",
        "cw-pool-1000m-4096mi-10gi-012345678",
        "cw-pool-1000m-4096mi-10gi-0123456G",
        "cw-pool-1000m-4096mi-10gi-0123ABCD",
        "cw-pool-01000m-4096mi-10gi-01234567",
        "cw-pool-0m-4096mi-10gi-01234567",
        "cw-pool-1000-4096mi-10gi-01234567",
        "cw-pool-1000m-4096mib-10gib-01234567",
        "cw-pool-1000m-4096mi-10gi-extra-01234567",
        "cw-pool-2147483648m-4096mi-10gi-01234567",
        "xcw-pool-1000m-4096mi-10gi-01234567",
    ] {
        assert!(!is_warm_pool_name(malformed), "{malformed}");
    }
}

#[test]
fn pool_objects_share_one_name_revision_and_identity_free_labels() {
    let objects = render(&pool_opts());
    let [template, pool] = [&objects.template, &objects.pool];
    assert_eq!(objects.name, objects.key.name());
    assert_eq!(template["kind"], "SandboxTemplate");
    assert_eq!(pool["kind"], "SandboxWarmPool");
    for object in [template, pool] {
        assert_eq!(object["metadata"]["name"], objects.name);
        assert_eq!(object["metadata"]["namespace"], NAMESPACE);
        assert_eq!(
            object["metadata"]["labels"],
            json!({
                "app.kubernetes.io/managed-by": "codewire",
                "codewire.sh/type": "workspace-pool",
            })
        );
        assert_eq!(
            object["metadata"]["annotations"],
            json!({ POOL_REVISION_ANNOTATION: objects.revision })
        );
    }
    assert_eq!(objects.revision, pool_revision(&template["spec"]));
    assert_eq!(objects.revision.len(), 64);
    assert_eq!(
        pool["spec"],
        json!({
            "replicas": 2,
            "sandboxTemplateRef": { "name": objects.name },
            "updateStrategy": { "type": "Recreate" },
        })
    );
    let text = format!("{template}{pool}");
    assert!(!text.contains("codewire.sh/environment-id"));
    assert!(!text.contains("codewire.sh/org-id"));
}

/// The pool template is the per-environment identity-free rendering of the
/// same shape: only the environment's own name differs (invariant 10).
#[test]
fn pool_spec_equals_each_environment_rendering_of_its_shape() {
    for shape in owner_shapes() {
        let opts = TemplateOpts {
            cpu_millicores: shape.cpu_millicores,
            memory_mib: shape.memory_mib,
            disk_gib: shape.disk_gib,
            ..pool_opts()
        };
        let pool = render(&opts);
        for environment in [
            TemplateOpts {
                name: "workspace-3d6bb495-efac-419f-bf3a-91696e7c7ca4".into(),
                environment_id: "3d6bb495-efac-419f-bf3a-91696e7c7ca4".into(),
                organization_id: "76169e1f-3bbf-46be-96e0-cac68e0ac910".into(),
                operation_generation: 7,
                gateway_token: "synthetic-coordinate".into(),
                daemon_auth_token: "synthetic-daemon".into(),
                ..opts.clone()
            },
            TemplateOpts {
                name: "workspace-1d2e3f4a-5b6c-4d7e-8f90-a1b2c3d4e5f6".into(),
                environment_id: "1d2e3f4a-5b6c-4d7e-8f90-a1b2c3d4e5f6".into(),
                organization_id: "org-other".into(),
                operation_generation: 12,
                gateway_token: "synthetic-coordinate-2".into(),
                daemon_auth_token: "synthetic-daemon-2".into(),
                projection_selection_sha256: Some([0x11; 32]),
                managed_credential_clients:
                    codewire_access::ManagedCredentialClients::from_profile_slots([
                        "codex",
                        "openai",
                        "anthropic",
                        "ssh",
                        "github",
                    ])
                    .unwrap(),
                ..opts.clone()
            },
        ] {
            let rendered = render_sandbox_template(NAMESPACE, &environment);
            assert_eq!(rendered["spec"], pool.template["spec"]);
            assert_eq!(rendered["metadata"]["labels"], json!({}));
        }
    }
}

#[test]
fn each_image_digest_changes_the_revision() {
    let base = render(&pool_opts()).revision;
    let digest = "4444444444444444444444444444444444444444444444444444444444444444";
    let changed = [
        TemplateOpts {
            image: format!("registry.example.invalid/codewire/workspace@sha256:{digest}"),
            ..pool_opts()
        },
        TemplateOpts {
            dind_image: format!("docker.io/library/docker:29.7.1-dind@sha256:{digest}"),
            ..pool_opts()
        },
        TemplateOpts {
            support_image: format!("registry.example.invalid/codewire/gateway@sha256:{digest}"),
            ..pool_opts()
        },
    ];
    let mut revisions = std::collections::BTreeSet::from([base.clone()]);
    for opts in changed {
        let objects = render(&opts);
        assert_ne!(objects.revision, base);
        // The name is the shape and placement only: a new release updates
        // the same pool in place.
        assert_eq!(objects.name, render(&pool_opts()).name);
        revisions.insert(objects.revision);
    }
    assert_eq!(revisions.len(), 4);

    // The runc profile copies the daemon with an init container; its image
    // is the support image too.
    let runc = TemplateOpts {
        runtime_profile: RUNTIME_PROFILE_RUNC.into(),
        ..pool_opts()
    };
    let runc_changed = TemplateOpts {
        support_image: format!("registry.example.invalid/codewire/gateway@sha256:{digest}"),
        ..runc.clone()
    };
    assert_ne!(render(&runc).revision, render(&runc_changed).revision);
}

#[test]
fn revision_ignores_replicas_and_key_order() {
    let opts = pool_opts();
    let two = render_warm_pool(NAMESPACE, &opts, 2, false).unwrap();
    let zero = render_warm_pool(NAMESPACE, &opts, 0, false).unwrap();
    assert_eq!(two.revision, zero.revision);
    assert_eq!(two.template, zero.template);
    assert_eq!(zero.pool["spec"]["replicas"], 0);
    assert!(render_warm_pool(NAMESPACE, &opts, -1, false).is_err());

    let mut forward = serde_json::Map::new();
    forward.insert("a".into(), json!(1));
    forward.insert("b".into(), json!({ "y": 2, "x": 3 }));
    let mut backward = serde_json::Map::new();
    backward.insert("b".into(), json!({ "x": 3, "y": 2 }));
    backward.insert("a".into(), json!(1));
    assert_eq!(
        pool_revision(&Value::Object(forward)),
        pool_revision(&Value::Object(backward))
    );
}

#[test]
fn pool_inputs_carry_no_environment_identity() {
    assert!(validate_pool_template_opts(&pool_opts()).is_ok());
    let base = pool_opts;
    let environment_state = [
        TemplateOpts {
            name: "workspace-env".into(),
            ..base()
        },
        TemplateOpts {
            environment_id: "3d6bb495-efac-419f-bf3a-91696e7c7ca4".into(),
            ..base()
        },
        TemplateOpts {
            organization_id: "org".into(),
            ..base()
        },
        TemplateOpts {
            operation_generation: 7,
            ..base()
        },
        TemplateOpts {
            gateway_token: "synthetic-coordinate".into(),
            ..base()
        },
        TemplateOpts {
            daemon_auth_token: "synthetic-daemon".into(),
            ..base()
        },
        TemplateOpts {
            projection_selection_sha256: Some([0x11; 32]),
            ..base()
        },
        TemplateOpts {
            managed_credential_clients:
                codewire_access::ManagedCredentialClients::from_profile_slots(["github"]).unwrap(),
            ..base()
        },
        TemplateOpts {
            confidential_storage_manifest_uri: "kbs:///synthetic".into(),
            ..base()
        },
        // The environment-token rollback renders the daemon token.
        TemplateOpts {
            workspace_identity: WorkspaceIdentity::EnvironmentToken,
            ..base()
        },
    ];
    for opts in environment_state {
        assert!(
            render_warm_pool(NAMESPACE, &opts, 2, false).is_err(),
            "{opts:?}"
        );
    }
}

#[test]
fn confidential_is_never_pooled() {
    let confidential = TemplateOpts {
        runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
        ..pool_opts()
    };
    let error = render_warm_pool(NAMESPACE, &confidential, 2, true).unwrap_err();
    assert!(error.to_string().contains("confidential"), "{error}");
}

#[test]
fn pool_images_must_be_digest_pinned_outside_diagnostic_runtimes() {
    let tagged = [
        TemplateOpts {
            image: "registry.example.invalid/codewire/workspace:main".into(),
            ..pool_opts()
        },
        TemplateOpts {
            dind_image: "docker.io/library/docker:29.7.1-dind".into(),
            ..pool_opts()
        },
        TemplateOpts {
            support_image: "git.example.invalid/codewire/gateway:main-4b5b65d".into(),
            ..pool_opts()
        },
        TemplateOpts {
            support_image: "git.example.invalid/codewire/gateway@sha256:short".into(),
            ..pool_opts()
        },
        TemplateOpts {
            runtime_profile: RUNTIME_PROFILE_RUNC.into(),
            support_image: "git.example.com/codewire/gateway:local".into(),
            ..pool_opts()
        },
    ];
    for opts in tagged {
        let error = render_warm_pool(NAMESPACE, &opts, 2, false).unwrap_err();
        assert!(error.to_string().contains("digest-pinned"), "{error}");
        assert!(render_warm_pool(NAMESPACE, &opts, 2, true).is_ok());
    }
    // A tag plus digest is pinned.
    let tag_and_digest = TemplateOpts {
        support_image: format!(
            "git.example.invalid/codewire/gateway:main-4b5b65d@sha256:{}",
            "5".repeat(64)
        ),
        ..pool_opts()
    };
    assert!(render_warm_pool(NAMESPACE, &tag_and_digest, 2, false).is_ok());
}
