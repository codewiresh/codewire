use super::*;
use crate::sandbox::shadow_warm_pool_name;
use crate::sandbox::template::{
    CredentialRuntimeTemplateConfig, DOCKER_MODE_GUEST_DIND, RUNTIME_PROFILE_COMMODITY,
    RUNTIME_PROFILE_RUNC, WorkspaceIdentity,
};

const NAMESPACE: &str = "dev-sandboxes";
const WORKSPACE_IMAGE: &str = "registry.example.invalid/codewire/workspace@sha256:1111111111111111111111111111111111111111111111111111111111111111";
const SUPPORT_IMAGE: &str = "registry.example.invalid/codewire/daemon@sha256:2222222222222222222222222222222222222222222222222222222222222222";
const DIND_IMAGE: &str = "docker.io/library/docker:29.7.1-dind@sha256:3333333333333333333333333333333333333333333333333333333333333333";
const BINDING_URL: &str =
    "https://codewire-orchestration-workspace-binding.dev.svc.cluster.local:8087";

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
                daemon_auth_token: "synthetic-daemon".into(),
                ..opts.clone()
            },
            TemplateOpts {
                name: "workspace-1d2e3f4a-5b6c-4d7e-8f90-a1b2c3d4e5f6".into(),
                environment_id: "1d2e3f4a-5b6c-4d7e-8f90-a1b2c3d4e5f6".into(),
                organization_id: "org-other".into(),
                operation_generation: 12,
                daemon_auth_token: "daemon-token-other".into(),
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
            assert_eq!(
                rendered["spec"],
                without_revision_marker(&pool.template["spec"])
            );
            assert_eq!(pool_revision(&rendered["spec"]), pool.revision);
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
            support_image: format!("registry.example.invalid/codewire/daemon@sha256:{digest}"),
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
        support_image: format!("registry.example.invalid/codewire/daemon@sha256:{digest}"),
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
            support_image: "registry.example.invalid/codewire/daemon:main-4b5b65d".into(),
            ..pool_opts()
        },
        TemplateOpts {
            support_image: "registry.example.invalid/codewire/daemon@sha256:short".into(),
            ..pool_opts()
        },
        TemplateOpts {
            runtime_profile: RUNTIME_PROFILE_RUNC.into(),
            support_image: "git.example.com/codewire/daemon:local".into(),
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
            "registry.example.invalid/codewire/daemon:main-4b5b65d@sha256:{}",
            "5".repeat(64)
        ),
        ..pool_opts()
    };
    assert!(render_warm_pool(NAMESPACE, &tag_and_digest, 2, false).is_ok());
}

#[test]
fn warm_pool_shapes_parse_exact_shapes_and_member_counts() {
    assert_eq!(parse_warm_pool_shapes("").unwrap(), []);
    assert_eq!(parse_warm_pool_shapes("  ").unwrap(), []);
    assert_eq!(
        parse_warm_pool_shapes(" 1000m/4096Mi/10Gi=2 , 2000m/8192Mi/10Gi=0").unwrap(),
        [
            ConfiguredShape {
                shape: shape(1000, 4096, 10),
                members: 2,
            },
            ConfiguredShape {
                shape: shape(2000, 8192, 10),
                members: 0,
            },
        ]
    );
    assert_eq!(
        parse_warm_pool_shapes("500m/1024Mi/5Gi=16").unwrap()[0].members,
        MAX_POOL_MEMBERS
    );
    for invalid in [
        "1000m/4096Mi/10Gi",
        "1000m/4096Mi/10Gi=",
        "1000m/4096Mi/10Gi=17",
        "1000m/4096Mi/10Gi=-1",
        "1000m/4096Mi/10Gi=02",
        "1/4096Mi/10Gi=1",
        "1000m/4Gi/10Gi=1",
        "1000m/4096Mi/10G=1",
        "1000m/4096Mi=1",
        "1000m/4096Mi/10Gi/1Gi=1",
        "0m/4096Mi/10Gi=1",
        "01000m/4096Mi/10Gi=1",
        "1000m/4096Mi/0Gi=1",
        "1000m/4096Mi/10Gi=1,",
        "1000m/4096Mi/10Gi=1,1000m/4096Mi/10Gi=2",
        "4294967296m/4096Mi/10Gi=1",
        "1000m / 4096Mi / 10Gi=1",
    ] {
        assert!(
            parse_warm_pool_shapes(invalid).is_err(),
            "{invalid:?} must be refused"
        );
    }
}

#[test]
fn shape_labels_and_pool_names_round_trip() {
    let [small, large] = owner_shapes();
    assert_eq!(shape_label(small), "1000m-4096mi-10gi");
    for shape in [small, large] {
        let name = key(shape, "linstor-local", NAMESPACE, "dev").name();
        assert_eq!(warm_pool_name_shape(&name), Some(shape));
    }
    assert_eq!(warm_pool_name_shape("shadow-pool-workspace-env"), None);
    assert_eq!(warm_pool_name_shape("cw-pool-1000m-4096mi-10gi"), None);
}

#[test]
fn pool_labels_select_only_codewire_pools() {
    use std::collections::BTreeMap;
    assert_eq!(
        pool_label_selector(),
        "app.kubernetes.io/managed-by=codewire,codewire.sh/type=workspace-pool"
    );
    let labels = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    };
    let pool = labels(&[
        ("app.kubernetes.io/managed-by", "codewire"),
        ("codewire.sh/type", "workspace-pool"),
        (TEMPLATE_REF_HASH_LABEL, "0f0f0f0f"),
    ]);
    assert!(has_pool_labels(Some(&pool)));
    assert!(!has_pool_labels(Some(&labels(&[(
        "codewire.sh/type",
        "workspace-pool"
    )]))));
    assert!(!has_pool_labels(None));
}

/// The admission policies pin what this renderer produces; drift in either
/// fails here first.
#[test]
fn the_admission_policy_pins_the_renderer() {
    let policy = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deployments/k8s/orchestration/warm-pool-authz.yaml"
    ))
    .expect("warm-pool admission policy");
    for fragment in [
        format!("object.spec.replicas <= {MAX_POOL_MEMBERS}"),
        format!("'{POOL_REVISION_ANNOTATION}' in object.metadata.annotations"),
        format!("object.metadata.labels['codewire.sh/type'] == '{WARM_POOL_TYPE}'"),
        format!("request.name.startsWith('{WARM_POOL_NAME_PREFIX}')"),
        "object.spec.updateStrategy.type == 'Recreate'".to_owned(),
        format!(
            "variables.pod.runtimeClassName != '{}'",
            crate::sandbox::template::RUNTIME_CLASS_CONFIDENTIAL
        ),
    ] {
        assert!(policy.contains(&fragment), "policy lost {fragment}");
    }
    // The policy's name pattern accepts exactly the names the renderer emits.
    let pattern = "^cw-pool-[1-9][0-9]{0,9}m-[1-9][0-9]{0,9}mi-[1-9][0-9]{0,9}gi-[0-9a-f]{8}$";
    assert!(policy.contains(pattern));
    for shape in owner_shapes() {
        let name = key(shape, "linstor-local", NAMESPACE, "dev").name();
        assert!(is_warm_pool_name(&name));
        let (_, hash) = name.rsplit_once('-').unwrap();
        assert_eq!(hash.len(), 8);
    }
    let rendered = render(&pool_opts());
    assert_eq!(rendered.pool["spec"]["updateStrategy"]["type"], "Recreate");
    assert_eq!(
        rendered.template["spec"]["podTemplate"]["spec"]["serviceAccountName"],
        "codewire-sandbox"
    );
    assert_eq!(
        rendered.template["spec"]["podTemplate"]["spec"]["automountServiceAccountToken"],
        false
    );
    assert!(
        rendered.template["spec"]["networkPolicy"]
            .get("ingress")
            .is_none()
    );
    // Review M2: the template policy is an allowlist, so everything the
    // renderer emits must be on it.
    let pod = &rendered.template["spec"]["podTemplate"]["spec"];
    assert_eq!(pod["runtimeClassName"], "commodity");
    assert!(policy.contains(r#"expression: "['commodity']""#));
    let containers = pod["containers"]
        .as_array()
        .unwrap()
        .iter()
        .chain(pod["initContainers"].as_array().into_iter().flatten());
    for container in containers {
        for entry in container["env"].as_array().into_iter().flatten() {
            let name = entry["name"].as_str().unwrap();
            assert!(policy.contains(&format!("'{name}'")), "policy lacks {name}");
        }
    }
    assert!(policy.contains(&format!("'{POOL_REVISION_ENV}'")));
    for volume in pod["volumes"].as_array().unwrap() {
        let source = volume
            .as_object()
            .unwrap()
            .keys()
            .find(|key| *key != "name")
            .unwrap();
        assert!(
            ["image", "emptyDir", "configMap", "projected"].contains(&source.as_str()),
            "policy refuses {source}"
        );
        for projected in volume["projected"]["sources"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let audience = projected["serviceAccountToken"]["audience"]
                .as_str()
                .unwrap();
            assert!(
                policy.contains(&format!("'{audience}'")),
                "policy lacks {audience}"
            );
        }
    }
}

/// What the agent-sandbox controller stores when it copies a rendering
/// through typed Go structs: canonical quantities and no empty `omitempty`
/// values.
pub(crate) fn controller_copy(rendered: &Value) -> Value {
    fn walk(value: &mut Value, path: &str) {
        match value {
            Value::Object(fields) => {
                fields.retain(|key, field| !(key == "value" && field.as_str() == Some("")));
                for (key, field) in fields.iter_mut() {
                    walk(field, &format!("{path}/{key}"));
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter_mut().enumerate() {
                    walk(item, &format!("{path}/{index}"));
                }
            }
            Value::String(text) if path.contains("/resources/") => {
                let canonical = match text.as_str() {
                    "1000m" => "1",
                    "2000m" => "2",
                    "4096Mi" => "4Gi",
                    "8192Mi" => "8Gi",
                    other => other,
                };
                *text = canonical.to_owned();
            }
            _ => {}
        }
    }
    let mut copy = rendered.clone();
    walk(&mut copy, "");
    copy
}

#[test]
fn stored_specs_compare_by_meaning_not_spelling() {
    let rendered = render(&pool_opts()).template["spec"].clone();
    let stored = controller_copy(&rendered);
    assert_ne!(
        stored, rendered,
        "the fixture exercises the controller's spelling"
    );
    assert_eq!(spec_equivalent(&rendered, &stored, "/spec"), Ok(()));

    let mut defaulted = stored.clone();
    defaulted["podTemplate"]["spec"]["containers"][0]["terminationMessagePath"] = json!("");
    defaulted["podTemplate"]["spec"]["containers"][0]["stdin"] = json!(false);
    assert_eq!(spec_equivalent(&rendered, &defaulted, "/spec"), Ok(()));

    let refused = |mutate: &dyn Fn(&mut Value)| {
        let mut live = stored.clone();
        mutate(&mut live);
        spec_equivalent(&rendered, &live, "/spec").expect_err("a different spec was equivalent")
    };
    assert_eq!(
        refused(
            &|live| live["podTemplate"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] =
                json!("2")
        ),
        "/spec/podTemplate/spec/containers/0/resources/limits/cpu"
    );
    assert_eq!(
        refused(&|live| live["podTemplate"]["spec"]["hostNetwork"] = json!(true)),
        "/spec/podTemplate/spec/hostNetwork"
    );
    assert_eq!(
        refused(&|live| live["podTemplate"]["spec"]["securityContext"]["runAsUser"] = json!(0)),
        "/spec/podTemplate/spec/securityContext/runAsUser"
    );
    assert_eq!(
        refused(
            &|live| live["podTemplate"]["spec"]["containers"][0]["image"] = json!("x@sha256:0")
        ),
        "/spec/podTemplate/spec/containers/0/image"
    );
    assert_eq!(
        refused(&|live| {
            live["podTemplate"]["spec"]["volumes"]
                .as_array_mut()
                .unwrap()
                .pop();
        }),
        "/spec/podTemplate/spec/volumes"
    );
    // Only resource quantities are compared by value.
    let with_env = |value: &str| json!({ "env": [{ "name": "LIMIT", "value": value }] });
    assert!(spec_equivalent(&with_env("1000m"), &with_env("1"), "/container").is_err());
    assert!(
        spec_equivalent(
            &json!({ "resources": { "limits": { "memory": "4096Mi" } } }),
            &json!({ "resources": { "limits": { "memory": "4Gi" } } }),
            "/container"
        )
        .is_ok()
    );
}

/// Review L1: an absent pointer boolean is the API default, not `false`.
#[test]
fn an_absent_rendered_false_is_not_equivalent() {
    let rendered = render(&pool_opts()).template["spec"].clone();
    let mut live = controller_copy(&rendered);
    live["podTemplate"]["spec"]
        .as_object_mut()
        .unwrap()
        .remove("automountServiceAccountToken");
    assert_eq!(
        spec_equivalent(&rendered, &live, "/spec"),
        Err("/spec/podTemplate/spec/automountServiceAccountToken".to_owned())
    );
}

/// What the agent-sandbox controller makes of a pool template: the member
/// Sandbox copies the blueprint through typed structs, adoption replaces the
/// Pod metadata with the template's plus the claim's labels, and the API
/// server may add its CRD's scalar defaults.
fn adopted_sandbox(template: &Value) -> Value {
    let mut sandbox = json!({
        "apiVersion": "agents.x-k8s.io/v1beta1",
        "kind": "Sandbox",
        "metadata": { "name": "cw-pool-1000m-4096mi-10gi-78909fe3-x7k2p" },
        "spec": controller_copy(template)["spec"].clone(),
    });
    let labels = sandbox["spec"]["podTemplate"]["metadata"]["labels"]
        .as_object_mut()
        .unwrap();
    labels.insert("codewire.sh/environment-id".into(), json!("env"));
    labels.insert("agents.x-k8s.io/claim-uid".into(), json!("claim"));
    sandbox["spec"]["podTemplate"]["spec"]["containers"][0]["terminationMessagePath"] = json!("");
    sandbox
}

#[test]
fn a_pool_born_sandbox_must_equal_the_rendering() {
    let rendered = render(&pool_opts()).template;
    let sandbox = adopted_sandbox(&rendered);
    assert_eq!(sandbox_matches_rendering(&sandbox, &rendered), Ok(()));
    let mut evictable = sandbox.clone();
    evictable["spec"]["podTemplate"]["metadata"]["annotations"]["cluster-autoscaler.kubernetes.io/safe-to-evict"] =
        json!("true");
    assert_eq!(sandbox_matches_rendering(&evictable, &rendered), Ok(()));

    let refused = |mutate: &dyn Fn(&mut Value)| {
        let mut sandbox = sandbox.clone();
        mutate(&mut sandbox);
        sandbox_matches_rendering(&sandbox, &rendered).expect_err("a changed member was accepted")
    };
    assert_eq!(
        refused(
            &|sandbox| sandbox["spec"]["podTemplate"]["spec"]["containers"][0]["image"] = json!(
                "registry.example.invalid/codewire/workspace@sha256:9999999999999999999999999999999999999999999999999999999999999999"
            )
        ),
        "/spec/podTemplate/spec/containers/0/image"
    );
    assert_eq!(
        refused(
            &|sandbox| sandbox["spec"]["podTemplate"]["spec"]["containers"][0]["env"]
                .as_array_mut()
                .unwrap()
                .push(json!({ "name": "CODEWIRE_DAEMON_AUTH_TOKEN", "value": "x" }))
        ),
        "/spec/podTemplate/spec/containers/0/env"
    );
    assert_eq!(
        refused(&|sandbox| sandbox["spec"]["podTemplate"]["spec"]["hostNetwork"] = json!(true)),
        "/spec/podTemplate/spec/hostNetwork"
    );
    assert_eq!(
        refused(&|sandbox| sandbox["spec"]["podTemplate"]["spec"]
            .as_object_mut()
            .unwrap()
            .remove("runtimeClassName")
            .map(|_| ())
            .unwrap()),
        "/spec/podTemplate/spec/runtimeClassName"
    );
    assert_eq!(
        refused(
            &|sandbox| sandbox["spec"]["volumeClaimTemplates"][0]["spec"]["resources"]["requests"]
                ["storage"] = json!("20Gi")
        ),
        "/spec/volumeClaimTemplates/0/spec/resources/requests/storage"
    );
    assert_eq!(
        refused(
            &|sandbox| sandbox["spec"]["podTemplate"]["metadata"]["annotations"]["io.katacontainers.config.hypervisor.kernel_params"] =
                json!("x")
        ),
        "/spec/podTemplate/metadata/annotations/io.katacontainers.config.hypervisor.kernel_params"
    );
    assert_eq!(
        refused(
            &|sandbox| sandbox["spec"]["podTemplate"]["metadata"]["labels"]["codewire.sh/type"] =
                json!("gateway")
        ),
        "/spec/podTemplate/metadata/labels/codewire.sh/type"
    );
    // Another shape's rendering is another spec.
    let other = render(&TemplateOpts {
        cpu_millicores: 2000,
        memory_mib: 8192,
        ..pool_opts()
    })
    .template;
    assert!(sandbox_matches_rendering(&sandbox, &other).is_err());
}
