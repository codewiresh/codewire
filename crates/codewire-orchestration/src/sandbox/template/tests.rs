#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    use base64::Engine;
    use flate2::read::GzDecoder;
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    const CONTENT_ADDRESSED_MANIFEST_URI: &str = "kbs:///default/codewire-storage-manifests/sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[cfg(unix)]
    #[test]
    fn commodity_shell_pid_survives_kubelet_command_expansion() {
        let rendered = render_sandbox_template("dev-sandboxes", &commodity_opts());
        let containers = rendered["spec"]["podTemplate"]["spec"]["containers"]
            .as_array()
            .unwrap();
        let dind = containers.iter().find(|c| c["name"] == "dind").unwrap();
        let command = dind["command"][2].as_str().unwrap();
        // Container.command's documented expansion reduces each `$$` once,
        // before the shell runs (kubelet expansion.go, Kubernetes v1.36.0).
        let expanded = command.replace("$$", "$");
        let self_move = expanded
            .lines()
            .find(|line| line.contains("> \"$cgroup_root/init/cgroup.procs\""))
            .unwrap()
            .split_once(" || ")
            .unwrap()
            .0
            .replace("$cgroup_root/init/cgroup.procs", "$TEST_MOVED_PID");
        let marker = expanded
            .lines()
            .find(|line| line.starts_with("  marker_temporary="))
            .unwrap();
        let scratch = tempfile::tempdir().unwrap();
        // Execute only the rendered self-PID write and marker assignment in
        // ordinary files, never the actual cgroup or Docker data operations.
        let script = format!(
            "printf '%s\\n' \"$$\" > \"$TEST_EXPECTED_PID\"\n\
             data_root=\"$TEST_ROOT\"\n{self_move}\n{marker}\n\
             printf '%s\\n' \"$marker_temporary\" > \"$TEST_MARKER\""
        );
        let output = std::process::Command::new("sh")
            .args(["-ec", &script])
            .env("TEST_ROOT", scratch.path())
            .env("TEST_EXPECTED_PID", scratch.path().join("expected"))
            .env("TEST_MOVED_PID", scratch.path().join("moved"))
            .env("TEST_MARKER", scratch.path().join("marker"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let expected = std::fs::read_to_string(scratch.path().join("expected")).unwrap();
        assert!(expected.trim().parse::<u32>().unwrap() > 0);
        assert_eq!(
            std::fs::read_to_string(scratch.path().join("moved")).unwrap(),
            expected
        );
        assert_eq!(
            std::fs::read_to_string(scratch.path().join("marker")).unwrap(),
            format!(
                "{}/.codewire-containerd-store-v1.tmp.{}\n",
                scratch.path().display(),
                expected.trim()
            )
        );
    }

    #[test]
    fn a_workspace_claim_restores_only_from_the_snapshot_it_names() {
        let claim = |source: Option<&str>| {
            let rendered = render_sandbox_template(
                "dev-sandboxes",
                &TemplateOpts {
                    name: "tmpl-from-snapshot".into(),
                    disk_gib: 80,
                    workspace_storage_class: "example-workspace-class".into(),
                    workspace_source_snapshot: source.map(str::to_owned),
                    ..Default::default()
                },
            );
            rendered["spec"]["volumeClaimTemplates"][0]["spec"].clone()
        };
        assert!(claim(None)["dataSource"].is_null());
        let restored = claim(Some("cw-snap-one"));
        assert_eq!(restored["dataSource"]["kind"], "VolumeSnapshot");
        assert_eq!(restored["dataSource"]["apiGroup"], "snapshot.storage.k8s.io");
        assert_eq!(restored["dataSource"]["name"], "cw-snap-one");
        assert_eq!(restored["storageClassName"], "example-workspace-class");
    }

    #[test]
    fn the_environment_shadow_pool_names_its_label_free_template() {
        let opts = TemplateOpts {
            environment_id: "env-test".into(),
            ..commodity_opts()
        };
        let rendered = render_sandbox_template("dev-sandboxes", &opts);
        assert!(rendered["metadata"]["labels"].as_object().unwrap().is_empty());
        let shadow = render_sandbox_shadow_pool("dev-sandboxes", "shadow", &opts.name, "env-test");
        assert_eq!(shadow["metadata"]["labels"][LABEL_ENV_ID], "env-test");
        assert_eq!(shadow["spec"]["sandboxTemplateRef"]["name"], opts.name);
    }

    fn decode_gzip_base64(encoded: &str) -> String {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let mut decoder = GzDecoder::new(&raw[..]);
        let mut decoded = String::new();
        decoder.read_to_string(&mut decoded).unwrap();
        decoded
    }

    fn kata_policy_allows(policy: &str, input: &Value) -> bool {
        let mut engine = regorus::Engine::new();
        engine.set_strict_builtin_errors(false);
        engine
            .add_policy("codewire.rego".to_string(), policy.to_string())
            .expect("Kata regorus must parse the rendered policy");
        engine
            .set_input_json(&input.to_string())
            .expect("policy input must be valid JSON");
        let result = engine
            .eval_query(
                "data.agent_policy.CreateContainerRequest".to_string(),
                false,
            )
            .expect("Kata regorus must evaluate the rendered policy");
        assert_eq!(
            result.result.len(),
            1,
            "unexpected policy result: {result:?}"
        );
        assert_eq!(
            result.result[0].expressions.len(),
            1,
            "unexpected policy expression result: {result:?}"
        );
        result.result[0].expressions[0].value == regorus::Value::Bool(true)
    }

    fn confidential_create_input(container: &str, image: &str, destinations: &[&str]) -> Value {
        let digest = Sha256::digest(CONTENT_ADDRESSED_MANIFEST_URI.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let mount_point =
            format!("/run/kata-containers/shared/containers/passthrough/confidential-{digest}");
        serde_json::json!({
            "OCI": {
                "Annotations": {
                    "io.kubernetes.cri.container-name": container,
                    "io.kubernetes.cri.image-name": image,
                },
                "Linux": { "Devices": [] },
                "Mounts": destinations.iter().map(|destination| serde_json::json!({
                    "destination": destination,
                    "source": mount_point,
                    "type_": "bind",
                    "options": ["rbind", "rprivate", "rw"],
                })).collect::<Vec<_>>(),
            },
            "devices": [],
            "storages": [{
                "driver": "blk",
                "driver_options": [],
                "fstype": "confidential-storage",
                "fs_group": {
                    "group_id": 1000,
                    "group_change_policy": 1,
                },
                "mount_point": mount_point,
                "options": [],
                "shared": false,
                "source": "00/00",
                "confidential_storage": {
                    "manifest_uri": CONTENT_ADDRESSED_MANIFEST_URI,
                    "requested_access": 2,
                },
            }],
        })
    }

    /// The OCI process the runtime presents for a rendered container: its
    /// command, and its literal env entries among the ones the kubelet and
    /// image add. Downward-API entries carry a per-Pod value.
    fn runtime_process(pod_spec: &Value, container: &str) -> Value {
        let container = pod_spec["containers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|candidate| candidate["name"] == container)
            .unwrap();
        let mut env = vec![
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned(),
            "HOSTNAME=workspace-0".to_owned(),
            "KUBERNETES_SERVICE_HOST=10.43.0.1".to_owned(),
        ];
        for entry in container["env"].as_array().into_iter().flatten() {
            let name = entry["name"].as_str().unwrap();
            match entry["value"].as_str() {
                Some(value) => env.push(format!("{name}={value}")),
                None => env.push(format!("{name}=7e7b20f6-0bd2-4f11-8b16-9c239851eb52")),
            }
        }
        json!({ "Args": container["command"].clone(), "Env": env })
    }

    fn kata_cri_sandbox_create_input() -> Value {
        serde_json::json!({
            "OCI": {
                "Annotations": {
                    "io.katacontainers.pkg.oci.container_type": "pod_sandbox",
                    "io.kubernetes.cri.container-type": "sandbox",
                    "io.kubernetes.cri.podsandbox.image-name": "registry.k8s.io/pause:3.10",
                },
                "Linux": { "Devices": [] },
                "Mounts": [{
                    "destination": "/proc",
                    "source": "proc",
                    "type_": "proc",
                    "options": ["nosuid", "noexec", "nodev"],
                }],
            },
            "devices": [],
            "storages": [{
                "driver": "image_guest_pull",
                "driver_options": [],
                "fstype": "overlay",
                "fs_group": null,
                "mount_point": "/run/kata-containers/sandbox/rootfs",
                "options": [],
                "shared": false,
                "source": "pause",
            }],
        })
    }

    fn confidential_policy_conformance_fixture() -> Value {
        serde_json::from_str(include_str!(
            "../../../tests/fixtures/confidential-storage-policy-v1.json"
        ))
        .expect("shared confidential-storage policy fixture must be valid JSON")
    }

    fn apply_conformance_patches(request: &mut Value, patches: &Value) {
        for patch in patches.as_array().expect("patches must be an array") {
            let path = patch["path"].as_str().expect("patch path must be a string");
            if let Some(copy_from) = patch.get("copy_from").and_then(Value::as_str) {
                let value = request
                    .pointer(copy_from)
                    .unwrap_or_else(|| panic!("copy source {copy_from:?} must exist"))
                    .clone();
                let parent_path = path
                    .strip_suffix("/-")
                    .unwrap_or_else(|| panic!("copy destination {path:?} must append to an array"));
                request
                    .pointer_mut(parent_path)
                    .and_then(Value::as_array_mut)
                    .unwrap_or_else(|| panic!("copy destination parent {parent_path:?} must exist"))
                    .push(value);
            } else {
                *request
                    .pointer_mut(path)
                    .unwrap_or_else(|| panic!("replacement path {path:?} must exist")) =
                    patch["value"].clone();
            }
        }
    }

    /// A commodity Pod spec's init containers are `mount-workspace`, which
    /// also prepares the guest DinD's Docker data image from the three data
    /// variables, then the `workspace-flush` sidecar: unprivileged, with only
    /// the mounted workspace, so no credential, token or daemon copy reaches
    /// either (#3718, durability design §1, §4).
    fn assert_block_workspace_inits(pod_spec: &Value) {
        let inits = pod_spec["initContainers"].as_array().expect("init containers");
        let names: Vec<_> = inits.iter().map(|init| init["name"].as_str().unwrap()).collect();
        assert_eq!(names, [MOUNT_WORKSPACE_CONTAINER, WORKSPACE_FLUSH_CONTAINER]);
        let mount = &inits[0];
        assert_eq!(mount["command"][2], MOUNT_WORKSPACE_SCRIPT);
        let env: Vec<_> = mount["env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["name"].as_str().unwrap())
            .collect();
        assert_eq!(env, DOCKER_DATA_INIT_ENV);
        assert!(mount.get("envFrom").is_none());
        let flush = &inits[1];
        assert_eq!(flush["restartPolicy"], "Always");
        assert_eq!(flush["command"], json!(["sh", "-c", WORKSPACE_FLUSH_SCRIPT]));
        assert_eq!(
            flush["volumeMounts"],
            json!([{ "name": "wsmnt", "mountPath": "/mnt/ws", "mountPropagation": "HostToContainer" }])
        );
        assert_eq!(flush["securityContext"]["runAsUser"], 1000);
        assert_eq!(flush["securityContext"]["capabilities"], json!({ "drop": ["ALL"] }));
        assert_eq!(flush["securityContext"]["allowPrivilegeEscalation"], false);
        assert!(flush.get("env").is_none() && flush.get("envFrom").is_none());
        assert!(flush.get("volumeDevices").is_none());
    }


    #[test]
    fn operation_generation_never_changes_the_workspace_template() {
        let mut opts = commodity_opts();
        let first_workspace = render_sandbox_template("dev-sandboxes", &opts);
        opts.operation_generation = 8;
        assert_eq!(
            first_workspace,
            render_sandbox_template("dev-sandboxes", &opts)
        );
        assert!(
            first_workspace["spec"]["podTemplate"]["metadata"]["labels"]
                .get(super::super::LABEL_OPERATION_GENERATION)
                .is_none()
        );
    }

    /// A synthetic, public roots bundle: only its shape matters to rendering.
    const MEASURED_BINDING_ROOTS: &str =
        "-----BEGIN CERTIFICATE-----\nMIIBsynthetic\n-----END CERTIFICATE-----\n";
    const MEASURED_BINDING_URL: &str =
        "https://codewire-orchestration-workspace-binding.dev.svc.cluster.local:8087";

    /// The environment token a pre-binding rendering carried. No rendering
    /// carries it any more.
    const LEGACY_DAEMON_AUTH_TOKEN_ENV: &str = "CODEWIRE_DAEMON_AUTH_TOKEN";

    /// A confidential rendering as orchestration builds it (B2c): bound,
    /// with measured binding roots.
    fn measured(opts: TemplateOpts) -> TemplateOpts {
        TemplateOpts {
            runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
            workspace_binding_url: MEASURED_BINDING_URL.into(),
            measured_binding_roots: MEASURED_BINDING_ROOTS.into(),
            ..opts
        }
    }

    fn commodity_opts() -> TemplateOpts {
        TemplateOpts {
            name: "tmpl-golden-commodity".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            support_image: "registry.example.invalid/codewire/daemon:golden".into(),
            runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
            environment_id: "env-golden-commodity".into(),
            organization_id: "org-golden-commodity".into(),
            operation_generation: 7,
            api_base_url: "https://codewire-dev.sh".into(),
            server_namespace: "dev".into(),
            derp_host: "derp.codewire-dev.sh".into(),
            derp_port: 443,
            stun_host: "stun.codewire-dev.sh".into(),
            stun_port: 3478,
            cpu_millicores: 2000,
            memory_mib: 4096,
            disk_gib: 40,
            workspace_storage_class: "local-path".into(),
            ..Default::default()
        }
    }

    fn credential_opts() -> TemplateOpts {
        TemplateOpts {
            environment_id: "be31063a-8ec8-46d5-aa17-75cda1729370".into(),
            credential_runtime: Some(CredentialRuntimeTemplateConfig::synthetic("dev-sandboxes")),
            managed_credential_clients:
                codewire_access::ManagedCredentialClients::from_profile_slots(["codex"]).unwrap(),
            projection_selection_sha256: Some([0xab; 32]),
            ..commodity_opts()
        }
    }

    /// Every hosted rendering that once carried Codex's ConfigMap, memory home
    /// or init copy. The daemon now writes the user's `~/.codex` itself.
    const LEGACY_CODEX_FRAGMENTS: [&str; 5] = [
        "cw-credential-codex-",
        "credential-codex-config",
        "credential-codex-home",
        "codex-bootstrap",
        "/run/codewire-codex",
    ];

    fn assert_no_legacy_codex(rendered: &Value) {
        let text = rendered.to_string();
        for fragment in LEGACY_CODEX_FRAGMENTS {
            assert!(!text.contains(fragment), "{fragment} rendered");
        }
    }

    #[test]
    fn credential_runtime_renders_no_codex_object() {
        // Selected Codex renders no ConfigMap, memory home or init copy in any
        // tier or identity mode: the daemon writes `~/.codex` itself.
        for profile in [RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_RUNC] {
            for identity_free in [false, true] {
                let mut variant = credential_opts();
                variant.runtime_profile = profile.into();
                if identity_free {
                    variant.workspace_binding_url = "http://binding.dev.svc.cluster.local:8087".into();
                }
                assert_no_legacy_codex(&render_sandbox_template("dev-sandboxes", &variant));
            }
        }
        // A confidential workspace always binds (B2c).
        assert_no_legacy_codex(&render_sandbox_template(
            "dev-sandboxes",
            &measured(credential_opts()),
        ));
    }

    #[test]
    fn hosted_provider_loopback_is_not_exposed_by_workspace_templates_or_services() {
        for profile in [RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_CONFIDENTIAL] {
            let mut opts = credential_opts();
            opts.runtime_profile = profile.into();
            if profile == RUNTIME_PROFILE_CONFIDENTIAL {
                opts = measured(opts);
            }
            let template = render_sandbox_template("dev-sandboxes", &opts);
            let spec = &template["spec"]["podTemplate"]["spec"];
            assert!(!spec["hostNetwork"].as_bool().unwrap_or(false));
            for group in ["containers", "initContainers"] {
                for container in spec[group].as_array().into_iter().flatten() {
                    for port in container["ports"].as_array().into_iter().flatten() {
                        assert_ne!(port["containerPort"], 38081);
                        assert_ne!(port["hostPort"], 38081);
                    }
                }
            }
            let service = render_workspace_daemon_service("dev-sandboxes", &opts);
            for port in service["spec"]["ports"].as_array().unwrap() {
                for key in ["port", "targetPort", "nodePort"] {
                    assert_ne!(port[key], 38081);
                }
            }
        }
    }

    #[test]
    fn hosted_projection_bootstrap_binds_the_workspace_and_private_process_directory() {
        for profile in [RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_CONFIDENTIAL] {
            let mut opts = credential_opts();
            opts.runtime_profile = profile.into();
            opts.projection_selection_sha256 = Some([0xab; 32]);
            if profile == RUNTIME_PROFILE_CONFIDENTIAL {
                opts = measured(opts);
            }
            let template = render_sandbox_template("dev-sandboxes", &opts);
            let workspace = &template["spec"]["podTemplate"]["spec"];
            // Every workspace binds: its projection arrives in the bind
            // response, never as rendered env.
            let env = workspace["containers"][0]["env"].to_string();
            for name in [
                codewire_daemon::config::HOSTED_PROJECTION_SHA256_ENV,
                codewire_daemon::config::ENVIRONMENT_ID_ENV,
                codewire_daemon::config::ENVIRONMENT_GENERATION_ENV,
            ] {
                assert!(!env.contains(&format!("\"{name}\"")), "{name}");
            }
            assert_eq!(workspace["securityContext"]["runAsUser"], 1000);
            assert_eq!(workspace["securityContext"]["runAsGroup"], 1000);
            assert!(
                workspace["containers"][0]["volumeMounts"]
                    .as_array()
                    .unwrap()
                    .contains(&json!({"name":"codewire-run","mountPath":"/codewire/run"}))
            );
            if profile == RUNTIME_PROFILE_CONFIDENTIAL {
                let init = &workspace["initContainers"][0];
                assert!(init.get("securityContext").is_none());
                let command = init["command"][2].as_str().unwrap();
                assert_eq!(init["name"], "codewire-daemon-init");
                assert!(command.contains(
                    "umask 077; mkdir -p /codewire/run/processes && chmod 0700 /codewire/run/processes"
                ));
                assert!(
                    init["volumeMounts"]
                        .as_array()
                        .unwrap()
                        .contains(&json!({"name":"codewire-run","mountPath":"/codewire/run"}))
                );
            } else {
                // The same-UID hosted daemon creates its owner-private process
                // directory and writes Codex's home at startup: only the
                // guest DinD's Docker data init runs, and it reaches only the
                // workspace volume.
                assert_block_workspace_inits(workspace);
            }
        }
    }



    #[test]
    fn credential_mounts_and_identities_are_separate_for_workspace_and_init() {
        use codewire_access::{CODEX_PLATFORM_HOME, CODEX_PLATFORM_TOKEN_FILE};
        use codewire_daemon_proto::CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE;
        let opts = credential_opts();
        let template = render_sandbox_template("dev-sandboxes", &opts);
        let workspace = &template["spec"]["podTemplate"]["spec"];
        {
            let (spec, volume_name, audience) = (
                workspace,
                "credential-workspace-identity",
                CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE,
            );
            assert_eq!(spec["automountServiceAccountToken"], false);
            assert_eq!(spec["enableServiceLinks"], false);
            let volume = spec["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|volume| volume["name"] == volume_name)
                .unwrap();
            assert_eq!(volume["projected"]["defaultMode"], 0o440);
            assert_eq!(
                volume["projected"]["sources"],
                json!([{"serviceAccountToken":{"audience":audience,"expirationSeconds":600,"path":"token"}}])
            );
            let projected: Vec<_> = spec["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|volume| volume.get("projected").is_some())
                .map(|volume| &volume["name"])
                .collect();
            for collection in ["containers", "initContainers"] {
                for container in spec[collection].as_array().into_iter().flatten() {
                    for mount in container["volumeMounts"].as_array().unwrap() {
                        assert!(
                            !projected.contains(&&mount["name"]) || mount.get("subPath").is_none(),
                            "projected rotations need directory mounts"
                        );
                    }
                }
            }
        }
        // Commodity mounts the daemon from the support image and selected
        // Codex needs no init container, so only the guest DinD's Docker data
        // init runs, without a credential; confidential keeps only the daemon
        // copy, which never reaches the home.
        assert_block_workspace_inits(workspace);
        let confidential = measured(opts.clone());
        let confidential = render_sandbox_template("dev-sandboxes", &confidential);
        let confidential_inits = confidential["spec"]["podTemplate"]["spec"]["initContainers"]
            .as_array()
            .unwrap();
        assert_eq!(confidential_inits.len(), 1);
        let confidential_init = &confidential_inits[0];
        assert_eq!(confidential_init["name"], "codewire-daemon-init");
        let confidential_mounts: Vec<_> = confidential_init["volumeMounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|mount| mount["name"].as_str().unwrap())
            .collect();
        assert_eq!(confidential_mounts, ["codewire-bin", "codewire-run"]);
        assert!(
            !confidential_init["command"]
                .to_string()
                .contains("codex")
        );
        // Codex's home is the persistent home itself, mounted only as the
        // workspace volume.
        let ws = &workspace["containers"][0];
        assert!(
            ws["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|mount| mount
                    == &json!({"name":"wsmnt","mountPath":"/home/codewire","mountPropagation":"HostToContainer"}))
        );
        assert!(CODEX_PLATFORM_HOME.starts_with("/home/codewire/"));
        // The bound daemon sets `CODEX_HOME` for the sessions it launches; the
        // container itself never carries a selected client's environment.
        assert!(
            !ws["env"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["name"] == "CODEX_HOME")
        );
        assert!(
            ws["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|mount| mount["mountPath"]
                    == CODEX_PLATFORM_TOKEN_FILE.rsplit_once('/').unwrap().0
                    && mount["readOnly"] == true)
        );
        for container in workspace["containers"].as_array().unwrap().iter().skip(1) {
            assert!(
                !container.to_string().contains("credential-"),
                "sibling Docker has no credential mounts"
            );
        }
    }

    #[test]
    fn credential_network_gives_the_workspace_no_broker_peer() {
        let opts = credential_opts();
        let workspace = render_workspace_daemon_network_policy("dev-sandboxes", &opts);
        let egress = workspace["spec"]["egress"].as_array().unwrap();
        // The credential relay in orchestration dials the daemon's bridge and
        // the broker; the workspace reaches neither port itself.
        for port in [8443, 9443] {
            assert!(
                egress.iter().all(|rule| rule["ports"]
                    .as_array()
                    .is_none_or(|ports| ports.iter().all(|item| item["port"] != port))),
                "workspace egress opens {port}"
            );
        }
    }

    #[test]
    fn unselected_runtime_generation_does_not_roll_the_workspace() {
        let mut opts = credential_opts();
        opts.managed_credential_clients = Default::default();
        opts.projection_selection_sha256 = None;
        let before = render_sandbox_template("dev-sandboxes", &opts);
        opts.operation_generation += 1;
        assert_eq!(before, render_sandbox_template("dev-sandboxes", &opts));
    }

    #[test]
    fn credential_free_templates_do_not_mount_provider_bootstrap_or_activate_listener() {
        let opts = commodity_opts();
        let encoded = render_sandbox_template("dev-sandboxes", &opts).to_string();
        for absent in ["credential-workspace-identity", "CODEX_HOME"] {
            assert!(!encoded.contains(absent));
        }
    }

    #[test]
    fn only_exact_selected_clients_render_environment_and_no_codex_objects() {
        use codewire_access::{
            ManagedCredentialClientPlacement, ManagedCredentialClients,
        };
        for slots in [
            vec![],
            vec!["github"],
            vec!["codex"],
            vec!["openai"],
            vec!["anthropic"],
            vec!["ssh"],
            vec!["codex", "openai", "anthropic", "ssh", "github"],
        ] {
            let mut opts = credential_opts();
            opts.managed_credential_clients =
                ManagedCredentialClients::from_profile_slots(slots).unwrap();
            let rendered = render_sandbox_template("dev-sandboxes", &opts);
            let spec = &rendered["spec"]["podTemplate"]["spec"];
            let environment = spec["containers"][0]["env"].as_array().unwrap();
            // The bound daemon expands its selected clients into the sessions
            // it launches, from the bind response: the Pod renders none.
            let all_keys = ManagedCredentialClients::from_profile_slots([
                "codex",
                "openai",
                "anthropic",
                "ssh",
            ])
            .unwrap()
            .for_placement(ManagedCredentialClientPlacement::Platform)
            .environment;
            for name in all_keys.keys() {
                assert!(!environment.iter().any(|entry| entry["name"] == *name));
            }
            assert!(
                !environment
                    .iter()
                    .any(|entry| entry["name"] == MANAGED_CREDENTIAL_CLIENTS_ENV)
            );
            // The selection changes nothing in the Pod: no environment, Codex
            // volume, mount or init container in any case.
            assert_eq!(
                rendered["spec"],
                render_sandbox_template(
                    "dev-sandboxes",
                    &TemplateOpts {
                        managed_credential_clients: Default::default(),
                        ..opts.clone()
                    }
                )["spec"]
            );
            assert_no_legacy_codex(&rendered);
            assert_block_workspace_inits(spec);
        }
        let mut opts = credential_opts();
        opts.managed_credential_clients = Default::default();
        opts.projection_selection_sha256 = None;
        let unselected = render_sandbox_template("dev-sandboxes", &opts);
        assert!(
            !unselected
                .to_string()
                .contains(MANAGED_CREDENTIAL_CLIENTS_ENV)
        );
        assert!(!unselected.to_string().contains("credential-codex"));
    }

    #[test]
    fn credential_mounts_preserve_the_measured_confidential_storage_boundary() {
        let mut opts = measured(credential_opts());
        opts.kata_coco_init_data_enabled = true;
        opts.confidential_storage_manifest_uri = CONTENT_ADDRESSED_MANIFEST_URI.into();
        let authorized = confidential_init_data(&opts).unwrap();
        let rendered = render_sandbox_template("dev-sandboxes", &opts);
        assert_eq!(
            authorized,
            decode_gzip_base64(
                rendered["spec"]["podTemplate"]["metadata"]["annotations"]
                    [KATA_COCO_INIT_DATA_ANNOTATION_KEY]
                    .as_str()
                    .unwrap()
            )
        );
        let parsed: toml::Value = toml::from_str(&authorized).unwrap();
        let policy = parsed["data"]["policy.rego"].as_str().unwrap();
        let mut workspace =
            confidential_create_input("workspace", &opts.image, &["/home/codewire", "/workspace"]);
        workspace["OCI"]["Process"] =
            runtime_process(&rendered["spec"]["podTemplate"]["spec"], "workspace");
        workspace["OCI"]["Mounts"].as_array_mut().unwrap().push(json!({"destination":"/run/codewire-credentials/workspace","source":"/synthetic/public-bootstrap","type_":"bind","options":["rbind","ro"]}));
        assert!(kata_policy_allows(policy, &workspace));
        let mut substituted = workspace.clone();
        substituted["storages"][0]["confidential_storage"]["manifest_uri"] = "kbs:///default/codewire-storage-manifests/sha256-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
        assert!(!kata_policy_allows(policy, &substituted));
        let mut init = workspace.clone();
        init["OCI"]["Annotations"]["io.kubernetes.cri.container-name"] =
            "codewire-daemon-init".into();
        assert!(
            !kata_policy_allows(policy, &init),
            "bootstrap init must not acquire protected workspace storage"
        );
        init["storages"] = json!([]);
        init["OCI"]["Mounts"] = json!([
            {"destination":"/codewire/bin","source":"/synthetic/daemon-copy","type_":"bind","options":["rbind","rw"]},
            {"destination":"/codewire/run","source":"/synthetic/daemon-run","type_":"bind","options":["rbind","rw"]},
        ]);
        assert!(kata_policy_allows(policy, &init));
        // The daemon in the workspace container writes Codex's `~/.codex` on
        // the protected disk. No init container can reach that home, not
        // even through a plaintext bind at the protected path.
        for destination in ["/home/codewire", "/workspace"] {
            let mut home_writer = init.clone();
            home_writer["OCI"]["Mounts"].as_array_mut().unwrap().push(json!(
                {"destination":destination,"source":"/synthetic/plaintext-home","type_":"bind","options":["rbind","rw"]}
            ));
            assert!(
                !kata_policy_allows(policy, &home_writer),
                "init container reached {destination}"
            );
        }
        let rendered_spec = &rendered["spec"]["podTemplate"]["spec"];
        assert_no_legacy_codex(&rendered);
        for init in rendered_spec["initContainers"].as_array().unwrap() {
            for mount in init["volumeMounts"].as_array().unwrap() {
                assert_ne!(mount["name"], "workspace");
            }
            assert!(init.get("volumeDevices").is_none());
        }
        opts.credential_runtime = None;
        assert_eq!(
            authorized,
            confidential_init_data(&opts).unwrap(),
            "public projections do not rewrite the protected-volume policy"
        );
    }

    #[test]
    fn template_opts_debug_redacts_bearer_tokens_and_embedded_ca() {
        let rendered = format!(
            "{:?}",
            TemplateOpts {
                udp_relay_allocator_token: "relay-secret-value".into(),
                kata_coco_kbs_ca_pem: "embedded-public-ca".into(),
                ..Default::default()
            }
        );

        assert!(rendered.contains("udp_relay_allocator_token: \"<redacted>\""));
        assert!(rendered.contains("kata_coco_kbs_ca_pem: \"<configured>\""));
        assert!(!rendered.contains("daemon-secret-value"));
        assert!(!rendered.contains("relay-secret-value"));
        assert!(!rendered.contains("embedded-public-ca"));
    }

    /// Every variable the workspace container is given is in the workspace
    /// daemon's own environment, and the daemon passes that environment on to
    /// every session, command and managed agent, except the names it treats
    /// as internal. So each rendered name is listed here on purpose: a new
    /// one fails this test until the daemon filters it or it is accepted as
    /// visible to everything that runs in the Sandbox.
    #[test]
    fn workspace_environment_names_are_an_explicit_child_visible_list() {
        use std::collections::BTreeSet;

        use codewire_access::{ManagedCredentialClientPlacement, ManagedCredentialClients};
        // The measured anchors (B2c) are public: orchestration's issuing CA
        // and the environment's own ID, pinned by its measured Kata policy.
        const CHILD_VISIBLE: [&str; 8] = [
            "CODEWIRE_MEASURED_BINDING_ROOTS",
            "CODEWIRE_MEASURED_ENVIRONMENT_ID",
            "CODEWIRE_POD_UID",
            "CODEWIRE_WORKSPACE_BINDING_URL",
            "CODEWIRE_WORKSPACE_SHIM_ADDR",
            "DOCKER_HOST",
            "HOME",
            "USER",
        ];
        // No workspace renders a daemon token or a client selection (B2c):
        // the bound daemon receives both from its binding.
        const DAEMON_ONLY: [&str; 0] = [];
        let all = ManagedCredentialClients::from_profile_slots([
            "codex",
            "openai",
            "anthropic",
            "ssh",
            "github",
        ])
        .unwrap();
        // The managed client projection is child-visible by design; its exact
        // names and values are pinned in codewire-access.
        let projected: BTreeSet<String> = all
            .for_placement(ManagedCredentialClientPlacement::Platform)
            .environment
            .into_keys()
            .collect();
        let selected = TemplateOpts {
            managed_credential_clients: all,
            ..credential_opts()
        };
        let binding = TemplateOpts {
            managed_credential_clients: all,
            ..identity_free_opts()
        };
        let mut visible = BTreeSet::new();
        let mut daemon_only = BTreeSet::new();
        // Both identity modes, with and without a selection, on every
        // runtime profile: whatever a workspace container can be given.
        for opts in [commodity_opts(), credential_opts(), selected, binding] {
            for profile in [
                RUNTIME_PROFILE_COMMODITY,
                RUNTIME_PROFILE_CONFIDENTIAL,
                RUNTIME_PROFILE_RUNC,
            ] {
                let opts = if profile == RUNTIME_PROFILE_CONFIDENTIAL {
                    measured(opts.clone())
                } else {
                    TemplateOpts {
                        runtime_profile: profile.into(),
                        ..opts.clone()
                    }
                };
                let rendered = render_sandbox_template("dev-sandboxes", &opts);
                let workspace = &rendered["spec"]["podTemplate"]["spec"]["containers"][0];
                assert_eq!(workspace["name"], "workspace");
                for entry in workspace["env"].as_array().unwrap() {
                    let name = entry["name"].as_str().unwrap();
                    if projected.contains(name) {
                        continue;
                    }
                    if codewire_daemon::env::is_internal_environment_name(name) {
                        daemon_only.insert(name.to_owned());
                    } else {
                        visible.insert(name.to_owned());
                    }
                }
            }
        }
        assert_eq!(
            daemon_only,
            DAEMON_ONLY.into_iter().map(str::to_owned).collect()
        );
        assert_eq!(
            visible,
            CHILD_VISIBLE.into_iter().map(str::to_owned).collect()
        );
        // No listed child-visible name is a credential or a capability: the
        // daemon token and the client selection are the daemon-only ones.
        for name in CHILD_VISIBLE {
            assert!(!codewire_daemon::env::is_internal_environment_name(name));
            assert!(!name.contains("TOKEN") && !name.contains("SECRET") && !name.contains("KEY"));
        }
    }

    #[test]
    fn extracted_template_modules_keep_one_way_dependencies() {
        let leaves = [
            ("encoding", include_str!("encoding.rs")),
            ("naming", include_str!("naming.rs")),
            ("runtime_policy", include_str!("runtime_policy.rs")),
        ];
        for (name, source) in leaves {
            for forbidden in ["super::network", "super::workspace"] {
                assert!(
                    !source.contains(forbidden),
                    "{name} leaf imports forbidden renderer {forbidden}"
                );
            }
        }

        let network = include_str!("network.rs");
        assert!(!network.contains("super::workspace"));
    }

    #[test]
    fn workspace_declares_live_cpu_and_memory_resize_policy() {
        let template = render_sandbox_template("dev-sandboxes", &commodity_opts());
        assert_eq!(
            template.pointer("/spec/podTemplate/spec/containers/0/resizePolicy"),
            Some(&json!([
                {"resourceName": "cpu", "restartPolicy": "NotRequired"},
                {"resourceName": "memory", "restartPolicy": "NotRequired"}
            ]))
        );
    }

    #[test]
    fn workspace_avoids_reapplying_recursive_volume_ownership() {
        let template = render_sandbox_template("dev-sandboxes", &commodity_opts());
        assert_eq!(
            template.pointer("/spec/podTemplate/spec/securityContext/fsGroupChangePolicy"),
            Some(&json!("OnRootMismatch"))
        );
    }

    #[test]
    fn runtime_profile_spec_resolves_only_named_profiles() {
        assert_eq!(
            runtime_profile_spec(RUNTIME_PROFILE_RUNC, DOCKER_MODE_PROFILE_DEFAULT, false,),
            RuntimeProfileSpec {
                profile: RUNTIME_PROFILE_RUNC.into(),
                runtime_class_name: RUNTIME_CLASS_RUNC.into(),
                docker_mode: DOCKER_MODE_NONE.into(),
            }
        );

        assert_eq!(
            runtime_profile_spec(
                RUNTIME_PROFILE_COMMODITY,
                DOCKER_MODE_PROFILE_DEFAULT,
                false,
            ),
            RuntimeProfileSpec {
                profile: RUNTIME_PROFILE_COMMODITY.into(),
                runtime_class_name: RUNTIME_CLASS_COMMODITY.into(),
                docker_mode: DOCKER_MODE_GUEST_DIND.into(),
            }
        );

        assert_eq!(
            runtime_profile_spec(RUNTIME_PROFILE_COMMODITY, DOCKER_MODE_NONE, false,).docker_mode,
            DOCKER_MODE_NONE
        );

        assert_eq!(
            runtime_profile_spec(RUNTIME_PROFILE_RUNC, DOCKER_MODE_PROFILE_DEFAULT, true)
                .docker_mode,
            DOCKER_MODE_LOCAL_DIND_DIRECT
        );
    }

    #[test]
    fn a_commodity_workspace_renders_its_memory_tier_class() {
        for (memory_mib, class) in [
            (4096, RUNTIME_CLASS_COMMODITY),
            (8192, RUNTIME_CLASS_COMMODITY),
            (16384, RUNTIME_CLASS_COMMODITY),
            (16385, RUNTIME_CLASS_COMMODITY_32G),
            (32768, RUNTIME_CLASS_COMMODITY_32G),
        ] {
            assert_eq!(commodity_runtime_class(memory_mib), class, "{memory_mib}");
            let opts = TemplateOpts {
                memory_mib,
                ..commodity_opts()
            };
            assert_eq!(opts.runtime_profile_spec().runtime_class_name, class);
            let template = render_sandbox_template("dev-sandboxes", &opts);
            assert_eq!(
                template.pointer("/spec/podTemplate/spec/runtimeClassName"),
                Some(&json!(class)),
                "{memory_mib}"
            );
        }
        assert!(is_commodity_runtime_class(RUNTIME_CLASS_COMMODITY));
        assert!(is_commodity_runtime_class(RUNTIME_CLASS_COMMODITY_32G));
        assert!(!is_commodity_runtime_class(RUNTIME_CLASS_CONFIDENTIAL));
        assert!(!is_commodity_runtime_class("kata-clh"));
    }

    #[test]
    fn managed_runtime_validation_rejects_diagnostic_profiles() {
        let commodity = runtime_profile_spec(
            RUNTIME_PROFILE_COMMODITY,
            DOCKER_MODE_PROFILE_DEFAULT,
            false,
        );
        assert!(validate_managed_runtime_profile(&commodity, false).is_ok());

        let confidential = runtime_profile_spec(
            RUNTIME_PROFILE_CONFIDENTIAL,
            DOCKER_MODE_PROFILE_DEFAULT,
            false,
        );
        assert!(validate_managed_runtime_profile(&confidential, false).is_ok());

        let runc = runtime_profile_spec(RUNTIME_PROFILE_RUNC, DOCKER_MODE_PROFILE_DEFAULT, false);
        assert!(validate_managed_runtime_profile(&runc, false).is_err());
        assert!(validate_managed_runtime_profile(&runc, true).is_ok());

        let none = runtime_profile_spec(RUNTIME_PROFILE_NONE, DOCKER_MODE_PROFILE_DEFAULT, false);
        assert!(validate_managed_runtime_profile(&none, false).is_err());
        assert!(validate_managed_runtime_profile(&none, true).is_ok());

        let missing = runtime_profile_spec("", DOCKER_MODE_PROFILE_DEFAULT, false);
        assert!(validate_managed_runtime_profile(&missing, true).is_err());

        let unknown = runtime_profile_spec("kata-dev", DOCKER_MODE_PROFILE_DEFAULT, false);
        assert!(validate_managed_runtime_profile(&unknown, true).is_err());

        let unsupported_docker =
            runtime_profile_spec(RUNTIME_PROFILE_COMMODITY, "unsupported", false);
        assert!(validate_managed_runtime_profile(&unsupported_docker, false).is_err());
    }

    #[test]
    fn only_commodity_mounts_the_exact_support_image_daemon_without_init() {
        let support = "registry.example.invalid/codewire/daemon@sha256:48549d19114407c712d043af3ba2136d97052a2c30c82935190f75a3a61f13ab";
        for profile in [
            RUNTIME_PROFILE_COMMODITY,
            RUNTIME_PROFILE_CONFIDENTIAL,
            RUNTIME_PROFILE_RUNC,
            RUNTIME_PROFILE_NONE,
        ] {
            let mut opts = TemplateOpts {
                runtime_profile: profile.into(),
                support_image: support.into(),
                ..commodity_opts()
            };
            if profile == RUNTIME_PROFILE_CONFIDENTIAL {
                opts = measured(opts);
            }
            let template = render_sandbox_template("dev-sandboxes", &opts);
            let spec = &template["spec"]["podTemplate"]["spec"];
            let volume = spec["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|volume| volume["name"] == "codewire-bin")
                .unwrap();
            let mount = spec["containers"][0]["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|mount| mount["name"] == "codewire-bin")
                .unwrap();
            if profile == RUNTIME_PROFILE_COMMODITY {
                assert_eq!(
                    volume,
                    &json!({"name":"codewire-bin","image":{"reference":support,"pullPolicy":"IfNotPresent"}})
                );
                assert_eq!(
                    mount,
                    &json!({"name":"codewire-bin","mountPath":"/codewire/bin","subPath":"usr/local/bin","readOnly":true})
                );
                assert_block_workspace_inits(spec);
            } else {
                assert_eq!(volume, &json!({"name":"codewire-bin","emptyDir":{}}));
                assert_eq!(
                    mount,
                    &json!({"name":"codewire-bin","mountPath":"/codewire/bin"})
                );
                // Without a guest DinD (runc and none here), or with
                // confidential's plain directory, only the daemon copy runs.
                let init = spec["initContainers"].as_array().unwrap();
                assert_eq!(init.len(), 1, "{profile}");
                assert_eq!(init[0]["name"], "codewire-daemon-init");
                assert_eq!(init[0]["image"], support);
            }
            // The supervisor still starts the same executable path.
            assert!(
                spec["containers"][0]["command"][2]
                    .as_str()
                    .unwrap()
                    .contains("/codewire/bin/cw __hosted-daemon")
            );
        }
    }

    #[test]
    fn workspace_pod_carries_the_configured_egress_bandwidth_cap() {
        let commodity = TemplateOpts {
            egress_bandwidth: "100M".into(),
            ..commodity_opts()
        };
        for opts in [commodity.clone(), measured(commodity)] {
            let profile = opts.runtime_profile_spec().profile;
            let capped = render_sandbox_template("dev-sandboxes", &opts);
            assert_eq!(
                capped["spec"]["podTemplate"]["metadata"]["annotations"]
                    [EGRESS_BANDWIDTH_ANNOTATION_KEY]
                    .as_str(),
                Some("100M"),
                "{profile}"
            );
        }
        let uncapped = render_sandbox_template(
            "dev-sandboxes",
            &TemplateOpts {
                egress_bandwidth: String::new(),
                ..commodity_opts()
            },
        );
        assert!(
            uncapped["spec"]["podTemplate"]["metadata"]["annotations"]
                .get(EGRESS_BANDWIDTH_ANNOTATION_KEY)
                .is_none()
        );
    }

    #[test]
    fn cpu_sharing_divides_the_workspace_request_and_nothing_else() {
        let opts = TemplateOpts {
            cpu_millicores: 2000,
            memory_mib: 8192,
            dind_enabled: true,
            ..commodity_opts()
        };
        let resources_of = |opts: &TemplateOpts, name: &str| {
            render_sandbox_template("dev-sandboxes", opts)["spec"]["podTemplate"]["spec"]
                ["containers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|container| container["name"] == name)
                .map(|container| container["resources"].clone())
        };
        let shared = TemplateOpts {
            cpu_sharing: CpuSharingRatio::parse(Some("2")).unwrap(),
            ..opts.clone()
        };

        let dedicated = resources_of(&opts, "workspace").unwrap();
        assert_eq!(dedicated["requests"]["cpu"], "2000m");
        assert_eq!(dedicated["limits"]["cpu"], "2000m");

        let workspace = resources_of(&shared, "workspace").unwrap();
        assert_eq!(workspace["requests"]["cpu"], "1000m");
        assert_eq!(workspace["limits"]["cpu"], "2000m", "the VM keeps its vCPUs");
        assert_eq!(workspace["requests"]["memory"], "8192Mi");
        assert_eq!(workspace["limits"]["memory"], "8192Mi");

        assert_eq!(
            resources_of(&shared, "dind"),
            resources_of(&opts, "dind"),
            "only the workspace shares"
        );
    }

    #[test]
    fn cpu_sharing_ratio_defaults_to_off_and_refuses_malformed_values() {
        for off in [None, Some(""), Some(" "), Some("1")] {
            assert_eq!(CpuSharingRatio::parse(off).unwrap(), CpuSharingRatio::NONE);
        }
        assert_eq!(CpuSharingRatio::default(), CpuSharingRatio::NONE);
        let ratio = |value| CpuSharingRatio::parse(Some(value)).unwrap();
        assert_eq!(ratio(" 2 ").request_millicores(2000), 1000);
        assert_eq!(ratio("8").request_millicores(8000), 1000);
        for refused in ["0", "-1", "9", "1.5", "2:1", "on"] {
            let error = CpuSharingRatio::parse(Some(refused)).unwrap_err();
            assert!(error.contains(CPU_SHARING_RATIO_ENV), "{error}");
        }
    }

    #[test]
    fn a_cpu_request_rounds_up_and_the_observed_ratio_survives_it() {
        let ratio = |value| CpuSharingRatio::parse(Some(value)).unwrap();
        assert_eq!(ratio("2").request_millicores(1500), 750);
        assert_eq!(ratio("2").request_millicores(1001), 501);
        assert_eq!(ratio("3").request_millicores(1000), 334);
        assert_eq!(CpuSharingRatio::NONE.request_millicores(1234), 1234);
        for value in ["1", "2", "3", "4", "8"] {
            for vcpus in [250, 500, 1000, 1500, 2000, 3000, 32000] {
                let request = ratio(value).request_millicores(vcpus);
                assert_eq!(
                    CpuSharingRatio::observed(request, vcpus),
                    ratio(value),
                    "{vcpus}m at {value}:1"
                );
            }
        }
        assert_eq!(CpuSharingRatio::observed(0, 2000), CpuSharingRatio::NONE);
        assert_eq!(CpuSharingRatio::observed(2000, 0), CpuSharingRatio::NONE);
    }

    #[test]
    fn egress_bandwidth_defaults_to_100m_and_refuses_malformed_values() {
        assert_eq!(sandbox_egress_bandwidth(None).unwrap(), "100M");
        assert_eq!(sandbox_egress_bandwidth(Some("")).unwrap(), "100M");
        assert_eq!(sandbox_egress_bandwidth(Some(" ")).unwrap(), "100M");
        for accepted in ["100M", "1G", "500K", "250000000", " 50M "] {
            assert_eq!(
                sandbox_egress_bandwidth(Some(accepted)).unwrap(),
                accepted.trim()
            );
        }
        for refused in [
            "0", "0M", "010M", "100m", "100Mi", "100Mbit", "M", "-1M", "1.5G", "100 M",
            "1T", "9999999999999",
        ] {
            let error = sandbox_egress_bandwidth(Some(refused)).unwrap_err();
            assert!(error.contains(EGRESS_BANDWIDTH_ENV), "{refused}: {error}");
        }
    }

    #[test]
    fn commodity_template_uses_neutral_annotations_and_guest_dockerd() {
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-commodity".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
                disk_gib: 40,
                support_image: TEST_SUPPORT_IMAGE.into(),
                server_namespace: "dev".into(),
                ..Default::default()
            },
        );

        let pod_template = &rendered["spec"]["podTemplate"];
        let annotations = pod_template["metadata"]["annotations"].as_object().unwrap();
        assert_eq!(
            pod_template["metadata"]["labels"]["codewire.sh/type"].as_str(),
            Some("workspace")
        );
        assert!(
            pod_template["metadata"]["labels"]
                .get("codewire.sh/environment-id")
                .is_none(),
            "reusable SandboxTemplates must not pin an empty environment-id label"
        );
        // The shared template admits exactly orchestration on the daemon and
        // SSH ports (codewire#3626); everything else stays per environment.
        assert_eq!(
            rendered["spec"]["networkPolicy"]["ingress"],
            orchestration_only_template_ingress("dev")
        );
        assert_eq!(
            annotations.get(WORKSPACE_ANNOTATION_KEY).unwrap().as_str(),
            Some("true")
        );
        assert_eq!(
            annotations
                .get(WORKSPACE_DISK_GIB_ANNOTATION_KEY)
                .unwrap()
                .as_str(),
            Some("40")
        );
        assert!(!annotations.contains_key(KATA_COCO_INIT_DATA_ANNOTATION_KEY));
        assert_eq!(
            pod_template["spec"]["runtimeClassName"].as_str(),
            Some(RUNTIME_CLASS_COMMODITY)
        );

        let containers = pod_template["spec"]["containers"].as_array().unwrap();
        assert_eq!(
            containers
                .iter()
                .filter_map(|container| container["name"].as_str())
                .collect::<Vec<_>>(),
            vec!["workspace", "dind"]
        );
        assert!(
            containers
                .iter()
                .all(|container| container["name"].as_str() != Some("codewire-gateway")),
            "gateway must not share the workspace runtime pod"
        );
        // The daemon comes read-only from the exact support image, so the
        // commodity Pod's only init container prepares the guest DinD's data
        // image (#3208).
        assert_block_workspace_inits(&pod_template["spec"]);
        assert!(
            pod_template["spec"]["volumes"]
                .as_array()
                .unwrap()
                .contains(&json!({
                    "name": "codewire-bin",
                    "image": { "reference": TEST_SUPPORT_IMAGE, "pullPolicy": "IfNotPresent" },
                }))
        );
        let workspace_container = &containers[0];
        assert!(
            workspace_container["volumeMounts"]
                .as_array()
                .unwrap()
                .contains(&json!({
                    "name": "codewire-bin",
                    "mountPath": "/codewire/bin",
                    "subPath": "usr/local/bin",
                    "readOnly": true,
                }))
        );
        assert!(
            containers[1]["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .all(|mount| mount["name"] != "codewire-bin"),
            "Docker never sees the daemon image"
        );
        let dind = containers
            .iter()
            .find(|container| container["name"].as_str() == Some("dind"))
            .unwrap();
        assert_eq!(dind["image"].as_str(), Some(DEFAULT_DIND_IMAGE));
        let command = dind["command"].as_array().unwrap();
        assert_eq!(command[0].as_str(), Some("sh"));
        assert_eq!(command[1].as_str(), Some("-ec"));
        let bootstrap = command[2].as_str().unwrap();
        assert_eq!(bootstrap, commodity_dind_bootstrap_script());
        // DinD only mounts the image the data init prepared, with busybox:
        // the Docker 29.9.2 DinD image ships no e2fsprogs (#3208).
        for tool in [
            "mkfs", "mke2fs", "e2fsck", "resize2fs", "dumpe2fs", "losetup", "truncate", "chown",
            "chmod",
        ] {
            assert!(!bootstrap.contains(tool), "DinD runs {tool}");
        }
        assert!(bootstrap.contains("mkdir -p \"$data_root\""));
        assert!(bootstrap.contains("mount -o loop \"$data_image\" \"$data_root\""));
        assert!(bootstrap.contains(
            "awk -v target=\"$data_root\" '$2 == target && $3 == \"ext4\" { found = 1 } END { exit found ? 0 : 1 }' /proc/mounts"
        ));
        let missing = bootstrap.find("if [ ! -s \"$data_image\" ]; then").unwrap();
        assert!(missing < bootstrap.find("mount -o loop").unwrap());
        assert!(bootstrap[missing..].starts_with(
            "if [ ! -s \"$data_image\" ]; then\n    echo \"the Docker data image $data_image is missing; the codewire-docker-data-init init container prepares it before Docker starts\" >&2\n    exit 1\n  fi"
        ));
        assert!(bootstrap.contains("echo \"unsupported CODEWIRE_DOCKER_MOUNT_MODE=$mount_mode\" >&2"));
        let self_move = bootstrap.find("printf '%s\\n' \"$$$$\" > \"$cgroup_root/init/cgroup.procs\"").unwrap();
        let enable = bootstrap.find("printf '%s\\n' \"$enable_controllers\"").unwrap();
        assert!(self_move < enable);
        assert!(enable < bootstrap.find("exec dockerd").unwrap());
        assert!(bootstrap.contains("--feature containerd-snapshotter=true --storage-driver overlayfs"));

        // The data init prepares the image offline: it owns `.codewire`,
        // formats a missing image lazily (Program #2238), and grows a grown
        // one with a forced check before resize2fs, never shrinking it and
        // never failing the init container.
        let prepare = docker_data_image_prepare_script();
        assert!(prepare.contains("chown 1000:1000 \"$codewire_dir\""));
        assert!(prepare.contains("chmod 0755 \"$codewire_dir\""));
        assert!(!prepare.contains("0775"));
        assert!(prepare.contains(
            "mkfs.ext4 -q -F -E lazy_itable_init=1,lazy_journal_init=1 \"$data_image\""
        ));
        assert!(prepare.contains("rm -f \"$data_image\""));
        assert!(prepare.contains("truncate -s \"$data_size\" \"$data_image\" || true"));
        assert!(prepare.contains("dumpe2fs -h \"$data_image\""));
        let fsck = prepare.find("e2fsck -fy \"$data_image\"").unwrap();
        let resize = prepare.find("resize2fs \"$data_image\"").unwrap();
        assert!(fsck < resize);
        for absent in ["mount -o", "losetup", "set -e", "dockerd"] {
            assert!(!prepare.contains(absent), "the data init runs {absent}");
        }
        assert!(
            prepare
                .lines()
                .all(|line| !line.trim_start().starts_with("exit")),
            "the data init never exits early"
        );
        assert!(
            prepare.find("mkfs.ext4").unwrap() < prepare.find("data_gib=").unwrap(),
            "growth follows the format of a missing image"
        );

        // The bootstraps stored Sandboxes carry. The one from before
        // 531fc0f7e differs from the eager-mkfs one only in its 0775 mode
        // (#2639); the eager one, rendered until #2238, from the lazy one
        // only in its mkfs; the lazy one, rendered until #3554, from the one
        // that grows inside DinD only in not growing. Start and Pod
        // replacement re-render each of them (#3208).
        let growth_in_dind = growth_in_dind_bootstrap_script();
        assert_eq!(
            LEGACY_DIND_BOOTSTRAP_SCRIPT.replace(
                "chmod 0775 \"$codewire_dir\"",
                "# Owner-writable only: the workspace daemon refuses a group- or\n\
                 # world-writable ancestor of its platform session store.\n\
                 chmod 0755 \"$codewire_dir\""
            ),
            eager_mkfs_dind_bootstrap_script()
        );
        assert_ne!(eager_mkfs_dind_bootstrap_script(), growth_in_dind);
        assert_eq!(
            eager_mkfs_dind_bootstrap_script().replace(
                "    mkfs.ext4 -q -F \"$data_image\"",
                "    # A fresh sparse image reads as zeros, so mke2fs skips zeroing its\n    \
                 # inode tables and journal: a few MiB of writes at any size.\n    \
                 mkfs.ext4 -q -F -E lazy_itable_init=1,lazy_journal_init=1 \"$data_image\""
            ),
            pre_growth_dind_bootstrap_script()
        );
        let growth_start = growth_in_dind.find("  # A grown workspace disk").unwrap();
        let growth_end = growth_in_dind
            .find("elif [ \"$mount_mode\" != \"none\" ]")
            .unwrap();
        assert_eq!(
            format!(
                "{}{}",
                &growth_in_dind[..growth_start],
                &growth_in_dind[growth_end..]
            ),
            pre_growth_dind_bootstrap_script()
        );
        let growth = &growth_in_dind[growth_start..growth_end];
        assert!(growth.contains("losetup -c \"$data_device\" && resize2fs \"$data_device\""));
        // The variants a Start re-renders are all distinct from the current
        // bootstrap and from each other.
        let variants = [
            LEGACY_DIND_BOOTSTRAP_SCRIPT.to_owned(),
            eager_mkfs_dind_bootstrap_script(),
            pre_growth_dind_bootstrap_script(),
            growth_in_dind,
            dind_bootstrap_script(),
            commodity_dind_bootstrap_script(),
        ];
        for (index, variant) in variants.iter().enumerate() {
            assert!(
                variants[index + 1..].iter().all(|other| other != variant),
                "variant {index} repeats"
            );
        }
        assert!(bootstrap.contains("--data-root \"$data_root\""));
        assert!(!bootstrap.contains("--storage-driver vfs"));
        assert!(dind["env"].as_array().unwrap().iter().any(|env| {
            env["name"].as_str() == Some("CODEWIRE_DOCKER_DATA_IMAGE")
                && env["value"].as_str() == Some("/workspace/.codewire/docker-data.ext4")
        }));
        assert!(dind["env"].as_array().unwrap().iter().any(|env| {
            env["name"].as_str() == Some("CODEWIRE_DOCKER_DATA_ROOT")
                && env["value"].as_str() == Some("/var/lib/docker")
        }));
        assert!(dind["env"].as_array().unwrap().iter().any(|env| {
            env["name"].as_str() == Some("CODEWIRE_DOCKER_DATA_SIZE")
                && env["value"].as_str() == Some("38G")
        }));
        assert!(dind["env"].as_array().unwrap().iter().any(|env| {
            env["name"].as_str() == Some("CODEWIRE_DOCKER_MOUNT_MODE")
                && env["value"].as_str() == Some("loop")
        }));
        let workspace = containers
            .iter()
            .find(|container| container["name"].as_str() == Some("workspace"))
            .unwrap();
        assert!(workspace["env"].as_array().unwrap().iter().any(|env| {
            env["name"].as_str() == Some("DOCKER_HOST")
                && env["value"].as_str() == Some("unix:///var/run/docker/docker.sock")
        }));
        assert!(
            workspace["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|mount| mount["name"].as_str() == Some("docker-sock")
                    && mount["mountPath"].as_str() == Some("/var/run/docker"))
        );
        let volumes = pod_template["spec"]["volumes"].as_array().unwrap();
        let docker_socket = volumes
            .iter()
            .find(|volume| volume["name"].as_str() == Some("docker-sock"))
            .expect("Docker-enabled workspace must declare docker-sock");
        assert_eq!(
            docker_socket["emptyDir"],
            json!({ "medium": "Memory" }),
            "Kata cross-container Unix sockets must use guest tmpfs"
        );
        // Every hosted workspace binds (B2c): readiness is the daemon's
        // local marker alone, never Docker (#3559), and DinD has no probe.
        assert_eq!(
            workspace["readinessProbe"],
            json!({
                "exec": {
                    "command": ["sh", "-ec", "test -f /codewire/run/daemon/ready"],
                },
                "periodSeconds": 2,
                "timeoutSeconds": 2,
                "failureThreshold": 3,
                "successThreshold": 1,
            })
        );
        assert_eq!(
            workspace["startupProbe"],
            json!({
                "exec": workspace["readinessProbe"]["exec"],
                "periodSeconds": 1,
                "timeoutSeconds": 2,
                "failureThreshold": WORKSPACE_READY_TIMEOUT.as_secs(),
                "successThreshold": 1,
            }),
            "a start notices the marker within a second and is never stopped \
             before the commodity ready wait gives up"
        );
        for probe in ["readinessProbe", "startupProbe", "livenessProbe"] {
            assert!(dind.get(probe).is_none(), "DinD must not render {probe}");
        }
        assert!(
            volumes
                .iter()
                .all(|volume| volume.get("hostPath").is_none()),
            "commodity workspace pod must not mount host Docker or containerd sockets"
        );
    }

    #[test]
    fn confidential_template_uses_guest_memory_for_docker_socket() {
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-confidential-docker-socket".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
                environment_id: "8ce0bf4b-bdeb-4fde-95cf-97e27b44c90d".into(),
                workspace_binding_url: MEASURED_BINDING_URL.into(),
                measured_binding_roots: MEASURED_BINDING_ROOTS.into(),
                disk_gib: 40,
                ..Default::default()
            },
        );

        let pod_spec = &rendered["spec"]["podTemplate"]["spec"];
        let docker_socket = pod_spec["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|volume| volume["name"].as_str() == Some("docker-sock"))
            .expect("confidential Docker profile must declare docker-sock");
        assert_eq!(docker_socket["emptyDir"], json!({ "medium": "Memory" }));

        let containers = pod_spec["containers"].as_array().unwrap();
        let workspace = containers
            .iter()
            .find(|container| container["name"].as_str() == Some("workspace"))
            .unwrap();
        // A bound daemon's readiness marker (B2c), as on commodity: Pod
        // readiness depends on neither the binding nor Docker (#3559).
        assert_eq!(
            workspace["readinessProbe"]["exec"]["command"][2].as_str(),
            Some("test -f /codewire/run/daemon/ready")
        );
        assert_eq!(
            workspace["startupProbe"]["exec"],
            workspace["readinessProbe"]["exec"]
        );
        assert_eq!(
            workspace["startupProbe"]["failureThreshold"].as_u64().unwrap()
                * workspace["startupProbe"]["periodSeconds"].as_u64().unwrap(),
            CONFIDENTIAL_WORKSPACE_READY_TIMEOUT.as_secs(),
            "a confidential start keeps the tier's cold-start budget"
        );
        for container in containers
            .iter()
            .filter(|container| container["name"].as_str() != Some("workspace"))
        {
            assert!(container.get("readinessProbe").is_none());
            assert!(container.get("startupProbe").is_none());
        }
        let dind = containers
            .iter()
            .find(|container| container["name"].as_str() == Some("dind"))
            .unwrap();
        assert!(dind["env"].as_array().unwrap().iter().any(|env| {
            env["name"].as_str() == Some("CODEWIRE_DOCKER_DATA_ROOT")
                && env["value"].as_str() == Some("/workspace/.codewire/docker-root")
        }));
    }

    #[test]
    fn managed_and_custom_workspaces_supervise_the_self_contained_daemon() {
        let managed = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-managed-daemon".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                support_image: "registry.example.invalid/codewire/daemon:test".into(),
                environment_id: "env-managed-daemon".into(),
                ..Default::default()
            },
        );
        let managed_spec = &managed["spec"]["podTemplate"]["spec"];
        let managed_workspace = &managed_spec["containers"][0];
        let managed_command = managed_workspace["command"][2].as_str().unwrap();
        assert!(managed_command.contains("while [ ! -x /codewire/bin/cw ]"));
        assert!(managed_command.contains("/codewire/bin/cw __hosted-daemon & daemon_pid=$!"));
        assert!(!managed_command.contains("exec /codewire/bin/cw __hosted-daemon"));
        assert!(managed_command.contains("wait \"$daemon_pid\"; status=$?;"));
        assert!(!managed_command.contains("nohup cw node"));
        assert!(
            !managed_workspace["env"]
                .as_array()
                .unwrap()
                .iter()
                .any(|env| env["name"].as_str() == Some(LEGACY_DAEMON_AUTH_TOKEN_ENV))
        );
        let init_command = managed_spec["initContainers"][0]["command"][2]
            .as_str()
            .unwrap();
        assert!(init_command.contains("cp /usr/local/bin/cw"));
        assert!(!init_command.contains("ln -sf"));

        let custom = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-custom-daemon".into(),
                image: "example.invalid/custom:golden".into(),
                image_command: vec!["/bin/custom-entrypoint".into(), "--serve".into()],
                support_image: "registry.example.invalid/codewire/daemon:test".into(),
                environment_id: "env-custom-daemon".into(),
                ..Default::default()
            },
        );
        let custom_command = custom["spec"]["podTemplate"]["spec"]["containers"][0]["command"][2]
            .as_str()
            .unwrap();
        assert!(custom_command.contains(
            "(exec '/bin/custom-entrypoint' '--serve') & workload_pid=$!"
        ));
        assert!(custom_command.contains("/codewire/bin/cw __hosted-daemon & daemon_pid=$!"));
        assert!(custom_command.contains("if ! kill -0 \"$daemon_pid\""));
        assert!(
            custom_command
                .matches("/codewire/bin/cw __hosted-daemon & daemon_pid=$!")
                .count()
                >= 2,
            "custom supervisor must restart the daemon while the workload remains alive"
        );
        assert!(!custom_command.contains("nohup cw node"));
    }


    #[test]
    fn custom_entrypoint_arguments_are_shell_quoted() {
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-custom-quoted".into(),
                image: "example.invalid/custom:golden".into(),
                image_command: vec![
                    "/bin/custom entrypoint".into(),
                    "literal $(touch /tmp/not-run) 'quote'".into(),
                ],
                environment_id: "env-custom-quoted".into(),
                ..Default::default()
            },
        );
        let command = rendered["spec"]["podTemplate"]["spec"]["containers"][0]["command"][2]
            .as_str()
            .unwrap();
        assert!(command.contains("'/bin/custom entrypoint'"));
        assert!(command.contains("'literal $(touch /tmp/not-run) '\\''quote'\\'''"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_workspace_supervisor_is_the_daemon_parent_and_preserves_exit_status() {
        for status in [0, 7] {
            let command = super::workspace::managed_workspace_supervisor_command(
                "",
                "",
                &format!("sh -c 'printf \"%s\\n\" \"$PPID\"; exit {status}'"),
            );
            let child = tokio::process::Command::new("/bin/sh")
                .args(["-c", &command])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let supervisor_pid = child.id().unwrap();
            let output =
                tokio::time::timeout(std::time::Duration::from_secs(3), child.wait_with_output())
                    .await
                    .expect("managed daemon exits")
                    .unwrap();
            assert_eq!(output.status.code(), Some(status));
            assert_eq!(
                std::str::from_utf8(&output.stdout).unwrap().trim(),
                supervisor_pid.to_string(),
            );
            assert!(supervisor_pid > 1);
        }
    }

    /// Kubernetes starts container PID 1 with default signal dispositions, but
    /// a test may inherit SIGINT ignored, as every job a non-interactive
    /// shell starts in the background does (the preflight lanes), and a shell
    /// cannot trap a signal that was ignored on entry. Give the supervisor
    /// the dispositions its container has.
    #[cfg(unix)]
    fn container_signal_dispositions(command: &mut tokio::process::Command) {
        // SAFETY: signal(2) is async-signal-safe, and it changes only the
        // forked child's own dispositions before exec.
        unsafe {
            command.pre_exec(|| {
                libc::signal(libc::SIGINT, libc::SIG_DFL);
                libc::signal(libc::SIGTERM, libc::SIG_DFL);
                Ok(())
            });
        }
    }

    /// The fixture is not namespace PID 1: killing its shell alone would leave
    /// the synthetic daemon alive on assertion panic or timeout. Keep its own
    /// process group until every output pipe has closed and the shell is reaped.
    #[cfg(unix)]
    struct SupervisorFixture {
        child: tokio::process::Child,
        group: u32,
        drained: bool,
    }

    #[cfg(unix)]
    impl Drop for SupervisorFixture {
        fn drop(&mut self) {
            if !self.drained {
                let _ = std::process::Command::new("/bin/kill")
                    .args(["-KILL", "--", &format!("-{}", self.group)])
                    .env_clear()
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                // Child's kill-on-drop retains Tokio's direct-child reaper.
                // Any remaining descendants were killed as part of the group.
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_workspace_supervisor_forwards_termination_and_reaps_daemon() {
        use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, BufReader};

        for (signal, expected_status) in [("-TERM", 143), ("-INT", 130)] {
            let command = super::workspace::managed_workspace_supervisor_command(
                "",
                "",
                "sh -c 'trap \"printf stopped; exit 0\" TERM; printf \"ready\\n\"; while :; do sleep 0.1; done'",
            );
            let mut supervisor = tokio::process::Command::new("/bin/sh");
            supervisor
                .args(["-c", &command])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .process_group(0)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true);
            container_signal_dispositions(&mut supervisor);
            let child = supervisor.spawn().unwrap();
            let mut fixture = SupervisorFixture {
                group: child.id().unwrap(),
                child,
                drained: false,
            };
            assert!(fixture.group > 1);
            let mut stdout = BufReader::new(fixture.child.stdout.take().unwrap());
            let mut ready = String::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                stdout.read_line(&mut ready),
            )
            .await
            .expect("daemon ready")
            .unwrap();
            assert_eq!(ready, "ready\n");
            assert!(
                tokio::process::Command::new("/bin/kill")
                    .args([signal, &fixture.group.to_string()])
                    .env_clear()
                    .status()
                    .await
                    .unwrap()
                    .success()
            );
            let mut stopped = String::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                stdout.read_to_string(&mut stopped),
            )
            .await
            .expect("daemon output reaches EOF")
            .unwrap();
            let status =
                tokio::time::timeout(std::time::Duration::from_secs(3), fixture.child.wait())
                    .await
                    .expect("supervisor drains daemon")
                    .unwrap();
            fixture.drained = true;
            assert_eq!(status.code(), Some(expected_status));
            assert_eq!(stopped, "stopped");
        }
    }

    /// A Stop while the supervisor still waits for its daemon binary ends it
    /// with the trap's status and starts no daemon. Without its traps first, a
    /// non-PID-1 supervisor died of the signal, and as PID 1 it dropped the
    /// signal until the Pod's termination grace ran out (#2667).
    #[cfg(unix)]
    #[tokio::test]
    async fn managed_workspace_supervisor_stops_while_waiting_for_its_daemon() {
        use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, BufReader};

        for (signal, expected_status) in [("-TERM", 143), ("-INT", 130)] {
            let command = super::workspace::managed_workspace_supervisor_command(
                "",
                "printf 'waiting\\n'; while :; do sleep 0.1; done;",
                "printf started",
            );
            let mut supervisor = tokio::process::Command::new("/bin/sh");
            supervisor
                .args(["-c", &command])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .process_group(0)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true);
            container_signal_dispositions(&mut supervisor);
            let child = supervisor.spawn().unwrap();
            let mut fixture = SupervisorFixture {
                group: child.id().unwrap(),
                child,
                drained: false,
            };
            let mut stdout = BufReader::new(fixture.child.stdout.take().unwrap());
            let mut waiting = String::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                stdout.read_line(&mut waiting),
            )
            .await
            .expect("supervisor waits for its daemon")
            .unwrap();
            assert_eq!(waiting, "waiting\n");
            assert!(
                tokio::process::Command::new("/bin/kill")
                    .args([signal, &fixture.group.to_string()])
                    .env_clear()
                    .status()
                    .await
                    .unwrap()
                    .success()
            );
            let mut rest = String::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                stdout.read_to_string(&mut rest),
            )
            .await
            .expect("supervisor output reaches EOF")
            .unwrap();
            let status =
                tokio::time::timeout(std::time::Duration::from_secs(3), fixture.child.wait())
                    .await
                    .expect("supervisor stops")
                    .unwrap();
            fixture.drained = true;
            assert_eq!(status.code(), Some(expected_status));
            assert_eq!(rest, "");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn custom_workspace_supervisor_restarts_a_failed_daemon() {
        use std::os::unix::fs::PermissionsExt as _;
        use std::process::Stdio;

        let temp = tempfile::tempdir().unwrap();
        let daemon = temp.path().join("daemon");
        let workload = temp.path().join("workload");
        let count = temp.path().join("daemon-count");
        let pid = temp.path().join("daemon-pid");
        let daemon_env = temp.path().join("daemon-env");
        let workload_env = temp.path().join("workload-env");
        std::fs::write(
            &daemon,
            format!(
                "#!/bin/sh\n\
                 count=0\n\
                 [ ! -f {count} ] || count=\"$(cat {count})\"\n\
                 echo $((count + 1)) > {count}\n\
                 echo $$ > {pid}\n\
                 echo \"${{CODEWIRE_DAEMON_AUTH_TOKEN-unset}}\" > {daemon_env}\n\
                 trap 'exit 0' TERM INT\n\
                 while true; do sleep 0.1; done\n",
                count = count.display(),
                pid = pid.display(),
                daemon_env = daemon_env.display(),
            ),
        )
        .unwrap();
        std::fs::write(
            &workload,
            format!(
                "#!/bin/sh\necho \"${{CODEWIRE_DAEMON_AUTH_TOKEN-unset}}\" > {workload_env}\ntrap 'exit 0' TERM INT\nwhile true; do sleep 0.1; done\n",
                workload_env = workload_env.display(),
            ),
        )
        .unwrap();
        for path in [&daemon, &workload] {
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions).unwrap();
        }

        let command = custom_workspace_supervisor_command(
            "",
            "",
            &format!("sh {}", daemon.display()),
            &format!("sh {}", workload.display()),
        );
        let mut supervisor = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        wait_for_file_value(&count, "1").await;
        wait_for_file_value(&daemon_env, "unset").await;
        wait_for_file_value(&workload_env, "unset").await;
        let daemon_pid = std::fs::read_to_string(&pid).unwrap();
        assert!(
            tokio::process::Command::new("kill")
                .args(["-TERM", daemon_pid.trim()])
                .status()
                .await
                .unwrap()
                .success()
        );
        wait_for_file_value(&count, "2").await;

        let supervisor_pid = supervisor.id().unwrap().to_string();
        assert!(
            tokio::process::Command::new("kill")
                .args(["-TERM", &supervisor_pid])
                .status()
                .await
                .unwrap()
                .success()
        );
        tokio::time::timeout(std::time::Duration::from_secs(3), supervisor.wait())
            .await
            .expect("custom supervisor shutdown")
            .unwrap();
    }

    #[cfg(unix)]
    async fn wait_for_file_value(path: &std::path::Path, expected: &str) {
        for _ in 0..80 {
            if std::fs::read_to_string(path)
                .ok()
                .is_some_and(|value| value.trim() == expected)
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!(
            "timed out waiting for {} to contain {expected}",
            path.display()
        );
    }

    #[test]
    fn dind_memory_limit_scales_for_large_environments() {
        for (name, memory_mib, want_limit) in [("small", 4096, "2Gi"), ("large", 16384, "4Gi")] {
            let rendered = render_sandbox_template(
                "codewire-runtime",
                &TemplateOpts {
                    name: format!("tmpl-dind-memory-{name}"),
                    image: crate::sandbox::PUBLIC_CANONICAL_WORKSPACE_RUNTIME_IMAGE.into(),
                    runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
                    memory_mib,
                    disk_gib: 50,
                    ..Default::default()
                },
            );
            let containers = rendered["spec"]["podTemplate"]["spec"]["containers"]
                .as_array()
                .unwrap();
            let dind = containers
                .iter()
                .find(|container| container["name"].as_str() == Some("dind"))
                .unwrap();
            assert_eq!(
                dind["resources"]["limits"]["memory"].as_str(),
                Some(want_limit)
            );
        }
    }

    #[test]
    fn dind_image_override_preserves_guest_dind_shape() {
        let image = "docker.io/library/docker:29.7.0-dind@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-dind-image".into(),
                image: crate::sandbox::PUBLIC_CANONICAL_WORKSPACE_RUNTIME_IMAGE.into(),
                dind_image: image.into(),
                runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
                disk_gib: 50,
                ..Default::default()
            },
        );
        let containers = rendered["spec"]["podTemplate"]["spec"]["containers"]
            .as_array()
            .unwrap();
        let dind = containers
            .iter()
            .find(|container| container["name"].as_str() == Some("dind"))
            .unwrap();
        assert_eq!(dind["image"].as_str(), Some(image));
        assert_eq!(
            dind["securityContext"]["privileged"].as_bool(),
            Some(true),
            "the support image override must not change the guest-local Docker shape"
        );
    }

    #[test]
    fn commodity_template_agent_policy_init_data_when_enabled() {
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-commodity".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
                kata_agent_policy_enabled: true,
                ..Default::default()
            },
        );

        let pod_template = &rendered["spec"]["podTemplate"];
        let annotations = pod_template["metadata"]["annotations"].as_object().unwrap();
        let decoded = decode_gzip_base64(
            annotations
                .get(KATA_COCO_INIT_DATA_ANNOTATION_KEY)
                .unwrap()
                .as_str()
                .unwrap(),
        );
        for want in [
            "package agent_policy",
            "default ExecProcessRequest := true",
            "default ReadStreamRequest := true",
            "default WriteStreamRequest := true",
            "default GetDiagnosticDataRequest := false",
            "default SetPolicyRequest := false",
            "default StartTracingRequest := false",
            "default StopTracingRequest := false",
        ] {
            assert!(decoded.contains(want), "missing {want:?} in {decoded}");
        }
    }

    #[test]
    fn commodity_agent_policy_init_data_never_names_trustee() {
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-commodity".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
                kata_agent_policy_enabled: true,
                kata_coco_init_data_enabled: true,
                kata_coco_kbs_url: "https://kbs.codewire-dev.sh".into(),
                ..Default::default()
            },
        );
        let decoded = decode_gzip_base64(
            rendered["spec"]["podTemplate"]["metadata"]["annotations"]
                [KATA_COCO_INIT_DATA_ANNOTATION_KEY]
                .as_str()
                .unwrap(),
        );
        assert!(decoded.contains("package agent_policy"));
        for absent in ["aa.toml", "cdh.toml", "kbs.codewire-dev.sh"] {
            assert!(!decoded.contains(absent), "{absent:?} in {decoded}");
        }
    }

    #[test]
    fn commodity_template_ignores_coco_only_init_data_flag() {
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-commodity".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
                kata_coco_init_data_enabled: true,
                ..Default::default()
            },
        );

        let pod_template = &rendered["spec"]["podTemplate"];
        let annotations = pod_template["metadata"]["annotations"].as_object().unwrap();
        assert!(!annotations.contains_key(KATA_COCO_INIT_DATA_ANNOTATION_KEY));
        assert!(
            pod_template["metadata"]["labels"]["codewire.sh/isolation-tier"].is_null(),
            "ordinary Kata templates must not gain the confidential NetworkPolicy label"
        );
    }

    #[test]
    fn confidential_template_policy_init_data_carries_kbs_config() {
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-confidential".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
                workspace_binding_url: MEASURED_BINDING_URL.into(),
                measured_binding_roots: MEASURED_BINDING_ROOTS.into(),
                environment_id: "be31063a-8ec8-46d5-aa17-75cda1729370".into(),
                confidential_storage_manifest_uri: CONTENT_ADDRESSED_MANIFEST_URI.into(),
                disk_gib: 20,
                kata_coco_init_data_enabled: true,
                kata_coco_kbs_url: "https://kbs.codewire-dev.sh".into(),
                kata_coco_kbs_ca_pem:
                    "-----BEGIN CERTIFICATE-----\nCODEWIRE-DEV-CA\n-----END CERTIFICATE-----\n"
                        .into(),
                kata_coco_test_resource_uri: "kbs:///default/codewire/runtime-test-resource".into(),
                ..Default::default()
            },
        );

        let pod_template = &rendered["spec"]["podTemplate"];
        let annotations = pod_template["metadata"]["annotations"].as_object().unwrap();
        let decoded = decode_gzip_base64(
            annotations
                .get(KATA_COCO_INIT_DATA_ANNOTATION_KEY)
                .unwrap()
                .as_str()
                .unwrap(),
        );
        for want in [
            "\"aa.toml\" = '''".to_string(),
            "[token_configs.kbs]".to_string(),
            "\"cdh.toml\" = '''".to_string(),
            "default SetPolicyRequest := false".to_string(),
            "default CreateContainerRequest := false".to_string(),
            "url = \"https://kbs.codewire-dev.sh\"".to_string(),
            CONTENT_ADDRESSED_MANIFEST_URI.to_string(),
            "\"group_change_policy\": 1".to_string(),
        ] {
            assert!(decoded.contains(&want), "missing {want:?} in {decoded}");
        }
        assert!(
            !decoded.contains("[[credentials]]"),
            "init-data should leave runtime resource retrieval to Agent-only CDH instead of credential prefetch:\n{decoded}"
        );
        let init_data: toml::Value = toml::from_str(&decoded).unwrap();
        let data = init_data["data"].as_table().unwrap();
        assert_eq!(
            data["codewire_workspace_storage_key_id"].as_str(),
            Some("be31063a-8ec8-46d5-aa17-75cda1729370"),
            "Trustee key release must remain bound to the measured environment ID"
        );
        assert_eq!(
            data["codewire_workspace_storage_manifest_tag"].as_str(),
            Some("sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            "Trustee manifest release must remain bound to the measured content tag"
        );
        assert!(
            !data.contains_key("confidential_storage"),
            "the retired parallel storage registry must remain absent"
        );
        let policy = data["policy.rego"].as_str().unwrap();
        let mut workspace = confidential_create_input(
            "workspace",
            "ghcr.io/codewiresh/workspace:golden",
            &["/home/codewire", "/workspace"],
        );
        workspace["OCI"]["Process"] = runtime_process(&pod_template["spec"], "workspace");
        assert!(kata_policy_allows(policy, &workspace));

        // The measured anchors the daemon trusts (B2c): each appears exactly
        // once, with its measured value, or the workspace never starts.
        let env_of = |request: &Value| -> Vec<String> {
            request["OCI"]["Process"]["Env"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry.as_str().unwrap().to_owned())
                .collect()
        };
        let with_env = |env: Vec<String>| {
            let mut request = workspace.clone();
            request["OCI"]["Process"]["Env"] = json!(env);
            request
        };
        for (name, substitute) in [
            (
                codewire_daemon_proto::WORKSPACE_MEASURED_BINDING_ROOTS_ENV,
                "-----BEGIN CERTIFICATE-----\nATTACKER\n-----END CERTIFICATE-----\n",
            ),
            (
                codewire_daemon_proto::WORKSPACE_MEASURED_ENVIRONMENT_ID_ENV,
                "b3a9c6f2-1d4e-4f5a-8b7c-6d5e4f3a2b1c",
            ),
            (
                codewire_daemon_proto::WORKSPACE_BINDING_URL_ENV,
                "https://attacker.example:8087",
            ),
        ] {
            let prefix = format!("{name}=");
            let original = env_of(&workspace);
            assert_eq!(
                original
                    .iter()
                    .filter(|entry| entry.starts_with(&prefix))
                    .count(),
                1,
                "{name} is rendered exactly once"
            );
            let substituted = original
                .iter()
                .map(|entry| {
                    if entry.starts_with(&prefix) {
                        format!("{prefix}{substitute}")
                    } else {
                        entry.clone()
                    }
                })
                .collect();
            assert!(
                !kata_policy_allows(policy, &with_env(substituted)),
                "{name} substituted"
            );
            let missing = original
                .iter()
                .filter(|entry| !entry.starts_with(&prefix))
                .cloned()
                .collect();
            assert!(!kata_policy_allows(policy, &with_env(missing)), "{name} missing");
            let mut shadowed = original.clone();
            shadowed.push(format!("{prefix}{substitute}"));
            assert!(
                !kata_policy_allows(policy, &with_env(shadowed)),
                "{name} shadowed by a second entry"
            );
            let mut repeated = original.clone();
            repeated.push(
                original
                    .iter()
                    .find(|entry| entry.starts_with(&prefix))
                    .unwrap()
                    .clone(),
            );
            assert!(
                !kata_policy_allows(policy, &with_env(repeated)),
                "{name} repeated"
            );
        }
        let mut no_process = workspace.clone();
        no_process["OCI"].as_object_mut().unwrap().remove("Process");
        assert!(!kata_policy_allows(policy, &no_process));
        // The measured init-data carries the anchors themselves and never a
        // daemon token.
        for want in [
            MEASURED_BINDING_URL,
            "MIIBsynthetic",
            "be31063a-8ec8-46d5-aa17-75cda1729370",
        ] {
            assert!(policy.contains(want), "policy lacks {want}");
        }
        assert!(!decoded.contains("CODEWIRE_DAEMON_AUTH_TOKEN"));
        assert!(!decoded.contains("test-daemon-token"));
        let dind_image = pod_template["spec"]["containers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|container| container["name"].as_str() == Some("dind"))
            .and_then(|container| container["image"].as_str())
            .unwrap();
        assert!(kata_policy_allows(
            policy,
            &confidential_create_input("dind", dind_image, &["/workspace"])
        ));
        let cri_sandbox = kata_cri_sandbox_create_input();
        assert!(
            kata_policy_allows(policy, &cri_sandbox),
            "Kata's CRI sandbox request has no container-name and must be authorized before init containers"
        );
        let mut sandbox_with_confidential_storage = cri_sandbox.clone();
        sandbox_with_confidential_storage["storages"] = workspace["storages"].clone();
        assert!(
            !kata_policy_allows(policy, &sandbox_with_confidential_storage),
            "the CRI sandbox must not activate confidential storage"
        );
        let mut sandbox_with_protected_mount = cri_sandbox.clone();
        sandbox_with_protected_mount["OCI"]["Mounts"] = workspace["OCI"]["Mounts"].clone();
        assert!(
            !kata_policy_allows(policy, &sandbox_with_protected_mount),
            "the CRI sandbox must not receive a protected workspace mount"
        );
        let mut unnamed_non_sandbox = cri_sandbox.clone();
        unnamed_non_sandbox["OCI"]["Annotations"]["io.kubernetes.cri.container-type"] =
            "container".into();
        assert!(
            !kata_policy_allows(policy, &unnamed_non_sandbox),
            "only the canonical CRI sandbox shape may omit container-name"
        );
        let mut auxiliary = workspace.clone();
        auxiliary["OCI"]["Annotations"]["io.kubernetes.cri.container-name"] =
            "codewire-daemon-init".into();
        auxiliary["OCI"]["Mounts"] = serde_json::json!([]);
        auxiliary["storages"] = serde_json::json!([]);
        assert!(
            kata_policy_allows(policy, &auxiliary),
            "containers outside the measured volume declaration remain usable"
        );

        let mut manifest_substitution = workspace.clone();
        manifest_substitution["storages"][0]["confidential_storage"]["manifest_uri"] =
            "kbs:///default/codewire-storage-manifests/sha256-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
        assert!(!kata_policy_allows(policy, &manifest_substitution));
        let mut access_downgrade = workspace.clone();
        access_downgrade["storages"][0]["confidential_storage"]["requested_access"] = 1.into();
        assert!(!kata_policy_allows(policy, &access_downgrade));
        let mut image_substitution = workspace.clone();
        image_substitution["OCI"]["Annotations"]["io.kubernetes.cri.image-name"] =
            "ghcr.io/codewiresh/workspace:substituted".into();
        assert!(!kata_policy_allows(policy, &image_substitution));
        let mut missing_storage = workspace.clone();
        missing_storage["storages"] = serde_json::json!([]);
        assert!(!kata_policy_allows(policy, &missing_storage));
        let mut missing_contract = missing_storage.clone();
        missing_contract["OCI"]["Mounts"] = serde_json::json!([]);
        assert!(
            !kata_policy_allows(policy, &missing_contract),
            "a protected container must not start without its measured storage contract"
        );
        let mut mount_option_substitution = workspace.clone();
        mount_option_substitution["OCI"]["Mounts"][0]["options"] =
            serde_json::json!(["rbind", "rw"]);
        assert!(!kata_policy_allows(policy, &mount_option_substitution));
        let mut fs_group_substitution = workspace.clone();
        fs_group_substitution["storages"][0]["fs_group"]["group_id"] = 0.into();
        assert!(!kata_policy_allows(policy, &fs_group_substitution));
        let mut mount_point_substitution = workspace.clone();
        mount_point_substitution["storages"][0]["mount_point"] =
            "/run/kata-containers/shared/containers/passthrough/confidential-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
        mount_point_substitution["OCI"]["Mounts"][0]["source"] =
            mount_point_substitution["storages"][0]["mount_point"].clone();
        mount_point_substitution["OCI"]["Mounts"][1]["source"] =
            mount_point_substitution["storages"][0]["mount_point"].clone();
        assert!(!kata_policy_allows(policy, &mount_point_substitution));
        let mut extra_storage = workspace.clone();
        extra_storage["storages"]
            .as_array_mut()
            .unwrap()
            .push(workspace["storages"][0].clone());
        assert!(!kata_policy_allows(policy, &extra_storage));
        let mut raw_agent_device = workspace.clone();
        raw_agent_device["devices"] = serde_json::json!([{
            "container_path": KATA_CONFIDENTIAL_WORKSPACE_DEVICE_PATH,
        }]);
        assert!(!kata_policy_allows(policy, &raw_agent_device));
        let mut raw_oci_device = workspace.clone();
        raw_oci_device["OCI"]["Linux"]["Devices"] = serde_json::json!([{
            "Path": KATA_CONFIDENTIAL_WORKSPACE_DEVICE_PATH,
        }]);
        assert!(!kata_policy_allows(policy, &raw_oci_device));

        let declaration: serde_json::Value = serde_json::from_str(
            annotations[KATA_CONFIDENTIAL_VOLUME_ANNOTATION]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            declaration,
            serde_json::json!({
                "workspace": {
                    "devicePath": KATA_CONFIDENTIAL_WORKSPACE_DEVICE_PATH,
                    "manifestUri": CONTENT_ADDRESSED_MANIFEST_URI,
                    "access": "readWrite",
                    "fsGroup": 1000,
                    "fsGroupChangePolicy": "OnRootMismatch",
                    "mounts": {
                        "workspace": ["/home/codewire", "/workspace"],
                        "dind": ["/workspace"],
                    },
                }
            })
        );
        for (container_name, destinations) in [
            ("workspace", vec!["/home/codewire", "/workspace"]),
            ("dind", vec!["/workspace"]),
        ] {
            let container = pod_template["spec"]["containers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|container| container["name"].as_str() == Some(container_name))
                .unwrap();
            assert_eq!(
                container["volumeDevices"],
                serde_json::json!([{
                    "name": "workspace",
                    "devicePath": KATA_CONFIDENTIAL_WORKSPACE_DEVICE_PATH,
                }])
            );
            assert!(
                container["volumeMounts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|mount| mount["name"].as_str() != Some("workspace"))
            );
            assert_eq!(
                declaration["workspace"]["mounts"][container_name],
                serde_json::json!(destinations)
            );
        }
        let aa: toml::Value = toml::from_str(data["aa.toml"].as_str().unwrap()).unwrap();
        assert_eq!(
            aa["token_configs"]["kbs"]["cert"].as_str(),
            Some("-----BEGIN CERTIFICATE-----\nCODEWIRE-DEV-CA\n-----END CERTIFICATE-----")
        );
        let cdh: toml::Value = toml::from_str(data["cdh.toml"].as_str().unwrap()).unwrap();
        assert_eq!(
            cdh["kbc"]["kbs_cert"].as_str(),
            Some("-----BEGIN CERTIFICATE-----\nCODEWIRE-DEV-CA\n-----END CERTIFICATE-----")
        );
        assert_eq!(
            cdh["protected_resource_uri_prefixes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["kbs:///default/codewire-workspace-luks/"]
        );
        assert!(
            cdh.get("image").is_none(),
            "a partial image table would suppress agent.image_registry_auth"
        );
        assert_eq!(
            pod_template["metadata"]["labels"]["codewire.sh/isolation-tier"].as_str(),
            Some("confidential")
        );
        let containers = pod_template["spec"]["containers"].as_array().unwrap();
        let dind = containers
            .iter()
            .find(|container| container["name"].as_str() == Some("dind"))
            .unwrap();
        let command = dind["command"].as_array().unwrap();
        assert_eq!(command[0].as_str(), Some("sh"));
        assert_eq!(command[1].as_str(), Some("-ec"));
        let bootstrap = command[2].as_str().unwrap();
        assert!(bootstrap.contains("CODEWIRE_DOCKER_MOUNT_MODE"));
        assert!(bootstrap.contains("--data-root \"$data_root\""));
        assert!(bootstrap.contains("--storage-driver vfs"));
        assert!(dind["env"].as_array().unwrap().iter().any(|env| {
            env["name"].as_str() == Some("CODEWIRE_DOCKER_DATA_ROOT")
                && env["value"].as_str() == Some("/workspace/.codewire/docker-root")
        }));
        assert!(dind["env"].as_array().unwrap().iter().any(|env| {
            env["name"].as_str() == Some("CODEWIRE_DOCKER_MOUNT_MODE")
                && env["value"].as_str() == Some("none")
        }));
    }

    #[test]
    fn confidential_policy_matches_shared_kata_contract_corpus() {
        let fixture = confidential_policy_conformance_fixture();
        assert_eq!(fixture["schema_version"], 1);
        let manifest_uri = fixture["declaration"]["workspace"]["manifestUri"]
            .as_str()
            .unwrap();
        let image =
            fixture["workload_request"]["OCI"]["Annotations"]["io.kubernetes.cri.image-name"]
                .as_str()
                .unwrap();
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-confidential-policy-conformance".into(),
                image: image.into(),
                runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
                workspace_binding_url: MEASURED_BINDING_URL.into(),
                measured_binding_roots: MEASURED_BINDING_ROOTS.into(),
                docker_mode: DOCKER_MODE_NONE.into(),
                environment_id: "be31063a-8ec8-46d5-aa17-75cda1729370".into(),
                confidential_storage_manifest_uri: manifest_uri.into(),
                disk_gib: 20,
                kata_coco_init_data_enabled: true,
                ..Default::default()
            },
        );
        let annotations = rendered["spec"]["podTemplate"]["metadata"]["annotations"]
            .as_object()
            .unwrap();
        let declaration: Value = serde_json::from_str(
            annotations[KATA_CONFIDENTIAL_VOLUME_ANNOTATION]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            declaration, fixture["declaration"],
            "Codewire's typed renderer must emit the shared Kata declaration"
        );

        let init_data = decode_gzip_base64(
            annotations[KATA_COCO_INIT_DATA_ANNOTATION_KEY]
                .as_str()
                .unwrap(),
        );
        let init_data: toml::Value = toml::from_str(&init_data).unwrap();
        let policy = init_data["data"]["policy.rego"].as_str().unwrap();

        // The shared corpus covers storage. The workspace process carries the
        // measured binding anchors (B2c), which the corpus leaves out: give
        // each workload request the rendered process, keeping the corpus
        // byte-identical with the Kata fork's copy.
        let mut workload_request = fixture["workload_request"].clone();
        workload_request["OCI"]["Process"] =
            runtime_process(&rendered["spec"]["podTemplate"]["spec"], "workspace");
        for case in fixture["cases"].as_array().unwrap() {
            let mut request = match case["base"].as_str().unwrap() {
                "workload" => workload_request.clone(),
                "sandbox" => fixture["sandbox_request"].clone(),
                base => panic!("unknown conformance base {base:?}"),
            };
            apply_conformance_patches(&mut request, &case["patches"]);
            assert_eq!(
                kata_policy_allows(policy, &request),
                case["allowed"].as_bool().unwrap(),
                "shared confidential-storage policy case {:?}",
                case["name"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn confidential_template_requires_content_addressed_manifest_before_mutation() {
        let mut opts = TemplateOpts {
            runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
            workspace_binding_url: MEASURED_BINDING_URL.into(),
            measured_binding_roots: MEASURED_BINDING_ROOTS.into(),
            disk_gib: 20,
            ..Default::default()
        };
        assert!(opts.validate_confidential_storage_manifest().is_err());
        opts.confidential_storage_manifest_uri = CONTENT_ADDRESSED_MANIFEST_URI.into();
        assert!(opts.validate_confidential_storage_manifest().is_ok());
        opts.confidential_storage_manifest_uri =
            "kbs:///default/codewire-storage-manifests/latest".into();
        assert!(opts.validate_confidential_storage_manifest().is_err());
    }

    #[test]
    fn owner_authorization_hashes_the_exact_measured_init_data_bytes() {
        let opts = TemplateOpts {
            name: "tmpl-confidential-owner-authorization".into(),
            image: "ghcr.io/codewiresh/workspace-base@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
            workspace_binding_url: MEASURED_BINDING_URL.into(),
            measured_binding_roots: MEASURED_BINDING_ROOTS.into(),
            environment_id: "be31063a-8ec8-46d5-aa17-75cda1729370".into(),
            confidential_storage_manifest_uri: CONTENT_ADDRESSED_MANIFEST_URI.into(),
            disk_gib: 20,
            kata_coco_init_data_enabled: true,
            ..Default::default()
        };

        let authorized = confidential_init_data(&opts).unwrap();
        let rendered = render_sandbox_template("codewire-runtime", &opts);
        let measured = decode_gzip_base64(
            rendered["spec"]["podTemplate"]["metadata"]["annotations"]
                [KATA_COCO_INIT_DATA_ANNOTATION_KEY]
                .as_str()
                .unwrap(),
        );

        assert_eq!(authorized, measured);
        assert_eq!(
            format!("{:x}", Sha256::digest(authorized.as_bytes())),
            format!("{:x}", Sha256::digest(measured.as_bytes()))
        );
    }

    #[test]
    fn measured_key_release_claim_requires_the_exact_protected_contract() {
        let mut opts = TemplateOpts {
            runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
            workspace_binding_url: MEASURED_BINDING_URL.into(),
            measured_binding_roots: MEASURED_BINDING_ROOTS.into(),
            environment_id: "be31063a-8ec8-46d5-aa17-75cda1729370".into(),
            confidential_storage_manifest_uri: CONTENT_ADDRESSED_MANIFEST_URI.into(),
            disk_gib: 20,
            ..Default::default()
        };
        let data = |opts: &TemplateOpts| {
            let init_data = encoding::build_codewire_kata_policy_init_data(opts, true);
            toml::from_str::<toml::Value>(&init_data).unwrap()["data"]
                .as_table()
                .unwrap()
                .clone()
        };

        assert_eq!(
            data(&opts)["codewire_workspace_storage_key_id"].as_str(),
            Some("be31063a-8ec8-46d5-aa17-75cda1729370")
        );
        assert_eq!(
            data(&opts)["codewire_workspace_storage_manifest_tag"].as_str(),
            Some("sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );

        opts.confidential_storage_manifest_uri =
            "kbs:///default/codewire-storage-manifests/latest".into();
        assert!(!data(&opts).contains_key("codewire_workspace_storage_key_id"));
        assert!(!data(&opts).contains_key("codewire_workspace_storage_manifest_tag"));

        opts.confidential_storage_manifest_uri = CONTENT_ADDRESSED_MANIFEST_URI.into();
        opts.environment_id = "BE31063A-8EC8-46D5-AA17-75CDA1729370".into();
        assert!(!data(&opts).contains_key("codewire_workspace_storage_key_id"));
        assert!(!data(&opts).contains_key("codewire_workspace_storage_manifest_tag"));
    }

    #[test]
    fn confidential_template_carries_coco_resource_kernel_params() {
        let opts = TemplateOpts {
            name: "tmpl-confidential-auth".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            support_image: "registry.example.invalid/codewire/daemon:test".into(),
            runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
            workspace_binding_url: MEASURED_BINDING_URL.into(),
            measured_binding_roots: MEASURED_BINDING_ROOTS.into(),
            kata_coco_init_data_enabled: true,
            kata_coco_kbs_url:
                "http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080".into(),
            kata_coco_image_registry_auth_uri: "kbs:///default/containers/auth".into(),
            environment_id: "be31063a-8ec8-46d5-aa17-75cda1729370".into(),
            confidential_storage_manifest_uri: CONTENT_ADDRESSED_MANIFEST_URI.into(),
            disk_gib: 20,
            server_namespace: "dev".into(),
            ..Default::default()
        };
        let want_kernel_params = "agent.image_registry_auth=kbs:///default/containers/auth agent.image_resource_timeout_secs=300 agent.guest_components_procs=confidential-data-hub agent.aa_kbc_params=cc_kbc::http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080 agent.log_vport=1025";

        let rendered = render_sandbox_template("codewire-runtime", &opts);
        let annotations = rendered["spec"]["podTemplate"]["metadata"]["annotations"]
            .as_object()
            .unwrap();
        assert_eq!(
            annotations
                .get(KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY)
                .and_then(Value::as_str),
            Some(want_kernel_params)
        );
    }

    #[test]
    fn confidential_template_carries_resource_kernel_params_without_registry_auth() {
        let opts = TemplateOpts {
            name: "tmpl-confidential-resource".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
            workspace_binding_url: MEASURED_BINDING_URL.into(),
            measured_binding_roots: MEASURED_BINDING_ROOTS.into(),
            kata_coco_init_data_enabled: true,
            kata_coco_kbs_url:
                "http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080".into(),
            ..Default::default()
        };
        let want_kernel_params = "agent.image_resource_timeout_secs=300 agent.guest_components_procs=confidential-data-hub agent.aa_kbc_params=cc_kbc::http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080 agent.log_vport=1025";

        let rendered = render_sandbox_template("codewire-runtime", &opts);
        let annotations = rendered["spec"]["podTemplate"]["metadata"]["annotations"]
            .as_object()
            .unwrap();
        assert_eq!(
            annotations
                .get(KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY)
                .and_then(Value::as_str),
            Some(want_kernel_params)
        );
    }

    #[test]
    fn commodity_template_ignores_registry_auth_kernel_params() {
        let opts = TemplateOpts {
            name: "tmpl-commodity-auth".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
            kata_coco_init_data_enabled: true,
            kata_coco_kbs_url: "https://kbs.codewire-dev.sh".into(),
            kata_coco_image_registry_auth_uri: "kbs:///default/containers/auth".into(),
            ..Default::default()
        };

        let rendered = render_sandbox_template("codewire-runtime", &opts);
        let annotations = rendered["spec"]["podTemplate"]["metadata"]["annotations"]
            .as_object()
            .unwrap();
        assert!(!annotations.contains_key(KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY));
    }

    #[test]
    fn gzip_base64_uses_deterministic_stored_blocks() {
        let want = "H4sIAAAAAAAA/wEFAPr/aGVsbG+GphA2BQAAAA==";
        assert_eq!(gzip_base64("hello"), want);
        assert_eq!(decode_gzip_base64(want), "hello");
    }

    #[test]
    fn template_allows_cluster_local_kbs_egress() {
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-kbs-egress".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                support_image: "registry.example.invalid/codewire/daemon:test".into(),
                runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
                workspace_binding_url: MEASURED_BINDING_URL.into(),
                measured_binding_roots: MEASURED_BINDING_ROOTS.into(),
                kata_coco_init_data_enabled: true,
                kata_coco_kbs_url:
                    "http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080".into(),
                kata_coco_test_resource_uri: "kbs:///default/codewire/runtime-test-resource".into(),
                kata_coco_test_resource_path: DEFAULT_KATA_COCO_TEST_RESOURCE_PATH.into(),
                api_base_url: "https://codewire-dev.sh".into(),
                server_namespace: "dev".into(),
                derp_host: "derp.codewire-dev.sh".into(),
                derp_port: 443,
                stun_host: "stun.codewire.sh".into(),
                stun_port: 3478,
                cpu_millicores: 1000,
                memory_mib: 2048,
                ..Default::default()
            },
        );

        let egress = rendered["spec"]["networkPolicy"]["egress"]
            .as_array()
            .unwrap();
        let kbs_rule = egress.iter().find(|rule| {
            rule["to"].as_array().is_some_and(|targets| {
                targets.iter().any(|target| {
                    target["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                        .as_str()
                        == Some("codewire-trustee")
                        && target["podSelector"].is_null()
                })
            })
        });
        let kbs_rule = kbs_rule.expect("KBS egress rule missing");
        let ports = kbs_rule["ports"].as_array().unwrap();
        assert!(ports.iter().any(|port| {
            port["protocol"].as_str() == Some("TCP") && port["port"].as_i64() == Some(8080)
        }));
    }

    /// codewire#3332: the KBS URL is configured cluster-wide, but only a
    /// confidential workspace may reach the Trustee namespace. A standard
    /// workspace's template and its own daemon policy carry no Trustee rule.
    #[test]
    fn standard_workspaces_get_no_kbs_egress() {
        let names_trustee = |policy: &Value| {
            policy["egress"].as_array().into_iter().flatten().any(|rule| {
                rule.to_string().contains("codewire-trustee")
            })
        };
        for profile in ["", RUNTIME_PROFILE_COMMODITY] {
            let opts = TemplateOpts {
                name: "tmpl-standard".into(),
                environment_id: "00000000-0000-4000-8000-000000000001".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                support_image: "registry.example.invalid/codewire/daemon:test".into(),
                runtime_profile: profile.into(),
                kata_coco_kbs_url:
                    "http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080".into(),
                api_base_url: "https://codewire-dev.sh".into(),
                server_namespace: "dev".into(),
                cpu_millicores: 1000,
                memory_mib: 2048,
                ..Default::default()
            };
            let rendered = render_sandbox_template("codewire-runtime", &opts);
            assert!(!names_trustee(&rendered["spec"]["networkPolicy"]), "{profile:?} template");
            let daemon = network::render_workspace_daemon_network_policy("dev-sandboxes", &opts);
            assert!(!names_trustee(&daemon["spec"]), "{profile:?} daemon policy");
            assert!(!network::identity_free_workspace_egress_rules(&opts)
                .iter()
                .any(|rule| rule.to_string().contains("codewire-trustee")));
        }
    }

    #[test]
    fn workspace_storage_class_is_required_except_for_confidential() {
        for missing in ["", "  "] {
            for profile in ["", RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_RUNC] {
                let error = required_workspace_storage_class(profile, missing).unwrap_err();
                assert!(error.contains(WORKSPACE_STORAGE_CLASS_ENV), "{error}");
                assert!(error.contains("docs/CONFIGURATION.md"), "{error}");
            }
            assert_eq!(
                required_workspace_storage_class(RUNTIME_PROFILE_CONFIDENTIAL, missing).unwrap(),
                ""
            );
        }
        assert!(required_workspace_storage_class(RUNTIME_PROFILE_COMMODITY, "two words").is_err());
        assert_eq!(
            required_workspace_storage_class(RUNTIME_PROFILE_COMMODITY, " example-class ").unwrap(),
            "example-class"
        );
    }

    #[test]
    fn confidential_workspace_storage_class_is_one_name_or_unset() {
        assert_eq!(confidential_workspace_storage_class("").unwrap(), "");
        assert_eq!(confidential_workspace_storage_class("  ").unwrap(), "");
        assert_eq!(
            confidential_workspace_storage_class(" linstor-confidential ").unwrap(),
            "linstor-confidential"
        );
        let error = confidential_workspace_storage_class("two words").unwrap_err();
        assert!(
            error.contains(CONFIDENTIAL_WORKSPACE_STORAGE_CLASS_ENV),
            "{error}"
        );
    }

    #[test]
    fn workspace_storage_class_is_the_configured_class() {
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-storage-configured".into(),
                disk_gib: 20,
                workspace_storage_class: "example-workspace-class".into(),
                ..Default::default()
            },
        );
        assert_eq!(
            rendered["spec"]["volumeClaimTemplates"][0]["spec"]["storageClassName"].as_str(),
            Some("example-workspace-class")
        );
        assert!(
            rendered["spec"]["volumeClaimTemplates"][0]["spec"]["volumeMode"].is_null(),
            "ordinary claims retain Kubernetes' default Filesystem mode"
        );
        let ordinary_workspace = &rendered["spec"]["podTemplate"]["spec"]["containers"][0];
        assert!(ordinary_workspace["volumeDevices"].is_null());
        assert!(
            ordinary_workspace["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|mount| mount["name"].as_str() == Some("workspace"))
        );

        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-storage-local".into(),
                disk_gib: 20,
                workspace_storage_class: "local-path".into(),
                ..Default::default()
            },
        );
        assert_eq!(
            rendered["spec"]["volumeClaimTemplates"][0]["spec"]["storageClassName"].as_str(),
            Some("local-path")
        );

        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-storage-confidential".into(),
                environment_id: "be31063a-8ec8-46d5-aa17-75cda1729370".into(),
                workspace_binding_url: MEASURED_BINDING_URL.into(),
                measured_binding_roots: MEASURED_BINDING_ROOTS.into(),
                confidential_storage_manifest_uri: CONTENT_ADDRESSED_MANIFEST_URI.into(),
                runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
                disk_gib: 20,
                workspace_storage_class: "example-confidential-class".into(),
                ..Default::default()
            },
        );
        let claim = &rendered["spec"]["volumeClaimTemplates"][0];
        assert_eq!(
            claim["spec"]["storageClassName"].as_str(),
            Some("example-confidential-class")
        );
        assert_eq!(
            claim["spec"]["accessModes"][0].as_str(),
            Some("ReadWriteOncePod")
        );
        assert_eq!(claim["spec"]["volumeMode"].as_str(), Some("Block"));
        assert!(claim["metadata"]["annotations"].is_null());
    }

    #[test]
    fn direct_udp_load_balancer_service_uses_cilium_lb_ipam_without_nodeports() {
        let opts = TemplateOpts {
            direct_udp_lb_enabled: true,
            direct_udp_lb_ip: "203.0.113.36".into(),
            direct_udp_lb_port: 33123,
            direct_udp_lb_class: "io.cilium/l2-announcer".into(),
            direct_udp_lb_sharing_key: "codewire-direct-udp".into(),
            direct_udp_transport_zone: "example-zone".into(),
            ..commodity_opts()
        };

        let service = render_direct_udp_service("codewire-runtime", &opts)
            .expect("direct UDP LoadBalancer service");
        assert_eq!(
            service["metadata"]["name"].as_str(),
            Some("cw-tailnet-udp-env-golden-commodity")
        );
        assert_eq!(
            service["metadata"]["annotations"]["lbipam.cilium.io/ips"].as_str(),
            Some("203.0.113.36")
        );
        assert_eq!(
            service["metadata"]["annotations"]["lbipam.cilium.io/sharing-key"].as_str(),
            Some("codewire-direct-udp")
        );
        assert_eq!(
            service["metadata"]["annotations"]["lbipam.cilium.io/sharing-cross-namespace"].as_str(),
            Some("*")
        );
        assert_eq!(
            service["metadata"]["labels"]["codewire.sh/type"].as_str(),
            Some("direct-udp-lb")
        );
        assert_eq!(
            service["metadata"]["labels"]["codewire.sh/runtime-network"].as_str(),
            Some("direct-udp")
        );
        assert_eq!(
            service["metadata"]["labels"]["codewire.sh/transport-zone"].as_str(),
            Some("example-zone")
        );
        assert_eq!(service["spec"]["type"].as_str(), Some("LoadBalancer"));
        assert_eq!(
            service["spec"]["loadBalancerClass"].as_str(),
            Some("io.cilium/l2-announcer")
        );
        assert_eq!(
            service["spec"]["allocateLoadBalancerNodePorts"].as_bool(),
            Some(false)
        );
        assert_eq!(
            service["spec"]["externalTrafficPolicy"].as_str(),
            Some("Cluster")
        );
        assert!(
            service["spec"]["ports"]
                .as_array()
                .unwrap()
                .iter()
                .all(|port| port.get("nodePort").is_none()),
            "direct UDP LoadBalancer service must not allocate NodePorts"
        );
        assert_eq!(service["spec"]["ports"][0]["port"].as_i64(), Some(33123));
        assert_eq!(
            service["spec"]["ports"][0]["targetPort"].as_i64(),
            Some(i64::from(codewire_daemon_proto::WORKSPACE_TAILNET_UDP_PORT))
        );
        assert_eq!(
            service["spec"]["selector"]["codewire.sh/type"].as_str(),
            Some("workspace")
        );
    }

    #[test]
    fn workspace_daemon_service_and_policy_select_expected_identities() {
        let opts = commodity_opts();
        let service = render_workspace_daemon_service("codewire-runtime", &opts);
        assert_eq!(
            service["spec"]["selector"]["codewire.sh/environment-id"].as_str(),
            Some("env-golden-commodity")
        );
        assert_eq!(
            service["spec"]["selector"]["codewire.sh/type"].as_str(),
            Some("workspace")
        );
        assert_eq!(
            service["spec"]["ports"][0]["port"].as_i64(),
            Some(WORKSPACE_DAEMON_PORT)
        );
        // The gateway reaches a commodity daemon while Docker is still
        // starting; confidential keeps Ready-only endpoints.
        assert_eq!(
            service["spec"]["publishNotReadyAddresses"].as_bool(),
            Some(true)
        );
        let confidential = measured(opts.clone());
        assert_eq!(
            render_workspace_daemon_service("codewire-runtime", &confidential)["spec"]
                ["publishNotReadyAddresses"]
                .as_bool(),
            Some(false)
        );

        let policy = render_workspace_daemon_network_policy("codewire-runtime", &opts);
        assert_eq!(
            policy["spec"]["podSelector"]["matchLabels"]["codewire.sh/type"].as_str(),
            Some("workspace")
        );
        // Only orchestration reaches the daemon, SSH and preview ports; no
        // gateway or other same-namespace Pod is a peer.
        let ingress = policy["spec"]["ingress"].as_array().unwrap();
        assert_eq!(ingress.len(), 2, "{ingress:?}");
        assert_eq!(
            ingress[0]["from"][0]["namespaceSelector"]["matchLabels"]
                ["kubernetes.io/metadata.name"]
                .as_str(),
            Some("dev")
        );
        assert_eq!(
            ingress[0]["from"][0]["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
                .as_str(),
            Some("orchestration")
        );
        assert_eq!(
            ingress[0]["ports"],
            json!([
                {"protocol": "TCP", "port": WORKSPACE_DAEMON_PORT},
                {"protocol": "TCP", "port": codewire_daemon_proto::WORKSPACE_SSH_PORT},
                {"protocol": "TCP", "port": APP_PREVIEW_MIN_PORT, "endPort": APP_PREVIEW_MAX_PORT},
            ])
        );
        // The tailnet UDP listener's port admits the world alone (N1): no
        // cluster or Pod address.
        let world = &ingress[1];
        assert_eq!(
            world["ports"],
            json!([{"protocol": "UDP", "port": codewire_daemon_proto::WORKSPACE_TAILNET_UDP_PORT}])
        );
        let peers = world["from"].as_array().unwrap();
        assert_eq!(peers.len(), 2);
        for peer in peers {
            assert_eq!(peer.as_object().unwrap().len(), 1, "{peer}");
            let block = &peer["ipBlock"];
            let except: Vec<&str> = block["except"]
                .as_array()
                .unwrap()
                .iter()
                .map(|cidr| cidr.as_str().unwrap())
                .collect();
            match block["cidr"].as_str() {
                Some("0.0.0.0/0") => {
                    for cluster in ["10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"] {
                        assert!(except.contains(&cluster), "{cluster} may send to the tailnet port");
                    }
                }
                Some("::/0") => assert_eq!(except, ["fc00::/7"]),
                other => panic!("unexpected tailnet peer {other:?}"),
            }
        }
        let egress = policy["spec"]["egress"].as_array().unwrap();
        assert!(egress.iter().any(|rule| {
            rule["to"]
                .as_array()
                .is_some_and(|targets| targets.iter().any(|target| target.get("ipBlock").is_some()))
        }));
        assert_eq!(policy["spec"]["policyTypes"][1].as_str(), Some("Egress"));
    }

    #[test]
    fn zero_replica_shadow_pool_matches_golden_file() {
        crate::test_golden::assert_golden(
            "sandboxwarmpool.golden.json",
            &render_sandbox_shadow_pool(
                "codewire-runtime",
                "shadow-golden",
                "tmpl-golden",
                "env-golden",
            ),
        );
    }

    // ------------------------------------------- identity-free (B2, §13)

    const IDENTITY_FREE_BINDING_URL: &str =
        "https://codewire-orchestration-workspace-binding.dev.svc.cluster.local:8087";

    fn identity_free_opts() -> TemplateOpts {
        TemplateOpts {
            workspace_binding_url: IDENTITY_FREE_BINDING_URL.into(),
            ..credential_opts()
        }
    }

    fn workspace_volume<'a>(template: &'a Value, name: &str) -> Option<&'a Value> {
        template["spec"]["podTemplate"]["spec"]["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|volume| volume["name"] == name)
    }

    fn ingress_egress_target(template: &Value) -> (String, String) {
        let rule = template["spec"]["networkPolicy"]["egress"]
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| {
                rule["ports"].as_array().is_some_and(|ports| {
                    ports.iter().any(|port| port["port"] == 443 && port["protocol"] == "TCP")
                }) && rule["to"][0]["podSelector"].is_object()
            })
            .expect("ingress controller egress rule");
        let target = &rule["to"][0];
        (
            target["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                .as_str()
                .unwrap()
                .to_owned(),
            target["podSelector"]["matchLabels"]["app.kubernetes.io/name"]
                .as_str()
                .unwrap()
                .to_owned(),
        )
    }

    #[test]
    fn coordinator_extra_roots_and_ingress_target_default_to_dev_and_production() {
        let template = render_sandbox_template("dev-sandboxes", &identity_free_opts());
        assert!(workspace_volume(&template, "coordinator-extra-roots").is_none());
        assert!(!template.to_string().contains("/run/codewire-coordinator-extra-roots"));
        assert_eq!(
            ingress_egress_target(&template),
            ("kube-system".to_owned(), "rke2-ingress-nginx".to_owned())
        );
    }

    #[test]
    fn a_local_cluster_mounts_only_the_public_coordinator_roots_and_names_its_ingress() {
        let opts = TemplateOpts {
            coordinator_extra_roots: true,
            ingress_namespace: "ingress-nginx".into(),
            ingress_pod_name: "ingress-nginx".into(),
            ..identity_free_opts()
        };
        let template = render_sandbox_template("dev-sandboxes", &opts);
        assert_eq!(
            workspace_volume(&template, "coordinator-extra-roots"),
            Some(&serde_json::json!({
                "name": "coordinator-extra-roots",
                "configMap": {
                    "name": "codewire-coordinator-extra-roots",
                    "items": [{ "key": "ca.crt", "path": "ca.crt" }],
                    "defaultMode": 0o444,
                },
            }))
        );
        let containers = template["spec"]["podTemplate"]["spec"]["containers"]
            .as_array()
            .unwrap();
        let mounts: Vec<(&str, &Value)> = containers
            .iter()
            .flat_map(|container| {
                container["volumeMounts"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|mount| mount["name"] == "coordinator-extra-roots")
                    .map(move |mount| (container["name"].as_str().unwrap(), mount))
            })
            .collect();
        // The workspace container alone, read-only, at the daemon's path.
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].0, "workspace");
        assert_eq!(
            mounts[0].1,
            &serde_json::json!({
                "name": "coordinator-extra-roots",
                "mountPath": "/run/codewire-coordinator-extra-roots",
                "readOnly": true,
            })
        );
        assert_eq!(
            ingress_egress_target(&template),
            ("ingress-nginx".to_owned(), "ingress-nginx".to_owned())
        );
    }

    /// Invariant 1 / design §13: names that must never appear in an
    /// identity-free workspace template.
    const IDENTITY_FREE_FORBIDDEN_NAMES: [&str; 18] = [
        "CODEWIRE_DAEMON_AUTH_TOKEN",
        "CODEWIRE_ENVIRONMENT_ID",
        "CODEWIRE_ENVIRONMENT_OPERATION_GENERATION",
        "CODEWIRE_ENVIRONMENT_PROJECTION_SHA256",
        "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS",
        "OPENAI_BASE_URL",
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_API_KEY",
        "CODEX_HOME",
        "CODEX_CA_CERTIFICATE",
        "SSH_AUTH_SOCK",
        "credential-codex-config",
        "credential-codex-home",
        "/run/codewire-codex",
        "cw-credential-codex-",
        "codewire-client-bootstrap",
        "codex-bootstrap",
        "codewire.sh/environment-id",
    ];

    fn assert_identity_free(template: &Value, opts: &TemplateOpts) {
        let text = template.to_string();
        for forbidden in IDENTITY_FREE_FORBIDDEN_NAMES {
            assert!(!text.contains(forbidden), "{forbidden} in an identity-free template");
        }
        for value in [
            opts.environment_id.as_str(),
            opts.organization_id.as_str(),
        ] {
            assert!(!text.contains(value), "environment value in an identity-free template");
        }
        if let Some(digest) = opts.projection_selection_sha256 {
            let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            assert!(!text.contains(&hex));
        }
        // No egress to the environment's own gateway; exactly one new rule,
        // TCP 8087 to orchestration in the server namespace.
        let egress = template["spec"]["networkPolicy"]["egress"].as_array().unwrap();
        assert!(!egress.iter().any(|rule| rule.to_string().contains("\"port\":8443")));
        let binding_rules: Vec<_> = egress
            .iter()
            .filter(|rule| rule.to_string().contains("\"port\":8087"))
            .collect();
        assert_eq!(binding_rules.len(), 1);
        assert_eq!(
            binding_rules[0],
            &json!({
                "to": [{
                    "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": "dev" } },
                    "podSelector": { "matchLabels": { "app.kubernetes.io/component": "orchestration" } },
                }],
                "ports": [{ "protocol": "TCP", "port": 8087 }],
            })
        );
        // The binding token, URL and downward-API UID are in the workspace
        // container only, and the token volume has the exact audience.
        let spec = &template["spec"]["podTemplate"]["spec"];
        let volume = spec["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|volume| volume["name"] == "workspace-binding-identity")
            .expect("binding token volume");
        assert_eq!(
            volume["projected"]["sources"][0]["serviceAccountToken"],
            json!({
                "audience": "codewire.internal.workspace-binding.v1",
                "expirationSeconds": 600,
                "path": "token",
            })
        );
        assert_eq!(volume["projected"]["defaultMode"], 0o440);
        assert_eq!(spec["automountServiceAccountToken"], false);
        // No other environment's Service reaches workspace processes as
        // `*_SERVICE_HOST` variables.
        assert_eq!(spec["enableServiceLinks"], false);
        for container in spec["containers"]
            .as_array()
            .unwrap()
            .iter()
            .chain(spec["initContainers"].as_array().into_iter().flatten())
        {
            let mounts_token = container["volumeMounts"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|mount| mount["name"] == "workspace-binding-identity");
            assert_eq!(mounts_token, container["name"] == "workspace", "{}", container["name"]);
        }
        let workspace = spec["containers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|container| container["name"] == "workspace")
            .unwrap();
        let env = workspace["env"].as_array().unwrap();
        assert!(env.contains(&json!({
            "name": "CODEWIRE_WORKSPACE_BINDING_URL",
            "value": IDENTITY_FREE_BINDING_URL,
        })));
        assert!(env.contains(&json!({
            "name": "CODEWIRE_POD_UID",
            "valueFrom": { "fieldRef": { "fieldPath": "metadata.uid" } },
        })));
        // Pod readiness is the daemon's local marker, never the binding.
        assert!(
            workspace["readinessProbe"]
                .to_string()
                .contains("test -f /codewire/run/daemon/ready")
        );
    }

    /// Only Kind's test deployment selects a Codex login check period; the
    /// workspace daemon gets it in either identity mode, and nothing else
    /// renders the variable.
    #[test]
    fn kind_codex_login_check_period_renders_only_when_selected() {
        let period = |opts: &TemplateOpts| {
            let template = render_sandbox_template("dev-sandboxes", opts);
            let containers = template["spec"]["podTemplate"]["spec"]["containers"]
                .as_array()
                .unwrap()
                .clone();
            let mut found = Vec::new();
            for container in &containers {
                for entry in container["env"].as_array().into_iter().flatten() {
                    if entry["name"] == codewire_daemon::CODEX_LOGIN_CHECK_PERIOD_ENV {
                        found.push((container["name"].clone(), entry["value"].clone()));
                    }
                }
            }
            found
        };
        for opts in [identity_free_opts(), credential_opts()] {
            assert!(period(&opts).is_empty());
            let selected = TemplateOpts {
                codex_login_check_period_seconds: Some(30),
                ..opts
            };
            assert_eq!(period(&selected), vec![(json!("workspace"), json!("30"))]);
        }
    }

    #[test]
    fn identity_free_templates_carry_no_environment_state() {
        let mut variants = vec![identity_free_opts()];
        // No credential runtime, no clients.
        variants.push(TemplateOpts {
            credential_runtime: None,
            managed_credential_clients: Default::default(),
            projection_selection_sha256: None,
            ..identity_free_opts()
        });
        // The runc profile copies the daemon with an init container.
        variants.push(TemplateOpts {
            runtime_profile: RUNTIME_PROFILE_RUNC.into(),
            ..identity_free_opts()
        });
        // Without DinD.
        variants.push(TemplateOpts {
            docker_mode: DOCKER_MODE_NONE.into(),
            ..identity_free_opts()
        });
        // A custom image under the keepalive supervisor.
        variants.push(TemplateOpts {
            image: "example.invalid/custom:golden".into(),
            image_command: vec!["sleep".into(), "infinity".into()],
            ..identity_free_opts()
        });
        // The commodity Kata agent policy init-data is shape configuration.
        variants.push(TemplateOpts {
            kata_agent_policy_enabled: true,
            ..identity_free_opts()
        });
        // Every managed client selected.
        variants.push(TemplateOpts {
            managed_credential_clients:
                codewire_access::ManagedCredentialClients::from_profile_slots([
                    "codex",
                    "openai",
                    "anthropic",
                    "ssh",
                    "github",
                ])
                .unwrap(),
            ..identity_free_opts()
        });
        for opts in variants {
            let template = render_sandbox_template("dev-sandboxes", &opts);
            assert_identity_free(&template, &opts);
        }
    }

    /// Two environments of one shape render the same pod template: nothing
    /// environment-specific remains (C1 later shares one object per key).
    #[test]
    fn identity_free_pod_templates_do_not_differ_by_environment() {
        let first = identity_free_opts();
        let second = TemplateOpts {
            environment_id: "1d2e3f4a-5b6c-4d7e-8f90-a1b2c3d4e5f6".into(),
            organization_id: "org-other".into(),
            operation_generation: 12,
            managed_credential_clients:
                codewire_access::ManagedCredentialClients::from_profile_slots(["github"]).unwrap(),
            projection_selection_sha256: Some([0x11; 32]),
            ..identity_free_opts()
        };
        let render = |opts: &TemplateOpts| render_sandbox_template("dev-sandboxes", opts)["spec"].clone();
        assert_eq!(render(&first), render(&second));
    }

    /// A confidential workspace as orchestration renders it on Dev (B2c).
    fn confidential_golden_opts() -> TemplateOpts {
        TemplateOpts {
            name: "tmpl-golden-confidential".into(),
            environment_id: "be31063a-8ec8-46d5-aa17-75cda1729370".into(),
            support_image: "registry.example.invalid/codewire/daemon@sha256:48549d19114407c712d043af3ba2136d97052a2c30c82935190f75a3a61f13ab".into(),
            confidential_storage_manifest_uri: CONTENT_ADDRESSED_MANIFEST_URI.into(),
            disk_gib: 20,
            workspace_storage_class: "linstor-confidential".into(),
            kata_coco_init_data_enabled: true,
            kata_coco_kbs_url:
                "https://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080".into(),
            kata_coco_image_registry_auth_uri: "kbs:///default/containers/auth".into(),
            // A local-cluster knob never reaches a confidential daemon.
            coordinator_extra_roots: true,
            ..measured(identity_free_opts())
        }
    }

    #[test]
    fn confidential_workspace_binds_with_only_its_measured_anchors() {
        let opts = confidential_golden_opts();
        let template = render_sandbox_template("dev-sandboxes", &opts);
        let pod_spec = &template["spec"]["podTemplate"]["spec"];
        let workspace = pod_spec["containers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|container| container["name"] == "workspace")
            .unwrap();
        let env = workspace["env"].as_array().unwrap();
        let named = |name: &str| -> Vec<&Value> {
            env.iter().filter(|entry| entry["name"] == name).collect()
        };
        for (name, value) in opts.measured_workspace_environment().unwrap() {
            assert_eq!(named(name), vec![&json!({ "name": name, "value": value })]);
        }
        assert_eq!(
            named(codewire_daemon_proto::WORKSPACE_MEASURED_ENVIRONMENT_ID_ENV)[0]["value"],
            "be31063a-8ec8-46d5-aa17-75cda1729370"
        );
        assert_eq!(
            named(codewire_daemon_proto::WORKSPACE_POD_UID_ENV),
            vec![&json!({
                "name": codewire_daemon_proto::WORKSPACE_POD_UID_ENV,
                "valueFrom": { "fieldRef": { "fieldPath": "metadata.uid" } },
            })]
        );
        for forbidden in [
            LEGACY_DAEMON_AUTH_TOKEN_ENV,
            codewire_daemon::config::ENVIRONMENT_ID_ENV,
            codewire_daemon::config::ENVIRONMENT_GENERATION_ENV,
            codewire_daemon::config::HOSTED_PROJECTION_SHA256_ENV,
        ] {
            assert!(named(forbidden).is_empty(), "{forbidden}");
        }
        assert!(!template.to_string().contains("daemon-token"));
        // The host supplies every mounted file under SEV-SNP: no roots
        // ConfigMap at all, and the daemon's state lives in guest memory.
        assert!(workspace_volume(&template, "orchestration-internal-roots").is_none());
        assert!(workspace_volume(&template, "coordinator-extra-roots").is_none());
        assert!(!template.to_string().contains("codewire-orchestration-internal-roots"));
        assert_eq!(
            workspace_volume(&template, "codewire-run").unwrap()["emptyDir"],
            json!({ "medium": "Memory" })
        );
        assert!(
            workspace_volume(
                &template,
                crate::worker::workspace_binding::WORKSPACE_BINDING_VOLUME
            )
            .is_some()
        );
        // It binds like a standard workspace, and stays cold: its template
        // carries no environment label, only its measured claim and volume do.
        assert!(
            template["metadata"]["labels"]
                .as_object()
                .unwrap()
                .is_empty()
        );
        assert_eq!(pod_spec["runtimeClassName"], "confidential");
        let init_data = confidential_init_data(&opts).unwrap();
        assert_eq!(
            init_data,
            decode_gzip_base64(
                template["spec"]["podTemplate"]["metadata"]["annotations"]
                    [KATA_COCO_INIT_DATA_ANNOTATION_KEY]
                    .as_str()
                    .unwrap()
            )
        );
        for want in [
            MEASURED_BINDING_URL,
            "MIIBsynthetic",
            codewire_daemon_proto::WORKSPACE_MEASURED_BINDING_ROOTS_ENV,
            codewire_daemon_proto::WORKSPACE_MEASURED_ENVIRONMENT_ID_ENV,
        ] {
            assert!(init_data.contains(want), "init-data lacks {want}");
        }
        // Without measured roots, or without a binding, there is no
        // confidential init-data to authorize.
        assert!(
            confidential_init_data(&TemplateOpts {
                measured_binding_roots: String::new(),
                ..opts.clone()
            })
            .is_err()
        );
        assert!(
            confidential_init_data(&TemplateOpts {
                workspace_binding_url: String::new(),
                ..opts.clone()
            })
            .is_err()
        );
        // Changing any anchor changes the measurement.
        for changed in [
            TemplateOpts {
                measured_binding_roots: "-----BEGIN CERTIFICATE-----\nOTHER\n-----END CERTIFICATE-----\n".into(),
                ..opts.clone()
            },
            TemplateOpts {
                workspace_binding_url: "https://codewire-orchestration-workspace-binding.prod.svc.cluster.local:8087".into(),
                ..opts.clone()
            },
        ] {
            assert_ne!(confidential_init_data(&changed).unwrap(), init_data);
        }
    }

    #[test]
    fn confidential_template_matches_golden_file() {
        crate::test_golden::assert_golden(
            "confidential-sandboxtemplate.golden.json",
            &render_sandbox_template("dev-sandboxes", &confidential_golden_opts()),
        );
    }

    /// The Docker data image is prepared beside a guest DinD with a
    /// loop-mounted image on every profile but confidential, from DinD's own
    /// data image, size and mount mode (#3208): by the data init after any
    /// daemon copy, or on a commodity Block workspace by `mount-workspace`,
    /// which a `workspace-flush` sidecar follows (#3718).
    #[test]
    fn a_guest_dind_renders_the_docker_data_init_after_any_daemon_copy() {
        let spec = |opts: &TemplateOpts| {
            render_sandbox_template("dev-sandboxes", opts)["spec"]["podTemplate"]["spec"].clone()
        };
        let init_names = |spec: &Value| -> Vec<String> {
            spec["initContainers"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|init| init["name"].as_str().unwrap().to_owned())
                .collect()
        };
        for (profile, docker_mode, expected) in [
            (
                RUNTIME_PROFILE_COMMODITY,
                DOCKER_MODE_GUEST_DIND,
                &[MOUNT_WORKSPACE_CONTAINER, WORKSPACE_FLUSH_CONTAINER][..],
            ),
            (
                RUNTIME_PROFILE_COMMODITY,
                DOCKER_MODE_LOCAL_DIND_DIRECT,
                &[MOUNT_WORKSPACE_CONTAINER, WORKSPACE_FLUSH_CONTAINER],
            ),
            (
                RUNTIME_PROFILE_COMMODITY,
                DOCKER_MODE_NONE,
                &[MOUNT_WORKSPACE_CONTAINER, WORKSPACE_FLUSH_CONTAINER],
            ),
            (
                RUNTIME_PROFILE_RUNC,
                DOCKER_MODE_GUEST_DIND,
                &["codewire-daemon-init", DOCKER_DATA_INIT_CONTAINER],
            ),
            (
                RUNTIME_PROFILE_NONE,
                DOCKER_MODE_GUEST_DIND,
                &["codewire-daemon-init", DOCKER_DATA_INIT_CONTAINER],
            ),
            (
                RUNTIME_PROFILE_RUNC,
                DOCKER_MODE_LOCAL_DIND_DIRECT,
                &["codewire-daemon-init"],
            ),
        ] {
            let opts = TemplateOpts {
                runtime_profile: profile.into(),
                docker_mode: docker_mode.into(),
                ..commodity_opts()
            };
            let spec = spec(&opts);
            assert_eq!(init_names(&spec), expected, "{profile} {docker_mode}");
            let Some(data_init) = spec["initContainers"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|init| {
                    init["name"] == DOCKER_DATA_INIT_CONTAINER
                        || (init["name"] == MOUNT_WORKSPACE_CONTAINER && init.get("env").is_some())
                })
            else {
                continue;
            };
            assert_eq!(data_init["image"], opts.effective_support_image());
            let dind = spec["containers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|container| container["name"] == "dind")
                .unwrap();
            let expected = if profile == RUNTIME_PROFILE_COMMODITY {
                commodity_dind_bootstrap_script()
            } else {
                dind_bootstrap_script()
            };
            assert_eq!(dind["command"][2], expected);
            let dind_data_env: Vec<_> = dind["env"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|entry| DOCKER_DATA_INIT_ENV.contains(&entry["name"].as_str().unwrap()))
                .cloned()
                .collect();
            assert_eq!(data_init["env"], Value::Array(dind_data_env));
        }
    }

    /// Confidential keeps its DinD bootstrap and its daemon copy exactly:
    /// its DinD keeps a plain directory, so it runs only busybox on the
    /// Docker 29.9.2 image and no init container reaches the protected disk.
    #[test]
    fn confidential_keeps_its_dind_bootstrap_and_only_the_daemon_copy() {
        let rendered = render_sandbox_template("dev-sandboxes", &confidential_golden_opts());
        let spec = &rendered["spec"]["podTemplate"]["spec"];
        let inits = spec["initContainers"].as_array().unwrap();
        assert_eq!(inits.len(), 1);
        assert_eq!(inits[0]["name"], "codewire-daemon-init");
        assert!(!rendered.to_string().contains(DOCKER_DATA_INIT_CONTAINER));
        let dind = spec["containers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|container| container["name"] == "dind")
            .unwrap();
        assert_eq!(dind["command"], json!(["sh", "-ec", growth_in_dind_bootstrap_script()]));
        assert!(dind["env"].as_array().unwrap().contains(
            &json!({ "name": "CODEWIRE_DOCKER_MOUNT_MODE", "value": "none" })
        ));
        assert_eq!(dind["image"], DEFAULT_DIND_IMAGE);
    }

    /// Moving the data image's preparation changes the pool template, so a
    /// warm pool rolls to members whose DinD no longer formats inside DinD.
    #[test]
    fn the_docker_data_init_changes_the_pool_revision() {
        let template = render_sandbox_template("dev-sandboxes", &commodity_opts());
        let mut prior = template["spec"].clone();
        let pod = prior["podTemplate"]["spec"].as_object_mut().unwrap();
        pod.remove("initContainers").unwrap();
        let dind = pod["containers"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|container| container["name"] == "dind")
            .unwrap();
        dind["command"][2] = growth_in_dind_bootstrap_script().into();
        assert_ne!(
            crate::sandbox::warm_pool::pool_revision(&template["spec"]),
            crate::sandbox::warm_pool::pool_revision(&prior)
        );
    }

    #[test]
    fn identity_free_template_matches_golden_file() {
        let opts = identity_free_opts();
        crate::test_golden::assert_golden(
            "identity-free-sandboxtemplate.golden.json",
            &render_sandbox_template("dev-sandboxes", &opts),
        );
        let runc = TemplateOpts {
            runtime_profile: RUNTIME_PROFILE_RUNC.into(),
            ..identity_free_opts()
        };
        crate::test_golden::assert_golden(
            "identity-free-sandboxtemplate-runc.golden.json",
            &render_sandbox_template("dev-sandboxes", &runc),
        );
    }

    /// Usable means the user can SSH in (owner, 2026-10-06), and Docker comes
    /// up after (owner, 2026-10-27): with DinD the workspace is Ready on its
    /// daemon's marker exactly as without Docker, and nothing in the Pod
    /// waits for dockerd (Program #2238).
    #[test]
    fn identity_free_readiness_never_waits_for_docker() {
        let containers = |opts: &TemplateOpts| {
            render_sandbox_template("dev-sandboxes", opts)["spec"]["podTemplate"]["spec"]
                ["containers"]
                .as_array()
                .unwrap()
                .clone()
        };
        let probes = |container: &Value| {
            ["readinessProbe", "startupProbe", "livenessProbe"]
                .map(|probe| container.get(probe).cloned())
        };
        let runc = containers(&TemplateOpts {
            runtime_profile: RUNTIME_PROFILE_RUNC.into(),
            ..identity_free_opts()
        });
        assert_eq!(runc.len(), 1);
        for docker_mode in [DOCKER_MODE_GUEST_DIND, DOCKER_MODE_LOCAL_DIND_DIRECT] {
            let dind = containers(&TemplateOpts {
                docker_mode: docker_mode.into(),
                ..identity_free_opts()
            });
            let names: Vec<_> = dind.iter().map(|c| c["name"].as_str().unwrap()).collect();
            assert_eq!(names, ["workspace", "dind"], "{docker_mode}");
            assert_eq!(probes(&dind[0]), probes(&runc[0]), "{docker_mode}");
            assert_eq!(
                dind[0]["readinessProbe"]["exec"]["command"][2],
                "test -f /codewire/run/daemon/ready",
                "{docker_mode}"
            );
            assert_eq!(probes(&dind[1]), [None, None, None], "{docker_mode}");
            assert!(
                !Value::Array(dind.clone()).to_string().contains("docker version"),
                "{docker_mode}: a probe runs Docker"
            );
        }
    }


    // ------------------------------- template ingress (codewire#3626)

    /// The one ingress rule a non-confidential template carries from a
    /// member's birth: orchestration's identity (its namespace AND its Pod
    /// labels, in one peer) on TCP 7777 and 2222, and nothing else.
    fn orchestration_only_template_ingress(server_namespace: &str) -> Value {
        json!([{
            "from": [{
                "namespaceSelector": {
                    "matchLabels": { "kubernetes.io/metadata.name": server_namespace },
                },
                "podSelector": {
                    "matchLabels": {
                        "app.kubernetes.io/name": "codewire",
                        "app.kubernetes.io/component": "orchestration",
                    },
                },
            }],
            "ports": [
                { "protocol": "TCP", "port": 7777 },
                { "protocol": "TCP", "port": 2222 },
            ],
        }])
    }

    #[test]
    fn non_confidential_templates_admit_only_orchestration_on_daemon_and_ssh() {
        let runc = TemplateOpts {
            runtime_profile: RUNTIME_PROFILE_RUNC.into(),
            ..identity_free_opts()
        };
        for (label, opts) in [
            ("commodity", commodity_opts()),
            ("identity-free commodity", identity_free_opts()),
            ("identity-free runc", runc),
        ] {
            let policy = &render_sandbox_template("dev-sandboxes", &opts)["spec"]["networkPolicy"];
            assert_eq!(
                policy["ingress"],
                orchestration_only_template_ingress("dev"),
                "{label}"
            );
            // The peer is the per-environment policy's orchestration peer.
            let daemon = render_workspace_daemon_network_policy("dev-sandboxes", &opts);
            assert_eq!(
                policy["ingress"][0]["from"], daemon["spec"]["ingress"][0]["from"],
                "{label}"
            );
            let text = policy["ingress"].to_string();
            for absent in ["endPort", "UDP", "ipBlock", "31000"] {
                assert!(!text.contains(absent), "{label}: template ingress has {absent}");
            }
        }
        // No server namespace names no peer, so no rule.
        let unplaced = TemplateOpts {
            server_namespace: String::new(),
            ..commodity_opts()
        };
        assert!(
            render_sandbox_template("dev-sandboxes", &unplaced)["spec"]["networkPolicy"]
                .get("ingress")
                .is_none()
        );
    }

    /// Confidential is never pooled and keeps no template ingress: its
    /// access stays in its per-environment policy alone.
    #[test]
    fn confidential_template_keeps_no_ingress() {
        let rendered = render_sandbox_template("dev-sandboxes", &confidential_golden_opts());
        assert!(rendered["spec"]["networkPolicy"].get("ingress").is_none());
    }

    /// The pool rule is in addition to the per-environment policies, which
    /// keep previews and the tailnet's world UDP (codewire#3626 condition 6).
    #[test]
    fn per_environment_policies_keep_previews_and_world_udp() {
        let opts = identity_free_opts();
        let daemon = render_workspace_daemon_network_policy("dev-sandboxes", &opts);
        let ingress = daemon["spec"]["ingress"].as_array().unwrap();
        assert_eq!(ingress.len(), 2);
        assert_eq!(
            ingress[0]["ports"],
            json!([
                { "protocol": "TCP", "port": 7777 },
                { "protocol": "TCP", "port": 2222 },
                { "protocol": "TCP", "port": APP_PREVIEW_MIN_PORT, "endPort": APP_PREVIEW_MAX_PORT },
            ])
        );
        assert_eq!(
            ingress[1]["ports"],
            json!([{
                "protocol": "UDP",
                "port": i64::from(codewire_daemon_proto::WORKSPACE_TAILNET_UDP_PORT),
            }])
        );
        let bridge = render_warm_member_bridge(
            "dev-sandboxes",
            &TemplateOpts {
                environment_id: "3d6bb495-efac-419f-bf3a-91696e7c7ca4".into(),
                ..opts.clone()
            },
            "9a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d",
        )
        .unwrap();
        assert_eq!(bridge["spec"]["ingress"], daemon["spec"]["ingress"]);
    }
}
