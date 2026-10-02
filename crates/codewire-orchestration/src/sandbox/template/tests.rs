#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    use base64::Engine;
    use flate2::read::GzDecoder;
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    const CONTENT_ADDRESSED_MANIFEST_URI: &str = "kbs:///default/codewire-storage-manifests/sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn environment_template_has_top_level_cleanup_identity() {
        let opts = TemplateOpts {
            environment_id: "env-test".into(),
            ..commodity_opts()
        };
        let rendered = render_sandbox_template("dev-sandboxes", &opts);
        assert_eq!(rendered["metadata"]["labels"][LABEL_ENV_ID], "env-test");
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

    fn load_golden(name: &str) -> Value {
        let path = format!(
            "{}/tests/fixtures/sandbox/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(
            &std::fs::read_to_string(&path).expect("Rust-owned golden file missing"),
        )
        .unwrap()
    }

    #[test]
    fn gateway_generation_rolls_only_its_template_and_never_changes_selectors_or_workspace_template()
     {
        let mut opts = commodity_opts();
        let first_gateway = render_gateway_deployment("dev-sandboxes", &opts);
        let first_workspace = render_sandbox_template("dev-sandboxes", &opts);
        for labels in [
            &first_gateway["metadata"]["labels"],
            &first_gateway["spec"]["template"]["metadata"]["labels"],
        ] {
            assert_eq!(labels["codewire.sh/environment-id"], opts.environment_id);
            assert_eq!(labels["codewire.sh/org-id"], opts.organization_id);
            assert_eq!(labels["codewire.sh/type"], "gateway");
            assert_eq!(labels[super::super::LABEL_OPERATION_GENERATION], "7");
        }
        opts.operation_generation = 8;
        let next_gateway = render_gateway_deployment("dev-sandboxes", &opts);
        assert_eq!(
            first_gateway["spec"]["selector"],
            next_gateway["spec"]["selector"]
        );
        assert!(
            next_gateway["spec"]["selector"]["matchLabels"]
                .get(super::super::LABEL_OPERATION_GENERATION)
                .is_none()
        );
        assert_eq!(
            next_gateway["spec"]["template"]["metadata"]["labels"]
                [super::super::LABEL_OPERATION_GENERATION],
            "8"
        );
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

    fn commodity_opts() -> TemplateOpts {
        TemplateOpts {
            name: "tmpl-golden-commodity".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            support_image: "git.example.invalid/codewire/gateway:golden".into(),
            runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
            environment_id: "env-golden-commodity".into(),
            organization_id: "org-golden-commodity".into(),
            operation_generation: 7,
            gateway_token: "gw-token-golden-commodity".into(),
            daemon_auth_token: "daemon-token-golden-commodity".into(),
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

    #[test]
    fn credential_bootstrap_has_exact_tls_intent_and_public_codex_config_only() {
        let opts = credential_opts();
        let certificate = render_credential_gateway_certificate("dev-sandboxes", &opts).unwrap();
        assert_eq!(
            certificate["spec"]["secretName"],
            credential_gateway_certificate_name(&opts.environment_id)
        );
        assert_eq!(
            certificate["spec"]["issuerRef"],
            json!({"name":CREDENTIAL_GATEWAY_ISSUER_NAME,"kind":"Issuer","group":"cert-manager.io"})
        );
        let dns = format!(
            "{}.dev-sandboxes.svc.cluster.local",
            gateway_service_name(&opts.environment_id)
        );
        assert_eq!(certificate["spec"]["dnsNames"], json!([dns]));
        assert_eq!(certificate["spec"]["isCA"], false);
        assert_eq!(
            certificate["spec"]["usages"],
            json!(["digital signature", "server auth"])
        );
        assert_eq!(
            certificate["spec"]["privateKey"]["rotationPolicy"],
            "Always"
        );
        assert_eq!(
            certificate["spec"]["secretTemplate"]["labels"],
            certificate["metadata"]["labels"]
        );
        let config = render_credential_codex_config("dev-sandboxes", &opts).unwrap();
        assert_eq!(config["data"].as_object().unwrap().len(), 1);
        let text = config["data"]["config.toml"].as_str().unwrap();
        assert_eq!(
            text,
            opts.managed_credential_clients
                .for_placement(codewire_access::ManagedCredentialClientPlacement::Platform)
                .codex
                .unwrap()
                .config_toml()
        );
        for forbidden in [
            "auth.json",
            "OPENAI_API_KEY",
            "api.openai.com",
            "chatgpt.com",
            "synthetic-trust-3",
            &opts.gateway_token,
            &opts.daemon_auth_token,
        ] {
            assert!(!text.contains(forbidden));
        }
    }

    #[test]
    fn hosted_provider_loopback_is_not_exposed_by_workspace_templates_or_services() {
        for profile in [RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_CONFIDENTIAL] {
            let mut opts = credential_opts();
            opts.runtime_profile = profile.into();
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
            for service in [
                render_workspace_daemon_service("dev-sandboxes", &opts),
                render_gateway_service("dev-sandboxes", &opts),
            ] {
                for port in service["spec"]["ports"].as_array().unwrap() {
                    for key in ["port", "targetPort", "nodePort"] {
                        assert_ne!(port[key], 38081);
                    }
                }
            }
        }
    }

    #[test]
    fn hosted_projection_bootstrap_binds_both_peers_and_private_process_directory() {
        for profile in [RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_CONFIDENTIAL] {
            let mut opts = credential_opts();
            opts.runtime_profile = profile.into();
            opts.projection_selection_sha256 = Some([0xab; 32]);
            let template = render_sandbox_template("dev-sandboxes", &opts);
            let workspace = &template["spec"]["podTemplate"]["spec"];
            let gateway = render_gateway_deployment("dev-sandboxes", &opts);
            for env in [
                &workspace["containers"][0]["env"],
                &gateway["spec"]["template"]["spec"]["containers"][0]["env"],
            ] {
                for (name, value) in [
                    (
                        codewire_daemon::config::HOSTED_PROJECTION_SHA256_ENV,
                        "ab".repeat(32),
                    ),
                    (
                        codewire_daemon::config::ENVIRONMENT_ID_ENV,
                        opts.environment_id.clone(),
                    ),
                    (
                        codewire_daemon::config::ENVIRONMENT_GENERATION_ENV,
                        "7".into(),
                    ),
                ] {
                    let matching: Vec<_> = env
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|entry| entry["name"] == name)
                        .collect();
                    assert_eq!(matching, vec![&json!({"name":name,"value":value})]);
                }
            }
            assert_eq!(workspace["securityContext"]["runAsUser"], 1000);
            assert_eq!(workspace["securityContext"]["runAsGroup"], 1000);
            assert!(
                workspace["containers"][0]["volumeMounts"]
                    .as_array()
                    .unwrap()
                    .contains(&json!({"name":"codewire-run","mountPath":"/codewire/run"}))
            );
            let init = &workspace["initContainers"][0];
            assert!(init.get("securityContext").is_none());
            let command = init["command"][2].as_str().unwrap();
            if profile == RUNTIME_PROFILE_CONFIDENTIAL {
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
                // directory at startup; the client bootstrap never touches it.
                assert_eq!(init["name"], "codewire-client-bootstrap");
                assert!(!command.contains("/codewire/run"));
                assert!(!init.to_string().contains("codewire-run"));
                assert_eq!(workspace["initContainers"].as_array().unwrap().len(), 1);
            }
        }
    }

    #[test]
    fn hosted_projection_generation_and_selection_change_both_bootstraps() {
        let mut opts = credential_opts();
        opts.projection_selection_sha256 = Some([0xab; 32]);
        let rendered = |opts: &TemplateOpts| {
            (
                render_sandbox_template("dev-sandboxes", opts),
                render_gateway_deployment("dev-sandboxes", opts),
            )
        };
        let original = rendered(&opts);
        opts.operation_generation += 1;
        let generation = rendered(&opts);
        assert_ne!(original.0, generation.0);
        assert_ne!(original.1, generation.1);
        opts.projection_selection_sha256 = Some([0xcd; 32]);
        let selection = rendered(&opts);
        assert_ne!(generation.0, selection.0);
        assert_ne!(generation.1, selection.1);
        opts.projection_selection_sha256 = None;
        opts.managed_credential_clients = Default::default();
        let cleared = rendered(&opts);
        for value in [cleared.0, cleared.1] {
            assert!(
                !value
                    .to_string()
                    .contains(codewire_daemon::config::HOSTED_PROJECTION_SHA256_ENV)
            );
        }
    }

    #[test]
    fn hosted_projection_cannot_render_without_runtime_trust() {
        let opts = TemplateOpts {
            projection_selection_sha256: Some([0xab; 32]),
            ..commodity_opts()
        };
        assert!(
            std::panic::catch_unwind(|| render_sandbox_template("dev-sandboxes", &opts)).is_err()
        );
        assert!(
            std::panic::catch_unwind(|| render_gateway_deployment("dev-sandboxes", &opts)).is_err()
        );
    }

    #[test]
    fn credential_mounts_and_identities_are_separate_for_workspace_gateway_and_init() {
        use codewire_access::{CODEX_PLATFORM_HOME, CODEX_PLATFORM_TOKEN_FILE};
        use codewire_gateway_proto::{
            CREDENTIAL_GATEWAY_TOKEN_AUDIENCE, CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE,
        };
        let opts = credential_opts();
        let template = render_sandbox_template("dev-sandboxes", &opts);
        let workspace = &template["spec"]["podTemplate"]["spec"];
        let deployment = render_gateway_deployment("dev-sandboxes", &opts);
        let gateway = &deployment["spec"]["template"]["spec"];
        for (spec, volume_name, audience) in [
            (
                workspace,
                "credential-workspace-identity",
                CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE,
            ),
            (
                gateway,
                "credential-gateway-identity",
                CREDENTIAL_GATEWAY_TOKEN_AUDIENCE,
            ),
        ] {
            assert_eq!(spec["automountServiceAccountToken"], false);
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
                for container in spec[collection].as_array().unwrap() {
                    for mount in container["volumeMounts"].as_array().unwrap() {
                        assert!(
                            !projected.contains(&&mount["name"]) || mount.get("subPath").is_none(),
                            "projected rotations need directory mounts"
                        );
                    }
                }
            }
        }
        // Commodity mounts the daemon from the support image, so only the
        // stock-client bootstrap remains; confidential keeps the daemon copy.
        let init = &workspace["initContainers"][0];
        assert_eq!(workspace["initContainers"].as_array().unwrap().len(), 1);
        assert_eq!(init["name"], "codewire-client-bootstrap");
        assert_eq!(init["image"], opts.support_image);
        let init_mounts = init["volumeMounts"].as_array().unwrap();
        assert_eq!(init_mounts.len(), 2);
        for name in ["credential-codex-config", "credential-codex-home"] {
            assert!(init_mounts.iter().any(|mount| mount["name"] == name));
        }
        assert_eq!(
            init["command"],
            json!(["sh", "-c", format!(
                "umask 077 && mkdir -p -m 0700 {CODEX_PLATFORM_HOME} && cp /codewire/codex-bootstrap/config.toml {CODEX_PLATFORM_HOME}/config.toml"
            )])
        );
        let mut confidential = opts.clone();
        confidential.runtime_profile = RUNTIME_PROFILE_CONFIDENTIAL.into();
        let confidential = render_sandbox_template("dev-sandboxes", &confidential);
        let confidential_init = &confidential["spec"]["podTemplate"]["spec"]["initContainers"][0];
        assert_eq!(confidential_init["name"], "codewire-daemon-init");
        let confidential_mounts = confidential_init["volumeMounts"].as_array().unwrap();
        assert_eq!(confidential_mounts.len(), 4);
        for name in [
            "codewire-bin",
            "codewire-run",
            "credential-codex-config",
            "credential-codex-home",
        ] {
            assert!(confidential_mounts.iter().any(|mount| mount["name"] == name));
        }
        assert!(
            confidential_init["command"][2]
                .as_str()
                .unwrap()
                .contains(&format!("mkdir -p -m 0700 {CODEX_PLATFORM_HOME}"))
        );
        let home = workspace["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|volume| volume["name"] == "credential-codex-home")
            .unwrap();
        assert_eq!(
            home["emptyDir"],
            json!({"medium":"Memory","sizeLimit":"256Mi"})
        );
        let ws = &workspace["containers"][0];
        assert!(
            ws["env"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry == &json!({"name":"CODEX_HOME","value":CODEX_PLATFORM_HOME}))
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
        assert!(!workspace.to_string().contains("credential-gateway-tls"));
        assert!(
            !workspace
                .to_string()
                .contains(CREDENTIAL_GATEWAY_TOKEN_AUDIENCE)
        );
        assert!(
            !gateway
                .to_string()
                .contains(CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE)
        );
        assert!(!gateway.to_string().contains("credential-codex-home"));
        for container in workspace["containers"].as_array().unwrap().iter().skip(1) {
            assert!(
                !container.to_string().contains("credential-"),
                "sibling Docker has no credential mounts"
            );
        }
        let service = render_gateway_service("dev-sandboxes", &opts);
        assert!(
            service["spec"]["ports"]
                .as_array()
                .unwrap()
                .iter()
                .any(|port| port["port"] == 443
                    && port["targetPort"] == CREDENTIAL_GATEWAY_HTTPS_PORT)
        );
    }

    #[test]
    fn credential_network_allows_only_same_environment_gateway_and_exact_broker_peer() {
        let opts = credential_opts();
        let gateway = render_gateway_network_policy("dev-sandboxes", &opts);
        let workspace = render_workspace_daemon_network_policy("dev-sandboxes", &opts);
        let find = |rules: &Value, port: i64| {
            rules
                .as_array()
                .unwrap()
                .iter()
                .filter(|rule| {
                    rule["ports"]
                        .as_array()
                        .is_some_and(|ports| ports.iter().any(|item| item["port"] == port))
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(
            find(&gateway["spec"]["ingress"], 8443),
            vec![
                json!({"from":[{"podSelector":{"matchLabels":naming::workspace_selector(&opts)}}],"ports":[{"protocol":"TCP","port":8443}]})
            ]
        );
        assert_eq!(
            find(&workspace["spec"]["egress"], 8443),
            vec![
                json!({"to":[{"podSelector":{"matchLabels":naming::gateway_selector(&opts)}}],"ports":[{"protocol":"TCP","port":8443}]})
            ]
        );
        assert_eq!(
            find(&gateway["spec"]["egress"], 9443),
            vec![
                json!({"to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"synthetic-trust-0"}},"podSelector":{"matchLabels":{"app.kubernetes.io/name":"codewire","app.kubernetes.io/component":"credential-service"}}}],"ports":[{"protocol":"TCP","port":9443}]})
            ]
        );
        assert!(find(&workspace["spec"]["egress"], 9443).is_empty());
    }

    #[test]
    fn unselected_runtime_generation_rolls_gateway_but_not_public_bootstrap_or_workspace() {
        let mut opts = credential_opts();
        opts.managed_credential_clients = Default::default();
        opts.projection_selection_sha256 = None;
        let before = (
            render_sandbox_template("dev-sandboxes", &opts),
            render_credential_codex_config("dev-sandboxes", &opts),
            render_credential_gateway_certificate("dev-sandboxes", &opts),
        );
        let first_gateway = render_gateway_deployment("dev-sandboxes", &opts);
        opts.operation_generation += 1;
        let after = (
            render_sandbox_template("dev-sandboxes", &opts),
            render_credential_codex_config("dev-sandboxes", &opts),
            render_credential_gateway_certificate("dev-sandboxes", &opts),
        );
        assert_eq!(before, after);
        let gateway = render_gateway_deployment("dev-sandboxes", &opts);
        assert_eq!(
            first_gateway["spec"]["selector"],
            gateway["spec"]["selector"]
        );
        assert!(
            gateway["spec"]["template"]["spec"]["containers"][0]["env"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry
                    == &json!({"name":"CODEWIRE_ENVIRONMENT_OPERATION_GENERATION","value":"8"}))
        );
    }

    #[test]
    fn credential_free_templates_do_not_mount_provider_bootstrap_or_activate_listener() {
        let opts = commodity_opts();
        assert!(render_credential_gateway_certificate("dev-sandboxes", &opts).is_none());
        assert!(render_credential_codex_config("dev-sandboxes", &opts).is_none());
        for value in [
            render_sandbox_template("dev-sandboxes", &opts),
            render_gateway_deployment("dev-sandboxes", &opts),
        ] {
            let encoded = value.to_string();
            for absent in [
                "credential-workspace-identity",
                "credential-gateway-identity",
                "CODEX_HOME",
                "CODEWIRE_CREDENTIAL_HTTPS_LISTEN_ADDR",
            ] {
                assert!(!encoded.contains(absent));
            }
        }
    }

    #[test]
    fn only_exact_selected_clients_render_environment_codex_config_and_mounts() {
        use codewire_access::{
            ManagedCredentialClient, ManagedCredentialClientPlacement, ManagedCredentialClients,
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
            let expected = opts
                .managed_credential_clients
                .for_placement(ManagedCredentialClientPlacement::Platform);
            for (name, value) in &expected.environment {
                assert!(environment.contains(&json!({"name":name,"value":value})));
            }
            let all_keys = ManagedCredentialClients::from_profile_slots([
                "codex",
                "openai",
                "anthropic",
                "ssh",
            ])
            .unwrap()
            .for_placement(ManagedCredentialClientPlacement::Platform)
            .environment;
            for name in all_keys
                .keys()
                .filter(|name| !expected.environment.contains_key(*name))
            {
                assert!(!environment.iter().any(|entry| entry["name"] == *name));
            }
            assert!(environment.contains(
                &json!({"name":MANAGED_CREDENTIAL_CLIENTS_ENV,"value":opts.managed_credential_clients.encode()})
            ));
            let codex = opts
                .managed_credential_clients
                .contains(ManagedCredentialClient::Codex);
            assert_eq!(
                render_credential_codex_config("dev-sandboxes", &opts).is_some(),
                codex
            );
            for field in [
                &spec["volumes"],
                &spec["containers"][0]["volumeMounts"],
                &spec["initContainers"][0]["volumeMounts"],
            ] {
                assert_eq!(field.to_string().contains("credential-codex-home"), codex);
            }
            assert_eq!(
                spec["initContainers"][0]["command"]
                    .to_string()
                    .contains("/codewire/codex-bootstrap/config.toml"),
                codex
            );
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
        let mut opts = credential_opts();
        opts.runtime_profile = RUNTIME_PROFILE_CONFIDENTIAL.into();
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
        for path in [
            "/run/codewire-credentials/workspace",
            "/run/codewire-credentials/gateway-roots",
            "/run/codewire-codex",
        ] {
            workspace["OCI"]["Mounts"].as_array_mut().unwrap().push(json!({"destination":path,"source":"/synthetic/public-bootstrap","type_":"bind","options":["rbind","ro"]}));
        }
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
        init["OCI"]["Mounts"] = json!([{"destination":"/codewire/codex-bootstrap","source":"/synthetic/public-bootstrap","type_":"bind","options":["rbind","ro"]}]);
        assert!(kata_policy_allows(policy, &init));
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
                gateway_token: "gateway-secret-value".into(),
                daemon_auth_token: "daemon-secret-value".into(),
                udp_relay_allocator_token: "relay-secret-value".into(),
                kata_coco_kbs_ca_pem: "embedded-public-ca".into(),
                ..Default::default()
            }
        );

        assert!(rendered.contains("gateway_token: \"<redacted>\""));
        assert!(rendered.contains("daemon_auth_token: \"<redacted>\""));
        assert!(rendered.contains("udp_relay_allocator_token: \"<redacted>\""));
        assert!(rendered.contains("kata_coco_kbs_ca_pem: \"<configured>\""));
        assert!(!rendered.contains("gateway-secret-value"));
        assert!(!rendered.contains("daemon-secret-value"));
        assert!(!rendered.contains("relay-secret-value"));
        assert!(!rendered.contains("embedded-public-ca"));
    }

    #[test]
    fn template_keeps_coordinate_and_daemon_capabilities_in_separate_env_vars() {
        let opts = commodity_opts();
        let gateway = render_gateway_deployment("codewire-runtime", &opts);
        let gateway_env = gateway["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array()
            .unwrap();
        let workspace = render_sandbox_template("codewire-runtime", &opts);
        let workspace_env = workspace["spec"]["podTemplate"]["spec"]["containers"][0]["env"]
            .as_array()
            .unwrap();
        let value = |env: &[Value], name: &str| {
            env.iter().find_map(|entry| {
                (entry["name"].as_str() == Some(name))
                    .then(|| entry["value"].as_str().unwrap().to_owned())
            })
        };

        assert_eq!(
            value(gateway_env, "CODEWIRE_GATEWAY_TOKEN"),
            Some("gw-token-golden-commodity".into())
        );
        assert_eq!(
            value(gateway_env, DAEMON_AUTH_TOKEN_ENV),
            Some("daemon-token-golden-commodity".into())
        );
        assert_eq!(
            value(workspace_env, DAEMON_AUTH_TOKEN_ENV),
            Some("daemon-token-golden-commodity".into())
        );
        assert_eq!(value(workspace_env, "CODEWIRE_GATEWAY_TOKEN"), None);
    }

    #[test]
    fn projected_binding_identity_is_bounded_and_mounted_only_in_the_gateway() {
        use codewire_gateway_proto::{
            GATEWAY_BINDING_TOKEN_AUDIENCE, GATEWAY_BINDING_TOKEN_EXPIRATION_SECONDS,
            GATEWAY_BINDING_TOKEN_MOUNT_PATH, GATEWAY_BINDING_TOKEN_PATH,
        };

        for runtime_profile in [RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_CONFIDENTIAL] {
            let mut opts = commodity_opts();
            opts.environment_id = "550e8400-e29b-41d4-a716-446655440000".into();
            opts.runtime_profile = runtime_profile.into();
            let deployment = render_gateway_deployment("codewire-runtime", &opts);
            let spec = &deployment["spec"]["template"]["spec"];

            assert_eq!(spec["automountServiceAccountToken"].as_bool(), Some(false));
            assert_eq!(
                spec["serviceAccountName"].as_str(),
                Some(SANDBOX_SERVICE_ACCOUNT)
            );
            let volumes = spec["volumes"].as_array().unwrap();
            let identity_volume = volumes
                .iter()
                .find(|volume| volume["name"].as_str() == Some(GATEWAY_BINDING_TOKEN_VOLUME))
                .expect("gateway binding identity volume");
            assert_eq!(
                identity_volume["projected"]["defaultMode"].as_i64(),
                Some(0o440)
            );
            let sources = identity_volume["projected"]["sources"].as_array().unwrap();
            assert_eq!(sources.len(), 1);
            let projected = &sources[0]["serviceAccountToken"];
            assert_eq!(
                projected["audience"].as_str(),
                Some(GATEWAY_BINDING_TOKEN_AUDIENCE)
            );
            assert_eq!(
                projected["expirationSeconds"].as_i64(),
                Some(GATEWAY_BINDING_TOKEN_EXPIRATION_SECONDS)
            );
            assert_eq!(projected["path"].as_str(), Some("token"));

            let gateway = &spec["containers"][0];
            assert!(gateway["env"].as_array().unwrap().iter().all(|entry| {
                !matches!(
                    entry["name"].as_str(),
                    Some("POD_NAMESPACE") | Some("POD_NAME")
                )
            }));
            assert!(
                gateway["volumeMounts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|mount| {
                        mount["name"].as_str() == Some(GATEWAY_BINDING_TOKEN_VOLUME)
                            && mount["mountPath"].as_str() == Some(GATEWAY_BINDING_TOKEN_MOUNT_PATH)
                            && mount["readOnly"].as_bool() == Some(true)
                    })
            );
            assert!(
                spec["initContainers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|container| {
                        container["volumeMounts"].as_array().is_none_or(|mounts| {
                            mounts.iter().all(|mount| {
                                mount["name"].as_str() != Some(GATEWAY_BINDING_TOKEN_VOLUME)
                            })
                        })
                    })
            );
            assert_eq!(
                GATEWAY_BINDING_TOKEN_PATH,
                format!("{GATEWAY_BINDING_TOKEN_MOUNT_PATH}/token")
            );
        }

        let workspace = render_sandbox_template("codewire-runtime", &commodity_opts());
        let workspace_spec = &workspace["spec"]["podTemplate"]["spec"];
        assert!(
            workspace_spec["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|volume| volume["name"].as_str() != Some(GATEWAY_BINDING_TOKEN_VOLUME))
        );
        for collection in ["containers", "initContainers"] {
            assert!(
                workspace_spec[collection]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .all(|container| {
                        container["volumeMounts"].as_array().is_none_or(|mounts| {
                            mounts.iter().all(|mount| {
                                mount["name"].as_str() != Some(GATEWAY_BINDING_TOKEN_VOLUME)
                                    && mount["mountPath"].as_str()
                                        != Some(GATEWAY_BINDING_TOKEN_MOUNT_PATH)
                            })
                        })
                    })
            );
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
            for forbidden in ["super::gateway", "super::network", "super::workspace"] {
                assert!(
                    !source.contains(forbidden),
                    "{name} leaf imports forbidden renderer {forbidden}"
                );
            }
        }

        let gateway = include_str!("gateway.rs");
        assert!(!gateway.contains("super::network"));
        assert!(!gateway.contains("super::workspace"));

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
        let support = "registry.example.invalid/codewire/gateway@sha256:48549d19114407c712d043af3ba2136d97052a2c30c82935190f75a3a61f13ab";
        for profile in [
            RUNTIME_PROFILE_COMMODITY,
            RUNTIME_PROFILE_CONFIDENTIAL,
            RUNTIME_PROFILE_RUNC,
            RUNTIME_PROFILE_NONE,
        ] {
            let opts = TemplateOpts {
                runtime_profile: profile.into(),
                support_image: support.into(),
                ..commodity_opts()
            };
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
                assert!(spec.get("initContainers").is_none(), "{profile}");
            } else {
                assert_eq!(volume, &json!({"name":"codewire-bin","emptyDir":{}}));
                assert_eq!(
                    mount,
                    &json!({"name":"codewire-bin","mountPath":"/codewire/bin"})
                );
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
    fn commodity_template_uses_neutral_annotations_and_guest_dockerd() {
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-commodity".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
                gateway_token: "commodity-template-token".into(),
                daemon_auth_token: "commodity-template-daemon-token".into(),
                disk_gib: 40,
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
        assert!(
            rendered["spec"]["networkPolicy"].get("ingress").is_none(),
            "workspace daemon ingress is owned by the per-environment companion NetworkPolicy"
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
        // commodity Pod starts without an init container.
        assert!(pod_template["spec"].get("initContainers").is_none());
        assert!(
            pod_template["spec"]["volumes"]
                .as_array()
                .unwrap()
                .contains(&json!({
                    "name": "codewire-bin",
                    "image": { "reference": DEFAULT_GATEWAY_IMAGE, "pullPolicy": "IfNotPresent" },
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
        assert!(bootstrap.contains("mkfs.ext4"));
        assert!(bootstrap.contains("mount -o loop"));
        assert!(bootstrap.contains("chown 1000:1000 \"$codewire_dir\""));
        assert!(bootstrap.contains("chmod 0775 \"$codewire_dir\""));
        assert!(bootstrap.contains("--data-root \"$data_root\""));
        assert!(bootstrap.contains("--storage-driver vfs"));
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
        assert_eq!(
            workspace["readinessProbe"],
            json!({
                "exec": {
                    "command": [
                        "sh",
                        "-ec",
                        "docker version --format '{{.Server.Version}}' >/dev/null",
                    ],
                },
                "periodSeconds": 2,
                "timeoutSeconds": 2,
                "failureThreshold": 3,
                "successThreshold": 1,
            }),
            "workspace readiness must prove the cross-container Docker socket"
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
            "a start notices Docker within a second and is never stopped before \
             the commodity ready wait gives up"
        );
        assert!(
            volumes
                .iter()
                .all(|volume| volume.get("hostPath").is_none()),
            "commodity workspace pod must not mount host Docker or containerd sockets"
        );

        let gateway = render_gateway_deployment(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-commodity".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                support_image: "git.example.invalid/codewire/gateway:test".into(),
                runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
                environment_id: "env-commodity".into(),
                gateway_token: "gw-token".into(),
                daemon_auth_token: "commodity-daemon-token".into(),
                server_namespace: "dev".into(),
                ..Default::default()
            },
        );
        let spec = &gateway["spec"]["template"]["spec"];
        assert_eq!(
            gateway["spec"]["progressDeadlineSeconds"],
            json!(WORKSPACE_READY_TIMEOUT.as_secs()),
            "the commodity gateway rollout deadline matches the tier ready timeout"
        );
        assert!(
            gateway["spec"]["template"]["metadata"]["labels"]["codewire.sh/isolation-tier"]
                .is_null(),
            "commodity gateways must not gain the confidential Trustee ingress label"
        );
        assert_eq!(
            spec["runtimeClassName"].as_str(),
            Some(RUNTIME_CLASS_COMMODITY)
        );
        let gateway_container = &spec["containers"][0];
        assert_eq!(gateway_container["name"].as_str(), Some("codewire-gateway"));
        assert!(gateway_container.get("resources").is_some());
        assert_eq!(
            startup_probe_budget_seconds(gateway_container),
            WORKSPACE_READY_TIMEOUT.as_secs(),
            "the kubelet must not restart a commodity gateway during a slow start"
        );
        assert_eq!(
            gateway_container["startupProbe"]["periodSeconds"],
            json!(1),
            "create notices the gateway reaching its daemon within one second"
        );
        assert_eq!(
            gateway_container["readinessProbe"],
            json!({
                "httpGet": { "path": "/readyz", "port": DEFAULT_GATEWAY_READYZ_PORT },
                "periodSeconds": 2,
                "timeoutSeconds": 2,
                "failureThreshold": 3,
            }),
            "steady-state gateway readiness keeps its period and failure budget"
        );
        assert!(
            spec["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|volume| volume.get("hostPath").is_none()),
            "split gateway pod must not mount host Docker or containerd sockets"
        );
        assert!(
            gateway_container["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|mount| {
                    mount["name"].as_str() == Some("gateway-state")
                        && mount["mountPath"].as_str() == Some("/codewire/gateway")
                })
        );
        assert!(
            gateway_container["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .all(|mount| mount["name"].as_str() != Some("docker-sock")
                    && mount["mountPath"].as_str() != Some("/var/run/docker")),
            "split gateway must not mount the workspace pod-local Docker socket"
        );
        assert!(
            gateway_container["env"]
                .as_array()
                .unwrap()
                .iter()
                .any(|env| env["name"].as_str() == Some(DAEMON_AUTH_TOKEN_ENV)
                    && env["value"].as_str() == Some("commodity-daemon-token"))
        );
        assert!(
            gateway_container["env"]
                .as_array()
                .unwrap()
                .iter()
                .any(|env| env["name"].as_str() == Some("CODEWIRE_GATEWAY_TOKEN")
                    && env["value"].as_str() == Some("gw-token"))
        );
        assert_no_gateway_daemon_deadline(gateway_container);
    }

    /// The kubelet restarts a container whose startup probe fails this long.
    fn startup_probe_budget_seconds(container: &Value) -> u64 {
        let probe = &container["startupProbe"];
        probe["failureThreshold"].as_u64().unwrap() * probe["periodSeconds"].as_u64().unwrap()
    }

    /// The gateway waits for its daemon without exiting; no rendered setting
    /// may reintroduce the retired connect deadline.
    fn assert_no_gateway_daemon_deadline(container: &Value) {
        assert!(
            container["env"]
                .as_array()
                .unwrap()
                .iter()
                .all(|env| env["name"].as_str() != Some("CODEWIRE_DAEMON_CONNECT_TIMEOUT_SECONDS")),
            "the gateway must not be given a daemon-connect deadline"
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
                gateway_token: "confidential-template-token".into(),
                daemon_auth_token: "confidential-daemon-token".into(),
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
        assert_eq!(
            workspace["readinessProbe"]["exec"]["command"][2].as_str(),
            Some("docker version --format '{{.Server.Version}}' >/dev/null")
        );
        assert_eq!(
            workspace["startupProbe"]["exec"],
            workspace["readinessProbe"]["exec"]
        );
        assert_eq!(
            workspace["startupProbe"]["failureThreshold"].as_u64().unwrap()
                * workspace["startupProbe"]["periodSeconds"].as_u64().unwrap(),
            CONFIDENTIAL_WORKSPACE_READY_TIMEOUT.as_secs(),
            "confidential Docker startup keeps the tier's cold-start budget"
        );
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
                support_image: "git.example.invalid/codewire/gateway:test".into(),
                environment_id: "env-managed-daemon".into(),
                gateway_token: "managed-coordinate-token".into(),
                daemon_auth_token: "managed-daemon-token".into(),
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
            managed_workspace["env"]
                .as_array()
                .unwrap()
                .iter()
                .any(|env| env["name"].as_str() == Some(DAEMON_AUTH_TOKEN_ENV)
                    && env["value"].as_str() == Some("managed-daemon-token"))
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
                support_image: "git.example.invalid/codewire/gateway:test".into(),
                environment_id: "env-custom-daemon".into(),
                gateway_token: "custom-coordinate-token".into(),
                daemon_auth_token: "custom-daemon-token".into(),
                ..Default::default()
            },
        );
        let custom_command = custom["spec"]["podTemplate"]["spec"]["containers"][0]["command"][2]
            .as_str()
            .unwrap();
        assert!(custom_command.contains(
            "(unset CODEWIRE_DAEMON_AUTH_TOKEN; exec '/bin/custom-entrypoint' '--serve') & workload_pid=$!"
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
    #[should_panic(expected = "hosted workspace requires a canonical daemon auth token")]
    fn hosted_workspace_rejects_a_missing_daemon_token() {
        let _ = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "missing-daemon-token".into(),
                image: "example.invalid/workspace:test".into(),
                ..Default::default()
            },
        );
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
                gateway_token: "custom-quoted-coordinate-token".into(),
                daemon_auth_token: "custom-quoted-daemon-token".into(),
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
            let child = tokio::process::Command::new("/bin/sh")
                .args(["-c", &command])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .process_group(0)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
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
            true,
        );
        let mut supervisor = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .env(DAEMON_AUTH_TOKEN_ENV, "synthetic-daemon-supervisor-token")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        wait_for_file_value(&count, "1").await;
        wait_for_file_value(&daemon_env, "synthetic-daemon-supervisor-token").await;
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
                    image: "ghcr.io/codewiresh/workspace@sha256:18af6b9ff1ac123754aff20b3229ecf882b5553117d9c5fbe43ab2f36f282cff".into(),
                    runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
            gateway_token: "test-coordinate-token".into(),
            daemon_auth_token: "test-daemon-token".into(),
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
                image: "ghcr.io/codewiresh/workspace@sha256:18af6b9ff1ac123754aff20b3229ecf882b5553117d9c5fbe43ab2f36f282cff".into(),
                dind_image: image.into(),
                runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
                gateway_token: "test-coordinate-token".into(),
                daemon_auth_token: "test-daemon-token".into(),
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
    fn gateway_host_key_secret_and_mount_are_environment_scoped() {
        let opts = TemplateOpts {
            name: "tmpl-gateway-host-key".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            support_image: "git.example.invalid/codewire/gateway:test".into(),
            runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
            environment_id: "env-gateway-host-key".into(),
            gateway_token: "gw-token".into(),
            daemon_auth_token: "gateway-host-key-daemon-token".into(),
            server_namespace: "dev".into(),
            ..Default::default()
        };
        let secret = render_gateway_host_key_secret(
            "codewire-runtime",
            &opts,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----\n",
        );
        assert_eq!(
            secret["metadata"]["name"].as_str(),
            Some("cw-gateway-host-key-env-gateway-host-key")
        );
        assert_eq!(
            secret["metadata"]["labels"]["codewire.sh/type"].as_str(),
            Some("gateway-host-key")
        );
        assert_eq!(
            secret["metadata"]["labels"]["codewire.sh/environment-id"].as_str(),
            Some("env-gateway-host-key")
        );
        assert_eq!(
            secret["stringData"][GATEWAY_HOST_KEY_SECRET_KEY].as_str(),
            Some(
                "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----\n"
            )
        );

        let deployment = render_gateway_deployment("codewire-runtime", &opts);
        let pod_spec = &deployment["spec"]["template"]["spec"];
        let volumes = pod_spec["volumes"].as_array().unwrap();
        assert!(volumes.iter().any(|volume| {
            volume["name"].as_str() == Some("gateway-state") && volume.get("emptyDir").is_some()
        }));
        let host_key_volume = volumes
            .iter()
            .find(|volume| volume["name"].as_str() == Some("gateway-host-key"))
            .expect("gateway-host-key volume");
        assert_eq!(
            host_key_volume["secret"]["secretName"].as_str(),
            Some("cw-gateway-host-key-env-gateway-host-key")
        );
        assert_eq!(
            host_key_volume["secret"]["items"][0]["key"].as_str(),
            Some(GATEWAY_HOST_KEY_SECRET_KEY)
        );
        assert_eq!(
            host_key_volume["secret"]["items"][0]["mode"].as_i64(),
            Some(0o444)
        );

        let init = &pod_spec["initContainers"][0];
        assert_eq!(
            init["name"].as_str(),
            Some("codewire-gateway-host-key-init")
        );
        assert_eq!(
            init["image"].as_str(),
            Some("git.example.invalid/codewire/gateway:test")
        );
        let init_command = init["command"][2].as_str().unwrap();
        assert!(init_command.contains(GATEWAY_HOST_KEY_SECRET_MOUNT_PATH));
        assert!(init_command.contains(GATEWAY_HOST_KEY_PATH));
        assert!(init_command.contains("chmod 0600"));
        assert!(
            init["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|mount| {
                    mount["name"].as_str() == Some("gateway-host-key")
                        && mount["mountPath"].as_str() == Some(GATEWAY_HOST_KEY_SECRET_MOUNT_PATH)
                        && mount["readOnly"].as_bool() == Some(true)
                })
        );

        let gateway_container = &pod_spec["containers"][0];
        assert!(gateway_container["env"].as_array().unwrap().iter().any(
            |env| env["name"].as_str() == Some("CODEWIRE_SSH_HOST_KEY_PATH")
                && env["value"].as_str() == Some(GATEWAY_HOST_KEY_PATH)
        ));
        assert!(
            gateway_container["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .all(|mount| mount["name"].as_str() != Some("workspace")),
            "gateway must not mount workspace state for host-key persistence"
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
                gateway_token: "test-coordinate-token".into(),
                daemon_auth_token: "test-daemon-token".into(),
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
    fn commodity_template_ignores_coco_only_init_data_flag() {
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-commodity".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
                gateway_token: "test-coordinate-token".into(),
                daemon_auth_token: "test-daemon-token".into(),
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
                gateway_token: "test-coordinate-token".into(),
                daemon_auth_token: "test-daemon-token".into(),
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
        let workspace = confidential_create_input(
            "workspace",
            "ghcr.io/codewiresh/workspace:golden",
            &["/home/codewire", "/workspace"],
        );
        assert!(kata_policy_allows(policy, &workspace));
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
                gateway_token: "test-coordinate-token".into(),
                daemon_auth_token: "test-daemon-token".into(),
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

        for case in fixture["cases"].as_array().unwrap() {
            let mut request = match case["base"].as_str().unwrap() {
                "workload" => fixture["workload_request"].clone(),
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
            gateway_token: "test-coordinate-token".into(),
            daemon_auth_token: "test-daemon-token".into(),
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
            gateway_token: "test-coordinate-token".into(),
            daemon_auth_token: "test-daemon-token".into(),
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
            gateway_token: "test-coordinate-token".into(),
            daemon_auth_token: "test-daemon-token".into(),
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
    fn confidential_template_and_gateway_carry_coco_resource_kernel_params() {
        let opts = TemplateOpts {
            name: "tmpl-confidential-auth".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            support_image: "git.example.invalid/codewire/gateway:test".into(),
            runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
            gateway_token: "test-coordinate-token".into(),
            daemon_auth_token: "test-daemon-token".into(),
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

        let gateway = render_gateway_deployment("codewire-runtime", &opts);
        assert_eq!(
            gateway["spec"]["progressDeadlineSeconds"],
            json!(CONFIDENTIAL_WORKSPACE_READY_TIMEOUT.as_secs()),
            "confidential guest initialization keeps the tier's cold-start budget"
        );
        let gateway_container = &gateway["spec"]["template"]["spec"]["containers"][0];
        assert_eq!(
            startup_probe_budget_seconds(gateway_container),
            CONFIDENTIAL_WORKSPACE_READY_TIMEOUT.as_secs(),
            "the startup probe must last as long as the confidential ready wait"
        );
        assert_no_gateway_daemon_deadline(gateway_container);
        assert_eq!(
            gateway["spec"]["template"]["metadata"]["labels"]["codewire.sh/isolation-tier"]
                .as_str(),
            Some("confidential")
        );
        let gateway_annotations = gateway["spec"]["template"]["metadata"]["annotations"]
            .as_object()
            .unwrap();
        assert_ne!(
            gateway_annotations
                .get(KATA_COCO_INIT_DATA_ANNOTATION_KEY)
                .and_then(Value::as_str),
            annotations
                .get(KATA_COCO_INIT_DATA_ANNOTATION_KEY)
                .and_then(Value::as_str),
            "only the workspace policy authorizes the persistent volume"
        );
        let gateway_init_data = decode_gzip_base64(
            gateway_annotations
                .get(KATA_COCO_INIT_DATA_ANNOTATION_KEY)
                .and_then(Value::as_str)
                .unwrap(),
        );
        let gateway_init_data: toml::Value = toml::from_str(&gateway_init_data).unwrap();
        assert!(
            !gateway_init_data["data"]
                .as_table()
                .unwrap()
                .contains_key("codewire_workspace_storage_key_id"),
            "the gateway must not receive workspace key-release authority"
        );
        assert!(
            !gateway_init_data["data"]
                .as_table()
                .unwrap()
                .contains_key("codewire_workspace_storage_manifest_tag"),
            "the gateway must not receive workspace manifest-release authority"
        );
        let gateway_init_data = decode_gzip_base64(
            gateway_annotations[KATA_COCO_INIT_DATA_ANNOTATION_KEY]
                .as_str()
                .unwrap(),
        );
        assert!(gateway_init_data.contains("default CreateContainerRequest := true"));
        assert!(!gateway_init_data.contains("codewire_confidential_storage :="));
        assert_eq!(
            gateway_annotations[KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY].as_str(),
            Some(want_kernel_params)
        );

        let policy = render_gateway_network_policy("codewire-runtime", &opts);
        let egress = policy["spec"]["egress"].as_array().unwrap();
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
        assert!(kbs_rule.is_some(), "gateway KBS egress rule missing");
    }

    #[test]
    fn confidential_gateway_omits_coco_annotations_when_init_data_is_disabled() {
        let gateway = render_gateway_deployment(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-confidential-no-coco".into(),
                support_image: "nexus.example.invalid/gateway@sha256:golden".into(),
                runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
                gateway_token: "test-coordinate-token".into(),
                daemon_auth_token: "test-daemon-token".into(),
                environment_id: "be31063a-8ec8-46d5-aa17-75cda1729370".into(),
                kata_coco_kbs_url:
                    "https://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080".into(),
                kata_coco_image_registry_auth_uri: "kbs:///default/containers/auth".into(),
                ..Default::default()
            },
        );

        assert!(
            gateway["spec"]["template"]["metadata"]
                .get("annotations")
                .is_none()
        );
    }

    #[test]
    fn confidential_template_carries_resource_kernel_params_without_registry_auth() {
        let opts = TemplateOpts {
            name: "tmpl-confidential-resource".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
            gateway_token: "test-coordinate-token".into(),
            daemon_auth_token: "test-daemon-token".into(),
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
            gateway_token: "test-coordinate-token".into(),
            daemon_auth_token: "test-daemon-token".into(),
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

        let gateway = render_gateway_deployment("codewire-runtime", &opts);
        assert!(
            gateway["spec"]["template"]["metadata"]
                .get("annotations")
                .is_none()
        );
    }

    #[test]
    fn gzip_base64_uses_deterministic_stored_blocks() {
        let want = "H4sIAAAAAAAA/wEFAPr/aGVsbG+GphA2BQAAAA==";
        assert_eq!(gzip_base64("hello"), want);
        assert_eq!(decode_gzip_base64(want), "hello");
    }

    #[test]
    fn template_allows_derp_egress() {
        let rendered = render_gateway_network_policy(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-derp-egress".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                support_image: "git.example.invalid/codewire/gateway:test".into(),
                api_base_url: "https://codewire-dev.sh".into(),
                gateway_token: "test-coordinate-token".into(),
                daemon_auth_token: "test-daemon-token".into(),
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

        let egress = rendered["spec"]["egress"].as_array().unwrap();
        let derp_rule = egress.iter().find(|rule| {
            rule["to"].as_array().is_some_and(|targets| {
                targets.iter().any(|target| {
                    target["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                        .as_str()
                        == Some("dev")
                        && target["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
                            .as_str()
                            == Some("derp")
                })
            })
        });
        let derp_rule = derp_rule.expect("DERP egress rule missing");
        let ports = derp_rule["ports"].as_array().unwrap();
        assert!(ports.iter().any(|port| {
            port["protocol"].as_str() == Some("TCP")
                && port["port"].as_i64() == Some(INTERNAL_DERP_TLS_PORT)
        }));
        assert!(ports.iter().any(|port| {
            port["protocol"].as_str() == Some("UDP")
                && port["port"].as_i64() == Some(INTERNAL_DERP_STUN_PORT)
        }));
    }

    #[test]
    fn template_omits_legacy_server_egress() {
        let rendered = render_gateway_network_policy(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-no-legacy-server-egress".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                support_image: "git.example.invalid/codewire/gateway:test".into(),
                api_base_url: "https://codewire-dev.sh".into(),
                gateway_token: "test-coordinate-token".into(),
                daemon_auth_token: "test-daemon-token".into(),
                server_namespace: "dev".into(),
                cpu_millicores: 1000,
                memory_mib: 2048,
                ..Default::default()
            },
        );

        let egress = rendered["spec"]["egress"].as_array().unwrap();
        let legacy_server_rule = egress.iter().find(|rule| {
            rule["to"].as_array().is_some_and(|targets| {
                targets.iter().any(|target| {
                    target["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                        .as_str()
                        == Some("dev")
                        && target["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
                            .as_str()
                            == Some("server")
                })
            })
        });
        assert!(
            legacy_server_rule.is_none(),
            "legacy monolith egress rule should be absent"
        );
    }

    #[test]
    fn template_allows_direct_udp_ingress_when_stun_is_configured() {
        let opts = TemplateOpts {
            name: "tmpl-direct-udp-ingress".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            support_image: "git.example.invalid/codewire/gateway:test".into(),
            api_base_url: "https://codewire-dev.sh".into(),
            gateway_token: "test-coordinate-token".into(),
            daemon_auth_token: "test-daemon-token".into(),
            stun_host: "stun.codewire-dev.sh".into(),
            stun_port: 3478,
            cpu_millicores: 1000,
            memory_mib: 2048,
            ..Default::default()
        };
        let rendered = render_gateway_network_policy("codewire-runtime", &opts);

        let ingress = rendered["spec"]["ingress"].as_array().unwrap();
        assert!(ingress.iter().any(|rule| {
            rule["ports"].as_array().is_some_and(|ports| {
                ports.iter().any(|port| {
                    port["protocol"].as_str() == Some("UDP")
                        && port["port"].as_i64() == Some(GATEWAY_TAILNET_UDP_PORT)
                })
            })
        }));

        let deployment = render_gateway_deployment("codewire-runtime", &opts);
        let env = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array()
            .unwrap();
        assert!(env.iter().any(|entry| {
            entry["name"].as_str() == Some(GATEWAY_TAILNET_UDP_LISTEN_ADDR_ENV)
                && entry["value"].as_str() == Some(GATEWAY_TAILNET_UDP_LISTEN_ADDR)
        }));
    }

    #[test]
    fn template_wires_udp_relay_allocator_env_and_egress() {
        let opts = TemplateOpts {
            name: "tmpl-udp-relay".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            support_image: "git.example.invalid/codewire/gateway:test".into(),
            api_base_url: "https://codewire-dev.sh".into(),
            gateway_token: "test-coordinate-token".into(),
            daemon_auth_token: "test-daemon-token".into(),
            server_namespace: "dev".into(),
            udp_relay_allocator_url:
                "http://codewire-udp-relay.dev.svc.cluster.local:8095/internal/udp-relay/allocations"
                    .into(),
            udp_relay_allocator_token: "relay-token".into(),
            udp_relay_bind_addrs: "codewire-udp-relay.dev.svc.cluster.local:41641".into(),
            cpu_millicores: 1000,
            memory_mib: 2048,
            ..Default::default()
        };
        let deployment = render_gateway_deployment("codewire-runtime", &opts);
        let env = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array()
            .unwrap();
        assert!(env.iter().any(|entry| {
            entry["name"].as_str() == Some(GATEWAY_UDP_RELAY_ALLOCATOR_URL_ENV)
                && entry["value"].as_str()
                    == Some(
                        "http://codewire-udp-relay.dev.svc.cluster.local:8095/internal/udp-relay/allocations",
                    )
        }));
        assert!(env.iter().any(|entry| {
            entry["name"].as_str() == Some(GATEWAY_UDP_RELAY_ALLOCATOR_TOKEN_ENV)
                && entry["value"].as_str() == Some("relay-token")
        }));
        assert!(env.iter().any(|entry| {
            entry["name"].as_str() == Some(GATEWAY_UDP_RELAY_BIND_ADDRS_ENV)
                && entry["value"].as_str() == Some("codewire-udp-relay.dev.svc.cluster.local:41641")
        }));

        let policy = render_gateway_network_policy("codewire-runtime", &opts);
        let egress = policy["spec"]["egress"].as_array().unwrap();
        let relay_rule = egress.iter().find(|rule| {
            rule["to"].as_array().is_some_and(|targets| {
                targets.iter().any(|target| {
                    target["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                        .as_str()
                        == Some("dev")
                        && target["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
                            .as_str()
                            == Some("udp-relay")
                })
            })
        });
        let relay_rule = relay_rule.expect("UDP relay allocator egress rule missing");
        assert!(relay_rule["ports"].as_array().unwrap().iter().any(|port| {
            port["protocol"].as_str() == Some("TCP") && port["port"].as_i64() == Some(8095)
        }));
        assert!(relay_rule["ports"].as_array().unwrap().iter().any(|port| {
            port["protocol"].as_str() == Some("UDP") && port["port"].as_i64() == Some(41641)
        }));
    }

    #[test]
    fn template_allows_udp_relay_egress_without_flat_env_in_registry_mode() {
        let opts = TemplateOpts {
            name: "tmpl-udp-relay-registry".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            support_image: "git.example.invalid/codewire/gateway:test".into(),
            api_base_url: "https://codewire-dev.sh".into(),
            gateway_token: "test-coordinate-token".into(),
            daemon_auth_token: "test-daemon-token".into(),
            server_namespace: "dev".into(),
            udp_relay_allocator_egress_enabled: true,
            cpu_millicores: 1000,
            memory_mib: 2048,
            ..Default::default()
        };

        let deployment = render_gateway_deployment("codewire-runtime", &opts);
        let env = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array()
            .unwrap();
        assert!(!env.iter().any(|entry| {
            matches!(
                entry["name"].as_str(),
                Some(GATEWAY_UDP_RELAY_ALLOCATOR_URL_ENV)
                    | Some(GATEWAY_UDP_RELAY_ALLOCATOR_TOKEN_ENV)
                    | Some(GATEWAY_UDP_RELAY_BIND_ADDRS_ENV)
            )
        }));

        let policy = render_gateway_network_policy("codewire-runtime", &opts);
        let egress = policy["spec"]["egress"].as_array().unwrap();
        let relay_rule = egress.iter().find(|rule| {
            rule["to"].as_array().is_some_and(|targets| {
                targets.iter().any(|target| {
                    target["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                        .as_str()
                        == Some("dev")
                        && target["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
                            .as_str()
                            == Some("udp-relay")
                })
            })
        });
        let relay_rule = relay_rule.expect("UDP relay allocator egress rule missing");
        assert!(relay_rule["ports"].as_array().unwrap().iter().any(|port| {
            port["protocol"].as_str() == Some("TCP") && port["port"].as_i64() == Some(8095)
        }));
        assert!(relay_rule["ports"].as_array().unwrap().iter().any(|port| {
            port["protocol"].as_str() == Some("UDP") && port["port"].as_i64() == Some(41641)
        }));
    }

    #[test]
    fn template_allows_cluster_local_kbs_egress() {
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-kbs-egress".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                support_image: "git.example.invalid/codewire/gateway:test".into(),
                runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
                gateway_token: "test-coordinate-token".into(),
                daemon_auth_token: "test-daemon-token".into(),
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

    #[test]
    fn workspace_storage_class_defaults_and_overrides() {
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-storage-default".into(),
                gateway_token: "test-coordinate-token".into(),
                daemon_auth_token: "test-daemon-token".into(),
                disk_gib: 20,
                ..Default::default()
            },
        );
        assert_eq!(
            rendered["spec"]["volumeClaimTemplates"][0]["spec"]["storageClassName"].as_str(),
            Some(DEFAULT_WORKSPACE_STORAGE_CLASS)
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
                gateway_token: "test-coordinate-token".into(),
                daemon_auth_token: "test-daemon-token".into(),
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
                gateway_token: "test-coordinate-token".into(),
                daemon_auth_token: "test-daemon-token".into(),
                confidential_storage_manifest_uri: CONTENT_ADDRESSED_MANIFEST_URI.into(),
                runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
                disk_gib: 20,
                workspace_storage_class: "must-not-be-used".into(),
                ..Default::default()
            },
        );
        let claim = &rendered["spec"]["volumeClaimTemplates"][0];
        assert_eq!(
            claim["spec"]["storageClassName"].as_str(),
            Some(CONFIDENTIAL_WORKSPACE_STORAGE_CLASS)
        );
        assert_eq!(
            claim["spec"]["accessModes"][0].as_str(),
            Some("ReadWriteOncePod")
        );
        assert_eq!(claim["spec"]["volumeMode"].as_str(), Some("Block"));
        assert!(claim["metadata"]["annotations"].is_null());
    }

    #[test]
    fn gateway_service_is_cluster_ip_without_node_ports() {
        let rendered = render_gateway_service("codewire-runtime", &commodity_opts());
        assert_eq!(
            rendered["spec"]["type"].as_str(),
            Some("ClusterIP"),
            "gateway service must not reintroduce per-sandbox NodePorts"
        );
        let ports = rendered["spec"]["ports"].as_array().unwrap();
        assert!(
            ports.iter().all(|port| port.get("nodePort").is_none()),
            "gateway service ports must not carry static nodePort fields: {ports:?}"
        );
    }

    #[test]
    fn direct_udp_load_balancer_service_uses_cilium_lb_ipam_without_nodeports() {
        let opts = TemplateOpts {
            direct_udp_lb_enabled: true,
            gateway_token: "test-coordinate-token".into(),
            daemon_auth_token: "test-daemon-token".into(),
            direct_udp_lb_ip: "192.0.2.36".into(),
            direct_udp_lb_port: 33123,
            direct_udp_lb_class: "io.cilium/l2-announcer".into(),
            direct_udp_lb_sharing_key: "codewire-direct-udp".into(),
            direct_udp_transport_zone: "prod-node".into(),
            ..commodity_opts()
        };

        let service = render_gateway_direct_udp_service("codewire-runtime", &opts)
            .expect("direct UDP LoadBalancer service");
        assert_eq!(
            service["metadata"]["name"].as_str(),
            Some("cw-gateway-udp-env-golden-commodity")
        );
        assert_eq!(
            service["metadata"]["annotations"]["lbipam.cilium.io/ips"].as_str(),
            Some("192.0.2.36")
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
            Some("prod-node")
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
            Some(GATEWAY_TAILNET_UDP_PORT)
        );

        let deployment = render_gateway_deployment("codewire-runtime", &opts);
        let env = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array()
            .unwrap();
        assert!(env.iter().any(|entry| {
            entry["name"].as_str() == Some(GATEWAY_TAILNET_UDP_LISTEN_ADDR_ENV)
                && entry["value"].as_str() == Some(GATEWAY_TAILNET_UDP_LISTEN_ADDR)
        }));
        assert!(env.iter().any(|entry| {
            entry["name"].as_str() == Some(GATEWAY_TAILNET_DIRECT_UDP_ADVERTISE_ENDPOINTS_ENV)
                && entry["value"].as_str() == Some("192.0.2.36:33123")
        }));
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

        let policy = render_workspace_daemon_network_policy("codewire-runtime", &opts);
        assert_eq!(
            policy["spec"]["podSelector"]["matchLabels"]["codewire.sh/type"].as_str(),
            Some("workspace")
        );
        let ingress = policy["spec"]["ingress"].as_array().unwrap();
        assert_eq!(
            ingress[0]["from"][0]["podSelector"]["matchLabels"]["codewire.sh/type"].as_str(),
            Some("gateway")
        );
        assert_eq!(
            ingress[0]["ports"][0]["port"].as_i64(),
            Some(WORKSPACE_DAEMON_PORT)
        );
        assert_eq!(
            ingress[1]["from"][0]["namespaceSelector"]["matchLabels"]
                ["kubernetes.io/metadata.name"]
                .as_str(),
            Some("dev")
        );
        assert_eq!(
            ingress[1]["from"][0]["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
                .as_str(),
            Some("orchestration")
        );
        assert_eq!(ingress[1]["ports"][0]["protocol"].as_str(), Some("TCP"));
        assert_eq!(
            ingress[1]["ports"][0]["port"].as_i64(),
            Some(WORKSPACE_DAEMON_PORT)
        );
        assert_eq!(ingress[1]["ports"][1]["protocol"].as_str(), Some("TCP"));
        assert_eq!(
            ingress[1]["ports"][1]["port"].as_i64(),
            Some(APP_PREVIEW_MIN_PORT)
        );
        assert_eq!(
            ingress[1]["ports"][1]["endPort"].as_i64(),
            Some(APP_PREVIEW_MAX_PORT)
        );
        let egress = policy["spec"]["egress"].as_array().unwrap();
        assert!(egress.iter().any(|rule| {
            rule["to"]
                .as_array()
                .is_some_and(|targets| targets.iter().any(|target| target.get("ipBlock").is_some()))
        }));
        assert_eq!(policy["spec"]["policyTypes"][1].as_str(), Some("Egress"));
    }

    #[test]
    fn explicit_coordinator_url_and_internal_binding_url_are_independent_of_public_api_url() {
        let env = build_sidecar_env(&TemplateOpts {
            gateway_token: "coordinator-url-token".into(),
            daemon_auth_token: "coordinator-url-daemon-token".into(),
            api_base_url: "https://codewire.example".into(),
            coordinator_url: "http://codewire-coordinator.default.svc.cluster.local:8090".into(),
            server_namespace: "default".into(),
            ..Default::default()
        });
        let get = |name: &str| {
            env.iter().find_map(|entry| {
                (entry.get("name")?.as_str()? == name)
                    .then(|| entry.get("value")?.as_str().map(str::to_string))
                    .flatten()
            })
        };

        assert_eq!(
            get("CODEWIRE_API_URL").as_deref(),
            Some("https://codewire.example")
        );
        assert_eq!(
            get("CODEWIRE_COORDINATOR_URL").as_deref(),
            Some("http://codewire-coordinator.default.svc.cluster.local:8090")
        );
        assert_eq!(
            get("CODEWIRE_BINDING_URL").as_deref(),
            Some("http://codewire-orchestration.default.svc.cluster.local:8085")
        );
    }

    #[test]
    fn binding_url_is_omitted_without_a_server_namespace() {
        let env = build_sidecar_env(&TemplateOpts {
            gateway_token: "binding-url-token".into(),
            daemon_auth_token: "binding-url-daemon-token".into(),
            api_base_url: "https://codewire.example".into(),
            ..Default::default()
        });

        assert!(
            !env.iter()
                .any(|entry| entry["name"].as_str() == Some(GATEWAY_BINDING_URL_ENV))
        );
    }

    #[test]
    fn gateway_policy_keeps_rest_and_connect_orchestration_egress_during_dual_serve() {
        let rendered = render_gateway_network_policy(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-binding-egress".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                support_image: "git.example.invalid/codewire/gateway:test".into(),
                gateway_token: "test-coordinate-token".into(),
                daemon_auth_token: "test-daemon-token".into(),
                server_namespace: "dev".into(),
                ..Default::default()
            },
        );
        let rule = rendered["spec"]["egress"]
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| {
                rule["to"].as_array().is_some_and(|targets| {
                    targets.iter().any(|target| {
                        target["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                            .as_str()
                            == Some("dev")
                            && target["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
                                .as_str()
                                == Some("orchestration")
                    })
                })
            })
            .expect("orchestration egress rule");
        let ports: Vec<i64> = rule["ports"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|port| port["port"].as_i64())
            .collect();

        assert_eq!(ports, vec![8084, 8085]);
    }

    #[test]
    fn zero_replica_shadow_pool_matches_golden_file() {
        assert_eq!(
            render_sandbox_shadow_pool(
                "codewire-runtime",
                "shadow-golden",
                "tmpl-golden",
                "env-golden",
            ),
            load_golden("sandboxwarmpool.golden.json"),
        );
    }

    // ------------------------------------------- identity-free (B2, §13)

    const IDENTITY_FREE_BINDING_URL: &str =
        "http://codewire-orchestration-workspace-binding.dev.svc.cluster.local:8087";

    fn identity_free_opts() -> TemplateOpts {
        TemplateOpts {
            workspace_identity: WorkspaceIdentity::Binding {
                binding_url: IDENTITY_FREE_BINDING_URL.into(),
            },
            ..credential_opts()
        }
    }

    /// Invariant 1 / design §13: names that must never appear in an
    /// identity-free workspace template.
    const IDENTITY_FREE_FORBIDDEN_NAMES: [&str; 16] = [
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
            opts.gateway_token.as_str(),
            opts.daemon_auth_token.as_str(),
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
            gateway_token: "gw-token-other".into(),
            daemon_auth_token: "daemon-token-other".into(),
            managed_credential_clients:
                codewire_access::ManagedCredentialClients::from_profile_slots(["github"]).unwrap(),
            projection_selection_sha256: Some([0x11; 32]),
            ..identity_free_opts()
        };
        let render = |opts: &TemplateOpts| render_sandbox_template("dev-sandboxes", opts)["spec"].clone();
        assert_eq!(render(&first), render(&second));
    }

    #[test]
    fn identity_free_template_matches_golden_file() {
        let opts = identity_free_opts();
        assert_eq!(
            render_sandbox_template("dev-sandboxes", &opts),
            load_golden("identity-free-sandboxtemplate.golden.json"),
        );
        let runc = TemplateOpts {
            runtime_profile: RUNTIME_PROFILE_RUNC.into(),
            ..identity_free_opts()
        };
        assert_eq!(
            render_sandbox_template("dev-sandboxes", &runc),
            load_golden("identity-free-sandboxtemplate-runc.golden.json"),
        );
    }

    /// The identity-free gateway fetches its daemon credential over its own
    /// binding; the legacy rendering is unchanged for rollback and
    /// confidential.
    #[test]
    fn identity_free_gateway_gets_no_daemon_token_and_no_codex_config_map() {
        let opts = identity_free_opts();
        let env = build_sidecar_env(&opts);
        assert!(!env.iter().any(|entry| entry["name"] == DAEMON_AUTH_TOKEN_ENV));
        assert!(!serde_json::to_string(&env).unwrap().contains(&opts.daemon_auth_token));
        assert!(env.iter().any(|entry| entry["name"] == GATEWAY_BINDING_URL_ENV));
        assert!(render_credential_codex_config("dev-sandboxes", &opts).is_none());
        let legacy = credential_opts();
        assert!(build_sidecar_env(&legacy)
            .iter()
            .any(|entry| entry["name"] == DAEMON_AUTH_TOKEN_ENV));
        assert!(render_credential_codex_config("dev-sandboxes", &legacy).is_some());
        // The per-environment daemon policy keeps the gateway 8443 egress
        // that left the shared template.
        let policy = render_workspace_daemon_network_policy("dev-sandboxes", &opts);
        assert!(policy["spec"]["egress"].to_string().contains("\"port\":8443"));
    }

}
