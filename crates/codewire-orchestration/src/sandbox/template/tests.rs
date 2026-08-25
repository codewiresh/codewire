#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    use base64::Engine;
    use flate2::read::GzDecoder;
    use serde_json::Value;

    fn decode_gzip_base64(encoded: &str) -> String {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let mut decoder = GzDecoder::new(&raw[..]);
        let mut decoded = String::new();
        decoder.read_to_string(&mut decoded).unwrap();
        decoded
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

    /// Inputs cover every branch represented by the checked-in fixtures.
    fn isol8_opts() -> TemplateOpts {
        TemplateOpts {
            name: "tmpl-golden-isol8".into(),
            image: "git.example.com/codewire/workspace:golden".into(),
            image_command: vec!["/bin/start".into(), "--flag".into()],
            support_image: "git.example.com/codewire/gateway:golden".into(),
            runtime_class_name: RUNTIME_CLASS_NAME.into(),
            node_selector: default_node_selector(RUNTIME_CLASS_NAME),
            tolerations: isol8_tolerations(),
            environment_id: "env-golden-isol8".into(),
            gateway_token: "gw-token-golden".into(),
            api_base_url: "https://codewire.sh".into(),
            server_namespace: "prod".into(),
            derp_host: "derp.codewire.sh".into(),
            derp_port: 443,
            stun_host: "stun.codewire.sh".into(),
            stun_port: 3478,
            cpu_millicores: 2000,
            memory_mib: 4096,
            disk_gib: 20,
            network_policy_management: "Unmanaged".into(),
            debug_tailnet: true,
            ..Default::default()
        }
    }

    fn commodity_opts() -> TemplateOpts {
        TemplateOpts {
            name: "tmpl-golden-commodity".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            support_image: "git.example.invalid/codewire/gateway:golden".into(),
            runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
            environment_id: "env-golden-commodity".into(),
            gateway_token: "gw-token-golden-commodity".into(),
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

    #[test]
    fn template_opts_debug_redacts_bearer_tokens_and_embedded_ca() {
        let rendered = format!(
            "{:?}",
            TemplateOpts {
                gateway_token: "gateway-secret-value".into(),
                udp_relay_allocator_token: "relay-secret-value".into(),
                kata_coco_kbs_ca_pem: "embedded-public-ca".into(),
                ..Default::default()
            }
        );

        assert!(rendered.contains("gateway_token: \"<redacted>\""));
        assert!(rendered.contains("udp_relay_allocator_token: \"<redacted>\""));
        assert!(rendered.contains("kata_coco_kbs_ca_pem: \"<configured>\""));
        assert!(!rendered.contains("gateway-secret-value"));
        assert!(!rendered.contains("relay-secret-value"));
        assert!(!rendered.contains("embedded-public-ca"));
    }

    #[test]
    fn extracted_template_modules_keep_one_way_dependencies() {
        let leaves = [
            ("encoding", include_str!("encoding.rs")),
            ("naming", include_str!("naming.rs")),
            ("runtime_policy", include_str!("runtime_policy.rs")),
        ];
        for (name, source) in leaves {
            for forbidden in [
                "super::gateway",
                "super::network",
                "super::workspace",
            ] {
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
    fn runtime_profile_spec_resolves_guard_profiles() {
        assert_eq!(
            runtime_profile_spec("", RUNTIME_CLASS_RUNC, DOCKER_MODE_PROFILE_DEFAULT, false),
            RuntimeProfileSpec {
                profile: RUNTIME_PROFILE_RUNC.into(),
                runtime_class_name: RUNTIME_CLASS_RUNC.into(),
                docker_mode: DOCKER_MODE_NONE.into(),
                sidecar_resource_mode: SIDECAR_RESOURCE_MODE_EXPLICIT.into(),
            }
        );

        assert_eq!(
            runtime_profile_spec(
                RUNTIME_PROFILE_COMMODITY,
                RUNTIME_CLASS_EXTERNAL_ISOL8_XEN,
                DOCKER_MODE_PROFILE_DEFAULT,
                false,
            ),
            RuntimeProfileSpec {
                profile: RUNTIME_PROFILE_COMMODITY.into(),
                runtime_class_name: RUNTIME_CLASS_COMMODITY.into(),
                docker_mode: DOCKER_MODE_GUEST_DIND.into(),
                sidecar_resource_mode: SIDECAR_RESOURCE_MODE_EXPLICIT.into(),
            }
        );

        assert_eq!(
            runtime_profile_spec(
                "",
                RUNTIME_CLASS_EXTERNAL_ISOL8_XEN,
                DOCKER_MODE_PROFILE_DEFAULT,
                false,
            ),
            RuntimeProfileSpec {
                profile: RUNTIME_PROFILE_EXTERNAL_ISOL8_XEN.into(),
                runtime_class_name: RUNTIME_CLASS_EXTERNAL_ISOL8_XEN.into(),
                docker_mode: DOCKER_MODE_EXTERNAL_ISOL8_PROXY.into(),
                sidecar_resource_mode: SIDECAR_RESOURCE_MODE_RUNTIME_ENVELOPE.into(),
            }
        );

        assert_eq!(
            runtime_profile_spec(
                RUNTIME_PROFILE_COMMODITY,
                RUNTIME_CLASS_COMMODITY,
                DOCKER_MODE_NONE,
                false,
            )
            .docker_mode,
            DOCKER_MODE_NONE
        );

        assert_eq!(
            runtime_profile_spec("", RUNTIME_CLASS_RUNC, DOCKER_MODE_PROFILE_DEFAULT, true)
                .docker_mode,
            DOCKER_MODE_LOCAL_DIND_DIRECT
        );
    }

    #[test]
    fn managed_runtime_validation_rejects_diagnostic_profiles() {
        let commodity = RuntimeProfileSpec {
            profile: RUNTIME_PROFILE_COMMODITY.into(),
            ..Default::default()
        };
        assert!(validate_managed_runtime_profile(&commodity, false).is_ok());

        let confidential = RuntimeProfileSpec {
            profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
            ..Default::default()
        };
        assert!(validate_managed_runtime_profile(&confidential, false).is_ok());

        let external_isol8 = RuntimeProfileSpec {
            profile: RUNTIME_PROFILE_EXTERNAL_ISOL8_XEN.into(),
            ..Default::default()
        };
        assert!(validate_managed_runtime_profile(&external_isol8, false).is_err());

        let runc = RuntimeProfileSpec {
            profile: RUNTIME_PROFILE_RUNC.into(),
            ..Default::default()
        };
        assert!(validate_managed_runtime_profile(&runc, false).is_err());
        assert!(validate_managed_runtime_profile(&runc, true).is_ok());

        let none = RuntimeProfileSpec {
            profile: RUNTIME_PROFILE_NONE.into(),
            ..Default::default()
        };
        assert!(validate_managed_runtime_profile(&none, false).is_err());

        let unknown = RuntimeProfileSpec {
            profile: "kata-dev".into(),
            ..Default::default()
        };
        assert!(validate_managed_runtime_profile(&unknown, true).is_err());
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
        assert!(!annotations.contains_key(ISOL8_WORKSPACE_ANNOTATION_KEY));
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
        let init_containers = pod_template["spec"]["initContainers"].as_array().unwrap();
        assert_eq!(
            init_containers[0]["name"].as_str(),
            Some("codewire-daemon-init")
        );
        assert_eq!(
            init_containers[0]["image"].as_str(),
            Some(DEFAULT_GATEWAY_IMAGE)
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
                server_namespace: "dev".into(),
                ..Default::default()
            },
        );
        let spec = &gateway["spec"]["template"]["spec"];
        assert!(
            gateway["spec"]["template"]["metadata"]["labels"]
                ["codewire.sh/isolation-tier"]
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
                    && env["value"].as_str() == Some("gw-token"))
        );
        assert!(
            gateway_container["env"]
                .as_array()
                .unwrap()
                .iter()
                .all(|env| {
                    !matches!(
                        env["name"].as_str(),
                        Some("CODEWIRE_DOCKER_PROXY_SOCK") | Some(GATEWAY_DOCKER_UPSTREAM_SOCK_ENV)
                    )
                }),
            "split gateway must not advertise Docker proxy env vars unless a future proxy mode is explicitly enabled"
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
                gateway_token: "managed-daemon-token".into(),
                ..Default::default()
            },
        );
        let managed_spec = &managed["spec"]["podTemplate"]["spec"];
        let managed_workspace = &managed_spec["containers"][0];
        let managed_command = managed_workspace["command"][2].as_str().unwrap();
        assert!(managed_command.contains("while [ ! -x /codewire/bin/cw ]"));
        assert!(managed_command.contains("exec /codewire/bin/cw daemon"));
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
        assert!(init_command.contains("ln -sf cw /codewire/bin/daemon"));
        assert!(init_command.contains("ln -sf cw /codewire/bin/codewire-daemon"));

        let custom = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-custom-daemon".into(),
                image: "example.invalid/custom:golden".into(),
                image_command: vec!["/bin/custom-entrypoint".into(), "--serve".into()],
                support_image: "git.example.invalid/codewire/gateway:test".into(),
                environment_id: "env-custom-daemon".into(),
                gateway_token: "custom-daemon-token".into(),
                ..Default::default()
            },
        );
        let custom_command = custom["spec"]["podTemplate"]["spec"]["containers"][0]["command"][2]
            .as_str()
            .unwrap();
        assert!(custom_command.contains("/bin/custom-entrypoint --serve & workload_pid=$!"));
        assert!(custom_command.contains("/codewire/bin/cw daemon & daemon_pid=$!"));
        assert!(custom_command.contains("if ! kill -0 \"$daemon_pid\""));
        assert!(
            custom_command
                .matches("/codewire/bin/cw daemon & daemon_pid=$!")
                .count()
                >= 2,
            "custom supervisor must restart the daemon while the workload remains alive"
        );
        assert!(!custom_command.contains("nohup cw node"));
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
        std::fs::write(
            &daemon,
            format!(
                "#!/bin/sh\n\
                 count=0\n\
                 [ ! -f {count} ] || count=\"$(cat {count})\"\n\
                 echo $((count + 1)) > {count}\n\
                 echo $$ > {pid}\n\
                 trap 'exit 0' TERM INT\n\
                 while true; do sleep 0.1; done\n",
                count = count.display(),
                pid = pid.display(),
            ),
        )
        .unwrap();
        std::fs::write(
            &workload,
            "#!/bin/sh\ntrap 'exit 0' TERM INT\nwhile true; do sleep 0.1; done\n",
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
                    image: "ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467".into(),
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
                image: "ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467".into(),
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
    fn gateway_host_key_secret_and_mount_are_environment_scoped() {
        let opts = TemplateOpts {
            name: "tmpl-gateway-host-key".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            support_image: "git.example.invalid/codewire/gateway:test".into(),
            runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
            environment_id: "env-gateway-host-key".into(),
            gateway_token: "gw-token".into(),
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
                environment_id: "be31063a-8ec8-46d5-aa17-75cda1729370".into(),
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
            "url = \"https://kbs.codewire-dev.sh\"".to_string(),
            "\"codewire_workspace_storage_key_id\" = \"be31063a-8ec8-46d5-aa17-75cda1729370\"".to_string(),
        ] {
            assert!(decoded.contains(&want), "missing {want:?} in {decoded}");
        }
        assert!(
            !decoded.contains("[[credentials]]"),
            "init-data should use post-boot CDH REST resource fetch instead of credential prefetch:\n{decoded}"
        );
        let init_data: toml::Value = toml::from_str(&decoded).unwrap();
        let data = init_data["data"].as_table().unwrap();
        assert_eq!(
            data["codewire_workspace_storage_key_id"].as_str(),
            Some("be31063a-8ec8-46d5-aa17-75cda1729370")
        );
        let storage_registry: serde_json::Value =
            serde_json::from_str(data["confidential_storage"].as_str().unwrap()).unwrap();
        assert_eq!(storage_registry["version"].as_u64(), Some(1));
        assert_eq!(
            storage_registry["volumes"][0],
            serde_json::json!({
                "profile": "luks2-integrity-ext4",
                "volumeId": "be31063a-8ec8-46d5-aa17-75cda1729370",
                "keyUri": "kbs:///default/codewire-workspace-luks/be31063a-8ec8-46d5-aa17-75cda1729370",
            })
        );
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
    fn confidential_template_and_gateway_carry_coco_resource_kernel_params() {
        let opts = TemplateOpts {
            name: "tmpl-confidential-auth".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            support_image: "git.example.invalid/codewire/gateway:test".into(),
            runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
            kata_coco_init_data_enabled: true,
            kata_coco_kbs_url:
                "http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080".into(),
            kata_coco_image_registry_auth_uri: "kbs:///default/containers/auth".into(),
            environment_id: "be31063a-8ec8-46d5-aa17-75cda1729370".into(),
            server_namespace: "dev".into(),
            ..Default::default()
        };
        let want_kernel_params = "agent.image_registry_auth=kbs:///default/containers/auth agent.image_resource_timeout_secs=300 agent.guest_components_rest_api=resource agent.aa_kbc_params=cc_kbc::http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080 agent.log_vport=1025";

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
            gateway["spec"]["template"]["metadata"]["labels"]
                ["codewire.sh/isolation-tier"]
                .as_str(),
            Some("confidential")
        );
        let gateway_annotations = gateway["spec"]["template"]["metadata"]["annotations"]
            .as_object()
            .unwrap();
        assert_eq!(
            gateway_annotations
                .get(KATA_COCO_INIT_DATA_ANNOTATION_KEY)
                .and_then(Value::as_str),
            annotations
                .get(KATA_COCO_INIT_DATA_ANNOTATION_KEY)
                .and_then(Value::as_str),
            "workspace and gateway must carry identical measured CoCo init-data"
        );
        let gateway_init_data = decode_gzip_base64(
            gateway_annotations[KATA_COCO_INIT_DATA_ANNOTATION_KEY]
                .as_str()
                .unwrap(),
        );
        assert!(gateway_init_data.contains(
            "\"codewire_workspace_storage_key_id\" = \"be31063a-8ec8-46d5-aa17-75cda1729370\""
        ));
        assert_eq!(
            gateway_annotations[KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY]
                .as_str(),
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
            kata_coco_init_data_enabled: true,
            kata_coco_kbs_url:
                "http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080".into(),
            ..Default::default()
        };
        let want_kernel_params = "agent.image_resource_timeout_secs=300 agent.guest_components_rest_api=resource agent.aa_kbc_params=cc_kbc::http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080 agent.log_vport=1025";

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
                disk_gib: 20,
                ..Default::default()
            },
        );
        assert_eq!(
            rendered["spec"]["volumeClaimTemplates"][0]["spec"]["storageClassName"].as_str(),
            Some(DEFAULT_WORKSPACE_STORAGE_CLASS)
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
        assert_eq!(claim["spec"]["volumeMode"].as_str(), Some("Filesystem"));
        assert_eq!(
            claim["metadata"]["annotations"]
                [KATA_CONFIDENTIAL_STORAGE_VOLUME_ID_ANNOTATION]
                .as_str(),
            Some("be31063a-8ec8-46d5-aa17-75cda1729370")
        );
        assert_eq!(
            claim["metadata"]["annotations"][KATA_CONFIDENTIAL_STORAGE_KEY_URI_ANNOTATION]
                .as_str(),
            Some(
                "kbs:///default/codewire-workspace-luks/be31063a-8ec8-46d5-aa17-75cda1729370"
            )
        );
    }

    #[test]
    fn template_isol8_renders_workspace_pod_without_gateway_container() {
        let rendered = render_sandbox_template("codewire-runtime", &isol8_opts());
        let pod_spec = &rendered["spec"]["podTemplate"]["spec"];
        let containers = pod_spec["containers"].as_array().unwrap();
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0]["name"].as_str(), Some("workspace"));
        assert!(
            containers
                .iter()
                .all(|container| container["name"].as_str() != Some("codewire-gateway"))
        );
        assert_eq!(
            pod_spec["initContainers"][0]["name"].as_str(),
            Some("codewire-daemon-init")
        );
        assert_eq!(pod_spec["runtimeClassName"].as_str(), Some("isol8"));
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
    fn warm_pool_matches_golden_file() {
        assert_eq!(
            render_sandbox_warm_pool("codewire-runtime", "warm-golden", "tmpl-golden-isol8", 3),
            load_golden("sandboxwarmpool.golden.json"),
        );
    }
}
