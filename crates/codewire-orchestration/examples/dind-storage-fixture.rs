//! Render the existing commodity storage topology for the maintained DinD probe.
//! No API client, credentials, custom bootstrap or runtime-policy exception.

use std::collections::HashSet;

use anyhow::{Context, ensure};
use codewire_orchestration::sandbox::template::{
    DEFAULT_DIND_IMAGE, TemplateOpts, render_sandbox_template,
    render_workspace_daemon_network_policy,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn fixture(name: &str, support: &str, storage: &str) -> anyhow::Result<Value> {
    ensure!(name.starts_with("dind-storage-") && name.len() <= 63);
    ensure!(
        name.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    );
    let (_, digest) = support
        .rsplit_once("@sha256:")
        .context("support image must be digest-pinned")?;
    ensure!(digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()));
    ensure!(
        !storage.is_empty()
            && storage
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    );
    let opts = TemplateOpts {
        name: name.into(),
        environment_id: name.into(),
        image: DEFAULT_DIND_IMAGE.into(),
        support_image: support.into(),
        runtime_profile: "commodity".into(),
        docker_mode: "guest-dind".into(),
        cpu_millicores: 2000,
        memory_mib: 4096,
        disk_gib: 8,
        workspace_storage_class: storage.into(),
        kata_agent_policy_enabled: true,
        ..Default::default()
    };
    let template = render_sandbox_template("dev-sandboxes", &opts);
    let mut policy = render_workspace_daemon_network_policy("dev-sandboxes", &opts);
    policy.sort_all_objects();
    let rendered = &template["spec"]["podTemplate"];
    let original = &rendered["spec"];
    let dind = original["containers"]
        .as_array()
        .context("rendered containers")?
        .iter()
        .find(|c| c["name"] == "dind")
        .context("rendered DinD")?
        .clone();
    let inits: Vec<Value> = original["initContainers"]
        .as_array()
        .context("rendered storage init")?
        .iter()
        .filter(|c| {
            matches!(
                c["name"].as_str(),
                Some("mount-workspace" | "workspace-flush" | "codewire-docker-data-init")
            )
        })
        .cloned()
        .collect();
    ensure!(inits.iter().any(|c| c["name"] == "mount-workspace"));
    let mut refs = HashSet::new();
    for c in inits.iter().chain(std::iter::once(&dind)) {
        for field in ["volumeMounts", "volumeDevices"] {
            for mount in c[field].as_array().into_iter().flatten() {
                refs.insert(mount["name"].as_str().context("volume name")?.to_owned());
            }
        }
    }
    let mut volumes: Vec<Value> = original["volumes"]
        .as_array()
        .context("rendered volumes")?
        .iter()
        .filter(|v| refs.contains(v["name"].as_str().unwrap_or_default()))
        .cloned()
        .collect();
    volumes.push(json!({"name":"workspace", "persistentVolumeClaim":{"claimName":format!("{name}-workspace")}}));
    ensure!(!volumes.iter().any(|v| v.get("hostPath").is_some()
        || v.get("secret").is_some()
        || v.get("projected").is_some()));
    let mounts: Vec<Value> = dind["volumeMounts"]
        .as_array()
        .context("DinD mounts")?
        .iter()
        .filter(|v| v["mountPath"] == "/workspace" || v["mountPath"] == "/var/run/docker")
        .cloned()
        .collect();
    ensure!(mounts.len() == 2);
    let client = json!({
        "name":"client", "image":DEFAULT_DIND_IMAGE,
        "command":["sh","-ec","umask 077; mkdir \"$DOCKER_CONFIG\"; exec sleep 86400"],
        "env":[
            {"name":"DOCKER_HOST","value":"unix:///var/run/docker/docker.sock"},
            {"name":"DOCKER_CONFIG","value":"/tmp/codewire-dind-client"}
        ],
        "securityContext":{"runAsUser":1000,"runAsGroup":1000,"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}},
        "resources":{"requests":{"cpu":"100m","memory":"128Mi"},"limits":{"cpu":"1","memory":"512Mi"}},
        "volumeMounts":mounts,
    });
    let mut annotations = rendered["metadata"]["annotations"].clone();
    annotations["codewire.sh/workspace"] = "true".into();
    let pod = json!({
        "apiVersion":"v1","kind":"Pod",
        "metadata":{"name":name,"namespace":"dev-sandboxes", "annotations":annotations,
            "labels":{"codewire.sh/type":"workspace","codewire.sh/environment-id":name,"codewire.sh/probe":"dind-storage","codewire.sh/probe-id":name,"agents.x-k8s.io/sandbox-name-hash":name}},
        "spec":{"runtimeClassName":original["runtimeClassName"],"restartPolicy":"Never",
            "serviceAccountName":original["serviceAccountName"],
            "automountServiceAccountToken":false,"enableServiceLinks":false,
            "securityContext":original["securityContext"],"terminationGracePeriodSeconds":original["terminationGracePeriodSeconds"],
            "initContainers":inits,"containers":[dind,client],"volumes":volumes},
    });
    let claim = json!({"apiVersion":"v1","kind":"PersistentVolumeClaim",
        "metadata":{"name":format!("{name}-workspace"),"namespace":"dev-sandboxes","labels":{"codewire.sh/probe-id":name}},
        "spec":template["spec"]["volumeClaimTemplates"][0]["spec"]});
    let command = serde_json::to_vec(&pod["spec"]["containers"][0]["command"])?;
    let policy_hash = format!("{:x}", Sha256::digest(serde_json::to_vec(&policy)?));
    Ok(
        json!({"schema_version":1,"bootstrap_argv_sha256":format!("{:x}",Sha256::digest(command)),
        "network_policy_sha256":policy_hash,"support_image":support,"dind_image":DEFAULT_DIND_IMAGE,"objects":[claim,pod,policy]}),
    )
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 3,
        "usage: dind-storage-fixture NAME SUPPORT_IMAGE STORAGE_CLASS"
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&fixture(&args[0], &args[1], &args[2])?)?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::{os::unix::fs::PermissionsExt, process::Command};

    fn rendered() -> Value {
        fixture(
            "dind-storage-fixture",
            &format!("registry.example.invalid/daemon@sha256:{}", "a".repeat(64)),
            "example-workspace",
        )
        .unwrap()
    }

    #[test]
    fn uses_product_bootstrap_as_pid_one_and_product_disk_preparation() {
        let got = rendered();
        let pod = &got["objects"][1]["spec"];
        let template = render_sandbox_template(
            "dev-sandboxes",
            &TemplateOpts {
                runtime_profile: "commodity".into(),
                docker_mode: "guest-dind".into(),
                disk_gib: 8,
                memory_mib: 4096,
                ..Default::default()
            },
        );
        let dind = template["spec"]["podTemplate"]["spec"]["containers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "dind")
            .unwrap();
        assert_eq!(pod["containers"][0]["command"], dind["command"]);
        assert_eq!(pod["initContainers"][0]["name"], "mount-workspace");
        assert_eq!(got["objects"][0]["spec"]["volumeMode"], "Block");
        assert_eq!(pod["runtimeClassName"], "commodity");
    }

    #[test]
    fn observer_is_unprivileged_with_no_platform_identity_or_host_mounts() {
        let got = rendered();
        let pod = &got["objects"][1]["spec"];
        assert_eq!(pod["automountServiceAccountToken"], false);
        assert_eq!(pod["serviceAccountName"], "codewire-sandbox");
        assert_eq!(pod["containers"][1]["securityContext"]["runAsUser"], 1000);
        assert_eq!(
            pod["containers"][1]["securityContext"]["allowPrivilegeEscalation"],
            false
        );
        for volume in pod["volumes"].as_array().unwrap() {
            assert!(
                volume.get("hostPath").is_none()
                    && volume.get("secret").is_none()
                    && volume.get("projected").is_none()
            );
        }
        assert!(pod.get("hostPID").is_none() && pod.get("hostNetwork").is_none());
    }

    #[test]
    #[cfg(unix)]
    fn observer_setup_creates_empty_private_config_with_unwritable_home() {
        let got = rendered();
        let client = &got["objects"][1]["spec"]["containers"][1];
        assert_eq!(
            client["env"],
            json!([
                {"name":"DOCKER_HOST","value":"unix:///var/run/docker/docker.sock"},
                {"name":"DOCKER_CONFIG","value":"/tmp/codewire-dind-client"}
            ])
        );
        let work = tempfile::tempdir().unwrap();
        // A non-directory HOME cannot hold Docker configuration, even when
        // the test runs as root. The setup must use its own empty directory.
        let home = work.path().join("unwritable-home");
        std::fs::write(&home, b"synthetic home boundary").unwrap();
        let config = work.path().join("docker-config");
        let sleep = work.path().join("sleep");
        std::fs::write(&sleep, b"#!/bin/sh\nset -eu\ntest \"$1\" = 86400\nif mkdir \"$HOME/.docker\" 2>/dev/null; then exit 90; fi\ntest -d \"$DOCKER_CONFIG\"\ntest -z \"$(ls -A \"$DOCKER_CONFIG\")\"\nprintf '{\"auths\":{}}\\n' > \"$DOCKER_CONFIG/config.json\"\n").unwrap();
        std::fs::set_permissions(&sleep, std::fs::Permissions::from_mode(0o700)).unwrap();
        let argv = client["command"].as_array().unwrap();
        let result = Command::new(argv[0].as_str().unwrap())
            .args(argv.iter().skip(1).map(|v| v.as_str().unwrap()))
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", work.path().display()))
            .env("HOME", &home)
            .env("DOCKER_CONFIG", &config)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            std::fs::metadata(&config).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::read(config.join("config.json")).unwrap(),
            b"{\"auths\":{}}\n"
        );
        assert_eq!(std::fs::read(home).unwrap(), b"synthetic home boundary");
    }

    #[test]
    fn refuses_unpinned_images_and_names_outside_owned_prefix() {
        assert!(fixture("dind-storage-fixture", "daemon:latest", "example-workspace").is_err());
        assert!(
            fixture(
                "existing-user-workspace",
                "daemon:latest",
                "example-workspace"
            )
            .is_err()
        );
    }

    #[test]
    fn network_rules_and_selector_come_from_the_product_renderer() {
        let got = rendered();
        let expected = render_workspace_daemon_network_policy(
            "dev-sandboxes",
            &TemplateOpts {
                environment_id: "dind-storage-fixture".into(),
                runtime_profile: "commodity".into(),
                ..Default::default()
            },
        );
        assert_eq!(got["objects"][2], expected);
        let selector = got["objects"][2]["spec"]["podSelector"]["matchLabels"]
            .as_object()
            .unwrap();
        let labels = &got["objects"][1]["metadata"]["labels"];
        for (key, value) in selector {
            assert_eq!(&labels[key], value);
        }
    }
}
