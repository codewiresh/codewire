//! A systemd workspace's rendering (docs/dev/SYSTEMD-WORKSPACE.md, "How
//! orchestration renders it" and "The first process"): the fixed first
//! process, root with one added capability, and memory mounts where systemd
//! needs mount points.

use serde_json::{Value, json};

use super::workspace::{
    SYSTEMD_BOOTSTRAP_START, SYSTEMD_BOOTSTRAP_SUPERVISE, systemd_bootstrap_command,
};
use super::{RUNTIME_PROFILE_COMMODITY, TemplateOpts, render_sandbox_template};

fn opts(profile: &str, disk_gib: i64, systemd_workspace: bool) -> TemplateOpts {
    TemplateOpts {
        name: "tmpl-systemd".into(),
        image: format!(
            "registry.example.invalid/codewire/workspace-systemd@sha256:{}",
            "a".repeat(64)
        ),
        systemd_workspace,
        support_image: super::TEST_SUPPORT_IMAGE.into(),
        runtime_profile: profile.into(),
        cpu_millicores: 2000,
        memory_mib: 4096,
        disk_gib,
        workspace_storage_class: "local-path".into(),
        ..Default::default()
    }
}

fn pod_spec(opts: &TemplateOpts) -> Value {
    render_sandbox_template("dev-sandboxes", opts)["spec"]["podTemplate"]["spec"].clone()
}

fn mount_paths(workspace: &Value, name_prefix: &str) -> Vec<String> {
    workspace["volumeMounts"]
        .as_array()
        .expect("workspace mounts")
        .iter()
        .filter(|mount| {
            mount["name"]
                .as_str()
                .unwrap_or_default()
                .starts_with(name_prefix)
        })
        .map(|mount| mount["mountPath"].as_str().unwrap_or_default().to_owned())
        .collect()
}

#[test]
fn a_systemd_workspace_boots_through_the_fixed_bootstrap_as_root_with_one_capability() {
    let spec = pod_spec(&opts(RUNTIME_PROFILE_COMMODITY, 40, true));
    let workspace = &spec["containers"][0];
    assert_eq!(workspace["name"], "workspace");
    assert_eq!(
        workspace["command"],
        json!(["/bin/bash", "-c", systemd_bootstrap_command()])
    );
    assert_eq!(
        workspace["securityContext"],
        json!({ "runAsUser": 0, "runAsGroup": 0, "capabilities": { "add": ["SYS_ADMIN"] } })
    );
    // The Pod's own settings stay the default workspace's.
    assert_eq!(spec["securityContext"]["runAsUser"], 1000);
    assert_eq!(spec["securityContext"]["fsGroup"], 1000);
    // The probes are execs, which is why systemd runs in a child cgroup.
    assert!(workspace["startupProbe"]["exec"].is_object());
}

#[test]
fn the_first_process_starts_systemd_nested_without_the_capability_and_survives_expansion() {
    let command = systemd_bootstrap_command();
    // Kubernetes expands `$(NAME)` and `$$` in a container command.
    assert!(
        !command.contains("$(") && !command.contains("$$"),
        "{command}"
    );
    // systemd is PID 1 of its own PID and mount namespace, in the child
    // cgroup `workspace`, and starts without CAP_SYS_ADMIN.
    assert!(SYSTEMD_BOOTSTRAP_START.contains(
        "unshare --pid --fork --mount --propagation private /bin/sh -c \
         'echo 0 > /sys/fs/cgroup/workspace/cgroup.procs && mount -t proc proc /proc \
         && exec setpriv --bounding-set=-sys_admin /sbin/init' &"
    ));
    assert!(!command.contains("/sys/fs/cgroup/system"));
    // The first process itself never moves.
    assert_eq!(command.matches("cgroup.procs").count(), 1);
    assert!(SYSTEMD_BOOTSTRAP_START.ends_with("u=$!"));
}

/// Runs the supervise half against a stand-in for systemd: `$u` is a shell
/// whose child plays systemd. `signal` is sent to the supervising shell after
/// it starts. Returns its exit status.
#[cfg(target_os = "linux")]
fn supervise(stand_in: &str, signal: Option<&str>) -> i32 {
    use std::process::Command;
    use std::time::Duration;

    let script = format!("{stand_in} &\nu=$!\n{SYSTEMD_BOOTSTRAP_SUPERVISE}");
    let mut child = Command::new("timeout")
        .args(["20", "bash", "-c", &script])
        .spawn()
        .expect("start bash");
    if let Some(signal) = signal {
        std::thread::sleep(Duration::from_millis(500));
        // `timeout` runs bash as its child; signal bash, not `timeout`.
        let status = Command::new("pkill")
            .args([&format!("-{signal}"), "-P", &child.id().to_string(), "bash"])
            .status()
            .expect("signal the supervising shell");
        assert!(status.success(), "the supervising shell was not found");
    }
    child
        .wait()
        .expect("wait for bash")
        .code()
        .expect("an exit code")
}

/// A stand-in systemd that ends with `status` on SIGRTMIN+3 and otherwise
/// runs until the test's timeout.
#[cfg(target_os = "linux")]
fn systemd_stopping_with(status: i32) -> String {
    format!(
        "bash -c 'bash -c \"trap \\\"exit {status}\\\" RTMIN+3; while :; do sleep 0.05; done\"; exit $?'"
    )
}

#[cfg(target_os = "linux")]
#[test]
fn systemd_ending_unasked_fails_the_pod() {
    // A poweroff in a session: systemd exits 0 without a stop signal.
    assert_eq!(supervise("bash -c 'exit 0'", None), 1);
    assert_eq!(supervise("bash -c 'exit 3'", None), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn a_stop_signal_reaches_systemd_and_the_first_process_exits_with_its_status() {
    // Without the forward the stand-in never ends, and `timeout` exits 124.
    for signal in ["TERM", "RTMIN+3"] {
        assert_eq!(
            supervise(&systemd_stopping_with(0), Some(signal)),
            0,
            "{signal}"
        );
    }
    assert_eq!(supervise(&systemd_stopping_with(3), Some("TERM")), 3);
}

#[test]
fn systemd_gets_memory_mounts_at_run_and_run_lock_and_one_tmp() {
    // A Block workspace already mounts a memory /tmp.
    let block = pod_spec(&opts(RUNTIME_PROFILE_COMMODITY, 40, true));
    assert_eq!(
        mount_paths(&block["containers"][0], "systemd-"),
        ["/run", "/run/lock"]
    );
    // Without a disk the workspace is an emptyDir and nothing mounts /tmp.
    let filesystem = pod_spec(&opts(RUNTIME_PROFILE_COMMODITY, 0, true));
    assert_eq!(
        mount_paths(&filesystem["containers"][0], "systemd-"),
        ["/run", "/run/lock", "/tmp"]
    );
    for spec in [&block, &filesystem] {
        let tmp_mounts = spec["containers"][0]["volumeMounts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|mount| mount["mountPath"] == "/tmp")
            .count();
        assert_eq!(tmp_mounts, 1);
        for volume in spec["volumes"].as_array().unwrap() {
            if volume["name"].as_str().unwrap().starts_with("systemd-") {
                assert_eq!(volume["emptyDir"], json!({ "medium": "Memory" }));
            }
        }
    }
}

#[test]
fn a_default_workspace_gets_none_of_it() {
    let spec = pod_spec(&opts(RUNTIME_PROFILE_COMMODITY, 40, false));
    let workspace = &spec["containers"][0];
    assert!(workspace.get("securityContext").is_none());
    assert!(mount_paths(workspace, "systemd-").is_empty());
    assert_ne!(workspace["command"][2], systemd_bootstrap_command());
}
