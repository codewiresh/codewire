//! Live-cluster smoke test for the workspace exec primitive (#36
//! Stage B2), run by the kind-e2e CI job.
//!
//! The pod exec subresource is the riskiest piece of the env-setup
//! port (SPDY/WebSocket upgrade, container targeting, exit-code
//! propagation through the Status frame), so this exercises the real
//! `SandboxClient::exec_workspace_result_on_pod` path against a pod in
//! the cluster:
//!
//!   1. stdout capture and zero exit
//!   2. workdir + env handling through build_workspace_exec_command
//!      (including shell-quoting hazards)
//!   3. nonzero exit codes surfaced via exit_code, stderr captured
//!
//! Env: SMOKE_NAMESPACE (default "default") and required SMOKE_POD_NAME.
//! The caller owns a ready workspace Pod with the staged private CLI and
//! authenticated daemon, and retains it for subsequent service-level smokes.

use std::collections::BTreeMap;

use codewire_orchestration::sandbox::client::SandboxClient;
use k8s_openapi::api::core::v1::Pod;
use kube::api::Api;

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let namespace = std::env::var("SMOKE_NAMESPACE").unwrap_or_else(|_| "default".to_string());
    let pod_name = std::env::var("SMOKE_POD_NAME")?;
    anyhow::ensure!(!pod_name.is_empty(), "SMOKE_POD_NAME must not be empty");

    let client = kube::Client::try_default().await?;
    let pods: Api<Pod> = Api::namespaced(client.clone(), &namespace);

    let pod = pods.get(&pod_name).await?;
    anyhow::ensure!(
        pod.status
            .as_ref()
            .and_then(|status| status.conditions.as_ref())
            .is_some_and(|conditions| conditions
                .iter()
                .any(|condition| condition.type_ == "Ready" && condition.status == "True")),
        "workspace exec fixture is not Ready"
    );
    println!("exec-smoke: caller-owned pod ready in {namespace}");

    let sandbox = SandboxClient::new(client, &namespace);

    // 1. stdout + zero exit.
    let r = sandbox
        .exec_workspace_result_on_pod(&pod_name, &argv(&["echo", "hello"]), "", &BTreeMap::new())
        .await?;
    assert_eq!(r.exit_code, 0, "echo exit code: {r:?}");
    assert_eq!(r.stdout, b"hello\n", "echo stdout: {r:?}");
    println!("exec-smoke: stdout capture OK");

    // 2. workdir + env with quoting hazards.
    let mut env = BTreeMap::new();
    env.insert("SMOKE_VAR".to_string(), "it's $HOME `quoted`".to_string());
    let r = sandbox
        .exec_workspace_result_on_pod(
            &pod_name,
            &argv(&["sh", "-c", "pwd && printf '%s' \"$SMOKE_VAR\""]),
            "/tmp",
            &env,
        )
        .await?;
    assert_eq!(r.exit_code, 0, "workdir/env exit code: {r:?}");
    assert_eq!(
        r.stdout, b"/tmp\nit's $HOME `quoted`",
        "workdir/env stdout: {r:?}"
    );
    println!("exec-smoke: workdir + env quoting OK");

    // 3. nonzero exit + stderr.
    let r = sandbox
        .exec_workspace_result_on_pod(
            &pod_name,
            &argv(&["sh", "-c", "echo errout 1>&2; exit 42"]),
            "",
            &BTreeMap::new(),
        )
        .await?;
    assert_eq!(r.exit_code, 42, "exit code propagation: {r:?}");
    assert_eq!(r.stderr, b"errout\n", "stderr capture: {r:?}");
    println!("exec-smoke: exit-code + stderr propagation OK");

    // 4. Successful execution with no output is still an explicit zero exit.
    let r = sandbox
        .exec_workspace_result_on_pod(&pod_name, &argv(&["true"]), "", &BTreeMap::new())
        .await?;
    assert_eq!(r.exit_code, 0);
    assert!(r.stdout.is_empty() && r.stderr.is_empty());
    println!("exec-smoke: PASS");
    Ok(())
}
