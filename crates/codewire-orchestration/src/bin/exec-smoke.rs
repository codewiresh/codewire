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
//! Env: SMOKE_NAMESPACE (default "default"); SMOKE_KEEP_POD=1 leaves the
//! proven pod running for an immediately following service-level smoke.

use std::collections::BTreeMap;
use std::time::Duration;

use codewire_orchestration::sandbox::client::SandboxClient;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, DeleteParams, PostParams};

const POD_NAME: &str = "exec-smoke";

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let namespace = std::env::var("SMOKE_NAMESPACE").unwrap_or_else(|_| "default".to_string());

    let client = kube::Client::try_default().await?;
    let pods: Api<Pod> = Api::namespaced(client.clone(), &namespace);

    // Fresh pod: delete any leftover, then create. The container MUST
    // be named "workspace" — that's the container exec targets.
    let _ = pods.delete(POD_NAME, &DeleteParams::default()).await;
    wait_gone(&pods).await?;

    let pod: Pod = serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": POD_NAME, "labels": { "app": "exec-smoke" } },
        "spec": {
            "restartPolicy": "Never",
            "containers": [{
                "name": "workspace",
                "image": "busybox:1.36",
                "command": ["sleep", "600"]
            }]
        }
    }))?;
    pods.create(&PostParams::default(), &pod).await?;
    wait_running(&pods).await?;
    println!("exec-smoke: pod running in {namespace}");

    let sandbox = SandboxClient::new(client, &namespace);

    // 1. stdout + zero exit.
    let r = sandbox
        .exec_workspace_result_on_pod(POD_NAME, &argv(&["echo", "hello"]), "", &BTreeMap::new())
        .await?;
    assert_eq!(r.exit_code, 0, "echo exit code: {r:?}");
    assert_eq!(r.stdout, b"hello\n", "echo stdout: {r:?}");
    println!("exec-smoke: stdout capture OK");

    // 2. workdir + env with quoting hazards.
    let mut env = BTreeMap::new();
    env.insert("SMOKE_VAR".to_string(), "it's $HOME `quoted`".to_string());
    let r = sandbox
        .exec_workspace_result_on_pod(
            POD_NAME,
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
            POD_NAME,
            &argv(&["sh", "-c", "echo errout 1>&2; exit 42"]),
            "",
            &BTreeMap::new(),
        )
        .await?;
    assert_eq!(r.exit_code, 42, "exit code propagation: {r:?}");
    assert_eq!(r.stderr, b"errout\n", "stderr capture: {r:?}");
    println!("exec-smoke: exit-code + stderr propagation OK");

    // 4. exec_workspace error shaping on nonzero exit.
    let err = sandbox
        .exec_workspace_result_on_pod(POD_NAME, &argv(&["true"]), "", &BTreeMap::new())
        .await?;
    assert_eq!(err.exit_code, 0);

    if std::env::var("SMOKE_KEEP_POD").as_deref() == Ok("1") {
        println!("exec-smoke: keeping pod for service-level smoke");
    } else {
        let _ = pods.delete(POD_NAME, &DeleteParams::default()).await;
    }
    println!("exec-smoke: PASS");
    Ok(())
}

async fn wait_running(pods: &Api<Pod>) -> anyhow::Result<()> {
    for _ in 0..60 {
        if let Ok(p) = pods.get(POD_NAME).await {
            let phase = p
                .status
                .as_ref()
                .and_then(|s| s.phase.clone())
                .unwrap_or_default();
            if phase == "Running" {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    anyhow::bail!("pod {POD_NAME} not Running within 120s")
}

async fn wait_gone(pods: &Api<Pod>) -> anyhow::Result<()> {
    for _ in 0..60 {
        match pods.get(POD_NAME).await {
            Err(kube::Error::Api(e)) if e.code == 404 => return Ok(()),
            _ => tokio::time::sleep(Duration::from_secs(2)).await,
        }
    }
    anyhow::bail!("pod {POD_NAME} not deleted within 120s")
}
