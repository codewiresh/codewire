#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::Output;
use std::time::Duration;

use codewire_mesh::{Config as MeshConfig, LocalMeshAuthorizationConfig};
use codewire_server_core::auth::hash_api_key;
use tokio::process::Command;

const ORG: &str = "org-network-delete";
const KEY: &str = "cw_synthetic-network-delete-owner";

async fn cw(root: &Path, mesh_url: &str, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cw"));
    command
        .env_clear()
        .env("HOME", root)
        .env("CW_CONFIG_DIR", root.join("platform"))
        .env("CODEWIRE_MESH_URL", mesh_url)
        .env("CODEWIRE_MESH_AUTH_TOKEN", KEY)
        .current_dir(root)
        .args(args)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(10), command.output())
        .await
        .expect("CLI command timed out")
        .expect("run normal cw")
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[tokio::test]
async fn public_network_delete_requires_confirmation_and_cleans_only_its_network() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mesh_url = format!("http://{address}");
    let app = codewire_mesh::router(MeshConfig {
        bind_addr: address,
        base_url: mesh_url.clone(),
        derp_url: Some("http://127.0.0.1:9".into()),
        stun_servers: Vec::new(),
        database_url: None,
        mesh_authorization: None,
        local_authorization: Some(LocalMeshAuthorizationConfig {
            organization_id: ORG.into(),
            api_key_hash: hash_api_key(KEY),
        }),
    });
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let root = tempfile::tempdir().unwrap();
    let run = |args| cw(root.path(), &mesh_url, args);

    success(run(&["network", "create", "keep", "--org", ORG, "--no-use"]).await);
    success(run(&["network", "create", "remove", "--org", ORG]).await);
    let unconfirmed = run(&["network", "delete", "remove", "--org", ORG]).await;
    assert!(!unconfirmed.status.success());
    assert!(String::from_utf8_lossy(&unconfirmed.stderr).contains("requires --yes"));
    assert_eq!(success(run(&["network", "current"]).await).trim(), "remove");

    let denied = run(&["network", "delete", "remove", "--org", "wrong-org", "--yes"]).await;
    assert!(!denied.status.success());
    assert_eq!(success(run(&["network", "current"]).await).trim(), "remove");
    let before = success(run(&["network", "list", "--org", ORG, "--output", "json"]).await);
    assert!(before.contains("remove") && before.contains("keep"));

    success(run(&["network", "delete", "remove", "--org", ORG, "--yes"]).await);
    assert_eq!(success(run(&["network", "current"]).await).trim(), "none");
    let after = success(run(&["network", "list", "--org", ORG, "--output", "json"]).await);
    assert!(!after.contains("remove") && after.contains("keep"));
    let reused = run(&["network", "create", "remove", "--org", ORG, "--no-use"]).await;
    assert!(!reused.status.success());
    assert!(String::from_utf8_lossy(&reused.stderr).contains("cannot be reused"));
    server.abort();
}
