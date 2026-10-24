#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::Output;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use codewire_mesh::{Config as MeshConfig, LocalMeshAuthorizationConfig};
use codewire_server_core::auth::hash_api_key;
use tokio::process::Command;

const ORG: &str = "org-network-delete";
const KEY: &str = "cw_synthetic-network-delete-owner";
const OTHER_ORG: &str = "org-network-other";
const OTHER_KEY: &str = "cw_synthetic-network-other-owner";

/// A Mesh service that admits one organization's synthetic key.
async fn mesh(organization: &str, key: &str) -> (String, tokio::task::JoinHandle<()>) {
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
        derp_verify_addr: None,
        local_authorization: Some(LocalMeshAuthorizationConfig {
            organization_id: organization.into(),
            api_key_hash: hash_api_key(key),
        }),
    });
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (mesh_url, server)
}

/// `cw` signed in to a platform at `server`: a non-codewire.sh platform's
/// hosted Mesh is the platform origin itself, so `--cloud` reaches the Mesh
/// service there with the platform credential.
async fn cw(root: &Path, server: &str, environment: &[(&str, &str)], args: &[&str]) -> Output {
    let platform = root.join("platform");
    std::fs::create_dir_all(&platform).unwrap();
    std::fs::write(
        platform.join("config.json"),
        format!(r#"{{"server_url":"{server}","default_org":"{ORG}"}}"#),
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_cw"));
    command
        .env_clear()
        .env("HOME", root)
        .env("CW_CONFIG_DIR", &platform)
        .env("CODEWIRE_API_KEY", KEY)
        .envs(environment.iter().copied())
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
    let (mesh_url, server) = mesh(ORG, KEY).await;
    let (other_url, other) = mesh(OTHER_ORG, OTHER_KEY).await;
    let root = tempfile::tempdir().unwrap();
    let run = |args| cw(root.path(), &mesh_url, &[], args);
    let other_env = [("CODEWIRE_MESH_AUTH_TOKEN", OTHER_KEY)];

    success(
        run(&[
            "--cloud", "network", "create", "keep", "--org", ORG, "--no-use",
        ])
        .await,
    );
    let created = success(run(&["--cloud", "network", "create", "remove", "--org", ORG]).await);
    assert!(created.contains("Network remove created"), "{created}");
    assert!(
        created.contains("  Mesh          Codewire Cloud Mesh\n"),
        "{created}"
    );
    assert!(
        created.contains(&format!("  Endpoint      {mesh_url}\n")),
        "{created}"
    );
    assert!(
        created.contains("Selected for new environments"),
        "{created}"
    );
    // The same name on a second Mesh endpoint is a different network.
    success(
        cw(
            root.path(),
            &mesh_url,
            &other_env,
            &[
                "network",
                "create",
                "remove",
                "--org",
                OTHER_ORG,
                "--no-use",
                "--mesh-url",
                &other_url,
            ],
        )
        .await,
    );
    assert_eq!(
        success(run(&["network", "current"]).await).lines().next(),
        Some("remove")
    );

    let unconfirmed = run(&["--cloud", "network", "delete", "remove", "--org", ORG]).await;
    assert!(!unconfirmed.status.success());
    assert!(String::from_utf8_lossy(&unconfirmed.stderr).contains("requires --yes"));
    let denied = run(&[
        "--cloud",
        "network",
        "delete",
        "remove",
        "--org",
        "wrong-org",
        "--yes",
    ])
    .await;
    assert!(!denied.status.success());
    // Deleting the same name on the other Mesh keeps this selection.
    success(
        cw(
            root.path(),
            &mesh_url,
            &other_env,
            &[
                "network",
                "delete",
                "remove",
                "--org",
                OTHER_ORG,
                "--yes",
                "--mesh-url",
                &other_url,
            ],
        )
        .await,
    );
    assert_eq!(
        success(run(&["network", "current"]).await).lines().next(),
        Some("remove")
    );
    let before = success(
        run(&[
            "--cloud", "network", "list", "--org", ORG, "--output", "json",
        ])
        .await,
    );
    assert!(before.contains("remove") && before.contains("keep"));

    let deleted = success(
        run(&[
            "--cloud", "network", "delete", "remove", "--org", ORG, "--yes",
        ])
        .await,
    );
    assert!(deleted.contains("Network remove deleted"), "{deleted}");
    assert!(
        deleted.contains("Its saved selection was cleared."),
        "{deleted}"
    );
    assert_eq!(
        success(run(&["network", "current"]).await).trim(),
        "No network is selected."
    );
    let after = success(
        run(&[
            "--cloud", "network", "list", "--org", ORG, "--output", "json",
        ])
        .await,
    );
    assert!(!after.contains("remove") && after.contains("keep"));
    let reused = run(&[
        "--cloud", "network", "create", "remove", "--org", ORG, "--no-use",
    ])
    .await;
    assert!(!reused.status.success());
    assert!(String::from_utf8_lossy(&reused.stderr).contains("cannot be reused"));
    server.abort();
    other.abort();
}

#[tokio::test]
async fn network_use_selects_only_an_existing_network_in_the_owner_organization() {
    let (mesh_url, server) = mesh(ORG, KEY).await;
    let root = tempfile::tempdir().unwrap();
    let run = |args| cw(root.path(), &mesh_url, &[], args);

    success(
        run(&[
            "--cloud", "network", "create", "work", "--org", ORG, "--no-use",
        ])
        .await,
    );
    let missing = run(&["--cloud", "network", "use", "absent"]).await;
    assert!(!missing.status.success());
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("nothing was selected"),
        "{}",
        String::from_utf8_lossy(&missing.stderr)
    );
    let selected = success(run(&["--cloud", "network", "use", "work", "--auto-connect"]).await);
    assert!(selected.contains("Selected network work"), "{selected}");
    assert!(
        selected.contains(&format!("  Organization  {ORG}\n")),
        "{selected}"
    );
    let saved: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.path().join(".codewire/network_selection.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        saved,
        serde_json::json!({
            "schema_version": 1,
            "mesh": "cloud",
            "mesh_url": mesh_url,
            "organization_id": ORG,
            "network_id": "work",
            "auto_connect": true,
        })
    );
    // --cloud and --mesh-url are one choice; both is refused.
    let both = cw(
        root.path(),
        &mesh_url,
        &[],
        &[
            "--cloud",
            "network",
            "list",
            "--org",
            ORG,
            "--mesh-url",
            &mesh_url,
        ],
    )
    .await;
    assert!(!both.status.success());
    // The local Mesh service is not running: --local never falls back.
    let local = run(&["--local", "network", "list", "--org", ORG]).await;
    assert!(!local.status.success());
    assert!(String::from_utf8_lossy(&local.stderr).contains("cw mesh up"));
    server.abort();
}

/// An explicit `--network` on a cloud create is refused before the CLI
/// sends any request, so nothing can be allocated.
#[tokio::test]
async fn cloud_create_refuses_mesh_attachment_before_any_request() {
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_url = format!("http://{}", listener.local_addr().unwrap());
    let app = axum::Router::new().fallback(move || {
        let counted = counted.clone();
        async move {
            counted.fetch_add(1, Ordering::SeqCst);
            axum::http::StatusCode::NOT_IMPLEMENTED
        }
    });
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let root = tempfile::tempdir().unwrap();
    for (network, expected) in [
        (
            "cloud:work",
            "cannot join Codewire Cloud Mesh network cloud:work",
        ),
        ("work", "cannot join Codewire Cloud Mesh network cloud:work"),
        ("local:work", "cannot join the local Mesh service"),
    ] {
        let refused = cw(
            root.path(),
            &server_url,
            &[],
            &[
                "--cloud",
                "create",
                "--name",
                "mesh-refusal",
                "--network",
                network,
            ],
        )
        .await;
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(!refused.status.success(), "{stderr}");
        assert!(stderr.contains(expected), "{stderr}");
        assert!(stderr.contains("No environment was created"), "{stderr}");
    }
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    server.abort();
}
