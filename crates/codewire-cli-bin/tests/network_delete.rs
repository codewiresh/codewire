#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::Output;
use std::sync::Arc;
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
    let app = mesh_router(organization, key, address);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (mesh_url, server)
}

/// The Mesh service's routes at `address`, admitting one organization's key.
fn mesh_router(organization: &str, key: &str, address: std::net::SocketAddr) -> axum::Router {
    let mesh_url = format!("http://{address}");
    codewire_mesh::router(MeshConfig {
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
    })
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

/// A cloud create's `--network`: `local:NAME` is refused before the CLI
/// sends any request. A cloud network is checked first with the user's own
/// sign-in, by listing the networks they belong to; one they are not a member
/// of is refused with nothing created, and only a member's create is sent.
#[tokio::test]
async fn cloud_create_checks_mesh_membership_before_it_creates() {
    use buffa::Message as _;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_url = format!("http://{address}");
    // The platform's organization list; the hosted Mesh is the platform
    // origin itself; anything else, such as the create, is not implemented.
    let organizations = codewire_client::ListOrganizationsResponse {
        organizations: vec![codewire_client::OrganizationMembership {
            organization: Some(codewire_client::Organization {
                id: ORG.into(),
                name: "Network delete".into(),
                slug: ORG.into(),
                ..Default::default()
            })
            .into(),
            role: codewire_client::OrgRole::Owner.into(),
            ..Default::default()
        }],
        ..Default::default()
    }
    .encode_to_vec();
    let requests = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let recorded = requests.clone();
    let mesh = mesh_router(ORG, KEY, address);
    let app = axum::Router::new()
        .route(
            "/codewire.v1.OrganizationService/ListOrganizations",
            axum::routing::post(move || {
                let body = organizations.clone();
                async move { ([("content-type", "application/proto")], body) }
            }),
        )
        .route(
            "/codewire.v1.EnvironmentService/CreateEnvironment",
            axum::routing::post(|| async { axum::http::StatusCode::NOT_IMPLEMENTED }),
        )
        .fallback_service(mesh)
        .layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let recorded = recorded.clone();
                async move {
                    recorded
                        .lock()
                        .unwrap()
                        .push(request.uri().path().to_owned());
                    next.run(request).await
                }
            },
        ));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let root = tempfile::tempdir().unwrap();
    let run = |args| cw(root.path(), &server_url, &[], args);
    let create = |network: &'static str| {
        let (root, server_url) = (root.path().to_owned(), server_url.clone());
        async move {
            let args = [
                "--cloud",
                "create",
                "--name",
                "mesh-membership",
                "--network",
                network,
            ];
            cw(&root, &server_url, &[], &args).await
        }
    };
    success(
        run(&[
            "--cloud", "network", "create", "work", "--org", ORG, "--no-use",
        ])
        .await,
    );
    let sent = || std::mem::take(&mut *requests.lock().unwrap());
    sent();

    let local = create("local:work").await;
    let stderr = String::from_utf8_lossy(&local.stderr);
    assert!(!local.status.success(), "{stderr}");
    assert!(
        stderr.contains("cannot join the local Mesh service"),
        "{stderr}"
    );
    assert!(stderr.contains("No environment was created"), "{stderr}");
    assert_eq!(sent(), Vec::<String>::new(), "local:NAME sent a request");

    for network in ["cloud:absent", "absent"] {
        let refused = create(network).await;
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(!refused.status.success(), "{stderr}");
        assert!(
            stderr.contains("you are not a member of Codewire Cloud Mesh network cloud:absent"),
            "{stderr}"
        );
        assert!(stderr.contains("No environment was created"), "{stderr}");
        let paths = sent();
        assert!(
            paths.iter().any(|path| path.ends_with("/ListMeshNetworks")),
            "{paths:?}"
        );
        assert!(
            !paths
                .iter()
                .any(|path| path.ends_with("/CreateEnvironment")),
            "a non-member's create was sent: {paths:?}"
        );
    }

    // A member's create is sent, after the membership check.
    let member = create("cloud:work").await;
    assert!(!member.status.success());
    let paths = sent();
    let listed = paths
        .iter()
        .position(|path| path.ends_with("/ListMeshNetworks"));
    let created = paths
        .iter()
        .position(|path| path.ends_with("/CreateEnvironment"));
    assert!(
        matches!((listed, created), (Some(listed), Some(created)) if listed < created),
        "{paths:?}"
    );
    server.abort();
}
