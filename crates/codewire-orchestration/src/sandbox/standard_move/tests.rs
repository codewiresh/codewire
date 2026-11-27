//! What a create records, when `standard` is available, and who may move an
//! organization (#5602).

use codewire_server_core::auth::AuthUser;
use serde_json::json;

use super::*;
use crate::egress::own_mode::HostedEgress;
use crate::sandbox::template::{GatewayPeer, HostedEgressTemplate};

const OTHER_IMAGE: &str =
    "ghcr.io/example/own@sha256:9999999999999999999999999999999999999999999999999999999999999999";

fn hosted_egress() -> HostedEgressTemplate {
    HostedEgressTemplate {
        stream_addr: "10.44.0.89:8089".into(),
        binding_addr: "10.44.0.87:8087".into(),
        fence_revision: "4".into(),
        gateway: GatewayPeer {
            namespace: "gateway-proxies".into(),
            gateway_name: "public".into(),
            gateway_namespace: "gateway".into(),
            port: 10443,
        },
        derp_tls_port: 8443,
        gateway_addr: "10.44.0.43:443".into(),
        derp_addr: "derp.example.test=10.44.0.84:8443".into(),
        cluster_dns_ip: "10.44.0.10".into(),
        udp_relay_peers: Vec::new(),
    }
}

/// A standard runtime whose disk boots the canonical workspace image.
fn runtime() -> StandardRuntime {
    let canonical = crate::sandbox::canonical_workspace_runtime_image();
    let (_, digest) = canonical.rsplit_once('@').unwrap();
    StandardRuntime::parse(
        "registry.example.invalid/codewire/pod-runtime@sha256:1111111111111111111111111111111111111111111111111111111111111111",
        &format!(
            "registry.example.invalid/codewire/workspace-disk@sha256:2222222222222222222222222222222222222222222222222222222222222222 \
             3333333333333333333333333333333333333333333333333333333333333333 \
             44444444444444444444444444444444 \
             registry.example.invalid/codewire/workspace@{digest}"
        ),
    )
    .unwrap()
    .unwrap()
}

fn cfg(default: &str, standard: bool, egress: bool) -> SandboxWorkerCfg {
    SandboxWorkerCfg {
        runtime_profile: default.into(),
        standard_runtime: standard.then(runtime),
        hosted_egress: if egress {
            HostedEgress::on(hosted_egress())
        } else {
            HostedEgress::default()
        },
        ..SandboxWorkerCfg::default()
    }
}

fn user(is_admin: bool, via_api_key: bool) -> AuthUser {
    AuthUser {
        user_id: "standard-move-actor".into(),
        org_id: None,
        is_admin,
        via_api_key,
    }
}

#[test]
fn standard_is_available_only_with_its_runtime_its_disk_and_hosted_egress() {
    assert!(available(&cfg(RUNTIME_PROFILE_COMMODITY, true, true)).is_some());
    assert!(available(&cfg(RUNTIME_PROFILE_COMMODITY, false, true)).is_none());
    assert!(available(&cfg(RUNTIME_PROFILE_COMMODITY, true, false)).is_none());
}

#[test]
fn a_create_records_its_profile_from_the_tier_the_move_and_the_image() {
    let canonical = crate::sandbox::canonical_workspace_runtime_image();
    let commodity = cfg(RUNTIME_PROFILE_COMMODITY, true, true);
    for (cfg, tier, image, moved, expected) in [
        // A moved organization's canonical create runs on `standard`.
        (&commodity, "standard", canonical, true, "standard"),
        // Any other image is `commodity`: the VM boots only its disk's image.
        (&commodity, "standard", OTHER_IMAGE, true, "commodity"),
        // An organization that is not moved keeps the deployment's default.
        (&commodity, "standard", canonical, false, "commodity"),
        // Confidential stays confidential in a moved organization.
        (&commodity, "confidential", canonical, true, "confidential"),
    ] {
        assert_eq!(
            create_profile(cfg, tier, image, moved),
            expected,
            "{tier} {image} {moved}"
        );
    }
    // A moved organization on a deployment without `standard` stays on the
    // default.
    let unavailable = cfg(RUNTIME_PROFILE_COMMODITY, true, false);
    assert_eq!(
        create_profile(&unavailable, "standard", canonical, true),
        "commodity"
    );
    // `standard` as the default is every organization's.
    let standard = cfg(RUNTIME_PROFILE_STANDARD, true, true);
    assert_eq!(
        create_profile(&standard, "standard", canonical, false),
        "standard"
    );
    // A local Kind deployment records its diagnostic profile.
    let kind = cfg("none", false, false);
    assert_eq!(create_profile(&kind, "standard", canonical, true), "none");
    // A deployment that names no profile records none, and its starts are
    // refused as before: the create itself still reaches its own checks.
    let unprofiled = cfg("", false, false);
    assert_eq!(create_profile(&unprofiled, "standard", canonical, true), "");
}

#[test]
fn a_live_sandbox_on_another_class_than_its_commodity_record_disagrees() {
    let sandbox = |id: &str, class: &str| {
        serde_json::from_value::<kube::api::DynamicObject>(json!({
            "apiVersion": "agents.x-k8s.io/v1beta1",
            "kind": "Sandbox",
            "metadata": {"name": format!("sandbox-{id}")},
            "spec": {"podTemplate": {
                "metadata": {"labels": {"codewire.sh/environment-id": id}},
                "spec": {"runtimeClassName": class},
            }},
        }))
        .unwrap()
    };
    let sandboxes = [
        sandbox("on-commodity", "commodity"),
        sandbox("on-commodity-32g", "commodity-32g"),
        sandbox("on-standard", "standard"),
    ];
    let recorded = [
        "on-commodity",
        "on-commodity-32g",
        "on-standard",
        "no-sandbox",
    ]
    .map(String::from);
    assert_eq!(disagreeing(&recorded, &sandboxes), ["on-standard"]);
}

fn lazy_pool() -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://refused.invalid/none")
        .unwrap()
}

#[tokio::test]
async fn only_a_global_administrator_moves_or_lists_an_organization() {
    let pool = lazy_pool();
    let available = cfg(RUNTIME_PROFILE_COMMODITY, true, true);
    // An organization administrator, and an API key even of a global
    // administrator, are refused before the database is read.
    for caller in [user(false, false), user(true, true)] {
        let refused = set_core(&pool, &available, &caller, "org", true)
            .await
            .expect_err("a move by a caller who is not a global administrator");
        assert!(
            matches!(refused, AppError::Forbidden | AppError::Coded { .. }),
            "{refused:?}"
        );
        assert!(list_core(&pool, &caller).await.is_err());
    }
}

#[tokio::test]
async fn no_organization_is_moved_onto_standard_while_the_deployment_lacks_it() {
    let pool = lazy_pool();
    for unavailable in [
        cfg(RUNTIME_PROFILE_COMMODITY, false, true),
        cfg(RUNTIME_PROFILE_COMMODITY, true, false),
    ] {
        let refused = set_core(&pool, &unavailable, &user(true, false), "org", true)
            .await
            .expect_err("a move onto an unavailable standard");
        assert!(
            matches!(
                &refused,
                AppError::Coded {
                    code: "standard_runtime_unavailable",
                    ..
                }
            ),
            "{refused:?}"
        );
    }
}
