//! Real admission/controller proof, selected only by the managed Kind harness.
//! The administrator reads only the synthetic leaves this test just created.
//! All product bootstrap operations use the deployed orchestration identity.

use super::*;
use crate::sandbox::template::CredentialRuntimeTemplateConfig;
use anyhow::{Result, ensure};
use kube::config::{KubeConfigOptions, Kubeconfig};
use serde_json::json;

const NAMESPACE: &str = "dev-sandboxes";
const SERVICE_ACCOUNT: &str = "system:serviceaccount:codewire-e2e:codewire-orchestration";

#[tokio::test]
#[ignore = "requires the managed disposable Kind cluster and real cert-manager fixture"]
async fn credential_bootstrap_kind() -> Result<()> {
    ensure!(
        std::env::var("CODEWIRE_KIND_CREDENTIAL_BOOTSTRAP").as_deref() == Ok("1"),
        "managed Kind bootstrap selection required"
    );
    let context = std::env::var("CODEWIRE_KIND_CONTEXT")?;
    ensure!(
        context.starts_with("kind-codewire-"),
        "expected managed Kind context"
    );
    // Never fall back to an ambient kubeconfig or in-cluster identity.
    let path = std::env::var("KUBECONFIG")?;
    let kubeconfig = Kubeconfig::read_from(path)?;
    ensure!(
        kubeconfig.current_context.as_deref() == Some(&context),
        "Kind context differs"
    );
    let config = kube::Config::from_custom_kubeconfig(
        kubeconfig,
        &KubeConfigOptions {
            context: Some(context),
            ..Default::default()
        },
    )
    .await?;
    let admin = SandboxClient::new(Client::try_from(config.clone())?, NAMESPACE);
    let mut restricted = config;
    restricted.auth_info.impersonate = Some(SERVICE_ACCOUNT.into());
    restricted.auth_info.impersonate_groups = Some(vec![
        "system:authenticated".into(),
        "system:serviceaccounts".into(),
        "system:serviceaccounts:codewire-e2e".into(),
    ]);
    let orchestration = SandboxClient::new(Client::try_from(restricted)?, NAMESPACE);
    let opts = TemplateOpts {
        environment_id: uuid::Uuid::new_v4().to_string(),
        organization_id: "kind-credential-bootstrap-synthetic".into(),
        operation_generation: 7,
        credential_runtime: Some(CredentialRuntimeTemplateConfig::synthetic(NAMESPACE)),
        ..Default::default()
    };
    let result = prove_bootstrap(&admin, &orchestration, &opts).await;
    // Cleanup uses only exact random names owned by this test, including a
    // finalizer used below to observe DELETE admission after the issuer object
    // is gone. Preserve the original assertion failure if cleanup also fails.
    let cleanup = cleanup(&admin, &opts.environment_id).await;
    result?;
    cleanup?;
    println!(
        "credential bootstrap Kind: issuance, no-op retry, RBAC, admission and cleanup passed"
    );
    Ok(())
}

async fn prove_bootstrap(
    admin: &SandboxClient,
    orchestration: &SandboxClient,
    opts: &TemplateOpts,
) -> Result<()> {
    let name = credential_gateway_certificate_name(&opts.environment_id);
    let config_name = credential_codex_config_name(&opts.environment_id);
    orchestration.ensure_credential_bootstrap(opts).await?;
    let certificate = issued(orchestration, &name).await?;
    let rendered = render_credential_gateway_certificate(NAMESPACE, opts).unwrap();
    ensure!(
        certificate.data["spec"] == rendered["spec"],
        "API defaulting changed certificate intent"
    );
    let config = orchestration
        .credential_config_maps()
        .get(&config_name)
        .await?;
    orchestration.ensure_credential_bootstrap(opts).await?;
    let retried = orchestration.credential_certificates().get(&name).await?;
    // cert-manager may advance status/resourceVersion independently. The
    // counted unit test proves GET-only retries; live proof checks the exact
    // persisted intent and identity without mistaking a status write for ours.
    ensure!(
        certificate.metadata.uid == retried.metadata.uid
            && certificate.metadata.generation == retried.metadata.generation
            && certificate.data["spec"] == retried.data["spec"],
        "unchanged bootstrap retry changed Certificate identity or intent"
    );
    ensure!(
        config.metadata.resource_version
            == orchestration
                .credential_config_maps()
                .get(&config_name)
                .await?
                .metadata
                .resource_version,
        "unchanged bootstrap retry wrote ConfigMap"
    );

    let leaf = admin.secrets().get(&name).await?;
    ensure!(
        leaf.data["type"] == "kubernetes.io/tls",
        "issued leaf has wrong type"
    );
    ensure!(
        leaf.metadata
            .owner_references
            .as_ref()
            .is_some_and(|owners| owners.iter().any(|owner| owner.api_version
                == "cert-manager.io/v1"
                && owner.kind == "Certificate"
                && owner.name == name
                && Some(&owner.uid) == certificate.metadata.uid.as_ref()
                && owner.controller == Some(true))),
        "cert-manager did not bind leaf ownership"
    );
    ensure!(
        leaf.data["data"]["tls.crt"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
            && leaf.data["data"]["tls.key"]
                .as_str()
                .is_some_and(|v| !v.is_empty()),
        "issued TLS leaf is incomplete"
    );
    denied(orchestration.secrets().get(&name).await, "Secret read").await?;
    denied(
        orchestration.secrets().list(&ListParams::default()).await,
        "Secret list",
    )
    .await?;
    let metadata_result = orchestration.secrets().get_metadata(&name).await;
    denied(metadata_result, "metadata-only Secret read").await?;
    for (field, value) in [
        ("isCA", json!(true)),
        ("dnsNames", json!(["foreign.example.test"])),
        ("uris", json!(["spiffe://foreign.example.test/workload"])),
        (
            "issuerRef",
            json!({"name":"foreign","kind":"Issuer","group":"cert-manager.io"}),
        ),
        (
            "privateKey",
            json!({"algorithm":"ECDSA","size":384,"encoding":"PKCS8","rotationPolicy":"Always"}),
        ),
        (
            "privateKey",
            json!({"algorithm":"ECDSA","size":256,"encoding":"PKCS8","rotationPolicy":"Never"}),
        ),
    ] {
        let mut invalid = orchestration.credential_certificates().get(&name).await?;
        invalid.data["spec"][field] = value;
        admission_denied(
            orchestration
                .credential_certificates()
                .replace(&name, &PostParams::default(), &invalid)
                .await,
            if field == "uris" {
                "credential leaves cannot request alternate subjects, identities, outputs or Secret annotations"
            } else {
                "only the exact environment gateway leaf under the dedicated Issuer may be requested"
            },
        )
        .await?;
    }
    denied(
        orchestration
            .secrets()
            .replace(&name, &PostParams::default(), &leaf)
            .await,
        "Secret overwrite",
    )
    .await?;
    let mut invalid_config = config;
    invalid_config.data["data"]["roots.pem"] = json!("synthetic-not-a-root");
    admission_denied(
        orchestration
            .credential_config_maps()
            .replace(&config_name, &PostParams::default(), &invalid_config)
            .await,
        "only the per-environment public Codex config is writable; public trust bundles are not",
    )
    .await?;

    // Keep this real issued leaf observable after its real Certificate is
    // absent. The fixture-only finalizer does not confer cleanup authority.
    admin
        .secrets()
        .patch(
            &name,
            &PatchParams::default(),
            &Patch::Merge(json!({
                "metadata":{"finalizers":["codewire.sh/kind-credential-proof"]}
            })),
        )
        .await?;
    orchestration
        .credential_certificates()
        .delete(
            &name,
            &DeleteParams {
                propagation_policy: Some(kube::api::PropagationPolicy::Background),
                preconditions: Some(Preconditions {
                    uid: certificate.metadata.uid,
                    resource_version: None,
                }),
                ..Default::default()
            },
        )
        .await?;
    absent(&orchestration.credential_certificates(), &name).await?;
    ensure!(
        admin.secrets().get_opt(&name).await?.is_some(),
        "proof leaf vanished before DELETE admission"
    );
    orchestration
        .secrets()
        .delete(&name, &DeleteParams::default())
        .await?;
    admin
        .secrets()
        .patch(
            &name,
            &PatchParams::default(),
            &Patch::Merge(json!({
                "metadata":{"finalizers":null}
            })),
        )
        .await?;
    absent(&admin.secrets(), &name).await?;

    // Same namespace and prefix do not authorize deleting a foreign or
    // orphan leaf. No Certificate exists at this point. These contain only
    // fixed synthetic non-key bytes and are removed by the administrator.
    for managed in [false, true] {
        let mut foreign: DynamicObject = serde_json::from_value(json!({
            "apiVersion":"v1", "kind":"Secret", "metadata":{"name":name,"namespace":NAMESPACE},
            "type":"kubernetes.io/tls", "stringData":{"tls.crt":"synthetic","tls.key":"synthetic"}
        }))?;
        if managed {
            foreign.metadata.labels = leaf.metadata.labels.clone();
            admission_denied(
                orchestration
                    .secrets()
                    .create(&PostParams::default(), &foreign)
                    .await,
                "only cert-manager may write credential leaf Secrets",
            )
            .await?;
        }
        admin
            .secrets()
            .create(&PostParams::default(), &foreign)
            .await?;
        admission_denied(
            orchestration
                .secrets()
                .delete(&name, &DeleteParams::default())
                .await,
            "deleting a credential leaf requires its existing exact managed Certificate ownership",
        )
        .await?;
        admin
            .secrets()
            .delete(&name, &DeleteParams::default())
            .await?;
        absent(&admin.secrets(), &name).await?;
    }
    // Exercise the production destroy helper and its idempotent retry, then
    // re-create and destroy once more with normal foreground issuance cleanup.
    orchestration
        .delete_credential_bootstrap(&opts.environment_id, Duration::from_secs(30))
        .await?;
    orchestration.ensure_credential_bootstrap(opts).await?;
    let reissued = issued(orchestration, &name).await?;
    ensure!(
        reissued.metadata.uid != retried.metadata.uid,
        "recreated Certificate reused its old identity"
    );
    let reissued_leaf = admin.secrets().get(&name).await?;
    ensure!(
        reissued_leaf
            .metadata
            .owner_references
            .as_ref()
            .is_some_and(|owners| owners.iter().any(|owner| owner.api_version
                == "cert-manager.io/v1"
                && owner.kind == "Certificate"
                && owner.name == name
                && Some(&owner.uid) == reissued.metadata.uid.as_ref()
                && owner.controller == Some(true))),
        "foreground cleanup lacks a real newly issued leaf"
    );
    orchestration
        .delete_credential_bootstrap(&opts.environment_id, Duration::from_secs(30))
        .await?;
    orchestration
        .delete_credential_bootstrap(&opts.environment_id, Duration::from_secs(30))
        .await?;
    absent(&admin.credential_certificates(), &name).await?;
    absent(&admin.secrets(), &name).await?;
    absent(&admin.credential_config_maps(), &config_name).await
}

async fn issued(client: &SandboxClient, name: &str) -> Result<DynamicObject> {
    Ok(tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let certificate = client.credential_certificates().get(name).await?;
            if certificate_ready(&certificate) {
                return Ok::<_, kube::Error>(certificate);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await??)
}

async fn denied<T>(result: Result<T, kube::Error>, action: &str) -> Result<()> {
    ensure!(
        matches!(result, Err(kube::Error::Api(ref error)) if error.code == 403),
        "{action} did not receive the required authorization denial"
    );
    Ok(())
}

async fn admission_denied<T>(result: Result<T, kube::Error>, message: &str) -> Result<()> {
    ensure!(
        matches!(result, Err(kube::Error::Api(ref error))
        if error.code == 403 && error.message.contains(message)),
        "expected credential admission denial was not observed: {message}"
    );
    Ok(())
}

async fn absent(api: &Api<DynamicObject>, name: &str) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if api.get_opt(name).await?.is_none() {
                return Ok::<_, kube::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await??;
    Ok(())
}

async fn cleanup(admin: &SandboxClient, environment: &str) -> Result<()> {
    let name = credential_gateway_certificate_name(environment);
    if admin.secrets().get_opt(&name).await?.is_some() {
        admin
            .secrets()
            .patch(
                &name,
                &PatchParams::default(),
                &Patch::Merge(json!({"metadata":{"finalizers":null}})),
            )
            .await?;
    }
    for (api, name) in [
        (admin.credential_certificates(), name.clone()),
        (admin.secrets(), name),
        (
            admin.credential_config_maps(),
            credential_codex_config_name(environment),
        ),
    ] {
        match api.delete(&name, &DeleteParams::default()).await {
            Ok(_) => {}
            Err(kube::Error::Api(error)) if error.code == 404 => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
