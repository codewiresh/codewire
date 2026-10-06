//! Real admission/controller proof, selected only by the managed Kind harness.
//! The administrator reads only the synthetic leaves this test just created.
//! The legacy bootstrap objects an environment created before the gateway's
//! HTTPS listener was removed are planted, and every product cleanup runs,
//! with the deployed orchestration identity.

use super::*;
use crate::sandbox::template::CredentialRuntimeTemplateConfig;
use anyhow::{Context, Result, ensure};
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
    let opts =
        TemplateOpts {
            environment_id: uuid::Uuid::new_v4().to_string(),
            organization_id: "kind-credential-bootstrap-synthetic".into(),
            operation_generation: 7,
            managed_credential_clients:
                codewire_access::ManagedCredentialClients::from_profile_slots(["codex"]).unwrap(),
            projection_selection_sha256: Some([0xab; 32]),
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
    println!("credential bootstrap Kind: legacy issuance, RBAC, admission and cleanup passed");
    Ok(())
}

/// The exact gateway Certificate the previous orchestration requested, which
/// the kept admission policy still admits for the orchestration identity.
fn legacy_certificate(opts: &TemplateOpts) -> Value {
    let name = credential_gateway_certificate_name(&opts.environment_id);
    let labels = json!({"app.kubernetes.io/name":"codewire", "app.kubernetes.io/managed-by":"codewire",
        "codewire.sh/environment-id":opts.environment_id, "codewire.sh/org-id":opts.organization_id,
        "codewire.sh/type":"credential-bootstrap"});
    json!({"apiVersion":"cert-manager.io/v1", "kind":"Certificate",
        "metadata":{"name":name,"namespace":NAMESPACE,"labels":labels},
        "spec":{"secretName":name, "secretTemplate":{"labels":labels},
            "issuerRef":{"name":"codewire-credential-gateway","kind":"Issuer","group":"cert-manager.io"},
            "dnsNames":[format!("cw-gateway-svc-{}.{NAMESPACE}.svc.cluster.local", opts.environment_id)],
            "duration":"24h", "renewBefore":"8h",
            "privateKey":{"algorithm":"ECDSA","size":256,"encoding":"PKCS8","rotationPolicy":"Always"},
            "isCA":false,"revisionHistoryLimit":1,
            "usages":["digital signature","server auth"]}})
}

async fn plant_legacy_certificate(
    orchestration: &SandboxClient,
    opts: &TemplateOpts,
) -> Result<DynamicObject> {
    let legacy: DynamicObject = serde_json::from_value(legacy_certificate(opts))?;
    orchestration
        .credential_certificates()
        .create(&PostParams::default(), &legacy)
        .await?;
    issued(
        orchestration,
        &credential_gateway_certificate_name(&opts.environment_id),
    )
    .await
}

async fn prove_bootstrap(
    admin: &SandboxClient,
    orchestration: &SandboxClient,
    opts: &TemplateOpts,
) -> Result<()> {
    let name = credential_gateway_certificate_name(&opts.environment_id);
    let config_name = credential_codex_config_name(&opts.environment_id);
    // Nothing creates a gateway Certificate now. An environment created before
    // the gateway's HTTPS listener was removed still owns one, which the kept
    // admission policy and final destruction must handle. Plant it the way
    // the previous orchestration created it.
    let certificate = plant_legacy_certificate(orchestration, opts).await?;
    ensure!(
        certificate.data["spec"] == legacy_certificate(opts)["spec"],
        "API defaulting changed certificate intent"
    );
    // Selected Codex creates no ConfigMap either: the workspace daemon writes
    // `~/.codex`. Plant an earlier environment's ConfigMap the same way.
    let legacy: DynamicObject = serde_json::from_value(json!({
        "apiVersion":"v1", "kind":"ConfigMap",
        "metadata":{"name":config_name,"namespace":NAMESPACE,"labels":certificate.metadata.labels},
        "data":{"config.toml":"model_provider = \"codewire_openai\"\n"}
    }))?;
    let config = orchestration
        .credential_config_maps()
        .create(&PostParams::default(), &legacy)
        .await?;

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
        .await
        .with_context(|| format!("Certificate {field} mutation"))?;
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
                    uid: certificate.metadata.uid.clone(),
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
            // Both independent policies forbid CREATE. Kubernetes may report
            // either first; this proves composed denial, not their ordering.
            admission_denied_by(
                orchestration
                    .secrets()
                    .create(&PostParams::default(), &foreign)
                    .await,
                &[
                    "only cert-manager may write credential leaf Secrets",
                    "codewire-orchestration may only create or delete gateway host-key Secrets, or delete an independently validated credential leaf",
                ],
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
    // Re-create and destroy once more with a real leaf. Hold that leaf's
    // deletion so the ordering is deterministic: the issuing Certificate must
    // disappear first, and cleanup must still wait for the leaf to disappear.
    // Foreground Certificate deletion instead keeps the issuer intent visible
    // while cert-manager can react to dependent removal by starting issuance.
    orchestration
        .delete_credential_bootstrap(&opts.environment_id, Duration::from_secs(30))
        .await?;
    let reissued = plant_legacy_certificate(orchestration, opts).await?;
    ensure!(
        reissued.metadata.uid != certificate.metadata.uid,
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
        "cleanup lacks a real newly issued leaf"
    );
    admin
        .secrets()
        .patch(
            &name,
            &PatchParams::default(),
            &Patch::Merge(json!({"metadata":{"finalizers":["codewire.sh/kind-cleanup-proof"]}})),
        )
        .await?;
    let deletion =
        orchestration.delete_credential_bootstrap(&opts.environment_id, Duration::from_secs(30));
    tokio::pin!(deletion);
    let certificates = orchestration.credential_certificates();
    tokio::select! {
        result = &mut deletion => {
            result?;
            anyhow::bail!("cleanup returned before the held leaf was deleted");
        }
        result = tokio::time::timeout(
            Duration::from_secs(10),
            absent(&certificates, &name),
        ) => {
            result.context("issuing Certificate was retained behind its held leaf")??;
        }
    }
    ensure!(
        admin.secrets().get(&name).await?.metadata.uid == reissued_leaf.metadata.uid,
        "held leaf identity changed during cleanup"
    );
    // Keep driving the deletion future while the leaf is held: merely pausing
    // it until after releasing the finalizer would not prove that it waits.
    ensure!(
        tokio::time::timeout(Duration::from_secs(1), &mut deletion)
            .await
            .is_err(),
        "cleanup completed while its leaf was still held"
    );
    ensure!(
        admin
            .secrets()
            .get(&name)
            .await?
            .metadata
            .deletion_timestamp
            .is_some(),
        "cleanup did not request held leaf deletion after removing its Certificate"
    );
    admin
        .secrets()
        .patch(
            &name,
            &PatchParams::default(),
            &Patch::Merge(json!({"metadata":{"finalizers":null}})),
        )
        .await?;
    deletion.await?;
    orchestration
        .delete_credential_bootstrap(&opts.environment_id, Duration::from_secs(30))
        .await?;
    absent(&admin.credential_certificates(), &name).await?;
    absent(&admin.secrets(), &name).await?;
    absent(&admin.credential_config_maps(), &config_name).await
}

fn certificate_ready(certificate: &DynamicObject) -> bool {
    let Some(generation) = certificate
        .metadata
        .generation
        .filter(|generation| *generation > 0)
    else {
        return false;
    };
    certificate
        .data
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .is_some_and(|conditions| {
            conditions.iter().any(|condition| {
                condition["type"] == "Ready"
                    && condition["status"] == "True"
                    && condition["observedGeneration"].as_i64() == Some(generation)
            })
        })
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
    admission_denied_by(result, &[message]).await
}

async fn admission_denied_by<T>(result: Result<T, kube::Error>, messages: &[&str]) -> Result<()> {
    // These policies omit validation.reason, so Kubernetes returns Invalid
    // (422), not the independent RBAC Forbidden (403) checked above.
    let status = match &result {
        Err(kube::Error::Api(error)) => Some(error.code),
        _ => None,
    };
    ensure!(
        matches!(result, Err(kube::Error::Api(ref error))
        if error.code == 422 && error.reason == "Invalid"
            && messages.iter().any(|message| error.message.contains(message))),
        "expected credential admission denial was not observed (API status {status:?}): {messages:?}"
    );
    Ok(())
}

#[tokio::test]
async fn admission_assertion_requires_policy_invalid_not_rbac_or_schema_failure() {
    const MESSAGE: &str = "exact fixture admission policy denial";
    let response = |code, reason: &str, message: &str| -> Result<(), kube::Error> {
        Err(kube::Error::Api(Box::new(
            kube::core::Status::failure(message, reason).with_code(code),
        )))
    };
    assert!(
        admission_denied(response(422, "Invalid", MESSAGE), MESSAGE)
            .await
            .is_ok()
    );
    for result in [
        response(403, "Forbidden", MESSAGE),
        response(422, "Forbidden", MESSAGE),
        response(422, "Invalid", "unrelated schema validation"),
        response(500, "InternalError", MESSAGE),
        Ok(()),
    ] {
        assert!(admission_denied(result, MESSAGE).await.is_err());
    }
}

#[tokio::test]
async fn overlapping_admission_requires_one_of_the_exact_policy_messages() {
    let response = |message| -> Result<(), kube::Error> {
        Err(kube::Error::Api(Box::new(
            kube::core::Status::failure(message, "Invalid").with_code(422),
        )))
    };
    let policies = ["first exact policy denial", "second exact policy denial"];
    for message in policies {
        assert!(
            admission_denied_by(response(message), &policies)
                .await
                .is_ok()
        );
    }
    assert!(
        admission_denied_by(response("unrelated schema error"), &policies)
            .await
            .is_err()
    );
    assert!(
        admission_denied_by(response(policies[0]), &[])
            .await
            .is_err()
    );
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
