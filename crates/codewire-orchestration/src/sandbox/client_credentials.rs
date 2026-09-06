//! Environment-owned public bootstrap intent. Never reads TLS Secret data.

use super::*;
use crate::sandbox::template::{
    credential_codex_config_name, credential_gateway_certificate_name,
    render_credential_codex_config, render_credential_gateway_certificate,
};

impl SandboxClient {
    pub(super) fn credential_certificates(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk("cert-manager.io", "v1", "Certificate");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "certificates");
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    pub(super) fn credential_config_maps(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk("", "v1", "ConfigMap");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "configmaps");
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    /// Called before submitting the workspace template, and on gateway restart.
    /// An unchanged retry only reads public intent. A name collision with an
    /// object not owned by this exact environment is never silently adopted.
    pub(super) async fn ensure_credential_bootstrap(
        &self,
        opts: &TemplateOpts,
    ) -> anyhow::Result<()> {
        if let Some(certificate) = render_credential_gateway_certificate(&self.namespace, opts) {
            self.ensure_credential_object(self.credential_certificates(), certificate, "spec")
                .await?;
        }
        if let Some(config) = render_credential_codex_config(&self.namespace, opts) {
            self.ensure_credential_object(self.credential_config_maps(), config, "data")
                .await?;
        }
        Ok(())
    }

    async fn ensure_credential_object(
        &self,
        api: Api<DynamicObject>,
        rendered: Value,
        field: &str,
    ) -> anyhow::Result<()> {
        let mut desired: DynamicObject = serde_json::from_value(rendered)?;
        let name = desired
            .metadata
            .name
            .clone()
            .expect("rendered bootstrap name");
        for _ in 0..3 {
            let existing = match api.get(&name).await {
                Ok(existing) => existing,
                Err(kube::Error::Api(error)) if error.code == 404 => {
                    match api.create(&PostParams::default(), &desired).await {
                        Ok(_) => return Ok(()),
                        Err(kube::Error::Api(error)) if error.code == 409 => continue,
                        Err(error) => {
                            return Err(anyhow::anyhow!(
                                "create credential bootstrap {name}: {error}"
                            ));
                        }
                    }
                }
                Err(error) => {
                    return Err(anyhow::anyhow!("get credential bootstrap {name}: {error}"));
                }
            };
            validate_bootstrap_owner(&existing, &desired)?;
            // Exact intent prevents accepting extra SANs, usages, or an added
            // CA capability. Renderer supplies certificate defaults explicitly.
            if existing.data[field] == desired.data[field] {
                return Ok(());
            }
            desired.metadata.resource_version = existing.metadata.resource_version;
            desired.metadata.finalizers = existing.metadata.finalizers;
            desired.metadata.owner_references = existing.metadata.owner_references;
            match api.replace(&name, &PostParams::default(), &desired).await {
                Ok(_) => return Ok(()),
                Err(kube::Error::Api(error)) if error.code == 409 => {}
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "update credential bootstrap {name}: {error}"
                    ));
                }
            }
        }
        anyhow::bail!("credential bootstrap update conflicts exhausted")
    }

    /// Removes the issuing Certificate before removing its leaf Secret. Do not
    /// use foreground GC for the Certificate: retaining it while its leaf is
    /// collected lets cert-manager start issuance again during teardown.
    /// The dedicated issuer's
    /// cert-manager installation must enable Certificate owner references so
    /// Kubernetes also collects a late in-flight issuance after deletion.
    /// Ordinary stop keeps bootstrap objects for the still-existing workspace;
    /// final environment destruction alone owns this cleanup.
    pub(super) async fn delete_credential_bootstrap(
        &self,
        env_id: &str,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let name = credential_gateway_certificate_name(env_id);
        self.delete_owned_credential_object(
            &self.credential_certificates(),
            &name,
            env_id,
            timeout,
            kube::api::PropagationPolicy::Background,
        )
        .await?;
        // DELETE admission validates the old Secret's management labels and
        // exact Certificate owner reference. There is no Secret GET permission,
        // not even a metadata-only GET (which would grant the same read verb).
        delete_dynamic_until_absent(&self.secrets(), &name, timeout).await?;
        self.delete_owned_credential_object(
            &self.credential_config_maps(),
            &credential_codex_config_name(env_id),
            env_id,
            timeout,
            kube::api::PropagationPolicy::Foreground,
        )
        .await
    }

    async fn delete_owned_credential_object(
        &self,
        api: &Api<DynamicObject>,
        name: &str,
        env_id: &str,
        timeout: Duration,
        propagation_policy: kube::api::PropagationPolicy,
    ) -> anyhow::Result<()> {
        tokio::time::timeout(timeout, async {
            loop {
                let existing = match api.get(name).await {
                    Ok(existing) => existing,
                    Err(kube::Error::Api(error)) if error.code == 404 => return Ok(()),
                    Err(error) => {
                        return Err(anyhow::anyhow!(
                            "get credential bootstrap before deletion: {error}"
                        ));
                    }
                };
                anyhow::ensure!(
                    existing.metadata.namespace.as_deref() == Some(self.namespace.as_str())
                        && existing.metadata.name.as_deref() == Some(name),
                    "credential bootstrap deletion identity changed"
                );
                let uid = existing
                    .metadata
                    .uid
                    .as_deref()
                    .filter(|uid| !uid.is_empty())
                    .ok_or_else(|| anyhow::anyhow!("credential bootstrap has no UID"))?;
                let labels = existing.metadata.labels.as_ref();
                anyhow::ensure!(
                    [
                        (LABEL_ENV_ID, env_id),
                        ("app.kubernetes.io/name", "codewire"),
                        ("app.kubernetes.io/managed-by", "codewire"),
                        (LABEL_TYPE, "credential-bootstrap"),
                    ]
                    .iter()
                    .all(|(key, value)| labels
                        .and_then(|labels| labels.get(*key))
                        .map(String::as_str)
                        == Some(*value)),
                    "refusing to delete foreign credential bootstrap"
                );
                let params = DeleteParams {
                    preconditions: Some(Preconditions {
                        uid: Some(uid.to_owned()),
                        resource_version: None,
                    }),
                    propagation_policy: Some(propagation_policy.clone()),
                    ..Default::default()
                };
                match api.delete(name, &params).await {
                    Ok(_) => {}
                    Err(kube::Error::Api(error)) if error.code == 404 => return Ok(()),
                    Err(error) => {
                        return Err(anyhow::anyhow!(
                            "delete owned credential bootstrap: {error}"
                        ));
                    }
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("credential bootstrap deletion timed out"))?
    }

    /// A read-only convergence wait, always outside the activity's SQL mutation
    /// fence. Ready means the current Certificate revision and exact generation
    /// gateway rollout are ready, not that a provider account was contacted.
    pub async fn wait_for_credential_gateway_ready(
        &self,
        opts: &TemplateOpts,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let Some(rendered) = render_credential_gateway_certificate(&self.namespace, opts) else {
            return Ok(());
        };
        let desired: DynamicObject = serde_json::from_value(rendered)?;
        let certificate_name = credential_gateway_certificate_name(&opts.environment_id);
        let gateway_name = gateway_workload_name(&opts.environment_id);
        tokio::time::timeout(timeout, async {
            loop {
                let certificate = self
                    .credential_certificates()
                    .get(&certificate_name)
                    .await?;
                validate_bootstrap_owner(&certificate, &desired)?;
                anyhow::ensure!(
                    certificate.data["spec"] == desired.data["spec"],
                    "credential Certificate intent changed during readiness"
                );
                let gateway = self.deployments().get(&gateway_name).await?;
                if certificate_ready(&certificate) && gateway_ready(&gateway, opts) {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("credential gateway readiness timed out"))?
    }
}

fn validate_bootstrap_owner(
    existing: &DynamicObject,
    desired: &DynamicObject,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        existing.metadata.name == desired.metadata.name
            && existing.metadata.namespace == desired.metadata.namespace
            && existing.metadata.deletion_timestamp.is_none()
            && desired
                .metadata
                .labels
                .as_ref()
                .is_some_and(|labels| labels.iter().all(|(key, value)| existing
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|existing| existing.get(key))
                    == Some(value))),
        "credential bootstrap ownership does not match environment"
    );
    Ok(())
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

fn gateway_ready(gateway: &DynamicObject, opts: &TemplateOpts) -> bool {
    let Some(generation) = gateway
        .metadata
        .generation
        .filter(|generation| *generation > 0)
    else {
        return false;
    };
    let labels = &gateway.data["spec"]["template"]["metadata"]["labels"];
    let status = &gateway.data["status"];
    let operation_generation = opts.operation_generation.to_string();
    gateway.metadata.deletion_timestamp.is_none()
        && labels[LABEL_ENV_ID] == opts.environment_id
        && labels[LABEL_ORG_ID] == opts.organization_id
        && labels[crate::sandbox::LABEL_OPERATION_GENERATION].as_str()
            == Some(operation_generation.as_str())
        && status["observedGeneration"]
            .as_i64()
            .is_some_and(|observed| observed >= generation)
        && [
            "replicas",
            "updatedReplicas",
            "availableReplicas",
            "readyReplicas",
        ]
        .iter()
        .all(|field| status[field].as_i64() == Some(1))
}

#[cfg(test)]
#[path = "client_credentials_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "client_credentials_kind.rs"]
mod kind;
