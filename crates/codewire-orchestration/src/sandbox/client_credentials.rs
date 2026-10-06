//! Leftover per-environment credential bootstrap objects. Never reads TLS
//! Secret data.

use super::*;
use crate::sandbox::template::{credential_codex_config_name, credential_gateway_certificate_name};

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

    /// Only environments created before the gateway's workspace-facing HTTPS
    /// listener was removed still own a gateway Certificate and its leaf; a
    /// gateway Deployment rendered then mounts that leaf until its next
    /// render, so ordinary stop keeps them and final environment destruction
    /// alone owns this cleanup. Absence is the normal case.
    ///
    /// Removes the issuing Certificate before removing its leaf Secret. Do not
    /// use foreground GC for the Certificate: retaining it while its leaf is
    /// collected lets cert-manager start issuance again during teardown.
    /// The dedicated issuer's
    /// cert-manager installation must enable Certificate owner references so
    /// Kubernetes also collects a late in-flight issuance after deletion.
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
        // Only environments created before the daemon wrote `~/.codex` still
        // own a Codex ConfigMap; absence is the normal case.
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
}

#[cfg(test)]
#[path = "client_credentials_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "client_credentials_kind.rs"]
mod kind;
