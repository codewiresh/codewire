//! Warm-pool reads and the cold re-claim (Program #2238 C3).
//!
//! Routing reads one shared pool and its template by name. A pool-born Claim
//! whose first bind failed a definitive check is deleted with its Sandbox,
//! each by UID, so the create re-claims cold; its Sandbox never bound, so it
//! never held tenant data, and a member is never handed back to its pool.

use super::*;
use crate::sandbox::warm_pool::is_warm_pool_name;

/// A Claim that selects a shared warm pool, as observed for a re-claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolBornClaim {
    pub claim_uid: String,
    pub pool: String,
    /// The Sandbox the Claim controls (name, UID), when it has one.
    pub sandbox: Option<(String, String)>,
}

impl SandboxClient {
    /// The live SandboxWarmPool and SandboxTemplate named `name`.
    pub async fn warm_pool_objects(
        &self,
        name: &str,
    ) -> anyhow::Result<(Option<DynamicObject>, Option<DynamicObject>)> {
        let pool = self
            .warm_pools()
            .get_opt(name)
            .await
            .map_err(|error| anyhow::anyhow!("get SandboxWarmPool {name}: {error}"))?;
        let template = self
            .templates()
            .get_opt(name)
            .await
            .map_err(|error| anyhow::anyhow!("get SandboxTemplate {name}: {error}"))?;
        Ok((pool, template))
    }

    /// The environment's recorded Claim when it selects a shared `cw-pool-`
    /// pool, with the live Sandbox it controls. `None` for any other Claim,
    /// including a replaced one.
    pub async fn pool_born_claim(
        &self,
        env_id: &str,
        claim_uid: &str,
    ) -> anyhow::Result<Option<PoolBornClaim>> {
        let Some(claim) = self.get_sandbox_claim(env_id).await? else {
            return Ok(None);
        };
        let pool = claim
            .data
            .pointer("/spec/warmPoolRef/name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if claim_uid.is_empty()
            || claim.metadata.uid.as_deref() != Some(claim_uid)
            || claim.metadata.deletion_timestamp.is_some()
            || !is_warm_pool_name(pool)
        {
            return Ok(None);
        }
        let name = claim_name(env_id);
        let sandbox = match claim_bound_sandbox_name(&claim) {
            None => None,
            Some(sandbox_name) => match self.sandboxes().get_opt(sandbox_name).await {
                Ok(Some(sandbox)) => {
                    require_runtime_controller(
                        &sandbox.metadata,
                        crate::sandbox::EXTENSIONS_API_VERSION,
                        "SandboxClaim",
                        &name,
                        claim_uid,
                    )?;
                    let uid = sandbox
                        .metadata
                        .uid
                        .clone()
                        .filter(|uid| !uid.is_empty())
                        .ok_or_else(|| anyhow::anyhow!("pool-born Sandbox has no UID"))?;
                    Some((sandbox_name.to_owned(), uid))
                }
                Ok(None) => None,
                Err(error) => {
                    return Err(anyhow::anyhow!("get pool-born Sandbox: {error}"));
                }
            },
        };
        Ok(Some(PoolBornClaim {
            claim_uid: claim_uid.to_owned(),
            pool: pool.to_owned(),
            sandbox,
        }))
    }

    /// Delete a pool-born Claim's Sandbox and then the Claim, each with a UID
    /// precondition, and wait until the Claim's name is free for a cold
    /// Claim. A replacement under either name is never deleted.
    pub async fn delete_pool_born_claim(
        &self,
        env_id: &str,
        observed: &PoolBornClaim,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        if let Some((name, uid)) = &observed.sandbox {
            match self
                .sandboxes()
                .delete(name, &delete_params_for_observed_uid(uid))
                .await
            {
                Ok(_) => {}
                Err(kube::Error::Api(error)) if matches!(error.code, 404 | 409) => {}
                Err(error) => return Err(anyhow::anyhow!("delete pool-born Sandbox: {error}")),
            }
        }
        let name = claim_name(env_id);
        if let Some(claim) = self.get_sandbox_claim(env_id).await?
            && claim.metadata.uid.as_deref() == Some(observed.claim_uid.as_str())
        {
            let finalizers = claim.metadata.finalizers.clone().unwrap_or_default();
            let kept: Vec<&String> = finalizers
                .iter()
                .filter(|finalizer| finalizer.as_str() != DELETION_PROTECTION_FINALIZER)
                .collect();
            if kept.len() != finalizers.len() {
                let patch: Patch<()> = Patch::Json(serde_json::from_value(serde_json::json!([
                    { "op": "test", "path": "/metadata/uid", "value": observed.claim_uid },
                    { "op": "replace", "path": "/metadata/finalizers", "value": kept },
                ]))?);
                self.claims
                    .patch(&name, &PatchParams::default(), &patch)
                    .await
                    .map_err(|error| {
                        anyhow::anyhow!("release pool-born SandboxClaim finalizer: {error}")
                    })?;
            }
            match self
                .claims
                .delete(&name, &delete_params_for_observed_uid(&observed.claim_uid))
                .await
            {
                Ok(_) => {}
                Err(kube::Error::Api(error)) if matches!(error.code, 404 | 409) => {}
                Err(error) => {
                    return Err(anyhow::anyhow!("delete pool-born SandboxClaim: {error}"));
                }
            }
        }
        tokio::time::timeout(timeout, async {
            loop {
                match self.get_sandbox_claim(env_id).await? {
                    Some(claim)
                        if claim.metadata.uid.as_deref() == Some(observed.claim_uid.as_str()) => {}
                    _ => return Ok::<_, anyhow::Error>(()),
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("pool-born SandboxClaim {name} was not removed in time"))?
    }
}

#[cfg(test)]
#[path = "warm_pool_tests.rs"]
mod tests;
