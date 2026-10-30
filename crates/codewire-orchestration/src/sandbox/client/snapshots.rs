//! Kubernetes calls of a hosted disk snapshot (#3046 H1). They stand apart from
//! the rest of [`SandboxClient`] so the runtime driver's extraction (#3628) can
//! move them whole. Every call is idempotent, keyed by the snapshot's id.

use super::*;
use crate::sandbox::shadow_warm_pool_name;
use crate::sandbox::snapshots::{
    ClearingOpts, clearing_name, clearing_volume_name, kept_snapshot_name, raw_snapshot_name,
    render_clearing_claim, render_clearing_pool, render_clearing_template, render_volume_snapshot,
};

/// What a VolumeSnapshot's status says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VolumeSnapshotProgress {
    Pending,
    Ready {
        restore_size: String,
    },
    /// The driver reported an error. Its message isn't kept: it may name
    /// anything the driver saw.
    Failed,
}

/// Whether deleting a capture's objects includes the kept snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeptSnapshot {
    Retain,
    Delete,
}

/// Where the clearing container stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClearingProgress {
    Pending,
    Succeeded,
    Failed,
}

fn volume_snapshot_progress(object: &DynamicObject) -> VolumeSnapshotProgress {
    let status = object.data.get("status");
    if status
        .and_then(|status| status.pointer("/error/message"))
        .is_some()
        && status
            .and_then(|status| status.get("readyToUse"))
            .and_then(Value::as_bool)
            != Some(true)
    {
        return VolumeSnapshotProgress::Failed;
    }
    let ready = status
        .and_then(|status| status.get("readyToUse"))
        .and_then(Value::as_bool)
        == Some(true);
    match status
        .and_then(|status| status.get("restoreSize"))
        .and_then(Value::as_str)
    {
        Some(size) if ready => VolumeSnapshotProgress::Ready {
            restore_size: size.to_owned(),
        },
        _ => VolumeSnapshotProgress::Pending,
    }
}

fn clearing_progress(pod: &Pod) -> ClearingProgress {
    match pod
        .status
        .as_ref()
        .and_then(|status| status.phase.as_deref())
    {
        Some("Succeeded") => ClearingProgress::Succeeded,
        Some("Failed") => ClearingProgress::Failed,
        _ => ClearingProgress::Pending,
    }
}

impl SandboxClient {
    fn volume_snapshots(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk("snapshot.storage.k8s.io", "v1", "VolumeSnapshot");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "volumesnapshots");
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    /// Create the VolumeSnapshot `name` of `source_pvc`, or find it.
    pub async fn ensure_volume_snapshot(
        &self,
        name: &str,
        snapshot_id: &str,
        source_pvc: &str,
        snapshot_class: &str,
    ) -> anyhow::Result<()> {
        let rendered = render_volume_snapshot(
            &self.namespace,
            name,
            snapshot_id,
            source_pvc,
            snapshot_class,
        );
        let object: DynamicObject = serde_json::from_value(rendered)?;
        match self
            .volume_snapshots()
            .create(&PostParams::default(), &object)
            .await
        {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(error)) if error.code == 409 => Ok(()),
            Err(error) => Err(anyhow::anyhow!("create VolumeSnapshot {name}: {error}")),
        }
    }

    pub async fn volume_snapshot_progress(
        &self,
        name: &str,
    ) -> anyhow::Result<VolumeSnapshotProgress> {
        let object = self
            .volume_snapshots()
            .get(name)
            .await
            .map_err(|error| anyhow::anyhow!("get VolumeSnapshot {name}: {error}"))?;
        Ok(volume_snapshot_progress(&object))
    }

    /// Wait until the VolumeSnapshot `name` is ready, and return its size. An
    /// error the driver reports ends the wait.
    pub async fn wait_for_volume_snapshot(
        &self,
        name: &str,
        timeout: Duration,
    ) -> anyhow::Result<String> {
        let wait = async {
            loop {
                match self.volume_snapshot_progress(name).await? {
                    VolumeSnapshotProgress::Ready { restore_size } => return Ok(restore_size),
                    VolumeSnapshotProgress::Failed => {
                        anyhow::bail!("VolumeSnapshot {name} failed")
                    }
                    VolumeSnapshotProgress::Pending => {
                        tokio::time::sleep(Duration::from_millis(250)).await
                    }
                }
            }
        };
        tokio::time::timeout(timeout, wait)
            .await
            .map_err(|_| anyhow::anyhow!("VolumeSnapshot {name} was not ready in time"))?
    }

    /// Create a clearing Sandbox's template, shadow pool and claim, or find them.
    pub async fn ensure_clearing_sandbox(&self, opts: &ClearingOpts<'_>) -> anyhow::Result<()> {
        let snapshot_id = opts.snapshot_id;
        let template: DynamicObject = serde_json::from_value(render_clearing_template(opts))?;
        let pool: DynamicObject =
            serde_json::from_value(render_clearing_pool(&self.namespace, snapshot_id))?;
        let claim: DynamicObject =
            serde_json::from_value(render_clearing_claim(&self.namespace, snapshot_id))?;
        for (kind, api, object) in [
            ("SandboxTemplate", self.templates(), &template),
            ("SandboxWarmPool", self.warm_pools(), &pool),
            ("SandboxClaim", self.claims.clone(), &claim),
        ] {
            match api.create(&PostParams::default(), object).await {
                Ok(_) => {}
                Err(kube::Error::Api(error)) if error.code == 409 => {}
                Err(error) => return Err(anyhow::anyhow!("create clearing {kind}: {error}")),
            }
        }
        Ok(())
    }

    /// Whether the clearing container has finished. Its Pod's name is its claim's.
    pub async fn clearing_progress(&self, snapshot_id: &str) -> anyhow::Result<ClearingProgress> {
        let name = clearing_name(snapshot_id);
        let pod = self
            .pods()
            .get_opt(&name)
            .await
            .map_err(|error| anyhow::anyhow!("get clearing Pod: {error}"))?;
        Ok(pod
            .as_ref()
            .map_or(ClearingProgress::Pending, clearing_progress))
    }

    /// Stop the clearing Sandbox's Pod and wait until it is gone, which is when
    /// its filesystem is unmounted. Suspending, not deleting, so the controller
    /// doesn't start a new one. An already absent Sandbox is done.
    pub async fn stop_clearing_pod(
        &self,
        snapshot_id: &str,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let name = clearing_name(snapshot_id);
        let patch = serde_json::json!({ "spec": { "operatingMode": "Suspended" } });
        match self
            .sandboxes()
            .patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
        {
            Ok(_) => {}
            Err(kube::Error::Api(error)) if error.code == 404 => {}
            Err(error) => return Err(anyhow::anyhow!("suspend clearing Sandbox: {error}")),
        }
        let pods = self.pods();
        let wait = async {
            while pods
                .get_opt(&name)
                .await
                .map_err(|error| anyhow::anyhow!("get clearing Pod: {error}"))?
                .is_some()
            {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            anyhow::Ok(())
        };
        tokio::time::timeout(timeout, wait)
            .await
            .map_err(|_| anyhow::anyhow!("clearing Pod was not gone in time"))?
    }

    /// Delete a capture's objects: its clearing Sandbox, its volume and the raw
    /// snapshot, and with [`KeptSnapshot::Delete`] the kept one too. Every delete
    /// is issued before any wait, because they hold each other: the snapshot
    /// controller keeps a PVC while a snapshot of it isn't ready, and a snapshot
    /// while a PVC is still restoring from it (external-snapshotter v8.6.0,
    /// `isPVCBeingUsed`, `isVolumeBeingCreatedFromSnapshot`). Waiting on one first
    /// could leave the raw snapshot undeleted behind a stuck kept snapshot, and
    /// the raw snapshot and an uncleared volume hold sign-ins whole. An error
    /// never stops the rest; the first is returned, and a retry finishes the job.
    pub async fn delete_capture_objects(
        &self,
        snapshot_id: &str,
        kept: KeptSnapshot,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let name = clearing_name(snapshot_id);
        let volume = clearing_volume_name(snapshot_id);
        let raw = raw_snapshot_name(snapshot_id);
        let kept_name = kept_snapshot_name(snapshot_id);
        let snapshots = self.volume_snapshots();
        let volumes = self.persistent_volume_claims();
        let mut first_error = None;
        let mut note = |result: anyhow::Result<()>| {
            if let Err(error) = result
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        };

        if kept == KeptSnapshot::Delete {
            note(delete_object("VolumeSnapshot", &snapshots, &kept_name).await);
        }
        note(delete_object("clearing SandboxClaim", &self.claims, &name).await);
        note(delete_object("clearing volume", &volumes, &volume).await);
        note(delete_object("VolumeSnapshot", &snapshots, &raw).await);

        let (kept_gone, volume_gone, raw_gone) = tokio::join!(
            async {
                if kept == KeptSnapshot::Delete {
                    wait_until_gone("VolumeSnapshot", &snapshots, &kept_name, timeout).await
                } else {
                    Ok(())
                }
            },
            wait_until_gone("clearing volume", &volumes, &volume, timeout),
            wait_until_gone("VolumeSnapshot", &snapshots, &raw, timeout),
        );
        note(kept_gone);
        note(volume_gone);
        note(raw_gone);

        // The controller reads these while a claim exists, so they go last.
        note(
            delete_object(
                "clearing SandboxWarmPool",
                &self.warm_pools(),
                &shadow_warm_pool_name(&name),
            )
            .await,
        );
        note(delete_object("clearing SandboxTemplate", &self.templates(), &name).await);
        first_error.map_or(Ok(()), Err)
    }
}

async fn delete_object<K>(what: &str, api: &Api<K>, name: &str) -> anyhow::Result<()>
where
    K: Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    match api.delete(name, &DeleteParams::default()).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(error)) if error.code == 404 => Ok(()),
        Err(error) => Err(anyhow::anyhow!("delete {what} {name}: {error}")),
    }
}

async fn wait_until_gone<K>(
    what: &str,
    api: &Api<K>,
    name: &str,
    timeout: Duration,
) -> anyhow::Result<()>
where
    K: Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    let wait = async {
        while api
            .get_opt(name)
            .await
            .map_err(|error| anyhow::anyhow!("get {what} {name}: {error}"))?
            .is_some()
        {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        anyhow::Ok(())
    };
    tokio::time::timeout(timeout, wait)
        .await
        .map_err(|_| anyhow::anyhow!("{what} {name} was not deleted in time"))?
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Method, Request, Response, StatusCode};
    use serde_json::json;

    use super::*;

    const ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    #[derive(Default)]
    struct Cluster {
        /// (plural, name) of what exists.
        objects: BTreeSet<(String, String)>,
        /// Deletes issued, in order.
        deletes: Vec<String>,
        /// A deleted object that stays until its holder is gone, as a finalizer
        /// keeps it: (held, holder).
        holds: Vec<((String, String), (String, String))>,
        /// (plural, name) that never leaves, as a driver that can't delete.
        stuck: BTreeSet<(String, String)>,
        deleted: BTreeSet<(String, String)>,
    }

    impl Cluster {
        fn settle(&mut self) {
            let gone: Vec<_> = self
                .deleted
                .iter()
                .filter(|key| {
                    !self.stuck.contains(*key)
                        && !self
                            .holds
                            .iter()
                            .any(|(held, holder)| held == *key && self.objects.contains(holder))
                })
                .cloned()
                .collect();
            for key in gone {
                self.objects.remove(&key);
                self.deleted.remove(&key);
            }
        }
    }

    fn snapshots_key(name: String) -> (String, String) {
        ("volumesnapshots".into(), name)
    }

    fn volume_key() -> (String, String) {
        ("persistentvolumeclaims".into(), clearing_volume_name(ID))
    }

    /// A cluster holding one capture's objects, its held volume included.
    fn cluster() -> (SandboxClient, Arc<Mutex<Cluster>>) {
        let mut state = Cluster::default();
        for key in [
            snapshots_key(raw_snapshot_name(ID)),
            snapshots_key(kept_snapshot_name(ID)),
            volume_key(),
            ("sandboxclaims".to_owned(), clearing_name(ID)),
            ("sandboxtemplates".to_owned(), clearing_name(ID)),
            (
                "sandboxwarmpools".to_owned(),
                shadow_warm_pool_name(&clearing_name(ID)),
            ),
        ] {
            state.objects.insert(key);
        }
        let state = Arc::new(Mutex::new(state));
        let shared = state.clone();
        let service = Router::new().fallback(move |request: Request<Body>| {
            let shared = shared.clone();
            async move {
                let path: Vec<String> = request
                    .uri()
                    .path()
                    .split('/')
                    .filter(|part| !part.is_empty())
                    .map(str::to_owned)
                    .collect();
                let key = (path[path.len() - 2].clone(), path[path.len() - 1].clone());
                let mut cluster = shared.lock().unwrap();
                if request.method() == Method::DELETE && cluster.objects.contains(&key) {
                    cluster.deletes.push(key.1.clone());
                    cluster.deleted.insert(key.clone());
                }
                cluster.settle();
                let found = cluster.objects.contains(&key);
                drop(cluster);
                let (status, body) = if found {
                    (
                        StatusCode::OK,
                        json!({
                            "apiVersion": "v1", "kind": "Object",
                            "metadata": { "name": key.1, "namespace": "dev-sandboxes" },
                        }),
                    )
                } else {
                    (
                        StatusCode::NOT_FOUND,
                        json!({
                            "apiVersion": "v1", "kind": "Status", "status": "Failure",
                            "reason": "NotFound", "code": 404,
                        }),
                    )
                };
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            }
        });
        (
            SandboxClient::new(Client::new(service, "default"), "dev-sandboxes"),
            state,
        )
    }

    /// The deadlock the review found: an unready kept snapshot holds the
    /// clearing volume, and the raw snapshot was never reached behind that wait.
    #[tokio::test]
    async fn an_unready_kept_snapshot_cannot_keep_the_raw_snapshot_or_the_volume() {
        let (client, state) = cluster();
        state
            .lock()
            .unwrap()
            .holds
            .push((volume_key(), snapshots_key(kept_snapshot_name(ID))));

        client
            .delete_capture_objects(ID, KeptSnapshot::Delete, Duration::from_secs(5))
            .await
            .unwrap();

        assert_eq!(state.lock().unwrap().objects, BTreeSet::new());
    }

    /// A volume still restoring holds the raw snapshot, the other way round.
    #[tokio::test]
    async fn a_restoring_volume_cannot_keep_the_raw_snapshot() {
        let (client, state) = cluster();
        state
            .lock()
            .unwrap()
            .holds
            .push((snapshots_key(raw_snapshot_name(ID)), volume_key()));

        client
            .delete_capture_objects(ID, KeptSnapshot::Delete, Duration::from_secs(5))
            .await
            .unwrap();

        assert_eq!(state.lock().unwrap().objects, BTreeSet::new());
    }

    /// When the kept snapshot can't go at all, the call fails so the workflow
    /// retries, but everything else has gone already.
    #[tokio::test]
    async fn a_stuck_kept_snapshot_fails_the_call_and_nothing_else_stays() {
        let (client, state) = cluster();
        let kept = snapshots_key(kept_snapshot_name(ID));
        state.lock().unwrap().stuck.insert(kept.clone());

        let error = client
            .delete_capture_objects(ID, KeptSnapshot::Delete, Duration::from_millis(600))
            .await
            .unwrap_err();

        assert!(
            error.to_string().contains("was not deleted in time"),
            "{error}"
        );
        assert_eq!(state.lock().unwrap().objects, BTreeSet::from([kept]));
    }

    #[tokio::test]
    async fn finishing_a_capture_retains_the_kept_snapshot() {
        let (client, state) = cluster();

        client
            .delete_capture_objects(ID, KeptSnapshot::Retain, Duration::from_secs(5))
            .await
            .unwrap();

        let state = state.lock().unwrap();
        assert_eq!(
            state.objects,
            BTreeSet::from([snapshots_key(kept_snapshot_name(ID))])
        );
        assert!(!state.deletes.contains(&kept_snapshot_name(ID)));
    }

    fn snapshot(status: Value) -> DynamicObject {
        serde_json::from_value(json!({
            "apiVersion": "snapshot.storage.k8s.io/v1",
            "kind": "VolumeSnapshot",
            "metadata": { "name": "s" },
            "status": status,
        }))
        .unwrap()
    }

    #[test]
    fn a_volume_snapshot_is_ready_only_with_its_size_and_a_driver_error_ends_the_wait() {
        assert_eq!(
            volume_snapshot_progress(&snapshot(json!({}))),
            VolumeSnapshotProgress::Pending
        );
        assert_eq!(
            volume_snapshot_progress(&snapshot(json!({ "readyToUse": false }))),
            VolumeSnapshotProgress::Pending
        );
        assert_eq!(
            volume_snapshot_progress(&snapshot(json!({ "readyToUse": true }))),
            VolumeSnapshotProgress::Pending
        );
        assert_eq!(
            volume_snapshot_progress(&snapshot(
                json!({ "readyToUse": true, "restoreSize": "80Gi" })
            )),
            VolumeSnapshotProgress::Ready {
                restore_size: "80Gi".into()
            }
        );
        assert_eq!(
            volume_snapshot_progress(&snapshot(
                json!({ "readyToUse": false, "error": { "message": "no" } })
            )),
            VolumeSnapshotProgress::Failed
        );
        // An error the driver later recovered from doesn't undo readiness.
        assert_eq!(
            volume_snapshot_progress(&snapshot(json!({
                "readyToUse": true, "restoreSize": "80Gi", "error": { "message": "old" }
            }))),
            VolumeSnapshotProgress::Ready {
                restore_size: "80Gi".into()
            }
        );
    }

    #[test]
    fn only_a_terminal_pod_phase_settles_clearing() {
        let pod = |phase: &str| -> Pod {
            serde_json::from_value(json!({ "status": { "phase": phase } })).unwrap()
        };
        assert_eq!(
            clearing_progress(&pod("Pending")),
            ClearingProgress::Pending
        );
        assert_eq!(
            clearing_progress(&pod("Running")),
            ClearingProgress::Pending
        );
        assert_eq!(
            clearing_progress(&pod("Succeeded")),
            ClearingProgress::Succeeded
        );
        assert_eq!(clearing_progress(&pod("Failed")), ClearingProgress::Failed);
    }
}
