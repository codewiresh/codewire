//! Warm-pool reconciler decisions (Program #2238 C2).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use k8s_openapi::api::core::v1::{Node, Taint, Toleration};
use k8s_openapi::jiff::Timestamp;
use kube::api::DynamicObject;
use serde_json::{Value, json};

use super::*;
use crate::sandbox::client::sandbox_name_hash;
use crate::sandbox::image_cache::{CacheState, DesiredSet, RenderConfig, merge, render_daemon_set};
use crate::sandbox::template::{
    CredentialRuntimeTemplateConfig, DOCKER_MODE_PROFILE_DEFAULT, RUNTIME_PROFILE_COMMODITY,
};
use crate::worker::create::SandboxWorkerCfg;
use crate::worker::warm_pool::WarmPoolConfig;

const NAMESPACE: &str = "dev-sandboxes";
const NOW: i64 = 1_790_000_000;

/// The Dev commodity configuration with synthetic, approved digests.
fn dev_cfg(shapes: &str) -> SandboxWorkerCfg {
    SandboxWorkerCfg {
        sandbox_namespace: NAMESPACE.into(),
        credential_runtime: Some(CredentialRuntimeTemplateConfig::synthetic(NAMESPACE)),
        daemon_image: "registry.example.invalid/codewire/daemon@sha256:2222222222222222222222222222222222222222222222222222222222222222".into(),
        dind_image: "docker.io/library/docker:29.7.1-dind@sha256:3333333333333333333333333333333333333333333333333333333333333333".into(),
        runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
        docker_mode: DOCKER_MODE_PROFILE_DEFAULT.into(),
        workspace_storage_class: "linstor-local".into(),
        network_policy_management: "Managed".into(),
        kata_agent_policy_enabled: true,
        api_base_url: "https://codewire-dev.sh".into(),
        coordinator_url: "http://codewire-coordinator.dev.svc.cluster.local:8090".into(),
        pod_namespace: "dev".into(),
        warm_pool_shapes: shapes.into(),
        ..Default::default()
    }
}

/// The pools this configuration wants, as the driver renders them.
fn rendered(cfg: &SandboxWorkerCfg) -> super::super::RenderedPools {
    let config = WarmPoolConfig::from_cfg(cfg, true).unwrap().unwrap();
    super::super::render(&cfg.into(), NAMESPACE, &config.wanted).unwrap()
}

fn desired() -> Vec<DesiredPool> {
    rendered(&dev_cfg("1000m/4096Mi/10Gi=2,2000m/8192Mi/10Gi=2")).pools
}

fn object(value: Value) -> DynamicObject {
    serde_json::from_value(value).unwrap()
}

/// A live copy of a rendered object, as the API server returns it.
fn live(rendered: &Value, uid: &str) -> DynamicObject {
    let mut value = rendered.clone();
    value["metadata"]["uid"] = json!(uid);
    value["metadata"]["resourceVersion"] = json!("41");
    object(value)
}

fn live_pool(pool: &DesiredPool, uid: &str, replicas: i64, ready: i64) -> DynamicObject {
    let mut value = pool.objects.pool.clone();
    value["metadata"]["uid"] = json!(uid);
    value["metadata"]["resourceVersion"] = json!("52");
    value["spec"]["replicas"] = json!(replicas);
    value["status"] = json!({ "replicas": replicas, "readyReplicas": ready });
    object(value)
}

/// An unclaimed member the controller built from `template`.
fn member(pool: &DesiredPool, pool_uid: &str, name: &str, template: &Value) -> Value {
    json!({
        "apiVersion": "agents.x-k8s.io/v1beta1",
        "kind": "Sandbox",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "uid": format!("uid-{name}"),
            "resourceVersion": "77",
            "creationTimestamp": Timestamp::from_second(NOW - 60).unwrap().to_string(),
            "labels": { MEMBER_POOL_LABEL: sandbox_name_hash(&pool.objects.name) },
            "ownerReferences": [{
                "apiVersion": EXTENSIONS_API_VERSION,
                "kind": "SandboxWarmPool",
                "name": pool.objects.name,
                "uid": pool_uid,
                "controller": true,
            }],
        },
        "spec": template["spec"].clone(),
    })
}

struct Fixture {
    desired: Vec<DesiredPool>,
    allowed: Vec<i32>,
    templates: BTreeMap<String, DynamicObject>,
    pools: BTreeMap<String, DynamicObject>,
    members: Vec<DynamicObject>,
    member_pods: BTreeMap<String, Placement>,
    nodes: BTreeMap<String, Node>,
    referenced: Option<BTreeSet<String>>,
    template_users: Option<BTreeSet<String>>,
    cache_warm: bool,
    rotation: Option<(String, Duration)>,
}

impl Fixture {
    fn empty() -> Self {
        let desired = desired();
        Self {
            allowed: desired.iter().map(|pool| pool.configured.members).collect(),
            desired,
            templates: BTreeMap::new(),
            pools: BTreeMap::new(),
            members: Vec::new(),
            member_pods: BTreeMap::new(),
            nodes: BTreeMap::from([
                (
                    "runtime-1".to_owned(),
                    node("runtime-1", "32", "128Gi", true, false),
                ),
                (
                    "runtime-2".to_owned(),
                    node("runtime-2", "32", "128Gi", true, true),
                ),
            ]),
            referenced: None,
            template_users: None,
            cache_warm: true,
            rotation: None,
        }
    }

    /// Both pools current, full and ready.
    fn settled() -> Self {
        let mut fixture = Self::empty();
        for (index, pool) in fixture.desired.clone().iter().enumerate() {
            let name = pool.objects.name.clone();
            fixture.templates.insert(
                name.clone(),
                live(&pool.objects.template, &format!("template-{index}")),
            );
            fixture
                .pools
                .insert(name, live_pool(pool, &format!("pool-{index}"), 2, 2));
        }
        fixture
    }

    /// Place a member's Pod on `node` with no tolerations.
    fn place(&mut self, pod: &str, node: &str) {
        self.member_pods.insert(
            pod.to_owned(),
            Placement {
                node: node.to_owned(),
                tolerations: Vec::new(),
            },
        );
    }

    fn plan(&self) -> Plan {
        plan(&Observed {
            desired: &self.desired,
            allowed_members: &self.allowed,
            templates: &self.templates,
            pools: &self.pools,
            members: &self.members,
            member_pods: &self.member_pods,
            nodes: &self.nodes,
            referenced_pools: self.referenced.as_ref(),
            template_users: self.template_users.as_ref(),
            cache_warm: self.cache_warm,
            rotation: self
                .rotation
                .as_ref()
                .map(|(name, elapsed)| (name.as_str(), *elapsed)),
            now: Timestamp::from_second(NOW).unwrap(),
        })
    }
}

fn names(writes: &[Write]) -> Vec<String> {
    writes
        .iter()
        .map(|write| match write {
            Write::CreateTemplate { name, .. } => format!("create-template {name}"),
            Write::ReplaceTemplate { name, .. } => format!("replace-template {name}"),
            Write::CreatePool { name, .. } => format!("create-pool {name}"),
            Write::ReplacePool { name, .. } => format!("replace-pool {name}"),
            Write::DeleteMember { name, reason, .. } => {
                format!("delete-member {name} {}", reason.as_str())
            }
            Write::DeletePool { name, .. } => format!("delete-pool {name}"),
            Write::DeleteTemplate { name, .. } => format!("delete-template {name}"),
        })
        .collect()
}

#[test]
fn a_fresh_cluster_creates_one_template_per_pass_then_its_pool() {
    let mut fixture = Fixture::empty();
    let [small, large] = [fixture.desired[0].clone(), fixture.desired[1].clone()];
    let first = fixture.plan();
    assert_eq!(
        names(&first.writes),
        [format!("create-template {}", small.objects.name)]
    );
    assert_eq!(
        first.started_rotation.as_deref(),
        Some(small.objects.name.as_str())
    );
    match &first.writes[0] {
        Write::CreateTemplate { body, .. } => assert_eq!(body, &small.objects.template),
        other => panic!("unexpected {other:?}"),
    }
    assert!(!first.reports[&small.label()].blocked_by_cache);
    assert!(first.reports[&large.label()].blocked_by_rotation);

    // The template exists; its pool follows, and the other shape still waits
    // for this one to refill.
    fixture.templates.insert(
        small.objects.name.clone(),
        live(&small.objects.template, "template-0"),
    );
    fixture.rotation = Some((small.objects.name.clone(), Duration::from_secs(30)));
    let second = fixture.plan();
    assert_eq!(
        names(&second.writes),
        [format!("create-pool {}", small.objects.name)]
    );
    match &second.writes[0] {
        Write::CreatePool { body, .. } => {
            assert_eq!(body["spec"]["replicas"], 2);
            assert_eq!(body["spec"]["updateStrategy"]["type"], "Recreate");
            assert_eq!(
                body["metadata"]["annotations"][POOL_REVISION_ANNOTATION],
                small.objects.revision.as_str()
            );
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(second.reports[&large.label()].blocked_by_rotation);
    assert!(!second.rotation_settled);

    // Refilled: the next shape rotates and the remembered rotation settles.
    fixture.pools.insert(
        small.objects.name.clone(),
        live_pool(&small, "pool-0", 2, 2),
    );
    let third = fixture.plan();
    assert_eq!(
        names(&third.writes),
        [format!("create-template {}", large.objects.name)]
    );
    assert!(third.rotation_settled);
}

#[test]
fn a_cold_image_cache_blocks_every_template_change() {
    let mut fixture = Fixture::empty();
    fixture.cache_warm = false;
    let plan = fixture.plan();
    assert!(plan.writes.is_empty());
    assert!(plan.started_rotation.is_none());
    assert!(plan.reports.values().all(|report| report.blocked_by_cache));

    // A stale template is not replaced either, but its pool may shrink.
    let mut fixture = Fixture::settled();
    fixture.cache_warm = false;
    let name = fixture.desired[0].objects.name.clone();
    fixture
        .templates
        .get_mut(&name)
        .unwrap()
        .metadata
        .annotations
        .as_mut()
        .unwrap()
        .insert(POOL_REVISION_ANNOTATION.into(), "0".repeat(64));
    fixture.allowed[0] = 1;
    let plan = fixture.plan();
    assert_eq!(names(&plan.writes), [format!("replace-pool {name}")]);
    match &plan.writes[0] {
        Write::ReplacePool { body, .. } => {
            assert_eq!(body["spec"]["replicas"], 1);
            assert_eq!(body["metadata"]["resourceVersion"], "52");
            assert_eq!(
                body["metadata"]["annotations"][POOL_REVISION_ANNOTATION],
                fixture.desired[0].objects.revision.as_str(),
                "the live pool is changed only in its member count"
            );
            assert!(body.get("status").is_none());
        }
        other => panic!("unexpected {other:?}"),
    }
    // Growing a stale pool waits for its template.
    fixture.pools.insert(
        name.clone(),
        live_pool(&fixture.desired[0].clone(), "pool-0", 1, 1),
    );
    fixture.allowed[0] = 2;
    assert!(fixture.plan().writes.is_empty());
}

#[test]
fn templates_rotate_one_shape_at_a_time_with_their_resource_version() {
    let mut fixture = Fixture::settled();
    let [small, large] = [fixture.desired[0].clone(), fixture.desired[1].clone()];
    for pool in [&small, &large] {
        let template = fixture.templates.get_mut(&pool.objects.name).unwrap();
        template
            .metadata
            .annotations
            .as_mut()
            .unwrap()
            .insert(POOL_REVISION_ANNOTATION.into(), "0".repeat(64));
        template
            .metadata
            .labels
            .as_mut()
            .unwrap()
            .insert(TEMPLATE_REF_HASH_LABEL.into(), "0f0f0f0f".into());
    }
    let plan = fixture.plan();
    assert_eq!(
        names(&plan.writes),
        [format!("replace-template {}", small.objects.name)]
    );
    match &plan.writes[0] {
        Write::ReplaceTemplate { body, .. } => {
            assert_eq!(body["metadata"]["resourceVersion"], "41");
            assert_eq!(body["spec"], small.objects.template["spec"]);
            assert_eq!(
                body["metadata"]["labels"][TEMPLATE_REF_HASH_LABEL],
                "0f0f0f0f"
            );
            assert_eq!(
                body["metadata"]["annotations"][POOL_REVISION_ANNOTATION],
                small.objects.revision.as_str()
            );
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(plan.reports[&large.label()].blocked_by_rotation);

    // Stale members still on the rotated shape block the next one, even
    // without a remembered rotation (a new leader).
    let mut fixture = Fixture::settled();
    let old_template = {
        let mut template = small.objects.template.clone();
        template["spec"]["podTemplate"]["spec"]["containers"][0]["image"] = json!(
            "registry.example.invalid/codewire/workspace@sha256:9999999999999999999999999999999999999999999999999999999999999999"
        );
        template
    };
    fixture.members.push(object(member(
        &small,
        "pool-0",
        "cw-pool-old-1",
        &old_template,
    )));
    let large_template = fixture.templates.get_mut(&large.objects.name).unwrap();
    large_template
        .metadata
        .annotations
        .as_mut()
        .unwrap()
        .insert(POOL_REVISION_ANNOTATION.into(), "0".repeat(64));
    let plan = fixture.plan();
    assert_eq!(names(&plan.writes), ["delete-member cw-pool-old-1 stale"]);
    assert!(plan.reports[&large.label()].blocked_by_rotation);
}

#[test]
fn a_current_pool_follows_the_node_cap_and_is_otherwise_left_alone() {
    let mut fixture = Fixture::settled();
    assert!(fixture.plan().writes.is_empty());
    fixture.allowed = vec![1, 0];
    let plan = fixture.plan();
    assert_eq!(
        names(&plan.writes),
        [
            format!("replace-pool {}", fixture.desired[0].objects.name),
            format!("replace-pool {}", fixture.desired[1].objects.name),
        ]
    );
    for (write, replicas) in plan.writes.iter().zip([1, 0]) {
        match write {
            Write::ReplacePool { body, .. } => {
                assert_eq!(body["spec"]["replicas"], replicas);
                assert_eq!(body["metadata"]["resourceVersion"], "52");
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[test]
fn unclaimed_members_are_deleted_with_preconditions_by_reason() {
    let mut fixture = Fixture::settled();
    let small = fixture.desired[0].clone();
    let template = small.objects.template.clone();
    let mut stale = template.clone();
    stale["spec"]["podTemplate"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] =
        json!("999m");
    let mut over_age = member(&small, "pool-0", "member-old", &template);
    over_age["metadata"]["creationTimestamp"] =
        json!(Timestamp::from_second(NOW - 25 * 3600).unwrap().to_string());
    let mut adopted = member(&small, "pool-0", "member-adopted", &template);
    adopted["metadata"]["ownerReferences"] = json!([{
        "apiVersion": EXTENSIONS_API_VERSION, "kind": "SandboxClaim",
        "name": "sandbox-env", "uid": "claim-uid", "controller": true,
    }]);
    let mut terminating = member(&small, "pool-0", "member-terminating", &stale);
    terminating["metadata"]["deletionTimestamp"] =
        json!(Timestamp::from_second(NOW).unwrap().to_string());
    let mut other_pool = member(&small, "pool-9", "member-other-pool", &stale);
    other_pool["metadata"]["labels"][MEMBER_POOL_LABEL] = json!("deadbeef");
    let mut annotated = template.clone();
    annotated["spec"]["podTemplate"]["metadata"]["annotations"]["cluster-autoscaler.kubernetes.io/safe-to-evict"] =
        json!("true");
    fixture.members = [
        member(&small, "pool-0", "member-fresh", &template),
        member(&small, "pool-0", "member-evictable", &annotated),
        member(&small, "pool-0", "member-stale", &stale),
        over_age,
        member(&small, "pool-0", "member-cordoned", &template),
        adopted,
        terminating,
        other_pool,
    ]
    .into_iter()
    .map(object)
    .collect();
    fixture.place("member-cordoned", "runtime-2");
    fixture.place("member-fresh", "runtime-1");
    let plan = fixture.plan();
    assert_eq!(
        names(&plan.writes),
        [
            "delete-member member-cordoned node_unfit",
            "delete-member member-stale stale",
            "delete-member member-old over_age",
        ]
    );
    match &plan.writes[0] {
        Write::DeleteMember {
            uid,
            resource_version,
            pool,
            ..
        } => {
            assert_eq!(uid, "uid-member-cordoned");
            assert_eq!(resource_version, "77");
            assert_eq!(pool, &small.objects.name);
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(plan.reports[&small.label()].members, 5);
}

#[test]
fn member_deletions_are_bounded_per_pass() {
    let mut fixture = Fixture::settled();
    let small = fixture.desired[0].clone();
    for index in 0..7 {
        let name = format!("member-{index}");
        fixture.members.push(object(member(
            &small,
            "pool-0",
            &name,
            &small.objects.template,
        )));
        fixture.place(&name, "runtime-2");
    }
    let plan = fixture.plan();
    assert_eq!(plan.writes.len(), MAX_MEMBER_DELETES_PER_PASS);
}

#[test]
fn unconfigured_pools_drain_and_are_removed_only_when_no_claim_names_them() {
    let retired = desired()
        .into_iter()
        .find(|pool| pool.configured.shape.cpu_millicores == 2000)
        .unwrap();
    let mut fixture = Fixture::settled();
    // Only the small shape stays configured.
    fixture.desired.truncate(1);
    fixture.allowed.truncate(1);
    let name = retired.objects.name.clone();
    let plan = fixture.plan();
    assert_eq!(names(&plan.writes), [format!("replace-pool {name}")]);
    match &plan.writes[0] {
        Write::ReplacePool { body, .. } => assert_eq!(body["spec"]["replicas"], 0),
        other => panic!("unexpected {other:?}"),
    }
    assert!(plan.unconfigured.contains(&name));

    fixture
        .pools
        .insert(name.clone(), live_pool(&retired, "pool-1", 0, 0));
    fixture.members.push(object(member(
        &retired,
        "pool-1",
        "member-retired",
        &retired.objects.template,
    )));
    assert_eq!(
        names(&fixture.plan().writes),
        ["delete-member member-retired unconfigured"]
    );

    // Drained. Claims that were not read, or that name it, keep it.
    fixture.members.clear();
    assert!(fixture.plan().writes.is_empty());
    fixture.referenced = Some(BTreeSet::from([name.clone()]));
    assert!(fixture.plan().writes.is_empty());
    fixture.referenced = Some(BTreeSet::from(["shadow-pool-workspace-env".to_owned()]));
    // The pool goes; its template stays while template users are unread.
    assert_eq!(
        names(&fixture.plan().writes),
        [format!("delete-pool {name}")]
    );
    // Review L4: or while a live Sandbox runs under its NetworkPolicy.
    fixture.template_users = Some(BTreeSet::from([sandbox_name_hash(&name)]));
    assert_eq!(
        names(&fixture.plan().writes),
        [format!("delete-pool {name}")]
    );
    fixture.template_users = Some(BTreeSet::new());
    let plan = fixture.plan();
    assert_eq!(
        names(&plan.writes),
        [
            format!("delete-pool {name}"),
            format!("delete-template {name}")
        ]
    );
    match &plan.writes[0] {
        Write::DeletePool {
            uid,
            resource_version,
            ..
        } => assert_eq!((uid.as_str(), resource_version.as_str()), ("pool-1", "52")),
        other => panic!("unexpected {other:?}"),
    }

    // An orphan template goes once no pool names it; objects that are not
    // Codewire's labelled pools are never touched.
    fixture.pools.remove(&name);
    assert_eq!(
        names(&fixture.plan().writes),
        [format!("delete-template {name}")]
    );
    fixture
        .templates
        .get_mut(&name)
        .unwrap()
        .metadata
        .labels
        .as_mut()
        .unwrap()
        .remove("codewire.sh/type");
    assert!(fixture.plan().writes.is_empty());
}

/// `object` as created at `second`.
fn created(object: DynamicObject, second: i64) -> DynamicObject {
    let mut value = serde_json::to_value(object).unwrap();
    value["metadata"]["creationTimestamp"] =
        json!(Timestamp::from_second(second).unwrap().to_string());
    serde_json::from_value(value).unwrap()
}

/// #3572: a configured shape's pool at another revision keeps serving the
/// replicas that rendered it until this leader's own pool of the shape has a
/// ready member. A newer one is the next release's and is left alone, until
/// it is older than [`SUPERSEDED_GRACE`] (a rolled-back release).
#[test]
fn another_revision_of_a_configured_shape_drains_only_behind_a_ready_own_pool() {
    let mut previous_cfg = dev_cfg("1000m/4096Mi/10Gi=2,2000m/8192Mi/10Gi=2");
    previous_cfg.daemon_image = "registry.example.invalid/codewire/daemon@sha256:4444444444444444444444444444444444444444444444444444444444444444".into();
    let previous = rendered(&previous_cfg).pools.remove(0);
    let mut fixture = Fixture::settled();
    let own = fixture.desired[0].clone();
    assert_eq!(previous.configured.shape, own.configured.shape);
    assert_ne!(previous.objects.name, own.objects.name);
    let old = previous.objects.name.clone();
    fixture.templates.insert(
        old.clone(),
        live(&previous.objects.template, "template-previous"),
    );
    let pool_at = |pool: &DesiredPool, uid: &str, ready: i64, second: i64| {
        created(live_pool(pool, uid, 2, ready), second)
    };

    // The old revision's pool is older, but this leader's own pool has no
    // ready member yet: nothing touches the old one.
    fixture.pools.insert(
        old.clone(),
        pool_at(&previous, "pool-previous", 2, NOW - 3600),
    );
    fixture.pools.insert(
        own.objects.name.clone(),
        pool_at(&own, "pool-0", 0, NOW - 120),
    );
    let plan = fixture.plan();
    assert!(plan.superseded_kept.contains(&old), "{plan:?}");
    assert!(!plan.unconfigured.contains(&old));
    assert!(
        names(&plan.writes)
            .iter()
            .all(|write| !write.contains(&old))
    );

    // Once it has one, the older revision drains like an unconfigured pool,
    // and its report never replaces the own pool's.
    fixture.pools.insert(
        own.objects.name.clone(),
        pool_at(&own, "pool-0", 1, NOW - 120),
    );
    let plan = fixture.plan();
    assert_eq!(names(&plan.writes), [format!("replace-pool {old}")]);
    assert!(plan.unconfigured.contains(&old));
    assert_eq!(plan.reports[&own.label()].ready, 1);

    // A newer revision is the next release's: kept while this leader serves.
    fixture.pools.insert(
        old.clone(),
        pool_at(&previous, "pool-previous", 2, NOW - 60),
    );
    let plan = fixture.plan();
    assert!(plan.superseded_kept.contains(&old));
    assert!(
        names(&plan.writes)
            .iter()
            .all(|write| !write.contains(&old))
    );

    // Past the grace it drains, newer or not.
    fixture.pools.insert(
        own.objects.name.clone(),
        pool_at(&own, "pool-0", 1, NOW - 7200),
    );
    let grace = SUPERSEDED_GRACE.as_secs() as i64;
    fixture.pools.insert(
        old.clone(),
        pool_at(&previous, "pool-previous", 2, NOW - grace + 1),
    );
    assert!(fixture.plan().superseded_kept.contains(&old));
    fixture.pools.insert(
        old.clone(),
        pool_at(&previous, "pool-previous", 2, NOW - grace),
    );
    assert_eq!(
        names(&fixture.plan().writes),
        [format!("replace-pool {old}")]
    );
}

/// #3824: a shape configured to zero wants no members, so another revision's
/// pool of it drains with no ready own member to wait for, by the same age
/// rules. The node cap's zero is not that: an operator still wants members
/// there, and the old pool keeps serving until the own pool is ready.
#[test]
fn a_configured_zero_drains_another_revision_of_its_shape() {
    let mut previous_cfg = dev_cfg("1000m/4096Mi/10Gi=2,2000m/8192Mi/10Gi=2");
    previous_cfg.daemon_image = "registry.example.invalid/codewire/daemon@sha256:4444444444444444444444444444444444444444444444444444444444444444".into();
    let previous = rendered(&previous_cfg).pools.remove(0);
    let mut fixture = Fixture::settled();
    fixture.desired[0].configured.members = 0;
    fixture.allowed[0] = 0;
    let own = fixture.desired[0].clone();
    assert_eq!(previous.configured.shape, own.configured.shape);
    let old = previous.objects.name.clone();
    fixture.templates.insert(
        old.clone(),
        live(&previous.objects.template, "template-previous"),
    );
    let grace = SUPERSEDED_GRACE.as_secs() as i64;
    let old_pool = |second: i64| created(live_pool(&previous, "pool-previous", 2, 2), second);
    let own_pool = |second: i64| created(live_pool(&own, "pool-0", 0, 0), second);
    let untouched = |plan: &Plan| {
        plan.superseded_kept.contains(&old)
            && names(&plan.writes)
                .iter()
                .all(|write| !write.contains(&old))
    };

    // The older revision drains at once, though the own pool has no ready
    // member and never will.
    fixture.pools.insert(old.clone(), old_pool(NOW - 3600));
    fixture
        .pools
        .insert(own.objects.name.clone(), own_pool(NOW - 120));
    let plan = fixture.plan();
    assert!(
        names(&plan.writes).contains(&format!("replace-pool {old}")),
        "{plan:?}"
    );
    assert!(plan.unconfigured.contains(&old));

    // A newer revision is the next release's: kept until the grace.
    fixture
        .pools
        .insert(own.objects.name.clone(), own_pool(NOW - 7200));
    fixture.pools.insert(old.clone(), old_pool(NOW - grace + 1));
    assert!(untouched(&fixture.plan()));
    fixture.pools.insert(old.clone(), old_pool(NOW - grace));
    assert!(names(&fixture.plan().writes).contains(&format!("replace-pool {old}")));

    // No own pool yet, its template still waiting: only the grace drains.
    fixture.pools.remove(&own.objects.name);
    fixture.pools.insert(old.clone(), old_pool(NOW - grace + 1));
    assert!(untouched(&fixture.plan()));
    fixture.pools.insert(old.clone(), old_pool(NOW - grace));
    assert!(names(&fixture.plan().writes).contains(&format!("replace-pool {old}")));

    // The node cap's zero keeps the old pool behind an unready own pool.
    fixture.desired[0].configured.members = 2;
    fixture
        .pools
        .insert(own.objects.name.clone(), own_pool(NOW - 120));
    fixture.pools.insert(old.clone(), old_pool(NOW - 3600));
    assert!(untouched(&fixture.plan()));
}

#[test]
fn terminating_pool_objects_are_never_written() {
    let mut fixture = Fixture::empty();
    let small = fixture.desired[0].clone();
    let mut template = small.objects.template.clone();
    template["metadata"]["deletionTimestamp"] =
        json!(Timestamp::from_second(NOW).unwrap().to_string());
    fixture
        .templates
        .insert(small.objects.name.clone(), live(&template, "template-0"));
    let plan = fixture.plan();
    assert!(
        !names(&plan.writes)
            .iter()
            .any(|write| write.ends_with(&small.objects.name))
    );
}

fn node(name: &str, cpu: &str, memory: &str, ready: bool, cordoned: bool) -> Node {
    serde_json::from_value(json!({
        "metadata": { "name": name },
        "spec": { "unschedulable": cordoned },
        "status": {
            "allocatable": { "cpu": cpu, "memory": memory },
            "conditions": [{ "type": "Ready", "status": if ready { "True" } else { "False" } }],
        },
    }))
    .unwrap()
}

#[test]
fn the_node_cap_uses_the_configured_percentage_of_the_smallest_schedulable_node() {
    let nodes = [
        node("large", "16", "64Gi", true, false),
        node("medium", "7800m", "32Gi", true, false),
        node("cordoned", "2", "8Gi", true, true),
        node("not-ready", "1", "4Gi", false, false),
    ];
    let budget = node_budget(&nodes, 25);
    assert_eq!(budget.cpu_millis, 1950);
    assert_eq!(budget.memory_bytes, 8 << 30);
    let dev_budget = node_budget(&nodes, 50);
    assert_eq!(dev_budget.cpu_millis, 3900);
    assert_eq!(dev_budget.memory_bytes, 16 << 30);
    assert_eq!(node_budget(&[], 50), Budget::default());
    assert_eq!(node_budget(&nodes[2..], 25), Budget::default());
    let unreadable = node("odd", "lots", "64Gi", true, false);
    assert_eq!(
        node_budget(&[nodes[0].clone(), unreadable], 50),
        Budget::default()
    );
    assert!(node_unfit(Some(&nodes[2]), &[]) && !node_unfit(Some(&nodes[0]), &[]));
}

#[test]
fn member_reservations_count_requests_sidecars_and_runtime_overhead() {
    let pools = desired();
    let overhead = BTreeMap::from([
        ("cpu".to_owned(), "250m".to_owned()),
        ("memory".to_owned(), "130Mi".to_owned()),
    ]);
    // Workspace requests plus DinD (500m, 1Gi), the workspace-flush sidecar
    // (5m, 8Mi) and the commodity overhead.
    let small = member_reservation(
        &pools[0].objects.template["spec"]["podTemplate"]["spec"],
        &overhead,
    )
    .unwrap();
    assert_eq!(small.cpu_millis, 1000 + 500 + 5 + 250);
    assert_eq!(small.memory_bytes, (4096 + 1024 + 8 + 130) << 20);

    let spec = json!({
        "containers": [{ "resources": { "requests": { "cpu": "1", "memory": "1Gi" } } }],
        "initContainers": [
            { "restartPolicy": "Always", "resources": { "requests": { "cpu": "100m", "memory": "64Mi" } } },
            { "resources": { "requests": { "cpu": "3", "memory": "128Mi" } } },
        ],
    });
    let reservation = member_reservation(&spec, &BTreeMap::new()).unwrap();
    assert_eq!(reservation.cpu_millis, 3100);
    assert_eq!(reservation.memory_bytes, (1024 + 64) << 20);
    let unparsable = json!({ "containers": [{ "resources": { "requests": { "cpu": "fast" } } }] });
    assert_eq!(member_reservation(&unparsable, &BTreeMap::new()), None);
}

#[test]
fn a_pod_takes_its_own_runtime_class_overhead() {
    let tier = |memory: &str| BTreeMap::from([("memory".to_owned(), memory.to_owned())]);
    let overheads = ClassOverheads::from([
        ("commodity".to_owned(), tier("1536Mi")),
        ("commodity-32g".to_owned(), tier("4Gi")),
    ]);
    let class = |name: &str| json!({ "runtimeClassName": name });
    assert_eq!(
        pod_overhead(&class("commodity"), &overheads),
        Some(&tier("1536Mi"))
    );
    assert_eq!(
        pod_overhead(&class("commodity-32g"), &overheads),
        Some(&tier("4Gi"))
    );
    // No class adds nothing; a class that was not read can't be counted.
    assert_eq!(pod_overhead(&json!({}), &overheads), Some(&BTreeMap::new()));
    assert_eq!(pod_overhead(&class(""), &overheads), Some(&BTreeMap::new()));
    assert_eq!(pod_overhead(&class("confidential"), &overheads), None);
}

#[test]
fn members_are_clamped_in_configuration_order() {
    let pools = desired();
    let small = Reservation {
        cpu_millis: 1750,
        memory_bytes: 5250 << 20,
    };
    let large = Reservation {
        cpu_millis: 2750,
        memory_bytes: 9346 << 20,
    };
    let budget = |cpu: i128, memory_gib: i128| Budget {
        cpu_millis: cpu,
        memory_bytes: memory_gib << 30,
    };
    let reservations = [Some(small), Some(large)];
    assert_eq!(
        clamp_members(&pools, &reservations, budget(16_000, 64)),
        [2, 2]
    );
    assert_eq!(
        clamp_members(&pools, &reservations, budget(4_000, 16)),
        [2, 0]
    );
    assert_eq!(
        clamp_members(&pools, &reservations, budget(1_000, 64)),
        [0, 0]
    );
    assert_eq!(
        clamp_members(&pools, &[None, Some(large)], budget(16_000, 64)),
        [0, 2]
    );
    assert_eq!(
        clamp_members(&pools, &reservations, Budget::default()),
        [0, 0]
    );
}

fn cache(images: &[&str], complete: bool) -> Value {
    let desired = DesiredSet {
        images: images.iter().map(|image| (*image).to_owned()).collect(),
        skipped: 0,
        release: 3,
    };
    let mut state = CacheState::default();
    merge(&mut state, &desired);
    let (mut daemon_set, _) = render_daemon_set(
        &RenderConfig {
            namespace: NAMESPACE.into(),
        },
        &state,
    );
    daemon_set["metadata"]["generation"] = json!(4);
    daemon_set["status"] = json!({
        "observedGeneration": 4,
        "desiredNumberScheduled": 1,
        "updatedNumberScheduled": if complete { 1 } else { 0 },
        "numberAvailable": 1,
        "numberReady": 1,
    });
    daemon_set
}

#[test]
fn the_image_cache_gate_needs_every_cacheable_image_held_and_rolled_out() {
    let cfg = dev_cfg("1000m/4096Mi/10Gi=2");
    let config = WarmPoolConfig::from_cfg(&cfg, true).unwrap().unwrap();
    let rendered = super::super::render(&(&cfg).into(), NAMESPACE, &config.wanted).unwrap();
    let images = super::super::images(&rendered);
    assert_eq!(
        images.len(),
        3,
        "workspace, DinD and the daemon support image"
    );
    assert!(image_cache_warm(Some(&cache(&images, true)), &images));
    assert!(!image_cache_warm(Some(&cache(&images, false)), &images));
    assert!(!image_cache_warm(Some(&cache(&images[..2], true)), &images));
    assert!(!image_cache_warm(None, &images));
    let mut unreadable = cache(&images, true);
    unreadable["metadata"]["annotations"] = json!({});
    assert!(!image_cache_warm(Some(&unreadable), &images));
    // An image the cache never holds does not block.
    let mut with_local = images.clone();
    with_local.push("codewire-daemon:e2e");
    assert!(image_cache_warm(Some(&cache(&images, true)), &with_local));
}

/// The controller stores members through typed structs: canonical
/// quantities and dropped empty values. Such a member is current, not stale.
#[test]
fn a_member_in_the_controllers_spelling_is_current() {
    let mut fixture = Fixture::settled();
    let small = fixture.desired[0].clone();
    let copy = crate::sandbox::warm_pool::tests::controller_copy(&small.objects.template);
    assert_ne!(copy["spec"], small.objects.template["spec"]);
    fixture
        .members
        .push(object(member(&small, "pool-0", "member-copied", &copy)));
    assert!(fixture.plan().writes.is_empty());
    assert_eq!(fixture.plan().reports[&small.label()].members, 1);
}

/// Review M3: members on nodes that are not Ready, or tainted against them,
/// are replaced like cordoned ones; a tolerated taint keeps them.
#[test]
fn members_on_unfit_nodes_are_replaced() {
    let mut fixture = Fixture::settled();
    let small = fixture.desired[0].clone();
    let mut tainted = node("runtime-3", "32", "128Gi", true, false);
    tainted.spec.as_mut().unwrap().taints = Some(vec![Taint {
        key: "node.codewire.sh/maintenance".into(),
        effect: "NoExecute".into(),
        ..Taint::default()
    }]);
    fixture.nodes.insert("runtime-3".into(), tainted);
    fixture.nodes.insert(
        "runtime-4".into(),
        node("runtime-4", "32", "128Gi", false, false),
    );
    for (pod, node) in [
        ("member-tainted", "runtime-3"),
        ("member-not-ready", "runtime-4"),
        ("member-gone-node", "runtime-9"),
        ("member-healthy", "runtime-1"),
        ("member-tolerating", "runtime-3"),
    ] {
        fixture.members.push(object(member(
            &small,
            "pool-0",
            pod,
            &small.objects.template,
        )));
        fixture.place(pod, node);
    }
    fixture
        .member_pods
        .get_mut("member-tolerating")
        .unwrap()
        .tolerations = vec![Toleration {
        key: Some("node.codewire.sh/maintenance".into()),
        operator: Some("Exists".into()),
        ..Toleration::default()
    }];
    assert_eq!(
        names(&fixture.plan().writes),
        [
            "delete-member member-tainted node_unfit",
            "delete-member member-not-ready node_unfit",
            "delete-member member-gone-node node_unfit",
        ]
    );
}

/// Review H1: only a pool whose status observed its current generation shows
/// a claim-safe controller; the pinned controller writes no such field.
#[test]
fn only_an_observed_generation_shows_a_capable_controller() {
    let small = desired()[0].clone();
    let with_status = |generation: i64, status: Value| {
        let mut pool = small.objects.pool.clone();
        pool["metadata"]["generation"] = json!(generation);
        pool["status"] = status;
        object(pool)
    };
    assert!(!controller_capable(&[]));
    assert!(!controller_capable(&[with_status(
        2,
        json!({ "replicas": 0, "readyReplicas": 0 })
    )]));
    assert!(!controller_capable(&[with_status(
        3,
        json!({ "observedGeneration": 2 })
    )]));
    assert!(controller_capable(&[
        with_status(1, json!({})),
        with_status(3, json!({ "observedGeneration": 3 })),
    ]));
}

/// With no SandboxWarmPool anywhere, the held reconciler creates the first
/// configured pool's template (only behind a warm image cache), then that
/// pool with zero members, and nothing else.
#[test]
fn a_held_cluster_without_pools_bootstraps_one_empty_pool() {
    let desired = desired();
    let first = &desired[0];
    let none = BTreeMap::new();
    assert!(bootstrap_writes(&desired, &none, false).is_empty());
    assert!(bootstrap_writes(&[], &none, true).is_empty());
    assert_eq!(
        bootstrap_writes(&desired, &none, true),
        [Write::CreateTemplate {
            name: first.objects.name.clone(),
            body: first.objects.template.clone(),
        }]
    );

    let templates = BTreeMap::from([(
        first.objects.name.clone(),
        live(&first.objects.template, "template-uid"),
    )]);
    let writes = bootstrap_writes(&desired, &templates, false);
    let [Write::CreatePool { name, body }] = writes.as_slice() else {
        panic!("one empty pool after its template: {writes:?}");
    };
    assert_eq!(name, &first.objects.name);
    assert_eq!(body["spec"]["replicas"], 0);
    let mut expected = first.objects.pool.clone();
    expected["spec"]["replicas"] = json!(0);
    assert_eq!(body, &expected);

    let mut terminating = first.objects.template.clone();
    terminating["metadata"]["deletionTimestamp"] = json!("2026-10-03T00:00:00Z");
    let templates = BTreeMap::from([(first.objects.name.clone(), live(&terminating, "t"))]);
    assert!(bootstrap_writes(&desired, &templates, true).is_empty());
}

/// Review L6: a lower budget waits three passes; a higher one applies now.
#[test]
fn a_lower_budget_applies_only_after_it_holds() {
    let high = Budget {
        cpu_millis: 8000,
        memory_bytes: 32 << 30,
    };
    let low = Budget {
        cpu_millis: 2000,
        memory_bytes: 32 << 30,
    };
    assert_eq!(settle_budget(None, low), (low, 0));
    let mut state = settle_budget(None, high);
    for expected in [1, 2] {
        state = settle_budget(Some(state), low);
        assert_eq!(state, (high, expected));
    }
    assert_eq!(settle_budget(Some(state), low), (low, 0));
    // A recovery resets the count.
    let state = settle_budget(Some((high, 2)), high);
    assert_eq!(state, (high, 0));
}

/// Review L5: a template with this replica's revision label but another spec
/// is not current, and is replaced.
#[test]
fn a_template_is_current_only_when_its_spec_is() {
    let mut fixture = Fixture::settled();
    let small = fixture.desired[0].clone();
    let template = fixture.templates.get_mut(&small.objects.name).unwrap();
    assert!(template_spec_current(template, &small.objects.template));
    template.data["spec"]["podTemplate"]["spec"]["hostNetwork"] = json!(true);
    assert!(!template_spec_current(template, &small.objects.template));
    let plan = fixture.plan();
    assert_eq!(
        names(&plan.writes),
        [format!("replace-template {}", small.objects.name)]
    );
    assert!(!plan.reports[&small.label()].template_current);
}

/// #3572: while two revisions of a shape are live, the other revision's
/// members count against the node cap, so a rotation never reserves more than
/// steady state on a busy node. A draining pool counts the members it still
/// has; pools of unconfigured shapes and unlabelled objects do not count.
#[test]
fn another_revisions_members_count_against_the_node_cap() {
    let mut previous_cfg = dev_cfg("1000m/4096Mi/10Gi=2,2000m/8192Mi/10Gi=2");
    previous_cfg.daemon_image = "registry.example.invalid/codewire/daemon@sha256:4444444444444444444444444444444444444444444444444444444444444444".into();
    let previous = rendered(&previous_cfg).pools;
    let fixture = Fixture::settled();
    let reservations = [
        Some(Reservation {
            cpu_millis: 1_500,
            memory_bytes: 5 << 30,
        }),
        Some(Reservation {
            cpu_millis: 2_500,
            memory_bytes: 9 << 30,
        }),
    ];
    let mut pools = fixture.pools.clone();
    // Only this replica's own pools: nothing is held.
    assert_eq!(
        superseded_reservation(&fixture.desired, &reservations, &pools),
        Reservation::default()
    );
    // The small shape's older revision, draining: spec 0, two members left.
    let mut draining = live_pool(&previous[0], "pool-previous", 0, 0);
    draining.data["status"]["replicas"] = json!(2);
    pools.insert(previous[0].objects.name.clone(), draining);
    let held = superseded_reservation(&fixture.desired, &reservations, &pools);
    assert_eq!(
        held,
        Reservation {
            cpu_millis: 3_000,
            memory_bytes: 10 << 30,
        }
    );
    let budget = Budget {
        cpu_millis: 5_000,
        memory_bytes: 64 << 30,
    };
    let left = budget_after(budget, held);
    assert_eq!((left.cpu_millis, left.memory_bytes), (2_000, 54 << 30));
    // The large shape can then hold fewer members than it is configured for.
    assert_eq!(
        clamp_members(&fixture.desired[1..], &reservations[1..], left),
        [0]
    );
    // Never below zero.
    let none = budget_after(
        Budget {
            cpu_millis: 1_000,
            memory_bytes: 1 << 30,
        },
        held,
    );
    assert_eq!((none.cpu_millis, none.memory_bytes), (0, 0));
    // An unlabelled object of a pool's name is not a pool.
    let mut unlabelled = fixture.pools.clone();
    let mut object = live_pool(&previous[1], "pool-other", 2, 2);
    object.metadata.labels = None;
    unlabelled.insert(previous[1].objects.name.clone(), object);
    assert_eq!(
        superseded_reservation(&fixture.desired, &reservations, &unlabelled),
        Reservation::default()
    );
}
