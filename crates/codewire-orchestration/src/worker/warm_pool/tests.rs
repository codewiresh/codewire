//! The warm-pool loop's configuration and the start gate (Program #2238 C2,
//! #3572).

use super::*;
use crate::runtime::kubernetes::warm_pools::{render, runtime_classes};
use crate::sandbox::template::{
    CredentialRuntimeTemplateConfig, DOCKER_MODE_PROFILE_DEFAULT, RUNTIME_PROFILE_COMMODITY,
    RUNTIME_PROFILE_CONFIDENTIAL,
};

const NAMESPACE: &str = "dev-sandboxes";

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

#[test]
fn no_configured_shape_keeps_the_reconciler_inert() {
    for unset in ["", "   ", "\n"] {
        for cache in [true, false] {
            assert!(
                WarmPoolConfig::from_cfg(&dev_cfg(unset), cache)
                    .unwrap()
                    .is_none(),
                "{unset:?} configures no pool"
            );
        }
    }
    // The default configuration carries no shape.
    assert!(SandboxWorkerCfg::default().warm_pool_shapes.is_empty());
    assert!(
        WarmPoolConfig::from_cfg(&SandboxWorkerCfg::default(), true)
            .unwrap()
            .is_none()
    );
    let mut cfg = dev_cfg("");
    cfg.warm_pool_max_node_percent = "invalid".into();
    assert!(matches!(startup(&cfg, Ok(true)), Startup::Inert));
}

#[test]
fn the_node_reservation_percentage_defaults_and_refuses_invalid_configuration() {
    assert_eq!(parse_max_node_percent("").unwrap(), 25);
    for (value, expected) in [("1", 1), ("25", 25), ("50", 50), ("100", 100)] {
        let mut cfg = dev_cfg("2000m/16384Mi/80Gi=1");
        cfg.warm_pool_max_node_percent = value.into();
        let config = WarmPoolConfig::from_cfg(&cfg, false).unwrap().unwrap();
        assert_eq!(config.wanted.max_host_percent, expected);
    }
    for value in [
        "0", "101", "256", "-1", "+50", "50%", "0.5", " 50", "50 ", "bad",
    ] {
        let mut cfg = dev_cfg("2000m/16384Mi/80Gi=1");
        cfg.warm_pool_max_node_percent = value.into();
        assert!(WarmPoolConfig::from_cfg(&cfg, false).is_err(), "{value}");
        assert!(
            matches!(
                startup(&cfg, Ok(false)),
                Startup::Reconcile(WarmPoolConfig { wanted: WantedPools { draining: true, pools, .. }, .. }) if pools.is_empty()
            ),
            "{value} must drain existing pools"
        );
    }
}

#[test]
fn configured_shapes_render_through_the_identity_free_pool_renderer() {
    let config =
        WarmPoolConfig::from_cfg(&dev_cfg("1000m/4096Mi/10Gi=2,2000m/8192Mi/10Gi=1"), true)
            .unwrap()
            .unwrap();
    assert_eq!(config.placement, Placement::new(NAMESPACE));
    assert_eq!(config.wanted.pools.len(), 2);
    let rendered = render(NAMESPACE, &config.wanted).unwrap();
    assert!(
        rendered.pools[0]
            .objects
            .name
            .starts_with("cw-pool-1000m-4096mi-10gi-")
    );
    assert_eq!(config.wanted.pools[1].configured.members, 1);
    assert_eq!(rendered.pools[1].objects.pool["spec"]["replicas"], 1);
    assert_eq!(runtime_classes(&rendered), ["commodity"]);
    // A 32 GiB pool renders its memory tier's class, listed once.
    let tiers = WarmPoolConfig::from_cfg(
        &dev_cfg("1000m/4096Mi/10Gi=1,8000m/32768Mi/10Gi=1,16000m/32768Mi/10Gi=1"),
        true,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        runtime_classes(&render(NAMESPACE, &tiers.wanted).unwrap()),
        ["commodity", "commodity-32g"]
    );

    // Every renderer refusal refuses the whole configuration.
    assert!(WarmPoolConfig::from_cfg(&dev_cfg("1000m/4096Mi/10Gi"), true).is_err());
    let mut unbindable = dev_cfg("1000m/4096Mi/10Gi=1");
    unbindable.pod_namespace.clear();
    assert!(WarmPoolConfig::from_cfg(&unbindable, true).is_err());
    let mut confidential = dev_cfg("1000m/4096Mi/10Gi=1");
    confidential.runtime_profile = RUNTIME_PROFILE_CONFIDENTIAL.into();
    assert!(WarmPoolConfig::from_cfg(&confidential, true).is_err());
    let mut unpinned = dev_cfg("1000m/4096Mi/10Gi=1");
    unpinned.daemon_image = "registry.example.invalid/codewire/daemon:main".into();
    assert!(WarmPoolConfig::from_cfg(&unpinned, true).is_err());
    let mut no_namespace = dev_cfg("1000m/4096Mi/10Gi=1");
    no_namespace.sandbox_namespace.clear();
    assert!(WarmPoolConfig::from_cfg(&no_namespace, true).is_err());
}

/// Review L7: an invalid configuration drains existing pools instead of
/// leaving them unmanaged; no configuration stays inert.
#[test]
fn an_invalid_configuration_drains_and_none_is_inert() {
    assert!(matches!(startup(&dev_cfg(""), Ok(true)), Startup::Inert));
    assert!(matches!(
        startup(&dev_cfg(" "), Err(anyhow::anyhow!("bad cache"))),
        Startup::Inert
    ));
    for (shapes, cache) in [
        ("not-a-shape", Ok(true)),
        ("1000m/4096Mi/10Gi=2", Err(anyhow::anyhow!("bad cache"))),
    ] {
        match startup(&dev_cfg(shapes), cache) {
            Startup::Reconcile(config) => {
                assert!(
                    config.wanted.draining && config.wanted.pools.is_empty(),
                    "{shapes}"
                );
                assert_eq!(config.placement, Placement::new(NAMESPACE));
            }
            Startup::Inert => panic!("{shapes} must drain"),
        }
    }
    let mut unbindable = dev_cfg("1000m/4096Mi/10Gi=2");
    unbindable.pod_namespace.clear();
    assert!(matches!(
        startup(&unbindable, Ok(false)),
        Startup::Reconcile(WarmPoolConfig {
            wanted: WantedPools { draining: true, .. },
            ..
        })
    ));
    match startup(&dev_cfg("1000m/4096Mi/10Gi=2"), Ok(true)) {
        Startup::Reconcile(config) => {
            assert!(!config.wanted.draining && config.wanted.pools.len() == 1)
        }
        Startup::Inert => panic!("a valid configuration reconciles"),
    }
}

/// #3572: the gate a starting replica's `/readyz` and Temporal worker wait on
/// (one create missed on Dev, 2026-10-30, while a new replica's worker ran it
/// from a pool still warming). A start that does not rotate is warm at once
/// and warms nothing; a rotating start is held until its pools have a member.
/// The warm-up bound, a failed or slow rotation check, a failed warm-up and a
/// dropped sender all release it.
#[tokio::test(start_paused = true)]
async fn only_a_rotating_start_holds_the_temporal_worker() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::time::timeout;

    const DECIDE: Duration = Duration::from_secs(15);
    const WARM: Duration = Duration::from_secs(180);

    // A crash restart, a scale-up or a release without a template change.
    let (ready, mut worker) = watch::channel(false);
    let warmed = AtomicBool::new(false);
    hold_until_warm(
        &ready,
        async { Ok(None::<()>) },
        |()| async {
            warmed.store(true, Ordering::SeqCst);
            Ok(())
        },
        DECIDE,
        WARM,
    )
    .await;
    assert!(!warmed.load(Ordering::SeqCst));
    timeout(Duration::ZERO, pools_warmed(&mut worker))
        .await
        .expect("a start that does not rotate is never held");

    // A release rotating a pool: held until the pool has a member.
    let (ready, mut worker) = watch::channel(false);
    let (member_ready, member) = tokio::sync::oneshot::channel::<()>();
    let gate = tokio::spawn(async move {
        hold_until_warm(
            &ready,
            async { Ok(Some(())) },
            |()| async move {
                let _ = member.await;
                Ok(())
            },
            DECIDE,
            WARM,
        )
        .await;
    });
    assert!(
        timeout(Duration::from_secs(60), pools_warmed(&mut worker))
            .await
            .is_err(),
        "a rotating start holds its worker while its pools warm"
    );
    member_ready.send(()).unwrap();
    timeout(Duration::from_secs(1), pools_warmed(&mut worker))
        .await
        .expect("released once its pools have a member");
    gate.await.unwrap();

    // A pool that never warms: released at the bound.
    let (ready, mut worker) = watch::channel(false);
    let gate = tokio::spawn(async move {
        hold_until_warm(
            &ready,
            async { Ok(Some(())) },
            |()| std::future::pending::<anyhow::Result<()>>(),
            DECIDE,
            WARM,
        )
        .await;
    });
    assert!(
        timeout(WARM - Duration::from_secs(1), pools_warmed(&mut worker))
            .await
            .is_err()
    );
    timeout(Duration::from_secs(2), pools_warmed(&mut worker))
        .await
        .expect("released at the warm-up bound");
    gate.await.unwrap();

    // A warm-up that fails, and a rotation check that fails: released at once.
    let (ready, mut worker) = watch::channel(false);
    hold_until_warm(
        &ready,
        async { Ok(Some(())) },
        |()| async { Err(anyhow::anyhow!("pool create refused")) },
        DECIDE,
        WARM,
    )
    .await;
    timeout(Duration::ZERO, pools_warmed(&mut worker))
        .await
        .expect("a failed warm-up releases the worker");
    let (ready, mut worker) = watch::channel(false);
    hold_until_warm(
        &ready,
        async { Err::<Option<()>, _>(anyhow::anyhow!("API unreachable")) },
        |()| async { Ok(()) },
        DECIDE,
        WARM,
    )
    .await;
    timeout(Duration::ZERO, pools_warmed(&mut worker))
        .await
        .expect("a failed rotation check releases the worker");

    // A rotation check that hangs: released at its own, shorter bound.
    let (ready, mut worker) = watch::channel(false);
    let gate = tokio::spawn(async move {
        hold_until_warm(
            &ready,
            std::future::pending::<anyhow::Result<Option<()>>>(),
            |()| async { Ok(()) },
            DECIDE,
            WARM,
        )
        .await;
    });
    timeout(DECIDE + Duration::from_secs(1), pools_warmed(&mut worker))
        .await
        .expect("released at the rotation-check bound");
    gate.await.unwrap();

    // A sender that is gone holds nothing.
    let (ready, mut worker) = watch::channel(false);
    drop(ready);
    timeout(Duration::ZERO, pools_warmed(&mut worker))
        .await
        .expect("a dropped sender releases the worker");
}

/// Only the leader asks the driver for a pass, one per tick at its placement.
/// Every tick a replica is not the leader, it has the driver forget what
/// earlier passes remembered, so a later leader starts afresh.
#[tokio::test]
async fn only_the_leader_keeps_pools_and_every_other_tick_forgets() {
    use crate::runtime::fake::FakeRuntimeDriver;

    let config = WarmPoolConfig::from_cfg(&dev_cfg("1000m/4096Mi/10Gi=2"), false)
        .unwrap()
        .unwrap();
    let runtime = FakeRuntimeDriver::default();
    runtime.pool_passes.lock().unwrap().extend([
        Ok(PoolPass::Wrote),
        Err("list refused".to_string()),
        Ok(PoolPass::Conflict),
    ]);
    for _ in 0..3 {
        assert_eq!(tick(&runtime, &config, false).await, None);
    }
    assert_eq!(*runtime.pool_memory_forgotten.lock().unwrap(), 3);
    assert!(runtime.placements.lock().unwrap().is_empty());

    assert_eq!(tick(&runtime, &config, true).await, Some(PassResult::Wrote));
    assert_eq!(tick(&runtime, &config, true).await, Some(PassResult::Error));
    assert_eq!(
        tick(&runtime, &config, true).await,
        Some(PassResult::Conflict)
    );
    assert_eq!(*runtime.pool_memory_forgotten.lock().unwrap(), 3);
    assert_eq!(
        *runtime.placements.lock().unwrap(),
        vec![Placement::new(NAMESPACE); 3]
    );
}

/// The loop's own metrics keep their names and labels (#3628).
#[test]
fn the_loops_metric_names_and_labels_are_unchanged() {
    use prometheus::core::Collector;

    let named = |collector: &dyn Collector| {
        let desc = collector.desc()[0];
        (desc.fq_name.clone(), desc.variable_labels.clone())
    };
    record_result(PassResult::Unchanged);
    assert_eq!(
        named(RECONCILES.get().unwrap()),
        (
            "codewire_warm_pool_reconciles_total".to_string(),
            vec!["result".to_string()]
        )
    );
    assert_eq!(
        named(config_valid_metric()),
        ("codewire_warm_pool_config_valid".to_string(), vec![])
    );
}
